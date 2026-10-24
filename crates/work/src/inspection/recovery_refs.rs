//! Explicit create-only recovery-ref protection. Local, not backup or retirement.
//! Tests were authored before this logic; no local RED/GREEN claim.
use super::*;
use crate::config::{Config, ConfigDocument};
use rustix::fs::{self as rfs, Mode, OFlags, ResolveFlags};
use serde::Serialize;
use std::{
    fs::File,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
};

mod storage;
mod sync;

type Held<T> = Result<T, &'static str>;

#[derive(Debug, Serialize)]
pub struct RecoveryReport {
    checkout: Uuid,
    operation: Option<Uuid>,
    coverage: &'static str,
    outcome: &'static str,
    reason: &'static str,
    intent_id: Option<Uuid>,
    result_id: Option<Uuid>,
    intent_checksum: Option<String>,
    created_refs: Vec<String>,
    verified_refs: Vec<String>,
    inspection_findings: serde_json::Value,
    additional_work_holds: serde_json::Value,
    remote_head: serde_json::Value,
    durability: &'static str,
    limitation: &'static str,
    recorded: bool,
    retirement_authority: bool,
    resume: bool,
    cleanup: &'static str,
}
impl RecoveryReport {
    pub fn prepared(&self) -> bool {
        self.outcome == "prepared" || self.outcome == "historical"
    }
    fn held(checkout: Uuid, operation: Option<Uuid>) -> Self {
        Self {
            checkout,
            operation,
            coverage: "incomplete",
            outcome: "held",
            reason: "creation_required",
            intent_id: None,
            result_id: None,
            intent_checksum: None,
            created_refs: vec![],
            verified_refs: vec![],
            inspection_findings: serde_json::json!([]),
            additional_work_holds: serde_json::json!([]),
            remote_head: serde_json::Value::Null,
            durability: "not_attempted",
            limitation: "LOCAL storage is not off-host backup. Preparation is local protection only, never remote preservation, ownership attribution, approval eligibility or retirement. Without --create and --operation, no mutation occurs; use work audit-preservation.",
            recorded: false,
            retirement_authority: false,
            resume: false,
            cleanup: "not_created",
        }
    }
}

/// Refuse mutation unless the caller supplied both required flags.
pub fn prepare_recovery_refused(checkout: Uuid) -> RecoveryReport {
    RecoveryReport::held(checkout, None)
}

pub fn prepare_recovery(checkout: Uuid, operation: Uuid) -> RecoveryReport {
    match Config::discover_path() {
        Some(path) => prepare_path(
            &path,
            checkout,
            operation,
            #[cfg(test)]
            Fault::None,
        ),
        None => {
            let mut report = RecoveryReport::held(checkout, Some(operation));
            report.reason = "configuration_unknown";
            report
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    IntentWrite,
    IntentSync,
    BeforeCas,
    AfterFirstCas,
    ObjectSync,
    RefSync,
    ResultWrite,
}

#[cfg(test)]
thread_local! {
    static FAULT_HIT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
    static AFTER_CAS: std::cell::RefCell<Option<fn()>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn fault_hit(fault: Fault) {
    FAULT_HIT.with(|hit| hit.set(fault));
}

#[cfg(test)]
fn take_fault_hit() -> Fault {
    FAULT_HIT.with(|hit| hit.replace(Fault::None))
}

struct CommonKey {
    path: Vec<u8>,
    dev: u64,
    ino: u64,
}

struct OperationLock {
    authority: File,
    directory: File,
    file: File,
    authority_id: (u64, u64),
    directory_id: (u64, u64),
    file_id: (u64, u64),
    name: String,
}
impl OperationLock {
    fn revalidate(&self, store: &Store, key: &CommonKey, common_path: &[u8]) -> Held<()> {
        let identity = store.authority_identity();
        if key.path != common_path {
            return Err("common_identity_changed");
        }
        let authority = open_lock_authority(store)?;
        let named_dir = open_lock_child(&authority, LOCK_DIR, OFlags::RDONLY | OFlags::DIRECTORY)?;
        let named_file = open_lock_child(&named_dir, &self.name, OFlags::RDONLY)?;
        if lock_identity(&authority)? != self.authority_id
            || lock_identity(&named_dir)? != self.directory_id
            || lock_identity(&self.directory)? != self.directory_id
            || lock_identity(&named_file)? != self.file_id
            || lock_identity(&self.file)? != self.file_id
            || identity.directory_id != self.authority_id
        {
            return Err("lock_unknown");
        }
        Ok(())
    }
}

pub(super) struct Retained {
    pub(super) context: Context,
    pub(super) physical: Physical,
    pub(super) document_policy: Vec<u8>,
    pub(super) config: filesystem::Manifest,
}

pub(super) struct Collector {
    checkout: Uuid,
    operation: Uuid,
    store: Option<Store>,
    lock: Option<OperationLock>,
    key: Option<CommonKey>,
    plan: Option<FreshRecoveryPlan>,
    failure: Option<&'static str>,
    mutating_git: u64,
    #[cfg(test)]
    fault: Fault,
}
impl Collector {
    fn new(checkout: Uuid, operation: Uuid, #[cfg(test)] fault: Fault) -> Self {
        Self {
            checkout,
            operation,
            store: None,
            lock: None,
            key: None,
            plan: None,
            failure: None,
            mutating_git: 0,
            #[cfg(test)]
            fault,
        }
    }
    pub(super) fn failed(&mut self, reason: &'static str) {
        self.failure = Some(reason);
    }
    pub(super) fn configure(&mut self, _document: &ConfigDocument, config: &Config) -> Held<()> {
        let store = open_configured_store(config).map_err(|_| "authority_unknown")?;
        self.store = Some(store);
        Ok(())
    }
    pub(super) fn context(&mut self, b: &mut Budget) -> Held<Context> {
        let store = self.store.as_mut().ok_or("authority_unknown")?;
        store.may_acquire_lease().map_err(|_| "authority_unknown")?;
        let authority = std::sync::Arc::clone(store.authority_identity());
        let phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|_| "authority_unknown")?;
        let context = snapshot_in_transaction(&tx, &authority, self.checkout, b)
            .map_err(|_| "context_unknown")?;
        tx.rollback().map_err(|_| "context_unknown")?;
        drop(phase);
        Ok(context)
    }
    pub(super) fn lock_common(&mut self, context: &Context, b: &mut Budget) -> Held<()> {
        let identity = context
            .allocation
            .identity
            .as_ref()
            .ok_or("identity_unknown")?;
        native_anchor_path(&identity.common_git_dir).map_err(|_| "identity_unknown")?;
        let manifest = filesystem::Manifest::new(&identity.common_git_dir, b)
            .map_err(|_| "identity_unknown")?;
        sync::persistent_manifest(&manifest)?;
        let (dev, ino) = manifest.root_dev_ino();
        let key = CommonKey {
            path: identity.common_git_dir.as_os_str().as_bytes().to_vec(),
            dev,
            ino,
        };
        let store = self.store.as_ref().ok_or("authority_unknown")?;
        self.lock = Some(acquire_lock(store, &key)?);
        self.key = Some(key);
        Ok(())
    }
    pub(super) fn confirm_common(&self, common: &filesystem::Manifest, path: &[u8]) -> Held<()> {
        let key = self.key.as_ref().ok_or("identity_unknown")?;
        let lock = self.lock.as_ref().ok_or("lock_unknown")?;
        let (dev, ino) = common.root_dev_ino();
        if (dev, ino) != (key.dev, key.ino) || key.path != path {
            return Err("common_identity_changed");
        }
        let store = self.store.as_ref().ok_or("authority_unknown")?;
        lock.revalidate(store, key, path)?;
        sync::persistent_manifest(common)?;
        Ok(())
    }
    pub(super) fn seal(
        &mut self,
        retained: Retained,
        census: preservation::RecoveryCensus,
        budget: Budget,
        remote: &RemoteReport,
    ) -> Held<()> {
        let key = self.key.as_ref().ok_or("identity_unknown")?;
        if census.common_dev_ino() != (key.dev, key.ino) {
            return Err("common_identity_changed");
        }
        if census.reserved_namespace_held() {
            return Err("recovery_namespace_unknown");
        }
        let plan = census
            .plan(self.checkout)?
            .into_iter()
            .map(|row| storage::PlanEntry {
                reference: row.reference,
                oid: row.oid,
                object_type: row.object_type.into(),
                provenance: row.provenance,
            })
            .collect();
        let lock = self.lock.take().ok_or("lock_unknown")?;
        let key = self.key.take().ok_or("identity_unknown")?;
        let source_witness = census.source_witness(
            &retained.physical.first,
            &retained.physical.before,
            Some(&retained.config),
        );
        if source_witness.len() as u64 > 2 * 1024 * 1024 {
            return Err("encoding_limit");
        }
        let source_commitment = census.source_commitment(
            &retained.physical.first,
            &retained.physical.before,
            Some(&retained.config),
        );
        self.plan = Some(FreshRecoveryPlan {
            checkout: self.checkout,
            operation: self.operation,
            result_id: Uuid::now_v7(),
            retained,
            census,
            plan,
            source_commitment,
            source_witness,
            budget,
            remote_cleanup: remote.cleanup() == "complete",
            lock,
            key,
        });
        Ok(())
    }
}

struct FreshRecoveryPlan {
    checkout: Uuid,
    operation: Uuid,
    result_id: Uuid,
    retained: Retained,
    census: preservation::RecoveryCensus,
    plan: Vec<storage::PlanEntry>,
    source_commitment: [u8; 32],
    source_witness: Vec<u8>,
    budget: Budget,
    remote_cleanup: bool,
    lock: OperationLock,
    key: CommonKey,
}

fn prepare_path(
    path: &Path,
    checkout: Uuid,
    operation: Uuid,
    #[cfg(test)] fault: Fault,
) -> RecoveryReport {
    if checkout.get_version_num() != 7
        || operation.get_version_num() != 7
        || checkout.get_variant() != uuid::Variant::RFC4122
        || operation.get_variant() != uuid::Variant::RFC4122
    {
        let mut report = RecoveryReport::held(checkout, Some(operation));
        report.reason = "invalid_checkout";
        return report;
    }
    let mut collector = Collector::new(
        checkout,
        operation,
        #[cfg(test)]
        fault,
    );
    let mut audit = preservation::Audit::new(checkout);
    let remote = remote_proof::recovery_path(path, checkout, &mut audit, &mut collector);
    let preservation = audit.finish(remote);
    let failure = collector.failure;
    let mutating_git = collector.mutating_git;
    #[cfg(test)]
    let fault = collector.fault;
    let mut report = RecoveryReport::held(checkout, Some(operation));
    report.reason = failure.unwrap_or(preservation.reason());
    if let Ok(value) = serde_json::to_value(&preservation) {
        report.coverage = match value.get("coverage").and_then(|v| v.as_str()) {
            Some("complete") => "complete",
            _ => "incomplete",
        };
        report.inspection_findings = value
            .get("inspection_findings")
            .cloned()
            .unwrap_or(serde_json::json!([]));
        report.additional_work_holds = value
            .get("additional_work_holds")
            .cloned()
            .unwrap_or(serde_json::json!([]));
        report.remote_head = value
            .get("remote_head")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        report.cleanup = match value.get("cleanup").and_then(|v| v.as_str()) {
            Some("complete") => "complete",
            Some("not_created") => "not_created",
            _ => "incomplete",
        };
    }
    if let (Some(mut store), Some(plan)) = (collector.store.take(), collector.plan.take()) {
        match resume_or_execute(
            &mut store,
            plan,
            &mut report,
            mutating_git,
            #[cfg(test)]
            fault,
        ) {
            Ok(()) => (),
            Err(reason) => {
                report.reason = reason;
                if report.outcome == "prepared" {
                    report.outcome = "unknown";
                }
            }
        }
    }
    if report.outcome == "held" && report.reason == "consistent_observation" {
        report.reason = failure.unwrap_or("recovery_sequence_unknown");
    }
    report
}

fn resume_or_execute(
    store: &mut Store,
    mut plan: FreshRecoveryPlan,
    report: &mut RecoveryReport,
    mut mutating_git: u64,
    #[cfg(test)] fault: Fault,
) -> Held<()> {
    if !plan.remote_cleanup {
        return Err("incomplete_observation");
    }
    sync::persistent_manifest(plan.census.common())?;
    match receipts::read_raw(store, plan.operation) {
        Ok(bytes) => resume_published(
            store,
            bytes,
            plan,
            report,
            &mut mutating_git,
            #[cfg(test)]
            fault,
        ),
        Err(ReceiptError::Missing) => execute_fresh(
            store,
            &mut plan,
            report,
            &mut mutating_git,
            #[cfg(test)]
            fault,
        ),
        Err(ReceiptError::Corrupt) => Err("intent_corrupt"),
        Err(_) => Err("intent_unknown"),
    }
}

fn resume_published(
    store: &mut Store,
    bytes: Vec<u8>,
    mut plan: FreshRecoveryPlan,
    report: &mut RecoveryReport,
    mutating_git: &mut u64,
    #[cfg(test)] fault: Fault,
) -> Held<()> {
    report.resume = true;
    let decoded = storage::decode(&bytes)?;
    let intent = match decoded {
        storage::Record::Intent(intent) => intent,
        storage::Record::Result(_) => return Err("result_without_intent"),
    };
    let identity = plan
        .retained
        .context
        .allocation
        .identity
        .as_ref()
        .ok_or("identity_unknown")?;
    plan.lock.revalidate(
        store,
        &plan.key,
        identity.common_git_dir.as_os_str().as_bytes(),
    )?;
    let planned_names = sync::planned_names(&plan.plan);
    let planned_new =
        preservation::planned_new_from_witness(&intent.source_witness, &planned_names);
    let current_witness = plan.census.source_witness(
        &plan.retained.physical.first,
        &plan.retained.physical.before,
        Some(&plan.retained.config),
    );
    if intent.operation != plan.operation
        || intent.checkout != plan.checkout
        || intent.authority != storage::authority_bytes(store)
        || intent.common_dev != plan.census.common_dev_ino().0
        || intent.common_ino != plan.census.common_dev_ino().1
        || intent.common_path != plan.key.path
        || intent.context_digest != hash32(&Sha256::digest(&plan.retained.context.canonical))
        || intent.policy_digest != hash32(&Sha256::digest(&plan.retained.document_policy))
        || intent.plan != plan.plan
    {
        return Err("intent_binding_changed");
    }
    preservation::source_witness_delta(&intent.source_witness, &current_witness, &planned_new)?;
    receipts::resync_recovery_published(store, plan.operation).map_err(|error| {
        if matches!(error, ReceiptError::UnsafeReceiptStore) {
            "nonpersistent_filesystem"
        } else {
            receipt_reason(error)
        }
    })?;
    report.intent_id = Some(plan.operation);
    report.intent_checksum = Some(hex(&storage::intent_checksum(&bytes)?));
    report.result_id = Some(intent.result_id);
    plan.result_id = intent.result_id;
    match receipts::read_raw(store, intent.result_id) {
        Ok(result_bytes) => historical_result(
            &result_bytes,
            &intent,
            storage::intent_checksum(&bytes)?,
            report,
        ),
        Err(ReceiptError::Missing) => {
            let bound = receipts::RecoveryResultBinding {
                id: intent.result_id,
                length: intent.result_length,
                dev: intent.result_dev,
                ino: intent.result_ino,
            };
            execute_cas(
                store,
                &mut plan,
                report,
                mutating_git,
                Some(bytes),
                Some(bound),
                #[cfg(test)]
                fault,
            )
        }
        Err(_) => Err("result_unknown"),
    }
}

fn historical_result(
    bytes: &[u8],
    intent: &storage::Intent,
    intent_checksum: [u8; 32],
    report: &mut RecoveryReport,
) -> Held<()> {
    match storage::decode(bytes)? {
        storage::Record::Result(result) => {
            let expected: Vec<_> = intent
                .plan
                .iter()
                .map(|entry| (entry.reference.clone(), entry.oid.clone()))
                .collect();
            if result.operation != intent.operation
                || result.result_id != intent.result_id
                || result.checkout != intent.checkout
                || result.intent_checksum != intent_checksum
                || result.target_count != intent.plan.len() as u64
                || result.targets != expected
                || result.retirement_authority
                || !result.sync_ack
            {
                return Err("result_binding_changed");
            }
            report.outcome = "historical";
            report.reason = "historical_completion";
            report.durability = "historical";
            report.recorded = true;
            report.verified_refs = result.targets.iter().map(|(r, _)| r.clone()).collect();
            Ok(())
        }
        storage::Record::Intent(_) => Err("result_kind"),
    }
}

fn execute_fresh(
    store: &mut Store,
    plan: &mut FreshRecoveryPlan,
    report: &mut RecoveryReport,
    mutating_git: &mut u64,
    #[cfg(test)] fault: Fault,
) -> Held<()> {
    receipts::recovery_storage_persistent(store).map_err(|error| {
        if matches!(error, ReceiptError::UnsafeReceiptStore) {
            "nonpersistent_filesystem"
        } else {
            receipt_reason(error)
        }
    })?;
    let identity = plan
        .retained
        .context
        .allocation
        .identity
        .as_ref()
        .ok_or("identity_unknown")?;
    plan.lock.revalidate(
        store,
        &plan.key,
        identity.common_git_dir.as_os_str().as_bytes(),
    )?;
    let result_len = storage::encode_result(&empty_result_stub(plan))?.len() as u64;
    let result_res =
        receipts::reserve(store, plan.result_id, result_len).map_err(receipt_reason)?;
    let bound = receipts::reservation_binding(&result_res).map_err(receipt_reason)?;
    drop(result_res);
    let intent = current_intent(store, plan, &bound)?;
    let intent_bytes = storage::encode_intent(&intent)?;
    let intent_res = receipts::reserve(store, plan.operation, intent_bytes.len() as u64)
        .map_err(receipt_reason)?;
    #[cfg(test)]
    if fault == Fault::IntentWrite {
        fault_hit(Fault::IntentWrite);
        return Err("intent_io");
    }
    receipts::write_reserved(intent_res, &intent_bytes).map_err(receipt_reason)?;
    #[cfg(test)]
    if fault == Fault::IntentSync {
        fault_hit(Fault::IntentSync);
        return Err("intent_io");
    }
    let published = receipts::publish_recovery_reserved(
        store,
        plan.operation,
        intent_bytes.len() as u64,
        &plan.retained.context,
        &mut plan.budget,
    )
    .map_err(|error| {
        if matches!(error, ReceiptError::UnsafeReceiptStore) {
            "nonpersistent_filesystem"
        } else {
            receipt_reason(error)
        }
    })?;
    report.intent_id = Some(published.id());
    report.intent_checksum = Some(hex(&storage::intent_checksum(&intent_bytes)?));
    report.result_id = Some(plan.result_id);
    execute_cas(
        store,
        plan,
        report,
        mutating_git,
        Some(intent_bytes),
        Some(bound),
        #[cfg(test)]
        fault,
    )
}

fn empty_result_stub(plan: &FreshRecoveryPlan) -> storage::ResultRecord {
    storage::ResultRecord {
        operation: plan.operation,
        intent_checksum: [0; 32],
        result_id: plan.result_id,
        checkout: plan.checkout,
        target_count: plan.plan.len() as u64,
        targets: plan
            .plan
            .iter()
            .map(|e| (e.reference.clone(), e.oid.clone()))
            .collect(),
        closure_digest: [0; 32],
        sync_ack: true,
        retirement_authority: false,
    }
}

fn current_intent(
    store: &Store,
    plan: &FreshRecoveryPlan,
    bound: &receipts::RecoveryResultBinding,
) -> Held<storage::Intent> {
    let identity = plan
        .retained
        .context
        .allocation
        .identity
        .as_ref()
        .ok_or("identity_unknown")?;
    let (dev, ino) = plan.census.common_dev_ino();
    if bound.id != plan.result_id {
        return Err("result_binding_changed");
    }
    Ok(storage::Intent {
        operation: plan.operation,
        result_id: plan.result_id,
        checkout: plan.checkout,
        authority: storage::authority_bytes(store),
        common_path: identity.common_git_dir.as_os_str().as_bytes().to_vec(),
        common_dev: dev,
        common_ino: ino,
        private_path: identity.private_git_dir.as_os_str().as_bytes().to_vec(),
        boot: identity.boot_id.as_bytes().to_vec(),
        context_digest: hash32(&Sha256::digest(&plan.retained.context.canonical)),
        policy_digest: hash32(&Sha256::digest(&plan.retained.document_policy)),
        source_commitment: plan.source_commitment,
        source_witness: plan.source_witness.clone(),
        object_format: plan.census.object_format().into(),
        plan: plan.plan.clone(),
        create_only: true,
        result_length: bound.length,
        result_dev: bound.dev,
        result_ino: bound.ino,
    })
}

fn fail_after(
    report: &mut RecoveryReport,
    created: Vec<String>,
    verified: Vec<String>,
    launched: bool,
    reason: &'static str,
) -> Held<()> {
    report.created_refs = created;
    report.verified_refs = verified;
    if launched {
        report.outcome = "unknown";
        report.durability = "unknown";
    }
    Err(reason)
}

fn execute_cas(
    store: &mut Store,
    plan: &mut FreshRecoveryPlan,
    report: &mut RecoveryReport,
    mutating_git: &mut u64,
    intent_bytes: Option<Vec<u8>>,
    bound: Option<receipts::RecoveryResultBinding>,
    #[cfg(test)] fault: Fault,
) -> Held<()> {
    #[cfg(test)]
    if fault == Fault::BeforeCas {
        fault_hit(Fault::BeforeCas);
        return Err("cas_not_started");
    }
    let (git_path, common_path) = {
        let identity = plan
            .retained
            .context
            .allocation
            .identity
            .as_ref()
            .ok_or("identity_unknown")?;
        (
            identity.path.clone(),
            identity.common_git_dir.as_os_str().as_bytes().to_vec(),
        )
    };
    plan.lock.revalidate(store, &plan.key, &common_path)?;
    let format = plan.census.format();
    let mut created = Vec::new();
    let mut verified = Vec::new();
    let mut launched = false;
    plan.retained
        .physical
        .recheck(&mut plan.budget)
        .map_err(|_| "census_changed")?;
    plan.census.recheck(&mut plan.budget)?;
    #[cfg(test)]
    if fault == Fault::ObjectSync {
        fault_hit(Fault::ObjectSync);
        return Err("object_sync_failed");
    }
    sync::sync_objects(&plan.retained.physical.before.common, &mut plan.budget)?;
    for entry in &plan.plan {
        sync::recovery_log_absent(plan.census.common_mut(), &entry.reference, &mut plan.budget)?;
        match plan.census.existing_target(&entry.reference) {
            Some(existing) if existing == entry.oid.as_bytes() => {
                verified.push(entry.reference.clone());
                report.verified_refs = verified.clone();
            }
            Some(_) => return Err("recovery_ref_conflict"),
            None => {
                if !launched {
                    launched = true;
                    report.outcome = "unknown";
                    report.durability = "unknown";
                }
                *mutating_git += 1;
                match sync::create_missing(&git_path, entry, format, &mut plan.budget) {
                    Ok(_) => {
                        created.push(entry.reference.clone());
                        report.created_refs = created.clone();
                    }
                    Err(reason) => {
                        return fail_after(report, created, verified, true, reason);
                    }
                }
                #[cfg(test)]
                if fault == Fault::AfterFirstCas {
                    fault_hit(Fault::AfterFirstCas);
                    return fail_after(report, created, verified, true, "cas_partial");
                }
            }
        }
    }
    let fail = |report: &mut RecoveryReport, reason: &'static str| {
        fail_after(report, created.clone(), verified.clone(), launched, reason)
    };
    #[cfg(test)]
    if fault == Fault::RefSync {
        fault_hit(Fault::RefSync);
        return fail(report, "ref_sync_failed");
    }
    #[cfg(test)]
    AFTER_CAS.with(|hook| {
        if let Some(call) = hook.borrow_mut().take() {
            call();
        }
    });
    let (mut later, after_checkout, after_inputs) =
        match preservation::RecoveryCensus::recapture(&plan.retained.context, &mut plan.budget) {
            Ok(value) => value,
            Err(reason) => return fail(report, reason),
        };
    let packed = later.packed_recovery();
    let mut targets = created.clone();
    targets.extend(verified.iter().cloned());
    if let Err(reason) = sync::sync_refs(later.common(), &targets, packed, &mut plan.budget) {
        return fail(report, reason);
    }
    for entry in &plan.plan {
        if let Err(reason) =
            sync::recovery_log_absent(later.common_mut(), &entry.reference, &mut plan.budget)
        {
            return fail(report, reason);
        }
    }
    let planned_names = sync::planned_names(&plan.plan);
    let planned_new = plan.census.planned_new(&planned_names);
    if let Err(reason) = later.expected_delta(
        &plan.census,
        &plan.retained.physical.first,
        &plan.retained.physical.before,
        &after_checkout,
        &after_inputs,
        &planned_new,
    ) {
        return fail(report, reason);
    }
    let named: Vec<_> = plan
        .plan
        .iter()
        .map(|e| (e.reference.clone(), e.oid.clone()))
        .collect();
    if let Err(reason) = later.verify_closure(&plan.census, &named) {
        return fail(report, reason);
    }
    if let Err(reason) = plan.lock.revalidate(store, &plan.key, &common_path) {
        return fail(report, reason);
    }
    if let Err(reason) = short_context_matches(store, &plan.retained.context, &mut plan.budget) {
        return fail(report, reason);
    }
    let intent_checksum = match &intent_bytes {
        Some(bytes) => match storage::intent_checksum(bytes) {
            Ok(value) => value,
            Err(reason) => return fail(report, reason),
        },
        None => return fail(report, "intent_missing"),
    };
    let result = storage::ResultRecord {
        operation: plan.operation,
        intent_checksum,
        result_id: plan.result_id,
        checkout: plan.checkout,
        target_count: plan.plan.len() as u64,
        targets: named,
        closure_digest: later.closure_digest(
            &after_checkout,
            &after_inputs,
            Some(&plan.retained.config),
        ),
        sync_ack: true,
        retirement_authority: false,
    };
    let result_bytes = match storage::encode_result(&result) {
        Ok(bytes) => bytes,
        Err(reason) => return fail(report, reason),
    };
    #[cfg(test)]
    if fault == Fault::ResultWrite {
        fault_hit(Fault::ResultWrite);
        return fail(report, "result_io");
    }
    let bound = match bound {
        Some(value) => value,
        None => return fail(report, "result_binding_changed"),
    };
    match receipts::restart_recovery_result(store, &bound, &result_bytes) {
        Ok(()) => (),
        Err(error) => {
            let reason = if matches!(error, ReceiptError::UnsafeReceiptStore) {
                "nonpersistent_filesystem"
            } else {
                receipt_reason(error)
            };
            return fail(report, reason);
        }
    }
    if let Err(error) = receipts::publish_recovery_reserved(
        store,
        plan.result_id,
        result_bytes.len() as u64,
        &plan.retained.context,
        &mut plan.budget,
    ) {
        let reason = if matches!(error, ReceiptError::UnsafeReceiptStore) {
            "nonpersistent_filesystem"
        } else {
            receipt_reason(error)
        };
        return fail(report, reason);
    }
    drop(fail);
    report.outcome = "prepared";
    report.reason = "local_protection";
    report.durability = "acknowledged";
    report.recorded = true;
    report.created_refs = created;
    report.verified_refs = verified;
    report.coverage = "complete";
    Ok(())
}

fn short_context_matches(store: &mut Store, expected: &Context, b: &mut Budget) -> Held<()> {
    store.may_acquire_lease().map_err(|_| "authority_unknown")?;
    let lease = store.authority_lease().map_err(|_| "authority_busy")?;
    let authority = std::sync::Arc::clone(store.authority_identity());
    {
        let phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|_| "context_unknown")?;
        let current = snapshot_in_transaction(&tx, &authority, expected.allocation.checkout, b)
            .map_err(|_| "context_unknown")?;
        if current.canonical != expected.canonical {
            return Err("context_changed");
        }
        tx.rollback().map_err(|_| "context_unknown")?;
        drop(phase);
    }
    drop(lease);
    Ok(())
}

fn receipt_reason(error: ReceiptError) -> &'static str {
    match error {
        ReceiptError::Conflict => "receipt_conflict",
        ReceiptError::CapacityFull => "capacity_full",
        ReceiptError::UnsafeReceiptStore => "unsafe_receipt_store",
        ReceiptError::Busy => "authority_busy",
        ReceiptError::EncodingLimit => "encoding_limit",
        ReceiptError::Io => "receipt_io",
        ReceiptError::Missing => "receipt_missing",
        ReceiptError::Corrupt => "receipt_corrupt",
        ReceiptError::DurabilityUnknown { .. } => "durability_unknown",
    }
}

fn hash32(digest: &sha2::digest::Output<Sha256>) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest);
    out
}

const LOCK_DIR: &str = "recovery-preparation-locks-v1";
const LOCK_RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

fn lock_identity(file: &File) -> Held<(u64, u64)> {
    let meta = file.metadata().map_err(|_| "lock_unknown")?;
    Ok((meta.dev(), meta.ino()))
}

fn open_lock_authority(store: &Store) -> Held<File> {
    let identity = store.authority_identity();
    let directory = rfs::openat2(
        rfs::CWD,
        identity.directory.as_path(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(|_| "lock_unknown")?;
    let meta = directory.metadata().map_err(|_| "lock_unknown")?;
    if !meta.is_dir()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o777 != 0o700
        || (meta.dev(), meta.ino()) != identity.directory_id
    {
        return Err("lock_unknown");
    }
    Ok(directory)
}

fn open_lock_child(parent: &File, name: &str, flags: OFlags) -> Held<File> {
    let additional = if flags.contains(OFlags::PATH) {
        OFlags::empty()
    } else {
        OFlags::NONBLOCK
    };
    rfs::openat2(
        parent,
        name,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW | additional,
        Mode::empty(),
        LOCK_RESOLVE,
    )
    .map(File::from)
    .map_err(|_| "lock_unknown")
}

fn acquire_lock(store: &Store, key: &CommonKey) -> Held<OperationLock> {
    let authority = open_lock_authority(store)?;
    let authority_id = lock_identity(&authority)?;
    match rfs::mkdirat(&authority, LOCK_DIR, Mode::from_raw_mode(0o700)) {
        Ok(()) => (),
        Err(error) if error == rustix::io::Errno::EXIST => (),
        Err(_) => return Err("lock_unknown"),
    }
    let directory = open_lock_child(&authority, LOCK_DIR, OFlags::RDONLY | OFlags::DIRECTORY)?;
    let dir_meta = directory.metadata().map_err(|_| "lock_unknown")?;
    if !dir_meta.is_dir()
        || dir_meta.uid() != rustix::process::geteuid().as_raw()
        || dir_meta.mode() & 0o777 != 0o700
    {
        return Err("lock_unknown");
    }
    let named_dir = open_lock_child(&authority, LOCK_DIR, OFlags::PATH | OFlags::DIRECTORY)?;
    if lock_identity(&named_dir)? != lock_identity(&directory)? {
        return Err("lock_unknown");
    }
    let name = format!("{:016x}-{:016x}.lock", key.dev, key.ino);
    let file = rfs::openat2(
        &directory,
        name.as_str(),
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::from_raw_mode(0o600),
        LOCK_RESOLVE,
    )
    .map(File::from)
    .map_err(|_| "lock_unknown")?;
    let meta = file.metadata().map_err(|_| "lock_unknown")?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o777 != 0o600
    {
        return Err("lock_unknown");
    }
    let named_file = open_lock_child(&directory, &name, OFlags::PATH)?;
    if lock_identity(&named_file)? != lock_identity(&file)? {
        return Err("lock_unknown");
    }
    match rfs::flock(&file, rfs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(OperationLock {
            authority,
            directory,
            file,
            authority_id,
            directory_id: lock_identity(&named_dir)?,
            file_id: lock_identity(&named_file)?,
            name,
        }),
        Err(e) if e == rustix::io::Errno::WOULDBLOCK => Err("preparation_busy"),
        Err(_) => Err("lock_unknown"),
    }
}

#[cfg(test)]
use crate as work_cli_api;
#[cfg(test)]
#[path = "../../tests/support/inspection_fixture.rs"]
mod fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::MetadataExt};

    fn setup(format: &str) -> (fixture::ManagedFixture, std::path::PathBuf) {
        let f = fixture::ManagedFixture::recovery(format, "2");
        let remote = f.temp.path().join("backup.git");
        fixture::git(
            f.temp.path(),
            &[
                "init".as_ref(),
                "--bare".as_ref(),
                "--template=".as_ref(),
                remote.as_os_str(),
            ],
        );
        let url = format!("file://{}", remote.display());
        f.git(&[
            "remote".as_ref(),
            "add".as_ref(),
            "backup".as_ref(),
            url.as_ref(),
        ]);
        f.git(&[
            "-c".as_ref(),
            "protocol.file.allow=always".as_ref(),
            "push".as_ref(),
            "backup".as_ref(),
            "HEAD:refs/heads/preserved".as_ref(),
        ]);
        let path = f.temp.path().join("config.toml");
        fs::write(&path, format!("store_dir={:?}\ntrusted_registry={:?}\nroots=[{:?}]\n[remote_preservation]\nformat=1\nversion='fixture-v1'\n[[remote_preservation.targets]]\ncommon_dir={:?}\nremote='backup'\nurl={url:?}\nbranch='refs/heads/preserved'\n[capture]\nexecutable=false\n", f.temp.path().join("authority"), f.temp.path().join("registry"), f.root, f.common())).unwrap();
        (f, path)
    }

    #[test]
    fn intent_fault_makes_zero_mutating_git_calls() {
        for fault in [Fault::IntentWrite, Fault::IntentSync] {
            let (f, config) = setup("sha1");
            let before = f.common().join("refs/work-recovery").exists();
            let report = prepare_path(&config, f.allocation.checkout, Uuid::now_v7(), fault);
            assert_eq!(take_fault_hit(), fault, "{report:?}");
            assert_eq!(report.reason, "intent_io", "{report:?}");
            assert_ne!(report.outcome, "prepared", "{report:?}");
            assert_eq!(report.durability, "not_attempted");
            assert_eq!(f.common().join("refs/work-recovery").exists(), before);
            assert_eq!(report.created_refs.len(), 0);
        }
    }

    #[test]
    fn bounded_faults_never_report_prepared() {
        for (fault, reason, launched) in [
            (Fault::AfterFirstCas, "cas_partial", true),
            (Fault::ObjectSync, "object_sync_failed", false),
            (Fault::RefSync, "ref_sync_failed", true),
            (Fault::ResultWrite, "result_io", true),
        ] {
            let (f, config) = setup("sha1");
            let report = prepare_path(&config, f.allocation.checkout, Uuid::now_v7(), fault);
            assert_eq!(take_fault_hit(), fault, "{fault:?} {report:?}");
            assert_eq!(report.reason, reason, "{fault:?} {report:?}");
            assert_ne!(report.outcome, "prepared", "{fault:?} {report:?}");
            if launched {
                assert_eq!(report.durability, "unknown", "{fault:?} {report:?}");
                assert_eq!(report.outcome, "unknown", "{fault:?} {report:?}");
            } else {
                assert_eq!(report.durability, "not_attempted", "{fault:?} {report:?}");
                assert!(report.created_refs.is_empty(), "{fault:?} {report:?}");
            }
        }
    }
    #[test]
    fn before_cas_fault_does_not_create_refs() {
        let (f, config) = setup("sha1");
        let report = prepare_path(
            &config,
            f.allocation.checkout,
            Uuid::now_v7(),
            Fault::BeforeCas,
        );
        assert_eq!(take_fault_hit(), Fault::BeforeCas, "{report:?}");
        assert_eq!(report.reason, "cas_not_started");
        assert_eq!(report.durability, "not_attempted");
        assert_ne!(report.outcome, "prepared");
        assert!(!f.common().join("refs/work-recovery").exists() || report.created_refs.is_empty());
    }

    #[test]
    fn mismatched_pending_result_is_not_truncated() {
        let f = fixture::ManagedFixture::recovery("sha1", "2");
        let dir = f.temp.path().join("authority/inspection-receipts-v1");
        fs::create_dir_all(&dir).unwrap();
        let id = Uuid::now_v7();
        let pending = dir.join(format!("pending-{id}-32"));
        fs::write(&pending, b"partial-not-matching-bytes").unwrap();
        let before = fs::read(&pending).unwrap();
        let meta = fs::metadata(&pending).unwrap();
        let bound = receipts::RecoveryResultBinding {
            id,
            length: 32,
            dev: meta.dev(),
            ino: meta.ino(),
        };
        assert!(receipts::restart_recovery_result(&f.store, &bound, &[0u8; 32]).is_err());
        assert_eq!(fs::read(&pending).unwrap(), before);
        let replaced = dir.join(format!("pending-{id}-32"));
        fs::remove_file(&replaced).unwrap();
        fs::write(&replaced, b"").unwrap();
        let other = fs::read(&replaced).unwrap();
        let replaced_meta = fs::metadata(&replaced).unwrap();
        assert!(replaced_meta.ino() != bound.ino || other != before);
        assert!(receipts::restart_recovery_result(&f.store, &bound, &[0u8; 32]).is_err());
        assert_eq!(fs::read(&replaced).unwrap(), other);
    }

    #[test]
    fn codec_capacity_rejects_oversize_intent() {
        let mut intent = storage::Intent {
            operation: Uuid::now_v7(),
            result_id: Uuid::now_v7(),
            checkout: Uuid::now_v7(),
            authority: vec![],
            common_path: vec![],
            common_dev: 0,
            common_ino: 0,
            private_path: vec![],
            boot: vec![],
            context_digest: [0; 32],
            policy_digest: [0; 32],
            source_commitment: [0; 32],
            source_witness: vec![],
            object_format: "sha1".into(),
            plan: vec![],
            create_only: true,
            result_length: 32,
            result_dev: 1,
            result_ino: 1,
        };
        intent.authority = vec![0; 3 * 1024 * 1024];
        assert!(storage::encode_intent(&intent).is_err());
    }

    #[test]
    fn refused_entry_is_not_prepared() {
        let report = prepare_recovery_refused(Uuid::now_v7());
        assert_eq!(report.outcome, "held");
        assert_eq!(report.retirement_authority, false);
        assert!(report.limitation.contains("audit-preservation"));
    }

    #[test]
    fn resume_holds_ordinary_reflog_and_payload_mutations() {
        let (f, config) = setup("sha1");
        let operation = Uuid::now_v7();
        let first = prepare_path(&config, f.allocation.checkout, operation, Fault::BeforeCas);
        assert_eq!(take_fault_hit(), Fault::BeforeCas, "{first:?}");
        assert_eq!(first.reason, "cas_not_started");
        assert_eq!(first.durability, "not_attempted");
        let log = f.private().join("logs/HEAD");
        let mut bytes = fs::read(&log).unwrap();
        bytes.extend(b"message-only change\n");
        fs::write(&log, bytes).unwrap();
        let resume = prepare_path(&config, f.allocation.checkout, operation, Fault::None);
        assert_ne!(resume.outcome, "prepared", "{resume:?}");
        assert_ne!(resume.durability, "acknowledged");
    }
}
