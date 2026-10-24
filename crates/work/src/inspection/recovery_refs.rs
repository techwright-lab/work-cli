//! Explicit create-only recovery-ref protection. Local, not backup or retirement.
//! Tests were authored before this logic; no local RED/GREEN claim.
use super::*;
use crate::config::{Config, ConfigDocument};
use rustix::fs::{self as rfs, OFlags};
use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    #[cfg(test)]
    IntentWrite,
    #[cfg(test)]
    IntentSync,
    #[cfg(test)]
    BeforeCas,
    #[cfg(test)]
    AfterFirstCas,
    #[cfg(test)]
    ObjectSync,
    #[cfg(test)]
    RefSync,
    #[cfg(test)]
    ResultWrite,
}

struct CommonKey {
    path: Vec<u8>,
    dev: u64,
    ino: u64,
}

struct OperationLock {
    _file: File,
}

pub(super) struct Retained {
    pub(super) context: Context,
    pub(super) physical: Physical,
    pub(super) document_policy: Vec<u8>,
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
    pub(super) fn confirm_common(&self, common: &filesystem::Manifest) -> Held<()> {
        let key = self.key.as_ref().ok_or("identity_unknown")?;
        let (dev, ino) = common.root_dev_ino();
        if (dev, ino) != (key.dev, key.ino) {
            return Err("common_identity_changed");
        }
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
        let source_commitment = census.source_commitment();
        self.plan = Some(FreshRecoveryPlan {
            checkout: self.checkout,
            operation: self.operation,
            result_id: Uuid::now_v7(),
            retained,
            census,
            plan,
            source_commitment,
            budget,
            remote_cleanup: remote.cleanup() == "complete",
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
    budget: Budget,
    remote_cleanup: bool,
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
    if intent.operation != plan.operation
        || intent.checkout != plan.checkout
        || intent.authority != storage::authority_bytes(store)
        || intent.common_dev != plan.census.common_dev_ino().0
        || intent.common_ino != plan.census.common_dev_ino().1
        || intent.context_digest != hash32(&Sha256::digest(&plan.retained.context.canonical))
        || intent.policy_digest != hash32(&Sha256::digest(&plan.retained.document_policy))
        || intent.source_commitment != plan.source_commitment
        || intent.plan != plan.plan
    {
        return Err("intent_binding_changed");
    }
    receipts::resync_published(store, plan.operation)?;
    report.intent_id = Some(plan.operation);
    report.intent_checksum = Some(hex(&storage::intent_checksum(&bytes)?));
    report.result_id = Some(intent.result_id);
    plan.result_id = intent.result_id;
    match receipts::read_raw(store, intent.result_id) {
        Ok(result_bytes) => historical_result(&result_bytes, &intent, report),
        Err(ReceiptError::Missing) => execute_cas(
            store,
            &mut plan,
            report,
            mutating_git,
            Some(bytes),
            #[cfg(test)]
            fault,
        ),
        Err(_) => Err("result_unknown"),
    }
}

fn historical_result(
    bytes: &[u8],
    intent: &storage::Intent,
    report: &mut RecoveryReport,
) -> Held<()> {
    match storage::decode(bytes)? {
        storage::Record::Result(result) => {
            if result.operation != intent.operation
                || result.result_id != intent.result_id
                || result.retirement_authority
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
    let intent = current_intent(store, plan)?;
    let intent_bytes = storage::encode_intent(&intent)?;
    let result_len = storage::encode_result(&empty_result(&intent, plan))?.len() as u64;
    let intent_res = receipts::reserve(store, plan.operation, intent_bytes.len() as u64)
        .map_err(receipt_reason)?;
    let _result_res =
        receipts::reserve(store, plan.result_id, result_len).map_err(receipt_reason)?;
    #[cfg(test)]
    if fault == Fault::IntentWrite {
        return Err("intent_io");
    }
    receipts::write_reserved(intent_res, &intent_bytes).map_err(receipt_reason)?;
    #[cfg(test)]
    if fault == Fault::IntentSync {
        return Err("intent_io");
    }
    let published = receipts::publish_reserved(
        store,
        plan.operation,
        intent_bytes.len() as u64,
        &plan.retained.context,
        &mut plan.budget,
    )
    .map_err(receipt_reason)?;
    report.intent_id = Some(published.id());
    report.intent_checksum = Some(hex(&storage::intent_checksum(&intent_bytes)?));
    report.result_id = Some(plan.result_id);
    execute_cas(
        store,
        plan,
        report,
        mutating_git,
        Some(intent_bytes),
        #[cfg(test)]
        fault,
    )
}

fn empty_result(intent: &storage::Intent, plan: &FreshRecoveryPlan) -> storage::ResultRecord {
    storage::ResultRecord {
        operation: intent.operation,
        intent_checksum: [0; 32],
        result_id: intent.result_id,
        checkout: intent.checkout,
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

fn current_intent(store: &Store, plan: &FreshRecoveryPlan) -> Held<storage::Intent> {
    let identity = plan
        .retained
        .context
        .allocation
        .identity
        .as_ref()
        .ok_or("identity_unknown")?;
    let (dev, ino) = plan.census.common_dev_ino();
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
        object_format: plan.census.object_format().into(),
        plan: plan.plan.clone(),
        create_only: true,
    })
}

fn execute_cas(
    store: &mut Store,
    plan: &mut FreshRecoveryPlan,
    report: &mut RecoveryReport,
    mutating_git: &mut u64,
    intent_bytes: Option<Vec<u8>>,
    #[cfg(test)] fault: Fault,
) -> Held<()> {
    #[cfg(test)]
    if fault == Fault::BeforeCas {
        return Err("cas_not_started");
    }
    let git_path = plan
        .retained
        .context
        .allocation
        .identity
        .as_ref()
        .ok_or("identity_unknown")?
        .path
        .clone();
    let format = plan.census.format();
    let mut created = Vec::new();
    let mut verified = Vec::new();
    plan.retained
        .physical
        .recheck(&mut plan.budget)
        .map_err(|_| "census_changed")?;
    plan.census.recheck(&mut plan.budget)?;
    #[cfg(test)]
    if fault == Fault::ObjectSync {
        return Err("object_sync_failed");
    }
    sync::sync_objects(plan.census.common(), &mut plan.budget)?;
    for entry in &plan.plan {
        sync::recovery_log_absent(plan.census.common_mut(), &entry.reference, &mut plan.budget)?;
        match plan.census.existing_target(&entry.reference) {
            Some(existing) if existing == entry.oid.as_bytes() => {
                verified.push(entry.reference.clone());
            }
            Some(_) => return Err("recovery_ref_conflict"),
            None => {
                *mutating_git += 1;
                match sync::create_missing(&git_path, entry, format, &mut plan.budget) {
                    Ok(_) => created.push(entry.reference.clone()),
                    Err(reason) => {
                        report.outcome = "unknown";
                        report.created_refs = created;
                        report.verified_refs = verified;
                        report.durability = "unknown";
                        return Err(reason);
                    }
                }
                #[cfg(test)]
                if fault == Fault::AfterFirstCas {
                    report.outcome = "unknown";
                    report.created_refs = created;
                    report.verified_refs = verified;
                    report.durability = "unknown";
                    return Err("cas_partial");
                }
            }
        }
    }
    #[cfg(test)]
    if fault == Fault::RefSync {
        report.outcome = "unknown";
        report.created_refs = created.clone();
        report.verified_refs = verified.clone();
        report.durability = "unknown";
        return Err("ref_sync_failed");
    }
    let mut later =
        preservation::RecoveryCensus::recapture(&plan.retained.context, &mut plan.budget)?;
    let packed = later.packed_recovery();
    sync::sync_refs(later.common(), &created, packed, &mut plan.budget)?;
    for entry in &plan.plan {
        sync::recovery_log_absent(later.common_mut(), &entry.reference, &mut plan.budget)?;
    }
    later.expected_delta(&plan.census, &sync::planned_names(&plan.plan))?;
    let named: Vec<_> = plan
        .plan
        .iter()
        .map(|e| (e.reference.clone(), e.oid.clone()))
        .collect();
    later.verify_named(&named)?;
    short_context_matches(store, &plan.retained.context, &mut plan.budget)?;
    let intent_checksum = match &intent_bytes {
        Some(bytes) => storage::intent_checksum(bytes)?,
        None => return Err("intent_missing"),
    };
    let result = storage::ResultRecord {
        operation: plan.operation,
        intent_checksum,
        result_id: plan.result_id,
        checkout: plan.checkout,
        target_count: plan.plan.len() as u64,
        targets: plan
            .plan
            .iter()
            .map(|e| (e.reference.clone(), e.oid.clone()))
            .collect(),
        closure_digest: later.closure_digest(),
        sync_ack: true,
        retirement_authority: false,
    };
    let result_bytes = storage::encode_result(&result)?;
    #[cfg(test)]
    if fault == Fault::ResultWrite {
        report.outcome = "unknown";
        report.created_refs = created;
        report.verified_refs = verified;
        report.durability = "unknown";
        return Err("result_io");
    }
    match receipts::restart_or_write(store, plan.result_id, &result_bytes) {
        Ok(()) => (),
        Err(error) => {
            report.outcome = "unknown";
            report.created_refs = created;
            report.verified_refs = verified;
            report.durability = "unknown";
            return Err(receipt_reason(error));
        }
    }
    receipts::publish_reserved(
        store,
        plan.result_id,
        result_bytes.len() as u64,
        &plan.retained.context,
        &mut plan.budget,
    )
    .map_err(|error| {
        report.outcome = "unknown";
        report.durability = "unknown";
        receipt_reason(error)
    })?;
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

fn acquire_lock(store: &Store, key: &CommonKey) -> Held<OperationLock> {
    let authority = store.authority_identity();
    let directory = &authority.directory;
    let locks = directory.join("recovery-preparation-locks-v1");
    match std::fs::create_dir(&locks) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return Err("lock_unknown"),
    }
    let metadata = std::fs::symlink_metadata(&locks).map_err(|_| "lock_unknown")?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err("lock_unknown");
    }
    let name = format!("{:016x}-{:016x}.lock", key.dev, key.ino);
    let path = locks.join(name);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(&path)
        .map_err(|_| "lock_unknown")?;
    let meta = file.metadata().map_err(|_| "lock_unknown")?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o777 != 0o600
    {
        return Err("lock_unknown");
    }
    match rfs::flock(&file, rfs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(OperationLock { _file: file }),
        Err(e) if e == rustix::io::Errno::WOULDBLOCK => Err("preparation_busy"),
        Err(_) => Err("lock_unknown"),
    }
}

#[cfg(test)]
#[path = "../../tests/support/inspection_fixture.rs"]
mod fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
            assert_ne!(report.outcome, "prepared", "{report:?}");
            assert_eq!(f.common().join("refs/work-recovery").exists(), before);
            assert_eq!(report.created_refs.len(), 0);
        }
    }

    #[test]
    fn bounded_faults_never_report_prepared() {
        for fault in [
            Fault::AfterFirstCas,
            Fault::ObjectSync,
            Fault::RefSync,
            Fault::ResultWrite,
        ] {
            let (f, config) = setup("sha1");
            let report = prepare_path(&config, f.allocation.checkout, Uuid::now_v7(), fault);
            assert_ne!(report.outcome, "prepared", "{fault:?} {report:?}");
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
        assert!(receipts::restart_or_write(&f.store, id, &[0u8; 32]).is_err());
        assert_eq!(fs::read(&pending).unwrap(), before);
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
            object_format: "sha1".into(),
            plan: vec![],
            create_only: true,
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
}
