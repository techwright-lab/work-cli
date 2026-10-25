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

pub(super) struct RecoveryIntentPublication<'g> {
    guard: &'g crate::checkout_guard::CheckoutGuard,
    checkout: Uuid,
    id: Uuid,
    length: u64,
    bytes: Vec<u8>,
}
impl RecoveryIntentPublication<'_> {
    pub(super) fn guard(&self) -> &crate::checkout_guard::CheckoutGuard {
        self.guard
    }
    pub(super) fn checkout(&self) -> Uuid {
        self.checkout
    }
    pub(super) fn id(&self) -> Uuid {
        self.id
    }
    pub(super) fn length(&self) -> u64 {
        self.length
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub(super) struct RecoveryResultPublication<'g> {
    guard: &'g crate::checkout_guard::CheckoutGuard,
    checkout: Uuid,
    id: Uuid,
    length: u64,
    bytes: Vec<u8>,
    binding: receipts::RecoveryResultBinding,
}
impl RecoveryResultPublication<'_> {
    pub(super) fn guard(&self) -> &crate::checkout_guard::CheckoutGuard {
        self.guard
    }
    pub(super) fn checkout(&self) -> Uuid {
        self.checkout
    }
    pub(super) fn id(&self) -> Uuid {
        self.id
    }
    pub(super) fn length(&self) -> u64 {
        self.length
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn binding(&self) -> receipts::RecoveryResultBinding {
        self.binding
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
    IntentDurability,
    BeforeCas,
    AfterFirstCas,
    ObjectSync,
    RefSync,
    AttachmentSync,
    ResultWrite,
    ResultFsync,
    PublishReopen,
    PublishDeadline,
}

#[cfg(test)]
thread_local! {
    static FAULT_HIT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
    static ACTIVE_FAULT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
    static AFTER_CAS: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static AFTER_CLOSING_CAPTURE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static WITNESS_DELTA: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn fault_hit(fault: Fault) {
    FAULT_HIT.with(|hit| hit.set(fault));
}

#[cfg(test)]
fn take_fault_hit() -> Fault {
    FAULT_HIT.with(|hit| hit.replace(Fault::None))
}

#[cfg(test)]
fn set_active_fault(fault: Fault) {
    ACTIVE_FAULT.with(|active| active.set(fault));
}

#[cfg(test)]
pub(super) fn active_fault_is_result_fsync() -> bool {
    ACTIVE_FAULT.with(|active| active.get() == Fault::ResultFsync)
}

#[cfg(test)]
pub(super) fn active_fault_is_intent_durability() -> bool {
    ACTIVE_FAULT.with(|active| active.get() == Fault::IntentDurability)
}

#[cfg(test)]
pub(super) fn active_fault_is_publish_reopen() -> bool {
    ACTIVE_FAULT.with(|active| active.get() == Fault::PublishReopen)
}

#[cfg(test)]
pub(super) fn active_fault_is_publish_deadline() -> bool {
    ACTIVE_FAULT.with(|active| active.get() == Fault::PublishDeadline)
}

#[cfg(test)]
pub(super) fn note_active_fault() {
    ACTIVE_FAULT.with(|active| fault_hit(active.get()));
}

#[cfg(test)]
fn take_witness_delta() -> bool {
    WITNESS_DELTA.with(|hit| hit.replace(false))
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
        lock_directory_meta(&self.authority)?;
        lock_directory_meta(&authority)?;
        if lock_identity(&self.authority)? != self.authority_id
            || lock_identity(&authority)? != self.authority_id
            || identity.directory_id != self.authority_id
        {
            return Err("lock_unknown");
        }
        let named_dir = open_lock_child(&authority, LOCK_DIR, OFlags::RDONLY | OFlags::DIRECTORY)?;
        lock_directory_meta(&self.directory)?;
        lock_directory_meta(&named_dir)?;
        let named_file = open_lock_child(&named_dir, &self.name, OFlags::RDONLY)?;
        lock_file_meta(&self.file)?;
        lock_file_meta(&named_file)?;
        if lock_identity(&named_dir)? != self.directory_id
            || lock_identity(&self.directory)? != self.directory_id
            || lock_identity(&named_file)? != self.file_id
            || lock_identity(&self.file)? != self.file_id
        {
            return Err("lock_unknown");
        }
        Ok(())
    }
}

/// Allocation's narrow common-operation owner. The opened Manifest is retained
/// across Git writes; only binding identity (not mutable directory timestamps)
/// is compared when reopening the common root after those writes.
pub(crate) struct AllocationCommonLock {
    lock: OperationLock,
    key: CommonKey,
    manifest: filesystem::Manifest,
    authority: std::sync::Arc<crate::store::AuthorityIdentity>,
    budget: Budget,
}
impl AllocationCommonLock {
    pub(crate) fn acquire(store: &Store, path: &std::path::Path) -> std::io::Result<Self> {
        crate::allocate::db(store.may_acquire_lease())?;
        let mut budget = Budget::new();
        native_anchor_path(path)
            .map_err(|_| crate::allocate::err("unsafe allocation common path"))?;
        let manifest = filesystem::Manifest::new(path, &mut budget)
            .map_err(|_| crate::allocate::err("allocation common identity unavailable"))?;
        // Allocation needs cooperative identity exclusion, not a recovery-storage
        // durability acknowledgment. Keep the original supported filesystems.
        let (dev, ino) = manifest.root_dev_ino();
        let key = CommonKey {
            path: path.as_os_str().as_bytes().to_vec(),
            dev,
            ino,
        };
        let lock = acquire_lock(store, &key).map_err(|reason| {
            if reason == "preparation_busy" {
                std::io::Error::from(std::io::ErrorKind::WouldBlock)
            } else {
                crate::allocate::err(reason)
            }
        })?;
        Ok(Self {
            lock,
            key,
            manifest,
            authority: store.authority_identity().clone(),
            budget,
        })
    }
    pub(crate) fn revalidate(&mut self, store: &Store) -> std::io::Result<()> {
        crate::allocate::db(store.may_acquire_lease())?;
        if self.authority.as_ref() != store.authority_identity().as_ref() {
            return Err(crate::allocate::err("allocation common authority changed"));
        }
        self.check_budget()?;
        let path = std::path::Path::new(std::ffi::OsStr::from_bytes(&self.key.path));
        let current = filesystem::Manifest::new(path, &mut self.budget)
            .map_err(|_| crate::allocate::err("allocation common identity changed"))?;
        if current.root_dev_ino() != (self.key.dev, self.key.ino)
            || self.manifest.root_dev_ino() != (self.key.dev, self.key.ino)
        {
            return Err(crate::allocate::err("allocation common identity changed"));
        }
        self.lock
            .revalidate(store, &self.key, &self.key.path)
            .map_err(crate::allocate::err)
    }
    /// Clock/counters only, safe at the SQL commit boundary. Never restart Budget.
    pub(crate) fn check_budget(&mut self) -> std::io::Result<()> {
        self.budget
            .check()
            .map_err(|_| crate::allocate::err("allocation observation budget expired"))
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
    guard: Option<crate::checkout_guard::CheckoutGuard>,
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
            guard: None,
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
        let guard = crate::checkout_guard::CheckoutGuard::shared_known(config, self.checkout)
            .map_err(|_| "checkout_guard_unavailable")?;
        let mut store = open_configured_store(config).map_err(|_| "authority_unknown")?;
        receipts::guarded_checkpoint(
            &mut store,
            &guard,
            self.checkout,
            crate::retirement_journal::Attempt::RecoveryRefs,
        )
        .map_err(receipt_reason)?;
        self.guard = Some(guard);
        self.store = Some(store);
        Ok(())
    }
    pub(super) fn context(&mut self, b: &mut Budget) -> Held<Context> {
        let store = self.store.as_mut().ok_or("authority_unknown")?;
        self.guard
            .as_ref()
            .ok_or("checkout_guard_unavailable")?
            .require_matching(store, self.checkout)
            .map_err(|_| "checkout_guard_unavailable")?;
        store.may_acquire_lease().map_err(|_| "authority_unknown")?;
        let authority = std::sync::Arc::clone(store.authority_identity());
        let schema = store.schema_participation();
        let phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|_| "authority_unknown")?;
        let context = snapshot_in_transaction(&tx, &authority, &schema, self.checkout, b)
            .map_err(|_| "context_unknown")?;
        tx.rollback().map_err(|_| "context_unknown")?;
        drop(phase);
        Ok(context)
    }
    pub(super) fn lock_common(&mut self, context: &Context, b: &mut Budget) -> Held<()> {
        self.guard
            .as_ref()
            .ok_or("checkout_guard_unavailable")?
            .require_matching(
                self.store.as_ref().ok_or("authority_unknown")?,
                context.allocation.checkout,
            )
            .map_err(|_| "checkout_guard_unavailable")?;
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
            guard: self.guard.take().ok_or("checkout_guard_unavailable")?,
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
    guard: crate::checkout_guard::CheckoutGuard,
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
    #[cfg(test)]
    set_active_fault(fault);
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
    // Keep the owned plan (and SH/common guards) through the final report, not
    // merely until the receipt helper returns.
    let mut plan = collector.plan.take();
    if let (Some(mut store), Some(plan)) = (collector.store.take(), plan.as_mut()) {
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
    plan: &mut FreshRecoveryPlan,
    report: &mut RecoveryReport,
    mut mutating_git: u64,
    #[cfg(test)] fault: Fault,
) -> Held<()> {
    if !plan.remote_cleanup {
        return Err("incomplete_observation");
    }
    short_context_matches(store, &plan.guard, &plan.retained.context, &mut plan.budget)?;
    sync::persistent_manifest(plan.census.common())?;
    match receipts::read_raw(store, plan.operation, &mut plan.budget) {
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
            plan,
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
    plan: &mut FreshRecoveryPlan,
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
    intent_redundant_bindings(&intent, plan)?;
    let planned_names = sync::planned_names(&plan.plan);
    let planned_new =
        preservation::planned_new_from_witness(&intent.source_witness, &planned_names)?;
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
    #[cfg(test)]
    WITNESS_DELTA.with(|hit| hit.set(true));
    preservation::source_witness_delta(&intent.source_witness, &current_witness, &planned_new)?;
    short_context_matches(store, &plan.guard, &plan.retained.context, &mut plan.budget)?;
    receipts::resync_recovery_published(
        store,
        &plan.guard,
        plan.checkout,
        plan.operation,
        &mut plan.budget,
    )
    .map_err(|error| {
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
    match receipts::read_raw(store, intent.result_id, &mut plan.budget) {
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
                plan,
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
    short_context_matches(store, &plan.guard, &plan.retained.context, &mut plan.budget)?;
    receipts::recovery_storage_persistent(store, &plan.guard, plan.checkout).map_err(|error| {
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
    let result_res = receipts::reserve_recovery(
        store,
        &plan.guard,
        plan.checkout,
        plan.result_id,
        result_len,
        &mut plan.budget,
    )
    .map_err(receipt_reason)?;
    let bound = receipts::reservation_binding(&result_res).map_err(receipt_reason)?;
    drop(result_res);
    let intent = current_intent(store, plan, &bound)?;
    let intent_bytes = storage::encode_intent(&intent)?;
    let intent_res = receipts::reserve_recovery(
        store,
        &plan.guard,
        plan.checkout,
        plan.operation,
        intent_bytes.len() as u64,
        &mut plan.budget,
    )
    .map_err(receipt_reason)?;
    let publication =
        mint_intent_publication(plan, &plan.guard, intent_bytes, &bound, plan.operation)?;
    #[cfg(test)]
    if fault == Fault::IntentWrite {
        fault_hit(Fault::IntentWrite);
        return Err("intent_io");
    }
    #[cfg(test)]
    if fault == Fault::IntentSync {
        fault_hit(Fault::IntentSync);
        return Err("intent_io");
    }
    let published = match receipts::publish_recovery_intent(
        store,
        &publication,
        intent_res,
        &plan.retained.context,
        &mut plan.budget,
    ) {
        Ok(published) => published,
        Err(error) => {
            if matches!(error, ReceiptError::DurabilityUnknown { .. }) {
                report.durability = "unknown";
            }
            return Err(if matches!(error, ReceiptError::UnsafeReceiptStore) {
                "nonpersistent_filesystem"
            } else {
                receipt_reason(error)
            });
        }
    };
    report.intent_id = Some(published.id());
    report.intent_checksum = Some(hex(&storage::intent_checksum(publication.bytes())?));
    report.result_id = Some(plan.result_id);
    let intent_bytes = publication.bytes().to_vec();
    drop(publication);
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

fn intent_redundant_bindings(intent: &storage::Intent, plan: &FreshRecoveryPlan) -> Held<()> {
    let identity = plan
        .retained
        .context
        .allocation
        .identity
        .as_ref()
        .ok_or("identity_unknown")?;
    if intent.source_commitment != hash32(&Sha256::digest(&intent.source_witness)) {
        return Err("source_commitment_changed");
    }
    if intent.private_path != identity.private_git_dir.as_os_str().as_bytes() {
        return Err("identity_unknown");
    }
    if intent.boot != identity.boot_id.as_bytes() {
        return Err("identity_unknown");
    }
    Ok(())
}

fn mint_intent_publication<'g>(
    plan: &FreshRecoveryPlan,
    guard: &'g crate::checkout_guard::CheckoutGuard,
    intent_bytes: Vec<u8>,
    bound: &receipts::RecoveryResultBinding,
    intent_id: Uuid,
) -> Held<RecoveryIntentPublication<'g>> {
    guard
        .matches_checkout(plan.checkout)
        .map_err(|_| "checkout_guard_unavailable")?;
    if intent_id != plan.operation
        || bound.id != plan.result_id
        || intent_bytes.len() as u64 > 2 * 1024 * 1024
    {
        return Err("result_binding_changed");
    }
    match storage::decode(&intent_bytes)? {
        storage::Record::Intent(intent) => {
            if intent.operation != plan.operation
                || intent.result_id != plan.result_id
                || intent.result_dev != bound.dev
                || intent.result_ino != bound.ino
                || intent.result_length != bound.length
            {
                return Err("result_binding_changed");
            }
        }
        storage::Record::Result(_) => return Err("record_kind"),
    }
    Ok(RecoveryIntentPublication {
        guard,
        checkout: plan.checkout,
        id: plan.operation,
        length: intent_bytes.len() as u64,
        bytes: intent_bytes,
    })
}

fn mint_result_publication<'g>(
    guard: &'g crate::checkout_guard::CheckoutGuard,
    intent: &storage::Intent,
    intent_checksum: [u8; 32],
    bound: receipts::RecoveryResultBinding,
    result_bytes: Vec<u8>,
) -> Held<RecoveryResultPublication<'g>> {
    guard
        .matches_checkout(intent.checkout)
        .map_err(|_| "checkout_guard_unavailable")?;
    if bound.id != intent.result_id
        || bound.length != result_bytes.len() as u64
        || bound.length != intent.result_length
        || bound.dev != intent.result_dev
        || bound.ino != intent.result_ino
    {
        return Err("result_binding_changed");
    }
    match storage::decode(&result_bytes)? {
        storage::Record::Result(result) => {
            if result.operation != intent.operation
                || result.result_id != intent.result_id
                || result.checkout != intent.checkout
                || result.intent_checksum != intent_checksum
            {
                return Err("result_binding_changed");
            }
        }
        storage::Record::Intent(_) => return Err("record_kind"),
    }
    Ok(RecoveryResultPublication {
        guard,
        checkout: intent.checkout,
        id: intent.result_id,
        length: result_bytes.len() as u64,
        bytes: result_bytes,
        binding: bound,
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
    if launched || reason == "durability_unknown" {
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
    plan.guard
        .require_matching(store, plan.checkout)
        .map_err(|_| "checkout_guard_unavailable")?;
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
    short_context_matches(store, &plan.guard, &plan.retained.context, &mut plan.budget)?;
    // SQL and allocation lease are gone; SH/common guards span sync and every CAS.
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
    #[cfg(test)]
    if fault == Fault::AttachmentSync {
        fault_hit(Fault::AttachmentSync);
        return fail(report, "attachment_sync_failed");
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
    if let Err(reason) =
        short_context_matches(store, &plan.guard, &plan.retained.context, &mut plan.budget)
    {
        return fail(report, reason);
    }
    #[cfg(test)]
    AFTER_CLOSING_CAPTURE.with(|hook| {
        if let Some(call) = hook.borrow_mut().take() {
            call();
        }
    });
    if after_checkout.recheck(&mut plan.budget).is_err() {
        return fail(report, "census_changed");
    }
    if after_inputs.recheck(&mut plan.budget).is_err() {
        return fail(report, "census_changed");
    }
    if plan.retained.config.recheck(&mut plan.budget).is_err() {
        return fail(report, "census_changed");
    }
    if later.recheck(&mut plan.budget).is_err() {
        return fail(report, "census_changed");
    }
    let intent_checksum = match &intent_bytes {
        Some(bytes) => match storage::intent_checksum(bytes) {
            Ok(value) => value,
            Err(reason) => return fail(report, reason),
        },
        None => return fail(report, "intent_missing"),
    };
    let decoded_intent = match intent_bytes.as_deref().map(storage::decode) {
        Some(Ok(storage::Record::Intent(intent))) => intent,
        Some(Ok(_)) => return fail(report, "record_kind"),
        Some(Err(reason)) => return fail(report, reason),
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
    let publication = match mint_result_publication(
        &plan.guard,
        &decoded_intent,
        intent_checksum,
        bound,
        result_bytes,
    ) {
        Ok(value) => value,
        Err(reason) => return fail(report, reason),
    };
    if let Err(error) = receipts::publish_recovery_result(
        store,
        &publication,
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
    report.outcome = "prepared";
    report.reason = "local_protection";
    report.durability = "acknowledged";
    report.recorded = true;
    report.created_refs = created;
    report.verified_refs = verified;
    report.coverage = "complete";
    Ok(())
}

fn short_context_matches(
    store: &mut Store,
    guard: &crate::checkout_guard::CheckoutGuard,
    expected: &Context,
    b: &mut Budget,
) -> Held<()> {
    guard
        .require_matching(store, expected.allocation.checkout)
        .map_err(|_| "checkout_guard_unavailable")?;
    store.may_acquire_lease().map_err(|_| "authority_unknown")?;
    let lease = store.authority_lease().map_err(|_| "authority_busy")?;
    let authority = std::sync::Arc::clone(store.authority_identity());
    let schema = store.schema_participation();
    {
        let phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| "context_unknown")?;
        let tx = crate::retirement_journal::fence(
            tx,
            &lease,
            &authority,
            crate::retirement_journal::Scope::Checkout(expected.allocation.checkout),
            crate::retirement_journal::Attempt::RecoveryRefs,
        )
        .map_err(|error| receipt_reason(receipts::store_error(error)))?;
        let current =
            snapshot_in_transaction(&tx, &authority, &schema, expected.allocation.checkout, b)
                .map_err(|_| "context_unknown")?;
        if current.canonical != expected.canonical {
            return Err("context_changed");
        }
        tx.commit().map_err(|_| "context_unknown")?;
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
        ReceiptError::RetirementIntentActive => "retirement_intent_active",
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

fn lock_directory_meta(file: &File) -> Held<()> {
    let meta = file.metadata().map_err(|_| "lock_unknown")?;
    if !meta.is_dir()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o7777 != 0o700
    {
        return Err("lock_unknown");
    }
    Ok(())
}

fn lock_file_meta(file: &File) -> Held<()> {
    let meta = file.metadata().map_err(|_| "lock_unknown")?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o7777 != 0o600
    {
        return Err("lock_unknown");
    }
    Ok(())
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
        || meta.mode() & 0o7777 != 0o700
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
    lock_directory_meta(&directory)?;
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
    lock_file_meta(&file)?;
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

fn acquire_existing_lock(store: &Store, key: &CommonKey) -> Held<OperationLock> {
    let authority = open_lock_authority(store)?;
    let authority_id = lock_identity(&authority)?;
    let directory = match rfs::openat2(
        &authority,
        LOCK_DIR,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        LOCK_RESOLVE,
    ) {
        Ok(dir) => File::from(dir),
        Err(error) if error == rustix::io::Errno::NOENT => return Err("preparation_required"),
        Err(_) => return Err("lock_unknown"),
    };
    lock_directory_meta(&directory)?;
    let named_dir = open_lock_child(&authority, LOCK_DIR, OFlags::PATH | OFlags::DIRECTORY)?;
    if lock_identity(&named_dir)? != lock_identity(&directory)? {
        return Err("lock_unknown");
    }
    let name = format!("{:016x}-{:016x}.lock", key.dev, key.ino);
    let file = match rfs::openat2(
        &directory,
        name.as_str(),
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        LOCK_RESOLVE,
    ) {
        Ok(file) => File::from(file),
        Err(error) if error == rustix::io::Errno::NOENT => return Err("preparation_required"),
        Err(_) => return Err("lock_unknown"),
    };
    lock_file_meta(&file)?;
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

pub(super) struct ExistingLock {
    lock: OperationLock,
    key: CommonKey,
}
impl ExistingLock {
    pub(super) fn retain(store: &Store, context: &Context, b: &mut Budget) -> Held<Self> {
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
        Ok(Self {
            lock: acquire_existing_lock(store, &key)?,
            key,
        })
    }
    pub(super) fn confirm(
        &self,
        store: &Store,
        common: &filesystem::Manifest,
        path: &[u8],
    ) -> Held<()> {
        let (dev, ino) = common.root_dev_ino();
        if (dev, ino) != (self.key.dev, self.key.ino) || self.key.path != path {
            return Err("common_identity_changed");
        }
        self.lock.revalidate(store, &self.key, path)?;
        sync::persistent_manifest(common)?;
        Ok(())
    }
    pub(super) fn revalidate(&self, store: &Store, path: &[u8]) -> Held<()> {
        self.lock.revalidate(store, &self.key, path)
    }
    pub(super) fn matches_census(&self, census: &preservation::RecoveryCensus) -> Held<()> {
        if census.common_dev_ino() != (self.key.dev, self.key.ino) {
            return Err("common_identity_changed");
        }
        Ok(())
    }
}

pub(super) fn verify_existing_protection(
    census: &preservation::RecoveryCensus,
    checkout: Uuid,
) -> Held<Vec<(String, String)>> {
    if census.reserved_namespace_held() {
        return Err("recovery_namespace_unknown");
    }
    let plan = census.plan(checkout)?;
    if plan.is_empty() {
        return Err("recovery_target_unknown");
    }
    let targets = plan
        .into_iter()
        .map(|row| (row.reference, row.oid))
        .collect::<Vec<_>>();
    for (reference, oid) in &targets {
        match census.existing_target(reference) {
            Some(existing) if existing == oid.as_bytes() => {}
            Some(_) => return Err("recovery_ref_conflict"),
            None => return Err("recovery_target_unknown"),
        }
    }
    census.verify_named(&targets)?;
    Ok(targets)
}

pub(super) fn sync_existing_protection(
    objects: &filesystem::Manifest,
    census: &mut preservation::RecoveryCensus,
    targets: &[(String, String)],
    b: &mut Budget,
) -> Held<()> {
    sync::persistent_manifest(census.common())?;
    sync::sync_objects(objects, b)?;
    let names = targets
        .iter()
        .map(|(reference, _)| reference.clone())
        .collect::<Vec<_>>();
    let packed = census.packed_recovery();
    sync::sync_refs(census.common(), &names, packed, b)?;
    for (reference, _) in targets {
        sync::recovery_log_absent(census.common_mut(), reference, b)?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn prepare_for_assessment(path: &Path, checkout: Uuid) -> RecoveryReport {
    prepare_path(path, checkout, Uuid::now_v7(), Fault::None)
}

#[cfg(test)]
use crate::inspection::fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };

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
    fn recovery_mutation_holds_before_common_lock_or_pending_files() {
        let (mut f, path) = setup("sha1");
        let lock_dir = f
            .temp
            .path()
            .join("authority/recovery-preparation-locks-v1");
        let locks = || {
            fs::read_dir(&lock_dir)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    let meta = entry.metadata().unwrap();
                    (
                        entry.file_name(),
                        (meta.dev(), meta.ino(), meta.mode(), meta.nlink()),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let prior_locks = locks();
        assert!(
            !prior_locks.is_empty(),
            "allocation must own an existing common lock"
        );
        receipts::seed_collector_intent(&f.store, f.allocation.checkout);
        let before = receipts::collector_source(&mut f.store, f.allocation.checkout);
        for _ in 0..2 {
            let report = prepare_path(&path, f.allocation.checkout, Uuid::now_v7(), Fault::None);
            assert_eq!(report.reason, "retirement_intent_active", "{report:?}");
            assert!(!report.prepared());
            assert!(report.created_refs.is_empty());
            receipts::assert_collector_held(&f.store, f.allocation.checkout, "recovery_refs");
            assert_eq!(
                before,
                receipts::collector_source(&mut f.store, f.allocation.checkout)
            );
            assert!(!f
                .temp
                .path()
                .join("authority/inspection-receipts-v1")
                .exists());
            assert_eq!(
                locks(),
                prior_locks,
                "fenced recovery must not create or replace common locks"
            );
        }
    }

    #[test]
    fn shared_guard_survives_cas_without_global_lease() {
        use crate::checkout_guard::CheckoutGuard;
        let (f, path) = setup("sha1");
        let registry = f.temp.path().join("registry");
        let authority = f.temp.path().join("authority");
        let root = f.root.clone();
        let checkout = f.allocation.checkout;
        let reached = std::rc::Rc::new(std::cell::Cell::new(false));
        let observed = reached.clone();
        AFTER_CAS.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let store =
                    Store::open_existing_registered_mut(&registry, &authority, &[root]).unwrap();
                assert!(matches!(
                    CheckoutGuard::exclusive(&store, checkout),
                    Err(crate::store::StoreError::OperationsInFlight)
                ));
                let other = CheckoutGuard::shared(&store, Uuid::now_v7()).unwrap();
                let lock = File::open(authority.join("allocation.lock")).unwrap();
                rfs::flock(&lock, rfs::FlockOperation::NonBlockingLockExclusive).unwrap();
                drop((lock, other));
                observed.set(true);
            }))
        });
        let report = prepare_path(&path, checkout, Uuid::now_v7(), Fault::None);
        assert!(reached.get(), "{report:?}");
        assert!(report.prepared(), "{report:?}");
        assert!(CheckoutGuard::exclusive(&f.store, checkout).is_ok());
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
            (Fault::AttachmentSync, "attachment_sync_failed", true),
            (Fault::ResultWrite, "result_io", true),
            (Fault::ResultFsync, "receipt_io", true),
            (Fault::PublishReopen, "durability_unknown", true),
            (Fault::PublishDeadline, "durability_unknown", true),
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

    fn pending_result_path(
        f: &fixture::ManagedFixture,
        report: &RecoveryReport,
    ) -> std::path::PathBuf {
        let id = report.result_id.expect("result reservation");
        let dir = f.temp.path().join("authority/inspection-receipts-v1");
        for entry in fs::read_dir(&dir).unwrap() {
            let name = entry.unwrap().file_name();
            let text = name.to_string_lossy();
            if text.starts_with(&format!("pending-{id}-")) {
                return dir.join(name);
            }
        }
        panic!("missing pending result for {id}");
    }

    fn lock_file(f: &fixture::ManagedFixture) -> std::path::PathBuf {
        let common = fs::metadata(f.common()).unwrap();
        f.temp
            .path()
            .join("authority/recovery-preparation-locks-v1")
            .join(format!("{:016x}-{:016x}.lock", common.dev(), common.ino()))
    }

    fn mutate_reflog_message_only(f: &fixture::ManagedFixture) {
        let log = f.private().join("logs/HEAD");
        let bytes = fs::read(&log).unwrap();
        let mut lines: Vec<Vec<u8>> = bytes.split(|c| *c == b'\n').map(|l| l.to_vec()).collect();
        if lines.last().is_some_and(|l| l.is_empty()) {
            lines.pop();
        }
        let last = lines.last_mut().expect("reflog");
        if let Some(tab) = last.iter().position(|c| *c == b'\t') {
            last.truncate(tab + 1);
            last.extend(b"message-only");
        } else {
            last.extend(b"\tmessage-only");
        }
        let mut out = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                out.push(b'\n');
            }
            out.extend(line);
        }
        out.push(b'\n');
        fs::write(&log, out).unwrap();
    }

    #[test]
    fn mismatched_pending_result_is_not_truncated() {
        let (f, config) = setup("sha1");
        let operation = Uuid::now_v7();
        let first = prepare_path(
            &config,
            f.allocation.checkout,
            operation,
            Fault::ResultWrite,
        );
        assert_eq!(take_fault_hit(), Fault::ResultWrite, "{first:?}");
        assert_eq!(first.reason, "result_io", "{first:?}");
        assert_eq!(first.durability, "unknown");
        assert!(!first.created_refs.is_empty(), "{first:?}");
        let pending = pending_result_path(&f, &first);
        fs::write(&pending, b"partial-not-matching-bytes").unwrap();
        let before = fs::read(&pending).unwrap();
        let resume = prepare_path(&config, f.allocation.checkout, operation, Fault::None);
        assert_ne!(resume.outcome, "prepared", "{resume:?}");
        assert_eq!(fs::read(&pending).unwrap(), before);
        assert!(f.common().join("refs/work-recovery").exists());
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
        assert!(!report.retirement_authority);
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
        mutate_reflog_message_only(&f);
        let resume = prepare_path(&config, f.allocation.checkout, operation, Fault::None);
        assert_eq!(resume.reason, "census_changed", "{resume:?}");
        assert_ne!(resume.outcome, "prepared", "{resume:?}");
        assert_ne!(resume.durability, "acknowledged");
        assert!(!f.common().join("refs/work-recovery").exists());
    }

    #[test]
    fn resume_holds_payload_index_config_and_identity_mutations() {
        for case in ["payload", "index", "config", "identity"] {
            let (f, config) = setup("sha1");
            let operation = Uuid::now_v7();
            let first = prepare_path(&config, f.allocation.checkout, operation, Fault::BeforeCas);
            assert_eq!(take_fault_hit(), Fault::BeforeCas, "{case} {first:?}");
            let _ = take_witness_delta();
            match case {
                "payload" => fs::write(f.path(b"tracked"), b"mutated payload\n").unwrap(),
                "index" => f.git(&[
                    "update-index".as_ref(),
                    "--chmod=+x".as_ref(),
                    "tracked".as_ref(),
                ]),
                "config" => {
                    let mut bytes = fs::read(&config).unwrap();
                    bytes.extend(b"\n# valid-field-comment\n");
                    fs::write(&config, bytes).unwrap();
                }
                _ => {
                    let path = f.private().join("work-lease.json");
                    let bytes = fs::read(&path).unwrap();
                    let mode = fs::metadata(&path).unwrap().permissions();
                    let tmp = path.with_extension("json.replace");
                    fs::write(&tmp, &bytes).unwrap();
                    fs::set_permissions(&tmp, mode).unwrap();
                    fs::rename(&tmp, &path).unwrap();
                }
            }
            let resume = prepare_path(&config, f.allocation.checkout, operation, Fault::None);
            assert!(take_witness_delta(), "{case} {resume:?}");
            assert_eq!(resume.reason, "census_changed", "{case} {resume:?}");
            assert_ne!(resume.outcome, "prepared", "{case} {resume:?}");
            assert_ne!(resume.durability, "acknowledged", "{case}");
            assert!(!f.common().join("refs/work-recovery").exists(), "{case}");
        }
    }

    #[test]
    fn intent_durability_unknown_does_not_call_git() {
        let (f, config) = setup("sha1");
        let before = f.common().join("refs/work-recovery").exists();
        let report = prepare_path(
            &config,
            f.allocation.checkout,
            Uuid::now_v7(),
            Fault::IntentDurability,
        );
        assert_eq!(take_fault_hit(), Fault::IntentDurability, "{report:?}");
        assert_eq!(report.reason, "durability_unknown", "{report:?}");
        assert_eq!(report.durability, "unknown", "{report:?}");
        assert_ne!(report.outcome, "prepared");
        assert_ne!(report.outcome, "unknown");
        assert_eq!(f.common().join("refs/work-recovery").exists(), before);
        assert!(report.created_refs.is_empty());
    }

    #[test]
    fn same_id_continues_after_first_cas_and_retries_matching_pending() {
        let (f, config) = setup("sha1");
        let operation = Uuid::now_v7();
        let first = prepare_path(
            &config,
            f.allocation.checkout,
            operation,
            Fault::AfterFirstCas,
        );
        assert_eq!(take_fault_hit(), Fault::AfterFirstCas, "{first:?}");
        assert_eq!(first.durability, "unknown");
        assert!(!first.created_refs.is_empty(), "{first:?}");
        let created = first.created_refs.clone();
        let resume = prepare_path(&config, f.allocation.checkout, operation, Fault::None);
        assert_eq!(resume.outcome, "prepared", "{resume:?}");
        assert_eq!(resume.durability, "acknowledged", "{resume:?}");
        assert!(resume.resume);
        for name in &created {
            assert!(
                resume.verified_refs.iter().any(|r| r == name)
                    || resume.created_refs.iter().any(|r| r == name),
                "{name} {resume:?}"
            );
        }
    }

    #[test]
    fn matching_pending_fsync_fault_retries_same_artifact() {
        let (f, config) = setup("sha1");
        let operation = Uuid::now_v7();
        let first = prepare_path(
            &config,
            f.allocation.checkout,
            operation,
            Fault::ResultFsync,
        );
        assert_eq!(take_fault_hit(), Fault::ResultFsync, "{first:?}");
        assert_eq!(first.reason, "receipt_io", "{first:?}");
        assert_eq!(first.durability, "unknown");
        let pending = pending_result_path(&f, &first);
        let before = fs::metadata(&pending).unwrap();
        let ino = before.ino();
        let resume = prepare_path(&config, f.allocation.checkout, operation, Fault::None);
        assert_eq!(resume.outcome, "prepared", "{resume:?}");
        assert_eq!(resume.durability, "acknowledged");
        let published = f.temp.path().join(format!(
            "authority/inspection-receipts-v1/{}.receipt",
            first.result_id.unwrap()
        ));
        assert!(published.exists(), "{resume:?}");
        assert_eq!(fs::metadata(&published).unwrap().ino(), ino);
        assert!(!pending.exists());
    }

    #[test]
    fn lock_chmod_and_hardlink_fail_revalidate() {
        let (f, config) = setup("sha1");
        let lock = lock_file(&f);
        AFTER_CAS.with(|hook| {
            let path = lock.clone();
            *hook.borrow_mut() = Some(Box::new(move || {
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o644));
            }));
        });
        let report = prepare_path(&config, f.allocation.checkout, Uuid::now_v7(), Fault::None);
        assert_eq!(report.reason, "lock_unknown", "{report:?}");
        assert_eq!(report.durability, "unknown", "{report:?}");
        let (f, config) = setup("sha1");
        let lock = lock_file(&f);
        AFTER_CAS.with(|hook| {
            let path = lock.clone();
            *hook.borrow_mut() = Some(Box::new(move || {
                let extra = path.with_extension("link");
                let _ = fs::hard_link(&path, &extra);
            }));
        });
        let report = prepare_path(&config, f.allocation.checkout, Uuid::now_v7(), Fault::None);
        assert_eq!(report.reason, "lock_unknown", "{report:?}");
        assert_ne!(report.outcome, "prepared");
    }

    #[test]
    fn lock_namespace_replacement_fails_revalidate() {
        let (f, config) = setup("sha1");
        let dir = f
            .temp
            .path()
            .join("authority/recovery-preparation-locks-v1");
        AFTER_CAS.with(|hook| {
            let path = dir.clone();
            *hook.borrow_mut() = Some(Box::new(move || {
                let replaced = path.with_extension("old");
                let _ = fs::rename(&path, &replaced);
                let _ = fs::create_dir(&path);
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
            }));
        });
        let report = prepare_path(&config, f.allocation.checkout, Uuid::now_v7(), Fault::None);
        assert_eq!(report.reason, "lock_unknown", "{report:?}");
        assert_ne!(report.outcome, "prepared");
    }

    #[test]
    fn lock_special_mode_bits_fail_revalidate() {
        for (directory, mode) in [(false, 0o4600), (true, 0o2700)] {
            let (f, config) = setup("sha1");
            let path = if directory {
                f.temp
                    .path()
                    .join("authority/recovery-preparation-locks-v1")
            } else {
                lock_file(&f)
            };
            AFTER_CAS.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    let before = fs::metadata(&path).unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
                    let after = fs::metadata(&path).unwrap();
                    assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
                    assert_eq!(after.mode() & 0o7777, mode);
                }));
            });
            let report = prepare_path(&config, f.allocation.checkout, Uuid::now_v7(), Fault::None);
            AFTER_CAS.with(|hook| assert!(hook.borrow().is_none(), "{report:?}"));
            assert_eq!(report.reason, "lock_unknown", "{report:?}");
            assert_eq!(report.durability, "unknown", "{report:?}");
            assert!(!report.created_refs.is_empty(), "{report:?}");
            assert_ne!(report.outcome, "prepared");
        }
    }

    #[test]
    fn rechecksummed_source_commitment_contradiction_is_rejected_on_resume() {
        let (f, config) = setup("sha1");
        let operation = Uuid::now_v7();
        let first = prepare_path(&config, f.allocation.checkout, operation, Fault::BeforeCas);
        assert_eq!(take_fault_hit(), Fault::BeforeCas, "{first:?}");
        let path = f.temp.path().join(format!(
            "authority/inspection-receipts-v1/{}.receipt",
            operation
        ));
        let bytes = fs::read(&path).unwrap();
        let mut intent = match storage::decode(&bytes).unwrap() {
            storage::Record::Intent(intent) => *intent,
            storage::Record::Result(_) => panic!("kind"),
        };
        intent.source_commitment = [9; 32];
        let forged = storage::encode_intent(&intent).unwrap();
        fs::write(&path, forged).unwrap();
        let resume = prepare_path(&config, f.allocation.checkout, operation, Fault::None);
        assert_eq!(resume.reason, "source_commitment_changed", "{resume:?}");
        assert_ne!(resume.outcome, "prepared");
        assert!(!f.common().join("refs/work-recovery").exists());
    }

    fn framed(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut at = 0;
        let mut out = Vec::new();
        while at < bytes.len() {
            let tag = bytes[at];
            at += 1;
            let len = u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap()) as usize;
            at += 8;
            out.push((tag, bytes[at..at + len].to_vec()));
            at += len;
        }
        out
    }

    fn encode_framed(frames: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (tag, value) in frames {
            out.push(*tag);
            out.extend((value.len() as u64).to_be_bytes());
            out.extend(value);
        }
        out
    }

    fn swap_two_path_blocks(manifest: &[u8]) -> Vec<u8> {
        let frames = framed(manifest);
        assert_eq!(frames[0].0, 0);
        let mut blocks = Vec::new();
        let mut absences = Vec::new();
        let mut i = 1;
        while i < frames.len() {
            if frames[i].0 == 6 {
                absences.extend_from_slice(&frames[i..]);
                break;
            }
            assert_eq!(frames[i].0, 1);
            let start = i;
            i += 1;
            while i < frames.len() && !matches!(frames[i].0, 1 | 6) {
                i += 1;
            }
            blocks.push(frames[start..i].to_vec());
        }
        assert!(blocks.len() >= 2, "need two path blocks to swap");
        blocks.swap(0, 1);
        let mut out = vec![frames[0].clone()];
        for block in blocks {
            out.extend(block);
        }
        out.extend(absences);
        encode_framed(&out)
    }

    #[test]
    fn closing_payload_mutation_is_caught_by_live_recheck() {
        let (f, config) = setup("sha1");
        AFTER_CLOSING_CAPTURE.with(|hook| {
            let path = f.path(b"tracked");
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::write(&path, b"mutated after closing capture\n").unwrap();
            }));
        });
        let report = prepare_path(&config, f.allocation.checkout, Uuid::now_v7(), Fault::None);
        assert_eq!(report.reason, "census_changed", "{report:?}");
        assert_ne!(report.outcome, "prepared", "{report:?}");
        assert_eq!(report.durability, "unknown", "{report:?}");
        assert!(!report.created_refs.is_empty(), "{report:?}");
        AFTER_CLOSING_CAPTURE.with(|hook| assert!(hook.borrow().is_none(), "{report:?}"));
    }

    #[test]
    fn verified_only_publication_unknown_is_independent_of_git_launch() {
        let (f, config) = setup("sha1");
        let first = prepare_path(&config, f.allocation.checkout, Uuid::now_v7(), Fault::None);
        assert_eq!(first.outcome, "prepared", "{first:?}");
        assert!(!first.verified_refs.is_empty() || !first.created_refs.is_empty());
        let report = prepare_path(
            &config,
            f.allocation.checkout,
            Uuid::now_v7(),
            Fault::PublishReopen,
        );
        assert_eq!(take_fault_hit(), Fault::PublishReopen, "{report:?}");
        assert_eq!(report.reason, "durability_unknown", "{report:?}");
        assert_eq!(report.outcome, "unknown", "{report:?}");
        assert_eq!(report.durability, "unknown", "{report:?}");
        assert!(!report.recorded, "{report:?}");
        assert!(report.created_refs.is_empty(), "{report:?}");
        assert!(!report.verified_refs.is_empty(), "{report:?}");
        let published = f.temp.path().join(format!(
            "authority/inspection-receipts-v1/{}.receipt",
            report.result_id.expect("result id")
        ));
        let _ = published.exists();
    }

    #[test]
    fn matching_short_prefix_pending_retries_same_inode() {
        let (f, config) = setup("sha1");
        let operation = Uuid::now_v7();
        let first = prepare_path(
            &config,
            f.allocation.checkout,
            operation,
            Fault::ResultFsync,
        );
        assert_eq!(take_fault_hit(), Fault::ResultFsync, "{first:?}");
        assert_eq!(first.reason, "receipt_io", "{first:?}");
        let pending = pending_result_path(&f, &first);
        let before = fs::metadata(&pending).unwrap();
        let ino = before.ino();
        let full = fs::read(&pending).unwrap();
        assert!(full.len() > 1, "{first:?}");
        {
            let file = fs::OpenOptions::new().write(true).open(&pending).unwrap();
            file.set_len((full.len() / 2) as u64).unwrap();
        }
        assert_eq!(fs::metadata(&pending).unwrap().ino(), ino);
        let prefix = fs::read(&pending).unwrap();
        assert!(!prefix.is_empty());
        assert!(prefix.len() < full.len());
        assert_eq!(prefix, &full[..prefix.len()]);
        let resume = prepare_path(&config, f.allocation.checkout, operation, Fault::None);
        assert_eq!(resume.outcome, "prepared", "{resume:?}");
        assert_eq!(resume.durability, "acknowledged");
        let published = f.temp.path().join(format!(
            "authority/inspection-receipts-v1/{}.receipt",
            first.result_id.unwrap()
        ));
        assert!(published.exists(), "{resume:?}");
        assert_eq!(fs::metadata(&published).unwrap().ino(), ino);
        assert!(!pending.exists());
    }

    fn malformed_manifest_shape(manifest: &[u8], case: u8) -> Vec<u8> {
        let mut frames = framed(manifest);
        match case {
            0 => {
                let start = frames
                    .iter()
                    .position(|(tag, value)| *tag == 3 && value == &[1])
                    .unwrap();
                let end = (start + 1..frames.len())
                    .find(|i| matches!(frames[*i].0, 1 | 6))
                    .unwrap_or(frames.len());
                frames.insert(end, (5, vec![7; 32]));
            }
            1 => {
                let start = frames
                    .iter()
                    .position(|(tag, value)| *tag == 3 && value == &[0])
                    .unwrap();
                frames.insert(start + 1, (4, b"impossible-child".to_vec()));
            }
            2 => {
                let identity = &mut frames.iter_mut().find(|(tag, _)| *tag == 2).unwrap().1;
                assert_eq!(identity.len(), 88);
                identity.truncate(87);
            }
            3 => {
                let content = &mut frames.iter_mut().find(|(tag, _)| *tag == 5).unwrap().1;
                assert_eq!(content.len(), 32);
                content.truncate(31);
            }
            _ => unreachable!(),
        }
        encode_framed(&frames)
    }

    #[test]
    fn rechecksummed_malformed_manifest_shapes_are_rejected_on_resume() {
        for case in 0..4 {
            let (f, config) = setup("sha1");
            let operation = Uuid::now_v7();
            let first = prepare_path(&config, f.allocation.checkout, operation, Fault::BeforeCas);
            assert_eq!(take_fault_hit(), Fault::BeforeCas, "{first:?}");
            let path = f.temp.path().join(format!(
                "authority/inspection-receipts-v1/{operation}.receipt"
            ));
            let mut intent = match storage::decode(&fs::read(&path).unwrap()).unwrap() {
                storage::Record::Intent(intent) => *intent,
                storage::Record::Result(_) => panic!("kind"),
            };
            let mut source = framed(&intent.source_witness);
            let admin = source.iter_mut().find(|(tag, _)| *tag == 3).unwrap();
            admin.1 = malformed_manifest_shape(&admin.1, case);
            intent.source_witness = encode_framed(&source);
            intent.source_commitment = hash32(&Sha256::digest(&intent.source_witness));
            fs::write(&path, storage::encode_intent(&intent).unwrap()).unwrap();
            let _ = take_witness_delta();
            let resume = prepare_path(&config, f.allocation.checkout, operation, Fault::None);
            assert!(take_witness_delta(), "case {case}: {resume:?}");
            assert_eq!(resume.reason, "census_changed", "case {case}: {resume:?}");
            assert_ne!(resume.outcome, "prepared");
            assert!(!f.common().join("refs/work-recovery").exists());
        }
    }

    #[test]
    fn rechecksummed_reordered_manifest_witness_is_rejected_on_resume() {
        let (f, config) = setup("sha1");
        let operation = Uuid::now_v7();
        let first = prepare_path(&config, f.allocation.checkout, operation, Fault::BeforeCas);
        assert_eq!(take_fault_hit(), Fault::BeforeCas, "{first:?}");
        let path = f.temp.path().join(format!(
            "authority/inspection-receipts-v1/{}.receipt",
            operation
        ));
        let bytes = fs::read(&path).unwrap();
        let mut intent = match storage::decode(&bytes).unwrap() {
            storage::Record::Intent(intent) => *intent,
            storage::Record::Result(_) => panic!("kind"),
        };
        let mut source = framed(&intent.source_witness);
        let mut swapped = false;
        for frame in &mut source {
            if frame.0 == 3 {
                frame.1 = swap_two_path_blocks(&frame.1);
                swapped = true;
            }
        }
        assert!(swapped, "admin manifest witness missing");
        intent.source_witness = encode_framed(&source);
        intent.source_commitment = hash32(&Sha256::digest(&intent.source_witness));
        let forged = storage::encode_intent(&intent).unwrap();
        fs::write(&path, forged).unwrap();
        let _ = take_witness_delta();
        let resume = prepare_path(&config, f.allocation.checkout, operation, Fault::None);
        assert!(take_witness_delta(), "{resume:?}");
        assert_eq!(resume.reason, "census_changed", "{resume:?}");
        assert_ne!(resume.outcome, "prepared");
        assert!(!f.common().join("refs/work-recovery").exists());
    }
}
