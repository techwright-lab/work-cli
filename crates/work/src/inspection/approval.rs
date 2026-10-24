//! Adopted two-endpoint observations, never OS quiescence or lifecycle authority.
use super::*;
use crate::config::{ApprovalPolicy, Config, ConfigDocument};
use serde::{Deserialize, Serialize};
type Held<T> = Result<T, &'static str>;

#[derive(Debug, clap::Subcommand)]
pub(crate) enum ApprovalCommand {
    /// Print fresh findings and record an adopted baseline; no automatic confirmation
    Begin {
        #[arg(value_name="checkout-uuidv7", value_parser=super::parse_checkout)]
        checkout: Uuid,
    },
    /// Assert relevant sessions, background jobs and editors are stopped; not OS proof
    Confirm {
        #[arg(value_name="checkout-uuidv7", value_parser=super::parse_checkout)]
        checkout: Uuid,
        #[arg(long, value_parser=super::parse_checkout)]
        observation: Uuid,
        /// Explicitly claim relevant sessions, background jobs and editors are stopped
        #[arg(long)]
        assert_quiescent: bool,
    },
}
#[derive(Debug, Serialize)]
pub struct ApprovalReport {
    checkout: Uuid,
    outcome: &'static str,
    reason: &'static str,
    receipt_id: Option<Uuid>,
    baseline_id: Option<Uuid>,
    reserved_assertion_id: Option<Uuid>,
    inspection_digest: Option<String>,
    quiet_window_seconds: Option<u64>,
    confirmation_deadline: Option<Deadline>,
    assertion_expiry: Option<Deadline>,
    preservation: Option<PreservationReport>,
    recorded: bool,
    retirement_authority: bool,
    automatic_quiescence: bool,
    limitation: &'static str,
}
impl ApprovalReport {
    pub fn recorded(&self) -> bool {
        self.recorded
    }
    pub fn reason(&self) -> &str {
        self.reason
    }
    fn held(checkout: Uuid) -> Self {
        Self { checkout, outcome:"held", reason:"configuration_unknown", receipt_id:None, baseline_id:None, reserved_assertion_id:None, inspection_digest:None, quiet_window_seconds:None, confirmation_deadline:None, assertion_expiry:None, preservation:None, recorded:false, retirement_authority:false, automatic_quiescence:false, limitation:"Two unchanged observations are not continuous monitoring or OS quiescence. Only confirm --assert-quiescent records the operator's claim that relevant sessions, background jobs and editors are stopped. Writer, holds, task charge and all lifecycle rows remain unchanged; assertions expire and are historical after any activity or binding change." }
    }
}
#[derive(Clone, Copy)]
enum Operation {
    Begin,
    Confirm { observation: Uuid },
}
/// Configured fresh collection only. Neither receipts nor reports grant freshness.
pub fn approve_begin(checkout: Uuid) -> ApprovalReport {
    configured(checkout, Operation::Begin)
}
pub fn approve_confirm(
    checkout: Uuid,
    observation: Uuid,
    assert_quiescent: bool,
) -> ApprovalReport {
    if !assert_quiescent {
        let mut report = ApprovalReport::held(checkout);
        report.reason = "assertion_required";
        return report;
    }
    configured(checkout, Operation::Confirm { observation })
}
fn configured(checkout: Uuid, op: Operation) -> ApprovalReport {
    match Config::discover_path() {
        Some(path) => approve_path(&path, checkout, op, Clock::default()),
        None => ApprovalReport::held(checkout),
    }
}
fn approve_path(path: &Path, checkout: Uuid, op: Operation, clock: Clock) -> ApprovalReport {
    let mut collector = Collector::new(checkout, op, clock);
    let mut audit = preservation::Audit::new(checkout);
    let remote = remote_proof::approval_path(path, checkout, &mut audit, &mut collector);
    let mut report = ApprovalReport::held(checkout);
    report.reason = collector.failure.unwrap_or_else(|| {
        if remote.observed() {
            "approval_unknown"
        } else {
            "observation_held"
        }
    });
    report.preservation = Some(audit.finish(remote));
    if let (Some(mut store), Some(mut sealed)) = (collector.store.take(), collector.sealed.take()) {
        report.baseline_id = Some(sealed.record.baseline_id);
        report.reserved_assertion_id = Some(sealed.record.reserved_assertion_id);
        report.inspection_digest = Some(hex(&sealed.captured.observation.digest()));
        report.quiet_window_seconds = Some(sealed.record.policy.quiet_window_seconds);
        report.confirmation_deadline = Some(sealed.record.confirmation_deadline.clone());
        report.assertion_expiry = sealed.record.claim_expiry.clone();
        match receipts::publish_approval(&mut store, &mut sealed) {
            Ok(receipt) => {
                report.receipt_id = Some(receipt.id());
                report.recorded = true;
                report.outcome = match sealed.record.kind {
                    RecordKind::ApprovalObservation => "approval_observation",
                    RecordKind::OperatorAssertion => "operator_assertion",
                };
                report.reason = "stored";
            }
            Err(ReceiptError::DurabilityUnknown { id, .. }) => {
                report.receipt_id = Some(id);
                report.reason = "durability_unknown";
            }
            Err(error) => report.reason = error.label(),
        }
    }
    report
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApprovalStamp {
    boot: String,
    wall_ms: u64,
    low_ns: u64,
    high_ns: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Deadline {
    wall_ms: u64,
    boottime_ns: u64,
}
#[cfg(test)]
#[derive(Clone, Copy)]
enum ClockFault {
    Boot,
    WallSkew,
    Backwards,
}
#[derive(Default)]
struct Clock {
    #[cfg(test)]
    offset_ms: u64,
    #[cfg(test)]
    fault: Option<ClockFault>,
}
impl Clock {
    fn sample(&self, boot: &str) -> Held<ApprovalStamp> {
        fn ns() -> Held<u64> {
            let t = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
            let seconds = u64::try_from(t.tv_sec).map_err(|_| "clock_anomaly")?;
            let nanos = u64::try_from(t.tv_nsec).map_err(|_| "clock_anomaly")?;
            if nanos >= 1_000_000_000 {
                return Err("clock_anomaly");
            }
            seconds
                .checked_mul(1_000_000_000)
                .and_then(|s| s.checked_add(nanos))
                .ok_or("clock_anomaly")
        }
        let low_ns = ns()?;
        let wall_ms = wall_time().map_err(|_| "clock_anomaly")?;
        let high_ns = ns()?;
        let stamp = ApprovalStamp {
            boot: boot.into(),
            wall_ms,
            low_ns,
            high_ns,
        };
        #[cfg(test)]
        let stamp = {
            let offset = self
                .offset_ms
                .checked_mul(1_000_000)
                .ok_or("clock_anomaly")?;
            let mut stamp = ApprovalStamp {
                wall_ms: stamp
                    .wall_ms
                    .checked_add(self.offset_ms)
                    .ok_or("clock_anomaly")?,
                low_ns: stamp.low_ns.checked_add(offset).ok_or("clock_anomaly")?,
                high_ns: stamp.high_ns.checked_add(offset).ok_or("clock_anomaly")?,
                ..stamp
            };
            match self.fault {
                Some(ClockFault::Boot) => {
                    stamp.boot = "00000000-0000-4000-8000-000000000099".into()
                }
                Some(ClockFault::WallSkew) => {
                    stamp.wall_ms = stamp.wall_ms.checked_add(10_000).ok_or("clock_anomaly")?
                }
                Some(ClockFault::Backwards) => {
                    stamp.wall_ms = stamp.wall_ms.checked_sub(60_000).ok_or("clock_anomaly")?
                }
                None => (),
            }
            stamp
        };
        validate_stamp(&stamp)?;
        Ok(stamp)
    }
}
fn validate_stamp(s: &ApprovalStamp) -> Held<()> {
    let boot = Uuid::parse_str(&s.boot).map_err(|_| "clock_anomaly")?;
    if boot.to_string() != s.boot
        || s.wall_ms == 0
        || s.high_ns < s.low_ns
        || s.high_ns - s.low_ns > 1_000_000_000
    {
        return Err("clock_anomaly");
    }
    Ok(())
}
fn boot(b: &mut Budget) -> Held<String> {
    let bytes = filesystem::boot_id(b).map_err(|_| "clock_anomaly")?;
    String::from_utf8(bytes.strip_suffix(b"\n").ok_or("clock_anomaly")?.to_vec())
        .map_err(|_| "clock_anomaly")
}
fn elapsed(a: &ApprovalStamp, z: &ApprovalStamp) -> Held<(u64, u64)> {
    validate_stamp(a)?;
    validate_stamp(z)?;
    if a.boot != z.boot {
        return Err("clock_anomaly");
    }
    let wall = z.wall_ms.checked_sub(a.wall_ms).ok_or("clock_anomaly")?;
    let low = z.low_ns.checked_sub(a.high_ns).ok_or("clock_anomaly")?;
    let high = z.high_ns.checked_sub(a.low_ns).ok_or("clock_anomaly")?;
    let wall_ns = wall.checked_mul(1_000_000).ok_or("clock_anomaly")?;
    if wall_ns.abs_diff(low) > 1_000_000_000 || wall_ns.abs_diff(high) > 1_000_000_000 {
        return Err("clock_anomaly");
    }
    Ok((wall, low))
}
fn quiet(a: &ApprovalStamp, z: &ApprovalStamp, seconds: u64) -> Held<()> {
    let (wall, mono) = elapsed(a, z)?;
    if wall < seconds.checked_mul(1000).ok_or("clock_anomaly")?
        || mono < seconds.checked_mul(1_000_000_000).ok_or("clock_anomaly")?
    {
        return Err("quiet_interval_early");
    }
    Ok(())
}
fn deadline(end: &ApprovalStamp, quiet_seconds: u64, expiry_seconds: u64) -> Held<Deadline> {
    validate_stamp(end)?;
    let duration = quiet_seconds
        .checked_add(expiry_seconds)
        .ok_or("clock_anomaly")?;
    Ok(Deadline {
        wall_ms: end
            .wall_ms
            .checked_add(duration.checked_mul(1000).ok_or("clock_anomaly")?)
            .ok_or("clock_anomaly")?,
        boottime_ns: end
            .low_ns
            .checked_add(duration.checked_mul(1_000_000_000).ok_or("clock_anomaly")?)
            .ok_or("clock_anomaly")?,
    })
}
fn within(base: &ApprovalStamp, now: &ApprovalStamp, end: &Deadline) -> Held<()> {
    elapsed(base, now)?;
    if now.wall_ms >= end.wall_ms || now.high_ns >= end.boottime_ns {
        return Err("approval_expired");
    }
    Ok(())
}
fn expiry(limit: &Deadline, claim: &ApprovalStamp, seconds: u64) -> Held<Deadline> {
    let own = deadline(claim, 0, seconds)?;
    Ok(Deadline {
        wall_ms: limit.wall_ms.min(own.wall_ms),
        boottime_ns: limit.boottime_ns.min(own.boottime_ns),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RecordKind {
    ApprovalObservation,
    OperatorAssertion,
}
/// Strict passive v2 extension. Deserializing this never constructs a seal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApprovalRecord {
    kind: RecordKind,
    binding_version: u32,
    semantic: String,
    context: String,
    invalidation: String,
    activity: String,
    mode: String,
    mode_digest: String,
    policy_digest_version: u32,
    policy_digest: String,
    policy: ApprovalPolicy,
    collection_start: ApprovalStamp,
    collection_end: ApprovalStamp,
    baseline_end: ApprovalStamp,
    confirmation_deadline: Deadline,
    baseline_id: Uuid,
    reserved_assertion_id: Uuid,
    claim_version: Option<u32>,
    claim_time: Option<ApprovalStamp>,
    claim_expiry: Option<Deadline>,
}
impl ApprovalRecord {
    pub(super) fn encode(&self) -> Held<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| "encoding_unknown")
    }
    pub(super) fn decode(
        bytes: &[u8],
        id: Uuid,
        context: [u8; 32],
        started: u64,
        ended: u64,
    ) -> Held<Self> {
        let value: Self = serde_json::from_slice(bytes).map_err(|_| "record_corrupt")?;
        if value.encode()? != bytes {
            return Err("record_corrupt");
        }
        value.validate(id, context, started, ended)?;
        Ok(value)
    }
    fn validate(&self, id: Uuid, context: [u8; 32], started: u64, ended: u64) -> Held<()> {
        self.policy.validate().map_err(|_| "record_corrupt")?;
        for digest in [
            &self.semantic,
            &self.context,
            &self.invalidation,
            &self.activity,
            &self.mode_digest,
            &self.policy_digest,
        ] {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("record_corrupt");
            }
        }
        for uuid in [id, self.baseline_id, self.reserved_assertion_id] {
            parse_checkout(&uuid.to_string()).map_err(|_| "record_corrupt")?;
        }
        if self.binding_version != 1
            || self.policy_digest_version != 1
            || self.mode != "adopted"
            || self.context != hex(&context)
            || self.baseline_id == self.reserved_assertion_id
            || self.collection_start.wall_ms != started
            || self.collection_end.wall_ms != ended
            || self.confirmation_deadline
                != deadline(
                    &self.baseline_end,
                    self.policy.quiet_window_seconds,
                    self.policy.expiry_seconds,
                )?
        {
            return Err("record_corrupt");
        }
        elapsed(&self.collection_start, &self.collection_end)?;
        match self.kind {
            RecordKind::ApprovalObservation => {
                if id != self.baseline_id
                    || self.baseline_end != self.collection_end
                    || self.claim_version.is_some()
                    || self.claim_time.is_some()
                    || self.claim_expiry.is_some()
                {
                    return Err("record_corrupt");
                }
            }
            RecordKind::OperatorAssertion => {
                let claim = self.claim_time.as_ref().ok_or("record_corrupt")?;
                quiet(
                    &self.baseline_end,
                    &self.collection_start,
                    self.policy.quiet_window_seconds,
                )?;
                elapsed(&self.collection_end, claim)?;
                within(&self.baseline_end, claim, &self.confirmation_deadline)?;
                if id != self.reserved_assertion_id
                    || self.claim_version != Some(1)
                    || self.claim_expiry
                        != Some(expiry(
                            &self.confirmation_deadline,
                            claim,
                            self.policy.expiry_seconds,
                        )?)
                {
                    return Err("record_corrupt");
                }
            }
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
struct AdoptedMode {
    digest: [u8; 32],
    activity: [u8; 32],
}
impl AdoptedMode {
    fn read(tx: &rusqlite::Connection, context: &Context) -> Held<Self> {
        let checkout = context.allocation.checkout.to_string();
        let runs: Vec<String> = {
            let mut stmt = tx
                .prepare("SELECT run_id FROM adopted_groups WHERE checkout=?1 ORDER BY id LIMIT 2")
                .map_err(|_| "mode_unknown")?;
            let rows = stmt
                .query_map([&checkout], |r| r.get(0))
                .map_err(|_| "mode_unknown")?;
            rows.collect::<Result<_, _>>().map_err(|_| "mode_unknown")?
        };
        if runs.len() != 1 {
            return Err("adopted_mode_required");
        }
        let run = work_contract::RunId::parse(&runs[0]).map_err(|_| "mode_unknown")?;
        let (request, revision, reconcile) = crate::adopted::read(tx, &run)
            .map_err(|_| "mode_unknown")?
            .ok_or("mode_unknown")?;
        if request.identity.checkout.to_string() != checkout {
            return Err("mode_unknown");
        }
        crate::adopted::held(tx, &request).map_err(|_| "mode_unknown")?;
        let roster = crate::participants::roster(tx, &request).map_err(|_| "mode_unknown")?;
        let invalid: bool = tx.query_row("SELECT
            NOT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 AND state='active' AND ready=1)
            OR (SELECT count(*) FROM writers WHERE checkout=?1)<>1
            OR EXISTS(SELECT 1 FROM run_groups WHERE checkout=?1 OR id=?2)
            OR EXISTS(SELECT 1 FROM runs WHERE group_id=?2 OR id=?3 OR run_ref=?4 OR group_id IN (SELECT id FROM run_groups WHERE checkout=?1))
            OR EXISTS(SELECT 1 FROM run_participants WHERE group_id=?2 OR id=?3 OR run_ref=?4 OR group_id IN (SELECT id FROM run_groups WHERE checkout=?1))
            OR EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1)
            OR EXISTS(SELECT 1 FROM capture_requirements WHERE checkout=?1)
            OR EXISTS(SELECT 1 FROM capture_runs WHERE checkout=?1 OR run=?3 OR group_id=?2)
            OR EXISTS(SELECT 1 FROM capture_finalizations WHERE run=?3)
            OR EXISTS(SELECT 1 FROM capture_readiness WHERE checkout=?1)
            OR EXISTS(SELECT 1 FROM attribution_gaps WHERE checkout=?1 OR run=?3)
            OR EXISTS(SELECT 1 FROM gap_qualifications WHERE checkout=?1 OR run=?3)
            OR EXISTS(SELECT 1 FROM gap_eligibility WHERE checkout=?1)",
            rusqlite::params![checkout,request.identity.group.to_string(),request.identity.run.to_string(),request.identity.run_ref.as_str()], |r| r.get(0)).map_err(|_| "mode_unknown")?;
        if invalid {
            return Err("mode_contradiction");
        }
        let bytes = serde_json::to_vec(&(&request, revision, reconcile, roster))
            .map_err(|_| "mode_unknown")?;
        // Roster validation above checks every segment. Commit exact stored fields
        // separately, streaming within this SAME snapshot (no detached status read).
        let mut activity = Sha256::new();
        activity.update(b"work.approval.activity.v1");
        activity.update((bytes.len() as u64).to_be_bytes());
        activity.update(&bytes);
        let mut stmt=tx.prepare("SELECT source,session,agent,prompt,tool,kind,event_ref,body FROM adopted_segments WHERE group_id=?1 ORDER BY source,session,agent,prompt,tool,kind,event_ref").map_err(|_| "mode_unknown")?;
        let mut rows = stmt
            .query([request.identity.group.to_string()])
            .map_err(|_| "mode_unknown")?;
        while let Some(row) = rows.next().map_err(|_| "mode_unknown")? {
            for column in 0..8 {
                let rusqlite::types::ValueRef::Text(value) =
                    row.get_ref(column).map_err(|_| "mode_unknown")?
                else {
                    return Err("mode_unknown");
                };
                activity.update((value.len() as u64).to_be_bytes());
                activity.update(value);
            }
        }
        Ok(Self {
            digest: Sha256::digest(bytes).into(),
            activity: activity.finalize().into(),
        })
    }
}

pub(super) struct Retained {
    pub(super) context: Context,
    pub(super) physical: Physical,
    pub(super) manifests: [filesystem::Manifest; 2],
    pub(super) entries: Vec<ObservedEntry>,
    pub(super) findings: Vec<Finding>,
    pub(super) evidence: Vec<u8>,
}
pub(super) struct Collector {
    checkout: Uuid,
    operation: Operation,
    clock: Clock,
    start: Option<ApprovalStamp>,
    policy: Option<ApprovalPolicy>,
    policies: Option<ValidatedPolicies>,
    policy_digest: Option<String>,
    mode: Option<AdoptedMode>,
    baseline: Option<ApprovalRecord>,
    store: Option<Store>,
    sealed: Option<SealedApproval>,
    failure: Option<&'static str>,
}
impl Collector {
    fn new(checkout: Uuid, operation: Operation, clock: Clock) -> Self {
        Self {
            checkout,
            operation,
            clock,
            start: None,
            policy: None,
            policies: None,
            policy_digest: None,
            mode: None,
            baseline: None,
            store: None,
            sealed: None,
            failure: None,
        }
    }
    pub(super) fn start(&mut self, b: &mut Budget) -> Held<()> {
        self.start = Some(self.clock.sample(&boot(b)?)?);
        Ok(())
    }
    pub(super) fn configure(&mut self, document: &ConfigDocument, config: &Config) -> Held<()> {
        let policy = document.approval().map_err(|_| "approval_policy_unknown")?;
        let policies = document
            .inspection_policies()
            .map_err(|_| "inspection_policy_unknown")?;
        let mut all = Vec::new();
        frame(&mut all, 0, b"work.approval.policy.v1");
        frame(
            &mut all,
            1,
            &serde_json::to_vec(&policy).map_err(|_| "approval_policy_unknown")?,
        );
        frame(&mut all, 2, policies.canonical_bytes());
        frame(
            &mut all,
            3,
            &serde_json::to_vec(
                &document
                    .remote_preservation()
                    .map_err(|_| "policy_unknown")?,
            )
            .map_err(|_| "policy_unknown")?,
        );
        let store = open_configured_store(config).map_err(|_| "authority_unknown")?;
        if let Operation::Confirm { observation } = self.operation {
            let receipt = read_receipt(&store, observation).map_err(|_| "baseline_ineligible")?;
            let baseline = receipt.approval_record().ok_or("baseline_ineligible")?;
            if receipt.checkout() != self.checkout
                || baseline.kind != RecordKind::ApprovalObservation
                || baseline.baseline_id != observation
            {
                return Err("baseline_ineligible");
            }
            self.baseline = Some(baseline.clone());
        }
        self.policy_digest = Some(hex(&Sha256::digest(all)));
        self.policy = Some(policy);
        self.policies = Some(policies);
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
        if self.start.as_ref().ok_or("clock_anomaly")?.boot
            != context
                .allocation
                .identity
                .as_ref()
                .ok_or("identity_unknown")?
                .boot_id
        {
            return Err("clock_anomaly");
        }
        let mode = AdoptedMode::read(&tx, &context)?;
        if self.mode.as_ref().is_some_and(|m| m != &mode) {
            return Err("mode_changed");
        }
        self.mode = Some(mode);
        tx.rollback().map_err(|_| "context_unknown")?;
        drop(phase);
        Ok(context)
    }
    pub(super) fn seal(
        &mut self,
        retained: Retained,
        local: preservation::ApprovalLocal,
        mut budget: Budget,
    ) -> Held<()> {
        let start = self.start.take().ok_or("clock_anomaly")?;
        let end = self.clock.sample(&boot(&mut budget)?)?;
        elapsed(&start, &end)?;
        if retained
            .context
            .allocation
            .identity
            .as_ref()
            .ok_or("identity_unknown")?
            .boot_id
            != end.boot
        {
            return Err("clock_anomaly");
        }
        let policy = self.policy.take().ok_or("approval_policy_unknown")?;
        let policies = self.policies.take().ok_or("inspection_policy_unknown")?;
        let mode = self.mode.take().ok_or("mode_unknown")?;
        let observation = finish_observation(
            &policies,
            &retained.context.canonical,
            &retained.evidence,
            retained.entries,
            retained.findings,
            None,
            &budget,
        )
        .map_err(|_| "inspection_unknown")?;
        if observation.coverage() != Coverage::Complete || !observation.findings().is_empty() {
            return Err("inspection_held");
        }
        let context_digest = hex(&Sha256::digest(&retained.context.canonical));
        let policy_digest = self.policy_digest.take().ok_or("policy_unknown")?;
        let mut semantic = Vec::new();
        frame(&mut semantic, 0, b"work.approval.semantic.v1");
        for bytes in [
            context_digest.as_bytes(),
            policy_digest.as_bytes(),
            &mode.digest,
            &mode.activity,
            &entry_semantics(&observation),
            &retained.physical.first.approval_semantic_v1(),
            &retained.physical.before.approval_semantic_v1(),
            &local.semantic(),
        ] {
            frame(&mut semantic, 1, bytes);
        }
        let mut invalidation = Vec::new();
        frame(&mut invalidation, 0, b"work.approval.invalidation.v1");
        for bytes in [
            retained.context.canonical.as_slice(),
            &mode.digest,
            &mode.activity,
            &retained.physical.first.fingerprint(),
            &retained.physical.before.fingerprint(),
            &local.invalidation(),
        ] {
            frame(&mut invalidation, 1, bytes);
        }
        for manifest in &retained.manifests {
            frame(&mut semantic, 2, &manifest.approval_semantic_v1());
            frame(&mut invalidation, 2, &manifest.fingerprint());
        }
        let id = match self.operation {
            Operation::Begin => Uuid::now_v7(),
            Operation::Confirm { .. } => {
                self.baseline
                    .as_ref()
                    .ok_or("baseline_ineligible")?
                    .reserved_assertion_id
            }
        };
        let mut record = ApprovalRecord {
            kind: RecordKind::ApprovalObservation,
            binding_version: 1,
            semantic: hex(&Sha256::digest(semantic)),
            context: context_digest,
            invalidation: hex(&Sha256::digest(invalidation)),
            activity: hex(&mode.activity),
            mode: "adopted".into(),
            mode_digest: hex(&mode.digest),
            policy_digest_version: 1,
            policy_digest,
            policy,
            collection_start: start,
            collection_end: end.clone(),
            baseline_end: end.clone(),
            confirmation_deadline: Deadline {
                wall_ms: 0,
                boottime_ns: 0,
            },
            baseline_id: id,
            reserved_assertion_id: Uuid::now_v7(),
            claim_version: None,
            claim_time: None,
            claim_expiry: None,
        };
        record.confirmation_deadline = deadline(
            &end,
            record.policy.quiet_window_seconds,
            record.policy.expiry_seconds,
        )?;
        if let Some(baseline) = self.baseline.take() {
            if record.semantic != baseline.semantic
                || record.context != baseline.context
                || record.invalidation != baseline.invalidation
                || record.activity != baseline.activity
                || record.mode_digest != baseline.mode_digest
                || record.policy_digest != baseline.policy_digest
                || record.policy != baseline.policy
            {
                return Err("baseline_changed");
            }
            quiet(
                &baseline.collection_end,
                &record.collection_start,
                record.policy.quiet_window_seconds,
            )?;
            let claim = self.clock.sample(&end.boot)?;
            within(
                &baseline.collection_end,
                &claim,
                &baseline.confirmation_deadline,
            )?;
            record.kind = RecordKind::OperatorAssertion;
            record.baseline_end = baseline.collection_end;
            record.confirmation_deadline = baseline.confirmation_deadline;
            record.baseline_id = baseline.baseline_id;
            record.reserved_assertion_id = baseline.reserved_assertion_id;
            record.claim_version = Some(1);
            record.claim_expiry = Some(expiry(
                &record.confirmation_deadline,
                &claim,
                record.policy.expiry_seconds,
            )?);
            record.claim_time = Some(claim);
        }
        record.validate(
            id,
            Sha256::digest(&retained.context.canonical).into(),
            record.collection_start.wall_ms,
            record.collection_end.wall_ms,
        )?;
        let captured = Captured {
            observation,
            context: Some(retained.context),
            physical: Some(retained.physical),
            budget,
            started: record.collection_start.wall_ms,
            ended: record.collection_end.wall_ms,
        };
        self.sealed = Some(SealedApproval {
            captured,
            record,
            id,
            mode,
            manifests: retained.manifests,
            local,
            clock: std::mem::take(&mut self.clock),
            #[cfg(test)]
            before_publication: None,
        });
        Ok(())
    }
    pub(super) fn failed(&mut self, reason: &'static str) {
        self.failure = Some(reason);
        self.sealed = None;
    }
}
fn entry_semantics(observation: &Observation) -> Vec<u8> {
    let mut bytes = Vec::new();
    frame(&mut bytes, 0, b"work.approval.entries.semantic.v1");
    for e in observation.entries() {
        frame(&mut bytes, 1, e.path.as_bytes());
        frame(&mut bytes, 2, &e.mode.to_be_bytes());
        frame(&mut bytes, 3, &e.length.to_be_bytes());
        frame(
            &mut bytes,
            4,
            e.content.as_ref().map_or(&[][..], |v| v.as_slice()),
        );
        frame(&mut bytes, 5, e.policy.as_deref().unwrap_or("").as_bytes());
        frame(
            &mut bytes,
            6,
            &[
                u8::from(e.tracked),
                u8::from(e.assume_unchanged),
                u8::from(e.skip_worktree),
            ],
        );
    }
    bytes
}
/// No Clone/Deserialize or public constructor. Created only by completed audit collection.
pub(super) struct SealedApproval {
    captured: Captured,
    record: ApprovalRecord,
    id: Uuid,
    mode: AdoptedMode,
    manifests: [filesystem::Manifest; 2],
    local: preservation::ApprovalLocal,
    clock: Clock,
    #[cfg(test)]
    before_publication: Option<Box<dyn FnOnce()>>,
}
impl SealedApproval {
    pub(super) fn captured(&mut self) -> &mut Captured {
        &mut self.captured
    }
    pub(super) fn id(&self) -> Uuid {
        self.id
    }
    pub(super) fn extension(&self) -> Held<Vec<u8>> {
        self.record.encode()
    }
    pub(super) fn recheck(&mut self) -> Held<()> {
        let b = &mut self.captured.budget;
        for manifest in &self.manifests {
            manifest.recheck(b).map_err(|_| "configuration_changed")?;
        }
        self.local.recheck(b)?;
        let now = self.clock.sample(&boot(b)?)?;
        elapsed(&self.record.collection_end, &now)?;
        Ok(())
    }
    pub(super) fn context_matches(&self, tx: &rusqlite::Connection, context: &Context) -> Held<()> {
        if AdoptedMode::read(tx, context)? != self.mode {
            return Err("mode_changed");
        }
        Ok(())
    }
    // CLOCK_BOOTTIME/wall only: boot was validated outside the lease in recheck.
    // No filesystem, Git, config or payload operation in this final fence.
    pub(super) fn publication_time(&mut self) -> Held<()> {
        #[cfg(test)]
        if let Some(hook) = self.before_publication.take() {
            hook();
        }
        self.captured.budget.check().map_err(|_| "deadline")?;
        let now = self.clock.sample(&self.record.collection_end.boot)?;
        elapsed(&self.record.collection_end, &now)?;
        within(
            &self.record.baseline_end,
            &now,
            self.record
                .claim_expiry
                .as_ref()
                .unwrap_or(&self.record.confirmation_deadline),
        )?;
        self.captured.budget.check().map_err(|_| "deadline")
    }
}

#[cfg(test)]
pub(super) fn collect_for_receipt_test(path: &Path, checkout: Uuid) -> (Store, SealedApproval) {
    let mut collector = Collector::new(checkout, Operation::Begin, Clock::default());
    let mut audit = preservation::Audit::new(checkout);
    let remote = remote_proof::approval_path(path, checkout, &mut audit, &mut collector);
    assert!(remote.observed(), "{}", remote.reason());
    assert!(collector.failure.is_none(), "{:?}", collector.failure);
    (
        collector.store.take().unwrap(),
        collector.sealed.take().unwrap(),
    )
}
#[cfg(test)]
use crate as work_cli_api;
#[cfg(test)]
#[path = "../../tests/support/inspection_fixture.rs"]
mod fixture;

#[cfg(test)]
mod tests {
    use super::*;
    fn collected(
        f: &fixture::ManagedFixture,
        path: &Path,
        op: Operation,
        offset_ms: u64,
    ) -> Collector {
        let mut collector = Collector::new(
            f.allocation.checkout,
            op,
            Clock {
                offset_ms,
                ..Clock::default()
            },
        );
        let mut audit = preservation::Audit::new(f.allocation.checkout);
        let remote =
            remote_proof::approval_path(path, f.allocation.checkout, &mut audit, &mut collector);
        assert!(remote.observed(), "{}", remote.reason());
        collector
    }
    #[test]
    fn actual_collector_clock_seam_expiry_and_early_without_minutes_sleep() {
        let f = fixture::ManagedFixture::new("sha1", "2");
        let (path, _) = f.approval();
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("quiet_window_seconds=1", "quiet_window_seconds=1800");
        std::fs::write(&path, text).unwrap();
        let mut first = collected(&f, &path, Operation::Begin, 0);
        let mut sealed = first.sealed.take().unwrap();
        let id = sealed.id;
        receipts::publish_approval(first.store.as_mut().unwrap(), &mut sealed).unwrap();
        let early = collected(&f, &path, Operation::Confirm { observation: id }, 0);
        assert!(early.sealed.is_none());
        assert_eq!(early.failure, Some("quiet_interval_early"));
        let expired = collected(&f, &path, Operation::Confirm { observation: id }, 1_861_000);
        assert!(expired.sealed.is_none());
        assert_eq!(expired.failure, Some("approval_expired"));
    }
    #[test]
    fn declared_closure_reconcile_writer_and_entire_context_survive_success() {
        let mut f = fixture::ManagedFixture::new("sha1", "2");
        let (path, request) = f.approval();
        let mut event = fixture::ManagedFixture::activity(&request);
        event.kind = crate::participants::ActivityKind::SessionEnd;
        f.store.record_activity(&event).unwrap();
        let status = f.store.adopted_status(&request.identity.run).unwrap();
        assert!(
            status.writer_held
                && status.reconciliation_requested
                && status.participants[0].declared_closed
        );
        let before = snapshot(&mut f.store, f.allocation.checkout, &mut Budget::new())
            .unwrap()
            .canonical;
        let first = approve_path(
            &path,
            f.allocation.checkout,
            Operation::Begin,
            Clock::default(),
        );
        assert!(first.recorded(), "{}", first.reason());
        let result = approve_path(
            &path,
            f.allocation.checkout,
            Operation::Confirm {
                observation: first.receipt_id.unwrap(),
            },
            Clock {
                offset_ms: 2000,
                ..Clock::default()
            },
        );
        assert!(result.recorded(), "{}", result.reason());
        assert_eq!(result.outcome, "operator_assertion");
        assert_eq!(
            f.store.adopted_status(&request.identity.run).unwrap(),
            status
        );
        assert_eq!(
            snapshot(&mut f.store, f.allocation.checkout, &mut Budget::new())
                .unwrap()
                .canonical,
            before
        );
    }
    #[test]
    fn clock_faults_in_actual_collector_never_publish_assertions() {
        let f = fixture::ManagedFixture::new("sha1", "2");
        let (path, _) = f.approval();
        let first = approve_path(
            &path,
            f.allocation.checkout,
            Operation::Begin,
            Clock::default(),
        );
        assert!(first.recorded(), "{}", first.reason());
        let id = first.receipt_id.unwrap();
        for fault in [
            ClockFault::Boot,
            ClockFault::WallSkew,
            ClockFault::Backwards,
        ] {
            let result = approve_path(
                &path,
                f.allocation.checkout,
                Operation::Confirm { observation: id },
                Clock {
                    offset_ms: 2000,
                    fault: Some(fault),
                },
            );
            assert!(!result.recorded());
            assert_eq!(result.reason(), "clock_anomaly");
        }
        let result = approve_path(
            &path,
            f.allocation.checkout,
            Operation::Confirm { observation: id },
            Clock {
                offset_ms: u64::MAX,
                fault: None,
            },
        );
        assert!(!result.recorded());
        assert_eq!(result.reason(), "clock_anomaly");
    }
    #[test]
    fn expiry_after_collection_cannot_publish_or_renew_the_reserved_id() {
        let f = fixture::ManagedFixture::new("sha1", "2");
        let (path, _) = f.approval();
        let mut collector = collected(&f, &path, Operation::Begin, 0);
        let mut sealed = collector.sealed.take().unwrap();
        sealed.clock.offset_ms = 62_000;
        let store = collector.store.as_mut().unwrap();
        assert_eq!(
            receipts::publish_approval(store, &mut sealed).unwrap_err(),
            ReceiptError::Conflict
        );
        assert!(matches!(
            read_receipt(store, sealed.id),
            Err(ReceiptError::Missing)
        ));
        // The failed pending remains charged; resetting a TEST clock cannot retry it.
        sealed.clock.offset_ms = 0;
        assert_eq!(
            receipts::publish_approval(store, &mut sealed).unwrap_err(),
            ReceiptError::Conflict
        );
        assert_eq!(
            std::fs::read_dir(f.temp.path().join("authority/inspection-receipts-v1"))
                .unwrap()
                .count(),
            1
        );
    }
    #[test]
    fn real_activity_cannot_commit_between_final_sql_compare_and_publication() {
        let f = fixture::ManagedFixture::new("sha1", "2");
        let (path, request) = f.approval();
        let mut collector = collected(&f, &path, Operation::Begin, 0);
        let mut sealed = collector.sealed.take().unwrap();
        let (registry, directory, root) = (
            f.temp.path().join("registry"),
            f.temp.path().join("authority"),
            f.root.clone(),
        );
        let event = fixture::ManagedFixture::activity(&request);
        let retry = event.clone();
        let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = fired.clone();
        sealed.before_publication = Some(Box::new(move || {
            let worker = std::thread::spawn(move || {
                let mut other =
                    Store::open_existing_registered_mut(&registry, &directory, &[root]).unwrap();
                assert!(other.record_activity(&event).is_err());
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            worker.join().unwrap();
        }));
        receipts::publish_approval(collector.store.as_mut().unwrap(), &mut sealed).unwrap();
        assert!(fired.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            f.store
                .adopted_status(&request.identity.run)
                .unwrap()
                .revision,
            1
        );
        assert_eq!(
            collector
                .store
                .as_mut()
                .unwrap()
                .record_activity(&retry)
                .unwrap(),
            crate::run_journal::Transition::Changed
        );
        let mut readonly = Store::open_existing_registered_readonly(
            &f.temp.path().join("registry"),
            &f.temp.path().join("authority"),
            std::slice::from_ref(&f.root),
        )
        .unwrap();
        assert!(readonly.record_activity(&retry).is_err());
    }
    #[test]
    fn original_context_config_path_and_activity_changes_refuse_retained_publication() {
        for change in ["context", "config", "path", "activity"] {
            let mut f = fixture::ManagedFixture::new("sha1", "2");
            let (path, request) = f.approval();
            let mut collector = collected(&f, &path, Operation::Begin, 0);
            let mut sealed = collector.sealed.take().unwrap();
            match change {
                "context" => {
                    f.store
                        .conn
                        .execute(
                            "UPDATE checkouts SET owner='changed' WHERE id=?1",
                            [f.allocation.checkout.to_string()],
                        )
                        .unwrap();
                }
                "config" => {
                    let bytes = std::fs::read(&path).unwrap();
                    std::fs::write(&path, bytes).unwrap();
                }
                "path" => {
                    let payload = f.path(b"tracked");
                    let bytes = std::fs::read(&payload).unwrap();
                    std::fs::rename(&payload, f.path(b"old-tracked")).unwrap();
                    std::fs::write(&payload, bytes).unwrap();
                }
                "activity" => {
                    f.store
                        .record_activity(&fixture::ManagedFixture::activity(&request))
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(
                receipts::publish_approval(collector.store.as_mut().unwrap(), &mut sealed)
                    .unwrap_err(),
                ReceiptError::Conflict,
                "{change}"
            );
        }
    }
    #[test]
    fn real_unadopted_allocation_has_no_approval_mode() {
        let mut f = fixture::ManagedFixture::new("sha1", "2");
        let authority = std::sync::Arc::clone(f.store.authority_identity());
        let phase = f.store.sql_phase();
        let tx = f
            .store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .unwrap();
        let context =
            snapshot_in_transaction(&tx, &authority, f.allocation.checkout, &mut Budget::new())
                .unwrap();
        assert!(matches!(
            AdoptedMode::read(&tx, &context),
            Err("adopted_mode_required")
        ));
        tx.rollback().unwrap();
        drop(phase);
    }
    #[test]
    fn malformed_or_mixed_mode_never_becomes_a_boolean_approval_selector() {
        for contradiction in ["malformed", "mixed", "wrong_writer"] {
            let f = fixture::ManagedFixture::new("sha1", "2");
            let (path, request) = f.approval();
            // Actual public adoption first; only negative contradictions are injected.
            match contradiction {
                "malformed" => {
                    f.store
                        .conn
                        .execute(
                            "UPDATE adopted_groups SET request='{}' WHERE id=?1",
                            [request.identity.group.to_string()],
                        )
                        .unwrap();
                }
                "mixed" => {
                    f.store.conn.execute("INSERT INTO run_groups(id,checkout,mode,revision) VALUES(?1,?2,'supervised',1)",rusqlite::params![Uuid::now_v7().to_string(),f.allocation.checkout.to_string()]).unwrap();
                }
                "wrong_writer" => {
                    f.store
                        .conn
                        .execute(
                            "UPDATE writers SET group_id=?1 WHERE checkout=?2",
                            rusqlite::params![
                                Uuid::now_v7().to_string(),
                                f.allocation.checkout.to_string()
                            ],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let result = approve_path(
                &path,
                f.allocation.checkout,
                Operation::Begin,
                Clock::default(),
            );
            assert!(!result.recorded());
            assert_eq!(
                result.reason(),
                if contradiction == "mixed" {
                    "mode_contradiction"
                } else {
                    "mode_unknown"
                }
            );
        }
    }
    #[test]
    fn v2_extension_rejects_unknown_versions_fields_duplicates_and_kind_combinations() {
        let f = fixture::ManagedFixture::new("sha1", "2");
        let (path, _) = f.approval();
        let mut collector = collected(&f, &path, Operation::Begin, 0);
        let sealed = collector.sealed.take().unwrap();
        let bytes = sealed.extension().unwrap();
        let context = Sha256::digest(&sealed.captured.context.as_ref().unwrap().canonical).into();
        let decode = |bytes: &[u8]| {
            ApprovalRecord::decode(
                bytes,
                sealed.id,
                context,
                sealed.captured.started,
                sealed.captured.ended,
            )
        };
        assert!(decode(&bytes).is_ok());
        let text = String::from_utf8(bytes).unwrap();
        for bad in [
            text.replace("\"binding_version\":1", "\"binding_version\":2"),
            text.replacen('{', "{\"unknown\":1,", 1),
            text.replacen('{', "{\"binding_version\":1,", 1),
            text.replace("approval_observation", "operator_assertion"),
            text.replace("\"claim_version\":null", "\"claim_version\":1"),
        ] {
            assert!(decode(bad.as_bytes()).is_err());
        }
    }
    #[test]
    fn returned_file_reflog_and_object_bytes_keep_semantics_but_invalidate_baseline() {
        use std::os::unix::fs::PermissionsExt;
        for kind in ["payload", "reflog", "object"] {
            let f = fixture::ManagedFixture::new("sha1", "2");
            let (path, _) = f.approval();
            let mut first = collected(&f, &path, Operation::Begin, 0);
            let mut sealed = first.sealed.take().unwrap();
            receipts::publish_approval(first.store.as_mut().unwrap(), &mut sealed).unwrap();
            let target = match kind {
                "payload" => f.path(b"tracked"),
                "reflog" => f.common().join("logs/HEAD"),
                "object" => {
                    let directory = std::fs::read_dir(f.common().join("objects"))
                        .unwrap()
                        .map(|e| e.unwrap().path())
                        .find(|p| {
                            p.is_dir() && p.file_name().unwrap().as_encoded_bytes().len() == 2
                        })
                        .unwrap();
                    std::fs::read_dir(directory)
                        .unwrap()
                        .next()
                        .unwrap()
                        .unwrap()
                        .path()
                }
                _ => unreachable!(),
            };
            let original = std::fs::read(&target).unwrap();
            let permissions = std::fs::metadata(&target).unwrap().permissions();
            if kind == "object" {
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            std::fs::write(&target, b"transient owned-fixture mutation").unwrap();
            std::fs::write(&target, original).unwrap();
            if kind == "object" {
                std::fs::set_permissions(&target, permissions).unwrap();
            }
            let mut next = collected(&f, &path, Operation::Begin, 0);
            let next = next.sealed.take().unwrap();
            assert_eq!(sealed.record.semantic, next.record.semantic, "{kind}");
            assert_ne!(
                sealed.record.invalidation, next.record.invalidation,
                "{kind}"
            );
            let result = approve_path(
                &path,
                f.allocation.checkout,
                Operation::Confirm {
                    observation: sealed.id,
                },
                Clock {
                    offset_ms: 2000,
                    ..Clock::default()
                },
            );
            assert!(!result.recorded());
            assert_eq!(result.reason(), "baseline_changed");
        }
    }
    #[test]
    fn full_endpoint_semantics_are_stable_and_activity_is_not_erased() {
        let mut f = fixture::ManagedFixture::new("sha1", "2");
        let (path, request) = f.approval();
        let mut first = collected(&f, &path, Operation::Begin, 0);
        let first = first.sealed.take().unwrap();
        let mut next = collected(&f, &path, Operation::Begin, 0);
        let next = next.sealed.take().unwrap();
        assert_eq!(first.record.semantic, next.record.semantic);
        assert_eq!(first.record.invalidation, next.record.invalidation);
        f.store
            .record_activity(&fixture::ManagedFixture::activity(&request))
            .unwrap();
        let mut changed = collected(&f, &path, Operation::Begin, 0);
        let changed = changed.sealed.take().unwrap();
        assert_ne!(first.record.invalidation, changed.record.invalidation);
        assert_ne!(first.record.mode_digest, changed.record.mode_digest);
    }
    fn stamp(ms: u64) -> ApprovalStamp {
        ApprovalStamp {
            boot: "00000000-0000-4000-8000-000000000001".into(),
            wall_ms: ms,
            low_ns: ms * 1_000_000,
            high_ns: ms * 1_000_000,
        }
    }
    #[test]
    fn quiet_uses_baseline_end_final_start_and_both_clocks() {
        let end = stamp(100_000);
        assert!(quiet(&end, &stamp(100_999), 1).is_err());
        assert!(quiet(&end, &stamp(101_000), 1).is_ok());
        let mut bad = stamp(101_000);
        bad.low_ns -= 1;
        assert!(quiet(&end, &bad, 1).is_err());
        let mut bad = stamp(101_000);
        bad.wall_ms -= 1;
        assert!(quiet(&end, &bad, 1).is_err());
    }
    #[test]
    fn boot_backward_order_skew_overflow_and_deadlines_fail_closed() {
        let base = stamp(100_000);
        for mut other in [stamp(99_999), stamp(102_001)] {
            other.low_ns = base.low_ns;
            other.high_ns = base.high_ns;
            assert!(elapsed(&base, &other).is_err());
        }
        let mut other = stamp(101_000);
        other.boot = "00000000-0000-4000-8000-000000000002".into();
        assert!(elapsed(&base, &other).is_err());
        other = stamp(101_000);
        other.high_ns = other.low_ns - 1;
        assert!(elapsed(&base, &other).is_err());
        let limit = deadline(&base, 1, 2).unwrap();
        assert!(within(&base, &stamp(102_999), &limit).is_ok());
        assert!(within(&base, &stamp(103_000), &limit).is_err());
        let claim = expiry(&limit, &stamp(102_500), 2).unwrap();
        assert_eq!(claim, limit);
        let bad = ApprovalStamp {
            wall_ms: u64::MAX,
            low_ns: u64::MAX,
            high_ns: u64::MAX,
            ..base
        };
        assert!(deadline(&bad, 1, 1).is_err());
    }
    #[test]
    fn semantic_projection_excludes_accounting_but_original_digest_does_not() {
        let policies = crate::disposal::validate(crate::disposal::PolicyDocument {
            format: 1,
            policies: vec![],
        })
        .unwrap();
        let mut b = Budget::new();
        let a = finish_observation(&policies, b"context", b"evidence", vec![], vec![], None, &b)
            .unwrap();
        b.counters.child_launches += 1;
        let z = finish_observation(&policies, b"context", b"evidence", vec![], vec![], None, &b)
            .unwrap();
        assert_ne!(a.digest(), z.digest());
        assert_eq!(entry_semantics(&a), entry_semantics(&z));
    }
}
