//! Durable supervised journal and fresh OS-proof writer handoff.
//! Unknown child hosts are barriers; recorded hosts require fresh full-roster absence.
//! No launch, task-finish or retirement authority.
use crate::{
    runtime_scope::{validate_structure, Binding, ChildIdentity, LaunchIntent, ScopeIdentity},
    store::{Result, Store, StoreError},
};
use serde::{Deserialize, Serialize};
use work_contract::{ActorId, ChainText, CheckoutId, ExecutionChain, GroupId, RunId, RunRef};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunIdentity {
    pub checkout: CheckoutId,
    pub group: GroupId,
    pub run: RunId,
    pub run_ref: RunRef,
    pub actor: ActorId,
    /// Declaration only. An external parent never grants local writer authority.
    pub parent_run_ref: Option<RunRef>,
    pub execution_chain: ExecutionChain,
}
/// An explicit declaration, never writer or launch authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum AttributionDecision {
    Off,
}
impl<'de> Deserialize<'de> for AttributionDecision {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "off" => Ok(Self::Off),
            _ => Err(serde::de::Error::unknown_variant(&value, &["off"])),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunInput {
    /// Digests only; callers must never supply raw commands, environment or prompts.
    pub command_digest: [u8; 32],
    pub input_digest: [u8; 32],
    pub context_ref: ChainText,
    pub intent_ref: ChainText,
    pub boot: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution: Option<AttributionDecision>,
}
impl<'de> Deserialize<'de> for RunInput {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de::{Error, MapAccess, SeqAccess, Visitor};
        const FIELDS: &[&str] = &[
            "command_digest",
            "input_digest",
            "context_ref",
            "intent_ref",
            "boot",
            "attribution",
        ];
        struct InputVisitor;
        impl<'de> Visitor<'de> for InputVisitor {
            type Value = RunInput;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("RunInput object or legacy five-field sequence")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<RunInput, A::Error> {
                let (
                    mut command_digest,
                    mut input_digest,
                    mut context_ref,
                    mut intent_ref,
                    mut boot,
                    mut attribution,
                ) = (None, None, None, None, None, None);
                while let Some(key) = map.next_key::<String>()? {
                    macro_rules! field {
                        ($slot:ident, $name:literal) => {{
                            if $slot.is_some() {
                                return Err(A::Error::duplicate_field($name));
                            }
                            $slot = Some(map.next_value()?);
                        }};
                    }
                    match key.as_str() {
                        "command_digest" => field!(command_digest, "command_digest"),
                        "input_digest" => field!(input_digest, "input_digest"),
                        "context_ref" => field!(context_ref, "context_ref"),
                        "intent_ref" => field!(intent_ref, "intent_ref"),
                        "boot" => field!(boot, "boot"),
                        "attribution" => field!(attribution, "attribution"),
                        _ => return Err(A::Error::unknown_field(&key, FIELDS)),
                    }
                }
                Ok(RunInput {
                    command_digest: command_digest
                        .ok_or_else(|| A::Error::missing_field("command_digest"))?,
                    input_digest: input_digest
                        .ok_or_else(|| A::Error::missing_field("input_digest"))?,
                    context_ref: context_ref
                        .ok_or_else(|| A::Error::missing_field("context_ref"))?,
                    intent_ref: intent_ref.ok_or_else(|| A::Error::missing_field("intent_ref"))?,
                    boot: boot.ok_or_else(|| A::Error::missing_field("boot"))?,
                    attribution,
                })
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<RunInput, A::Error> {
                let input = RunInput {
                    command_digest: seq
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(0, &self))?,
                    input_digest: seq
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(1, &self))?,
                    context_ref: seq
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(2, &self))?,
                    intent_ref: seq
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(3, &self))?,
                    boot: seq
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(4, &self))?,
                    attribution: None,
                };
                if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(A::Error::invalid_length(6, &self));
                }
                Ok(input)
            }
        }
        deserializer.deserialize_struct("RunInput", FIELDS, InputVisitor)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RequestWire")]
pub struct RootRunRequest {
    identity: RunIdentity,
    input: RunInput,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestWire {
    identity: RunIdentity,
    input: RunInput,
}
impl TryFrom<RequestWire> for RootRunRequest {
    type Error = StoreError;
    fn try_from(w: RequestWire) -> Result<Self> {
        Self::new(w.identity, w.input)
    }
}
impl RootRunRequest {
    pub fn new(identity: RunIdentity, input: RunInput) -> Result<Self> {
        LaunchIntent::new(identity.run.clone(), &input.boot).map_err(|_| StoreError::Invalid)?;
        if identity.run.to_string() == identity.group.to_string()
            || identity.run.to_string() == identity.checkout.to_string()
            || identity.group.to_string() == identity.checkout.to_string()
        {
            return Err(StoreError::Invalid);
        }
        Ok(Self { identity, input })
    }
    pub fn identity(&self) -> &RunIdentity {
        &self.identity
    }
    pub fn input(&self) -> &RunInput {
        &self.input
    }
}
/// Only Created may lead to a first launch. Existing always means recovery,
/// never relaunch, including after terminal outcome or an uncertain commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginRun {
    Created,
    Existing,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    Changed,
    Existing,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStage {
    Intent,
    Bound,
    PermitAttempt,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootOutcome {
    Completed,
    Failed,
    Cancelled,
}
/// Plain historical metadata. Deserialization NEVER creates a runtime Binding,
/// VerifiedEmpty token, cancellation or execution permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundSnapshot {
    pub unit: String,
    pub invocation: String,
    pub cgroup: String,
    pub boot: String,
    pub root_pid: u32,
    pub root_start_ticks: u64,
    pub root_cgroup: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    pub request: RootRunRequest,
    pub stage: RunStage,
    pub binding: Option<BoundSnapshot>,
    pub outcome: Option<RootOutcome>,
    pub recovery_hold: bool,
    pub closed: bool,
    pub revision: u64,
    pub children: Vec<crate::run_participants::ChildRecord>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalChange {
    Intent,
    Bound,
    PermitAttempt,
    RootTerminal,
    RecoveryHold,
    GroupClosed,
    ChildRegistered,
    ChildDeclaredOutcome,
    ChildHold,
    ChildEnrolled,
    ChildrenInterrupted,
    CaptureIntent,
    CapturePrepared,
    CaptureReconciled,
    CaptureGroupEnd,
}

use crate::{
    runtime_scope::ParticipantStatus,
    scope_driver::{Driver, Participant},
};
use std::time::{Duration, Instant};
const EMPTY_MAX_AGE: Duration = Duration::from_secs(2);

/// Store-validated exact root roster context. Not serializable or caller-built.
#[derive(Debug)]
pub struct GroupSnapshot {
    record: RunRecord,
}
/// Writer handoff only, bound to the exact immutable context and group revision.
/// Never task completion, quota release, deletion or retirement authorization.
#[derive(Debug)]
pub struct GroupEmptyProof {
    record: RunRecord,
    interrupted_children: Vec<RunId>,
    collected_at: Instant,
    observed_wall: std::time::SystemTime,
}
/// A non-executing candidate made only from a Store-validated group snapshot.
/// Not serializable; cannot authorize launch, cancellation, or delegation.
pub(crate) struct RecordedScopeExpectation {
    pub(crate) identity: ScopeIdentity,
    pub(crate) boot: String,
}
impl RecordedScopeExpectation {
    pub(crate) fn identity(&self) -> &ScopeIdentity {
        &self.identity
    }
    pub(crate) fn boot(&self) -> &str {
        &self.boot
    }
}
impl GroupSnapshot {
    pub fn certify_child_enrollment(
        &self,
        driver: &Driver,
        child_run: &RunId,
        controller: Option<&Binding>,
    ) -> Result<crate::run_participants::EnrollmentProof> {
        crate::run_participants::certify(&self.record, driver, child_run, controller)
    }
    /// Actual validated hosts only, never raw expected_host or a caller roster.
    /// Keep same-PID/different-start identities; exact shared hosts may dedup.
    fn closure_roster(&self, root: ChildIdentity) -> Result<Vec<Participant>> {
        use crate::run_participants::Enrollment;
        let mut identities = vec![root];
        for child in &self.record.children {
            if child.enrollment != Enrollment::Contained {
                return Err(StoreError::Invalid);
            }
            let host = &child.host.as_ref().ok_or(StoreError::Invalid)?.host;
            let identity = ChildIdentity {
                pid: host.pid,
                start_ticks: host.start_ticks,
                boot: host.boot.clone(),
                cgroup: host.cgroup.clone(),
            };
            if !identities.contains(&identity) {
                identities.push(identity);
            }
        }
        Ok(identities
            .into_iter()
            .map(|identity| Participant {
                // Candidate only, inspected twice even for declared terminal hosts.
                status: ParticipantStatus::ProvenAbsent,
                identity: Some(identity),
            })
            .collect())
    }
    fn empty_proof(&self, collected_at: Instant) -> GroupEmptyProof {
        GroupEmptyProof {
            record: self.record.clone(),
            interrupted_children: self
                .record
                .children
                .iter()
                .filter(|child| child.outcome.is_none())
                .map(|child| child.request.run.clone())
                .collect(),
            collected_at,
            observed_wall: std::time::SystemTime::now(),
        }
    }
    /// Reinspect historical full-roster metadata without restoring a Binding.
    /// The stored roster is a candidate, never an absence assertion.
    pub fn certify_historical_empty(&self, driver: &Driver) -> Result<GroupEmptyProof> {
        let r = &self.record;
        if r.closed {
            return Err(StoreError::Invalid);
        }
        let b = r.binding.as_ref().ok_or(StoreError::Invalid)?;
        let expected = RecordedScopeExpectation {
            identity: ScopeIdentity {
                unit: b.unit.clone(),
                invocation: b.invocation.clone(),
                cgroup: b.cgroup.clone(),
            },
            boot: b.boot.clone(),
        };
        let intent = LaunchIntent::new(r.request.identity.run.clone(), &r.request.input.boot)
            .map_err(|_| StoreError::Invalid)?;
        let roster = self.closure_roster(ChildIdentity {
            pid: b.root_pid,
            start_ticks: b.root_start_ticks,
            boot: b.boot.clone(),
            cgroup: b.root_cgroup.clone(),
        })?;
        let observation = driver.observe_recorded(&intent, &expected, &roster);
        crate::runtime_scope::verify_empty_evidence(
            expected.identity(),
            expected.boot(),
            &observation,
            Instant::now(),
            EMPTY_MAX_AGE,
        )
        .map_err(|_| StoreError::Invalid)?;
        Ok(self.empty_proof(observation.observed_at))
    }
    /// Collect fresh evidence using this snapshot's internally owned full host
    /// roster, never caller-supplied participant claims. Requires the original
    /// opaque Binding; historical JSON cannot restore runtime authority.
    pub fn certify_empty(&self, driver: &Driver, binding: &Binding) -> Result<GroupEmptyProof> {
        let r = &self.record;
        if r.closed || r.binding.as_ref() != Some(&BoundSnapshot::capture(&r.request, binding)?) {
            return Err(StoreError::Conflict);
        }
        let intent = LaunchIntent::new(r.request.identity.run.clone(), &r.request.input.boot)
            .map_err(|_| StoreError::Invalid)?;
        let roster = self.closure_roster(binding.trusted_child().clone())?;
        let observation = driver.observe(&intent, Some(binding), Some(&roster));
        binding
            .verify_empty(&observation, Instant::now(), EMPTY_MAX_AGE)
            .map_err(|_| StoreError::Invalid)?;
        Ok(self.empty_proof(observation.observed_at))
    }
}

use crate::{events::Event, store::emit};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use uuid::Uuid;
fn json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| StoreError::Invalid)
}
fn parse<T: serde::de::DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(|_| StoreError::Invalid)
}
fn uuid(value: &impl ToString) -> Result<Uuid> {
    Uuid::parse_str(&value.to_string()).map_err(|_| StoreError::Invalid)
}
impl BoundSnapshot {
    pub(crate) fn capture(request: &RootRunRequest, binding: &Binding) -> Result<Self> {
        let intent = LaunchIntent::new(request.identity.run.clone(), &request.input.boot)
            .map_err(|_| StoreError::Invalid)?;
        if binding.identity().unit != intent.unit_name() || binding.boot_id() != intent.boot_id() {
            return Err(StoreError::Conflict);
        }
        let child = binding.trusted_child();
        Ok(Self {
            unit: binding.identity().unit.clone(),
            invocation: binding.identity().invocation.clone(),
            cgroup: binding.identity().cgroup.clone(),
            boot: binding.boot_id().into(),
            root_pid: child.pid,
            root_start_ticks: child.start_ticks,
            root_cgroup: child.cgroup.clone(),
        })
    }
}
pub(crate) fn journal_event(
    conn: &Connection,
    request: &RootRunRequest,
    revision: u64,
    change: JournalChange,
) -> Result<()> {
    emit(
        conn,
        &Event::RunJournalChanged {
            checkout: uuid(&request.identity.checkout)?,
            group: uuid(&request.identity.group)?,
            run: uuid(&request.identity.run)?,
            revision,
            change,
        },
    )
}
const SELECT: &str = "SELECT r.request,r.stage,r.binding,r.outcome,g.recovery_hold,g.revision,
    r.id,r.group_id,r.run_ref,g.checkout,g.mode,g.closed FROM runs r LEFT JOIN run_groups g ON g.id=r.group_id";
fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<RunRecord>> {
    let request: String = row.get(0)?;
    let stage: String = row.get(1)?;
    let binding: Option<String> = row.get(2)?;
    let outcome: Option<String> = row.get(3)?;
    let hold: i64 = row.get(4)?;
    let revision: i64 = row.get(5)?;
    let run: String = row.get(6)?;
    let group: String = row.get(7)?;
    let run_ref: String = row.get(8)?;
    let checkout: String = row.get(9)?;
    let mode: String = row.get(10)?;
    let closed: i64 = row.get(11)?;
    Ok((|| {
        let request: RootRunRequest = parse(&request)?;
        let stage = match stage.as_str() {
            "intent" => RunStage::Intent,
            "bound" => RunStage::Bound,
            "permit_attempt" => RunStage::PermitAttempt,
            _ => return Err(StoreError::Invalid),
        };
        let binding: Option<BoundSnapshot> = binding.as_deref().map(parse).transpose()?;
        let outcome = outcome.as_deref().map(parse).transpose()?;
        if request.identity.run.to_string() != run
            || request.identity.group.to_string() != group
            || request.identity.checkout.to_string() != checkout
            || request.identity.run_ref.as_str() != run_ref
            || mode != "supervised"
            || !matches!(hold, 0 | 1)
            || !matches!(closed, 0 | 1)
            || (closed == 1 && (hold != 0 || binding.is_none()))
            || revision < 1
            || (stage == RunStage::Intent) != binding.is_none()
            || (outcome == Some(RootOutcome::Completed) && stage != RunStage::PermitAttempt)
        {
            return Err(StoreError::Invalid);
        }
        if let Some(b) = &binding {
            let intent = LaunchIntent::new(request.identity.run.clone(), &request.input.boot)
                .map_err(|_| StoreError::Invalid)?;
            // Plain metadata values feed the same structural checks as live
            // bind; this never reconstructs a Binding or observation/authority.
            validate_structure(
                &intent,
                &ScopeIdentity {
                    unit: b.unit.clone(),
                    invocation: b.invocation.clone(),
                    cgroup: b.cgroup.clone(),
                },
                &ChildIdentity {
                    pid: b.root_pid,
                    start_ticks: b.root_start_ticks,
                    boot: b.boot.clone(),
                    cgroup: b.root_cgroup.clone(),
                },
            )
            .map_err(|_| StoreError::Invalid)?;
        }
        Ok(RunRecord {
            request,
            stage,
            binding,
            outcome,
            recovery_hold: hold == 1,
            closed: closed == 1,
            revision: revision as u64,
            children: Vec::new(),
        })
    })())
}
fn validate_child_history(record: &RunRecord) -> Result<()> {
    use crate::run_participants::{ChildOutcome, Enrollment};
    for child in &record.children {
        if (record.closed
            && (child.enrollment != Enrollment::Contained
                || child.host.is_none()
                || child.outcome.is_none()))
            || (!record.closed && child.outcome == Some(ChildOutcome::Interrupted))
        {
            return Err(StoreError::Invalid);
        }
    }
    Ok(())
}
fn apply_interruptions(record: &mut RunRecord, ids: &[RunId]) -> Result<()> {
    use crate::run_participants::{ChildOutcome, Enrollment};
    let required = record
        .children
        .iter()
        .filter(|c| c.outcome.is_none())
        .map(|c| c.request.run.clone())
        .collect::<Vec<_>>();
    if required != ids {
        return Err(StoreError::Conflict);
    }
    for child in &mut record.children {
        if child.enrollment != Enrollment::Contained || child.host.is_none() {
            return Err(StoreError::Invalid);
        }
        if child.outcome.is_none() {
            child.outcome = Some(ChildOutcome::Interrupted);
        }
    }
    Ok(())
}
// Validated tuples never escape their read snapshot. No context is retained
// across physical I/O, mutations, or subsequent admission transactions.
pub(crate) fn with_capture_history<T>(
    conn: &Connection,
    checkout: uuid::Uuid,
    use_history: impl FnOnce(Vec<(RunRecord, crate::capture_journal::QualifiedTerminal)>) -> Result<T>,
) -> Result<T> {
    #[cfg(test)]
    use crate::capture_diagnostics::{span, Subphase};
    let _snapshot = read_transaction(conn)?;
    #[cfg(test)]
    let ids_profile = span(Subphase::HistoryIds);
    let mut stmt = conn.prepare("SELECT run FROM capture_runs WHERE checkout=?1 ORDER BY run")?;
    let ids = stmt
        .query_map([checkout.to_string()], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    #[cfg(test)]
    drop(ids_profile);
    let mut history = Vec::new();
    if ids.is_empty() {
        return use_history(history);
    }
    #[cfg(test)]
    let rosters_profile = span(Subphase::HistoryTargetRosters);
    let mut rosters = crate::run_participants::TargetRosters::read(conn, &checkout.to_string())?;
    #[cfg(test)]
    drop(rosters_profile);
    crate::capture_journal::with_qualification_batch(conn, checkout, |batch| {
        for id in ids {
            #[cfg(test)]
            let read_profile = span(Subphase::HistoryRootReadDecode);
            let run = RunId::parse(&id).map_err(|_| StoreError::Invalid)?;
            let mut root = conn
                .query_row(
                    &format!("{SELECT} WHERE r.id=?1"),
                    [run.to_string()],
                    read_row,
                )
                .optional()?
                .transpose()?
                .ok_or(StoreError::Invalid)?;
            if root.request.identity().checkout.to_string() != checkout.to_string() {
                return Err(StoreError::Invalid);
            }
            #[cfg(test)]
            drop(read_profile);
            #[cfg(test)]
            let roster_profile = span(Subphase::HistoryRoster);
            root.children = rosters.roster(conn, &root.request, root.binding.as_ref())?;
            #[cfg(test)]
            drop(roster_profile);
            #[cfg(test)]
            let child_profile = span(Subphase::HistoryChildExact);
            validate_child_history(&root)?;
            exact_record(conn, &root.request, &root)?;
            #[cfg(test)]
            drop(child_profile);
            #[cfg(test)]
            let terminal_profile = span(Subphase::HistoryTerminal);
            crate::attribution_gap::qualify_root(conn, &root.request)?;
            let tuple = batch.terminal(&root)?.ok_or(StoreError::Invalid)?;
            #[cfg(test)]
            drop(terminal_profile);
            history.push((root, tuple));
        }
        Ok(())
    })?;
    use_history(history)
}
pub(crate) fn read(conn: &Connection, run: &RunId) -> Result<Option<RunRecord>> {
    let _snapshot = read_transaction(conn)?;
    crate::attribution_gap::validate_raw(conn)?;
    let record = read_base(conn, run)?;
    if let Some(r) = &record {
        crate::attribution_gap::validate_related(conn, uuid(&r.request.identity.checkout)?)?;
        crate::capture_journal::read(conn, r)?;
    }
    Ok(record)
}
// Legacy enrollment validation must retain its authority-wide root/child
// structural checks, without parsing unrelated capture payloads. Only targeted
// readers layer capture validation on top; this is not a caller-selectable flag.
fn read_base(conn: &Connection, run: &RunId) -> Result<Option<RunRecord>> {
    // Typed domain validation is shared with admission. Historical reads must
    // not impose a smaller serialized size than previously accepted requests.
    let _snapshot = read_transaction(conn)?;
    crate::run_participants::validate_orphans(conn)?;
    let mut record = conn
        .query_row(
            &format!("{SELECT} WHERE r.id=?1"),
            [run.to_string()],
            read_row,
        )
        .optional()?
        .transpose()?;
    if let Some(r) = &mut record {
        crate::attribution_gap::qualify_presence(conn, &r.request)?;
        r.children = crate::run_participants::roster(conn, &r.request, r.binding.as_ref())?;
        validate_child_history(r)?;
    }
    Ok(record)
}
/// One snapshot-local target batch; never recursively invokes public Root reads.
pub(crate) fn gap_history(
    conn: &Connection,
    checkout: uuid::Uuid,
) -> Result<Vec<(RunRecord, Option<crate::attribution_gap::GapRecord>)>> {
    crate::gap_continuation::with_history(conn, checkout, |history| Ok(history.nodes))
}
pub(crate) fn gap_history_base(
    conn: &Connection,
    checkout: uuid::Uuid,
) -> Result<Vec<(RunRecord, Option<crate::attribution_gap::GapRecord>)>> {
    let _snapshot = read_transaction(conn)?;
    crate::attribution_gap::validate_raw(conn)?;
    let mut rosters = crate::run_participants::TargetRosters::read(conn, &checkout.to_string())?;
    let rows = conn
        .prepare(&format!("{SELECT} WHERE g.checkout=?1 ORDER BY r.id"))?
        .query_map([checkout.to_string()], read_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut history = Vec::with_capacity(rows.len());
    for row in rows {
        #[cfg(test)]
        crate::gap_continuation::decoded_node();
        let mut record = row?;
        record.children = rosters.roster(conn, &record.request, record.binding.as_ref())?;
        validate_child_history(&record)?;
        exact_record(conn, &record.request, &record)?;
        let gap = crate::attribution_gap::validated_record(conn, &record.request)?;
        history.push((record, gap));
    }
    Ok(history)
}
pub(crate) fn validate_enrollment_rosters(conn: &Connection) -> Result<()> {
    let _snapshot = read_transaction(conn)?;
    let mut rosters = crate::run_participants::TargetRosters::authority(conn)?;
    let mut stmt = conn.prepare(SELECT)?;
    let records = stmt
        .query_map([], read_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for record in records {
        let mut record = record?;
        record.children = rosters.roster(conn, &record.request, record.binding.as_ref())?;
        validate_child_history(&record)?;
        exact_record(conn, &record.request, &record)?;
        crate::attribution_gap::qualify_presence(conn, &record.request)?;
    }
    Ok(())
}
pub(crate) fn read_transaction(conn: &Connection) -> Result<Option<rusqlite::Transaction<'_>>> {
    if conn.is_autocommit() {
        Ok(Some(rusqlite::Transaction::new_unchecked(
            conn,
            TransactionBehavior::Deferred,
        )?))
    } else {
        Ok(None)
    }
}
pub(crate) fn exact(conn: &Connection, request: &RootRunRequest) -> Result<RunRecord> {
    let _snapshot = read_transaction(conn)?;
    let record = read(conn, &request.identity.run)?.ok_or(StoreError::Invalid)?;
    exact_record(conn, request, &record)?;
    Ok(record)
}
// Close-only counterpart of exact/read: retain the related qualification at
// read's existing validation point, on this actual unmutated transaction.
fn exact_for_close<'tx, 'conn>(
    tx: &'tx rusqlite::Transaction<'conn>,
    request: &RootRunRequest,
) -> Result<(
    RunRecord,
    Option<crate::gap_continuation::Related<'tx, 'conn>>,
)> {
    crate::attribution_gap::validate_raw(tx)?;
    let record = read_base(tx, &request.identity.run)?.ok_or(StoreError::Invalid)?;
    let checkout = uuid(&record.request.identity.checkout)?;
    let related = if crate::attribution_gap::raw_history(tx, checkout)? {
        Some(crate::gap_continuation::Related::qualify(tx, checkout)?)
    } else {
        None
    };
    crate::capture_journal::read(tx, &record)?;
    exact_record(tx, request, &record)?;
    Ok((record, related))
}
fn exact_record(conn: &Connection, request: &RootRunRequest, record: &RunRecord) -> Result<()> {
    if &record.request != request {
        return Err(StoreError::Conflict);
    }
    let writer: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM writers WHERE checkout=?1 AND group_id=?2)",
        (
            request.identity.checkout.to_string(),
            request.identity.group.to_string(),
        ),
        |r| r.get(0),
    )?;
    if writer == record.closed {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
impl Store {
    /// Acquires writer, records root participant intent, and appends events in
    /// ONE IMMEDIATE transaction. No OS calls occur inside it. On any error,
    /// including uncertain commit durability, recover by RunId; never launch.
    pub fn begin_run(&mut self, request: &RootRunRequest) -> Result<BeginRun> {
        let lease = self.authority_lease()?;
        self.begin_run_under_lease(request, &lease)
    }
    pub(crate) fn begin_run_under_lease(
        &mut self,
        request: &RootRunRequest,
        lease: &crate::allocate::AuthorityLease,
    ) -> Result<BeginRun> {
        lease.check(self)?;
        let authority = self.authority_identity().clone();
        let _phase = self.sql_phase();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = begin_run_tx(&tx, request, lease, &authority)?;
        tx.commit()?;
        Ok(result)
    }
    /// Historical snapshot from opaque observed Binding, never reconstructed
    /// from serialized metadata. Must commit before any permit attempt.
    pub fn record_bound(
        &mut self,
        request: &RootRunRequest,
        binding: &Binding,
    ) -> Result<Transition> {
        self.transition(
            request,
            Change::Bound(BoundSnapshot::capture(request, binding)?),
        )
    }
}
#[derive(Clone, Copy)]
pub(crate) enum WriterAdmission<'a, 'tx, 'conn> {
    Ordinary,
    Captured(
        &'a crate::capture_setup::AdmissionProof<'a>,
        &'a crate::capture_setup::Related<'tx, 'conn>,
    ),
    Gap(
        &'a crate::attribution_gap::GapAdmissionProof,
        &'a crate::gap_continuation::Related<'tx, 'conn>,
    ),
}
pub(crate) fn begin_run_tx(
    tx: &Connection,
    request: &RootRunRequest,
    lease: &crate::allocate::AuthorityLease,
    authority: &std::sync::Arc<crate::store::AuthorityIdentity>,
) -> Result<BeginRun> {
    begin_run_context(tx, request, WriterAdmission::Ordinary, lease, authority)
}
pub(crate) fn begin_run_context(
    tx: &Connection,
    request: &RootRunRequest,
    materialized: WriterAdmission<'_, '_, '_>,
    lease: &crate::allocate::AuthorityLease,
    authority: &std::sync::Arc<crate::store::AuthorityIdentity>,
) -> Result<BeginRun> {
    lease.check_authority(authority)?;
    if !matches!(materialized, WriterAdmission::Gap(_, _)) && request.input.attribution.is_some() {
        return Err(StoreError::Invalid);
    }
    if let WriterAdmission::Captured(_, related) = materialized {
        related.check(tx, uuid(&request.identity.checkout)?)?;
    } else {
        crate::capture_journal::validate_related(tx, &request.identity.checkout)?;
    }
    crate::capture_journal::exclude_operation(tx, &request.identity.run)?;
    crate::capture_journal::exclude_operation(tx, &request.identity.group)?;
    if read(tx, &request.identity.run)?.is_some() {
        exact(tx, request)?;
        return Ok(BeginRun::Existing);
    }
    if !matches!(materialized, WriterAdmission::Gap(_, _)) {
        crate::attribution_gap::validate_related(tx, uuid(&request.identity.checkout)?)?;
    }
    let i = &request.identity;
    let conflict: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM runs WHERE run_ref=?1 OR id=?2 OR group_id=?2 OR group_id=?3)
            OR EXISTS(SELECT 1 FROM run_groups WHERE id=?2 OR id=?3)
            OR EXISTS(SELECT 1 FROM checkouts WHERE id IN (?2,?3) OR operation IN (?2,?3))
            OR EXISTS(SELECT 1 FROM adopted_groups WHERE run_ref=?1 OR id IN (?2,?3) OR run_id IN (?2,?3) OR operation IN (?2,?3))
            OR EXISTS(SELECT 1 FROM writers WHERE group_id IN (?2,?3))
            OR EXISTS(SELECT 1 FROM run_participants WHERE run_ref=?1 OR id IN (?2,?3))
            OR EXISTS(SELECT 1 FROM task_finishes WHERE operation IN (?2,?3))
            ",
            (i.run_ref.as_str(), i.group.to_string(), i.run.to_string()), |r| r.get(0))?;
    if conflict {
        return Err(StoreError::Conflict);
    }
    crate::store::acquire_writer_context(
        tx,
        uuid(&i.checkout)?,
        uuid(&i.group)?,
        false,
        materialized,
        lease,
        authority,
    )?;
    tx.execute(
        "INSERT INTO run_groups(id,checkout,mode,revision) VALUES(?1,?2,'supervised',1)",
        (i.group.to_string(), i.checkout.to_string()),
    )?;
    tx.execute(
        "INSERT INTO runs(id,group_id,run_ref,request,stage) VALUES(?1,?2,?3,?4,'intent')",
        (
            i.run.to_string(),
            i.group.to_string(),
            i.run_ref.as_str(),
            match materialized {
                WriterAdmission::Gap(proof, _) => proof.request_bytes(request)?.to_owned(),
                _ => json(request)?,
            },
        ),
    )?;
    journal_event(tx, request, 1, JournalChange::Intent)?;
    Ok(BeginRun::Created)
}
impl Store {
    /// Commit BEFORE publishing a gate. This records a potentially launched run,
    /// NOT proof of exec. A failed/uncertain fsync may still leave launch possible.
    /// Callers must separately revalidate the runtime binding at publication.
    pub fn record_permit_attempt(
        &mut self,
        request: &RootRunRequest,
        binding: &Binding,
    ) -> Result<Transition> {
        self.transition(
            request,
            Change::Permit(BoundSnapshot::capture(request, binding)?),
        )
    }
    /// Root participant only. Never closes descendants or releases authority.
    pub fn record_root_outcome(
        &mut self,
        request: &RootRunRequest,
        outcome: RootOutcome,
    ) -> Result<Transition> {
        self.transition(request, Change::Outcome(outcome))
    }
    pub fn record_recovery_hold(&mut self, request: &RootRunRequest) -> Result<Transition> {
        self.transition(request, Change::Hold)
    }
    pub fn run_snapshot(&self, run: &RunId) -> Result<Option<RunRecord>> {
        let _phase = self.sql_phase();
        let _snapshot = read_transaction(&self.conn)?;
        let record = read(&self.conn, run)?;
        if let Some(record) = &record {
            crate::capture_journal::validate_related(
                &self.conn,
                &record.request.identity.checkout,
            )?;
        }
        Ok(record)
    }
    pub(crate) fn run_status_record(&self, run: &RunId) -> Result<(RunRecord, bool, bool)> {
        let _phase = self.sql_phase();
        let _snapshot = read_transaction(&self.conn)?;
        let record = read(&self.conn, run)?.ok_or(StoreError::Invalid)?;
        crate::capture_journal::validate_related(&self.conn, &record.request.identity.checkout)?;
        exact_record(&self.conn, &record.request, &record)?;
        let state: String = self.conn.query_row(
            "SELECT CASE WHEN length(state)<=32 THEN state ELSE '' END FROM checkouts WHERE id=?1",
            [record.request.identity.checkout.to_string()],
            |r| r.get(0),
        )?;
        if !matches!(
            state.as_str(),
            "reserved"
                | "partial"
                | "active"
                | "expired"
                | "interrupted"
                | "held"
                | "quarantined"
                | "partially_deleted"
                | "retired"
        ) {
            return Err(StoreError::Invalid);
        }
        let task_open =
            crate::finish::task_open(&self.conn, uuid(&record.request.identity.checkout)?)?;
        Ok((record, state != "retired", task_open))
    }
    /// Only unresolved groups; closed roots remain historical receipts.
    /// No heartbeat/reboot inference, no reconstructed runtime authority.
    pub fn recovery_runs(&self) -> Result<Vec<RunRecord>> {
        let _phase = self.sql_phase();
        let _snapshot = read_transaction(&self.conn)?;
        crate::run_participants::validate_orphans(&self.conn)?;
        let mut stmt = self.conn.prepare(&format!("{SELECT} ORDER BY r.rowid"))?;
        let rows = stmt.query_map([], read_row)?;
        // Validate historical receipts too: a malformed closed flag must never
        // hide corrupt bound/hold metadata from recovery.
        let mut records = rows
            .map(|r| r.map_err(StoreError::from).and_then(|v| v))
            .collect::<Result<Vec<_>>>()?;
        crate::attribution_gap::validate_raw(&self.conn)?;
        let mut checkouts = std::collections::BTreeSet::new();
        for record in &mut records {
            crate::attribution_gap::qualify_root(&self.conn, &record.request)?;
            record.children = crate::run_participants::roster(
                &self.conn,
                &record.request,
                record.binding.as_ref(),
            )?;
            validate_child_history(record)?;
            checkouts.insert(uuid(&record.request.identity.checkout)?);
        }
        // Closed receipts retain cursor/Q/claim obligations. Validate each
        // related checkout once in this snapshot, before filtering, without
        // recursive public Root reads or decoding unrelated capture payloads.
        for checkout in checkouts {
            crate::attribution_gap::validate_related(&self.conn, checkout)?;
        }
        records.retain(|record| !record.closed);
        Ok(records)
    }
    /// Exact root and complete child ledger, pinned to one SQLite snapshot.
    pub fn group_snapshot(&self, run: &RunId) -> Result<GroupSnapshot> {
        let _phase = self.sql_phase();
        let _snapshot = read_transaction(&self.conn)?;
        let record = read(&self.conn, run)?.ok_or(StoreError::Invalid)?;
        crate::capture_journal::validate_related(&self.conn, &record.request.identity.checkout)?;
        let record = exact(&self.conn, &record.request)?;
        if record.closed || record.binding.is_none() {
            return Err(StoreError::Invalid);
        }
        Ok(GroupSnapshot { record })
    }
    /// Atomically interrupt proven-lost open children, close this group and release only
    /// its writer. Revalidate freshness after the IMMEDIATE lock. Identical
    /// terminal retries acknowledge metadata without consuming a new writer;
    /// Existing is never execution permission. Checkout accounting is untouched.
    pub fn close_supervised_group(
        &mut self,
        snapshot: &GroupSnapshot,
        proof: &GroupEmptyProof,
    ) -> Result<Transition> {
        self.close_supervised_group_context(snapshot, proof, None)
            .map(|(transition, _)| transition)
    }
    pub(crate) fn close_supervised_group_context(
        &mut self,
        snapshot: &GroupSnapshot,
        proof: &GroupEmptyProof,
        live: Option<&crate::capture_preparation::LiveCapture>,
    ) -> Result<(Transition, Option<crate::capture_readiness::ClosureSeal>)> {
        let lease = self.authority_lease()?;
        self.close_supervised_group_context_under_lease(snapshot, proof, live, &lease)
    }
    pub(crate) fn close_supervised_group_context_under_lease(
        &mut self,
        snapshot: &GroupSnapshot,
        proof: &GroupEmptyProof,
        live: Option<&crate::capture_preparation::LiveCapture>,
        lease: &crate::allocate::AuthorityLease,
    ) -> Result<(Transition, Option<crate::capture_readiness::ClosureSeal>)> {
        let mode = live.map_or(CloseMode::Ordinary, CloseMode::Captured);
        let result = self.close_mode_under_lease(snapshot, proof, mode, lease)?;
        Ok((result.transition, result.capture_seal))
    }
    pub(crate) fn close_live_gap(
        &mut self,
        snapshot: &GroupSnapshot,
        proof: &GroupEmptyProof,
        live: &crate::attribution_gap::CreatedOffLive,
    ) -> Result<(Transition, Option<crate::gap_continuation::GapClosureSeal>)> {
        let lease = self.authority_lease()?;
        self.close_live_gap_under_lease(snapshot, proof, live, &lease)
    }
    pub(crate) fn close_live_gap_under_lease(
        &mut self,
        snapshot: &GroupSnapshot,
        proof: &GroupEmptyProof,
        live: &crate::attribution_gap::CreatedOffLive,
        lease: &crate::allocate::AuthorityLease,
    ) -> Result<(Transition, Option<crate::gap_continuation::GapClosureSeal>)> {
        let result = self.close_mode_under_lease(snapshot, proof, CloseMode::Gap(live), lease)?;
        Ok((result.transition, result.gap_seal))
    }
    fn close_mode_under_lease(
        &mut self,
        snapshot: &GroupSnapshot,
        proof: &GroupEmptyProof,
        mode: CloseMode<'_>,
        lease: &crate::allocate::AuthorityLease,
    ) -> Result<CloseResult> {
        #[cfg(test)]
        let _counts = CloseHistorySample::start();
        lease.check(self)?;
        let authority = self.authority_identity().clone();
        let _phase = self.sql_phase();
        if snapshot.record != proof.record {
            return Err(StoreError::Conflict);
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let expected = &snapshot.record;
        crate::capture_journal::validate_related(&tx, &expected.request.identity.checkout)?;
        let (current, related) = exact_for_close(&tx, &expected.request)?;
        let revision = expected
            .revision
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(StoreError::Invalid)?;
        if current.closed {
            let mut receipt = expected.clone();
            receipt.closed = true;
            receipt.recovery_hold = false;
            receipt.revision = revision;
            apply_interruptions(&mut receipt, &proof.interrupted_children)?;
            return if current == receipt {
                Ok(CloseResult {
                    transition: Transition::Existing,
                    capture_seal: None,
                    gap_seal: None,
                })
            } else {
                Err(StoreError::Conflict)
            };
        }
        // Revalidate AFTER acquiring the database writer lock; waiting may have
        // consumed the entire proof lifetime or allowed journal activity.
        if &current != expected
            || Instant::now()
                .checked_duration_since(proof.collected_at)
                .is_none_or(|age| age > EMPTY_MAX_AGE)
        {
            return Err(StoreError::Conflict);
        }
        let live = match mode {
            CloseMode::Captured(live) => Some(live),
            _ => None,
        };
        let gap_live = match mode {
            CloseMode::Gap(live) => Some(live),
            _ => None,
        };
        let classification = if let Some(related) = related {
            crate::gap_continuation::before_close_related(
                &tx, related, &current, gap_live, &authority,
            )?
        } else {
            crate::gap_continuation::before_close(&tx, &current, gap_live, &authority)?
        };
        let required = classification.required();
        let seal_eligible = live.is_some()
            && crate::capture_readiness::before_close(&tx, &current).unwrap_or(false);
        let mut receipt = expected.clone();
        apply_interruptions(&mut receipt, &proof.interrupted_children)?;
        for run in &proof.interrupted_children {
            let updated = tx.execute(
                "UPDATE run_participants SET outcome=?2 WHERE id=?1 AND group_id=?3 AND enrollment='contained' AND outcome IS NULL",
                (run.to_string(), json(&crate::run_participants::ChildOutcome::Interrupted)?, expected.request.identity.group.to_string()),
            )?;
            if updated != 1 {
                return Err(StoreError::Conflict);
            }
        }
        if !proof.interrupted_children.is_empty() {
            journal_event(
                &tx,
                &expected.request,
                revision,
                JournalChange::ChildrenInterrupted,
            )?;
        }
        crate::capture_journal::observe_group_end(
            &tx,
            &current,
            proof.observed_wall,
            lease,
            &authority,
        )?;
        // Child updates/outbox work consume the original evidence window too.
        if Instant::now()
            .checked_duration_since(proof.collected_at)
            .is_none_or(|age| age > EMPTY_MAX_AGE)
        {
            return Err(StoreError::Conflict);
        }
        let i = &expected.request.identity;
        let removed = tx.execute(
            "DELETE FROM writers WHERE checkout=?1 AND group_id=?2",
            (i.checkout.to_string(), i.group.to_string()),
        )?;
        if removed != 1 {
            return Err(StoreError::Conflict);
        }
        tx.execute(
            "UPDATE run_groups SET closed=1,recovery_hold=0,revision=?2 WHERE id=?1",
            (i.group.to_string(), revision as i64),
        )?;
        journal_event(&tx, &expected.request, revision, JournalChange::GroupClosed)?;
        if required {
            tx.execute("UPDATE checkouts SET state='held',ready=0 WHERE id=?1 AND state IN ('active','partial','held') AND NOT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1)", [i.checkout.to_string()])?;
        }
        receipt.closed = true;
        receipt.recovery_hold = false;
        receipt.revision = revision;
        let gap_seal = crate::gap_continuation::after_changed_close(
            &tx,
            &authority,
            lease,
            &receipt,
            classification,
        )?;
        // Validate only after child/writer/group/checkout/cursor writes form a
        // coherent graph. Never inspect closed+unavailable between writes.
        crate::attribution_gap::validate_related(&tx, uuid(&i.checkout)?)?;
        // Capture eligibility never vetoes proven physical closure. Only this
        // Changed transaction can seal its exact post-close context.
        let seal = if seal_eligible {
            live.and_then(|live| {
                crate::capture_readiness::closed(&tx, &expected.request, live).ok()
            })
        } else {
            None
        };
        if Instant::now()
            .checked_duration_since(proof.collected_at)
            .is_none_or(|age| age > EMPTY_MAX_AGE)
        {
            return Err(StoreError::Conflict);
        }
        tx.commit()?;
        Ok(CloseResult {
            transition: Transition::Changed,
            capture_seal: seal,
            gap_seal,
        })
    }
    fn transition(&mut self, request: &RootRunRequest, change: Change) -> Result<Transition> {
        let lease = self.authority_lease()?;
        self.transition_under_lease(request, change, &lease)
    }
    fn transition_under_lease(
        &mut self,
        request: &RootRunRequest,
        change: Change,
        lease: &crate::allocate::AuthorityLease,
    ) -> Result<Transition> {
        lease.check(self)?;
        let authority = self.authority_identity().clone();
        let _phase = self.sql_phase();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = exact(&tx, request)?;
        if record.closed {
            return Err(StoreError::Invalid);
        }
        if matches!(change, Change::Bound(_) | Change::Permit(_)) {
            if let Some(capture) = crate::capture_journal::read(&tx, &record)? {
                let eligible: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 AND state='active' AND ready=1) AND NOT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1)",[request.identity.checkout.to_string()],|r|r.get(0))?;
                if !eligible
                    || record.recovery_hold
                    || record.outcome.is_some()
                    || !capture.prepared.is_some_and(|p| p.live_preparation)
                {
                    return Err(StoreError::Invalid);
                }
            }
        }
        let run = request.identity.run.to_string();
        let group = request.identity.group.to_string();
        let kind = match change {
            Change::Bound(snapshot) => {
                if let Some(existing) = &record.binding {
                    return if existing == &snapshot {
                        Ok(Transition::Existing)
                    } else {
                        Err(StoreError::Conflict)
                    };
                }
                if record.stage != RunStage::Intent
                    || record.outcome.is_some()
                    || record.recovery_hold
                {
                    return Err(StoreError::Invalid);
                }
                tx.execute(
                    "UPDATE runs SET stage='bound',binding=?2 WHERE id=?1",
                    (&run, json(&snapshot)?),
                )?;
                JournalChange::Bound
            }
            Change::Permit(snapshot) => {
                if record.binding.as_ref() != Some(&snapshot) {
                    return Err(StoreError::Conflict);
                }
                if record.stage == RunStage::PermitAttempt {
                    return Ok(Transition::Existing);
                }
                if record.stage != RunStage::Bound
                    || record.outcome.is_some()
                    || record.recovery_hold
                {
                    return Err(StoreError::Invalid);
                }
                tx.execute("UPDATE runs SET stage='permit_attempt' WHERE id=?1", [&run])?;
                JournalChange::PermitAttempt
            }
            Change::Outcome(outcome) => {
                if let Some(existing) = record.outcome {
                    return if existing == outcome {
                        Ok(Transition::Existing)
                    } else {
                        Err(StoreError::Conflict)
                    };
                }
                if outcome == RootOutcome::Completed && record.stage != RunStage::PermitAttempt {
                    return Err(StoreError::Invalid);
                }
                tx.execute(
                    "UPDATE runs SET outcome=?2 WHERE id=?1",
                    (&run, json(&outcome)?),
                )?;
                JournalChange::RootTerminal
            }
            Change::Hold => {
                if record.recovery_hold {
                    return Ok(Transition::Existing);
                }
                crate::gap_continuation::revoke(
                    &tx,
                    &authority,
                    lease,
                    uuid(&request.identity.checkout)?,
                )?;
                tx.execute(
                    "UPDATE run_groups SET recovery_hold=1 WHERE id=?1",
                    [&group],
                )?;
                JournalChange::RecoveryHold
            }
        };
        let revision = record
            .revision
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(StoreError::Invalid)?;
        tx.execute(
            "UPDATE run_groups SET revision=?2 WHERE id=?1",
            (&group, revision as i64),
        )?;
        journal_event(&tx, request, revision, kind)?;
        tx.commit()?;
        Ok(Transition::Changed)
    }
}
#[cfg(test)]
type CloseHistoryCounts = (usize, usize, usize, usize);
#[cfg(test)]
thread_local! {
    static CLOSE_HISTORY_COUNTS: std::cell::RefCell<Option<Vec<CloseHistoryCounts>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(crate) struct CloseHistoryCounter;
#[cfg(test)]
impl CloseHistoryCounter {
    pub(crate) fn new() -> Self {
        CLOSE_HISTORY_COUNTS.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(Vec::new());
        });
        Self
    }
    pub(crate) fn take(&self) -> Vec<CloseHistoryCounts> {
        CLOSE_HISTORY_COUNTS.with(|slot| std::mem::take(slot.borrow_mut().as_mut().unwrap()))
    }
}
#[cfg(test)]
impl Drop for CloseHistoryCounter {
    fn drop(&mut self) {
        CLOSE_HISTORY_COUNTS.with(|slot| *slot.borrow_mut() = None);
    }
}
#[cfg(test)]
struct CloseHistorySample(bool);
#[cfg(test)]
impl CloseHistorySample {
    fn start() -> Self {
        let enabled = CLOSE_HISTORY_COUNTS.with(|slot| slot.borrow().is_some());
        if enabled {
            crate::gap_continuation::take_history_counts();
        }
        Self(enabled)
    }
}
#[cfg(test)]
impl Drop for CloseHistorySample {
    fn drop(&mut self) {
        if self.0 {
            let counts = crate::gap_continuation::take_history_counts();
            CLOSE_HISTORY_COUNTS.with(|slot| slot.borrow_mut().as_mut().unwrap().push(counts));
        }
    }
}

enum CloseMode<'a> {
    Ordinary,
    Captured(&'a crate::capture_preparation::LiveCapture),
    Gap(&'a crate::attribution_gap::CreatedOffLive),
}
struct CloseResult {
    transition: Transition,
    capture_seal: Option<crate::capture_readiness::ClosureSeal>,
    gap_seal: Option<crate::gap_continuation::GapClosureSeal>,
}

enum Change {
    Bound(BoundSnapshot),
    Permit(BoundSnapshot),
    Outcome(RootOutcome),
    Hold,
}
