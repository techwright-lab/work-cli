//! Supervised child declarations. These grant no launch, writer or OS authority.
//! Positive enrollment is historical host metadata only, never fresh absence.
#[cfg(test)]
#[path = "run_enrollment_tests.rs"]
mod enrollment_tests;
#[cfg(test)]
#[path = "run_participants_tests.rs"]
mod tests;
use crate::{
    participants::Ref,
    run_journal::{BeginRun, RootRunRequest, Transition},
    store::{Result, Store, StoreError},
};
use serde::{Deserialize, Serialize};
use work_contract::{ActorId, CheckoutId, ExecutionChain, GroupId, RunId, RunRef};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedHost {
    pub boot: String,
    pub pid: u32,
    pub start_ticks: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildRequest {
    pub checkout: CheckoutId,
    pub group: GroupId,
    pub run: RunId,
    pub run_ref: RunRef,
    pub parent_run: RunId,
    pub parent_run_ref: RunRef,
    pub execution_chain: ExecutionChain,
    pub source: Option<Ref>,
    pub session: Option<Ref>,
    pub agent: Option<Ref>,
    /// Declaration only, not process-proven individual authorship.
    pub actor: Option<ActorId>,
    pub expected_host: Option<ExpectedHost>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enrollment {
    Pending,
    Contained,
    Unverified,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildOutcome {
    Completed,
    Failed,
    Cancelled,
    /// Kernel-confirmed host loss, writable only by atomic whole-group closure.
    Interrupted,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildRecord {
    pub request: ChildRequest,
    pub enrollment: Enrollment,
    pub outcome: Option<ChildOutcome>,
    pub depth: u8,
    pub host: Option<EnrollmentRecord>,
}
/// Plain historical host metadata; never current containment or runtime authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSnapshot {
    pub pid: u32,
    pub start_ticks: u64,
    pub boot: String,
    pub cgroup: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRecord {
    pub root: crate::run_journal::BoundSnapshot,
    pub host: HostSnapshot,
}
/// Exact snapshot and earliest observation, nonserializable and privately built.
/// Serialized metadata cannot manufacture a proof:
/// ```compile_fail
/// let _: work_cli::run_participants::EnrollmentProof = serde_json::from_str("{}").unwrap();
/// ```
/// Nor can a plain host snapshot be committed as evidence:
/// ```compile_fail
/// fn forged(store: &mut work_cli::store::Store, root: &work_cli::run_journal::RootRunRequest,
///     child: &work_cli::run_participants::ChildRequest, host: &work_cli::run_participants::HostSnapshot) {
///     store.record_child_enrollment(root, child, host);
/// }
/// ```
#[derive(Debug)]
pub struct EnrollmentProof {
    record: crate::run_journal::RunRecord,
    child: ChildRequest,
    enrollment: EnrollmentRecord,
    observed_at: std::time::Instant,
}

fn validate_host(
    root: &RootRunRequest,
    binding: Option<&crate::run_journal::BoundSnapshot>,
    child: &ChildRequest,
    enrollment: &EnrollmentRecord,
) -> Result<()> {
    use crate::runtime_scope::{validate_structure, ChildIdentity, LaunchIntent, ScopeIdentity};
    let b = binding.ok_or(StoreError::Invalid)?;
    let host = &enrollment.host;
    let expected = child.expected_host.as_ref().ok_or(StoreError::Invalid)?;
    if &enrollment.root != b
        || host.pid != expected.pid
        || host.start_ticks != expected.start_ticks
        || host.boot != expected.boot
        || (host.pid == b.root_pid
            && (host.start_ticks != b.root_start_ticks
                || host.boot != b.boot
                || host.cgroup != b.root_cgroup))
    {
        return Err(StoreError::Invalid);
    }
    let intent = LaunchIntent::new(root.identity().run.clone(), &root.input().boot)
        .map_err(|_| StoreError::Invalid)?;
    validate_structure(
        &intent,
        &ScopeIdentity {
            unit: b.unit.clone(),
            invocation: b.invocation.clone(),
            cgroup: b.cgroup.clone(),
        },
        &ChildIdentity {
            pid: host.pid,
            start_ticks: host.start_ticks,
            boot: host.boot.clone(),
            cgroup: host.cgroup.clone(),
        },
    )
    .map_err(|_| StoreError::Invalid)
}

pub(crate) fn certify(
    record: &crate::run_journal::RunRecord,
    driver: &crate::scope_driver::Driver,
    run: &RunId,
    controller: Option<&crate::runtime_scope::Binding>,
) -> Result<EnrollmentProof> {
    use crate::{
        run_journal::{BoundSnapshot, RecordedScopeExpectation, RunStage},
        runtime_scope::{LaunchIntent, ParticipantStatus, ScopeIdentity},
        scope_driver::Participant,
    };
    let began = std::time::Instant::now();
    if record.closed || record.stage != RunStage::PermitAttempt {
        return Err(StoreError::Invalid);
    }
    let child = record
        .children
        .iter()
        .find(|c| &c.request.run == run)
        .ok_or(StoreError::Invalid)?;
    if child.enrollment != Enrollment::Pending {
        return Err(StoreError::Invalid);
    }
    let expected_host = child
        .request
        .expected_host
        .as_ref()
        .ok_or(StoreError::Invalid)?;
    let b = record.binding.as_ref().ok_or(StoreError::Invalid)?;
    if let Some(controller) = controller {
        if BoundSnapshot::capture(&record.request, controller)?.ne(b) {
            return Err(StoreError::Conflict);
        }
    }
    let expected = RecordedScopeExpectation {
        identity: ScopeIdentity {
            unit: b.unit.clone(),
            invocation: b.invocation.clone(),
            cgroup: b.cgroup.clone(),
        },
        boot: b.boot.clone(),
    };
    let intent = LaunchIntent::new(
        record.request.identity().run.clone(),
        &record.request.input().boot,
    )
    .map_err(|_| StoreError::Invalid)?;
    let mut budget = driver.enrollment_budget(began);
    let host = driver
        .identify_with(expected_host.pid, &mut budget)
        .map_err(|_| StoreError::Invalid)?;
    // Preserve the immutable original root identity even when it is not observed.
    let enrollment = EnrollmentRecord {
        root: b.clone(),
        host: HostSnapshot {
            pid: host.pid,
            start_ticks: host.start_ticks,
            boot: host.boot.clone(),
            cgroup: host.cgroup.clone(),
        },
    };
    validate_host(&record.request, Some(b), &child.request, &enrollment)?;
    let mut identities = vec![host.clone()];
    if controller.is_none() && host.pid != std::process::id() {
        let registrar = driver
            .identify_with(std::process::id(), &mut budget)
            .map_err(|_| StoreError::Invalid)?;
        add_identity(&mut identities, registrar)?;
    }
    let roster = identities
        .iter()
        .map(|i| Participant {
            status: ParticipantStatus::Open,
            identity: Some(i.clone()),
        })
        .collect::<Vec<_>>();
    let mut obs = driver.observe_recorded_with(&intent, &expected, &roster, &mut budget);
    obs.observed_at = began; // Includes identification, never refreshed at census completion.
    let validated = crate::runtime_scope::validate_enrollment_host(
        &intent,
        expected.identity(),
        expected_host,
        &host,
        &identities,
        &obs,
        std::time::Instant::now(),
        std::time::Duration::from_secs(2),
    )
    .map_err(|_| StoreError::Invalid)?;
    let h = validated.host;
    Ok(EnrollmentProof {
        record: record.clone(),
        child: child.request.clone(),
        enrollment: EnrollmentRecord {
            root: b.clone(),
            host: HostSnapshot {
                pid: h.pid,
                start_ticks: h.start_ticks,
                boot: h.boot,
                cgroup: h.cgroup,
            },
        },
        observed_at: validated.observed_at,
    })
}
fn add_identity(
    identities: &mut Vec<crate::runtime_scope::ChildIdentity>,
    identity: crate::runtime_scope::ChildIdentity,
) -> Result<()> {
    if let Some(existing) = identities.iter().find(|i| i.pid == identity.pid) {
        if existing != &identity {
            return Err(StoreError::Conflict);
        }
    } else {
        identities.push(identity);
    }
    Ok(())
}
impl ChildRequest {
    fn validate(&self) -> Result<()> {
        if self.run == self.parent_run
            || self.run_ref == self.parent_run_ref
            || self.run.to_string() == self.group.to_string()
            || self.run.to_string() == self.checkout.to_string()
        {
            return Err(StoreError::Invalid);
        }
        if let Some(host) = &self.expected_host {
            crate::runtime_scope::LaunchIntent::new(self.run.clone(), &host.boot)
                .map_err(|_| StoreError::Invalid)?;
            if host.pid == 0 || host.pid > i32::MAX as u32 || host.start_ticks == 0 {
                return Err(StoreError::Invalid);
            }
        }
        Ok(())
    }
}
pub(crate) fn validate_schema(conn: &rusqlite::Connection) -> Result<()> {
    validate_schema_version(conn, true)
}
pub(crate) fn validate_v7_schema(conn: &rusqlite::Connection) -> Result<()> {
    validate_schema_version(conn, false)
}
fn validate_schema_version(conn: &rusqlite::Connection, contained: bool) -> Result<()> {
    let definition: String = conn.query_row(
        "SELECT sql FROM sqlite_schema WHERE name='run_participants' AND type='table'",
        [],
        |r| r.get(0),
    )?;
    let compact: String = definition
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '"')
        .collect();
    let enrollment = if contained {
        "CHECK(enrollmentIN('pending','contained','unverified'))"
    } else {
        "CHECK(enrollmentIN('pending','unverified'))"
    };
    if contained && !compact.contains("CHECK((enrollment='pending'ANDhostISNULL)OR(enrollment='contained'ANDhostISNOTNULL)ORenrollment='unverified')") { return Err(StoreError::Invalid); }
    for constraint in [
        "idTEXTPRIMARYKEY",
        "group_idTEXTNOTNULLREFERENCESrun_groups(id)",
        "run_refTEXTNOTNULLUNIQUE",
        "parent_runTEXTNOTNULL",
        "requestTEXTNOTNULL",
        "enrollmentTEXTNOTNULL",
        enrollment,
        "depthINTEGERNOTNULLCHECK(depthBETWEEN1AND16)",
    ] {
        if !compact.contains(constraint) {
            return Err(StoreError::Invalid);
        }
    }
    let mut stmt = conn.prepare("PRAGMA table_info(run_participants)")?;
    let columns = stmt
        .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let expected = [
        ("id", "TEXT"),
        ("group_id", "TEXT"),
        ("run_ref", "TEXT"),
        ("parent_run", "TEXT"),
        ("request", "TEXT"),
        ("enrollment", "TEXT"),
        ("outcome", "TEXT"),
        ("depth", "INTEGER"),
        ("host", "TEXT"),
    ];
    let expected = &expected[..if contained { 9 } else { 8 }];
    if columns.len() != expected.len()
        || columns
            .iter()
            .zip(expected)
            .any(|((name, ty), (e, t))| name != e || ty != t)
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
pub(crate) fn validate_orphans(conn: &rusqlite::Connection) -> Result<()> {
    validate_schema(conn)?;
    let invalid: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM run_participants p LEFT JOIN run_groups g ON g.id=p.group_id LEFT JOIN runs r ON r.group_id=p.group_id WHERE g.id IS NULL OR r.id IS NULL OR g.mode!='supervised')", [], |r| r.get(0))?;
    if invalid {
        Err(StoreError::Invalid)
    } else {
        Ok(())
    }
}
fn namespace_conflict(conn: &rusqlite::Connection, request: &ChildRequest) -> Result<bool> {
    if crate::finish::operation_reserved(conn, &request.run.to_string())?
        || crate::capture_journal::operation_reserved(conn, &request.run.to_string())?
    {
        return Ok(true);
    }
    conn.query_row("SELECT
        EXISTS(SELECT 1 FROM runs WHERE id=?1 OR group_id=?1 OR run_ref=?2)
        OR EXISTS(SELECT 1 FROM run_groups WHERE id=?1)
        OR EXISTS(SELECT 1 FROM adopted_groups WHERE id=?1 OR run_id=?1 OR operation=?1 OR run_ref=?2)
        OR EXISTS(SELECT 1 FROM checkouts WHERE id=?1 OR operation=?1)
        OR EXISTS(SELECT 1 FROM writers WHERE group_id=?1)
        OR EXISTS(SELECT 1 FROM run_participants WHERE id!=?1 AND run_ref=?2)",
        (request.run.to_string(), request.run_ref.as_str()), |r| r.get(0)).map_err(StoreError::from)
}
pub(crate) fn roster(
    conn: &rusqlite::Connection,
    root: &RootRunRequest,
    binding: Option<&crate::run_journal::BoundSnapshot>,
) -> Result<Vec<ChildRecord>> {
    validate_orphans(conn)?;
    let count: i64 = conn.query_row(
        "SELECT child_count FROM run_groups WHERE id=?1",
        [root.identity().group.to_string()],
        |r| r.get(0),
    )?;
    let mut stmt = conn.prepare("SELECT id,group_id,run_ref,parent_run,request,enrollment,outcome,depth,host FROM run_participants WHERE group_id=?1 ORDER BY rowid LIMIT 257")?;
    let mut rows = stmt.query([root.identity().group.to_string()])?;
    let mut records = Vec::new();
    while let Some(row) = rows.next()? {
        let body: String = row.get(4)?;
        let request: ChildRequest = serde_json::from_str(&body).map_err(|_| StoreError::Invalid)?;
        request.validate()?;
        let state: String = row.get(5)?;
        let enrollment = match state.as_str() {
            "pending" => Enrollment::Pending,
            "contained" => Enrollment::Contained,
            "unverified" => Enrollment::Unverified,
            _ => return Err(StoreError::Invalid),
        };
        let host: Option<String> = row.get(8)?;
        let host: Option<EnrollmentRecord> = host
            .map(|s| serde_json::from_str(&s).map_err(|_| StoreError::Invalid))
            .transpose()?;
        if (enrollment == Enrollment::Pending && host.is_some())
            || (enrollment == Enrollment::Contained && host.is_none())
        {
            return Err(StoreError::Invalid);
        }
        if let Some(host) = &host {
            validate_host(root, binding, &request, host)?;
        }
        let outcome: Option<String> = row.get(6)?;
        let outcome = outcome
            .map(|s| serde_json::from_str(&s).map_err(|_| StoreError::Invalid))
            .transpose()?;
        if request.run.to_string() != row.get::<_, String>(0)?
            || request.group.to_string() != row.get::<_, String>(1)?
            || request.run_ref.as_str() != row.get::<_, String>(2)?
            || request.parent_run.to_string() != row.get::<_, String>(3)?
            || request.checkout != root.identity().checkout
            || request.group != root.identity().group
            || (request.expected_host.is_none() && enrollment != Enrollment::Unverified)
            || namespace_conflict(conn, &request)?
        {
            return Err(StoreError::Invalid);
        }
        records.push(ChildRecord {
            request,
            enrollment,
            outcome,
            depth: row.get(7)?,
            host,
        });
    }
    if count < 0 || count as usize != records.len() || records.len() > 256 {
        return Err(StoreError::Invalid);
    }
    for record in &records {
        let depth = parent_depth(root, &records, &record.request)?;
        if record.depth != depth || depth > 16 {
            return Err(StoreError::Invalid);
        }
    }
    Ok(records)
}
fn parent_depth(
    root: &RootRunRequest,
    records: &[ChildRecord],
    request: &ChildRequest,
) -> Result<u8> {
    let mut node = request;
    for depth in 1..=16 {
        if node.parent_run == root.identity().run {
            return if node.parent_run_ref == root.identity().run_ref {
                Ok(depth)
            } else {
                Err(StoreError::Invalid)
            };
        }
        let parent = records
            .iter()
            .find(|r| r.request.run == node.parent_run)
            .ok_or(StoreError::Invalid)?;
        if parent.request.run_ref != node.parent_run_ref {
            return Err(StoreError::Invalid);
        }
        node = &parent.request;
    }
    Err(StoreError::Invalid)
}
fn bump(
    conn: &rusqlite::Connection,
    root: &RootRunRequest,
    revision: u64,
    change: crate::run_journal::JournalChange,
) -> Result<()> {
    let revision = revision
        .checked_add(1)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(StoreError::Invalid)?;
    conn.execute(
        "UPDATE run_groups SET revision=?2 WHERE id=?1",
        (root.identity().group.to_string(), revision as i64),
    )?;
    crate::run_journal::journal_event(conn, root, revision, change)
}
impl Store {
    /// Commit positive historical enrollment only. No OS inspection, authority
    /// creation, heartbeat or writer release occurs within the transaction.
    pub fn record_child_enrollment(
        &mut self,
        root: &RootRunRequest,
        child: &ChildRequest,
        proof: &EnrollmentProof,
    ) -> Result<Transition> {
        self.record_child_enrollment_using(root, child, proof, std::time::Instant::now)
    }
    // Private clock seam permits deterministic post-lock boundary tests; callers
    // cannot select the clock or refresh an observation.
    fn record_child_enrollment_using(
        &mut self,
        root: &RootRunRequest,
        child: &ChildRequest,
        proof: &EnrollmentProof,
        now: impl FnOnce() -> std::time::Instant,
    ) -> Result<Transition> {
        let _phase = self.sql_phase();
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current = crate::run_journal::exact(&tx, root)?;
        if &proof.record.request != root || &proof.child != child || current.closed {
            return Err(StoreError::Conflict);
        }
        validate_host(root, current.binding.as_ref(), child, &proof.enrollment)
            .map_err(|_| StoreError::Conflict)?;
        let stored = current
            .children
            .iter()
            .find(|c| c.request.run == child.run)
            .ok_or(StoreError::Conflict)?;
        if &stored.request != child {
            return Err(StoreError::Conflict);
        }
        // A committed receipt is metadata only, not refreshed evidence. Accept
        // only the exact post-commit snapshot, never a changed hold/outcome/tree.
        let mut receipt = proof.record.clone();
        let enrolled = receipt
            .children
            .iter_mut()
            .find(|c| c.request.run == child.run)
            .ok_or(StoreError::Conflict)?;
        enrolled.enrollment = Enrollment::Contained;
        enrolled.host = Some(proof.enrollment.clone());
        receipt.revision = receipt.revision.checked_add(1).ok_or(StoreError::Invalid)?;
        if stored.enrollment == Enrollment::Contained && current == receipt {
            return Ok(Transition::Existing);
        }
        if current != proof.record
            || stored.enrollment != Enrollment::Pending
            || now()
                .checked_duration_since(proof.observed_at)
                .is_none_or(|age| age > std::time::Duration::from_secs(2))
        {
            return Err(StoreError::Conflict);
        }
        tx.execute(
            "UPDATE run_participants SET enrollment='contained',host=?2 WHERE id=?1",
            (
                child.run.to_string(),
                crate::adopted::json(&proof.enrollment)?,
            ),
        )?;
        bump(
            &tx,
            root,
            current.revision,
            crate::run_journal::JournalChange::ChildEnrolled,
        )?;
        tx.commit()?;
        Ok(Transition::Changed)
    }
    /// Commit a durable barrier BEFORE any execution-host inspection. This is
    /// metadata registration, not permission to launch, join or write. No OS calls.
    /// Existing validates the entire tree and grants nothing, even on retry.
    pub fn register_child(
        &mut self,
        root: &RootRunRequest,
        request: &ChildRequest,
    ) -> Result<BeginRun> {
        request.validate()?;
        let _phase = self.sql_phase();
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let record = crate::run_journal::exact(&tx, root)?;
        if let Some(existing) = record
            .children
            .iter()
            .find(|r| r.request.run == request.run)
        {
            return if &existing.request == request {
                Ok(BeginRun::Existing)
            } else {
                Err(StoreError::Conflict)
            };
        }
        if record.closed
            || record.stage != crate::run_journal::RunStage::PermitAttempt
            || request.checkout != root.identity().checkout
            || request.group != root.identity().group
            || record.children.len() >= 256
        {
            return Err(StoreError::Invalid);
        }
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM run_participants WHERE id=?1)",
            [request.run.to_string()],
            |r| r.get(0),
        )?;
        if exists || namespace_conflict(&tx, request)? {
            return Err(StoreError::Conflict);
        }
        let depth = parent_depth(root, &record.children, request)?;
        let state = if request.expected_host.is_some() {
            "pending"
        } else {
            "unverified"
        };
        tx.execute("INSERT INTO run_participants(id,group_id,run_ref,parent_run,request,enrollment,depth) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            (request.run.to_string(), request.group.to_string(), request.run_ref.as_str(), request.parent_run.to_string(), crate::adopted::json(request)?, state, depth))?;
        tx.execute(
            "UPDATE run_groups SET child_count=child_count+1 WHERE id=?1",
            [request.group.to_string()],
        )?;
        bump(
            &tx,
            root,
            record.revision,
            crate::run_journal::JournalChange::ChildRegistered,
        )?;
        tx.commit()?;
        Ok(BeginRun::Created)
    }
    /// Logical outcome only. Never physical absence or writer release. There is
    /// deliberately no caller-declarable Interrupted outcome.
    pub fn record_child_outcome(
        &mut self,
        root: &RootRunRequest,
        request: &ChildRequest,
        outcome: ChildOutcome,
    ) -> Result<Transition> {
        if outcome == ChildOutcome::Interrupted {
            return Err(StoreError::Invalid);
        }
        self.child_change(root, request, Some(outcome))
    }
    /// Tighten a failed/uncertain enrollment to a durable unverified barrier.
    /// There is no metadata-only upgrade back to pending or contained.
    pub fn record_child_hold(
        &mut self,
        root: &RootRunRequest,
        request: &ChildRequest,
    ) -> Result<Transition> {
        self.child_change(root, request, None)
    }
    fn child_change(
        &mut self,
        root: &RootRunRequest,
        request: &ChildRequest,
        outcome: Option<ChildOutcome>,
    ) -> Result<Transition> {
        let _phase = self.sql_phase();
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let record = crate::run_journal::exact(&tx, root)?;
        let child = record
            .children
            .iter()
            .find(|c| c.request.run == request.run)
            .ok_or(StoreError::Invalid)?;
        if &child.request != request {
            return Err(StoreError::Conflict);
        }
        // Exact declared-outcome receipts are metadata even after closure.
        // Holds and new outcomes still require an open group.
        if let (Some(outcome), Some(existing)) = (outcome, child.outcome) {
            return if existing == outcome {
                Ok(Transition::Existing)
            } else {
                Err(StoreError::Conflict)
            };
        }
        if record.closed {
            return Err(StoreError::Invalid);
        }
        let kind = if let Some(outcome) = outcome {
            tx.execute(
                "UPDATE run_participants SET outcome=?2 WHERE id=?1",
                (request.run.to_string(), crate::adopted::json(&outcome)?),
            )?;
            crate::run_journal::JournalChange::ChildDeclaredOutcome
        } else {
            if child.enrollment == Enrollment::Unverified {
                return Ok(Transition::Existing);
            }
            tx.execute(
                "UPDATE run_participants SET enrollment='unverified' WHERE id=?1",
                [request.run.to_string()],
            )?;
            crate::run_journal::JournalChange::ChildHold
        };
        bump(&tx, root, record.revision, kind)?;
        tx.commit()?;
        Ok(Transition::Changed)
    }
}
