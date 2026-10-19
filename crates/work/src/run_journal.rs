//! Durable supervised root intent and recovery metadata only. No backend calls,
//! launch permission, participant registration or group-closure authority.
//! All groups remain writer-held, even after root exit; roster-bound fresh empty
//! proof integration is intentionally unsupported in this increment.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunInput {
    /// Digests only; callers must never supply raw commands, environment or prompts.
    pub command_digest: [u8; 32],
    pub input_digest: [u8; 32],
    pub context_ref: ChainText,
    pub intent_ref: ChainText,
    pub boot: String,
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
    pub revision: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalChange {
    Intent,
    Bound,
    PermitAttempt,
    RootTerminal,
    RecoveryHold,
}

use crate::{
    events::Event,
    store::{acquire_writer_tx, emit},
};
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
    fn capture(request: &RootRunRequest, binding: &Binding) -> Result<Self> {
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
fn journal_event(
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
    r.id,r.group_id,r.run_ref,g.checkout,g.mode FROM runs r LEFT JOIN run_groups g ON g.id=r.group_id";
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
            revision: revision as u64,
        })
    })())
}
fn read(conn: &Connection, run: &RunId) -> Result<Option<RunRecord>> {
    conn.query_row(
        &format!("{SELECT} WHERE r.id=?1"),
        [run.to_string()],
        read_row,
    )
    .optional()?
    .transpose()
}
fn exact(conn: &Connection, request: &RootRunRequest) -> Result<RunRecord> {
    let record = read(conn, &request.identity.run)?.ok_or(StoreError::Invalid)?;
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
    if !writer {
        return Err(StoreError::Invalid);
    }
    Ok(record)
}
impl Store {
    /// Acquires writer, records root participant intent, and appends events in
    /// ONE IMMEDIATE transaction. No OS calls occur inside it. On any error,
    /// including uncertain commit durability, recover by RunId; never launch.
    pub fn begin_run(&mut self, request: &RootRunRequest) -> Result<BeginRun> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if read(&tx, &request.identity.run)?.is_some() {
            exact(&tx, request)?;
            return Ok(BeginRun::Existing);
        }
        let i = &request.identity;
        let conflict: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM runs WHERE run_ref=?1 OR id=?2 OR group_id=?2 OR group_id=?3)
            OR EXISTS(SELECT 1 FROM run_groups WHERE id=?2 OR id=?3)
            OR EXISTS(SELECT 1 FROM checkouts WHERE id IN (?2,?3) OR operation IN (?2,?3))",
            (i.run_ref.as_str(), i.group.to_string(), i.run.to_string()), |r| r.get(0))?;
        if conflict {
            return Err(StoreError::Conflict);
        }
        acquire_writer_tx(&tx, uuid(&i.checkout)?, uuid(&i.group)?, false)?;
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
                json(request)?,
            ),
        )?;
        journal_event(&tx, request, 1, JournalChange::Intent)?;
        tx.commit()?;
        Ok(BeginRun::Created)
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
        read(&self.conn, run)
    }
    /// All groups remain unresolved until roster-aware closure is implemented.
    /// No heartbeat/reboot inference, no reconstructed runtime authority.
    pub fn recovery_runs(&self) -> Result<Vec<RunRecord>> {
        let mut stmt = self.conn.prepare(&format!("{SELECT} ORDER BY r.rowid"))?;
        let rows = stmt.query_map([], read_row)?;
        rows.map(|r| r.map_err(StoreError::from).and_then(|v| v))
            .collect()
    }
    fn transition(&mut self, request: &RootRunRequest, change: Change) -> Result<Transition> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = exact(&tx, request)?;
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
enum Change {
    Bound(BoundSnapshot),
    Permit(BoundSnapshot),
    Outcome(RootOutcome),
    Hold,
}
