//! Supervised child declarations. These grant no launch, writer or OS authority.
//! Enrollment is intentionally fail-closed: pending/unverified are permanent
//! closure barriers until fresh execution-host proof support is implemented.
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
    Unverified,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildOutcome {
    Completed,
    Failed,
    Cancelled,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildRecord {
    pub request: ChildRequest,
    pub enrollment: Enrollment,
    pub outcome: Option<ChildOutcome>,
    pub depth: u8,
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
pub(crate) fn validate_orphans(conn: &rusqlite::Connection) -> Result<()> {
    let invalid: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM run_participants p LEFT JOIN run_groups g ON g.id=p.group_id LEFT JOIN runs r ON r.group_id=p.group_id WHERE g.id IS NULL OR r.id IS NULL OR g.mode!='supervised')", [], |r| r.get(0))?;
    if invalid {
        Err(StoreError::Invalid)
    } else {
        Ok(())
    }
}
fn namespace_conflict(conn: &rusqlite::Connection, request: &ChildRequest) -> Result<bool> {
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
) -> Result<Vec<ChildRecord>> {
    validate_orphans(conn)?;
    let count: i64 = conn.query_row(
        "SELECT child_count FROM run_groups WHERE id=?1",
        [root.identity().group.to_string()],
        |r| r.get(0),
    )?;
    let mut stmt = conn.prepare("SELECT id,group_id,run_ref,parent_run,request,enrollment,outcome,depth FROM run_participants WHERE group_id=?1 ORDER BY rowid LIMIT 257")?;
    let mut rows = stmt.query([root.identity().group.to_string()])?;
    let mut records = Vec::new();
    while let Some(row) = rows.next()? {
        let body: String = row.get(4)?;
        let request: ChildRequest = serde_json::from_str(&body).map_err(|_| StoreError::Invalid)?;
        request.validate()?;
        let state: String = row.get(5)?;
        let enrollment = match state.as_str() {
            "pending" => Enrollment::Pending,
            "unverified" => Enrollment::Unverified,
            _ => return Err(StoreError::Invalid),
        };
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
        if record.closed {
            return Err(StoreError::Invalid);
        }
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
        if record.stage != crate::run_journal::RunStage::PermitAttempt
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
        if record.closed {
            return Err(StoreError::Invalid);
        }
        let child = record
            .children
            .iter()
            .find(|c| c.request.run == request.run)
            .ok_or(StoreError::Invalid)?;
        if &child.request != request {
            return Err(StoreError::Conflict);
        }
        let kind = if let Some(outcome) = outcome {
            if let Some(existing) = child.outcome {
                return if existing == outcome {
                    Ok(Transition::Existing)
                } else {
                    Err(StoreError::Conflict)
                };
            }
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
