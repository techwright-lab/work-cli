//! Private task-completion qualification. This never grants writer or readiness authority.
use super::*;
use std::time::{Duration, Instant};

#[derive(PartialEq, Eq)]
struct Context {
    allocation: String,
    state: String,
    ready: bool,
    charge: String,
    requirement: Option<crate::capture_requirement::Requirement>,
    history: [u8; 32],
}
fn context(conn: &Connection, checkout: Uuid) -> Result<Context> {
    let _snapshot = crate::run_journal::read_transaction(conn)?;
    let (a, state, ready) = allocation(conn, checkout)?;
    if a.reason.is_some() || !((state == "active" && ready) || (state == "held" && !ready)) {
        return Err(StoreError::Invalid);
    }
    writer_fence(conn, checkout)?;
    let charge: (String, String, String, String, String, Vec<u8>) = conn.query_row(
        "SELECT owner,repository,actor,task,operation,digest FROM checkouts WHERE id=?1",
        [checkout.to_string()],
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        },
    )?;
    let history = crate::run_journal::with_capture_history(conn, checkout, |history| {
        if history.is_empty()
            || history.iter().any(|(r, (c, _, _))| {
                !r.closed || r.recovery_hold || c.prepared.is_none() || c.group_end.is_none()
            })
        {
            return Err(StoreError::Invalid);
        }
        let contexts = history
            .iter()
            .map(|(r, (c, s, frozen))| {
                // qualified_terminal already checked exact context equality
                // for this tuple, on this connection in this read snapshot.
                match frozen {
                    Some(frozen) => Ok(frozen.intent.context.clone()),
                    None => crate::capture_finalization::context(r, c, s),
                }
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(digest(json(&contexts)?))
    })?;
    Ok(Context {
        allocation: json(&a)?,
        state,
        ready,
        charge: json(&charge)?,
        requirement: crate::capture_requirement::read(conn, checkout)?,
        history,
    })
}
pub(super) struct Completion {
    original: Context,
    allocation: allocate::Allocation,
    observed: Instant,
}
impl Completion {
    pub(super) fn inspect(store: &Store, checkout: Uuid) -> Result<Self> {
        let original = {
            let _phase = store.sql_phase();
            let _snapshot = crate::run_journal::read_transaction(&store.conn)?;
            context(&store.conn, checkout)?
        };
        let mut allocation: allocate::Allocation = parse(&original.allocation)?;
        let common = allocation
            .identity
            .as_ref()
            .ok_or(StoreError::Invalid)?
            .common_git_dir
            .clone();
        let observed = Instant::now();
        let physical = crate::capture_setup::inspect_physical(&allocation, &common)?;
        allocation.identity = Some(physical.checkout.clone());
        if crate::capture_setup::inspect_physical(&allocation, &common)? != physical {
            return Err(StoreError::Conflict);
        }
        let proof = Self {
            original,
            allocation,
            observed,
        };
        proof.fresh()?;
        Ok(proof)
    }
    pub(super) fn fresh(&self) -> Result<()> {
        if self.observed.elapsed() > Duration::from_secs(2) {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }
    pub(super) fn validate(&self, conn: &Connection) -> Result<()> {
        self.fresh()?;
        if context(conn, self.allocation.checkout)? != self.original {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }
    pub(super) fn allocation(&self) -> allocate::Allocation {
        self.allocation.clone()
    }
}

/// Prepare every known terminal intent under the lifecycle lock, after the task
/// transaction committed. Any failure is capture failure, never task rollback.
pub(super) fn intents(
    store: &mut Store,
    checkout: Uuid,
    lease: &allocate::AuthorityLease,
) -> Result<()> {
    lease.check(store)?;
    let authority = store.authority_identity().clone();
    let _phase = store.sql_phase();
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    crate::run_journal::with_capture_history(&tx, checkout, |history| {
        for (root, (capture, spec, _)) in history {
            if root.outcome.is_none()
                || capture.group_end.as_ref().is_none_or(|e| e.clock_uncertain)
            {
                continue;
            }
            crate::capture_finalization::prepare_intent(
                &tx, &root, &capture, &spec, lease, &authority,
            )?;
        }
        Ok(())
    })?;
    tx.commit()?;
    Ok(())
}
