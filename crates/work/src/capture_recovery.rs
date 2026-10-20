//! Explicit pre-bind metadata recovery; never a runtime capability.
#[cfg(test)]
#[path = "capture_recovery_tests.rs"]
mod tests;
use crate::{
    allocate::Allocation,
    capture_journal::{self, CaptureRecord, CaptureSpec},
    config::Config,
    run_journal::{self, RunRecord, RunStage},
    store::{Result, Store, StoreError},
};
use rusqlite::{Connection, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use work_contract::RunId;

fn seal(value: &impl Serialize) -> Result<[u8; 32]> {
    struct Writer(Sha256);
    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer(Sha256::new());
    serde_json::to_writer(&mut writer, value).map_err(|_| StoreError::Invalid)?;
    Ok(writer.0.finalize().into())
}
struct Snapshot {
    root: RunRecord,
    capture: CaptureRecord,
    spec: CaptureSpec,
    allocation: Allocation,
    common: PathBuf,
    seal: [u8; 32],
    passive: bool,
}
fn target(conn: &Connection, run: &RunId) -> Result<Snapshot> {
    let root = run_journal::read(conn, run)?.ok_or(StoreError::Invalid)?;
    capture_journal::validate_related(conn, &root.request.identity().checkout)?;
    let root = run_journal::exact(conn, &root.request)?;
    let (capture, spec) = capture_journal::qualified(conn, &root)?.ok_or(StoreError::Invalid)?;
    let allocation = spec.agrees(conn, &root.request)?;
    // Closed known history is passive before task/writer-current/physical checks.
    if root.closed {
        if capture.prepared.is_none() {
            return Err(StoreError::Invalid);
        }
        return Ok(Snapshot {
            root,
            capture,
            spec,
            allocation,
            common: PathBuf::new(),
            seal: [0; 32],
            passive: true,
        });
    }
    let checkout = root.request.identity().checkout.to_string();
    // Schema foreign keys only fence runs -> groups. Fence rootless groups and
    // competing open/held history on this checkout in both preflight and CAS.
    let bad: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1)
         OR EXISTS(SELECT 1 FROM adopted_groups WHERE checkout=?1)
         OR EXISTS(SELECT 1 FROM runs r LEFT JOIN run_groups g ON g.id=r.group_id WHERE g.id IS NULL)
         OR EXISTS(SELECT 1 FROM writers WHERE checkout=?1 AND group_id!=?2)
         OR EXISTS(SELECT 1 FROM run_groups g LEFT JOIN runs r ON r.group_id=g.id
                   WHERE g.checkout=?1 AND (r.id IS NULL
                     OR (g.id!=?2 AND (g.closed=0 OR g.recovery_hold!=0))))",
        (&checkout, root.request.identity().group.to_string()),
        |r| r.get(0),
    )?;
    if bad
        || root.stage != RunStage::Intent
        || root.binding.is_some()
        || root.outcome.is_some()
        || capture.group_end.is_some()
    {
        return Err(StoreError::Conflict);
    }
    let (state, ready): (String, bool) = conn.query_row(
        "SELECT state,ready FROM checkouts WHERE id=?1",
        [&checkout],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if !matches!(state.as_str(), "active" | "held") {
        return Err(StoreError::Conflict);
    }
    let requirement = crate::capture_requirement::read(conn, allocation.checkout)?;
    let (record, request, operation, digest, repository, actor, task, owner): (String,String,String,Vec<u8>,String,String,String,String) = conn.query_row("SELECT a.record,a.request,c.operation,c.digest,c.repository,c.actor,c.task,c.owner FROM checkouts c JOIN allocations a ON a.checkout=c.id WHERE c.id=?1", [&checkout], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)))?;
    if capture.prepared.is_none()
        && (ready
            || !((allocation.stage == "capture_pending"
                && requirement.is_some()
                && allocation.reason.as_deref()
                    == Some("capture required; root preparation pending"))
                || (allocation.stage == "ready" && allocation.reason.is_none())))
    {
        return Err(StoreError::Conflict);
    }
    let context = seal(&(
        &root,
        &capture,
        &spec,
        &record,
        &request,
        &operation,
        &digest,
        &repository,
        &actor,
        &task,
        &owner,
        &requirement,
        &state,
        ready,
    ))?;
    let passive = capture.prepared.is_some() && root.recovery_hold && state == "held" && !ready;
    Ok(Snapshot {
        root,
        capture,
        spec,
        allocation,
        common: repository.into(),
        seal: context,
        passive,
    })
}
fn fresh(observed: Instant) -> Result<()> {
    #[cfg(test)]
    let observed = observed - tests::clock_offset();
    if observed.elapsed() > Duration::from_secs(2) {
        Err(StoreError::Conflict)
    } else {
        Ok(())
    }
}
pub(crate) fn reconcile(config: &Config, run: &RunId) -> Result<&'static str> {
    let registry = config
        .trusted_registry
        .as_deref()
        .ok_or(StoreError::Invalid)?;
    let dir = config.store_dir.as_deref().ok_or(StoreError::Invalid)?;
    let before = {
        let store = Store::open_existing_registered_readonly(registry, dir, &config.roots)?;
        let _phase = store.sql_phase();
        let _read = run_journal::read_transaction(&store.conn)?;
        target(&store.conn, run)?
    };
    if before.passive {
        return Ok("existing_preparation");
    }
    let mut store = Store::open_existing_registered_mut(registry, dir, &config.roots)?;
    if before.capture.prepared.is_some() {
        let _phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = target(&tx, run)?;
        if current.seal != before.seal {
            return Err(StoreError::Conflict);
        }
        capture_journal::reconcile_hold(&tx, &current.root)?;
        tx.commit()?;
        return Ok("metadata_reconciled");
    }
    #[cfg(test)]
    tests::observe("pre_physical", &store);
    let observed = Instant::now();
    let physical = crate::capture_setup::inspect_physical(&before.allocation, &before.common)?;
    let sink = crate::sinks::ProcessSink::new(before.spec.sink().process_settings()?);
    #[cfg(test)]
    tests::observe("pre_process", &store);
    fresh(observed)?;
    // Once BEGIN is dispatched, every failure is conservatively uncertain.
    let outcome = (|| -> Result<()> {
        let prepared = sink
            .begin(&before.spec.begin_request(), &before.spec.expected_git())
            .map_err(|_| StoreError::Invalid)?;
        #[cfg(test)]
        tests::observe("post_process", &store);
        let observation = capture_journal::observation(&before.spec, &prepared, false)?;
        let observed = Instant::now();
        let after = crate::capture_setup::inspect_physical(&before.allocation, &before.common)?;
        if after != physical {
            return Err(StoreError::Conflict);
        }
        #[cfg(test)]
        tests::observe("post_physical", &store);
        let _lock = crate::allocate::lifecycle_lock(dir)?;
        fresh(observed)?;
        let _phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = target(&tx, run)?;
        if current.seal != before.seal || current.capture.prepared.is_some() {
            return Err(StoreError::Conflict);
        }
        tx.execute(
            "UPDATE capture_runs SET prepared=?2 WHERE run=?1",
            (run.to_string(), capture_journal::json(&observation)?),
        )?;
        capture_journal::reconcile_hold(&tx, &current.root)?;
        fresh(observed)?;
        tx.commit()?;
        Ok(())
    })();
    Ok(if outcome.is_ok() {
        "metadata_reconciled"
    } else {
        "begin_uncertain"
    })
}
