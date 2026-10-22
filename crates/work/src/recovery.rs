//! Non-destructive reconciliation. Uncertain allocations remain quota charged.
use crate::{
    allocate::{self, Allocation},
    identity::CheckoutIdentity,
    store::Store,
};
use serde::{Deserialize, Serialize};
use std::{io, path::PathBuf};
use uuid::Uuid;
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Marker {
    version: u32,
    checkout: Uuid,
    operation: Uuid,
    path: PathBuf,
    private: PathBuf,
    common: PathBuf,
    head: String,
}
impl From<&Allocation> for Marker {
    fn from(a: &Allocation) -> Self {
        let i = a
            .identity
            .as_ref()
            .expect("marker needs persisted identity");
        Self {
            version: 1,
            checkout: a.checkout,
            operation: a.request.operation,
            path: i.path.clone(),
            private: i.private_git_dir.clone(),
            common: i.common_git_dir.clone(),
            head: a.base_commit.clone(),
        }
    }
}
#[cfg(test)]
pub(crate) fn hold(store: &mut Store, a: &mut Allocation, reason: &str) -> io::Result<()> {
    let lease = allocate::lifecycle_lock(store)?;
    hold_under_lease(store, a, reason, &lease)
}
pub(crate) fn hold_under_lease(
    store: &mut Store,
    a: &mut Allocation,
    reason: &str,
    lease: &allocate::AuthorityLease,
) -> io::Result<()> {
    allocate::db(lease.check(store))?;
    let _phase = store.sql_phase();
    {
        let tx = allocate::sql(
            store
                .conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate),
        )?;
        if allocate::db(crate::attribution_gap::required_origin(&tx, a.checkout))? {
            let (state,record,finished):(String,String,bool)=allocate::sql(tx.query_row(
                "SELECT c.state,a.record,EXISTS(SELECT 1 FROM task_finishes WHERE checkout=c.id) FROM checkouts c JOIN allocations a ON a.checkout=c.id WHERE c.id=?1",
                [a.checkout.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
            ))?;
            if finished || !matches!(state.as_str(), "active" | "partial" | "held") {
                return Ok(());
            }
            let mut current: Allocation = serde_json::from_str(&record)?;
            if current
                .reason
                .as_deref()
                .is_none_or(|r| r == "capture required; root preparation pending")
            {
                current.reason = Some(reason.into());
            }
            let updated = serde_json::to_string(&current)?;
            if state != "held" || updated != record {
                allocate::sql(tx.execute(
                    "UPDATE checkouts SET state='held',ready=0 WHERE id=?1",
                    [a.checkout.to_string()],
                ))?;
                allocate::sql(tx.execute(
                    "UPDATE allocations SET record=?2 WHERE checkout=?1",
                    (a.checkout.to_string(), updated),
                ))?;
                allocate::db(crate::store::emit(
                    &tx,
                    &crate::events::Event::AllocationStage {
                        checkout: a.checkout,
                        operation: current.request.operation,
                        stage: current.stage.clone(),
                        reason: current.reason.clone(),
                    },
                ))?;
            }
            allocate::sql(tx.commit())?;
            *a = current;
            return Ok(());
        }
    }
    a.stage = "held".into();
    a.reason = Some(reason.into());
    allocate::save_under_lease(store, a, lease)
}
#[cfg(test)]
pub(crate) fn reconcile(store: &mut Store, a: &mut Allocation) -> io::Result<()> {
    let lease = allocate::lifecycle_lock(store)?;
    reconcile_under_lease(store, a, &lease)
}
pub(crate) fn reconcile_under_lease(
    store: &mut Store,
    a: &mut Allocation,
    lease: &allocate::AuthorityLease,
) -> io::Result<()> {
    allocate::db(lease.check(store))?;
    {
        let _phase = store.sql_phase();
        allocate::db(crate::attribution_gap::guard_legacy_allocation(
            &store.conn,
            a.checkout,
        ))?;
    }
    let required =
        allocate::db(crate::capture_requirement::read(&store.conn, a.checkout))?.is_some();
    if required
        && !matches!(
            a.stage.as_str(),
            "reserved" | "creating" | "created" | "capture_pending" | "ready"
        )
    {
        return Err(allocate::err(
            "capture requirement has an unknown or later allocation stage",
        ));
    }
    let result = verify(a);
    match result {
        Ok(current) => {
            // Boot/device changes alone are not activity. Durable paths, marker,
            // registration, HEAD and inode must still agree before refreshing stat.
            if let Some(prior) = &a.identity {
                if prior.head != current.head {
                    // Commit evidence before refreshing the snapshot. A crash between
                    // commits only repeats the ancestry observation; it grants no writer.
                    let _phase=store.sql_phase();
                    let tx = allocate::sql(store.conn.transaction())?;
                    allocate::db(crate::capture_journal::guard_allocation_identity(&tx,a.checkout))?;
                    allocate::db(crate::store::emit(&tx, &crate::events::Event::HeadAdvanced {
                        checkout: a.checkout, old: prior.head.clone(), new: current.head.clone(),
                    }))?;
                    allocate::sql(tx.commit())?;
                }
            }
            a.identity = Some(current);
            if required && a.stage != "ready" {
                a.stage = "capture_pending".into();
                a.reason = Some("capture required; root preparation pending".into());
            } else {
                a.stage = "ready".into(); a.reason = None;
            }
            allocate::save_under_lease(store, a, lease)
        }
        Err(_) => hold_under_lease(store, a, "identity/marker/registration incomplete or changed; operator reconciliation required (slot retained)", lease),
    }
}
pub(crate) fn verify(a: &Allocation) -> io::Result<CheckoutIdentity> {
    let fail = || allocate::err("insufficient allocation identity");
    let prior = a.identity.as_ref().ok_or_else(fail)?;
    for path in [
        &a.destination,
        &prior.private_git_dir,
        &prior.common_git_dir,
    ] {
        crate::config::validate_path(path, true).map_err(|_| fail())?;
    }
    let current = CheckoutIdentity::inspect(&a.destination)?;
    if current.path != prior.path
        || current.private_git_dir != prior.private_git_dir
        || current.common_git_dir != prior.common_git_dir
        || current.directory.inode != prior.directory.inode
        || (current.boot_id == prior.boot_id && current.directory.device != prior.directory.device)
    {
        return Err(fail());
    }
    let branch = crate::identity::query(&a.destination, &["symbolic-ref", "--quiet", "HEAD"])?;
    if branch
        != format!(
            "refs/heads/{}",
            a.request.branch.as_deref().ok_or_else(fail)?
        )
    {
        return Err(fail());
    }
    if current.head != prior.head {
        if a.stage != "ready" {
            return Err(fail());
        }
        crate::identity::query(
            &a.destination,
            &["merge-base", "--is-ancestor", &prior.head, &current.head],
        )?;
    }
    let path = prior.private_git_dir.join("work-lease.json");
    let marker: Marker = serde_json::from_slice(&crate::identity::read_metadata(&path, 16384)?)?;
    if marker != Marker::from(a) {
        return Err(fail());
    }
    Ok(current)
}
