//! Non-destructive reconciliation. Uncertain allocations remain quota charged.
use crate::{
    allocate::{self, Allocation},
    identity::CheckoutIdentity,
    store::Store,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
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
    let authority = store.authority_identity().clone();
    #[cfg(test)]
    crate::retirement_journal::tests::observe_late(
        crate::retirement_journal::tests::LateBoundary::RequiredGapHold,
        store,
    );
    let _phase = store.sql_phase();
    {
        let tx = allocate::sql(
            store
                .conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate),
        )?;
        let tx = allocate::db(crate::retirement_journal::fence(
            tx,
            lease,
            &authority,
            crate::retirement_journal::Scope::Checkout(a.checkout),
            crate::retirement_journal::Attempt::AllocationHold,
        ))?;
        if allocate::db(crate::attribution_gap::required_origin(&tx, a.checkout))? {
            let (state,record,finished):(String,String,bool)=allocate::sql(tx.query_row(
                "SELECT c.state,a.record,EXISTS(SELECT 1 FROM task_finishes WHERE checkout=c.id) FROM checkouts c JOIN allocations a ON a.checkout=c.id WHERE c.id=?1",
                [a.checkout.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
            ))?;
            if finished || !matches!(state.as_str(), "active" | "partial" | "held") {
                return Ok(());
            }
            allocate::db(crate::gap_continuation::revoke(
                &tx, &authority, lease, a.checkout,
            ))?;
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
    let guard = allocate::db(crate::checkout_guard::CheckoutGuard::shared(
        store, a.checkout,
    ))?;
    let observed = allocate::observe_reconciliation(store, a, &guard)?;
    let lease = allocate::lifecycle_lock(store)?;
    reconcile_under_lease(store, a, observed, &lease)
}
pub(crate) fn reconcile_under_lease(
    store: &mut Store,
    a: &mut Allocation,
    observed: allocate::PhysicalObservation,
    lease: &allocate::AuthorityLease,
) -> io::Result<()> {
    observed.matches_allocation(a)?;
    let current = allocate::reconcile_observation_under_lease(store, observed, lease)?;
    *a = current;
    Ok(())
}
pub(crate) fn verify(a: &Allocation) -> io::Result<CheckoutIdentity> {
    verify_identity(a, false)
}

/// Narrow descriptor reader for the Gap-only verifier. Do not relax the legacy
/// identity reader or accept a hardlinked, symlinked or blocking metadata file.
pub(crate) fn gap_metadata(path: &Path) -> io::Result<Vec<u8>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    let matches = |current: &std::fs::Metadata| {
        current.is_file()
            && current.nlink() == 1
            && (current.dev(), current.ino()) == (metadata.dev(), metadata.ino())
    };
    if !matches(&metadata) || !matches(&std::fs::symlink_metadata(path)?) || metadata.len() > 16384
    {
        return Err(allocate::err("unsafe Gap metadata descriptor"));
    }
    let mut bytes = Vec::new();
    file.take(16385).read_to_end(&mut bytes)?;
    if bytes.len() > 16384 || !matches(&std::fs::symlink_metadata(path)?) {
        return Err(allocate::err("changed or oversized Gap metadata"));
    }
    Ok(bytes)
}

/// Only the continuation module calls this purpose-specific verifier. Pending
/// allocations remain exact-HEAD in verify(); no stage or identity is rewritten.
pub(crate) fn verify_gap(a: &Allocation) -> io::Result<CheckoutIdentity> {
    let prior = a
        .identity
        .as_ref()
        .ok_or_else(|| allocate::err("missing Gap identity"))?;
    let text = |path: &Path| -> io::Result<String> {
        String::from_utf8(gap_metadata(path)?).map_err(|_| allocate::err("non-UTF8 Gap metadata"))
    };
    // Check the known linked-worktree metadata BEFORE asking Git to consume it.
    let dotgit = text(&a.destination.join(".git"))?;
    if dotgit.trim_end_matches('\n') != format!("gitdir: {}", prior.private_git_dir.display()) {
        return Err(allocate::err("Gap gitdir link changed"));
    }
    let backlink = text(&prior.private_git_dir.join("gitdir"))?;
    if Path::new(backlink.trim_end_matches('\n')) != a.destination.join(".git") {
        return Err(allocate::err("Gap backlink changed"));
    }
    let common = text(&prior.private_git_dir.join("commondir"))?;
    let common = prior
        .private_git_dir
        .join(common.trim_end_matches('\n'))
        .canonicalize()?;
    if common != prior.common_git_dir || prior.private_git_dir == prior.common_git_dir {
        return Err(allocate::err("Gap common directory changed"));
    }
    gap_metadata(&prior.private_git_dir.join("work-lease.json"))?;
    verify_identity(a, true)
}

fn verify_identity(a: &Allocation, gap_descendants: bool) -> io::Result<CheckoutIdentity> {
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
        if !gap_descendants && a.stage != "ready" {
            return Err(fail());
        }
        crate::identity::query(
            &a.destination,
            &["merge-base", "--is-ancestor", &prior.head, &current.head],
        )?;
    }
    let path = prior.private_git_dir.join("work-lease.json");
    let marker: Marker = serde_json::from_slice(&if gap_descendants {
        gap_metadata(&path)?
    } else {
        crate::identity::read_metadata(&path, 16384)?
    })?;
    if marker != Marker::from(a) {
        return Err(fail());
    }
    Ok(current)
}
