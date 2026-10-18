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
pub(crate) fn hold(store: &mut Store, a: &mut Allocation, reason: &str) -> io::Result<()> {
    a.stage = "held".into();
    a.reason = Some(reason.into());
    allocate::save(store, a)
}
pub(crate) fn reconcile(store: &mut Store, a: &mut Allocation) -> io::Result<()> {
    let result = verify(a);
    match result {
        Ok(current) => {
            // Boot/device changes alone are not activity. Durable paths, marker,
            // registration, HEAD and inode must still agree before refreshing stat.
            if let Some(prior) = &a.identity {
                if prior.head != current.head {
                    // Commit evidence before refreshing the snapshot. A crash between
                    // commits only repeats the ancestry observation; it grants no writer.
                    let tx = allocate::sql(store.conn.transaction())?;
                    allocate::db(crate::store::emit(&tx, &crate::events::Event::HeadAdvanced {
                        checkout: a.checkout, old: prior.head.clone(), new: current.head.clone(),
                    }))?;
                    allocate::sql(tx.commit())?;
                }
            }
            a.identity = Some(current); a.stage = "ready".into(); a.reason = None;
            allocate::save(store, a)
        }
        Err(_) => hold(store, a, "identity/marker/registration incomplete or changed; operator reconciliation required (slot retained)"),
    }
}
fn verify(a: &Allocation) -> io::Result<CheckoutIdentity> {
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
