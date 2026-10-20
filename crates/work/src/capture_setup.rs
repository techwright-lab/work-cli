//! Trusted library setup; no capture subprocess, scope, callback or launch.
use crate::{
    allocate::Allocation,
    capture_journal::{BeginCapturedRun, CaptureSpec},
    capture_requirement::Requirement,
    config::Config,
    identity::CheckoutIdentity,
    run_journal::RootRunRequest,
    store::{Result, Store, StoreError},
};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::MetadataExt,
    time::{Duration, Instant},
};
const MAX_AGE: Duration = Duration::from_secs(2);
#[cfg(test)]
#[path = "capture_setup_tests.rs"]
mod tests;

/// Existing acknowledgements are metadata only. Never returns runtime authority.
/// New required roots always inspect the actual registered Git checkout. No
/// caller-provided flag, DTO, fake OS backend or version probe can bypass this.
pub fn begin(
    config: &Config,
    request: &RootRunRequest,
    spec: &CaptureSpec,
) -> std::io::Result<(Store, BeginCapturedRun)> {
    let (mut store, lock) = crate::allocate::locked(config)?;
    // Exact historical receipts use their sealed settings, with no FS refresh,
    // current actor/profile requirement or new preparation capability.
    if crate::allocate::db(store.run_snapshot(&request.identity().run))?.is_some() {
        let result = crate::allocate::db(store.begin_captured_run(request, spec))?;
        drop(lock);
        return Ok((store, result));
    }
    let allocation = crate::allocate::db(spec.agrees(&store.conn, request))?;
    let d = spec.begin_request();
    let selected = crate::allocate::db(config.capture_spec(
        request,
        &allocation,
        spec.operation(),
        d.task_refs,
        d.source,
    ))?;
    if serde_json::to_vec(&selected)? != serde_json::to_vec(spec)? {
        return Err(crate::allocate::err(
            "capture does not match selected host settings",
        ));
    }
    let proof = crate::allocate::db(MaterializationProof::inspect(&store, request, spec))?;
    let result = crate::allocate::db(store.begin_materialized_capture(request, spec, &proof))?;
    drop(lock);
    Ok((store, result))
}

/// Exact durable context sealed into the Created-only preparation handle. Not a
/// public receipt or eligibility selector. Includes allocation bytes unchanged.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PendingPreparation {
    record: String,
    request: String,
    requirement: Requirement,
    charged: [u8; 32],
}
impl PendingPreparation {
    fn read(conn: &Connection, checkout: uuid::Uuid) -> Result<Self> {
        let (record, request, operation, digest, repository, actor, task, owner): (String,String,String,Vec<u8>,String,String,String,String) = conn.query_row(
            "SELECT a.record,a.request,c.operation,c.digest,c.repository,c.actor,c.task,c.owner FROM checkouts c JOIN allocations a ON a.checkout=c.id WHERE c.id=?1", [checkout.to_string()],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)))?;
        let requirement =
            crate::capture_requirement::read(conn, checkout)?.ok_or(StoreError::Invalid)?;
        let charged = Sha256::digest(
            serde_json::to_vec(&(operation, digest, repository, actor, task, owner))
                .map_err(|_| StoreError::Invalid)?,
        )
        .into();
        Ok(Self {
            record,
            request,
            requirement,
            charged,
        })
    }
    pub(crate) fn promote(&self, conn: &Connection, checkout: uuid::Uuid) -> Result<()> {
        if Self::read(conn, checkout)? != *self {
            return Err(StoreError::Conflict);
        }
        let mut allocation: Allocation =
            serde_json::from_str(&self.record).map_err(|_| StoreError::Invalid)?;
        if allocation.checkout != checkout || allocation.stage != "capture_pending" {
            return Err(StoreError::Invalid);
        }
        allocation.stage = "ready".into();
        allocation.reason = None;
        conn.execute(
            "UPDATE allocations SET record=?2 WHERE checkout=?1",
            (
                checkout.to_string(),
                serde_json::to_string(&allocation).map_err(|_| StoreError::Invalid)?,
            ),
        )?;
        crate::store::emit(
            conn,
            &crate::events::Event::AllocationStage {
                checkout,
                operation: allocation.request.operation,
                stage: allocation.stage,
                reason: None,
            },
        )
    }
}

// No Clone/Serde, private fields and a single real-inspection constructor. A
// stored flag, root declaration or preparation response cannot mint this proof.
pub(crate) struct MaterializationProof {
    root: RootRunRequest,
    allocation: Allocation,
    pending: PendingPreparation,
    physical: Physical,
    observed: Instant,
    spec_digest: [u8; 32],
}
#[derive(PartialEq, Eq)]
struct Physical {
    checkout: CheckoutIdentity,
    directories: Vec<(u64, u64)>,
    marker: Vec<u8>,
}
fn physical(conn: &Connection, a: &Allocation) -> Result<Physical> {
    let source = a.request.repository.as_ref().ok_or(StoreError::Invalid)?;
    crate::config::validate_path(source, true).map_err(|_| StoreError::Unsafe)?;
    let charged_common = crate::allocate::source_authority_evidence(conn, a)?;
    let checkout = crate::recovery::verify(a)?;
    if checkout.common_git_dir != charged_common
        || checkout.private_git_dir == checkout.common_git_dir
        || a.identity.as_ref() != Some(&checkout)
    {
        return Err(StoreError::Conflict);
    }
    let mut directories = Vec::new();
    for path in [
        source,
        &checkout.path,
        &checkout.private_git_dir,
        &checkout.common_git_dir,
    ] {
        let m = std::fs::symlink_metadata(path)?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err(StoreError::Unsafe);
        }
        directories.push((m.dev(), m.ino()));
    }
    let marker =
        crate::identity::read_metadata(&checkout.private_git_dir.join("work-lease.json"), 16384)?;
    Ok(Physical {
        checkout,
        directories,
        marker,
    })
}
impl MaterializationProof {
    fn inspect(store: &Store, root: &RootRunRequest, spec: &CaptureSpec) -> Result<Self> {
        let _phase = store.sql_phase();
        let a = spec.agrees(&store.conn, root)?;
        let pending = PendingPreparation::read(&store.conn, a.checkout)?;
        let observed = Instant::now();
        let physical = physical(&store.conn, &a)?;
        let spec_digest =
            Sha256::digest(serde_json::to_vec(spec).map_err(|_| StoreError::Invalid)?).into();
        let proof = Self {
            root: root.clone(),
            allocation: a,
            pending,
            physical,
            observed,
            spec_digest,
        };
        proof.validate(&store.conn, root)?;
        Ok(proof)
    }
    pub(crate) fn validate(&self, conn: &Connection, root: &RootRunRequest) -> Result<()> {
        if &self.root != root
            || self.allocation.stage != "capture_pending"
            || self.allocation.reason.as_deref()
                != Some("capture required; root preparation pending")
            || root.input().boot != self.physical.checkout.boot_id
            || PendingPreparation::read(conn, self.allocation.checkout)? != self.pending
        {
            return Err(StoreError::Conflict);
        }
        let eligible: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 AND state='partial' AND ready=0)
            AND NOT EXISTS(SELECT 1 FROM writers WHERE checkout=?1)
            AND NOT EXISTS(SELECT 1 FROM run_groups WHERE checkout=?1 AND closed=0)
            AND NOT EXISTS(SELECT 1 FROM adopted_groups WHERE checkout=?1)
            AND NOT EXISTS(SELECT 1 FROM capture_runs WHERE checkout=?1)
            AND NOT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1)",
            [self.allocation.checkout.to_string()],
            |r| r.get(0),
        )?;
        if !eligible {
            return Err(StoreError::Invalid);
        }
        self.fresh()?;
        if physical(conn, &self.allocation)? != self.physical {
            return Err(StoreError::Conflict);
        }
        self.fresh()
    }
    pub(crate) fn validate_capture(
        &self,
        conn: &Connection,
        root: &RootRunRequest,
        spec: &CaptureSpec,
    ) -> Result<()> {
        let digest: [u8; 32] =
            Sha256::digest(serde_json::to_vec(spec).map_err(|_| StoreError::Invalid)?).into();
        if self.spec_digest != digest {
            return Err(StoreError::Conflict);
        }
        self.validate(conn, root)
    }
    pub(crate) fn validate_writer(
        &self,
        conn: &Connection,
        checkout: uuid::Uuid,
        group: uuid::Uuid,
    ) -> Result<()> {
        if self.root.identity().checkout.to_string() != checkout.to_string()
            || self.root.identity().group.to_string() != group.to_string()
        {
            return Err(StoreError::Conflict);
        }
        self.validate(conn, &self.root)
    }
    pub(crate) fn fresh(&self) -> Result<()> {
        if Instant::now()
            .checked_duration_since(self.observed)
            .is_none_or(|age| age > MAX_AGE)
        {
            Err(StoreError::Conflict)
        } else {
            Ok(())
        }
    }
    pub(crate) fn preparation(&self) -> PendingPreparation {
        self.pending.clone()
    }
}
