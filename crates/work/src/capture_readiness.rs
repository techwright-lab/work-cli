//! Live capture closure and post-freeze readiness authority.
use crate::{
    capture_preparation::LiveCapture,
    run_journal::{GroupEmptyProof, GroupSnapshot, Transition},
    store::{Result, Store},
};

pub(crate) const SCHEMA: &str = "CREATE TABLE capture_readiness(checkout TEXT PRIMARY KEY REFERENCES checkouts(id), run TEXT NOT NULL REFERENCES capture_runs(run), certificate TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))); PRAGMA user_version=13;";
pub(crate) fn validate_schema(conn: &rusqlite::Connection) -> Result<()> {
    let ddl: String = conn.query_row(
        "SELECT sql FROM sqlite_schema WHERE name='capture_readiness' AND type='table'",
        [],
        |r| r.get(0),
    )?;
    let normalize = |s: &str| {
        s.chars()
            .filter(|c| !c.is_whitespace() && *c != '"')
            .collect::<String>()
            .to_ascii_lowercase()
    };
    if normalize(&ddl)
        != normalize(
            SCHEMA
                .split(';')
                .next()
                .ok_or(crate::store::StoreError::Invalid)?,
        )
    {
        return Err(crate::store::StoreError::Invalid);
    }
    Ok(())
}
pub(crate) struct ClosureSeal {
    root: crate::run_journal::RunRecord,
    context: crate::capture_finalization::ContextSeal,
    allocation: crate::capture_setup::PendingPreparation,
    authority: std::path::PathBuf,
    registry: std::path::PathBuf,
}
impl std::fmt::Debug for ClosureSeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClosureSeal([REDACTED])")
    }
}
impl Store {
    pub(crate) fn close_live_capture(
        &mut self,
        snapshot: &GroupSnapshot,
        proof: &GroupEmptyProof,
        live: &LiveCapture,
    ) -> Result<(Transition, Option<ClosureSeal>)> {
        self.close_supervised_group_context(snapshot, proof, Some(live))
    }
}
pub(crate) fn before_close(
    conn: &rusqlite::Connection,
    root: &crate::run_journal::RunRecord,
) -> Result<bool> {
    if root.recovery_hold || root.outcome.is_none() {
        return Ok(false);
    }
    Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 AND state='active' AND ready=1)
        AND NOT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1)
        AND NOT EXISTS(SELECT 1 FROM run_groups WHERE checkout=?1 AND id<>?2 AND (closed=0 OR recovery_hold<>0))
        AND NOT EXISTS(SELECT 1 FROM adopted_groups WHERE checkout=?1)", (root.request.identity().checkout.to_string(), root.request.identity().group.to_string()), |r| r.get(0))?)
}
pub(crate) fn closed(
    conn: &rusqlite::Connection,
    request: &crate::run_journal::RootRunRequest,
    live: &LiveCapture,
) -> Result<ClosureSeal> {
    use crate::store::StoreError;
    let root =
        crate::run_journal::read(conn, &request.identity().run)?.ok_or(StoreError::Invalid)?;
    let (capture, spec) =
        crate::capture_journal::qualified(conn, &root)?.ok_or(StoreError::Invalid)?;
    if !root.closed
        || root.recovery_hold
        || root.outcome.is_none()
        || !capture
            .group_end
            .as_ref()
            .is_some_and(|end| !end.clock_uncertain)
        || !live.closure_matches(request, &capture, &spec)
    {
        return Err(StoreError::Invalid);
    }
    let checkout = uuid::Uuid::parse_str(&request.identity().checkout.to_string())
        .map_err(|_| StoreError::Invalid)?;
    let eligible: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 AND state='held' AND ready=0)
        AND NOT EXISTS(SELECT 1 FROM writers WHERE checkout=?1)
        AND NOT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1)",
        [checkout.to_string()],
        |r| r.get(0),
    )?;
    if !eligible {
        return Err(StoreError::Invalid);
    }
    let allocation = crate::capture_setup::PendingPreparation::read(conn, checkout)?;
    let current = allocation.allocation()?;
    if current.checkout != checkout || current.stage != "ready" || current.reason.is_some() {
        return Err(StoreError::Invalid);
    }
    Ok(ClosureSeal {
        authority: std::path::PathBuf::from(conn.path().ok_or(StoreError::Invalid)?),
        registry: live.authority_registry().to_owned(),
        context: crate::capture_finalization::context(&root, &capture, &spec)?,
        root,
        allocation,
    })
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Certificate {
    version: u32,
    checkout: uuid::Uuid,
    run: work_contract::RunId,
    stable: [u8; 32],
    physical: crate::capture_setup::Physical,
    frontier: [u8; 32],
    registry: std::path::PathBuf,
    store: std::path::PathBuf,
}
fn hash(value: &impl serde::Serialize) -> Result<[u8; 32]> {
    use sha2::Digest;
    Ok(sha2::Sha256::digest(crate::capture_journal::json(value)?.as_bytes()).into())
}
fn stable(conn: &rusqlite::Connection, a: &crate::allocate::Allocation) -> Result<[u8; 32]> {
    let requirement = crate::capture_requirement::read(conn, a.checkout)?
        .ok_or(crate::store::StoreError::Invalid)?;
    let charge: (String, Vec<u8>, String, String, String) = conn.query_row(
        "SELECT operation,digest,repository,actor,task FROM checkouts WHERE id=?1",
        [a.checkout.to_string()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )?;
    hash(&(
        "work.capture-readiness.allocation.v1",
        a.checkout,
        &a.request,
        &a.destination,
        &a.base_commit,
        requirement,
        charge,
    ))
}
fn frontier(conn: &rusqlite::Connection, checkout: uuid::Uuid) -> Result<[u8; 32]> {
    frontier_except(conn, checkout, "")
}
fn frontier_except(
    conn: &rusqlite::Connection,
    checkout: uuid::Uuid,
    current: &str,
) -> Result<[u8; 32]> {
    let _snapshot = crate::run_journal::read_transaction(conn)?;
    frontier_prequery(conn, checkout, current)?;
    crate::run_journal::with_capture_history(conn, checkout, |history| {
        frontier_fold(checkout, current, &history)
    })
}
pub(crate) fn frontier_prequery(
    conn: &rusqlite::Connection,
    checkout: uuid::Uuid,
    current: &str,
) -> Result<()> {
    use crate::store::StoreError;
    let invalid: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM run_groups g WHERE checkout=?1 AND g.id NOT IN (SELECT group_id FROM capture_runs WHERE run=?2) AND (closed=0 OR recovery_hold<>0 OR NOT EXISTS(SELECT 1 FROM capture_runs c WHERE c.group_id=g.id))) OR EXISTS(SELECT 1 FROM adopted_groups WHERE checkout=?1) OR EXISTS(SELECT 1 FROM runs r LEFT JOIN run_groups g ON g.id=r.group_id WHERE g.id IS NULL)", (checkout.to_string(),current), |r| r.get(0))?;
    if invalid {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
pub(crate) fn frontier_fold(
    checkout: uuid::Uuid,
    current: &str,
    history: &[(
        crate::run_journal::RunRecord,
        crate::capture_journal::QualifiedTerminal,
    )],
) -> Result<[u8; 32]> {
    use crate::store::StoreError;
    use sha2::Digest;
    let mut digest = sha2::Sha256::new();
    digest.update(b"work.capture-readiness.frontier.v1\0");
    digest.update(checkout.as_bytes());
    let mut any = false;
    for (root, (capture, _spec, frozen)) in history {
        let id = &root.request.identity().run;
        if id.to_string() == current {
            continue;
        }
        let frozen = frozen.as_ref().ok_or(StoreError::Invalid)?;
        if frozen.confirmation.is_none() {
            return Err(StoreError::Invalid);
        }
        digest.update(hash(&(id, capture.operation, &frozen.intent))?);
        any = true;
    }
    if !any {
        return Err(StoreError::Invalid);
    }
    Ok(digest.finalize().into())
}
impl ClosureSeal {
    fn validate(
        &self,
        conn: &rusqlite::Connection,
        ack: &crate::capture_finalization::FreezeAcknowledgement,
    ) -> Result<crate::allocate::Allocation> {
        use crate::store::StoreError;
        let checkout = uuid::Uuid::parse_str(&self.root.request.identity().checkout.to_string())
            .map_err(|_| StoreError::Invalid)?;
        if self.authority.to_str() != conn.path()
            || ack.run() != &self.root.request.identity().run
            || ack.intent().context != self.context
            || crate::capture_setup::PendingPreparation::read(conn, checkout)? != self.allocation
            || crate::run_journal::read(conn, ack.run())?.as_ref() != Some(&self.root)
        {
            return Err(StoreError::Conflict);
        }
        let eligible: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 AND state='held' AND ready=0) AND NOT EXISTS(SELECT 1 FROM writers WHERE checkout=?1) AND NOT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1)", [checkout.to_string()], |r| r.get(0))?;
        if !eligible {
            return Err(StoreError::Invalid);
        }
        let (capture, spec) =
            crate::capture_journal::qualified(conn, &self.root)?.ok_or(StoreError::Invalid)?;
        let frozen = crate::capture_finalization::validate(conn, &self.root, &capture, &spec)?
            .ok_or(StoreError::Invalid)?;
        if &frozen.intent != ack.intent() || frozen.confirmation.is_none() {
            return Err(StoreError::Conflict);
        }
        let allocation = self.allocation.allocation()?;
        if allocation.checkout != checkout
            || allocation.stage != "ready"
            || allocation.reason.is_some()
        {
            return Err(StoreError::Invalid);
        }
        Ok(allocation)
    }
}
fn fresh(observed: std::time::Instant) -> Result<()> {
    if std::time::Instant::now()
        .checked_duration_since(observed)
        .is_none_or(|age| age > std::time::Duration::from_secs(2))
    {
        return Err(crate::store::StoreError::Conflict);
    }
    Ok(())
}
pub(crate) fn restore(
    config: &crate::config::Config,
    seal: ClosureSeal,
    ack: crate::capture_finalization::FreezeAcknowledgement,
) -> Result<()> {
    use crate::store::StoreError;
    let dir = config.store_dir.as_ref().ok_or(StoreError::Invalid)?;
    let registry = config
        .trusted_registry
        .as_ref()
        .ok_or(StoreError::Invalid)?;
    if registry != &seal.registry {
        return Err(StoreError::Conflict);
    }
    let mut store = Store::open_existing_registered_mut(registry, dir, &config.roots)?;
    let (mut allocation, frontier_before, stable_before) = {
        let _phase = store.sql_phase();
        let _snapshot = crate::run_journal::read_transaction(&store.conn)?;
        let a = seal.validate(&store.conn, &ack)?;
        let frontier = frontier(&store.conn, a.checkout)?;
        let stable = stable(&store.conn, &a)?;
        (a, frontier, stable)
    };
    // No SQL phase, read transaction or allocator flock spans either inspection.
    let observed = std::time::Instant::now();
    let physical =
        crate::capture_setup::inspect_physical(&allocation, seal.allocation.source_common())?;
    let registry = registry.canonicalize()?;
    let authority = dir.canonicalize()?;
    let mut reinspection = allocation.clone();
    reinspection.identity = Some(physical.checkout.clone());
    if physical
        != crate::capture_setup::inspect_physical(&reinspection, seal.allocation.source_common())?
    {
        return Err(StoreError::Conflict);
    }
    #[cfg(test)]
    tests::observe("physical", &store.conn, observed);
    fresh(observed)?;
    let lease = store.authority_lease()?;
    lease.check(&store)?;
    let _phase = store.sql_phase();
    let tx = store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    fresh(observed)?;
    seal.validate(&tx, &ack)?;
    if frontier(&tx, allocation.checkout)? != frontier_before
        || stable(&tx, &allocation)? != stable_before
    {
        return Err(StoreError::Conflict);
    }
    allocation.identity = Some(physical.checkout.clone());
    let certificate = Certificate {
        version: 1,
        checkout: allocation.checkout,
        run: ack.run().clone(),
        stable: stable_before,
        physical,
        frontier: frontier_before,
        registry,
        store: authority,
    };
    tx.execute("INSERT INTO capture_readiness(checkout,run,certificate) VALUES(?1,?2,?3) ON CONFLICT(checkout) DO UPDATE SET run=excluded.run,certificate=excluded.certificate,revoked=0", (allocation.checkout.to_string(), ack.run().to_string(), crate::capture_journal::json(&certificate)?))?;
    tx.execute(
        "UPDATE allocations SET record=?2 WHERE checkout=?1",
        (
            allocation.checkout.to_string(),
            crate::capture_journal::json(&allocation)?,
        ),
    )?;
    let changed = tx.execute(
        "UPDATE checkouts SET state='active',ready=1 WHERE id=?1 AND state='held' AND ready=0",
        [allocation.checkout.to_string()],
    )?;
    if changed != 1 {
        return Err(StoreError::Conflict);
    }
    crate::store::emit(
        &tx,
        &crate::events::Event::AllocationStage {
            checkout: allocation.checkout,
            operation: allocation.request.operation,
            stage: "ready".into(),
            reason: None,
        },
    )?;
    #[cfg(test)]
    tests::observe("commit", &tx, observed);
    fresh(observed)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn invalidate(
    conn: &rusqlite::Connection,
    checkout: uuid::Uuid,
    lease: &crate::allocate::AuthorityLease,
    authority: &std::sync::Arc<crate::store::AuthorityIdentity>,
) -> Result<()> {
    lease.check_authority(authority)?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version >= 13 {
        conn.execute(
            "UPDATE capture_readiness SET revoked=1 WHERE checkout=?1",
            [checkout.to_string()],
        )?;
    }
    Ok(())
}
pub(crate) fn guard_certified_identity(
    conn: &rusqlite::Connection,
    checkout: uuid::Uuid,
) -> Result<()> {
    use crate::store::StoreError;
    let _snapshot = crate::run_journal::read_transaction(conn)?;
    let cert = certificate(conn, checkout)?;
    let a = crate::capture_setup::PendingPreparation::read(conn, checkout)?.allocation()?;
    if stable(conn, &a)? != cert.stable || a.stage != "ready" || a.reason.is_some() {
        return Err(StoreError::Conflict);
    }
    let mut current = None;
    let mut query=conn.prepare("SELECT r.id FROM runs r JOIN run_groups g ON g.id=r.group_id WHERE g.checkout=?1 AND g.closed=0")?;
    let rows = query.query_map([checkout.to_string()], |r| r.get::<_, String>(0))?;
    for row in rows {
        if current.is_some() {
            return Err(StoreError::Invalid);
        }
        let run = work_contract::RunId::parse(&row?).map_err(|_| StoreError::Invalid)?;
        let root = crate::run_journal::read(conn, &run)?.ok_or(StoreError::Invalid)?;
        let capture = crate::capture_journal::read(conn, &root)?.ok_or(StoreError::Invalid)?;
        let writer: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM writers WHERE checkout=?1 AND group_id=?2)",
            (
                checkout.to_string(),
                root.request.identity().group.to_string(),
            ),
            |r| r.get(0),
        )?;
        if root.recovery_hold
            || root.outcome.is_some()
            || !writer
            || !capture.prepared.is_some_and(|p| p.live_preparation)
        {
            return Err(StoreError::Invalid);
        }
        current = Some(run.to_string());
    }
    let writers: i64 = conn.query_row(
        "SELECT count(*) FROM writers WHERE checkout=?1",
        [checkout.to_string()],
        |r| r.get(0),
    )?;
    if writers != i64::from(current.is_some()) {
        return Err(StoreError::Invalid);
    }
    if frontier_except(conn, checkout, current.as_deref().unwrap_or(""))? != cert.frontier {
        return Err(StoreError::Conflict);
    }
    Ok(())
}
fn certificate(conn: &rusqlite::Connection, checkout: uuid::Uuid) -> Result<Certificate> {
    use crate::store::StoreError;
    let (run, body): (String,String) = conn.query_row("SELECT run,certificate FROM capture_readiness WHERE checkout=?1 AND revoked=0", [checkout.to_string()], |r| {
        if matches!(r.get_ref(1)?, rusqlite::types::ValueRef::Text(b) if b.len() > crate::capture_journal::MAX_RECORD_BYTES) { return Err(rusqlite::Error::InvalidQuery); }
        Ok((r.get(0)?, r.get(1)?))
    })?;
    let cert: Certificate = crate::capture_journal::strict(&body)?;
    if !matches!(cert.physical.checkout.head.len(), 40 | 64)
        || !cert
            .physical
            .checkout
            .head
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || cert.version != 1
        || cert.checkout != checkout
        || cert.run.to_string() != run
        || cert.store.join("store.sqlite").to_str() != conn.path()
        || !cert.registry.is_absolute()
    {
        return Err(StoreError::Conflict);
    }
    Ok(cert)
}
fn ready(conn: &rusqlite::Connection, checkout: uuid::Uuid) -> Result<()> {
    let eligible: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 AND state='active' AND ready=1) AND NOT EXISTS(SELECT 1 FROM writers WHERE checkout=?1) AND NOT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1) AND NOT EXISTS(SELECT 1 FROM runs r LEFT JOIN run_groups g ON g.id=r.group_id WHERE g.id IS NULL)", [checkout.to_string()], |r| r.get(0))?;
    if !eligible {
        return Err(crate::store::StoreError::Invalid);
    }
    Ok(())
}
pub(crate) struct ContinuationProof {
    root: crate::run_journal::RootRunRequest,
    spec: [u8; 32],
    pending: crate::capture_setup::PendingPreparation,
    certificate: [u8; 32],
    anchor: crate::allocate::Allocation,
    physical: crate::capture_setup::Physical,
    observed: std::time::Instant,
}
impl ContinuationProof {
    pub(crate) fn inspect(
        store: &Store,
        cfg: &crate::config::Config,
        root: &crate::run_journal::RootRunRequest,
        spec: &crate::capture_journal::CaptureSpec,
    ) -> Result<Self> {
        use crate::store::StoreError;
        let (mut anchor, pending, cert) = {
            let _phase = store.sql_phase();
            let _snapshot = crate::run_journal::read_transaction(&store.conn)?;
            let a = spec.agrees(&store.conn, root)?;
            ready(&store.conn, a.checkout)?;
            if a.stage != "ready" || a.reason.is_some() {
                return Err(StoreError::Invalid);
            }
            let cert = certificate(&store.conn, a.checkout)?;
            if stable(&store.conn, &a)? != cert.stable
                || frontier(&store.conn, a.checkout)? != cert.frontier
                || cfg.trusted_registry.as_ref() != Some(&cert.registry)
                || cfg.store_dir.as_ref() != Some(&cert.store)
            {
                return Err(StoreError::Conflict);
            }
            let identity = a.identity.as_ref().ok_or(StoreError::Invalid)?;
            let certified = &cert.physical.checkout;
            if identity.path != certified.path
                || identity.private_git_dir != certified.private_git_dir
                || identity.common_git_dir != certified.common_git_dir
                || identity.directory.inode != certified.directory.inode
            {
                return Err(StoreError::Conflict);
            }
            let pending = crate::capture_setup::PendingPreparation::read(&store.conn, a.checkout)?;
            (a, pending, cert)
        };
        // Preserve current durable ancestry first; the older certificate cannot
        // erase a HEAD advance already observed by normal identity refresh.
        let observed = std::time::Instant::now();
        let physical = crate::capture_setup::inspect_physical(&anchor, pending.source_common())?;
        if cert.physical.checkout.head != physical.checkout.head {
            crate::identity::query(
                &physical.checkout.path,
                &[
                    "merge-base",
                    "--is-ancestor",
                    &cert.physical.checkout.head,
                    &physical.checkout.head,
                ],
            )?;
        }
        if physical.marker != cert.physical.marker
            || physical.directories.len() != cert.physical.directories.len()
            || physical
                .directories
                .iter()
                .zip(&cert.physical.directories)
                .any(|(a, b)| {
                    a.1 != b.1
                        || (physical.checkout.boot_id == cert.physical.checkout.boot_id
                            && a.0 != b.0)
                })
            || root.input().boot != physical.checkout.boot_id
        {
            return Err(StoreError::Conflict);
        }
        // Reinspection must match this actual observation. Successful descent
        // uses at most one additional certificate graph check, never one per
        // history row or a repeated check during unchanged physical reinspection.
        anchor.identity = Some(physical.checkout.clone());
        let proof = Self {
            root: root.clone(),
            spec: hash(spec)?,
            pending,
            certificate: hash(&cert)?,
            anchor,
            physical,
            observed,
        };
        proof.fresh()?;
        Ok(proof)
    }
    pub(crate) fn reinspect(&self, store: &Store) -> Result<()> {
        if !store.conn.is_autocommit() {
            return Err(crate::store::StoreError::Invalid);
        }
        self.fresh()?;
        if crate::capture_setup::inspect_physical(&self.anchor, self.pending.source_common())?
            != self.physical
        {
            return Err(crate::store::StoreError::Conflict);
        }
        self.fresh()
    }
    fn validate(
        &self,
        conn: &rusqlite::Connection,
        related: &crate::capture_setup::Related<'_, '_>,
    ) -> Result<()> {
        use crate::store::StoreError;
        related.check(conn, self.anchor.checkout)?;
        self.fresh()?;
        ready(conn, self.anchor.checkout)?;
        if crate::capture_setup::PendingPreparation::read(conn, self.anchor.checkout)?
            != self.pending
        {
            return Err(StoreError::Conflict);
        }
        let cert = certificate(conn, self.anchor.checkout)?;
        if hash(&cert)? != self.certificate
            || related.frontier(conn, self.anchor.checkout)? != cert.frontier
        {
            return Err(StoreError::Conflict);
        }
        self.fresh()
    }
    pub(crate) fn validate_capture(
        &self,
        conn: &rusqlite::Connection,
        root: &crate::run_journal::RootRunRequest,
        spec: &crate::capture_journal::CaptureSpec,
        related: &crate::capture_setup::Related<'_, '_>,
    ) -> Result<()> {
        if root != &self.root || hash(spec)? != self.spec {
            return Err(crate::store::StoreError::Conflict);
        }
        self.validate(conn, related)
    }
    pub(crate) fn validate_writer(
        &self,
        conn: &rusqlite::Connection,
        checkout: uuid::Uuid,
        group: uuid::Uuid,
        related: &crate::capture_setup::Related<'_, '_>,
    ) -> Result<()> {
        if checkout != self.anchor.checkout
            || group.to_string() != self.root.identity().group.to_string()
        {
            return Err(crate::store::StoreError::Conflict);
        }
        self.validate(conn, related)
    }
    pub(crate) fn fresh(&self) -> Result<()> {
        fresh(self.observed)
    }
    pub(crate) fn preparation(&self) -> crate::capture_setup::PendingPreparation {
        self.pending.clone()
    }
}

#[cfg(test)]
use crate::test_run_fixture as fixture;
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::capture_diagnostics::{outside_sql_span, FrameName};

    // Only existing top-level test calls use this wrapper. Product frames (and
    // their SQL/TX/flock locals) return or unwind before the CPU guard drops;
    // the caller's original unwrap/expect/assert remains outside the sample.
    fn measured_finish(
        cfg: &crate::config::Config,
        checkout: uuid::Uuid,
    ) -> crate::store::Result<crate::finish::Report> {
        let _cpu = outside_sql_span(FrameName::WholeFinish);
        crate::finish::finish(cfg, checkout)
    }
    type Observer = Box<dyn FnMut(&str, &rusqlite::Connection, std::time::Instant)>;
    thread_local! { static OBSERVER: std::cell::RefCell<Option<Observer>> = std::cell::RefCell::new(None); }
    pub(super) fn observe(stage: &str, conn: &rusqlite::Connection, at: std::time::Instant) {
        OBSERVER.with(|o| {
            if let Some(callback) = o.borrow_mut().as_mut() {
                callback(stage, conn, at)
            }
        });
    }
    struct Observation;
    impl Drop for Observation {
        fn drop(&mut self) {
            OBSERVER.with(|o| *o.borrow_mut() = None);
        }
    }
    fn observing(
        f: impl FnMut(&str, &rusqlite::Connection, std::time::Instant) + 'static,
    ) -> Observation {
        OBSERVER.with(|o| *o.borrow_mut() = Some(Box::new(f)));
        Observation
    }
    #[test]
    fn post_inspection_durable_changes_fail_the_locked_exact_cas() {
        for change in ["owner", "requirement", "finish", "writer", "allocation"] {
            let (_temp, cfg, store, a, _r, seal, ack) = closed();
            let dir = cfg.store_dir.clone().unwrap();
            let _observation = observing(move |stage, _, _| {
                if stage != "physical" {
                    return;
                }
                let other = rusqlite::Connection::open(dir.join("store.sqlite")).unwrap();
                match change {
                    "owner" => {
                        other
                            .execute("UPDATE checkouts SET owner='late-owner'", [])
                            .unwrap();
                    }
                    "requirement" => {
                        other
                            .execute("UPDATE capture_requirements SET revision=revision+1", [])
                            .unwrap();
                    }
                    "finish" => {
                        other
                            .execute(
                                "INSERT INTO task_finishes VALUES(?1,?2,'{}')",
                                (a.checkout.to_string(), uuid::Uuid::now_v7().to_string()),
                            )
                            .unwrap();
                    }
                    "writer" => {
                        other
                            .execute(
                                "INSERT INTO writers VALUES(?1,?2)",
                                (a.checkout.to_string(), uuid::Uuid::now_v7().to_string()),
                            )
                            .unwrap();
                    }
                    "allocation" => {
                        other
                            .execute("UPDATE allocations SET record='{}'", [])
                            .unwrap();
                    }
                    _ => unreachable!(),
                }
            });
            assert!(
                restore(&cfg, seal, ack).is_err(),
                "{change} changed after actual FS but bypassed locked CAS"
            );
            assert!(!store
                .conn
                .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
                .unwrap());
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT count(*) FROM capture_readiness", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }
    #[test]
    fn external_physical_delay_does_not_hold_sql_or_allocator_authority() {
        let (_temp, cfg, store, _a, _r, seal, ack) = closed();
        let dir = cfg.store_dir.clone().unwrap();
        let lock_store = Store::open_existing_registered_mut(
            cfg.trusted_registry.as_ref().unwrap(),
            &dir,
            &cfg.roots,
        )
        .unwrap();
        let _observation = observing(move |stage, conn, _| {
            if stage != "physical" {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(650));
            assert!(conn.is_autocommit());
            let other = rusqlite::Connection::open(dir.join("store.sqlite")).unwrap();
            other.busy_timeout(std::time::Duration::ZERO).unwrap();
            other.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
            drop(crate::allocate::lifecycle_lock(&lock_store).unwrap());
            let sum:i64=conn.query_row("WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<5000) SELECT sum(x) FROM n",[],|r|r.get(0)).unwrap();
            assert_eq!(sum, 12_502_500);
        });
        restore(&cfg, seal, ack).unwrap();
        assert!(store
            .conn
            .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
            .unwrap());
    }
    #[test]
    fn original_post_ack_proof_expires_after_real_flock_contention_or_near_commit() {
        use std::time::Duration;
        for stage in ["contention", "commit"] {
            let (_temp, cfg, store, _a, _r, seal, ack) = closed();
            let dir = cfg.store_dir.clone().unwrap();
            let lock_store = Store::open_existing_registered_mut(
                cfg.trusted_registry.as_ref().unwrap(),
                &dir,
                &cfg.roots,
            )
            .unwrap();
            let joined = std::rc::Rc::new(std::cell::RefCell::new(None));
            let child = joined.clone();
            let _observation = observing(move |boundary, conn, at| {
                if boundary == "physical" {
                    assert!(conn.is_autocommit());
                    let other = rusqlite::Connection::open(dir.join("store.sqlite")).unwrap();
                    other.busy_timeout(Duration::ZERO).unwrap();
                    other.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
                    std::thread::sleep(Duration::from_millis(1750).saturating_sub(at.elapsed()));
                    if stage == "contention" {
                        let lock = crate::allocate::lifecycle_lock(&lock_store).unwrap();
                        *child.borrow_mut() = Some(std::thread::spawn(move || {
                            std::thread::sleep(Duration::from_millis(350));
                            drop(lock);
                        }));
                    }
                }
                if boundary == "commit" && stage == "commit" {
                    std::thread::sleep(Duration::from_millis(2100).saturating_sub(at.elapsed()));
                }
            });
            let result = restore(&cfg, seal, ack);
            assert!(
                matches!(result, Err(crate::store::StoreError::Conflict)),
                "{stage} must refuse expired original proof, not another budget: {result:?}"
            );
            if let Some(thread) = joined.borrow_mut().take() {
                thread.join().unwrap();
            }
            assert!(!store
                .conn
                .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
                .unwrap());
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT count(*) FROM capture_readiness", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }
    #[test]
    fn live_closure_cannot_be_transplanted_to_another_registered_authority() {
        use std::os::unix::fs::PermissionsExt;
        let (temp, cfg, store, _a, _root, seal, ack) = closed();
        let backup = temp.path().join("copied.sqlite");
        store
            .conn
            .execute("VACUUM INTO ?1", [backup.to_str().unwrap()])
            .unwrap();
        std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut other = cfg.clone();
        other.store_dir = Some(temp.path().join("other-private"));
        other.trusted_registry = Some(temp.path().join("other-registry"));
        let keeper = Store::open_registered(
            other.trusted_registry.as_ref().unwrap(),
            other.store_dir.as_ref().unwrap(),
            &other.roots,
        )
        .unwrap();
        keeper
            .conn
            .execute_batch("PRAGMA foreign_keys=OFF")
            .unwrap();
        keeper
            .conn
            .execute("ATTACH DATABASE ?1 AS copied", [backup.to_str().unwrap()])
            .unwrap();
        let tables=keeper.conn.prepare("SELECT name FROM copied.sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").unwrap().query_map([],|r|r.get::<_,String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        for table in tables {
            keeper
                .conn
                .execute(
                    &format!("INSERT OR REPLACE INTO main.{table} SELECT * FROM copied.{table}"),
                    [],
                )
                .unwrap();
        }
        keeper
            .conn
            .execute_batch("DETACH DATABASE copied; PRAGMA foreign_keys=ON")
            .unwrap();
        assert_eq!(
            keeper
                .conn
                .query_row("SELECT count(*) FROM capture_finalizations", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        let result = restore(&other, seal, ack);
        assert!(
            matches!(result, Err(crate::store::StoreError::Conflict)),
            "copied database must fail the live authority binding: {result:?}"
        );
    }
    #[test]
    fn unknown_outcome_or_backward_clock_cannot_veto_physical_closure() {
        for case in ["unknown", "clock", "frame", "hold"] {
            let uncertain_clock = case == "clock";
            let (_temp, cfg, _a, root, spec) =
                crate::capture_preparation::tests::qualified_fixture();
            let (mut store, crate::capture_preparation::PreparationResult::Live(live)) =
                crate::capture_preparation::prepare(&cfg, &root, &spec).unwrap()
            else {
                panic!("live")
            };
            let binding = fixture::binding(&root);
            store.record_bound(&root, &binding).unwrap();
            store.record_permit_attempt(&root, &binding).unwrap();
            if case != "unknown" {
                store
                    .record_root_outcome(&root, crate::run_journal::RootOutcome::Completed)
                    .unwrap();
            }
            if uncertain_clock || case == "frame" {
                let mut prepared = serde_json::to_value(
                    store
                        .capture_snapshot(&root.identity().run)
                        .unwrap()
                        .unwrap()
                        .prepared
                        .unwrap(),
                )
                .unwrap();
                if uncertain_clock {
                    prepared["observed_wall"] = "2999-01-01T00:00:00+00:00".into();
                    store.conn.execute("UPDATE capture_runs SET intent_wall='2999-01-01T00:00:00+00:00',prepared=?1",[prepared.to_string()]).unwrap();
                } else {
                    prepared["context_artifact"]["sha256"] =
                        serde_json::to_value([0u8; 32]).unwrap();
                    store
                        .conn
                        .execute(
                            "UPDATE capture_runs SET prepared=?1",
                            [prepared.to_string()],
                        )
                        .unwrap();
                }
            }
            if case == "hold" {
                let mut a =
                    crate::capture_setup::PendingPreparation::read(&store.conn, _a.checkout)
                        .unwrap()
                        .allocation()
                        .unwrap();
                a.stage = "held".into();
                a.reason = Some("known unrelated hold".into());
                store
                    .conn
                    .execute(
                        "UPDATE allocations SET record=?1",
                        [serde_json::to_string(&a).unwrap()],
                    )
                    .unwrap();
            }
            let os = fixture::ClosureOs::new(&root, &binding);
            let snapshot = store.group_snapshot(&root.identity().run).unwrap();
            let proof = snapshot.certify_empty(&os.driver, &binding).unwrap();
            let (transition, seal) = store.close_live_capture(&snapshot, &proof, &live).unwrap();
            assert!(matches!(transition, Transition::Changed));
            assert!(seal.is_none());
            let record = store.run_snapshot(&root.identity().run).unwrap().unwrap();
            assert!(record.closed);
            assert_eq!(record.outcome.is_some(), case != "unknown");
            assert!(!store
                .conn
                .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
                .unwrap());
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                0
            );
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT count(*) FROM capture_finalizations", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }
    #[test]
    fn live_closure_cannot_switch_trusted_registry_for_the_same_store() {
        let (temp, cfg, _store, _a, _root, seal, ack) = closed();
        let mut other = cfg.clone();
        other.trusted_registry = Some(temp.path().join("second-registry"));
        use std::os::unix::fs::PermissionsExt;
        let registry = other.trusted_registry.as_ref().unwrap();
        std::fs::create_dir(registry).unwrap();
        std::fs::set_permissions(registry, std::fs::Permissions::from_mode(0o700)).unwrap();
        let original = cfg.trusted_registry.as_ref().unwrap();
        let marker = registry.join("initialization.json");
        std::fs::write(
            &marker,
            std::fs::read(original.join("initialization.json")).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(marker, std::fs::Permissions::from_mode(0o600)).unwrap();
        let source = rusqlite::Connection::open(original.join("authorities.sqlite")).unwrap();
        let database = registry.join("authorities.sqlite");
        source
            .execute("VACUUM INTO ?1", [database.to_str().unwrap()])
            .unwrap();
        std::fs::set_permissions(database, std::fs::Permissions::from_mode(0o600)).unwrap();
        let _keeper = Store::open_registered(
            other.trusted_registry.as_ref().unwrap(),
            other.store_dir.as_ref().unwrap(),
            &other.roots,
        )
        .unwrap();
        assert!(
            matches!(
                restore(&other, seal, ack),
                Err(crate::store::StoreError::Conflict)
            ),
            "live closure switched trusted authority registry"
        );
    }
    #[test]
    fn actual_finish_acknowledgement_for_another_root_cannot_match_live_closure() {
        let (_temp, cfg, store, _a, _root, seal, _ack) = closed();
        let (_other_temp, _other_cfg, _other_store, _other_a, _other_root, _other_seal, other_ack) =
            closed();
        assert!(matches!(
            restore(&cfg, seal, other_ack),
            Err(crate::store::StoreError::Conflict)
        ));
        assert!(!store
            .conn
            .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
            .unwrap());
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM capture_readiness", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn late_durable_or_physical_change_retains_capture_hold() {
        for change in [
            "owner",
            "requirement",
            "allocation",
            "marker",
            "branch",
            "state",
            "finish",
        ] {
            let (_temp, cfg, store, a, _root, seal, ack) = closed();
            match change {
                "owner" => {
                    store
                        .conn
                        .execute("UPDATE checkouts SET owner='other'", [])
                        .unwrap();
                }
                "requirement" => {
                    store
                        .conn
                        .execute("UPDATE capture_requirements SET revision=revision+1", [])
                        .unwrap();
                }
                "allocation" => {
                    let mut changed = a.clone();
                    changed.stage = "held".into();
                    store
                        .conn
                        .execute(
                            "UPDATE allocations SET record=?1",
                            [serde_json::to_string(&changed).unwrap()],
                        )
                        .unwrap();
                }
                "marker" => {
                    std::fs::write(
                        a.identity
                            .as_ref()
                            .unwrap()
                            .private_git_dir
                            .join("work-lease.json"),
                        b"{}",
                    )
                    .unwrap();
                }
                "branch" => {
                    assert!(std::process::Command::new("/usr/bin/git")
                        .args(["symbolic-ref", "HEAD", "refs/heads/other"])
                        .current_dir(&a.destination)
                        .status()
                        .unwrap()
                        .success());
                }
                "state" => {
                    store
                        .conn
                        .execute("UPDATE checkouts SET state='expired'", [])
                        .unwrap();
                }
                "finish" => {
                    store.conn.execute("INSERT INTO task_finishes(checkout,operation,record) VALUES(?1,?2,'{}')", (a.checkout.to_string(),uuid::Uuid::now_v7().to_string())).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                restore(&cfg, seal, ack).is_err(),
                "{change} bypassed closed context"
            );
            assert!(!store
                .conn
                .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
                .unwrap());
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT count(*) FROM capture_readiness", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
            assert_eq!(
                store
                    .charged(a.request.repository.as_ref().unwrap(), None)
                    .unwrap(),
                1
            );
        }
    }
    #[test]
    fn strict_json_preserves_typed_roundtrip_and_rejects_noncanonical_shapes() {
        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct Nested {
            text: String,
        }
        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct Shape {
            nested: Nested,
            #[serde(default)]
            count: u64,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            optional: Option<String>,
        }
        for text in [
            "é".to_owned(),
            "é".repeat((crate::capture_journal::MAX_RECORD_BYTES - 80) / 2),
        ] {
            let bytes = serde_json::to_string(&Shape {
                nested: Nested { text },
                count: 0,
                optional: None,
            })
            .unwrap();
            let value: serde_json::Value = serde_json::from_str(&bytes).unwrap();
            let reference: Shape = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(&reference).unwrap(), value);
            assert_eq!(
                crate::capture_journal::strict::<Shape>(&bytes).unwrap(),
                reference
            );
        }
        for bytes in [
            r#"{"nested":{"text":"a","unknown":1},"count":0}"#,
            r#"{"nested":{"text":"a","text":"b"},"count":0}"#,
            r#"{"nested":{"text":"a"},"count":0,"count":0}"#,
            r#"{"nested":["a"],"count":0}"#,
            r#"[{"text":"a"},0,null]"#,
            r#"{"nested":{"text":"a"}}"#,
            r#"{"nested":{"text":"a"},"count":0,"optional":null}"#,
            r#"{"nested":{"text":"a"},"count":"0"}"#,
        ] {
            assert!(
                matches!(
                    crate::capture_journal::strict::<Shape>(bytes),
                    Err(crate::store::StoreError::Invalid)
                ),
                "{bytes}"
            );
        }
        let oversized = serde_json::to_string(&Shape {
            nested: Nested {
                text: "é".repeat(crate::capture_journal::MAX_RECORD_BYTES / 2),
            },
            count: 0,
            optional: None,
        })
        .unwrap();
        assert!(matches!(
            crate::capture_journal::strict::<Shape>(&oversized),
            Err(crate::store::StoreError::Invalid)
        ));
    }
    #[test]
    fn related_witness_is_connection_bound_and_frontier_bytes_match_reference() {
        many_closed_history(|cfg, store, a, original| {
            use sha2::Digest;
            let other =
                rusqlite::Connection::open(cfg.store_dir.as_ref().unwrap().join("store.sqlite"))
                    .unwrap();
            let tx = rusqlite::Transaction::new_unchecked(
                &store.conn,
                rusqlite::TransactionBehavior::Immediate,
            )
            .unwrap();
            let related = crate::capture_setup::Related::qualify(&tx, a.checkout).unwrap();
            assert!(related.check(&tx, a.checkout).is_ok());
            assert!(matches!(
                related.check(&other, a.checkout),
                Err(crate::store::StoreError::Conflict)
            ));
            assert!(matches!(
                related.frontier(&other, a.checkout),
                Err(crate::store::StoreError::Conflict)
            ));
            assert!(matches!(
                related.check(&tx, uuid::Uuid::now_v7()),
                Err(crate::store::StoreError::Conflict)
            ));
            let reference = crate::run_journal::with_capture_history(&tx, a.checkout, |history| {
                let mut digest = sha2::Sha256::new();
                digest.update(b"work.capture-readiness.frontier.v1\0");
                digest.update(a.checkout.as_bytes());
                let mut ids = Vec::new();
                for (root, (capture, spec, frozen)) in &history {
                    let id = &root.request.identity().run;
                    ids.push(id.to_string());
                    let frozen = frozen.as_ref().unwrap();
                    assert!(frozen.confirmation.is_some());
                    assert!(
                        frozen.intent.context
                            == crate::capture_finalization::context(root, capture, spec)?
                    );
                    // The fresh standalone reader retains every validator, and
                    // must produce identical durable DTO bytes to batch reads.
                    let fresh = crate::capture_journal::qualified_terminal(&tx, root)?.unwrap();
                    assert_eq!(
                        crate::capture_journal::json(&(capture, spec, &frozen.intent))?,
                        crate::capture_journal::json(&(
                            &fresh.0,
                            &fresh.1,
                            &fresh.2.unwrap().intent
                        ))?
                    );
                    digest.update(hash(&(id, capture.operation, frozen.intent.clone()))?);
                }
                assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
                // Exercise the original skip rule independently of the empty
                // current-run admission fold.
                let current = original.identity().run.to_string();
                let mut skipped = sha2::Sha256::new();
                skipped.update(b"work.capture-readiness.frontier.v1\0");
                skipped.update(a.checkout.as_bytes());
                for (root, (capture, _, frozen)) in &history {
                    let id = &root.request.identity().run;
                    if id.to_string() != current {
                        skipped.update(hash(&(
                            id,
                            capture.operation,
                            frozen.as_ref().unwrap().intent.clone(),
                        ))?);
                    }
                }
                assert_eq!(
                    frontier_fold(a.checkout, &current, &history)?,
                    <[u8; 32]>::from(skipped.finalize())
                );
                Ok(<[u8; 32]>::from(digest.finalize()))
            })
            .unwrap();
            assert_eq!(related.frontier(&tx, a.checkout).unwrap(), reference);
            assert_eq!(certificate(&tx, a.checkout).unwrap().frontier, reference);
            drop(related);
            tx.rollback().unwrap();
        });
    }
    #[test]
    fn certified_existing_precedes_unconfirmed_frontier_and_proof_subject() {
        let (_temp, cfg, mut store, a, root, seal, ack) = closed();
        restore(&cfg, seal, ack).unwrap();
        let next = next_root(&root);
        let spec = cfg
            .capture_spec(&next, &a, uuid::Uuid::now_v7(), vec!["task".into()], None)
            .unwrap();
        let proof = ContinuationProof::inspect(&store, &cfg, &next, &spec).unwrap();
        let record = crate::run_journal::read(&store.conn, &root.identity().run)
            .unwrap()
            .unwrap();
        let (_, original_spec) = crate::capture_journal::qualified(&store.conn, &record)
            .unwrap()
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE capture_finalizations SET confirmation=NULL,revision=1",
                [],
            )
            .unwrap();
        let before = durable_rows(&store.conn);
        assert!(matches!(
            store.begin_certified_capture(&root, &original_spec, &proof),
            Ok(crate::capture_journal::BeginCapturedRun::Existing(_))
        ));
        assert_eq!(before, durable_rows(&store.conn));
    }
    fn durable_rows(conn: &rusqlite::Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
        let tables = conn
            .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        tables
            .into_iter()
            .map(|table| {
                let mut stmt = conn
                    .prepare(&format!("SELECT * FROM \"{table}\" ORDER BY rowid"))
                    .unwrap();
                let columns = stmt.column_count();
                stmt.query_map([], |r| {
                    (0..columns)
                        .map(|i| r.get(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
            })
            .collect()
    }
    #[test]
    fn certified_admission_rechecks_current_transaction_without_mutation() {
        use crate::store::StoreError;
        for change in [
            "writer",
            "finish",
            "owner",
            "requirement",
            "allocation",
            "revoked",
            "open",
            "rootless",
            "orphan",
            "missing_capture",
            "confirmation",
            "namespace",
        ] {
            let (_temp, cfg, mut store, a, root, seal, ack) = closed();
            restore(&cfg, seal, ack).unwrap();
            let next = next_root(&root);
            let spec = cfg
                .capture_spec(&next, &a, uuid::Uuid::now_v7(), vec!["task".into()], None)
                .unwrap();
            let proof = ContinuationProof::inspect(&store, &cfg, &next, &spec).unwrap();
            store.conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            match change {
                "writer" => {
                    store
                        .conn
                        .execute(
                            "INSERT INTO writers VALUES(?1,?2)",
                            (a.checkout.to_string(), uuid::Uuid::now_v7().to_string()),
                        )
                        .unwrap();
                }
                "finish" => {
                    store
                        .conn
                        .execute(
                            "INSERT INTO task_finishes VALUES(?1,?2,'{}')",
                            (a.checkout.to_string(), uuid::Uuid::now_v7().to_string()),
                        )
                        .unwrap();
                }
                "owner" => {
                    store
                        .conn
                        .execute("UPDATE checkouts SET owner='changed'", [])
                        .unwrap();
                }
                "requirement" => {
                    store
                        .conn
                        .execute("UPDATE capture_requirements SET revision=revision+1", [])
                        .unwrap();
                }
                "allocation" => {
                    store
                        .conn
                        .execute(
                            "UPDATE allocations SET record=json_set(record,'$.reason','changed')",
                            [],
                        )
                        .unwrap();
                }
                "revoked" => {
                    store
                        .conn
                        .execute("UPDATE capture_readiness SET revoked=1", [])
                        .unwrap();
                }
                "open" => {
                    store
                        .conn
                        .execute("UPDATE run_groups SET closed=0", [])
                        .unwrap();
                }
                "rootless" => {
                    store.conn.execute("INSERT INTO run_groups(id,checkout,mode,revision) VALUES(?1,?2,'supervised',1)", (uuid::Uuid::now_v7().to_string(), a.checkout.to_string())).unwrap();
                }
                "orphan" => {
                    store
                        .conn
                        .execute(
                            "UPDATE runs SET group_id=?1",
                            [uuid::Uuid::now_v7().to_string()],
                        )
                        .unwrap();
                }
                "missing_capture" => {
                    store.conn.execute("DELETE FROM capture_runs", []).unwrap();
                }
                "confirmation" => {
                    store
                        .conn
                        .execute(
                            "UPDATE capture_finalizations SET confirmation=NULL,revision=1",
                            [],
                        )
                        .unwrap();
                }
                "namespace" => {
                    store
                        .conn
                        .execute(
                            "INSERT INTO task_finishes VALUES(?1,?2,'{}')",
                            (
                                uuid::Uuid::now_v7().to_string(),
                                spec.operation().to_string(),
                            ),
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let before = durable_rows(&store.conn);
            let result = store.begin_certified_capture(&next, &spec, &proof);
            let expected_conflict =
                matches!(change, "owner" | "requirement" | "allocation" | "namespace");
            assert!(
                if change == "revoked" {
                    matches!(
                        result,
                        Err(StoreError::Database(rusqlite::Error::QueryReturnedNoRows))
                    )
                } else if change == "orphan" {
                    matches!(
                        result,
                        Err(StoreError::Database(rusqlite::Error::InvalidColumnType(
                            4,
                            _,
                            rusqlite::types::Type::Null
                        )))
                    )
                } else if expected_conflict {
                    matches!(result, Err(StoreError::Conflict))
                } else {
                    matches!(result, Err(StoreError::Invalid))
                },
                "{change}: {:?}",
                result.err()
            );
            assert_eq!(before, durable_rows(&store.conn), "{change}");
        }
    }
    #[test]
    fn certified_ready_admits_one_distinct_next_capture_without_new_charge() {
        let (_temp, cfg, mut store, a, root, seal, ack) = closed();
        restore(&cfg, seal, ack).unwrap();
        store
            .transfer(
                a.checkout,
                "recipient",
                crate::admission::Limits {
                    repository: 10,
                    owner: 10,
                    available_bytes: Some(1_000_000),
                    floor_bytes: 0,
                    warn_bytes: 0,
                },
            )
            .unwrap();
        std::fs::write(_temp.path().join("response"),serde_json::json!({"state":"pending","capture_id":"550e8400-e29b-41d4-a716-446655440001","actor_ref":"actor:alice","run_ref":root.identity().run_ref.as_str(),"last_attempt_at":chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now()).to_rfc3339()}).to_string()).unwrap();
        crate::capture_finalization::retry_delivery(&cfg, &root.identity().run).unwrap();
        assert!(
            store
                .capture_finalization_snapshot(&root.identity().run)
                .unwrap()
                .unwrap()
                .revision
                > 2
        );
        let mut value = serde_json::to_value(&root).unwrap();
        value["identity"]["run"] = uuid::Uuid::now_v7().to_string().into();
        value["identity"]["group"] = uuid::Uuid::now_v7().to_string().into();
        value["identity"]["run_ref"] = "run:next".into();
        let next: crate::run_journal::RootRunRequest = serde_json::from_value(value).unwrap();
        let spec = cfg
            .capture_spec(&next, &a, uuid::Uuid::now_v7(), vec!["task".into()], None)
            .unwrap();
        let result = crate::capture_setup::begin(&cfg, &next, &spec);
        assert!(
            result.is_ok(),
            "certified continuation must admit a distinct captured root: {:?}",
            result.as_ref().err()
        );
        let (_store, begin) = result.unwrap();
        assert!(matches!(
            begin,
            crate::capture_journal::BeginCapturedRun::Created(_)
        ));
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM capture_runs", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            store
                .charged(a.request.repository.as_ref().unwrap(), None)
                .unwrap(),
            1
        );
        assert!(!store
            .conn
            .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
            .unwrap());
    }
    #[test]
    fn generic_ready_finish_refuses_removed_capture_selection_without_mutation() {
        let (_temp, mut cfg, store, a, _root, seal, ack) = closed();
        restore(&cfg, seal, ack).unwrap();
        cfg.allocation.as_mut().unwrap().capture_sink = None;
        let snapshot = || {
            let tables = store
                .conn
                .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
                .unwrap()
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            tables
                .into_iter()
                .map(|table| {
                    let mut stmt = store
                        .conn
                        .prepare(&format!("SELECT * FROM \"{table}\" ORDER BY rowid"))
                        .unwrap();
                    let columns = stmt.column_count();
                    stmt.query_map([], |r| {
                        (0..columns)
                            .map(|i| r.get::<_, rusqlite::types::Value>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap()
                })
                .collect::<Vec<_>>()
        };
        let before = snapshot();
        let result = crate::finish::finish_with_sink_observed(&cfg, a.checkout, None, |_| {});
        assert!(
            result.is_err(),
            "durable captured finish must be refused, got {result:?}"
        );
        let after = snapshot();
        assert_eq!(before, after, "refusal must not mutate durable authority");
    }
    #[test]
    fn historical_captured_finish_receipt_survives_removed_selection() {
        let (_temp, mut cfg, store, a, _root, seal, ack) = closed();
        restore(&cfg, seal, ack).unwrap();
        let original =
            crate::finish::finish_with_sink_observed(&cfg, a.checkout, None, |_| {}).unwrap();
        assert!(original.task_finished);
        assert!(original.capture_incomplete);
        cfg.allocation.as_mut().unwrap().capture_sink = None;
        let replay = measured_finish(&cfg, a.checkout).unwrap();
        assert_eq!(original.operation, replay.operation);
        assert!(!replay.capture_incomplete);
        assert_eq!(replay.local_freeze, crate::finish::Freeze::Frozen);
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM task_finishes", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    #[ignore = "Deferred pilot performance/budget qualification; run explicitly with --ignored"]
    fn many_closed_captured_roots_with_terminal_children_fit_sql_budget() {
        let _diagnostics = crate::capture_diagnostics::Guard::new();
        many_closed_history_stress(|cfg, _store, a, original| {
            let next = next_root(original);
            let spec = cfg
                .capture_spec(&next, a, uuid::Uuid::now_v7(), vec!["task".into()], None)
                .unwrap();
            let result = {
                let _cpu = outside_sql_span(FrameName::WholeAdmission);
                crate::capture_setup::begin(cfg, &next, &spec)
            };
            assert!(
                result.is_ok(),
                "large-history admission: {:?}",
                result.as_ref().err()
            );
        });
    }
    #[test]
    #[ignore = "Deferred pilot performance/budget qualification; run explicitly with --ignored"]
    fn captured_finish_many_roots_preserves_shared_sql_budgets() {
        let _diagnostics = crate::capture_diagnostics::Guard::new();
        many_closed_history_stress(|cfg, _store, a, _original| {
            Store::open_finish_authority(
                cfg.trusted_registry.as_ref().unwrap(),
                cfg.store_dir.as_ref().unwrap(),
                &cfg.roots,
            )
            .expect("bounded finish authority preflight");
            let report = measured_finish(cfg, a.checkout).expect("bounded all-root completion");
            assert!(report.task_finished);
            assert_eq!(report.local_freeze, crate::finish::Freeze::Frozen);
        });
    }
    #[test]
    #[ignore = "Deferred pilot performance/budget qualification; run explicitly with --ignored"]
    fn captured_finish_many_unmapped_roots_preserves_shared_sql_budgets() {
        many_closed_history_stress(|cfg, store, a, original| {
            let rows = |table: &str| {
                let mut stmt = store
                    .conn
                    .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                    .unwrap();
                let columns = stmt.column_count();
                stmt.query_map([], |r| {
                    (0..columns)
                        .map(|i| r.get::<_, rusqlite::types::Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
            };
            let before = ["runs", "run_groups", "run_participants", "allocations"].map(rows);
            let expected = store
                .conn
                .prepare("SELECT id FROM runs ORDER BY id")
                .unwrap()
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let bytes = || {
                ["store.sqlite", "store.sqlite-wal", "store.sqlite-shm"]
                    .iter()
                    .map(|name| {
                        std::fs::metadata(cfg.store_dir.as_ref().unwrap().join(name))
                            .map(|m| m.len())
                            .unwrap_or(0)
                    })
                    .sum::<u64>()
            };
            let pre = bytes();
            // Missing evidence only: retain every root, child, outcome and physical identity.
            for table in ["capture_finalizations", "capture_runs"] {
                assert_eq!(
                    store
                        .conn
                        .execute(
                            &format!("DELETE FROM {table} WHERE run<>?1"),
                            [original.identity().run.to_string()]
                        )
                        .unwrap(),
                    expected.len() - 1
                );
            }
            eprintln!("many_unmapped roots={} children={} pre_deletion_bytes={pre} post_deletion_bytes={}", expected.len(), before[2].len(), bytes());
            assert_eq!(
                ["runs", "run_groups", "run_participants", "allocations"].map(rows),
                before
            );
            assert_eq!(before[2].len(), (expected.len() - 1) * 4);
            let calls = cfg
                .store_dir
                .as_ref()
                .unwrap()
                .join("unexpected-producer-call");
            std::fs::write(
                &cfg.capture.as_ref().unwrap().executable,
                format!(
                    "#!/usr/bin/python3\nimport sys\nopen({calls:?},'w').close()\nsys.exit(1)\n"
                ),
            )
            .unwrap();
            let mut passive_cfg = cfg.clone();
            passive_cfg.supervisor = None;
            let frozen = rows("capture_finalizations");
            let report = measured_finish(&passive_cfg, a.checkout)
                .expect("bounded many-unmapped completion must expose committed task truth");
            assert!(
                report.task_finished
                    && report.capture_incomplete
                    && report.lease_held
                    && report.charge_retained
            );
            assert_eq!(report.local_freeze, crate::finish::Freeze::Failed);
            assert_eq!(report.delivery, None);
            assert_eq!(report.retirement, "disabled");
            assert_eq!(report.action, "none");
            assert_eq!(
                report
                    .run_outcomes
                    .iter()
                    .map(|r| r.run.to_string())
                    .collect::<Vec<_>>(),
                expected
            );
            assert!(report
                .run_outcomes
                .iter()
                .all(|r| r.outcome == Some(crate::run_journal::RootOutcome::Completed)));
            assert_eq!(
                report
                    .run_outcomes
                    .iter()
                    .filter(|r| r.capture == crate::finish::RunCapture::Missing)
                    .count(),
                expected.len() - 1
            );
            assert_eq!(
                report
                    .run_outcomes
                    .iter()
                    .find(|r| r.run == original.identity().run)
                    .unwrap()
                    .capture,
                crate::finish::RunCapture::Frozen {
                    delivery: crate::finish::Delivery::Pending
                }
            );
            let receipt = rows("task_finishes");
            let retry = measured_finish(&passive_cfg, a.checkout).unwrap();
            assert_eq!(retry, report);
            assert_eq!(rows("task_finishes"), receipt);
            assert_eq!(rows("capture_finalizations"), frozen);
            assert!(!calls.exists());
            assert_eq!(rows("writers").len(), 0);
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT state,ready FROM checkouts", [], |r| Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, bool>(1)?
                    )))
                    .unwrap(),
                ("held".into(), false)
            );
            assert!(store
                .conn
                .query_row("SELECT revoked FROM capture_readiness", [], |r| r
                    .get::<_, bool>(0))
                .unwrap());
            assert_eq!(store.conn.query_row("SELECT count(*) FROM outbox WHERE json_extract(payload,'$.type')='task_finished'", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
            assert_eq!(
                store
                    .charged(a.request.repository.as_ref().unwrap(), None)
                    .unwrap(),
                1
            );
            assert_eq!(
                ["runs", "run_groups", "run_participants", "allocations"].map(rows),
                before
            );
            assert_eq!(rows("capture_runs").len(), 1);
            assert_eq!(rows("capture_finalizations").len(), 1);
        });
    }
    #[test]
    fn ordering_fixture_timeout_is_selected_before_any_root_intent() {
        for selected in [None, Some(1000_u64)] {
            let (temp, cfg, _a, _root, spec) = match selected {
                None => crate::capture_preparation::tests::qualified_fixture(),
                Some(timeout_ms) => {
                    crate::capture_preparation::tests::qualified_fixture_with_timeout(timeout_ms)
                }
            };
            let sql = rusqlite::Connection::open(temp.path().join("private/store.sqlite")).unwrap();
            for table in ["runs", "capture_runs"] {
                let count: i64 = sql
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                    .unwrap();
                assert_eq!(count, 0, "fixture must not have sealed a root intent");
            }
            let expected = selected.unwrap_or(50);
            assert_eq!(cfg.capture.as_ref().unwrap().timeout_ms, expected);
            assert_eq!(
                serde_json::to_value(&spec).unwrap()["sink"]["timeout_ms"],
                serde_json::json!(expected)
            );
        }
    }
    #[test]
    fn captured_finish_prepares_all_intents_before_any_producer() {
        let _diagnostics = crate::capture_diagnostics::Guard::new();
        // Success-path ordering qualification, not a 50ms timing qualification.
        // Choose the approved deadline before the first Config/spec/root intent.
        many_closed_history_with_timeout(1000, |cfg, store, a, _| {
            crate::run_journal::with_capture_history(&store.conn, a.checkout, |history| {
                for (_, (_, spec, _)) in history {
                    assert_eq!(
                        serde_json::to_value(&spec).unwrap()["sink"]["timeout_ms"],
                        serde_json::json!(1000)
                    );
                }
                Ok(())
            })
            .unwrap();
            store
                .conn
                .execute("DELETE FROM capture_finalizations", [])
                .unwrap();
            let producer = &cfg.capture.as_ref().unwrap().executable;
            std::fs::write(producer, format!(r#"#!/usr/bin/python3
import sqlite3,json,sys
r=json.load(sys.stdin)
c=sqlite3.connect({database:?})
assert c.execute('SELECT count(*) FROM task_finishes').fetchone()[0]==1
assert c.execute('SELECT count(*) FROM capture_finalizations').fetchone()[0]==c.execute('SELECT count(*) FROM capture_runs').fetchone()[0]
p=json.loads(c.execute("SELECT prepared FROM capture_runs WHERE json_extract(prepared,'$.capture_id')=?",(r['capture_id'],)).fetchone()[0])
json.dump({{'capture_id':r['capture_id'],'actor_ref':p['actor_ref'],'run_ref':p['run_ref'],'state':'pending'}},sys.stdout)
"#, database=cfg.store_dir.as_ref().unwrap().join("store.sqlite"))).unwrap();
            let report = measured_finish(cfg, a.checkout).unwrap();
            assert_eq!(report.local_freeze, crate::finish::Freeze::Frozen);
        });
    }
    #[test]
    fn missing_capture_remains_failed_even_when_another_finish_is_uncertain() {
        let _diagnostics = crate::capture_diagnostics::Guard::new();
        many_closed_history(|cfg, store, a, original| {
            let run: String = store
                .conn
                .query_row(
                    "SELECT run FROM capture_runs WHERE run<>?1 LIMIT 1",
                    [original.identity().run.to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            store
                .conn
                .execute("DELETE FROM capture_finalizations WHERE run=?1", [&run])
                .unwrap();
            store
                .conn
                .execute("DELETE FROM capture_runs WHERE run=?1", [&run])
                .unwrap();
            store
                .conn
                .execute(
                    "UPDATE capture_finalizations SET confirmation=NULL,revision=1",
                    [],
                )
                .unwrap();
            std::fs::write(
                &cfg.capture.as_ref().unwrap().executable,
                "#!/bin/sh\nexit 1\n",
            )
            .unwrap();
            let report = measured_finish(cfg, a.checkout).unwrap();
            assert!(report.task_finished);
            assert_eq!(report.local_freeze, crate::finish::Freeze::Failed);
        });
    }
    #[test]
    fn captured_finish_counts_closed_roots_without_maps() {
        let _diagnostics = crate::capture_diagnostics::Guard::new();
        many_closed_history(|cfg, store, a, original| {
            let run: String = store
                .conn
                .query_row(
                    "SELECT run FROM capture_runs WHERE run<>?1 LIMIT 1",
                    [original.identity().run.to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            store
                .conn
                .execute("DELETE FROM capture_finalizations WHERE run=?1", [&run])
                .unwrap();
            store
                .conn
                .execute("DELETE FROM capture_runs WHERE run=?1", [&run])
                .unwrap();
            let report = measured_finish(cfg, a.checkout).unwrap();
            assert!(report.task_finished && report.capture_incomplete);
            assert_eq!(report.local_freeze, crate::finish::Freeze::Failed);
            assert!(report
                .run_outcomes
                .iter()
                .any(|r| r.capture == crate::finish::RunCapture::Missing));
        });
    }
    pub(crate) fn many_closed_history(
        completed: impl FnMut(
            &crate::config::Config,
            &Store,
            &crate::allocate::Allocation,
            &crate::run_journal::RootRunRequest,
        ),
    ) {
        many_closed_history_with_timeout(50, completed);
    }
    // Pilot functional coverage keeps every assertion at two roots; full-load
    // qualification remains explicit in the ignored stress callers.
    fn many_closed_history_with_timeout(
        timeout_ms: u64,
        completed: impl FnMut(
            &crate::config::Config,
            &Store,
            &crate::allocate::Allocation,
            &crate::run_journal::RootRunRequest,
        ),
    ) {
        many_closed_history_with_counts(&[2], timeout_ms, completed);
    }
    pub(crate) fn many_closed_history_stress(
        completed: impl FnMut(
            &crate::config::Config,
            &Store,
            &crate::allocate::Allocation,
            &crate::run_journal::RootRunRequest,
        ),
    ) {
        many_closed_history_with_counts(&[2, 48], 50, completed);
    }
    fn many_closed_history_with_counts(
        counts: &[usize],
        timeout_ms: u64,
        mut completed: impl FnMut(
            &crate::config::Config,
            &Store,
            &crate::allocate::Allocation,
            &crate::run_journal::RootRunRequest,
        ),
    ) {
        use crate::capture_journal::json;
        use crate::run_participants::{ChildRequest, EnrollmentRecord, ExpectedHost, HostSnapshot};
        for &count in counts {
            crate::capture_diagnostics::record(crate::capture_diagnostics::Event::Workload {
                roots: count,
            });
            let (_temp, cfg, store, a, original, seal, ack) = closed_with_timeout(timeout_ms);
            restore(&cfg, seal, ack).unwrap();
            let template = crate::run_journal::read(&store.conn, &original.identity().run)
                .unwrap()
                .unwrap();
            let (capture, _) = crate::capture_journal::qualified(&store.conn, &template)
                .unwrap()
                .unwrap();
            let frozen = store
                .capture_finalization_snapshot(&original.identity().run)
                .unwrap()
                .unwrap();
            for n in 1..count {
                // Synthetic durable history, not a claim of N physical executions.
                let mut root = next_root(&original);
                let mut value = serde_json::to_value(&root).unwrap();
                value["identity"]["run_ref"] = format!("run:history:{n}").into();
                root = serde_json::from_value(value).unwrap();
                let run = root.identity().run.to_string();
                let group = root.identity().group.to_string();
                let binding = fixture::binding(&root);
                let mut record = template.clone();
                record.request = root.clone();
                let b = binding.identity();
                // Reuse the shape from the accepted bound root, replacing its run-scoped paths.
                let old = json(&record.binding).unwrap();
                record.binding = serde_json::from_str(
                    &old.replace(&template.binding.as_ref().unwrap().unit, &b.unit)
                        .replace(&template.binding.as_ref().unwrap().cgroup, &b.cgroup),
                )
                .unwrap();
                store.conn.execute("INSERT INTO run_groups(id,checkout,mode,revision,recovery_hold,closed,child_count) VALUES(?1,?2,'supervised',?3,0,1,4)", rusqlite::params![group,a.checkout.to_string(),record.revision as i64]).unwrap();
                store
                    .conn
                    .execute(
                        "INSERT INTO runs VALUES(?1,?2,?3,?4,'permit_attempt',?5,?6)",
                        rusqlite::params![
                            run,
                            group,
                            root.identity().run_ref.as_str(),
                            json(&root).unwrap(),
                            json(&record.binding).unwrap(),
                            json(&record.outcome).unwrap()
                        ],
                    )
                    .unwrap();
                for _ in 0..4 {
                    let b = record.binding.as_ref().unwrap();
                    let child = ChildRequest {
                        checkout: root.identity().checkout.clone(),
                        group: root.identity().group.clone(),
                        run: work_contract::RunId::generate(),
                        run_ref: work_contract::RunRef::parse(&format!(
                            "child:{}",
                            uuid::Uuid::now_v7()
                        ))
                        .unwrap(),
                        parent_run: root.identity().run.clone(),
                        parent_run_ref: root.identity().run_ref.clone(),
                        execution_chain: root.identity().execution_chain.clone(),
                        source: None,
                        session: None,
                        agent: None,
                        actor: None,
                        expected_host: Some(ExpectedHost {
                            boot: b.boot.clone(),
                            pid: b.root_pid,
                            start_ticks: b.root_start_ticks,
                        }),
                    };
                    let host = EnrollmentRecord {
                        root: b.clone(),
                        host: HostSnapshot {
                            pid: b.root_pid,
                            start_ticks: b.root_start_ticks,
                            boot: b.boot.clone(),
                            cgroup: b.root_cgroup.clone(),
                        },
                    };
                    store.conn.execute("INSERT INTO run_participants VALUES(?1,?2,?3,?4,?5,'contained',?6,1,?7)", rusqlite::params![child.run.to_string(),group,child.run_ref.as_str(),run,json(&child).unwrap(),"\"completed\"",json(&host).unwrap()]).unwrap();
                }
                let spec = cfg
                    .capture_spec(&root, &a, uuid::Uuid::now_v7(), vec!["task".into()], None)
                    .unwrap();
                let mut prepared =
                    serde_json::to_value(capture.prepared.as_ref().unwrap()).unwrap();
                prepared["run_ref"] = root.identity().run_ref.as_str().into();
                let capture_id = uuid::Uuid::now_v7().to_string();
                let context = std::path::PathBuf::from(prepared["context"].as_str().unwrap())
                    .with_file_name(format!("{capture_id}.context.json"));
                prepared["capture_id"] = capture_id.clone().into();
                prepared["context"] = serde_json::to_value(&context).unwrap();
                #[derive(serde::Serialize, serde::Deserialize)]
                struct ExpectedGit {
                    #[serde(skip_serializing_if = "Option::is_none")]
                    author_name: Option<String>,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    author_email: Option<String>,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    committer_name: Option<String>,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    committer_email: Option<String>,
                }
                let git: ExpectedGit = serde_json::from_value(prepared["git"].clone()).unwrap();
                prepared["projection_digest"] =
                    serde_json::to_value(hash(&(&capture_id, &context, &git)).unwrap()).unwrap();
                store
                    .conn
                    .execute(
                        "INSERT INTO capture_runs VALUES(?1,?2,?3,?4,?5,?6,?7,1,?8,?9)",
                        rusqlite::params![
                            run,
                            group,
                            a.checkout.to_string(),
                            spec.operation().to_string(),
                            json(&spec).unwrap(),
                            hash(&spec).unwrap().to_vec(),
                            capture.intent_wall,
                            json(&prepared).unwrap(),
                            json(&capture.group_end).unwrap()
                        ],
                    )
                    .unwrap();
                let record = crate::run_journal::read(&store.conn, &root.identity().run)
                    .unwrap()
                    .unwrap();
                assert_eq!(record.children.len(), 4);
                let (capture, spec) = crate::capture_journal::qualified(&store.conn, &record)
                    .unwrap()
                    .unwrap();
                let mut intent = frozen.intent.clone();
                intent.context =
                    crate::capture_finalization::context(&record, &capture, &spec).unwrap();
                intent.body = intent.body.replace(&intent.capture_id, &capture_id);
                intent.capture_id = capture_id;
                use sha2::Digest;
                intent.fingerprint = sha2::Sha256::digest(intent.body.as_bytes()).into();
                store
                    .conn
                    .execute(
                        "INSERT INTO capture_finalizations VALUES(?1,?2,?3,2)",
                        rusqlite::params![
                            run,
                            json(&intent).unwrap(),
                            json(&frozen.confirmation).unwrap()
                        ],
                    )
                    .unwrap();
            }
            let db: String = store
                .conn
                .query_row("PRAGMA database_list", [], |r| r.get(2))
                .unwrap();
            let bytes = [db.clone(), format!("{db}-wal"), format!("{db}-shm")]
                .iter()
                .map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
                .sum::<u64>();
            assert!(bytes < 16 * 1024 * 1024, "authority size {bytes}");
            // CPU reads enclose both guards, including on assertion unwind.
            // This inclusive sample retains the existing stderr work below.
            let cpu = outside_sql_span(FrameName::FixtureFrontier);
            let _phase = store.sql_phase();
            let _snapshot = crate::run_journal::read_transaction(&store.conn).unwrap();
            let started = std::time::Instant::now();
            let result = frontier(&store.conn, a.checkout);
            eprintln!("frontier_elapsed={:?}", started.elapsed());
            eprintln!("roots={count} contained_terminal_children={} authority_bytes={bytes} result={result:?}", (count-1)*4);
            assert!(
                result.is_ok(),
                "legal captured history must fit unchanged SQL budget: {result:?}"
            );
            drop(_snapshot);
            drop(_phase);
            drop(cpu);
            {
                let _cpu = outside_sql_span(FrameName::FixtureHistory);
                let _phase = store.sql_phase();
                crate::run_journal::with_capture_history(&store.conn, a.checkout, |history| {
                    assert_eq!(history.len(), count);
                    assert_eq!(
                        history.iter().map(|(r, _)| r.children.len()).sum::<usize>(),
                        (count - 1) * 4
                    );
                    for (root, (capture, spec, frozen)) in history {
                        assert!(root.closed);
                        assert!(root.children.iter().all(|c| c.enrollment
                            == crate::run_participants::Enrollment::Contained
                            && c.outcome
                                == Some(crate::run_participants::ChildOutcome::Completed)));
                        assert!(
                            frozen.unwrap().intent.context
                                == crate::capture_finalization::context(&root, &capture, &spec)?
                        );
                    }
                    Ok(())
                })
                .unwrap();
            }
            // Extend the synthetic fixture's passive frontier; no runtime proof
            // or physical execution is manufactured by this metadata setup.
            let mut cert = certificate(&store.conn, a.checkout).unwrap();
            cert.frontier = result.unwrap();
            store
                .conn
                .execute(
                    "UPDATE capture_readiness SET certificate=?1 WHERE checkout=?2",
                    rusqlite::params![json(&cert).unwrap(), a.checkout.to_string()],
                )
                .unwrap();
            {
                let _cpu = outside_sql_span(FrameName::FixtureCertifiedIdentity);
                let _phase = store.sql_phase();
                guard_certified_identity(&store.conn, a.checkout).unwrap();
            }
            completed(&cfg, &store, &a, &original);
        }
    }
    fn git_at(a: &crate::allocate::Allocation, args: &[&str]) -> String {
        let out = std::process::Command::new("/usr/bin/git")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
            ])
            .args(args)
            .current_dir(&a.destination)
            .output()
            .unwrap();
        assert!(out.status.success(), "Git fixture failed: {:?}", out.stderr);
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }
    fn next_root(root: &crate::run_journal::RootRunRequest) -> crate::run_journal::RootRunRequest {
        let mut value = serde_json::to_value(root).unwrap();
        value["identity"]["run"] = uuid::Uuid::now_v7().to_string().into();
        value["identity"]["group"] = uuid::Uuid::now_v7().to_string().into();
        value["identity"]["run_ref"] = "run:regression-next".into();
        serde_json::from_value(value).unwrap()
    }
    #[test]
    fn continuation_accepts_current_durable_head_or_its_descendant_with_older_certificate() {
        for advance_again in [false, true] {
            let (_temp, cfg, mut store, a, root, seal, ack) = closed();
            restore(&cfg, seal, ack).unwrap();
            let certified = certificate(&store.conn, a.checkout)
                .unwrap()
                .physical
                .checkout
                .head;
            git_at(&a, &["commit", "--allow-empty", "-m", "descendant B"]);
            let refreshed = crate::allocate::verified_checkout(&mut store, a.checkout).unwrap();
            assert_ne!(refreshed.identity.as_ref().unwrap().head, certified);
            assert_eq!(
                certificate(&store.conn, a.checkout)
                    .unwrap()
                    .physical
                    .checkout
                    .head,
                certified
            );
            if advance_again {
                git_at(&a, &["commit", "--allow-empty", "-m", "descendant C"]);
            }
            let next = next_root(&root);
            let spec = cfg
                .capture_spec(
                    &next,
                    &refreshed,
                    uuid::Uuid::now_v7(),
                    vec!["task".into()],
                    None,
                )
                .unwrap();
            assert!(matches!(
                crate::capture_setup::begin(&cfg, &next, &spec).unwrap().1,
                crate::capture_journal::BeginCapturedRun::Created(_)
            ));
        }
    }
    #[test]
    fn continuation_refuses_reset_behind_normally_refreshed_durable_head_before_prepare() {
        let (temp, cfg, mut store, a, root, seal, ack) = closed();
        restore(&cfg, seal, ack).unwrap();
        let certified = certificate(&store.conn, a.checkout)
            .unwrap()
            .physical
            .checkout
            .head;
        git_at(&a, &["commit", "--allow-empty", "-m", "descendant B"]);
        let b = git_at(&a, &["rev-parse", "HEAD"]);
        let refreshed = crate::allocate::verified_checkout(&mut store, a.checkout).unwrap();
        assert_eq!(refreshed.identity.as_ref().unwrap().head, b);
        assert_eq!(
            crate::capture_setup::PendingPreparation::read(&store.conn, a.checkout)
                .unwrap()
                .allocation()
                .unwrap()
                .identity
                .unwrap()
                .head,
            b
        );
        assert_eq!(
            certificate(&store.conn, a.checkout)
                .unwrap()
                .physical
                .checkout
                .head,
            certified
        );
        git_at(&a, &["reset", "--hard", &certified]);
        let next = next_root(&root);
        let spec = cfg
            .capture_spec(
                &next,
                &refreshed,
                uuid::Uuid::now_v7(),
                vec!["task".into()],
                None,
            )
            .unwrap();
        let calls = temp.path().join("receiver-calls");
        std::fs::write(
            &cfg.capture.as_ref().unwrap().executable,
            format!(
                "#!/bin/sh\nprintf called >> '{}'\nexit 1\n",
                calls.display()
            ),
        )
        .unwrap();
        let events = store.pending_events(100).unwrap();
        let counts = || {
            ["runs", "run_groups", "writers", "capture_runs"].map(|table| {
                store
                    .conn
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| {
                        r.get::<_, i64>(0)
                    })
                    .unwrap()
            })
        };
        let before = counts();
        assert!(
            crate::capture_setup::begin(&cfg, &next, &spec).is_err(),
            "reset behind durable B admitted a new captured root"
        );
        assert!(crate::capture_preparation::prepare(&cfg, &next, &spec).is_err());
        assert!(!calls.exists(), "rejected continuation invoked receiver");
        assert_eq!(counts(), before);
        assert_eq!(store.pending_events(100).unwrap(), events);
    }
    #[test]
    fn certificate_head_must_be_an_immutable_object_id_not_a_mutable_ref() {
        let (_temp, cfg, store, a, root, seal, ack) = closed();
        restore(&cfg, seal, ack).unwrap();
        let git = |args: &[&str]| {
            let out = std::process::Command::new("/usr/bin/git")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .args([
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                ])
                .args(args)
                .current_dir(&a.destination)
                .output()
                .unwrap();
            assert!(out.status.success());
            String::from_utf8(out.stdout).unwrap().trim().to_owned()
        };
        let tree = git(&["rev-parse", "HEAD^{tree}"]);
        let unrelated = git(&["commit-tree", &tree, "-m", "unrelated"]);
        git(&["update-ref", "refs/heads/topic", &unrelated]);
        let text: String = store
            .conn
            .query_row("SELECT certificate FROM capture_readiness", [], |r| {
                r.get(0)
            })
            .unwrap();
        let mut cert: serde_json::Value = serde_json::from_str(&text).unwrap();
        cert["physical"]["checkout"]["head"] = "HEAD".into();
        store
            .conn
            .execute(
                "UPDATE capture_readiness SET certificate=?1",
                [cert.to_string()],
            )
            .unwrap();
        let mut value = serde_json::to_value(&root).unwrap();
        value["identity"]["run"] = uuid::Uuid::now_v7().to_string().into();
        value["identity"]["group"] = uuid::Uuid::now_v7().to_string().into();
        value["identity"]["run_ref"] = "run:mutable-anchor".into();
        let next = serde_json::from_value(value).unwrap();
        let spec = cfg
            .capture_spec(&next, &a, uuid::Uuid::now_v7(), vec!["task".into()], None)
            .unwrap();
        assert!(
            crate::capture_setup::begin(&cfg, &next, &spec).is_err(),
            "mutable certificate HEAD authorized an unrelated raw commit"
        );
    }
    #[test]
    fn target_certificate_rejects_unknown_nested_fields_and_positional_structs() {
        let mut accepted = Vec::new();
        for shape in [
            "checkout-extra",
            "directory-extra",
            "certificate-array",
            "physical-array",
            "checkout-array",
            "directory-array",
        ] {
            let (_temp, cfg, store, a, root, seal, ack) = closed();
            restore(&cfg, seal, ack).unwrap();
            let original = certificate(&store.conn, a.checkout).unwrap();
            let mut value = serde_json::to_value(&original).unwrap();
            let (pointer, fields): (&str, &[&str]) = match shape {
                "certificate-array" => (
                    "",
                    &[
                        "version", "checkout", "run", "stable", "physical", "frontier", "registry",
                        "store",
                    ],
                ),
                "physical-array" => ("/physical", &["checkout", "directories", "marker"]),
                "checkout-array" => (
                    "/physical/checkout",
                    &[
                        "path",
                        "private_git_dir",
                        "common_git_dir",
                        "directory",
                        "head",
                        "boot_id",
                    ],
                ),
                "directory-array" => ("/physical/checkout/directory", &["device", "inode"]),
                "checkout-extra" => ("/physical/checkout", &[]),
                "directory-extra" => ("/physical/checkout/directory", &[]),
                _ => unreachable!(),
            };
            let target = value.pointer_mut(pointer).unwrap();
            if fields.is_empty() {
                target["unknown"] = true.into();
            } else {
                *target =
                    serde_json::Value::Array(fields.iter().map(|f| target[*f].clone()).collect());
            }
            // These are valid serde representations of the SAME typed certificate,
            // not broken fixtures that already fail ordinary deserialization.
            let decoded: Certificate = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(hash(&decoded).unwrap(), hash(&original).unwrap());
            store
                .conn
                .execute(
                    "UPDATE capture_readiness SET certificate=?1",
                    [value.to_string()],
                )
                .unwrap();
            drop(
                Store::open_registered(
                    cfg.trusted_registry.as_ref().unwrap(),
                    cfg.store_dir.as_ref().unwrap(),
                    &cfg.roots,
                )
                .unwrap(),
            );
            let next = next_root(&root);
            let spec = cfg
                .capture_spec(&next, &a, uuid::Uuid::now_v7(), vec!["task".into()], None)
                .unwrap();
            let events = store.pending_events(100).unwrap();
            if crate::capture_setup::begin(&cfg, &next, &spec).is_ok() {
                accepted.push(shape);
            } else {
                assert_eq!(store.pending_events(100).unwrap(), events);
                assert_eq!(
                    store
                        .conn
                        .query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                        .unwrap(),
                    0
                );
            }
        }
        assert!(
            accepted.is_empty(),
            "noncanonical certificates admitted: {accepted:?}"
        );
    }
    #[test]
    fn ready_flags_without_a_target_bound_certificate_do_not_admit() {
        for damage in ["absent", "checkout", "authority", "malformed"] {
            let (_temp, cfg, store, a, root, seal, ack) = closed();
            restore(&cfg, seal, ack).unwrap();
            let text: String = store
                .conn
                .query_row("SELECT certificate FROM capture_readiness", [], |r| {
                    r.get(0)
                })
                .unwrap();
            let mut cert: serde_json::Value = serde_json::from_str(&text).unwrap();
            match damage {
                "checkout" => cert["checkout"] = uuid::Uuid::now_v7().to_string().into(),
                "authority" => cert["store"] = "/unrelated-authority".into(),
                "malformed" => cert = serde_json::json!({}),
                "absent" => {}
                _ => unreachable!(),
            }
            if damage == "absent" {
                store
                    .conn
                    .execute("DELETE FROM capture_readiness", [])
                    .unwrap();
            } else {
                store
                    .conn
                    .execute(
                        "UPDATE capture_readiness SET certificate=?1",
                        [cert.to_string()],
                    )
                    .unwrap();
            }
            // Opening is shape-only, not a global certificate payload scan.
            drop(
                Store::open_registered(
                    cfg.trusted_registry.as_ref().unwrap(),
                    cfg.store_dir.as_ref().unwrap(),
                    &cfg.roots,
                )
                .unwrap(),
            );
            let mut value = serde_json::to_value(&root).unwrap();
            value["identity"]["run"] = uuid::Uuid::now_v7().to_string().into();
            value["identity"]["group"] = uuid::Uuid::now_v7().to_string().into();
            value["identity"]["run_ref"] = "run:bad-certificate".into();
            let next = serde_json::from_value(value).unwrap();
            let spec = cfg
                .capture_spec(&next, &a, uuid::Uuid::now_v7(), vec!["task".into()], None)
                .unwrap();
            let events = store.pending_events(100).unwrap();
            assert!(
                crate::capture_setup::begin(&cfg, &next, &spec).is_err(),
                "{damage} certificate admitted a writer"
            );
            assert_eq!(store.pending_events(100).unwrap(), events);
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }
    #[test]
    fn certified_identity_refresh_refuses_bare_writer_without_mutation() {
        let (_temp, cfg, mut store, a, _root, seal, ack) = closed();
        restore(&cfg, seal, ack).unwrap();
        store
            .conn
            .execute(
                "INSERT INTO writers VALUES(?1,?2)",
                (a.checkout.to_string(), uuid::Uuid::now_v7().to_string()),
            )
            .unwrap();
        git_at(
            &a,
            &[
                "commit",
                "--allow-empty",
                "-m",
                "advance with orphan writer",
            ],
        );
        let before = crate::capture_setup::PendingPreparation::read(&store.conn, a.checkout)
            .unwrap()
            .allocation()
            .unwrap();
        let events = store.pending_events(100).unwrap();
        assert!(
            crate::allocate::verified_checkout(&mut store, a.checkout).is_err(),
            "bare orphan writer allowed identity refresh"
        );
        let after = crate::capture_setup::PendingPreparation::read(&store.conn, a.checkout)
            .unwrap()
            .allocation()
            .unwrap();
        assert_eq!(before.identity, after.identity);
        assert_eq!(store.pending_events(100).unwrap(), events);
    }
    #[test]
    fn certified_identity_refresh_refuses_orphan_supervised_history() {
        let (_temp, cfg, store, a, root, seal, ack) = closed();
        restore(&cfg, seal, ack).unwrap();
        let mut value = serde_json::to_value(&root).unwrap();
        let run = uuid::Uuid::now_v7();
        let group = uuid::Uuid::now_v7();
        value["identity"]["run"] = run.to_string().into();
        value["identity"]["group"] = group.to_string().into();
        value["identity"]["run_ref"] = "run:orphan".into();
        store.conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        store.conn.execute("INSERT INTO runs(id,group_id,run_ref,request,stage) VALUES(?1,?2,'run:orphan',?3,'intent')",(run.to_string(),group.to_string(),value.to_string())).unwrap();
        store.conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        assert!(
            crate::capture_journal::guard_allocation_identity(&store.conn, a.checkout).is_err(),
            "certification hid orphan supervised history"
        );
    }
    #[test]
    fn concurrent_certified_admitters_have_one_winner() {
        let (_temp, cfg, store, a, root, seal, ack) = closed();
        restore(&cfg, seal, ack).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut threads = Vec::new();
        for n in 0..2 {
            let mut value = serde_json::to_value(&root).unwrap();
            value["identity"]["run"] = uuid::Uuid::now_v7().to_string().into();
            value["identity"]["group"] = uuid::Uuid::now_v7().to_string().into();
            value["identity"]["run_ref"] = format!("run:concurrent-{n}").into();
            let next = serde_json::from_value(value).unwrap();
            let spec = cfg
                .capture_spec(&next, &a, uuid::Uuid::now_v7(), vec!["task".into()], None)
                .unwrap();
            let cfg = cfg.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                matches!(
                    crate::capture_setup::begin(&cfg, &next, &spec),
                    Ok((_, crate::capture_journal::BeginCapturedRun::Created(_)))
                )
            }));
        }
        assert_eq!(
            threads
                .into_iter()
                .map(|t| t.join().unwrap())
                .filter(|winner| *winner)
                .count(),
            1
        );
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM capture_runs", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
    #[test]
    fn unrelated_work_hold_invalidates_certificate_even_after_flags_are_restored() {
        for damage in ["held", "malformed"] {
            let (_temp, cfg, mut store, _a, root, seal, ack) = closed();
            restore(&cfg, seal, ack).unwrap();
            let p =
                crate::capture_setup::PendingPreparation::read(&store.conn, _a.checkout).unwrap();
            let original = p.allocation().unwrap();
            let mut held = original.clone();
            if damage == "held" {
                crate::recovery::hold(&mut store, &mut held, "unrelated identity damage").unwrap();
            } else {
                store
                    .conn
                    .execute("UPDATE allocations SET record='{}'", [])
                    .unwrap();
                assert!(crate::allocate::load(&mut store, original.request.operation).is_err());
            }
            store
                .conn
                .execute("UPDATE checkouts SET state='active',ready=1", [])
                .unwrap();
            store
                .conn
                .execute(
                    "UPDATE allocations SET record=?1",
                    [serde_json::to_string(&original).unwrap()],
                )
                .unwrap();
            let mut value = serde_json::to_value(&root).unwrap();
            value["identity"]["run"] = uuid::Uuid::now_v7().to_string().into();
            value["identity"]["group"] = uuid::Uuid::now_v7().to_string().into();
            value["identity"]["run_ref"] = "run:after-hold".into();
            let next = serde_json::from_value(value).unwrap();
            let spec = cfg
                .capture_spec(
                    &next,
                    &original,
                    uuid::Uuid::now_v7(),
                    vec!["task".into()],
                    None,
                )
                .unwrap();
            assert!(
                crate::capture_setup::begin(&cfg, &next, &spec).is_err(),
                "restored flags revived {damage} Work hold"
            );
        }
    }
    type ClosedFixture = (
        tempfile::TempDir,
        crate::config::Config,
        Store,
        crate::allocate::Allocation,
        crate::run_journal::RootRunRequest,
        ClosureSeal,
        crate::capture_finalization::FreezeAcknowledgement,
    );
    fn closed() -> ClosedFixture {
        closed_with_timeout(50)
    }
    fn closed_with_timeout(timeout_ms: u64) -> ClosedFixture {
        let (_temp, cfg, a, root, spec) =
            crate::capture_preparation::tests::qualified_fixture_with_timeout(timeout_ms);
        let (mut store, crate::capture_preparation::PreparationResult::Live(live)) =
            crate::capture_preparation::prepare(&cfg, &root, &spec).unwrap()
        else {
            panic!("created live")
        };
        let binding = fixture::binding(&root);
        store.record_bound(&root, &binding).unwrap();
        store.record_permit_attempt(&root, &binding).unwrap();
        store
            .record_root_outcome(&root, crate::run_journal::RootOutcome::Completed)
            .unwrap();
        let os = fixture::ClosureOs::new(&root, &binding);
        let snapshot = store.group_snapshot(&root.identity().run).unwrap();
        let proof = snapshot.certify_empty(&os.driver, &binding).unwrap();
        let (transition, seal) = store.close_live_capture(&snapshot, &proof, &live).unwrap();
        assert!(matches!(transition, Transition::Changed));
        assert!(
            seal.is_some(),
            "Changed close of actual Created live capture must mint closure authority"
        );
        let closure = seal.unwrap();
        let (transition, seal) = store.close_live_capture(&snapshot, &proof, &live).unwrap();
        assert!(matches!(transition, Transition::Existing));
        assert!(seal.is_none());
        let declaration = spec.begin_request();
        std::fs::write(_temp.path().join("response"), serde_json::to_vec(&serde_json::json!({"state":"pending","capture_id":"550e8400-e29b-41d4-a716-446655440001","actor_ref":declaration.actor_ref,"run_ref":declaration.run_ref})).unwrap()).unwrap();
        let (
            _,
            crate::capture_finalization::FinalizeResult::Confirmed {
                acknowledgement, ..
            },
        ) = crate::capture_finalization::finalize(&cfg, &root.identity().run).unwrap()
        else {
            panic!("actual FINISH required")
        };
        (_temp, cfg, store, a, root, closure, acknowledgement)
    }
    #[test]
    fn changed_live_close_returns_seal_but_historical_close_never_does() {
        let (_temp, cfg, store, a, _root, closure, acknowledgement) = closed();
        assert!(restore(&cfg, closure, acknowledgement).is_ok(), "fresh actual FINISH and closed live context must certify Ready even with pending delivery");
        assert_eq!(
            store
                .conn
                .query_row("SELECT state,ready FROM checkouts", [], |r| Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, bool>(1)?
                )))
                .unwrap(),
            ("active".into(), true)
        );
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM capture_readiness", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .charged(a.request.repository.as_ref().unwrap(), None)
                .unwrap(),
            1
        );
    }
}
