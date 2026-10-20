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
    use crate::store::StoreError;
    use sha2::Digest;
    let invalid: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM run_groups g WHERE checkout=?1 AND g.id NOT IN (SELECT group_id FROM capture_runs WHERE run=?2) AND (closed=0 OR recovery_hold<>0 OR NOT EXISTS(SELECT 1 FROM capture_runs c WHERE c.group_id=g.id))) OR EXISTS(SELECT 1 FROM adopted_groups WHERE checkout=?1) OR EXISTS(SELECT 1 FROM runs r LEFT JOIN run_groups g ON g.id=r.group_id WHERE g.id IS NULL)", (checkout.to_string(),current), |r| r.get(0))?;
    if invalid {
        return Err(StoreError::Invalid);
    }
    let mut digest = sha2::Sha256::new();
    digest.update(b"work.capture-readiness.frontier.v1\0");
    digest.update(checkout.as_bytes());
    let mut query =
        conn.prepare("SELECT run FROM capture_runs WHERE checkout=?1 AND run<>?2 ORDER BY run")?;
    let rows = query.query_map((checkout.to_string(), current), |r| r.get::<_, String>(0))?;
    let mut any = false;
    for row in rows {
        let id = work_contract::RunId::parse(&row?).map_err(|_| StoreError::Invalid)?;
        let root = crate::run_journal::read(conn, &id)?.ok_or(StoreError::Invalid)?;
        let (capture, spec) =
            crate::capture_journal::qualified(conn, &root)?.ok_or(StoreError::Invalid)?;
        let frozen = crate::capture_finalization::validate(conn, &root, &capture, &spec)?
            .ok_or(StoreError::Invalid)?;
        if frozen.confirmation.is_none() {
            return Err(StoreError::Invalid);
        }
        digest.update(hash(&(id, capture.operation, frozen.intent))?);
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
    let _lock = crate::allocate::lifecycle_lock(dir)?;
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

pub(crate) fn invalidate(conn: &rusqlite::Connection, checkout: uuid::Uuid) -> Result<()> {
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
    let cert: Certificate = serde_json::from_str(&body).map_err(|_| StoreError::Invalid)?;
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
        // The certified HEAD is the immutable ancestry anchor. The actual durable
        // stage remains Ready; no synthetic stage override is used.
        anchor.identity = Some(cert.physical.checkout.clone());
        let observed = std::time::Instant::now();
        let physical = crate::capture_setup::inspect_physical(&anchor, pending.source_common())?;
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
        // needs one graph check against the certificate, not one per history row
        // or another repeated check during unchanged physical reinspection.
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
    fn validate(&self, conn: &rusqlite::Connection) -> Result<()> {
        use crate::store::StoreError;
        self.fresh()?;
        ready(conn, self.anchor.checkout)?;
        if crate::capture_setup::PendingPreparation::read(conn, self.anchor.checkout)?
            != self.pending
        {
            return Err(StoreError::Conflict);
        }
        let cert = certificate(conn, self.anchor.checkout)?;
        if hash(&cert)? != self.certificate
            || frontier(conn, self.anchor.checkout)? != cert.frontier
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
    ) -> Result<()> {
        if root != &self.root || hash(spec)? != self.spec {
            return Err(crate::store::StoreError::Conflict);
        }
        self.validate(conn)
    }
    pub(crate) fn validate_writer(
        &self,
        conn: &rusqlite::Connection,
        checkout: uuid::Uuid,
        group: uuid::Uuid,
    ) -> Result<()> {
        if checkout != self.anchor.checkout
            || group.to_string() != self.root.identity().group.to_string()
        {
            return Err(crate::store::StoreError::Conflict);
        }
        self.validate(conn)
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
mod tests {
    use super::*;
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
        let _observation = observing(move |stage, conn, _| {
            if stage != "physical" {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(650));
            assert!(conn.is_autocommit());
            let other = rusqlite::Connection::open(dir.join("store.sqlite")).unwrap();
            other.busy_timeout(std::time::Duration::ZERO).unwrap();
            other.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
            drop(crate::allocate::lifecycle_lock(&dir).unwrap());
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
                        let lock = crate::allocate::lifecycle_lock(&dir).unwrap();
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
    fn closed() -> (
        tempfile::TempDir,
        crate::config::Config,
        Store,
        crate::allocate::Allocation,
        crate::run_journal::RootRunRequest,
        ClosureSeal,
        crate::capture_finalization::FreezeAcknowledgement,
    ) {
        let (_temp, cfg, a, root, spec) = crate::capture_preparation::tests::qualified_fixture();
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
