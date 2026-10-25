//! Cooperative allocation only. No writer is launched, capture prepared or payload removed.
#[cfg(test)]
#[path = "allocation_finish_tests.rs"]
mod finish_tests;
use crate::{
    admission::{Limits, Reservation},
    config::Config,
    identity::{query, CheckoutIdentity},
    store::Store,
};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, clap::Args)]
#[serde(deny_unknown_fields)]
pub struct Start {
    #[arg(long, default_value_t = Uuid::now_v7())]
    pub operation: Uuid,
    #[arg(long)]
    pub repository: Option<PathBuf>,
    #[arg(long)]
    pub root: Option<PathBuf>,
    #[arg(long)]
    pub actor: Option<String>,
    #[arg(long)]
    pub owner: Option<String>,
    #[arg(long)]
    pub task: String,
    #[arg(long)]
    pub branch: Option<String>,
    #[arg(long, default_value = "HEAD")]
    pub base: String,
    #[arg(long)]
    pub reuse_branch: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allocation {
    pub checkout: Uuid,
    pub request: Start,
    pub destination: PathBuf,
    pub base_commit: String,
    pub stage: String,
    pub reason: Option<String>,
    pub identity: Option<CheckoutIdentity>,
}
pub(crate) fn err(message: &str) -> io::Error {
    io::Error::other(message)
}
pub(crate) fn db<T>(r: crate::store::Result<T>) -> io::Result<T> {
    r.map_err(|e| {
        #[cfg(test)]
        crate::capture_diagnostics::store_error("allocate::db", &e);
        err(&e.to_string())
    })
}
pub(crate) fn sql<T>(r: rusqlite::Result<T>) -> io::Result<T> {
    r.map_err(|e| err(&e.to_string()))
}
fn component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with(['-', '.'])
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
#[cfg(test)]
pub(crate) fn save(store: &mut Store, a: &Allocation) -> io::Result<()> {
    let lease = lifecycle_lock(store)?;
    save_under_lease(store, a, &lease)
}
pub(crate) fn save_under_lease(
    store: &mut Store,
    a: &Allocation,
    lease: &AuthorityLease,
) -> io::Result<()> {
    save_checked_under_lease(store, a, lease, None)
}
fn save_checked_under_lease(
    store: &mut Store,
    a: &Allocation,
    lease: &AuthorityLease,
    predecessor: Option<&Predecessor>,
) -> io::Result<()> {
    db(lease.check(store))?;
    let authority = store.authority_identity().clone();
    let record = serde_json::to_string(a)?;
    let request = serde_json::to_string(&a.request)?;
    let _phase = store.sql_phase();
    let tx = sql(store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate))?;
    let tx = db(crate::retirement_journal::fence(
        tx,
        lease,
        &authority,
        crate::retirement_journal::Scope::Checkout(a.checkout),
        if predecessor.is_some() && a.stage == "held" {
            crate::retirement_journal::Attempt::AllocationHold
        } else {
            crate::retirement_journal::Attempt::AllocationStage
        },
    ))?;
    if let Some(expected) = predecessor {
        expected.compare(&tx, &authority)?;
    }
    db(crate::attribution_gap::guard_legacy_allocation(
        &tx, a.checkout,
    ))?;
    let finished: bool = sql(tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1)",
        [a.checkout.to_string()],
        |r| r.get(0),
    ))?;
    if finished {
        return Err(err("explicit finish fence forbids allocation mutation"));
    }
    if a.stage == "ready" {
        if db(crate::capture_requirement::present(&tx, a.checkout))?
            && !db(crate::capture_journal::unresolved_checkout(&tx, a.checkout))?
        {
            return Err(err(
                "capture requirement forbids generic readiness promotion",
            ));
        }
        db(crate::capture_journal::guard_allocation_identity(
            &tx, a.checkout,
        ))?;
    }
    if a.stage != "ready" {
        db(crate::capture_readiness::invalidate(
            &tx, a.checkout, lease, &authority,
        ))?;
    }
    if predecessor.is_some() {
        let old: String = sql(tx.query_row(
            "SELECT record FROM allocations WHERE checkout=?1",
            [a.checkout.to_string()],
            |r| r.get(0),
        ))?;
        let old: Allocation = serde_json::from_str(&old)?;
        if let (Some(prior), Some(current)) = (&old.identity, &a.identity) {
            if prior.head != current.head {
                db(crate::store::emit(
                    &tx,
                    &crate::events::Event::HeadAdvanced {
                        checkout: a.checkout,
                        old: prior.head.clone(),
                        new: current.head.clone(),
                    },
                ))?;
            }
        }
    }
    sql(tx.execute("INSERT INTO allocations VALUES(?1,?2,?3) ON CONFLICT(checkout) DO UPDATE SET record=excluded.record", rusqlite::params![a.checkout.to_string(), request, record]))?;
    sql(tx.execute(
        "UPDATE checkouts SET state=?2,ready=?3 WHERE id=?1",
        rusqlite::params![
            a.checkout.to_string(),
            if a.stage == "ready" {
                "active"
            } else if a.stage == "held" {
                "held"
            } else {
                "partial"
            },
            a.stage == "ready"
        ],
    ))?;
    db(crate::store::emit(
        &tx,
        &crate::events::Event::AllocationStage {
            checkout: a.checkout,
            operation: a.request.operation,
            stage: a.stage.clone(),
            reason: a.reason.clone(),
        },
    ))?;
    if a.stage != "held" {
        if let Some(expected) = predecessor {
            expected.check_time()?;
        }
    }
    sql(tx.commit())
}
#[cfg(test)]
pub(crate) fn load(store: &mut Store, operation: Uuid) -> io::Result<Option<Allocation>> {
    let lease = lifecycle_lock(store)?;
    load_under_lease(store, operation, &lease)
}
pub(crate) fn load_under_lease(
    store: &mut Store,
    operation: Uuid,
    lease: &AuthorityLease,
) -> io::Result<Option<Allocation>> {
    db(lease.check(store))?;
    let authority = store.authority_identity().clone();
    let _phase = store.sql_phase();
    db(crate::capture_journal::exclude_operation(
        &store.conn,
        &operation,
    ))?;
    let value: Option<(String, Option<String>, Option<String>)> = sql(store.conn.query_row("SELECT c.id,a.request,a.record FROM checkouts c LEFT JOIN allocations a ON c.id=a.checkout WHERE c.operation=?1", [operation.to_string()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional())?;
    let Some((id, request, record)) = value else {
        return Ok(None);
    };
    let checkout = Uuid::parse_str(&id).map_err(|_| err("invalid checkout key"))?;
    let parsed = record
        .as_deref()
        .and_then(|v| serde_json::from_str::<Allocation>(v).ok())
        .filter(|a| {
            a.checkout.to_string() == id
                && a.request.operation == operation
                && request
                    .as_deref()
                    .and_then(|v| serde_json::from_str::<Start>(v).ok())
                    .as_ref()
                    == Some(&a.request)
        });
    if let Some(a) = parsed {
        db(crate::capture_journal::guard_allocation_identity(
            &store.conn,
            checkout,
        ))?;
        return Ok(Some(a));
    }
    // Gap reconciliation is forbidden even when the allocation itself is malformed.
    db(crate::attribution_gap::guard_legacy_allocation(
        &store.conn,
        checkout,
    ))?;
    // Keep corrupt evidence untouched, but revoke eligibility using the trusted row
    // key, never an ID supplied by malformed JSON.
    let tx = sql(store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate))?;
    let tx = db(crate::retirement_journal::fence(
        tx,
        lease,
        &authority,
        crate::retirement_journal::Scope::Checkout(checkout),
        crate::retirement_journal::Attempt::AllocationHold,
    ))?;
    db(crate::capture_readiness::invalidate(
        &tx, checkout, lease, &authority,
    ))?;
    sql(tx.execute(
        "UPDATE checkouts SET state='held',ready=0 WHERE id=?1",
        [&id],
    ))?;
    db(crate::store::emit(
        &tx,
        &crate::events::Event::AllocationStage {
            checkout: Uuid::parse_str(&id).map_err(|_| err("invalid checkout key"))?,
            operation,
            stage: "held".into(),
            reason: Some("malformed allocation metadata; operator reconciliation required".into()),
        },
    ))?;
    sql(tx.commit())?;
    Err(err(
        "malformed allocation metadata; held with charge retained",
    ))
}
// Completion is an independent durable fence, even if readiness was corrupted
// or the receipt body cannot be decoded. Never infer eligibility from its JSON.
fn refuse_finished(store: &Store, checkout: Uuid) -> io::Result<()> {
    let finished: bool = sql(store.conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1)",
        [checkout.to_string()],
        |row| row.get(0),
    ))?;
    if finished {
        return Err(err(
            "checkout has durable task completion; no allocation authority",
        ));
    }
    Ok(())
}
// Full target SQL predecessor, not a caller-created positive proof. Values are
// compared exactly (including NULL and malformed record bytes), under the same
// bounded SQL phase as the final write. Unrelated checkout activity is excluded.
struct Predecessor {
    authority: std::sync::Arc<crate::store::AuthorityIdentity>,
    checkout: Uuid,
    rows: Vec<Vec<Vec<rusqlite::types::Value>>>,
    started: std::time::Instant,
}
impl Predecessor {
    fn rows(
        conn: &rusqlite::Connection,
        checkout: Uuid,
    ) -> io::Result<Vec<Vec<Vec<rusqlite::types::Value>>>> {
        let queries = [
            "SELECT * FROM checkouts WHERE id=?1 ORDER BY id",
            "SELECT * FROM allocations WHERE checkout=?1 ORDER BY checkout",
            "SELECT * FROM repository_aliases WHERE alias=(SELECT repository FROM checkouts WHERE id=?1) OR common=(SELECT repository FROM checkouts WHERE id=?1) ORDER BY alias",
            "SELECT * FROM writers WHERE checkout=?1 ORDER BY checkout",
            "SELECT * FROM run_groups WHERE checkout=?1 ORDER BY id",
            "SELECT * FROM runs WHERE group_id IN (SELECT id FROM run_groups WHERE checkout=?1) ORDER BY id",
            "SELECT * FROM run_participants WHERE group_id IN (SELECT id FROM run_groups WHERE checkout=?1) ORDER BY id",
            "SELECT * FROM adopted_groups WHERE checkout=?1 ORDER BY id",
            "SELECT * FROM adopted_sessions WHERE group_id IN (SELECT id FROM adopted_groups WHERE checkout=?1) ORDER BY group_id,source,session,agent",
            "SELECT * FROM adopted_segments WHERE group_id IN (SELECT id FROM adopted_groups WHERE checkout=?1) ORDER BY group_id,source,session,agent,prompt,tool,kind,event_ref",
            "SELECT * FROM task_finishes WHERE checkout=?1 ORDER BY checkout",
            "SELECT * FROM capture_requirements WHERE checkout=?1 ORDER BY checkout",
            "SELECT * FROM capture_runs WHERE checkout=?1 ORDER BY run",
            "SELECT * FROM capture_finalizations WHERE run IN (SELECT run FROM capture_runs WHERE checkout=?1) ORDER BY run",
            "SELECT * FROM capture_readiness WHERE checkout=?1 ORDER BY checkout",
            "SELECT * FROM attribution_gaps WHERE checkout=?1 ORDER BY run",
            "SELECT * FROM gap_qualifications WHERE checkout=?1 ORDER BY run",
            "SELECT * FROM gap_eligibility WHERE checkout=?1 ORDER BY checkout",
            "SELECT * FROM retirement_intents WHERE checkout=?1 ORDER BY operation",
            "SELECT * FROM retired_owners WHERE owner=(SELECT owner FROM checkouts WHERE id=?1) ORDER BY owner",
        ];
        let mut bytes = 0usize;
        let mut result = Vec::new();
        for query in queries {
            let mut stmt = sql(conn.prepare(query))?;
            let columns = stmt.column_count();
            let mut rows = sql(stmt.query([checkout.to_string()]))?;
            let mut values = Vec::new();
            while let Some(row) = sql(rows.next())? {
                let mut fields = Vec::new();
                for column in 0..columns {
                    let value: rusqlite::types::Value = sql(row.get(column))?;
                    bytes = bytes.saturating_add(
                        16 + match &value {
                            rusqlite::types::Value::Text(v) => v.len(),
                            rusqlite::types::Value::Blob(v) => v.len(),
                            _ => 8,
                        },
                    );
                    if bytes > 16 * 1024 * 1024 {
                        return Err(err("allocation context exceeds bound"));
                    }
                    fields.push(value);
                }
                values.push(fields);
            }
            result.push(values);
        }
        for pragma in ["PRAGMA user_version", "PRAGMA schema_version"] {
            let version: i64 = sql(conn.query_row(pragma, [], |r| r.get(0)))?;
            result.push(vec![vec![rusqlite::types::Value::Integer(version)]]);
        }
        Ok(result)
    }
    fn read(
        store: &Store,
        allocation: &Allocation,
        started: std::time::Instant,
    ) -> io::Result<Self> {
        let checkout = allocation.checkout;
        let _phase = store.sql_phase();
        let _snapshot = db(crate::run_journal::read_transaction(&store.conn))?;
        let (request, record, operation, state, ready): (String,String,String,String,bool) = sql(store.conn.query_row(
            "SELECT a.request,a.record,c.operation,c.state,c.ready FROM allocations a JOIN checkouts c ON c.id=a.checkout WHERE c.id=?1",
            [checkout.to_string()], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))))?;
        let eligible = match allocation.stage.as_str() {
            "reserved" => state == "reserved" && !ready,
            "creating" | "created" | "capture_pending" => state == "partial" && !ready,
            "ready" => state == "active" && ready,
            _ => false,
        };
        if !eligible
            || operation != allocation.request.operation.to_string()
            || serde_json::from_str::<Start>(&request)? != allocation.request
            || serde_json::from_str::<serde_json::Value>(&record)?
                != serde_json::to_value(allocation)?
        {
            return Err(err("allocation changed before context snapshot"));
        }
        Ok(Self {
            authority: store.authority_identity().clone(),
            checkout,
            rows: Self::rows(&store.conn, checkout)?,
            started,
        })
    }
    fn compare(
        &self,
        conn: &rusqlite::Connection,
        authority: &std::sync::Arc<crate::store::AuthorityIdentity>,
    ) -> io::Result<()> {
        if !std::sync::Arc::ptr_eq(&self.authority, authority)
            || self.rows != Self::rows(conn, self.checkout)?
        {
            return Err(err("allocation predecessor changed"));
        }
        Ok(())
    }
    fn check_time(&self) -> io::Result<()> {
        if self.started.elapsed() >= std::time::Duration::from_secs(30) {
            return Err(err("allocation observation expired"));
        }
        Ok(())
    }
}

#[derive(PartialEq)]
struct PhysicalEvidence {
    source: CheckoutIdentity,
    checkout: CheckoutIdentity,
    marker: RawMarker,
}
struct RawMarker {
    _file: fs::File,
    identity: [u64; 11],
    bytes: Vec<u8>,
}
impl PartialEq for RawMarker {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity && self.bytes == other.bytes
    }
}
impl RawMarker {
    fn capture(path: &std::path::Path) -> io::Result<Self> {
        use std::{io::Read, os::unix::fs::MetadataExt};
        let signature = |m: &fs::Metadata| {
            [
                m.dev(),
                m.ino(),
                m.mode() as u64,
                m.nlink(),
                m.uid() as u64,
                m.gid() as u64,
                m.len(),
                m.mtime() as u64,
                m.mtime_nsec() as u64,
                m.ctime() as u64,
                m.ctime_nsec() as u64,
            ]
        };
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.mode() & 0o7777 != 0o600
            || meta.len() > 16384
        {
            return Err(err("unsafe allocation marker descriptor"));
        }
        let identity = signature(&meta);
        let mut bytes = Vec::new();
        (&mut file).take(16385).read_to_end(&mut bytes)?;
        if bytes.len() > 16384
            || signature(&file.metadata()?) != identity
            || signature(&fs::symlink_metadata(path)?) != identity
        {
            return Err(err("allocation marker changed while reading"));
        }
        Ok(Self {
            _file: file,
            identity,
            bytes,
        })
    }
}
/// Non-Clone, non-deserializable retained observation. Its constructor performs
/// actual Git/marker inspection with no authority lease; final consumers do SQL
/// only. The original operation clock and common descriptors survive the handoff.
pub(crate) struct PhysicalObservation {
    allocation: Allocation,
    predecessor: Predecessor,
    common: crate::inspection::AllocationCommonLock,
    evidence: io::Result<PhysicalEvidence>,
}
impl PhysicalObservation {
    fn require_store(&self, store: &Store) -> io::Result<()> {
        if !std::sync::Arc::ptr_eq(&self.predecessor.authority, store.authority_identity()) {
            return Err(err("physical observation belongs to another Store"));
        }
        Ok(())
    }
    pub(crate) fn matches_allocation(&self, a: &Allocation) -> io::Result<()> {
        if serde_json::to_value(&self.allocation)? != serde_json::to_value(a)? {
            return Err(err("reconciliation allocation mismatch"));
        }
        Ok(())
    }
}
fn physical_evidence(a: &Allocation, charged: &std::path::Path) -> io::Result<PhysicalEvidence> {
    let source_path = a
        .request
        .repository
        .as_deref()
        .ok_or_else(|| err("missing source repository"))?;
    crate::config::validate_path(source_path, true)
        .map_err(|_| err("unsafe source repository path"))?;
    let source = CheckoutIdentity::inspect(source_path)?;
    if source.common_git_dir != charged {
        return Err(err("source authority changed"));
    }
    let checkout = crate::recovery::verify(a)?;
    let marker = RawMarker::capture(&checkout.private_git_dir.join("work-lease.json"))?;
    let decoded: crate::recovery::Marker = serde_json::from_slice(&marker.bytes)?;
    if decoded != crate::recovery::Marker::from(a) {
        return Err(err("marker changed"));
    }
    Ok(PhysicalEvidence {
        source,
        checkout,
        marker,
    })
}
#[cfg(test)]
mod physical_fixture {
    type Callback = Box<dyn FnOnce(&super::Store)>;
    thread_local! { pub(super) static AFTER_FIRST: std::cell::RefCell<Option<Callback>> = const { std::cell::RefCell::new(None) }; }
}
fn collect_physical(
    store: &Store,
    a: Allocation,
    predecessor: Predecessor,
    mut common: crate::inspection::AllocationCommonLock,
    guard: &crate::checkout_guard::CheckoutGuard,
    creation_source: Option<&CheckoutIdentity>,
) -> io::Result<PhysicalObservation> {
    let charged: String = sql(store.conn.query_row(
        "SELECT repository FROM checkouts WHERE id=?1",
        [a.checkout.to_string()],
        |r| r.get(0),
    ))?;
    let evidence = physical_evidence(&a, std::path::Path::new(&charged)).and_then(|evidence| {
        if creation_source.is_some_and(|source| *source != evidence.source) {
            return Err(err("creation source changed before acknowledgment"));
        }
        Ok(evidence)
    });
    #[cfg(test)]
    physical_fixture::AFTER_FIRST.with(|slot| {
        let callback = slot.borrow_mut().take();
        if let Some(callback) = callback {
            callback(store);
        }
    });
    // Repeat actual Git and raw-marker evidence, not just path/stat equality.
    // Never reset the first observation's deadline after this recheck.
    let evidence = evidence.and_then(|first| {
        let fresh = physical_evidence(&a, std::path::Path::new(&charged))?;
        if fresh != first {
            return Err(err("physical evidence changed during observation"));
        }
        common.revalidate(store)?;
        db(guard.require_matching(store, a.checkout))?;
        predecessor.check_time()?;
        Ok(first)
    });
    db(guard.require_matching(store, a.checkout))?;
    Ok(PhysicalObservation {
        allocation: a,
        predecessor,
        common,
        evidence,
    })
}
fn observe_allocation(
    store: &mut Store,
    checkout: Uuid,
    guard: &crate::checkout_guard::CheckoutGuard,
    expected: Option<&Allocation>,
) -> io::Result<PhysicalObservation> {
    db(guard.require_matching(store, checkout))?;
    // Commit a retirement hold before any lifecycle/physical early refusal.
    let lease = lifecycle_lock(store)?;
    db(crate::retirement_journal::checkpoint(
        store,
        &lease,
        crate::retirement_journal::Scope::Checkout(checkout),
        crate::retirement_journal::Attempt::AllocationIdentity,
    ))?;
    let started = std::time::Instant::now();
    refuse_finished(store, checkout)?;
    {
        let _phase = store.sql_phase();
        db(crate::attribution_gap::guard_legacy_allocation(
            &store.conn,
            checkout,
        ))?;
        db(crate::capture_journal::guard_allocation_identity(
            &store.conn,
            checkout,
        ))?;
    }
    let (charged, operation, state, ready): (String, String, String, bool) =
        sql(store.conn.query_row(
            "SELECT repository,operation,state,ready FROM checkouts WHERE id=?1",
            [checkout.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ))?;
    if (expected.is_none() && (state != "active" || !ready))
        || !matches!(state.as_str(), "reserved" | "partial" | "active")
    {
        return Err(err("checkout not eligible for observation"));
    }
    let initial = load_under_lease(
        store,
        Uuid::parse_str(&operation).map_err(|_| err("invalid operation"))?,
        &lease,
    )?
    .ok_or_else(|| err("missing allocation"))?;
    if let Some(expected) = expected {
        if serde_json::to_value(&initial)? != serde_json::to_value(expected)?
            || !matches!(
                initial.stage.as_str(),
                "reserved" | "creating" | "created" | "capture_pending" | "ready"
            )
        {
            return Err(err("allocation changed before observation"));
        }
    } else if initial.stage != "ready" {
        return Err(err("allocation not ready"));
    }
    let before_lock = Predecessor::read(store, &initial, started)?;
    drop(lease);
    let common = match crate::inspection::AllocationCommonLock::acquire(
        store,
        std::path::Path::new(&charged),
    ) {
        Ok(common) => common,
        Err(error) => {
            if error.kind() != io::ErrorKind::WouldBlock {
                let lease = lifecycle_lock(store)?;
                failed_observation(store, &initial, &before_lock, &lease)?;
            }
            return Err(error);
        }
    };
    let lease = lifecycle_lock(store)?;
    db(crate::retirement_journal::checkpoint(
        store,
        &lease,
        crate::retirement_journal::Scope::Checkout(checkout),
        crate::retirement_journal::Attempt::AllocationIdentity,
    ))?;
    refuse_finished(store, checkout)?;
    {
        let _phase = store.sql_phase();
        db(crate::attribution_gap::guard_legacy_allocation(
            &store.conn,
            checkout,
        ))?;
        db(crate::capture_journal::guard_allocation_identity(
            &store.conn,
            checkout,
        ))?;
    }
    let (operation, current_charged, state, ready): (String, String, String, bool) =
        sql(store.conn.query_row(
            "SELECT operation,repository,state,ready FROM checkouts WHERE id=?1",
            [checkout.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ))?;
    if current_charged != charged {
        return Err(err("charged common changed"));
    }
    let a = load_under_lease(
        store,
        Uuid::parse_str(&operation).map_err(|_| err("invalid operation"))?,
        &lease,
    )?
    .ok_or_else(|| err("missing allocation"))?;
    if let Some(expected) = expected {
        if serde_json::to_value(&a)? != serde_json::to_value(expected)? {
            return Err(err("allocation changed before observation"));
        }
        if !matches!(
            a.stage.as_str(),
            "reserved" | "creating" | "created" | "capture_pending" | "ready"
        ) || !matches!(state.as_str(), "reserved" | "partial" | "active")
        {
            return Err(err("later lifecycle cannot be reconciled by start"));
        }
    } else if state != "active" || !ready || a.stage != "ready" {
        return Err(err("checkout not active and ready"));
    }
    let predecessor = Predecessor::read(store, &a, started)?;
    drop(lease);
    collect_physical(store, a, predecessor, common, guard, None)
}
pub(crate) fn observe_checkout(
    store: &mut Store,
    checkout: Uuid,
    guard: &crate::checkout_guard::CheckoutGuard,
) -> io::Result<PhysicalObservation> {
    observe_allocation(store, checkout, guard, None)
}
pub(crate) fn observe_reconciliation(
    store: &mut Store,
    a: &Allocation,
    guard: &crate::checkout_guard::CheckoutGuard,
) -> io::Result<PhysicalObservation> {
    observe_allocation(store, a.checkout, guard, Some(a))
}
fn failed_observation(
    store: &mut Store,
    a: &Allocation,
    predecessor: &Predecessor,
    lease: &AuthorityLease,
) -> io::Result<Allocation> {
    let mut held = a.clone();
    held.stage = "held".into();
    held.reason = Some("fresh physical evidence incomplete or changed; charge retained".into());
    save_checked_under_lease(store, &held, lease, Some(predecessor))?;
    Ok(held)
}
pub(crate) fn reconcile_observation_under_lease(
    store: &mut Store,
    mut observed: PhysicalObservation,
    lease: &AuthorityLease,
) -> io::Result<Allocation> {
    db(lease.check(store))?;
    observed.require_store(store)?;
    db(crate::retirement_journal::checkpoint(
        store,
        lease,
        crate::retirement_journal::Scope::Checkout(observed.allocation.checkout),
        crate::retirement_journal::Attempt::AllocationIdentity,
    ))?;
    if let Err(error) = observed.common.check_budget() {
        failed_observation(store, &observed.allocation, &observed.predecessor, lease)?;
        return Err(error);
    }
    let mut a = observed.allocation;
    let current = match &observed.evidence {
        Ok(evidence) => evidence.checkout.clone(),
        Err(_) => return failed_observation(store, &a, &observed.predecessor, lease),
    };
    let required = db(crate::capture_requirement::read(&store.conn, a.checkout))?.is_some();
    let original = a.clone();
    a.identity = Some(current);
    if required && a.stage != "ready" {
        a.stage = "capture_pending".into();
        a.reason = Some("capture required; root preparation pending".into());
    } else {
        a.stage = "ready".into();
        a.reason = None;
    }
    if let Err(error) = save_checked_under_lease(store, &a, lease, Some(&observed.predecessor)) {
        // A failed acknowledgment grants nothing. Hold only the exact original
        // source context; if it changed, this additional comparison writes nothing.
        let _held = failed_observation(store, &original, &observed.predecessor, lease);
        return Err(error);
    }
    Ok(a)
}

/// Standalone test adapter: physical observation precedes the short final lease.
/// The production consumer below does only SQL/clock work with an opaque retained
/// observation, and never revives held/quarantined rows.
#[cfg(test)]
pub(crate) fn verified_checkout(store: &mut Store, checkout: Uuid) -> io::Result<Allocation> {
    let guard = db(crate::checkout_guard::CheckoutGuard::shared(
        store, checkout,
    ))?;
    let observed = observe_checkout(store, checkout, &guard)?;
    let lease = lifecycle_lock(store)?;
    verified_checkout_under_lease(store, observed, &lease)
}
pub(crate) fn verified_checkout_under_lease(
    store: &mut Store,
    mut observed: PhysicalObservation,
    lease: &AuthorityLease,
) -> io::Result<Allocation> {
    db(lease.check(store))?;
    observed.require_store(store)?;
    db(crate::retirement_journal::checkpoint(
        store,
        lease,
        crate::retirement_journal::Scope::Checkout(observed.allocation.checkout),
        crate::retirement_journal::Attempt::AllocationIdentity,
    ))?;
    if let Err(error) = observed.common.check_budget() {
        failed_observation(store, &observed.allocation, &observed.predecessor, lease)?;
        return Err(error);
    }
    let mut a = observed.allocation;
    let current = match &observed.evidence {
        Ok(evidence) => evidence.checkout.clone(),
        Err(_) => {
            failed_observation(store, &a, &observed.predecessor, lease)?;
            return Err(err("lease identity changed; held"));
        }
    };
    if let Err(error) = refresh_ready_identity_under_lease(
        store,
        &mut a,
        current,
        lease,
        Some(&observed.predecessor),
    ) {
        let _held = failed_observation(store, &a, &observed.predecessor, lease);
        return Err(error);
    }
    Ok(a)
}
/// Identity evidence only: atomically refresh a still-active/ready allocation
/// and its HEAD event. Never changes checkout eligibility, stage, or lease base.
#[cfg(test)]
fn refresh_ready_identity(
    store: &mut Store,
    a: &mut Allocation,
    current: CheckoutIdentity,
) -> io::Result<()> {
    let lease = lifecycle_lock(store)?;
    refresh_ready_identity_under_lease(store, a, current, &lease, None)
}
fn refresh_ready_identity_under_lease(
    store: &mut Store,
    a: &mut Allocation,
    current: CheckoutIdentity,
    lease: &AuthorityLease,
    predecessor: Option<&Predecessor>,
) -> io::Result<()> {
    db(lease.check(store))?;
    let authority = store.authority_identity().clone();
    let _phase = store.sql_phase();
    let tx = sql(store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate))?;
    let tx = db(crate::retirement_journal::fence(
        tx,
        lease,
        &authority,
        crate::retirement_journal::Scope::Checkout(a.checkout),
        crate::retirement_journal::Attempt::AllocationIdentity,
    ))?;
    if let Some(expected) = predecessor {
        expected.compare(&tx, &authority)?;
    }
    db(crate::attribution_gap::guard_legacy_allocation(
        &tx, a.checkout,
    ))?;
    db(crate::capture_journal::guard_allocation_identity(
        &tx, a.checkout,
    ))?;
    let stored: Option<(String, String)> = sql(tx
        .query_row(
            "SELECT a.request,a.record FROM allocations a JOIN checkouts c ON c.id=a.checkout
         WHERE c.id=?1 AND c.operation=?2 AND c.state='active' AND c.ready=1
         AND NOT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=c.id)",
            (a.checkout.to_string(), a.request.operation.to_string()),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional())?;
    let (request, record) =
        stored.ok_or_else(|| err("checkout eligibility changed during verification"))?;
    if serde_json::from_str::<Start>(&request)? != a.request
        || serde_json::from_str::<serde_json::Value>(&record)? != serde_json::to_value(&*a)?
    {
        return Err(err("allocation changed during verification"));
    }
    let mut refreshed = a.clone();
    if a.identity.as_ref() != Some(&current) {
        let prior = a
            .identity
            .as_ref()
            .ok_or_else(|| err("missing prior identity"))?;
        if prior.head != current.head {
            db(crate::store::emit(
                &tx,
                &crate::events::Event::HeadAdvanced {
                    checkout: a.checkout,
                    old: prior.head.clone(),
                    new: current.head.clone(),
                },
            ))?;
        }
        refreshed.identity = Some(current);
        sql(tx.execute(
            "UPDATE allocations SET record=?2 WHERE checkout=?1",
            (a.checkout.to_string(), serde_json::to_string(&refreshed)?),
        ))?;
    }
    if let Some(expected) = predecessor {
        expected.check_time()?;
    }
    sql(tx.commit())?;
    *a = refreshed;
    Ok(())
}
#[cfg(test)]
mod physical_tests {
    use super::*;
    fn git(path: &std::path::Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .current_dir(path)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }
    fn fixture() -> (tempfile::TempDir, Config, Allocation) {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        let root = temp.path().join("root");
        fs::create_dir(&repo).unwrap();
        fs::create_dir(&root).unwrap();
        git(&repo, &["init", "-b", "main"]);
        git(&repo, &["config", "user.name", "Test"]);
        git(&repo, &["config", "user.email", "test@example.invalid"]);
        git(&repo, &["commit", "--allow-empty", "-m", "initial"]);
        let config = Config::from_text(&format!("store_dir = {:?}\ntrusted_registry = {:?}\nroots = [{:?}]\nrepositories = [{:?}]\n[allocation]\nrepository_limit = 10\nowner_limit = 10\nfloor_bytes = 0\nwarn_bytes = 0\n", temp.path().join("private"), temp.path().join("registry"), root, repo)).unwrap();
        let allocation = start(
            &config,
            Start {
                operation: Uuid::now_v7(),
                repository: Some(repo),
                root: Some(root),
                actor: Some("actor".into()),
                owner: None,
                task: "task".into(),
                branch: Some("topic".into()),
                base: "main".into(),
                reuse_branch: false,
            },
        )
        .unwrap();
        (temp, config, allocation)
    }
    #[test]
    fn allocation_and_reuse_with_published_aliases_leave_other_checkout_prepared() {
        let (_temp, config, a) = fixture();
        let (store, lease) = locked(&config).unwrap();
        drop(lease);
        let operation = Uuid::now_v7();
        crate::retirement_journal::tests::seed_prepared(&store, a.checkout, operation);
        let before = crate::retirement_journal::load_operation(&store.conn, operation).unwrap();
        let mut request = a.request.clone();
        request.operation = Uuid::now_v7();
        request.task = "independent".into();
        request.branch = Some("independent".into());
        let b = start(&config, request.clone()).unwrap();
        assert_ne!(a.checkout, b.checkout);
        assert_eq!(
            start(&config, request.clone()).unwrap().checkout,
            b.checkout
        );
        request.operation = Uuid::now_v7();
        assert_eq!(start(&config, request).unwrap().checkout, b.checkout);
        assert_eq!(
            crate::retirement_journal::load_operation(&store.conn, operation).unwrap(),
            before
        );
        assert!(!store.pending_events(1000).unwrap().iter().any(|e| matches!(&e.event, crate::events::Event::RetirementIntentChanged { stage, .. } if stage == "held")));
    }

    #[test]
    fn legacy_verification_refuses_gap_history_before_physical_observation() {
        let (_temp, config, a) = fixture();
        let (mut store, lease) = locked(&config).unwrap();
        drop(lease);
        let root = crate::test_run_fixture::request(a.checkout);
        store.begin_run(&root).unwrap();
        // Raw malformed Gap presence is uncertainty, not an ordinary allocation.
        // The existing required_gap_continuation tests cover both valid origins.
        store
            .conn
            .execute(
                "INSERT INTO attribution_gaps VALUES(?1,?2,?3,?4,'{}',zeroblob(32))",
                (
                    root.identity().run.to_string(),
                    root.identity().group.to_string(),
                    a.checkout.to_string(),
                    Uuid::now_v7().to_string(),
                ),
            )
            .unwrap();
        let before = crate::retirement_journal::tests::source_rows(&store);
        let events = store.pending_events(1000).unwrap();
        physical_fixture::AFTER_FIRST.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|_| {
                panic!("legacy Gap rejection must precede physical observation")
            }))
        });
        assert!(verified_checkout(&mut store, a.checkout).is_err());
        assert!(physical_fixture::AFTER_FIRST.with(|hook| hook.borrow_mut().take().is_some()));
        assert_eq!(
            crate::retirement_journal::tests::source_rows(&store),
            before
        );
        assert_eq!(store.pending_events(1000).unwrap(), events);
    }

    #[test]
    fn finish_post_sink_fence_preserves_committed_completion_and_blocks_existing_retry() {
        use crate::retirement_journal::{
            load_operation,
            tests::{seed_prepared, source_rows},
        };
        struct Sink(std::cell::Cell<usize>);
        impl crate::finish::LocalSink for Sink {
            fn freeze(&self, _: &crate::finish::CaptureContext) -> crate::finish::CaptureResult {
                self.0.set(self.0.get() + 1);
                crate::finish::CaptureResult::Frozen { delivery: None }
            }
        }
        let (_temp, mut config, a) = fixture();
        config.allocation.as_mut().unwrap().capture_sink = Some("fixture".into());
        let (store, lease) = locked(&config).unwrap();
        drop(lease);
        let operation = Uuid::now_v7();
        let sink = Sink(std::cell::Cell::new(0));
        let mut before = None;
        let mut events = 0;
        let mut record = String::new();
        let result = crate::finish::finish_with_sink_observed(
            &config,
            a.checkout,
            Some(&sink),
            |boundary| {
                if boundary == "external_frozen" {
                    record = seed_prepared(&store, a.checkout, operation);
                    before = Some(source_rows(&store));
                    events = store.pending_events(1000).unwrap().len();
                }
                assert_ne!(boundary, "outcome_committed");
                assert_ne!(boundary, "before_ack");
            },
        );
        assert!(matches!(
            result,
            Err(crate::store::StoreError::RetirementFenced)
        ));
        assert_eq!(sink.0.get(), 1);
        let before = before.expect("real sink boundary reached after completion commit");
        let row = load_operation(&store.conn, operation).unwrap();
        assert_eq!(
            (
                row.stage.as_str(),
                row.revision,
                row.held_reason.as_deref(),
                row.record.as_str()
            ),
            ("held", 2, Some("finish_capture_result"), record.as_str())
        );
        assert_eq!(source_rows(&store), before);
        assert_eq!(store.pending_events(1000).unwrap().len(), events + 1);
        assert!(matches!(
            crate::finish::finish_with_sink_observed(&config, a.checkout, Some(&sink), |_| panic!(
                "held Existing must not dispatch"
            )),
            Err(crate::store::StoreError::RetirementFenced)
        ));
        assert_eq!(sink.0.get(), 1);
        assert_eq!(source_rows(&store), before);
        assert_eq!(store.pending_events(1000).unwrap().len(), events + 1);
    }

    #[test]
    fn physical_observation_has_no_global_lease_or_sql_and_rechecks_original_evidence() {
        for change in ["none", "marker", "head", "context"] {
            let (_temp, config, a) = fixture();
            let (mut store, lease) = locked(&config).unwrap();
            drop(lease);
            let guard = crate::checkout_guard::CheckoutGuard::shared(&store, a.checkout).unwrap();
            let checkout = a.checkout;
            let destination = a.destination.clone();
            let marker = a
                .identity
                .as_ref()
                .unwrap()
                .private_git_dir
                .join("work-lease.json");
            physical_fixture::AFTER_FIRST.with(|hook| *hook.borrow_mut() = Some(Box::new(move |store| {
                let file = crate::store::AuthorityIdentity::open_lock(&store.authority_identity().directory, false).unwrap();
                rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
                let conn = rusqlite::Connection::open(store.authority_identity().directory.join("store.sqlite")).unwrap();
                conn.busy_timeout(std::time::Duration::ZERO).unwrap();
                conn.execute_batch("BEGIN IMMEDIATE; ROLLBACK;").unwrap();
                let unrelated = crate::checkout_guard::CheckoutGuard::shared(store, Uuid::now_v7()).unwrap();
                assert!(matches!(crate::checkout_guard::CheckoutGuard::exclusive(store, checkout), Err(crate::store::StoreError::OperationsInFlight)));
                drop(unrelated); drop(file);
                match change {
                    "marker" => fs::write(marker, "{}").unwrap(),
                    "head" => git(&destination, &["commit", "--allow-empty", "-m", "race"]),
                    "context" => { conn.execute("UPDATE checkouts SET owner='new-owner',state='held',ready=0 WHERE id=?1", [checkout.to_string()]).unwrap(); },
                    _ => {}
                }
            })));
            let observed = observe_checkout(&mut store, checkout, &guard).unwrap();
            assert!(
                physical_fixture::AFTER_FIRST.with(|hook| hook.borrow().is_none()),
                "physical seam not reached"
            );
            let lease = lifecycle_lock(&store).unwrap();
            let result = verified_checkout_under_lease(&mut store, observed, &lease);
            assert_eq!(result.is_ok(), change == "none", "{change}");
            if change == "context" {
                let state: (String, String, bool) = store
                    .conn
                    .query_row(
                        "SELECT owner,state,ready FROM checkouts WHERE id=?1",
                        [checkout.to_string()],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .unwrap();
                assert_eq!(state, ("new-owner".into(), "held".into(), false));
                assert_eq!(
                    store
                        .conn
                        .query_row(
                            "SELECT record FROM allocations WHERE checkout=?1",
                            [checkout.to_string()],
                            |r| r.get::<_, String>(0)
                        )
                        .unwrap(),
                    serde_json::to_string(&a).unwrap()
                );
            }
        }
    }

    #[test]
    fn expired_or_other_store_observation_cannot_refresh_head_or_acknowledge() {
        for mismatch in ["expired", "store"] {
            let (_temp, config, a) = fixture();
            git(
                &a.destination,
                &["commit", "--allow-empty", "-m", "advance"],
            );
            let (mut store, lease) = locked(&config).unwrap();
            drop(lease);
            let guard = crate::checkout_guard::CheckoutGuard::shared(&store, a.checkout).unwrap();
            let mut observed = observe_checkout(&mut store, a.checkout, &guard).unwrap();
            assert_ne!(
                observed.evidence.as_ref().unwrap().checkout.head,
                a.identity.as_ref().unwrap().head
            );
            let events: i64 = store
                .conn
                .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
                .unwrap();
            let result = if mismatch == "expired" {
                observed.predecessor.started -= std::time::Duration::from_secs(31);
                let lease = lifecycle_lock(&store).unwrap();
                verified_checkout_under_lease(&mut store, observed, &lease)
            } else {
                let mut other = Store::open_existing_registered_mut(
                    config.trusted_registry.as_ref().unwrap(),
                    config.store_dir.as_ref().unwrap(),
                    &config.roots,
                )
                .unwrap();
                let lease = lifecycle_lock(&other).unwrap();
                verified_checkout_under_lease(&mut other, observed, &lease)
            };
            assert!(result.is_err(), "{mismatch}");
            let stored: Allocation = serde_json::from_str(
                &store
                    .conn
                    .query_row(
                        "SELECT record FROM allocations WHERE checkout=?1",
                        [a.checkout.to_string()],
                        |r| r.get::<_, String>(0),
                    )
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                stored.identity, a.identity,
                "failed observation must not refresh HEAD"
            );
            if mismatch == "expired" {
                assert_eq!(stored.stage, "held");
                assert!(!store
                    .conn
                    .query_row(
                        "SELECT ready FROM checkouts WHERE id=?1",
                        [a.checkout.to_string()],
                        |r| r.get::<_, bool>(0)
                    )
                    .unwrap());
            } else {
                assert_eq!(
                    serde_json::to_value(&stored).unwrap(),
                    serde_json::to_value(&a).unwrap()
                );
            }
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                events + i64::from(mismatch == "expired")
            );
        }
    }
}

/// A live, Store-instance-bound exclusion capability, never a wire value.
pub(crate) struct AuthorityLease {
    _file: fs::File,
    authority: std::sync::Arc<crate::store::AuthorityIdentity>,
}
impl AuthorityLease {
    pub(crate) fn check(&self, store: &Store) -> crate::store::Result<()> {
        if !store.writable_authority() {
            return Err(crate::store::StoreError::Unsafe);
        }
        self.check_authority(store.authority_identity())
    }
    pub(crate) fn check_authority(
        &self,
        authority: &std::sync::Arc<crate::store::AuthorityIdentity>,
    ) -> crate::store::Result<()> {
        if !std::sync::Arc::ptr_eq(&self.authority, authority)
            || self.authority.as_ref() != authority.as_ref()
            || authority.lock_id.is_none()
        {
            return Err(crate::store::StoreError::Invalid);
        }
        Ok(())
    }
}
pub(crate) fn locked(config: &Config) -> io::Result<(Store, AuthorityLease)> {
    let dir = config
        .store_dir
        .as_ref()
        .ok_or_else(|| err("configure store_dir in WORK_CONFIG"))?;
    let registry = config
        .trusted_registry
        .as_ref()
        .ok_or_else(|| err("configure trusted_registry in WORK_CONFIG"))?;
    let store = db(Store::open_registered(registry, dir, &config.roots))?;
    let lock = lifecycle_lock(&store)?;
    Ok((store, lock))
}
pub(crate) fn lifecycle_lock(store: &Store) -> io::Result<AuthorityLease> {
    use std::os::unix::fs::MetadataExt;
    db(store.may_acquire_lease())?;
    let authority = store.authority_identity();
    let directory = fs::symlink_metadata(&authority.directory)?;
    if !directory.is_dir()
        || directory.uid() != rustix::process::geteuid().as_raw()
        || directory.mode() & 0o077 != 0
        || (directory.dev(), directory.ino()) != authority.directory_id
    {
        return Err(err("authority directory changed"));
    }
    let lock = db(crate::store::AuthorityIdentity::open_lock(
        &authority.directory,
        false,
    ))?;
    let metadata = lock.metadata()?;
    if Some((metadata.dev(), metadata.ino())) != authority.lock_id {
        return Err(err("authority lock changed"));
    }
    // Bound contention; do not wait indefinitely behind an unknown allocator.
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    loop {
        match rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => break,
            Err(e)
                if e == rustix::io::Errno::WOULDBLOCK && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(AuthorityLease {
        _file: lock,
        authority: std::sync::Arc::clone(authority),
    })
}
fn normalize(config: &Config, mut r: Start) -> io::Result<Start> {
    let policy = config
        .allocation
        .as_ref()
        .ok_or_else(|| err("configure [allocation] quotas and byte floors in WORK_CONFIG"))?;
    if policy.warn_bytes < policy.floor_bytes {
        return Err(err("invalid configured disk thresholds"));
    }
    let repo = r
        .repository
        .as_ref()
        .ok_or_else(|| err("configure and supply --repository"))?;
    let root = r
        .root
        .as_ref()
        .ok_or_else(|| err("configure and supply --root"))?;
    if !config.repositories.contains(repo) || !config.roots.contains(root) {
        return Err(err("repository/root not allowed by configuration"));
    }
    for path in [repo, root] {
        crate::config::validate_path(path, true)
            .map_err(|_| err("noncanonical or symlink path"))?;
    }
    let actor = r.actor.as_ref().ok_or_else(|| err("supply --actor"))?;
    if !component(actor) || !component(&r.task) || !component(r.owner.as_ref().unwrap_or(actor)) {
        return Err(err("unsafe actor/owner/task component"));
    }
    if r.owner.as_ref().is_some_and(|owner| owner != actor) {
        return Err(err(
            "allocating actor must remain accountable; use explicit transfer after allocation",
        ));
    }
    r.owner = Some(actor.clone());
    let branch = r.branch.clone().unwrap_or_else(|| r.task.clone());
    if !component(&branch)
        || branch.ends_with(".lock")
        || r.base.starts_with('-')
        || r.base.contains("..")
        || r.base.chars().any(char::is_whitespace)
        || r.base.contains(['\\', ':', '~', '^', '?', '*', '['])
        || r.base.is_empty()
    {
        return Err(err("unsafe branch/base ref"));
    }
    r.branch = Some(branch);
    if r.operation.get_version_num() != 7 || r.operation.get_variant() != uuid::Variant::RFC4122 {
        return Err(err("operation must be UUIDv7"));
    }
    Ok(r)
}
pub fn start(config: &Config, request: Start) -> io::Result<Allocation> {
    start_observed(config, request, |_| {})
}
/// Observer is called only at persisted protocol boundaries. It does not supply policy
/// or authority. Used by subprocess qualification to abort the allocator itself.
pub fn start_observed(
    config: &Config,
    request: Start,
    mut boundary: impl FnMut(&str),
) -> io::Result<Allocation> {
    let r = normalize(config, request)?;
    let (mut store, lease) = locked(config)?;
    let authority = store.authority_identity().clone();
    let prior_checkout: Option<String> = {
        let _phase = store.sql_phase();
        sql(store
            .conn
            .query_row(
                "SELECT id FROM checkouts WHERE operation=?1",
                [r.operation.to_string()],
                |row| row.get(0),
            )
            .optional())?
    };
    let prior_checkout = prior_checkout
        .as_deref()
        .map(|id| Uuid::parse_str(id).map_err(|_| err("invalid checkout key")))
        .transpose()?;
    if let Some(checkout) = prior_checkout {
        return resume_operation(config, &mut store, &r, checkout, lease, &mut boundary);
    }
    drop(lease);
    let repo = r.repository.as_ref().unwrap();
    query(
        repo,
        &[
            "check-ref-format",
            &format!("refs/heads/{}", r.branch.as_ref().unwrap()),
        ],
    )?;
    // Resolve aliases only for new operations: retries first validate the durable
    // charge and persist a hold even when source Git is unavailable.
    let alias_observations = config
        .repositories
        .iter()
        .map(|path| {
            crate::config::validate_path(path, true).map_err(|_| err("unsafe repository alias"))?;
            Ok((path.clone(), CheckoutIdentity::inspect(path)?))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let aliases: Vec<_> = alias_observations
        .iter()
        .map(|(path, identity)| (path.clone(), identity.common_git_dir.clone()))
        .collect();
    let source = CheckoutIdentity::inspect(repo)?;
    let common = &source.common_git_dir;
    let reservation = Reservation {
        operation: r.operation,
        repository: common.clone(),
        actor: r.actor.clone().unwrap(),
        owner: r.owner.clone().unwrap(),
        task: r.task.clone(),
    };
    // New-charge-only physical inputs cannot defeat a reusable match.
    let candidate = candidate_observation(config, &r, &source);
    for (path, original) in &alias_observations {
        if CheckoutIdentity::inspect(path)? != *original {
            return Err(err("repository alias changed during observation"));
        }
    }
    if CheckoutIdentity::inspect(repo)? != source {
        return Err(err("source changed during observation"));
    }
    let lease = lifecycle_lock(&store)?;
    let appeared: Option<String> = sql(store
        .conn
        .query_row(
            "SELECT id FROM checkouts WHERE operation=?1",
            [r.operation.to_string()],
            |r| r.get(0),
        )
        .optional())?;
    if let Some(id) = appeared {
        return resume_operation(
            config,
            &mut store,
            &r,
            Uuid::parse_str(&id).map_err(|_| err("invalid checkout"))?,
            lease,
            &mut boundary,
        );
    }
    let selection = {
        let phase = store.sql_phase();
        let tx = sql(store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred))?;
        let selected = db(crate::admission::allocation_selection(
            &tx,
            &reservation,
            &aliases,
        ))?;
        sql(tx.rollback())?;
        drop(phase);
        selected
    };
    let matches = selection.matches.clone();
    if !matches.is_empty() {
        // Sorted UUIDs, one nonblocking attempt each, outside SQL. Failure drops
        // every acquired SH without publishing aliases or partial batch holds.
        let guards = matches
            .iter()
            .map(|checkout| {
                db(crate::checkout_guard::CheckoutGuard::shared(
                    &store, *checkout,
                ))
            })
            .collect::<io::Result<Vec<_>>>()?;
        for guard in &guards {
            db(guard.revalidate(&store))?;
        }
        let phase = store.sql_phase();
        let tx = sql(store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate))?;
        let current = db(crate::admission::allocation_selection(
            &tx,
            &reservation,
            &aliases,
        ))?;
        let mut affected = matches.clone();
        affected.extend(current.matches.iter().copied());
        let tx = db(crate::retirement_journal::fence(
            tx,
            &lease,
            &authority,
            db(crate::admission::allocation_scope(
                &current.missing_aliases,
                affected,
            ))?,
            if matches.len() == 1 {
                crate::retirement_journal::Attempt::AliasPublication
            } else {
                crate::retirement_journal::Attempt::AllocationHold
            },
        ))?;
        if current != selection {
            return Err(err("allocation alias/target selection changed"));
        }
        db(crate::admission::publish_aliases(
            &tx,
            &current.missing_aliases,
        ))?;
        // Preserve the original unresolved-legacy fail-closed count semantics,
        // with staged mappings visible only inside the still-uncommitted tx.
        db(crate::store::count(&tx, common.to_str().unwrap(), None))?;
        if matches.len() != 1 {
            for id in matches {
                db(crate::gap_continuation::revoke(&tx, &authority, &lease, id))?;
                db(crate::capture_readiness::invalidate(
                    &tx, id, &lease, &authority,
                ))?;
                sql(tx.execute("UPDATE checkouts SET ready=0,state=CASE WHEN state IN ('reserved','partial','active') THEN 'held' ELSE state END WHERE id=?1", [id.to_string()]))?;
                let operation: String = sql(tx.query_row(
                    "SELECT operation FROM checkouts WHERE id=?1",
                    [id.to_string()],
                    |row| row.get(0),
                ))?;
                db(crate::store::emit(
                    &tx,
                    &crate::events::Event::AllocationStage {
                        checkout: id,
                        operation: Uuid::parse_str(&operation)
                            .map_err(|_| err("invalid stored operation"))?,
                        stage: "held".into(),
                        reason: Some(
                            "ambiguous matching allocations; operator reconciliation required"
                                .into(),
                        ),
                    },
                ))?;
            }
            sql(tx.commit())?;
            return Err(err(
                "ambiguous matching allocations; hold for reconciliation",
            ));
        }
        sql(tx.commit())?;
        drop(phase);
        {
            let _phase = store.sql_phase();
            db(crate::attribution_gap::guard_legacy_allocation(
                &store.conn,
                matches[0],
            ))?;
        }
        refuse_finished(&store, matches[0])?;
        let (operation, state): (String, String) = sql(store.conn.query_row(
            "SELECT operation,state FROM checkouts WHERE id=?1",
            [matches[0].to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ))?;
        let mut a = load_under_lease(
            &mut store,
            Uuid::parse_str(&operation).map_err(|_| err("invalid stored operation"))?,
            &lease,
        )?
        .ok_or_else(|| err("matching charge lacks intent; hold"))?;
        let required = db(crate::capture_requirement::read(&store.conn, a.checkout))?.is_some();
        if !((state == "active" && a.stage == "ready")
            || (required && state == "partial" && a.stage == "capture_pending"))
        {
            return Err(err(
                "matching allocation incomplete or held; explicit recovery required",
            ));
        }
        if !required && config.allocation.as_ref().unwrap().capture_sink.is_some() {
            crate::recovery::hold_under_lease(
                &mut store,
                &mut a,
                "configured capture unsupported",
                &lease,
            )?;
            return Err(err("configured capture unsupported"));
        }
        drop(lease);
        let observed = observe_reconciliation(&mut store, &a, &guards[0])?;
        let lease = lifecycle_lock(&store)?;
        crate::recovery::reconcile_under_lease(&mut store, &mut a, observed, &lease)?;
        return if matches!(a.stage.as_str(), "ready" | "capture_pending") {
            Ok(a)
        } else {
            Err(err("matching allocation held"))
        };
    }
    let (mut a, limits, capture_required) = candidate?;
    let recorded = db(store.reserve_recorded_under_lease(
        &reservation,
        limits,
        |checkout| {
            a.checkout = checkout;
            Ok(Some(crate::admission::AllocationIntent {
                request: serde_json::to_string(&a.request)
                    .map_err(|_| crate::store::StoreError::Invalid)?,
                record: serde_json::to_string(&a).map_err(|_| crate::store::StoreError::Invalid)?,
                capture_required,
            }))
        },
        &lease,
        crate::admission::ReservationPurpose::Allocation(&aliases),
    ))?;
    let guard = recorded
        .guard
        .ok_or_else(|| err("missing allocation guard"))?;
    if recorded.checkout != a.checkout {
        return Err(err(
            "operation appeared during allocation observation; retry required",
        ));
    }
    drop(lease);
    boundary("charged");
    boundary("reserved");
    create(config, &mut store, a, &mut boundary, &guard)
}
fn resume_operation(
    config: &Config,
    store: &mut Store,
    r: &Start,
    checkout: Uuid,
    lease: AuthorityLease,
    boundary: &mut impl FnMut(&str),
) -> io::Result<Allocation> {
    let guard = db(crate::checkout_guard::CheckoutGuard::shared(
        store, checkout,
    ))?;
    db(crate::retirement_journal::checkpoint(
        store,
        &lease,
        crate::retirement_journal::Scope::Checkout(checkout),
        crate::retirement_journal::Attempt::AllocationStage,
    ))?;
    db(crate::attribution_gap::guard_legacy_allocation(
        &store.conn,
        checkout,
    ))?;
    let mut a = load_under_lease(store, r.operation, &lease)?
        .ok_or_else(|| err("reservation lacks allocation intent; charge retained"))?;
    refuse_finished(store, checkout)?;
    if &a.request != r {
        return Err(err("operation request conflicts"));
    }
    let state: String = sql(store.conn.query_row(
        "SELECT state FROM checkouts WHERE id=?1",
        [checkout.to_string()],
        |r| r.get(0),
    ))?;
    if a.stage == "held" || !matches!(state.as_str(), "reserved" | "partial" | "active") {
        return Err(err("later lifecycle state requires explicit recovery"));
    }
    if !db(crate::capture_requirement::present(&store.conn, checkout))?
        && config.allocation.as_ref().unwrap().capture_sink.is_some()
    {
        crate::recovery::hold_under_lease(
            store,
            &mut a,
            "configured capture unsupported; no capture prepared",
            &lease,
        )?;
        return Err(err(
            "configured capture unsupported; writer eligibility revoked",
        ));
    }
    drop(lease);
    if a.stage == "reserved" {
        return create(config, store, a, boundary, &guard);
    }
    let observed = observe_reconciliation(store, &a, &guard)?;
    let lease = lifecycle_lock(store)?;
    crate::recovery::reconcile_under_lease(store, &mut a, observed, &lease)?;
    if matches!(a.stage.as_str(), "ready" | "capture_pending") {
        Ok(a)
    } else {
        Err(err(a.reason.as_deref().unwrap_or("allocation held")))
    }
}
fn candidate_observation(
    config: &Config,
    r: &Start,
    source: &CheckoutIdentity,
) -> io::Result<(Allocation, Limits, bool)> {
    let policy = config.allocation.as_ref().unwrap();
    let capture_required = config
        .selected_capture()
        .map_err(|_| err("configured capture missing or unsupported; no reservation"))?
        .is_some();
    let repo = r.repository.as_ref().unwrap();
    if repo.join(".gitmodules").exists() || source.common_git_dir.join("modules").exists() {
        return Err(err("unsupported submodule layout; hold"));
    }
    let destination = r.root.as_ref().unwrap().join(&r.task);
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(err(
            "destination collision; never adopting existing directory",
        ));
    }
    let branch = r.branch.as_ref().unwrap();
    let exists = query(
        repo,
        &["show-ref", "--verify", &format!("refs/heads/{branch}")],
    )
    .is_ok();
    if exists != r.reuse_branch {
        return Err(err(
            "existing branch requires explicit --reuse-branch; missing branch cannot be reused",
        ));
    }
    let base_commit = query(
        repo,
        &[
            "rev-parse",
            "--verify",
            &format!("{}^{{commit}}", if exists { branch } else { &r.base }),
        ],
    )?;
    let stat = rustix::fs::statvfs(r.root.as_ref().unwrap()).map_err(io::Error::from)?;
    let limits = Limits {
        repository: policy.repository_limit,
        owner: policy.owner_limit,
        available_bytes: stat.f_bavail.checked_mul(stat.f_frsize),
        floor_bytes: policy.floor_bytes,
        warn_bytes: policy.warn_bytes,
    };
    Ok((
        Allocation {
            checkout: Uuid::nil(),
            request: r.clone(),
            destination,
            base_commit,
            stage: "reserved".into(),
            reason: None,
            identity: None,
        },
        limits,
        capture_required,
    ))
}
/// Physical source inspection against an already-owned charged common directory.
/// Performs no SQL; capture setup must collect the expected authority beforehand.
pub(crate) fn verify_source_authority(
    a: &Allocation,
    charged_common: &std::path::Path,
) -> io::Result<PathBuf> {
    let result = a
        .request
        .repository
        .as_ref()
        .ok_or_else(|| err("missing durable source authority"))
        .and_then(|path| CheckoutIdentity::inspect(path));
    match result {
        Ok(source) if source.common_git_dir == charged_common => Ok(source.common_git_dir),
        _ => Err(err("source repository authority mismatch")),
    }
}
fn recheck_creation_root(file: &fs::File, path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    crate::config::validate_path(path, true).map_err(|_| err("creation root path changed"))?;
    let held = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !named.is_dir() || (held.dev(), held.ino()) != (named.dev(), named.ino()) {
        return Err(err("creation root identity changed"));
    }
    Ok(())
}
fn create(
    config: &Config,
    store: &mut Store,
    mut a: Allocation,
    boundary: &mut impl FnMut(&str),
    guard: &crate::checkout_guard::CheckoutGuard,
) -> io::Result<Allocation> {
    db(guard.require_matching(store, a.checkout))?;
    let started = std::time::Instant::now();
    let lease = lifecycle_lock(store)?;
    db(crate::retirement_journal::checkpoint(
        store,
        &lease,
        crate::retirement_journal::Scope::Checkout(a.checkout),
        crate::retirement_journal::Attempt::AllocationStage,
    ))?;
    let initial = load_under_lease(store, a.request.operation, &lease)?
        .ok_or_else(|| err("allocation disappeared"))?;
    if serde_json::to_value(&initial)? != serde_json::to_value(&a)? {
        return Err(err("allocation creation predecessor changed"));
    }
    let (charged, state): (String, String) = sql(store.conn.query_row(
        "SELECT repository,state FROM checkouts WHERE id=?1",
        [a.checkout.to_string()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ))?;
    if state != "reserved" || a.stage != "reserved" {
        return Err(err("allocation creation predecessor changed"));
    }
    let before_lock = Predecessor::read(store, &a, started)?;
    drop(lease);
    let mut common = match crate::inspection::AllocationCommonLock::acquire(
        store,
        std::path::Path::new(&charged),
    ) {
        Ok(common) => common,
        Err(error) => {
            if error.kind() != io::ErrorKind::WouldBlock {
                let lease = lifecycle_lock(store)?;
                failed_observation(store, &a, &before_lock, &lease)?;
            }
            return Err(error);
        }
    };
    // Common lock acquisition precedes this reread. A second allocator cannot
    // turn a stale reserved selection into a second Git worktree add.
    let lease = lifecycle_lock(store)?;
    db(crate::retirement_journal::checkpoint(
        store,
        &lease,
        crate::retirement_journal::Scope::Checkout(a.checkout),
        crate::retirement_journal::Attempt::AllocationStage,
    ))?;
    let current = load_under_lease(store, a.request.operation, &lease)?
        .ok_or_else(|| err("allocation disappeared"))?;
    let (repository, state): (String, String) = sql(store.conn.query_row(
        "SELECT repository,state FROM checkouts WHERE id=?1",
        [a.checkout.to_string()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ))?;
    if serde_json::to_value(&current)? != serde_json::to_value(&a)?
        || a.stage != "reserved"
        || state != "reserved"
        || repository != charged
    {
        return Err(err("allocation creation predecessor changed"));
    }
    let before = Predecessor::read(store, &a, started)?;
    drop(lease);
    let source = (|| {
        let normalized = normalize(config, a.request.clone())?;
        if normalized != a.request
            || a.destination != normalized.root.as_ref().unwrap().join(&normalized.task)
            || !matches!(a.base_commit.len(), 40 | 64)
            || !a
                .base_commit
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(err("unsafe durable creation request"));
        }
        if fs::symlink_metadata(&a.destination).is_ok() {
            return Err(err("destination collision"));
        }
        let repo = a.request.repository.as_ref().unwrap();
        let source = CheckoutIdentity::inspect(repo)?;
        if source.common_git_dir != std::path::Path::new(&charged) {
            return Err(err("source authority changed"));
        }
        crate::identity::preflight_creation(repo)?;
        if a.request.reuse_branch
            && query(
                repo,
                &[
                    "rev-parse",
                    &format!("refs/heads/{}", a.request.branch.as_ref().unwrap()),
                ],
            )? != a.base_commit
        {
            return Err(err("branch moved"));
        }
        let root = fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NONBLOCK)
                    .bits() as i32,
            )
            .open(a.request.root.as_ref().unwrap())?;
        recheck_creation_root(&root, a.request.root.as_ref().unwrap())?;
        common.revalidate(store)?;
        Ok((source, root))
    })();
    let (source, root) = match source {
        Ok(source) => source,
        Err(error) => {
            let lease = lifecycle_lock(store)?;
            failed_observation(store, &a, &before, &lease)?;
            return Err(error);
        }
    };
    db(guard.require_matching(store, a.checkout))?;
    let lease = lifecycle_lock(store)?;
    a.stage = "creating".into();
    save_checked_under_lease(store, &a, &lease, Some(&before))?;
    let creating = Predecessor::read(store, &a, started)?;
    drop(lease);
    boundary("intent");
    let physical = (|| {
        if normalize(config, a.request.clone())? != a.request {
            return Err(err("creation request changed"));
        }
        recheck_creation_root(&root, a.request.root.as_ref().unwrap())?;
        if fs::symlink_metadata(&a.destination).is_ok() {
            return Err(err("destination collision before Git add"));
        }
        let repo = a.request.repository.as_ref().unwrap();
        if CheckoutIdentity::inspect(repo)? != source {
            return Err(err("source changed before Git add"));
        }
        common.revalidate(store)?;
        // The persisted-intent callback and intervening I/O cannot freeze Git
        // configuration. Repeat the executable-filter gate at the actual add.
        crate::identity::preflight_creation(repo)?;
        let branch = a.request.branch.as_ref().unwrap();
        if a.request.reuse_branch
            && query(repo, &["rev-parse", &format!("refs/heads/{branch}")])? != a.base_commit
        {
            return Err(err("branch moved before Git add"));
        }
        let result = if a.request.reuse_branch {
            query(
                repo,
                &[
                    "-c",
                    "core.hooksPath=/dev/null",
                    "worktree",
                    "add",
                    "--",
                    a.destination
                        .to_str()
                        .ok_or_else(|| err("non-UTF8 destination"))?,
                    branch,
                ],
            )
        } else {
            query(
                repo,
                &[
                    "-c",
                    "core.hooksPath=/dev/null",
                    "worktree",
                    "add",
                    "-b",
                    branch,
                    "--",
                    a.destination
                        .to_str()
                        .ok_or_else(|| err("non-UTF8 destination"))?,
                    &a.base_commit,
                ],
            )
        };
        boundary("created");
        result?;
        recheck_creation_root(&root, a.request.root.as_ref().unwrap())?;
        if CheckoutIdentity::inspect(repo)? != source {
            return Err(err("source changed during Git add"));
        }
        let identity = CheckoutIdentity::inspect(&a.destination)?;
        if identity.common_git_dir != source.common_git_dir
            || identity.private_git_dir == identity.common_git_dir
            || identity.head != a.base_commit
        {
            return Err(err("created Git identity mismatch"));
        }
        common.revalidate(store)?;
        db(guard.require_matching(store, a.checkout))?;
        Ok(identity)
    })();
    let identity = match physical {
        Ok(identity) => identity,
        Err(error) => {
            let lease = lifecycle_lock(store)?;
            failed_observation(store, &a, &creating, &lease)?;
            return Err(error);
        }
    };
    let lease = lifecycle_lock(store)?;
    a.identity = Some(identity);
    a.stage = "created".into();
    save_checked_under_lease(store, &a, &lease, Some(&creating))?;
    let created = Predecessor::read(store, &a, started)?;
    drop(lease);
    boundary("identity");
    let marker_result = (|| {
        recheck_creation_root(&root, a.request.root.as_ref().unwrap())?;
        let identity = a.identity.as_ref().unwrap();
        if CheckoutIdentity::inspect(a.request.repository.as_ref().unwrap())? != source {
            return Err(err("source changed before marker"));
        }
        if CheckoutIdentity::inspect(&a.destination)? != *identity {
            return Err(err("identity changed before marker"));
        }
        let marker = identity.private_git_dir.join("work-lease.json");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(&marker)?;
        file.write_all(&serde_json::to_vec(&crate::recovery::Marker::from(&a))?)?;
        file.sync_all()?;
        fs::File::open(marker.parent().unwrap())?.sync_all()?;
        fs::File::open(&a.destination)?.sync_all()?;
        fs::File::open(a.destination.parent().unwrap())?.sync_all()?;
        Ok::<_, io::Error>(())
    })();
    if let Err(error) = marker_result {
        let lease = lifecycle_lock(store)?;
        failed_observation(store, &a, &created, &lease)?;
        return Err(error);
    }
    boundary("marker");
    let mut observed = collect_physical(store, a.clone(), created, common, guard, Some(&source))?;
    if let Err(error) = recheck_creation_root(&root, a.request.root.as_ref().unwrap()) {
        observed.evidence = Err(error);
    }
    let lease = lifecycle_lock(store)?;
    crate::recovery::reconcile_under_lease(store, &mut a, observed, &lease)?;
    drop(lease);
    if !matches!(a.stage.as_str(), "ready" | "capture_pending") {
        return Err(err("identity changed before readiness; allocation held"));
    }
    boundary(&a.stage);
    Ok(a)
}
