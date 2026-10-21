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
pub(crate) fn save(store: &mut Store, a: &Allocation) -> io::Result<()> {
    let record = serde_json::to_string(a)?;
    let request = serde_json::to_string(&a.request)?;
    let _phase = store.sql_phase();
    let tx = sql(store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate))?;
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
        db(crate::capture_readiness::invalidate(&tx, a.checkout))?;
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
    sql(tx.commit())
}
pub(crate) fn load(store: &mut Store, operation: Uuid) -> io::Result<Option<Allocation>> {
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
    let tx = sql(store.conn.transaction())?;
    db(crate::capture_readiness::invalidate(&tx, checkout))?;
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
/// Fresh checkout-by-ID validation. Caller holds allocation lock only for a
/// short preflight/transaction, never for the supervised actor lifetime.
/// Unlike allocation reconciliation this never revives held/quarantined rows.
pub(crate) fn verified_checkout(store: &mut Store, checkout: Uuid) -> io::Result<Allocation> {
    refuse_finished(store, checkout)?;
    {
        let _phase = store.sql_phase();
        db(crate::capture_journal::guard_allocation_identity(
            &store.conn,
            checkout,
        ))?;
    }
    let (operation, state, ready): (String, String, bool) = sql(store.conn.query_row(
        "SELECT operation,state,ready FROM checkouts WHERE id=?1",
        [checkout.to_string()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ))?;
    if state != "active" || !ready {
        return Err(err("checkout not active and ready"));
    }
    let mut a = load(
        store,
        Uuid::parse_str(&operation).map_err(|_| err("invalid operation"))?,
    )?
    .filter(|a| a.checkout == checkout && a.stage == "ready")
    .ok_or_else(|| err("checkout allocation not ready"))?;
    source_authority(store, &mut a)?;
    let current = match crate::recovery::verify(&a) {
        Ok(current) => current,
        Err(_) => {
            crate::recovery::hold(
                store,
                &mut a,
                "fresh lease identity verification failed; charge retained",
            )?;
            return Err(err("lease identity changed; held"));
        }
    };
    refresh_ready_identity(store, &mut a, current)?;
    Ok(a)
}
/// Identity evidence only: atomically refresh a still-active/ready allocation
/// and its HEAD event. Never changes checkout eligibility, stage, or lease base.
fn refresh_ready_identity(
    store: &mut Store,
    a: &mut Allocation,
    current: CheckoutIdentity,
) -> io::Result<()> {
    let _phase = store.sql_phase();
    let tx = sql(store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate))?;
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
    sql(tx.commit())?;
    *a = refreshed;
    Ok(())
}
pub(crate) fn locked(config: &Config) -> io::Result<(Store, fs::File)> {
    let dir = config
        .store_dir
        .as_ref()
        .ok_or_else(|| err("configure store_dir in WORK_CONFIG"))?;
    let registry = config
        .trusted_registry
        .as_ref()
        .ok_or_else(|| err("configure trusted_registry in WORK_CONFIG"))?;
    let store = db(Store::open_registered(registry, dir, &config.roots))?;
    let lock = lifecycle_lock(dir)?;
    Ok((store, lock))
}
pub(crate) fn lifecycle_lock(dir: &std::path::Path) -> io::Result<fs::File> {
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(dir.join("allocation.lock"))?;
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
    Ok(lock)
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
    let (mut store, _lock) = locked(config)?;
    {
        let _phase = store.sql_phase();
        let checkout: Option<String> = sql(store
            .conn
            .query_row(
                "SELECT id FROM checkouts WHERE operation=?1",
                [r.operation.to_string()],
                |row| row.get(0),
            )
            .optional())?;
        if let Some(checkout) = checkout {
            let checkout = Uuid::parse_str(&checkout).map_err(|_| err("invalid checkout key"))?;
            db(crate::attribution_gap::guard_legacy_allocation(
                &store.conn,
                checkout,
            ))?;
        }
    }
    if let Some(mut a) = load(&mut store, r.operation)? {
        refuse_finished(&store, a.checkout)?;
        if a.request != r {
            return Err(err("operation request conflicts"));
        }
        let state: String = sql(store.conn.query_row(
            "SELECT state FROM checkouts WHERE id=?1",
            [a.checkout.to_string()],
            |row| row.get(0),
        ))?;
        if a.stage == "held" || !matches!(state.as_str(), "reserved" | "partial" | "active") {
            return Err(err(
                "later lifecycle state requires explicit recovery; start cannot reverse it",
            ));
        }
        if !db(crate::capture_requirement::present(&store.conn, a.checkout))?
            && config.allocation.as_ref().unwrap().capture_sink.is_some()
        {
            crate::recovery::hold(
                &mut store,
                &mut a,
                "configured capture unsupported; no capture prepared",
            )?;
            return Err(err(
                "configured capture unsupported; writer eligibility revoked",
            ));
        }
        if a.stage == "reserved" {
            return create(config, &mut store, a, &mut boundary);
        }
        source_authority(&mut store, &mut a)?;
        crate::recovery::reconcile(&mut store, &mut a)?;
        return if matches!(a.stage.as_str(), "ready" | "capture_pending") {
            Ok(a)
        } else {
            Err(err(a.reason.as_deref().unwrap_or("allocation held")))
        };
    }
    let prior: bool = sql(store.conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM checkouts WHERE operation=?1)",
        [r.operation.to_string()],
        |row| row.get(0),
    ))?;
    if prior {
        return Err(err(
            "reservation lacks allocation intent; hold charged for operator reconciliation",
        ));
    }
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
    let aliases = config
        .repositories
        .iter()
        .map(|path| {
            crate::config::validate_path(path, true).map_err(|_| err("unsafe repository alias"))?;
            Ok((
                path.clone(),
                CheckoutIdentity::inspect(path)?.common_git_dir,
            ))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let source = CheckoutIdentity::inspect(repo)?;
    let common = &source.common_git_dir;
    let tx = sql(store.conn.transaction())?;
    for (alias, identity) in &aliases {
        let existing: Option<String> = sql(tx
            .query_row(
                "SELECT common FROM repository_aliases WHERE alias=?1",
                [alias.to_str().unwrap()],
                |row| row.get(0),
            )
            .optional())?;
        if existing
            .as_deref()
            .is_some_and(|v| v != identity.to_str().unwrap())
        {
            return Err(err("repository alias identity changed; hold"));
        }
        sql(tx.execute(
            "INSERT OR IGNORE INTO repository_aliases VALUES(?1,?2)",
            rusqlite::params![alias.to_str().unwrap(), identity.to_str().unwrap()],
        ))?;
    }
    sql(tx.commit())?;
    // A charged legacy identity that cannot be resolved must never become zero usage.
    db(crate::store::count(
        &store.conn,
        common.to_str().unwrap(),
        None,
    ))?;
    let matches = db(store.find_reusable(r.actor.as_ref().unwrap(), common, &r.task))?;
    if !matches.is_empty() {
        if matches.len() != 1 {
            let tx = sql(store.conn.transaction())?;
            for id in matches {
                db(crate::capture_readiness::invalidate(&tx, id))?;
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
        let mut a = load(
            &mut store,
            Uuid::parse_str(&operation).map_err(|_| err("invalid stored operation"))?,
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
            crate::recovery::hold(&mut store, &mut a, "configured capture unsupported")?;
            return Err(err("configured capture unsupported"));
        }
        source_authority(&mut store, &mut a)?;
        crate::recovery::reconcile(&mut store, &mut a)?;
        return if matches!(a.stage.as_str(), "ready" | "capture_pending") {
            Ok(a)
        } else {
            Err(err("matching allocation held"))
        };
    }
    let policy = config.allocation.as_ref().unwrap();
    let capture_required = config
        .selected_capture()
        .map_err(|_| err("configured capture missing or unsupported; no reservation"))?
        .is_some();
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
    let available = stat.f_bavail.checked_mul(stat.f_frsize);
    let mut a = Allocation {
        checkout: Uuid::nil(),
        request: r.clone(),
        destination,
        base_commit,
        stage: "reserved".into(),
        reason: None,
        identity: None,
    };
    db(store.reserve_recorded(
        &Reservation {
            operation: r.operation,
            repository: common.clone(),
            actor: r.actor.clone().unwrap(),
            owner: r.owner.clone().unwrap(),
            task: r.task.clone(),
        },
        Limits {
            repository: policy.repository_limit,
            owner: policy.owner_limit,
            available_bytes: available,
            floor_bytes: policy.floor_bytes,
            warn_bytes: policy.warn_bytes,
        },
        |checkout| {
            a.checkout = checkout;
            Ok(Some(crate::admission::AllocationIntent {
                request: serde_json::to_string(&a.request)
                    .map_err(|_| crate::store::StoreError::Invalid)?,
                record: serde_json::to_string(&a).map_err(|_| crate::store::StoreError::Invalid)?,
                capture_required,
            }))
        },
    ))?;
    boundary("charged");
    boundary("reserved");
    create(config, &mut store, a, &mut boundary)
}
// The charged row, not a second fresh Git query, is repository authority.
fn source_authority_evidence(conn: &rusqlite::Connection, a: &Allocation) -> io::Result<PathBuf> {
    let charged: String = sql(conn.query_row(
        "SELECT repository FROM checkouts WHERE id=?1",
        [a.checkout.to_string()],
        |row| row.get(0),
    ))?;
    verify_source_authority(a, std::path::Path::new(&charged))
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
fn source_authority(store: &mut Store, a: &mut Allocation) -> io::Result<PathBuf> {
    {
        let _phase = store.sql_phase();
        db(crate::attribution_gap::guard_legacy_allocation(
            &store.conn,
            a.checkout,
        ))?;
    }
    match source_authority_evidence(&store.conn, a) {
        Ok(common) => Ok(common),
        Err(_) => {
            crate::recovery::hold(
                store,
                a,
                "source repository differs from durable charged authority or is unavailable",
            )?;
            Err(err("source repository authority mismatch; allocation held"))
        }
    }
}

fn create(
    _config: &Config,
    store: &mut Store,
    mut a: Allocation,
    boundary: &mut impl FnMut(&str),
) -> io::Result<Allocation> {
    {
        let _phase = store.sql_phase();
        db(crate::attribution_gap::guard_legacy_allocation(
            &store.conn,
            a.checkout,
        ))?;
    }
    crate::config::validate_path(a.destination.parent().unwrap(), true)
        .map_err(|_| err("destination ancestor changed"))?;
    if fs::symlink_metadata(&a.destination).is_ok() {
        return crate::recovery::hold(store, &mut a, "destination collision")
            .and_then(|()| Err(err("destination collision")));
    }
    a.stage = "creating".into();
    save(store, &a)?;
    boundary("intent");
    let charged_common = source_authority(store, &mut a)?;
    let repo = a.request.repository.as_ref().unwrap();
    let branch = a.request.branch.as_ref().unwrap();
    if let Err(e) = crate::identity::preflight_creation(repo) {
        crate::recovery::hold(store, &mut a, &format!("creation preflight failed: {e}"))?;
        return Err(e);
    }
    let result = if a.request.reuse_branch {
        // Freeze the explicit existing branch boundary; do not reset it to base.
        if query(repo, &["rev-parse", &format!("refs/heads/{branch}")])
            .ok()
            .as_deref()
            != Some(a.base_commit.as_str())
        {
            crate::recovery::hold(
                store,
                &mut a,
                "branch moved or unavailable; charged intent requires reconciliation",
            )?;
            return Err(err("branch moved; allocation held"));
        }
        query(
            repo,
            &[
                "-c",
                "core.hooksPath=/dev/null",
                "worktree",
                "add",
                "--",
                a.destination.to_str().unwrap(),
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
                a.destination.to_str().unwrap(),
                &a.base_commit,
            ],
        )
    };
    boundary("created");
    if result.is_err() {
        crate::recovery::hold(
            store,
            &mut a,
            "Git creation failed; inspect path and registration (charge retained)",
        )?;
        return Err(err("Git creation failed; allocation held"));
    }
    let identity = CheckoutIdentity::inspect(&a.destination)?;
    if identity.common_git_dir != charged_common
        || identity.private_git_dir == identity.common_git_dir
        || identity.head != a.base_commit
    {
        crate::recovery::hold(store, &mut a, "unsupported or changed Git identity")?;
        return Err(err("Git identity mismatch; held"));
    }
    a.identity = Some(identity);
    // Identity commit BEFORE marker: an interrupted marker write is not adopted.
    a.stage = "created".into();
    save(store, &a)?;
    boundary("identity");
    let marker = a
        .identity
        .as_ref()
        .unwrap()
        .private_git_dir
        .join("work-lease.json");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&marker)?;
    file.write_all(&serde_json::to_vec(&crate::recovery::Marker::from(&a))?)?;
    file.sync_all()?;
    fs::File::open(marker.parent().unwrap())?.sync_all()?;
    fs::File::open(&a.destination)?.sync_all()?;
    fs::File::open(a.destination.parent().unwrap())?.sync_all()?;
    boundary("marker");
    crate::recovery::reconcile(store, &mut a)?;
    if !matches!(a.stage.as_str(), "ready" | "capture_pending") {
        return Err(err("identity changed before readiness; allocation held"));
    }
    boundary(&a.stage);
    Ok(a)
}
