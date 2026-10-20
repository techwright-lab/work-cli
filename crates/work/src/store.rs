//! Private local SQLite authority. Callers must select one trusted host-local
//! registry with one authoritative store for all managed roots. This is cooperative
//! configuration enforcement, not discovery of arbitrary databases or protection
//! from a malicious same UID.
use crate::events::{Event, PendingEvent};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("unsafe local store or authority configuration")]
    Unsafe,
    #[error("store database failure")]
    Database(#[from] rusqlite::Error),
    #[error("local store I/O failure")]
    Io(#[from] std::io::Error),
    #[error("operation request conflicts")]
    Conflict,
    #[error("capacity unavailable")]
    Capacity,
    #[error("writer already held")]
    Writer,
    #[error("invalid store record")]
    Invalid,
    #[error("historical run status unknown: schema upgrade required")]
    UpgradeRequired,
}
pub type Result<T> = std::result::Result<T, StoreError>;
pub struct Store {
    pub(crate) conn: Connection,
    budget: SqlBudget,
}

// Linux filesystem magic allowlist: ext, Btrfs, XFS, tmpfs and local
// overlayfs. Unknown/FUSE/network filesystems require separate qualification.
fn local_filesystem(magic: u64) -> bool {
    matches!(
        magic,
        0xef53 | 0x9123683e | 0x58465342 | 0x01021994 | 0x794c7630
    )
}

fn private_dir(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(StoreError::Unsafe);
    }
    for ancestor in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(ancestor)?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || (m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0)
        {
            return Err(StoreError::Unsafe);
        }
    }
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.mode() & 0o077 != 0 || m.uid() != rustix::process::geteuid().as_raw() {
        return Err(StoreError::Unsafe);
    }
    let filesystem = rustix::fs::statfs(path).map_err(std::io::Error::from)?;
    if !local_filesystem(filesystem.f_type as u64) {
        return Err(StoreError::Unsafe);
    }
    Ok(fs::canonicalize(path)?)
}
fn check_file(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.mode() & 0o077 != 0
        || m.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(StoreError::Unsafe);
    }
    Ok(())
}
fn database(dir: &Path, name: &str, pending: bool) -> Result<Connection> {
    let path = dir.join(name);
    if !pending {
        check_file(&path)?;
        if fs::metadata(&path)?.len() < 100 {
            return Err(StoreError::Unsafe);
        }
    }
    if pending {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
    }
    check_file(&path)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let side = dir.join(format!("{name}{suffix}"));
        match fs::symlink_metadata(&side) {
            Ok(_) => check_file(&side)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    // Retain ordinary WAL/SHM bookkeeping at last close so strict readers never
    // need to create it. FULL commits and normal autocheckpoint remain enabled.
    conn.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        true,
    )?;
    conn.busy_timeout(Duration::from_millis(500))?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if !(version == 1
        || (name == "store.sqlite" && matches!(version, 2..=12))
        || (pending && version == 0))
    {
        return Err(StoreError::Unsafe);
    }
    conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")?;
    let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
    if mode != "wal" {
        return Err(StoreError::Unsafe);
    }
    Ok(conn)
}
// The registry lock serializes the entire bootstrap, not just claims. The file
// is private, never unlinked, and NOFOLLOW prevents following a planted link.
fn initialization_lock(registry: &Path) -> Result<fs::File> {
    let path = registry.join("initialization.lock");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)?;
    check_file(&path)?;
    let metadata = file.metadata()?;
    if metadata.ino() != fs::symlink_metadata(&path)?.ino() {
        return Err(StoreError::Unsafe);
    }
    let start = std::time::Instant::now();
    loop {
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(file),
            Err(rustix::io::Errno::WOULDBLOCK) if start.elapsed() < Duration::from_millis(500) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(std::io::Error::from(e).into()),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Initialization {
    version: u32,
    store: PathBuf,
    initialized: bool,
}
fn sync_dir(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}
fn persist_initialization(registry: &Path, record: &Initialization) -> Result<()> {
    let temporary = registry.join("initialization.tmp");
    if temporary.try_exists()? {
        check_file(&temporary)?;
        fs::remove_file(&temporary)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let bytes = serde_json::to_vec(record).map_err(|_| StoreError::Invalid)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    initialization_boundary(if record.initialized {
        "initialized_temp"
    } else {
        "pending_temp"
    });
    fs::rename(temporary, registry.join("initialization.json"))?;
    sync_dir(registry)
}

// Only unit-test builds can interrupt the real protocol at durability boundaries.
fn initialization_boundary(_name: &str) {
    #[cfg(test)]
    if std::env::var("WORK_INIT_TEST_BOUNDARY").as_deref() == Ok(_name) {
        // Worker-local only: retain SIGABRT crash semantics without costly core dumps.
        use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
        setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                ..getrlimit(Resource::Core)
            },
        )
        .unwrap();
        assert_eq!(
            getrlimit(Resource::Core).current,
            Some(0),
            "intentional fault worker must not dump core"
        );
        std::process::abort();
    }
}

pub(crate) fn canonical(path: &Path) -> Result<String> {
    let p = fs::canonicalize(path)?;
    p.to_str().map(str::to_owned).ok_or(StoreError::Invalid)
}
fn roots(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    if paths.is_empty() {
        return Err(StoreError::Unsafe);
    }
    let mut result = Vec::new();
    for p in paths {
        let c = PathBuf::from(canonical(p)?);
        if &c != p || !c.is_dir() {
            return Err(StoreError::Unsafe);
        }
        result.push(c);
    }
    result.sort();
    for (i, a) in result.iter().enumerate() {
        if result[i + 1..].iter().any(|b| b.starts_with(a)) {
            return Err(StoreError::Unsafe);
        }
    }
    Ok(result)
}
impl Store {
    pub(crate) fn sql_phase(&self) -> SqlPhase {
        self.budget.enter()
    }
    /// Existing authority only. No bootstrap, schema migration, event writes or
    /// repair; reads committed WAL through SQLite's ordinary read-only mode.
    pub fn open_existing_registered_readonly(
        registry: &Path,
        dir: &Path,
        managed: &[PathBuf],
    ) -> Result<Self> {
        let (conn, budget, _) = existing_authority(registry, dir, managed, false)?;
        let _phase = budget.enter();
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version != 12 {
            return Err(StoreError::UpgradeRequired);
        }
        validate_existing_schema(&conn, version)?;
        Ok(Self { conn, budget })
    }
    /// Recovery can mutate an established current-schema authority only; never initializes
    /// an empty authority for an unknown RunId or upgrades historical schemas.
    pub fn open_existing_registered_mut(
        registry: &Path,
        dir: &Path,
        managed: &[PathBuf],
    ) -> Result<Self> {
        let (conn, budget, _) = existing_authority(registry, dir, managed, true)?;
        let _phase = budget.enter();
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version != 12 {
            return Err(StoreError::UpgradeRequired);
        }
        validate_existing_schema(&conn, version)?;
        Ok(Self { conn, budget })
    }
    /// Finish may upgrade a proven established v8 authority, never bootstrap or
    /// repair an invalid authority. The read-only preflight precedes mutable open.
    pub(crate) fn open_finish_authority(
        registry: &Path,
        dir: &Path,
        managed: &[PathBuf],
    ) -> Result<Self> {
        let (conn, budget, _) = existing_authority(registry, dir, managed, false)?;
        {
            let (reg, reg_budget) = existing_database(registry, "authorities.sqlite")?;
            let _reg_phase = reg_budget.enter();
            let _phase = budget.enter();
            for db in [&conn, &reg] {
                let mode: String = db.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
                if mode != "wal" {
                    return Err(StoreError::Unsafe);
                }
            }
            let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            if !matches!(version, 8..=12) {
                return Err(StoreError::UpgradeRequired);
            }
            validate_existing_schema(&conn, version)?;
            crate::run_journal::validate_enrollment_rosters(&conn)?;
        }
        drop(conn);
        Self::open_registered(registry, dir, managed)
    }
    /// Uses `.work-authorities` at the store's parent as the trusted registry,
    /// permitting only one authoritative store there, even for disjoint roots.
    /// Callers spanning different parents MUST use `open_registered` with their
    /// common trusted registry. Choosing a different registry is explicit host
    /// policy, not a security guarantee; no global filesystem scan is performed.
    pub fn open(dir: &Path, managed: &[PathBuf]) -> Result<Self> {
        let parent = dir.parent().ok_or(StoreError::Unsafe)?;
        Self::open_registered(&parent.join(".work-authorities"), dir, managed)
    }
    /// One trusted registry permits only one authoritative store, regardless of
    /// root overlap. Registry claims are never auto-released on database loss.
    /// Reconfiguration needs an audited operator migration; no second authority is
    /// silently substituted. The registry is an explicitly trusted host policy
    /// boundary, not a global scan. Keep this path fixed across all configurations.
    /// A private, bounded registry lock serializes durable pending/initialized
    /// intent. Only pending bootstrap may create schemas; established database
    /// loss, version zero, or SQLite files without initialization proof fail
    /// closed. Pre-protocol databases require explicit operator migration.
    /// Only allowlisted Linux local filesystem types are accepted. Overlay backing
    /// storage durability/locality remains a host qualification obligation.
    pub fn open_registered(registry: &Path, dir: &Path, managed: &[PathBuf]) -> Result<Self> {
        let managed = roots(managed)?;
        let registry = private_dir(registry)?;
        sync_dir(registry.parent().ok_or(StoreError::Unsafe)?)?;
        initialization_boundary("registry_dir");
        let _lock = initialization_lock(&registry)?;
        // Bind pending intent before creating either database (or the store
        // directory). A marker-less directory is recoverable only with no prior
        // authority data; SQLite files without proof are never adopted.
        let parent = dir.parent().ok_or(StoreError::Unsafe)?;
        let expected =
            PathBuf::from(canonical(parent)?).join(dir.file_name().ok_or(StoreError::Unsafe)?);
        if expected != dir || !dir.is_absolute() {
            return Err(StoreError::Unsafe);
        }
        let marker = registry.join("initialization.json");
        let mut record: Initialization = match fs::symlink_metadata(&marker) {
            Ok(_) => {
                check_file(&marker)?;
                serde_json::from_slice(&fs::read(&marker)?).map_err(|_| StoreError::Unsafe)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                for entry in fs::read_dir(&registry)? {
                    let name = entry?.file_name();
                    if name != "initialization.lock" && name != "initialization.tmp" {
                        return Err(StoreError::Unsafe);
                    }
                }
                for suffix in ["", "-wal", "-shm", "-journal"] {
                    match fs::symlink_metadata(dir.join(format!("store.sqlite{suffix}"))) {
                        Ok(_) => return Err(StoreError::Unsafe),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                        Err(e) => return Err(e.into()),
                    }
                }
                let record = Initialization {
                    version: 1,
                    store: expected.clone(),
                    initialized: false,
                };
                persist_initialization(&registry, &record)?;
                record
            }
            Err(e) => return Err(e.into()),
        };
        if record.version != 1 || record.store != expected {
            return Err(StoreError::Unsafe);
        }
        let pending = !record.initialized;
        initialization_boundary("pending");
        let dir = private_dir(dir)?;
        sync_dir(parent)?;
        initialization_boundary("store_dir");
        let mut reg = database(&registry, "authorities.sqlite", pending)?;
        initialization_boundary("registry_db");
        let reg_budget = SqlBudget::install(&reg)?;
        let reg_phase = reg_budget.enter();
        let version: i64 = reg.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if !matches!(version, 0 | 1) {
            return Err(StoreError::Unsafe);
        }
        let tx = reg.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if version == 0 {
            tx.execute_batch("CREATE TABLE authorities(root TEXT PRIMARY KEY, store TEXT NOT NULL); PRAGMA user_version=1;")?;
        }
        initialization_boundary("registry_schema");
        let claims: Vec<(String, String)> = {
            let mut s = tx.prepare("SELECT root,store FROM authorities")?;
            let rows = s
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<std::result::Result<_, _>>()?;
            rows
        };
        for (root, owner) in &claims {
            if owner != dir.to_str().ok_or(StoreError::Invalid)?
                || !managed.contains(&PathBuf::from(root))
            {
                return Err(StoreError::Unsafe);
            }
        }
        for root in &managed {
            tx.execute(
                "INSERT OR IGNORE INTO authorities VALUES (?1,?2)",
                (root.to_str(), dir.to_str()),
            )?;
        }
        tx.commit()?;
        drop(reg_phase);
        initialization_boundary("claims");
        let mut conn = database(&dir, "store.sqlite", pending)?;
        initialization_boundary("store_db");
        // Bound mutable validation/migration before taking the SQLite writer
        // lock. The same Store-owned callback remains installed on return.
        let budget = SqlBudget::install(&conn)?;
        let phase = budget.enter();
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if !matches!(version, 0..=12) {
            return Err(StoreError::Unsafe);
        }
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if version == 0 {
            tx.execute_batch("CREATE TABLE checkouts(
    id TEXT PRIMARY KEY, operation TEXT NOT NULL UNIQUE, digest BLOB NOT NULL,
    repository TEXT NOT NULL, actor TEXT NOT NULL, task TEXT NOT NULL,
    owner TEXT NOT NULL CHECK(length(owner)>0), state TEXT NOT NULL DEFAULT 'reserved'
    CHECK(state IN ('reserved','partial','active','expired','interrupted','held','quarantined','partially_deleted','retired')));
   CREATE TABLE writers(checkout TEXT PRIMARY KEY REFERENCES checkouts(id), group_id TEXT NOT NULL UNIQUE);
   CREATE TABLE retired_owners(owner TEXT PRIMARY KEY);
   CREATE TABLE outbox(sequence INTEGER PRIMARY KEY AUTOINCREMENT, version INTEGER NOT NULL CHECK(version=1), payload TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(acknowledged IN (0,1)));
   PRAGMA user_version=1;")?;
        }
        if version < 2 {
            // Preserve every earlier charge; old reservations have no readiness proof.
            tx.execute_batch("ALTER TABLE checkouts ADD COLUMN ready INTEGER NOT NULL DEFAULT 0 CHECK(ready IN (0,1));
                CREATE TABLE allocations(checkout TEXT PRIMARY KEY REFERENCES checkouts(id), request TEXT NOT NULL, record TEXT NOT NULL);
                PRAGMA user_version=2;")?;
        }
        if version < 3 {
            tx.execute_batch("CREATE TABLE repository_aliases(alias TEXT PRIMARY KEY, common TEXT NOT NULL); PRAGMA user_version=3;")?;
        }
        if version < 4 {
            tx.execute_batch("CREATE TABLE run_groups(
                id TEXT PRIMARY KEY, checkout TEXT NOT NULL REFERENCES checkouts(id),
                mode TEXT NOT NULL CHECK(mode='supervised'), revision INTEGER NOT NULL CHECK(revision>=1),
                recovery_hold INTEGER NOT NULL DEFAULT 0 CHECK(recovery_hold IN (0,1)));")?;
            initialization_boundary("run_schema");
            tx.execute_batch(
                "CREATE TABLE runs(
                id TEXT PRIMARY KEY, group_id TEXT NOT NULL UNIQUE REFERENCES run_groups(id),
                run_ref TEXT NOT NULL UNIQUE, request TEXT NOT NULL,
                stage TEXT NOT NULL CHECK(stage IN ('intent','bound','permit_attempt')),
                binding TEXT, outcome TEXT);
                PRAGMA user_version=4;",
            )?;
        }
        if version < 5 {
            validate_run_schema(&tx)?;
            tx.execute_batch("ALTER TABLE run_groups ADD COLUMN closed INTEGER NOT NULL DEFAULT 0 CHECK(closed IN (0,1)); PRAGMA user_version=5;")?;
        }
        if version < 6 {
            validate_existing_schema(&tx, 5)?;
            tx.execute_batch("CREATE TABLE adopted_groups(
                id TEXT PRIMARY KEY, checkout TEXT NOT NULL REFERENCES checkouts(id),
                run_id TEXT NOT NULL UNIQUE, run_ref TEXT NOT NULL UNIQUE,
                operation TEXT NOT NULL UNIQUE, request TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision>=1), reconcile INTEGER NOT NULL DEFAULT 0 CHECK(reconcile IN (0,1)));
                CREATE TABLE adopted_sessions(
                group_id TEXT NOT NULL REFERENCES adopted_groups(id), source TEXT NOT NULL,
                session TEXT NOT NULL, agent TEXT NOT NULL, actor TEXT,
                parent TEXT, closed INTEGER NOT NULL CHECK(closed IN (0,1)),
                heartbeat INTEGER, depth INTEGER NOT NULL CHECK(depth BETWEEN 0 AND 16),
                PRIMARY KEY(group_id,source,session,agent));
                CREATE TABLE adopted_segments(
                group_id TEXT NOT NULL REFERENCES adopted_groups(id), source TEXT NOT NULL,
                session TEXT NOT NULL, agent TEXT NOT NULL, prompt TEXT NOT NULL,
                tool TEXT NOT NULL, kind TEXT NOT NULL, event_ref TEXT NOT NULL, body TEXT NOT NULL,
                FOREIGN KEY(group_id,source,session,agent) REFERENCES adopted_sessions(group_id,source,session,agent),
                PRIMARY KEY(group_id,source,session,agent,prompt,tool,kind,event_ref));
                PRAGMA user_version=6;")?;
        }
        if version < 7 {
            validate_existing_schema(&tx, 6)?;
            tx.execute_batch("ALTER TABLE run_groups ADD COLUMN child_count INTEGER NOT NULL DEFAULT 0 CHECK(child_count BETWEEN 0 AND 256);
                CREATE TABLE run_participants(
                id TEXT PRIMARY KEY, group_id TEXT NOT NULL REFERENCES run_groups(id),
                run_ref TEXT NOT NULL UNIQUE, parent_run TEXT NOT NULL, request TEXT NOT NULL,
                enrollment TEXT NOT NULL CHECK(enrollment IN ('pending','unverified')),
                outcome TEXT, depth INTEGER NOT NULL CHECK(depth BETWEEN 1 AND 16));
                PRAGMA user_version=7;")?;
            initialization_boundary("participant_schema");
        }
        if version < 8 {
            validate_existing_schema(&tx, 7)?;
            crate::run_participants::validate_v7_schema(&tx)?;
            tx.execute_batch("ALTER TABLE run_participants RENAME TO run_participants_v7;
                CREATE TABLE run_participants(
                id TEXT PRIMARY KEY, group_id TEXT NOT NULL REFERENCES run_groups(id),
                run_ref TEXT NOT NULL UNIQUE, parent_run TEXT NOT NULL, request TEXT NOT NULL,
                enrollment TEXT NOT NULL CHECK(enrollment IN ('pending','contained','unverified')),
                outcome TEXT, depth INTEGER NOT NULL CHECK(depth BETWEEN 1 AND 16), host TEXT,
                CHECK((enrollment='pending' AND host IS NULL) OR (enrollment='contained' AND host IS NOT NULL) OR enrollment='unverified'));
                INSERT INTO run_participants(id,group_id,run_ref,parent_run,request,enrollment,outcome,depth)
                    SELECT id,group_id,run_ref,parent_run,request,enrollment,outcome,depth FROM run_participants_v7 ORDER BY rowid;
                DROP TABLE run_participants_v7;
                PRAGMA user_version=8;")?;
            initialization_boundary("enrollment_schema");
        }
        if version < 9 {
            validate_existing_schema(&tx, 8)?;
            tx.execute_batch(crate::finish::SCHEMA)?;
            initialization_boundary("finish_schema");
        }
        if version < 10 {
            validate_existing_schema(&tx, 9)?;
            tx.execute_batch(crate::capture_journal::SCHEMA)?;
        }
        if version < 11 {
            validate_existing_schema(&tx, 10)?;
            tx.execute_batch(crate::capture_requirement::SCHEMA)?;
        }
        if version < 12 {
            validate_existing_schema(&tx, 11)?;
            tx.execute_batch(crate::capture_finalization::SCHEMA)?;
        }
        validate_existing_schema(&tx, 12)?;
        if version < 8 {
            crate::run_journal::validate_enrollment_rosters(&tx)?;
        }
        tx.prepare("SELECT alias,common FROM repository_aliases LIMIT 0")?;
        tx.prepare("SELECT ready FROM checkouts LIMIT 0")?;
        tx.prepare("SELECT checkout,request,record FROM allocations LIMIT 0")?;
        // Never repair a versioned schema by manufacturing empty accounting.
        tx.prepare(
            "SELECT id,operation,digest,repository,actor,task,owner,state FROM checkouts LIMIT 0",
        )?;
        tx.prepare("SELECT checkout,group_id FROM writers LIMIT 0")?;
        tx.prepare("SELECT owner FROM retired_owners LIMIT 0")?;
        tx.prepare("SELECT sequence,version,payload,acknowledged FROM outbox LIMIT 0")?;
        tx.commit()?;
        drop(phase);
        initialization_boundary("store_schema");
        // FULL SQLite commits make schema and claims durable, including their
        // WAL records. Sync directory entries before publishing initialized.
        sync_dir(&dir)?;
        sync_dir(&registry)?;
        if pending {
            record.initialized = true;
            persist_initialization(&registry, &record)?;
        }
        initialization_boundary("initialized");
        Ok(Self { conn, budget })
    }
    pub fn charged(&self, repository: &Path, owner: Option<&str>) -> Result<u64> {
        let repo = canonical(repository)?;
        let _phase = self.sql_phase();
        count(&self.conn, &repo, owner)
    }
    pub fn find_reusable(&self, actor: &str, repository: &Path, task: &str) -> Result<Vec<Uuid>> {
        let repo = canonical(repository)?;
        let _phase = self.sql_phase();
        let mut stmt = self.conn.prepare("SELECT id FROM checkouts c WHERE actor=?1 AND COALESCE((SELECT common FROM repository_aliases WHERE alias=c.repository),c.repository)=COALESCE((SELECT common FROM repository_aliases WHERE alias=?2),?2) AND task=?3 AND state!='retired' ORDER BY rowid")?;
        let ids = stmt
            .query_map((actor, repo, task), |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ids.iter()
            .map(|v| Uuid::parse_str(v).map_err(|_| StoreError::Invalid))
            .collect()
    }
    pub fn acquire_writer(&mut self, checkout: Uuid, group: Uuid) -> Result<()> {
        if group.get_version_num() != 7 || group.get_variant() != uuid::Variant::RFC4122 {
            return Err(StoreError::Invalid);
        }
        let _phase = self.sql_phase();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        acquire_writer_tx(&tx, checkout, group, true)?;
        tx.commit()?;
        Ok(())
    }
    pub fn pending_events(&self, limit: usize) -> Result<Vec<PendingEvent>> {
        let _phase = self.sql_phase();
        let mut stmt = self.conn.prepare(
            "SELECT sequence,payload FROM outbox WHERE acknowledged=0 ORDER BY sequence LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit.min(1000) as i64], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (sequence, payload) = row?;
            let event = serde_json::from_str(&payload).map_err(|_| StoreError::Invalid)?;
            Ok(PendingEvent { sequence, event })
        })
        .collect()
    }
    pub fn acknowledge(&mut self, sequence: i64) -> Result<()> {
        let _phase = self.sql_phase();
        self.conn.execute(
            "UPDATE outbox SET acknowledged=1 WHERE sequence=?1",
            [sequence],
        )?;
        Ok(())
    }
}
/// Aggregated accounting only; current schema does not bind records to FS paths.
#[derive(Debug, serde::Serialize)]
pub struct Charge {
    pub owner: String,
    pub state: String,
    pub count: u64,
    pub charged: u64,
}

// Technical report-only budgets, never lifecycle admission policy. Exhaustion
// rejects all accounting; a prefix must not masquerade as a complete report.
const REPORT_DATABASE_BYTES: u64 = 16 * 1024 * 1024;
const REPORT_CLAIMS: usize = 1024;
const REPORT_GROUPS: usize = 256;
const REPORT_ROWS: i64 = 4096;
const REPORT_OUTPUT_BYTES: usize = 256 * 1024;

fn existing_directory(dir: &Path) -> Result<()> {
    crate::config::validate_path(dir, true).map_err(|_| StoreError::Unsafe)?;
    let m = fs::symlink_metadata(dir)?;
    if m.mode() & 0o077 != 0 || m.uid() != rustix::process::geteuid().as_raw() {
        return Err(StoreError::Unsafe);
    }
    Ok(())
}
fn existing_database(dir: &Path, name: &str) -> Result<(Connection, SqlBudget)> {
    existing_directory(dir)?;
    let path = dir.join(name);
    check_file(&path)?;
    let mut bytes = fs::symlink_metadata(&path)?.len();
    if bytes > REPORT_DATABASE_BYTES {
        return Err(StoreError::Unsafe);
    }
    // SQLite WAL readers may create sidecars even with READONLY on the DB.
    // Require both pre-existing sidecars before opening a WAL database. Never
    // use immutable=1: that would silently ignore committed active WAL records.
    use std::io::Read;
    let mut header = [0u8; 100];
    fs::File::open(&path)?.read_exact(&mut header)?;
    if &header[..16] != b"SQLite format 3\0" {
        return Err(StoreError::Unsafe);
    }
    match fs::symlink_metadata(dir.join(format!("{name}-journal"))) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err(StoreError::Unsafe),
    }
    for suffix in ["-wal", "-shm"] {
        let side = dir.join(format!("{name}{suffix}"));
        match fs::symlink_metadata(&side) {
            Ok(m) => {
                check_file(&side)?;
                bytes = bytes.checked_add(m.len()).ok_or(StoreError::Unsafe)?;
                if bytes > REPORT_DATABASE_BYTES {
                    return Err(StoreError::Unsafe);
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && header[18] != 2
                    && header[19] != 2 => {}
            _ => return Err(StoreError::Unsafe),
        }
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    conn.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        true,
    )?;
    conn.busy_timeout(Duration::from_millis(500))?;
    let budget = SqlBudget::install(&conn)?;
    let _phase = budget.enter();
    query_protections(&conn)?;
    conn.execute_batch("PRAGMA query_only=ON;")?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let integrity: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    if !(version == 1 || (name == "store.sqlite" && matches!(version, 2..=12))) || integrity != "ok"
    {
        return Err(StoreError::Unsafe);
    }
    Ok((conn, budget))
}

// The installed callback is inert outside a SQL operation. Guards own cloned
// state, not a Connection borrow, so IMMEDIATE transactions remain available.
// Nested phases share the outer deadline and instruction allowance.
#[derive(Clone, Default)]
struct SqlBudget(Arc<Mutex<BudgetState>>);
#[derive(Default)]
struct BudgetState {
    depth: usize,
    deadline: Option<Instant>,
    ticks: u32,
}
pub(crate) struct SqlPhase(SqlBudget);
impl SqlBudget {
    fn install(conn: &Connection) -> Result<Self> {
        let budget = Self::default();
        let callback = budget.clone();
        conn.progress_handler(
            1000,
            Some(move || {
                let mut state = callback.0.lock().unwrap_or_else(|e| e.into_inner());
                if state.depth == 0 {
                    return false;
                }
                state.ticks = state.ticks.saturating_add(1);
                state.ticks >= 200 || state.deadline.is_some_and(|d| Instant::now() >= d)
            }),
        )?;
        Ok(budget)
    }
    fn enter(&self) -> SqlPhase {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.depth == 0 {
            state.deadline = Some(Instant::now() + Duration::from_millis(500));
            state.ticks = 0;
        }
        state.depth += 1;
        SqlPhase(self.clone())
    }
}
impl Drop for SqlPhase {
    fn drop(&mut self) {
        let mut state = self.0 .0.lock().unwrap_or_else(|e| e.into_inner());
        state.depth -= 1;
        if state.depth == 0 {
            state.deadline = None;
            state.ticks = 0;
        }
    }
}
fn query_protections(conn: &Connection) -> Result<()> {
    // Composite SQLite rows must accommodate the full legal UTF-8/JSON domain,
    // not just short CLI examples. The file budget already bounds total input.
    conn.set_limit(
        rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
        REPORT_DATABASE_BYTES as i32,
    )?;
    conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_SQL_LENGTH, 65536)?;
    conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_COLUMN, 64)?;
    conn.execute_batch("PRAGMA temp_store=MEMORY; PRAGMA cache_size=-1024; PRAGMA mmap_size=0;")?;
    Ok(())
}

/// Shared existing-authority validation, never bootstrap/migration/repair.
/// Read-only callers cannot create even WAL bookkeeping; recovery may open
/// existing files read-write only after initialized intent/claims validation.
fn existing_authority(
    registry: &Path,
    dir: &Path,
    managed: &[PathBuf],
    writable: bool,
) -> Result<(Connection, SqlBudget, usize)> {
    existing_directory(registry)?;
    existing_directory(dir)?;
    let marker = registry.join("initialization.json");
    check_file(&marker)?;
    if fs::metadata(&marker)?.len() > 8192 {
        return Err(StoreError::Unsafe);
    }
    let record: Initialization =
        serde_json::from_slice(&fs::read(marker)?).map_err(|_| StoreError::Unsafe)?;
    if record.version != 1 || !record.initialized || record.store != dir {
        return Err(StoreError::Unsafe);
    }
    let (reg, reg_budget) = existing_database(registry, "authorities.sqlite")?;
    let _reg_phase = reg_budget.enter();
    let mut stmt = reg.prepare("SELECT root,store FROM authorities LIMIT 1025")?;
    let mut rows = stmt.query([])?;
    let mut claims = Vec::new();
    let mut output_bytes = 0usize;
    while let Some(row) = rows.next()? {
        if claims.len() >= REPORT_CLAIMS {
            return Err(StoreError::Unsafe);
        }
        let root: String = row.get(0)?;
        let store: String = row.get(1)?;
        output_bytes += root.len() + store.len();
        if output_bytes > REPORT_OUTPUT_BYTES {
            return Err(StoreError::Unsafe);
        }
        claims.push((root, store));
    }
    if claims.len() != managed.len()
        || claims
            .iter()
            .any(|(root, store)| Path::new(store) != dir || !managed.contains(&PathBuf::from(root)))
    {
        return Err(StoreError::Unsafe);
    }
    let (conn, budget) = existing_database(dir, "store.sqlite")?;
    let _phase = budget.enter();
    conn.execute_batch("BEGIN;")?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if writable && version != 12 {
        return Err(StoreError::UpgradeRequired);
    }
    validate_existing_schema(&conn, version)?;
    if writable {
        let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        if mode != "wal" {
            return Err(StoreError::Unsafe);
        }
        // Complete the bounded read-only preflight before any mutable open.
        // In particular, do not switch a rejected DELETE-mode DB into WAL.
        drop(rows);
        drop(stmt);
        drop(reg);
        drop(conn);
        let writer = database(dir, "store.sqlite", false)?;
        let writer_budget = SqlBudget::install(&writer)?;
        let _writer_phase = writer_budget.enter();
        query_protections(&writer)?;
        Ok((writer, writer_budget, output_bytes))
    } else {
        Ok((conn, budget, output_bytes))
    }
}
fn validate_existing_schema(conn: &Connection, version: i64) -> Result<()> {
    if version >= 12 {
        crate::capture_finalization::validate_schema(conn)?;
    }
    if version >= 11 {
        crate::capture_requirement::validate_schema(conn)?;
    }
    if version >= 10 {
        crate::capture_journal::validate_schema(conn)?;
    }
    if version >= 9 {
        crate::finish::validate_schema(conn)?;
    }
    if version >= 8 {
        crate::run_participants::validate_schema(conn)?;
    }
    if version >= 7 {
        let table: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='run_participants' AND type='table')", [], |r| r.get(0))?;
        if !table {
            return Err(StoreError::Invalid);
        }
        conn.prepare("SELECT child_count FROM run_groups LIMIT 0")?;
        conn.prepare("SELECT id,group_id,run_ref,parent_run,request,enrollment,outcome,depth FROM run_participants LIMIT 0")?;
        let orphan: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM run_participants p LEFT JOIN run_groups g ON g.id=p.group_id LEFT JOIN runs r ON r.group_id=p.group_id WHERE g.id IS NULL OR r.id IS NULL OR g.mode!='supervised')", [], |r| r.get(0))?;
        if orphan {
            return Err(StoreError::Invalid);
        }
    }
    if version >= 6 {
        for name in ["adopted_groups", "adopted_sessions", "adopted_segments"] {
            let table: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name=?1 AND type='table')",
                [name],
                |r| r.get(0),
            )?;
            if !table {
                return Err(StoreError::Unsafe);
            }
        }
        conn.prepare("SELECT id,checkout,run_id,run_ref,operation,request,revision,reconcile FROM adopted_groups LIMIT 0")?;
        conn.prepare("SELECT group_id,source,session,agent,actor,parent,closed,heartbeat,depth FROM adopted_sessions LIMIT 0")?;
        conn.prepare("SELECT group_id,source,session,agent,prompt,tool,kind,event_ref,body FROM adopted_segments LIMIT 0")?;
    }
    if version >= 2 {
        conn.prepare("SELECT ready FROM checkouts LIMIT 0")?;
        conn.prepare("SELECT checkout,request,record FROM allocations LIMIT 0")?;
    }
    if version >= 3 {
        conn.prepare("SELECT alias,common FROM repository_aliases LIMIT 0")?;
    }
    if version >= 4 {
        validate_run_schema(conn)?;
    }
    conn.prepare(
        "SELECT id,operation,digest,repository,actor,task,owner,state FROM checkouts LIMIT 0",
    )?;
    conn.prepare("SELECT checkout,group_id FROM writers LIMIT 0")?;
    conn.prepare("SELECT owner FROM retired_owners LIMIT 0")?;
    conn.prepare("SELECT sequence,version,payload,acknowledged FROM outbox LIMIT 0")?;
    Ok(())
}
/// Strict bounded accounting report using the same existing authority reader.
pub fn report_existing(registry: &Path, dir: &Path, managed: &[PathBuf]) -> Result<Vec<Charge>> {
    let (conn, budget, mut output_bytes) = existing_authority(registry, dir, managed, false)?;
    let _phase = budget.enter();
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    validate_existing_schema(&conn, version)?;
    // Bound aggregate input before SQLite allocates its in-memory sorter.
    let rows: i64 = conn.query_row(
        "SELECT count(*) FROM (SELECT 1 FROM checkouts LIMIT 4097)",
        [],
        |r| r.get(0),
    )?;
    if rows > REPORT_ROWS {
        return Err(StoreError::Unsafe);
    }
    let mut stmt = conn.prepare(
        "SELECT owner,state,count(*) FROM checkouts GROUP BY owner,state ORDER BY owner,state LIMIT 257",
    )?;
    let charges = stmt
        .query_map([], |r| {
            let state: String = r.get(1)?;
            let count = u64::from(r.get::<_, u32>(2)?);
            Ok(Charge {
                owner: r.get(0)?,
                charged: if state == "retired" { 0 } else { count },
                state,
                count,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if charges.len() > REPORT_GROUPS {
        return Err(StoreError::Unsafe);
    }
    for charge in &charges {
        output_bytes += charge.owner.len() + charge.state.len();
        if output_bytes > REPORT_OUTPUT_BYTES {
            return Err(StoreError::Unsafe);
        }
        identity(&charge.owner)?;
        if !matches!(
            charge.state.as_str(),
            "reserved"
                | "partial"
                | "active"
                | "expired"
                | "interrupted"
                | "held"
                | "quarantined"
                | "partially_deleted"
                | "retired"
        ) {
            return Err(StoreError::Invalid);
        }
    }
    Ok(charges)
}

/// Caller owns the IMMEDIATE transaction. Journal identities stay reserved
/// across terminal outcomes and closure, including before exact retry acks.
pub(crate) fn exclude_journal_identity(conn: &Connection, id: Uuid) -> Result<()> {
    crate::capture_journal::exclude_operation(conn, &id)?;
    let reserved: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM runs WHERE id=?1 OR group_id=?1)
            OR EXISTS(SELECT 1 FROM run_groups WHERE id=?1)
            OR EXISTS(SELECT 1 FROM adopted_groups WHERE id=?1 OR run_id=?1 OR operation=?1)
            OR EXISTS(SELECT 1 FROM run_participants WHERE id=?1)
            OR EXISTS(SELECT 1 FROM task_finishes WHERE operation=?1)",
        [id.to_string()],
        |r| r.get(0),
    )?;
    if reserved {
        Err(StoreError::Conflict)
    } else {
        Ok(())
    }
}

/// Caller owns the IMMEDIATE transaction. A journal may never adopt an older
/// bare writer, even when its group identifier happens to match.
pub(crate) fn acquire_writer_tx(
    conn: &Connection,
    checkout: Uuid,
    group: Uuid,
    allow_existing: bool,
) -> Result<()> {
    acquire_writer_context(conn, checkout, group, allow_existing, None)
}
pub(crate) fn acquire_writer_context(
    conn: &Connection,
    checkout: Uuid,
    group: Uuid,
    allow_existing: bool,
    materialized: Option<&crate::capture_setup::MaterializationProof>,
) -> Result<()> {
    // New managed groups acquire before inserting their journal. Existing
    // managed requests retry through their journal API, never as bare writers.
    exclude_journal_identity(conn, group)?;
    if let Some(proof) = materialized {
        proof.validate_writer(conn, checkout, group)?;
    } else {
        if crate::capture_requirement::present(conn, checkout)?
            || crate::capture_journal::unresolved_checkout(conn, checkout)?
        {
            return Err(StoreError::Invalid);
        }
        let eligible: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 AND state='active' AND ready=1
             AND NOT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1))",
            [checkout.to_string()],
            |r| r.get(0),
        )?;
        if !eligible {
            return Err(StoreError::Invalid);
        }
    }
    let existing: Option<String> = conn
        .query_row(
            "SELECT group_id FROM writers WHERE checkout=?1",
            [checkout.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(g) = existing {
        return if allow_existing && g == group.to_string() {
            Ok(())
        } else {
            Err(StoreError::Writer)
        };
    }
    conn.execute(
        "INSERT INTO writers VALUES(?1,?2)",
        (checkout.to_string(), group.to_string()),
    )?;
    emit(conn, &Event::WriterAcquired { checkout, group })
}

fn validate_run_schema(conn: &Connection) -> Result<()> {
    for name in ["runs", "run_groups"] {
        let table: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name=?1 AND type='table')",
            [name],
            |r| r.get(0),
        )?;
        if !table {
            return Err(StoreError::Unsafe);
        }
    }
    conn.prepare("SELECT id,checkout,mode,revision,recovery_hold FROM run_groups LIMIT 0")?;
    conn.prepare("SELECT id,group_id,run_ref,request,stage,binding,outcome FROM runs LIMIT 0")?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version >= 5 {
        conn.prepare("SELECT closed FROM run_groups LIMIT 0")?;
    }
    Ok(())
}

pub(crate) fn count(conn: &Connection, repo: &str, owner: Option<&str>) -> Result<u64> {
    let mapped: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM repository_aliases WHERE alias=?1 OR common=?1)",
        [repo],
        |r| r.get(0),
    )?;
    if mapped {
        let unresolved: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM checkouts c WHERE state!='retired' AND NOT EXISTS(SELECT 1 FROM repository_aliases a WHERE a.alias=c.repository OR a.common=c.repository))", [], |r| r.get(0))?;
        if unresolved {
            return Err(StoreError::Unsafe);
        }
    }
    let n: i64 = conn.query_row("SELECT count(*) FROM checkouts c WHERE COALESCE((SELECT common FROM repository_aliases WHERE alias=c.repository),c.repository)=COALESCE((SELECT common FROM repository_aliases WHERE alias=?1),?1) AND state!='retired' AND (?2 IS NULL OR owner=?2)", (repo,owner), |r| r.get(0))?;
    u64::try_from(n).map_err(|_| StoreError::Invalid)
}
pub(crate) fn emit(conn: &Connection, event: &Event) -> Result<()> {
    let payload = serde_json::to_string(event).map_err(|_| StoreError::Invalid)?;
    conn.execute(
        "INSERT INTO outbox(version,payload) VALUES(1,?1)",
        [payload],
    )?;
    Ok(())
}
pub(crate) fn identity(value: &str) -> Result<()> {
    if value.trim().is_empty() || value != value.trim() || value.len() > 1024 {
        Err(StoreError::Invalid)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    const SCAN: &str = "WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<5000) SELECT sum(x) FROM n";

    #[test]
    fn nested_sql_phases_share_instruction_budget_and_disarm_on_unwind() {
        fn assert_send<T: Send>() {}
        assert_send::<super::Store>();
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let budget = super::SqlBudget::install(&conn).unwrap();
        let scan = || conn.query_row(SCAN, [], |r| r.get::<_, i64>(0));
        let outer = budget.enter();
        scan().unwrap();
        let inner = budget.enter();
        scan().unwrap();
        drop(inner);
        assert!(
            matches!(scan(), Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::OperationInterrupted)
        );
        drop(outer);
        scan().unwrap();
        // An error/early return or panic cannot strand an active phase.
        let fail = || -> super::Result<()> {
            let _phase = budget.enter();
            Err(super::StoreError::Invalid)
        };
        assert!(fail().is_err());
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _phase = budget.enter();
            panic!("fixture unwind");
        }));
        assert_eq!(budget.0.lock().unwrap().depth, 0);
        assert!(budget.0.lock().unwrap().deadline.is_none());
        let _fresh = budget.enter();
        scan().unwrap();
    }

    #[test]
    fn nested_sql_phases_cannot_reset_deadline_or_disarm_outer_phase() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let budget = super::SqlBudget::install(&conn).unwrap();
        let outer = budget.enter();
        std::thread::sleep(std::time::Duration::from_millis(650));
        let inner = budget.enter();
        for phase in [inner, outer] {
            assert!(matches!(conn.query_row(SCAN, [], |r| r.get::<_, i64>(0)),
                Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::OperationInterrupted));
            drop(phase);
        }
        // Outside a phase even a query exceeding the instruction cap is inert.
        conn.query_row(&SCAN.replace("5000", "20000"), [], |r| r.get::<_, i64>(0))
            .unwrap();
    }

    #[test]
    fn mutable_open_budget_exhaustion_rolls_back_migration() {
        for version in [8, 9, 10] {
            let children = if version == 10 { 9000 } else { 6000 };
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            std::fs::create_dir(&root).unwrap();
            let dir = temp.path().join("private");
            let store = super::Store::open(&dir, std::slice::from_ref(&root)).unwrap();
            // Adversarial but relationally consistent input: schema validation must
            // bound its orphan scan even before it can return a Store. No test-only
            // production selector or altered budget is involved.
            store
                .conn
                .execute_batch("DROP TABLE capture_finalizations; DROP TABLE capture_requirements;")
                .unwrap();
            if version < 10 {
                store
                    .conn
                    .execute_batch("DROP TABLE capture_runs;")
                    .unwrap();
            }
            if version == 8 {
                store
                    .conn
                    .execute_batch("DROP TABLE task_finishes;")
                    .unwrap();
            }
            store.conn.execute_batch(&format!("PRAGMA user_version={version};
            INSERT INTO checkouts VALUES('checkout','allocation',x'00','repo','actor','task','owner','held',0);
            INSERT INTO run_groups VALUES('group','checkout','supervised',1,0,1,0);
            INSERT INTO runs VALUES('run','group','ref','{{}}','intent',NULL,NULL);
            WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<{children})
            INSERT INTO run_participants SELECT 'child'||x,'group','ref'||x,'run','{{}}','pending',NULL,1,NULL FROM n;")).unwrap();
            // One pre-migration scan fits; cumulative validation around the v9
            // DDL must exhaust the allowance, rolling that DDL back as well.
            {
                let _phase = store.sql_phase();
                super::validate_existing_schema(&store.conn, version).unwrap();
            }
            let before: Vec<(String, String)> = store
                .conn
                .prepare("SELECT name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name")
                .unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            drop(store);
            let result = super::Store::open(&dir, std::slice::from_ref(&root));
            assert!(
                matches!(result, Err(super::StoreError::Database(rusqlite::Error::SqliteFailure(e, _)))
            if e.code == rusqlite::ErrorCode::OperationInterrupted),
                "mutable pre-return validation must exhaust the real SQL budget"
            );
            let conn = rusqlite::Connection::open(dir.join("store.sqlite")).unwrap();
            assert_eq!(
                conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                version
            );
            let after: Vec<(String, String)> = conn
                .prepare("SELECT name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name")
                .unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert_eq!(before, after);
            assert_eq!(
                conn.query_row("SELECT count(*) FROM run_participants", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                children
            );
            assert_eq!(
                conn.query_row("SELECT state FROM checkouts", [], |r| r.get::<_, String>(0))
                    .unwrap(),
                "held"
            );
            // Removing the expensive private fixture history permits the same
            // authority to migrate, demonstrating rollback and released locks.
            conn.execute("DELETE FROM run_participants", []).unwrap();
            super::Store::open(&dir, std::slice::from_ref(&root)).unwrap();
        }
    }

    #[test]
    fn initialization_worker() {
        let Ok(base) = std::env::var("WORK_INIT_TEST_BASE") else {
            return;
        };
        let base = std::path::Path::new(&base);
        super::Store::open(&base.join("private"), &[base.join("root")]).unwrap();
    }

    #[test]
    fn subprocess_initialization_interruptions_resume() {
        for boundary in [
            "registry_dir",
            "pending_temp",
            "pending",
            "store_dir",
            "registry_db",
            "registry_schema",
            "claims",
            "store_db",
            "store_schema",
            "initialized_temp",
            "initialized",
        ] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir(dir.path().join("root")).unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "store::tests::initialization_worker"])
                .env("WORK_INIT_TEST_BASE", dir.path())
                .env("WORK_INIT_TEST_BOUNDARY", boundary)
                .current_dir(dir.path())
                .status()
                .unwrap();
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                status.signal(),
                Some(6),
                "child did not abort at {boundary}"
            );
            if boundary == "claims" {
                // A normal creation error after durable claims must not strand
                // retries either. No Store has escaped the pending protocol.
                let obstacle = dir.path().join("private/store.sqlite");
                std::fs::create_dir(&obstacle).unwrap();
                assert!(super::Store::open(
                    &dir.path().join("private"),
                    &[dir.path().join("root")]
                )
                .is_err());
                std::fs::remove_dir(obstacle).unwrap();
            }
            let store = super::Store::open(&dir.path().join("private"), &[dir.path().join("root")])
                .unwrap();
            assert_eq!(
                store.charged(&dir.path().join("root"), None).unwrap(),
                0,
                "{boundary}"
            );
        }
    }

    #[test]
    fn killed_v6_migration_rolls_back_child_and_enrollment_schema_without_touching_accounting() {
        for boundary in ["participant_schema", "enrollment_schema"] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("root");
            std::fs::create_dir(&root).unwrap();
            let mut store =
                super::Store::open(&dir.path().join("private"), std::slice::from_ref(&root))
                    .unwrap();
            store
                .reserve(
                    &crate::admission::Reservation {
                        operation: uuid::Uuid::now_v7(),
                        repository: root.clone(),
                        actor: "allocator".into(),
                        owner: "owner".into(),
                        task: "task".into(),
                    },
                    crate::admission::Limits {
                        repository: 2,
                        owner: 2,
                        available_bytes: Some(10),
                        floor_bytes: 0,
                        warn_bytes: 0,
                    },
                )
                .unwrap();
            let events = store.pending_events(100).unwrap();
            store.conn.execute_batch("DROP TABLE capture_finalizations; DROP TABLE capture_requirements; DROP TABLE capture_runs; DROP TABLE task_finishes; DROP TABLE run_participants; ALTER TABLE run_groups DROP COLUMN child_count; PRAGMA user_version=6;").unwrap();
            drop(store);
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "store::tests::initialization_worker"])
                .env("WORK_INIT_TEST_BASE", dir.path())
                .env("WORK_INIT_TEST_BOUNDARY", boundary)
                .current_dir(dir.path())
                .status()
                .unwrap();
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(6));
            let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
            assert_eq!(
                sql.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                6
            );
            assert_eq!(
                sql.query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name='run_participants'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                0
            );
            assert!(sql.prepare("SELECT child_count FROM run_groups").is_err());
            let store =
                super::Store::open(&dir.path().join("private"), std::slice::from_ref(&root))
                    .unwrap();
            assert_eq!(store.charged(&root, Some("owner")).unwrap(), 1);
            assert_eq!(store.pending_events(100).unwrap(), events);
        }
    }

    #[test]
    fn killed_v3_migration_rolls_back_partial_schema_and_preserves_accounting() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let mut store =
            super::Store::open(&dir.path().join("private"), std::slice::from_ref(&root)).unwrap();
        store
            .reserve(
                &crate::admission::Reservation {
                    operation: uuid::Uuid::now_v7(),
                    repository: root.clone(),
                    actor: "actor".into(),
                    owner: "owner".into(),
                    task: "task".into(),
                },
                crate::admission::Limits {
                    repository: 2,
                    owner: 2,
                    available_bytes: Some(10),
                    floor_bytes: 0,
                    warn_bytes: 0,
                },
            )
            .unwrap();
        let events = store.pending_events(100).unwrap();
        store
            .conn
            .execute_batch("DROP TABLE capture_finalizations; DROP TABLE capture_requirements; DROP TABLE capture_runs; DROP TABLE task_finishes; DROP TABLE run_participants; DROP TABLE adopted_segments; DROP TABLE adopted_sessions; DROP TABLE adopted_groups; DROP TABLE runs; DROP TABLE run_groups; PRAGMA user_version=3")
            .unwrap();
        drop(store);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "store::tests::initialization_worker"])
            .env("WORK_INIT_TEST_BASE", dir.path())
            .env("WORK_INIT_TEST_BOUNDARY", "run_schema")
            .current_dir(dir.path())
            .status()
            .unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(6));
        let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        assert_eq!(
            sql.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            3
        );
        assert_eq!(
            sql.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name IN ('runs','run_groups')",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        let store =
            super::Store::open(&dir.path().join("private"), std::slice::from_ref(&root)).unwrap();
        assert_eq!(store.charged(&root, Some("owner")).unwrap(), 1);
        assert_eq!(store.pending_events(100).unwrap(), events);
    }

    #[test]
    fn interrupted_v8_finish_migration_is_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let store =
            super::Store::open(&dir.path().join("private"), std::slice::from_ref(&root)).unwrap();
        store
            .conn
            .execute_batch(
                "DROP TABLE capture_finalizations; DROP TABLE capture_requirements; DROP TABLE capture_runs; DROP TABLE task_finishes; PRAGMA user_version=8",
            )
            .unwrap();
        drop(store);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "store::tests::initialization_worker"])
            .env("WORK_INIT_TEST_BASE", dir.path())
            .env("WORK_INIT_TEST_BOUNDARY", "finish_schema")
            .status()
            .unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(6));
        let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        assert_eq!(
            sql.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            8
        );
        assert_eq!(
            sql.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='task_finishes'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        super::Store::open(&dir.path().join("private"), &[root]).unwrap();
        assert_eq!(
            sql.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            12
        );
    }
    #[test]
    fn remote_and_unknown_filesystems_are_not_store_authorities() {
        for magic in [0x6969, 0xff534d42, 0x65735546, 0] {
            assert!(
                !super::local_filesystem(magic),
                "filesystem magic {magic:x}"
            );
        }
        for magic in [0xef53, 0x9123683e, 0x58465342, 0x01021994, 0x794c7630] {
            assert!(super::local_filesystem(magic));
        }
    }
}
