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
    time::Duration,
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
}
pub type Result<T> = std::result::Result<T, StoreError>;
pub struct Store {
    pub(crate) conn: Connection,
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
    conn.busy_timeout(Duration::from_millis(500))?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if !(version == 1
        || (name == "store.sqlite" && matches!(version, 2..=4))
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
        initialization_boundary("claims");
        let mut conn = database(&dir, "store.sqlite", pending)?;
        initialization_boundary("store_db");
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if !matches!(version, 0..=4) {
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
        validate_run_schema(&tx)?;
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
        Ok(Self { conn })
    }
    pub fn charged(&self, repository: &Path, owner: Option<&str>) -> Result<u64> {
        let repo = canonical(repository)?;
        count(&self.conn, &repo, owner)
    }
    pub fn find_reusable(&self, actor: &str, repository: &Path, task: &str) -> Result<Vec<Uuid>> {
        let repo = canonical(repository)?;
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
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        acquire_writer_tx(&tx, checkout, group, true)?;
        tx.commit()?;
        Ok(())
    }
    pub fn pending_events(&self, limit: usize) -> Result<Vec<PendingEvent>> {
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

fn existing_database(dir: &Path, name: &str) -> Result<Connection> {
    crate::config::validate_path(dir, true).map_err(|_| StoreError::Unsafe)?;
    let m = fs::symlink_metadata(dir)?;
    if m.mode() & 0o077 != 0 || m.uid() != rustix::process::geteuid().as_raw() {
        return Err(StoreError::Unsafe);
    }
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
    conn.busy_timeout(Duration::from_millis(500))?;
    // Cumulative VM/time budget includes schema inspection, integrity checks
    // and subsequent queries, even when untrusted schema contains views.
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    let mut ticks = 0u32;
    conn.progress_handler(
        1000,
        Some(move || {
            ticks += 1;
            ticks >= 200 || std::time::Instant::now() >= deadline
        }),
    )?;
    conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 8192)?;
    conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_SQL_LENGTH, 65536)?;
    conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_COLUMN, 64)?;
    // Aggregation/integrity queries must not spill SQLite temporary files.
    conn.execute_batch("PRAGMA query_only=ON; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-1024; PRAGMA mmap_size=0;")?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let integrity: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    if !(version == 1 || (name == "store.sqlite" && matches!(version, 2..=4))) || integrity != "ok"
    {
        return Err(StoreError::Unsafe);
    }
    Ok(conn)
}

/// Strict existing-evidence reader: no bootstrap, migration, locks created on
/// disk, writes, repair, event generation or acknowledgments. Existing WAL SHM
/// lock bookkeeping can change; this is not a byte-immutability guarantee.
pub fn report_existing(registry: &Path, dir: &Path, managed: &[PathBuf]) -> Result<Vec<Charge>> {
    crate::config::validate_path(registry, true).map_err(|_| StoreError::Unsafe)?;
    crate::config::validate_path(dir, true).map_err(|_| StoreError::Unsafe)?;
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
    let reg = existing_database(registry, "authorities.sqlite")?;
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
    let conn = existing_database(dir, "store.sqlite")?;
    conn.execute_batch("BEGIN;")?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version >= 2 {
        conn.prepare("SELECT ready FROM checkouts LIMIT 0")?;
        conn.prepare("SELECT checkout,request,record FROM allocations LIMIT 0")?;
    }
    if version >= 3 {
        conn.prepare("SELECT alias,common FROM repository_aliases LIMIT 0")?;
    }
    if version >= 4 {
        validate_run_schema(&conn)?;
    }
    conn.prepare(
        "SELECT id,operation,digest,repository,actor,task,owner,state FROM checkouts LIMIT 0",
    )?;
    conn.prepare("SELECT checkout,group_id FROM writers LIMIT 0")?;
    conn.prepare("SELECT owner FROM retired_owners LIMIT 0")?;
    conn.prepare("SELECT sequence,version,payload,acknowledged FROM outbox LIMIT 0")?;
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

/// Caller owns the IMMEDIATE transaction. A journal may never adopt an older
/// bare writer, even when its group identifier happens to match.
pub(crate) fn acquire_writer_tx(
    conn: &Connection,
    checkout: Uuid,
    group: Uuid,
    allow_existing: bool,
) -> Result<()> {
    let eligible: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 AND state='active' AND ready=1)",
        [checkout.to_string()],
        |r| r.get(0),
    )?;
    if !eligible {
        return Err(StoreError::Invalid);
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
            .execute_batch("DROP TABLE runs; DROP TABLE run_groups; PRAGMA user_version=3")
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
