//! Private local SQLite authority. Callers must select one trusted host-local
//! registry for all managed roots. This is cooperative configuration enforcement,
//! not discovery of arbitrary databases or protection from a malicious same UID.
use crate::events::{Event, PendingEvent};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{
    fs,
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
fn database(dir: &Path, name: &str) -> Result<Connection> {
    let path = dir.join(name);
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
    conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")?;
    let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
    if mode != "wal" {
        return Err(StoreError::Unsafe);
    }
    Ok(conn)
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
    /// Convenience for a registry colocated at the store's parent. Production
    /// callers spanning different parents MUST supply their common trusted registry.
    pub fn open(dir: &Path, managed: &[PathBuf]) -> Result<Self> {
        let parent = dir.parent().ok_or(StoreError::Unsafe)?;
        Self::open_registered(&parent.join(".work-authorities"), dir, managed)
    }
    /// Registry claims are deliberately never auto-released on database loss.
    /// Reconfiguration needs an audited operator migration; no second authority is
    /// silently substituted. The registry is an explicitly trusted host policy
    /// boundary, not a global scan. Keep this path fixed across all configurations.
    /// Only allowlisted Linux local filesystem types are accepted. Overlay backing
    /// storage durability/locality remains a host qualification obligation.
    pub fn open_registered(registry: &Path, dir: &Path, managed: &[PathBuf]) -> Result<Self> {
        let managed = roots(managed)?;
        let registry_existed = match fs::symlink_metadata(registry) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        let registry = private_dir(registry)?;
        if registry_existed {
            check_file(&registry.join("authorities.sqlite"))?;
        }
        let dir = private_dir(dir)?;
        // Filesystem evidence is read before taking the registry write lock.
        let store_exists = match fs::symlink_metadata(dir.join("store.sqlite")) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        let mut reg = database(&registry, "authorities.sqlite")?;
        let version: i64 = reg.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if !matches!(version, 0 | 1) {
            return Err(StoreError::Unsafe);
        }
        let tx = reg.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if version == 0 {
            tx.execute_batch("CREATE TABLE authorities(root TEXT PRIMARY KEY, store TEXT NOT NULL); PRAGMA user_version=1;")?;
        }
        let claims: Vec<(String, String)> = {
            let mut s = tx.prepare("SELECT root,store FROM authorities")?;
            let rows = s
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<std::result::Result<_, _>>()?;
            rows
        };
        for (root, owner) in &claims {
            if owner == dir.to_str().ok_or(StoreError::Invalid)? && !store_exists {
                return Err(StoreError::Unsafe);
            }
            if managed
                .iter()
                .any(|p| p.starts_with(root) || Path::new(root).starts_with(p))
                && owner != dir.to_str().ok_or(StoreError::Invalid)?
            {
                return Err(StoreError::Unsafe);
            }
            if owner == dir.to_str().ok_or(StoreError::Invalid)?
                && !managed.contains(&PathBuf::from(root))
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
        let mut conn = database(&dir, "store.sqlite")?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if !matches!(version, 0 | 1) {
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
        // Never repair a versioned schema by manufacturing empty accounting.
        tx.prepare(
            "SELECT id,operation,digest,repository,actor,task,owner,state FROM checkouts LIMIT 0",
        )?;
        tx.prepare("SELECT checkout,group_id FROM writers LIMIT 0")?;
        tx.prepare("SELECT owner FROM retired_owners LIMIT 0")?;
        tx.prepare("SELECT sequence,version,payload,acknowledged FROM outbox LIMIT 0")?;
        tx.commit()?;
        Ok(Self { conn })
    }
    pub fn charged(&self, repository: &Path, owner: Option<&str>) -> Result<u64> {
        let repo = canonical(repository)?;
        count(&self.conn, &repo, owner)
    }
    pub fn find_reusable(&self, actor: &str, repository: &Path, task: &str) -> Result<Vec<Uuid>> {
        let repo = canonical(repository)?;
        let mut stmt = self.conn.prepare("SELECT id FROM checkouts WHERE actor=?1 AND repository=?2 AND task=?3 AND state!='retired' ORDER BY rowid")?;
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
        let existing: Option<String> = tx
            .query_row(
                "SELECT group_id FROM writers WHERE checkout=?1",
                [checkout.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(g) = existing {
            return if g == group.to_string() {
                Ok(())
            } else {
                Err(StoreError::Writer)
            };
        }
        let live: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 AND state!='retired')",
            [checkout.to_string()],
            |r| r.get(0),
        )?;
        if !live {
            return Err(StoreError::Invalid);
        }
        tx.execute(
            "INSERT INTO writers VALUES(?1,?2)",
            (checkout.to_string(), group.to_string()),
        )?;
        emit(&tx, &Event::WriterAcquired { checkout, group })?;
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
pub(crate) fn count(conn: &Connection, repo: &str, owner: Option<&str>) -> Result<u64> {
    let n: i64 = conn.query_row("SELECT count(*) FROM checkouts WHERE repository=?1 AND state!='retired' AND (?2 IS NULL OR owner=?2)", (repo,owner), |r| r.get(0))?;
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
