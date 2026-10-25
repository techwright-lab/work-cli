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
    /// FINISH was attempted; no reliable confirmation was committed.
    #[error("capture FINISH may have occurred; confirmation unknown")]
    CaptureFinishUncertain,
    /// RETRY was attempted; the previously confirmed freeze is unchanged.
    #[error("capture delivery observation unknown; prior freeze retained")]
    CaptureDeliveryUncertain,
    #[error("historical run status unknown: schema upgrade required")]
    UpgradeRequired,
    #[error("retirement intent fences cooperative writes")]
    RetirementFenced,
    #[error("checkout operations in flight")]
    OperationsInFlight,
}
pub type Result<T> = std::result::Result<T, StoreError>;

/// Diagnostic provenance only at retirement open/abort admission. It grants no
/// role or permission and preserves the original error for StoreError callers.
#[derive(Debug)]
pub(crate) enum RetirementAdmissionError {
    Authority(StoreError),
    History(StoreError),
}
impl RetirementAdmissionError {
    // Call ONLY at the actual global-history validation phase. An Invalid from
    // binding or role admission must never be relabeled as history corruption.
    pub(crate) fn history(error: StoreError) -> Self {
        match error {
            StoreError::Invalid | StoreError::Conflict => Self::History(error),
            _ => Self::Authority(error),
        }
    }
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Authority(_) => "authority_unknown",
            Self::History(_) => "history_unknown",
        }
    }
    pub(crate) fn into_store_error(self) -> StoreError {
        match self {
            Self::Authority(error) | Self::History(error) => error,
        }
    }
}
impl From<StoreError> for RetirementAdmissionError {
    fn from(error: StoreError) -> Self {
        Self::Authority(error)
    }
}

pub struct Store {
    pub(crate) conn: Connection,
    budget: SqlBudget,
    authority: Arc<AuthorityIdentity>,
    schema: SchemaParticipation,
    access: StoreAccess,
    role: SchemaRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SupportedRetirementVersion {
    V16,
    V17,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SchemaRole {
    Current17,
    Legacy16Abort,
    HistoricalRead(SupportedRetirementVersion),
}
impl SchemaRole {
    pub(crate) fn version(self) -> i64 {
        match self {
            Self::Current17 | Self::HistoricalRead(SupportedRetirementVersion::V17) => 17,
            Self::Legacy16Abort | Self::HistoricalRead(SupportedRetirementVersion::V16) => 16,
        }
    }
    pub(crate) fn validate(self, conn: &Connection) -> Result<()> {
        let actual: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if actual != self.version() {
            return Err(StoreError::Invalid);
        }
        validate_existing_schema(conn, actual)?;
        if actual == 16 {
            let modern: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name IN ('quarantine_actions','quarantine_actions_checkout') OR tbl_name='quarantine_actions')", [], |r| r.get(0))?;
            if modern {
                return Err(StoreError::Invalid);
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum StoreAccess {
    ReadOnly,
    ReadWrite,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AuthorityIdentity {
    registry: PathBuf,
    pub(crate) directory: PathBuf,
    pub(crate) directory_id: (u64, u64),
    database_id: (u64, u64),
    pub(crate) lock_id: Option<(u64, u64)>,
}
impl AuthorityIdentity {
    /// Cached metadata only; never opens/stat's the authority under a lease.
    pub(crate) fn registry(&self) -> &Path {
        &self.registry
    }
    pub(crate) fn database_id(&self) -> (u64, u64) {
        self.database_id
    }
    fn collect(registry: &Path, directory: &Path, writable: bool) -> Result<Arc<Self>> {
        existing_directory(registry)?;
        existing_directory(directory)?;
        check_file(&directory.join("store.sqlite"))?;
        let dir = fs::symlink_metadata(directory)?;
        let db = fs::symlink_metadata(directory.join("store.sqlite"))?;
        let lock_id = if writable {
            let file = Self::open_lock(directory, false)?;
            let m = file.metadata()?;
            Some((m.dev(), m.ino()))
        } else {
            None
        };
        Ok(Arc::new(Self {
            registry: fs::canonicalize(registry)?,
            directory: fs::canonicalize(directory)?,
            directory_id: (dir.dev(), dir.ino()),
            database_id: (db.dev(), db.ino()),
            lock_id,
        }))
    }
    pub(crate) fn revalidate_migration(&self) -> Result<()> {
        existing_directory(&self.registry)?;
        existing_directory(&self.directory)?;
        check_file(&self.directory.join("store.sqlite"))?;
        let dir = fs::symlink_metadata(&self.directory)?;
        let db = fs::symlink_metadata(self.directory.join("store.sqlite"))?;
        if (dir.dev(), dir.ino()) != self.directory_id || (db.dev(), db.ino()) != self.database_id {
            return Err(StoreError::Unsafe);
        }
        Ok(())
    }
    pub(crate) fn open_lock(directory: &Path, create: bool) -> Result<fs::File> {
        let path = directory.join("allocation.lock");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .truncate(false)
            .mode(0o600)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(&path)?;
        check_file(&path)?;
        let descriptor = file.metadata()?;
        let named = fs::symlink_metadata(&path)?;
        if !descriptor.is_file()
            || descriptor.nlink() != 1
            || descriptor.uid() != rustix::process::geteuid().as_raw()
            || descriptor.mode() & 0o777 != 0o600
            || (descriptor.dev(), descriptor.ino()) != (named.dev(), named.ino())
        {
            return Err(StoreError::Unsafe);
        }
        Ok(file)
    }
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
fn database(dir: &Path, name: &str, pending: bool, initialize: bool) -> Result<Connection> {
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
        || (name == "store.sqlite" && matches!(version, 2..=17))
        || (pending && version == 0))
    {
        return Err(StoreError::Unsafe);
    }
    conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")?;
    let mode: String = conn.query_row(
        if initialize {
            "PRAGMA journal_mode=WAL"
        } else {
            "PRAGMA journal_mode"
        },
        [],
        |r| r.get(0),
    )?;
    if mode != "wal" {
        return Err(StoreError::Unsafe);
    }
    Ok(conn)
}
// One actual open-file description per independent schema participant. Runtime
// clones share ownership, not a path-based permission or a serialized proof.
#[derive(Clone)]
pub(crate) struct SchemaParticipation(Arc<SharedSchemaOwner>);
struct SharedSchemaOwner {
    file: fs::File,
    registry: PathBuf,
    registry_file: fs::File,
    marker: SchemaFile,
    marker_bytes: Vec<u8>,
    registration: SchemaFile,
    directory: PathBuf,
    directory_file: fs::File,
    directory_id: (u64, u64),
    database: SchemaFile,
    database_id: (u64, u64),
}
struct SchemaFile {
    path: PathBuf,
    file: fs::File,
}
impl SchemaFile {
    fn open(path: PathBuf) -> Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(&path)?;
        let binding = Self { path, file };
        binding.revalidate()?;
        Ok(binding)
    }
    fn revalidate(&self) -> Result<()> {
        checked_schema_file(&self.path, &self.file)
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        use std::io::Read;
        // Reopen independently: do not share a mutable seek offset with another
        // legitimate Arc owner. Compare this descriptor with the retained inode.
        let current = Self::open(self.path.clone())?;
        if file_id(&current.file)? != file_id(&self.file)? {
            return Err(StoreError::Unsafe);
        }
        let mut bytes = Vec::new();
        current.file.take(8193).read_to_end(&mut bytes)?;
        if bytes.len() > 8192 {
            return Err(StoreError::Unsafe);
        }
        Ok(bytes)
    }
}
fn file_id(file: &fs::File) -> Result<(u64, u64)> {
    let m = file.metadata()?;
    Ok((m.dev(), m.ino()))
}
fn checked_schema_file(path: &Path, file: &fs::File) -> Result<()> {
    check_file(path)?;
    let held = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !held.is_file()
        || held.nlink() != 1
        || held.uid() != rustix::process::geteuid().as_raw()
        || held.mode() & 0o7777 != 0o600
        || named.mode() & 0o7777 != 0o600
        || (held.dev(), held.ino()) != (named.dev(), named.ino())
    {
        return Err(StoreError::Unsafe);
    }
    Ok(())
}
fn schema_directory(path: &Path) -> Result<fs::File> {
    existing_directory(path)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            (rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK)
                .bits() as i32,
        )
        .open(path)?;
    revalidate_schema_directory(path, &file)?;
    Ok(file)
}
fn revalidate_schema_directory(path: &Path, file: &fs::File) -> Result<()> {
    existing_directory(path)?;
    let held = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !held.is_dir()
        || held.uid() != rustix::process::geteuid().as_raw()
        || held.mode() & 0o7777 != 0o700
        || named.mode() & 0o7777 != 0o700
        || (held.dev(), held.ino()) != (named.dev(), named.ino())
    {
        return Err(StoreError::Unsafe);
    }
    Ok(())
}
fn open_initialization_file(registry: &Path, create: bool) -> Result<fs::File> {
    let path = registry.join("initialization.lock");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(create)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(&path)?;
    checked_schema_file(&path, &file)?;
    Ok(file)
}
fn lock_initialization(file: &fs::File, exclusive: bool) -> Result<()> {
    let op = if exclusive {
        rustix::fs::FlockOperation::NonBlockingLockExclusive
    } else {
        rustix::fs::FlockOperation::NonBlockingLockShared
    };
    let start = Instant::now();
    loop {
        match rustix::fs::flock(file, op) {
            Ok(()) => return Ok(()),
            Err(rustix::io::Errno::WOULDBLOCK) if start.elapsed() < Duration::from_millis(500) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(std::io::Error::from(e).into()),
        }
    }
}
impl Drop for SharedSchemaOwner {
    fn drop(&mut self) {
        // End the last legitimate owner's participation even if a dup/fork FD
        // survives. Unlocking this OFD cannot unlock an independent SH owner.
        let _ = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}
impl SchemaParticipation {
    pub(crate) fn open_existing(registry: &Path) -> Result<Self> {
        let registry_file = schema_directory(registry)?;
        let file = open_initialization_file(registry, false)?;
        lock_initialization(&file, false)?;
        revalidate_schema_directory(registry, &registry_file)?;
        checked_schema_file(&registry.join("initialization.lock"), &file)?;
        let marker = SchemaFile::open(registry.join("initialization.json"))?;
        let marker_bytes = marker.bytes()?;
        let record: Initialization =
            serde_json::from_slice(&marker_bytes).map_err(|_| StoreError::Unsafe)?;
        if record.version != 1 || !record.store.is_absolute() {
            return Err(StoreError::Unsafe);
        }
        if !record.initialized {
            return Err(StoreError::UpgradeRequired);
        }
        let directory_file = schema_directory(&record.store)?;
        let database = SchemaFile::open(record.store.join("store.sqlite"))?;
        let registration = SchemaFile::open(registry.join("authorities.sqlite"))?;
        let owner = Self(Arc::new(SharedSchemaOwner {
            file,
            registry: registry.to_path_buf(),
            registry_file,
            marker,
            marker_bytes,
            registration,
            directory: record.store,
            directory_id: file_id(&directory_file)?,
            database_id: file_id(&database.file)?,
            directory_file,
            database,
        }));
        owner.revalidate()?;
        Ok(owner)
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        let owner = &self.0;
        #[cfg(test)]
        schema_participation_tests::observe_schema_fs(&owner.directory);
        revalidate_schema_directory(&owner.registry, &owner.registry_file)?;
        checked_schema_file(&owner.registry.join("initialization.lock"), &owner.file)?;
        owner.marker.revalidate()?;
        if owner.marker.bytes()? != owner.marker_bytes {
            return Err(StoreError::Unsafe);
        }
        owner.registration.revalidate()?;
        revalidate_schema_directory(&owner.directory, &owner.directory_file)?;
        owner.database.revalidate()
    }
    // Cached comparisons only: callers may use this inside bounded SQL. The
    // inode tuple is captured at acquisition, never filesystem work under SQL.
    pub(crate) fn matches_authority(&self, authority: &AuthorityIdentity) -> Result<()> {
        if self.0.registry != authority.registry
            || self.0.directory != authority.directory
            || self.0.directory_id != authority.directory_id
            || self.0.database_id != authority.database_id
        {
            return Err(StoreError::Unsafe);
        }
        Ok(())
    }
}
// Non-Clone facade; migration children retain this actual EX, never acquire SH.
pub(crate) struct ExclusiveInitialization(Arc<ExclusiveInitializationOwner>);
pub(crate) struct ExclusiveInitializationOwner {
    file: fs::File,
    registry: PathBuf,
    directory: fs::File,
}
pub(crate) enum InitializationRetention {
    Shared(SchemaParticipation),
    Migration(Arc<ExclusiveInitializationOwner>),
}
impl InitializationRetention {
    pub(crate) fn revalidate(&self) -> Result<()> {
        match self {
            Self::Shared(owner) => owner.revalidate(),
            Self::Migration(owner) => owner.revalidate(),
        }
    }
    pub(crate) fn matches_authority(&self, authority: &AuthorityIdentity) -> Result<()> {
        match self {
            Self::Shared(owner) => owner.matches_authority(authority),
            Self::Migration(owner) if owner.registry == authority.registry => Ok(()),
            Self::Migration(_) => Err(StoreError::Unsafe),
        }
    }
}
impl ExclusiveInitialization {
    fn acquire(registry: &Path, create: bool) -> Result<Self> {
        if create {
            private_dir(registry)?;
        }
        let directory = schema_directory(registry)?;
        match fs::symlink_metadata(registry.join("initialization.lock")) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match fs::symlink_metadata(registry.join("initialization.json")) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Ok(_) => return Err(StoreError::Unsafe),
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
        }
        let file = open_initialization_file(registry, create)?;
        lock_initialization(&file, true)?;
        let owner = Self(Arc::new(ExclusiveInitializationOwner {
            file,
            registry: registry.to_path_buf(),
            directory,
        }));
        owner.revalidate()?;
        if create {
            owner.0.file.sync_all()?;
            sync_dir(registry)?;
            sync_dir(registry.parent().ok_or(StoreError::Unsafe)?)?;
        }
        Ok(owner)
    }
    pub(crate) fn retain(&self) -> Arc<ExclusiveInitializationOwner> {
        self.0.clone()
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.0.revalidate()
    }
}
impl ExclusiveInitializationOwner {
    fn revalidate(&self) -> Result<()> {
        revalidate_schema_directory(&self.registry, &self.directory)?;
        checked_schema_file(&self.registry.join("initialization.lock"), &self.file)
    }
}
impl Drop for ExclusiveInitializationOwner {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}

#[cfg(test)]
mod schema_handoff_fixture {
    use std::cell::RefCell;
    type Hook = Box<dyn FnMut()>;
    thread_local! { static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) }; }
    pub(super) struct Guard(std::marker::PhantomData<std::rc::Rc<()>>);
    pub(super) fn install(hook: impl FnMut() + 'static) -> Guard {
        HOOK.with(|slot| {
            assert!(slot.borrow_mut().replace(Box::new(hook)).is_none());
        });
        Guard(std::marker::PhantomData)
    }
    pub(super) fn reached() {
        let hook = HOOK.with(|slot| slot.borrow_mut().take());
        if let Some(mut hook) = hook {
            hook();
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            HOOK.with(|slot| {
                slot.borrow_mut().take();
            });
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
// Absence is bootstrap only when neither authority database has ever been
// published here. Check before creating a lock, then again under initialization EX.
fn validate_uninitialized(registry: &Path, dir: &Path) -> Result<()> {
    match fs::symlink_metadata(registry) {
        Ok(_) => {
            existing_directory(registry)?;
            for entry in fs::read_dir(registry)? {
                let name = entry?.file_name();
                if name != "initialization.lock" && name != "initialization.tmp" {
                    return Err(StoreError::Unsafe);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    for suffix in ["", "-wal", "-shm", "-journal"] {
        match fs::symlink_metadata(dir.join(format!("store.sqlite{suffix}"))) {
            Ok(_) => return Err(StoreError::Unsafe),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
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
    #[cfg_attr(test, track_caller)]
    pub(crate) fn sql_phase(&self) -> SqlPhase {
        self.budget.enter()
    }
    pub(crate) fn schema_role(&self) -> SchemaRole {
        self.role
    }
    pub(crate) fn require_current(&self) -> Result<()> {
        if self.access != StoreAccess::ReadWrite || self.role != SchemaRole::Current17 {
            return Err(StoreError::Unsafe);
        }
        Ok(())
    }
    pub(crate) fn schema_participation(&self) -> SchemaParticipation {
        self.schema.clone()
    }
    pub(crate) fn authority_identity(&self) -> &Arc<AuthorityIdentity> {
        &self.authority
    }
    pub(crate) fn may_acquire_lease(&self) -> Result<()> {
        if self.access != StoreAccess::ReadWrite {
            return Err(StoreError::Unsafe);
        }
        self.require_outside_sql()
    }
    // Checkout metadata has the same outside-SQL boundary as lease acquisition,
    // but readonly participants may acquire a guard after closing their BEGIN.
    pub(crate) fn require_outside_sql(&self) -> Result<()> {
        if self.budget.is_active() || !self.conn.is_autocommit() {
            return Err(StoreError::Invalid);
        }
        Ok(())
    }
    pub(crate) fn authority_lease(&self) -> Result<crate::allocate::AuthorityLease> {
        self.may_acquire_lease()?;
        Ok(crate::allocate::lifecycle_lock(self)?)
    }
    pub(crate) fn writable_authority(&self) -> bool {
        self.access == StoreAccess::ReadWrite
    }
    /// Existing authority only. No bootstrap, schema migration, event writes or
    /// repair; reads committed WAL through SQLite's ordinary read-only mode.
    pub fn open_existing_registered_readonly(
        registry: &Path,
        dir: &Path,
        managed: &[PathBuf],
    ) -> Result<Self> {
        let (schema, conn, budget, _, authority) =
            existing_authority(registry, dir, managed, false)?;
        let _phase = budget.enter();
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version != 17 {
            return Err(StoreError::UpgradeRequired);
        }
        SchemaRole::Current17.validate(&conn)?;
        drop(_phase);
        Ok(Self {
            conn,
            budget,
            authority,
            schema,
            role: SchemaRole::Current17,
            access: StoreAccess::ReadOnly,
        })
    }
    /// Recovery can mutate an established current-schema authority only; never initializes
    /// an empty authority for an unknown RunId or upgrades historical schemas.
    pub fn open_existing_registered_mut(
        registry: &Path,
        dir: &Path,
        managed: &[PathBuf],
    ) -> Result<Self> {
        let (schema, conn, budget, _, authority) =
            existing_authority(registry, dir, managed, true)?;
        let _phase = budget.enter();
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version != 17 {
            return Err(StoreError::UpgradeRequired);
        }
        SchemaRole::Current17.validate(&conn)?;
        drop(_phase);
        Ok(Self {
            conn,
            budget,
            authority,
            schema,
            role: SchemaRole::Current17,
            access: StoreAccess::ReadWrite,
        })
    }
    pub(crate) fn open_retirement_readonly(
        registry: &Path,
        dir: &Path,
        managed: &[PathBuf],
    ) -> std::result::Result<Self, RetirementAdmissionError> {
        let (schema, conn, budget, _, authority) =
            existing_authority(registry, dir, managed, false)?;
        let phase = budget.enter();
        let role = match crate::retirement_journal::schema_version(&conn)? {
            16 => SchemaRole::HistoricalRead(SupportedRetirementVersion::V16),
            17 => SchemaRole::HistoricalRead(SupportedRetirementVersion::V17),
            _ => return Err(StoreError::UpgradeRequired.into()),
        };
        role.validate(&conn)?;
        crate::retirement_journal::validate_all(&conn)
            .map_err(RetirementAdmissionError::history)?;
        drop(phase);
        Ok(Self {
            conn,
            budget,
            authority,
            schema,
            access: StoreAccess::ReadOnly,
            role,
        })
    }
    pub(crate) fn open_retirement_abort_existing(
        registry: &Path,
        dir: &Path,
        managed: &[PathBuf],
    ) -> std::result::Result<Self, RetirementAdmissionError> {
        let reader = Self::open_retirement_readonly(registry, dir, managed)?;
        let role = match reader.role {
            SchemaRole::HistoricalRead(SupportedRetirementVersion::V16) => {
                SchemaRole::Legacy16Abort
            }
            SchemaRole::HistoricalRead(SupportedRetirementVersion::V17) => SchemaRole::Current17,
            _ => return Err(StoreError::Invalid.into()),
        };
        {
            let _phase = reader.sql_phase();
            reader
                .conn
                .execute_batch("ROLLBACK;")
                .map_err(StoreError::from)?;
        }
        let schema = reader.schema_participation();
        drop(reader);
        roots(managed)?;
        schema.revalidate()?;
        let conn = database(dir, "store.sqlite", false, false)?;
        let budget = SqlBudget::install(&conn)?;
        let phase = budget.enter();
        query_protections(&conn)?;
        role.validate(&conn)?;
        crate::retirement_journal::validate_all(&conn)
            .map_err(RetirementAdmissionError::history)?;
        drop(phase);
        let authority = AuthorityIdentity::collect(registry, dir, true)?;
        schema.revalidate()?;
        schema.matches_authority(&authority)?;
        Ok(Self {
            conn,
            budget,
            authority,
            schema,
            access: StoreAccess::ReadWrite,
            role,
        })
    }
    /// Disposable test-format construction BEFORE any retirement observation.
    /// This returns only the ordinary abort-only Store, never a preparation
    /// owner or an authorization override. All setup participants must be gone.
    #[cfg(test)]
    pub(crate) fn construct_legacy16_preobservation_fixture(
        registry: &Path,
        dir: &Path,
        managed: &[PathBuf],
    ) -> Result<Self> {
        fn require_empty_current(conn: &Connection) -> Result<()> {
            SchemaRole::Current17.validate(conn)?;
            // GLOBAL emptiness, not merely absence of an active scoped row.
            // Refuse tombstones and orphans rather than erase or reinterpret.
            let nonempty: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM retirement_intents) OR EXISTS(SELECT 1 FROM quarantine_actions)",
                [],
                |row| row.get(0),
            )?;
            if nonempty {
                return Err(StoreError::Invalid);
            }
            crate::retirement_journal::validate_all(conn)
        }

        let initialization = ExclusiveInitialization::acquire(registry, false)?;
        let managed = roots(managed)?;
        let marker = SchemaFile::open(registry.join("initialization.json"))?;
        let marker_bytes = marker.bytes()?;
        let record: Initialization =
            serde_json::from_slice(&marker_bytes).map_err(|_| StoreError::Unsafe)?;
        if record.version != 1 || !record.initialized || record.store != dir {
            return Err(StoreError::Unsafe);
        }
        let database_file = SchemaFile::open(dir.join("store.sqlite"))?;
        let registration_file = SchemaFile::open(registry.join("authorities.sqlite"))?;
        let allocation_lock = SchemaFile::open(dir.join("allocation.lock"))?;
        let authority = AuthorityIdentity::collect(registry, dir, true)?;
        {
            let (reg, reg_budget) = existing_database(registry, "authorities.sqlite")?;
            let _phase = reg_budget.enter();
            validate_registry_claims(&reg, dir, &managed)?;
            let claims: i64 =
                reg.query_row("SELECT count(*) FROM authorities", [], |r| r.get(0))?;
            let mode: String = reg.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
            if claims != managed.len() as i64 || mode != "wal" {
                return Err(StoreError::Unsafe);
            }
        }
        let selected = {
            let (reader, budget) = existing_database(dir, "store.sqlite")?;
            let _phase = budget.enter();
            reader.execute_batch("BEGIN;")?;
            require_empty_current(&reader)?;
            let mode: String = reader.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
            if mode != "wal" {
                return Err(StoreError::Unsafe);
            }
            let selected = migration_checkouts(&reader)?;
            reader.execute_batch("ROLLBACK;")?;
            selected
        };
        // End all preliminary SQL before the complete sorted checkout EX set.
        let mut guards = Vec::new();
        for checkout in &selected {
            guards.push(
                crate::checkout_guard::CheckoutGuard::exclusive_for_migration(
                    &authority,
                    &initialization,
                    *checkout,
                )?,
            );
        }
        let mut conn = database(dir, "store.sqlite", false, false)?;
        let budget = SqlBudget::install(&conn)?;
        initialization.revalidate()?;
        database_file.revalidate()?;
        registration_file.revalidate()?;
        allocation_lock.revalidate()?;
        if marker.bytes()? != marker_bytes {
            return Err(StoreError::Unsafe);
        }
        let lease = crate::allocate::migration_lease(&authority, &initialization)?;
        {
            let _phase = budget.enter();
            query_protections(&conn)?;
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            lease.check_migration(&authority)?;
            if migration_checkouts(&tx)? != selected {
                return Err(StoreError::Conflict);
            }
            require_empty_current(&tx)?;
            // The actual 16->17 migration adds ONLY this table and its indexes;
            // DROP TABLE removes its implicit PK and explicit checkout index.
            // Never assign schema_version: SQLite produces the new native cookie.
            tx.execute_batch("DROP TABLE quarantine_actions; PRAGMA user_version=16;")?;
            SchemaRole::Legacy16Abort.validate(&tx)?;
            crate::retirement_journal::validate_all(&tx)?;
            tx.commit()?;
        }
        drop(lease);
        // No filesystem/sync under authority or SQL. Retain EX and all children
        // through synchronization, then drain them before the actual fresh SH.
        database_file.revalidate()?;
        registration_file.revalidate()?;
        allocation_lock.revalidate()?;
        authority.revalidate_migration()?;
        if marker.bytes()? != marker_bytes {
            return Err(StoreError::Unsafe);
        }
        sync_dir(dir)?;
        sync_dir(registry)?;
        initialization.revalidate()?;
        drop(conn);
        drop(guards);
        drop(initialization);
        let store = Self::open_retirement_abort_existing(registry, dir, &managed)
            .map_err(RetirementAdmissionError::into_store_error)?;
        if store.schema_role() != SchemaRole::Legacy16Abort
            || store.authority_identity().as_ref() != authority.as_ref()
        {
            return Err(StoreError::Unsafe);
        }
        Ok(store)
    }

    /// No-create identity check only. Ends SQL, the connection and its actual
    /// schema participation before returning; never exports a historical Store.
    pub(crate) fn preflight_existing_identity(
        registry: &Path,
        dir: &Path,
        managed: &[PathBuf],
        accepted: impl Fn(i64) -> bool,
    ) -> Result<()> {
        let (schema, conn, budget, _, _authority) =
            existing_authority(registry, dir, managed, false)?;
        let phase = budget.enter();
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if !accepted(version) {
            return Err(StoreError::UpgradeRequired);
        }
        validate_existing_schema(&conn, version)?;
        conn.execute_batch("ROLLBACK;")?;
        drop(phase);
        drop(conn);
        drop(schema);
        Ok(())
    }
    /// Finish may upgrade a proven established v8 authority, never bootstrap or
    /// repair an invalid authority. The read-only preflight precedes mutable open.
    pub(crate) fn open_finish_authority(
        registry: &Path,
        dir: &Path,
        managed: &[PathBuf],
    ) -> Result<Self> {
        let (schema, conn, budget, _, _authority) =
            existing_authority(registry, dir, managed, false)?;
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
            if !matches!(version, 8..=17) {
                return Err(StoreError::UpgradeRequired);
            }
            validate_existing_schema(&conn, version)?;
            crate::run_journal::validate_enrollment_rosters(&conn)?;
        }
        drop(conn);
        drop(schema);
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
        // Only a specifically validated need for bootstrap, registration or
        // migration reaches EX. Corrupt established metadata is never retried.
        let marker_present = match fs::symlink_metadata(registry.join("initialization.json")) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        if marker_present {
            match existing_authority_for_open(registry, dir, &managed, true, true) {
                Ok((schema, conn, budget, _, authority)) => {
                    return Ok(Self {
                        conn,
                        budget,
                        authority,
                        schema,
                        access: StoreAccess::ReadWrite,
                        role: SchemaRole::Current17,
                    })
                }
                Err(StoreError::UpgradeRequired) => {}
                Err(error) => return Err(error),
            }
        } else {
            validate_uninitialized(registry, dir)?;
        }
        // Preliminary connections/owners have ended. EX never upgrades SH.
        let initialization = ExclusiveInitialization::acquire(registry, !marker_present)?;
        let managed = roots(&managed)?;
        let registry = registry.to_path_buf();
        initialization_boundary("registry_dir");
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
                let marker = SchemaFile::open(marker.clone())?;
                serde_json::from_slice(&marker.bytes()?).map_err(|_| StoreError::Unsafe)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                validate_uninitialized(&registry, dir)?;
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
        // A pending marker is not evidence that an existing database is empty.
        // Classify BOTH databases without transitions under actual init EX;
        // an old/corrupt store must fail before even the registry journal changes.
        let (new_database, initialize_store) =
            match initialization_database(&initialization, &dir, "store.sqlite", pending)? {
                InitializationDatabase::Absent => (true, true),
                InitializationDatabase::Empty => (false, true),
                InitializationDatabase::Versioned(conn, budget, version) => {
                    let _phase = budget.enter();
                    validate_migration_source(&conn, version)?;
                    (false, false)
                }
            };
        let initialize_registry = match initialization_database(
            &initialization,
            &registry,
            "authorities.sqlite",
            pending,
        )? {
            InitializationDatabase::Absent | InitializationDatabase::Empty => true,
            InitializationDatabase::Versioned(conn, budget, _) => {
                let _phase = budget.enter();
                validate_registry_claims(&conn, &dir, &managed)?;
                false
            }
        };
        // All preflight connections/SQL have ended. Only actual absent/empty
        // pending bootstrap storage may initialize its journal.
        let mut reg = database(
            &registry,
            "authorities.sqlite",
            initialize_registry,
            initialize_registry,
        )?;
        initialization_boundary("registry_db");
        let reg_budget = SqlBudget::install(&reg)?;
        // Preserve bootstrap's durable-claims-before-database crash boundary.
        // This branch has no database/history to migrate; an existing database
        // ALWAYS waits for the complete authoritative history gate below.
        if new_database {
            register_roots(&mut reg, &reg_budget, &dir, &managed)?;
        }
        let mut conn = database(&dir, "store.sqlite", initialize_store, initialize_store)?;
        initialization_boundary("store_db");
        let budget = SqlBudget::install(&conn)?;
        let (version, selected) = {
            let phase = budget.enter();
            conn.execute_batch("BEGIN;")?;
            let version = crate::retirement_journal::schema_version(&conn)?;
            if !(0..=17).contains(&version) {
                return Err(StoreError::Unsafe);
            }
            let selected = if version == 0 {
                Vec::new()
            } else {
                migration_checkouts(&conn)?
            };
            conn.execute_batch("ROLLBACK;")?;
            drop(phase);
            (version, selected)
        };
        initialization.revalidate()?;
        if initialize_store {
            let infrastructure = AuthorityIdentity::open_lock(&dir, true)?;
            infrastructure.sync_all()?;
        }
        let authority = AuthorityIdentity::collect(&registry, &dir, true)?;
        let mut guards = Vec::new();
        for checkout in &selected {
            guards.push(
                crate::checkout_guard::CheckoutGuard::exclusive_for_migration(
                    &authority,
                    &initialization,
                    *checkout,
                )?,
            );
        }
        let lease = crate::allocate::migration_lease(&authority, &initialization)?;
        let phase = budget.enter();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        lease.check_migration(&authority)?;
        if crate::retirement_journal::schema_version(&tx)? != version
            || (version != 0 && migration_checkouts(&tx)? != selected)
        {
            return Err(StoreError::Conflict);
        }
        validate_migration_source(&tx, version)?;
        // Only now may registry DDL/claims change. No filesystem work occurs
        // while either transaction or the actual migration authority is held.
        if !new_database {
            register_roots(&mut reg, &reg_budget, &dir, &managed)?;
        }
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
        if version < 13 {
            validate_existing_schema(&tx, 12)?;
            tx.execute_batch(crate::capture_readiness::SCHEMA)?;
        }
        if version < 14 {
            validate_existing_schema(&tx, 13)?;
            tx.execute_batch(crate::attribution_gap::SCHEMA)?;
        }
        validate_existing_schema(&tx, 14)?;
        if version < 15 {
            tx.execute_batch(crate::gap_continuation::SCHEMA)?;
        }
        validate_existing_schema(&tx, 15)?;
        if version < 16 {
            tx.execute_batch(crate::retirement_journal::SCHEMA)?;
        }
        validate_existing_schema(&tx, 16)?;
        if version < 17 {
            tx.execute_batch(crate::quarantine_journal::SCHEMA)?;
            tx.pragma_update(None, "user_version", 17)?;
        }
        SchemaRole::Current17.validate(&tx)?;
        crate::quarantine_journal::validate_all(&tx)?;
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
        drop(lease);
        initialization_boundary("store_schema");
        // Complete ordinary authority guard infrastructure under bootstrap EX;
        // discard the descriptor before the fresh shared observation below.
        let allocation_lock = AuthorityIdentity::open_lock(&dir, false)?;
        allocation_lock.sync_all()?;
        drop(allocation_lock);
        // FULL SQLite commits make schema and claims durable, including their
        // WAL records. Sync directory entries before publishing initialized.
        sync_dir(&dir)?;
        sync_dir(&registry)?;
        if pending {
            record.initialized = true;
            persist_initialization(&registry, &record)?;
        }
        initialization_boundary("initialized");
        initialization.revalidate()?;
        drop(conn);
        drop(reg);
        drop(guards);
        drop(initialization);
        #[cfg(test)]
        schema_handoff_fixture::reached();
        // No observations or connections cross the non-atomic EX/SH gap. A
        // complete no-create current-schema reopen is the only return path.
        Self::open_existing_registered_mut(&registry, &dir, &managed)
    }
    pub fn charged(&self, repository: &Path, owner: Option<&str>) -> Result<u64> {
        let repo = canonical(repository)?;
        let _phase = self.sql_phase();
        self.role.validate(&self.conn)?;
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
        let lease = self.authority_lease()?;
        lease.check(self)?;
        let authority = self.authority_identity().clone();
        if group.get_version_num() != 7 || group.get_variant() != uuid::Variant::RFC4122 {
            return Err(StoreError::Invalid);
        }
        let _phase = self.sql_phase();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let tx = crate::retirement_journal::fence(
            tx,
            &lease,
            &authority,
            crate::retirement_journal::Scope::Checkout(checkout),
            crate::retirement_journal::Attempt::WriterAcquire,
        )?;
        acquire_writer_tx(&tx, checkout, group, true, &lease, &authority)?;
        tx.commit()?;
        Ok(())
    }
    pub fn pending_events(&self, limit: usize) -> Result<Vec<PendingEvent>> {
        let _phase = self.sql_phase();
        self.role.validate(&self.conn)?;
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
        self.require_current()?;
        let lease = self.authority_lease()?;
        lease.check(self)?;
        let authority = self.authority_identity().clone();
        let _phase = self.sql_phase();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        lease.check_authority(&authority)?;
        SchemaRole::Current17.validate(&tx)?;
        crate::quarantine_journal::validate_all(&tx)?;
        tx.execute(
            "UPDATE outbox SET acknowledged=1 WHERE sequence=?1",
            [sequence],
        )?;
        tx.commit()?;
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

// Called only within open_registered's retained initialization EX. No I/O.
fn register_roots(
    reg: &mut Connection,
    budget: &SqlBudget,
    dir: &Path,
    managed: &[PathBuf],
) -> Result<()> {
    let phase = budget.enter();
    let version: i64 = reg.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if !matches!(version, 0 | 1) {
        return Err(StoreError::Unsafe);
    }
    let tx = reg.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if version == 0 {
        tx.execute_batch("CREATE TABLE authorities(root TEXT PRIMARY KEY, store TEXT NOT NULL); PRAGMA user_version=1;")?;
    }
    initialization_boundary("registry_schema");
    validate_registry_claims(&tx, dir, managed)?;
    for root in managed {
        tx.execute(
            "INSERT OR IGNORE INTO authorities VALUES (?1,?2)",
            (root.to_str(), dir.to_str()),
        )?;
    }
    tx.commit()?;
    drop(phase);
    initialization_boundary("claims");
    Ok(())
}

// Read-only admission, repeated under the authoritative IMMEDIATE transaction.
// Neither helper grants a Store role, lease, or migration permission.
fn validate_registry_claims(conn: &Connection, dir: &Path, managed: &[PathBuf]) -> Result<()> {
    let mut stmt = conn.prepare("SELECT root,store FROM authorities LIMIT 1025")?;
    let claims = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if claims.len() > REPORT_CLAIMS {
        return Err(StoreError::Unsafe);
    }
    for (root, owner) in &claims {
        if owner != dir.to_str().ok_or(StoreError::Invalid)?
            || !managed.contains(&PathBuf::from(root))
        {
            return Err(StoreError::Unsafe);
        }
    }
    Ok(())
}

fn validate_migration_source(conn: &Connection, version: i64) -> Result<()> {
    if version == 0 {
        return validate_empty_initialization_database(conn);
    }
    validate_existing_schema(conn, version)?;
    if version == 16 {
        SchemaRole::Legacy16Abort.validate(conn)?;
        crate::retirement_journal::validate_all(conn)?;
        let active: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM retirement_intents WHERE stage IN ('prepared','held'))",
            [],
            |r| r.get(0),
        )?;
        if active {
            return Err(StoreError::RetirementFenced);
        }
    } else if version == 17 {
        crate::quarantine_journal::validate_all(conn)?;
    } else {
        let modern: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE tbl_name IN ('retirement_intents','quarantine_actions'))", [], |r| r.get(0))?;
        if modern {
            return Err(StoreError::Invalid);
        }
    }
    Ok(())
}

// Only open_registered, while holding actual initialization EX, consumes this
// classification. An Empty database is not a legacy/versioned Store capability.
enum InitializationDatabase {
    Absent,
    Empty,
    Versioned(Box<Connection>, SqlBudget, i64),
}

fn validate_empty_initialization_database(conn: &Connection) -> Result<()> {
    let objects: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema)", [], |r| {
        r.get(0)
    })?;
    let cookie: i64 = conn.query_row("PRAGMA schema_version", [], |r| r.get(0))?;
    if objects || cookie != 0 || crate::retirement_journal::schema_version(conn)? != 0 {
        return Err(StoreError::Unsafe);
    }
    Ok(())
}

fn initialization_database(
    initialization: &ExclusiveInitialization,
    dir: &Path,
    name: &str,
    pending: bool,
) -> Result<InitializationDatabase> {
    initialization.revalidate()?;
    existing_directory(dir)?;
    let path = dir.join(name);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            check_file(&path)?;
            Some(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && pending => None,
        Err(error) => return Err(error.into()),
    };
    if metadata.as_ref().is_none_or(|m| m.len() == 0) {
        if !pending {
            return Err(StoreError::Unsafe);
        }
        // An absent/zero-byte file cannot authorize adoption of stale sidecars.
        for suffix in ["-wal", "-shm", "-journal"] {
            match fs::symlink_metadata(dir.join(format!("{name}{suffix}"))) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(StoreError::Unsafe),
            }
        }
        return Ok(if metadata.is_none() {
            InitializationDatabase::Absent
        } else {
            InitializationDatabase::Empty
        });
    }
    if pending {
        let mut sidecar_present = false;
        for suffix in ["-wal", "-shm", "-journal"] {
            match fs::symlink_metadata(dir.join(format!("{name}{suffix}"))) {
                Ok(_) => sidecar_present = true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if !sidecar_present {
            // A crash immediately after first journal_mode=WAL can leave a
            // genuine empty SQLite header with NO WAL/SHM yet. A normal readonly
            // WAL open could create them before proving emptiness. Only here,
            // under actual init EX with ALL sidecars absent, inspect immutably.
            // Never ignore an existing WAL, and NEVER admit versioned data via
            // this branch: both native schema contents and cookies must be empty.
            if fs::symlink_metadata(&path)?.len() > REPORT_DATABASE_BYTES {
                return Err(StoreError::Unsafe);
            }
            let mut uri = String::from("file:");
            for byte in path.as_os_str().as_encoded_bytes() {
                use std::fmt::Write;
                write!(&mut uri, "%{byte:02X}").map_err(|_| StoreError::Invalid)?;
            }
            uri.push_str("?immutable=1");
            let conn = Connection::open_with_flags(
                uri,
                OpenFlags::SQLITE_OPEN_READ_ONLY
                    | OpenFlags::SQLITE_OPEN_URI
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )?;
            conn.busy_timeout(Duration::from_millis(500))?;
            let budget = SqlBudget::install(&conn)?;
            let _phase = budget.enter();
            query_protections(&conn)?;
            conn.execute_batch("PRAGMA query_only=ON;")?;
            validate_empty_initialization_database(&conn)?;
            let integrity: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
            if integrity != "ok" {
                return Err(StoreError::Unsafe);
            }
            return Ok(InitializationDatabase::Empty);
        }
    }
    let (conn, budget, version) = inspect_database_readonly(dir, name)?;
    let phase = budget.enter();
    if version == 0 {
        if !pending {
            return Err(StoreError::Unsafe);
        }
        validate_empty_initialization_database(&conn)?;
        return Ok(InitializationDatabase::Empty);
    }
    // Versioned databases never acquire WAL simply because a marker is pending.
    let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    if mode != "wal" {
        return Err(StoreError::Unsafe);
    }
    drop(phase);
    Ok(InitializationDatabase::Versioned(
        Box::new(conn),
        budget,
        version,
    ))
}

fn migration_checkouts(conn: &Connection) -> Result<Vec<Uuid>> {
    let mut stmt = conn.prepare("SELECT id FROM checkouts ORDER BY id LIMIT 4097")?;
    let mut cursor = stmt.query([])?;
    let mut selected = Vec::new();
    while let Some(row) = cursor.next()? {
        if selected.len() == REPORT_ROWS as usize {
            return Err(StoreError::Invalid);
        }
        let id = match row.get_ref(0)? {
            rusqlite::types::ValueRef::Text(bytes) if bytes.len() == 36 => {
                crate::retirement_journal::parse_uuid(
                    std::str::from_utf8(bytes).map_err(|_| StoreError::Invalid)?,
                )?
            }
            _ => return Err(StoreError::Invalid),
        };
        selected.push(id);
    }
    Ok(selected)
}

fn existing_directory(dir: &Path) -> Result<()> {
    crate::config::validate_path(dir, true).map_err(|_| StoreError::Unsafe)?;
    let m = fs::symlink_metadata(dir)?;
    if m.mode() & 0o077 != 0 || m.uid() != rustix::process::geteuid().as_raw() {
        return Err(StoreError::Unsafe);
    }
    Ok(())
}
fn existing_database(dir: &Path, name: &str) -> Result<(Connection, SqlBudget)> {
    let (conn, budget, version) = inspect_database_readonly(dir, name)?;
    if version == 0 {
        return Err(StoreError::Unsafe);
    }
    Ok((conn, budget))
}

// Storage inspection only: no create/journal transition and no Store admission.
// Version0 is exclusively classified by initialization_database under init EX;
// every established reader above continues to refuse it.
fn inspect_database_readonly(dir: &Path, name: &str) -> Result<(Connection, SqlBudget, i64)> {
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
    if !(matches!(version, 0 | 1) || (name == "store.sqlite" && matches!(version, 2..=17)))
        || integrity != "ok"
    {
        return Err(StoreError::Unsafe);
    }
    Ok((conn, budget, version))
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
    #[cfg(test)]
    origin: Option<&'static std::panic::Location<'static>>,
    #[cfg(test)]
    recorded: bool,
}
pub(crate) struct SqlPhase(SqlBudget);
impl SqlBudget {
    fn is_active(&self) -> bool {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).depth != 0
    }
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
                let interrupted =
                    state.ticks >= 200 || state.deadline.is_some_and(|d| Instant::now() >= d);
                #[cfg(test)]
                if interrupted && !state.recorded {
                    state.recorded = true;
                    let now = Instant::now();
                    let origin = state.origin.unwrap();
                    crate::capture_diagnostics::record(crate::capture_diagnostics::Event::Sql {
                        file: origin.file(),
                        line: origin.line(),
                        ticks: state.ticks,
                        vm: state.ticks >= 200,
                        wall: state.deadline.is_some_and(|d| now >= d),
                        elapsed_ms: state.deadline.map_or(0, |d| {
                            now.saturating_duration_since(d - Duration::from_millis(500))
                                .as_millis()
                        }),
                        depth: state.depth,
                    });
                }
                interrupted
            }),
        )?;
        Ok(budget)
    }
    #[cfg_attr(test, track_caller)]
    fn enter(&self) -> SqlPhase {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.depth == 0 {
            state.deadline = Some(Instant::now() + Duration::from_millis(500));
            state.ticks = 0;
            #[cfg(test)]
            {
                state.origin = Some(std::panic::Location::caller());
                state.recorded = false;
            }
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
) -> Result<ExistingAuthority> {
    existing_authority_for_open(registry, dir, managed, writable, false)
}
// Destructure schema FIRST so the connection/SQL cleanup ends before its last
// local participation owner on every early-return path as well as success.
type ExistingAuthority = (
    SchemaParticipation,
    Connection,
    SqlBudget,
    usize,
    Arc<AuthorityIdentity>,
);
fn existing_authority_for_open(
    registry: &Path,
    dir: &Path,
    managed: &[PathBuf],
    writable: bool,
    allow_registration: bool,
) -> Result<ExistingAuthority> {
    let schema = SchemaParticipation::open_existing(registry)?;
    // Passive historical accounting never requires the old payload roots to
    // remain on disk. Mutable opens revalidate actual roots under participation.
    let managed = if writable {
        roots(managed)?
    } else {
        managed.to_vec()
    };
    if schema.0.directory != dir {
        return Err(StoreError::Unsafe);
    }
    let (reg, reg_budget) = existing_database(registry, "authorities.sqlite")?;
    let _reg_phase = reg_budget.enter();
    if writable {
        let mode: String = reg.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        if mode != "wal" {
            return Err(StoreError::Unsafe);
        }
    }
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
    if claims
        .iter()
        .any(|(root, store)| Path::new(store) != dir || !managed.contains(&PathBuf::from(root)))
    {
        return Err(StoreError::Unsafe);
    }
    let registration_needed = claims.len() != managed.len();
    if registration_needed && !allow_registration {
        return Err(StoreError::Unsafe);
    }
    drop(rows);
    drop(stmt);
    drop(_reg_phase);
    drop(reg);
    let (conn, budget) = existing_database(dir, "store.sqlite")?;
    let readonly_authority = AuthorityIdentity::collect(registry, dir, false)?;
    schema.revalidate()?;
    schema.matches_authority(&readonly_authority)?;
    let _phase = budget.enter();
    conn.execute_batch("BEGIN;")?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    validate_existing_schema(&conn, version)?;
    if writable && (version != 17 || registration_needed) {
        return Err(StoreError::UpgradeRequired);
    }
    if writable {
        let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        if mode != "wal" {
            return Err(StoreError::Unsafe);
        }
        // Complete the bounded read-only preflight before any mutable open.
        // In particular, do not switch a rejected DELETE-mode DB into WAL.
        drop(_phase);
        drop(conn);
        schema.revalidate()?;
        let writer = database(dir, "store.sqlite", false, false)?;
        let writer_budget = SqlBudget::install(&writer)?;
        let _writer_phase = writer_budget.enter();
        query_protections(&writer)?;
        let version: i64 = writer.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version != 17 {
            return Err(StoreError::Unsafe);
        }
        validate_existing_schema(&writer, version)?;
        drop(_writer_phase);
        let authority = AuthorityIdentity::collect(registry, dir, true)?;
        schema.revalidate()?;
        schema.matches_authority(&authority)?;
        Ok((schema, writer, writer_budget, output_bytes, authority))
    } else {
        Ok((schema, conn, budget, output_bytes, readonly_authority))
    }
}
fn validate_existing_schema(conn: &Connection, version: i64) -> Result<()> {
    if version >= 17 {
        crate::quarantine_journal::validate_schema(conn)?;
    }
    if version >= 16 {
        crate::retirement_journal::validate_schema(conn)?;
    }
    if version >= 15 {
        crate::gap_continuation::validate_schema(conn)?;
    }
    if version >= 14 {
        crate::attribution_gap::validate_schema(conn)?;
    }
    if version >= 13 {
        crate::capture_readiness::validate_schema(conn)?;
    }
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
    let (_schema, conn, budget, mut output_bytes, _authority) =
        existing_authority(registry, dir, managed, false)?;
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
    crate::retirement_journal::exclude_operation(conn, id)?;
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
    lease: &crate::allocate::AuthorityLease,
    authority: &Arc<AuthorityIdentity>,
) -> Result<()> {
    lease.check_authority(authority)?;
    crate::retirement_journal::require_unfenced(conn, checkout)?;
    crate::attribution_gap::validate_related(conn, checkout)?;
    acquire_writer_context(
        conn,
        checkout,
        group,
        allow_existing,
        crate::run_journal::WriterAdmission::Ordinary,
        lease,
        authority,
    )
}
pub(crate) fn acquire_writer_context(
    conn: &Connection,
    checkout: Uuid,
    group: Uuid,
    allow_existing: bool,
    materialized: crate::run_journal::WriterAdmission<'_, '_, '_>,
    lease: &crate::allocate::AuthorityLease,
    authority: &Arc<AuthorityIdentity>,
) -> Result<()> {
    lease.check_authority(authority)?;
    crate::retirement_journal::require_unfenced(conn, checkout)?;
    // New managed groups acquire before inserting their journal. Existing
    // managed requests retry through their journal API, never as bare writers.
    exclude_journal_identity(conn, group)?;
    if let crate::run_journal::WriterAdmission::Captured(proof, related) = materialized {
        proof.validate_writer(conn, checkout, group, related)?;
    } else if let crate::run_journal::WriterAdmission::Gap(proof, related) = materialized {
        proof.validate_writer(conn, checkout, group, related, lease, authority)?;
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
#[path = "schema_participation_tests.rs"]
pub(crate) mod schema_participation_tests;

#[cfg(test)]
#[path = "schema17_migration_tests.rs"]
mod schema17_migration_tests;

#[cfg(test)]
mod tests {
    const SCAN: &str = "WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<5000) SELECT sum(x) FROM n";

    #[test]
    fn diagnostics_distinguish_sql_limits_and_outer_origin() {
        let diagnostics = crate::capture_diagnostics::Guard::new();
        let mut observed = Vec::new();
        for wall in [false, true] {
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            let budget = super::SqlBudget::install(&conn).unwrap();
            let outer_line = line!() + 1;
            let outer = budget.enter();
            if wall {
                // Private deterministic deadline control, not a production threshold change.
                budget.0.lock().unwrap().deadline =
                    Some(std::time::Instant::now() - std::time::Duration::from_millis(1));
            }
            let inner = budget.enter();
            let error = conn
                .query_row(&SCAN.replace("5000", "20000"), [], |r| r.get::<_, i64>(0))
                .unwrap_err();
            assert!(
                matches!(error, rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::OperationInterrupted)
            );
            drop(inner);
            drop(outer);
            drop(budget);
            drop(conn);
            observed.push((wall, outer_line, diagnostics.events()));
        }
        for (wall, line, events) in observed {
            assert!(events.iter().any(|event| matches!(event,
                crate::capture_diagnostics::Event::Sql { file, line: origin, wall: expired, vm, depth: 2, .. }
                if *file == file!() && *origin == line && *expired == wall && *vm != wall)), "missing classified interruption: {events:?}");
        }
    }

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
                .execute_batch("DROP TABLE quarantine_actions; DROP TABLE retirement_intents; DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; DROP TABLE attribution_gaps; DROP TABLE capture_readiness; DROP TABLE capture_finalizations; DROP TABLE capture_requirements;")
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
            INSERT INTO checkouts VALUES('00000000-0000-7000-8000-000000000001','00000000-0000-7000-8000-000000000002',x'00','repo','actor','task','owner','held',0);
            INSERT INTO run_groups VALUES('group','00000000-0000-7000-8000-000000000001','supervised',1,0,1,0);
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
    fn authority_lease_rejects_readonly_sql_active_and_wrong_store() {
        use super::{Store, StoreError};
        use crate::allocate::lifecycle_lock;
        use std::os::unix::fs::{symlink, PermissionsExt};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let dir = temp.path().join("private");
        let registry = temp.path().join(".work-authorities");
        let roots = std::slice::from_ref(&root);
        let mut store = Store::open(&dir, roots).unwrap();
        let limits = crate::admission::Limits {
            repository: 10,
            owner: 10,
            available_bytes: Some(10),
            floor_bytes: 0,
            warn_bytes: 0,
        };
        let checkout = store
            .reserve(
                &crate::admission::Reservation {
                    operation: uuid::Uuid::now_v7(),
                    repository: root.clone(),
                    actor: "alice".into(),
                    owner: "alice".into(),
                    task: "lease".into(),
                },
                limits,
            )
            .unwrap();
        let lease = lifecycle_lock(&store).unwrap();
        lease.check(&store).unwrap();
        let mut other = Store::open_existing_registered_mut(&registry, &dir, roots).unwrap();
        assert_eq!(store.authority_identity(), other.authority_identity());
        assert!(
            lease.check(&other).is_err(),
            "value equality is not Store-instance authority"
        );
        let before = other.pending_events(100).unwrap();
        assert!(other
            .transfer_under_lease(checkout, "bob", limits, &lease)
            .is_err());
        assert_eq!(other.pending_events(100).unwrap(), before);
        assert_eq!(other.charged(&root, Some("alice")).unwrap(), 1);
        store
            .transfer_under_lease(checkout, "bob", limits, &lease)
            .unwrap();
        assert_eq!(store.charged(&root, Some("bob")).unwrap(), 1);
        let foreign_temp = tempfile::tempdir().unwrap();
        let foreign_root = foreign_temp.path().join("root");
        std::fs::create_dir(&foreign_root).unwrap();
        let foreign = Store::open(&foreign_temp.path().join("private"), &[foreign_root]).unwrap();
        assert!(lease.check(&foreign).is_err());
        // A borrowed check is cached-only, including inside an armed SQL phase.
        let lock = dir.join("allocation.lock");
        std::fs::rename(&lock, dir.join("original.lock")).unwrap();
        let phase = store.sql_phase();
        assert!(store.conn.is_autocommit());
        lease.check(&store).unwrap();
        assert!(matches!(store.authority_lease(), Err(StoreError::Invalid)));
        assert!(!lock.exists());
        drop(phase);
        drop(lease);
        store.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert!(matches!(store.authority_lease(), Err(StoreError::Invalid)));
        assert!(!lock.exists());
        store.conn.execute_batch("ROLLBACK").unwrap();
        let mut readonly =
            Store::open_existing_registered_readonly(&registry, &dir, roots).unwrap();
        assert_eq!(readonly.charged(&root, Some("bob")).unwrap(), 1);
        assert!(matches!(
            readonly.transfer(checkout, "alice", limits),
            Err(StoreError::Unsafe)
        ));
        assert!(
            !lock.exists(),
            "readonly mutation must not create allocation.lock"
        );
        assert!(
            lifecycle_lock(&store).is_err(),
            "missing pinned file is not recreated by acquisition"
        );
        drop(readonly);
        for damage in ["symlink", "hardlink", "mode", "replacement"] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            std::fs::create_dir(&root).unwrap();
            let dir = temp.path().join("private");
            let store = Store::open(&dir, std::slice::from_ref(&root)).unwrap();
            let lock = dir.join("allocation.lock");
            match damage {
                "symlink" => {
                    std::fs::rename(&lock, dir.join("original.lock")).unwrap();
                    symlink(dir.join("original.lock"), &lock).unwrap();
                }
                "hardlink" => std::fs::hard_link(&lock, dir.join("second.lock")).unwrap(),
                "mode" => {
                    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap()
                }
                "replacement" => {
                    std::fs::rename(&lock, dir.join("original.lock")).unwrap();
                    std::fs::write(&lock, []).unwrap();
                    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                lifecycle_lock(&store).is_err(),
                "{damage} accepted by pinned Store"
            );
            if damage != "replacement" {
                assert!(
                    Store::open(&dir, std::slice::from_ref(&root)).is_err(),
                    "unsafe {damage} accepted during opening"
                );
            }
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
            store.conn.execute_batch("DROP TABLE quarantine_actions; DROP TABLE retirement_intents; DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; DROP TABLE attribution_gaps; DROP TABLE capture_readiness; DROP TABLE capture_finalizations; DROP TABLE capture_requirements; DROP TABLE capture_runs; DROP TABLE task_finishes; DROP TABLE run_participants; ALTER TABLE run_groups DROP COLUMN child_count; PRAGMA user_version=6;").unwrap();
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
            .execute_batch("DROP TABLE quarantine_actions; DROP TABLE retirement_intents; DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; DROP TABLE attribution_gaps; DROP TABLE capture_readiness; DROP TABLE capture_finalizations; DROP TABLE capture_requirements; DROP TABLE capture_runs; DROP TABLE task_finishes; DROP TABLE run_participants; DROP TABLE adopted_segments; DROP TABLE adopted_sessions; DROP TABLE adopted_groups; DROP TABLE runs; DROP TABLE run_groups; PRAGMA user_version=3")
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
                "DROP TABLE quarantine_actions; DROP TABLE retirement_intents; DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; DROP TABLE attribution_gaps; DROP TABLE capture_readiness; DROP TABLE capture_finalizations; DROP TABLE capture_requirements; DROP TABLE capture_runs; DROP TABLE task_finishes; PRAGMA user_version=8",
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
            17
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
