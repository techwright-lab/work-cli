//! Checkout-bound operation exclusion. Non-Clone RAII; never unlinks the lock.
use crate::store::{Result, Store, StoreError};
use rustix::fs::{self as rfs, Mode, OFlags, ResolveFlags};
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use uuid::Uuid;

const LOCK_DIR: &str = "checkout-operations-v1";
const LOCK_RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

pub(crate) struct CheckoutGuard {
    authority: File,
    directory: File,
    file: File,
    authority_id: (u64, u64),
    directory_id: (u64, u64),
    file_id: (u64, u64),
    checkout: Uuid,
    registry: PathBuf,
    directory_path: PathBuf,
    database_id: (u64, u64),
    lock_id: Option<(u64, u64)>,
    exclusive: bool,
    schema: crate::store::InitializationRetention,
}

impl Drop for CheckoutGuard {
    fn drop(&mut self) {
        // CLOEXEC does not close fork-inherited descriptors until exec. Revoke
        // this owner's flock at its lifetime boundary even if such a duplicate
        // still exists. Independently opened SH owners keep their own locks.
        // Drop cannot report failure; normal descriptor close remains fallback.
        let _ = rfs::flock(&self.file, rfs::FlockOperation::Unlock);
    }
}

impl CheckoutGuard {
    pub(crate) fn shared(store: &Store, checkout: Uuid) -> Result<Self> {
        acquire(store, checkout, false)
    }
    pub(crate) fn exclusive(store: &Store, checkout: Uuid) -> Result<Self> {
        acquire(store, checkout, true)
    }
    // Only the existing nonblocking checkout metadata exception is permitted
    // under authority. The actual lease proves Store provenance; its retained
    // schema SH keeps cooperative schema/marker changes excluded.
    pub(crate) fn shared_under_lease(
        store: &Store,
        checkout: Uuid,
        lease: &crate::allocate::AuthorityLease,
    ) -> Result<Self> {
        store.require_outside_sql()?;
        lease.check(store)?;
        let schema = store.schema_participation();
        schema.matches_authority(store.authority_identity())?;
        acquire_validated(
            store.authority_identity(),
            checkout,
            false,
            crate::store::InitializationRetention::Shared(schema),
        )
    }
    pub(crate) fn exclusive_for_migration(
        authority: &std::sync::Arc<crate::store::AuthorityIdentity>,
        initialization: &crate::store::ExclusiveInitialization,
        checkout: Uuid,
    ) -> Result<Self> {
        let schema = crate::store::InitializationRetention::Migration(initialization.retain());
        schema.revalidate()?;
        schema.matches_authority(authority)?;
        acquire_validated(authority, checkout, true, schema)
    }
    pub(crate) fn shared_known(config: &crate::config::Config, checkout: Uuid) -> Result<Self> {
        let registry = config
            .trusted_registry
            .as_deref()
            .ok_or(StoreError::Invalid)?;
        let dir = config.store_dir.as_deref().ok_or(StoreError::Invalid)?;
        let readonly = Store::open_existing_registered_readonly(registry, dir, &config.roots)?;
        // End BEGIN before acquiring filesystem guards, retaining the actual
        // schema owner across that boundary and after this temporary Store dies.
        {
            let _phase = readonly.sql_phase();
            readonly.conn.execute_batch("ROLLBACK;")?;
        }
        Self::shared(&readonly, checkout)
    }
    pub(crate) fn matches_checkout(&self, checkout: Uuid) -> Result<()> {
        if self.checkout != checkout {
            Err(StoreError::Invalid)
        } else {
            Ok(())
        }
    }
    pub(crate) fn exclusive_held(&self) -> bool {
        self.exclusive
    }
    pub(crate) fn revalidate(&self, store: &Store) -> Result<()> {
        store.require_outside_sql()?;
        self.schema.revalidate()?;
        self.revalidate_checkout_metadata(store)
    }
    pub(crate) fn revalidate_under_lease(
        &self,
        store: &Store,
        lease: &crate::allocate::AuthorityLease,
    ) -> Result<()> {
        store.require_outside_sql()?;
        lease.check(store)?;
        self.revalidate_checkout_metadata(store)
    }
    fn revalidate_checkout_metadata(&self, store: &Store) -> Result<()> {
        self.schema.matches_authority(store.authority_identity())?;
        let identity = store.authority_identity();
        if identity.registry() != self.registry.as_path()
            || identity.directory != self.directory_path
            || identity.database_id() != self.database_id
        {
            return Err(StoreError::Invalid);
        }
        match (identity.lock_id, self.lock_id) {
            (Some(current), Some(original)) if current != original => {
                return Err(StoreError::Invalid);
            }
            (None, Some(_)) => return Err(StoreError::Invalid),
            _ => {}
        }
        if identity.directory_id != self.authority_id {
            return Err(StoreError::Invalid);
        }
        let authority = open_authority(store.authority_identity())?;
        lock_directory_meta(&self.authority)?;
        lock_directory_meta(&authority)?;
        if lock_identity(&self.authority)? != self.authority_id
            || lock_identity(&authority)? != self.authority_id
        {
            return Err(StoreError::Invalid);
        }
        let named_dir = open_child(&authority, LOCK_DIR, OFlags::RDONLY | OFlags::DIRECTORY)?;
        lock_directory_meta(&self.directory)?;
        lock_directory_meta(&named_dir)?;
        let name = lock_name(self.checkout);
        let named_file = open_child(&named_dir, &name, OFlags::RDONLY)?;
        lock_file_meta(&self.file)?;
        lock_file_meta(&named_file)?;
        if lock_identity(&named_dir)? != self.directory_id
            || lock_identity(&self.directory)? != self.directory_id
            || lock_identity(&named_file)? != self.file_id
            || lock_identity(&self.file)? != self.file_id
        {
            return Err(StoreError::Invalid);
        }
        Ok(())
    }
    pub(crate) fn require_matching(&self, store: &Store, checkout: Uuid) -> Result<()> {
        self.matches_checkout(checkout)?;
        self.revalidate(store)
    }
    pub(crate) fn require_matching_under_lease(
        &self,
        store: &Store,
        checkout: Uuid,
        lease: &crate::allocate::AuthorityLease,
    ) -> Result<()> {
        self.matches_checkout(checkout)?;
        self.revalidate_under_lease(store, lease)
    }
}

fn acquire(store: &Store, checkout: Uuid, exclusive: bool) -> Result<CheckoutGuard> {
    store.require_outside_sql()?;
    let schema = store.schema_participation();
    schema.revalidate()?;
    schema.matches_authority(store.authority_identity())?;
    acquire_validated(
        store.authority_identity(),
        checkout,
        exclusive,
        crate::store::InitializationRetention::Shared(schema),
    )
}
// Private shared mechanism receives the actual owner validated by one of the
// two purpose-specific entry points above, never a validation-bypass flag.
fn acquire_validated(
    identity: &crate::store::AuthorityIdentity,
    checkout: Uuid,
    exclusive: bool,
    schema: crate::store::InitializationRetention,
) -> Result<CheckoutGuard> {
    crate::retirement_journal::parse_uuid(&checkout.to_string())?;
    let authority = open_authority(identity)?;
    let authority_id = lock_identity(&authority)?;
    match rfs::mkdirat(&authority, LOCK_DIR, Mode::from_raw_mode(0o700)) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::EXIST => {}
        Err(_) => return Err(StoreError::Unsafe),
    }
    let directory = open_child(&authority, LOCK_DIR, OFlags::RDONLY | OFlags::DIRECTORY)?;
    lock_directory_meta(&directory)?;
    let named_dir = open_child(&authority, LOCK_DIR, OFlags::PATH | OFlags::DIRECTORY)?;
    if lock_identity(&named_dir)? != lock_identity(&directory)? {
        return Err(StoreError::Unsafe);
    }
    let name = lock_name(checkout);
    let file = rfs::openat2(
        &directory,
        name.as_str(),
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::from_raw_mode(0o600),
        LOCK_RESOLVE,
    )
    .map(File::from)
    .map_err(|_| StoreError::Unsafe)?;
    lock_file_meta(&file)?;
    let named_file = open_child(&directory, &name, OFlags::PATH)?;
    if lock_identity(&named_file)? != lock_identity(&file)? {
        return Err(StoreError::Unsafe);
    }
    let op = if exclusive {
        rfs::FlockOperation::NonBlockingLockExclusive
    } else {
        rfs::FlockOperation::NonBlockingLockShared
    };
    match rfs::flock(&file, op) {
        Ok(()) => Ok(CheckoutGuard {
            authority,
            directory,
            file,
            authority_id,
            directory_id: lock_identity(&named_dir)?,
            file_id: lock_identity(&named_file)?,
            checkout,
            registry: identity.registry().to_path_buf(),
            directory_path: identity.directory.clone(),
            database_id: identity.database_id(),
            lock_id: identity.lock_id,
            exclusive,
            schema,
        }),
        Err(e) if e == rustix::io::Errno::WOULDBLOCK => Err(StoreError::OperationsInFlight),
        Err(_) => Err(StoreError::Unsafe),
    }
}

fn lock_name(checkout: Uuid) -> String {
    format!("{checkout}.lock")
}

fn lock_identity(file: &File) -> Result<(u64, u64)> {
    let meta = file.metadata().map_err(|_| StoreError::Unsafe)?;
    Ok((meta.dev(), meta.ino()))
}

fn lock_directory_meta(file: &File) -> Result<()> {
    let meta = file.metadata().map_err(|_| StoreError::Unsafe)?;
    if !meta.is_dir()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o7777 != 0o700
    {
        return Err(StoreError::Unsafe);
    }
    Ok(())
}

fn lock_file_meta(file: &File) -> Result<()> {
    let meta = file.metadata().map_err(|_| StoreError::Unsafe)?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o7777 != 0o600
    {
        return Err(StoreError::Unsafe);
    }
    Ok(())
}

fn open_authority(identity: &crate::store::AuthorityIdentity) -> Result<File> {
    let directory = rfs::openat2(
        rfs::CWD,
        identity.directory.as_path(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(|_| StoreError::Unsafe)?;
    let meta = directory.metadata().map_err(|_| StoreError::Unsafe)?;
    if !meta.is_dir()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o7777 != 0o700
        || (meta.dev(), meta.ino()) != identity.directory_id
    {
        return Err(StoreError::Unsafe);
    }
    Ok(directory)
}

fn open_child(parent: &File, name: &str, flags: OFlags) -> Result<File> {
    let additional = if flags.contains(OFlags::PATH) {
        OFlags::empty()
    } else {
        OFlags::NONBLOCK
    };
    rfs::openat2(
        parent,
        name,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW | additional,
        Mode::empty(),
        LOCK_RESOLVE,
    )
    .map(File::from)
    .map_err(|_| StoreError::Unsafe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::mpsc;
    use std::thread;

    fn open_pair() -> (
        tempfile::TempDir,
        Store,
        Store,
        uuid::Uuid,
        std::path::PathBuf,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let dir = temp.path().join("private");
        let store = Store::open(&dir, std::slice::from_ref(&root)).unwrap();
        let registry = dir.parent().unwrap().join(".work-authorities");
        let other =
            Store::open_existing_registered_mut(&registry, &dir, std::slice::from_ref(&root))
                .unwrap();
        let checkout = uuid::Uuid::now_v7();
        (temp, store, other, checkout, root)
    }

    #[test]
    fn shared_guards_coexist() {
        let (_temp, store, other, checkout, _) = open_pair();
        let first = CheckoutGuard::shared(&store, checkout).unwrap();
        let second = CheckoutGuard::shared(&other, checkout).unwrap();
        first.revalidate(&store).unwrap();
        second.revalidate(&other).unwrap();
    }

    #[test]
    fn exclusive_contends_with_shared_without_retry() {
        let (_temp, store, other, checkout, _) = open_pair();
        let shared = CheckoutGuard::shared(&store, checkout).unwrap();
        assert!(matches!(
            CheckoutGuard::exclusive(&other, checkout),
            Err(StoreError::OperationsInFlight)
        ));
        drop(shared);
        CheckoutGuard::exclusive(&other, checkout).unwrap();
    }

    #[test]
    fn drop_unlocks_even_when_an_inherited_descriptor_remains_open() {
        for exclusive in [false, true] {
            let (_temp, store, other, checkout, _) = open_pair();
            let guard = if exclusive {
                CheckoutGuard::exclusive(&store, checkout).unwrap()
            } else {
                CheckoutGuard::shared(&store, checkout).unwrap()
            };
            // dup and fork inheritance retain the same open-file description.
            // No second operation guard or permission is created by this handle.
            let inherited = guard.file.try_clone().unwrap();
            drop(guard);
            let next = CheckoutGuard::exclusive(&other, checkout).unwrap();
            assert!(inherited.metadata().unwrap().is_file());
            drop(inherited);
            assert!(matches!(
                CheckoutGuard::shared(&store, checkout),
                Err(StoreError::OperationsInFlight)
            ));
            drop(next);
            CheckoutGuard::shared(&store, checkout).unwrap();
        }
    }

    #[test]
    fn dropping_one_shared_owner_does_not_unlock_another() {
        let (_temp, store, other, checkout, _) = open_pair();
        let first = CheckoutGuard::shared(&store, checkout).unwrap();
        let second = CheckoutGuard::shared(&other, checkout).unwrap();
        let inherited = first.file.try_clone().unwrap();
        drop(first);
        assert!(matches!(
            CheckoutGuard::exclusive(&store, checkout),
            Err(StoreError::OperationsInFlight)
        ));
        drop(second);
        let exclusive = CheckoutGuard::exclusive(&store, checkout).unwrap();
        assert!(inherited.metadata().unwrap().is_file());
        drop(inherited);
        assert!(matches!(
            CheckoutGuard::shared(&other, checkout),
            Err(StoreError::OperationsInFlight)
        ));
        drop(exclusive);
    }

    #[test]
    fn exclusive_contends_across_threads_with_barriers() {
        let (_temp, store, other, checkout, _) = open_pair();
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let handle = thread::spawn(move || {
            let guard = CheckoutGuard::exclusive(&other, checkout).unwrap();
            ready_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(guard);
        });
        ready_rx.recv().unwrap();
        assert!(matches!(
            CheckoutGuard::shared(&store, checkout),
            Err(StoreError::OperationsInFlight)
        ));
        release_tx.send(()).unwrap();
        handle.join().unwrap();
        CheckoutGuard::shared(&store, checkout).unwrap();
    }

    #[test]
    fn identity_continues_across_readonly_and_mutable_reopen() {
        let (temp, store, _, checkout, root) = open_pair();
        let dir = temp.path().join("private");
        let registry = dir.parent().unwrap().join(".work-authorities");
        let readonly =
            Store::open_existing_registered_readonly(&registry, &dir, std::slice::from_ref(&root))
                .unwrap();
        {
            let _phase = readonly.sql_phase();
            readonly.conn.execute_batch("ROLLBACK;").unwrap();
        }
        let guard = CheckoutGuard::shared(&readonly, checkout).unwrap();
        guard.revalidate(&store).unwrap();
        let mut_again =
            Store::open_existing_registered_mut(&registry, &dir, std::slice::from_ref(&root))
                .unwrap();
        guard.revalidate(&mut_again).unwrap();
    }

    #[test]
    fn directory_replacement_fails_revalidation() {
        let (_temp, store, _, checkout, _) = open_pair();
        let guard = CheckoutGuard::shared(&store, checkout).unwrap();
        let path = store.authority_identity().directory.join(LOCK_DIR);
        std::fs::remove_dir_all(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(guard.revalidate(&store).is_err());
    }

    #[test]
    fn symlink_lock_is_refused() {
        let (_temp, store, _, checkout, _) = open_pair();
        let authority = store.authority_identity().directory.clone();
        let dir = authority.join(LOCK_DIR);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink("/tmp", dir.join(format!("{checkout}.lock"))).unwrap();
        assert!(CheckoutGuard::shared(&store, checkout).is_err());
    }

    #[test]
    fn hardlink_lock_is_refused() {
        let (_temp, store, _, checkout, _) = open_pair();
        let authority = store.authority_identity().directory.clone();
        let dir = authority.join(LOCK_DIR);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let lock = dir.join(format!("{checkout}.lock"));
        std::fs::File::create(&lock).unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&lock, dir.join("extra.lock")).unwrap();
        assert!(CheckoutGuard::shared(&store, checkout).is_err());
    }

    #[test]
    fn mode_refusal() {
        let (_temp, store, _, checkout, _) = open_pair();
        let authority = store.authority_identity().directory.clone();
        let dir = authority.join(LOCK_DIR);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(CheckoutGuard::shared(&store, checkout).is_err());
    }

    #[test]
    fn require_matching_refuses_unrelated_checkout() {
        let (_temp, store, _, checkout, _) = open_pair();
        let guard = CheckoutGuard::shared(&store, checkout).unwrap();
        assert!(matches!(
            guard.require_matching(&store, uuid::Uuid::now_v7()),
            Err(StoreError::Invalid)
        ));
        guard.require_matching(&store, checkout).unwrap();
    }
}
