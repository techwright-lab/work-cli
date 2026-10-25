//! Native schema-owner regressions. W1A behavioral RED was observed in parent CI;
//! W1B API/lifetime cases are authored tests awaiting isolated CI.
use super::{Store, StoreError};
use std::{
    fs,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExclusiveProbe {
    Acquired,
    Blocked,
}

/// Independently open ONLY the existing qualified initialization lock. Never
/// open a Store, create metadata, or take SH to manufacture a positive result.
/// Release a successful EX immediately so callers can finish cleanup before
/// asserting the recorded outcome. All non-contention errors remain errors.
pub(crate) fn probe_initialization_exclusive(registry: &Path) -> super::Result<ExclusiveProbe> {
    super::existing_directory(registry)?;
    let path = registry.join("initialization.lock");
    super::check_file(&path)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(&path)?;
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
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {
            rustix::fs::flock(&file, rustix::fs::FlockOperation::Unlock)
                .map_err(std::io::Error::from)?;
            Ok(ExclusiveProbe::Acquired)
        }
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(ExclusiveProbe::Blocked),
        Err(error) => Err(std::io::Error::from(error).into()),
    }
}

fn initialized() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    Store,
) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    fs::create_dir(&root).unwrap();
    let registry = temp.path().join("registry");
    let directory = temp.path().join("private");
    let store = Store::open_registered(&registry, &directory, std::slice::from_ref(&root)).unwrap();
    (temp, registry, directory, root, store)
}

// Observe the actual full schema filesystem entry, never a caller-supplied
// semantic permission. Per-thread RAII keeps unrelated fixtures independent.
type SchemaFsObserver = Box<dyn FnMut(&Path)>;
thread_local! {
    static SCHEMA_FS_OBSERVER: std::cell::RefCell<Option<SchemaFsObserver>> =
        const { std::cell::RefCell::new(None) };
}
struct SchemaFsObservation;
impl SchemaFsObservation {
    fn install(observer: impl FnMut(&Path) + 'static) -> Self {
        SCHEMA_FS_OBSERVER.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(Box::new(observer));
        });
        Self
    }
}
impl Drop for SchemaFsObservation {
    fn drop(&mut self) {
        SCHEMA_FS_OBSERVER.with(|slot| *slot.borrow_mut() = None);
    }
}
pub(super) fn observe_schema_fs(directory: &Path) {
    SCHEMA_FS_OBSERVER.with(|slot| {
        if let Some(observer) = slot.borrow_mut().as_mut() {
            observer(directory);
        }
    });
}
fn probe_authority_exclusive(directory: &Path) -> super::Result<ExclusiveProbe> {
    let file = super::AuthorityIdentity::open_lock(directory, false)?;
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {
            rustix::fs::flock(&file, rustix::fs::FlockOperation::Unlock)
                .map_err(std::io::Error::from)?;
            Ok(ExclusiveProbe::Acquired)
        }
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(ExclusiveProbe::Blocked),
        Err(error) => Err(std::io::Error::from(error).into()),
    }
}

#[test]
fn borrowed_checkout_lease_keeps_schema_filesystem_outside_authority() {
    use crate::checkout_guard::CheckoutGuard;
    let (_temp, registry, directory, root, store) = initialized();
    let other = Store::open_registered(&registry, &directory, &[root]).unwrap();
    let checkout = uuid::Uuid::now_v7();
    let observations = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let observed = observations.clone();
    let observer = SchemaFsObservation::install(move |directory| {
        observed
            .borrow_mut()
            .push(probe_authority_exclusive(directory));
    });
    let ordinary = CheckoutGuard::shared(&store, checkout).unwrap();
    ordinary.revalidate(&store).unwrap();
    let unleased_count = observations.borrow().len();
    assert_eq!(
        unleased_count, 2,
        "ordinary guard calls must validate actual schema metadata"
    );
    let lease = store.authority_lease().unwrap();
    let before_borrow = observations.borrow().len();
    assert_eq!(
        before_borrow,
        unleased_count + 1,
        "lease validates schema before flock"
    );
    let held_probe = probe_authority_exclusive(&directory);
    let guard = CheckoutGuard::shared_under_lease(&store, checkout, &lease).unwrap();
    guard.revalidate_under_lease(&store, &lease).unwrap();
    guard
        .require_matching_under_lease(&store, checkout, &lease)
        .unwrap();
    assert!(CheckoutGuard::shared_under_lease(&other, checkout, &lease).is_err());
    assert!(guard.revalidate_under_lease(&other, &lease).is_err());
    assert!(guard
        .require_matching_under_lease(&store, uuid::Uuid::now_v7(), &lease)
        .is_err());
    let phase = store.sql_phase();
    assert!(CheckoutGuard::shared_under_lease(&store, checkout, &lease).is_err());
    assert!(guard.revalidate_under_lease(&store, &lease).is_err());
    drop(phase);
    store.conn.execute_batch("BEGIN;").unwrap();
    assert!(CheckoutGuard::shared_under_lease(&store, checkout, &lease).is_err());
    assert!(guard.revalidate_under_lease(&store, &lease).is_err());
    store.conn.execute_batch("ROLLBACK;").unwrap();
    // Cached schema validation must not suppress the existing narrow checkout
    // metadata recheck. Rename only the checkout lock, never schema metadata.
    let lock = directory
        .join("checkout-operations-v1")
        .join(format!("{checkout}.lock"));
    fs::rename(&lock, lock.with_extension("saved")).unwrap();
    assert!(guard.revalidate_under_lease(&store, &lease).is_err());
    assert_eq!(
        observations.borrow().len(),
        before_borrow,
        "no full schema FS under borrowed authority"
    );
    drop(guard);
    drop(ordinary);
    drop(lease);
    let released_probe = probe_authority_exclusive(&directory);
    // Negative control: invalid actual marker bytes are refused by the full
    // pre-lease validation, with authority still free at its entry.
    fs::write(registry.join("initialization.json"), b"{}").unwrap();
    assert!(store.authority_lease().is_err());
    assert_eq!(observations.borrow().len(), before_borrow + 1);
    drop(observer);
    assert_eq!(held_probe.unwrap(), ExclusiveProbe::Blocked);
    assert_eq!(released_probe.unwrap(), ExclusiveProbe::Acquired);
    for observation in observations.borrow_mut().drain(..) {
        assert_eq!(observation.unwrap(), ExclusiveProbe::Acquired);
    }
}

#[test]
fn checkout_metadata_requires_caller_to_close_readonly_begin() {
    use crate::checkout_guard::CheckoutGuard;
    let (_temp, registry, directory, root, store) = initialized();
    drop(store);
    let readonly =
        Store::open_existing_registered_readonly(&registry, &directory, &[root]).unwrap();
    let checkout = uuid::Uuid::now_v7();
    assert!(!readonly.conn.is_autocommit());
    assert!(CheckoutGuard::exclusive(&readonly, checkout).is_err());
    assert!(
        !directory.join("checkout-operations-v1").exists(),
        "refusal precedes checkout metadata"
    );
    {
        let _phase = readonly.sql_phase();
        readonly.conn.execute_batch("ROLLBACK;").unwrap();
        assert!(
            CheckoutGuard::exclusive(&readonly, checkout).is_err(),
            "armed SQL phase also refuses"
        );
    }
    let guard = CheckoutGuard::exclusive(&readonly, checkout).unwrap();
    drop(readonly);
    let retained = probe_initialization_exclusive(&registry);
    drop(guard);
    assert_eq!(retained.unwrap(), ExclusiveProbe::Blocked);
    assert_eq!(
        probe_initialization_exclusive(&registry).unwrap(),
        ExclusiveProbe::Acquired
    );
}

#[test]
fn duplicate_fd_does_not_extend_owner_or_unlock_independent_owner() {
    let (_temp, registry, directory, root, first) = initialized();
    let retained = first.schema_participation();
    let duplicate = retained.0.file.try_clone().unwrap();
    let second =
        Store::open_registered(&registry, &directory, std::slice::from_ref(&root)).unwrap();
    // Ordinary DML stays concurrent with both schema owners and does not change
    // the stable metadata binding (WAL sizes and timestamps are not epochs).
    second
        .conn
        .execute("INSERT INTO retired_owners VALUES ('schema-test')", [])
        .unwrap();
    retained.revalidate().unwrap();
    drop(first);
    let retained_alive = probe_initialization_exclusive(&registry);
    drop(retained);
    let independent_alive = probe_initialization_exclusive(&registry);
    drop(second);
    let last_dropped = probe_initialization_exclusive(&registry);
    assert!(duplicate.metadata().unwrap().is_file());
    drop(duplicate);
    assert_eq!(retained_alive.unwrap(), ExclusiveProbe::Blocked);
    assert_eq!(independent_alive.unwrap(), ExclusiveProbe::Blocked);
    assert_eq!(last_dropped.unwrap(), ExclusiveProbe::Acquired);
}

#[test]
fn no_create_missing_or_replaced_initialization_refuses() {
    let missing = tempfile::tempdir().unwrap();
    let registry = missing.path().join("absent");
    assert!(super::SchemaParticipation::open_existing(&registry).is_err());
    assert!(!registry.exists());
    for name in [
        "initialization.lock",
        "initialization.json",
        "authorities.sqlite",
    ] {
        let (_temp, registry, directory, root, store) = initialized();
        let owner = store.schema_participation();
        let path = registry.join(name);
        let saved = registry.join(format!("{name}.saved"));
        fs::rename(&path, &saved).unwrap();
        assert!(owner.revalidate().is_err());
        assert!(Store::open_existing_registered_readonly(
            &registry,
            &directory,
            std::slice::from_ref(&root)
        )
        .is_err());
        assert!(!path.exists(), "readonly must not recreate {name}");
        fs::copy(&saved, &path).unwrap();
        assert!(
            owner.revalidate().is_err(),
            "a new inode cannot replace {name}"
        );
        drop(owner);
        drop(store);
    }
}

#[test]
fn corrupt_missing_marker_never_manufactures_initialization_lock() {
    let (_temp, registry, directory, root, store) = initialized();
    drop(store);
    fs::remove_file(registry.join("initialization.json")).unwrap();
    fs::remove_file(registry.join("initialization.lock")).unwrap();
    assert!(Store::open_registered(&registry, &directory, std::slice::from_ref(&root)).is_err());
    assert!(!registry.join("initialization.lock").exists());
    assert!(!registry.join("initialization.json").exists());
}

#[test]
fn checkout_and_authority_owners_outlive_their_store() {
    let (_temp, registry, _directory, _root, store) = initialized();
    let guard = crate::checkout_guard::CheckoutGuard::shared(&store, uuid::Uuid::now_v7()).unwrap();
    let lease = store.authority_lease().unwrap();
    drop(store);
    let both = probe_initialization_exclusive(&registry);
    drop(lease);
    let checkout_only = probe_initialization_exclusive(&registry);
    drop(guard);
    let released = probe_initialization_exclusive(&registry);
    assert_eq!(both.unwrap(), ExclusiveProbe::Blocked);
    assert_eq!(checkout_only.unwrap(), ExclusiveProbe::Blocked);
    assert_eq!(released.unwrap(), ExclusiveProbe::Acquired);
}

#[test]
fn finish_upgrade_never_recursively_upgrades_shared_owner() {
    let (_temp, registry, directory, root, store) = initialized();
    // Genuine schema15, not a version-only downgrade with modern tables left.
    store
        .conn
        .execute_batch("DROP TABLE retirement_intents; PRAGMA user_version=15;")
        .unwrap();
    drop(store);
    let upgraded =
        Store::open_finish_authority(&registry, &directory, std::slice::from_ref(&root)).unwrap();
    let version: i64 = upgraded
        .conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    let owned = probe_initialization_exclusive(&registry);
    drop(upgraded);
    assert_eq!(version, 16);
    assert_eq!(owned.unwrap(), ExclusiveProbe::Blocked);
    assert_eq!(
        probe_initialization_exclusive(&registry).unwrap(),
        ExclusiveProbe::Acquired
    );
}

#[test]
fn exclusive_handoff_discards_observations() {
    let (_temp, registry, directory, root, store) = initialized();
    store
        .conn
        .execute_batch("DROP TABLE retirement_intents; PRAGMA user_version=15;")
        .unwrap();
    drop(store);
    let probe_registry = registry.clone();
    let database = directory.join("store.sqlite");
    let reached = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = reached.clone();
    let hook = super::schema_handoff_fixture::install(move || {
        assert_eq!(
            probe_initialization_exclusive(&probe_registry).unwrap(),
            ExclusiveProbe::Acquired
        );
        observed.set(true);
        let conn = rusqlite::Connection::open(&database).unwrap();
        conn.execute_batch("PRAGMA user_version=0;").unwrap();
    });
    let result = Store::open_registered(&registry, &directory, std::slice::from_ref(&root));
    drop(hook);
    assert!(
        reached.get(),
        "the actual EX-to-fresh-SH gap must be reached"
    );
    assert!(
        result.is_err(),
        "pre-handoff schema observations cannot be returned"
    );
    assert_eq!(
        probe_initialization_exclusive(&registry).unwrap(),
        ExclusiveProbe::Acquired
    );
}

#[test]
fn shared_owners_are_concurrent_and_last_drop_unlocks() {
    // Same genuine bootstrap shape as the adjacent Store tests; no Git or
    // synthetic owner is needed to exercise the existing public openers.
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    fs::create_dir(&root).unwrap();
    let directory = temp.path().join("private");
    let registry = temp.path().join("registry");
    let roots = std::slice::from_ref(&root);
    let first = Store::open_registered(&registry, &directory, roots).unwrap();
    let version: i64 = first
        .conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let first_alive = probe_initialization_exclusive(&registry);

    // A normal established open must succeed while the first Store is alive;
    // retaining initialization EX on ordinary Stores is not a valid fix.
    let second = Store::open_registered(&registry, &directory, roots);
    let second_error = second.as_ref().err().map(ToString::to_string);
    let both_alive = probe_initialization_exclusive(&registry);
    drop(first);
    let second_alive = probe_initialization_exclusive(&registry);
    drop(second);
    let all_dropped = probe_initialization_exclusive(&registry);

    assert_eq!(version, 16, "W1 does not change the schema version");
    assert_eq!(second_error, None, "established participants must coexist");
    assert_eq!(all_dropped.unwrap(), ExclusiveProbe::Acquired);
    assert_eq!(first_alive.unwrap(), ExclusiveProbe::Blocked);
    assert_eq!(both_alive.unwrap(), ExclusiveProbe::Blocked);
    assert_eq!(second_alive.unwrap(), ExclusiveProbe::Blocked);
}
