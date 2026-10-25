//! Authored tests only; behavioral RED requires future isolated CI execution.
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
