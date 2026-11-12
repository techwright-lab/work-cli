use super::{commit, database, StoreError};
use rusqlite::Connection;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

const NAME: &str = "store.sqlite";

fn private_directory() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let dir = std::fs::canonicalize(temp.path()).unwrap().join("private");
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    (temp, dir)
}
fn bootstrap(dir: &Path) -> Connection {
    let conn = database(dir, NAME, true, true).unwrap();
    conn.execute_batch("CREATE TABLE entries(value INTEGER); PRAGMA user_version=1;")
        .unwrap();
    conn
}
fn reopen(dir: &Path) -> Connection {
    database(dir, NAME, false, false).unwrap()
}

#[test]
fn every_mutable_open_carries_the_platform_durability_settings() {
    let (_temp, dir) = private_directory();
    let expected = if cfg!(target_os = "macos") {
        [2, 1, 1, 0]
    } else {
        [2, 0, 0, 1000]
    };
    for conn in [bootstrap(&dir), reopen(&dir)] {
        let actual = [
            "synchronous",
            "fullfsync",
            "checkpoint_fullfsync",
            "wal_autocheckpoint",
        ]
        .map(|pragma| {
            conn.query_row(&format!("PRAGMA {pragma}"), [], |r| r.get::<_, i64>(0))
                .unwrap()
        });
        assert_eq!(actual, expected);
    }
}

#[test]
fn failed_commit_is_uncertain_not_an_ordinary_database_error() {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "PRAGMA foreign_keys=ON;
         CREATE TABLE parents(id INTEGER PRIMARY KEY);
         CREATE TABLE children(parent REFERENCES parents(id) DEFERRABLE INITIALLY DEFERRED);",
    )
    .unwrap();
    let tx = conn.transaction().unwrap();
    tx.execute("INSERT INTO children VALUES(1)", []).unwrap();
    assert!(matches!(
        commit(tx),
        Err(StoreError::CommitUncertain(rusqlite::Error::SqliteFailure(
            ..
        )))
    ));
    let tx = conn.transaction().unwrap();
    tx.execute("INSERT INTO parents VALUES(1)", []).unwrap();
    commit(tx).unwrap();
}

#[cfg(target_os = "macos")]
mod darwin {
    use super::super::{sync_dir, verify_darwin_connection};
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;

    fn insert(conn: &Connection) {
        conn.execute("INSERT INTO entries VALUES(1)", []).unwrap();
    }
    #[test]
    fn connection_without_the_darwin_settings_is_refused() {
        let (_temp, dir) = private_directory();
        drop(bootstrap(&dir));
        let plain = Connection::open(dir.join(NAME)).unwrap();
        assert!(matches!(
            verify_darwin_connection(&plain),
            Err(StoreError::Unsafe)
        ));
    }

    #[test]
    fn interrupted_bootstrap_file_is_acknowledged_and_initialized() {
        let (_temp, dir) = private_directory();
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(NAME))
            .unwrap();
        let conn = bootstrap(&dir);
        insert(&conn);
    }

    #[test]
    fn directory_accepts_the_full_sync_acknowledgement() {
        let (_temp, dir) = private_directory();
        sync_dir(&dir).unwrap();
    }
}
