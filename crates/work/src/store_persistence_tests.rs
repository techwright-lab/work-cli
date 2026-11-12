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

#[test]
fn failed_commit_on_the_allocation_paths_keeps_the_sqlite_text() {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "PRAGMA foreign_keys=ON;
         CREATE TABLE parents(id INTEGER PRIMARY KEY);
         CREATE TABLE children(parent REFERENCES parents(id) DEFERRABLE INITIALLY DEFERRED);",
    )
    .unwrap();
    let tx = conn.transaction().unwrap();
    tx.execute("INSERT INTO children VALUES(1)", []).unwrap();
    let error = crate::allocate::commit(tx).unwrap_err();
    assert_eq!(error.to_string(), "FOREIGN KEY constraint failed");
    assert!(error
        .get_ref()
        .is_some_and(|inner| !inner.is::<StoreError>()));
}

#[cfg(target_os = "macos")]
mod darwin {
    use super::super::{
        checkpoint_checked, require_complete_checkpoint, require_darwin_full_sync, sync_dir,
        verify_darwin_connection, Checkpoint, CheckpointMode,
    };
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;

    fn insert(conn: &Connection) {
        conn.execute("INSERT INTO entries VALUES(1)", []).unwrap();
    }
    fn wal_bytes(dir: &Path) -> u64 {
        std::fs::metadata(dir.join(format!("{NAME}-wal")))
            .unwrap()
            .len()
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

    // A journal copied from under its live writer has no lock holder: hot.
    // Without sync the writer stamps the journal header valid at once.
    fn hot_journal(dir: &Path) -> PathBuf {
        let (_source, source) = private_directory();
        let writer = Connection::open(source.join(NAME)).unwrap();
        writer
            .execute_batch(
                "PRAGMA synchronous=OFF;
                 CREATE TABLE entries(value INTEGER); INSERT INTO entries VALUES(1);
                 BEGIN; UPDATE entries SET value=2;",
            )
            .unwrap();
        let journal = format!("{NAME}-journal");
        for name in [NAME, journal.as_str()] {
            std::fs::copy(source.join(name), dir.join(name)).unwrap();
            std::fs::set_permissions(
                dir.join(name),
                std::os::unix::fs::PermissionsExt::from_mode(0o600),
            )
            .unwrap();
        }
        dir.join(journal)
    }

    #[test]
    fn full_sync_is_in_force_before_a_hot_journal_is_played_back() {
        let (_temp, dir) = private_directory();
        let journal = hot_journal(&dir);
        let conn = Connection::open(dir.join(NAME)).unwrap();
        require_darwin_full_sync(&conn).unwrap();
        assert!(journal.exists(), "configuration must not read the database");
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 0);
        assert!(!journal.exists(), "the first read plays the journal back");
    }

    #[test]
    fn interrupted_bootstrap_with_a_hot_journal_resumes_under_the_darwin_settings() {
        let (_temp, dir) = private_directory();
        let journal = hot_journal(&dir);
        let conn = database(&dir, NAME, true, true).unwrap();
        assert!(!journal.exists());
        verify_darwin_connection(&conn).unwrap();
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

    #[test]
    fn unobstructed_checkpoint_reports_every_frame_and_truncates_the_wal() {
        let (_temp, dir) = private_directory();
        let conn = bootstrap(&dir);
        insert(&conn);
        let passive = checkpoint_checked(&conn, CheckpointMode::Passive).unwrap();
        assert!(!passive.busy && passive.log > 0 && passive.checkpointed == passive.log);
        require_complete_checkpoint(passive).unwrap();
        assert!(wal_bytes(&dir) > 0);
        let truncated = checkpoint_checked(&conn, CheckpointMode::Truncate).unwrap();
        assert_eq!(
            truncated,
            Checkpoint {
                busy: false,
                log: 0,
                checkpointed: 0
            }
        );
        require_complete_checkpoint(truncated).unwrap();
        assert_eq!(wal_bytes(&dir), 0);
    }

    #[test]
    fn checkpoint_behind_a_held_reader_is_reported_and_refused() {
        let (_temp, dir) = private_directory();
        let writer = bootstrap(&dir);
        insert(&writer);
        let reader = reopen(&dir);
        reader
            .execute_batch("BEGIN; SELECT count(*) FROM entries;")
            .unwrap();
        insert(&writer);

        let passive = checkpoint_checked(&writer, CheckpointMode::Passive).unwrap();
        assert!(!passive.busy && passive.checkpointed < passive.log);
        assert!(matches!(
            require_complete_checkpoint(passive),
            Err(StoreError::CheckpointIncomplete)
        ));
        let truncate = checkpoint_checked(&writer, CheckpointMode::Truncate).unwrap();
        assert!(truncate.busy);
        assert!(matches!(
            require_complete_checkpoint(truncate),
            Err(StoreError::CheckpointIncomplete)
        ));
        assert!(wal_bytes(&dir) > 0);

        reader.execute_batch("ROLLBACK;").unwrap();
        require_complete_checkpoint(checkpoint_checked(&writer, CheckpointMode::Truncate).unwrap())
            .unwrap();
        assert_eq!(wal_bytes(&dir), 0);
    }

    #[test]
    fn checkpoint_outside_wal_mode_is_refused() {
        let conn = Connection::open_in_memory().unwrap();
        assert!(matches!(
            checkpoint_checked(&conn, CheckpointMode::Passive),
            Err(StoreError::Unsafe)
        ));
    }
}
