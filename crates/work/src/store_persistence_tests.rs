use super::{commit, StoreError};
use rusqlite::Connection;

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
