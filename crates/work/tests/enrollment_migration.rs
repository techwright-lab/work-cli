#[path = "support/run_fixture.rs"]
mod support;
use rusqlite::Connection;
use support::*;
const V7: &str = "DROP TABLE capture_requirements; DROP TABLE capture_runs; DROP TABLE task_finishes; ALTER TABLE run_participants RENAME TO v8_children;
CREATE TABLE run_participants(id TEXT PRIMARY KEY, group_id TEXT NOT NULL REFERENCES run_groups(id), run_ref TEXT NOT NULL UNIQUE, parent_run TEXT NOT NULL, request TEXT NOT NULL, enrollment TEXT NOT NULL CHECK(enrollment IN ('pending','unverified')), outcome TEXT, depth INTEGER NOT NULL CHECK(depth BETWEEN 1 AND 16));
INSERT INTO run_participants SELECT id,group_id,run_ref,parent_run,request,enrollment,outcome,depth FROM v8_children ORDER BY rowid;
DROP TABLE v8_children; PRAGMA user_version=7;";
fn rows(sql: &Connection, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
    let mut s = sql
        .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
        .unwrap();
    let n = s.column_count();
    s.query_map([], |r| (0..n).map(|i| r.get(i)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}
#[test]
fn v7_to_v8_preserves_mixed_child_tree_outcomes_and_every_other_table() {
    use work_cli::run_participants::{ChildOutcome, ChildRequest};
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let mut parent = r.identity().run.clone();
    let mut parent_ref = r.identity().run_ref.clone();
    for index in 0..3 {
        let c:ChildRequest=serde_json::from_value(serde_json::json!({"checkout":r.identity().checkout,"group":r.identity().group,"run":work_contract::RunId::generate(),"run_ref":format!("child:{index}"),"parent_run":parent,"parent_run_ref":parent_ref,"execution_chain":r.identity().execution_chain,"source":null,"session":null,"agent":null,"actor":null,"expected_host":if index==2 {serde_json::Value::Null} else {serde_json::json!({"boot":BOOT,"pid":42,"start_ticks":10})}})).unwrap();
        store.register_child(&r, &c).unwrap();
        if index == 1 {
            store
                .record_child_outcome(&r, &c, ChildOutcome::Failed)
                .unwrap();
            store.record_child_hold(&r, &c).unwrap();
        }
        parent = c.run;
        parent_ref = c.run_ref;
    }
    let before = store.run_snapshot(&r.identity().run).unwrap().unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch(V7).unwrap();
    let tables = [
        "checkouts",
        "writers",
        "runs",
        "run_groups",
        "adopted_groups",
        "adopted_sessions",
        "adopted_segments",
        "repository_aliases",
        "outbox",
    ];
    let old = tables.iter().map(|t| rows(&sql, t)).collect::<Vec<_>>();
    drop(store);
    let store = reopen(&dir).unwrap();
    assert_eq!(
        store.run_snapshot(&r.identity().run).unwrap().unwrap(),
        before
    );
    assert_eq!(
        tables.iter().map(|t| rows(&sql, t)).collect::<Vec<_>>(),
        old
    );
    assert_eq!(
        sql.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        11
    );
}
#[test]
fn malformed_enrollment_schema_fails_open_and_existing_reads_closed() {
    for corrupt in ["view", "missing", "malformed"] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        store.begin_run(&r).unwrap();
        let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        sql.execute_batch("ALTER TABLE run_participants RENAME TO old_children")
            .unwrap();
        match corrupt {
            "view" => sql
                .execute_batch("CREATE VIEW run_participants AS SELECT * FROM old_children")
                .unwrap(),
            "malformed" => sql
                .execute_batch("CREATE TABLE run_participants AS SELECT * FROM old_children")
                .unwrap(),
            _ => (),
        }
        assert!(
            store.run_snapshot(&r.identity().run).is_err(),
            "existing read {corrupt}"
        );
        assert!(reopen(&dir).is_err(), "open {corrupt}");
    }
}
#[test]
fn malformed_v7_table_is_not_silently_rebuilt_into_a_valid_enrollment_schema() {
    let (dir, store, _checkout) = fixture();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch(V7).unwrap();
    sql.execute_batch("ALTER TABLE run_participants RENAME TO old_children; CREATE TABLE run_participants AS SELECT * FROM old_children; DROP TABLE old_children;").unwrap();
    drop(store);
    assert!(reopen(&dir).is_err());
    assert_eq!(
        sql.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        7
    );
}
#[test]
fn failed_v7_migration_rolls_back_every_table_without_repair() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch(V7).unwrap();
    sql.execute_batch("CREATE TRIGGER prevent_child_drop AFTER DELETE ON run_participants BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    // Occupied rebuild name must abort rather than overwrite or discard it.
    sql.execute_batch("CREATE TABLE run_participants_v7(sentinel TEXT); INSERT INTO run_participants_v7 VALUES('retain')").unwrap();
    let old = rows(&sql, "outbox");
    drop(store);
    assert!(reopen(&dir).is_err());
    assert_eq!(
        sql.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        7
    );
    assert_eq!(rows(&sql, "outbox"), old);
    assert_eq!(
        sql.query_row("SELECT sentinel FROM run_participants_v7", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "retain"
    );
}
