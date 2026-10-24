use crate::{
    admission::{Limits, Reservation},
    run_journal::RootRunRequest,
    store::Store,
};
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use std::{sync::mpsc, time::Duration};
use uuid::Uuid;

// Disposable current-schema authority; no Git, process or physical enrollment.
fn statement_fixture() -> (
    tempfile::TempDir,
    Store,
    RootRunRequest,
    super::ChildRequest,
) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let mut store = Store::open(&dir.path().join("private"), std::slice::from_ref(&root)).unwrap();
    let checkout = store
        .reserve(
            &Reservation {
                operation: Uuid::now_v7(),
                repository: root,
                actor: "allocator".into(),
                owner: "owner".into(),
                task: "task".into(),
            },
            Limits {
                repository: 10,
                owner: 10,
                available_bytes: Some(100),
                floor_bytes: 0,
                warn_bytes: 0,
            },
        )
        .unwrap();
    store
        .conn
        .execute("UPDATE checkouts SET state='active',ready=1", [])
        .unwrap();
    let request: RootRunRequest = serde_json::from_value(serde_json::json!({
        "identity":{"checkout":checkout,"group":Uuid::now_v7(),"run":Uuid::now_v7(),"run_ref":"statement-root","actor":"root","parent_run_ref":null,"execution_chain":[{"kind":"executor","system":"fixture"}]},
        "input":{"command_digest":vec![1;32],"input_digest":vec![2;32],"context_ref":"context","intent_ref":"intent","boot":"550e8400-e29b-41d4-a716-446655440000"}
    })).unwrap();
    store.begin_run(&request).unwrap();
    let child = super::ChildRequest {
        checkout: request.identity().checkout.clone(),
        group: request.identity().group.clone(),
        run: work_contract::RunId::generate(),
        run_ref: work_contract::RunRef::parse("statement-child").unwrap(),
        parent_run: request.identity().run.clone(),
        parent_run_ref: request.identity().run_ref.clone(),
        execution_chain: request.identity().execution_chain.clone(),
        source: None,
        session: None,
        agent: None,
        actor: None,
        expected_host: None,
    };
    child.validate().unwrap();
    (dir, store, request, child)
}

fn authority_tables(conn: &rusqlite::Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    [
        "task_finishes",
        "capture_runs",
        "runs",
        "run_groups",
        "adopted_groups",
        "checkouts",
        "writers",
        "run_participants",
    ]
    .into_iter()
    .map(|table| {
        let mut stmt = conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let columns = stmt.column_count();
        stmt.query_map([], |row| {
            (0..columns).map(|column| row.get(column)).collect()
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
    })
    .collect()
}

#[test]
fn namespace_statements_reuse_compiled_syntax_with_fresh_parameters() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let (_dir, store, _root, child) = statement_fixture();
    let mut other = child.clone();
    other.run = work_contract::RunId::generate();
    other.run_ref = work_contract::RunRef::parse("statement-other").unwrap();
    other.validate().unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let counter = reads.clone();
    // Installed before warmup, unchanged between samples. Memory-only callback.
    store
        .conn
        .authorizer(Some(move |ctx: AuthContext<'_>| {
            if matches!(ctx.action, AuthAction::Read { .. }) {
                counter.fetch_add(1, Ordering::Relaxed);
            }
            Authorization::Allow
        }))
        .unwrap();
    assert!(!super::namespace_conflict(&store.conn, &child).unwrap());
    let first = reads.load(Ordering::Relaxed);
    assert!(!super::namespace_conflict(&store.conn, &other).unwrap());
    let second = reads.load(Ordering::Relaxed);
    store
        .conn
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .unwrap();
    assert!(first > 0, "warmup must compile authority reads");
    assert_eq!(
        second, first,
        "architectural reuse: second lookup must not compile again"
    );
}

#[test]
fn namespace_statement_safety_matrix_reads_current_authority_without_writes() {
    let (dir, store, root, child) = statement_fixture();
    let conn = &store.conn;
    let mut other = child.clone();
    other.run = work_contract::RunId::generate();
    other.run_ref = work_contract::RunRef::parse("statement-other").unwrap();
    other.validate().unwrap();
    // Each raw row is synthetic SQL, not physical authority. Malformed payloads
    // still reserve names. Savepoints remove each collision before the next row.
    let cases = [
        "INSERT INTO task_finishes VALUES (?3,?1,'{malformed')",
        "INSERT INTO capture_runs SELECT id,group_id,?3,?1,'{malformed',zeroblob(32),'2026-01-01T00:00:00Z',1,NULL,NULL FROM runs",
        "UPDATE runs SET id=?1",
        "UPDATE runs SET group_id=?1",
        "UPDATE runs SET run_ref=?2",
        "INSERT INTO run_groups(id,checkout,mode,revision) VALUES (?1,?3,'supervised',1)",
        "INSERT INTO adopted_groups(id,checkout,run_id,run_ref,operation,request,revision) VALUES (?1,?3,'adopted-run','adopted-ref','adopted-op','{}',1)",
        "INSERT INTO adopted_groups(id,checkout,run_id,run_ref,operation,request,revision) VALUES ('adopted',?3,?1,'adopted-ref','adopted-op','{}',1)",
        "INSERT INTO adopted_groups(id,checkout,run_id,run_ref,operation,request,revision) VALUES ('adopted',?3,'adopted-run',?2,'adopted-op','{}',1)",
        "INSERT INTO adopted_groups(id,checkout,run_id,run_ref,operation,request,revision) VALUES ('adopted',?3,'adopted-run','adopted-ref',?1,'{}',1)",
        "UPDATE checkouts SET operation=?1",
        "INSERT INTO checkouts(id,operation,digest,repository,actor,task,owner) VALUES (?1,'checkout-op',zeroblob(32),'repo','actor','task','owner')",
        "UPDATE writers SET group_id=?1",
        "INSERT INTO run_participants(id,group_id,run_ref,parent_run,request,enrollment,depth) VALUES ('other-child',?4,?2,'parent','{}','unverified',1)",
    ];
    for sql in cases {
        assert!(
            !super::namespace_conflict(conn, &child).unwrap(),
            "before {sql}"
        );
        conn.execute_batch("SAVEPOINT collision").unwrap();
        // Updating keys deliberately makes contradictory raw authority. FK
        // enforcement stays enabled: deferred checks are rolled back.
        conn.execute_batch("PRAGMA defer_foreign_keys=ON").unwrap();
        let mut stmt = conn.prepare(sql).unwrap();
        for (name, value) in [
            ("?1", child.run.to_string()),
            ("?2", child.run_ref.to_string()),
            ("?3", child.checkout.to_string()),
            ("?4", child.group.to_string()),
        ] {
            if let Some(index) = stmt.parameter_index(name).unwrap() {
                stmt.raw_bind_parameter(index, value).unwrap();
            }
        }
        stmt.raw_execute().unwrap();
        drop(stmt);
        let changes = conn.total_changes();
        let tables = authority_tables(conn);
        assert!(
            super::namespace_conflict(conn, &child).unwrap(),
            "collision {sql}"
        );
        assert!(
            !super::namespace_conflict(conn, &other).unwrap(),
            "fresh bindings {sql}"
        );
        assert_eq!(
            authority_tables(conn),
            tables,
            "reads preserve every row {sql}"
        );
        assert_eq!(conn.total_changes(), changes, "reads cannot mutate {sql}");
        assert!(!conn.is_autocommit());
        conn.execute_batch("ROLLBACK TO collision; RELEASE collision")
            .unwrap();
        assert!(
            !super::namespace_conflict(conn, &child).unwrap(),
            "deleted {sql}"
        );
        assert!(conn.is_autocommit());
    }
    // A completed query cannot pin a WAL read snapshot across function return.
    let writer = Store::open(&dir.path().join("private"), &[dir.path().join("root")]).unwrap();
    writer
        .conn
        .execute(
            "INSERT INTO task_finishes VALUES (?1,?2,'{}')",
            (child.checkout.to_string(), child.run.to_string()),
        )
        .unwrap();
    assert!(super::namespace_conflict(conn, &child).unwrap());
    writer
        .conn
        .execute("DELETE FROM task_finishes", [])
        .unwrap();
    assert!(!super::namespace_conflict(conn, &child).unwrap());
    // Caller-owned transaction remains the snapshot owner, even with cached SQL.
    conn.execute_batch("BEGIN").unwrap();
    assert!(!super::namespace_conflict(conn, &child).unwrap());
    writer
        .conn
        .execute(
            "INSERT INTO task_finishes VALUES (?1,?2,'{}')",
            (child.checkout.to_string(), child.run.to_string()),
        )
        .unwrap();
    assert!(!super::namespace_conflict(conn, &child).unwrap());
    assert!(!conn.is_autocommit());
    conn.execute_batch("ROLLBACK").unwrap();
    assert!(super::namespace_conflict(conn, &child).unwrap());
    writer
        .conn
        .execute("DELETE FROM task_finishes", [])
        .unwrap();
    // Warm child_count, then require fresh counts and current schema errors.
    assert!(super::validate_roster(conn, &root, None, vec![])
        .unwrap()
        .is_empty());
    conn.execute("UPDATE run_groups SET child_count=1", [])
        .unwrap();
    assert!(super::validate_roster(conn, &root, None, vec![]).is_err());
    conn.execute("UPDATE run_groups SET child_count=0", [])
        .unwrap();
    conn.execute_batch("ALTER TABLE run_groups RENAME COLUMN child_count TO missing_count")
        .unwrap();
    assert!(matches!(
        super::validate_roster(conn, &root, None, vec![]),
        Err(crate::store::StoreError::Database(_))
    ));
    assert!(conn.is_autocommit());
}

#[test]
fn operation_statement_safety_reads_fresh_versions_rows_and_schema_errors() {
    let (_dir, store, _root, child) = statement_fixture();
    let conn = &store.conn;
    let operation = child.run.to_string();
    conn.execute(
        "INSERT INTO task_finishes VALUES (?1,?2,'{malformed')",
        (child.checkout.to_string(), &operation),
    )
    .unwrap();
    conn.execute("INSERT INTO capture_runs SELECT id,group_id,?1,?2,'{malformed',zeroblob(32),'2026-01-01T00:00:00Z',1,NULL,NULL FROM runs", (child.checkout.to_string(), &operation)).unwrap();
    let changes = conn.total_changes();
    for version in [15, 14, 8, 9, 10, 8, 14, 15] {
        conn.pragma_update(None, "user_version", version).unwrap();
        assert_eq!(
            crate::finish::operation_reserved(conn, &operation).unwrap(),
            version >= 9
        );
        assert_eq!(
            crate::capture_journal::operation_reserved(conn, &operation).unwrap(),
            version >= 10
        );
        assert!(!crate::finish::operation_reserved(conn, "different-operation").unwrap());
        assert!(!crate::capture_journal::operation_reserved(conn, "different-operation").unwrap());
    }
    assert_eq!(conn.total_changes(), changes);
    conn.execute_batch("DELETE FROM task_finishes; DELETE FROM capture_runs")
        .unwrap();
    assert!(!crate::finish::operation_reserved(conn, &operation).unwrap());
    assert!(!crate::capture_journal::operation_reserved(conn, &operation).unwrap());
    conn.execute_batch("BEGIN; ALTER TABLE task_finishes RENAME COLUMN operation TO missing_operation; ALTER TABLE capture_runs RENAME COLUMN operation TO missing_operation").unwrap();
    assert!(matches!(
        crate::finish::operation_reserved(conn, &operation),
        Err(crate::store::StoreError::Database(_))
    ));
    assert!(matches!(
        crate::capture_journal::operation_reserved(conn, &operation),
        Err(crate::store::StoreError::Database(_))
    ));
    assert!(!conn.is_autocommit());
    conn.execute_batch("ROLLBACK").unwrap();
    assert!(!super::namespace_conflict(conn, &child).unwrap());
    conn.execute_batch("ALTER TABLE runs RENAME COLUMN run_ref TO missing_ref")
        .unwrap();
    assert!(matches!(
        super::namespace_conflict(conn, &child),
        Err(crate::store::StoreError::Database(_))
    ));
    assert!(conn.is_autocommit());
}

#[test]
fn root_revision_and_child_tree_share_one_snapshot_and_preserve_caller_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let private = dir.path().join("private");
    let mut store = Store::open(&private, std::slice::from_ref(&root)).unwrap();
    let checkout = store
        .reserve(
            &Reservation {
                operation: Uuid::now_v7(),
                repository: root.clone(),
                actor: "allocator".into(),
                owner: "owner".into(),
                task: "task".into(),
            },
            Limits {
                repository: 10,
                owner: 10,
                available_bytes: Some(100),
                floor_bytes: 0,
                warn_bytes: 0,
            },
        )
        .unwrap();
    store
        .conn
        .execute("UPDATE checkouts SET state='active',ready=1", [])
        .unwrap();
    let request: RootRunRequest = serde_json::from_value(serde_json::json!({
        "identity":{"checkout":checkout,"group":Uuid::now_v7(),"run":Uuid::now_v7(),"run_ref":"snapshot-root","actor":"root","parent_run_ref":null,"execution_chain":[{"kind":"executor","system":"fixture"}]},
        "input":{"command_digest":vec![1;32],"input_digest":vec![2;32],"context_ref":"context","intent_ref":"intent","boot":"550e8400-e29b-41d4-a716-446655440000"}
    })).unwrap();
    store.begin_run(&request).unwrap();
    // Synthetic journal stage only; never create runtime authority or a process.
    store.conn.execute("UPDATE runs SET stage='permit_attempt',binding=?1", [serde_json::json!({
        "unit":format!("work-run-{}.scope",request.identity().run),"invocation":"550e8400e29b41d4a716446655440000",
        "cgroup":format!("/fixture/work-run-{}.scope",request.identity().run),"boot":request.input().boot,"root_pid":42,"root_start_ticks":10,"root_cgroup":format!("/fixture/work-run-{}.scope",request.identity().run)
    }).to_string()]).unwrap();
    let child = super::ChildRequest {
        checkout: request.identity().checkout.clone(),
        group: request.identity().group.clone(),
        run: work_contract::RunId::generate(),
        run_ref: work_contract::RunRef::parse("snapshot-child").unwrap(),
        parent_run: request.identity().run.clone(),
        parent_run_ref: request.identity().run_ref.clone(),
        execution_chain: request.identity().execution_chain.clone(),
        source: None,
        session: None,
        agent: None,
        actor: None,
        expected_host: None,
    };
    let mut writer = Store::open(&private, &[root]).unwrap();
    let writer_root = request.clone();
    let (go, start) = mpsc::channel();
    let (done, ack) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        start.recv_timeout(Duration::from_secs(2)).unwrap();
        writer.register_child(&writer_root, &child).unwrap();
        done.send(()).unwrap();
    });
    let mut fired = false;
    store
        .conn
        .authorizer(Some(move |ctx: AuthContext<'_>| {
            if !fired
                && matches!(
                    ctx.action,
                    AuthAction::Read {
                        table_name: "run_participants",
                        ..
                    }
                )
            {
                fired = true;
                go.send(()).unwrap();
                ack.recv_timeout(Duration::from_secs(2)).unwrap();
            }
            Authorization::Allow
        }))
        .unwrap();
    let old = store.run_snapshot(&request.identity().run);
    store
        .conn
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .unwrap();
    thread.join().unwrap();
    let old = old.unwrap().unwrap();
    assert_eq!(old.revision, 1);
    assert!(old.children.is_empty());
    assert!(store.conn.is_autocommit());
    let new = store
        .run_snapshot(&request.identity().run)
        .unwrap()
        .unwrap();
    assert_eq!(new.revision, 2);
    assert_eq!(new.children.len(), 1);
    store.conn.execute_batch("BEGIN").unwrap();
    store.group_snapshot(&request.identity().run).unwrap();
    assert!(!store.conn.is_autocommit());
    store.conn.execute_batch("ROLLBACK").unwrap();
    store
        .conn
        .execute_batch("UPDATE run_participants SET request='{}'")
        .unwrap();
    assert!(store.run_snapshot(&request.identity().run).is_err());
    assert!(
        store.conn.is_autocommit(),
        "owned read transaction rolls back on errors"
    );
    store.conn.execute_batch("BEGIN").unwrap();
    assert!(store.run_snapshot(&request.identity().run).is_err());
    assert!(
        !store.conn.is_autocommit(),
        "errors never consume caller-owned read transaction"
    );
}
