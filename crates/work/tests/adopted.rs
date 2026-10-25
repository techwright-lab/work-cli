#[path = "support/run_fixture.rs"]
mod fixture;
use fixture::*;
use rusqlite::Connection;

use uuid::Uuid;
use work_cli::{adopted::AdoptedRequest, participants::Ref, run_journal::BeginRun};
fn adopted(checkout: Uuid) -> AdoptedRequest {
    AdoptedRequest {
        operation: Uuid::now_v7(),
        identity: request(checkout).identity().clone(),
        source: Ref::new("sdk".into()).unwrap(),
        session: Ref::new("session".into()).unwrap(),
        agent: Some(Ref::new("agent".into()).unwrap()),
    }
}
#[test]
fn adopted_retry_and_two_connection_writer_contention() {
    let (dir, mut store, checkout) = fixture();
    let mut other = reopen(&dir).unwrap();
    let r = adopted(checkout);
    assert_eq!(store.begin_adopted(&r).unwrap(), BeginRun::Created);
    let before = store.pending_events(1000).unwrap();
    assert_eq!(other.begin_adopted(&r).unwrap(), BeginRun::Existing);
    assert_eq!(store.pending_events(1000).unwrap(), before);
    let mut changed = r.clone();
    changed.agent = Some(Ref::new("different".into()).unwrap());
    assert!(other.begin_adopted(&changed).is_err());
    assert!(other.begin_adopted(&adopted(checkout)).is_err());
    assert!(other.begin_run(&request(checkout)).is_err());
    assert_eq!(
        other
            .charged(&dir.path().join("root"), Some("owner"))
            .unwrap(),
        1
    );
    let (dir2, mut sup, checkout2) = fixture();
    let mut adopted_store = reopen(&dir2).unwrap();
    sup.begin_run(&request(checkout2)).unwrap();
    assert!(adopted_store.begin_adopted(&adopted(checkout2)).is_err());
}
#[test]
fn adopted_root_cannot_declare_itself_its_run_parent() {
    let (dir, mut store, checkout) = fixture();
    let mut r = adopted(checkout);
    r.identity.parent_run_ref = Some(r.identity.run_ref.clone());
    let before = store.pending_events(1000).unwrap();
    assert!(store.begin_adopted(&r).is_err());
    assert_eq!(store.pending_events(1000).unwrap(), before);
    assert_eq!(
        store
            .charged(&dir.path().join("root"), Some("owner"))
            .unwrap(),
        1
    );
}
#[test]
fn existing_begin_validates_the_entire_roster() {
    let (dir, mut store, checkout) = fixture();
    let r = adopted(checkout);
    store.begin_adopted(&r).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute(
        "UPDATE adopted_sessions SET actor='another-valid-actor'",
        [],
    )
    .unwrap();
    let before = store.pending_events(1000).unwrap();
    assert!(store.adopted_status(&r.identity.run).is_err());
    assert!(store.begin_adopted(&r).is_err());
    assert_eq!(store.pending_events(1000).unwrap(), before);
}
#[test]
fn integrated_begin_does_not_verify_checkout_after_corrupt_existing_declaration() {
    let f = support::Fixture::new();
    let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
    assert!(out.status.success());
    let allocation: work_cli::allocate::Allocation = serde_json::from_slice(&out.stdout).unwrap();
    let r = adopted(allocation.checkout);
    let body = serde_json::to_string(&r).unwrap();
    assert!(cli_input(&f, &["adopt", "begin"], &body).status.success());
    let sql = Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
    sql.execute(
        "UPDATE adopted_sessions SET actor='another-valid-actor'",
        [],
    )
    .unwrap();
    for advance in [false, true] {
        if advance {
            support::git(
                &allocation.destination,
                &["commit", "--allow-empty", "-m", "advance"],
            );
        }
        let events = f.store().pending_events(1000).unwrap();
        let checkout_before: String = sql
            .query_row(
                "SELECT record FROM allocations WHERE checkout=?1",
                [allocation.checkout.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!cli_input(&f, &["adopt", "begin"], &body).status.success());
        let checkout_after: String = sql
            .query_row(
                "SELECT record FROM allocations WHERE checkout=?1",
                [allocation.checkout.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(checkout_after, checkout_before);
        assert_eq!(f.store().pending_events(1000).unwrap(), events);
    }
}
#[test]
fn namespace_and_readonly_authority_cover_both_modes() {
    use work_cli::store::{Store, StoreError};
    let (dir, mut store, checkout) = fixture();
    let r = adopted(checkout);
    store.begin_adopted(&r).unwrap();
    let sup = request(checkout);
    for (field, value) in [
        ("run", serde_json::to_value(&r.identity.run).unwrap()),
        ("group", serde_json::to_value(&r.identity.group).unwrap()),
        (
            "run_ref",
            serde_json::to_value(&r.identity.run_ref).unwrap(),
        ),
        ("run", serde_json::to_value(r.operation).unwrap()),
    ] {
        assert!(
            matches!(
                store.begin_run(&changed(&sup, field, value)),
                Err(StoreError::Conflict)
            ),
            "namespace {field}"
        );
    }
    let before = store.pending_events(1000).unwrap();
    let reader = Store::open_existing_registered_readonly(
        &dir.path().join(".work-authorities"),
        &dir.path().join("private"),
        &[dir.path().join("root")],
    )
    .unwrap();
    assert_eq!(
        reader.adopted_status(&r.identity.run).unwrap(),
        store.adopted_status(&r.identity.run).unwrap()
    );
    assert_eq!(store.pending_events(1000).unwrap(), before);
    drop(reader);
    assert!(Store::open_existing_registered_mut(
        &dir.path().join(".work-authorities"),
        &dir.path().join("private"),
        &[dir.path().join("root")]
    )
    .is_ok());
}
mod support;
fn cli_input(f: &support::Fixture, command: &[&str], body: &str) -> std::process::Output {
    use std::io::Write;
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_work"))
        .args(command)
        .env("WORK_CONFIG", f.temp.path().join("config.toml"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}
#[test]
fn adopted_cli_is_metadata_only_and_refuses_stale_lease_capture_and_secret_payloads() {
    let f = support::Fixture::new();
    let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
    assert!(out.status.success());
    let allocation: work_cli::allocate::Allocation = serde_json::from_slice(&out.stdout).unwrap();
    let r = adopted(allocation.checkout);
    let body = serde_json::to_string(&r).unwrap();
    let git_before = std::fs::read(f.repo.join(".git/config")).unwrap();
    let out = cli_input(&f, &["adopt", "begin"], &body);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let before = f.store().pending_events(1000).unwrap();
    assert!(cli_input(&f, &["adopt", "begin"], &body).status.success());
    let status = cli_input(&f, &["adopt", "status", &r.identity.run.to_string()], "");
    assert!(status.status.success());
    let value: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(value["adopted_basis"], "checkout/session declaration");
    assert_eq!(value["runtime"], "unknown");
    assert_eq!(f.store().pending_events(1000).unwrap(), before);
    let event = serde_json::json!({"run":r.identity.run,"group":r.identity.group,"source":r.source,"participant":{"session":r.session,"agent":r.agent},"parent":null,"actor":null,"prompt":"p","tool":"t","event_ref":"e","kind":"stop","observed_at":1});
    assert!(cli_input(&f, &["adopt", "event"], &event.to_string())
        .status
        .success());
    let bad = cli_input(&f, &["adopt", "event"], r#"{"credentials":"SUPER_SECRET"}"#);
    assert!(!bad.status.success());
    assert!(!String::from_utf8_lossy(&bad.stderr).contains("SUPER_SECRET"));
    let bad_args = cli_input(&f, &["adopt", "event", "SUPER_SECRET"], "");
    assert!(!bad_args.status.success());
    assert!(!String::from_utf8_lossy(&bad_args.stderr).contains("SUPER_SECRET"));
    assert_eq!(
        std::fs::read(f.repo.join(".git/config")).unwrap(),
        git_before
    );
    f.config(10, true);
    assert!(!cli_input(&f, &["adopt", "begin"], &body).status.success());
    f.config(10, false);
    support::git(
        &allocation.destination,
        &["checkout", "-b", "foreign-branch"],
    );
    let second = adopted(allocation.checkout);
    assert!(!cli_input(
        &f,
        &["adopt", "begin"],
        &serde_json::to_string(&second).unwrap()
    )
    .status
    .success());
    assert!(
        f.store()
            .adopted_status(&r.identity.run)
            .unwrap()
            .writer_held
    );
}
#[test]
fn cli_and_readonly_status_accept_the_full_utf8_typed_domain() {
    let f = support::Fixture::new();
    let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
    assert!(out.status.success());
    let allocation: work_cli::allocate::Allocation = serde_json::from_slice(&out.stdout).unwrap();
    let mut r = adopted(allocation.checkout);
    let scalar = "\u{1f680}".repeat(4096);
    r.identity.execution_chain = serde_json::from_value(serde_json::Value::Array(
        (0..32)
            .map(|_| serde_json::json!({"kind":"executor","system":scalar,"session_ref":scalar}))
            .collect(),
    ))
    .unwrap();
    let refs = "\u{1f680}".repeat(256);
    r.identity.actor = work_contract::ActorId::parse(&refs).unwrap();
    r.identity.run_ref = work_contract::RunRef::parse(&refs).unwrap();
    r.source = Ref::new(refs.clone()).unwrap();
    r.session = Ref::new(refs.clone()).unwrap();
    r.agent = Some(Ref::new(refs).unwrap());
    let body = serde_json::to_string(&r).unwrap();
    assert!(body.len() > 1024 * 1024);
    assert!(cli_input(&f, &["adopt", "begin"], &body).status.success());
    let status = cli_input(&f, &["adopt", "status", &r.identity.run.to_string()], "");
    assert!(status.status.success());
    let value: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(value["request"], serde_json::to_value(r).unwrap());
}
#[test]
fn v5_migration_preserves_supervised_history_accounting_legacy_writers_and_outbox() {
    let (dir, mut store, checkout) = fixture();
    let active = request(checkout);
    store.begin_run(&active).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let closed_checkout = Uuid::now_v7();
    let legacy = Uuid::now_v7();
    for id in [closed_checkout, legacy] {
        sql.execute("INSERT INTO checkouts(id,operation,digest,repository,actor,task,owner,state,ready) SELECT ?1,?2,digest,repository,actor,task,owner,state,ready FROM checkouts WHERE id=?3",(id.to_string(),Uuid::now_v7().to_string(),checkout.to_string())).unwrap();
    }
    let closed = request(closed_checkout);
    store.begin_run(&closed).unwrap();
    store.record_bound(&closed, &binding(&closed)).unwrap();
    sql.execute(
        "UPDATE run_groups SET closed=1 WHERE id=?1",
        [closed.identity().group.to_string()],
    )
    .unwrap();
    sql.execute(
        "DELETE FROM writers WHERE checkout=?1",
        [closed_checkout.to_string()],
    )
    .unwrap();
    store.acquire_writer(legacy, Uuid::now_v7()).unwrap();
    sql.execute(
        "INSERT INTO repository_aliases VALUES('preserved',?1)",
        [dir.path().join("root").to_str().unwrap()],
    )
    .unwrap();
    let active_before = store.run_snapshot(&active.identity().run).unwrap();
    let closed_before = store.run_snapshot(&closed.identity().run).unwrap();
    let events = store.pending_events(1000).unwrap();
    sql.execute_batch("DROP TABLE retirement_intents; DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; DROP TABLE attribution_gaps; DROP TABLE capture_readiness; DROP TABLE capture_finalizations; DROP TABLE capture_requirements; DROP TABLE capture_runs; DROP TABLE task_finishes; DROP TABLE run_participants; ALTER TABLE run_groups DROP COLUMN child_count; DROP TABLE adopted_segments; DROP TABLE adopted_sessions; DROP TABLE adopted_groups; PRAGMA user_version=5").unwrap();
    drop(store);
    assert!(work_cli::store::Store::open_existing_registered_readonly(
        &dir.path().join(".work-authorities"),
        &dir.path().join("private"),
        &[dir.path().join("root")]
    )
    .is_err());
    let mut migrated = reopen(&dir).unwrap();
    assert_eq!(
        migrated.run_snapshot(&active.identity().run).unwrap(),
        active_before
    );
    assert_eq!(
        migrated.run_snapshot(&closed.identity().run).unwrap(),
        closed_before
    );
    assert_eq!(migrated.pending_events(1000).unwrap(), events);
    assert_eq!(
        migrated
            .charged(&dir.path().join("root"), Some("owner"))
            .unwrap(),
        3
    );
    for field in ["run", "group", "run_ref", "operation"] {
        let mut collision = adopted(legacy);
        match field {
            "run" => collision.identity.run = closed.identity().run.clone(),
            "group" => collision.identity.group = closed.identity().group.clone(),
            "run_ref" => collision.identity.run_ref = closed.identity().run_ref.clone(),
            _ => collision.operation = Uuid::parse_str(&closed.identity().run.to_string()).unwrap(),
        }
        assert!(
            matches!(
                migrated.begin_adopted(&collision),
                Err(work_cli::store::StoreError::Conflict)
            ),
            "closed-history {field}"
        );
    }
    assert_eq!(
        sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        sql.query_row("SELECT count(*) FROM repository_aliases", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
#[test]
fn versioned_adopted_tables_cannot_be_replaced_with_views() {
    let (dir, store, _) = fixture();
    drop(store);
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    for table in ["adopted_groups", "adopted_sessions", "adopted_segments"] {
        sql.execute_batch(&format!("ALTER TABLE {table} RENAME TO saved_{table}; CREATE VIEW {table} AS SELECT * FROM saved_{table};")).unwrap();
        assert!(
            reopen(&dir).is_err(),
            "versioned table {table} must be a table"
        );
        assert!(work_cli::store::Store::open_existing_registered_readonly(
            &dir.path().join(".work-authorities"),
            &dir.path().join("private"),
            &[dir.path().join("root")]
        )
        .is_err());
        sql.execute_batch(&format!(
            "DROP VIEW {table}; ALTER TABLE saved_{table} RENAME TO {table};"
        ))
        .unwrap();
    }
}
#[test]
fn readonly_adopted_status_does_not_initialize_unknown_authority() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    assert!(work_cli::store::Store::open_existing_registered_readonly(
        &dir.path().join("registry"),
        &dir.path().join("store"),
        &[root]
    )
    .is_err());
    assert!(!dir.path().join("registry").exists());
    assert!(!dir.path().join("store").exists());
}
#[test]
fn schema_v6_is_additive_and_missing_tables_fail_closed() {
    let (dir, store, checkout) = fixture();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let version: i64 = sql
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        version, 16,
        "supervised child journal needs a distinct schema"
    );
    assert_eq!(
        store
            .charged(&dir.path().join("root"), Some("owner"))
            .unwrap(),
        1
    );
    let state: String = sql
        .query_row(
            "SELECT state FROM checkouts WHERE id=?1",
            [checkout.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "active");
    drop(store);
    for table in ["adopted_groups", "adopted_sessions", "adopted_segments"] {
        sql.execute_batch(&format!("ALTER TABLE {table} RENAME TO missing_{table}"))
            .unwrap();
        assert!(reopen(&dir).is_err());
        let registry = dir.path().join(".work-authorities");
        let store_dir = dir.path().join("private");
        let roots = [dir.path().join("root")];
        assert!(work_cli::store::Store::open_existing_registered_readonly(
            &registry, &store_dir, &roots
        )
        .is_err());
        assert!(work_cli::store::Store::open_existing_registered_mut(
            &registry, &store_dir, &roots
        )
        .is_err());
        assert!(work_cli::store::report_existing(&registry, &store_dir, &roots).is_err());
        sql.execute_batch(&format!("ALTER TABLE missing_{table} RENAME TO {table}"))
            .unwrap();
    }
    assert!(reopen(&dir).is_ok());
}
