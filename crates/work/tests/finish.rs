#[path = "support/run_fixture.rs"]
mod run_fixture;
mod support;
use std::process::{Command, Output};
use support::Fixture;
use uuid::Uuid;

fn finish(f: &Fixture, id: Uuid) -> Output {
    Command::new(env!("CARGO_BIN_EXE_work"))
        .args(["finish", &id.to_string()])
        .env("WORK_CONFIG", f.temp.path().join("config.toml"))
        .output()
        .unwrap()
}
fn config(f: &Fixture) -> work_cli::config::Config {
    work_cli::config::Config::from_text(
        &std::fs::read_to_string(f.temp.path().join("config.toml")).unwrap(),
    )
    .unwrap()
}
fn authority_files(f: &Fixture) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    for sub in ["registry", "private"] {
        for entry in std::fs::read_dir(f.temp.path().join(sub)).unwrap() {
            let path = entry.unwrap().path();
            let bytes = if path.to_string_lossy().ends_with("-shm") {
                Vec::new()
            } else {
                std::fs::read(&path).unwrap()
            };
            files.push((path, bytes));
        }
    }
    files.sort();
    files
}
fn allocated(f: &Fixture) -> serde_json::Value {
    let output = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
    assert!(output.status.success(), "{:?}", output);
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
fn explicit_no_sink_finish_retains_dirty_tree_charge_and_one_receipt() {
    let f = Fixture::new();
    let a = allocated(&f);
    let id = Uuid::parse_str(a["checkout"].as_str().unwrap()).unwrap();
    let tree = std::path::Path::new(a["destination"].as_str().unwrap());
    std::fs::write(tree.join("untracked"), b"not preservation proof").unwrap();
    let first = finish(&f, id);
    assert!(first.status.success(), "{:?}", first);
    let report: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(report["task_finished"], true);
    assert_eq!(report["task_completion"], "finished");
    assert_eq!(report["local_freeze"], "not_configured");
    assert_eq!(report["lease_held"], true);
    assert_eq!(report["charge_retained"], true);
    assert_eq!(report["retirement"], "disabled");
    assert_eq!(report["action"], "none");
    let again = finish(&f, id);
    assert!(again.status.success(), "{:?}", again);
    assert_eq!(
        report,
        serde_json::from_slice::<serde_json::Value>(&again.stdout).unwrap()
    );
    assert_eq!(
        std::fs::read(tree.join("untracked")).unwrap(),
        b"not preservation proof"
    );
    assert_eq!(f.store().charged(&f.repo, None).unwrap(), 1);
    let sql = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
    let (state, ready): (String, bool) = sql
        .query_row("SELECT state,ready FROM checkouts", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((state.as_str(), ready), ("held", false));
    let reason: Option<String> = sql
        .query_row(
            "SELECT json_extract(record,'$.hold_reason') FROM task_finishes",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(reason.as_deref(), Some("retirement-disabled"));
    let n: i64 = sql
        .query_row(
            "SELECT count(*) FROM outbox WHERE json_extract(payload,'$.type')='task_finished'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);
    assert!(!f
        .start(
            a["request"]["operation"].as_str().unwrap(),
            "task",
            "topic",
            &[]
        )
        .status
        .success());
}
#[test]
fn closed_root_remains_readable_with_task_closed_and_finish_namespace_reserved() {
    let f = Fixture::new();
    let a = allocated(&f);
    let id = Uuid::parse_str(a["checkout"].as_str().unwrap()).unwrap();
    let mut body = serde_json::to_value(run_fixture::request(id)).unwrap();
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update((9u64).to_be_bytes());
    hash.update(b"/bin/true");
    body["input"]["command_digest"] =
        serde_json::to_value(<[u8; 32]>::from(hash.finalize())).unwrap();
    let r: work_cli::run_journal::RootRunRequest = serde_json::from_value(body).unwrap();
    let mut store = f.store();
    store.begin_run(&r).unwrap();
    let b = run_fixture::binding(&r);
    store.record_bound(&r, &b).unwrap();
    store
        .record_root_outcome(&r, work_cli::run_journal::RootOutcome::Failed)
        .unwrap();
    let os = run_fixture::ClosureOs::new(&r, &b);
    let snap = store.group_snapshot(&r.identity().run).unwrap();
    let proof = snap.certify_empty(&os.driver, &b).unwrap();
    store.close_supervised_group(&snap, &proof).unwrap();
    let before = store.run_snapshot(&r.identity().run).unwrap();
    let old_reader = work_cli::store::Store::open_existing_registered_readonly(
        &f.temp.path().join("registry"),
        &f.temp.path().join("private"),
        std::slice::from_ref(&f.root),
    )
    .unwrap();
    let output = finish(&f, id);
    assert!(output.status.success(), "{:?}", output);
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["run_outcomes"][0]["outcome"], "failed");
    let files = authority_files(&f);
    let old = work_cli::run_recovery::status(&old_reader, &r.identity().run).unwrap();
    assert!(old.task_open);
    assert!(old.lease_charged);
    assert_eq!(old.record, before.clone().unwrap());
    let status = work_cli::run_recovery::status(&store, &r.identity().run).unwrap();
    assert!(!status.task_open);
    assert!(status.lease_charged);
    let command = work_cli::supervisor::RootCommand {
        checkout: id,
        actor: None,
        run_id: Uuid::parse_str(&r.identity().run.to_string()).unwrap(),
        execution_chain: r.identity().execution_chain.clone(),
        argv: vec!["/bin/true".into()],
    };
    let historical = work_cli::supervisor::existing_report(&config(&f), &command)
        .unwrap()
        .expect("finished receipt requires no supervisor/profile/runtime");
    assert!(!historical.task_open);
    assert!(historical.existing);
    assert_eq!(historical.record, status.record);
    let chain = f.temp.path().join("chain.json");
    std::fs::write(
        &chain,
        serde_json::to_vec(&command.execution_chain).unwrap(),
    )
    .unwrap();
    let cli = Command::new(env!("CARGO_BIN_EXE_work"))
        .args([
            "run",
            &id.to_string(),
            "--run-id",
            &command.run_id.to_string(),
            "--execution-chain",
            chain.to_str().unwrap(),
            "--",
            "/bin/true",
        ])
        .env("WORK_CONFIG", f.temp.path().join("config.toml"))
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&cli.stderr).contains("task=finished"),
        "{:?}",
        cli
    );
    assert_eq!(store.run_snapshot(&r.identity().run).unwrap(), before);
    assert_eq!(authority_files(&f), files);
    let op = result["operation"].as_str().unwrap();
    let other = run_fixture::request(id);
    let reused = run_fixture::changed(&other, "run", serde_json::json!(op));
    assert!(store.begin_run(&reused).is_err());
    assert!(store.acquire_writer(id, Uuid::now_v7()).is_err());
}
#[test]
fn finish_refuses_bare_writer_without_mutation() {
    let f = Fixture::new();
    let a = allocated(&f);
    let id = Uuid::parse_str(a["checkout"].as_str().unwrap()).unwrap();
    f.store().acquire_writer(id, Uuid::now_v7()).unwrap();
    assert!(!finish(&f, id).status.success());
    let sql = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
    let state: String = sql
        .query_row("SELECT state FROM checkouts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(state, "active");
}
struct Sink {
    calls: std::cell::Cell<usize>,
    fail: bool,
    f: Fixture,
}
impl work_cli::finish::LocalSink for Sink {
    fn freeze(
        &self,
        context: &work_cli::finish::CaptureContext,
    ) -> work_cli::finish::CaptureResult {
        self.calls.set(self.calls.get() + 1);
        let sql =
            rusqlite::Connection::open(self.f.temp.path().join("private/store.sqlite")).unwrap();
        let state: String = sql
            .query_row(
                "SELECT state FROM checkouts WHERE id=?1",
                [context.checkout.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "held");
        assert_eq!(self.f.store().charged(&self.f.repo, None).unwrap(), 1);
        // Capture is outside both the SQL transaction and lifecycle flock.
        let next = self
            .f
            .start(&Uuid::now_v7().to_string(), "other", "other", &[]);
        assert!(next.status.success(), "{:?}", next);
        let a: serde_json::Value = serde_json::from_slice(&next.stdout).unwrap();
        let id = Uuid::parse_str(a["checkout"].as_str().unwrap()).unwrap();
        self.f.store().begin_run(&run_fixture::request(id)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(700));
        if self.fail {
            work_cli::finish::CaptureResult::Failed
        } else {
            work_cli::finish::CaptureResult::Frozen {
                delivery: Some(work_cli::finish::Delivery::Pending),
            }
        }
    }
}
#[test]
fn local_capture_is_after_fence_outside_locks_and_network_is_separate() {
    use work_cli::finish::{finish_with_sink_observed, Delivery, Freeze};
    for fail in [false, true] {
        let f = Fixture::new();
        let a = allocated(&f);
        let id = Uuid::parse_str(a["checkout"].as_str().unwrap()).unwrap();
        let mut cfg = config(&f);
        cfg.allocation.as_mut().unwrap().capture_sink = Some("secret-capture-location".into());
        let sink = Sink {
            calls: std::cell::Cell::new(0),
            fail,
            f,
        };
        let report = finish_with_sink_observed(&cfg, id, Some(&sink), |_| {}).unwrap();
        assert_eq!(sink.calls.get(), 1);
        assert!(report.task_finished);
        assert_eq!(
            report.local_freeze,
            if fail { Freeze::Failed } else { Freeze::Frozen }
        );
        assert_eq!(
            report.delivery,
            if fail { None } else { Some(Delivery::Pending) }
        );
        assert_eq!(report.capture_incomplete, fail);
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("secret-capture-location"));
        let again = finish_with_sink_observed(&config(&sink.f), id, Some(&sink), |_| {}).unwrap();
        assert_eq!(report, again);
        assert_eq!(sink.calls.get(), 1);
    }
}
#[test]
fn malformed_receipt_never_becomes_existing_success() {
    for case in [
        "body",
        "state",
        "allocation",
        "missing_event",
        "invalid_reason",
        "operation_alias",
        "checkout_actor",
        "checkout_task",
        "checkout_repository",
        "checkout_digest",
        "writer_after_finish",
        "off_to_frozen",
    ] {
        let f = Fixture::new();
        let a = allocated(&f);
        let id = Uuid::parse_str(a["checkout"].as_str().unwrap()).unwrap();
        assert!(finish(&f, id).status.success());
        let sql = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
        match case {
            "off_to_frozen" => {
                sql.execute("UPDATE task_finishes SET record=json_set(record,'$.local_freeze','frozen','$.delivery',NULL)",[]).unwrap();
            }
            "writer_after_finish" => {
                sql.execute(
                    "INSERT INTO writers VALUES(?1,?2)",
                    (id.to_string(), Uuid::now_v7().to_string()),
                )
                .unwrap();
            }
            "checkout_actor" => {
                sql.execute("UPDATE checkouts SET actor='different'", [])
                    .unwrap();
            }
            "checkout_task" => {
                sql.execute("UPDATE checkouts SET task='different'", [])
                    .unwrap();
            }
            "checkout_repository" => {
                sql.execute("UPDATE checkouts SET repository='/different'", [])
                    .unwrap();
            }
            "checkout_digest" => {
                sql.execute("UPDATE checkouts SET digest=x'00'", [])
                    .unwrap();
            }
            "body" => {
                sql.execute("UPDATE task_finishes SET record='{}'", [])
                    .unwrap();
            }
            "state" => {
                sql.execute("UPDATE checkouts SET ready=1", []).unwrap();
            }
            "allocation" => {
                sql.execute("UPDATE allocations SET record='{}'", [])
                    .unwrap();
            }
            "missing_event" => {
                sql.execute(
                    "DELETE FROM outbox WHERE json_extract(payload,'$.type')='task_finished'",
                    [],
                )
                .unwrap();
            }
            "invalid_reason" => {
                sql.execute(
                    "UPDATE task_finishes SET record=json_set(record,'$.reason','secret-bogus')",
                    [],
                )
                .unwrap();
            }
            "operation_alias" => {
                sql.execute("UPDATE task_finishes SET operation=?1,record=json_set(record,'$.operation',?1)",[id.to_string()]).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(!finish(&f, id).status.success(), "{case}");
    }
}
#[test]
fn production_configured_capture_is_explicit_unsupported_not_off() {
    let f = Fixture::new();
    let a = allocated(&f);
    let id = Uuid::parse_str(a["checkout"].as_str().unwrap()).unwrap();
    f.config(10, true);
    let output = finish(&f, id);
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["task_finished"], true);
    assert_eq!(report["local_freeze"], "failed");
    assert_eq!(report["delivery"], serde_json::Value::Null);
    assert_eq!(report["reasons"][1], "capture-unsupported");
    assert_eq!(f.store().charged(&f.repo, None).unwrap(), 1);
}
#[test]
fn active_or_orphan_journal_refusal_precedes_head_refresh() {
    for case in [
        "root",
        "missing_writer",
        "missing_root",
        "child_orphan",
        "held",
    ] {
        let f = Fixture::new();
        let a = allocated(&f);
        let id = Uuid::parse_str(a["checkout"].as_str().unwrap()).unwrap();
        let mut store = f.store();
        let r = run_fixture::request(id);
        store.begin_run(&r).unwrap();
        let sql = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
        sql.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        match case {
            "missing_writer" => {
                sql.execute("DELETE FROM writers", []).unwrap();
            }
            "missing_root" => {
                sql.execute("DELETE FROM runs", []).unwrap();
                sql.execute("DELETE FROM writers", []).unwrap();
            }
            "child_orphan" => {
                sql.execute("UPDATE runs SET group_id='unknown'", [])
                    .unwrap();
            }
            "held" => {
                sql.execute("UPDATE checkouts SET state='held',ready=0", [])
                    .unwrap();
            }
            _ => {}
        }
        let path = std::path::Path::new(a["destination"].as_str().unwrap());
        support::git(
            path,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--allow-empty",
                "-m",
                "advance",
            ],
        );
        let prior: String = sql
            .query_row("SELECT record FROM allocations", [], |r| r.get(0))
            .unwrap();
        let events: i64 = sql
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert!(!finish(&f, id).status.success(), "{case}");
        let after: String = sql
            .query_row("SELECT record FROM allocations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(prior, after, "{case}");
        let n: i64 = sql
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, events, "{case}");
    }
}
#[test]
fn established_v8_migrates_but_unsafe_or_incomplete_authority_is_not_repaired() {
    for case in [
        "v8",
        "missing",
        "view",
        "constraints",
        "delete_mode",
        "unknown_schema",
        "rollback",
    ] {
        let f = Fixture::new();
        let a = allocated(&f);
        let id = Uuid::parse_str(a["checkout"].as_str().unwrap()).unwrap();
        let mut store = f.store();
        let r = run_fixture::request(id);
        store.begin_run(&r).unwrap();
        let b = run_fixture::binding(&r);
        store.record_bound(&r, &b).unwrap();
        let os = run_fixture::ClosureOs::new(&r, &b);
        let snap = store.group_snapshot(&r.identity().run).unwrap();
        let proof = snap.certify_empty(&os.driver, &b).unwrap();
        store.close_supervised_group(&snap, &proof).unwrap();
        drop(store);
        let sql = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
        match case {
            "v8" => sql.execute_batch("DROP TABLE task_finishes; PRAGMA user_version=8").unwrap(),
            "missing" => sql.execute_batch("DROP TABLE task_finishes").unwrap(),
            "view" => sql.execute_batch("ALTER TABLE task_finishes RENAME TO old_finishes; CREATE VIEW task_finishes AS SELECT * FROM old_finishes").unwrap(),
            "constraints" => sql.execute_batch("ALTER TABLE task_finishes RENAME TO old_finishes; CREATE TABLE task_finishes AS SELECT * FROM old_finishes").unwrap(),
            "delete_mode" => {sql.execute_batch("PRAGMA journal_mode=DELETE").unwrap();},
            "unknown_schema" => sql.execute_batch("PRAGMA user_version=999").unwrap(),
            "rollback" => sql.execute_batch("DROP TABLE task_finishes; PRAGMA user_version=8; CREATE TRIGGER block_completion BEFORE UPDATE ON checkouts BEGIN SELECT RAISE(ABORT,'fixture'); END").unwrap(),
            _=>unreachable!()
        }
        let before: i64 = sql
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        let output = finish(&f, id);
        assert_eq!(
            output.status.success(),
            case == "v8",
            "{case}: {:?}",
            output
        );
        assert_eq!(
            sql.query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            before + if case == "v8" { 1 } else { 0 }
        );
        assert_eq!(
            sql.query_row("SELECT state FROM checkouts", [], |r| r.get::<_, String>(0))
                .unwrap(),
            if case == "v8" { "held" } else { "active" }
        );
    }
}
fn adopted(id: Uuid) -> work_cli::adopted::AdoptedRequest {
    work_cli::adopted::AdoptedRequest {
        operation: Uuid::now_v7(),
        identity: run_fixture::request(id).identity().clone(),
        source: work_cli::participants::Ref::new("sdk".into()).unwrap(),
        session: work_cli::participants::Ref::new("session".into()).unwrap(),
        agent: None,
    }
}
#[test]
fn concurrent_completion_and_each_writer_api_have_one_sql_winner() {
    for kind in ["root", "adopted", "legacy"] {
        let f = Fixture::new();
        let a = allocated(&f);
        let id = Uuid::parse_str(a["checkout"].as_str().unwrap()).unwrap();
        let cfg = config(&f);
        let mut store = f.store();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let b = barrier.clone();
        let writer = std::thread::spawn(move || {
            b.wait();
            match kind {
                "root" => store.begin_run(&run_fixture::request(id)).map(|_| ()),
                "adopted" => store.begin_adopted(&adopted(id)).map(|_| ()),
                _ => store.acquire_writer(id, Uuid::now_v7()),
            }
        });
        barrier.wait();
        let completed = work_cli::finish::finish(&cfg, id);
        assert_ne!(completed.is_ok(), writer.join().unwrap().is_ok(), "{kind}");
        assert_eq!(f.store().charged(&f.repo, None).unwrap(), 1);
    }
}
#[test]
fn finish_operation_is_reserved_across_all_new_request_namespaces() {
    let f = Fixture::new();
    let a = allocated(&f);
    let id = Uuid::parse_str(a["checkout"].as_str().unwrap()).unwrap();
    let result = work_cli::finish::finish(&config(&f), id).unwrap();
    let out = f.start(&Uuid::now_v7().to_string(), "other", "other", &[]);
    assert!(out.status.success());
    let other: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let oid = Uuid::parse_str(other["checkout"].as_str().unwrap()).unwrap();
    let mut store = f.store();
    assert!(store.acquire_writer(oid, result.operation).is_err());
    let root = run_fixture::request(oid);
    for field in ["run", "group"] {
        assert!(store
            .begin_run(&run_fixture::changed(
                &root,
                field,
                serde_json::json!(result.operation)
            ))
            .is_err());
    }
    for field in ["operation", "run", "group"] {
        let mut a = adopted(oid);
        if field == "operation" {
            a.operation = result.operation;
        } else {
            a.identity = run_fixture::changed(&root, field, serde_json::json!(result.operation))
                .identity()
                .clone();
        }
        assert!(store.begin_adopted(&a).is_err(), "{field}");
    }
    assert!(!f
        .start(&result.operation.to_string(), "collision", "collision", &[])
        .status
        .success());
    store.begin_run(&root).unwrap();
    let child:work_cli::run_participants::ChildRequest=serde_json::from_value(serde_json::json!({"checkout":root.identity().checkout,"group":root.identity().group,"run":result.operation,"run_ref":"child:collision","parent_run":root.identity().run,"parent_run_ref":root.identity().run_ref,"execution_chain":root.identity().execution_chain,"source":null,"session":null,"agent":null,"actor":null,"expected_host":null})).unwrap();
    assert!(store.register_child(&root, &child).is_err());
}
#[test]
fn held_identity_and_changed_branch_marker_source_fail_closed() {
    for case in [
        "held",
        "expired",
        "partial",
        "quarantined",
        "retired",
        "marker",
        "branch",
        "source",
    ] {
        let f = Fixture::new();
        let a = allocated(&f);
        let id = Uuid::parse_str(a["checkout"].as_str().unwrap()).unwrap();
        let sql = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
        let tree = std::path::Path::new(a["destination"].as_str().unwrap());
        match case {
            "marker" => {
                std::fs::write(
                    std::path::Path::new(a["identity"]["private_git_dir"].as_str().unwrap())
                        .join("work-lease.json"),
                    "{}",
                )
                .unwrap();
            }
            "branch" => {
                support::git(tree, &["checkout", "-b", "replaced"]);
            }
            "source" => {
                std::fs::rename(&f.repo, f.temp.path().join("old-repo")).unwrap();
                std::fs::create_dir(&f.repo).unwrap();
                support::git(&f.repo, &["init", "-b", "main"]);
            }
            state => {
                sql.execute("UPDATE checkouts SET state=?1,ready=0", [state])
                    .unwrap();
            }
        }
        assert!(!finish(&f, id).status.success(), "{case}");
        assert!(tree.exists());
        assert_eq!(
            sql.query_row("SELECT count(*) FROM task_finishes", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
#[test]
fn adopted_stop_session_end_and_live_children_never_finish_or_release() {
    use work_cli::participants::{Activity, ActivityKind, ParticipantKey, Ref};
    for case in [
        "stop",
        "session_end",
        "missing_adopted_writer",
        "pending_child",
        "unverified_child",
    ] {
        let f = Fixture::new();
        let a = allocated(&f);
        let id = Uuid::parse_str(a["checkout"].as_str().unwrap()).unwrap();
        let mut store = f.store();
        if case.ends_with("child") {
            let root = run_fixture::request(id);
            store.begin_run(&root).unwrap();
            let b = run_fixture::binding(&root);
            store.record_bound(&root, &b).unwrap();
            store.record_permit_attempt(&root, &b).unwrap();
            let child:work_cli::run_participants::ChildRequest=serde_json::from_value(serde_json::json!({"checkout":root.identity().checkout,"group":root.identity().group,"run":work_contract::RunId::generate(),"run_ref":"child:live","parent_run":root.identity().run,"parent_run_ref":root.identity().run_ref,"execution_chain":root.identity().execution_chain,"source":null,"session":null,"agent":null,"actor":null,"expected_host":if case=="pending_child" {serde_json::json!({"boot":run_fixture::BOOT,"pid":42,"start_ticks":10})} else {serde_json::Value::Null}})).unwrap();
            store.register_child(&root, &child).unwrap();
        } else {
            let adopted = adopted(id);
            store.begin_adopted(&adopted).unwrap();
            store
                .record_activity(&Activity {
                    run: adopted.identity.run.clone(),
                    group: adopted.identity.group.clone(),
                    source: adopted.source.clone(),
                    participant: ParticipantKey {
                        session: adopted.session.clone(),
                        agent: None,
                    },
                    parent: None,
                    actor: None,
                    prompt: None,
                    tool: None,
                    event_ref: Ref::new("event".into()).unwrap(),
                    kind: if case == "stop" {
                        ActivityKind::Stop
                    } else {
                        ActivityKind::SessionEnd
                    },
                    observed_at: 10,
                })
                .unwrap();
            if case == "missing_adopted_writer" {
                let sql =
                    rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
                sql.execute("DELETE FROM writers", []).unwrap();
            }
        }
        let before = store.pending_events(1000).unwrap();
        assert!(!finish(&f, id).status.success(), "{case}");
        assert_eq!(store.pending_events(1000).unwrap(), before);
        assert_eq!(store.charged(&f.repo, None).unwrap(), 1);
    }
}
#[test]
fn closed_child_v8_history_upgrades_and_stays_readable_after_finish() {
    let f = Fixture::new();
    let a = allocated(&f);
    let id = Uuid::parse_str(a["checkout"].as_str().unwrap()).unwrap();
    let mut store = f.store();
    let r = run_fixture::request(id);
    let b = run_fixture::binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let os = run_fixture::ClosureOs::new(&r, &b);
    let child:work_cli::run_participants::ChildRequest=serde_json::from_value(serde_json::json!({"checkout":r.identity().checkout,"group":r.identity().group,"run":work_contract::RunId::generate(),"run_ref":"child:closed","parent_run":r.identity().run,"parent_run_ref":r.identity().run_ref,"execution_chain":r.identity().execution_chain,"source":null,"session":null,"agent":null,"actor":null,"expected_host":{"boot":run_fixture::BOOT,"pid":43,"start_ticks":20}})).unwrap();
    store.register_child(&r, &child).unwrap();
    os.process_pid(43, 20, &b.identity().cgroup);
    let properties = os.tmp.path().join("properties");
    let text = std::fs::read_to_string(&properties).unwrap();
    std::fs::write(
        &properties,
        text.replace("ActiveState=inactive", "ActiveState=active"),
    )
    .unwrap();
    let roster = os
        .tmp
        .path()
        .join("cg")
        .join(b.identity().cgroup.trim_start_matches('/'))
        .join("cgroup.procs");
    std::fs::write(&roster, "43\n").unwrap();
    let proof = store
        .group_snapshot(&r.identity().run)
        .unwrap()
        .certify_child_enrollment(&os.driver, &child.run, Some(&b))
        .unwrap();
    store.record_child_enrollment(&r, &child, &proof).unwrap();
    store
        .record_child_outcome(
            &r,
            &child,
            work_cli::run_participants::ChildOutcome::Completed,
        )
        .unwrap();
    std::fs::remove_dir_all(os.tmp.path().join("proc/43")).unwrap();
    std::fs::write(&roster, "").unwrap();
    std::fs::write(&properties, text).unwrap();
    let snap = store.group_snapshot(&r.identity().run).unwrap();
    let proof = snap.certify_empty(&os.driver, &b).unwrap();
    store.close_supervised_group(&snap, &proof).unwrap();
    let prior = store.run_snapshot(&r.identity().run).unwrap();
    let sql = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch("DROP TABLE task_finishes; PRAGMA user_version=8")
        .unwrap();
    assert!(matches!(
        work_cli::store::Store::open_existing_registered_readonly(
            &f.temp.path().join("registry"),
            &f.temp.path().join("private"),
            std::slice::from_ref(&f.root)
        ),
        Err(work_cli::store::StoreError::UpgradeRequired)
    ));
    let output = finish(&f, id);
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(prior, store.run_snapshot(&r.identity().run).unwrap());
    assert_eq!(
        store.register_child(&r, &child).unwrap(),
        work_cli::run_journal::BeginRun::Existing
    );
    assert_eq!(
        store
            .record_child_outcome(
                &r,
                &child,
                work_cli::run_participants::ChildOutcome::Completed
            )
            .unwrap(),
        work_cli::run_journal::Transition::Existing
    );
}
#[test]
fn failed_capture_retries_only_original_binding_and_network_failure_is_not_local_failure() {
    struct Retry(std::cell::RefCell<Vec<Uuid>>);
    impl work_cli::finish::LocalSink for Retry {
        fn freeze(&self, c: &work_cli::finish::CaptureContext) -> work_cli::finish::CaptureResult {
            self.0.borrow_mut().push(c.operation);
            if self.0.borrow().len() == 1 {
                work_cli::finish::CaptureResult::Failed
            } else {
                work_cli::finish::CaptureResult::Frozen {
                    delivery: Some(work_cli::finish::Delivery::Failed),
                }
            }
        }
    }
    let f = Fixture::new();
    let a = allocated(&f);
    let id = Uuid::parse_str(a["checkout"].as_str().unwrap()).unwrap();
    let mut cfg = config(&f);
    cfg.allocation.as_mut().unwrap().capture_sink = Some("secret-original-binding".into());
    let sink = Retry(Default::default());
    let first = work_cli::finish::finish_with_sink_observed(&cfg, id, Some(&sink), |_| {}).unwrap();
    assert!(first.capture_incomplete);
    let mut changed = cfg.clone();
    changed.allocation.as_mut().unwrap().capture_sink = Some("secret-new-binding".into());
    assert_eq!(
        first,
        work_cli::finish::finish_with_sink_observed(&changed, id, Some(&sink), |_| {}).unwrap()
    );
    assert_eq!(sink.0.borrow().len(), 1);
    let second =
        work_cli::finish::finish_with_sink_observed(&cfg, id, Some(&sink), |_| {}).unwrap();
    assert_eq!(*sink.0.borrow(), vec![first.operation, first.operation]);
    assert_eq!(second.operation, first.operation);
    assert_eq!(second.local_freeze, work_cli::finish::Freeze::Frozen);
    assert_eq!(second.delivery, Some(work_cli::finish::Delivery::Failed));
    assert!(!second.capture_incomplete);
    let sql = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
    let body: String = sql
        .query_row("SELECT record FROM task_finishes", [], |r| r.get(0))
        .unwrap();
    assert!(!body.contains("secret-"));
    assert_eq!(
        sql.query_row(
            "SELECT count(*) FROM outbox WHERE json_extract(payload,'$.type')='task_finished'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}
#[test]
fn unknown_authority_is_not_initialized_and_arguments_are_sanitized() {
    let f = Fixture::new();
    assert!(!finish(&f, Uuid::now_v7()).status.success());
    assert!(!f.temp.path().join("private").exists());
    assert!(!f.temp.path().join("registry").exists());
    let help = Command::new(env!("CARGO_BIN_EXE_work"))
        .args(["finish", "--help"])
        .env("WORK_CONFIG", f.temp.path().join("config.toml"))
        .output()
        .unwrap();
    assert!(help.status.success());
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("checkout-id"));
    assert!(!text.contains("--force"));
    assert!(!text.contains("--delete"));
    assert!(!f.temp.path().join("private").exists());
    assert!(!f.temp.path().join("registry").exists());
    let output = Command::new(env!("CARGO_BIN_EXE_work"))
        .args(["finish", "secret-token-value"])
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-token-value"));
}
