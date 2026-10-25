mod support;
use support::*;
use uuid::Uuid;
use work_cli::config::Config;
#[path = "support/run_fixture.rs"]
mod run_fixture;
use work_cli::capture_journal::{CaptureSpec, SinkSettings, SinkSnapshot};
fn root_spec(
    a: &work_cli::allocate::Allocation,
) -> (work_cli::run_journal::RootRunRequest, CaptureSpec) {
    let r = run_fixture::request(a.checkout);
    let d = work_cli::capture_bridge::BeginRequest {
        actor_ref: "actor:alice".into(),
        run_ref: r.identity().run_ref.as_str().into(),
        cwd: a.destination.clone(),
        execution_chain: r.identity().execution_chain.clone(),
        task_refs: vec![a.request.task.clone()],
        parent_run_ref: r
            .identity()
            .parent_run_ref
            .as_ref()
            .map(|p| p.as_str().into()),
        key_file: None,
        source: None,
        lifecycle: work_cli::capture_bridge::WorkLifecycle {
            checkout_id: r.identity().checkout.clone(),
            group_id: Some(r.identity().group.clone()),
            mode: work_contract::ExecutionMode::Supervised,
            operation_id: None,
        },
    };
    let s = CaptureSpec::new(
        Uuid::now_v7(),
        SinkSnapshot::new(SinkSettings {
            executable: "/private/capture".into(),
            registry: "/private/actors.json".into(),
            state: "/private/state".into(),
            timeout: std::time::Duration::from_millis(50),
            response_cap: 65536,
            endpoint_identity: "receiver:fixture".into(),
            registry_identity: format!("sha256:{}", "a".repeat(64)),
            receiver_credential_names: vec!["RECEIVER_TOKEN".into()],
            registry_actor_ref: "actor:alice".into(),
        })
        .unwrap(),
        d,
        work_cli::capture_bridge::GitProfile::default(),
    )
    .unwrap();
    (r, s)
}

fn capture_text(_f: &Fixture) -> String {
    format!("\n[capture]\nexecutable = '/private/capture'\nregistry = '/private/actors.json'\nstate_dir = '/private/state'\ntimeout_ms = 50\nresponse_cap = 65536\nregistry_sha256 = '{}'\nendpoint_identity = 'receiver:fixture'\nreceiver_credential_names = ['RECEIVER_TOKEN']\n[capture.actor_refs]\nalice = 'actor:alice'\n", "a".repeat(64))
}
fn configured(f: &Fixture, enabled: bool) -> String {
    let text = std::fs::read_to_string(f.temp.path().join("config.toml")).unwrap();
    let text = if enabled {
        text.replace("[allocation]", "[allocation]\ncapture_sink = 'devdiary'")
    } else {
        text
    };
    text + &capture_text(f)
}
fn setup_config(f: &Fixture) -> Config {
    let text = configured(f,true) + "\n[supervisor]\nruntime_directory = '/private/runtime'\nbus_address = 'unix:path=/private/runtime/bus'\nruntime_max_seconds = 60\npreexec_ms = 100\nclosure_grace_ms = 100\ncancel_grace_ms = 100\n[supervisor.actors.alice]\nauthor_name = 'Alice'\nauthor_email = 'alice@example.invalid'\ncommitter_name = 'Committer'\ncommitter_email = 'committer@example.invalid'\n";
    install(f, &text);
    Config::from_text(&text).unwrap()
}
fn selected_root(
    a: &work_cli::allocate::Allocation,
) -> (work_cli::run_journal::RootRunRequest, CaptureSpec) {
    let (r, s) = root_spec(a);
    let mut value = serde_json::to_value(r).unwrap();
    value["identity"]["actor"] = "alice".into();
    value["input"]["boot"] = a.identity.as_ref().unwrap().boot_id.clone().into();
    let r = serde_json::from_value(value).unwrap();
    let mut d = s.begin_request();
    d.lifecycle.operation_id =
        Some(work_contract::AllocationOperationId::parse(&s.operation().to_string()).unwrap());
    let s = CaptureSpec::new(
        s.operation(),
        s.sink().clone(),
        d,
        work_cli::capture_bridge::GitProfile {
            author_name: Some("Alice".into()),
            author_email: Some("alice@example.invalid".into()),
            committer_name: Some("Committer".into()),
            committer_email: Some("committer@example.invalid".into()),
        },
    )
    .unwrap();
    (r, s)
}
fn prepared(s: &CaptureSpec) -> work_cli::capture_bridge::Prepared {
    let d = s.begin_request();
    let capture = "550e8400-e29b-41d4-a716-446655440001";
    let context = format!("/private/state/{capture}.context.json");
    let g = s.expected_git();
    let value = serde_json::json!({"capture_id":capture,"actor_ref":d.actor_ref,"run_ref":d.run_ref,"state":"open","environment":{
        "AGENT_ATTRIBUTION_CONTEXT":context,"DEVDIARY_ATTRIBUTION_CONTEXT":context,"DEVDIARY_CAPTURE_ID":capture,
        "GIT_AUTHOR_NAME":g.author_name,"GIT_AUTHOR_EMAIL":g.author_email,"GIT_COMMITTER_NAME":g.committer_name,"GIT_COMMITTER_EMAIL":g.committer_email,
    }});
    work_cli::capture_bridge::decode_begin(&serde_json::to_vec(&value).unwrap(), &d, &g).unwrap()
}
fn install(f: &Fixture, text: &str) {
    std::fs::write(f.temp.path().join("config.toml"), text).unwrap();
}
fn sql(f: &Fixture) -> rusqlite::Connection {
    rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap()
}
#[test]
fn host_capture_configuration_is_bounded_and_secret_free() {
    let f = Fixture::new();
    let valid = configured(&f, true);
    assert!(Config::from_text(&valid).is_ok());
    for (from, to) in [
        ("timeout_ms = 50", "timeout_ms = 0"),
        ("timeout_ms = 50", "timeout_ms = 30001"),
        ("response_cap = 65536", "response_cap = 1048577"),
        ("'/private/capture'", "'relative'"),
        ("receiver:fixture", "https://secret@receiver.invalid"),
        ("'RECEIVER_TOKEN'", "'GIT_AUTHOR_NAME'"),
        ("'RECEIVER_TOKEN'", "'DBUS_SESSION_BUS_ADDRESS'"),
        ("['RECEIVER_TOKEN']", "[]"),
        (&"a".repeat(64), &"A".repeat(64)),
    ] {
        let text = valid.replace(from, to);
        let result = Config::from_text(&text);
        assert!(result.is_err(), "accepted {from} -> {to}");
        assert!(!result.unwrap_err().to_string().contains("secret@"));
    }
}
#[test]
fn configured_start_materializes_pending_without_root_or_writer() {
    let f = Fixture::new();
    install(&f, &configured(&f, true));
    let op = Uuid::now_v7().to_string();
    let out = f.start(&op, "task", "topic", &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let a: work_cli::allocate::Allocation = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(a.stage, "capture_pending");
    assert!(a.destination.join(".git").is_file());
    assert!(a
        .identity
        .as_ref()
        .unwrap()
        .private_git_dir
        .join("work-lease.json")
        .is_file());
    let db = sql(&f);
    let state: (String, bool) = db
        .query_row("SELECT state,ready FROM checkouts", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(state, ("partial".into(), false));
    assert_eq!(
        db.query_row(
            "SELECT allocation_operation FROM capture_requirements",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        op
    );
    for table in ["runs", "writers", "capture_runs"] {
        assert_eq!(
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    assert_eq!(f.store().charged(&f.repo, None).unwrap(), 1);
}
#[test]
fn capture_definition_without_opt_in_stays_no_sink() {
    let f = Fixture::new();
    install(&f, &configured(&f, false));
    let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
    assert!(out.status.success());
    let a: work_cli::allocate::Allocation = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(a.stage, "ready");
    assert_eq!(
        sql(&f)
            .query_row("SELECT count(*) FROM capture_requirements", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
#[test]
fn pending_retries_keep_original_charge_path_and_requirement_without_current_config() {
    for remove in [false, true] {
        let f = Fixture::new();
        install(&f, &configured(&f, true));
        let op = Uuid::now_v7().to_string();
        let out = f.start(&op, "task", "topic", &[]);
        assert!(out.status.success());
        let a: work_cli::allocate::Allocation = serde_json::from_slice(&out.stdout).unwrap();
        if remove {
            f.config(0, false);
        }
        for op in [op, Uuid::now_v7().to_string()] {
            let out = f.start(&op, "task", "different", &[]);
            // Exact operation must use its immutable request; matching-key retry can differ.
            let out = if op == a.request.operation.to_string() {
                f.start(&op, "task", "topic", &[])
            } else {
                out
            };
            assert!(
                out.status.success(),
                "remove={remove}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let retry: work_cli::allocate::Allocation =
                serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(retry.checkout, a.checkout);
            assert_eq!(retry.request, a.request);
            assert_eq!(retry.stage, "capture_pending");
        }
        assert_eq!(f.store().charged(&f.repo, None).unwrap(), 1);
        assert!(!sql(&f)
            .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
            .unwrap());
    }
}
#[test]
fn requirement_presence_fences_all_public_writer_admission_despite_forged_ready() {
    for malformed in [false, true] {
        for api in ["bare", "root", "adopted", "captured"] {
            let f = Fixture::new();
            install(&f, &configured(&f, true));
            let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
            let a: work_cli::allocate::Allocation = serde_json::from_slice(&out.stdout).unwrap();
            let (r, s) = root_spec(&a);
            let db = sql(&f);
            db.execute("UPDATE checkouts SET state='active',ready=1", [])
                .unwrap();
            db.execute(
                "UPDATE allocations SET record=json_set(record,'$.stage','ready')",
                [],
            )
            .unwrap();
            if malformed {
                db.execute("UPDATE allocations SET record='invalid'", [])
                    .unwrap();
            }
            let mut store = f.store();
            let events = store.pending_events(100).unwrap();
            let result = match api {
                "bare" => store.acquire_writer(a.checkout, Uuid::now_v7()),
                "root" => store.begin_run(&r).map(|_| ()),
                "captured" => store.begin_captured_run(&r, &s).map(|_| ()),
                _ => store
                    .begin_adopted(&work_cli::adopted::AdoptedRequest {
                        operation: Uuid::now_v7(),
                        identity: r.identity().clone(),
                        source: work_cli::participants::Ref::new("sdk".into()).unwrap(),
                        session: work_cli::participants::Ref::new("session".into()).unwrap(),
                        agent: None,
                    })
                    .map(|_| ()),
            };
            assert!(result.is_err(), "{api} malformed={malformed}");
            assert_eq!(store.pending_events(100).unwrap(), events);
            assert_eq!(
                db.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }
}
#[test]
fn physical_setup_creates_root_then_matched_codec_preparation_promotes_both_authorities() {
    let f = Fixture::new();
    let cfg = setup_config(&f);
    let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
    let a: work_cli::allocate::Allocation = serde_json::from_slice(&out.stdout).unwrap();
    let (r, s) = selected_root(&a);
    let (mut store, result) =
        work_cli::capture_setup::begin(&cfg, &r, &s).expect("fresh physical setup");
    let work_cli::capture_journal::BeginCapturedRun::Created(handle) = result else {
        panic!("created")
    };
    let db = sql(&f);
    assert_eq!(
        db.query_row("SELECT state,ready FROM checkouts", [], |r| Ok((
            r.get::<_, String>(0)?,
            r.get::<_, bool>(1)?
        )))
        .unwrap(),
        ("active".into(), false)
    );
    let p = prepared(&s);
    store.record_capture_prepared(handle, &p).unwrap();
    let a: work_cli::allocate::Allocation = serde_json::from_str(
        &db.query_row("SELECT record FROM allocations", [], |r| {
            r.get::<_, String>(0)
        })
        .unwrap(),
    )
    .unwrap();
    assert_eq!(a.stage, "ready");
    assert!(a.reason.is_none());
    assert_eq!(
        db.query_row("SELECT state,ready FROM checkouts", [], |r| Ok((
            r.get::<_, String>(0)?,
            r.get::<_, bool>(1)?
        )))
        .unwrap(),
        ("active".into(), true)
    );
    assert!(store
        .run_snapshot(&r.identity().run)
        .unwrap()
        .unwrap()
        .binding
        .is_none());
    assert!(store.acquire_writer(a.checkout, Uuid::now_v7()).is_err());
}
#[test]
fn current_selected_host_fields_are_mandatory_for_new_setup_but_not_historical_receipts() {
    let f = Fixture::new();
    let cfg = setup_config(&f);
    let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
    let a: work_cli::allocate::Allocation = serde_json::from_slice(&out.stdout).unwrap();
    let (r, s) = selected_root(&a);
    let before = f.store().pending_events(100).unwrap();
    for field in [
        "sink",
        "registry_actor",
        "git",
        "key_file",
        "no_profile",
        "no_config",
    ] {
        let mut c = cfg.clone();
        match field {
            "sink" => c.capture.as_mut().unwrap().state_dir = "/private/other".into(),
            "registry_actor" => {
                c.capture
                    .as_mut()
                    .unwrap()
                    .actor_refs
                    .insert("alice".into(), "actor:other".into());
            }
            "git" => {
                c.supervisor.as_mut().unwrap().actors.insert(
                    "alice".into(),
                    work_cli::scope_spawn::ActorGitProfile::new(
                        "Other",
                        "o@example.invalid",
                        "Other",
                        "o@example.invalid",
                    )
                    .unwrap(),
                );
            }
            "key_file" => c.capture.as_mut().unwrap().key_file = Some("/private/key".into()),
            "no_profile" => c.supervisor = None,
            _ => c.capture = None,
        }
        assert!(
            work_cli::capture_setup::begin(&c, &r, &s).is_err(),
            "{field}"
        );
        assert_eq!(f.store().pending_events(100).unwrap(), before, "{field}");
    }
    let mut c = cfg.clone();
    c.capture
        .as_mut()
        .unwrap()
        .actor_refs
        .insert("unrelated".into(), "actor:unrelated".into());
    let selected = c
        .capture_spec(&r, &a, s.operation(), vec!["task".into()], None)
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&selected).unwrap(),
        serde_json::to_vec(&s).unwrap()
    );
    let (store, result) = work_cli::capture_setup::begin(&c, &r, &s).unwrap();
    assert!(matches!(
        result,
        work_cli::capture_journal::BeginCapturedRun::Created(_)
    ));
    let events = store.pending_events(100).unwrap();
    drop(result);
    drop(store);
    std::fs::write(
        a.identity
            .as_ref()
            .unwrap()
            .private_git_dir
            .join("work-lease.json"),
        "{}",
    )
    .unwrap();
    std::fs::rename(&f.repo, f.temp.path().join("unavailable-source")).unwrap();
    c.capture = None;
    c.supervisor = None;
    c.allocation.as_mut().unwrap().capture_sink = None;
    let (store, result) = work_cli::capture_setup::begin(&c, &r, &s).unwrap();
    assert!(matches!(
        result,
        work_cli::capture_journal::BeginCapturedRun::Existing(_)
    ));
    assert_eq!(store.pending_events(100).unwrap(), events);
    assert!(!sql(&f)
        .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
        .unwrap());
}
#[test]
fn pending_preparation_refuses_late_durable_context_changes_atomically() {
    for case in [
        "allocation",
        "requirement",
        "finish",
        "hold",
        "outcome",
        "writer",
        "sql_allocation",
        "sql_event",
    ] {
        let f = Fixture::new();
        let cfg = setup_config(&f);
        let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
        let a: work_cli::allocate::Allocation = serde_json::from_slice(&out.stdout).unwrap();
        let (r, s) = selected_root(&a);
        let (mut store, result) = work_cli::capture_setup::begin(&cfg, &r, &s).unwrap();
        let work_cli::capture_journal::BeginCapturedRun::Created(h) = result else {
            panic!("created")
        };
        let db = sql(&f);
        match case {
            "allocation" => {
                db.execute(
                    "UPDATE allocations SET record=json_set(record,'$.reason','changed')",
                    [],
                )
                .unwrap();
            }
            "requirement" => {
                db.execute("UPDATE capture_requirements SET revision=2", [])
                    .unwrap();
            }
            "finish" => {
                db.execute(
                    "INSERT INTO task_finishes VALUES(?1,?2,'{}')",
                    (a.checkout.to_string(), Uuid::now_v7().to_string()),
                )
                .unwrap();
            }
            "sql_allocation" => {
                db.execute_batch("CREATE TRIGGER reject_prepare BEFORE UPDATE ON allocations BEGIN SELECT RAISE(ABORT,'fixture'); END").unwrap();
            }
            "sql_event" => {
                db.execute_batch("CREATE TRIGGER reject_prepare BEFORE INSERT ON outbox WHEN json_extract(NEW.payload,'$.stage')='ready' BEGIN SELECT RAISE(ABORT,'fixture'); END").unwrap();
            }
            "hold" => {
                store.record_recovery_hold(&r).unwrap();
            }
            "outcome" => {
                store
                    .record_root_outcome(&r, work_cli::run_journal::RootOutcome::Failed)
                    .unwrap();
            }
            _ => {
                db.execute(
                    "UPDATE writers SET group_id=?1",
                    [Uuid::now_v7().to_string()],
                )
                .unwrap();
            }
        }
        let events = store.pending_events(100).unwrap();
        let record: String = db
            .query_row("SELECT record FROM allocations", [], |r| r.get(0))
            .unwrap();
        assert!(
            store.record_capture_prepared(h, &prepared(&s)).is_err(),
            "{case}"
        );
        assert_eq!(store.pending_events(100).unwrap(), events);
        assert_eq!(
            db.query_row("SELECT record FROM allocations", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            record
        );
        assert!(!db
            .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
            .unwrap());
        assert!(db
            .query_row("SELECT prepared IS NULL FROM capture_runs", [], |r| r
                .get::<_, bool>(0))
            .unwrap());
    }
}
#[test]
fn schema_eleven_preserves_v10_capture_finish_allocation_and_outbox_bytes_without_backfill() {
    let f = Fixture::new();
    let mut cfg = setup_config(&f);
    let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
    let a: work_cli::allocate::Allocation = serde_json::from_slice(&out.stdout).unwrap();
    let (r, s) = selected_root(&a);
    let (mut store, result) = work_cli::capture_setup::begin(&cfg, &r, &s).unwrap();
    let work_cli::capture_journal::BeginCapturedRun::Created(h) = result else {
        panic!("created")
    };
    store.record_capture_prepared(h, &prepared(&s)).unwrap();
    cfg.allocation.as_mut().unwrap().capture_sink = None;
    let mut req = a.request.clone();
    req.operation = Uuid::now_v7();
    req.task = "other".into();
    req.branch = Some("other".into());
    let other = work_cli::allocate::start(&cfg, req).unwrap();
    work_cli::finish::finish(&cfg, other.checkout).unwrap();
    let db = sql(&f);
    let tables = [
        "checkouts",
        "allocations",
        "capture_runs",
        "task_finishes",
        "runs",
        "run_groups",
        "writers",
        "outbox",
    ];
    let rows = || {
        tables
            .iter()
            .map(|table| {
                let mut stmt = db
                    .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                    .unwrap();
                let cols = stmt.column_count();
                stmt.query_map([], |r| {
                    (0..cols)
                        .map(|i| r.get::<_, rusqlite::types::Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
            })
            .collect::<Vec<_>>()
    };
    let before = rows();
    db.execute_batch(
        "DROP TABLE quarantine_actions; DROP TABLE retirement_intents; DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; DROP TABLE attribution_gaps; DROP TABLE capture_readiness; DROP TABLE capture_finalizations; DROP TABLE capture_requirements; PRAGMA user_version=10",
    )
    .unwrap();
    drop(store);
    let mut store = f.store();
    assert_eq!(rows(), before);
    assert_eq!(
        db.query_row("SELECT count(*) FROM capture_requirements", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(matches!(
        store.begin_captured_run(&r, &s).unwrap(),
        work_cli::capture_journal::BeginCapturedRun::Existing(_)
    ));
    assert!(store.begin_run(&run_fixture::request(a.checkout)).is_err());
    drop(store);
    for ddl in ["DROP INDEX capture_requirement_operation", "ALTER TABLE capture_requirements RENAME TO old_requirements; CREATE VIEW capture_requirements AS SELECT * FROM old_requirements"] {
        db.execute_batch(ddl).unwrap();
        assert!(work_cli::store::Store::open_registered(&f.temp.path().join("registry"),&f.temp.path().join("private"),std::slice::from_ref(&f.root)).is_err());
        assert!(work_cli::store::Store::open_existing_registered_readonly(&f.temp.path().join("registry"),&f.temp.path().join("private"),std::slice::from_ref(&f.root)).is_err());
        if ddl.starts_with("DROP INDEX") {db.execute_batch("CREATE INDEX capture_requirement_operation ON capture_requirements(allocation_operation)").unwrap();}
        else {db.execute_batch("DROP VIEW capture_requirements; ALTER TABLE old_requirements RENAME TO capture_requirements").unwrap();}
    }
    db.execute_batch("DROP TABLE quarantine_actions; DROP TABLE retirement_intents; DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; DROP TABLE attribution_gaps; DROP TABLE capture_readiness; DROP TABLE capture_finalizations; DROP TABLE capture_requirements; PRAGMA user_version=10; CREATE VIEW capture_requirements AS SELECT 1 AS obstruction").unwrap();
    assert!(work_cli::store::Store::open_registered(
        &f.temp.path().join("registry"),
        &f.temp.path().join("private"),
        std::slice::from_ref(&f.root)
    )
    .is_err());
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        10
    );
    assert_eq!(rows(), before);
}
#[test]
fn forged_ready_allocation_cannot_make_generic_reconciliation_certify_capture() {
    let f = Fixture::new();
    install(&f, &configured(&f, true));
    let op = Uuid::now_v7().to_string();
    assert!(f.start(&op, "task", "topic", &[]).status.success());
    let db = sql(&f);
    db.execute(
        "UPDATE allocations SET record=json_set(record,'$.stage','ready','$.reason',NULL)",
        [],
    )
    .unwrap();
    db.execute("UPDATE checkouts SET state='active',ready=1", [])
        .unwrap();
    f.config(10, false);
    let result = f.start(&op, "task", "topic", &[]);
    assert!(
        !result.status.success(),
        "forged Ready certified by generic reconcile"
    );
}
#[test]
fn required_foreign_allocation_stages_cannot_be_reconciled_into_pending() {
    for stage in ["foreign", "closed", "capture_prepared"] {
        let f = Fixture::new();
        install(&f, &configured(&f, true));
        let op = Uuid::now_v7().to_string();
        assert!(f.start(&op, "task", "topic", &[]).status.success());
        let db = sql(&f);
        db.execute(
            "UPDATE allocations SET record=json_set(record,'$.stage',?1)",
            [stage],
        )
        .unwrap();
        let before: String = db
            .query_row("SELECT record FROM allocations", [], |r| r.get(0))
            .unwrap();
        let events = f.store().pending_events(100).unwrap();
        assert!(
            !f.start(&op, "task", "topic", &[]).status.success(),
            "revived {stage}"
        );
        assert_eq!(
            db.query_row("SELECT record FROM allocations", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            before
        );
        assert_eq!(f.store().pending_events(100).unwrap(), events);
    }
}
#[test]
fn interrupted_materialization_retains_requirement_when_current_config_is_removed() {
    for boundary in ["reserved", "identity", "marker"] {
        let f = Fixture::new();
        let cfg = Config::from_text(&configured(&f, true)).unwrap();
        let req = work_cli::allocate::Start {
            operation: Uuid::now_v7(),
            repository: Some(f.repo.clone()),
            root: Some(f.root.clone()),
            actor: Some("alice".into()),
            owner: None,
            task: "task".into(),
            branch: Some("topic".into()),
            base: "main".into(),
            reuse_branch: false,
        };
        let interrupted = std::panic::catch_unwind(|| {
            work_cli::allocate::start_observed(&cfg, req.clone(), |at| {
                if at == boundary {
                    panic!("fixture interrupted materialization")
                }
            })
        });
        assert!(interrupted.is_err());
        let db = sql(&f);
        assert_eq!(
            db.query_row(
                "SELECT allocation_operation FROM capture_requirements",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            req.operation.to_string()
        );
        f.config(0, false);
        let cfg =
            Config::from_text(&std::fs::read_to_string(f.temp.path().join("config.toml")).unwrap())
                .unwrap();
        let result = work_cli::allocate::start(&cfg, req);
        if boundary == "identity" {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap().stage, "capture_pending");
        }
        assert!(!db
            .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
            .unwrap());
        assert_eq!(f.store().charged(&f.repo, None).unwrap(), 1);
        assert_eq!(
            db.query_row("SELECT count(*) FROM capture_requirements", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        for table in ["runs", "capture_runs", "writers"] {
            assert_eq!(
                db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }
}
#[test]
fn requirement_and_allocation_intent_rollback_with_reservation_and_events() {
    for target in ["allocations", "capture_requirements", "outbox"] {
        let f = Fixture::new();
        install(&f, &configured(&f, true));
        let store = f.store();
        let events = store.pending_events(100).unwrap();
        let db = sql(&f);
        db.execute_batch(&format!("CREATE TRIGGER reject_reservation BEFORE INSERT ON {target} BEGIN SELECT RAISE(ABORT,'fixture'); END")).unwrap();
        let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
        assert!(!out.status.success());
        assert!(!f.root.join("task").exists());
        for table in ["checkouts", "allocations", "capture_requirements"] {
            assert_eq!(
                db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0,
                "{target}/{table}"
            );
        }
        assert_eq!(store.pending_events(100).unwrap(), events);
    }
}
