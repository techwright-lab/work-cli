use rusqlite::Connection;
use uuid::Uuid;
use work_cli::{
    admission::{Limits, Reservation},
    store::Store,
};

fn fixture() -> (tempfile::TempDir, Store, Uuid) {
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
    // Synthetic durable allocation-readiness fixture, no Git or scope backend.
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute(
        "UPDATE checkouts SET state='active',ready=1 WHERE id=?1",
        [checkout.to_string()],
    )
    .unwrap();
    (dir, store, checkout)
}
fn reopen(dir: &tempfile::TempDir) -> work_cli::store::Result<Store> {
    Store::open(&dir.path().join("private"), &[dir.path().join("root")])
}
use std::time::{Duration, Instant};
use work_cli::run_journal::{
    BeginRun, RootOutcome, RootRunRequest, RunIdentity, RunInput, RunStage, Transition,
};
use work_cli::runtime_scope::{
    self, ActiveStatus, Binding, ChildIdentity, Coverage, LaunchIntent, LoadStatus, Membership,
    Observation, ScopeIdentity, UnitPresence,
};
use work_contract::{ActorId, ChainText, CheckoutId, GroupId, RunId, RunRef};
const BOOT: &str = "550e8400-e29b-41d4-a716-446655440000";
fn request(checkout: Uuid) -> RootRunRequest {
    RootRunRequest::new(
        RunIdentity {
            checkout: CheckoutId::parse(&checkout.to_string()).unwrap(),
            group: GroupId::generate(),
            run: RunId::generate(),
            run_ref: RunRef::parse(&format!("run:{}", Uuid::now_v7())).unwrap(),
            actor: ActorId::parse("reviewer-not-owner").unwrap(),
            parent_run_ref: Some(RunRef::parse("external:parent").unwrap()),
            execution_chain: serde_json::from_value(
                serde_json::json!([{"kind":"executor","system":"test"}]),
            )
            .unwrap(),
        },
        RunInput {
            command_digest: [1; 32],
            input_digest: [2; 32],
            context_ref: ChainText::new("context".into()).unwrap(),
            intent_ref: ChainText::new("intent".into()).unwrap(),
            boot: BOOT.into(),
        },
    )
    .unwrap()
}
fn changed(r: &RootRunRequest, field: &str, value: serde_json::Value) -> RootRunRequest {
    let mut json = serde_json::to_value(r).unwrap();
    json["identity"][field] = value;
    serde_json::from_value(json).unwrap()
}
fn binding(r: &RootRunRequest) -> Binding {
    let intent = LaunchIntent::new(r.identity().run.clone(), &r.input().boot).unwrap();
    let identity = ScopeIdentity {
        unit: intent.unit_name().into(),
        invocation: "550e8400e29b41d4a716446655440000".into(),
        cgroup: format!("/test/{}", intent.unit_name()),
    };
    let child = ChildIdentity {
        pid: 42,
        start_ticks: 10,
        boot: r.input().boot.clone(),
        cgroup: identity.cgroup.clone(),
    };
    let now = Instant::now();
    runtime_scope::bind(
        &intent,
        &child,
        &Observation {
            boot: child.boot.clone(),
            observed_at: now,
            unit: UnitPresence::Present {
                identity,
                load: LoadStatus::Loaded,
                active: ActiveStatus::Active,
            },
            membership: Membership::Present(vec![child.clone()]),
            recursive_coverage: Coverage::Complete,
            participant_coverage: Coverage::Unknown,
            participants: vec![],
        },
        now,
        Duration::from_secs(1),
    )
    .unwrap()
}

#[test]
fn corrupt_persisted_run_metadata_fails_closed_at_every_recovery_entrypoint() {
    use serde_json::json;
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &binding(&r)).unwrap();
    let original = store.run_snapshot(&r.identity().run).unwrap().unwrap();
    let snapshot = serde_json::to_value(original.binding.as_ref().unwrap()).unwrap();
    let scope = snapshot["cgroup"].as_str().unwrap();
    let unit = snapshot["unit"].as_str().unwrap();
    let mut cases = Vec::new();
    for (field, bad) in [
        ("invocation", json!("")),
        ("invocation", json!("00000000000000000000000000000000")),
        ("invocation", json!("550E8400E29B41D4A716446655440000")),
        ("invocation", json!(BOOT)),
        ("unit", json!("work-run-other.scope")),
        ("cgroup", json!(format!("test/{unit}"))),
        ("cgroup", json!(format!("/test//{unit}"))),
        ("cgroup", json!(format!("/test/./{unit}"))),
        ("cgroup", json!(format!("/test/../{unit}"))),
        ("cgroup", json!(format!("/test/\n/{unit}"))),
        ("cgroup", json!(format!("{scope}/"))),
        ("cgroup", json!("/unrelated.scope")),
        ("root_cgroup", json!("/unrelated")),
        ("root_cgroup", json!(format!("{scope}-other/child"))),
        ("root_cgroup", json!(format!("{scope}//child"))),
        ("root_cgroup", json!(format!("{scope}/../child"))),
        ("root_cgroup", json!(format!("{scope}/child/"))),
        ("root_pid", json!(0)),
        ("root_pid", json!(i32::MAX as u32 + 1)),
        ("root_start_ticks", json!(0)),
        ("boot", json!("650e8400-e29b-41d4-a716-446655440000")),
    ] {
        let mut corrupt = snapshot.clone();
        corrupt[field] = bad.clone();
        cases.push((format!("{field}={bad}"), "bound", Some(corrupt), None));
    }
    for stage in ["intent", "bound"] {
        cases.push((
            format!("completed at {stage}"),
            stage,
            if stage == "intent" {
                None
            } else {
                Some(snapshot.clone())
            },
            Some("\"completed\""),
        ));
    }
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let events = store.pending_events(100).unwrap();
    let mut accepted = Vec::new();
    for (label, stage, bound, outcome) in cases {
        sql.execute(
            "UPDATE runs SET stage=?1,binding=?2,outcome=?3 WHERE id=?4",
            (
                stage,
                bound
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()
                    .unwrap(),
                outcome,
                r.identity().run.to_string(),
            ),
        )
        .unwrap();
        if store.run_snapshot(&r.identity().run).is_ok() {
            accepted.push(format!("snapshot: {label}"));
        }
        if store.recovery_runs().is_ok() {
            accepted.push(format!("recovery: {label}"));
        }
        if store.begin_run(&r).is_ok() {
            accepted.push(format!("retry: {label}"));
        }
        assert_eq!(store.pending_events(100).unwrap(), events, "{label}");
        let writer: String = sql
            .query_row(
                "SELECT group_id FROM writers WHERE checkout=?1",
                [checkout.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(writer, r.identity().group.to_string(), "{label}");
        assert_eq!(
            store
                .charged(&dir.path().join("root"), Some("owner"))
                .unwrap(),
            1,
            "{label}"
        );
    }
    sql.execute(
        "UPDATE runs SET stage='bound',binding=?1,outcome=NULL",
        [serde_json::to_string(&snapshot).unwrap()],
    )
    .unwrap();
    assert_eq!(
        store.run_snapshot(&r.identity().run).unwrap().unwrap(),
        original
    );
    assert!(
        accepted.is_empty(),
        "corrupt metadata accepted:\n{}",
        accepted.join("\n")
    );
}

#[test]
fn legal_stage_outcomes_and_structural_boundary_values_remain_readable() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &binding(&r)).unwrap();
    let mut snapshot = serde_json::to_value(
        store
            .run_snapshot(&r.identity().run)
            .unwrap()
            .unwrap()
            .binding
            .unwrap(),
    )
    .unwrap();
    snapshot["root_pid"] = serde_json::json!(i32::MAX);
    snapshot["root_cgroup"] = serde_json::json!(format!(
        "{}/child/nested",
        snapshot["cgroup"].as_str().unwrap()
    ));
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let events = store.pending_events(100).unwrap();
    for stage in ["intent", "bound", "permit_attempt"] {
        for outcome in [
            None,
            Some(RootOutcome::Failed),
            Some(RootOutcome::Cancelled),
            Some(RootOutcome::Completed),
        ] {
            if outcome == Some(RootOutcome::Completed) && stage != "permit_attempt" {
                continue;
            }
            sql.execute(
                "UPDATE runs SET stage=?1,binding=?2,outcome=?3 WHERE id=?4",
                (
                    stage,
                    if stage == "intent" {
                        None
                    } else {
                        Some(serde_json::to_string(&snapshot).unwrap())
                    },
                    outcome.map(|o| serde_json::to_string(&o).unwrap()),
                    r.identity().run.to_string(),
                ),
            )
            .unwrap();
            let record = store.run_snapshot(&r.identity().run).unwrap().unwrap();
            assert_eq!(record.outcome, outcome);
            assert_eq!(store.recovery_runs().unwrap(), vec![record]);
            assert_eq!(store.begin_run(&r).unwrap(), BeginRun::Existing);
        }
    }
    assert_eq!(store.pending_events(100).unwrap(), events);
}

#[test]
fn begin_is_atomic_idempotent_and_conflicts_on_every_immutable_dimension() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    assert_eq!(store.begin_run(&r).unwrap(), BeginRun::Created);
    let n = store.pending_events(100).unwrap().len();
    assert_eq!(store.begin_run(&r).unwrap(), BeginRun::Existing);
    for (field, value) in [
        ("actor", serde_json::json!("other")),
        ("run_ref", serde_json::json!("other:ref")),
        ("group", serde_json::json!(GroupId::generate())),
        ("checkout", serde_json::json!(CheckoutId::generate())),
        (
            "execution_chain",
            serde_json::json!([{"kind":"executor","system":"other"}]),
        ),
        ("parent_run_ref", serde_json::json!("other:parent")),
    ] {
        assert!(
            store.begin_run(&changed(&r, field, value)).is_err(),
            "{field}"
        );
    }
    let mut json = serde_json::to_value(&r).unwrap();
    json["input"]["input_digest"] = serde_json::json!(vec![3; 32]);
    let conflict: RootRunRequest = serde_json::from_value(json).unwrap();
    assert!(store.begin_run(&conflict).is_err());
    for field in ["group", "run_ref"] {
        let other = request(checkout);
        let same = serde_json::to_value(&r).unwrap()["identity"][field].clone();
        assert!(store.begin_run(&changed(&other, field, same)).is_err());
    }
    assert_eq!(store.pending_events(100).unwrap().len(), n);
    assert_eq!(
        store
            .charged(&dir.path().join("root"), Some("owner"))
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .charged(&dir.path().join("root"), Some("reviewer-not-owner"))
            .unwrap(),
        0
    );
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let counts: (i64,i64,i64) = sql.query_row("SELECT (SELECT count(*) FROM writers),(SELECT count(*) FROM runs),(SELECT count(*) FROM run_groups)", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
    assert_eq!(counts, (1, 1, 1));
}
#[test]
fn concurrent_independent_roots_contend_and_bare_writer_is_never_adopted() {
    let (dir, mut first, checkout) = fixture();
    let mut second = reopen(&dir).unwrap();
    let a = request(checkout);
    let b = request(checkout);
    let x = std::thread::spawn(move || first.begin_run(&a));
    let y = std::thread::spawn(move || second.begin_run(&b));
    assert_eq!(
        usize::from(x.join().unwrap().is_ok()) + usize::from(y.join().unwrap().is_ok()),
        1
    );
    let (_dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store
        .acquire_writer(
            checkout,
            Uuid::parse_str(&r.identity().group.to_string()).unwrap(),
        )
        .unwrap();
    assert!(store.begin_run(&r).is_err());
    assert!(store.run_snapshot(&r.identity().run).unwrap().is_none());
}
#[test]
fn bound_permit_terminal_and_hold_are_durable_separate_and_never_release_writer() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    assert!(store.record_permit_attempt(&r, &b).is_err());
    for wrong in [binding(&request(checkout)), {
        let mut json = serde_json::to_value(&r).unwrap();
        json["input"]["boot"] = serde_json::json!("650e8400-e29b-41d4-a716-446655440000");
        binding(&serde_json::from_value(json).unwrap())
    }] {
        assert!(store.record_bound(&r, &wrong).is_err());
    }
    assert_eq!(store.record_bound(&r, &b).unwrap(), Transition::Changed);
    let bound = store.run_snapshot(&r.identity().run).unwrap().unwrap();
    assert_eq!(bound.stage, RunStage::Bound);
    assert!(bound.binding.is_some());
    assert_eq!(store.record_bound(&r, &b).unwrap(), Transition::Existing);
    assert_eq!(
        store.record_permit_attempt(&r, &b).unwrap(),
        Transition::Changed
    );
    assert_eq!(store.record_bound(&r, &b).unwrap(), Transition::Existing);
    assert_eq!(
        store
            .run_snapshot(&r.identity().run)
            .unwrap()
            .unwrap()
            .stage,
        RunStage::PermitAttempt
    );
    assert_eq!(
        store
            .record_root_outcome(&r, RootOutcome::Completed)
            .unwrap(),
        Transition::Changed
    );
    let n = store.pending_events(100).unwrap().len();
    assert_eq!(
        store
            .record_root_outcome(&r, RootOutcome::Completed)
            .unwrap(),
        Transition::Existing
    );
    assert!(store.record_root_outcome(&r, RootOutcome::Failed).is_err());
    assert_eq!(store.begin_run(&r).unwrap(), BeginRun::Existing);
    assert_eq!(store.pending_events(100).unwrap().len(), n);
    // Root exit cannot close a group: recursive descendants / unknown roster may remain.
    assert!(store.acquire_writer(checkout, Uuid::now_v7()).is_err());
    assert!(store.begin_run(&request(checkout)).is_err());
    assert_eq!(store.record_recovery_hold(&r).unwrap(), Transition::Changed);
    assert_eq!(
        store.record_recovery_hold(&r).unwrap(),
        Transition::Existing
    );
    drop(store);
    let store = reopen(&dir).unwrap();
    let recovered = store.recovery_runs().unwrap();
    assert_eq!(recovered.len(), 1);
    assert!(recovered[0].recovery_hold);
    assert_eq!(recovered[0].outcome, Some(RootOutcome::Completed));
    assert_eq!(recovered[0].stage, RunStage::PermitAttempt);
}

#[test]
fn report_rejects_missing_older_versioned_tables_and_views_are_not_journals() {
    let (dir, _store, _) = fixture();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch(
        "ALTER TABLE runs RENAME TO saved_runs; CREATE VIEW runs AS SELECT * FROM saved_runs;",
    )
    .unwrap();
    assert!(
        reopen(&dir).is_err(),
        "a view must not substitute a journal table"
    );
    let registry =
        Connection::open(dir.path().join(".work-authorities/authorities.sqlite")).unwrap();
    registry
        .query_row("SELECT count(*) FROM authorities", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap();
    sql.execute_batch("DROP VIEW runs; ALTER TABLE saved_runs RENAME TO runs; DROP TABLE runs; DROP TABLE run_groups; PRAGMA user_version=3;").unwrap();
    work_cli::store::report_existing(
        &dir.path().join(".work-authorities"),
        &dir.path().join("private"),
        &[dir.path().join("root")],
    )
    .unwrap();
    sql.execute_batch("DROP TABLE repository_aliases").unwrap();
    assert!(work_cli::store::report_existing(
        &dir.path().join(".work-authorities"),
        &dir.path().join("private"),
        &[dir.path().join("root")]
    )
    .is_err());
}
#[test]
fn completed_root_requires_permit_intent_and_hold_blocks_new_launch_progress() {
    let (_dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    assert!(store
        .record_root_outcome(&r, RootOutcome::Completed)
        .is_err());
    store.record_recovery_hold(&r).unwrap();
    assert!(store.record_bound(&r, &binding(&r)).is_err());
    assert_eq!(
        store
            .record_root_outcome(&r, RootOutcome::Cancelled)
            .unwrap(),
        Transition::Changed
    );
    assert_eq!(store.begin_run(&r).unwrap(), BeginRun::Existing);
}

#[test]
fn journal_crash_worker() {
    let Ok(base) = std::env::var("WORK_JOURNAL_TEST_BASE") else {
        return;
    };
    let base = std::path::Path::new(&base);
    let r: RootRunRequest =
        serde_json::from_str(&std::env::var("WORK_JOURNAL_TEST_REQUEST").unwrap()).unwrap();
    let stage = std::env::var("WORK_JOURNAL_TEST_STAGE").unwrap();
    let mut store = Store::open(&base.join("private"), &[base.join("root")]).unwrap();
    store.begin_run(&r).unwrap();
    if stage != "intent" {
        store.record_bound(&r, &binding(&r)).unwrap();
    }
    if stage == "permit" {
        store.record_permit_attempt(&r, &binding(&r)).unwrap();
    }
    std::process::abort();
}
#[test]
fn killed_process_at_each_committed_stage_retains_writer_and_never_relaunches() {
    for (stage, expected) in [
        ("intent", RunStage::Intent),
        ("bound", RunStage::Bound),
        ("permit", RunStage::PermitAttempt),
    ] {
        let (dir, store, checkout) = fixture();
        let r = request(checkout);
        drop(store);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "journal_crash_worker"])
            .env("WORK_JOURNAL_TEST_BASE", dir.path())
            .env(
                "WORK_JOURNAL_TEST_REQUEST",
                serde_json::to_string(&r).unwrap(),
            )
            .env("WORK_JOURNAL_TEST_STAGE", stage)
            .current_dir(dir.path())
            .status()
            .unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(6), "{stage}");
        let mut store = reopen(&dir).unwrap();
        let n = store.pending_events(100).unwrap().len();
        assert_eq!(store.begin_run(&r).unwrap(), BeginRun::Existing);
        assert_eq!(store.pending_events(100).unwrap().len(), n);
        let snapshot = store.run_snapshot(&r.identity().run).unwrap().unwrap();
        assert_eq!(snapshot.stage, expected);
        assert_eq!(snapshot.outcome, None);
        assert!(!snapshot.recovery_hold); // no invented reboot/heartbeat activity
        assert!(store.acquire_writer(checkout, Uuid::now_v7()).is_err());
        assert!(store.begin_run(&request(checkout)).is_err());
    }
}
#[test]
fn failed_event_insert_rolls_back_writer_intent_and_transitions_together() {
    let (dir, mut store, checkout) = fixture();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch("CREATE TRIGGER reject_journal BEFORE INSERT ON outbox WHEN json_extract(NEW.payload,'$.type')='run_journal_changed' BEGIN SELECT RAISE(ABORT,'test disk failure'); END;").unwrap();
    let r = request(checkout);
    let n = store.pending_events(100).unwrap().len();
    assert!(store.begin_run(&r).is_err());
    assert!(store.run_snapshot(&r.identity().run).unwrap().is_none());
    let writer_count: i64 = sql
        .query_row("SELECT count(*) FROM writers", [], |r| r.get(0))
        .unwrap();
    assert_eq!(writer_count, 0);
    assert_eq!(store.pending_events(100).unwrap().len(), n);
    sql.execute_batch("DROP TRIGGER reject_journal").unwrap();
    assert_eq!(store.begin_run(&r).unwrap(), BeginRun::Created);
    sql.execute_batch("CREATE TRIGGER reject_journal BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'test disk failure'); END;").unwrap();
    assert!(store.record_bound(&r, &binding(&r)).is_err());
    let snapshot = store.run_snapshot(&r.identity().run).unwrap().unwrap();
    assert_eq!(snapshot.stage, RunStage::Intent);
    assert_eq!(snapshot.revision, 1);
    assert!(snapshot.binding.is_none());
}
#[test]
fn old_schemas_preserve_charges_outbox_legacy_writers_and_aliases() {
    for version in 1..=3 {
        let (dir, mut store, checkout) = fixture();
        let group = Uuid::now_v7();
        store.acquire_writer(checkout, group).unwrap();
        let events = store.pending_events(100).unwrap();
        let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        sql.execute(
            "INSERT INTO repository_aliases VALUES('alias',?1)",
            [dir.path().join("root").to_str().unwrap()],
        )
        .unwrap();
        sql.execute_batch("DROP TABLE runs; DROP TABLE run_groups;")
            .unwrap();
        if version < 3 {
            sql.execute_batch("DROP TABLE repository_aliases").unwrap();
        }
        if version < 2 {
            sql.execute_batch("DROP TABLE allocations; ALTER TABLE checkouts DROP COLUMN ready")
                .unwrap();
        }
        sql.execute_batch(&format!("PRAGMA user_version={version}"))
            .unwrap();
        drop(store);
        let mut store = reopen(&dir).unwrap();
        assert_eq!(store.pending_events(100).unwrap(), events, "v{version}");
        assert_eq!(
            store
                .charged(&dir.path().join("root"), Some("owner"))
                .unwrap(),
            1
        );
        let legacy: String = sql
            .query_row(
                "SELECT group_id FROM writers WHERE checkout=?1",
                [checkout.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(legacy, group.to_string());
        let r = changed(
            &request(checkout),
            "group",
            serde_json::json!(group.to_string()),
        );
        assert!(store.begin_run(&r).is_err());
        assert!(
            store.recovery_runs().unwrap().is_empty(),
            "legacy writers remain UNKNOWN, not converted"
        );
        if version == 3 {
            let alias: String = sql
                .query_row(
                    "SELECT common FROM repository_aliases WHERE alias='alias'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(alias, dir.path().join("root").to_str().unwrap());
        }
    }
}
#[test]
fn failed_migration_rolls_back_new_tables_and_version_without_repairing_old_loss() {
    let (dir, store, _) = fixture();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch("DROP TABLE runs; DROP TABLE run_groups; DROP TABLE repository_aliases; PRAGMA user_version=3").unwrap();
    drop(store);
    assert!(reopen(&dir).is_err());
    let version: i64 = sql
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 3);
    let tables: i64 = sql
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name IN ('runs','run_groups')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tables, 0);
}

#[test]
fn schema_four_is_durable_and_missing_versioned_tables_fail_closed() {
    let (dir, store, _) = fixture();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let version: i64 = sql
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 4, "journal requires a durable v4 migration");
    for table in ["run_groups", "runs"] {
        sql.execute_batch(&format!("ALTER TABLE {table} RENAME TO missing_{table}"))
            .unwrap();
        assert!(
            reopen(&dir).is_err(),
            "missing {table} must never be repaired"
        );
        sql.execute_batch(&format!("ALTER TABLE missing_{table} RENAME TO {table}"))
            .unwrap();
    }
    drop(store);
    assert!(reopen(&dir).is_ok());
}
