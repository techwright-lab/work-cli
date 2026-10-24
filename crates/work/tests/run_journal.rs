use rusqlite::Connection;
use uuid::Uuid;
use work_cli::store::Store;

use std::time::Duration;
use work_cli::run_journal::{BeginRun, RootOutcome, RootRunRequest, RunStage, Transition};
use work_contract::{CheckoutId, GroupId};
#[path = "support/run_fixture.rs"]
mod fixture_support;
use fixture_support::*;

#[test]
fn attribution_marker_preserves_legacy_shapes_and_rejects_positional_marker() {
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    let original = request(Uuid::now_v7());
    let canonical = serde_json::to_vec(&original).unwrap();
    let digest = Sha256::digest(&canonical);
    let object = serde_json::to_value(&original).unwrap();
    let input = &object["input"];
    assert!(input.get("attribution").is_none());
    let legacy_input = json!([
        input["command_digest"],
        input["input_digest"],
        input["context_ref"],
        input["intent_ref"],
        input["boot"]
    ]);
    let identity = &object["identity"];
    let legacy_identity = json!([
        identity["checkout"],
        identity["group"],
        identity["run"],
        identity["run_ref"],
        identity["actor"],
        identity["parent_run_ref"],
        identity["execution_chain"]
    ]);
    for identity in [identity.clone(), legacy_identity] {
        for input in [input.clone(), legacy_input.clone()] {
            for outer in [
                json!({"identity":identity,"input":input}),
                json!([identity, input]),
            ] {
                let decoded: RootRunRequest = serde_json::from_value(outer).unwrap();
                assert_eq!(decoded, original);
                let encoded = serde_json::to_vec(&decoded).unwrap();
                assert_eq!(encoded, canonical);
                assert_eq!(Sha256::digest(&encoded), digest);
            }
        }
    }
    let mut off = object.clone();
    off["input"]["attribution"] = json!("off");
    let decoded: RootRunRequest = serde_json::from_value(off.clone())
        .expect("map-only off declaration must decode without granting authority");
    assert_eq!(serde_json::to_value(decoded).unwrap(), off);
    for marker in [
        Value::Null,
        json!("on"),
        json!("unknown"),
        json!(true),
        json!(1),
        json!({}),
        json!({"off":null}),
        json!([]),
    ] {
        let mut invalid = object.clone();
        invalid["input"]["attribution"] = marker;
        assert!(serde_json::from_value::<RootRunRequest>(invalid).is_err());
    }
    let input_text = serde_json::to_string(input).unwrap();
    let duplicate = format!(
        "{},\"attribution\":\"off\",\"attribution\":\"off\"}}",
        input_text.strip_suffix('}').unwrap()
    );
    let duplicate = format!(
        "{{\"identity\":{},\"input\":{duplicate}}}",
        serde_json::to_string(identity).unwrap()
    );
    assert!(serde_json::from_str::<RootRunRequest>(&duplicate).is_err());
    for sixth in [
        json!("off"),
        Value::Null,
        json!(false),
        json!(0),
        json!({}),
        json!([]),
    ] {
        let mut sequence = legacy_input.as_array().unwrap().clone();
        sequence.push(sixth);
        let mut invalid = object.clone();
        invalid["input"] = json!(sequence);
        assert!(serde_json::from_value::<RootRunRequest>(invalid).is_err());
    }
    for length in 0..5 {
        let mut invalid = object.clone();
        invalid["input"] = json!(&legacy_input.as_array().unwrap()[..length]);
        assert!(serde_json::from_value::<RootRunRequest>(invalid).is_err());
    }
    for index in 0..5 {
        let mut invalid = object.clone();
        let mut sequence = legacy_input.as_array().unwrap().clone();
        sequence[index] = Value::Null;
        invalid["input"] = json!(sequence);
        assert!(serde_json::from_value::<RootRunRequest>(invalid).is_err());
    }
}

#[test]
fn lifecycle_sql_budget_does_not_charge_later_accounting_for_idle_time() {
    let (dir, mut store, checkout) = fixture();
    let root = dir.path().join("root");
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        true,
    )
    .unwrap();
    // Valid rows force progress callbacks in ordinary accounting/outbox scans.
    for _ in 0..300 {
        sql.execute("INSERT INTO checkouts SELECT ?1,?2,digest,repository,actor,task,owner,state,ready FROM checkouts WHERE id=?3",
            (Uuid::now_v7().to_string(), Uuid::now_v7().to_string(), checkout.to_string())).unwrap();
    }
    sql.execute_batch("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<600) INSERT INTO outbox(version,payload,acknowledged) SELECT version,payload,1 FROM outbox,n LIMIT 600;").unwrap();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    // Exercise a genuine bare-writer retry: managed identities may only retry
    // through begin_run, not acquire_writer, even on their original checkout.
    let bare_checkout: String = sql
        .query_row(
            "SELECT id FROM checkouts WHERE id!=?1 LIMIT 1",
            [checkout.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let bare_checkout = Uuid::parse_str(&bare_checkout).unwrap();
    let group = Uuid::now_v7();
    store.acquire_writer(bare_checkout, group).unwrap();
    for _ in 0..2 {
        for operation in [
            "charged",
            "find_reusable",
            "pending_events",
            "acquire_writer",
        ] {
            store.run_snapshot(&r.identity().run).unwrap().unwrap();
            std::thread::sleep(Duration::from_millis(650));
            match operation {
                "charged" => assert_eq!(store.charged(&root, None).unwrap(), 301),
                "find_reusable" => assert_eq!(
                    store
                        .find_reusable("allocator", &root, "task")
                        .unwrap()
                        .len(),
                    301
                ),
                "pending_events" => assert!(!store.pending_events(1000).unwrap().is_empty()),
                "acquire_writer" => store.acquire_writer(bare_checkout, group).unwrap(),
                _ => unreachable!(),
            }
        }
    }
    // Constructors must not return their bounded preflight deadline still armed.
    for writable in [false, true] {
        let registry = dir.path().join(".work-authorities");
        let private = dir.path().join("private");
        let reopened = if writable {
            Store::open_existing_registered_mut(&registry, &private, std::slice::from_ref(&root))
        } else {
            Store::open_existing_registered_readonly(
                &registry,
                &private,
                std::slice::from_ref(&root),
            )
        }
        .unwrap();
        std::thread::sleep(Duration::from_millis(650));
        assert_eq!(reopened.charged(&root, None).unwrap(), 301);
        assert_eq!(
            reopened
                .find_reusable("allocator", &root, "task")
                .unwrap()
                .len(),
            301
        );
        assert!(!reopened.pending_events(1000).unwrap().is_empty());
    }
}

#[test]
fn fresh_root_only_proof_hands_off_writer_without_finishing_or_releasing_charge() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    assert!(store.group_snapshot(&r.identity().run).is_err());
    let b = binding(&r);
    store.record_bound(&r, &b).unwrap();
    let os = ClosureOs::new(&r, &b);
    let snap = store.group_snapshot(&r.identity().run).unwrap();
    let proof = snap.certify_empty(&os.driver, &b).unwrap();
    let n = store.pending_events(100).unwrap().len();
    assert_eq!(
        store.close_supervised_group(&snap, &proof).unwrap(),
        Transition::Changed
    );
    let closed = store.run_snapshot(&r.identity().run).unwrap().unwrap();
    assert!(closed.closed);
    assert_eq!(closed.outcome, None);
    assert!(store.recovery_runs().unwrap().is_empty());
    assert_eq!(store.begin_run(&r).unwrap(), BeginRun::Existing);
    assert!(store.record_permit_attempt(&r, &b).is_err());
    assert!(store.record_recovery_hold(&r).is_err());
    assert_eq!(store.pending_events(100).unwrap().len(), n + 1);
    assert!(
        store
            .acquire_writer(
                checkout,
                Uuid::parse_str(&r.identity().group.to_string()).unwrap()
            )
            .is_err(),
        "a legacy writer call must not reopen a closed journal group"
    );
    let next = request(checkout);
    assert_eq!(store.begin_run(&next).unwrap(), BeginRun::Created);
    let n = store.pending_events(100).unwrap().len();
    assert_eq!(
        store.close_supervised_group(&snap, &proof).unwrap(),
        Transition::Existing
    );
    assert_eq!(store.pending_events(100).unwrap().len(), n);
    assert_eq!(store.begin_run(&r).unwrap(), BeginRun::Existing);
    assert_eq!(store.begin_run(&next).unwrap(), BeginRun::Existing);
    assert!(store.begin_run(&request(checkout)).is_err());
    assert_eq!(store.charged(&dir.path().join("root"), None).unwrap(), 1);
    assert_eq!(
        reopen(&dir)
            .unwrap()
            .run_snapshot(&r.identity().run)
            .unwrap()
            .unwrap(),
        closed
    );
}

#[test]
fn root_roster_cannot_be_omitted_and_uncertain_os_evidence_never_certifies() {
    for case in [
        "live",
        "escaped",
        "reused",
        "boot",
        "manager",
        "replacement",
        "unknown",
        "descendant",
        "foreign",
        "binding_pid",
        "binding_start",
        "binding_boot",
    ] {
        let (_dir, mut store, checkout) = fixture();
        let r = request(checkout);
        store.begin_run(&r).unwrap();
        let b = binding(&r);
        store.record_bound(&r, &b).unwrap();
        store.record_root_outcome(&r, RootOutcome::Failed).unwrap();
        let os = ClosureOs::new(&r, &b);
        let p = os.tmp.path();
        match case {
            "live" => os.process(&b, 10, &b.identity().cgroup),
            "escaped" => os.process(&b, 10, "/escaped"),
            "reused" => os.process(&b, 11, &b.identity().cgroup),
            "boot" => std::fs::write(
                p.join("proc/sys/kernel/random/boot_id"),
                "650e8400-e29b-41d4-a716-446655440000",
            )
            .unwrap(),
            "manager" => std::fs::remove_file(p.join("manager")).unwrap(),
            "replacement" => {
                let props = p.join("properties");
                let s = std::fs::read_to_string(&props).unwrap();
                std::fs::write(
                    props,
                    s.replace(
                        "550e8400e29b41d4a716446655440000",
                        "650e8400e29b41d4a716446655440000",
                    ),
                )
                .unwrap();
            }
            "unknown" => {
                std::fs::create_dir(p.join("proc/42")).unwrap();
            }
            "descendant" => {
                let group = format!("{}/child", b.identity().cgroup);
                os.process_pid(43, 20, &group);
                let cg = p.join("cg").join(group.trim_start_matches('/'));
                std::fs::create_dir_all(&cg).unwrap();
                std::fs::write(cg.join("cgroup.type"), "domain\n").unwrap();
                std::fs::write(cg.join("cgroup.procs"), "43\n").unwrap();
            }
            _ => (),
        }
        let snap = store.group_snapshot(&r.identity().run).unwrap();
        let mut different_boot = serde_json::to_value(&r).unwrap();
        different_boot["input"]["boot"] = serde_json::json!("650e8400-e29b-41d4-a716-446655440000");
        let different_boot: RootRunRequest = serde_json::from_value(different_boot).unwrap();
        let other = match case {
            "binding_pid" => binding_child(&r, 43, 10),
            "binding_start" => binding_child(&r, 42, 11),
            "binding_boot" => binding(&different_boot),
            _ => binding(&request(checkout)),
        };
        let supplied = if case == "foreign" || case.starts_with("binding_") {
            &other
        } else {
            &b
        };
        assert!(snap.certify_empty(&os.driver, supplied).is_err(), "{case}");
        assert!(store.begin_run(&request(checkout)).is_err(), "{case}");
    }
}

#[test]
fn closure_proof_is_snapshot_specific_and_invalidated_by_activity_or_age() {
    for activity in ["hold", "outcome", "age", "held"] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        store.begin_run(&r).unwrap();
        let b = binding(&r);
        store.record_bound(&r, &b).unwrap();
        let os = ClosureOs::new(&r, &b);
        let snap = store.group_snapshot(&r.identity().run).unwrap();
        let proof = snap.certify_empty(&os.driver, &b).unwrap();
        match activity {
            "hold" => {
                store.record_recovery_hold(&r).unwrap();
            }
            "outcome" => {
                store.record_root_outcome(&r, RootOutcome::Failed).unwrap();
            }
            "age" => std::thread::sleep(Duration::from_millis(2100)),
            _ => {
                let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
                sql.execute("UPDATE checkouts SET state='held'", [])
                    .unwrap();
            }
        }
        if activity != "held" {
            assert!(
                store.close_supervised_group(&snap, &proof).is_err(),
                "{activity}"
            );
            assert!(store.begin_run(&request(checkout)).is_err());
        }
        let current = store.group_snapshot(&r.identity().run).unwrap();
        if activity == "hold" || activity == "outcome" {
            assert!(store.close_supervised_group(&current, &proof).is_err());
        }
        let fresh = current.certify_empty(&os.driver, &b).unwrap();
        store.close_supervised_group(&current, &fresh).unwrap();
        assert!(
            !store
                .run_snapshot(&r.identity().run)
                .unwrap()
                .unwrap()
                .recovery_hold
        );
        if activity == "held" {
            assert!(store.begin_run(&request(checkout)).is_err());
        }
    }
}

#[test]
fn v4_migration_preserves_runs_and_fails_closed_on_missing_v5_state() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &binding(&r)).unwrap();
    let original = store.run_snapshot(&r.identity().run).unwrap().unwrap();
    let events = store.pending_events(100).unwrap();
    // Retain an existing WAL/SHM reader, as strict reporting never creates them.
    let registry =
        Connection::open(dir.path().join(".work-authorities/authorities.sqlite")).unwrap();
    registry
        .query_row("SELECT count(*) FROM authorities", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap();
    let report = || {
        work_cli::store::report_existing(
            &dir.path().join(".work-authorities"),
            &dir.path().join("private"),
            &[dir.path().join("root")],
        )
    };
    drop(store);
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch("DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; DROP TABLE attribution_gaps; DROP TABLE capture_readiness; DROP TABLE capture_finalizations; DROP TABLE capture_requirements; DROP TABLE capture_runs; DROP TABLE task_finishes; DROP TABLE run_participants; ALTER TABLE run_groups DROP COLUMN child_count; DROP TABLE adopted_segments; DROP TABLE adopted_sessions; DROP TABLE adopted_groups; ALTER TABLE run_groups DROP COLUMN closed; PRAGMA user_version=4;")
        .unwrap();
    assert!(
        report().is_ok(),
        "read-only v4 reporting must not require closed"
    );
    let migrated = reopen(&dir).unwrap();
    assert!(
        report().is_ok(),
        "read-only v5 reporting must recognize closed"
    );
    assert_eq!(
        migrated.run_snapshot(&r.identity().run).unwrap().unwrap(),
        original
    );
    assert_eq!(migrated.pending_events(100).unwrap(), events);
    assert_eq!(migrated.charged(&dir.path().join("root"), None).unwrap(), 1);
    drop(migrated);
    drop(sql);
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch("ALTER TABLE run_groups DROP COLUMN closed")
        .unwrap();
    assert!(reopen(&dir).is_err());
    assert!(report().is_err());
}

#[test]
fn proof_age_is_checked_after_waiting_for_the_writer_lock() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    let b = binding(&r);
    store.record_bound(&r, &b).unwrap();
    let os = ClosureOs::new(&r, &b);
    let snap = store.group_snapshot(&r.identity().run).unwrap();
    let proof = snap.certify_empty(&os.driver, &b).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch("BEGIN IMMEDIATE").unwrap();
    std::thread::sleep(Duration::from_millis(1850));
    let thread = std::thread::spawn(move || store.close_supervised_group(&snap, &proof));
    std::thread::sleep(Duration::from_millis(250));
    sql.execute_batch("COMMIT").unwrap();
    assert!(matches!(
        thread.join().unwrap(),
        Err(work_cli::store::StoreError::Conflict)
    ));
    assert_eq!(
        sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        sql.query_row("SELECT closed FROM run_groups", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn concurrent_close_and_new_root_are_serialized_without_losing_a_writer() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    let b = binding(&r);
    store.record_bound(&r, &b).unwrap();
    let os = ClosureOs::new(&r, &b);
    let snap = store.group_snapshot(&r.identity().run).unwrap();
    let proof = snap.certify_empty(&os.driver, &b).unwrap();
    let mut other = reopen(&dir).unwrap();
    let next = request(checkout);
    let retry = next.clone();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let ready = barrier.clone();
    let thread = std::thread::spawn(move || {
        ready.wait();
        let result = other.begin_run(&next);
        (other, result)
    });
    barrier.wait();
    store.close_supervised_group(&snap, &proof).unwrap();
    let (mut other, first) = thread.join().unwrap();
    if first.is_err() {
        assert_eq!(other.begin_run(&retry).unwrap(), BeginRun::Created);
    }
    assert_eq!(other.begin_run(&retry).unwrap(), BeginRun::Existing);
    let n = other.pending_events(100).unwrap().len();
    assert_eq!(
        other.close_supervised_group(&snap, &proof).unwrap(),
        Transition::Existing
    );
    assert_eq!(other.pending_events(100).unwrap().len(), n);
    assert!(other.begin_run(&request(checkout)).is_err());
}

#[test]
fn recovery_does_not_hide_orphaned_or_invalid_group_state() {
    for corrupt in [
        "PRAGMA foreign_keys=OFF; DELETE FROM run_groups",
        "PRAGMA ignore_check_constraints=ON; UPDATE run_groups SET closed=2",
    ] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        store.begin_run(&r).unwrap();
        let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        sql.execute_batch(corrupt).unwrap();
        assert!(store.run_snapshot(&r.identity().run).is_err());
        assert!(store.recovery_runs().is_err(), "{corrupt}");
    }
}

#[test]
fn recovery_validates_malformed_closed_receipts_before_omitting_them() {
    let mut hidden = Vec::new();
    for case in ["unbound_intent", "bound_recovery_hold"] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        store.begin_run(&r).unwrap();
        if case == "bound_recovery_hold" {
            store.record_bound(&r, &binding(&r)).unwrap();
            store.record_recovery_hold(&r).unwrap();
        }
        let events = store.pending_events(100).unwrap();
        let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        sql.execute("UPDATE run_groups SET closed=1", []).unwrap();
        assert!(store.run_snapshot(&r.identity().run).is_err(), "{case}");
        if store.recovery_runs().is_ok() {
            hidden.push(case);
        }
        let writer: String = sql
            .query_row(
                "SELECT group_id FROM writers WHERE checkout=?1",
                [checkout.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(writer, r.identity().group.to_string(), "{case}");
        assert_eq!(
            store
                .charged(&dir.path().join("root"), Some("owner"))
                .unwrap(),
            1,
            "{case}"
        );
        assert_eq!(store.pending_events(100).unwrap(), events, "{case}");
    }
    assert!(
        hidden.is_empty(),
        "malformed closed receipts silently hidden: {hidden:?}"
    );
}

#[test]
fn closure_schema_preserves_existing_charges_and_writer() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    assert_eq!(
        sql.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        15
    );
    assert_eq!(
        sql.query_row("SELECT closed FROM run_groups", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(store.charged(&dir.path().join("root"), None).unwrap(), 1);
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
    sql.execute_batch("DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; DROP TABLE attribution_gaps; DROP TABLE capture_readiness; DROP TABLE capture_finalizations; DROP TABLE capture_requirements; DROP TABLE capture_runs; DROP TABLE task_finishes; DROP TABLE run_participants; DROP TABLE adopted_segments; DROP TABLE adopted_sessions; DROP TABLE adopted_groups; DROP VIEW runs; ALTER TABLE saved_runs RENAME TO runs; DROP TABLE runs; DROP TABLE run_groups; PRAGMA user_version=3;").unwrap();
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
    // Worker-local only: retain SIGABRT crash semantics without costly core dumps.
    use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            ..getrlimit(Resource::Core)
        },
    )
    .unwrap();
    assert_eq!(
        getrlimit(Resource::Core).current,
        Some(0),
        "intentional fault worker must not dump core"
    );
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
    sql.execute_batch("DROP TRIGGER reject_journal").unwrap();
    let b = binding(&r);
    store.record_bound(&r, &b).unwrap();
    let os = ClosureOs::new(&r, &b);
    let snap = store.group_snapshot(&r.identity().run).unwrap();
    let proof = snap.certify_empty(&os.driver, &b).unwrap();
    let before = store.run_snapshot(&r.identity().run).unwrap();
    let events = store.pending_events(100).unwrap();
    sql.execute_batch("CREATE TRIGGER reject_close BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'test disk failure'); END;").unwrap();
    assert!(store.close_supervised_group(&snap, &proof).is_err());
    assert_eq!(store.run_snapshot(&r.identity().run).unwrap(), before);
    assert_eq!(store.pending_events(100).unwrap(), events);
    assert!(store.begin_run(&request(checkout)).is_err());
    sql.execute_batch("DROP TRIGGER reject_close").unwrap();
    store.close_supervised_group(&snap, &proof).unwrap();
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
        sql.execute_batch("DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; DROP TABLE attribution_gaps; DROP TABLE capture_readiness; DROP TABLE capture_finalizations; DROP TABLE capture_requirements; DROP TABLE capture_runs; DROP TABLE task_finishes; DROP TABLE run_participants; DROP TABLE adopted_segments; DROP TABLE adopted_sessions; DROP TABLE adopted_groups; DROP TABLE runs; DROP TABLE run_groups;")
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
    sql.execute_batch("DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; DROP TABLE attribution_gaps; DROP TABLE capture_readiness; DROP TABLE capture_finalizations; DROP TABLE capture_requirements; DROP TABLE capture_runs; DROP TABLE task_finishes; DROP TABLE run_participants; DROP TABLE adopted_segments; DROP TABLE adopted_sessions; DROP TABLE adopted_groups; DROP TABLE runs; DROP TABLE run_groups; DROP TABLE repository_aliases; PRAGMA user_version=3").unwrap();
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
fn schema_five_is_durable_and_missing_versioned_tables_fail_closed() {
    let (dir, store, _) = fixture();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let version: i64 = sql
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        version, 15,
        "positive child enrollment requires a durable v8 migration"
    );
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
