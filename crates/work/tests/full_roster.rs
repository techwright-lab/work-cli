#[path = "support/run_fixture.rs"]
mod support;
use rusqlite::Connection;
use support::*;
use work_cli::{
    run_journal::{BeginRun, RootRunRequest, Transition},
    run_participants::{ChildOutcome, ChildRequest, ExpectedHost},
    runtime_scope::Binding,
    store::{Store, StoreError},
};
use work_contract::{RunId, RunRef};

fn enroll(
    store: &mut Store,
    r: &RootRunRequest,
    b: &Binding,
    os: &ClosureOs,
    pid: u32,
    ticks: u64,
) -> ChildRequest {
    let c = ChildRequest {
        checkout: r.identity().checkout.clone(),
        group: r.identity().group.clone(),
        run: RunId::generate(),
        run_ref: RunRef::parse(&format!("child:{}", uuid::Uuid::now_v7())).unwrap(),
        parent_run: r.identity().run.clone(),
        parent_run_ref: r.identity().run_ref.clone(),
        execution_chain: r.identity().execution_chain.clone(),
        source: None,
        session: None,
        agent: None,
        actor: None,
        expected_host: Some(ExpectedHost {
            boot: BOOT.into(),
            pid,
            start_ticks: ticks,
        }),
    };
    store.register_child(r, &c).unwrap();
    os.process_pid(pid, ticks, &b.identity().cgroup);
    let properties = os.tmp.path().join("properties");
    let text = std::fs::read_to_string(&properties)
        .unwrap()
        .replace("ActiveState=inactive", "ActiveState=active");
    std::fs::write(&properties, text).unwrap();
    std::fs::write(
        os.tmp
            .path()
            .join("cg")
            .join(b.identity().cgroup.trim_start_matches('/'))
            .join("cgroup.procs"),
        format!("{pid}\n"),
    )
    .unwrap();
    let proof = store
        .group_snapshot(&r.identity().run)
        .unwrap()
        .certify_child_enrollment(&os.driver, &c.run, Some(b))
        .unwrap();
    store.record_child_enrollment(r, &c, &proof).unwrap();
    std::fs::remove_dir_all(os.tmp.path().join(format!("proc/{pid}"))).unwrap();
    std::fs::write(
        os.tmp
            .path()
            .join("cg")
            .join(b.identity().cgroup.trim_start_matches('/'))
            .join("cgroup.procs"),
        "",
    )
    .unwrap();
    let text = std::fs::read_to_string(&properties)
        .unwrap()
        .replace("ActiveState=active", "ActiveState=inactive");
    std::fs::write(properties, text).unwrap();
    c
}
#[test]
fn closed_declared_child_retries_are_metadata_only_and_preserve_new_writer() {
    for outcome in [
        ChildOutcome::Completed,
        ChildOutcome::Failed,
        ChildOutcome::Cancelled,
    ] {
        let (dir, mut store, r, b, os) = setup();
        let c = enroll(&mut store, &r, &b, &os, 43, 20);
        store.record_child_outcome(&r, &c, outcome).unwrap();
        let snap = store.group_snapshot(&r.identity().run).unwrap();
        let proof = snap.certify_empty(&os.driver, &b).unwrap();
        store.close_supervised_group(&snap, &proof).unwrap();
        let after = store.run_snapshot(&r.identity().run).unwrap();
        let next = request(uuid::Uuid::parse_str(&r.identity().checkout.to_string()).unwrap());
        store.begin_run(&next).unwrap();
        let events = store.pending_events(100).unwrap();
        let allocation = allocation_rows(&dir);
        // Metadata receipts require neither fresh kernel evidence nor the old writer.
        std::fs::remove_file(os.tmp.path().join("properties")).unwrap();
        assert_eq!(
            store.record_child_outcome(&r, &c, outcome).unwrap(),
            Transition::Existing
        );
        assert_eq!(store.register_child(&r, &c).unwrap(), BeginRun::Existing);
        for other in [
            ChildOutcome::Completed,
            ChildOutcome::Failed,
            ChildOutcome::Cancelled,
            ChildOutcome::Interrupted,
        ] {
            if other != outcome {
                if other == ChildOutcome::Interrupted {
                    assert!(matches!(
                        store.record_child_outcome(&r, &c, other),
                        Err(StoreError::Invalid)
                    ));
                } else {
                    assert!(matches!(
                        store.record_child_outcome(&r, &c, other),
                        Err(StoreError::Conflict)
                    ));
                }
            }
        }
        assert!(store.record_child_hold(&r, &c).is_err());
        for mismatch in ["new", "parent", "parent_ref", "ref", "actor", "host"] {
            let mut changed = c.clone();
            match mismatch {
                "new" => {
                    changed.run = RunId::generate();
                    changed.run_ref = RunRef::parse("new-child").unwrap();
                }
                "parent" => changed.parent_run = RunId::generate(),
                "parent_ref" => changed.parent_run_ref = RunRef::parse("wrong-parent").unwrap(),
                "ref" => changed.run_ref = RunRef::parse("wrong-child").unwrap(),
                "actor" => {
                    changed.actor =
                        Some(serde_json::from_value(serde_json::json!("other-actor")).unwrap())
                }
                "host" => changed.expected_host.as_mut().unwrap().start_ticks += 1,
                _ => unreachable!(),
            }
            if mismatch == "new" {
                assert!(matches!(
                    store.register_child(&r, &changed),
                    Err(StoreError::Invalid)
                ));
            } else {
                assert!(
                    matches!(
                        store.register_child(&r, &changed),
                        Err(StoreError::Conflict)
                    ),
                    "{mismatch}"
                );
            }
            assert!(
                store.record_child_outcome(&r, &changed, outcome).is_err(),
                "{mismatch}"
            );
        }
        assert_eq!(store.pending_events(100).unwrap(), events);
        assert_eq!(store.run_snapshot(&r.identity().run).unwrap(), after);
        assert_eq!(allocation_rows(&dir), allocation);
        assert_eq!(store.charged(&dir.path().join("root"), None).unwrap(), 1);
        assert!(store
            .begin_run(&request(
                uuid::Uuid::parse_str(&r.identity().checkout.to_string()).unwrap()
            ))
            .is_err());
        assert_eq!(
            reopen(&dir)
                .unwrap()
                .run_snapshot(&r.identity().run)
                .unwrap(),
            after
        );
        assert!(
            work_cli::run_recovery::status(&store, &r.identity().run)
                .unwrap()
                .record
                .closed
        );
        assert_eq!(
            work_cli::run_recovery::recover(&mut store, &r.identity().run, &os.driver).unwrap(),
            work_cli::run_recovery::RecoveryState::AlreadyClosed
        );
        assert!(!store
            .recovery_runs()
            .unwrap()
            .iter()
            .any(|record| record.request.identity().run == r.identity().run));
    }
}
fn allocation_rows(dir: &tempfile::TempDir) -> Vec<Vec<rusqlite::types::Value>> {
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let mut result = Vec::new();
    for table in [
        "checkouts",
        "allocations",
        "repository_aliases",
        "retired_owners",
    ] {
        let mut stmt = sql
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let columns = stmt.column_count();
        result.extend(
            stmt.query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
                .unwrap()
                .map(Result::unwrap),
        );
    }
    result
}
fn setup() -> (tempfile::TempDir, Store, RootRunRequest, Binding, ClosureOs) {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let os = ClosureOs::new(&r, &b);
    (dir, store, r, b, os)
}
#[test]
fn full_roster_disappearance_interrupts_only_open_children_and_exact_retry_preserves_new_writer() {
    for historical in [false, true] {
        let (dir, mut store, r, b, os) = setup();
        let open = enroll(&mut store, &r, &b, &os, 42, 10);
        let declared = enroll(&mut store, &r, &b, &os, 43, 20);
        let shared = enroll(&mut store, &r, &b, &os, 42, 10);
        store
            .record_child_outcome(&r, &declared, ChildOutcome::Completed)
            .unwrap();
        let before = store.run_snapshot(&r.identity().run).unwrap().unwrap();
        let allocation = allocation_rows(&dir);
        let snap = store.group_snapshot(&r.identity().run).unwrap();
        let proof = if historical {
            snap.certify_historical_empty(&os.driver)
        } else {
            snap.certify_empty(&os.driver, &b)
        }
        .expect("fresh complete roster must replace the temporary child barrier");
        let n = store.pending_events(100).unwrap().len();
        assert_eq!(
            store.close_supervised_group(&snap, &proof).unwrap(),
            Transition::Changed
        );
        let after = store.run_snapshot(&r.identity().run).unwrap().unwrap();
        assert_eq!(allocation_rows(&dir), allocation);
        assert!(after.closed);
        assert_eq!(after.outcome, None);
        assert_eq!(after.children.len(), 3);
        assert_eq!(after.revision, before.revision + 1);
        for child in &after.children {
            let outcome = serde_json::to_value(child).unwrap()["outcome"].clone();
            assert_eq!(
                outcome,
                serde_json::json!(if child.request.run == declared.run {
                    "completed"
                } else {
                    "interrupted"
                })
            );
        }
        assert_eq!(after.children[0].request, open);
        assert_eq!(after.children[2].request, shared);
        assert_eq!(store.pending_events(100).unwrap().len(), n + 2);
        let events = store.pending_events(100).unwrap();
        assert!(store
            .record_child_outcome(&r, &open, ChildOutcome::Interrupted)
            .is_err());
        assert_eq!(store.pending_events(100).unwrap(), events);
        assert!(store.recovery_runs().unwrap().is_empty());
        assert!(
            work_cli::run_recovery::status(&store, &r.identity().run)
                .unwrap()
                .record
                .closed
        );
        assert_eq!(
            work_cli::run_recovery::recover(&mut store, &r.identity().run, &os.driver).unwrap(),
            work_cli::run_recovery::RecoveryState::AlreadyClosed
        );
        let next = request(uuid::Uuid::parse_str(&r.identity().checkout.to_string()).unwrap());
        store.begin_run(&next).unwrap();
        if historical {
            std::thread::sleep(std::time::Duration::from_millis(2100));
        }
        let events = store.pending_events(100).unwrap();
        assert_eq!(
            store.close_supervised_group(&snap, &proof).unwrap(),
            Transition::Existing
        );
        assert_eq!(store.register_child(&r, &open).unwrap(), BeginRun::Existing);
        for outcome in [
            ChildOutcome::Completed,
            ChildOutcome::Failed,
            ChildOutcome::Cancelled,
            ChildOutcome::Interrupted,
        ] {
            if outcome == ChildOutcome::Interrupted {
                assert!(matches!(
                    store.record_child_outcome(&r, &open, outcome),
                    Err(StoreError::Invalid)
                ));
            } else {
                assert!(matches!(
                    store.record_child_outcome(&r, &open, outcome),
                    Err(StoreError::Conflict)
                ));
            }
        }
        assert!(store.record_child_hold(&r, &open).is_err());
        assert_eq!(
            store.run_snapshot(&r.identity().run).unwrap().unwrap(),
            after
        );
        assert_eq!(store.pending_events(100).unwrap(), events);
        assert!(store
            .begin_run(&request(
                uuid::Uuid::parse_str(&r.identity().checkout.to_string()).unwrap()
            ))
            .is_err());
        assert_eq!(store.charged(&dir.path().join("root"), None).unwrap(), 1);
        assert_eq!(
            reopen(&dir)
                .unwrap()
                .run_snapshot(&r.identity().run)
                .unwrap()
                .unwrap(),
            after
        );
    }
}
#[test]
fn declared_terminal_hosts_still_require_fresh_absence_and_unknown_enrollment_holds() {
    for case in [
        "live",
        "escaped",
        "reuse",
        "unreadable",
        "boot",
        "replacement",
        "incomplete",
        "pending",
        "unverified",
        "held_audit",
        "same_pid_old_live",
    ] {
        let (_dir, mut store, r, b, os) = setup();
        let c = enroll(&mut store, &r, &b, &os, 43, 20);
        store
            .record_child_outcome(&r, &c, ChildOutcome::Completed)
            .unwrap();
        match case {
            "live" => os.process_pid(43, 20, &b.identity().cgroup),
            "escaped" => os.process_pid(43, 20, "/escaped"),
            "reuse" => os.process_pid(43, 21, &b.identity().cgroup),
            "unreadable" => {
                std::fs::create_dir(os.tmp.path().join("proc/43")).unwrap();
            }
            "boot" => std::fs::write(
                os.tmp.path().join("proc/sys/kernel/random/boot_id"),
                "650e8400-e29b-41d4-a716-446655440000",
            )
            .unwrap(),
            "replacement" => {
                let p = os.tmp.path().join("properties");
                let t = std::fs::read_to_string(&p).unwrap().replace(
                    "550e8400e29b41d4a716446655440000",
                    "650e8400e29b41d4a716446655440000",
                );
                std::fs::write(p, t).unwrap();
            }
            "incomplete" => std::fs::remove_file(
                os.tmp
                    .path()
                    .join("cg")
                    .join(b.identity().cgroup.trim_start_matches('/'))
                    .join("cgroup.procs"),
            )
            .unwrap(),
            "pending" => {
                let mut p = c.clone();
                p.run = RunId::generate();
                p.run_ref = RunRef::parse("pending").unwrap();
                store.register_child(&r, &p).unwrap();
                store
                    .record_child_outcome(&r, &p, ChildOutcome::Failed)
                    .unwrap();
            }
            "unverified" => {
                let mut p = c.clone();
                p.run = RunId::generate();
                p.run_ref = RunRef::parse("unknown").unwrap();
                p.expected_host = None;
                store.register_child(&r, &p).unwrap();
                store
                    .record_child_outcome(&r, &p, ChildOutcome::Cancelled)
                    .unwrap();
            }
            "same_pid_old_live" => {
                enroll(&mut store, &r, &b, &os, 43, 21);
                os.process_pid(43, 20, &b.identity().cgroup);
            }
            "held_audit" => {
                store.record_child_hold(&r, &c).unwrap();
            }
            _ => unreachable!(),
        }
        let snap = store.group_snapshot(&r.identity().run).unwrap();
        let before = store.run_snapshot(&r.identity().run).unwrap();
        let events = store.pending_events(100).unwrap();
        assert!(snap.certify_empty(&os.driver, &b).is_err(), "{case}");
        assert!(snap.certify_historical_empty(&os.driver).is_err(), "{case}");
        assert!(
            matches!(
                work_cli::run_recovery::recover(&mut store, &r.identity().run, &os.driver).unwrap(),
                work_cli::run_recovery::RecoveryState::Held { .. }
            ),
            "{case}"
        );
        assert_eq!(store.run_snapshot(&r.identity().run).unwrap(), before);
        assert_eq!(store.pending_events(100).unwrap(), events);
    }
}
#[test]
fn historical_full_roster_recovery_closes_unknown_root_without_session_end() {
    let (dir, mut store, r, b, os) = setup();
    enroll(&mut store, &r, &b, &os, 43, 20);
    enroll(&mut store, &r, &b, &os, 43, 21);
    let before = allocation_rows(&dir);
    assert_eq!(
        work_cli::run_recovery::recover(&mut store, &r.identity().run, &os.driver).unwrap(),
        work_cli::run_recovery::RecoveryState::Closed
    );
    let closed = work_cli::run_recovery::status(&store, &r.identity().run).unwrap();
    assert_eq!(closed.runtime, "not_inspected");
    assert_eq!(closed.record.outcome, None);
    assert!(closed
        .record
        .children
        .iter()
        .all(|c| c.outcome == Some(ChildOutcome::Interrupted)));
    assert_eq!(allocation_rows(&dir), before);
    let config = work_cli::config::Config {
        trusted_registry: Some(dir.path().join(".work-authorities")),
        store_dir: Some(dir.path().join("private")),
        roots: vec![dir.path().join("root")],
        ..Default::default()
    };
    assert_eq!(
        work_cli::run_recovery::command_recover(
            &config,
            uuid::Uuid::parse_str(&r.identity().run.to_string()).unwrap()
        )
        .unwrap(),
        work_cli::run_recovery::RecoveryState::AlreadyClosed
    );
    assert_eq!(
        work_cli::run_recovery::command_status(
            &config,
            uuid::Uuid::parse_str(&r.identity().run.to_string()).unwrap()
        )
        .unwrap()
        .record,
        closed.record
    );
}
#[test]
fn atomic_child_loss_rolls_back_on_either_event_and_concurrent_mutation_invalidates_proof() {
    for case in [
        "children_interrupted",
        "group_closed",
        "registration",
        "hold",
        "outcome",
    ] {
        let (dir, mut store, r, b, os) = setup();
        let c = enroll(&mut store, &r, &b, &os, 43, 20);
        let snap = store.group_snapshot(&r.identity().run).unwrap();
        let proof = snap
            .certify_empty(&os.driver, &b)
            .expect("full roster proof");
        let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        match case {
            "registration"=>{let mut p=c.clone();p.run=RunId::generate();p.run_ref=RunRef::parse("new").unwrap();store.register_child(&r,&p).unwrap();},
            "hold"=>{store.record_child_hold(&r,&c).unwrap();},
            "outcome"=>{store.record_child_outcome(&r,&c,ChildOutcome::Failed).unwrap();},
            _=>sql.execute_batch(&format!("CREATE TRIGGER reject_close BEFORE INSERT ON outbox WHEN instr(NEW.payload,'{case}')>0 BEGIN SELECT RAISE(ABORT,'fixture'); END;")).unwrap()
        }
        let before = store.run_snapshot(&r.identity().run).unwrap();
        let events = store.pending_events(100).unwrap();
        assert!(
            store.close_supervised_group(&snap, &proof).is_err(),
            "{case}"
        );
        assert_eq!(store.run_snapshot(&r.identity().run).unwrap(), before);
        assert_eq!(store.pending_events(100).unwrap(), events);
        assert!(store
            .begin_run(&request(
                uuid::Uuid::parse_str(&r.identity().checkout.to_string()).unwrap()
            ))
            .is_err());
    }
}
#[test]
fn closed_full_roster_history_validates_before_any_receipt_filtering() {
    for case in [
        "deleted",
        "orphan",
        "count",
        "pending",
        "missing_host",
        "open",
        "context",
        "host",
        "bad_parent",
        "open_interrupted",
    ] {
        let (dir, mut store, r, b, os) = setup();
        let c = enroll(&mut store, &r, &b, &os, 43, 20);
        let declared = enroll(&mut store, &r, &b, &os, 44, 30);
        store
            .record_child_outcome(&r, &declared, ChildOutcome::Completed)
            .unwrap();
        let snap = store.group_snapshot(&r.identity().run).unwrap();
        let proof = snap
            .certify_empty(&os.driver, &b)
            .expect("full roster proof");
        store.close_supervised_group(&snap, &proof).unwrap();
        let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        sql.execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        match case {
            "deleted" => {
                sql.execute("DELETE FROM run_participants", []).unwrap();
            }
            "orphan" => {
                sql.execute_batch(
                    "PRAGMA foreign_keys=OFF; UPDATE run_participants SET group_id='orphan';",
                )
                .unwrap();
            }
            "count" => {
                sql.execute("UPDATE run_groups SET child_count=0", [])
                    .unwrap();
            }
            "pending" => {
                sql.execute(
                    "UPDATE run_participants SET enrollment='pending',host=NULL",
                    [],
                )
                .unwrap();
            }
            "missing_host" => {
                sql.execute("UPDATE run_participants SET host=NULL", [])
                    .unwrap();
            }
            "open" => {
                sql.execute("UPDATE run_participants SET outcome=NULL", [])
                    .unwrap();
            }
            "open_interrupted" => {
                sql.execute("UPDATE run_groups SET closed=0", []).unwrap();
            }
            "host" => {
                sql.execute(
                    "UPDATE run_participants SET host=json_set(host,'$.host.start_ticks',99)",
                    [],
                )
                .unwrap();
            }
            "context" => {
                sql.execute(
                    "UPDATE run_participants SET request=json_set(request,'$.actor','changed')",
                    [],
                )
                .unwrap();
            }
            "bad_parent" => {
                sql.execute("UPDATE run_participants SET parent_run='missing'", [])
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            store.close_supervised_group(&snap, &proof).is_err(),
            "{case}"
        );
        assert!(store.register_child(&r, &c).is_err(), "{case}");
        assert!(
            store
                .record_child_outcome(&r, &declared, ChildOutcome::Completed)
                .is_err(),
            "{case}"
        );
        if case != "context" {
            assert!(store.run_snapshot(&r.identity().run).is_err(), "{case}");
            assert!(store.recovery_runs().is_err(), "{case}");
            assert!(
                work_cli::run_recovery::status(&store, &r.identity().run).is_err(),
                "{case}"
            );
            assert!(
                work_cli::run_recovery::recover(&mut store, &r.identity().run, &os.driver).is_err(),
                "{case}"
            );
            assert!(store.begin_run(&r).is_err(), "{case}");
        }
    }
}
