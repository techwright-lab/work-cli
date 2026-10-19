#[path = "support/run_fixture.rs"]
mod support;
use support::*;
use work_cli::{
    run_journal::{RootRunRequest, Transition},
    run_participants::{ChildRequest, Enrollment, ExpectedHost},
};
use work_contract::{RunId, RunRef};
fn child(r: &RootRunRequest) -> ChildRequest {
    ChildRequest {
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
            pid: 42,
            start_ticks: 10,
        }),
    }
}
fn active(os: &ClosureOs, b: &work_cli::runtime_scope::Binding, pids: &[u32]) {
    let root = os.tmp.path();
    let path = root.join("properties");
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace("ActiveState=inactive", "ActiveState=active");
    std::fs::write(path, text).unwrap();
    std::fs::write(
        root.join("cg")
            .join(b.identity().cgroup.trim_start_matches('/'))
            .join("cgroup.procs"),
        pids.iter().map(|p| format!("{p}\n")).collect::<String>(),
    )
    .unwrap();
    for pid in pids {
        os.process_pid(*pid, if *pid == 42 { 10 } else { 20 }, &b.identity().cgroup);
    }
}
#[test]
fn registrar_is_actual_in_scope_identity_unless_original_exact_controller_is_supplied() {
    for case in [
        "outside",
        "missing",
        "inside",
        "same_host",
        "controller",
        "wrong_controller",
    ] {
        let (_dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let pid = if case == "same_host" {
            std::process::id()
        } else {
            42
        };
        let b = binding_child(&r, pid, 10);
        store.begin_run(&r).unwrap();
        store.record_bound(&r, &b).unwrap();
        store.record_permit_attempt(&r, &b).unwrap();
        let mut c = child(&r);
        c.expected_host.as_mut().unwrap().pid = pid;
        store.register_child(&r, &c).unwrap();
        let os = ClosureOs::new(&r, &b);
        active(&os, &b, &[pid]);
        os.process_pid(pid, 10, &b.identity().cgroup);
        if case == "outside" || case == "controller" {
            os.process_pid(std::process::id(), 20, "/");
        }
        if case == "inside" {
            active(&os, &b, &[pid, std::process::id()]);
        }
        let other = binding(&request(checkout));
        let controller = match case {
            "controller" => Some(&b),
            "wrong_controller" => Some(&other),
            _ => None,
        };
        let result = store
            .group_snapshot(&r.identity().run)
            .unwrap()
            .certify_child_enrollment(&os.driver, &c.run, controller);
        assert_eq!(
            result.is_ok(),
            ["inside", "same_host", "controller"].contains(&case),
            "{case}: {result:?}"
        );
    }
}
#[test]
fn missing_reused_outside_inactive_reaped_and_changed_host_never_enroll() {
    for case in [
        "missing",
        "outside",
        "ticks",
        "boot",
        "inactive",
        "reaped",
        "invalid_cgroup",
        "missing_roster",
    ] {
        let (_dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let b = binding(&r);
        store.begin_run(&r).unwrap();
        store.record_bound(&r, &b).unwrap();
        store.record_permit_attempt(&r, &b).unwrap();
        let mut c = child(&r);
        c.expected_host.as_mut().unwrap().pid = 43;
        c.expected_host.as_mut().unwrap().start_ticks = 20;
        store.register_child(&r, &c).unwrap();
        let os = ClosureOs::new(&r, &b);
        active(&os, &b, &[42, 43]);
        match case {
            "missing" => std::fs::remove_dir_all(os.tmp.path().join("proc/43")).unwrap(),
            "outside" => os.process_pid(43, 20, "/outside"),
            "ticks" => os.process_pid(43, 21, &b.identity().cgroup),
            "boot" => std::fs::write(
                os.tmp.path().join("proc/sys/kernel/random/boot_id"),
                "650e8400-e29b-41d4-a716-446655440000",
            )
            .unwrap(),
            "inactive" => {
                let p = os.tmp.path().join("properties");
                let t = std::fs::read_to_string(&p)
                    .unwrap()
                    .replace("ActiveState=active", "ActiveState=inactive");
                std::fs::write(p, t).unwrap();
            }
            "reaped" => {
                let p = os.tmp.path().join("properties");
                std::fs::write(p,format!("Id={}\nInvocationID=\nControlGroup=\nLoadState=not-found\nActiveState=inactive\n",b.identity().unit)).unwrap();
            }
            "invalid_cgroup" => os.process_pid(43, 20, "/../bad"),
            "missing_roster" => {
                let mut unknown = child(&r);
                unknown.expected_host = None;
                store.register_child(&r, &unknown).unwrap();
            }
            _ => unreachable!(),
        }
        let before = store.run_snapshot(&r.identity().run).unwrap().unwrap();
        assert!(
            store
                .group_snapshot(&r.identity().run)
                .unwrap()
                .certify_child_enrollment(&os.driver, &c.run, Some(&b))
                .is_err(),
            "{case}"
        );
        assert_eq!(
            store.run_snapshot(&r.identity().run).unwrap().unwrap(),
            before
        );
    }
}
#[test]
fn proofs_bind_child_full_context_revision_and_preserve_terminal_root_and_hold() {
    for change in [
        "child",
        "other_child",
        "outcome",
        "hold",
        "child_outcome",
        "child_hold",
        "terminal_before",
        "hold_before",
    ] {
        let (_dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let b = binding(&r);
        store.begin_run(&r).unwrap();
        store.record_bound(&r, &b).unwrap();
        store.record_permit_attempt(&r, &b).unwrap();
        let c = child(&r);
        store.register_child(&r, &c).unwrap();
        let os = ClosureOs::new(&r, &b);
        active(&os, &b, &[42]);
        if change == "terminal_before" {
            store
                .record_root_outcome(&r, work_cli::run_journal::RootOutcome::Completed)
                .unwrap();
        }
        if change == "hold_before" {
            store.record_recovery_hold(&r).unwrap();
        }
        let proof = store
            .group_snapshot(&r.identity().run)
            .unwrap()
            .certify_child_enrollment(&os.driver, &c.run, Some(&b))
            .unwrap();
        let mut supplied = c.clone();
        match change {
            "child" => {
                supplied.agent = Some(work_cli::participants::Ref::new("changed".into()).unwrap())
            }
            "other_child" => {
                store.register_child(&r, &child(&r)).unwrap();
            }
            "outcome" => {
                store
                    .record_root_outcome(&r, work_cli::run_journal::RootOutcome::Completed)
                    .unwrap();
            }
            "hold" => {
                store.record_recovery_hold(&r).unwrap();
            }
            "child_outcome" => {
                store
                    .record_child_outcome(&r, &c, work_cli::run_participants::ChildOutcome::Failed)
                    .unwrap();
            }
            "child_hold" => {
                store.record_child_hold(&r, &c).unwrap();
            }
            _ => (),
        }
        let before = store.run_snapshot(&r.identity().run).unwrap().unwrap();
        let events = store.pending_events(100).unwrap();
        let result = store.record_child_enrollment(&r, &supplied, &proof);
        let succeeds = ["terminal_before", "hold_before"].contains(&change);
        assert_eq!(result.is_ok(), succeeds, "{change}: {result:?}");
        if succeeds {
            let after = store.run_snapshot(&r.identity().run).unwrap().unwrap();
            assert_eq!(after.outcome, before.outcome);
            assert_eq!(after.recovery_hold, before.recovery_hold);
        } else {
            assert_eq!(
                store.run_snapshot(&r.identity().run).unwrap().unwrap(),
                before
            );
            assert_eq!(store.pending_events(100).unwrap(), events);
        }
    }
}
#[test]
fn corrupt_persisted_host_scope_or_parent_blocks_every_metadata_reader_and_retry() {
    for field in ["pid", "start_ticks", "boot", "cgroup", "scope", "parent"] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let b = binding(&r);
        store.begin_run(&r).unwrap();
        store.record_bound(&r, &b).unwrap();
        store.record_permit_attempt(&r, &b).unwrap();
        let c = child(&r);
        store.register_child(&r, &c).unwrap();
        let os = ClosureOs::new(&r, &b);
        active(&os, &b, &[42]);
        let proof = store
            .group_snapshot(&r.identity().run)
            .unwrap()
            .certify_child_enrollment(&os.driver, &c.run, Some(&b))
            .unwrap();
        store.record_child_enrollment(&r, &c, &proof).unwrap();
        let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        let raw: String = sql
            .query_row("SELECT host FROM run_participants", [], |r| r.get(0))
            .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        match field {
            "pid" => value["host"][field] = serde_json::json!(43),
            "start_ticks" => value["host"][field] = serde_json::json!(11),
            "boot" => {
                value["host"][field] = serde_json::json!("650e8400-e29b-41d4-a716-446655440000")
            }
            "cgroup" => value["host"][field] = serde_json::json!("/outside"),
            "scope" => {
                value["root"]["invocation"] = serde_json::json!("650e8400e29b41d4a716446655440000")
            }
            _ => (),
        }
        if field == "parent" {
            sql.execute("UPDATE run_participants SET parent_run='wrong'", [])
                .unwrap();
        } else {
            sql.execute("UPDATE run_participants SET host=?1", [value.to_string()])
                .unwrap();
        }
        assert!(store.run_snapshot(&r.identity().run).is_err(), "{field}");
        assert!(store.begin_run(&r).is_err());
        assert!(store.recovery_runs().is_err());
        assert!(work_cli::run_recovery::status(&store, &r.identity().run).is_err());
        assert!(store.record_child_enrollment(&r, &c, &proof).is_err());
        assert!(reopen(&dir)
            .unwrap()
            .run_snapshot(&r.identity().run)
            .is_err());
    }
}
#[test]
fn changed_scope_context_conflicts_instead_of_consuming_a_positive_proof() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let c = child(&r);
    store.register_child(&r, &c).unwrap();
    let os = ClosureOs::new(&r, &b);
    active(&os, &b, &[42]);
    let proof = store
        .group_snapshot(&r.identity().run)
        .unwrap()
        .certify_child_enrollment(&os.driver, &c.run, Some(&b))
        .unwrap();
    let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let raw: String = sql
        .query_row("SELECT binding FROM runs", [], |r| r.get(0))
        .unwrap();
    let mut scope: serde_json::Value = serde_json::from_str(&raw).unwrap();
    scope["invocation"] = serde_json::json!("650e8400e29b41d4a716446655440000");
    sql.execute("UPDATE runs SET binding=?1", [scope.to_string()])
        .unwrap();
    let before = store.run_snapshot(&r.identity().run).unwrap().unwrap();
    let events = store.pending_events(100).unwrap();
    assert!(matches!(
        store.record_child_enrollment(&r, &c, &proof),
        Err(work_cli::store::StoreError::Conflict)
    ));
    assert_eq!(
        store.run_snapshot(&r.identity().run).unwrap().unwrap(),
        before
    );
    assert_eq!(store.pending_events(100).unwrap(), events);
}
#[test]
fn enrollment_rejects_census_churn_without_any_partial_receipt() {
    use work_cli::scope_driver::{Driver, LibraryIo, Limits, RuntimeContext};
    let (_dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let c = child(&r);
    store.register_child(&r, &c).unwrap();
    let os = ClosureOs::new(&r, &b);
    active(&os, &b, &[42]);
    let root = os.tmp.path();
    let changed = root
        .join("cg")
        .join(b.identity().cgroup.trim_start_matches('/'))
        .join("cgroup.procs");
    let driver = Driver::with_io(
        RuntimeContext::new(
            root.join("runtime"),
            format!("unix:path={}/runtime/bus", root.display()),
        )
        .unwrap(),
        LibraryIo {
            systemctl: root.join("manager"),
            proc_root: root.join("proc"),
            cgroup_root: root.join("cg"),
            between_censuses: Some(Box::new(move || std::fs::write(&changed, "").unwrap())),
        },
        Limits::default(),
    )
    .unwrap();
    let before = store.run_snapshot(&r.identity().run).unwrap().unwrap();
    assert!(store
        .group_snapshot(&r.identity().run)
        .unwrap()
        .certify_child_enrollment(&driver, &c.run, Some(&b))
        .is_err());
    assert_eq!(
        store.run_snapshot(&r.identity().run).unwrap().unwrap(),
        before
    );
}
#[test]
fn zombie_root_cannot_supply_open_participant_evidence_for_a_different_host() {
    let (_dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let mut c = child(&r);
    c.expected_host.as_mut().unwrap().pid = 43;
    c.expected_host.as_mut().unwrap().start_ticks = 20;
    store.register_child(&r, &c).unwrap();
    let os = ClosureOs::new(&r, &b);
    active(&os, &b, &[42, 43]);
    let path = os.tmp.path().join("proc/42/stat");
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace(") S ", ") Z ");
    std::fs::write(path, text).unwrap();
    assert!(store
        .group_snapshot(&r.identity().run)
        .unwrap()
        .certify_child_enrollment(&os.driver, &c.run, Some(&b))
        .is_err());
}
#[test]
fn exact_host_enrollment_is_metadata_only_idempotent_and_still_blocks_every_closure() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let c = child(&r);
    store.register_child(&r, &c).unwrap();
    let os = ClosureOs::new(&r, &b);
    active(&os, &b, &[42, 43]);
    let snap = store.group_snapshot(&r.identity().run).unwrap();
    let proof = snap
        .certify_child_enrollment(&os.driver, &c.run, Some(&b))
        .unwrap();
    assert_eq!(
        store.record_child_enrollment(&r, &c, &proof).unwrap(),
        Transition::Changed
    );
    let record = store.run_snapshot(&r.identity().run).unwrap().unwrap();
    assert_eq!(record.children[0].enrollment, Enrollment::Contained);
    assert!(record.children[0].host.is_some());
    assert_eq!(record.revision, 5);
    let status =
        serde_json::to_value(work_cli::run_recovery::status(&store, &r.identity().run).unwrap())
            .unwrap();
    assert_eq!(
        status["child_enrollment"],
        "enrollment recorded; runtime not inspected now"
    );
    assert_eq!(status["runtime"], "not_inspected");
    assert_eq!(store.charged(&dir.path().join("root"), None).unwrap(), 1);
    let events = store.pending_events(100).unwrap();
    assert_eq!(
        store.record_child_enrollment(&r, &c, &proof).unwrap(),
        Transition::Existing
    );
    assert_eq!(store.pending_events(100).unwrap(), events);
    let snap = store.group_snapshot(&r.identity().run).unwrap();
    assert!(snap.certify_empty(&os.driver, &b).is_err());
    assert!(snap.certify_historical_empty(&os.driver).is_err());
    assert_eq!(
        store.record_child_hold(&r, &c).unwrap(),
        Transition::Changed
    );
    assert!(store.record_child_enrollment(&r, &c, &proof).is_err());
    assert!(store
        .group_snapshot(&r.identity().run)
        .unwrap()
        .certify_child_enrollment(&os.driver, &c.run, Some(&b))
        .is_err());
    drop(store);
    assert!(reopen(&dir)
        .unwrap()
        .run_snapshot(&r.identity().run)
        .unwrap()
        .unwrap()
        .children[0]
        .host
        .is_some());
}
