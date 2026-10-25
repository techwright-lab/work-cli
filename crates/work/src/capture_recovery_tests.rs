use super::*;
use std::{
    cell::{Cell, RefCell},
    fs,
    os::unix::fs::PermissionsExt,
};
type Observer = Box<dyn FnMut(&str, &Store)>;
thread_local! {
    static OBSERVER: RefCell<Option<Observer>> = RefCell::new(None);
    static CLOCK: Cell<(u32, u32)> = const { Cell::new((0, 0)) };
}
pub(super) fn observe(stage: &str, store: &Store) {
    OBSERVER.with(|slot| {
        if let Some(f) = slot.borrow_mut().as_mut() {
            f(stage, store);
        }
    });
}
// Pure deterministic age seam. Never performs I/O or invokes callbacks under SQL/lock.
pub(super) fn clock_offset() -> Duration {
    CLOCK.with(|clock| {
        let (calls, expire) = clock.get();
        clock.set((calls + 1, expire));
        if expire != 0 && calls + 1 >= expire {
            Duration::from_secs(3)
        } else {
            Duration::ZERO
        }
    })
}
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        OBSERVER.with(|s| *s.borrow_mut() = None);
        CLOCK.with(|c| c.set((0, 0)));
    }
}
fn observing(f: impl FnMut(&str, &Store) + 'static) -> Guard {
    OBSERVER.with(|s| *s.borrow_mut() = Some(Box::new(f)));
    Guard
}
fn raw(store: &Store) -> String {
    let mut stmt = store
        .conn
        .prepare("SELECT prepared,group_end FROM capture_runs")
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, Option<String>>(1)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    format!("{rows:?}")
}
// All relational facts, including events/certificates/charge/owner and injected rows.
// File-level SQLite bookkeeping is deliberately not treated as operator metadata.
fn relational_facts(store: &Store) -> Vec<(String, Vec<String>)> {
    let tables = store
        .conn
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    tables
        .into_iter()
        .map(|name| {
            let mut stmt = store
                .conn
                .prepare(&format!("SELECT * FROM \"{}\"", name.replace('"', "\"\"")))
                .unwrap();
            let columns = stmt.column_count();
            let mut rows = stmt
                .query_map([], |r| {
                    (0..columns)
                        .map(|i| r.get::<_, rusqlite::types::Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .map(|v| format!("{v:?}"))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            rows.sort();
            (name, rows)
        })
        .collect()
}
fn inject_checkout_contradiction(
    store: &Store,
    root: &crate::run_journal::RootRunRequest,
    case: &str,
) {
    // Synthetic relational corruption, not a physical Git change. No foreign-key
    // bypass, capture row, participant or extra writer can mask the missing fence.
    let mut value = serde_json::to_value(root).unwrap();
    value["identity"]["group"] = uuid::Uuid::now_v7().to_string().into();
    value["identity"]["run"] = uuid::Uuid::now_v7().to_string().into();
    value["identity"]["run_ref"] = format!("run:extra-{}", uuid::Uuid::now_v7()).into();
    let extra: crate::run_journal::RootRunRequest = serde_json::from_value(value).unwrap();
    let closed = matches!(case, "rootless_closed" | "held_closed");
    store.conn.execute("INSERT INTO run_groups(id,checkout,mode,revision,closed,recovery_hold) VALUES(?1,?2,'supervised',1,?3,?4)",
        rusqlite::params![extra.identity().group.to_string(), extra.identity().checkout.to_string(), closed, case == "held_closed"]).unwrap();
    if matches!(case, "extra_open" | "held_closed") {
        store
            .conn
            .execute(
                "INSERT INTO runs(id,group_id,run_ref,request,stage) VALUES(?1,?2,?3,?4,'intent')",
                rusqlite::params![
                    extra.identity().run.to_string(),
                    extra.identity().group.to_string(),
                    extra.identity().run_ref.as_str(),
                    serde_json::to_string(&extra).unwrap()
                ],
            )
            .unwrap();
    }
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}
#[test]
fn begin_replay_checkout_contradictions_refuse_before_receiver() {
    let mut violations = Vec::new();
    for known in [false, true] {
        for case in [
            "rootless_open",
            "rootless_closed",
            "extra_open",
            "held_closed",
        ] {
            let (temp, cfg, _a, root, spec) =
                crate::capture_preparation::tests::qualified_fixture();
            let (mut store, created) = crate::capture_setup::begin(&cfg, &root, &spec).unwrap();
            if known {
                let crate::capture_journal::BeginCapturedRun::Created(handle) = created else {
                    panic!("created")
                };
                let prepared =
                    crate::sinks::ProcessSink::new(spec.sink().process_settings().unwrap())
                        .begin(&spec.begin_request(), &spec.expected_git())
                        .unwrap();
                store.record_capture_prepared(handle, &prepared).unwrap();
            } else {
                drop(created);
            }
            let exe = &cfg.capture.as_ref().unwrap().executable;
            let original = fs::read_to_string(exe).unwrap();
            let calls = temp.path().join("calls");
            fs::write(
                exe,
                original.replace(
                    "#!/bin/sh",
                    &format!("#!/bin/sh\nprintf called > '{}'", calls.display()),
                ),
            )
            .unwrap();
            inject_checkout_contradiction(&store, &root, case);
            let before = relational_facts(&store);
            let result = reconcile(&cfg, &root.identity().run);
            let unchanged = relational_facts(&store) == before;
            if result.is_ok() || calls.exists() || !unchanged {
                violations.push(format!(
                    "{case} known={known}: result={result:?}, receiver={}, unchanged={unchanged}",
                    calls.exists()
                ));
            }
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}
#[test]
fn begin_replay_checkout_contradictions_after_begin_are_uncertain() {
    let mut violations = Vec::new();
    for case in [
        "rootless_open",
        "rootless_closed",
        "extra_open",
        "held_closed",
    ] {
        let (temp, cfg, _a, root, spec) = crate::capture_preparation::tests::qualified_fixture();
        let (store, created) = crate::capture_setup::begin(&cfg, &root, &spec).unwrap();
        drop(created);
        let exe = &cfg.capture.as_ref().unwrap().executable;
        let original = fs::read_to_string(exe).unwrap();
        let calls = temp.path().join("calls");
        fs::write(
            exe,
            original.replace(
                "#!/bin/sh",
                &format!("#!/bin/sh\nprintf called > '{}'", calls.display()),
            ),
        )
        .unwrap();
        let expected = std::rc::Rc::new(RefCell::new(None));
        let slot = expected.clone();
        let root2 = root.clone();
        let _guard = observing(move |stage, db| {
            if stage == "post_process" {
                assert!(db.conn.is_autocommit());
                inject_checkout_contradiction(db, &root2, case);
                *slot.borrow_mut() = Some(relational_facts(db));
            }
        });
        let result = reconcile(&cfg, &root.identity().run);
        assert!(calls.exists(), "{case}: actual BEGIN must execute");
        let unchanged =
            relational_facts(&store) == *expected.borrow().as_ref().expect("post-BEGIN injection");
        if !matches!(result, Ok("begin_uncertain")) || !unchanged {
            violations.push(format!("{case}: result={result:?}, unchanged={unchanged}"));
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}
#[test]
fn begin_replay_retains_valid_closed_history_and_closed_target_passivity() {
    // Supplemental positive coverage added after the two behavioral REDs.
    for known in [false, true] {
        let (_temp, cfg, _a, root, spec) = crate::capture_preparation::tests::qualified_fixture();
        let (mut store, created) = crate::capture_setup::begin(&cfg, &root, &spec).unwrap();
        if known {
            let crate::capture_journal::BeginCapturedRun::Created(handle) = created else {
                panic!("created")
            };
            let prepared = crate::sinks::ProcessSink::new(spec.sink().process_settings().unwrap())
                .begin(&spec.begin_request(), &spec.expected_git())
                .unwrap();
            store.record_capture_prepared(handle, &prepared).unwrap();
        } else {
            drop(created);
        }
        let mut value = serde_json::to_value(&root).unwrap();
        value["identity"]["group"] = uuid::Uuid::now_v7().to_string().into();
        value["identity"]["run"] = uuid::Uuid::now_v7().to_string().into();
        value["identity"]["run_ref"] = format!("run:closed-{}", uuid::Uuid::now_v7()).into();
        let prior: crate::run_journal::RootRunRequest = serde_json::from_value(value).unwrap();
        // Synthetic valid closed metadata, with typed structurally valid binding;
        // no OS closure claim, capture row, extra writer or forged Ready stage.
        let binding = crate::test_run_fixture::binding(&prior);
        let bound = crate::run_journal::BoundSnapshot::capture(&prior, &binding).unwrap();
        store.conn.execute("INSERT INTO run_groups(id,checkout,mode,revision,closed) VALUES(?1,?2,'supervised',4,1)",
            (prior.identity().group.to_string(), prior.identity().checkout.to_string())).unwrap();
        store.conn.execute("INSERT INTO runs(id,group_id,run_ref,request,stage,binding,outcome) VALUES(?1,?2,?3,?4,'permit_attempt',?5,?6)",
            rusqlite::params![prior.identity().run.to_string(), prior.identity().group.to_string(), prior.identity().run_ref.as_str(), serde_json::to_string(&prior).unwrap(), serde_json::to_string(&bound).unwrap(), serde_json::to_string(&crate::run_journal::RootOutcome::Completed).unwrap()]).unwrap();
        let history = run_journal::exact(&store.conn, &prior).unwrap();
        assert!(history.closed);
        assert!(!history.recovery_hold);
        assert_eq!(
            reconcile(&cfg, &root.identity().run).unwrap(),
            "metadata_reconciled"
        );
        assert_eq!(run_journal::exact(&store.conn, &prior).unwrap(), history);
    }
    // A genuinely closed known target still acknowledges passively before the
    // checkout-local fence, even with a synthetic rootless row added afterward.
    let (_temp, cfg, _a, root, spec) = crate::capture_preparation::tests::qualified_fixture();
    let (mut store, created) = crate::capture_setup::begin(&cfg, &root, &spec).unwrap();
    let crate::capture_journal::BeginCapturedRun::Created(handle) = created else {
        panic!("created")
    };
    let prepared = crate::sinks::ProcessSink::new(spec.sink().process_settings().unwrap())
        .begin(&spec.begin_request(), &spec.expected_git())
        .unwrap();
    store.record_capture_prepared(handle, &prepared).unwrap();
    let binding = crate::test_run_fixture::binding(&root);
    store.record_bound(&root, &binding).unwrap();
    store.record_permit_attempt(&root, &binding).unwrap();
    store
        .record_root_outcome(&root, crate::run_journal::RootOutcome::Completed)
        .unwrap();
    let os = crate::test_run_fixture::ClosureOs::new(&root, &binding);
    let snapshot = store.group_snapshot(&root.identity().run).unwrap();
    let proof = snapshot.certify_empty(&os.driver, &binding).unwrap();
    store.close_supervised_group(&snapshot, &proof).unwrap();
    store
        .conn
        .execute(
            "INSERT INTO run_groups(id,checkout,mode,revision) VALUES(?1,?2,'supervised',1)",
            (
                uuid::Uuid::now_v7().to_string(),
                root.identity().checkout.to_string(),
            ),
        )
        .unwrap();
    let before = relational_facts(&store);
    assert_eq!(
        reconcile(&cfg, &root.identity().run).unwrap(),
        "existing_preparation"
    );
    assert_eq!(relational_facts(&store), before);
}
#[test]
fn begin_replay_missing_requirement_is_only_valid_for_legacy_ready_history() {
    let (temp, cfg, _a, root, spec) = crate::capture_preparation::tests::qualified_fixture();
    let (store, created) = crate::capture_setup::begin(&cfg, &root, &spec).unwrap();
    drop(created);
    store
        .conn
        .execute("DELETE FROM capture_requirements", [])
        .unwrap();
    let exe = &cfg.capture.as_ref().unwrap().executable;
    let original = fs::read_to_string(exe).unwrap();
    fs::write(
        exe,
        original.replace(
            "#!/bin/sh",
            &format!(
                "#!/bin/sh\nprintf called > '{}'",
                temp.path().join("calls").display()
            ),
        ),
    )
    .unwrap();
    let before = raw(&store);
    assert!(
        reconcile(&cfg, &root.identity().run).is_err(),
        "capture_pending without its permanent requirement must refuse before BEGIN"
    );
    assert!(!temp.path().join("calls").exists());
    assert_eq!(raw(&store), before);

    // Genuine ordinary allocation and public v10 BEGIN, not a forged pending stage.
    let (temp, mut cfg, a, old_root, _) = crate::capture_preparation::tests::qualified_fixture();
    cfg.allocation.as_mut().unwrap().capture_sink = None;
    let legacy = crate::allocate::start(
        &cfg,
        crate::allocate::Start {
            operation: uuid::Uuid::now_v7(),
            repository: a.request.repository.clone(),
            root: a.request.root.clone(),
            actor: Some("alice".into()),
            owner: None,
            task: "legacy-task".into(),
            branch: Some("legacy-branch".into()),
            base: "main".into(),
            reuse_branch: false,
        },
    )
    .unwrap();
    assert_eq!(legacy.stage, "ready");
    cfg.allocation.as_mut().unwrap().capture_sink = Some("devdiary".into());
    let mut value = serde_json::to_value(old_root).unwrap();
    value["identity"]["checkout"] = legacy.checkout.to_string().into();
    value["identity"]["group"] = uuid::Uuid::now_v7().to_string().into();
    value["identity"]["run"] = uuid::Uuid::now_v7().to_string().into();
    let root: crate::run_journal::RootRunRequest = serde_json::from_value(value).unwrap();
    let spec = cfg
        .capture_spec(
            &root,
            &legacy,
            uuid::Uuid::now_v7(),
            vec!["legacy-task".into()],
            None,
        )
        .unwrap();
    let (mut store, lock) = crate::allocate::locked(&cfg).unwrap();
    drop(lock);
    assert!(
        crate::capture_requirement::read(&store.conn, legacy.checkout)
            .unwrap()
            .is_none()
    );
    drop(store.begin_captured_run(&root, &spec).unwrap());
    assert_eq!(
        reconcile(&cfg, &root.identity().run).unwrap(),
        "metadata_reconciled"
    );
    assert!(
        !store
            .capture_snapshot(&root.identity().run)
            .unwrap()
            .unwrap()
            .prepared
            .unwrap()
            .live_preparation
    );
    assert!(temp.path().join("response").exists());
}
#[test]
fn begin_replay_preeligibility_refuses_without_receiver() {
    for case in ["adopted", "orphan", "ready", "writer", "terminal"] {
        let (temp, cfg, _a, root, spec) = crate::capture_preparation::tests::qualified_fixture();
        let (store, created) = crate::capture_setup::begin(&cfg, &root, &spec).unwrap();
        drop(created);
        let exe = &cfg.capture.as_ref().unwrap().executable;
        let original = fs::read_to_string(exe).unwrap();
        fs::write(
            exe,
            original.replace(
                "#!/bin/sh",
                &format!(
                    "#!/bin/sh\nprintf called > '{}'",
                    temp.path().join("calls").display()
                ),
            ),
        )
        .unwrap();
        match case {
            "adopted" => {
                store.conn.execute("INSERT INTO adopted_groups(id,checkout,run_id,run_ref,operation,request,revision) VALUES(?1,?2,?3,?4,?5,'{}',1)", rusqlite::params![uuid::Uuid::now_v7().to_string(), root.identity().checkout.to_string(), uuid::Uuid::now_v7().to_string(), "contradictory-adoption", uuid::Uuid::now_v7().to_string()]).unwrap();
            }
            "orphan" => {
                store.conn.execute_batch("PRAGMA foreign_keys=OFF; UPDATE runs SET group_id='missing-group'; PRAGMA foreign_keys=ON;").unwrap();
            }
            "ready" => {
                store
                    .conn
                    .execute("UPDATE checkouts SET ready=1", [])
                    .unwrap();
            }
            "writer" => {
                store.conn.execute("DELETE FROM writers", []).unwrap();
            }
            "terminal" => {
                store
                    .conn
                    .execute("UPDATE checkouts SET state='retired'", [])
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let before = raw(&store);
        assert!(reconcile(&cfg, &root.identity().run).is_err(), "{case}");
        assert!(!temp.path().join("calls").exists(), "{case}");
        assert_eq!(raw(&store), before, "{case}");
    }
}
#[test]
fn begin_replay_failure_preserves_intent_and_reports_uncertainty() {
    for mode in ["lost", "malformed", "mismatch"] {
        let (temp, cfg, _a, root, spec) = crate::capture_preparation::tests::qualified_fixture();
        let (store, created) = crate::capture_setup::begin(&cfg, &root, &spec).unwrap();
        drop(created);
        let original = fs::read(temp.path().join("response")).unwrap();
        let exe = &cfg.capture.as_ref().unwrap().executable;
        let script = |fail: bool| {
            format!(
                "#!/bin/sh\n/usr/bin/cat >> '{}'\n{}\nexec /usr/bin/cat '{}'\n",
                temp.path().join("input").display(),
                if fail { "exit 1" } else { ":" },
                temp.path().join("response").display()
            )
        };
        fs::write(exe, script(mode == "lost")).unwrap();
        if mode == "malformed" {
            fs::write(temp.path().join("response"), "{").unwrap();
        }
        if mode == "mismatch" {
            let mut v: serde_json::Value = serde_json::from_slice(&original).unwrap();
            v["actor_ref"] = "other".into();
            fs::write(temp.path().join("response"), v.to_string()).unwrap();
        }
        let before = raw(&store);
        assert_eq!(
            reconcile(&cfg, &root.identity().run).unwrap(),
            "begin_uncertain",
            "{mode}"
        );
        assert_eq!(raw(&store), before);
        assert_eq!(
            store
                .run_snapshot(&root.identity().run)
                .unwrap()
                .unwrap()
                .revision,
            1
        );
        fs::write(exe, script(false)).unwrap();
        fs::write(temp.path().join("response"), original).unwrap();
        assert_eq!(
            reconcile(&cfg, &root.identity().run).unwrap(),
            "metadata_reconciled"
        );
        let body = spec.begin_request().encode().unwrap();
        assert_eq!(
            fs::read(temp.path().join("input")).unwrap(),
            [body.clone(), body].concat()
        );
    }
}
#[test]
fn begin_replay_physical_and_durable_races_refuse_commit() {
    for case in [
        "pre_marker",
        "post_marker",
        "owner",
        "requirement",
        "hold",
        "creator",
        "closure",
        "task",
        "head",
        "source",
        "checkout",
        "identity",
    ] {
        let (temp, cfg, a, root, spec) = crate::capture_preparation::tests::qualified_fixture();
        let (store, created) = crate::capture_setup::begin(&cfg, &root, &spec).unwrap();
        let exe = &cfg.capture.as_ref().unwrap().executable;
        let original = fs::read_to_string(exe).unwrap();
        fs::write(
            exe,
            original.replace(
                "#!/bin/sh",
                &format!(
                    "#!/bin/sh\nprintf called >> '{}'",
                    temp.path().join("calls").display()
                ),
            ),
        )
        .unwrap();
        let mut created = Some(created);
        let root2 = root.clone();
        let cfg2 = cfg.clone();
        let before = raw(&store);
        let _guard = observing(move |stage, _| {
            if case == "pre_marker" && stage == "pre_physical"
                || case == "post_marker" && stage == "post_process"
            {
                fs::write(
                    a.identity
                        .as_ref()
                        .unwrap()
                        .private_git_dir
                        .join("work-lease.json"),
                    "{}",
                )
                .unwrap();
            }
            if stage != "post_process" {
                return;
            }
            let mut db = Store::open_existing_registered_mut(
                cfg2.trusted_registry.as_deref().unwrap(),
                cfg2.store_dir.as_deref().unwrap(),
                &cfg2.roots,
            )
            .unwrap();
            match case {
                "owner" => {
                    db.conn
                        .execute("UPDATE checkouts SET owner='changed'", [])
                        .unwrap();
                }
                "requirement" => {
                    db.conn
                        .execute("UPDATE capture_requirements SET revision=revision+1", [])
                        .unwrap();
                }
                "hold" => {
                    db.record_recovery_hold(&root2).unwrap();
                }
                "task" => {
                    db.conn
                        .execute(
                            "INSERT INTO task_finishes VALUES(?1,?2,'{}')",
                            (a.checkout.to_string(), uuid::Uuid::now_v7().to_string()),
                        )
                        .unwrap();
                }
                "creator" | "closure" => {
                    let crate::capture_journal::BeginCapturedRun::Created(handle) =
                        created.take().unwrap()
                    else {
                        panic!("created")
                    };
                    let p = crate::sinks::ProcessSink::new(spec.sink().process_settings().unwrap())
                        .begin(&spec.begin_request(), &spec.expected_git())
                        .unwrap();
                    db.record_capture_prepared(handle, &p).unwrap();
                    if case == "closure" {
                        // Original creator progresses concurrently; synthetic OS evidence only.
                        let binding = crate::test_run_fixture::binding(&root2);
                        db.record_bound(&root2, &binding).unwrap();
                        db.record_permit_attempt(&root2, &binding).unwrap();
                        db.record_root_outcome(&root2, crate::run_journal::RootOutcome::Completed)
                            .unwrap();
                        let os = crate::test_run_fixture::ClosureOs::new(&root2, &binding);
                        let snapshot = db.group_snapshot(&root2.identity().run).unwrap();
                        let proof = snapshot.certify_empty(&os.driver, &binding).unwrap();
                        db.close_supervised_group(&snapshot, &proof).unwrap();
                    }
                }
                "source" | "checkout" => {
                    let path = if case == "source" {
                        a.request.repository.as_ref().unwrap()
                    } else {
                        &a.destination
                    };
                    fs::rename(path, path.with_extension("moved")).unwrap();
                    fs::create_dir(path).unwrap();
                }
                "identity" => {
                    db.conn
                        .execute(
                            "UPDATE allocations SET record=json_set(record,'$.identity.head',?1)",
                            ["b".repeat(40)],
                        )
                        .unwrap();
                }
                "head" => {
                    assert!(std::process::Command::new("git")
                        .args([
                            "-c",
                            "user.name=Fixture",
                            "-c",
                            "user.email=fixture@example.invalid",
                            "commit",
                            "--allow-empty",
                            "-m",
                            "race"
                        ])
                        .current_dir(&a.destination)
                        .output()
                        .unwrap()
                        .status
                        .success());
                }
                _ => (),
            }
        });
        let result = reconcile(&cfg, &root.identity().run);
        if case == "pre_marker" {
            assert!(result.is_err());
            assert!(!temp.path().join("calls").exists());
        } else {
            assert!(temp.path().join("calls").exists());
            assert_eq!(result.unwrap(), "begin_uncertain", "{case}");
        }
        if case == "closure" {
            let snapshot = store.run_snapshot(&root.identity().run).unwrap().unwrap();
            assert!(snapshot.closed);
            assert!(!snapshot.recovery_hold);
            assert!(store
                .capture_snapshot(&root.identity().run)
                .unwrap()
                .unwrap()
                .group_end
                .is_some());
        } else if case != "creator" {
            assert_eq!(raw(&store), before, "{case}");
        } else {
            assert!(
                store
                    .capture_snapshot(&root.identity().run)
                    .unwrap()
                    .unwrap()
                    .prepared
                    .unwrap()
                    .live_preparation
            );
        }
    }
}
#[test]
fn begin_replay_observations_and_process_hold_no_sql_or_flock() {
    let (temp, mut cfg, a, root, old) = crate::capture_preparation::tests::qualified_fixture();
    cfg.capture.as_mut().unwrap().timeout_ms = 2000;
    let spec = cfg
        .capture_spec(&root, &a, old.operation(), vec!["task".into()], None)
        .unwrap();
    let (_store, created) = crate::capture_setup::begin(&cfg, &root, &spec).unwrap();
    drop(created);
    fs::write(&cfg.capture.as_ref().unwrap().executable, format!("#!/usr/bin/python3\nimport sqlite3,fcntl,pathlib,sys,time\np=pathlib.Path({:?})\nc=sqlite3.connect(p/'private/store.sqlite',timeout=0)\nc.execute('begin immediate')\nc.rollback()\nf=open(p/'private/allocation.lock','r+')\nfcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nfcntl.flock(f,fcntl.LOCK_UN)\nsys.stdin.buffer.read()\ntime.sleep(0.65)\nsys.stdout.buffer.write((p/'response').read_bytes())\n", temp.path().to_str().unwrap())).unwrap();
    let dir = cfg.store_dir.clone().unwrap();
    let lock_store = Store::open_existing_registered_mut(
        cfg.trusted_registry.as_ref().unwrap(),
        &dir,
        &cfg.roots,
    )
    .unwrap();
    let count = std::rc::Rc::new(Cell::new(0));
    let seen = count.clone();
    let _guard = observing(move |_, store| {
        assert!(store.conn.is_autocommit());
        let db = Connection::open(dir.join("store.sqlite")).unwrap();
        db.busy_timeout(Duration::ZERO).unwrap();
        db.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
        let lock = crate::allocate::lifecycle_lock(&lock_store).unwrap();
        drop(lock);
        std::thread::sleep(Duration::from_millis(650));
        let sum: i64 = store.conn.query_row("WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<5000) SELECT sum(x) FROM n", [], |r| r.get(0)).unwrap();
        assert_eq!(sum, 12_502_500);
        seen.set(seen.get() + 1);
    });
    assert_eq!(
        reconcile(&cfg, &root.identity().run).unwrap(),
        "metadata_reconciled"
    );
    assert_eq!(count.get(), 4);
}
#[test]
fn begin_replay_real_lock_contention_expires_post_observation() {
    let (_temp, cfg, _a, root, spec) = crate::capture_preparation::tests::qualified_fixture();
    let (store, created) = crate::capture_setup::begin(&cfg, &root, &spec).unwrap();
    drop(created);
    let dir = cfg.store_dir.clone().unwrap();
    let lock_store = Store::open_existing_registered_mut(
        cfg.trusted_registry.as_ref().unwrap(),
        &dir,
        &cfg.roots,
    )
    .unwrap();
    let worker = std::rc::Rc::new(RefCell::new(None));
    let slot = worker.clone();
    let _guard = observing(move |stage, _| {
        if stage == "post_physical" {
            std::thread::sleep(Duration::from_millis(1800));
            let lock = crate::allocate::lifecycle_lock(&lock_store).unwrap();
            *slot.borrow_mut() = Some(std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(350));
                drop(lock);
            }));
        }
    });
    let before = raw(&store);
    assert_eq!(
        reconcile(&cfg, &root.identity().run).unwrap(),
        "begin_uncertain"
    );
    worker.borrow_mut().take().unwrap().join().unwrap();
    assert_eq!(raw(&store), before);
    assert_eq!(
        store
            .run_snapshot(&root.identity().run)
            .unwrap()
            .unwrap()
            .revision,
        1
    );
}
#[test]
fn begin_replay_expired_original_observations_never_commit() {
    for expire in [1, 2, 3] {
        let (_temp, cfg, _a, root, spec) = crate::capture_preparation::tests::qualified_fixture();
        let (store, created) = crate::capture_setup::begin(&cfg, &root, &spec).unwrap();
        drop(created);
        let _guard = Guard;
        CLOCK.with(|clock| clock.set((0, expire)));
        let before = raw(&store);
        let result = reconcile(&cfg, &root.identity().run);
        if expire == 1 {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), "begin_uncertain");
        }
        assert_eq!(raw(&store), before);
        assert_eq!(
            store
                .run_snapshot(&root.identity().run)
                .unwrap()
                .unwrap()
                .revision,
            1
        );
    }
}
#[test]
fn missing_preparation_replays_exact_begin_and_stays_held() {
    let (temp, mut cfg, a, root, old) = crate::capture_preparation::tests::qualified_fixture();
    cfg.capture.as_mut().unwrap().timeout_ms = 2000;
    cfg.capture.as_mut().unwrap().key_file = Some(temp.path().join("sealed-key-locator"));
    let spec = cfg
        .capture_spec(
            &root,
            &a,
            old.operation(),
            vec!["task".into(), "secondary-task".into()],
            Some(crate::capture_bridge::Source {
                system: Some("sealed-source".into()),
                ..Default::default()
            }),
        )
        .unwrap();
    let (store, created) = crate::capture_setup::begin(&cfg, &root, &spec).unwrap();
    drop(created);
    // Deliberately corrupt unrelated capture bytes must not globally poison this target.
    // Synthetic unrelated row only; the target still uses the actual Git fixture.
    store
        .conn
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .unwrap();
    store.conn.execute("INSERT INTO capture_runs SELECT ?1,?2,?3,?4,'{',fingerprint,intent_wall,preparation_revision,NULL,NULL FROM capture_runs", rusqlite::params![uuid::Uuid::now_v7().to_string(), uuid::Uuid::now_v7().to_string(), uuid::Uuid::now_v7().to_string(), uuid::Uuid::now_v7().to_string()]).unwrap();
    store.conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    let exe = cfg.capture.as_ref().unwrap().executable.clone();
    // Fake producer is stdlib-only and checks durable intent before reading stdin.
    fs::write(&exe, format!("#!/usr/bin/python3\nimport sqlite3,sys,pathlib,json\np=pathlib.Path({:?})\nc=sqlite3.connect(p/'private/store.sqlite', timeout=0)\nassert c.execute('select prepared from capture_runs').fetchone()==(None,)\nc.execute('begin immediate')\nc.rollback()\n(p/'args').write_text(json.dumps(sys.argv[1:]))\n(p/'input').write_bytes(sys.stdin.buffer.read())\nsys.stdout.buffer.write((p/'response').read_bytes())\n", temp.path().to_str().unwrap())).unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o700)).unwrap();
    let original = cfg.capture.as_ref().unwrap().clone();
    cfg.capture.as_mut().unwrap().executable = "/must-not-use-current-profile".into();
    cfg.capture.as_mut().unwrap().registry = "/must-not-use-current-registry".into();
    cfg.capture.as_mut().unwrap().key_file = Some("/must-not-use-current-key".into());
    assert_eq!(
        reconcile(&cfg, &root.identity().run).unwrap(),
        "metadata_reconciled"
    );
    assert_eq!(
        fs::read(temp.path().join("input")).unwrap(),
        spec.begin_request().encode().unwrap()
    );
    let args: Vec<String> =
        serde_json::from_slice(&fs::read(temp.path().join("args")).unwrap()).unwrap();
    assert_eq!(
        args,
        vec![
            "--config".to_owned(),
            original.registry.to_str().unwrap().into(),
            "capture".into(),
            "begin".into(),
            "--state-dir".into(),
            original.state_dir.to_str().unwrap().into(),
            "--json".into()
        ]
    );
    let capture = store
        .capture_snapshot(&root.identity().run)
        .unwrap()
        .unwrap();
    assert!(!capture.prepared.unwrap().live_preparation);
    let snapshot = store.run_snapshot(&root.identity().run).unwrap().unwrap();
    assert!(snapshot.recovery_hold);
    assert!(snapshot.binding.is_none());
    assert_eq!(
        reconcile(&cfg, &root.identity().run).unwrap(),
        "existing_preparation"
    );
}
fn seed_prepared_fence(store: &Store, checkout: uuid::Uuid) {
    crate::retirement_journal::tests::seed_prepared(store, checkout, uuid::Uuid::now_v7());
    let rows = crate::retirement_journal::read_history(&store.conn, checkout).unwrap();
    assert_eq!(
        (rows.len(), rows[0].revision, rows[0].stage.as_str()),
        (1, 1, "prepared")
    );
}
fn root_checkout(root: &crate::run_journal::RootRunRequest) -> uuid::Uuid {
    uuid::Uuid::parse_str(&root.identity().checkout.to_string()).unwrap()
}
#[test]
fn unknown_run_refuses_without_invented_fence() {
    let (_temp, cfg, _a, root, spec) = crate::capture_preparation::tests::qualified_fixture();
    let (store, created) = crate::capture_setup::begin(&cfg, &root, &spec).unwrap();
    drop(created);
    let unknown = work_contract::RunId::parse(&uuid::Uuid::now_v7().to_string()).unwrap();
    assert!(matches!(
        reconcile(&cfg, &unknown),
        Err(StoreError::Invalid)
    ));
    let count: i64 = store
        .conn
        .query_row("SELECT count(*) FROM retirement_intents", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}
#[test]
fn reconcile_holds_prepared_intent_before_receiver() {
    let (temp, cfg, _a, root, spec) = crate::capture_preparation::tests::qualified_fixture();
    let (store, created) = crate::capture_setup::begin(&cfg, &root, &spec).unwrap();
    drop(created);
    let checkout = root_checkout(&root);
    seed_prepared_fence(&store, checkout);
    let source_before = crate::retirement_journal::tests::source_rows(&store);
    let before = raw(&store);
    let saw = std::rc::Rc::new(std::cell::Cell::new(false));
    let flag = saw.clone();
    let _guard = observing(move |stage, _| {
        if stage == "pre_process" {
            flag.set(true);
        }
    });
    assert!(matches!(
        reconcile(&cfg, &root.identity().run),
        Err(StoreError::RetirementFenced)
    ));
    assert!(!saw.get());
    assert_eq!(raw(&store), before);
    assert_eq!(
        crate::retirement_journal::tests::source_rows(&store),
        source_before
    );
    assert_eq!(store.pending_events(1000).unwrap().iter().filter(|e|
        matches!(&e.event, crate::events::Event::RetirementIntentChanged { stage, .. } if stage == "held")
    ).count(), 1);
    assert!(!temp.path().join("calls").exists());
    let (revision, stage, reason): (i64, String, Option<String>) = store
        .conn
        .query_row(
            "SELECT revision, stage, held_reason FROM retirement_intents WHERE checkout=?1",
            [checkout.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (revision, stage.as_str(), reason.as_deref()),
        (2, "held", Some("capture_reconcile"))
    );
}
#[test]
fn reconcile_commit_fences_after_actual_begin_without_mutating_caller_rows() {
    let (_temp, cfg, _a, root, spec) = crate::capture_preparation::tests::qualified_fixture();
    let (store, created) = crate::capture_setup::begin(&cfg, &root, &spec).unwrap();
    drop(created);
    let checkout = root_checkout(&root);
    let before = std::rc::Rc::new(std::cell::RefCell::new(None));
    let observed = before.clone();
    let _observer = observing(move |stage, store| {
        if stage == "post_process" {
            seed_prepared_fence(store, checkout);
            *observed.borrow_mut() = Some(crate::retirement_journal::tests::source_rows(store));
        }
    });
    assert!(reconcile(&cfg, &root.identity().run).is_err());
    assert!(
        before.borrow().is_some(),
        "actual BEGIN result boundary not reached"
    );
    assert_eq!(
        crate::retirement_journal::tests::source_rows(&store),
        before.borrow().as_ref().unwrap().clone()
    );
    let rows = crate::retirement_journal::read_history(&store.conn, checkout).unwrap();
    assert_eq!(
        (
            rows[0].revision,
            rows[0].stage.as_str(),
            rows[0].held_reason.as_deref()
        ),
        (2, "held", Some("capture_reconcile"))
    );
    assert_eq!(store.pending_events(1000).unwrap().iter().filter(|e|
        matches!(&e.event, crate::events::Event::RetirementIntentChanged { stage, .. } if stage == "held")
    ).count(), 1);
}
#[test]
fn reconcile_preboundary_refusal_disconnects_guard_waiter_before_join() {
    let (_temp, cfg, _a, _root, _spec) = crate::capture_preparation::tests::qualified_fixture();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let reached = std::rc::Rc::new(std::cell::Cell::new(false));
    let flag = reached.clone();
    let observer = observing(move |stage, _| {
        if stage == "post_process" {
            flag.set(true);
            ready_tx.send(()).unwrap();
        }
    });
    let worker =
        std::thread::spawn(move || ready_rx.recv_timeout(std::time::Duration::from_secs(5)));
    let unknown = work_contract::RunId::parse(&uuid::Uuid::now_v7().to_string()).unwrap();
    assert!(matches!(
        reconcile(&cfg, &unknown),
        Err(StoreError::Invalid)
    ));
    drop(observer);
    assert_eq!(
        worker.join().unwrap(),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
    );
    assert!(!reached.get());
}
#[test]
fn reconcile_shared_guard_excludes_exclusive_until_drain() {
    let (_temp, cfg, _a, root, spec) = crate::capture_preparation::tests::qualified_fixture();
    let (store, created) = crate::capture_setup::begin(&cfg, &root, &spec).unwrap();
    drop(created);
    drop(store);
    let checkout = root_checkout(&root);
    let registry = cfg.trusted_registry.clone().unwrap();
    let dir = cfg.store_dir.clone().unwrap();
    let roots = cfg.roots.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let reached = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = reached.clone();
    let observer = observing(move |stage, _| {
        if stage == "post_process" {
            observed.set(true);
            ready_tx.send(()).expect("guard worker disappeared");
            release_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("guard worker did not acknowledge post_process");
        }
    });
    let handle = std::thread::spawn({
        let registry = registry.clone();
        let dir = dir.clone();
        let roots = roots.clone();
        move || {
            ready_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("reconcile never reached post_process");
            let other = Store::open_existing_registered_mut(&registry, &dir, &roots).unwrap();
            assert!(matches!(
                crate::checkout_guard::CheckoutGuard::exclusive(&other, checkout),
                Err(StoreError::OperationsInFlight)
            ));
            crate::checkout_guard::CheckoutGuard::shared(&other, uuid::Uuid::now_v7()).unwrap();
            let lock = crate::store::AuthorityIdentity::open_lock(
                &other.authority_identity().directory,
                false,
            )
            .unwrap();
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
            drop(lock);
            release_tx.send(()).unwrap();
        }
    });
    let result = reconcile(&cfg, &root.identity().run);
    // Drop the retained sender before join even when reconcile refused early.
    drop(observer);
    let worker = handle.join();
    assert!(reached.get(), "post_process not reached: {result:?}");
    worker.unwrap();
    assert_eq!(result.unwrap(), "metadata_reconciled");
    let other = Store::open_existing_registered_mut(&registry, &dir, &roots).unwrap();
    crate::checkout_guard::CheckoutGuard::exclusive(&other, checkout).unwrap();
}
