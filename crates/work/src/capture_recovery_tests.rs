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
    let count = std::rc::Rc::new(Cell::new(0));
    let seen = count.clone();
    let _guard = observing(move |_, store| {
        assert!(store.conn.is_autocommit());
        let db = Connection::open(dir.join("store.sqlite")).unwrap();
        db.busy_timeout(Duration::ZERO).unwrap();
        db.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
        let lock = crate::allocate::lifecycle_lock(&dir).unwrap();
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
    let worker = std::rc::Rc::new(RefCell::new(None));
    let slot = worker.clone();
    let _guard = observing(move |stage, _| {
        if stage == "post_physical" {
            std::thread::sleep(Duration::from_millis(1800));
            let lock = crate::allocate::lifecycle_lock(&dir).unwrap();
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
