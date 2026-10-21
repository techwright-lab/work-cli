#[path = "support/run_fixture.rs"]
mod support;
use support::*;
#[path = "support/lifecycle_regressions.rs"]
mod regressions;

#[test]
fn configurationless_recovery_refuses_open_bound_gap() {
    let (dir, mut store, checkout) = fixture();
    let root = request(checkout);
    store.begin_run(&root).unwrap();
    let bound = binding(&root);
    store.record_bound(&root, &bound).unwrap();
    let os = ClosureOs::new(&root, &bound);
    let mut malformed = serde_json::to_value(&root).unwrap();
    malformed["input"]["attribution"] = "off".into();
    let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute(
        "UPDATE runs SET request=?1",
        [serde_json::to_string(&malformed).unwrap()],
    )
    .unwrap();
    // Marker without a matching strict record is corruption, not a proof fixture.
    let before = store.pending_events(100).unwrap();
    assert!(work_cli::run_recovery::recover(&mut store, &root.identity().run, &os.driver).is_err());
    assert_eq!(store.pending_events(100).unwrap(), before);
    assert_eq!(
        sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn ordinary_lifecycle_status_reads_committed_wal_without_keepers_or_mutation() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    let config = work_cli::config::Config {
        trusted_registry: Some(dir.path().join(".work-authorities")),
        store_dir: Some(dir.path().join("private")),
        roots: vec![dir.path().join("root")],
        ..Default::default()
    };
    let id = uuid::Uuid::parse_str(&r.identity().run.to_string()).unwrap();
    let n = store.pending_events(100).unwrap().len();
    // Registry is already closed, while the store's committed intent is in WAL.
    let before = regressions::files(dir.path());
    assert!(work_cli::run_recovery::command_status(&config, id).is_ok());
    assert!(regressions::files(dir.path()) == before);
    drop(store);
    let before = regressions::files(dir.path());
    for _ in 0..2 {
        let report = work_cli::run_recovery::command_status(&config, id).unwrap();
        assert!(report.record.request == r);
        assert!(!report.record.closed);
        assert!(regressions::files(dir.path()) == before);
    }
    let reader = work_cli::store::Store::open_existing_registered_readonly(
        config.trusted_registry.as_ref().unwrap(),
        config.store_dir.as_ref().unwrap(),
        &config.roots,
    )
    .unwrap();
    assert_eq!(reader.pending_events(100).unwrap().len(), n);
}

#[test]
fn accepted_large_requests_remain_readable_through_historical_recovery() {
    for (scalar, entries) in [("x", 1), ("x", 32), ("\"", 32), ("\u{10000}", 32)] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let text = scalar.repeat(4096);
        let chain = vec![
            serde_json::json!({"kind":"executor", "system":text, "session_ref":text});
            entries
        ];
        let r = changed(&r, "execution_chain", serde_json::json!(chain));
        let bytes = serde_json::to_vec(&r).unwrap().len();
        assert!(bytes > 8192);
        assert_eq!(bytes > 16384, entries > 1);
        store.begin_run(&r).unwrap();
        assert_eq!(store.begin_run(&r).unwrap(), BeginRun::Existing);
        let b = binding(&r);
        store.record_bound(&r, &b).unwrap();
        assert!(
            store
                .run_snapshot(&r.identity().run)
                .unwrap()
                .unwrap()
                .request
                == r
        );
        let os = ClosureOs::new(&r, &b);
        drop(store);
        let mut store = work_cli::store::Store::open_existing_registered_mut(
            &dir.path().join(".work-authorities"),
            &dir.path().join("private"),
            &[dir.path().join("root")],
        )
        .unwrap();
        assert!(
            work_cli::run_recovery::status(&store, &r.identity().run)
                .unwrap()
                .record
                .request
                == r
        );
        assert_eq!(
            recover(&mut store, &r.identity().run, &os.driver).unwrap(),
            RecoveryState::Closed
        );
        drop(store);
        let reader = work_cli::store::Store::open_existing_registered_readonly(
            &dir.path().join(".work-authorities"),
            &dir.path().join("private"),
            &[dir.path().join("root")],
        )
        .unwrap();
        assert!(
            work_cli::run_recovery::status(&reader, &r.identity().run)
                .unwrap()
                .record
                .request
                == r
        );
    }
}

#[test]
fn rejected_authority_never_changes_delete_mode_database_or_entries() {
    for case in ["claims", "v4", "schema"] {
        let (dir, store, _) = fixture();
        drop(store);
        let registry = dir.path().join(".work-authorities");
        let private = dir.path().join("private");
        let reg = rusqlite::Connection::open(registry.join("authorities.sqlite")).unwrap();
        if case == "claims" {
            reg.execute("UPDATE authorities SET store='wrong'", [])
                .unwrap();
        }
        reg.execute_batch("PRAGMA journal_mode=DELETE").unwrap();
        drop(reg);
        let sql = rusqlite::Connection::open(private.join("store.sqlite")).unwrap();
        match case {
            "v4" => sql.execute_batch("PRAGMA user_version=4").unwrap(),
            "schema" => sql.execute_batch("DROP TABLE runs").unwrap(),
            _ => (),
        }
        sql.execute_batch("PRAGMA journal_mode=DELETE").unwrap();
        drop(sql);
        let before = regressions::files(dir.path());
        assert!(work_cli::store::Store::open_existing_registered_mut(
            &registry,
            &private,
            &[dir.path().join("root")],
        )
        .is_err());
        assert!(regressions::files(dir.path()) == before, "{case}");
    }
}

#[test]
fn existing_recovery_writer_bounds_queries_but_not_os_inspection_age() {
    for expensive in [false, true] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        store.begin_run(&r).unwrap();
        let b = binding(&r);
        store.record_bound(&r, &b).unwrap();
        let os = ClosureOs::new(&r, &b);
        drop(store);
        if expensive {
            let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
            sql.execute_batch("ALTER TABLE writers RENAME TO real_writers;
                CREATE VIEW writers AS SELECT * FROM real_writers WHERE
                (WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<2000000) SELECT sum(x) FROM n)>0;").unwrap();
            // Do not let a test-only client remove the legitimate bookkeeping.
            sql.set_db_config(
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                true,
            )
            .unwrap();
        } else {
            std::fs::write(
                os.tmp.path().join("manager"),
                format!(
                    "#!/bin/sh\n/usr/bin/sleep 0.35\nexec /usr/bin/cat '{}'\n",
                    os.tmp.path().join("properties").display(),
                ),
            )
            .unwrap();
        }
        let mut store = work_cli::store::Store::open_existing_registered_mut(
            &dir.path().join(".work-authorities"),
            &dir.path().join("private"),
            &[dir.path().join("root")],
        )
        .unwrap();
        let started = std::time::Instant::now();
        if expensive {
            assert!(
                store.group_snapshot(&r.identity().run).is_err(),
                "expensive schema query must be interrupted"
            );
        } else {
            let result = recover(&mut store, &r.identity().run, &os.driver);
            assert_eq!(result.unwrap(), RecoveryState::Closed);
            assert!(started.elapsed() > std::time::Duration::from_millis(500));
        }
    }
}
use work_cli::{
    run_journal::BeginRun,
    run_recovery::{recover, RecoveryState},
};

#[test]
fn controller_loss_recovery_closes_only_writer_preserving_unknown_outcome_and_charge() {
    for reaped in [false, true] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        store.begin_run(&r).unwrap();
        let b = binding(&r);
        store.record_bound(&r, &b).unwrap();
        store.record_permit_attempt(&r, &b).unwrap();
        let os = ClosureOs::new(&r, &b);
        if reaped {
            std::fs::remove_dir_all(os.tmp.path().join("cg/test")).unwrap();
            std::fs::write(os.tmp.path().join("properties"), format!("Id={}\nInvocationID=\nControlGroup=\nLoadState=not-found\nActiveState=inactive\n", b.identity().unit)).unwrap();
        }
        drop(b);
        drop(store);
        let mut store = reopen(&dir).unwrap();
        assert_eq!(
            recover(&mut store, &r.identity().run, &os.driver).unwrap(),
            RecoveryState::Closed
        );
        let receipt = store.run_snapshot(&r.identity().run).unwrap().unwrap();
        assert!(receipt.closed);
        assert_eq!(receipt.outcome, None);
        assert_eq!(receipt.request, r);
        assert_eq!(store.charged(&dir.path().join("root"), None).unwrap(), 1);
        let next = request(checkout);
        assert_eq!(store.begin_run(&next).unwrap(), BeginRun::Created);
        let n = store.pending_events(100).unwrap().len();
        std::fs::remove_file(os.tmp.path().join("manager")).unwrap();
        assert_eq!(
            recover(&mut store, &r.identity().run, &os.driver).unwrap(),
            RecoveryState::AlreadyClosed
        );
        assert_eq!(store.pending_events(100).unwrap().len(), n);
        assert_eq!(store.begin_run(&next).unwrap(), BeginRun::Existing);
        assert!(store.begin_run(&request(checkout)).is_err());
    }
}

#[test]
fn uncertain_or_live_historical_roots_hold_without_mutating_journal() {
    for case in [
        "intent",
        "live",
        "reused",
        "escaped",
        "boot",
        "manager",
        "replacement",
        "populated",
    ] {
        let (_dir, mut store, checkout) = fixture();
        let r = request(checkout);
        store.begin_run(&r).unwrap();
        let b = binding(&r);
        if case != "intent" {
            store.record_bound(&r, &b).unwrap();
        }
        let os = ClosureOs::new(&r, &b);
        let p = os.tmp.path();
        match case {
            "live" => os.process(&b, 10, &b.identity().cgroup),
            "reused" => os.process(&b, 11, &b.identity().cgroup),
            "escaped" => os.process(&b, 10, "/escaped"),
            "boot" => std::fs::write(
                p.join("proc/sys/kernel/random/boot_id"),
                "650e8400-e29b-41d4-a716-446655440000",
            )
            .unwrap(),
            "manager" => std::fs::remove_file(p.join("manager")).unwrap(),
            "replacement" => {
                let text = std::fs::read_to_string(p.join("properties")).unwrap();
                std::fs::write(
                    p.join("properties"),
                    text.replace(
                        "550e8400e29b41d4a716446655440000",
                        "650e8400e29b41d4a716446655440000",
                    ),
                )
                .unwrap();
            }
            "populated" => {
                os.process_pid(43, 12, &b.identity().cgroup);
                std::fs::write(
                    p.join("cg")
                        .join(b.identity().cgroup.trim_start_matches('/'))
                        .join("cgroup.procs"),
                    "43\n",
                )
                .unwrap();
            }
            _ => {}
        }
        let before = store.run_snapshot(&r.identity().run).unwrap();
        let n = store.pending_events(100).unwrap().len();
        let result = recover(&mut store, &r.identity().run, &os.driver).unwrap();
        assert!(matches!(result, RecoveryState::Held { .. }), "{case}");
        assert_eq!(
            serde_json::to_value(&result).unwrap()["charges_retained"],
            true
        );
        assert_eq!(
            store.run_snapshot(&r.identity().run).unwrap(),
            before,
            "{case}"
        );
        assert_eq!(store.pending_events(100).unwrap().len(), n);
        assert!(store.begin_run(&request(checkout)).is_err());
    }
}

#[test]
fn public_historical_commands_need_no_old_actor_profile_or_runtime_for_receipts() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    let b = binding(&r);
    store.record_bound(&r, &b).unwrap();
    let os = ClosureOs::new(&r, &b);
    let config = work_cli::config::Config {
        trusted_registry: Some(dir.path().join(".work-authorities")),
        store_dir: Some(dir.path().join("private")),
        roots: vec![dir.path().join("root")],
        // No actor profiles and no bus configuration. Closed receipts require neither.
        ..Default::default()
    };
    let id = uuid::Uuid::parse_str(&r.identity().run.to_string()).unwrap();
    let before = store.run_snapshot(&r.identity().run).unwrap();
    assert!(matches!(
        work_cli::run_recovery::command_recover(&config, id).unwrap(),
        RecoveryState::Held {
            charges_retained: true,
            ..
        }
    ));
    assert_eq!(store.run_snapshot(&r.identity().run).unwrap(), before);
    assert_eq!(
        recover(&mut store, &r.identity().run, &os.driver).unwrap(),
        RecoveryState::Closed
    );
    let n = store.pending_events(100).unwrap().len();
    drop(store);
    assert_eq!(
        work_cli::run_recovery::command_recover(&config, id).unwrap(),
        RecoveryState::AlreadyClosed
    );
    // No keeper connections: normal writable lifecycle must retain bookkeeping.
    let config_path = dir.path().join("config.toml");
    let config_text = format!(
        "store_dir={:?}\ntrusted_registry={:?}\nroots=[{:?}]\n",
        config.store_dir.as_ref().unwrap(),
        config.trusted_registry.as_ref().unwrap(),
        config.roots[0]
    );
    std::fs::write(&config_path, &config_text).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_work"))
        .args(["status", "--run", &id.to_string()])
        .env_clear()
        .env("WORK_CONFIG", &config_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["runtime"], "not_inspected");
    assert_eq!(report["record"]["outcome"], serde_json::Value::Null);
    assert_eq!(
        report["record"]["request"],
        serde_json::to_value(&r).unwrap()
    );
    assert_eq!(std::fs::read_to_string(config_path).unwrap(), config_text);
    let reader = work_cli::store::Store::open_existing_registered_readonly(
        config.trusted_registry.as_ref().unwrap(),
        config.store_dir.as_ref().unwrap(),
        &config.roots,
    )
    .unwrap();
    assert_eq!(reader.pending_events(100).unwrap().len(), n);
}

#[test]
fn historical_proofs_are_revision_bound_and_expire_before_closure() {
    for stale in [false, true] {
        let (_dir, mut store, checkout) = fixture();
        let r = request(checkout);
        store.begin_run(&r).unwrap();
        let b = binding(&r);
        store.record_bound(&r, &b).unwrap();
        let os = ClosureOs::new(&r, &b);
        let snapshot = store.group_snapshot(&r.identity().run).unwrap();
        let proof = snapshot.certify_historical_empty(&os.driver).unwrap();
        if stale {
            std::thread::sleep(std::time::Duration::from_millis(2050));
        } else {
            store.record_recovery_hold(&r).unwrap();
        }
        assert!(store.close_supervised_group(&snapshot, &proof).is_err());
        assert!(
            !store
                .run_snapshot(&r.identity().run)
                .unwrap()
                .unwrap()
                .closed
        );
        assert!(store.begin_run(&request(checkout)).is_err());
    }
}

#[test]
fn bare_writer_and_missing_runs_have_no_historical_close_authority() {
    let (_dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store
        .acquire_writer(
            checkout,
            uuid::Uuid::parse_str(&r.identity().group.to_string()).unwrap(),
        )
        .unwrap();
    let b = binding(&r);
    let os = ClosureOs::new(&r, &b);
    let n = store.pending_events(100).unwrap().len();
    assert!(recover(&mut store, &r.identity().run, &os.driver).is_err());
    assert!(store.begin_run(&r).is_err());
    assert_eq!(store.pending_events(100).unwrap().len(), n);
}

#[test]
fn unsafe_authority_directory_is_rejected_before_mutable_sqlite_open() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, store, _checkout) = fixture();
    drop(store);
    let registry = dir.path().join(".work-authorities");
    let path = registry.join("authorities.sqlite");
    let reg = rusqlite::Connection::open(&path).unwrap();
    reg.execute_batch("PRAGMA journal_mode=DELETE").unwrap();
    drop(reg);
    let before = std::fs::read(&path).unwrap();
    std::fs::set_permissions(&registry, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(work_cli::store::Store::open_existing_registered_mut(
        &registry,
        &dir.path().join("private"),
        &[dir.path().join("root")]
    )
    .is_err());
    assert!(
        std::fs::read(&path).unwrap() == before,
        "unsafe authority was mutated"
    );
}

#[test]
fn corrupt_or_wrong_authority_and_malformed_history_fail_closed_without_events() {
    use work_cli::{run_recovery::status, store::Store};
    for case in ["marker", "claims", "schema", "history"] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        store.begin_run(&r).unwrap();
        let registry = dir.path().join(".work-authorities");
        let private = dir.path().join("private");
        let roots = [dir.path().join("root")];
        let reg = rusqlite::Connection::open(registry.join("authorities.sqlite")).unwrap();
        reg.query_row("SELECT count(*) FROM authorities", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap();
        let sql = rusqlite::Connection::open(private.join("store.sqlite")).unwrap();
        match case {
            "marker" => std::fs::write(registry.join("initialization.json"), "{}").unwrap(),
            "claims" => {
                reg.execute("DELETE FROM authorities", []).unwrap();
            }
            "schema" => sql.execute_batch("DROP TABLE runs").unwrap(),
            "history" => {
                sql.execute("UPDATE runs SET request='{}'", []).unwrap();
            }
            _ => unreachable!(),
        }
        let n = store.pending_events(100).unwrap().len();
        for writable in [false, true] {
            let opened = if writable {
                Store::open_existing_registered_mut(&registry, &private, &roots)
            } else {
                Store::open_existing_registered_readonly(&registry, &private, &roots)
            };
            match opened {
                Ok(reader) => assert!(status(&reader, &r.identity().run).is_err(), "{case}"),
                Err(_) => assert_ne!(case, "history"),
            }
        }
        assert_eq!(store.pending_events(100).unwrap().len(), n);
        assert_eq!(
            sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}

#[test]
fn existing_reader_sees_committed_wal_without_initialization_migration_or_acknowledgment() {
    use work_cli::{run_recovery::status, store::Store};
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    let b = binding(&r);
    store.record_bound(&r, &b).unwrap();
    let registry = dir.path().join(".work-authorities");
    let private = dir.path().join("private");
    let roots = [dir.path().join("root")];
    // Keep the registry's existing WAL sidecars available, as doctor requires.
    // The reader must refuse rather than create absent WAL bookkeeping files.
    let reg = rusqlite::Connection::open(registry.join("authorities.sqlite")).unwrap();
    reg.query_row("SELECT count(*) FROM authorities", [], |r| {
        r.get::<_, i64>(0)
    })
    .unwrap();
    let sql = rusqlite::Connection::open(private.join("store.sqlite")).unwrap();
    sql.execute_batch("PRAGMA wal_autocheckpoint=0").unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    assert!(private.join("store.sqlite-wal").metadata().unwrap().len() > 0);
    let before = store.pending_events(100).unwrap();
    let mut reader = Store::open_existing_registered_readonly(&registry, &private, &roots).unwrap();
    let report = status(&reader, &r.identity().run).unwrap();
    assert_eq!(
        report.record,
        store.run_snapshot(&r.identity().run).unwrap().unwrap()
    );
    assert_eq!(report.runtime, "not_inspected");
    assert!(report.lease_charged && report.task_open);
    assert!(serde_json::to_string(&report)
        .unwrap()
        .contains("reviewer-not-owner"));
    assert!(reader.acknowledge(before[0].sequence).is_err());
    assert_eq!(store.pending_events(100).unwrap().len(), before.len());
    drop(reader);
    sql.execute_batch("PRAGMA user_version=4").unwrap();
    assert!(Store::open_existing_registered_readonly(&registry, &private, &roots).is_err());
    assert_eq!(
        sql.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        4
    );
    let missing = dir.path().join("absent");
    assert!(Store::open_existing_registered_readonly(&missing, &missing, &roots).is_err());
    assert!(!missing.exists());
    assert!(Store::open_existing_registered_mut(&registry, &private, &roots).is_err());
}
