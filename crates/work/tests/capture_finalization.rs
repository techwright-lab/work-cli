#[path = "support/run_fixture.rs"]
mod fixture_support;

#[path = "support/capture_finalization_fixture.rs"]
mod capture_fixture;
use capture_fixture::Fixture;
use work_cli::{capture_finalization::finalize, run_journal::RootOutcome};

#[test]
fn closed_known_root_freezes_without_rewriting_root_or_writer() {
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    let before = f.store.run_snapshot(&f.root.identity().run).unwrap();
    let result = finalize(&f.config, &f.root.identity().run);
    assert!(result.is_ok(), "closed known capture must finalize");
    assert_eq!(
        f.store.run_snapshot(&f.root.identity().run).unwrap(),
        before
    );
    assert_eq!(
        std::fs::read_to_string(f.dir.path().join("calls")).unwrap(),
        "finish\n"
    );
    let sql = f.sql();
    let confirmed: bool = sql
        .query_row(
            "SELECT confirmation IS NOT NULL FROM capture_finalizations",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(confirmed);
}

use work_cli::capture_bridge::{decode_terminal, CaptureBinding};

#[test]
fn confirmed_is_passive_and_lost_ack_replays_exact_finish() {
    for lost in [false, true] {
        let f = Fixture::new(true, Some(RootOutcome::Failed));
        f.respond("pending", serde_json::json!({}), lost);
        assert_eq!(finalize(&f.config, &f.root.identity().run).is_ok(), !lost);
        let original = std::fs::read(f.dir.path().join("input")).unwrap();
        f.respond("pending", serde_json::json!({}), false);
        assert!(
            finalize(&f.config, &f.root.identity().run).is_ok(),
            "replay refused lost={lost}"
        );
        let calls = std::fs::read_to_string(f.dir.path().join("calls")).unwrap();
        assert_eq!(calls, if lost { "finish\nfinish\n" } else { "finish\n" });
        assert_eq!(
            std::fs::read(f.dir.path().join("input")).unwrap(),
            if lost { original.repeat(2) } else { original }
        );
    }
}

#[test]
fn intent_visible_outside_all_sql_before_process_and_delayed_callback() {
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    let mut called = false;
    let result = work_cli::capture_finalization::finalize_observed(
        &f.config,
        &f.root.identity().run,
        || {
            called = true;
            let sql = f.sql();
            sql.execute_batch("BEGIN IMMEDIATE; UPDATE checkouts SET owner=owner; COMMIT;")
                .unwrap();
            let intent: String = sql
                .query_row("SELECT intent FROM capture_finalizations", [], |r| r.get(0))
                .unwrap();
            let value: serde_json::Value = serde_json::from_str(&intent).unwrap();
            let end: String = sql
                .query_row(
                    "SELECT json_extract(group_end,'$.observed_wall') FROM capture_runs",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(value["ended_at"], end);
            std::thread::sleep(std::time::Duration::from_millis(550));
            assert!(!f.dir.path().join("calls").exists());
        },
    );
    assert!(result.is_ok());
    assert!(called, "boundary callback not executed");
}

#[test]
fn terminal_echo_must_match_intent_and_source() {
    for extra in [
        serde_json::json!({"ended_at":"2001-01-01T00:00:00Z"}),
        serde_json::json!({"source":{"system":"wrong"}}),
        serde_json::json!({"started_at":"2999-01-01T00:00:00Z"}),
    ] {
        let f = Fixture::new(true, Some(RootOutcome::Cancelled));
        f.respond("pending", extra, false);
        assert!(
            finalize(&f.config, &f.root.identity().run).is_err(),
            "contradictory terminal facts confirmed"
        );
        assert!(f
            .sql()
            .query_row(
                "SELECT confirmation IS NULL FROM capture_finalizations",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap());
    }
}

#[test]
fn explicit_retry_delivers_without_refreeze_and_keeps_receipt() {
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    assert!(
        work_cli::capture_finalization::retry_delivery(&f.config, &f.root.identity().run).is_err()
    );
    assert!(!f.dir.path().join("calls").exists());
    assert!(finalize(&f.config, &f.root.identity().run).is_ok());
    let receipt = serde_json::json!({"actor_ref":"actor","run_ref":f.root.identity().run_ref.as_str(),"event_id":"event","session_id":1});
    f.respond("delivered", serde_json::json!({"receipt":receipt}), false);
    assert!(
        work_cli::capture_finalization::retry_delivery(&f.config, &f.root.identity().run).is_ok(),
        "confirmed retry refused"
    );
    assert_eq!(
        std::fs::read_to_string(f.dir.path().join("calls")).unwrap(),
        "finish\nretry\n"
    );
}

#[test]
fn delivery_merge_preserves_identity_and_success_but_allows_session_refresh() {
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    let extra = |event: &str, session: u64| serde_json::json!({"receipt":{"actor_ref":"actor","run_ref":f.root.identity().run_ref.as_str(),"event_id":event,"session_id":session}});
    f.respond("delivered", extra("event", 1), false);
    assert!(finalize(&f.config, &f.root.identity().run).is_ok());
    f.respond(
        "pending",
        serde_json::json!({"error_code":"delivery_failed"}),
        false,
    );
    let (_, snapshot) =
        work_cli::capture_finalization::retry_delivery(&f.config, &f.root.identity().run).unwrap();
    let c = snapshot.confirmation.unwrap();
    assert!(
        c.delivered && c.receipt.as_ref().is_some_and(|r| r.event_id() == "event"),
        "delivery downgraded"
    );
    f.respond("delivered", extra("event", 2), false);
    let (_, snapshot) =
        work_cli::capture_finalization::retry_delivery(&f.config, &f.root.identity().run).unwrap();
    assert_eq!(
        snapshot.confirmation.unwrap().receipt.unwrap().session_id(),
        2
    );
    f.respond("delivered", extra("different", 3), false);
    assert!(
        work_cli::capture_finalization::retry_delivery(&f.config, &f.root.identity().run).is_err()
    );
}

#[test]
fn malformed_terminal_history_refuses_target_reader() {
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    assert!(finalize(&f.config, &f.root.identity().run).is_ok());
    f.sql()
        .execute("UPDATE capture_finalizations SET intent='{}'", [])
        .unwrap();
    assert!(
        f.store.run_snapshot(&f.root.identity().run).is_err(),
        "target ignored malformed finalization"
    );
}

#[test]
fn attempt_time_cannot_precede_whole_group_end() {
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    f.respond(
        "pending",
        serde_json::json!({"last_attempt_at":"2000-01-01T00:00:00Z"}),
        false,
    );
    assert!(
        finalize(&f.config, &f.root.identity().run).is_err(),
        "attempt before group end confirmed"
    );
}

// Supplemental adversarial coverage after the feature RED/GREEN cycles above.
#[test]
fn uncertain_or_open_history_never_invokes_receiver() {
    for (closed, outcome, clock) in [
        (false, Some(RootOutcome::Completed), false),
        (true, None, false),
        (true, Some(RootOutcome::Failed), true),
    ] {
        let f = Fixture::new(closed, outcome);
        if clock {
            f.sql()
                .execute(
                    "UPDATE capture_runs SET group_end=?1",
                    [r#"{"observed_wall":"2000-01-01T00:00:00Z","clock_uncertain":true}"#],
                )
                .unwrap();
        }
        assert!(finalize(&f.config, &f.root.identity().run).is_err());
        assert!(!f.dir.path().join("calls").exists());
        assert_eq!(
            f.sql()
                .query_row("SELECT count(*) FROM capture_finalizations", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}

#[test]
fn sql_faults_rollback_intent_or_confirmation_and_replay_finish() {
    for point in ["intent", "intent_event", "confirmation", "frozen_event"] {
        let f = Fixture::new(true, Some(RootOutcome::Completed));
        let trigger=match point {
            "intent"=>"CREATE TRIGGER fault BEFORE INSERT ON capture_finalizations BEGIN SELECT RAISE(ABORT,'fixture'); END",
            "intent_event"=>"CREATE TRIGGER fault BEFORE INSERT ON outbox WHEN json_extract(NEW.payload,'$.change')='intent' BEGIN SELECT RAISE(ABORT,'fixture'); END",
            "confirmation"=>"CREATE TRIGGER fault BEFORE UPDATE ON capture_finalizations BEGIN SELECT RAISE(ABORT,'fixture'); END",
            _=>"CREATE TRIGGER fault BEFORE INSERT ON outbox WHEN json_extract(NEW.payload,'$.change')='frozen' BEGIN SELECT RAISE(ABORT,'fixture'); END",
        };
        let sql = f.sql();
        sql.execute_batch(trigger).unwrap();
        let before = f.store.pending_events(100).unwrap();
        assert!(finalize(&f.config, &f.root.identity().run).is_err());
        let called = f.dir.path().join("calls").exists();
        assert_eq!(called, !point.starts_with("intent"));
        assert_eq!(
            sql.query_row(
                "SELECT count(*) FROM capture_finalizations WHERE confirmation IS NOT NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        if !called {
            assert_eq!(f.store.pending_events(100).unwrap(), before);
        }
        sql.execute_batch("DROP TRIGGER fault").unwrap();
        assert!(finalize(&f.config, &f.root.identity().run).is_ok());
        assert_eq!(
            std::fs::read_to_string(f.dir.path().join("calls")).unwrap(),
            if called {
                "finish\nfinish\n"
            } else {
                "finish\n"
            }
        );
    }
}

#[test]
fn echo_precision_is_explicit_and_original_nanoseconds_remain_unchanged() {
    for delta in [0, 1] {
        let f = Fixture::new(true, Some(RootOutcome::Completed));
        let sql = f.sql();
        let end: String = sql
            .query_row(
                "SELECT json_extract(group_end,'$.observed_wall') FROM capture_runs",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let time = chrono::DateTime::parse_from_rfc3339(&end).unwrap();
        let truncated = time.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        let echo = chrono::DateTime::parse_from_rfc3339(&truncated).unwrap()
            + chrono::Duration::microseconds(delta);
        f.respond("pending",serde_json::json!({"ended_at":echo.to_rfc3339_opts(chrono::SecondsFormat::Micros,true),"source":{}}),false);
        assert_eq!(
            finalize(&f.config, &f.root.identity().run).is_ok(),
            delta == 0
        );
        let intent: String = sql
            .query_row("SELECT intent FROM capture_finalizations", [], |r| r.get(0))
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&intent).unwrap();
        assert_eq!(value["ended_at"], end);
        if delta == 0 {
            let snapshot = f
                .store
                .capture_finalization_snapshot(&f.root.identity().run)
                .unwrap()
                .unwrap();
            assert!(snapshot.confirmation.unwrap().end_precision.is_some());
        }
    }
}

#[test]
fn concurrent_same_claim_confirms_once_and_never_downgrades() {
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    let (_, result) = work_cli::capture_finalization::finalize_observed(
        &f.config,
        &f.root.identity().run,
        || {
            f.respond("delivered",serde_json::json!({"receipt":{"actor_ref":"actor","run_ref":f.root.identity().run_ref.as_str(),"event_id":"event","session_id":1}}),false);
            assert!(finalize(&f.config, &f.root.identity().run).is_ok());
            f.respond("pending",serde_json::json!({}),false);
        },
    )
    .unwrap();
    assert!(matches!(
        result,
        work_cli::capture_finalization::FinalizeResult::Confirmed { .. }
    ));
    assert_eq!(f.sql().query_row("SELECT count(*) FROM outbox WHERE json_extract(payload,'$.type')='capture_finalization_changed' AND json_extract(payload,'$.change')='frozen'",[],|r|r.get::<_,i64>(0)).unwrap(),1);
    let snapshot = f
        .store
        .capture_finalization_snapshot(&f.root.identity().run)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.revision, 2);
    assert!(snapshot.confirmation.unwrap().delivered);
}

#[test]
fn schema_twelve_migration_preserves_old_bytes_and_requires_explicit_upgrade() {
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    let sql = f.sql();
    let before: (String, String, String) = sql
        .query_row(
            "SELECT spec,prepared,group_end FROM capture_runs",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let events = f.store.pending_events(100).unwrap();
    sql.execute_batch("DROP TABLE capture_finalizations; PRAGMA user_version=11")
        .unwrap();
    assert!(matches!(
        finalize(&f.config, &f.root.identity().run),
        Err(work_cli::store::StoreError::UpgradeRequired)
    ));
    assert!(!f.dir.path().join("calls").exists());
    let store = fixture_support::reopen(&f.dir).unwrap();
    assert_eq!(store.pending_events(100).unwrap(), events);
    let after = sql
        .query_row(
            "SELECT spec,prepared,group_end FROM capture_runs",
            [],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(before, after);
    assert!(store
        .capture_finalization_snapshot(&f.root.identity().run)
        .unwrap()
        .is_none());
    sql.execute_batch(
        "DROP TABLE capture_finalizations; CREATE VIEW capture_finalizations AS SELECT 1 AS run",
    )
    .unwrap();
    assert!(fixture_support::reopen(&f.dir).is_err());
}

#[test]
fn finalization_preserves_original_empty_receipt_accounting_and_legacy_writer_fence() {
    let mut f = Fixture::new(false, Some(RootOutcome::Completed));
    let binding = fixture_support::binding(&f.root);
    let os = fixture_support::ClosureOs::new(&f.root, &binding);
    let snapshot = f.store.group_snapshot(&f.root.identity().run).unwrap();
    let proof = snapshot.certify_empty(&os.driver, &binding).unwrap();
    f.store.close_supervised_group(&snapshot, &proof).unwrap();
    let sql = f.sql();
    let accounting = || {
        sql.query_row("SELECT state,ready,owner,(SELECT count(*) FROM writers),(SELECT count(*) FROM task_finishes) FROM checkouts",[],|r| Ok((r.get::<_,String>(0)?,r.get::<_,bool>(1)?,r.get::<_,String>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?))).unwrap()
    };
    let before = accounting();
    let charged = f.store.charged(&f.dir.path().join("root"), None).unwrap();
    assert!(finalize(&f.config, &f.root.identity().run).is_ok());
    f.store.close_supervised_group(&snapshot, &proof).unwrap();
    assert_eq!(accounting(), before);
    assert_eq!(
        f.store.charged(&f.dir.path().join("root"), None).unwrap(),
        charged
    );
    // This is a v10-style library allocation without a permanent requirement.
    sql.execute("UPDATE checkouts SET state='active',ready=1", [])
        .unwrap();
    assert!(f
        .store
        .acquire_writer(
            uuid::Uuid::parse_str(&f.root.identity().checkout.to_string()).unwrap(),
            uuid::Uuid::now_v7()
        )
        .is_err());
}

#[test]
fn unrelated_no_sink_root_ignores_bad_terminal_json() {
    let mut f = Fixture::new(true, Some(RootOutcome::Completed));
    let id = f
        .store
        .reserve(
            &work_cli::admission::Reservation {
                operation: uuid::Uuid::now_v7(),
                repository: f.dir.path().join("root"),
                actor: "allocator".into(),
                owner: "owner".into(),
                task: "other".into(),
            },
            work_cli::admission::Limits {
                repository: 10,
                owner: 10,
                available_bytes: Some(100),
                floor_bytes: 0,
                warn_bytes: 0,
            },
        )
        .unwrap();
    f.sql()
        .execute(
            "UPDATE checkouts SET state='active',ready=1 WHERE id=?1",
            [id.to_string()],
        )
        .unwrap();
    let root = fixture_support::request(id);
    f.store.begin_run(&root).unwrap();
    assert!(finalize(&f.config, &f.root.identity().run).is_ok());
    f.sql()
        .execute("UPDATE capture_finalizations SET intent='broken'", [])
        .unwrap();
    assert!(f
        .store
        .run_snapshot(&root.identity().run)
        .unwrap()
        .is_some());
    assert!(fixture_support::reopen(&f.dir).is_ok());
}

#[test]
fn terminal_producer_worker() {
    let Some(root) = std::env::var_os("WORK_TEST_CAPTURE_PRODUCER_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let sql = rusqlite::Connection::open(root.join("private/store.sqlite")).unwrap();
    // Independent process observes committed intent BEFORE consuming stdin/EOF.
    sql.execute_batch("BEGIN IMMEDIATE; UPDATE checkouts SET owner=owner; COMMIT;")
        .unwrap();
    let body: String=sql.query_row("SELECT json_extract(intent,'$.body') FROM capture_finalizations WHERE confirmation IS NULL",[],|r|r.get(0)).unwrap();
    let mut input = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut input).unwrap();
    assert_eq!(input, body);
    std::fs::write(root.join("producer-verified"), "committed before stdin").unwrap();
}

#[test]
fn actual_producer_observes_exact_intent_before_consuming_stdin() {
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    std::fs::write(f.dir.path().join("producer"),format!("#!/bin/sh\nWORK_TEST_CAPTURE_PRODUCER_ROOT='{}' '{}' --exact terminal_producer_worker >/dev/null || exit 1\nexec /usr/bin/cat '{}'\n",f.dir.path().display(),std::env::current_exe().unwrap().display(),f.dir.path().join("response").display())).unwrap();
    assert!(finalize(&f.config, &f.root.identity().run).is_ok());
    assert!(f.dir.path().join("producer-verified").exists());
}

#[test]
fn actual_retry_rejects_receipt_time_source_and_binding_contradictions() {
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    assert!(finalize(&f.config, &f.root.identity().run).is_ok());
    let original = serde_json::to_string(
        &f.store
            .capture_finalization_snapshot(&f.root.identity().run)
            .unwrap(),
    )
    .unwrap();
    let receipt = serde_json::json!({"actor_ref":"actor","run_ref":f.root.identity().run_ref.as_str(),"event_id":"event","session_id":1});
    let mut cases = vec![
        serde_json::json!({"actor_ref":"other"}),
        serde_json::json!({"run_ref":"other"}),
        serde_json::json!({"source":{"system":"other"}}),
        serde_json::json!({"ended_at":"2000-01-01T00:00:00Z"}),
        serde_json::json!({"error_code":"secret"}),
    ];
    for session in [
        serde_json::json!(0),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!(true),
        serde_json::json!("1"),
    ] {
        let mut r = receipt.clone();
        r["session_id"] = session;
        cases.push(serde_json::json!({"receipt":r}));
    }
    for extra in cases {
        f.respond("pending", extra, false);
        assert!(
            work_cli::capture_finalization::retry_delivery(&f.config, &f.root.identity().run)
                .is_err()
        );
        assert_eq!(
            serde_json::to_string(
                &f.store
                    .capture_finalization_snapshot(&f.root.identity().run)
                    .unwrap()
            )
            .unwrap(),
            original
        );
    }
}

#[test]
fn current_schema_has_separate_terminal_journal() {
    let (dir, _, _) = fixture_support::fixture();
    let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let version: i64 = sql
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 12);
    assert!(sql
        .prepare("SELECT run,intent,confirmation,revision FROM capture_finalizations")
        .is_ok());
}

#[test]
fn terminal_retains_receiver_reported_end() {
    let binding =
        CaptureBinding::new("550e8400-e29b-41d4-a716-446655440000", "actor", "run").unwrap();
    let frozen = decode_terminal(br#"{"capture_id":"550e8400-e29b-41d4-a716-446655440000","actor_ref":"actor","run_ref":"run","state":"pending","ended_at":"2026-10-18T12:00:00.123456Z"}"#, &binding).unwrap();
    assert_eq!(frozen.ended_at(), Some("2026-10-18T12:00:00.123456Z"));
}

#[test]
fn terminal_retains_bounded_optional_facts() {
    let binding =
        CaptureBinding::new("550e8400-e29b-41d4-a716-446655440000", "actor", "run").unwrap();
    let frozen = decode_terminal(br#"{"capture_id":"550e8400-e29b-41d4-a716-446655440000","actor_ref":"actor","run_ref":"run","state":"pending","started_at":"2026-10-18T11:00:00Z","last_attempt_at":"2026-10-18T12:00:00Z","source":{"system":"test"},"error_code":"delivery_failed","receipt":{"actor_ref":"actor","run_ref":"run","event_id":"event","session_id":1}}"#, &binding).unwrap();
    assert!(
        frozen.started_at().is_some()
            && frozen.last_attempt_at().is_some()
            && frozen.source().is_some()
            && frozen.error_code().is_some()
            && frozen.receipt().is_some(),
        "terminal facts discarded"
    );
}
