#[path = "support/run_fixture.rs"]
mod support;
use rusqlite::Connection;
use support::*;
use work_cli::{
    run_journal::{BeginRun, Transition},
    run_participants::{ChildOutcome, ChildRequest, Enrollment, ExpectedHost},
};
use work_contract::{RunId, RunRef};

fn table_rows(sql: &Connection, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
    let mut statement = sql
        .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
        .unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn child(root: &work_cli::run_journal::RootRunRequest) -> ChildRequest {
    let i = root.identity();
    ChildRequest {
        checkout: i.checkout.clone(),
        group: i.group.clone(),
        run: RunId::generate(),
        run_ref: RunRef::parse(&format!("child:{}", uuid::Uuid::now_v7())).unwrap(),
        parent_run: i.run.clone(),
        parent_run_ref: i.run_ref.clone(),
        execution_chain: i.execution_chain.clone(),
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

#[test]
fn registration_precedes_inspection_invalidates_proof_and_retries_without_events() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    let b = binding(&r);
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let snapshot = store.group_snapshot(&r.identity().run).unwrap();
    let os = ClosureOs::new(&r, &b);
    let proof = snapshot.certify_empty(&os.driver, &b).unwrap();
    let c = child(&r);
    assert_eq!(store.register_child(&r, &c).unwrap(), BeginRun::Created);
    let events = store.pending_events(100).unwrap();
    assert_eq!(store.register_child(&r, &c).unwrap(), BeginRun::Existing);
    assert_eq!(store.pending_events(100).unwrap(), events);
    assert!(store.close_supervised_group(&snapshot, &proof).is_err());
    let fresh = store.group_snapshot(&r.identity().run).unwrap();
    assert!(fresh.certify_empty(&os.driver, &b).is_err());
    assert!(fresh.certify_historical_empty(&os.driver).is_err());
    let record = store.run_snapshot(&r.identity().run).unwrap().unwrap();
    assert_eq!(record.children[0].request, c);
    assert_eq!(record.children[0].enrollment, Enrollment::Pending);
    assert_eq!(record.revision, 4);
    assert_eq!(
        store
            .charged(&dir.path().join("root"), Some("owner"))
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .record_child_outcome(&r, &c, ChildOutcome::Completed)
            .unwrap(),
        Transition::Changed
    );
    assert_eq!(
        store
            .record_child_outcome(&r, &c, ChildOutcome::Completed)
            .unwrap(),
        Transition::Existing
    );
    assert!(store
        .record_child_outcome(&r, &c, ChildOutcome::Failed)
        .is_err());
    assert_eq!(
        store.record_child_hold(&r, &c).unwrap(),
        Transition::Changed
    );
    assert_eq!(
        store.record_child_hold(&r, &c).unwrap(),
        Transition::Existing
    );
    let fresh = store.group_snapshot(&r.identity().run).unwrap();
    assert!(fresh.certify_empty(&os.driver, &b).is_err());
    assert!(matches!(
        work_cli::run_recovery::recover(&mut store, &r.identity().run, &os.driver).unwrap(),
        work_cli::run_recovery::RecoveryState::Held {
            reason: "unverified child execution host; charges retained",
            ..
        }
    ));
}

#[test]
fn child_namespaces_are_reserved_against_new_supervised_and_adopted_roots() {
    use work_cli::{adopted::AdoptedRequest, store::StoreError};
    let (_dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let c = child(&r);
    store.register_child(&r, &c).unwrap();
    for field in ["run", "group", "run_ref", "operation"] {
        let mut root = serde_json::to_value(request(checkout)).unwrap();
        if field != "operation" {
            root["identity"][field] = serde_json::json!(if field == "run_ref" {
                c.run_ref.to_string()
            } else {
                c.run.to_string()
            });
            let collision = serde_json::from_value(root.clone()).unwrap();
            assert!(
                matches!(store.begin_run(&collision), Err(StoreError::Conflict)),
                "supervised {field}"
            );
        }
        let operation = if field == "operation" {
            c.run.to_string()
        } else {
            uuid::Uuid::now_v7().to_string()
        };
        let adopted: AdoptedRequest = serde_json::from_value(serde_json::json!({
            "operation": operation, "identity": root["identity"], "source":"sdk", "session":"session", "agent":null
        })).unwrap();
        assert!(
            matches!(store.begin_adopted(&adopted), Err(StoreError::Conflict)),
            "adopted {field}"
        );
    }
}

#[test]
fn child_admission_requires_permitted_open_exact_context_and_known_parent() {
    for case in [
        "intent",
        "bound",
        "checkout",
        "group",
        "parent",
        "parent_ref",
        "self",
        "closed",
    ] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let b = binding(&r);
        store.begin_run(&r).unwrap();
        if case != "intent" {
            store.record_bound(&r, &b).unwrap();
        }
        if !["intent", "bound"].contains(&case) {
            store.record_permit_attempt(&r, &b).unwrap();
        }
        let mut c = child(&r);
        match case {
            "checkout" => c.checkout = work_contract::CheckoutId::generate(),
            "group" => c.group = work_contract::GroupId::generate(),
            "parent" => c.parent_run = RunId::generate(),
            "parent_ref" => c.parent_run_ref = RunRef::parse("wrong-parent").unwrap(),
            "self" => {
                c.parent_run = c.run.clone();
                c.parent_run_ref = c.run_ref.clone();
            }
            "closed" => {
                let os = ClosureOs::new(&r, &b);
                let snap = store.group_snapshot(&r.identity().run).unwrap();
                let proof = snap.certify_empty(&os.driver, &b).unwrap();
                store.close_supervised_group(&snap, &proof).unwrap();
            }
            _ => (),
        }
        let before = store.pending_events(100).unwrap();
        assert!(store.register_child(&r, &c).is_err(), "{case}");
        assert!(store
            .run_snapshot(&r.identity().run)
            .unwrap()
            .unwrap()
            .children
            .is_empty());
        assert_eq!(store.pending_events(100).unwrap(), before, "{case}");
        assert_eq!(store.charged(&dir.path().join("root"), None).unwrap(), 1);
    }
}

#[test]
fn late_metadata_after_logical_completion_or_hold_still_adds_a_barrier() {
    use work_cli::run_journal::RootOutcome;
    let mut failures = Vec::new();
    for case in ["root_completed", "root_held", "parent_completed"] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let b = binding(&r);
        store.begin_run(&r).unwrap();
        store.record_bound(&r, &b).unwrap();
        store.record_permit_attempt(&r, &b).unwrap();
        let mut c = child(&r);
        c.expected_host = None;
        match case {
            "root_completed" => {
                store
                    .record_root_outcome(&r, RootOutcome::Completed)
                    .unwrap();
            }
            "root_held" => {
                store.record_recovery_hold(&r).unwrap();
            }
            "parent_completed" => {
                let parent = child(&r);
                store.register_child(&r, &parent).unwrap();
                store
                    .record_child_outcome(&r, &parent, ChildOutcome::Completed)
                    .unwrap();
                c.parent_run = parent.run;
                c.parent_run_ref = parent.run_ref;
            }
            _ => unreachable!(),
        }
        let before = store.run_snapshot(&r.identity().run).unwrap().unwrap();
        let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        let checkouts = table_rows(&sql, "checkouts");
        let writers = table_rows(&sql, "writers");
        let events = store.pending_events(100).unwrap();
        let os = ClosureOs::new(&r, &b);
        // Capture AFTER terminal/hold, not a proof already stale from that change.
        let snap = store.group_snapshot(&r.identity().run).unwrap();
        let proof = if case == "parent_completed" {
            None // The existing unverified parent already blocks certification.
        } else {
            Some(snap.certify_empty(&os.driver, &b).unwrap())
        };
        let result = store.register_child(&r, &c);
        if !matches!(result, Ok(BeginRun::Created)) {
            failures.push(format!("{case}: {result:?}"));
            continue;
        }
        if let Some(proof) = proof {
            assert!(
                store.close_supervised_group(&snap, &proof).is_err(),
                "{case}"
            );
        }
        let after = store.run_snapshot(&r.identity().run).unwrap().unwrap();
        let mut expected = before.clone();
        expected.revision += 1;
        expected
            .children
            .push(after.children.last().unwrap().clone());
        assert_eq!(after, expected, "only revision and children change: {case}");
        assert_eq!(after.children.last().unwrap().request, c);
        assert_eq!(
            after.children.last().unwrap().enrollment,
            Enrollment::Unverified
        );
        assert_eq!(store.pending_events(100).unwrap().len(), events.len() + 1);
        assert_eq!(store.register_child(&r, &c).unwrap(), BeginRun::Existing);
        let fresh = store.group_snapshot(&r.identity().run).unwrap();
        assert!(fresh.certify_empty(&os.driver, &b).is_err(), "{case}");
        assert!(
            fresh.certify_historical_empty(&os.driver).is_err(),
            "{case}"
        );
        assert_eq!(
            store
                .charged(&dir.path().join("root"), Some("owner"))
                .unwrap(),
            1
        );
        assert_eq!(table_rows(&sql, "checkouts"), checkouts, "{case}");
        assert_eq!(table_rows(&sql, "writers"), writers, "{case}");
        assert_eq!(
            sql.query_row("SELECT child_count FROM run_groups", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            after.children.len() as i64
        );
        assert_eq!(
            sql.query_row("SELECT count(*) FROM writers", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    assert!(failures.is_empty(), "{failures:?}");
}

#[test]
fn registered_child_run_ids_cannot_become_legacy_writers_or_reservation_operations() {
    use work_cli::{
        admission::{Limits, Reservation},
        store::StoreError,
    };
    let mut failures = Vec::new();
    for path in ["writer", "reservation"] {
        for corrupt_existing in [false, true] {
            let (dir, mut store, checkout) = fixture();
            let limits = Limits {
                repository: 10,
                owner: 10,
                available_bytes: Some(100),
                floor_bytes: 0,
                warn_bytes: 0,
            };
            let mut reservation = Reservation {
                operation: uuid::Uuid::now_v7(),
                repository: dir.path().join("root"),
                actor: "allocator".into(),
                owner: "owner".into(),
                task: "other".into(),
            };
            let other = store.reserve(&reservation, limits).unwrap();
            let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
            sql.execute(
                "UPDATE checkouts SET state='active',ready=1 WHERE id=?1",
                [other.to_string()],
            )
            .unwrap();
            let r = request(checkout);
            store.begin_run(&r).unwrap();
            store.record_bound(&r, &binding(&r)).unwrap();
            store.record_permit_attempt(&r, &binding(&r)).unwrap();
            let c = child(&r);
            store.register_child(&r, &c).unwrap();
            let before = store.run_snapshot(&r.identity().run).unwrap().unwrap();
            let recovery = store.recovery_runs().unwrap();
            let group = uuid::Uuid::parse_str(&c.run.to_string()).unwrap();
            reservation.operation = group;
            if corrupt_existing {
                if path == "writer" {
                    sql.execute(
                        "INSERT INTO writers VALUES(?1,?2)",
                        (other.to_string(), group.to_string()),
                    )
                    .unwrap();
                } else {
                    // Preserve the original digest so this would be an exact retry.
                    sql.execute(
                        "UPDATE checkouts SET operation=?1 WHERE id=?2",
                        (group.to_string(), other.to_string()),
                    )
                    .unwrap();
                }
            }
            let tables = [
                "checkouts",
                "writers",
                "runs",
                "run_groups",
                "run_participants",
                "outbox",
                "repository_aliases",
            ];
            let durable_before: Vec<_> =
                tables.iter().map(|table| table_rows(&sql, table)).collect();
            let events = store.pending_events(100).unwrap();
            let charged = store.charged(&dir.path().join("root"), None).unwrap();
            let writers = sql
                .query_row("SELECT count(*) FROM writers", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap();
            let result = if path == "writer" {
                store.acquire_writer(other, group)
            } else {
                store.reserve(&reservation, limits).map(|_| ())
            };
            if !matches!(result, Err(StoreError::Conflict)) {
                failures.push(format!(
                    "{path}, corrupt_existing={corrupt_existing}: {result:?}"
                ));
                continue;
            }
            let durable_after: Vec<_> =
                tables.iter().map(|table| table_rows(&sql, table)).collect();
            assert_eq!(
                durable_after, durable_before,
                "{path}, corrupt_existing={corrupt_existing}"
            );
            assert_eq!(store.pending_events(100).unwrap(), events);
            assert_eq!(
                store.charged(&dir.path().join("root"), None).unwrap(),
                charged
            );
            assert_eq!(
                sql.query_row("SELECT count(*) FROM writers", [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                writers
            );
            if corrupt_existing {
                // The guard rejects, but must not repair/reclassify existing corruption.
                if path == "writer" {
                    sql.execute("DELETE FROM writers WHERE checkout=?1", [other.to_string()])
                        .unwrap();
                } else {
                    sql.execute(
                        "UPDATE checkouts SET operation=?1 WHERE id=?2",
                        (uuid::Uuid::now_v7().to_string(), other.to_string()),
                    )
                    .unwrap();
                }
            }
            assert_eq!(
                store.run_snapshot(&r.identity().run).unwrap().unwrap(),
                before
            );
            assert_eq!(store.recovery_runs().unwrap(), recovery);
            assert_eq!(store.register_child(&r, &c).unwrap(), BeginRun::Existing);
            assert_eq!(store.pending_events(100).unwrap(), events);
        }
    }
    assert!(failures.is_empty(), "{failures:?}");
}

#[test]
fn unknown_host_and_declared_end_remain_unverified_without_fabricated_attribution() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let mut c = child(&r);
    c.expected_host = None;
    store.register_child(&r, &c).unwrap();
    let revision = store
        .run_snapshot(&r.identity().run)
        .unwrap()
        .unwrap()
        .revision;
    store
        .record_child_outcome(&r, &c, ChildOutcome::Cancelled)
        .unwrap();
    let record = work_cli::run_recovery::status(&store, &r.identity().run).unwrap();
    assert_eq!(record.record.revision, revision + 1);
    assert_eq!(record.runtime, "not_inspected");
    assert_eq!(record.record.children[0].enrollment, Enrollment::Unverified);
    assert!(record.record.children[0].request.actor.is_none());
    assert!(record.record.children[0].request.session.is_none());
    assert!(serde_json::from_str::<ChildOutcome>("\"interrupted\"").is_err());
    let config = work_cli::config::Config {
        trusted_registry: Some(dir.path().join(".work-authorities")),
        store_dir: Some(dir.path().join("private")),
        roots: vec![dir.path().join("root")],
        ..Default::default()
    };
    assert!(matches!(
        work_cli::run_recovery::command_recover(
            &config,
            uuid::Uuid::parse_str(&r.identity().run.to_string()).unwrap()
        )
        .unwrap(),
        work_cli::run_recovery::RecoveryState::Held {
            reason: "unverified child execution host; charges retained",
            ..
        }
    ));
    drop(store);
    let store = reopen(&dir).unwrap();
    let snap = store.group_snapshot(&r.identity().run).unwrap();
    let os = ClosureOs::new(&r, &b);
    assert!(snap.certify_historical_empty(&os.driver).is_err());
    assert_eq!(
        store.recovery_runs().unwrap()[0].children,
        record.record.children
    );
}

#[test]
fn exact_retry_preserves_full_request_and_rejects_every_reparenting_or_mutation() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let c = child(&r);
    store.register_child(&r, &c).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let body = serde_json::to_string_pretty(&c).unwrap();
    sql.execute("UPDATE run_participants SET request=?1", [&body])
        .unwrap();
    assert_eq!(store.register_child(&r, &c).unwrap(), BeginRun::Existing);
    for (field, value) in [
        ("source", serde_json::json!("sdk")),
        ("session", serde_json::json!("s")),
        ("agent", serde_json::json!("a")),
        ("actor", serde_json::json!("declared-not-proven")),
        ("parent_run_ref", serde_json::json!("other-parent")),
        (
            "execution_chain",
            serde_json::json!([{"kind":"executor","system":"other"}]),
        ),
        ("expected_host", serde_json::Value::Null),
    ] {
        let mut value_c = serde_json::to_value(&c).unwrap();
        value_c[field] = value;
        let changed: ChildRequest = serde_json::from_value(value_c).unwrap();
        assert!(store.register_child(&r, &changed).is_err(), "{field}");
        assert!(store.record_child_hold(&r, &changed).is_err(), "{field}");
    }
    assert_eq!(
        sql.query_row("SELECT request FROM run_participants", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        body
    );
    let events = store.pending_events(100).unwrap();
    sql.execute(
        "UPDATE run_participants SET parent_run=?1",
        [RunId::generate().to_string()],
    )
    .unwrap();
    assert!(store.register_child(&r, &c).is_err());
    assert_eq!(store.pending_events(100).unwrap(), events);
}

#[test]
fn entire_tree_is_bounded_and_missing_or_orphaned_members_fail_closed() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let mut parent = child(&r);
    for depth in 1..=16 {
        store.register_child(&r, &parent).unwrap();
        let records = store
            .run_snapshot(&r.identity().run)
            .unwrap()
            .unwrap()
            .children;
        assert_eq!(records.last().unwrap().depth, depth);
        let mut next = child(&r);
        next.parent_run = parent.run;
        next.parent_run_ref = parent.run_ref;
        parent = next;
    }
    assert!(
        store.register_child(&r, &parent).is_err(),
        "depth seventeen"
    );
    for _ in 16..256 {
        store.register_child(&r, &child(&r)).unwrap();
    }
    assert!(store.register_child(&r, &child(&r)).is_err(), "child 257");
    let events = store.pending_events(1000).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute(
        "DELETE FROM run_participants WHERE rowid=(SELECT max(rowid) FROM run_participants)",
        [],
    )
    .unwrap();
    assert!(
        store.run_snapshot(&r.identity().run).is_err(),
        "missing member cannot silently disappear"
    );
    sql.execute_batch(
        "PRAGMA foreign_keys=OFF; UPDATE run_participants SET group_id='orphan' WHERE rowid=1;",
    )
    .unwrap();
    assert!(store.recovery_runs().is_err());
    assert!(reopen(&dir).is_err(), "orphan must fail schema preflight");
    assert_eq!(store.pending_events(1000).unwrap(), events);
}

#[test]
fn invalid_expected_birth_identities_cannot_be_registered_as_candidates() {
    let (_dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    for host in [
        ExpectedHost {
            boot: BOOT.into(),
            pid: u32::MAX,
            start_ticks: 10,
        },
        ExpectedHost {
            boot: BOOT.into(),
            pid: 0,
            start_ticks: 10,
        },
        ExpectedHost {
            boot: BOOT.into(),
            pid: 42,
            start_ticks: 0,
        },
        ExpectedHost {
            boot: "unknown".into(),
            pid: 42,
            start_ticks: 10,
        },
    ] {
        let mut c = child(&r);
        c.expected_host = Some(host);
        assert!(
            store.register_child(&r, &c).is_err(),
            "{:?}",
            c.expected_host
        );
    }
    assert!(store
        .run_snapshot(&r.identity().run)
        .unwrap()
        .unwrap()
        .children
        .is_empty());
}

#[test]
fn failed_outbox_insert_rolls_back_registration_count_and_revision() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let before = store.run_snapshot(&r.identity().run).unwrap().unwrap();
    let events = store.pending_events(100).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch("CREATE TRIGGER fail_child_event BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    let c = child(&r);
    assert!(store.register_child(&r, &c).is_err());
    assert_eq!(
        store.run_snapshot(&r.identity().run).unwrap().unwrap(),
        before
    );
    assert_eq!(store.pending_events(100).unwrap(), events);
    sql.execute_batch("DROP TRIGGER fail_child_event").unwrap();
    assert_eq!(store.register_child(&r, &c).unwrap(), BeginRun::Created);
}

#[test]
fn concurrent_registration_and_closure_never_release_a_registered_member() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let snapshot = store.group_snapshot(&r.identity().run).unwrap();
    let os = ClosureOs::new(&r, &b);
    let proof = snapshot.certify_empty(&os.driver, &b).unwrap();
    let mut registrar = reopen(&dir).unwrap();
    let registration_root = r.clone();
    let c = child(&r);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let gate = barrier.clone();
    let thread = std::thread::spawn(move || {
        gate.wait();
        registrar.register_child(&registration_root, &c)
    });
    barrier.wait();
    let closed = store.close_supervised_group(&snapshot, &proof);
    let registered = thread.join().unwrap();
    let record = store.run_snapshot(&r.identity().run).unwrap().unwrap();
    if registered.is_ok() {
        assert!(closed.is_err());
        assert!(!record.closed);
        assert_eq!(record.children.len(), 1);
    } else {
        assert_eq!(closed.unwrap(), Transition::Changed);
        assert!(record.closed);
        assert!(record.children.is_empty());
    }
}

#[test]
fn malformed_child_metadata_is_never_hidden_by_root_reads_or_retries() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &binding(&r)).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute(
        "INSERT INTO run_participants VALUES(?1,?2,'child',?3,'{}','pending',NULL,1)",
        (
            uuid::Uuid::now_v7().to_string(),
            r.identity().group.to_string(),
            r.identity().run.to_string(),
        ),
    )
    .unwrap();
    let before = store.pending_events(100).unwrap();
    assert!(store.run_snapshot(&r.identity().run).is_err());
    assert!(store.begin_run(&r).is_err());
    assert!(store.group_snapshot(&r.identity().run).is_err());
    assert!(store.recovery_runs().is_err());
    assert!(work_cli::run_recovery::status(&store, &r.identity().run).is_err());
    assert_eq!(store.pending_events(100).unwrap(), before);
}

#[test]
fn v6_migration_preserves_closed_and_active_roots_adopted_legacy_aliases_and_outbox() {
    use work_cli::{
        admission::{Limits, Reservation},
        adopted::AdoptedRequest,
    };
    let (dir, mut store, checkout) = fixture();
    let closed = request(checkout);
    let binding = binding(&closed);
    store.begin_run(&closed).unwrap();
    store.record_bound(&closed, &binding).unwrap();
    let os = ClosureOs::new(&closed, &binding);
    let snap = store.group_snapshot(&closed.identity().run).unwrap();
    store
        .close_supervised_group(&snap, &snap.certify_empty(&os.driver, &binding).unwrap())
        .unwrap();
    let active = request(checkout);
    store.begin_run(&active).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let mut extra = Vec::new();
    for task in ["adopted", "legacy"] {
        let id = store
            .reserve(
                &Reservation {
                    operation: uuid::Uuid::now_v7(),
                    repository: dir.path().join("root"),
                    actor: "allocator".into(),
                    owner: "owner".into(),
                    task: task.into(),
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
        sql.execute(
            "UPDATE checkouts SET state='active',ready=1 WHERE id=?1",
            [id.to_string()],
        )
        .unwrap();
        extra.push(id);
    }
    let adopted: AdoptedRequest = serde_json::from_value(serde_json::json!({
        "operation":uuid::Uuid::now_v7(), "identity":request(extra[0]).identity(),
        "source":"sdk", "session":"actual-session", "agent":null
    }))
    .unwrap();
    store.begin_adopted(&adopted).unwrap();
    store
        .acquire_writer(extra[1], uuid::Uuid::now_v7())
        .unwrap();
    sql.execute(
        "INSERT INTO repository_aliases VALUES('fixture-alias',?1)",
        [dir.path().join("root").to_str().unwrap()],
    )
    .unwrap();
    let events = store.pending_events(100).unwrap();
    let closed_before = store.run_snapshot(&closed.identity().run).unwrap().unwrap();
    let active_before = store.run_snapshot(&active.identity().run).unwrap().unwrap();
    let adopted_before =
        serde_json::to_value(store.adopted_status(&adopted.identity.run).unwrap()).unwrap();
    sql.execute_batch("DROP TABLE run_participants; ALTER TABLE run_groups DROP COLUMN child_count; PRAGMA user_version=6").unwrap();
    drop(store);
    let migrated = reopen(&dir).unwrap();
    assert_eq!(
        migrated
            .run_snapshot(&closed.identity().run)
            .unwrap()
            .unwrap(),
        closed_before
    );
    assert_eq!(
        migrated
            .run_snapshot(&active.identity().run)
            .unwrap()
            .unwrap(),
        active_before
    );
    assert_eq!(
        serde_json::to_value(migrated.adopted_status(&adopted.identity.run).unwrap()).unwrap(),
        adopted_before
    );
    assert_eq!(migrated.pending_events(100).unwrap(), events);
    assert_eq!(
        migrated
            .charged(&dir.path().join("root"), Some("owner"))
            .unwrap(),
        3
    );
    assert_eq!(
        sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        sql.query_row("SELECT count(*) FROM repository_aliases", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn v7_child_ledger_is_additive_and_versioned_tables_fail_closed() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    let events = store.pending_events(100).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    assert_eq!(
        sql.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        7
    );
    sql.execute_batch("DROP TABLE run_participants; ALTER TABLE run_groups DROP COLUMN child_count; PRAGMA user_version=6").unwrap();
    drop(store);
    let store = reopen(&dir).unwrap();
    assert_eq!(store.pending_events(100).unwrap(), events);
    assert_eq!(
        store
            .run_snapshot(&r.identity().run)
            .unwrap()
            .unwrap()
            .request,
        r
    );
    assert_eq!(
        store
            .charged(&dir.path().join("root"), Some("owner"))
            .unwrap(),
        1
    );
    sql.execute_batch("ALTER TABLE run_participants RENAME TO saved_children; CREATE VIEW run_participants AS SELECT * FROM saved_children").unwrap();
    assert!(reopen(&dir).is_err());
    sql.execute_batch("DROP VIEW run_participants").unwrap();
    assert!(reopen(&dir).is_err());
}
