#[path = "support/run_fixture.rs"]
mod run_fixture;
use rusqlite::Connection;
use uuid::Uuid;
use work_cli::{
    admission::{Limits, Reservation},
    store::Store,
};

fn fixture() -> (tempfile::TempDir, Store, Reservation) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let store = Store::open(&dir.path().join("private"), std::slice::from_ref(&root)).unwrap();
    let request = Reservation {
        operation: Uuid::now_v7(),
        repository: root,
        actor: "actor".into(),
        owner: "alice".into(),
        task: "task".into(),
    };
    (dir, store, request)
}
fn limits() -> Limits {
    Limits {
        repository: 2,
        owner: 1,
        available_bytes: Some(300),
        floor_bytes: 200,
        warn_bytes: 250,
    }
}

#[test]
fn reservation_retry_precedes_capacity_checks_but_changed_request_conflicts() {
    let (_dir, mut store, mut request) = fixture();
    let first = store.reserve(&request, limits()).unwrap();
    let mut lowered = limits();
    lowered.repository = 0;
    lowered.available_bytes = None;
    assert_eq!(store.reserve(&request, lowered).unwrap(), first);
    request.task = "changed".into();
    assert!(store.reserve(&request, limits()).is_err());
    assert_eq!(store.charged(&request.repository, None).unwrap(), 1);
    assert_eq!(store.pending_events(100).unwrap().len(), 1);
}

#[test]
fn invalid_request_identities_are_refused() {
    for non_rfc in [false, true] {
        let (_dir, mut store, mut request) = fixture();
        if non_rfc {
            request.operation = Uuid::parse_str("00000000-0000-7000-0000-000000000000").unwrap();
        } else {
            request.owner = " alice ".into();
        }
        assert!(
            store.reserve(&request, limits()).is_err(),
            "non_rfc={non_rfc}"
        );
    }
}

#[test]
fn invalid_writer_identity_cannot_hold_a_checkout() {
    let (_dir, mut store, request) = fixture();
    let checkout = store.reserve(&request, limits()).unwrap();
    assert!(store.acquire_writer(checkout, Uuid::nil()).is_err());
}

#[test]
fn disk_and_owner_limits_fail_closed_without_new_charges() {
    let (_dir, mut store, mut request) = fixture();
    for available in [None, Some(199)] {
        let mut l = limits();
        l.available_bytes = available;
        assert!(store.reserve(&request, l).is_err());
    }
    store.reserve(&request, limits()).unwrap();
    request.operation = Uuid::now_v7();
    assert!(store.reserve(&request, limits()).is_err());
    request.owner = "bob".into();
    store.reserve(&request, limits()).unwrap();
    request.operation = Uuid::now_v7();
    request.owner = "carol".into();
    assert!(store.reserve(&request, limits()).is_err());
    assert_eq!(store.charged(&request.repository, None).unwrap(), 2);
}

#[test]
fn independent_connections_serialize_last_slot() {
    let (dir, mut first, request) = fixture();
    let mut second = Store::open(
        &dir.path().join("private"),
        std::slice::from_ref(&request.repository),
    )
    .unwrap();
    let mut other = request.clone();
    other.operation = Uuid::now_v7();
    let a = std::thread::spawn(move || first.reserve(&request, limits()));
    let b = std::thread::spawn(move || second.reserve(&other, limits()));
    assert_eq!(
        usize::from(a.join().unwrap().is_ok()) + usize::from(b.join().unwrap().is_ok()),
        1
    );
}

// Full durable rows, including immutable digests and charge ownership, must not
// change even when a pre-existing invalid alias would otherwise acknowledge.
fn durable_rows(sql: &Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    [
        "checkouts",
        "writers",
        "runs",
        "run_groups",
        "run_participants",
        "adopted_groups",
        "adopted_sessions",
        "adopted_segments",
        "outbox",
    ]
    .into_iter()
    .map(|table| {
        let mut statement = sql
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let columns = statement.column_count();
        statement
            .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    })
    .collect()
}

#[test]
fn journal_identities_exclude_reverse_admission_even_before_existing_acknowledgement() {
    use work_cli::{
        adopted::AdoptedRequest,
        participants::Ref,
        run_journal::{BeginRun, RootOutcome},
        store::StoreError,
    };
    let mut failures = Vec::new();
    for mode in ["root", "terminal", "closed", "adopted"] {
        let fields: &[&str] = if mode == "adopted" {
            &["run", "group", "operation"]
        } else {
            &["run", "group"]
        };
        for field in fields {
            for path in ["reservation", "writer", "managed_writer"] {
                for corrupt_existing in [false, true] {
                    if path == "managed_writer" && corrupt_existing {
                        continue;
                    }
                    // UNIQUE writers.group_id prevents a duplicate group on the
                    // other checkout; managed_writer covers its exact-ack path.
                    if path == "writer" && corrupt_existing && *field == "group" && mode != "closed"
                    {
                        continue;
                    }
                    let (dir, mut store, checkout) = run_fixture::fixture();
                    let root = run_fixture::request(checkout);
                    let adopted = AdoptedRequest {
                        operation: Uuid::now_v7(),
                        identity: root.identity().clone(),
                        source: Ref::new("sdk".into()).unwrap(),
                        session: Ref::new("session".into()).unwrap(),
                        agent: None,
                    };
                    if mode == "adopted" {
                        assert_eq!(store.begin_adopted(&adopted).unwrap(), BeginRun::Created);
                        assert_eq!(store.begin_adopted(&adopted).unwrap(), BeginRun::Existing);
                        assert!(store.begin_run(&root).is_err());
                    } else {
                        assert_eq!(store.begin_run(&root).unwrap(), BeginRun::Created);
                        assert_eq!(store.begin_run(&root).unwrap(), BeginRun::Existing);
                        assert!(store.begin_adopted(&adopted).is_err());
                        if mode != "root" {
                            let b = run_fixture::binding(&root);
                            store.record_bound(&root, &b).unwrap();
                            store.record_permit_attempt(&root, &b).unwrap();
                            store
                                .record_root_outcome(&root, RootOutcome::Completed)
                                .unwrap();
                        }
                    }
                    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
                    if mode == "closed" {
                        // Synthetic historical closure fixture, not runtime proof or
                        // production closure: retain valid bound terminal history.
                        sql.execute("UPDATE run_groups SET closed=1", []).unwrap();
                        sql.execute("DELETE FROM writers", []).unwrap();
                    }
                    let high = Limits {
                        repository: 100,
                        owner: 100,
                        ..limits()
                    };
                    let mut reservation = Reservation {
                        operation: Uuid::now_v7(),
                        repository: dir.path().join("root"),
                        actor: "allocator".into(),
                        owner: "owner".into(),
                        task: "other".into(),
                    };
                    let other = store.reserve(&reservation, high).unwrap();
                    // Synthetic READY allocation, no launching or backend calls.
                    sql.execute(
                        "UPDATE checkouts SET state='active',ready=1 WHERE id=?1",
                        [other.to_string()],
                    )
                    .unwrap();
                    let id = match *field {
                        "run" => Uuid::parse_str(&root.identity().run.to_string()).unwrap(),
                        "group" => Uuid::parse_str(&root.identity().group.to_string()).unwrap(),
                        _ => adopted.operation,
                    };
                    reservation.operation = id;
                    if corrupt_existing {
                        if path == "writer" {
                            sql.execute(
                                "INSERT INTO writers VALUES(?1,?2)",
                                (other.to_string(), id.to_string()),
                            )
                            .unwrap();
                        } else {
                            // Existing digest is already the exact reservation identity;
                            // only corrupt its operation to collide with journal history.
                            sql.execute(
                                "UPDATE checkouts SET operation=?1 WHERE id=?2",
                                (id.to_string(), other.to_string()),
                            )
                            .unwrap();
                        }
                    }
                    let snapshot = if mode == "adopted" {
                        serde_json::to_value(store.adopted_status(&root.identity().run).unwrap())
                            .unwrap()
                    } else {
                        serde_json::to_value(store.run_snapshot(&root.identity().run).unwrap())
                            .unwrap()
                    };
                    let before = durable_rows(&sql);
                    let charged = store.charged(&reservation.repository, None).unwrap();
                    let result = match path {
                        "reservation" => store.reserve(&reservation, high).map(|_| ()),
                        "writer" => store.acquire_writer(other, id),
                        _ => store.acquire_writer(checkout, id),
                    };
                    let label = format!("{mode}/{field}/{path}/existing={corrupt_existing}");
                    if !matches!(result, Err(StoreError::Conflict)) {
                        failures.push(format!("{label}: expected Conflict, got {result:?}"));
                    }
                    if durable_rows(&sql) != before {
                        failures.push(format!("{label}: durable mutation"));
                    }
                    if store.charged(&reservation.repository, None).unwrap() != charged {
                        failures.push(format!("{label}: charge mutation"));
                    }
                    let after = if mode == "adopted" {
                        serde_json::to_value(store.adopted_status(&root.identity().run).unwrap())
                            .unwrap()
                    } else {
                        serde_json::to_value(store.run_snapshot(&root.identity().run).unwrap())
                            .unwrap()
                    };
                    assert_eq!(after, snapshot, "{label}");
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn allocation_operation_excludes_checkout_entities_and_bare_writer_groups_before_retry() {
    use work_cli::store::StoreError;
    let mut failures = Vec::new();
    for entity in ["checkout", "writer"] {
        for corrupt_existing in [false, true] {
            let (dir, mut store, checkout) = run_fixture::fixture();
            let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
            let group = Uuid::now_v7();
            store.acquire_writer(checkout, group).unwrap();
            let before_retry = durable_rows(&sql);
            store.acquire_writer(checkout, group).unwrap();
            assert_eq!(durable_rows(&sql), before_retry);
            let high = Limits {
                repository: 100,
                owner: 100,
                ..limits()
            };
            let mut request = Reservation {
                operation: Uuid::now_v7(),
                repository: dir.path().join("root"),
                actor: "allocator".into(),
                owner: "owner".into(),
                task: "other".into(),
            };
            let other = store.reserve(&request, high).unwrap();
            request.operation = if entity == "checkout" {
                checkout
            } else {
                group
            };
            if corrupt_existing {
                // Deliberately invalid operation/entity alias with an unchanged digest.
                sql.execute(
                    "UPDATE checkouts SET operation=?1 WHERE id=?2",
                    (request.operation.to_string(), other.to_string()),
                )
                .unwrap();
            }
            let before = durable_rows(&sql);
            let result = store.reserve(&request, high);
            if !matches!(result, Err(StoreError::Conflict)) {
                failures.push(format!("{entity}/existing={corrupt_existing}: {result:?}"));
            }
            if durable_rows(&sql) != before {
                failures.push(format!("{entity}: durable mutation"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn reuse_lookup_does_not_grant_an_independent_writer() {
    let (_dir, mut store, request) = fixture();
    let checkout = store.reserve(&request, limits()).unwrap();
    assert_eq!(
        store
            .find_reusable(&request.actor, &request.repository, &request.task)
            .unwrap(),
        vec![checkout]
    );
    // A lookup is not creation-readiness proof either. Real ready checkout
    // exclusivity is exercised by allocation.rs.
    assert!(store.acquire_writer(checkout, Uuid::now_v7()).is_err());
}
