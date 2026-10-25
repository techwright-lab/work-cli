use super::*;
use crate::admission::{Limits, Reservation};
use crate::events::Event;
use crate::store::{Store, StoreError};
use rusqlite::Connection;
use std::path::PathBuf;
use uuid::Uuid;

fn digest32(tag: u8) -> [u8; 32] {
    let mut bytes = [tag; 32];
    bytes[0] = tag;
    bytes
}

fn hex32(tag: u8) -> String {
    hex(&digest32(tag))
}

fn sample_record(operation: Uuid, checkout: Uuid) -> IntentRecord {
    IntentRecord {
        version: 1,
        operation: operation.to_string(),
        checkout: checkout.to_string(),
        mode: Mode::Supervised,
        revision: 1,
        stage: Stage::Prepared,
        assertion: None,
        declaration: None,
        predecessor_hex: hex32(1),
        source_hex: hex32(2),
        history_predecessor_hex: hex32(3),
        prior_history_count: 0,
        immutable_binding: ImmutableBinding {
            version: 1,
            authority_allocation: hex32(4),
            source_sql: hex32(2),
            managed_physical: hex32(6),
            census: hex32(7),
            git_private: hex32(8),
            local_git: hex32(9),
            git_inputs: hex32(10),
            source_commitment: hex32(11),
            approval_semantic: hex32(12),
            approval_invalidation: hex32(13),
            protection: hex32(14),
            protection_count: 0,
            config_manifests: [hex32(15), hex32(16)],
            inspection_policy: hex32(17),
            combined_policy: hex32(18),
            operator: hex32(19),
            source_repository: hex32(20),
        },
        quiescence: "empty".into(),
        task_completion: "supervised_empty".into(),
        policy_digest: hex32(17),
        combined_policy_digest: hex32(18),
        prepared_wall_ms: 1,
        remote_cleanup: "not_required".into(),
    }
}

fn open_store() -> (tempfile::TempDir, Store, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let dir = temp.path().join("private");
    let store = Store::open(&dir, std::slice::from_ref(&root)).unwrap();
    (temp, store, root)
}

fn insert_checkout(store: &Store, checkout: Uuid, operation: Uuid, owner: &str) {
    store
        .conn
        .execute(
            "INSERT INTO checkouts(id,operation,digest,repository,actor,task,owner,state,ready) VALUES(?1,?2,zeroblob(32),'repo','actor','task',?3,'active',1)",
            rusqlite::params![checkout.to_string(), operation.to_string(), owner],
        )
        .unwrap();
}

fn seed_prepared(store: &Store, checkout: Uuid, operation: Uuid) -> String {
    let record = encode_record(&sample_record(operation, checkout)).unwrap();
    store
        .conn
        .execute(
            "INSERT INTO retirement_intents(operation,checkout,revision,stage,mode,assertion,declared_task,declared_operator,predecessor,source,record,held_reason,aborted_from) VALUES(?1,?2,1,'prepared','supervised',NULL,NULL,NULL,?3,?4,?5,NULL,NULL)",
            rusqlite::params![
                operation.to_string(),
                checkout.to_string(),
                digest32(1).as_slice(),
                digest32(2).as_slice(),
                record.as_str()
            ],
        )
        .unwrap();
    record
}

#[test]
fn abort_history_removes_only_own_frame_and_keeps_prior_tombstones() {
    let (_temp, store, _root) = open_store();
    let checkout = Uuid::now_v7();
    insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
    let first = Uuid::now_v7();
    seed_prepared(&store, checkout, first);
    abort_cas(&store.conn, checkout, first, 1).unwrap();
    let mut predecessor = b"exact-source-frame".to_vec();
    let (history, count) = frame_history(&store.conn, checkout, &mut predecessor).unwrap();
    let second = Uuid::now_v7();
    seed_prepared(&store, checkout, second);
    for held in [false, true] {
        if held {
            hold_abort_validation(&store.conn, checkout, second).unwrap();
        }
        let mut reconstructed = b"exact-source-frame".to_vec();
        assert_eq!(
            frame_history_without(&store.conn, checkout, second, &mut reconstructed).unwrap(),
            (history.clone(), count)
        );
        assert_eq!(reconstructed, predecessor);
    }
    store.conn.execute("UPDATE retirement_intents SET revision=3,aborted_from=2,held_reason='reserve' WHERE operation=?1", [first.to_string()]).unwrap();
    let mut reconstructed = b"exact-source-frame".to_vec();
    frame_history_without(&store.conn, checkout, second, &mut reconstructed).unwrap();
    assert_ne!(reconstructed, predecessor);
    store
        .conn
        .execute(
            "UPDATE retirement_intents SET record='{}' WHERE operation=?1",
            [first.to_string()],
        )
        .unwrap();
    let mut unchanged = b"exact-source-frame".to_vec();
    assert!(frame_history_without(&store.conn, checkout, second, &mut unchanged).is_err());
    assert_eq!(unchanged, b"exact-source-frame");
}

fn limits() -> Limits {
    Limits {
        repository: 10,
        owner: 10,
        available_bytes: Some(100),
        floor_bytes: 0,
        warn_bytes: 0,
    }
}

fn held_events(store: &Store, checkout: Uuid) -> Vec<Event> {
    store
        .pending_events(1000)
        .unwrap()
        .into_iter()
        .map(|pending| pending.event)
        .filter(|event| matches!(event, Event::RetirementIntentChanged { checkout: id, stage, .. } if *id == checkout && stage == "held"))
        .collect()
}

#[test]
fn strict_operation_reader_bounds_raw_columns_and_never_hides_corruption() {
    for mutation in [
        "record=printf('%.*c',8193,'x')",
        "held_reason='untrusted',stage='held',revision=2",
        "record=replace(record,'supervised_empty','unknown')",
        "predecessor=zeroblob(31)",
        "declared_operator=printf('%.*c',8193,'x')",
        "stage='aborted',revision=3,aborted_from=1,held_reason='reserve'",
    ] {
        let (_temp, store, _) = open_store();
        let checkout = Uuid::now_v7();
        let operation = Uuid::now_v7();
        insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
        seed_prepared(&store, checkout, operation);
        store
            .conn
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        store
            .conn
            .execute(&format!("UPDATE retirement_intents SET {mutation}"), [])
            .unwrap();
        assert!(
            load_operation(&store.conn, operation).is_err(),
            "{mutation}"
        );
        assert!(
            find_operation(&store.conn, operation).is_err(),
            "{mutation}"
        );
        assert!(read_history(&store.conn, checkout).is_err(), "{mutation}");
    }
    let (_temp, store, _) = open_store();
    assert!(find_operation(&store.conn, Uuid::now_v7())
        .unwrap()
        .is_none());
}

#[test]
fn canonical_history_commits_held_reason_and_aborted_from() {
    let (_temp, store, _) = open_store();
    let checkout = Uuid::now_v7();
    let operation = Uuid::now_v7();
    insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
    seed_prepared(&store, checkout, operation);
    store
        .conn
        .execute(
            "UPDATE retirement_intents SET stage='held',revision=2,held_reason='reserve'",
            [],
        )
        .unwrap();
    let first = frame_history(&store.conn, checkout, &mut Vec::new())
        .unwrap()
        .0;
    store
        .conn
        .execute(
            "UPDATE retirement_intents SET held_reason='writer_acquire'",
            [],
        )
        .unwrap();
    let second = frame_history(&store.conn, checkout, &mut Vec::new())
        .unwrap()
        .0;
    assert_ne!(first, second);
    store
        .conn
        .execute(
            "UPDATE retirement_intents SET stage='aborted',revision=3,aborted_from=2",
            [],
        )
        .unwrap();
    let third = frame_history(&store.conn, checkout, &mut Vec::new())
        .unwrap()
        .0;
    assert_ne!(second, third);
    let row = load_operation(&store.conn, operation).unwrap();
    assert_eq!(row.decoded.stage, Stage::Prepared);
    assert_eq!(row.decoded.revision, 1);
    let mut full_context = vec![0; 16 * 1024 * 1024];
    assert!(frame_history(&store.conn, checkout, &mut full_context).is_err());
    assert_eq!(full_context.len(), 16 * 1024 * 1024);
}

#[test]
fn corrupt_batch_member_rolls_back_all_holds_and_events() {
    let (_temp, mut store, _) = open_store();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    insert_checkout(&store, a, Uuid::now_v7(), "owner");
    insert_checkout(&store, b, Uuid::now_v7(), "owner");
    let first = Uuid::now_v7();
    let second = Uuid::now_v7();
    seed_prepared(&store, a, first);
    seed_prepared(&store, b, second);
    store
        .conn
        .execute(
            "UPDATE retirement_intents SET record='{}' WHERE operation=?1",
            [second.to_string()],
        )
        .unwrap();
    let events = store.pending_events(1000).unwrap().len();
    let lease = store.authority_lease().unwrap();
    assert!(matches!(
        checkpoint(
            &mut store,
            &lease,
            Scope::Owner("owner".into()),
            Attempt::OwnerRetire
        ),
        Err(StoreError::Invalid)
    ));
    assert_eq!(
        load_operation(&store.conn, first).unwrap().stage,
        "prepared"
    );
    assert_eq!(events, store.pending_events(1000).unwrap().len());
}

#[test]
fn prepare_namespace_checks_checkout_operation_writer_and_journal_ids() {
    let (_temp, store, _) = open_store();
    let checkout = Uuid::now_v7();
    let allocation = Uuid::now_v7();
    let writer = Uuid::now_v7();
    insert_checkout(&store, checkout, allocation, "owner");
    store
        .conn
        .execute(
            "INSERT INTO writers(checkout,group_id) VALUES(?1,?2)",
            (checkout.to_string(), writer.to_string()),
        )
        .unwrap();
    let intent = Uuid::now_v7();
    seed_prepared(&store, checkout, intent);
    for id in [checkout, allocation, writer, intent] {
        assert!(
            matches!(
                exclude_prepare_operation(&store.conn, id),
                Err(StoreError::Conflict)
            ),
            "{id}"
        );
    }
    // Real journal fixture supplies run/group IDs; no positive retirement proof is seeded.
    let other = Uuid::now_v7();
    insert_checkout(&store, other, Uuid::now_v7(), "owner");
    let request = crate::test_run_fixture::request(other);
    let mut store = store;
    store.begin_run(&request).unwrap();
    for id in [
        request.identity().run.to_string(),
        request.identity().group.to_string(),
    ] {
        assert!(matches!(
            exclude_prepare_operation(&store.conn, parse_uuid(&id).unwrap()),
            Err(StoreError::Conflict)
        ));
    }
    exclude_prepare_operation(&store.conn, Uuid::now_v7()).unwrap();
}

#[test]
fn cas_tombstones_are_strict_and_hold_is_once() {
    for hold in [false, true] {
        let (_temp, mut store, _) = open_store();
        let checkout = Uuid::now_v7();
        let operation = Uuid::now_v7();
        insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
        seed_prepared(&store, checkout, operation);
        let lease = store.authority_lease().unwrap();
        if hold {
            for _ in 0..2 {
                assert!(matches!(
                    checkpoint(
                        &mut store,
                        &lease,
                        Scope::Checkout(checkout),
                        Attempt::Reserve
                    ),
                    Err(StoreError::RetirementFenced)
                ));
            }
            assert_eq!(held_events(&store, checkout).len(), 1);
        }
        let revision = if hold { 2 } else { 1 };
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        assert!(abort_cas(&tx, checkout, operation, revision + 1).is_err());
        assert_eq!(
            abort_cas(&tx, checkout, operation, revision).unwrap(),
            revision + 1
        );
        tx.commit().unwrap();
        let events = store.pending_events(1000).unwrap().len();
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            abort_cas(&tx, checkout, operation, revision).unwrap(),
            revision + 1
        );
        assert!(hold_abort_validation(&tx, checkout, operation).is_err());
        tx.commit().unwrap();
        assert_eq!(events, store.pending_events(1000).unwrap().len());
        assert_eq!(
            read_history(&store.conn, checkout).unwrap()[0].stage,
            "aborted"
        );
    }
}

#[test]
fn schema_ddl_and_indexes_match_canonical_bytes() {
    let (_temp, store, _) = open_store();
    let version: i64 = store
        .conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 16);
    validate_schema(&store.conn).unwrap();
}

#[test]
fn schema15_migrates_atomically_to_16() {
    let (temp, store, root) = open_store();
    store
        .conn
        .execute_batch("DROP TABLE retirement_intents; PRAGMA user_version=15;")
        .unwrap();
    drop(store);
    let store = Store::open(&temp.path().join("private"), std::slice::from_ref(&root)).unwrap();
    let version: i64 = store
        .conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 16);
    validate_schema(&store.conn).unwrap();
}

#[test]
fn current_only_openers_reject_schema15() {
    let (temp, store, root) = open_store();
    let dir = temp.path().join("private");
    let registry = temp.path().join(".work-authorities");
    store
        .conn
        .execute_batch("DROP TABLE retirement_intents; PRAGMA user_version=15;")
        .unwrap();
    drop(store);
    assert!(matches!(
        Store::open_existing_registered_readonly(&registry, &dir, std::slice::from_ref(&root)),
        Err(StoreError::UpgradeRequired)
    ));
    assert!(matches!(
        Store::open_existing_registered_mut(&registry, &dir, std::slice::from_ref(&root)),
        Err(StoreError::UpgradeRequired)
    ));
}

#[test]
fn leftover_retirement_objects_fail_migration() {
    for leftover in [
        "CREATE TABLE retirement_intents(x INTEGER)",
        "CREATE VIEW retirement_intents AS SELECT 1 AS operation",
        "CREATE INDEX retirement_intents_active ON checkouts(id)",
    ] {
        let (temp, store, root) = open_store();
        store
            .conn
            .execute_batch("DROP TABLE retirement_intents;")
            .unwrap();
        store.conn.execute_batch(leftover).unwrap();
        store.conn.execute_batch("PRAGMA user_version=15;").unwrap();
        drop(store);
        assert!(
            Store::open(&temp.path().join("private"), std::slice::from_ref(&root)).is_err(),
            "{leftover}"
        );
    }
}

#[test]
fn interrupted_migration_rolls_back() {
    let (temp, store, root) = open_store();
    store
        .conn
        .execute_batch("DROP TABLE retirement_intents; PRAGMA user_version=15;")
        .unwrap();
    store
        .conn
        .execute_batch("CREATE TRIGGER block_retirement BEFORE INSERT ON sqlite_schema BEGIN SELECT RAISE(ABORT,'fixture'); END;")
        .ok();
    drop(store);
    let _ = Store::open(&temp.path().join("private"), std::slice::from_ref(&root));
    let sql = Connection::open(temp.path().join("private/store.sqlite")).unwrap();
    let version: i64 = sql
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert!(version == 15 || version == 16);
    if version == 15 {
        let present: i64 = sql
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='retirement_intents' AND type='table'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(present, 0);
    }
}

#[test]
fn strict_codec_rejects_unknown_duplicate_and_oversized_fields() {
    let operation = Uuid::now_v7();
    let checkout = Uuid::now_v7();
    let record = sample_record(operation, checkout);
    let encoded = encode_record(&record).unwrap();
    assert!(encoded.len() <= MAX_RECORD_BYTES);
    decode_record(&encoded).unwrap();
    assert!(decode_record(&encoded.replace('}', ",\"extra\":1}")).is_err());
    assert!(
        decode_record(&encoded.replacen("\"version\":1", "\"version\":1,\"version\":1", 1))
            .is_err()
    );
    let mut wrong_binding = record.clone();
    wrong_binding.immutable_binding.source_sql = hex32(99);
    assert!(encode_record(&wrong_binding).is_err());
    let mut exhausted = record.clone();
    exhausted.prior_history_count = 64;
    assert!(encode_record(&exhausted).is_err());
    let mut huge = sample_record(operation, checkout);
    huge.quiescence = "empty".to_owned();
    huge.immutable_binding.operator = "aa".repeat(5000);
    assert!(encode_record(&huge).is_err());
    let mut adopted = sample_record(operation, checkout);
    adopted.mode = Mode::Adopted;
    assert!(encode_record(&adopted).is_err());
}

#[test]
fn relational_mismatch_and_stage_cas_are_strict() {
    let (_temp, mut store, _) = open_store();
    let checkout = Uuid::now_v7();
    let operation = Uuid::now_v7();
    insert_checkout(&store, checkout, operation, "owner");
    seed_prepared(&store, checkout, operation);
    let lease = store.authority_lease().unwrap();
    let authority = store.authority_identity().clone();
    let tx = store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    let err = fence(
        tx,
        &lease,
        &authority,
        Scope::Checkout(checkout),
        Attempt::Reserve,
    )
    .unwrap_err();
    assert!(matches!(err, StoreError::RetirementFenced));
    let row = load_operation(&store.conn, operation).unwrap();
    assert_eq!(row.stage, "held");
    assert_eq!(row.revision, 2);
    assert_eq!(row.held_reason.as_deref(), Some("reserve"));
}

#[test]
fn one_active_intent_and_operation_collisions() {
    let (_temp, store, _) = open_store();
    let checkout = Uuid::now_v7();
    let first = Uuid::now_v7();
    let second = Uuid::now_v7();
    insert_checkout(&store, checkout, first, "owner");
    seed_prepared(&store, checkout, first);
    let record = encode_record(&sample_record(second, checkout)).unwrap();
    assert!(store
        .conn
        .execute(
            "INSERT INTO retirement_intents(operation,checkout,revision,stage,mode,assertion,declared_task,declared_operator,predecessor,source,record,held_reason,aborted_from) VALUES(?1,?2,1,'prepared','supervised',NULL,NULL,NULL,?3,?4,?5,NULL,NULL)",
            rusqlite::params![
                second.to_string(),
                checkout.to_string(),
                digest32(1).as_slice(),
                digest32(2).as_slice(),
                record
            ],
        )
        .is_err());
}

#[test]
fn history_row_and_byte_bounds_fail_closed() {
    let (_temp, store, _) = open_store();
    let checkout = Uuid::now_v7();
    insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
    for _ in 0..64 {
        let operation = Uuid::now_v7();
        let encoded = encode_record(&sample_record(operation, checkout)).unwrap();
        store
            .conn
            .execute(
                "INSERT INTO retirement_intents(operation,checkout,revision,stage,mode,assertion,declared_task,declared_operator,predecessor,source,record,held_reason,aborted_from) VALUES(?1,?2,2,'aborted','supervised',NULL,NULL,NULL,?3,?4,?5,NULL,1)",
                rusqlite::params![
                    operation.to_string(),
                    checkout.to_string(),
                    digest32(1).as_slice(),
                    digest32(2).as_slice(),
                    encoded
                ],
            )
            .unwrap();
    }
    assert_eq!(read_history(&store.conn, checkout).unwrap().len(), 64);
    let extra = Uuid::now_v7();
    let encoded = encode_record(&sample_record(extra, checkout)).unwrap();
    store
        .conn
        .execute(
            "INSERT INTO retirement_intents(operation,checkout,revision,stage,mode,assertion,declared_task,declared_operator,predecessor,source,record,held_reason,aborted_from) VALUES(?1,?2,2,'aborted','supervised',NULL,NULL,NULL,?3,?4,?5,NULL,1)",
            rusqlite::params![
                extra.to_string(),
                checkout.to_string(),
                digest32(1).as_slice(),
                digest32(2).as_slice(),
                encoded
            ],
        )
        .unwrap();
    assert!(read_history(&store.conn, checkout).is_err());
}

#[test]
fn all_history_rows_are_validated_not_only_active() {
    let (_temp, store, _) = open_store();
    let checkout = Uuid::now_v7();
    let aborted = Uuid::now_v7();
    let active = Uuid::now_v7();
    insert_checkout(&store, checkout, active, "owner");
    let encoded = encode_record(&sample_record(aborted, checkout)).unwrap();
    store
        .conn
        .execute(
            "INSERT INTO retirement_intents(operation,checkout,revision,stage,mode,assertion,declared_task,declared_operator,predecessor,source,record,held_reason,aborted_from) VALUES(?1,?2,2,'aborted','supervised',NULL,NULL,NULL,?3,?4,?5,NULL,1)",
            rusqlite::params![
                aborted.to_string(),
                checkout.to_string(),
                digest32(1).as_slice(),
                digest32(2).as_slice(),
                encoded.replace("empty", "bogus")
            ],
        )
        .ok();
    seed_prepared(&store, checkout, active);
    assert!(read_history(&store.conn, checkout).is_err());
}

#[test]
fn repeated_hold_emits_nothing() {
    let (_temp, mut store, _) = open_store();
    let checkout = Uuid::now_v7();
    let operation = Uuid::now_v7();
    insert_checkout(&store, checkout, operation, "owner");
    seed_prepared(&store, checkout, operation);
    let lease = store.authority_lease().unwrap();
    let authority = store.authority_identity().clone();
    let tx = store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert!(matches!(
        fence(
            tx,
            &lease,
            &authority,
            Scope::Checkout(checkout),
            Attempt::Reserve
        ),
        Err(StoreError::RetirementFenced)
    ));
    let first = held_events(&store, checkout).len();
    let tx = store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert!(matches!(
        fence(
            tx,
            &lease,
            &authority,
            Scope::Checkout(checkout),
            Attempt::Reserve
        ),
        Err(StoreError::RetirementFenced)
    ));
    assert_eq!(held_events(&store, checkout).len(), first);
}

#[test]
fn batch_holds_all_prepared_before_any_caller_write() {
    let (_temp, mut store, _) = open_store();
    let first = Uuid::now_v7();
    let second = Uuid::now_v7();
    let held = Uuid::now_v7();
    insert_checkout(&store, first, Uuid::now_v7(), "owner");
    insert_checkout(&store, second, Uuid::now_v7(), "owner");
    insert_checkout(&store, held, Uuid::now_v7(), "owner");
    seed_prepared(&store, first, Uuid::now_v7());
    seed_prepared(&store, second, Uuid::now_v7());
    let held_op = Uuid::now_v7();
    seed_prepared(&store, held, held_op);
    store
        .conn
        .execute(
            "UPDATE retirement_intents SET revision=2, stage='held', held_reason='reserve' WHERE operation=?1",
            [held_op.to_string()],
        )
        .unwrap();
    let lease = store.authority_lease().unwrap();
    let authority = store.authority_identity().clone();
    let tx = store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert!(matches!(
        fence(
            tx,
            &lease,
            &authority,
            Scope::Owner("owner".into()),
            Attempt::OwnerRetire
        ),
        Err(StoreError::RetirementFenced)
    ));
    for checkout in [first, second, held] {
        let row = active_operation(&store.conn, checkout).unwrap().unwrap();
        assert_eq!(row.stage, "held");
        assert_eq!(row.revision, 2);
    }
    assert_eq!(held_events(&store, first).len(), 1);
    assert_eq!(held_events(&store, second).len(), 1);
    assert_eq!(held_events(&store, held).len(), 0);
}

#[test]
fn namespace_helpers_ignore_retirement_on_old_schema_only() {
    let (_temp, store, _) = open_store();
    let operation = Uuid::now_v7();
    let checkout = Uuid::now_v7();
    insert_checkout(&store, checkout, operation, "owner");
    seed_prepared(&store, checkout, operation);
    assert!(operation_reserved(&store.conn, &operation.to_string()).unwrap());
    store.conn.pragma_update(None, "user_version", 15).unwrap();
    assert!(!operation_reserved(&store.conn, &operation.to_string()).unwrap());
    store.conn.pragma_update(None, "user_version", 16).unwrap();
}

#[test]
fn reserve_retry_commits_hold_before_existing() {
    let (_temp, mut store, root) = open_store();
    let operation = Uuid::now_v7();
    let checkout = store
        .reserve(
            &Reservation {
                operation,
                repository: root.clone(),
                actor: "allocator".into(),
                owner: "owner".into(),
                task: "task".into(),
            },
            limits(),
        )
        .unwrap();
    seed_prepared(&store, checkout, Uuid::now_v7());
    let err = store
        .reserve(
            &Reservation {
                operation,
                repository: root,
                actor: "allocator".into(),
                owner: "owner".into(),
                task: "task".into(),
            },
            limits(),
        )
        .unwrap_err();
    assert!(matches!(err, StoreError::RetirementFenced));
    let active = active_operation(&store.conn, checkout).unwrap().unwrap();
    assert_eq!(active.stage, "held");
}

#[test]
fn writer_acquire_and_owner_transfer_are_fenced() {
    let (_temp, mut store, _) = open_store();
    let checkout = Uuid::now_v7();
    insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
    seed_prepared(&store, checkout, Uuid::now_v7());
    assert!(matches!(
        store.acquire_writer(checkout, Uuid::now_v7()),
        Err(StoreError::RetirementFenced)
    ));
    assert!(matches!(
        store.transfer(checkout, "other", limits()),
        Err(StoreError::RetirementFenced)
    ));
    let row = active_operation(&store.conn, checkout).unwrap().unwrap();
    assert_eq!(row.stage, "held");
}

#[test]
fn owner_retire_holds_every_prepared_intent() {
    let (_temp, mut store, _) = open_store();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    insert_checkout(&store, a, Uuid::now_v7(), "owner");
    insert_checkout(&store, b, Uuid::now_v7(), "owner");
    seed_prepared(&store, a, Uuid::now_v7());
    seed_prepared(&store, b, Uuid::now_v7());
    assert!(matches!(
        store.retire_owner("owner", Some("operator"), limits()),
        Err(StoreError::RetirementFenced)
    ));
    assert_eq!(
        active_operation(&store.conn, a).unwrap().unwrap().stage,
        "held"
    );
    assert_eq!(
        active_operation(&store.conn, b).unwrap().unwrap().stage,
        "held"
    );
    let owners: i64 = store
        .conn
        .query_row("SELECT count(*) FROM retired_owners", [], |r| r.get(0))
        .unwrap();
    assert_eq!(owners, 0);
}

#[test]
fn run_begin_and_adopted_begin_are_fenced() {
    let (_temp, mut store, _) = open_store();
    let checkout = Uuid::now_v7();
    insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
    seed_prepared(&store, checkout, Uuid::now_v7());
    let request = crate::test_run_fixture::request(checkout);
    assert!(matches!(
        store.begin_run(&request),
        Err(StoreError::RetirementFenced)
    ));
}

#[test]
fn save_under_lease_is_fenced() {
    let (_temp, mut store, _) = open_store();
    let checkout = Uuid::now_v7();
    let operation = Uuid::now_v7();
    insert_checkout(&store, checkout, operation, "owner");
    seed_prepared(&store, checkout, Uuid::now_v7());
    let allocation = crate::allocate::Allocation {
        checkout,
        request: crate::allocate::Start {
            operation,
            repository: None,
            root: None,
            actor: None,
            owner: None,
            task: "task".into(),
            branch: None,
            base: "HEAD".into(),
            reuse_branch: false,
        },
        destination: PathBuf::from("/tmp/work-retirement-fence"),
        base_commit: "0".repeat(40),
        stage: "held".into(),
        reason: None,
        identity: None,
    };
    let err = crate::allocate::save(&mut store, &allocation).unwrap_err();
    assert!(err.to_string().contains("retirement intent"));
}

#[test]
fn abort_cas_is_idempotent_and_does_not_hold_competitor() {
    let (_temp, mut store, _) = open_store();
    let checkout = Uuid::now_v7();
    let operation = Uuid::now_v7();
    let other = Uuid::now_v7();
    insert_checkout(&store, checkout, operation, "owner");
    insert_checkout(&store, other, Uuid::now_v7(), "owner");
    seed_prepared(&store, checkout, operation);
    seed_prepared(&store, other, Uuid::now_v7());
    let tx = store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert_eq!(abort_cas(&tx, checkout, operation, 1).unwrap(), 2);
    tx.commit().unwrap();
    let tx = store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert_eq!(abort_cas(&tx, checkout, operation, 1).unwrap(), 2);
    tx.commit().unwrap();
    let competitor = active_operation(&store.conn, other).unwrap().unwrap();
    assert_eq!(competitor.stage, "prepared");
}

#[test]
fn writer_matrix_attempts_commit_hold() {
    let attempts = [
        Attempt::Reserve,
        Attempt::AllocationStage,
        Attempt::AllocationHold,
        Attempt::AllocationIdentity,
        Attempt::AliasPublication,
        Attempt::OwnerTransfer,
        Attempt::OwnerRetire,
        Attempt::WriterAcquire,
        Attempt::RunJournal,
        Attempt::GroupClose,
        Attempt::ChildJournal,
        Attempt::AdoptedBegin,
        Attempt::AdoptedActivity,
        Attempt::FinishPrepare,
        Attempt::FinishCaptureResult,
        Attempt::CapturePreparation,
        Attempt::CaptureAdmission,
        Attempt::CaptureReconcile,
        Attempt::CaptureReadiness,
        Attempt::CaptureFinalization,
        Attempt::CaptureDelivery,
        Attempt::GapAdmission,
        Attempt::GapPublication,
        Attempt::ExecutionPermit,
        Attempt::ReceiptPublication,
        Attempt::RecoveryRefs,
        Attempt::AbortValidationFailed,
    ];
    for attempt in attempts {
        let (_temp, mut store, _) = open_store();
        let checkout = Uuid::now_v7();
        insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
        seed_prepared(&store, checkout, Uuid::now_v7());
        let lease = store.authority_lease().unwrap();
        let authority = store.authority_identity().clone();
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        assert!(
            matches!(
                fence(tx, &lease, &authority, Scope::Checkout(checkout), attempt),
                Err(StoreError::RetirementFenced)
            ),
            "{}",
            attempt.label()
        );
        let row = active_operation(&store.conn, checkout).unwrap().unwrap();
        assert_eq!(row.stage, "held");
        assert_eq!(row.held_reason.as_deref(), Some(attempt.label()));
    }
}
