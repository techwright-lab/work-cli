//! B1 metadata/DDL tests, AUTHORED_ONLY until parent isolated CI.
//! Synthetic records here are codec DATA, never a live retirement/move owner.
use super::*;
use rusqlite::{params, types::ValueRef, Connection};
use serde_json::{json, Value};

const OP: &str = "018f0102-0304-7506-8708-090a0b0c0d0e";
const CHECKOUT: &str = "018f1112-1314-7516-8718-191a1b1c1d1e";

fn digest() -> String {
    "ab".repeat(32)
}
fn identity(inode: u64) -> FileIdentity {
    FileIdentity {
        device: 1,
        inode,
        mount: 2,
    }
}
fn path_hex(path: &[u8]) -> String {
    crate::retirement_journal::hex(path)
}
fn binding(path: &str, inode: u64) -> PathIdentity {
    PathIdentity {
        path: path_hex(path.as_bytes()),
        identity: identity(inode),
    }
}
fn plan() -> PhysicalPlan {
    PhysicalPlan {
        version: 1,
        operation: OP.into(),
        checkout: CHECKOUT.into(),
        prepared_record_hash: digest(),
        predecessor: digest(),
        snapshot: digest(),
        source: digest(),
        intent_history: digest(),
        intent_count: 1,
        physical_history: digest(),
        physical_count: 0,
        schema_version: 17,
        schema_cookie: 35,
        store: digest(),
        config: [digest(), digest()],
        policy: digest(),
        boot: digest(),
        allocation: digest(),
        marker: digest(),
        protected_inputs: digest(),
        expected_links: digest(),
        original: binding("/work/checkout", 3),
        original_parent: binding("/work", 4),
        target: path_hex(format!("/quarantine/work-quarantine-v1-{CHECKOUT}-{OP}").as_bytes()),
        target_parent: binding("/quarantine", 5),
        administrative: binding("/repo/.git/worktrees/checkout", 6),
        common: binding("/repo/.git", 7),
        namespace_lock: binding("/quarantine/.work-quarantine-namespace-v1.lock", 8),
        profile: NativeProfile::Git255AbsoluteFilesSha1AttachedV1,
    }
}
fn result(plan: &PhysicalPlan, encoded: &str, state: ActionState) -> ResultRecord {
    ResultRecord {
        version: 1,
        operation: plan.operation.clone(),
        checkout: plan.checkout.clone(),
        revision: 2,
        state,
        plan_hash: plan_hash(encoded),
        reason: if state == ActionState::MoveUncertain {
            Some(UncertainReason::VerificationFailed)
        } else {
            None
        },
        native_exit: Some(0),
        observed_target: Some(plan.original.identity.clone()),
        observed_links: Some(plan.expected_links.clone()),
        protected_inputs: Some(plan.protected_inputs.clone()),
        observed_wall_ms: 1,
    }
}
fn row(plan: &PhysicalPlan, encoded: &str, state: ActionState) -> ActionRow {
    ActionRow {
        version: 1,
        operation: plan.operation.clone(),
        checkout: plan.checkout.clone(),
        revision: if state == ActionState::MovePending {
            1
        } else {
            2
        },
        state,
        plan: encoded.into(),
        result: if state == ActionState::MovePending {
            None
        } else {
            Some(serde_json::to_string(&result(plan, encoded, state)).unwrap())
        },
    }
}

#[test]
fn metadata_roundtrips_without_an_owner_or_store() {
    let plan = plan();
    let encoded = encode_plan_with_result_capacity(&plan).unwrap();
    assert_eq!(decode_plan(&encoded).unwrap(), plan);
    for state in [
        ActionState::MovePending,
        ActionState::Quarantined,
        ActionState::MoveUncertain,
    ] {
        let row = row(&plan, &encoded, state);
        let bytes = encode_row(&row).unwrap();
        assert!(bytes.len() <= MAX_ROW_BYTES);
        assert_eq!(decode_row(&bytes).unwrap(), row);
        if let Some(bytes) = &row.result {
            let decoded = decode_result(bytes).unwrap();
            assert_eq!(encode_result(&decoded).unwrap(), *bytes);
        }
    }
    // Declaration only: no emitter, SQL mutation, or permission is exercised.
    let event = crate::events::Event::QuarantineActionChanged {
        checkout: uuid::Uuid::parse_str(CHECKOUT).unwrap(),
        operation: uuid::Uuid::parse_str(OP).unwrap(),
        revision: 1,
        state: "move_pending".into(),
        reason: None,
    };
    assert_eq!(
        serde_json::to_value(event).unwrap()["type"],
        "quarantine_action_changed"
    );
}

#[test]
fn plan_rejects_unknown_duplicate_missing_positional_and_wrong_types() {
    let encoded = encode_plan_with_result_capacity(&plan()).unwrap();
    let mutations = [
        ("unknown", json!(true)),
        ("version", json!(2)),
        ("version", json!(-1)),
        ("version", json!(1.0)),
        ("intent_count", json!("1")),
        ("schema_version", json!(16)),
        ("schema_cookie", json!(2147483648u64)),
        ("config", json!([digest()])),
        ("original", json!(["/work", 3])),
        ("profile", json!("git255_relative_files_sha1_attached_v1")),
        ("intent_count", json!(0)),
        ("intent_count", json!(65)),
        ("physical_count", json!(1)),
    ];
    for (field, replacement) in mutations {
        let mut value: Value = serde_json::from_str(&encoded).unwrap();
        value[field] = replacement;
        assert!(decode_plan(&value.to_string()).is_err(), "{field}: {value}");
    }
    let mut nested: Value = serde_json::from_str(&encoded).unwrap();
    nested["original"]["identity"]["extra"] = json!(1);
    assert!(decode_plan(&nested.to_string()).is_err());
    let mut missing: Value = serde_json::from_str(&encoded).unwrap();
    missing.as_object_mut().unwrap().remove("marker");
    assert!(decode_plan(&missing.to_string()).is_err());
    assert!(decode_plan(&encoded.replacen("{", "{\"version\":1,", 1)).is_err());
    assert!(
        decode_plan(&encoded.replacen("\"device\":1", "\"device\":1,\"device\":1", 1)).is_err()
    );
    let values: Vec<_> = serde_json::from_str::<Value>(&encoded)
        .unwrap()
        .as_object()
        .unwrap()
        .values()
        .cloned()
        .collect();
    assert!(decode_plan(&serde_json::to_string(&values).unwrap()).is_err());
    assert!(decode_plan(&(encoded.clone() + "{}")).is_err());
    assert!(decode_plan(&" ".repeat(MAX_ROW_BYTES + 1)).is_err());
}

#[test]
fn plan_uuid_hash_identity_and_path_bindings_are_strict() {
    let good = plan();
    let encoded = encode_plan_with_result_capacity(&good).unwrap();
    for field in ["operation", "checkout"] {
        for bad in [
            OP.to_uppercase(),
            OP.replace('-', ""),
            "00000000-0000-0000-0000-000000000000".into(),
            "018f0102-0304-4506-8708-090a0b0c0d0e".into(),
            "018f0102-0304-7506-0708-090a0b0c0d0e".into(),
        ] {
            let mut value: Value = serde_json::from_str(&encoded).unwrap();
            value[field] = json!(bad);
            assert!(decode_plan(&value.to_string()).is_err());
        }
    }
    for field in [
        "prepared_record_hash",
        "predecessor",
        "snapshot",
        "source",
        "intent_history",
        "physical_history",
        "store",
        "policy",
        "boot",
        "allocation",
        "marker",
        "protected_inputs",
        "expected_links",
    ] {
        for bad in ["ab".repeat(31), "AB".repeat(32), "gg".repeat(32)] {
            let mut value: Value = serde_json::from_str(&encoded).unwrap();
            value[field] = json!(bad);
            assert!(decode_plan(&value.to_string()).is_err(), "{field}");
        }
    }
    for bad in [
        b"relative".as_slice(),
        b"/work//checkout",
        b"/work/../checkout",
        b"/work/./checkout",
        b"/work/checkout/",
        b"/work/\0checkout",
    ] {
        let mut plan = good.clone();
        plan.original.path = path_hex(bad);
        assert!(encode_plan_with_result_capacity(&plan).is_err());
    }
    for original in ["2f0", "2F776f726b", "zz"] {
        let mut plan = good.clone();
        plan.original.path = original.into();
        assert!(encode_plan_with_result_capacity(&plan).is_err());
    }
    let mut plan = good.clone();
    plan.original_parent.path = path_hex(b"/unrelated");
    assert!(encode_plan_with_result_capacity(&plan).is_err());
    let mut plan = good.clone();
    plan.target = path_hex(b"/quarantine/arbitrary-leaf");
    assert!(encode_plan_with_result_capacity(&plan).is_err());
    let mut plan = good.clone();
    plan.namespace_lock.path = path_hex(b"/quarantine/other.lock");
    assert!(encode_plan_with_result_capacity(&plan).is_err());
    let mut plan = good.clone();
    plan.common.path = plan.original.path.clone();
    assert!(encode_plan_with_result_capacity(&plan).is_err());
    for field in ["device", "inode", "mount"] {
        let mut value: Value = serde_json::from_str(&encoded).unwrap();
        value["target_parent"]["identity"][field] = json!(99);
        // A changed inode alone is valid metadata, unlike a changed mount/device.
        assert_eq!(decode_plan(&value.to_string()).is_err(), field != "inode");
    }
    let mut plan = good.clone();
    plan.original.identity.inode = 0;
    assert!(encode_plan_with_result_capacity(&plan).is_err());
    let mut plan = good.clone();
    plan.original.path = path_hex(format!("/work/{}", "a".repeat(256)).as_bytes());
    assert!(encode_plan_with_result_capacity(&plan).is_err());
    let mut plan = good.clone();
    plan.original.path = "ab".repeat(MAX_PATH_BYTES + 1);
    assert!(encode_plan_with_result_capacity(&plan).is_err());
    // Exact Unix bytes, not a lossy UTF-8 path conversion.
    let mut plan = good;
    plan.original.path = path_hex(b"/work/\xffcheckout");
    assert!(encode_plan_with_result_capacity(&plan).is_ok());
}

#[test]
fn row_state_revision_result_matrix_and_bindings_are_strict() {
    let plan = plan();
    let encoded = encode_plan_with_result_capacity(&plan).unwrap();
    let outcomes = [
        None,
        Some(serde_json::to_string(&result(&plan, &encoded, ActionState::Quarantined)).unwrap()),
        Some(serde_json::to_string(&result(&plan, &encoded, ActionState::MoveUncertain)).unwrap()),
    ];
    for (index, state) in [
        ActionState::MovePending,
        ActionState::Quarantined,
        ActionState::MoveUncertain,
    ]
    .into_iter()
    .enumerate()
    {
        for revision in [0, 1, 2, 3, u64::MAX] {
            for (outcome, value) in outcomes.iter().enumerate() {
                let mut row = row(&plan, &encoded, state);
                row.revision = revision;
                row.result = value.clone();
                let valid = index == outcome && revision == if index == 0 { 1 } else { 2 };
                assert_eq!(
                    encode_row(&row).is_ok(),
                    valid,
                    "{state:?}/{revision}/{outcome}"
                );
                assert_eq!(
                    decode_row(&serde_json::to_string(&row).unwrap()).is_ok(),
                    valid
                );
            }
        }
    }
    let valid = row(&plan, &encoded, ActionState::MovePending);
    let bytes = encode_row(&valid).unwrap();
    for (field, bad) in [
        ("version", json!(2)),
        ("operation", json!(CHECKOUT)),
        ("checkout", json!(OP)),
        ("revision", json!("1")),
        ("state", json!("retired")),
        ("extra", json!(false)),
        ("plan", json!(plan)),
    ] {
        let mut value: Value = serde_json::from_str(&bytes).unwrap();
        value[field] = bad;
        assert!(decode_row(&value.to_string()).is_err());
    }
    let mut value: Value = serde_json::from_str(&bytes).unwrap();
    value.as_object_mut().unwrap().remove("result");
    assert!(decode_row(&value.to_string()).is_err());
    assert!(decode_row(&bytes.replacen("{", "{\"version\":1,", 1)).is_err());
    assert!(decode_row(&" ".repeat(MAX_ROW_BYTES + 1)).is_err());
}

#[test]
fn result_codec_rejects_wrong_bindings_and_unbounded_reports() {
    let plan = plan();
    let encoded = encode_plan_with_result_capacity(&plan).unwrap();
    let good = result(&plan, &encoded, ActionState::Quarantined);
    let bytes = encode_result(&good).unwrap();
    for (field, bad) in [
        ("version", json!(2)),
        ("revision", json!(1)),
        ("state", json!("move_pending")),
        ("reason", json!("native_failed")),
        ("native_exit", json!(1)),
        ("observed_target", Value::Null),
        ("observed_links", json!("AB".repeat(32))),
        ("protected_inputs", Value::Null),
        ("native_exit", json!(2147483648u64)),
        ("stderr", json!("private bytes")),
    ] {
        let mut value: Value = serde_json::from_str(&bytes).unwrap();
        value[field] = bad;
        assert!(decode_result(&value.to_string()).is_err(), "{field}");
    }
    for (field, bad) in [
        ("operation", json!(CHECKOUT)),
        ("checkout", json!(OP)),
        ("plan_hash", json!("cd".repeat(32))),
        ("observed_links", json!("cd".repeat(32))),
        ("protected_inputs", json!("cd".repeat(32))),
    ] {
        let mut value: Value = serde_json::from_str(&bytes).unwrap();
        value[field] = bad;
        let mut row = row(&plan, &encoded, ActionState::Quarantined);
        row.result = Some(value.to_string());
        assert!(encode_row(&row).is_err(), "{field}");
    }
    let mut changed = good.clone();
    changed.observed_target = Some(identity(99));
    let mut row = row(&plan, &encoded, ActionState::Quarantined);
    row.result = Some(encode_result(&changed).unwrap());
    assert!(encode_row(&row).is_err());
    assert!(decode_result(&bytes.replacen("{", "{\"version\":1,", 1)).is_err());
    let mut missing: Value = serde_json::from_str(&bytes).unwrap();
    missing.as_object_mut().unwrap().remove("reason");
    assert!(decode_result(&missing.to_string()).is_err());
    assert!(decode_result(&" ".repeat(MAX_ROW_BYTES + 1)).is_err());
    let mut uncertain = result(&plan, &encoded, ActionState::MoveUncertain);
    uncertain.reason = None;
    assert!(encode_result(&uncertain).is_err());
    let mut value =
        serde_json::to_value(result(&plan, &encoded, ActionState::MoveUncertain)).unwrap();
    value["reason"] = json!("pretend_no_effect");
    assert!(decode_result(&value.to_string()).is_err());
    for reason in UncertainReason::ALL {
        let mut unknown = result(&plan, &encoded, ActionState::MoveUncertain);
        unknown.reason = Some(reason);
        unknown.native_exit = None;
        unknown.observed_target = None;
        unknown.observed_links = None;
        unknown.protected_inputs = None;
        assert_eq!(
            decode_result(&encode_result(&unknown).unwrap()).unwrap(),
            unknown
        );
    }
    assert_eq!(
        plan_hash(""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

// Independent size oracle: all uncertainty reasons, both signed extremes, all
// optional slots present at their largest widths. Success uses exact plan IDs.
fn widest_row(plan: &PhysicalPlan, encoded: &str) -> ActionRow {
    let mut candidates = vec![row(plan, encoded, ActionState::MovePending)];
    let mut success = result(plan, encoded, ActionState::Quarantined);
    success.observed_wall_ms = u64::MAX;
    let mut success_row = row(plan, encoded, ActionState::Quarantined);
    success_row.result = Some(serde_json::to_string(&success).unwrap());
    candidates.push(success_row);
    for reason in [
        UncertainReason::PreDispatchDrift,
        UncertainReason::NativeFailed,
        UncertainReason::NativeTimeout,
        UncertainReason::CleanupFailed,
        UncertainReason::IdentityDrift,
        UncertainReason::DurabilityFailed,
        UncertainReason::ScopeExpired,
        UncertainReason::AcknowledgmentUnknown,
        UncertainReason::VerificationFailed,
    ] {
        for exit in [i32::MIN, i32::MAX] {
            let mut record = result(plan, encoded, ActionState::MoveUncertain);
            record.reason = Some(reason);
            record.native_exit = Some(exit);
            record.observed_wall_ms = u64::MAX;
            record.observed_target = Some(FileIdentity {
                device: u64::MAX,
                inode: u64::MAX,
                mount: u64::MAX,
            });
            let mut candidate = row(plan, encoded, ActionState::MoveUncertain);
            candidate.result = Some(serde_json::to_string(&record).unwrap());
            candidates.push(candidate);
        }
    }
    candidates
        .into_iter()
        .max_by_key(|row| serde_json::to_string(row).unwrap().len())
        .unwrap()
}

#[test]
fn actual_encoded_plan_reserves_every_worst_result_at_exact_row_boundary() {
    let plan = plan();
    let encoded = encode_plan_with_result_capacity(&plan).unwrap();
    let maximum = serde_json::to_string(&widest_row(&plan, &encoded))
        .unwrap()
        .len();
    assert!(maximum < MAX_ROW_BYTES);
    // Legal whitespace increases the ACTUAL stored plan, not its normalized
    // representation. The capacity check must never silently compact this input.
    let boundary = format!("{}{}", " ".repeat(MAX_ROW_BYTES - maximum), encoded);
    assert!(decode_plan(&boundary).is_ok());
    let full = widest_row(&plan, &boundary);
    assert_eq!(serde_json::to_string(&full).unwrap().len(), MAX_ROW_BYTES);
    assert!(encode_row(&full).is_ok());
    assert!(decode_row(&encode_row(&full).unwrap()).is_ok());
    let mut oversized_result = full.clone();
    oversized_result.result = Some(format!(" {}", full.result.as_ref().unwrap()));
    assert!(oversized_result.result.as_ref().unwrap().len() < MAX_ROW_BYTES);
    let oversized_envelope = serde_json::to_string(&oversized_result).unwrap();
    assert_eq!(oversized_envelope.len(), MAX_ROW_BYTES + 1);
    assert!(encode_row(&oversized_result).is_err());
    assert!(decode_row(&oversized_envelope).is_err());
    let too_large = format!(" {boundary}");
    let pending = row(&plan, &too_large, ActionState::MovePending);
    assert!(serde_json::to_string(&pending).unwrap().len() < MAX_ROW_BYTES);
    assert!(decode_plan(&too_large).is_err());
    assert!(
        encode_row(&pending).is_err(),
        "pending-only fit cannot admit a plan"
    );
}

#[test]
fn typed_plan_encoder_rejects_combined_size_before_pending_would_overflow() {
    fn extended(n: usize) -> PhysicalPlan {
        let mut plan = plan();
        let parent = format!("/work{}", "/x".repeat(n));
        plan.original_parent.path = path_hex(parent.as_bytes());
        plan.original.path = path_hex(format!("{parent}/checkout").as_bytes());
        plan
    }
    let (mut low, mut high) = (0, 1024);
    assert!(encode_plan_with_result_capacity(&extended(low)).is_ok());
    assert!(encode_plan_with_result_capacity(&extended(high)).is_err());
    while high - low > 1 {
        let middle = (low + high) / 2;
        if encode_plan_with_result_capacity(&extended(middle)).is_ok() {
            low = middle;
        } else {
            high = middle;
        }
    }
    let rejected = extended(high);
    let encoded = serde_json::to_string(&rejected).unwrap();
    assert!(encoded.len() < MAX_ROW_BYTES);
    assert!(
        serde_json::to_string(&row(&rejected, &encoded, ActionState::MovePending))
            .unwrap()
            .len()
            < MAX_ROW_BYTES
    );
    assert!(
        serde_json::to_string(&widest_row(&rejected, &encoded))
            .unwrap()
            .len()
            > MAX_ROW_BYTES
    );
    assert!(encode_plan_with_result_capacity(&rejected).is_err());
}

fn schema_with(ddl: &str) -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    // Deliberately only SQL parent keys, not valid positive retirement history.
    conn.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE checkouts(id TEXT PRIMARY KEY); CREATE TABLE retirement_intents(operation TEXT PRIMARY KEY);").unwrap();
    conn.execute_batch(ddl).unwrap();
    conn.execute("INSERT INTO checkouts VALUES (?1)", [CHECKOUT])
        .unwrap();
    conn.execute("INSERT INTO retirement_intents VALUES (?1)", [OP])
        .unwrap();
    conn
}

#[test]
fn schema_is_exact_six_columns_with_parent_keys_and_no_version_change() {
    let conn = schema_with(SCHEMA);
    validate_schema(&conn).unwrap();
    assert_eq!(
        conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM pragma_table_info('quarantine_actions')",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        6
    );
    conn.execute(
        "INSERT INTO quarantine_actions VALUES (?1,?2,1,'move_pending','{}',NULL)",
        params![OP, CHECKOUT],
    )
    .unwrap();
    assert!(conn
        .execute(
            "INSERT INTO quarantine_actions VALUES (?1,?2,1,'move_pending','{}',NULL)",
            params![OP, CHECKOUT]
        )
        .is_err());
    assert!(conn
        .execute(
            "INSERT INTO quarantine_actions VALUES (?1,?2,1,'move_pending','{}',NULL)",
            params![CHECKOUT, CHECKOUT]
        )
        .is_err());
    assert!(conn
        .execute("UPDATE quarantine_actions SET checkout=?1", [OP])
        .is_err());
    assert!(conn
        .execute("UPDATE quarantine_actions SET operation=NULL", [])
        .is_err());
}

#[test]
fn ddl_state_matrix_raw_types_and_total_byte_boundary() {
    let conn = schema_with(SCHEMA);
    for state in ["move_pending", "quarantined", "move_uncertain", "retired"] {
        for revision in [0, 1, 2, 3] {
            for outcome in [None, Some("{}")] {
                let valid = matches!(
                    (state, revision, outcome),
                    ("move_pending", 1, None) | ("quarantined" | "move_uncertain", 2, Some(_))
                );
                let inserted = conn.execute(
                    "INSERT INTO quarantine_actions VALUES (?1,?2,?3,?4,'{}',?5)",
                    params![OP, CHECKOUT, revision, state, outcome],
                );
                assert_eq!(inserted.is_ok(), valid, "{state}/{revision}/{outcome:?}");
                conn.execute("DELETE FROM quarantine_actions", []).unwrap();
            }
        }
    }
    let size = MAX_ROW_BYTES - OP.len() - CHECKOUT.len() - 8 - "move_pending".len();
    conn.execute(
        "INSERT INTO quarantine_actions VALUES (?1,?2,1,'move_pending',?3,NULL)",
        params![OP, CHECKOUT, "x".repeat(size)],
    )
    .unwrap();
    assert!(conn
        .execute(
            "UPDATE quarantine_actions SET plan=?1",
            ["x".repeat(size + 1)]
        )
        .is_err());
    assert!(conn
        .execute("UPDATE quarantine_actions SET plan=x'7b7d'", [])
        .is_err());
    assert!(conn
        .execute("UPDATE quarantine_actions SET revision=1.5", [])
        .is_err());
    assert!(conn
        .execute(
            "UPDATE quarantine_actions SET state=x'6d6f76655f70656e64696e67'",
            []
        )
        .is_err());
    conn.execute("DELETE FROM quarantine_actions", []).unwrap();
    let result_size = MAX_ROW_BYTES - OP.len() - CHECKOUT.len() - 8 - "move_uncertain".len() - 2;
    conn.execute(
        "INSERT INTO quarantine_actions VALUES (?1,?2,2,'move_uncertain','{}',?3)",
        params![OP, CHECKOUT, "x".repeat(result_size)],
    )
    .unwrap();
    assert!(conn
        .execute(
            "UPDATE quarantine_actions SET result=?1",
            ["x".repeat(result_size + 1)]
        )
        .is_err());
    assert!(conn
        .execute("UPDATE quarantine_actions SET result=x'7b7d'", [])
        .is_err());
}

#[test]
fn counterfeit_ddl_indexes_and_literal_changes_are_refused() {
    for counterfeit in [
        SCHEMA.replace("'move_pending'", "'MOVE_PENDING'"),
        SCHEMA.replace("revision INTEGER", "revision  INTEGER"),
        SCHEMA.replace("<=8192", "<=8193"),
        SCHEMA.replace(
            "PRIMARY KEY REFERENCES retirement_intents(operation)",
            "PRIMARY KEY",
        ),
        SCHEMA.replace(
            "ON quarantine_actions(checkout)",
            "ON quarantine_actions(operation)",
        ),
        SCHEMA.replace(
            "CREATE INDEX quarantine_actions_checkout",
            "CREATE UNIQUE INDEX quarantine_actions_checkout",
        ),
    ] {
        assert_ne!(counterfeit, SCHEMA);
        let conn = schema_with(&counterfeit);
        assert!(validate_schema(&conn).is_err(), "{counterfeit}");
        // Canonical DDL never silently adopts the preexisting counterfeit table.
        assert!(conn.execute_batch(SCHEMA).is_err());
    }
    for extra in ["CREATE INDEX extra_action_index ON quarantine_actions(state);",
        "CREATE TRIGGER extra_action_trigger AFTER INSERT ON quarantine_actions BEGIN SELECT 1; END;",
        "DROP INDEX quarantine_actions_checkout;",
        "DROP INDEX quarantine_actions_checkout; CREATE INDEX quarantine_actions_checkout ON quarantine_actions(checkout) WHERE revision=1;"] {
        let conn = schema_with(SCHEMA);
        conn.execute_batch(extra).unwrap();
        assert!(validate_schema(&conn).is_err(), "{extra}");
    }
}

#[test]
fn borrowed_sql_columns_are_bounded_and_typed_before_owned_decode() {
    let plan = plan();
    let encoded = encode_plan_with_result_capacity(&plan).unwrap();
    let valid = [
        ValueRef::Text(OP.as_bytes()),
        ValueRef::Text(CHECKOUT.as_bytes()),
        ValueRef::Integer(1),
        ValueRef::Text(b"move_pending"),
        ValueRef::Text(encoded.as_bytes()),
        ValueRef::Null,
    ];
    assert_eq!(
        decode_columns(valid).unwrap(),
        row(&plan, &encoded, ActionState::MovePending)
    );
    let oversized = vec![b'x'; MAX_ROW_BYTES + 1];
    for (column, bad) in [
        (0, ValueRef::Null),
        (0, ValueRef::Blob(OP.as_bytes())),
        (1, ValueRef::Integer(1)),
        (2, ValueRef::Real(1.0)),
        (2, ValueRef::Text(b"1")),
        (3, ValueRef::Blob(b"move_pending")),
        (4, ValueRef::Blob(encoded.as_bytes())),
        (4, ValueRef::Text(&oversized)),
        (4, ValueRef::Text(b"\xff")),
        (5, ValueRef::Text(&oversized)),
        (5, ValueRef::Integer(0)),
    ] {
        let mut values = valid;
        values[column] = bad;
        assert!(decode_columns(values).is_err(), "column {column}");
    }
    let half = vec![b'x'; MAX_ROW_BYTES / 2];
    let values = [
        valid[0],
        valid[1],
        ValueRef::Integer(2),
        ValueRef::Text(b"move_uncertain"),
        ValueRef::Text(&half),
        ValueRef::Text(&half),
    ];
    assert!(decode_columns(values).is_err());
}
