use work_contract::{
    lifecycle_v1_schema_json, ActorId, AllocationOperationId, AttributionDelivery, CheckoutId,
    CheckoutLifecycle, ContractError, EventId, ExecutionMode, GroupId, LifecycleEnvelope,
    LifecycleEvent, OwnerId, RepositoryId, ReuseKey, RunId, RunOutcome, SchemaVersion,
    TaskCompletion, TaskId,
};

const OP: &str = "018f4b2e-8c3a-7d91-8a2b-0123456789ab";
const CHECKOUT: &str = "018f4b2e-8c3a-7d92-8a2b-0123456789ac";
const RUN: &str = "018f4b2e-8c3a-7d93-8a2b-0123456789ad";
const GROUP: &str = "018f4b2e-8c3a-7d94-8a2b-0123456789ae";
const EVENT_GAP: &str = "018f4b2e-8c3a-7d95-8a2b-0123456789af";
const EVENT_ESC: &str = "018f4b2e-8c3a-7d96-8a2b-0123456789b0";
const EVENT_INSP: &str = "018f4b2e-8c3a-7d97-8a2b-0123456789b1";
const EVENT_APPR: &str = "018f4b2e-8c3a-7d98-8a2b-0123456789b2";
const EVENT_RECON: &str = "018f4b2e-8c3a-7d99-8a2b-0123456789b3";
const UUID_V4: &str = "550e8400-e29b-41d4-a716-446655440000";

fn valid_json() -> serde_json::Value {
    serde_json::json!({
        "schema_version": "1.0",
        "operation_id": OP,
        "checkout_id": CHECKOUT,
        "run_id": RUN,
        "group_id": GROUP,
        "run_ref": "run:implementation",
        "parent_run_ref": "run:root",
        "execution_chain": "chain:task-1",
        "actor": "agent-1",
        "repository": "https://git.example.invalid/acme/app.git",
        "task": "TASK-1",
        "owner": "agent-1",
        "mode": "supervised",
        "lifecycle": "ready",
        "run_outcome": "completed",
        "delivery": "pending",
        "task_completion": "open",
        "events": [
            {
                "type": "attribution_gap",
                "id": EVENT_GAP,
                "reason": "attribution disabled"
            },
            {
                "type": "owner_escalation",
                "id": EVENT_ESC,
                "from": "agent-1",
                "to": "operator",
                "over_quota": true
            },
            {
                "type": "inspection",
                "id": EVENT_INSP,
                "digest": "sha256:deadbeef"
            },
            {
                "type": "approval",
                "id": EVENT_APPR,
                "operator": "operator",
                "inspection_digest": "sha256:deadbeef"
            },
            {
                "type": "reconciliation",
                "id": EVENT_RECON,
                "detail": "boot-id changed"
            }
        ]
    })
}

fn parse_valid() -> LifecycleEnvelope {
    LifecycleEnvelope::from_json(&valid_json().to_string()).expect("valid envelope")
}

#[test]
fn schema_round_trip_preserves_lifecycle_envelope() {
    let parsed = parse_valid();
    assert_eq!(parsed.schema_version, SchemaVersion::V1);
    assert_eq!(parsed.operation_id.to_string(), OP);
    assert_eq!(parsed.checkout_id.to_string(), CHECKOUT);
    assert_eq!(
        parsed.run_id.as_ref().map(ToString::to_string).as_deref(),
        Some(RUN)
    );
    assert_eq!(
        parsed.group_id.as_ref().map(ToString::to_string).as_deref(),
        Some(GROUP)
    );
    assert_eq!(parsed.actor.as_str(), "agent-1");
    assert_eq!(
        parsed.repository.as_str(),
        "https://git.example.invalid/acme/app.git"
    );
    assert_eq!(parsed.task.as_str(), "TASK-1");
    assert_eq!(parsed.owner.as_str(), "agent-1");
    assert_eq!(parsed.mode, ExecutionMode::Supervised);
    assert_eq!(parsed.lifecycle, CheckoutLifecycle::Ready);
    assert_eq!(parsed.run_outcome, Some(RunOutcome::Completed));
    assert_eq!(parsed.delivery, AttributionDelivery::Pending);
    assert_eq!(parsed.task_completion, TaskCompletion::Open);

    let json = parsed.to_json().expect("serialize");
    let again = LifecycleEnvelope::from_json(&json).expect("deserialize after serialize");
    assert_eq!(parsed, again);
}

#[test]
fn event_variants_include_required_kinds() {
    let parsed = parse_valid();
    let kinds: Vec<_> = parsed.events.iter().map(LifecycleEvent::kind).collect();
    for required in [
        "attribution_gap",
        "owner_escalation",
        "inspection",
        "approval",
        "reconciliation",
    ] {
        assert!(
            kinds.contains(&required),
            "missing event kind {required} in {kinds:?}"
        );
    }
}

#[test]
fn rejects_missing_identity_fields() {
    for field in ["actor", "repository", "task"] {
        let mut value = valid_json();
        value.as_object_mut().expect("object").remove(field);
        let err = LifecycleEnvelope::from_json(&value.to_string()).expect_err(field);
        assert!(err.to_string().contains(field), "{field}: {err:?}");
    }
}

#[test]
fn rejects_empty_identity_values() {
    for field in ["actor", "repository", "task", "owner"] {
        let mut value = valid_json();
        value[field] = serde_json::json!("");
        let err = LifecycleEnvelope::from_json(&value.to_string()).expect_err(field);
        assert!(err.to_string().contains(field), "{field}: {err:?}");
    }

    assert!(matches!(
        ActorId::parse(""),
        Err(ContractError::MissingIdentity { field: "actor" })
    ));
    assert!(matches!(
        ActorId::parse("   "),
        Err(ContractError::MissingIdentity { field: "actor" })
    ));
    assert!(matches!(
        OwnerId::parse(""),
        Err(ContractError::MissingIdentity { field: "owner" })
    ));
}

#[test]
fn rejects_null_owner() {
    let mut value = valid_json();
    value["owner"] = serde_json::Value::Null;
    let err = LifecycleEnvelope::from_json(&value.to_string()).expect_err("null owner");
    assert!(err.to_string().contains("invalid type: null"), "{err:?}");
}

#[test]
fn rejects_incompatible_schema_major() {
    let err = SchemaVersion::parse("2.0").expect_err("major 2");
    assert!(
        matches!(
            err,
            ContractError::IncompatibleSchema { major: 2, minor: 0 }
        ),
        "{err:?}"
    );

    let mut value = valid_json();
    value["schema_version"] = serde_json::json!("2.0");
    let err = LifecycleEnvelope::from_json(&value.to_string()).expect_err("envelope major 2");
    assert!(
        err.to_string().contains("incompatible schema version 2.0"),
        "{err:?}"
    );
}

#[test]
fn serialization_rejects_unsupported_schema_major() {
    let mut envelope = parse_valid();
    envelope.schema_version = SchemaVersion { major: 2, minor: 0 };
    assert!(envelope.validate().is_err());
    assert!(envelope.to_json().is_err());
    assert!(serde_json::to_string(&envelope).is_err());
}

#[test]
fn serialization_preserves_supported_schema_minors_and_optional_omission() {
    for version in ["1.0", "1.1", "1.4294967295"] {
        let mut envelope = parse_valid();
        envelope.schema_version = SchemaVersion::parse(version).unwrap();
        envelope.run_id = None;
        let value = serde_json::to_value(&envelope).unwrap();
        assert_eq!(value["schema_version"], version);
        assert!(value.get("run_id").is_none());
        assert_eq!(
            serde_json::from_value::<LifecycleEnvelope>(value).unwrap(),
            envelope
        );
    }
}

#[test]
fn serialization_rejects_operation_entity_aliases() {
    for field in ["checkout_id", "run_id", "group_id", "event_id"] {
        let mut envelope = parse_valid();
        match field {
            "checkout_id" => envelope.checkout_id = CheckoutId::parse(OP).unwrap(),
            "run_id" => envelope.run_id = Some(RunId::parse(OP).unwrap()),
            "group_id" => envelope.group_id = Some(GroupId::parse(OP).unwrap()),
            "event_id" => {
                let mut event = valid_json()["events"][0].clone();
                event["id"] = serde_json::json!(OP);
                envelope.events = vec![serde_json::from_value(event).unwrap()];
            }
            _ => unreachable!(),
        }
        assert!(serde_json::to_string(&envelope).is_err(), "{field}");
    }
    for event in core_events() {
        for field in ["run_id", "group_id", "checkout_id"] {
            if event.get(field).is_some() {
                let mut envelope = parse_valid();
                let mut invalid = event.clone();
                invalid[field] = serde_json::json!(OP);
                envelope.events = vec![serde_json::from_value(invalid).unwrap()];
                assert!(serde_json::to_string(&envelope).is_err(), "event {field}");
            }
        }
    }
}

#[test]
fn rejects_unknown_required_enums() {
    let cases = [
        ("mode", "telepathy"),
        ("lifecycle", "haunted"),
        ("run_outcome", "abandoned"),
        ("delivery", "faxed"),
        ("task_completion", "sorta"),
    ];
    for (field, value) in cases {
        let mut json = valid_json();
        json[field] = serde_json::json!(value);
        let err = LifecycleEnvelope::from_json(&json.to_string()).expect_err(field);
        assert!(err.to_string().contains(value), "{field}={value}: {err:?}");
    }
}

#[test]
fn allocation_operation_id_is_uuidv7_and_distinct_from_other_ids() {
    let operation = AllocationOperationId::generate();
    let checkout = CheckoutId::generate();
    let run = RunId::generate();
    let group = GroupId::generate();
    let event = EventId::generate();

    assert_eq!(operation.version(), 7);
    assert_eq!(checkout.version(), 7);
    assert_eq!(run.version(), 7);
    assert_eq!(group.version(), 7);
    assert_eq!(event.version(), 7);

    let mut values = std::collections::BTreeSet::new();
    assert!(values.insert(operation.to_string()));
    assert!(values.insert(checkout.to_string()));
    assert!(values.insert(run.to_string()));
    assert!(values.insert(group.to_string()));
    assert!(values.insert(event.to_string()));

    let parsed = AllocationOperationId::parse(OP).expect("fixture v7");
    assert_eq!(parsed.version(), 7);
    assert_eq!(parsed.to_string(), OP);

    let err = AllocationOperationId::parse(UUID_V4).expect_err("v4");
    assert!(
        matches!(
            err,
            ContractError::InvalidId {
                kind: "allocation_operation",
                ..
            }
        ),
        "{err:?}"
    );
    assert!(CheckoutId::parse(UUID_V4).is_err());
    assert!(RunId::parse(UUID_V4).is_err());
    assert!(GroupId::parse(UUID_V4).is_err());
    assert!(EventId::parse(UUID_V4).is_err());
}

#[test]
fn reuse_key_is_actor_repository_task_not_operation_id() {
    let actor = ActorId::parse("agent-1").expect("actor");
    let repository =
        RepositoryId::parse("https://git.example.invalid/acme/app.git").expect("repository");
    let task = TaskId::parse("TASK-1").expect("task");
    let key = ReuseKey::new(actor.clone(), repository.clone(), task.clone());

    assert_eq!(key.actor(), &actor);
    assert_eq!(key.repository(), &repository);
    assert_eq!(key.task(), &task);

    let joined = format!("{}:{}:{}", actor, repository, task);
    let err = AllocationOperationId::parse(&joined).expect_err("reuse key is not an operation id");
    assert!(
        matches!(
            err,
            ContractError::InvalidId {
                kind: "allocation_operation",
                ..
            }
        ),
        "{err:?}"
    );

    let operation = AllocationOperationId::generate();
    assert_ne!(operation.to_string(), joined);
}

#[test]
fn metadata_round_trips_without_being_discarded() {
    let parsed = parse_valid();
    assert_eq!(
        parsed.run_ref.as_ref().unwrap().as_str(),
        "run:implementation"
    );
    assert_eq!(parsed.parent_run_ref.as_ref().unwrap().as_str(), "run:root");
    assert_eq!(
        parsed.execution_chain.as_ref().unwrap().as_str(),
        "chain:task-1"
    );
    let serialized: serde_json::Value = serde_json::from_str(&parsed.to_json().unwrap()).unwrap();
    for field in ["run_ref", "parent_run_ref", "execution_chain"] {
        assert_eq!(serialized[field], valid_json()[field], "{field}");
    }
}

fn core_events() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({"type":"started", "id":EVENT_GAP, "run_id":RUN, "group_id":GROUP, "mode":"supervised"}),
        serde_json::json!({"type":"finished", "id":EVENT_GAP, "run_id":RUN, "outcome":"completed"}),
        serde_json::json!({"type":"held", "id":EVENT_GAP, "reason":"unpreserved_changes"}),
        serde_json::json!({"type":"expired", "id":EVENT_GAP, "reason":"lease_ttl"}),
        serde_json::json!({"type":"interrupted", "id":EVENT_GAP, "reason":"execution_lost"}),
        serde_json::json!({"type":"retired", "id":EVENT_GAP, "checkout_id":CHECKOUT, "reason":"absence_confirmed"}),
    ]
}

#[test]
fn core_lifecycle_events_have_typed_payloads() {
    for event in core_events() {
        let mut value = valid_json();
        value["events"] = serde_json::json!([event]);
        let parsed = LifecycleEnvelope::from_json(&value.to_string()).expect("core event");
        assert_eq!(parsed.events[0].kind(), event["type"]);
        let serialized: serde_json::Value =
            serde_json::from_str(&parsed.to_json().unwrap()).unwrap();
        assert_eq!(serialized["events"][0], event);
    }
}

#[test]
fn schema_validation_matches_runtime_constraints() {
    let schema: serde_json::Value = serde_json::from_str(&lifecycle_v1_schema_json()).unwrap();
    let validator = jsonschema::validator_for(&schema).expect("generated schema compiles");
    let mut failures = Vec::new();
    let mut check = |label: &str, value: serde_json::Value, expected: bool| {
        if validator.is_valid(&value) != expected {
            failures.push(format!("schema: {label}"));
        }
        if LifecycleEnvelope::from_json(&value.to_string()).is_ok() != expected {
            failures.push(format!("runtime: {label}"));
        }
        if serde_json::from_value::<LifecycleEnvelope>(value).is_ok() != expected {
            failures.push(format!("serde: {label}"));
        }
    };
    check("baseline", valid_json(), true);
    for event in core_events() {
        let mut value = valid_json();
        value["events"] = serde_json::json!([event]);
        check("core event", value.clone(), true);
        let fields: Vec<_> = event.as_object().unwrap().keys().cloned().collect();
        for field in fields {
            let mut invalid = value.clone();
            invalid["events"][0].as_object_mut().unwrap().remove(&field);
            check(&format!("event missing {field}"), invalid, false);
        }
        for field in ["mode", "outcome", "reason"] {
            if event.get(field).is_some() {
                let mut invalid = value.clone();
                invalid["events"][0][field] = serde_json::json!("unsupported");
                check("unknown event enum", invalid, false);
            }
        }
    }
    for field in [
        "actor",
        "repository",
        "task",
        "owner",
        "run_ref",
        "parent_run_ref",
        "execution_chain",
    ] {
        for blank in ["", " ", "\t\n", "\u{a0}"] {
            let mut value = valid_json();
            value[field] = serde_json::json!(blank);
            check(field, value, false);
        }
    }
    for field in ["operation_id", "checkout_id", "run_id", "group_id"] {
        for invalid in [
            UUID_V4,
            "not-a-uuid",
            "018f4b2e8c3a7d918a2b0123456789ab",
            "018f4b2e-8c3a-7d91-1a2b-0123456789ab",
        ] {
            let mut value = valid_json();
            value[field] = serde_json::json!(invalid);
            check(field, value, false);
        }
    }
    for version in [
        "1",
        "01.0",
        "1.00",
        "1.+1",
        "1.0.extra",
        "1.0.0",
        "1.0-beta",
        " 1.0",
        "2.0",
        "1.4294967296",
    ] {
        let mut value = valid_json();
        value["schema_version"] = serde_json::json!(version);
        check(version, value, false);
    }
    for version in ["1.0", "1.1", "1.4294967295"] {
        let mut value = valid_json();
        value["schema_version"] = serde_json::json!(version);
        check(version, value, true);
    }
    for field in ["actor", "repository", "task", "owner", "events"] {
        let mut value = valid_json();
        value.as_object_mut().unwrap().remove(field);
        check(&format!("missing {field}"), value, false);
        let mut value = valid_json();
        value[field] = serde_json::Value::Null;
        check(&format!("null {field}"), value, false);
    }
    let mut value = valid_json();
    value["events"][0]["id"] = serde_json::json!(UUID_V4);
    check("event UUIDv4", value, false);
    assert!(failures.is_empty(), "parity failures: {failures:#?}");
}

#[test]
fn allocation_operation_cannot_alias_entity_ids() {
    for field in ["checkout_id", "run_id", "group_id"] {
        let mut value = valid_json();
        value[field] = serde_json::json!(OP);
        assert!(
            LifecycleEnvelope::from_json(&value.to_string()).is_err(),
            "{field}"
        );
        assert!(
            serde_json::from_value::<LifecycleEnvelope>(value).is_err(),
            "serde {field}"
        );
    }
    let mut value = valid_json();
    value["events"][0]["id"] = serde_json::json!(OP);
    assert!(
        LifecycleEnvelope::from_json(&value.to_string()).is_err(),
        "event id"
    );
    assert!(
        serde_json::from_value::<LifecycleEnvelope>(value.clone()).is_err(),
        "serde event id"
    );
    for event in core_events() {
        for field in ["run_id", "group_id", "checkout_id"] {
            if event.get(field).is_some() {
                let mut invalid = event.clone();
                invalid[field] = serde_json::json!(OP);
                value["events"] = serde_json::json!([invalid]);
                assert!(
                    LifecycleEnvelope::from_json(&value.to_string()).is_err(),
                    "event {field}"
                );
            }
        }
    }
}

#[test]
fn checked_in_schema_matches_generated_types() {
    let generated = lifecycle_v1_schema_json();
    assert!(
        !generated.trim().is_empty(),
        "generated schema must not be empty"
    );

    let path = format!("{}/schemas/lifecycle-v1.json", env!("CARGO_MANIFEST_DIR"));
    let checked_in = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        generated, checked_in,
        "checked-in schema drifted from schemars output; regenerate schemas/lifecycle-v1.json"
    );
}
