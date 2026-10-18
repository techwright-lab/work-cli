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
        assert!(
            matches!(err, ContractError::MissingIdentity { field: got } if got == field),
            "{field}: {err:?}"
        );
    }
}

#[test]
fn rejects_empty_identity_values() {
    for field in ["actor", "repository", "task", "owner"] {
        let mut value = valid_json();
        value[field] = serde_json::json!("");
        let err = LifecycleEnvelope::from_json(&value.to_string()).expect_err(field);
        assert!(
            matches!(err, ContractError::MissingIdentity { field: got } if got == field),
            "{field}: {err:?}"
        );
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
    assert!(matches!(err, ContractError::NullOwner), "{err:?}");
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
        matches!(err, ContractError::IncompatibleSchema { major: 2, .. }),
        "{err:?}"
    );
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
        assert!(
            matches!(
                err,
                ContractError::UnknownEnum { field: got, value: ref got_value }
                    if got == field && got_value == value
            ),
            "{field}={value}: {err:?}"
        );
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
