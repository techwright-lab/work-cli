use std::borrow::Cow;
use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::events::LifecycleEvent;
use crate::identity::{
    ActorId, AllocationOperationId, CheckoutId, ContractError, GroupId, OwnerId, RepositoryId,
    RunId, TaskId,
};

/// Supported schema major version. Unknown majors are rejected.
pub const SCHEMA_MAJOR: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaVersion {
    pub major: u32,
    pub minor: u32,
}

impl SchemaVersion {
    pub const V1: Self = Self {
        major: SCHEMA_MAJOR,
        minor: 0,
    };

    pub fn parse(raw: &str) -> Result<Self, ContractError> {
        let raw = raw.trim();
        let mut parts = raw.split('.');
        let major = parts
            .next()
            .and_then(|part| part.parse::<u32>().ok())
            .ok_or_else(|| ContractError::Json(format!("invalid schema_version: {raw}")))?;
        let minor = match parts.next() {
            Some(part) => part
                .parse::<u32>()
                .map_err(|_| ContractError::Json(format!("invalid schema_version: {raw}")))?,
            None => 0,
        };
        if major != SCHEMA_MAJOR {
            return Err(ContractError::IncompatibleSchema { major, minor });
        }
        Ok(Self { major, minor })
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl Serialize for SchemaVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl JsonSchema for SchemaVersion {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("SchemaVersion")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": r"^[0-9]+\.[0-9]+$"
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    Supervised,
    Adopted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckoutLifecycle {
    Reserved,
    PartiallyCreated,
    Ready,
    Active,
    Expired,
    Interrupted,
    Held,
    Quarantined,
    PartiallyDeleted,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunOutcome {
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttributionDelivery {
    NotConfigured,
    Pending,
    Delivered,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskCompletion {
    Open,
    Finished,
}

/// Versioned lifecycle document. Owner is required and must never be null.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct LifecycleEnvelope {
    pub schema_version: SchemaVersion,
    pub operation_id: AllocationOperationId,
    pub checkout_id: CheckoutId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<GroupId>,
    pub actor: ActorId,
    pub repository: RepositoryId,
    pub task: TaskId,
    pub owner: OwnerId,
    pub mode: ExecutionMode,
    pub lifecycle: CheckoutLifecycle,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_outcome: Option<RunOutcome>,
    pub delivery: AttributionDelivery,
    pub task_completion: TaskCompletion,
    pub events: Vec<LifecycleEvent>,
}

impl LifecycleEnvelope {
    pub fn from_json(json: &str) -> Result<Self, ContractError> {
        let value: Value =
            serde_json::from_str(json).map_err(|err| ContractError::Json(err.to_string()))?;
        Self::from_value(value)
    }

    pub fn to_json(&self) -> Result<String, ContractError> {
        serde_json::to_string_pretty(self).map_err(|err| ContractError::Json(err.to_string()))
    }

    fn from_value(value: Value) -> Result<Self, ContractError> {
        let obj = value
            .as_object()
            .ok_or_else(|| ContractError::Json("expected a JSON object".into()))?;

        let schema_version = SchemaVersion::parse(required_str(obj, "schema_version")?)?;
        let operation_id = AllocationOperationId::parse(required_str(obj, "operation_id")?)?;
        let checkout_id = CheckoutId::parse(required_str(obj, "checkout_id")?)?;
        let run_id = optional_id(obj, "run_id", RunId::parse)?;
        let group_id = optional_id(obj, "group_id", GroupId::parse)?;
        let actor = ActorId::parse(required_identity(obj, "actor")?)?;
        let repository = RepositoryId::parse(required_identity(obj, "repository")?)?;
        let task = TaskId::parse(required_identity(obj, "task")?)?;
        let owner = required_owner(obj)?;
        let mode = required_enum(obj, "mode", parse_mode)?;
        let lifecycle = required_enum(obj, "lifecycle", parse_lifecycle)?;
        let run_outcome = optional_enum(obj, "run_outcome", parse_run_outcome)?;
        let delivery = required_enum(obj, "delivery", parse_delivery)?;
        let task_completion = required_enum(obj, "task_completion", parse_task_completion)?;
        let events = parse_events(obj.get("events"))?;

        Ok(Self {
            schema_version,
            operation_id,
            checkout_id,
            run_id,
            group_id,
            actor,
            repository,
            task,
            owner,
            mode,
            lifecycle,
            run_outcome,
            delivery,
            task_completion,
            events,
        })
    }
}

fn required_str<'a>(
    obj: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, ContractError> {
    match obj.get(field) {
        None => Err(ContractError::Json(format!("missing {field}"))),
        Some(Value::String(value)) => Ok(value.as_str()),
        Some(_) => Err(ContractError::Json(format!("{field} must be a string"))),
    }
}

fn required_identity<'a>(
    obj: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, ContractError> {
    match obj.get(field) {
        None => Err(ContractError::MissingIdentity { field }),
        Some(Value::Null) => Err(ContractError::MissingIdentity { field }),
        Some(Value::String(value)) => {
            if value.trim().is_empty() {
                Err(ContractError::MissingIdentity { field })
            } else {
                Ok(value.as_str())
            }
        }
        Some(_) => Err(ContractError::Json(format!("{field} must be a string"))),
    }
}

fn required_owner(obj: &Map<String, Value>) -> Result<OwnerId, ContractError> {
    match obj.get("owner") {
        None => Err(ContractError::MissingIdentity { field: "owner" }),
        Some(Value::Null) => Err(ContractError::NullOwner),
        Some(Value::String(value)) => OwnerId::parse(value),
        Some(_) => Err(ContractError::Json("owner must be a string".into())),
    }
}

fn optional_id<T>(
    obj: &Map<String, Value>,
    field: &'static str,
    parse: fn(&str) -> Result<T, ContractError>,
) -> Result<Option<T>, ContractError> {
    match obj.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => parse(value).map(Some),
        Some(_) => Err(ContractError::Json(format!("{field} must be a string"))),
    }
}

fn required_enum<T>(
    obj: &Map<String, Value>,
    field: &'static str,
    parse: fn(&str) -> Option<T>,
) -> Result<T, ContractError> {
    let raw = match obj.get(field) {
        None => return Err(ContractError::Json(format!("missing {field}"))),
        Some(Value::String(value)) => value.as_str(),
        Some(other) => {
            return Err(ContractError::UnknownEnum {
                field,
                value: other.to_string(),
            });
        }
    };
    parse(raw).ok_or_else(|| ContractError::UnknownEnum {
        field,
        value: raw.to_string(),
    })
}

fn optional_enum<T>(
    obj: &Map<String, Value>,
    field: &'static str,
    parse: fn(&str) -> Option<T>,
) -> Result<Option<T>, ContractError> {
    match obj.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            parse(value)
                .map(Some)
                .ok_or_else(|| ContractError::UnknownEnum {
                    field,
                    value: value.clone(),
                })
        }
        Some(other) => Err(ContractError::UnknownEnum {
            field,
            value: other.to_string(),
        }),
    }
}

fn parse_events(value: Option<&Value>) -> Result<Vec<LifecycleEvent>, ContractError> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(parse_event).collect(),
        Some(_) => Err(ContractError::Json("events must be an array".into())),
    }
}

fn parse_event(value: &Value) -> Result<LifecycleEvent, ContractError> {
    let obj = value
        .as_object()
        .ok_or_else(|| ContractError::Json("event must be an object".into()))?;
    let kind = required_str(obj, "type")?;
    let id = crate::identity::EventId::parse(required_str(obj, "id")?)?;
    match kind {
        "attribution_gap" => Ok(LifecycleEvent::AttributionGap {
            id,
            reason: required_str(obj, "reason")?.to_string(),
        }),
        "owner_escalation" => Ok(LifecycleEvent::OwnerEscalation {
            id,
            from: OwnerId::parse(required_identity(obj, "from")?)?,
            to: OwnerId::parse(required_identity(obj, "to")?)?,
            over_quota: required_bool(obj, "over_quota")?,
        }),
        "inspection" => Ok(LifecycleEvent::Inspection {
            id,
            digest: required_str(obj, "digest")?.to_string(),
        }),
        "approval" => Ok(LifecycleEvent::Approval {
            id,
            operator: ActorId::parse(required_identity(obj, "operator")?)?,
            inspection_digest: required_str(obj, "inspection_digest")?.to_string(),
        }),
        "reconciliation" => Ok(LifecycleEvent::Reconciliation {
            id,
            detail: required_str(obj, "detail")?.to_string(),
        }),
        other => Err(ContractError::UnknownEnum {
            field: "type",
            value: other.to_string(),
        }),
    }
}

fn required_bool(obj: &Map<String, Value>, field: &'static str) -> Result<bool, ContractError> {
    match obj.get(field) {
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(ContractError::Json(format!("{field} must be a boolean"))),
        None => Err(ContractError::Json(format!("missing {field}"))),
    }
}

fn parse_mode(raw: &str) -> Option<ExecutionMode> {
    match raw {
        "supervised" => Some(ExecutionMode::Supervised),
        "adopted" => Some(ExecutionMode::Adopted),
        _ => None,
    }
}

fn parse_lifecycle(raw: &str) -> Option<CheckoutLifecycle> {
    match raw {
        "reserved" => Some(CheckoutLifecycle::Reserved),
        "partially_created" => Some(CheckoutLifecycle::PartiallyCreated),
        "ready" => Some(CheckoutLifecycle::Ready),
        "active" => Some(CheckoutLifecycle::Active),
        "expired" => Some(CheckoutLifecycle::Expired),
        "interrupted" => Some(CheckoutLifecycle::Interrupted),
        "held" => Some(CheckoutLifecycle::Held),
        "quarantined" => Some(CheckoutLifecycle::Quarantined),
        "partially_deleted" => Some(CheckoutLifecycle::PartiallyDeleted),
        "retired" => Some(CheckoutLifecycle::Retired),
        _ => None,
    }
}

fn parse_run_outcome(raw: &str) -> Option<RunOutcome> {
    match raw {
        "completed" => Some(RunOutcome::Completed),
        "failed" => Some(RunOutcome::Failed),
        "cancelled" => Some(RunOutcome::Cancelled),
        _ => None,
    }
}

fn parse_delivery(raw: &str) -> Option<AttributionDelivery> {
    match raw {
        "not_configured" => Some(AttributionDelivery::NotConfigured),
        "pending" => Some(AttributionDelivery::Pending),
        "delivered" => Some(AttributionDelivery::Delivered),
        "failed" => Some(AttributionDelivery::Failed),
        _ => None,
    }
}

fn parse_task_completion(raw: &str) -> Option<TaskCompletion> {
    match raw {
        "open" => Some(TaskCompletion::Open),
        "finished" => Some(TaskCompletion::Finished),
        _ => None,
    }
}
