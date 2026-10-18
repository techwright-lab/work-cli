use std::borrow::Cow;
use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize};

use crate::events::LifecycleEvent;
use crate::identity::{
    ActorId, AllocationOperationId, CheckoutId, ContractError, ExecutionChain, GroupId, OwnerId,
    RepositoryId, RunId, RunRef, TaskId,
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
        let invalid = || ContractError::Json(format!("invalid schema_version: {raw}"));
        let (major, minor) = raw.split_once('.').ok_or_else(invalid)?;
        let canonical = |part: &str| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == "0" || !part.starts_with('0'))
        };
        if !canonical(major) || !canonical(minor) {
            return Err(invalid());
        }
        let major = major.parse::<u32>().map_err(|_| invalid())?;
        let minor = minor.parse::<u32>().map_err(|_| invalid())?;
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

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for SchemaVersion {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("SchemaVersion")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        // Canonical major 1 plus a decimal u32 minor, including its upper bound.
        schemars::json_schema!({
            "type": "string",
            "pattern": r"^1\.(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]|429496729[0-5])$"
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    Supervised,
    Adopted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunOutcome {
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttributionDelivery {
    NotConfigured,
    Pending,
    Delivered,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskCompletion {
    Open,
    Finished,
}

/// Versioned lifecycle document. Owner and events are required and cannot be null.
/// JSON Schema validates fields; operation/entity ID separation is additionally
/// enforced by Deserialize, since JSON Schema cannot compare arbitrary fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct LifecycleEnvelope {
    pub schema_version: SchemaVersion,
    pub operation_id: AllocationOperationId,
    pub checkout_id: CheckoutId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<GroupId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_ref: Option<RunRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_run_ref: Option<RunRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_chain: Option<ExecutionChain>,
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

// Serde's remote derive constructs the public type without a second manual JSON
// parser. The only custom deserialization step is the cross-field invariant.
#[derive(Deserialize)]
#[serde(remote = "LifecycleEnvelope")]
struct EnvelopeFields {
    schema_version: SchemaVersion,
    operation_id: AllocationOperationId,
    checkout_id: CheckoutId,
    run_id: Option<RunId>,
    group_id: Option<GroupId>,
    run_ref: Option<RunRef>,
    parent_run_ref: Option<RunRef>,
    execution_chain: Option<ExecutionChain>,
    actor: ActorId,
    repository: RepositoryId,
    task: TaskId,
    owner: OwnerId,
    mode: ExecutionMode,
    lifecycle: CheckoutLifecycle,
    run_outcome: Option<RunOutcome>,
    delivery: AttributionDelivery,
    task_completion: TaskCompletion,
    events: Vec<LifecycleEvent>,
}

impl<'de> Deserialize<'de> for LifecycleEnvelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let envelope = EnvelopeFields::deserialize(deserializer)?;
        envelope.validate().map_err(serde::de::Error::custom)?;
        Ok(envelope)
    }
}

impl LifecycleEnvelope {
    pub fn from_json(json: &str) -> Result<Self, ContractError> {
        serde_json::from_str(json).map_err(|err| ContractError::Json(err.to_string()))
    }

    pub fn to_json(&self) -> Result<String, ContractError> {
        self.validate()?;
        serde_json::to_string_pretty(self).map_err(|err| ContractError::Json(err.to_string()))
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        let operation = self.operation_id.to_string();
        let check = |kind, id: String| {
            if id == operation {
                Err(ContractError::InvalidId {
                    kind,
                    reason: "allocation operation ID must not be reused as an entity ID".into(),
                })
            } else {
                Ok(())
            }
        };
        check("checkout", self.checkout_id.to_string())?;
        if let Some(id) = &self.run_id {
            check("run", id.to_string())?;
        }
        if let Some(id) = &self.group_id {
            check("group", id.to_string())?;
        }
        for event in &self.events {
            check("event", event.id().to_string())?;
            match event {
                LifecycleEvent::Started {
                    run_id, group_id, ..
                } => {
                    check("run", run_id.to_string())?;
                    check("group", group_id.to_string())?;
                }
                LifecycleEvent::Finished { run_id, .. } => check("run", run_id.to_string())?,
                LifecycleEvent::Retired { checkout_id, .. } => {
                    check("checkout", checkout_id.to_string())?
                }
                _ => {}
            }
        }
        Ok(())
    }
}
