use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

/// Contract validation failures for identities, IDs, enums, and schema versions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContractError {
    #[error("missing identity: {field}")]
    MissingIdentity { field: &'static str },
    #[error("owner must not be null")]
    NullOwner,
    #[error("unknown {field} value: {value}")]
    UnknownEnum { field: &'static str, value: String },
    #[error("incompatible schema version {major}.{minor}")]
    IncompatibleSchema { major: u32, minor: u32 },
    #[error("invalid {kind} id: {reason}")]
    InvalidId { kind: &'static str, reason: String },
    #[error("invalid json: {0}")]
    Json(String),
}

macro_rules! nonempty_id {
    ($name:ident, $field:literal) => {
        /// Nonempty validated identity. Empty or whitespace-only values are rejected.
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(raw: &str) -> Result<Self, ContractError> {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(ContractError::MissingIdentity { field: $field });
                }
                Ok(Self(trimmed.to_string()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                Self::parse(&raw).map_err(serde::de::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed(stringify!($name))
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                // The explicit Unicode White_Space set matches Rust's str::trim.
                schemars::json_schema!({
                    "type": "string",
                    "pattern": r"[^\t-\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]"
                })
            }
        }
    };
}

nonempty_id!(ActorId, "actor");
nonempty_id!(RepositoryId, "repository");
nonempty_id!(TaskId, "task");
nonempty_id!(OwnerId, "owner");
nonempty_id!(RunRef, "run_ref");
/// A portable, caller-declared execution path. Never OS execution authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ExecutionChain(Vec<ExecutionEntry>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionEntry {
    Orchestrator {
        system: ChainText,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "session_ref"
        )]
        #[schemars(with = "ChainText")]
        session_ref: Option<ChainText>,
    },
    Executor {
        system: ChainText,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "session_ref"
        )]
        #[schemars(with = "ChainText")]
        session_ref: Option<ChainText>,
    },
    Model {
        provider: ChainText,
        model: ChainText,
    },
}

fn session_ref<'de, D: Deserializer<'de>>(d: D) -> Result<Option<ChainText>, D::Error> {
    ChainText::deserialize(d).map(Some)
}

/// Bounded, nonblank, control-free text; exact declared values are retained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ChainText(String);
impl ChainText {
    pub fn new(value: String) -> Result<Self, ContractError> {
        if value.trim().is_empty()
            || value.chars().count() > 4096
            || value.chars().any(char::is_control)
        {
            return Err(ContractError::InvalidId {
                kind: "execution_chain",
                reason: "invalid scalar".into(),
            });
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for ChainText {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
impl JsonSchema for ChainText {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ChainText".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({"type":"string", "maxLength":4096,
            "allOf":[{"pattern":r"[^\t-\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]"}, {"pattern":r"^[^\u0000-\u001f\u007f-\u009f]*$"}]})
    }
}
impl ExecutionChain {
    pub fn new(entries: Vec<ExecutionEntry>) -> Result<Self, ContractError> {
        if entries.is_empty()
            || entries.len() > 32
            || !entries.iter().any(|e| {
                matches!(
                    e,
                    ExecutionEntry::Orchestrator { .. } | ExecutionEntry::Executor { .. }
                )
            })
        {
            return Err(ContractError::InvalidId {
                kind: "execution_chain",
                reason: "expected 1..32 entries including an executor or orchestrator".into(),
            });
        }
        Ok(Self(entries))
    }
    pub fn entries(&self) -> &[ExecutionEntry] {
        &self.0
    }
}
impl<'de> Deserialize<'de> for ExecutionChain {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(Vec::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
impl JsonSchema for ExecutionChain {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ExecutionChain".into()
    }
    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let entry = generator.subschema_for::<ExecutionEntry>();
        schemars::json_schema!({"type":"array", "minItems":1, "maxItems":32, "items":entry,
            "contains":{"type":"object", "required":["kind"], "properties":{"kind":{"enum":["orchestrator","executor"]}}}})
    }
}

macro_rules! uuidv7_id {
    ($name:ident, $kind:literal) => {
        /// Time-ordered UUIDv7 identity. Other UUID versions are rejected.
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub fn generate() -> Self {
                Self(Uuid::now_v7())
            }

            pub fn parse(raw: &str) -> Result<Self, ContractError> {
                let uuid = Uuid::parse_str(raw).map_err(|err| ContractError::InvalidId {
                    kind: $kind,
                    reason: err.to_string(),
                })?;
                if !raw.eq_ignore_ascii_case(&uuid.hyphenated().to_string()) {
                    return Err(ContractError::InvalidId {
                        kind: $kind,
                        reason: "expected a hyphenated UUID".into(),
                    });
                }
                Self::from_uuid(uuid)
            }

            fn from_uuid(uuid: Uuid) -> Result<Self, ContractError> {
                let version = uuid.get_version_num();
                if version != 7 || uuid.get_variant() != uuid::Variant::RFC4122 {
                    return Err(ContractError::InvalidId {
                        kind: $kind,
                        reason: format!("expected UUIDv7, got version {version}"),
                    });
                }
                Ok(Self(uuid))
            }

            pub fn version(&self) -> u8 {
                u8::try_from(self.0.get_version_num()).unwrap_or(0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                Self::parse(&raw).map_err(serde::de::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed(stringify!($name))
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                schemars::json_schema!({
                    "type": "string",
                    "format": "uuid",
                    "pattern": r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
                })
            }
        }
    };
}

uuidv7_id!(AllocationOperationId, "allocation_operation");
uuidv7_id!(CheckoutId, "checkout");
uuidv7_id!(RunId, "run");
uuidv7_id!(GroupId, "group");
uuidv7_id!(EventId, "event");

/// Actor + canonical repository + task lookup key. Never an allocation operation ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReuseKey {
    actor: ActorId,
    repository: RepositoryId,
    task: TaskId,
}

impl ReuseKey {
    pub fn new(actor: ActorId, repository: RepositoryId, task: TaskId) -> Self {
        Self {
            actor,
            repository,
            task,
        }
    }

    pub fn actor(&self) -> &ActorId {
        &self.actor
    }

    pub fn repository(&self) -> &RepositoryId {
        &self.repository
    }

    pub fn task(&self) -> &TaskId {
        &self.task
    }
}
