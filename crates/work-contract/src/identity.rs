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
nonempty_id!(ExecutionChain, "execution_chain");

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
