//! Versioned lifecycle and identity contract for the `work` CLI.
//!
//! JSON is the cross-project compatibility boundary. Types here generate the
//! checked-in JSON Schema and reject incompatible majors, unknown required
//! enums, missing identities, and a null owner.

#![forbid(unsafe_code)]

mod events;
mod identity;
mod lifecycle;

pub use events::{ExpiryReason, HoldReason, InterruptionReason, LifecycleEvent, RetirementReason};
pub use identity::{
    ActorId, AllocationOperationId, ChainText, CheckoutId, ContractError, EventId, ExecutionChain,
    ExecutionEntry, GroupId, OwnerId, RepositoryId, ReuseKey, RunId, RunRef, TaskId,
};
pub use lifecycle::{
    AttributionDelivery, CheckoutLifecycle, ExecutionMode, LifecycleEnvelope, RunOutcome,
    SchemaVersion, TaskCompletion, SCHEMA_MAJOR,
};

/// Pretty JSON Schema for the v1 lifecycle envelope, including a trailing newline.
pub fn lifecycle_v1_schema_json() -> String {
    let schema = schemars::schema_for!(LifecycleEnvelope);
    let mut json = serde_json::to_string_pretty(&schema).expect("schema serialization");
    if !json.ends_with('\n') {
        json.push('\n');
    }
    json
}
