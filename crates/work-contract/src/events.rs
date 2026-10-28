use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::identity::{ActorId, CheckoutId, EventId, GroupId, OwnerId, RunId};
use crate::lifecycle::{ExecutionMode, RunOutcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HoldReason {
    UnpreservedChanges,
    UnknownArtifacts,
    UncertainWriters,
    IncompleteInspection,
    PreservationUnverified,
    IdentityMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryReason {
    LeaseTtl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InterruptionReason {
    ExecutionLost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetirementReason {
    AbsenceConfirmed,
}

/// Lifecycle journal events. Unknown required variants are rejected at parse time.
/// These payloads record evidence; no event alone authorizes retirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LifecycleEvent {
    Started {
        id: EventId,
        run_id: RunId,
        group_id: GroupId,
        mode: ExecutionMode,
    },
    Finished {
        id: EventId,
        run_id: RunId,
        outcome: RunOutcome,
    },
    Held {
        id: EventId,
        reason: HoldReason,
    },
    Expired {
        id: EventId,
        reason: ExpiryReason,
    },
    Interrupted {
        id: EventId,
        reason: InterruptionReason,
    },
    Retired {
        id: EventId,
        checkout_id: CheckoutId,
        reason: RetirementReason,
    },
    AttributionGap {
        id: EventId,
        reason: String,
    },
    OwnerEscalation {
        id: EventId,
        from: OwnerId,
        to: OwnerId,
        over_quota: bool,
    },
    Inspection {
        id: EventId,
        digest: String,
    },
    Approval {
        id: EventId,
        operator: ActorId,
        inspection_digest: String,
    },
    Reconciliation {
        id: EventId,
        detail: String,
    },
}

impl LifecycleEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Started { .. } => "started",
            Self::Finished { .. } => "finished",
            Self::Held { .. } => "held",
            Self::Expired { .. } => "expired",
            Self::Interrupted { .. } => "interrupted",
            Self::Retired { .. } => "retired",
            Self::AttributionGap { .. } => "attribution_gap",
            Self::OwnerEscalation { .. } => "owner_escalation",
            Self::Inspection { .. } => "inspection",
            Self::Approval { .. } => "approval",
            Self::Reconciliation { .. } => "reconciliation",
        }
    }

    pub fn id(&self) -> &EventId {
        match self {
            Self::Started { id, .. }
            | Self::Finished { id, .. }
            | Self::Held { id, .. }
            | Self::Expired { id, .. }
            | Self::Interrupted { id, .. }
            | Self::Retired { id, .. }
            | Self::AttributionGap { id, .. }
            | Self::OwnerEscalation { id, .. }
            | Self::Inspection { id, .. }
            | Self::Approval { id, .. }
            | Self::Reconciliation { id, .. } => id,
        }
    }
}
