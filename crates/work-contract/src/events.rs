use schemars::JsonSchema;
use serde::Serialize;

use crate::identity::{ActorId, EventId, OwnerId};

/// Lifecycle journal events. Unknown required variants are rejected at parse time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LifecycleEvent {
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
            Self::AttributionGap { .. } => "attribution_gap",
            Self::OwnerEscalation { .. } => "owner_escalation",
            Self::Inspection { .. } => "inspection",
            Self::Approval { .. } => "approval",
            Self::Reconciliation { .. } => "reconciliation",
        }
    }
}
