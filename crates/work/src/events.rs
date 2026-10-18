use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Reserved {
        checkout: Uuid,
        low_disk: bool,
    },
    WriterAcquired {
        checkout: Uuid,
        group: Uuid,
    },
    OwnerTransferred {
        checkout: Uuid,
        from: String,
        to: String,
    },
    OwnerEscalated {
        checkout: Uuid,
        from: String,
        to: String,
        over_quota: bool,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEvent {
    pub sequence: i64,
    pub event: Event,
}
