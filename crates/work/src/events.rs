use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    AttributionGapRecorded {
        checkout: Uuid,
        group: Uuid,
        run: Uuid,
        event_id: Uuid,
    },
    CaptureFinalizationChanged {
        checkout: Uuid,
        run: Uuid,
        operation: Uuid,
        revision: u64,
        change: crate::capture_finalization::Change,
    },
    TaskFinished {
        checkout: Uuid,
        operation: Uuid,
    },
    FinishCaptureResult {
        checkout: Uuid,
        operation: Uuid,
    },
    AdoptedJournalChanged {
        checkout: Uuid,
        group: Uuid,
        run: Uuid,
        revision: u64,
    },
    RunJournalChanged {
        checkout: Uuid,
        group: Uuid,
        run: Uuid,
        revision: u64,
        change: crate::run_journal::JournalChange,
    },
    AllocationStage {
        checkout: Uuid,
        operation: Uuid,
        stage: String,
        reason: Option<String>,
    },
    /// Observed ancestry, not evidence of process authorship.
    HeadAdvanced {
        checkout: Uuid,
        old: String,
        new: String,
    },
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
    RetirementIntentChanged {
        checkout: Uuid,
        operation: Uuid,
        revision: u64,
        stage: String,
        reason: Option<String>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEvent {
    pub sequence: i64,
    pub event: Event,
}
