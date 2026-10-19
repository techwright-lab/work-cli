//! Historical reconciliation. Unknown child hosts remain explicit proof barriers.
//! Never launch, signal, finish or uncharge.
use crate::{
    scope_driver::{Driver, RuntimeContext},
    store::{Result, Store, StoreError},
};
use serde::Serialize;
use work_contract::RunId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RecoveryState {
    Closed,
    AlreadyClosed,
    Held {
        reason: &'static str,
        charges_retained: bool,
    },
}
#[derive(Debug, Serialize)]
pub struct HistoricalStatus {
    pub record: crate::run_journal::RunRecord,
    pub runtime: &'static str,
    pub child_enrollment: &'static str,
    pub lease_charged: bool,
    /// Explicit completion is recorded separately from root run outcomes.
    pub task_open: bool,
}
/// Historical metadata only: never scope inspection or an actual exit-code claim.
pub fn status(store: &Store, run: &RunId) -> Result<HistoricalStatus> {
    let (record, lease_charged, task_open) = store.run_status_record(run)?;
    let child_enrollment = if record.children.iter().any(|child| child.host.is_some()) {
        "enrollment recorded; runtime not inspected now"
    } else {
        "no positive enrollment recorded; runtime not inspected now"
    };
    Ok(HistoricalStatus {
        child_enrollment,
        record,
        runtime: "not_inspected",
        lease_charged,
        task_open,
    })
}
fn configured_paths(
    config: &crate::config::Config,
) -> Result<(&std::path::Path, &std::path::Path)> {
    let registry = config
        .trusted_registry
        .as_deref()
        .ok_or(StoreError::Unsafe)?;
    let dir = config.store_dir.as_deref().ok_or(StoreError::Unsafe)?;
    if config.roots.is_empty() {
        return Err(StoreError::Unsafe);
    }
    Ok((registry, dir))
}
pub fn command_status(config: &crate::config::Config, run: uuid::Uuid) -> Result<HistoricalStatus> {
    let run = RunId::parse(&run.to_string()).map_err(|_| StoreError::Invalid)?;
    let (registry, dir) = configured_paths(config)?;
    let store = Store::open_existing_registered_readonly(registry, dir, &config.roots)?;
    status(&store, &run)
}
pub fn command_recover(config: &crate::config::Config, run: uuid::Uuid) -> Result<RecoveryState> {
    let run = RunId::parse(&run.to_string()).map_err(|_| StoreError::Invalid)?;
    let (registry, dir) = configured_paths(config)?;
    let mut store = Store::open_existing_registered_mut(registry, dir, &config.roots)?;
    if let Some(receipt) = historical_receipt(&store, &run)? {
        return Ok(receipt);
    }
    // No current or historical actor/Git profile is consulted for reconciliation.
    let driver = config.supervisor.as_ref().and_then(|policy| {
        RuntimeContext::new(policy.runtime_directory.clone(), policy.bus_address.clone())
            .ok()
            .and_then(|context| Driver::new(context).ok())
    });
    let Some(driver) = driver else {
        return Ok(RecoveryState::Held {
            reason: "runtime inspection unavailable",
            charges_retained: true,
        });
    };
    recover(&mut store, &run, &driver)
}
fn historical_receipt(store: &Store, run: &RunId) -> Result<Option<RecoveryState>> {
    let (record, _, _) = store.run_status_record(run)?;
    Ok(if record.closed {
        Some(RecoveryState::AlreadyClosed)
    } else if record.binding.is_none() {
        Some(RecoveryState::Held {
            reason: "unbound intent: historical proof unsupported",
            charges_retained: true,
        })
    } else if record
        .children
        .iter()
        .any(|child| child.enrollment != crate::run_participants::Enrollment::Contained)
    {
        Some(RecoveryState::Held {
            reason: "unverified child execution host; charges retained",
            charges_retained: true,
        })
    } else {
        None
    })
}
/// Try only a fresh writer handoff. Looking at an active or uncertain run does
/// not mutate its journal, fabricate an outcome, or refresh a heartbeat.
pub fn recover(store: &mut Store, run: &RunId, driver: &Driver) -> Result<RecoveryState> {
    if let Some(receipt) = historical_receipt(store, run)? {
        return Ok(receipt);
    }
    let snapshot = store.group_snapshot(run)?;
    let proof = match snapshot.certify_historical_empty(driver) {
        Ok(proof) => proof,
        Err(_) => {
            return Ok(RecoveryState::Held {
                reason: "runtime active or uncertain; charges retained",
                charges_retained: true,
            })
        }
    };
    store.close_supervised_group(&snapshot, &proof)?;
    Ok(RecoveryState::Closed)
}
