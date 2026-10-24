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
    pub gap: Option<crate::supervisor::GapObservation>,
    pub gap_limitations: Option<&'static str>,
    pub checkout_state: String,
    pub checkout_ready: bool,
    pub record: crate::run_journal::RunRecord,
    pub runtime: &'static str,
    pub child_enrollment: &'static str,
    pub lease_charged: bool,
    /// Explicit completion is recorded separately from root run outcomes.
    pub task_open: bool,
}
/// Historical metadata only: never scope inspection or an actual exit-code claim.
pub fn status(store: &Store, run: &RunId) -> Result<HistoricalStatus> {
    let _phase = store.sql_phase();
    let _snapshot = crate::run_journal::read_transaction(&store.conn)?;
    let (record, lease_charged, task_open) = store.run_status_record(run)?;
    let (checkout_state, checkout_ready) = store.conn.query_row(
        "SELECT state,ready FROM checkouts WHERE id=?1",
        [record.request.identity().checkout.to_string()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let gap = crate::attribution_gap::observation(&store.conn, &record.request)?;
    let gap_limitations = gap
        .as_ref()
        .filter(|g| matches!(g.origin, "required_initial" | "required_continuation"))
        .map(|_| crate::attribution_gap::REQUIRED_LIMITATIONS);
    let child_enrollment = if record.children.iter().any(|child| child.host.is_some()) {
        "enrollment recorded; runtime not inspected now"
    } else {
        "no positive enrollment recorded; runtime not inspected now"
    };
    Ok(HistoricalStatus {
        gap,
        gap_limitations,
        checkout_state,
        checkout_ready,
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
    let removal = match preflight(&store, &run, RecoveryPolicy::Config(config))? {
        Preflight::Passive(receipt) => return Ok(receipt),
        Preflight::Physical(removal) => removal,
    };
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
    physical_core(&mut store, &run, &driver, removal.as_ref())
}
pub(crate) fn command_recover_document(
    document: &crate::config::ConfigDocument,
    run: uuid::Uuid,
) -> Result<RecoveryState> {
    let config = document.authority().map_err(|_| StoreError::Unsafe)?;
    let run = RunId::parse(&run.to_string()).map_err(|_| StoreError::Invalid)?;
    let (registry, dir) = configured_paths(&config)?;
    let mut store = Store::open_existing_registered_mut(registry, dir, &config.roots)?;
    let removal = match preflight(&store, &run, RecoveryPolicy::Document(document))? {
        Preflight::Passive(receipt) => return Ok(receipt),
        Preflight::Physical(removal) => removal,
    };
    let driver = document.recovery_runtime().ok().and_then(|runtime| {
        RuntimeContext::new(runtime.runtime_directory, runtime.bus_address)
            .ok()
            .and_then(|context| Driver::new(context).ok())
    });
    let Some(driver) = driver else {
        return Ok(RecoveryState::Held {
            reason: "runtime inspection unavailable",
            charges_retained: true,
        });
    };
    physical_core(&mut store, &run, &driver, removal.as_ref())
}
fn historical_receipt(record: &crate::run_journal::RunRecord) -> Option<RecoveryState> {
    if record.closed {
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
    }
}
/// Try only a fresh writer handoff. Looking at an active or uncertain run does
/// not mutate its journal, fabricate an outcome, or refresh a heartbeat.
enum Preflight {
    Passive(RecoveryState),
    Physical(Option<crate::attribution_gap::RecoveryRemoval>),
}
enum RecoveryPolicy<'a> {
    Unavailable,
    Config(&'a crate::config::Config),
    Document(&'a crate::config::ConfigDocument),
}
fn preflight(store: &Store, run: &RunId, policy: RecoveryPolicy<'_>) -> Result<Preflight> {
    // Owned metadata only crosses this frame. No borrowed SQL witness or live authority.
    let (root, gap) = {
        let _phase = store.sql_phase();
        let _snapshot = crate::run_journal::read_transaction(&store.conn)?;
        let (root, _, _) = store.run_status_record(run)?;
        if let Some(receipt) = historical_receipt(&root) {
            return Ok(Preflight::Passive(receipt));
        }
        let gap = if root.request.input().attribution.is_some() {
            Some(crate::attribution_gap::read_record(
                &store.conn,
                &root.request,
            )?)
        } else {
            None
        };
        (root, gap)
    };
    if !store.conn.is_autocommit() {
        return Err(StoreError::Invalid);
    }
    let Some(gap) = gap else {
        return Ok(Preflight::Physical(None));
    };
    let held = || {
        Preflight::Passive(RecoveryState::Held {
            reason: "verified Gap recovery environment unavailable",
            charges_retained: true,
        })
    };
    let selected = match policy {
        RecoveryPolicy::Unavailable => return Ok(held()),
        RecoveryPolicy::Config(config) => config.selected_capture().map(|host| host.cloned()),
        RecoveryPolicy::Document(document) => document.recovery_target(),
    };
    let Ok(selected) = selected else {
        return Ok(held());
    };
    // Retain the validated historical Root through target resolution; no second lookup.
    debug_assert_eq!(&root.request.identity().run, run);
    match crate::attribution_gap::recovery_removal(gap, selected.as_ref()) {
        Ok(removal) => Ok(Preflight::Physical(Some(removal))),
        Err(_) => Ok(held()),
    }
}
pub fn recover_with_config(
    store: &mut Store,
    run: &RunId,
    driver: &Driver,
    config: &crate::config::Config,
) -> Result<RecoveryState> {
    match preflight(store, run, RecoveryPolicy::Config(config))? {
        Preflight::Passive(receipt) => Ok(receipt),
        Preflight::Physical(removal) => physical_core(store, run, driver, removal.as_ref()),
    }
}
pub fn recover(store: &mut Store, run: &RunId, driver: &Driver) -> Result<RecoveryState> {
    match preflight(store, run, RecoveryPolicy::Unavailable)? {
        Preflight::Passive(receipt) => Ok(receipt),
        Preflight::Physical(removal) => physical_core(store, run, driver, removal.as_ref()),
    }
}
fn physical_core(
    store: &mut Store,
    run: &RunId,
    driver: &Driver,
    removal: Option<&crate::attribution_gap::RecoveryRemoval>,
) -> Result<RecoveryState> {
    let filtered = removal.map(|r| driver.for_gap(r.policy()));
    let driver = filtered.as_ref().unwrap_or(driver);
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
#[cfg(test)]
pub(crate) mod document_fixture {
    // Test glue for an owned fake OS, not a production manager-path selector.
    // It invokes the exact historical/policy and physical cores used by CLI.
    pub(crate) fn recover(
        store: &mut super::Store,
        run: &work_contract::RunId,
        document: &crate::config::ConfigDocument,
        driver: &super::Driver,
    ) -> super::Result<super::RecoveryState> {
        match super::preflight(store, run, super::RecoveryPolicy::Document(document))? {
            super::Preflight::Passive(receipt) => Ok(receipt),
            super::Preflight::Physical(removal) => {
                document
                    .recovery_runtime()
                    .map_err(|_| super::StoreError::Invalid)?;
                super::physical_core(store, run, driver, removal.as_ref())
            }
        }
    }
}
