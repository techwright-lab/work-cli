//! Public report shell over the owned prepare and validated offline abort paths.
//! Reports are metadata only, never retirement or writer-release capabilities.
use super::*;
use crate::config::ConfigDocument;
use crate::retirement_journal::{self, find_operation, parse_uuid, read_history, IntentRow};
use crate::store::{Store, StoreError};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, serde::Serialize)]
pub struct RetirementIntentReport {
    checkout: Uuid,
    operation: Option<Uuid>,
    revision: Option<u64>,
    stage: &'static str,
    outcome: &'static str,
    reason: &'static str,
    recorded: &'static str,
    fresh_commit: bool,
    fence_active: bool,
    mode: &'static str,
    history_count: u64,
    execution_enabled: bool,
    retirement_authority: bool,
    writer_charges_retained: bool,
    protection_retained: bool,
}

impl RetirementIntentReport {
    pub fn outcome(&self) -> &str {
        self.outcome
    }
    pub fn reason(&self) -> &str {
        self.reason
    }
    pub fn fence_active(&self) -> bool {
        self.fence_active
    }
    pub fn fresh_commit(&self) -> bool {
        self.fresh_commit
    }
    fn base(checkout: Uuid) -> Self {
        Self {
            checkout,
            operation: None,
            revision: None,
            stage: "none",
            outcome: "held",
            reason: "configuration_unknown",
            recorded: "none",
            fresh_commit: false,
            fence_active: false,
            mode: "unknown",
            history_count: 0,
            execution_enabled: false,
            retirement_authority: false,
            writer_charges_retained: true,
            protection_retained: true,
        }
    }
}

pub fn prepare_retirement(
    config_path: &Path,
    checkout: Uuid,
    operation: Uuid,
    assertion: Option<Uuid>,
    task_complete: bool,
) -> RetirementIntentReport {
    prepare_inner(
        config_path,
        checkout,
        operation,
        assertion,
        task_complete,
        #[cfg(test)]
        None,
        #[cfg(test)]
        retirement::PrepareFault::None,
    )
    .unwrap_or_else(|reason| failed_operation(checkout, operation, reason))
}

pub fn abort_retirement(
    config_path: &Path,
    checkout: Uuid,
    operation: Uuid,
    revision: u64,
) -> RetirementIntentReport {
    abort_inner(
        config_path,
        checkout,
        operation,
        revision,
        #[cfg(test)]
        retirement::AbortFault::None,
    )
    .unwrap_or_else(|reason| failed_operation(checkout, operation, reason))
}

fn failed_operation(
    checkout: Uuid,
    operation: Uuid,
    reason: &'static str,
) -> RetirementIntentReport {
    // These are internal allowlisted reasons, not raw config, SQL or paths.
    // A refusal is not an observation of absence: validation may have held the
    // intent, or authority may be unreadable. Do not open another Store to format
    // the error or label the caller's requested revision as an observed revision.
    let mut report = RetirementIntentReport::base(checkout);
    report.operation = Some(operation);
    report.reason = reason;
    report.stage = "unknown";
    report.recorded = "unknown";
    report.fence_active = true;
    report
}

/// Faithful private offline path; no remote pipeline or SQL-only clearing.
pub(super) fn abort_inner(
    config_path: &Path,
    checkout: Uuid,
    operation: Uuid,
    revision: u64,
    #[cfg(test)] fault: retirement::AbortFault,
) -> Result<RetirementIntentReport, &'static str> {
    match retirement::abort_offline(
        config_path,
        checkout,
        operation,
        revision,
        #[cfg(test)]
        fault,
    ) {
        Ok(retirement::AbortCommit::Historical(row, count, fence_active)) => {
            Ok(historical(&row, count, fence_active))
        }
        Ok(retirement::AbortCommit::Aborted(aborted)) => Ok(aborted.into_report()),
        Err("commit_unknown") => {
            let mut report = RetirementIntentReport::base(checkout);
            report.operation = Some(operation);
            report.outcome = "uncertain";
            report.reason = "commit_unknown";
            report.recorded = "unknown";
            report.stage = "unknown";
            report.fence_active = true;
            Ok(report)
        }
        Err(reason) => Err(reason),
    }
}

pub fn retirement_status(config_path: &Path, checkout: Uuid) -> RetirementIntentReport {
    match status_inner(config_path, checkout) {
        Ok(report) => report,
        Err(reason) => {
            let mut report = RetirementIntentReport::base(checkout);
            report.reason = reason;
            // An unreadable authority/history is not evidence of absent fencing.
            report.stage = "unknown";
            report.recorded = "unknown";
            report.fence_active = true;
            report
        }
    }
}

/// Faithful private entry, NOT a report-to-proof adapter. The cfg(test) inputs
/// select the existing owned Driver fixture and negative commit faults only.
pub(super) fn prepare_inner(
    config_path: &Path,
    checkout: Uuid,
    operation: Uuid,
    assertion: Option<Uuid>,
    task_complete: bool,
    #[cfg(test)] driver: Option<&crate::scope_driver::Driver>,
    #[cfg(test)] fault: retirement::PrepareFault,
) -> Result<RetirementIntentReport, &'static str> {
    // Bounded no-follow flag read only: no Store, lock or collection Budget.
    // The collector's original Budget is later retained through commit unchanged.
    let document =
        ConfigDocument::load_from_path(config_path).map_err(|_| "configuration_unknown")?;
    if !document
        .retirement_prepare_intents()
        .map_err(|_| "configuration_unknown")?
    {
        return Ok(disabled(checkout));
    }
    parse_uuid(&checkout.to_string()).map_err(|_| "invalid_checkout")?;
    parse_uuid(&operation.to_string()).map_err(|_| "invalid_operation")?;
    if let Some(id) = assertion {
        parse_uuid(&id.to_string()).map_err(|_| "invalid_assertion")?;
    }
    let config = document.authority().map_err(|_| "authority_unknown")?;
    let registry = config
        .trusted_registry
        .as_deref()
        .ok_or("authority_unknown")?;
    let dir = config.store_dir.as_deref().ok_or("authority_unknown")?;
    let readonly = Store::open_existing_registered_readonly(registry, dir, &config.roots)
        .map_err(|_| "authority_unknown")?;
    {
        let _phase = readonly.sql_phase();
        if let Some((row, count, fence_active)) =
            historical_operation(&readonly.conn, checkout, operation)?
        {
            return Ok(historical(&row, count, fence_active));
        }
        retirement_journal::exclude_prepare_operation(&readonly.conn, operation)
            .map_err(prepare_store_error)?;
    }
    let guard =
        crate::checkout_guard::CheckoutGuard::exclusive(&readonly, checkout).map_err(|error| {
            match error {
                StoreError::OperationsInFlight => "operations_in_flight",
                _ => "lock_unknown",
            }
        })?;
    let mut store = Store::open_existing_registered_mut(registry, dir, &config.roots)
        .map_err(|_| "authority_unknown")?;
    guard
        .require_matching(&store, checkout)
        .map_err(|_| "lock_unknown")?;
    drop(readonly);
    // A prepare may have completed between the first readonly snapshot and EX.
    // Re-read without a lease/write before collecting any fresh evidence.
    {
        let _phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|_| "history_unknown")?;
        let retry = historical_operation(&tx, checkout, operation)?;
        tx.rollback().map_err(|_| "history_unknown")?;
        if let Some((row, count, fence_active)) = retry {
            return Ok(historical(&row, count, fence_active));
        }
    }
    // Declaration is not quiescence proof. The actual mode/operator/task come
    // from the validated fresh owner, never from the allocation owner's name.
    if assertion.is_some() && !task_complete {
        return Err("declaration_required");
    }
    let mut owner = {
        #[cfg(test)]
        if let Some(driver) = driver {
            retirement::collect_fresh_prepare_inner(
                config_path,
                checkout,
                assertion,
                store,
                guard,
                Some(driver),
            )?
        } else {
            retirement::collect_fresh_prepare(config_path, checkout, assertion, store, guard)?
        }
        #[cfg(not(test))]
        {
            retirement::collect_fresh_prepare(config_path, checkout, assertion, store, guard)?
        }
    };
    owner.recheck_prepare_configuration(config_path)?;
    match owner.commit_prepared(
        operation,
        task_complete,
        #[cfg(test)]
        fault,
    ) {
        Ok(retirement::PrepareCommit::Prepared(prepared)) => Ok(prepared.into_report()),
        Ok(retirement::PrepareCommit::Historical(row, count, fence_active)) => {
            Ok(historical(&row, count, fence_active))
        }
        Err("commit_unknown") => {
            // Never inspect a row and manufacture a fresh capability after an
            // uncertain acknowledgment. Exclusion is conservatively retained.
            let mut report = RetirementIntentReport::base(checkout);
            report.operation = Some(operation);
            report.outcome = "uncertain";
            report.reason = "commit_unknown";
            report.recorded = "unknown";
            report.stage = "unknown";
            report.fence_active = true;
            Ok(report)
        }
        Err(reason) => Err(reason),
    }
}

/// Strict absence is distinct from corruption. Called both in the retained
/// readonly snapshot and again inside the dedicated IMMEDIATE transaction.
pub(super) fn historical_operation(
    conn: &rusqlite::Connection,
    checkout: Uuid,
    operation: Uuid,
) -> Result<Option<(IntentRow, u64, bool)>, &'static str> {
    let history = read_history(conn, checkout).map_err(|_| "history_unknown")?;
    let fence_active = history.iter().any(|row| row.stage != "aborted");
    if let Some(row) = find_operation(conn, operation).map_err(|_| "history_unknown")? {
        if row.checkout != checkout {
            return Err("intent_conflict");
        }
        if !history.iter().any(|entry| entry == &row) {
            return Err("history_unknown");
        }
        // Historical A may be aborted while B fences this same checkout.
        // Report the full strictly decoded history, never just A's stage.
        return Ok(Some((row, history.len() as u64, fence_active)));
    }
    if fence_active {
        return Err("intent_conflict");
    }
    Ok(None)
}

pub(super) fn prepare_store_error(error: StoreError) -> &'static str {
    match error {
        StoreError::Conflict => "intent_conflict",
        StoreError::Invalid => "record_invalid",
        _ => "commit_unknown",
    }
}

fn status_inner(
    config_path: &Path,
    checkout: Uuid,
) -> Result<RetirementIntentReport, &'static str> {
    parse_uuid(&checkout.to_string()).map_err(|_| "invalid_checkout")?;
    let document =
        ConfigDocument::load_from_path(config_path).map_err(|_| "configuration_unknown")?;
    let config = document.authority().map_err(|_| "authority_unknown")?;
    let registry = config
        .trusted_registry
        .as_deref()
        .ok_or("authority_unknown")?;
    let dir = config.store_dir.as_deref().ok_or("authority_unknown")?;
    let store = Store::open_existing_registered_readonly(registry, dir, &config.roots)
        .map_err(|_| "authority_unknown")?;
    let _phase = store.sql_phase();
    let history = read_history(&store.conn, checkout).map_err(|_| "history_unknown")?;
    if let Some(active) = history.iter().find(|row| row.stage != "aborted") {
        let mut report = historical(active, history.len() as u64, true);
        report.outcome = "observed";
        report.reason = "status";
        Ok(report)
    } else {
        let mut report = RetirementIntentReport::base(checkout);
        report.outcome = "observed";
        report.reason = "status";
        report.recorded = if history.is_empty() {
            "none"
        } else {
            "committed"
        };
        report.history_count = history.len() as u64;
        report.stage = if history.is_empty() {
            "none"
        } else {
            "aborted"
        };
        Ok(report)
    }
}

fn disabled(checkout: Uuid) -> RetirementIntentReport {
    let mut report = RetirementIntentReport::base(checkout);
    report.outcome = "disabled";
    report.reason = "prepare_intents_disabled";
    report
}

fn historical(row: &IntentRow, count: u64, fence_active: bool) -> RetirementIntentReport {
    let mut report = RetirementIntentReport::base(row.checkout);
    report.operation = Some(row.operation);
    report.revision = Some(row.revision as u64);
    report.stage = match row.stage.as_str() {
        "prepared" => "prepared",
        "held" => "held",
        "aborted" => "aborted",
        _ => "unknown",
    };
    report.mode = match row.mode.as_str() {
        "supervised" => "supervised",
        "adopted" => "adopted",
        _ => "unknown",
    };
    report.outcome = "existing";
    report.reason = "historical";
    report.recorded = "committed";
    report.fence_active = fence_active;
    report.history_count = count;
    report
}

// Only the acknowledged private abort owner calls this, while retaining EX.
pub(super) fn aborted_report(row: &IntentRow, count: u64) -> RetirementIntentReport {
    let mut report = historical(row, count, false);
    report.outcome = "aborted";
    report.reason = "validated_abort";
    report.fresh_commit = true;
    report
}

// The sole caller consumes the private acknowledged-commit owner. A strict
// journal row has no route to this function through historical/status decoding.
pub(super) fn committed_report(
    checkout: Uuid,
    operation: Uuid,
    revision: u64,
    mode: retirement_journal::Mode,
    count: u64,
) -> RetirementIntentReport {
    let mut report = RetirementIntentReport::base(checkout);
    report.operation = Some(operation);
    report.revision = Some(revision);
    report.stage = "prepared";
    report.mode = match mode {
        retirement_journal::Mode::Supervised => "supervised",
        retirement_journal::Mode::Adopted => "adopted",
    };
    report.outcome = "prepared";
    report.reason = "fresh_commit";
    report.recorded = "committed";
    report.fresh_commit = true;
    report.fence_active = true;
    report.history_count = count;
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{Limits, Reservation};

    #[test]
    fn disabled_prepare_does_not_open_store() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        std::fs::write(&path, "").unwrap();
        let checkout = Uuid::now_v7();
        let report = prepare_retirement(&path, checkout, Uuid::now_v7(), None, false);
        assert_eq!(report.outcome, "disabled");
        assert_eq!(report.reason, "prepare_intents_disabled");
        assert!(!report.fresh_commit);
        assert!(!temp.path().join("private").exists());
    }

    #[test]
    fn private_disabled_and_public_abort_missing_authority_do_not_create_authority() {
        for flag in ["", "[retirement]\nprepare_intents=false\n"] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("config.toml");
            std::fs::write(&path, flag).unwrap();
            let report = prepare_inner(
                &path,
                Uuid::nil(),
                Uuid::nil(),
                None,
                false,
                None,
                retirement::PrepareFault::None,
            )
            .unwrap();
            assert_eq!(report.reason(), "prepare_intents_disabled");
            assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        }
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        std::fs::write(&path, "[retirement]\nprepare_intents=true\n").unwrap();
        for (checkout, operation, assertion, reason) in [
            (Uuid::nil(), Uuid::now_v7(), None, "invalid_checkout"),
            (Uuid::now_v7(), Uuid::nil(), None, "invalid_operation"),
            (
                Uuid::now_v7(),
                Uuid::now_v7(),
                Some(Uuid::nil()),
                "invalid_assertion",
            ),
        ] {
            assert_eq!(
                prepare_inner(
                    &path,
                    checkout,
                    operation,
                    assertion,
                    false,
                    None,
                    retirement::PrepareFault::None
                )
                .unwrap_err(),
                reason
            );
            assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        }
        let report = abort_retirement(&path, Uuid::now_v7(), Uuid::now_v7(), 1);
        assert_eq!(report.outcome(), "held");
        assert_eq!(report.reason(), "authority_unknown");
        assert!(!report.fresh_commit());
        assert!(report.fence_active());
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value["recorded"], "unknown");
        assert_eq!(value["stage"], "unknown");
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn enabled_prepare_without_ready_identity_holds() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let store_dir = temp.path().join("private");
        let registry = temp.path().join(".work-authorities");
        let mut store = Store::open(&store_dir, std::slice::from_ref(&root)).unwrap();
        let checkout = store
            .reserve(
                &Reservation {
                    operation: Uuid::now_v7(),
                    repository: root.clone(),
                    actor: "allocator".into(),
                    owner: "owner".into(),
                    task: "task".into(),
                },
                Limits {
                    repository: 10,
                    owner: 10,
                    available_bytes: Some(100),
                    floor_bytes: 0,
                    warn_bytes: 0,
                },
            )
            .unwrap();
        drop(store);
        let path = temp.path().join("config.toml");
        std::fs::write(&path, format!("store_dir = {:?}\ntrusted_registry = {:?}\nroots = [{:?}]\n[retirement]\nprepare_intents = true\n", store_dir, registry, root)).unwrap();
        let report = prepare_retirement(&path, checkout, Uuid::now_v7(), None, false);
        assert_eq!(report.outcome, "held");
        assert!(!report.fresh_commit);
        assert!(report.fence_active);
        assert_eq!(report.stage, "unknown");
        assert_eq!(report.recorded, "unknown");
        assert!(!report.retirement_authority);
        let intents: i64 = rusqlite::Connection::open(store_dir.join("store.sqlite"))
            .unwrap()
            .query_row("SELECT count(*) FROM retirement_intents", [], |r| r.get(0))
            .unwrap();
        assert_eq!(intents, 0);
    }
}
