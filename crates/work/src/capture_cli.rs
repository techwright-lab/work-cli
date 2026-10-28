//! Operator journal observations only; never runtime or task-completion authority.
use crate::{
    config::Config,
    store::{Result, Store, StoreError},
};
use serde::Serialize;
use work_contract::RunId;

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Recover BEGIN metadata only; invalidates pre-bind authority, never launches an actor
    ReconcileBegin {
        #[arg(value_parser = parse_run)]
        run: RunId,
    },
    /// Read WORK journal metadata only; never queries the capture receiver
    Status {
        #[arg(value_parser = parse_run)]
        run: RunId,
    },
    /// Replay the recorded FINISH intent for a closed, known-outcome root
    Finalize {
        #[arg(value_parser = parse_run)]
        run: RunId,
    },
    /// Explicit delivery refresh after confirmed local freeze; never sends FINISH
    Retry {
        #[arg(value_parser = parse_run)]
        run: RunId,
    },
}
fn parse_run(value: &str) -> std::result::Result<RunId, &'static str> {
    RunId::parse(value).map_err(|_| "invalid run")
}
#[derive(Serialize)]
#[serde(untagged)]
pub enum Report {
    Journal(Box<JournalReport>),
    Unknown {
        action: &'static str,
        attempt: &'static str,
        runtime: &'static str,
        result: &'static str,
    },
}
#[derive(Serialize)]
pub struct JournalReport {
    action: &'static str,
    attempt: &'static str,
    runtime: &'static str,
    run: RunId,
    checkout: work_contract::CheckoutId,
    recorded_root_closed: bool,
    recorded_root_outcome: Option<crate::run_journal::RootOutcome>,
    task_open: bool,
    lease_charged: bool,
    capture_id: Option<String>,
    preparation: &'static str,
    local_freeze: &'static str,
    delivery: &'static str,
    receipt: Option<crate::capture_bridge::Receipt>,
    receiver_error_recorded: bool,
}
impl Report {
    pub fn is_held(&self) -> bool {
        match self {
            Self::Unknown { .. } => true,
            Self::Journal(r) => matches!(
                r.attempt,
                "refused" | "finish_uncertain" | "delivery_uncertain" | "begin_uncertain"
            ),
        }
    }
}
fn observe(config: &Config, run: &RunId) -> Result<JournalReport> {
    if config.roots.is_empty() {
        return Err(StoreError::Unsafe);
    }
    let store = Store::open_existing_registered_readonly(
        config
            .trusted_registry
            .as_deref()
            .ok_or(StoreError::Unsafe)?,
        config.store_dir.as_deref().ok_or(StoreError::Unsafe)?,
        &config.roots,
    )?;
    let _phase = store.sql_phase();
    let _read = crate::run_journal::read_transaction(&store.conn)?;
    let root = crate::run_journal::read(&store.conn, run)?.ok_or(StoreError::Invalid)?;
    crate::capture_journal::validate_related(&store.conn, &root.request.identity().checkout)?;
    let root = crate::run_journal::exact(&store.conn, &root.request)?;
    let capture = crate::capture_journal::qualified_terminal(&store.conn, &root)?;
    let checkout = root.request.identity().checkout.clone();
    let state: String = store.conn.query_row(
        "SELECT CASE WHEN length(state)<=32 THEN state ELSE '' END FROM checkouts WHERE id=?1",
        [checkout.to_string()],
        |r| r.get(0),
    )?;
    if !matches!(
        state.as_str(),
        "reserved"
            | "partial"
            | "active"
            | "expired"
            | "interrupted"
            | "held"
            | "quarantined"
            | "partially_deleted"
            | "retired"
    ) {
        return Err(StoreError::Invalid);
    }
    let task_open = crate::finish::task_open(
        &store.conn,
        uuid::Uuid::parse_str(&checkout.to_string()).map_err(|_| StoreError::Invalid)?,
    )?;
    let mut report = JournalReport {
        action: "status",
        attempt: "not_requested",
        runtime: "not_inspected",
        run: run.clone(),
        checkout,
        recorded_root_closed: root.closed,
        recorded_root_outcome: root.outcome,
        task_open,
        lease_charged: state != "retired",
        capture_id: None,
        preparation: "missing",
        local_freeze: "missing",
        delivery: "not_observed",
        receipt: None,
        receiver_error_recorded: false,
    };
    if let Some((capture, _, terminal)) = capture {
        report.preparation = if capture.prepared.is_some() {
            "prepared"
        } else {
            "unprepared"
        };
        report.capture_id = capture.prepared.map(|p| p.capture_id);
        report.local_freeze = "unfrozen";
        if let Some(terminal) = terminal {
            report.local_freeze = "unconfirmed";
            if let Some(confirmation) = terminal.confirmation {
                report.local_freeze = "frozen";
                report.delivery = if confirmation.delivered {
                    "delivered"
                } else {
                    "pending"
                };
                report.receipt = confirmation.receipt;
                report.receiver_error_recorded = confirmation.error_code.is_some();
            }
        }
    }
    Ok(report)
}
pub fn command(config: &Config, command: Command) -> Result<Report> {
    let (run, action) = match command {
        Command::Status { run } => {
            return observe(config, &run).map(|r| Report::Journal(Box::new(r)))
        }
        Command::Finalize { run } => (run, "finalize"),
        Command::Retry { run } => (run, "retry"),
        Command::ReconcileBegin { run } => (run, "reconcile-begin"),
    };
    // Registered current-schema read-only target validation MUST precede mutable open.
    // No snapshot or SQL phase survives across the delegated process operation.
    observe(config, &run)?;
    let operation = if action == "reconcile-begin" {
        crate::capture_recovery::reconcile(config, &run)
    } else if action == "retry" {
        crate::capture_finalization::retry_delivery(config, &run).map(|_| "response_recorded")
    } else {
        crate::capture_finalization::finalize(config, &run).map(|(_store, result)| match result {
            crate::capture_finalization::FinalizeResult::Existing(_) => "existing_confirmation",
            crate::capture_finalization::FinalizeResult::Confirmed {
                acknowledgement, ..
            } => {
                // An actual acknowledgement is not writer/readiness authority. Never persist it.
                drop(acknowledgement);
                "response_recorded"
            }
        })
    };
    let attempt = match operation {
        Ok(attempt) => attempt,
        Err(StoreError::CaptureFinishUncertain) => "finish_uncertain",
        Err(StoreError::CaptureDeliveryUncertain) => "delivery_uncertain",
        Err(_) => "refused",
    };
    Ok(match observe(config, &run) {
        Ok(mut report) => {
            report.action = action;
            report.attempt = attempt;
            Report::Journal(Box::new(report))
        }
        Err(_) => Report::Unknown {
            action,
            attempt,
            runtime: "not_inspected",
            result: "held_result_unknown",
        },
    })
}
