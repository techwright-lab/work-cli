//! Dedicated-stdin child metadata declarations, never launch or writer authority.
use crate::{
    config::Config,
    run_journal::{BeginRun, Transition},
    run_participants::{ChildOutcome, ChildRequest, Enrollment, ExpectedHost},
    scope_driver::{Driver, RuntimeContext},
    store::{Result, Store, StoreError},
};
use serde::{Deserialize, Serialize};
use std::io::Read;
use work_contract::{ActorId, CheckoutId, ExecutionChain, GroupId, RunId, RunRef};

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Record explicit child intent from strict JSON on dedicated stdin; no inspection
    Register,
    /// Inspect a previously pending host from strict JSON on dedicated stdin
    Enroll,
    /// Declare completed/failed/cancelled metadata from strict JSON on dedicated stdin
    Close,
    /// Full historical metadata only; current runtime is never inspected
    Status {
        #[arg(value_parser = parse_run)]
        root_run: RunId,
    },
}

fn parse_run(value: &str) -> std::result::Result<RunId, &'static str> {
    RunId::parse(value).map_err(|_| "invalid root run")
}

// Remote serde definition requires even nullable fields to be explicitly present.
// Direct typed deserialization also rejects duplicate and unknown fields.
#[derive(Deserialize)]
#[serde(remote = "ChildRequest", deny_unknown_fields)]
struct ExplicitChild {
    checkout: CheckoutId,
    group: GroupId,
    run: RunId,
    run_ref: RunRef,
    parent_run: RunId,
    parent_run_ref: RunRef,
    execution_chain: ExecutionChain,
    #[serde(deserialize_with = "nullable")]
    source: Option<crate::participants::Ref>,
    #[serde(deserialize_with = "nullable")]
    session: Option<crate::participants::Ref>,
    #[serde(deserialize_with = "nullable")]
    agent: Option<crate::participants::Ref>,
    #[serde(deserialize_with = "nullable")]
    actor: Option<ActorId>,
    #[serde(deserialize_with = "nullable")]
    expected_host: Option<ExpectedHost>,
}
fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::deserialize(deserializer)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    root_run: RunId,
    #[serde(deserialize_with = "ExplicitChild::deserialize")]
    child: ChildRequest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloseEnvelope {
    root_run: RunId,
    #[serde(deserialize_with = "ExplicitChild::deserialize")]
    child: ChildRequest,
    outcome: DeclaredOutcome,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum DeclaredOutcome {
    Completed,
    Failed,
    Cancelled,
}
impl From<DeclaredOutcome> for ChildOutcome {
    fn from(value: DeclaredOutcome) -> Self {
        match value {
            DeclaredOutcome::Completed => Self::Completed,
            DeclaredOutcome::Failed => Self::Failed,
            DeclaredOutcome::Cancelled => Self::Cancelled,
        }
    }
}
fn input<T: serde::de::DeserializeOwned>(reader: impl Read) -> Result<T> {
    let mut bytes = Vec::new();
    reader
        .take((crate::adopted::INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > crate::adopted::INPUT_BYTES {
        return Err(StoreError::Invalid);
    }
    serde_json::from_slice(&bytes).map_err(|_| StoreError::Invalid)
}
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Report {
    Metadata {
        state: &'static str,
        reason: &'static str,
        no_execution_permission: bool,
        fresh_runtime_claim: bool,
        runtime: &'static str,
    },
    Status(Box<crate::run_recovery::HistoricalStatus>),
}
impl Report {
    pub fn is_held(&self) -> bool {
        matches!(self, Self::Metadata { state: "held", .. })
    }
}
fn report(state: &'static str, reason: &'static str) -> Report {
    Report::Metadata {
        state,
        reason,
        no_execution_permission: true,
        fresh_runtime_claim: false,
        runtime: "not_inspected",
    }
}
fn transition(t: Transition) -> Report {
    report(
        if t == Transition::Changed {
            "changed"
        } else {
            "existing"
        },
        "metadata_only",
    )
}
fn paths(config: &Config) -> Result<(&std::path::Path, &std::path::Path)> {
    if config.roots.is_empty() {
        return Err(StoreError::Unsafe);
    }
    Ok((
        config
            .trusted_registry
            .as_deref()
            .ok_or(StoreError::Unsafe)?,
        config.store_dir.as_deref().ok_or(StoreError::Unsafe)?,
    ))
}
pub fn command(config: &Config, command: Command) -> Result<Report> {
    command_with_driver(config, command, std::io::stdin().lock(), || {
        let policy = config.supervisor.as_ref()?;
        let context =
            RuntimeContext::new(policy.runtime_directory.clone(), policy.bus_address.clone())
                .ok()?;
        Driver::new(context).ok()
    })
}
/// Library-only trusted Driver injection. The binary always uses fixed OS paths;
/// neither JSON, argv nor environment can select fake proc/cgroup/manager IO.
/// The factory is lazy: only a pending exact target can require inspection.
pub fn command_with_driver(
    config: &Config,
    command: Command,
    reader: impl Read,
    driver: impl FnOnce() -> Option<Driver>,
) -> Result<Report> {
    let (registry, dir) = paths(config)?;
    if let Command::Status { root_run } = command {
        let store = Store::open_existing_registered_readonly(registry, dir, &config.roots)?;
        return Ok(Report::Status(Box::new(crate::run_recovery::status(
            &store, &root_run,
        )?)));
    }
    // Parse completely before opening mutable authority. No bootstrap or migrations.
    let (envelope, outcome) = if matches!(command, Command::Close) {
        let close: CloseEnvelope = input(reader)?;
        (
            Envelope {
                root_run: close.root_run,
                child: close.child,
            },
            Some(ChildOutcome::from(close.outcome)),
        )
    } else {
        (input::<Envelope>(reader)?, None)
    };
    let mut store = Store::open_existing_registered_mut(registry, dir, &config.roots)?;
    let record = store
        .run_snapshot(&envelope.root_run)?
        .ok_or(StoreError::Invalid)?;
    let root = &record.request;
    let child = &envelope.child;
    match command {
        Command::Register => Ok(report(
            if store.register_child(root, child)? == BeginRun::Created {
                "changed"
            } else {
                "existing"
            },
            "intent_recorded_no_inspection",
        )),
        Command::Close => Ok(transition(store.record_child_outcome(
            root,
            child,
            outcome.ok_or(StoreError::Invalid)?,
        )?)),
        Command::Enroll => {
            let target = record
                .children
                .iter()
                .find(|c| c.request.run == child.run)
                .ok_or(StoreError::Invalid)?;
            if &target.request != child {
                return Err(StoreError::Conflict);
            }
            if target.enrollment == Enrollment::Contained {
                return Ok(report("already_recorded", "historical_enrollment_only"));
            }
            if target.enrollment == Enrollment::Unverified {
                return Ok(report("held", "unverified_requires_reconciliation"));
            }
            if record.closed {
                return Err(StoreError::Invalid);
            }
            let Some(driver) = driver() else {
                store.record_child_hold(root, child)?;
                return Ok(report("held", "configure_supervisor_runtime"));
            };
            let snapshot = store.group_snapshot(&envelope.root_run)?;
            let proof = match snapshot.certify_child_enrollment(&driver, &child.run, None) {
                Ok(proof) => proof,
                Err(_) => {
                    store.record_child_hold(root, child)?;
                    return Ok(report("held", "host_or_registrar_not_qualified"));
                }
            };
            // A successful inspection followed by a CAS conflict must not downgrade
            // or erase the pending barrier. No retries and no fabricated proof receipt.
            match store.record_child_enrollment(root, child, &proof) {
                Ok(t) => Ok(transition(t)),
                Err(StoreError::Conflict) => {
                    Ok(report("held", "snapshot_changed_retry_explicitly"))
                }
                Err(e) => Err(e),
            }
        }
        Command::Status { .. } => unreachable!(),
    }
}
