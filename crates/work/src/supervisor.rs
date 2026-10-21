//! Concrete root-only coordinator. Intent/writer -> blocked spawn -> bind journal
//! -> permit-attempt journal -> release -> root status -> fresh whole-scope proof.
//! A root exit is never writer release. Holds retain charges and task openness.
//! Historical bindings cannot be restored; retry receipts never grant execution.
//! Configured captured roots use live closure, actual FINISH and fresh physical
//! certification. Adopted capture, explicit capture finish and retirement remain unsupported.
//!
//! Polling policy is finite, but kernel D-state can delay pre-exec kill/reaping
//! indefinitely. Released roots retain an owned reaper on drop (see scope_spawn).
//! Interactive TTY/job-control is not qualified: CLI refuses terminal stdio rather
//! than moving a foreground protocol into a background process group silently.
pub use crate::attribution_gap::{GapDelivery, GapObservation};
use crate::{
    allocate::{self, db, err, verified_checkout},
    config::{Config, SupervisorConfig},
    run_journal::{BeginRun, RootOutcome, RootRunRequest, RunIdentity, RunInput, RunRecord},
    runtime_scope::LaunchIntent,
    scope_driver::{Driver, RuntimeContext},
    scope_spawn::{ActorGitProfile, AttributedCommand, LaunchIo, LaunchPolicy, OwnedLaunch},
    store::Store,
};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs,
    io::{self, IsTerminal},
    os::unix::{ffi::OsStrExt, fs::DirBuilderExt},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use uuid::Uuid;
use work_contract::{ActorId, ChainText, CheckoutId, ExecutionChain, GroupId, RunId, RunRef};

#[derive(Debug, clap::Args)]
pub struct Run {
    pub checkout: Uuid,
    /// Explicit per-run non-session Gap intent; delivery transport is deferred
    #[arg(long, value_enum)]
    pub attribution: Option<crate::run_journal::AttributionDecision>,
    #[arg(long)]
    pub actor: Option<String>,
    #[arg(long)]
    pub run_id: Uuid,
    /// Bounded typed JSON file; stdin belongs exclusively to the delegate
    #[arg(long)]
    pub execution_chain: PathBuf,
    #[arg(last = true, required = true)]
    pub argv: Vec<OsString>,
}
#[derive(Clone)]
pub struct RootCommand {
    pub checkout: Uuid,
    pub actor: Option<String>,
    pub run_id: Uuid,
    pub execution_chain: ExecutionChain,
    pub argv: Vec<OsString>,
}
#[derive(Default, Clone)]
pub struct CancelToken(Arc<AtomicBool>);
impl CancelToken {
    pub fn request(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}
/// Library/test-only observers at persisted boundaries, never a CLI selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boundary {
    Intent,
    Bound,
    PermitAttempt,
    /// Captured-only: fresh FD proof collected, before allocator lock/lease/kernel gate.
    CapturedPreflight,
    RootTerminal,
    Closed,
}
#[derive(Debug)]
pub struct RunReport {
    pub gap: Option<GapObservation>,
    pub record: RunRecord,
    pub existing: bool,
    pub exit_code: Option<i32>,
    pub lease_charged: bool,
    pub task_open: bool,
    /// Durable readiness observation, not physical proof or execution permission.
    pub checkout_ready: bool,
    pub attribution_not_configured: bool,
    /// Capture is locally unfrozen; physical group closure is not freeze/delivery.
    pub capture_unfrozen: bool,
    /// Historical delivery observation, never readiness or a fresh live acknowledgement.
    pub capture_delivery: Option<crate::capture_bridge::DeliveryObservation>,
}
impl RunReport {
    pub fn process_exit_code(&self) -> i32 {
        if !self.record.closed
            || (self.record.outcome == Some(RootOutcome::Cancelled)
                && self.exit_code.unwrap_or(0) == 0)
        {
            // A delegate may handle TERM and exit zero. Preserve that observed
            // code in the report, but cancellation is never CLI success.
            1
        } else {
            self.exit_code
                .unwrap_or(if self.record.outcome == Some(RootOutcome::Completed) {
                    0
                } else {
                    1
                })
        }
    }
}
impl SupervisorConfig {
    fn policy(&self) -> io::Result<LaunchPolicy> {
        self.validate()
            .map_err(|_| err("invalid supervisor policy"))?;
        LaunchPolicy::new(
            Duration::from_secs(self.runtime_max_seconds),
            Duration::from_millis(self.preexec_ms),
        )
        .map_err(err)
    }
}
fn digest_fields(fields: impl IntoIterator<Item = impl AsRef<[u8]>>) -> [u8; 32] {
    let mut hash = Sha256::new();
    for field in fields {
        let bytes = field.as_ref();
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    hash.finalize().into()
}
pub(crate) fn command_digest(argv: &[OsString]) -> io::Result<[u8; 32]> {
    if argv.is_empty() || argv[0].is_empty() || argv.iter().any(|v| v.as_bytes().contains(&0)) {
        return Err(err("invalid command"));
    }
    Ok(digest_fields(argv.iter().map(|v| v.as_bytes())))
}
fn request(
    command: &RootCommand,
    a: &allocate::Allocation,
    actor: &str,
    profile: &ActorGitProfile,
    existing: Option<&RunRecord>,
) -> io::Result<RootRunRequest> {
    let run =
        RunId::parse(&command.run_id.to_string()).map_err(|_| err("run-id must be UUIDv7"))?;
    let checkout =
        CheckoutId::parse(&command.checkout.to_string()).map_err(|_| err("invalid checkout"))?;
    let actor = ActorId::parse(actor).map_err(|_| err("invalid actor"))?;
    let command_digest = command_digest(&command.argv)?;
    let metadata = serde_json::to_vec(&(
        a.checkout,
        a.request.operation,
        &a.base_commit,
        &a.request.task,
        &actor,
        profile,
        &command.execution_chain,
    ))
    .map_err(|_| err("invalid immutable input"))?;
    let input_digest = digest_fields([metadata.as_slice(), a.destination.as_os_str().as_bytes()]);
    let boot = match existing {
        Some(r) => r.request.input().boot.clone(),
        None => fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .into(),
    };
    let group = match existing {
        Some(r) => r.request.identity().group.clone(),
        None => GroupId::parse(&Uuid::now_v7().to_string()).map_err(|_| err("invalid group"))?,
    };
    db(RootRunRequest::new(
        RunIdentity {
            checkout,
            group,
            run,
            run_ref: match existing {
                Some(r) => r.request.identity().run_ref.clone(),
                None => RunRef::parse(&format!("urn:work:run:{}", command.run_id))
                    .map_err(|_| err("invalid run reference"))?,
            },
            actor,
            parent_run_ref: None,
            execution_chain: command.execution_chain.clone(),
        },
        RunInput {
            attribution: None,
            command_digest,
            input_digest,
            context_ref: match existing {
                Some(r) => r.request.input().context_ref.clone(),
                None => ChainText::new(format!("urn:work:context:{}", command.run_id))
                    .map_err(|_| err("invalid context"))?,
            },
            intent_ref: match existing {
                Some(r) => r.request.input().intent_ref.clone(),
                None => ChainText::new(format!("urn:work:intent:{}", command.run_id))
                    .map_err(|_| err("invalid intent"))?,
            },
            boot,
        },
    ))
}
fn record(store: &Store, request: &RootRunRequest) -> io::Result<RunRecord> {
    db(store.run_snapshot(&request.identity().run))?.ok_or_else(|| err("missing run journal"))
}
fn report(
    store: &Store,
    run: &RunId,
    existing: bool,
    exit_code: Option<i32>,
) -> io::Result<RunReport> {
    let _phase = store.sql_phase();
    let _snapshot = db(crate::run_journal::read_transaction(&store.conn))?;
    let (record, lease_charged, task_open) = db(store.run_status_record(run))?;
    let checkout_ready = allocate::sql(store.conn.query_row(
        "SELECT state='active' AND ready=1 FROM checkouts WHERE id=?1",
        [record.request.identity().checkout.to_string()],
        |r| r.get(0),
    ))?;
    let mapped = db(store.capture_snapshot(run))?.is_some();
    let confirmation = db(store.capture_finalization_snapshot(run))?.and_then(|s| s.confirmation);
    let capture_unfrozen = mapped && confirmation.is_none();
    let capture_delivery = confirmation.map(|c| {
        if c.delivered {
            crate::capture_bridge::DeliveryObservation::Delivered
        } else {
            crate::capture_bridge::DeliveryObservation::Pending
        }
    });
    let gap = db(crate::attribution_gap::observation(
        &store.conn,
        &record.request,
    ))?;
    let attribution_not_configured = gap.is_none()
        && !mapped
        && db(crate::finish::capture_not_configured(
            &store.conn,
            Uuid::parse_str(&record.request.identity().checkout.to_string())
                .map_err(|_| err("invalid checkout"))?,
        ))?;
    Ok(RunReport {
        gap,
        record,
        existing,
        exit_code,
        lease_charged,
        task_open,
        checkout_ready,
        attribution_not_configured,
        capture_unfrozen,
        capture_delivery,
    })
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExpectedMode {
    Default,
    /// Default attribution, additionally requiring an existing capture mapping.
    CapturedDefault,
    Off,
}
pub(crate) fn off_existing_report(
    config: &Config,
    command: &RootCommand,
) -> io::Result<Option<RunReport>> {
    historical_report(config, command, ExpectedMode::Off)
}
/// Historical finished-task receipt, without restoring actor/runtime authority.
pub fn existing_report(config: &Config, command: &RootCommand) -> io::Result<Option<RunReport>> {
    Ok(historical_report(config, command, ExpectedMode::Default)?
        .filter(|report| !report.task_open))
}
fn historical_report(
    config: &Config,
    command: &RootCommand,
    expected: ExpectedMode,
) -> io::Result<Option<RunReport>> {
    let (Some(registry), Some(dir)) = (
        config.trusted_registry.as_deref(),
        config.store_dir.as_deref(),
    ) else {
        return Ok(None);
    };
    if !dir.exists() {
        return Ok(None);
    }
    let store = db(Store::open_existing_registered_readonly(
        registry,
        dir,
        &config.roots,
    ))?;
    let _phase = store.sql_phase();
    let _snapshot = db(crate::run_journal::read_transaction(&store.conn))?;
    let run = RunId::parse(&command.run_id.to_string()).map_err(|_| err("invalid run"))?;
    let Some(record) = db(store.run_snapshot(&run))? else {
        return Ok(None);
    };
    if record.request.input().attribution.is_some() != (expected == ExpectedMode::Off) {
        return Err(err("historical attribution mode conflicts"));
    }
    // Qualify the existing report in the same snapshot before any route-specific
    // refusal. Reuse it below rather than adding another history traversal.
    let receipt = report(&store, &run, true, None)?;
    if expected == ExpectedMode::CapturedDefault
        && !receipt.capture_unfrozen
        && receipt.capture_delivery.is_none()
    {
        return Err(err("ordinary root cannot acquire capture"));
    }
    if record.request.identity().checkout.to_string() != command.checkout.to_string()
        || command
            .actor
            .as_ref()
            .is_some_and(|a| a != record.request.identity().actor.as_str())
        || record.request.identity().execution_chain != command.execution_chain
        || record.request.input().command_digest != command_digest(&command.argv)?
    {
        return Err(err("historical request conflicts"));
    }
    Ok(Some(receipt))
}
/// Actual accepted backend with explicit library-only IO fixtures. Production
/// never reads manager/launcher selectors from flags or the environment.
pub fn supervise_with_io(
    config: &Config,
    command: RootCommand,
    driver: &Driver,
    io: LaunchIo,
    cancel: &CancelToken,
    observer: impl FnMut(Boundary, &RunRecord),
) -> io::Result<RunReport> {
    supervise(config, command, driver, Some(io), cancel, observer)
}
fn captured_existing_report(
    config: &Config,
    command: &RootCommand,
    captured_only: bool,
) -> io::Result<Option<RunReport>> {
    let expected = if captured_only {
        ExpectedMode::CapturedDefault
    } else {
        ExpectedMode::Default
    };
    let Some(report) = historical_report(config, command, expected)? else {
        return Ok(None);
    };
    if !report.capture_unfrozen && report.capture_delivery.is_none() {
        return Ok(None);
    }
    Ok(Some(report))
}
/// Trusted integrated captured execution with explicit library-only IO fixtures.
/// Changed live closure, actual FINISH acknowledgement and new physical evidence
/// are all required for readiness. Pending delivery is not a workflow failure.
/// Production uses the same coordinator with fixed actual IO, never selectors.
pub fn supervise_captured_integrated_with_io(
    config: &Config,
    command: RootCommand,
    driver: &Driver,
    io: LaunchIo,
    cancel: &CancelToken,
    observer: impl FnMut(Boundary, &RunRecord),
) -> io::Result<RunReport> {
    supervise_captured(
        config,
        command,
        driver,
        Some(io),
        cancel,
        observer,
        CaptureCompletion::Certify,
    )
}
#[derive(Clone, Copy)]
enum CaptureCompletion {
    Unfrozen,
    Certify,
}
/// Library-only captured supervisor retaining the deliberately unfrozen b2 contract.
pub fn supervise_captured_with_io(
    config: &Config,
    command: RootCommand,
    driver: &Driver,
    io: LaunchIo,
    cancel: &CancelToken,
    observer: impl FnMut(Boundary, &RunRecord),
) -> io::Result<RunReport> {
    supervise_captured(
        config,
        command,
        driver,
        Some(io),
        cancel,
        observer,
        CaptureCompletion::Unfrozen,
    )
}
fn supervise_captured(
    config: &Config,
    command: RootCommand,
    driver: &Driver,
    io: Option<LaunchIo>,
    cancel: &CancelToken,
    observer: impl FnMut(Boundary, &RunRecord),
    completion: CaptureCompletion,
) -> io::Result<RunReport> {
    if let Some(report) = captured_existing_report(config, &command, true)? {
        return Ok(report);
    }
    let settings = config
        .supervisor
        .as_ref()
        .ok_or_else(|| err("supervisor not configured"))?;
    settings.policy()?;
    let (store, lock) = allocate::locked(config)?;
    let allocation: allocate::Allocation = {
        let _phase = store.sql_phase();
        let _snapshot = db(crate::run_journal::read_transaction(&store.conn))?;
        let text: String = allocate::sql(store.conn.query_row(
            "SELECT record FROM allocations WHERE checkout=?1",
            [command.checkout.to_string()],
            |r| r.get(0),
        ))?;
        serde_json::from_str(&text).map_err(|_| err("invalid allocation"))?
    };
    drop(lock);
    drop(store);
    let actor = command
        .actor
        .as_deref()
        .or(allocation.request.actor.as_deref())
        .ok_or_else(|| err("explicit actor required"))?;
    let profile = settings
        .actors
        .get(actor)
        .ok_or_else(|| err("actor Git profile not registered"))?;
    let root = request(&command, &allocation, actor, profile, None)?;
    let spec = db(config.capture_spec(
        &root,
        &allocation,
        Uuid::now_v7(),
        vec![allocation.request.task.clone()],
        None,
    ))?;
    let (store, prepared) = crate::capture_preparation::prepare(config, &root, &spec)?;
    let crate::capture_preparation::PreparationResult::Live(live) = prepared else {
        return report(&store, &root.identity().run, true, None);
    };
    execute(
        config,
        command,
        driver,
        io,
        cancel,
        observer,
        store,
        allocation,
        root,
        profile,
        ExecutionMode::Captured {
            live: Box::new(live),
            completion,
        },
    )
}
pub(crate) fn supervise_off(
    config: &Config,
    command: RootCommand,
    driver: &Driver,
    io: Option<LaunchIo>,
    cancel: &CancelToken,
    observer: impl FnMut(Boundary, &RunRecord),
) -> io::Result<RunReport> {
    if let Some(report) = off_existing_report(config, &command)? {
        return Ok(report);
    }
    let settings = config
        .supervisor
        .as_ref()
        .ok_or_else(|| err("supervisor not configured"))?;
    settings.policy()?;
    let (store, lock) = allocate::locked(config)?;
    let allocation: allocate::Allocation = {
        let _phase = store.sql_phase();
        let _snapshot = db(crate::run_journal::read_transaction(&store.conn))?;
        let bytes: String = allocate::sql(store.conn.query_row(
            "SELECT record FROM allocations WHERE checkout=?1",
            [command.checkout.to_string()],
            |r| r.get(0),
        ))?;
        serde_json::from_str(&bytes).map_err(|_| err("invalid allocation"))?
    };
    drop(lock);
    drop(store);
    let actor = command
        .actor
        .as_deref()
        .or(allocation.request.actor.as_deref())
        .ok_or_else(|| err("explicit actor required"))?;
    let profile = settings
        .actors
        .get(actor)
        .ok_or_else(|| err("actor Git profile not registered"))?;
    let default = request(&command, &allocation, actor, profile, None)?;
    let mut input = default.input().clone();
    input.attribution = Some(crate::run_journal::AttributionDecision::Off);
    let root = db(RootRunRequest::new(default.identity().clone(), input))?;
    let (store, began) = db(crate::attribution_gap::begin(config, &root, &command.argv))?;
    let live = match began {
        crate::attribution_gap::BeginGap::Created(live) => live,
        crate::attribution_gap::BeginGap::Existing(committed) => {
            let receipt = report(&store, &root.identity().run, true, None)?;
            if receipt.gap != Some(db(committed.observation())?) {
                return Err(err("committed Gap receipt changed"));
            }
            return Ok(receipt);
        }
    };
    execute(
        config,
        command,
        driver,
        io,
        cancel,
        observer,
        store,
        allocation,
        root,
        profile,
        ExecutionMode::Gap(live),
    )
}
fn supervise(
    config: &Config,
    command: RootCommand,
    driver: &Driver,
    io: Option<LaunchIo>,
    cancel: &CancelToken,
    observer: impl FnMut(Boundary, &RunRecord),
) -> io::Result<RunReport> {
    // Optional read-only finished receipt. Otherwise retain the ordinary run
    // preflight, which independently validates authority and cannot revive a
    // held finish fence (including when strict reader bookkeeping is absent).
    if let Some(report) = existing_report(config, &command)? {
        return Ok(report);
    }
    let settings = config
        .supervisor
        .as_ref()
        .ok_or_else(|| err("configure supervisor and actor Git profiles"))?;
    settings.policy()?;
    if config
        .allocation
        .as_ref()
        .is_some_and(|p| p.capture_sink.is_some())
    {
        return Err(err("capture bridge unsupported; no delegate launched"));
    }
    let run =
        RunId::parse(&command.run_id.to_string()).map_err(|_| err("run-id must be UUIDv7"))?;
    // Fresh lease BEFORE begin/writer/spawn, under the same short allocator lock.
    let (mut store, lock) = allocate::locked(config)?;
    let allocation = verified_checkout(&mut store, command.checkout)?;
    let actor = command
        .actor
        .as_deref()
        .or(allocation.request.actor.as_deref())
        .ok_or_else(|| err("explicit actor required"))?;
    let profile = settings
        .actors
        .get(actor)
        .ok_or_else(|| err("actor Git profile not registered"))?;
    let existing = db(store.run_snapshot(&run))?;
    let request = request(&command, &allocation, actor, profile, existing.as_ref())?;
    let began = db(store.begin_run(&request))?;
    drop(lock);
    if began == BeginRun::Existing {
        if !record(&store, &request)?.closed {
            db(store.record_recovery_hold(&request))?;
        }
        return report(&store, &request.identity().run, true, None);
    }
    execute(
        config,
        command,
        driver,
        io,
        cancel,
        observer,
        store,
        allocation,
        request,
        profile,
        ExecutionMode::Ordinary,
    )
}
enum ExecutionMode {
    Ordinary,
    Captured {
        live: Box<crate::capture_preparation::LiveCapture>,
        completion: CaptureCompletion,
    },
    Gap(Box<crate::attribution_gap::CreatedOffLive>),
}
#[allow(clippy::too_many_arguments)] // one execution/physical-closure loop for both admission paths
fn execute(
    config: &Config,
    command: RootCommand,
    driver: &Driver,
    io: Option<LaunchIo>,
    cancel: &CancelToken,
    mut observer: impl FnMut(Boundary, &RunRecord),
    mut store: Store,
    allocation: allocate::Allocation,
    request: RootRunRequest,
    profile: &ActorGitProfile,
    mode: ExecutionMode,
) -> io::Result<RunReport> {
    let settings = config
        .supervisor
        .as_ref()
        .ok_or_else(|| err("supervisor not configured"))?;
    let policy = settings.policy()?;
    let run = request.identity().run.clone();
    let (live, completion) = match &mode {
        ExecutionMode::Captured { live, completion } => (Some(live), *completion),
        _ => (None, CaptureCompletion::Unfrozen),
    };
    let owned_driver = match &mode {
        ExecutionMode::Captured { live, .. } => Some(driver.for_capture(live)),
        ExecutionMode::Gap(live) => Some(driver.for_gap(&live.removal_policy())),
        ExecutionMode::Ordinary => None,
    };
    let driver = owned_driver.as_ref().unwrap_or(driver);
    observer(Boundary::Intent, &record(&store, &request)?);
    // Before physical closure, failures retain writer and charge. Once closure
    // commits, subsequent capture/readiness errors must never rewrite that fact.
    let mut physically_closed = false;
    let result = (|| {
        let runs = config
            .store_dir
            .as_ref()
            .ok_or_else(|| err("missing store"))?
            .join("runs");
        match fs::DirBuilder::new().mode(0o700).create(&runs) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e),
        }
        crate::config::validate_path(&runs, true)
            .map_err(|_| err("unsafe run control directory"))?;
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(&runs)?;
        if metadata.uid() != rustix::process::getuid().as_raw() || metadata.mode() & 0o777 != 0o700
        {
            return Err(err("unsafe run control directory"));
        }
        let directory = runs.join(command.run_id.to_string());
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        fs::File::open(&runs)?.sync_all()?;
        let intent = LaunchIntent::new(run, &request.input().boot)
            .map_err(|_| err("invalid launch intent"))?;
        let attributed = AttributedCommand {
            cwd: &allocation.destination,
            argv: &command.argv,
            git: profile,
        };
        let mut launch = match &mode {
            ExecutionMode::Captured { live, .. } => OwnedLaunch::spawn_captured(
                driver, intent, &directory, &request, attributed, policy, io, live,
            ),
            ExecutionMode::Gap(live) => {
                OwnedLaunch::spawn_gap(driver, intent, &directory, attributed, policy, io, live)
            }
            ExecutionMode::Ordinary => {
                OwnedLaunch::spawn_attributed(driver, intent, &directory, attributed, policy, io)
            }
        }
        .map_err(err)?;
        while !launch.poll_blocked().map_err(err)? {
            std::thread::sleep(Duration::from_millis(5));
        }
        launch.bind(driver).map_err(err)?;
        db(store.record_bound(
            &request,
            launch.binding().ok_or_else(|| err("missing binding"))?,
        ))?;
        observer(Boundary::Bound, &record(&store, &request)?);
        let cancelled_blocked = if cancel.requested() {
            // Before permit, cancel() also reaps the exclusively owned blocked
            // launcher. Record Cancelled only after observing that actual exit,
            // then use the same whole-scope proof path as a released root.
            launch.cancel(driver).map_err(err)?;
            let status = launch
                .try_wait()
                .map_err(err)?
                .ok_or_else(|| err("cancel root status unknown"))?;
            db(store.record_root_outcome(&request, RootOutcome::Cancelled))?;
            observer(Boundary::RootTerminal, &record(&store, &request)?);
            Some(status)
        } else {
            db(store.record_permit_attempt(
                &request,
                launch.binding().ok_or_else(|| err("missing binding"))?,
            ))?;
            observer(Boundary::PermitAttempt, &record(&store, &request)?);
            // Actual descriptor reads precede allocator flock and SQL. The
            // original timestamp covers contention, lease verification and kernel gate.
            let capture_proof = live
                .as_ref()
                .map(|live| live.release_proof())
                .transpose()
                .map_err(|_| err("capture context changed"))?;
            if capture_proof.is_some() {
                observer(Boundary::CapturedPreflight, &record(&store, &request)?);
            }
            let gap_proof = match &mode {
                ExecutionMode::Gap(live) => Some(db(live.release_proof())?),
                _ => None,
            };
            // Do not reconcile/revive holds at the irreversible boundary. Other
            // checkouts remain allocatable for the entire running actor lifetime.
            let (mut fresh_store, lock) = allocate::locked(config)?;
            if let (Some(live), Some(proof)) = (&live, &capture_proof) {
                proof.validate(&live.guard()).map_err(err)?;
                proof.fresh().map_err(err)?;
            }
            if let Some(proof) = &gap_proof {
                db(proof.validate_current(
                    &fresh_store,
                    launch.binding().ok_or_else(|| err("missing binding"))?,
                ))?;
                if cancel.requested() {
                    return Err(err("release held"));
                }
            } else {
                let fresh = verified_checkout(&mut fresh_store, command.checkout)?;
                let current = record(&fresh_store, &request)?;
                if fresh.destination != allocation.destination
                    || current.closed
                    || current.recovery_hold
                    || current.outcome.is_some()
                    || cancel.requested()
                {
                    return Err(err("release held"));
                }
            }
            // Every SQL guard has dropped; the allocator lease remains held through publication.
            if let Some(proof) = gap_proof {
                launch.release_gap(driver, proof)
            } else {
                match capture_proof {
                    Some(proof) => launch.release_captured(driver, proof),
                    None => launch.release(driver),
                }
            }
            .map_err(err)?;
            drop(lock);
            drop(fresh_store);
            None
        };
        let deadline = Instant::now() + Duration::from_secs(settings.runtime_max_seconds);
        let mut cancel_at = cancelled_blocked.as_ref().map(|_| Instant::now());
        let mut root_code = cancelled_blocked.as_ref().and_then(|status| status.code());
        let mut root_seen = cancelled_blocked.is_some();
        let mut root_at = cancel_at;
        loop {
            let now = Instant::now();
            if (cancel.requested() || now >= deadline) && cancel_at.is_none() {
                // Fresh manager + original opaque Binding only, never PID/killpg.
                launch.cancel(driver).map_err(err)?;
                cancel_at = Some(Instant::now());
            }
            if !root_seen {
                if let Some(status) = launch.try_wait().map_err(err)? {
                    root_code = status.code();
                    let outcome = if cancel_at.is_some() {
                        RootOutcome::Cancelled
                    } else if status.success() {
                        RootOutcome::Completed
                    } else {
                        RootOutcome::Failed
                    };
                    db(store.record_root_outcome(&request, outcome))?;
                    root_seen = true;
                    root_at = Some(Instant::now());
                    observer(Boundary::RootTerminal, &record(&store, &request)?);
                }
            }
            if root_seen {
                let snapshot = db(store.group_snapshot(&request.identity().run))?;
                if let Ok(proof) = snapshot.certify_empty(
                    driver,
                    launch.binding().ok_or_else(|| err("missing binding"))?,
                ) {
                    let seal = match (&live, completion) {
                        (Some(live), CaptureCompletion::Certify) => {
                            db(store.close_live_capture(&snapshot, &proof, live))?.1
                        }
                        _ => {
                            db(store.close_supervised_group(&snapshot, &proof))?;
                            None
                        }
                    };
                    physically_closed = true;
                    observer(Boundary::Closed, &record(&store, &request)?);
                    if let Some(seal) = seal {
                        // Physical closure is already committed. Neither FINISH
                        // nor fresh filesystem inspection spans SQL or flock.
                        let (_, finalization) = db(crate::capture_finalization::finalize(
                            config,
                            &request.identity().run,
                        ))?;
                        if let crate::capture_finalization::FinalizeResult::Confirmed {
                            acknowledgement,
                            ..
                        } = finalization
                        {
                            db(crate::capture_readiness::restore(
                                config,
                                seal,
                                acknowledgement,
                            ))?;
                        }
                    }
                    return report(&store, &request.identity().run, false, root_code);
                }
            }
            if cancel_at.is_some_and(|at: Instant| {
                at.elapsed() >= Duration::from_millis(settings.cancel_grace_ms)
            }) || root_at.is_some_and(|at: Instant| {
                at.elapsed() >= Duration::from_millis(settings.closure_grace_ms)
            }) {
                db(store.record_recovery_hold(&request))?;
                return report(&store, &request.identity().run, false, root_code);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_err() && !physically_closed {
        let held = store.record_recovery_hold(&request).is_ok();
        if live.is_some() && !held {
            return Err(err("captured supervision refused; recovery hold uncertain"));
        }
    }
    result
}
fn parse_command(
    request: Run,
) -> io::Result<(RootCommand, Option<crate::run_journal::AttributionDecision>)> {
    if io::stdin().is_terminal() || io::stdout().is_terminal() || io::stderr().is_terminal() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "interactive TTY/job-control unsupported; use non-terminal protocol stdio",
        ));
    }
    let bytes = crate::identity::read_metadata(&request.execution_chain, 131_072)
        .map_err(|_| err("execution chain file unreadable or oversized"))?;
    let execution_chain: ExecutionChain =
        serde_json::from_slice(&bytes).map_err(|_| err("invalid typed execution chain JSON"))?;
    let attribution = request.attribution;
    let command = RootCommand {
        checkout: request.checkout,
        actor: request.actor,
        run_id: request.run_id,
        execution_chain,
        argv: request.argv,
    };
    Ok((command, attribution))
}
/// Explicit-Off history is resolved before execution policy from the same document.
pub(crate) fn command_off_document(
    document: &crate::config::ConfigDocument,
    request: Run,
) -> io::Result<i32> {
    let (command, attribution) = parse_command(request)?;
    if attribution != Some(crate::run_journal::AttributionDecision::Off) {
        return Err(err("Off required"));
    }
    let authority = document
        .authority()
        .map_err(|_| err("invalid configuration"))?;
    if let Some(report) = off_existing_report(&authority, &command)? {
        return Ok(print_report(&report));
    }
    let config = document
        .execution()
        .map_err(|_| err("invalid configuration"))?;
    command_parsed(&config, command, attribution)
}
/// CLI signal handlers only request cancellation; no handler sends OS signals.
pub fn command(config: &Config, request: Run) -> io::Result<i32> {
    let (command, attribution) = parse_command(request)?;
    command_parsed(config, command, attribution)
}
fn command_parsed(
    config: &Config,
    command: RootCommand,
    attribution: Option<crate::run_journal::AttributionDecision>,
) -> io::Result<i32> {
    if attribution.is_some() {
        if let Some(report) = off_existing_report(config, &command)? {
            return Ok(print_report(&report));
        }
    } else {
        if let Some(report) = captured_existing_report(config, &command, false)? {
            return Ok(print_report(&report));
        }
        if let Some(report) = existing_report(config, &command)? {
            return Ok(print_report(&report));
        }
    }
    let settings = config
        .supervisor
        .as_ref()
        .ok_or_else(|| err("supervisor not configured"))?;
    settings.policy()?;
    let context = RuntimeContext::new(
        settings.runtime_directory.clone(),
        settings.bus_address.clone(),
    )
    .map_err(err)?;
    let driver = Driver::new(context).map_err(err)?;
    let cancel = CancelToken::default();
    let mut handlers = Vec::new();
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        match signal_hook::flag::register(signal, cancel.0.clone()) {
            Ok(id) => handlers.push(id),
            Err(e) => {
                for id in handlers {
                    signal_hook::low_level::unregister(id);
                }
                return Err(e);
            }
        }
    }
    let result = if attribution.is_some() {
        supervise_off(config, command, &driver, None, &cancel, |_, _| {})
    } else if config
        .allocation
        .as_ref()
        .is_some_and(|a| a.capture_sink.is_some())
    {
        supervise_captured(
            config,
            command,
            &driver,
            None,
            &cancel,
            |_, _| {},
            CaptureCompletion::Certify,
        )
    } else {
        supervise(config, command, &driver, None, &cancel, |_, _| {})
    };
    for id in handlers {
        signal_hook::low_level::unregister(id);
    }
    let report = result?;
    Ok(print_report(&report))
}
fn print_report(report: &RunReport) -> i32 {
    eprintln!(
        "run {}: root={:?}; writer_group={}; lease={}; task={}; readiness={}; capture={}; delivery={:?}; attribution={}; receipt={}; observed_exit={:?}",
        report.record.request.identity().run,
        report.record.outcome,
        if report.record.closed {
            "closed"
        } else {
            "held; inspect durable journal; historical binding restoration unsupported"
        },
        if report.lease_charged { "charged" } else { "uncharged" },
        if report.task_open { "open" } else { "finished" },
        if report.checkout_ready { "ready" } else { "not_ready" },
        if report.gap.is_some() { "gap_no_session" } else if report.capture_unfrozen { "unfrozen" } else if report.capture_delivery.is_some() { "frozen" } else { "not_configured" },
        report.capture_delivery,
        if report.gap.is_some() { "off" } else if report.attribution_not_configured {
            "not_configured"
        } else {
            "configured"
        },
        report.existing,
        report.exit_code
    );
    if let Some(gap) = &report.gap {
        eprintln!("attribution_gap: event_recorded={}; event_id={}; delivery={:?}; transport_deferred={}; origin={}",gap.event_recorded,gap.event_id,gap.delivery,gap.transport_deferred,gap.origin);
        if gap.origin == "required_initial" {
            eprintln!("RequiredInitial: charge retained; physical closure leaves held/not_ready; next root and new finish unsupported");
        }
    }
    report.process_exit_code()
}
