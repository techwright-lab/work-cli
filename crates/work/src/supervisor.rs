//! Concrete root-only coordinator. Intent/writer -> blocked spawn -> bind journal
//! -> permit-attempt journal -> release -> root status -> fresh whole-scope proof.
//! A root exit is never writer release. Holds retain charges and task openness.
//! Historical bindings cannot be restored; retry receipts never grant execution.
//! No external/adopted participants, bridge capture, finish or retirement support.
//!
//! Polling policy is finite, but kernel D-state can delay pre-exec kill/reaping
//! indefinitely. Released roots retain an owned reaper on drop (see scope_spawn).
//! Interactive TTY/job-control is not qualified: CLI refuses terminal stdio rather
//! than moving a foreground protocol into a background process group silently.
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
    RootTerminal,
    Closed,
}
#[derive(Debug)]
pub struct RunReport {
    pub record: RunRecord,
    pub existing: bool,
    pub exit_code: Option<i32>,
    pub lease_charged: bool,
    pub task_open: bool,
    pub attribution_not_configured: bool,
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
fn command_digest(argv: &[OsString]) -> io::Result<[u8; 32]> {
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
fn report(record: RunRecord, existing: bool, exit_code: Option<i32>) -> RunReport {
    RunReport {
        record,
        existing,
        exit_code,
        lease_charged: true,
        task_open: true,
        attribution_not_configured: true,
    }
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
fn supervise(
    config: &Config,
    command: RootCommand,
    driver: &Driver,
    io: Option<LaunchIo>,
    cancel: &CancelToken,
    mut observer: impl FnMut(Boundary, &RunRecord),
) -> io::Result<RunReport> {
    let settings = config
        .supervisor
        .as_ref()
        .ok_or_else(|| err("configure supervisor and actor Git profiles"))?;
    let policy = settings.policy()?;
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
        return Ok(report(record(&store, &request)?, true, None));
    }
    observer(Boundary::Intent, &record(&store, &request)?);
    // All failures after intent retain writer and charge; never invent an outcome.
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
        let mut launch = OwnedLaunch::spawn_attributed(
            driver,
            intent,
            &directory,
            AttributedCommand {
                cwd: &allocation.destination,
                argv: &command.argv,
                git: profile,
            },
            policy,
            io,
        )
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
            // Do not reconcile/revive holds at the irreversible boundary. Other
            // checkouts remain allocatable for the entire running actor lifetime.
            let (mut fresh_store, lock) = allocate::locked(config)?;
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
            launch.release(driver).map_err(err)?;
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
                    db(store.close_supervised_group(&snapshot, &proof))?;
                    observer(Boundary::Closed, &record(&store, &request)?);
                    return Ok(report(record(&store, &request)?, false, root_code));
                }
            }
            if cancel_at.is_some_and(|at: Instant| {
                at.elapsed() >= Duration::from_millis(settings.cancel_grace_ms)
            }) || root_at.is_some_and(|at: Instant| {
                at.elapsed() >= Duration::from_millis(settings.closure_grace_ms)
            }) {
                db(store.record_recovery_hold(&request))?;
                return Ok(report(record(&store, &request)?, false, root_code));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_err() {
        let _ = store.record_recovery_hold(&request);
    }
    result
}
/// CLI signal handlers only request cancellation; no handler sends OS signals.
pub fn command(config: &Config, request: Run) -> io::Result<i32> {
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
    let result = supervise(
        config,
        RootCommand {
            checkout: request.checkout,
            actor: request.actor,
            run_id: request.run_id,
            execution_chain,
            argv: request.argv,
        },
        &driver,
        None,
        &cancel,
        |_, _| {},
    );
    for id in handlers {
        signal_hook::low_level::unregister(id);
    }
    let report = result?;
    eprintln!("run {}: root={:?}; writer_group={}; lease=charged; task=open; attribution=not_configured; receipt={}", report.record.request.identity().run, report.record.outcome, if report.record.closed {"closed"} else {"held; inspect durable journal; historical binding restoration unsupported"}, report.existing);
    Ok(report.process_exit_code())
}
