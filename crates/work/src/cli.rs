use clap::{Parser, Subcommand};
use work_contract::SchemaVersion;

use crate::config::Config;

#[cfg(test)]
mod git_option_tests {
    use super::*;

    #[test]
    fn root_globals_preserve_private_and_sensitive_command_boundaries() {
        for args in [
            vec!["--git", "/private/selector", "__scope-child"],
            vec!["--git=/private/selector", "run"],
            vec!["--git", "/private/selector", "--", "recover"],
        ] {
            let argv: Vec<std::ffi::OsString> = args.iter().map(Into::into).collect();
            assert_eq!(command_args(&argv)[0], args[args.len() - 1]);
        }
        let args: Vec<std::ffi::OsString> = ["--git", "run", "skill", "install"]
            .into_iter()
            .map(Into::into)
            .collect();
        assert_eq!(command_args(&args)[0], "skill");
    }

    #[test]
    fn global_git_is_accepted_before_or_after_subcommands_without_qualification() {
        for argv in [
            vec!["work", "--git", "/missing/git", "skill", "install"],
            vec!["work", "skill", "--git=/missing/git", "install"],
            vec!["work", "skill", "install", "--git", "/missing/git"],
        ] {
            assert_eq!(
                Cli::try_parse_from(argv).unwrap().git,
                Some("/missing/git".into())
            );
        }
    }
}

#[derive(Parser)]
#[command(
    name = "work",
    version,
    about = "Worktrees for interactive agent tasks",
    long_about = "Create or reuse a task worktree, run your agent there, then explicitly finish and remove it. Linux-first; help and status are read-only."
)]
struct Cli {
    /// Absolute Git executable; invocation-only except confirmed setup proposals
    #[arg(long, global = true, value_name = "ABSOLUTE_PATH")]
    git: Option<std::path::PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Terminal capture journal reconciliation only; no runtime or task authority
    #[command(version, propagate_version = true, hide = true)]
    Capture {
        #[command(subcommand)]
        command: crate::capture_cli::Command,
    },
    /// Child metadata only: no launch, writer permission or automatic handoff
    #[command(version, propagate_version = true, hide = true)]
    Participant {
        #[command(subcommand)]
        command: crate::participant_cli::Command,
    },
    /// Adopted declarations only: no process control, Git identity or automatic handoff
    #[command(hide = true)]
    Adopt {
        #[command(subcommand)]
        command: crate::adopted::Command,
    },
    /// Install embedded agent instructions without Python or a source checkout
    Skill {
        #[command(subcommand)]
        command: SkillCommand,
    },
    /// Guided or headless configuration without initializing Work authority
    Setup(crate::setup::SetupArgs),
    /// Reserve and create a configured checkout; does not launch a writer
    Start(crate::allocate::Start),
    /// Preview removal of a finished interactive checkout; branches are retained
    Remove {
        #[arg(value_name = "task-or-checkout-id")]
        checkout: String,
        /// Confirm that all agents, editors and other writers have stopped
        #[arg(long)]
        confirm_stopped: bool,
    },
    /// Observe checkout content; no deletion permission. Only --record writes provenance
    Inspect {
        #[arg(value_name = "checkout-id", value_parser = crate::inspection::parse_checkout)]
        checkout: uuid::Uuid,
        #[arg(long)]
        record: bool,
    },
    /// Observe configured remote ancestry once; no recording or retirement authority
    #[command(hide = true)]
    VerifyRemote {
        #[arg(value_name = "checkout-uuidv7", value_parser = crate::inspection::parse_checkout)]
        checkout: uuid::Uuid,
    },
    /// Audit configured preservation and additional local work; never retirement authority
    #[command(hide = true)]
    AuditPreservation {
        #[arg(value_name = "checkout-uuidv7", value_parser = crate::inspection::parse_checkout)]
        checkout: uuid::Uuid,
    },
    /// Two explicit adopted observations and operator assertion; never OS or retirement authority
    #[command(hide = true)]
    Approve {
        #[command(subcommand)]
        command: crate::inspection::ApprovalCommand,
    },
    /// Create local recovery-ref protection; never remote backup or retirement authority
    #[command(hide = true)]
    PrepareRecovery {
        #[arg(value_name = "checkout-uuidv7", value_parser = crate::inspection::parse_checkout)]
        checkout: uuid::Uuid,
        /// Required together with --operation before any ref or receipt mutation
        #[arg(long)]
        create: bool,
        /// Caller-selected operation identity, never caller-supplied evidence
        #[arg(long, value_parser = crate::inspection::parse_checkout)]
        operation: Option<uuid::Uuid>,
    },
    /// Persistent retirement intent fence; never move, delete or live activation
    #[command(hide = true)]
    Retire {
        #[command(subcommand)]
        command: RetireCommand,
    },
    /// Mark the task finished; retain checkout and charge until explicit removal
    Finish {
        #[arg(value_name = "task-or-checkout-id")]
        checkout: String,
    },
    /// Run an explicitly attributed command in a verified allocated checkout
    #[command(hide = true)]
    Run(crate::supervisor::Run),
    /// Show lifecycle status without changing state
    Status {
        #[arg(long)]
        json: bool,
        /// Historical UUIDv7 metadata only; runtime is NOT INSPECTED
        #[arg(long)]
        run: Option<uuid::Uuid>,
    },
    /// Try fresh full-roster supervised writer handoff; never launch, signal, finish or uncharge
    #[command(hide = true)]
    Recover {
        #[arg(value_name = "run-id")]
        run: uuid::Uuid,
    },
    /// Bounded read-only inventory; no initialization, repair or enforcement
    Doctor {
        #[arg(long)]
        json: bool,
        #[arg(long = "repository")]
        repositories: Vec<std::path::PathBuf>,
        #[arg(long = "managed-root")]
        roots: Vec<std::path::PathBuf>,
        #[arg(long)]
        store_dir: Option<std::path::PathBuf>,
        #[arg(long)]
        trusted_registry: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum SkillCommand {
    /// Register the bundled skill in ~/.agents/skills; preserves unrelated targets
    Install {
        /// Also register in ~/.claude/skills and ~/.codex/skills
        #[arg(long)]
        all: bool,
    },
}

// Only root global selectors precede the command. Do not search arbitrary argv:
// delegated commands and selector values may themselves spell Work commands.
fn command_args(mut args: &[std::ffi::OsString]) -> &[std::ffi::OsString] {
    loop {
        match args.first() {
            Some(arg) if arg == "--git" => {
                if args.len() < 2 {
                    return &[];
                }
                args = &args[2..];
            }
            Some(arg) if arg.as_encoded_bytes().starts_with(b"--git=") => args = &args[1..],
            Some(arg) if arg == "--" => return &args[1..],
            _ => return args,
        }
    }
}

/// Parse arguments and dispatch. Help/version parsing is read-only.
pub fn run() {
    // Parse the private entry point without Clap diagnostics echoing sensitive argv.
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(target_os = "macos")]
    refuse_incomplete_native_command(&args);
    let private_args = command_args(&args);
    if private_args.first().is_some_and(|a| a == "__scope-child") {
        #[cfg(not(target_os = "macos"))]
        if private_args.len() >= 5 && private_args[1] == "--context" && private_args[3] == "--" {
            let _ =
                crate::scope_child::run(std::path::Path::new(&private_args[2]), &private_args[4..]);
        }
        eprintln!("scope child held");
        std::process::exit(1);
    }
    dispatch_public(&args);
}

// Refuse before parsing identifiers or touching config/context/history. Never echo argv.
// These are development-build boundaries, not implemented Darwin capabilities.
#[cfg(target_os = "macos")]
fn refuse_incomplete_native_command(args: &[std::ffi::OsString]) {
    match command_args(args).first().and_then(|arg| arg.to_str()) {
        Some("__scope-child" | "run" | "recover") => {
            eprintln!("execution/supervision unsupported on macOS; no runtime action taken");
            std::process::exit(1);
        }
        Some(
            "setup" | "start" | "finish" | "remove" | "inspect" | "verify-remote"
            | "audit-preservation" | "prepare-recovery" | "approve" | "retire" | "capture"
            | "participant" | "adopt",
        ) => {
            eprintln!(
                "native backend incomplete; managed operation refused before authority access"
            );
            std::process::exit(1);
        }
        _ => {}
    }
}

/// Shared public argv boundary; the private scope-child entry remains in `run`.
pub(crate) fn dispatch_public(args: &[std::ffi::OsString]) {
    #[cfg(target_os = "macos")]
    refuse_incomplete_native_command(args);
    let argv = std::iter::once(std::ffi::OsString::from("work")).chain(args.iter().cloned());
    let cli = if command_args(args).first().is_some_and(|a| {
        a == "capture"
            || a == "inspect"
            || a == "verify-remote"
            || a == "audit-preservation"
            || a == "prepare-recovery"
            || a == "approve"
            || a == "finish"
            || a == "run"
            || a == "recover"
            || a == "status"
            || a == "adopt"
            || a == "participant"
            || a == "retire"
            || a == "remove"
    }) {
        match Cli::try_parse_from(argv) {
            Ok(cli) => cli,
            Err(error)
                if matches!(
                    error.kind(),
                    clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
                ) =>
            {
                error.exit()
            }
            Err(_) => {
                eprintln!("invalid command arguments; see work --help (delegate argv requires --)");
                std::process::exit(2);
            }
        }
    } else {
        Cli::parse_from(argv)
    };
    let git_override = cli.git;
    let invocation = crate::git::GitInvocation::unconfigured(git_override.clone());
    match cli.command {
        Command::Setup(mut args) => {
            args.git_path = git_override;
            crate::setup::command(args)
        }
        Command::Skill {
            command: SkillCommand::Install { all },
        } => match crate::skill_install::install(all) {
            Ok(report) => println!(
                "{}",
                serde_json::to_string(&report).expect("skill report serialization")
            ),
            Err(reason) => {
                eprintln!("skill installation held: {reason}; no Work authority modified");
                std::process::exit(1);
            }
        },
        Command::Remove {
            checkout,
            confirm_stopped,
        } => {
            let result = (|| {
                let config = Config::load().map_err(|e| e.to_string())?;
                let id =
                    crate::interactive::resolve(&config, &checkout).map_err(|e| e.to_string())?;
                crate::inspection::removal::command(&invocation, &config, id, confirm_stopped)
            })();
            match result {
                Ok(report) => println!(
                    "{}",
                    serde_json::to_string(&report).expect("removal serialization")
                ),
                Err(reason) => {
                    eprintln!("remove held: {reason}; inspect status; no force or automatic retry");
                    std::process::exit(1);
                }
            }
        }
        Command::Capture { command } => {
            let result = Config::load_capture_authority()
                .map_err(|_| crate::store::StoreError::Unsafe)
                .and_then(|config| {
                    crate::capture_cli::command_with_git(&invocation, &config, command)
                });
            match result {
                Ok(report) => {
                    println!(
                        "{}",
                        serde_json::to_string(&report).expect("capture serialization")
                    );
                    if report.is_held() {
                        std::process::exit(1);
                    }
                }
                Err(crate::store::StoreError::UpgradeRequired) => {
                    eprintln!("capture held: authority schema upgrade required; result unknown");
                    std::process::exit(1);
                }
                Err(_) => {
                    eprintln!(
                        "capture held: invalid_metadata_or_existing_authority; result unknown"
                    );
                    std::process::exit(1);
                }
            }
        }
        Command::Participant { command } => {
            let result = Config::load()
                .map_err(|_| crate::store::StoreError::Unsafe)
                .and_then(|config| crate::participant_cli::command(&config, command));
            match result {
                Ok(report) => {
                    println!(
                        "{}",
                        serde_json::to_string(&report).expect("participant serialization")
                    );
                    if report.is_held() {
                        std::process::exit(1);
                    }
                }
                Err(_) => {
                    eprintln!(
                        "participant refused: invalid_metadata_or_existing_authority; inspect explicit root/child context and current schema; no execution permission"
                    );
                    std::process::exit(1);
                }
            }
        }
        Command::Adopt { command } => {
            let result = Config::load()
                .map_err(|_| crate::store::StoreError::Unsafe)
                .and_then(|config| crate::adopted::command_with_git(&invocation, &config, command));
            match result {
                Ok(report) => println!("{report}"),
                Err(_) => {
                    eprintln!(
                        "adopted declaration refused/unknown; inspect explicit IDs, existing authority and held lease; no runtime authority granted"
                    );
                    std::process::exit(1);
                }
            }
        }
        Command::Start(mut request) => {
            eprintln!(
                "allocation operation: {} (retain for retries)",
                request.operation
            );
            let result = (|| {
                let document =
                    crate::config::ConfigDocument::load().map_err(std::io::Error::other)?;
                let config = document.execution().map_err(std::io::Error::other)?;
                if request.repository.is_none() && config.repositories.len() == 1 {
                    request.repository = config.repositories.first().cloned();
                }
                if request.root.is_none() && config.roots.len() == 1 {
                    request.root = config.roots.first().cloned();
                }
                if request.actor.is_none() {
                    request.actor = document.default_actor().map_err(std::io::Error::other)?;
                }
                crate::allocate::start_with_git(&invocation, &config, request)
            })();
            match result {
                Ok(a) => println!(
                    "{}",
                    serde_json::to_string(&a).expect("allocation serialization")
                ),
                Err(e) => {
                    eprintln!(
                        "start refused: {e}; inspect WORK_CONFIG and held allocations; retry with the same --operation UUID"
                    );
                    if matches!(
                        e.get_ref()
                            .and_then(|e| e.downcast_ref::<crate::store::StoreError>()),
                        Some(crate::store::StoreError::Capacity)
                    ) {
                        if let Some(status) = Config::load()
                            .ok()
                            .and_then(|config| crate::interactive::status(&config).ok())
                        {
                            for row in status.checkouts.into_iter().filter(|row| row.charged) {
                                eprintln!(
                                    "charged checkout: {} task={} owner={} path={}; next: {}",
                                    row.checkout,
                                    row.task,
                                    row.owner,
                                    row.path.display(),
                                    row.next_action
                                );
                            }
                        }
                    }
                    std::process::exit(1);
                }
            }
        }
        Command::Inspect { checkout, record } => {
            let result = crate::inspection::configured_report(&invocation, checkout, record);
            match result {
                Ok(report) => {
                    println!(
                        "{}",
                        serde_json::to_string(&report).expect("inspection summary serialization")
                    );
                    if report.is_held() {
                        std::process::exit(1);
                    }
                }
                Err(_) => {
                    eprintln!(
                        "inspection unavailable: invalid policy or existing authority; no deletion permission"
                    );
                    std::process::exit(1);
                }
            }
        }
        Command::VerifyRemote { checkout } => {
            let report = crate::inspection::verify_remote_with_git(&invocation, checkout);
            println!(
                "{}",
                serde_json::to_string(&report).expect("remote observation serialization")
            );
            if !report.observed() {
                std::process::exit(1);
            }
        }
        Command::AuditPreservation { checkout } => {
            let report = crate::inspection::audit_preservation_with_git(&invocation, checkout);
            println!(
                "{}",
                serde_json::to_string(&report).expect("preservation audit serialization")
            );
            if !report.observed() {
                std::process::exit(1);
            }
        }
        Command::Approve { command } => {
            let report = match command {
                crate::inspection::ApprovalCommand::Begin { checkout } => {
                    crate::inspection::approve_begin_with_git(&invocation, checkout)
                }
                crate::inspection::ApprovalCommand::Confirm {
                    checkout,
                    observation,
                    assert_quiescent,
                } => crate::inspection::approve_confirm_with_git(
                    &invocation,
                    checkout,
                    observation,
                    assert_quiescent,
                ),
            };
            println!(
                "{}",
                serde_json::to_string(&report).expect("approval summary serialization")
            );
            if !report.recorded() {
                std::process::exit(1);
            }
        }
        Command::PrepareRecovery {
            checkout,
            create,
            operation,
        } => {
            let report = match (create, operation) {
                (true, Some(operation)) => {
                    crate::inspection::prepare_recovery_with_git(&invocation, checkout, operation)
                }
                _ => crate::inspection::prepare_recovery_refused(checkout),
            };
            println!(
                "{}",
                serde_json::to_string(&report).expect("recovery preparation serialization")
            );
            if !report.prepared() {
                std::process::exit(1);
            }
        }
        Command::Finish { checkout } => {
            let result = Config::load()
                .map_err(|_| crate::store::StoreError::Unsafe)
                .and_then(|config| {
                    let id = crate::interactive::resolve_finish(&config, &checkout)?;
                    crate::finish::finish_with_git(&invocation, &config, id)
                });
            match result {
                Ok(report) => {
                    println!(
                        "{}",
                        serde_json::to_string(&report).expect("finish serialization")
                    );
                    if report.is_held() {
                        std::process::exit(1);
                    }
                }
                Err(_) => {
                    eprintln!(
                        "finish refused: invalid existing authority, identity or writer context; tree and charge retained"
                    );
                    std::process::exit(1);
                }
            }
        }
        Command::Run(request) => {
            eprintln!("run: {} (retain --run-id for retries)", request.run_id);
            let result = if request.attribution.is_some() {
                crate::config::ConfigDocument::load()
                    .map_err(|_| std::io::Error::other("invalid configuration"))
                    .and_then(|document| {
                        crate::supervisor::command_off_document_with_git(
                            &invocation,
                            &document,
                            request,
                        )
                    })
            } else {
                Config::load()
                    .map_err(|_| std::io::Error::other("invalid configuration"))
                    .and_then(|config| {
                        crate::supervisor::command_with_git(&invocation, &config, request)
                    })
            };
            match result {
                Ok(code) => std::process::exit(code),
                Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                    eprintln!(
                        "interactive TTY/job-control unsupported; use non-terminal protocol stdio; no delegate launched"
                    );
                    std::process::exit(1);
                }
                Err(_) => {
                    eprintln!(
                        "run held/refused; inspect lease and run journal; retry only with the same --run-id; historical bindings cannot be restored"
                    );
                    std::process::exit(1);
                }
            }
        }
        Command::Status { run: None, json } => print_status(json),
        Command::Status { run: Some(run), .. } => {
            let result = Config::load()
                .map_err(|_| crate::store::StoreError::Unsafe)
                .and_then(|config| crate::run_recovery::command_status(&config, run));
            match result {
                Ok(report) => println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("status serialization")
                ),
                Err(crate::store::StoreError::UpgradeRequired) => {
                    eprintln!("historical status unknown: authority schema upgrade required");
                    std::process::exit(1);
                }
                Err(_) => {
                    eprintln!(
                        "historical status unknown: existing trusted authority unavailable or invalid"
                    );
                    std::process::exit(1);
                }
            }
        }
        Command::Recover { run } => {
            let result = crate::config::ConfigDocument::load()
                .map_err(|_| crate::store::StoreError::Unsafe)
                .and_then(|document| crate::run_recovery::command_recover_document(&document, run));
            match result {
                Ok(state) => {
                    println!(
                        "{}",
                        serde_json::to_string(&state).expect("recovery serialization")
                    );
                    if matches!(state, crate::run_recovery::RecoveryState::Held { .. }) {
                        std::process::exit(1);
                    }
                }
                Err(_) => {
                    eprintln!(
                        "recovery held: existing trusted authority, schema or runtime unavailable; no launch, task completion or charge release"
                    );
                    std::process::exit(1);
                }
            }
        }
        Command::Retire { command } => retire(&invocation, command),
        Command::Doctor {
            json,
            repositories,
            roots,
            store_dir,
            trusted_registry,
        } => {
            let result = (|| {
                let mut config = Config::load()?;
                if !repositories.is_empty() {
                    config.repositories = repositories;
                }
                if !roots.is_empty() {
                    config.roots = roots;
                }
                if store_dir.is_some() {
                    config.store_dir = store_dir;
                }
                if trusted_registry.is_some() {
                    config.trusted_registry = trusted_registry;
                }
                crate::doctor::report_with_git(&config, &invocation)
            })();
            match result {
                Ok(report) => {
                    // JSON is also the initial human-readable format; pretty by default.
                    let text = if json {
                        serde_json::to_string(&report)
                    } else {
                        serde_json::to_string_pretty(&report)
                    };
                    match text {
                        Ok(text) => println!("{text}"),
                        Err(_) => {
                            eprintln!("doctor report unavailable");
                            std::process::exit(1);
                        }
                    }
                }
                Err(_) => {
                    eprintln!(
                        "doctor requires valid explicit scope and configuration; see work doctor --help"
                    );
                    std::process::exit(1);
                }
            }
        }
    }
}

#[derive(Subcommand)]
enum RetireCommand {
    /// Persist a prepared retirement fence; production execution stays disabled
    Prepare {
        #[arg(long, value_parser = crate::inspection::parse_checkout)]
        operation: uuid::Uuid,
        #[arg(long, value_parser = crate::inspection::parse_checkout)]
        assertion: Option<uuid::Uuid>,
        #[arg(long)]
        task_complete: bool,
        #[arg(value_name = "checkout", value_parser = crate::inspection::parse_checkout)]
        checkout: uuid::Uuid,
    },
    /// Explicit validated abort; never auto-clears on expiry, reboot or flag removal
    Abort {
        #[arg(long, value_parser = crate::inspection::parse_checkout)]
        operation: uuid::Uuid,
        #[arg(long)]
        revision: u64,
        #[arg(value_name = "checkout", value_parser = crate::inspection::parse_checkout)]
        checkout: uuid::Uuid,
    },
    /// Read-only fence description; cannot mint capability
    Status {
        #[arg(value_name = "checkout", value_parser = crate::inspection::parse_checkout)]
        checkout: uuid::Uuid,
    },
}

fn retire(invocation: &crate::git::GitInvocation, command: RetireCommand) {
    let path = match crate::config::Config::discover_path() {
        Some(path) => path,
        None => {
            eprintln!("retire refused: configuration path unknown");
            std::process::exit(2);
        }
    };
    let report = match command {
        RetireCommand::Prepare {
            operation,
            assertion,
            task_complete,
            checkout,
        } => crate::inspection::prepare_retirement_with_git(
            invocation,
            &path,
            checkout,
            operation,
            assertion,
            task_complete,
        ),
        RetireCommand::Abort {
            operation,
            revision,
            checkout,
        } => crate::inspection::abort_retirement_with_git(
            invocation, &path, checkout, operation, revision,
        ),
        RetireCommand::Status { checkout } => crate::inspection::retirement_status(&path, checkout),
    };
    println!(
        "{}",
        serde_json::to_string(&report).expect("retirement serialization")
    );
    // Interpret the result under the actual requested command, not a heuristic
    // inferred from the report. In particular a fresh validated abort succeeds.
    let ok = match command {
        RetireCommand::Prepare { .. } => matches!(report.outcome(), "prepared" | "existing"),
        RetireCommand::Abort { .. } => matches!(report.outcome(), "aborted" | "existing"),
        RetireCommand::Status { .. } => report.outcome() == "observed",
    };
    if !ok {
        std::process::exit(1);
    }
}

fn print_status(json: bool) {
    // Read-only: a missing or present config never creates files.
    let config = Config::load().unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(1);
    });
    let os = std::env::consts::OS;
    let qualification = "runtime qualification not verified";
    if config.store_dir.is_some() {
        match crate::interactive::status(&config) {
            Ok(report) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string(&report).expect("status serialization")
                    );
                    return;
                } else {
                    if !report.initialized {
                        println!("status: not initialized (configured authority absent)");
                    }
                    println!("charged: {}", report.charged);
                    for row in report.checkouts {
                        println!(
                            "{}  {}  owner={}  {}  {}\n  {}\n  next: {}",
                            row.checkout,
                            row.task,
                            row.owner,
                            row.state,
                            if row.task_finished {
                                "finished"
                            } else {
                                "unfinished"
                            },
                            row.path.display(),
                            row.next_action
                        );
                        if let Some(reason) = row.reason {
                            println!("  reason: {reason}");
                        }
                    }
                }
            }
            Err(error) => {
                eprintln!(
                    "status unavailable: {error}; existing authority was not initialized or repaired"
                );
                std::process::exit(1);
            }
        }
    } else {
        if json {
            println!("{{\"initialized\":false,\"charged\":0,\"checkouts\":[]}}");
            return;
        }
        println!("status: not initialized (no store configured)");
    }
    println!("platform: {os}");
    println!("qualification: {qualification}");
    println!("schema: {}", SchemaVersion::V1);
}
