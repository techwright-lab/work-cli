use clap::{Parser, Subcommand};
use work_contract::SchemaVersion;

use crate::config::Config;

#[derive(Parser)]
#[command(
    name = "work",
    version,
    about = "Managed worktree lifecycle CLI",
    long_about = "Linux-first CLI for managed worktree lifecycle. Help and status are read-only."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Reserve and create a configured checkout; does not launch a writer
    Start(crate::allocate::Start),
    /// Show lifecycle status without changing state
    Status,
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

/// Parse arguments and execute a read-only command. Clap exits for help/version.
pub fn run() {
    // Parse the private entry point without Clap diagnostics echoing sensitive argv.
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|a| a == "__scope-child") {
        if args.len() >= 5 && args[1] == "--context" && args[3] == "--" {
            let _ = crate::scope_child::run(std::path::Path::new(&args[2]), &args[4..]);
        }
        eprintln!("scope child held");
        std::process::exit(1);
    }
    let cli = Cli::parse();
    match cli.command {
        Command::Start(request) => {
            eprintln!(
                "allocation operation: {} (retain for retries)",
                request.operation
            );
            let result = Config::load()
                .map_err(|e| std::io::Error::other(e.to_string()))
                .and_then(|config| crate::allocate::start(&config, request));
            match result {
                Ok(a) => println!(
                    "{}",
                    serde_json::to_string(&a).expect("allocation serialization")
                ),
                Err(e) => {
                    eprintln!("start refused: {e}; inspect WORK_CONFIG and held allocations; retry with the same --operation UUID");
                    std::process::exit(1);
                }
            }
        }
        Command::Status => print_status(),
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
                crate::doctor::report(&config)
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
                    eprintln!("doctor requires valid explicit scope and configuration; see work doctor --help");
                    std::process::exit(1);
                }
            }
        }
    }
}

fn print_status() {
    // Read-only: a missing or present config never creates files.
    let _config = Config::load().unwrap_or_else(|err| {
        eprintln!("{err}");
        Config::default()
    });
    let os = std::env::consts::OS;
    let qualification = if os == "linux" {
        "qualified"
    } else {
        "unqualified"
    };
    println!("status: not initialized");
    println!("platform: {os}");
    println!("qualification: {qualification}");
    println!("schema: {}", SchemaVersion::V1);
}
