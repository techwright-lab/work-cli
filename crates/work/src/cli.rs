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
    let cli = Cli::parse();
    match cli.command {
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
