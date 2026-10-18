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
}

/// Parse arguments and execute a read-only command. Clap exits for help/version.
pub fn run() {
    let cli = Cli::parse();
    match cli.command {
        Command::Status => print_status(),
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
