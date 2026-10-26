//! Library surface for the `work` binary.
//!
//! Task 1 exposes read-only help and status only. Later commands must fail
//! closed rather than silently succeed.

#![forbid(unsafe_code)]

#[cfg(test)]
extern crate self as work_cli;
#[cfg(test)]
#[path = "../tests/support/run_fixture.rs"]
pub(crate) mod test_run_fixture;

pub mod admission;
pub mod adopted;
pub mod allocate;
mod attribution_gap;
mod bounded_process;
mod capture_artifacts;
pub mod capture_bridge;
pub mod capture_cli;
pub mod capture_config;
#[cfg(test)]
mod capture_diagnostics;
pub mod capture_finalization;
pub mod capture_journal;
pub mod capture_preparation;
mod capture_readiness;
mod capture_recovery;
mod capture_requirement;
pub mod capture_setup;
mod checkout_guard;
pub mod cli;
pub mod config;
pub mod disposal;
pub mod doctor;
pub mod error;
pub mod events;
pub mod finish;
mod gap_continuation;
pub mod identity;
pub mod inspection;
mod interactive;
pub mod linux_scope;
pub mod ownership;
pub mod participant_cli;
pub mod participants;
mod quarantine_journal;
pub mod recovery;
mod removal_journal;
mod retirement_journal;
pub mod run_journal;
pub mod run_participants;
pub mod run_recovery;
pub mod runtime_scope;
pub mod scope_child;
pub mod scope_driver;
pub mod scope_launch;
pub mod scope_spawn;
pub mod sinks;
pub mod store;
pub mod supervisor;

#[cfg(test)]
use crate as collector_target;
#[cfg(test)]
#[path = "../tests/support/capture_collector.rs"]
pub(crate) mod test_capture_collector;
#[cfg(test)]
#[path = "../tests/support/lifecycle_regressions.rs"]
pub(crate) mod test_lifecycle_fixture;
