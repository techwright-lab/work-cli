//! Library surface for the `work` binary.
//!
//! Task 1 exposes read-only help and status only. Later commands must fail
//! closed rather than silently succeed.

#![forbid(unsafe_code)]

pub mod admission;
pub mod adopted;
pub mod allocate;
mod bounded_process;
pub mod cli;
pub mod config;
pub mod doctor;
pub mod error;
pub mod events;
pub mod identity;
pub mod linux_scope;
pub mod ownership;
pub mod participant_cli;
pub mod participants;
pub mod recovery;
pub mod run_journal;
pub mod run_participants;
pub mod run_recovery;
pub mod runtime_scope;
pub mod scope_child;
pub mod scope_driver;
pub mod scope_launch;
pub mod scope_spawn;
pub mod store;
pub mod supervisor;
