//! Library surface for the `work` binary.
//!
//! Task 1 exposes read-only help and status only. Later commands must fail
//! closed rather than silently succeed.

#![forbid(unsafe_code)]

pub mod cli;
pub mod config;
pub mod error;
