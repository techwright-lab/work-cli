//! Guarded handoff of an **already prepared** child, not a systemd-run launcher.
//!
//! Caller must durably persist launch intent and writer BEFORE constructing this
//! handle, and persist `binding()` AFTER `bind` and BEFORE `release`. No method
//! combines those boundaries. Dropping this handle never deletes gate records or
//! claims closure; after release, journal recovery owns every uncertain outcome.
//!
//! This increment deliberately cannot spawn: `systemd-run` may fork, so preparing
//! a context with the supervisor as the assumed immediate parent is unsafe. A
//! future launcher must discover/revalidate the actual child and parent, prove
//! launch ancestry and owned-unit membership, and monitor the controller before
//! adopting its gate here. This module supplies none of that bootstrap proof.
use crate::{
    runtime_scope::{self, Binding, LaunchIntent},
    scope_child::Prepared,
    scope_driver::Driver,
};
use std::time::{Duration, Instant};
type Result<T> = std::result::Result<T, &'static str>;
const HOLD: &str = "scope launch held";
const MAX_AGE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Prepared,
    Blocked,
    Bound,
    /// Permit published, not proof of exec, exit or quiescence.
    Released,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Pending,
    WriterReleased,
    /// Request accepted by manager, not proof that any process exited.
    CancellationRequested,
    RecoveryHold,
}
/// Nonserializable handoff handle. No drop cleanup, implicit release or signals.
pub struct GuardedLaunch {
    intent: LaunchIntent,
    gate: Prepared,
    phase: Phase,
    outcome: Outcome,
    binding: Option<Binding>,
}
impl GuardedLaunch {
    /// Adopt a gate prepared with the verified **actual immediate parent**.
    /// This does not authorize spawning or authenticate a launch ancestry claim.
    pub fn adopt_prepared(intent: LaunchIntent, gate: Prepared) -> Self {
        Self {
            intent,
            gate,
            phase: Phase::Prepared,
            outcome: Outcome::Pending,
            binding: None,
        }
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }
    /// Read-only metadata boundary for durable journaling; never publishes permit.
    pub fn binding(&self) -> Option<&Binding> {
        self.binding.as_ref()
    }
    pub fn poll_blocked(&mut self) -> Result<bool> {
        if self.outcome != Outcome::Pending
            || !matches!(self.phase, Phase::Prepared | Phase::Blocked)
        {
            return Err(HOLD);
        }
        let result = self.gate.read_ready().map(|ready| {
            if ready.is_some() {
                self.phase = Phase::Blocked;
            }
            ready.is_some()
        });
        self.record(result)
    }
    /// Collect complete fresh driver evidence; caller persists the result before release.
    pub fn bind(&mut self, driver: &Driver) -> Result<()> {
        if self.phase != Phase::Blocked || self.outcome != Outcome::Pending {
            return Err(HOLD);
        }
        let result = (|| {
            let ready = self.gate.read_ready()?.ok_or(HOLD)?;
            let observation = driver.observe(&self.intent, None, None);
            let binding = runtime_scope::bind(
                &self.intent,
                ready.child(),
                &observation,
                Instant::now(),
                MAX_AGE,
            )
            .map_err(|_| HOLD)?;
            self.binding = Some(binding);
            self.phase = Phase::Bound;
            Ok(())
        })();
        self.record(result)
    }
    /// Irreversible gate publication. Caller MUST journal binding before this call.
    /// Reobserve immediately; cached bind-time membership cannot release a writer.
    pub fn release(&mut self, driver: &Driver) -> Result<()> {
        if self.phase != Phase::Bound || self.outcome != Outcome::Pending {
            return Err(HOLD);
        }
        let result = (|| {
            let binding = self.binding.as_ref().ok_or(HOLD)?;
            let observation = driver.observe(&self.intent, Some(binding), None);
            runtime_scope::bind(
                &self.intent,
                binding.trusted_child(),
                &observation,
                Instant::now(),
                MAX_AGE,
            )
            .map_err(|_| HOLD)?;
            self.gate.release(binding)?;
            self.phase = Phase::Released;
            self.outcome = Outcome::WriterReleased;
            Ok(())
        })();
        self.record(result)
    }
    /// Only the exact freshly observed bound unit is eligible. No PID/killpg fallback.
    /// Does not authorize deletion, retirement, or a closed journal outcome.
    pub fn cancel(&mut self, driver: &Driver) -> Result<()> {
        let result = self
            .binding
            .as_ref()
            .ok_or(HOLD)
            .and_then(|binding| driver.cancel_bound(&self.intent, binding));
        match result {
            Ok(()) => {
                self.outcome = Outcome::CancellationRequested;
                Ok(())
            }
            Err(_) => {
                self.outcome = Outcome::RecoveryHold;
                Err(HOLD)
            }
        }
    }
    fn record<T>(&mut self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            self.outcome = Outcome::RecoveryHold;
        }
        result
    }
}
