//! Guarded handoff of an already prepared child; `scope_spawn` owns EXEC-style launch.
//!
//! Caller must durably persist launch intent and writer BEFORE constructing this
//! handle, and persist `binding()` AFTER `bind` and BEFORE `release`. No method
//! combines those boundaries. Dropping this handle never deletes gate records or
//! claims closure; after release, journal recovery owns every uncertain outcome.
//!
//! `scope_spawn` supports systemd's EXEC-style scope launch only: the ready PID
//! must remain the owned launcher PID and the child validates its actual parent.
//! This lower-level gate adapter alone does not authenticate launch ancestry.
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
    pub(crate) fn poll_blocked_owned(&mut self, expected_pid: u32) -> Result<bool> {
        self.poll_blocked_for(Some(expected_pid))
    }
    pub fn poll_blocked(&mut self) -> Result<bool> {
        self.poll_blocked_for(None)
    }
    fn poll_blocked_for(&mut self, expected_pid: Option<u32>) -> Result<bool> {
        if self.outcome != Outcome::Pending
            || !matches!(self.phase, Phase::Prepared | Phase::Blocked)
        {
            return Err(HOLD);
        }
        let result = self.gate.read_ready().and_then(|ready| {
            if let Some(ready) = ready {
                if expected_pid.is_some_and(|pid| ready.child().pid != pid) {
                    return Err(HOLD);
                }
                self.phase = Phase::Blocked;
                Ok(true)
            } else {
                Ok(false)
            }
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
        self.validate_release(driver)?;
        self.publish_release()
    }
    pub(crate) fn validate_release(&mut self, driver: &Driver) -> Result<()> {
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
            Ok(())
        })();
        self.record(result)
    }
    pub(crate) fn publish_release(&mut self) -> Result<()> {
        let result = self
            .binding
            .as_ref()
            .ok_or(HOLD)
            .and_then(|binding| self.gate.release(binding));
        if result.is_ok() {
            self.phase = Phase::Released;
            self.outcome = Outcome::WriterReleased;
        }
        self.record(result)
    }
    pub(crate) fn ready_pid(&self) -> Result<Option<u32>> {
        Ok(self.gate.read_ready()?.map(|ready| ready.child().pid))
    }
    pub(crate) fn recovery_hold(&mut self) {
        self.outcome = Outcome::RecoveryHold;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        runtime_scope::ChildIdentity,
        scope_child::{prepare, OriginalRuntime},
    };
    use std::{
        fs,
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    use work_contract::RunId;

    #[test]
    fn owned_poll_validates_the_ready_record_that_declares_blocked() {
        for (ready_pid, expected_pid) in [
            (None, Some(41)),
            (Some(41), Some(41)),
            (Some(42), Some(41)),
            (Some(42), None),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let intent = LaunchIntent::new(
                RunId::parse("019281b2-67de-7000-8000-000000000001").unwrap(),
                "f312459a-9346-4d02-9139-c80a7017d962",
            )
            .unwrap();
            let child = ChildIdentity {
                pid: 41,
                start_ticks: 123,
                boot: intent.boot_id().into(),
                cgroup: format!("/user.slice/{}", intent.unit_name()),
            };
            let gate = prepare(
                tmp.path(),
                &intent,
                &child,
                tmp.path(),
                OriginalRuntime::new(None, None),
                Duration::from_secs(2),
            )
            .unwrap();
            let context: serde_json::Value =
                serde_json::from_slice(&fs::read(gate.context_path()).unwrap()).unwrap();
            let mut launch = GuardedLaunch::adopt_prepared(intent, gate);
            // Model the old ownership precheck, then publish before the poll's read.
            assert_eq!(launch.ready_pid().unwrap(), None);
            if let Some(pid) = ready_pid {
                let ready_child = serde_json::json!({
                    "pid": pid, "start_ticks": child.start_ticks,
                    "boot": child.boot, "cgroup": child.cgroup,
                });
                let ready = serde_json::json!({
                    "nonce": context["nonce"], "cwd": context["cwd"], "child": ready_child,
                });
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(tmp.path().join("ready.json"))
                    .unwrap();
                file.write_all(&serde_json::to_vec(&ready).unwrap())
                    .unwrap();
                file.sync_all().unwrap();
            }
            let result = match expected_pid {
                Some(pid) => launch.poll_blocked_owned(pid),
                None => launch.poll_blocked(),
            };
            if ready_pid.is_some() && expected_pid.is_some() && ready_pid != expected_pid {
                assert!(result.is_err(), "foreign ready must not report Blocked");
                assert_eq!(launch.phase(), Phase::Prepared);
                assert_eq!(launch.outcome(), Outcome::RecoveryHold);
            } else {
                assert_eq!(result, Ok(ready_pid.is_some()));
                assert_eq!(
                    launch.phase(),
                    if ready_pid.is_some() {
                        Phase::Blocked
                    } else {
                        Phase::Prepared
                    }
                );
                assert_eq!(launch.outcome(), Outcome::Pending);
            }
            assert!(launch.binding().is_none());
            assert!(!tmp.path().join("permit.json").exists());
        }
    }
}
