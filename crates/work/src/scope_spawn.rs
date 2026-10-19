//! Owned EXEC-style Linux user-scope launch (systemd 261 scope path joins self,
//! then execvpe, without forking). Any unexpected ready PID fails closed.
//!
//! Persist launch intent + writer BEFORE spawn; persist `binding()` BEFORE release.
//! No method infers scope quiescence from the root's exit. Keep the handle and
//! explicitly wait/cancel/recover after release; drop never deletes gate records.
//!
//! Cleanup sends SIGKILL only through the still-owned, unreaped `Child`, never a
//! scope PID or process group. The subsequent kernel wait is NOT strictly bounded:
//! an uninterruptible kernel sleep can delay reaping despite SIGKILL. After permit
//! publication is attempted, drop only starts a root reaper, never kills work.
//! That reaper can wait indefinitely on a stuck kernel task; thread creation failure
//! emits a fixed recovery-hold diagnostic. Durable journal recovery remains required.
//! Callers must not install an external reaper for this handle's exclusively owned PID.
use crate::{
    runtime_scope::{Binding, LaunchIntent},
    scope_child::{prepare, OriginalRuntime},
    scope_driver::{live_process, Driver},
    scope_launch::{GuardedLaunch, Outcome, Phase},
};
use std::{
    ffi::OsString,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, &'static str>;
const HOLD: &str = "scope launch held";
/// Explicit library-only fixture seam. Never selected by production CLI/env flags.
pub struct LaunchIo {
    pub systemd_run: PathBuf,
    pub self_binary: PathBuf,
}
/// Trusted finite policy, not arbitrary manager properties or command-line text.
pub struct LaunchPolicy {
    runtime_seconds: u64,
    preexec: Duration,
}
impl LaunchPolicy {
    /// Whole-second scope limit, 1s..24h; pre-exec deadline, 1ms..30s.
    pub fn new(runtime_max: Duration, preexec: Duration) -> Result<Self> {
        if runtime_max.subsec_nanos() != 0
            || !(1..=86_400).contains(&runtime_max.as_secs())
            || !(Duration::from_millis(1)..=Duration::from_secs(30)).contains(&preexec)
        {
            return Err(HOLD);
        }
        Ok(Self {
            runtime_seconds: runtime_max.as_secs(),
            preexec,
        })
    }
}
/// Explicit Git attribution, never human identity fallback or arbitrary environment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "GitWire")]
pub struct ActorGitProfile {
    author_name: String,
    author_email: String,
    committer_name: String,
    committer_email: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GitWire {
    author_name: String,
    author_email: String,
    committer_name: String,
    committer_email: String,
}
impl TryFrom<GitWire> for ActorGitProfile {
    type Error = &'static str;
    fn try_from(w: GitWire) -> Result<Self> {
        Self::new(
            &w.author_name,
            &w.author_email,
            &w.committer_name,
            &w.committer_email,
        )
    }
}
impl ActorGitProfile {
    pub fn new(
        author_name: &str,
        author_email: &str,
        committer_name: &str,
        committer_email: &str,
    ) -> Result<Self> {
        if [author_name, author_email, committer_name, committer_email]
            .iter()
            .any(|v| v.trim().is_empty() || v.len() > 256 || v.chars().any(char::is_control))
        {
            return Err(HOLD);
        }
        Ok(Self {
            author_name: author_name.into(),
            author_email: author_email.into(),
            committer_name: committer_name.into(),
            committer_email: committer_email.into(),
        })
    }
}
/// Typed command-scoped attribution; no arbitrary environment injection.
pub struct AttributedCommand<'a> {
    pub cwd: &'a Path,
    pub argv: &'a [OsString],
    pub git: &'a ActorGitProfile,
}
pub struct OwnedLaunch {
    gate: GuardedLaunch,
    child: Option<Child>,
    pid: u32,
    deadline: Instant,
    /// Set BEFORE publication: an fsync failure may still have exposed a permit.
    permit_attempted: bool,
}
impl OwnedLaunch {
    /// Fixed production tools and real controller birth/boot identity. Inherited
    /// protocol stdio belongs to the hidden child/delegate, never manager capture.
    pub fn spawn(
        driver: &Driver,
        intent: LaunchIntent,
        directory: &Path,
        cwd: &Path,
        argv: &[OsString],
        policy: LaunchPolicy,
    ) -> Result<Self> {
        Self::spawn_with_io(
            driver,
            intent,
            directory,
            cwd,
            argv,
            policy,
            LaunchIo {
                systemd_run: "/usr/bin/systemd-run".into(),
                self_binary: std::env::current_exe().map_err(|_| HOLD)?,
            },
        )
    }
    pub fn spawn_with_io(
        driver: &Driver,
        intent: LaunchIntent,
        directory: &Path,
        cwd: &Path,
        argv: &[OsString],
        policy: LaunchPolicy,
        io: LaunchIo,
    ) -> Result<Self> {
        Self::spawn_inner(driver, intent, directory, cwd, argv, policy, io, None)
    }
    pub fn spawn_attributed(
        driver: &Driver,
        intent: LaunchIntent,
        directory: &Path,
        command: AttributedCommand<'_>,
        policy: LaunchPolicy,
        io: Option<LaunchIo>,
    ) -> Result<Self> {
        let io = match io {
            Some(io) => io,
            None => LaunchIo {
                systemd_run: "/usr/bin/systemd-run".into(),
                self_binary: std::env::current_exe().map_err(|_| HOLD)?,
            },
        };
        Self::spawn_inner(
            driver,
            intent,
            directory,
            command.cwd,
            command.argv,
            policy,
            io,
            Some(command.git),
        )
    }
    #[allow(clippy::too_many_arguments)] // shared legacy unattributed gate + supervised typed entry
    fn spawn_inner(
        driver: &Driver,
        intent: LaunchIntent,
        directory: &Path,
        cwd: &Path,
        argv: &[OsString],
        policy: LaunchPolicy,
        io: LaunchIo,
        git: Option<&ActorGitProfile>,
    ) -> Result<Self> {
        let deadline = Instant::now().checked_add(policy.preexec).ok_or(HOLD)?;
        let original = OriginalRuntime::capture();
        if argv.is_empty()
            || argv.iter().any(|arg| arg.as_bytes().contains(&0))
            || !io.systemd_run.is_absolute()
            || !io.self_binary.is_absolute()
        {
            return Err(HOLD);
        }
        let parent = live_process(std::process::id()).map_err(|_| HOLD)?;
        if parent.boot != intent.boot_id() {
            return Err(HOLD);
        }
        // Exclusive private files and cwd identity are durable before any exec.
        let prepared = prepare(directory, &intent, &parent, cwd, original, policy.preexec)?;
        let mut command = Command::new(io.systemd_run);
        command
            .args([
                "--user",
                "--scope",
                "--quiet",
                "--no-ask-password",
                "--expand-environment=no",
            ])
            .arg(format!("--unit={}", intent.unit_name()))
            .arg("--description=work managed execution")
            .arg(format!(
                "--property=RuntimeMaxSec={}s",
                policy.runtime_seconds
            ))
            .arg("--")
            .arg(io.self_binary)
            .arg("__scope-child")
            .arg("--context")
            .arg(prepared.context_path())
            .arg("--")
            .args(argv)
            .current_dir(cwd)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        // Overrides only this manager command, after capturing original presence/bytes.
        driver.apply_manager_context(&mut command)?;
        // Scope launcher/hidden child/delegate share an owned process group;
        // never signal it as cancellation authority. CLI refuses unqualified TTY.
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        if let Some(git) = git {
            command
                .env("GIT_AUTHOR_NAME", &git.author_name)
                .env("GIT_AUTHOR_EMAIL", &git.author_email)
                .env("GIT_COMMITTER_NAME", &git.committer_name)
                .env("GIT_COMMITTER_EMAIL", &git.committer_email);
        }
        let child = loop {
            if Instant::now() >= deadline || live_process(parent.pid).map_err(|_| HOLD)? != parent {
                return Err(HOLD);
            }
            match command.spawn() {
                Ok(child) => break child,
                // ETXTBSY means exec never occurred: no manager/agent started.
                // A parallel fork can briefly retain a fresh launcher's writable
                // descriptor until exec closes it. Reuse the same prepared context
                // and immutable command, charging every retry to the original budget.
                Err(error)
                    if error.raw_os_error() == Some(rustix::io::Errno::TXTBSY.raw_os_error()) =>
                {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    std::thread::sleep(remaining.min(Duration::from_millis(2)));
                }
                Err(_) => return Err(HOLD),
            }
        };
        let pid = child.id();
        Ok(Self {
            gate: GuardedLaunch::adopt_prepared(intent, prepared),
            child: Some(child),
            pid,
            deadline,
            permit_attempted: false,
        })
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn phase(&self) -> Phase {
        self.gate.phase()
    }
    pub fn outcome(&self) -> Outcome {
        self.gate.outcome()
    }
    /// Caller persists this metadata before calling release, never after it.
    pub fn binding(&self) -> Option<&Binding> {
        self.gate.binding()
    }
    pub fn poll_blocked(&mut self) -> Result<bool> {
        if self.permit_attempted {
            return Err(HOLD);
        }
        self.check_owned()?;
        let result = self.gate.poll_blocked();
        self.preexec_result(result)
    }
    pub fn bind(&mut self, driver: &Driver) -> Result<()> {
        if self.permit_attempted {
            return Err(HOLD);
        }
        self.check_owned()?;
        let result = self.gate.bind(driver);
        self.preexec_result(result)?;
        // The bounded driver call may have crossed the pre-exec deadline.
        self.check_owned()
    }
    pub fn release(&mut self, driver: &Driver) -> Result<()> {
        if self.permit_attempted {
            return Err(HOLD);
        }
        if self.phase() != Phase::Bound {
            return self.preexec_result(Err(HOLD));
        }
        self.check_owned()?;
        let result = self.gate.validate_release(driver);
        self.preexec_result(result)?;
        self.check_owned()?;
        self.permit_attempted = true;
        self.gate.publish_release()
    }
    /// Fresh exact-unit manager request only; success is NOT scope quiescence.
    pub fn cancel(&mut self, driver: &Driver) -> Result<()> {
        let result = self.gate.cancel(driver);
        if !self.permit_attempted && self.stop_owned().is_err() {
            self.gate.recovery_hold();
            return Err(HOLD);
        }
        result
    }
    /// Root status only. Before permit, exit/deadline becomes a recovery hold.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        if !self.permit_attempted && Instant::now() >= self.deadline {
            self.gate.recovery_hold();
            self.stop_owned()?;
        }
        let result = self
            .child
            .as_mut()
            .ok_or(HOLD)?
            .try_wait()
            .map_err(|_| HOLD);
        match result {
            Ok(Some(_)) if !self.permit_attempted => self.gate.recovery_hold(),
            Err(_) => self.gate.recovery_hold(),
            _ => (),
        }
        result
    }
    /// Explicit root reap, never an empty-scope assertion. Before permit, honors
    /// the pre-exec deadline. After permit, kernel wait can be unbounded (see module).
    pub fn wait(&mut self) -> Result<ExitStatus> {
        if !self.permit_attempted {
            loop {
                if let Some(status) = self.try_wait()? {
                    return Ok(status);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        let result = self.child.as_mut().ok_or(HOLD)?.wait().map_err(|_| HOLD);
        if result.is_err() {
            self.gate.recovery_hold();
        }
        result
    }
    fn check_owned(&mut self) -> Result<()> {
        let result = (|| {
            if self.gate.outcome() != Outcome::Pending || Instant::now() >= self.deadline {
                return Err(HOLD);
            }
            if self
                .child
                .as_mut()
                .ok_or(HOLD)?
                .try_wait()
                .map_err(|_| HOLD)?
                .is_some()
            {
                return Err(HOLD);
            }
            if self.gate.ready_pid()?.is_some_and(|pid| pid != self.pid) {
                return Err(HOLD);
            }
            Ok(())
        })();
        self.preexec_result(result)
    }
    fn preexec_result<T>(&mut self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            self.gate.recovery_hold();
            // Preserve original hold even if kernel cleanup itself fails.
            if self.stop_owned().is_err() {
                eprintln!("scope launch recovery hold");
            }
        }
        result
    }
    fn stop_owned(&mut self) -> Result<()> {
        if self.permit_attempted {
            return Err(HOLD);
        }
        let child = self.child.as_mut().ok_or(HOLD)?;
        // try_wait may reap: never signal if it reported exit (PID may be reused).
        if child.try_wait().map_err(|_| HOLD)?.is_none() {
            child.kill().map_err(|_| HOLD)?;
            child.wait().map_err(|_| HOLD)?;
        }
        Ok(())
    }
}
impl Drop for OwnedLaunch {
    fn drop(&mut self) {
        if !self.permit_attempted {
            self.gate.recovery_hold();
            if self.stop_owned().is_err() {
                eprintln!("scope launch recovery hold");
            }
        } else if let Some(mut child) = self.child.take() {
            match child.try_wait() {
                Ok(Some(_)) => (),
                _ => {
                    // Do not kill released root or infer closure from dropping ownership.
                    if std::thread::Builder::new()
                        .name("scope-root-reaper".into())
                        .spawn(move || {
                            if child.wait().is_err() {
                                eprintln!("scope launch recovery hold");
                            }
                        })
                        .is_err()
                    {
                        eprintln!("scope launch recovery hold");
                    }
                }
            }
        }
    }
}
