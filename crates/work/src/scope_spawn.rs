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
    pub(crate) fn capture_profile(&self) -> crate::capture_bridge::GitProfile {
        crate::capture_bridge::GitProfile {
            author_name: Some(self.author_name.clone()),
            author_email: Some(self.author_email.clone()),
            committer_name: Some(self.committer_name.clone()),
            committer_email: Some(self.committer_email.clone()),
        }
    }
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
enum LaunchGuard {
    Ordinary,
    Captured(crate::capture_preparation::CapturedGuard),
    Gap(crate::attribution_gap::GapGuard),
}
pub(crate) enum ReleaseProof<'a> {
    Ordinary,
    Captured(&'a crate::capture_preparation::CapturedReleaseProof),
    Gap(&'a crate::attribution_gap::GapReleaseProof),
}
pub(crate) enum PublishProof<'a> {
    Ordinary,
    Captured(&'a crate::capture_preparation::CapturedReleaseProof),
    Gap(
        &'a crate::attribution_gap::GapReleaseProof,
        &'a crate::store::Store,
        &'a crate::allocate::AuthorityLease,
    ),
}
impl ReleaseProof<'_> {
    fn validate_guard(&self, guard: &LaunchGuard) -> Result<()> {
        match (self, guard) {
            (Self::Ordinary, LaunchGuard::Ordinary) => Ok(()),
            (Self::Captured(proof), LaunchGuard::Captured(guard)) => {
                proof.validate(guard).and_then(|()| proof.fresh())
            }
            (Self::Gap(proof), LaunchGuard::Gap(guard)) => proof.validate(guard).map_err(|_| HOLD),
            _ => Err(HOLD),
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReleaseMode {
    Ordinary,
    Captured,
    Gap,
}
impl LaunchGuard {
    fn mode(&self) -> ReleaseMode {
        match self {
            Self::Ordinary => ReleaseMode::Ordinary,
            Self::Captured(_) => ReleaseMode::Captured,
            Self::Gap(_) => ReleaseMode::Gap,
        }
    }
}
/// Private, non-Clone observation tied to one owned launch and exact Binding.
pub(crate) struct PreparedRelease {
    observed: Instant,
    identity: std::sync::Arc<()>,
    mode: ReleaseMode,
    binding: crate::runtime_scope::ScopeIdentity,
    child: crate::runtime_scope::ChildIdentity,
    boot: String,
}
pub struct OwnedLaunch {
    gate: GuardedLaunch,
    child: Option<Child>,
    pid: u32,
    deadline: Instant,
    /// Set BEFORE publication: an fsync failure may still have exposed a permit.
    permit_attempted: bool,
    guard: LaunchGuard,
    release_identity: std::sync::Arc<()>,
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
        Self::spawn_inner(driver, intent, directory, cwd, argv, policy, io, None, None)
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
            None,
        )
    }
    pub(crate) fn spawn_gap(
        driver: &Driver,
        intent: LaunchIntent,
        directory: &Path,
        command: AttributedCommand<'_>,
        policy: LaunchPolicy,
        io: Option<LaunchIo>,
        live: &crate::attribution_gap::CreatedOffLive,
    ) -> Result<Self> {
        live.validate_launch(&intent, &command).map_err(|_| HOLD)?;
        let io = match io {
            Some(io) => io,
            None => LaunchIo {
                systemd_run: "/usr/bin/systemd-run".into(),
                self_binary: std::env::current_exe().map_err(|_| HOLD)?,
            },
        };
        let mut launch = Self::spawn_inner(
            driver,
            intent,
            directory,
            command.cwd,
            command.argv,
            policy,
            io,
            Some(command.git),
            None,
        )?;
        launch.guard = LaunchGuard::Gap(live.guard());
        Ok(launch)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn_captured(
        driver: &Driver,
        intent: LaunchIntent,
        directory: &Path,
        root: &crate::run_journal::RootRunRequest,
        command: AttributedCommand<'_>,
        policy: LaunchPolicy,
        io: Option<LaunchIo>,
        live: &crate::capture_preparation::LiveCapture,
    ) -> Result<Self> {
        live.validate_launch(root, &command).map_err(|_| HOLD)?;
        let expected =
            LaunchIntent::new(root.identity().run.clone(), &root.input().boot).map_err(|_| HOLD)?;
        if intent.unit_name() != expected.unit_name() || intent.boot_id() != expected.boot_id() {
            return Err(HOLD);
        }
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
            Some(live),
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
        capture: Option<&crate::capture_preparation::LiveCapture>,
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
        if let Some(live) = capture {
            live.apply_environment(&mut command);
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
            release_identity: std::sync::Arc::new(()),
            guard: capture
                .map(|live| LaunchGuard::Captured(live.guard()))
                .unwrap_or(LaunchGuard::Ordinary),
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
        self.check_owned_root()?;
        let result = self.gate.poll_blocked_owned(self.pid);
        let blocked = self.preexec_result(result)?;
        self.check_owned_root()?;
        Ok(blocked)
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
        let prepared = self.observe_release(driver, ReleaseProof::Ordinary)?;
        self.publish_prepared_release(prepared, PublishProof::Ordinary)
    }
    pub(crate) fn observe_release(
        &mut self,
        driver: &Driver,
        proof: ReleaseProof<'_>,
    ) -> Result<PreparedRelease> {
        let observed = Instant::now();
        let checked = proof.validate_guard(&self.guard);
        self.preexec_result(checked)?;
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
        let checked = proof.validate_guard(&self.guard);
        self.preexec_result(checked)?;
        let binding = self.binding().ok_or(HOLD)?;
        Ok(PreparedRelease {
            observed,
            identity: self.release_identity.clone(),
            mode: self.guard.mode(),
            binding: binding.identity().clone(),
            child: binding.trusted_child().clone(),
            boot: binding.boot_id().into(),
        })
    }
    pub(crate) fn publish_prepared_release(
        &mut self,
        prepared: PreparedRelease,
        proof: PublishProof<'_>,
    ) -> Result<()> {
        if self.permit_attempted {
            return Err(HOLD);
        }
        let checked = (|| {
            self.check_prepared(&prepared)?;
            match proof {
                PublishProof::Ordinary => ReleaseProof::Ordinary.validate_guard(&self.guard)?,
                PublishProof::Captured(captured) => {
                    ReleaseProof::Captured(captured).validate_guard(&self.guard)?;
                }
                PublishProof::Gap(gap, store, lease) => {
                    ReleaseProof::Gap(gap).validate_guard(&self.guard)?;
                    gap.validate_current(store, self.binding().ok_or(HOLD)?, lease)
                        .map_err(|_| HOLD)?;
                }
            }
            // SQL comparison above may consume the remainder of the ORIGINAL
            // pre-exec/observation budget. Recheck at the actual publication edge.
            self.check_prepared(&prepared)
        })();
        if checked.is_err() {
            // No driver call or blocking child reap while the caller holds a lease.
            self.gate.recovery_hold();
            return Err(HOLD);
        }
        self.permit_attempted = true;
        self.gate.publish_release()
    }
    fn check_prepared(&self, prepared: &PreparedRelease) -> Result<()> {
        let now = Instant::now();
        let binding = self.binding().ok_or(HOLD)?;
        if self.permit_attempted
            || self.phase() != Phase::Bound
            || self.outcome() != Outcome::Pending
            || now >= self.deadline
            || !std::sync::Arc::ptr_eq(&prepared.identity, &self.release_identity)
            || prepared.mode != self.guard.mode()
            || &prepared.binding != binding.identity()
            || &prepared.child != binding.trusted_child()
            || prepared.boot != binding.boot_id()
            || now
                .checked_duration_since(prepared.observed)
                .is_none_or(|age| age > Duration::from_secs(2))
        {
            return Err(HOLD);
        }
        Ok(())
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
        self.check_owned_root()?;
        let result = self.gate.ready_pid().and_then(|ready| {
            if ready.is_some_and(|pid| pid != self.pid) {
                Err(HOLD)
            } else {
                Ok(())
            }
        });
        self.preexec_result(result)
    }
    fn check_owned_root(&mut self) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_scope::ChildIdentity;
    use crate::scope_driver::{LibraryIo, Limits, RuntimeContext};
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, net::UnixListener},
    };

    // Real prepared gate and driver parsing, fixture-only membership evidence.
    // No containment or retirement capability is manufactured by this fixture.
    struct Fixture {
        temp: tempfile::TempDir,
        _bus: UnixListener,
        driver: Driver,
        launch: OwnedLaunch,
    }
    impl Fixture {
        fn bound() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let p = temp.path();
            for name in ["runtime", "gate"] {
                fs::create_dir(p.join(name)).unwrap();
                fs::set_permissions(p.join(name), fs::Permissions::from_mode(0o700)).unwrap();
            }
            let bus = UnixListener::bind(p.join("runtime/bus")).unwrap();
            let boot = "f312459a-9346-4d02-9139-c80a7017d962";
            let intent = LaunchIntent::new(
                work_contract::RunId::parse(&uuid::Uuid::now_v7().to_string()).unwrap(),
                boot,
            )
            .unwrap();
            let unit = intent.unit_name().to_owned();
            let mut identity = ChildIdentity {
                pid: std::process::id(),
                start_ticks: 123,
                boot: boot.into(),
                cgroup: format!("/user.slice/{unit}"),
            };
            let gate = prepare(
                &p.join("gate"),
                &intent,
                &identity,
                p,
                OriginalRuntime::new(None, None),
                Duration::from_secs(30),
            )
            .unwrap();
            // Install ownership immediately after spawn, before any fallible fixture
            // setup, so a failed assertion cannot orphan the blocked process.
            let child = Command::new("/usr/bin/cat")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            let pid = child.id();
            identity.pid = pid;
            let mut launch = OwnedLaunch {
                gate: GuardedLaunch::adopt_prepared(intent, gate),
                child: Some(child),
                pid,
                deadline: Instant::now() + Duration::from_secs(30),
                permit_attempted: false,
                guard: LaunchGuard::Ordinary,
                release_identity: std::sync::Arc::new(()),
            };
            let context: serde_json::Value =
                serde_json::from_slice(&fs::read(p.join("gate/context.json")).unwrap()).unwrap();
            fs::write(p.join("gate/ready.json"), serde_json::to_vec(&serde_json::json!({
                "nonce": context["nonce"], "cwd": context["cwd"],
                "child": {"pid": pid, "start_ticks": 123, "boot": boot, "cgroup": identity.cgroup}
            })).unwrap()).unwrap();
            fs::set_permissions(p.join("gate/ready.json"), fs::Permissions::from_mode(0o600))
                .unwrap();
            fs::create_dir_all(p.join("proc/sys/kernel/random")).unwrap();
            fs::write(p.join("proc/sys/kernel/random/boot_id"), boot).unwrap();
            fs::create_dir_all(p.join(format!("proc/{pid}"))).unwrap();
            fs::write(
                p.join(format!("proc/{pid}/stat")),
                format!("{pid} (fixture) S {} 123 0\n", vec!["0"; 18].join(" ")),
            )
            .unwrap();
            fs::write(
                p.join(format!("proc/{pid}/cgroup")),
                format!("0::{}\n", identity.cgroup),
            )
            .unwrap();
            let group = p.join("cg").join(identity.cgroup.trim_start_matches('/'));
            fs::create_dir_all(&group).unwrap();
            fs::write(group.join("cgroup.type"), "domain\n").unwrap();
            fs::write(group.join("cgroup.procs"), format!("{pid}\n")).unwrap();
            fs::write(p.join("properties"), format!(
                "Id={}\nInvocationID=b312459a93464d029139c80a7017d962\nControlGroup={}\nLoadState=loaded\nActiveState=active\n",
                unit, identity.cgroup)).unwrap();
            fs::write(
                p.join("manager"),
                format!(
                    "#!/bin/sh\nexec /usr/bin/cat '{}/properties'\n",
                    p.display()
                ),
            )
            .unwrap();
            fs::set_permissions(p.join("manager"), fs::Permissions::from_mode(0o700)).unwrap();
            let driver = Driver::with_io(
                RuntimeContext::new(
                    p.join("runtime"),
                    format!("unix:path={}/runtime/bus", p.display()),
                )
                .unwrap(),
                LibraryIo {
                    systemctl: p.join("manager"),
                    proc_root: p.join("proc"),
                    cgroup_root: p.join("cg"),
                    between_censuses: None,
                },
                Limits::default(),
            )
            .unwrap();
            assert_eq!(launch.poll_blocked(), Ok(true));
            launch.bind(&driver).unwrap();
            Self {
                temp,
                _bus: bus,
                driver,
                launch,
            }
        }
        fn observe(&mut self) -> PreparedRelease {
            self.launch
                .observe_release(&self.driver, ReleaseProof::Ordinary)
                .unwrap()
        }
        fn refused(&mut self, prepared: PreparedRelease) {
            // Publication must not invoke the driver again, even on a refusal.
            fs::remove_file(self.temp.path().join("manager")).unwrap();
            assert!(self
                .launch
                .publish_prepared_release(prepared, PublishProof::Ordinary)
                .is_err());
            assert!(!self.launch.permit_attempted);
            assert!(!self.temp.path().join("gate/permit.json").exists());
            assert_eq!(self.launch.outcome(), Outcome::RecoveryHold);
        }
    }
    #[test]
    fn prepared_release_cannot_cross_launches() {
        let mut a = Fixture::bound();
        let mut b = Fixture::bound();
        let prepared = a.observe();
        b.refused(prepared);
        assert!(!a.temp.path().join("gate/permit.json").exists());
    }
    #[test]
    fn prepared_release_refuses_changed_mode_deadline_or_hold_after_observation() {
        for case in ["mode", "deadline", "hold", "cancel", "age"] {
            let mut f = Fixture::bound();
            let mut prepared = f.observe();
            match case {
                "mode" => prepared.mode = ReleaseMode::Captured,
                // Model crossing the ORIGINAL deadline, without sleeping or renewing observation.
                "deadline" => f.launch.deadline = prepared.observed,
                "hold" => f.launch.gate.recovery_hold(),
                "cancel" => {
                    let _ = f.launch.cancel(&f.driver);
                }
                "age" => prepared.observed -= Duration::from_secs(3),
                _ => unreachable!(),
            }
            f.refused(prepared);
        }
    }
    #[test]
    fn prepared_release_publishes_once_without_reobserving_driver() {
        let mut f = Fixture::bound();
        let earlier = f.observe();
        let prepared = f.observe();
        fs::remove_file(f.temp.path().join("manager")).unwrap();
        f.launch
            .publish_prepared_release(prepared, PublishProof::Ordinary)
            .unwrap();
        assert!(f.launch.permit_attempted);
        assert!(f.temp.path().join("gate/permit.json").exists());
        assert_eq!(f.launch.outcome(), Outcome::WriterReleased);
        assert!(f
            .launch
            .publish_prepared_release(earlier, PublishProof::Ordinary)
            .is_err());
        assert_eq!(f.launch.outcome(), Outcome::WriterReleased);
        // This fixture's blocked process is not a scope child. Explicitly end/reap it.
        f.launch.child.as_mut().unwrap().stdin.take();
        f.launch.wait().unwrap();
    }
}
