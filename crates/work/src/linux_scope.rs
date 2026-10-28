//! Bounded, disposable Linux qualification, not a supervisor or retirement proof.
//! Default inspection is read-only. Real scopes require explicit opt-in; this
//! never certifies Paperclip origin or excludes malicious same-UID writers.
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Accounted,
    UnknownHold,
}
#[derive(Debug, Serialize)]
pub struct HostCapabilities {
    pub uid: Option<u32>,
    pub runtime_directory_available: bool,
    pub user_bus_available: bool,
    pub cgroup_v2: bool,
    pub current_cgroup: Option<String>,
    pub systemd_version: Option<String>,
    pub git_version: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Observation {
    pub fixture: String,
    pub pid: u32,
    pub cgroup: String,
}
#[derive(Debug, Serialize)]
pub struct QualificationReport {
    pub run_id: String,
    pub adapter: String,
    pub host: HostCapabilities,
    pub disposition: Disposition,
    pub fixture_executed: bool,
    pub paperclip_qualified: bool,
    pub unit: Option<String>,
    pub unit_owner_uid: Option<u32>,
    pub unit_properties: Option<String>,
    pub scope_cgroup: Option<String>,
    pub observed_members: Vec<u32>,
    pub observations: Vec<Observation>,
    pub cleanup_outcome: String,
    pub reasons: Vec<String>,
    pub limitations: Vec<String>,
}
pub struct QualificationOptions<'a> {
    pub run_id: &'a str,
    pub adapter: &'a str,
    pub opt_in_fixture: bool,
}
fn bounded(command: &mut Command, duration: Duration) -> io::Result<Output> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let start = Instant::now();
    while child.try_wait()?.is_none() {
        if start.elapsed() >= duration {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "bounded command timed out",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output()
}
fn systemctl(args: &[&str]) -> io::Result<Output> {
    bounded(
        Command::new("systemctl")
            .args(["--user", "--no-pager"])
            .args(args)
            .env("SYSTEMD_COLORS", "0"),
        Duration::from_secs(2),
    )
}
fn version(name: &str) -> Option<String> {
    let out = bounded(Command::new(name).arg("--version"), Duration::from_secs(2)).ok()?;
    out.status.success().then(|| {
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .chars()
            .take(160)
            .collect()
    })
}
fn cgroup(pid: &str) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
}
pub fn inspect_host() -> HostCapabilities {
    let uid = fs::read_to_string("/proc/self/status").ok().and_then(|s| {
        s.lines().find_map(|l| {
            l.strip_prefix("Uid:")
                .and_then(|s| s.split_whitespace().next()?.parse().ok())
        })
    });
    HostCapabilities {
        uid,
        runtime_directory_available: std::env::var_os("XDG_RUNTIME_DIR")
            .is_some_and(|p| Path::new(&p).is_dir()),
        // Degraded manager still has a bus; exit status alone is insufficient.
        user_bus_available: systemctl(&["show", "--property=Version", "--value"])
            .is_ok_and(|o| o.status.success() && !o.stdout.is_empty()),
        cgroup_v2: Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
        current_cgroup: cgroup("self"),
        systemd_version: version("systemctl"),
        git_version: version("git"),
    }
}
/// A point-in-time membership observation, never a claim of killpg containment.
pub fn assess_membership(bus: bool, scope: Option<&str>, observed: &[String]) -> Disposition {
    if bus
        && scope.is_some_and(|s| {
            s.starts_with('/')
                && s != "/"
                && !observed.is_empty()
                && observed.iter().all(|o| o == s)
        })
    {
        Disposition::Accounted
    } else {
        Disposition::UnknownHold
    }
}
fn property<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|l| l.strip_prefix(key))
}
fn group_path(group: &str) -> Option<PathBuf> {
    if !group.starts_with('/') || group == "/" || group.split('/').any(|s| s == ".." || s == ".") {
        return None;
    }
    Some(Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/')))
}
fn members(group: &str) -> Option<Vec<u32>> {
    fs::read_to_string(group_path(group)?.join("cgroup.procs"))
        .ok()?
        .split_whitespace()
        .map(|p| p.parse().ok())
        .collect()
}
/// Identity captured from the exact newly created disposable scope.
#[derive(Clone, Copy)]
pub struct ScopeIdentity<'a> {
    pub unit: &'a str,
    pub cgroup: &'a str,
}
#[derive(Clone, Copy)]
pub struct UnitState<'a> {
    pub id: &'a str,
    pub load: &'a str,
    pub active: &'a str,
    pub cgroup: &'a str,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ParticipantState {
    Absent,
    Present,
    Unknown,
}
pub struct CleanupEvidence<'a> {
    pub created_scope: Option<ScopeIdentity<'a>>,
    pub unit_state: Option<UnitState<'a>>,
    pub membership: Option<&'a [u32]>,
    pub cgroup_absent: bool,
    pub participants: &'a [ParticipantState],
}
/// Point-in-time fixture cleanup only; grants no creation or retirement authority.
pub fn assess_cleanup(evidence: CleanupEvidence<'_>) -> bool {
    let Some(scope) = evidence.created_scope else {
        return false;
    };
    if !valid_label(scope.unit)
        || !scope.unit.starts_with("work-qualification-")
        || !scope.unit.ends_with(".scope")
        || group_path(scope.cgroup).is_none()
        || scope.cgroup.rsplit('/').next() != Some(scope.unit)
    {
        return false;
    }
    if evidence.participants.is_empty()
        || evidence
            .participants
            .iter()
            .any(|state| *state != ParticipantState::Absent)
    {
        return false;
    }
    if let Some(membership) = evidence.membership {
        return membership.is_empty();
    }
    evidence.cgroup_absent
        && evidence.unit_state.is_some_and(|state| {
            state.id == scope.unit
                && matches!(state.load, "loaded" | "not-found")
                && state.active == "inactive"
                && (state.cgroup.is_empty() || state.cgroup == scope.cgroup)
        })
}
fn participant_state(pid: u32) -> ParticipantState {
    // A present PID is never assumed to be a reused identity or safely dead.
    // Only ENOENT proves absence; permission/metadata errors hold.
    match fs::symlink_metadata(format!("/proc/{pid}")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => ParticipantState::Absent,
        Ok(_) => ParticipantState::Present,
        Err(_) => ParticipantState::Unknown,
    }
}
fn valid_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
pub fn qualify(options: QualificationOptions<'_>) -> io::Result<QualificationReport> {
    if !valid_label(options.run_id) || !valid_label(options.adapter) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "use bounded non-secret run/adapter identifiers",
        ));
    }
    let mut report = QualificationReport {
        run_id: options.run_id.into(), adapter: options.adapter.into(), host: inspect_host(),
        disposition: Disposition::UnknownHold, fixture_executed: false, paperclip_qualified: false,
        unit: None, unit_owner_uid: None, unit_properties: None, scope_cgroup: None,
        observed_members: vec![], observations: vec![], cleanup_outcome: "not-started".into(), reasons: vec![],
        limitations: vec!["Cooperative point-in-time fixture evidence only; not exclusion against malicious same-UID processes or unrelated writers.".into(), "Paperclip origin/adapter qualification requires independently reviewed actual-run evidence; labels are caller supplied.".into(), "Process groups, parent exit and rename do not prove quiescence; unknown membership holds retirement.".into()],
    };
    if !options.opt_in_fixture {
        report
            .reasons
            .push("real-user-scope-fixture-not-opted-in".into());
        return Ok(report);
    }
    if !report.host.user_bus_available || !report.host.cgroup_v2 {
        report
            .reasons
            .push("user-bus-or-cgroup-v2-unavailable".into());
        return Ok(report);
    }
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos()
    );
    let unit = format!("work-qualification-{suffix}.scope");
    let root = std::env::temp_dir().join(format!("work-qualification-{suffix}"));
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let result = run_fixture(&mut report, &root, &unit);
    // Only this private fixture directory. No live checkout/process cleanup.
    let _ = fs::remove_dir_all(&root);
    if result.is_err() {
        report.disposition = Disposition::UnknownHold;
        report.reasons.push("fixture-inspection-failed".into());
    }
    Ok(report)
}
fn run_fixture(report: &mut QualificationReport, root: &Path, unit: &str) -> io::Result<()> {
    report.unit = Some(unit.into());
    let mut child = Command::new("systemd-run")
        .args([
            "--user",
            "--scope",
            "--quiet",
            "--unit",
            unit,
            "--property=RuntimeMaxSec=10s",
            "python3",
            "-c",
            FIXTURE,
        ])
        .arg(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    report.fixture_executed = true;
    let start = Instant::now();
    while !root.join("ready").exists() && start.elapsed() < Duration::from_secs(3) {
        if child.try_wait()?.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    if let Ok(output) = systemctl(&[
        "show",
        unit,
        "--property=ControlGroup",
        "--property=Id",
        "--property=LoadState",
        "--property=ActiveState",
        "--property=Slice",
    ]) {
        let properties = String::from_utf8_lossy(&output.stdout).into_owned();
        if output.status.success()
            && property(&properties, "Id=") == Some(unit)
            && property(&properties, "LoadState=") == Some("loaded")
        {
            report.scope_cgroup = property(&properties, "ControlGroup=")
                .filter(|s| group_path(s).is_some() && s.rsplit('/').next() == Some(unit))
                .map(str::to_owned);
            // Unit queried through this UID's user manager, not the system manager.
            report.unit_owner_uid = report.host.uid;
        }
        report.unit_properties = Some(properties);
    }
    if let Some(group) = &report.scope_cgroup {
        report.observed_members = members(group).unwrap_or_default();
    }
    let mut live_membership = true;
    for case in [
        "setsid",
        "double_fork_parent_exit",
        "cwd_fd",
        "exit_during_inspection",
    ] {
        match fs::read(root.join(format!("{case}.json")))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Observation>(&bytes).ok())
        {
            Some(o) => {
                // Receipt alone is not fresh evidence: transient exit must hold.
                live_membership &= cgroup(&o.pid.to_string()).as_deref() == Some(o.cgroup.as_str())
                    && report.observed_members.contains(&o.pid);
                report.observations.push(o);
            }
            None => live_membership = false,
        }
    }
    report.disposition = assess_membership(
        report.host.user_bus_available,
        report.scope_cgroup.as_deref(),
        &report
            .observations
            .iter()
            .map(|o| o.cgroup.clone())
            .collect::<Vec<_>>(),
    );
    if !live_membership || report.unit_owner_uid.is_none() {
        report.disposition = Disposition::UnknownHold;
        report
            .reasons
            .push("incomplete-or-terminated-during-inspection-membership".into());
    }
    if report.disposition == Disposition::UnknownHold {
        report.reasons.push("scope-membership-not-proven".into());
    }
    // Bounded payloads exit themselves. Never signal a process group or arbitrary PID.
    while child.try_wait()?.is_none() && start.elapsed() < Duration::from_secs(12) {
        thread::sleep(Duration::from_millis(30));
    }
    if child.try_wait()?.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    // Stop only the exact scope whose identity was observed after creation.
    // Stop success or failure alone is never cleanup evidence.
    let empty = if let Some(group) = report.scope_cgroup.as_deref() {
        let _ = systemctl(&["stop", unit]);
        let output = systemctl(&[
            "show",
            unit,
            "--property=Id",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=ControlGroup",
        ])
        .ok();
        // A not-found unit may produce a nonzero exit with complete properties.
        let properties = output.as_ref().map(|o| String::from_utf8_lossy(&o.stdout));
        let state = properties.as_deref().and_then(|text| {
            Some(UnitState {
                id: property(text, "Id=")?,
                load: property(text, "LoadState=")?,
                active: property(text, "ActiveState=")?,
                cgroup: property(text, "ControlGroup=")?,
            })
        });
        let membership = members(group);
        let cgroup_absent = group_path(group).is_some_and(|path| {
            fs::symlink_metadata(path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
        });
        let mut participants: Vec<_> = report
            .observed_members
            .iter()
            .copied()
            .chain(report.observations.iter().map(|o| o.pid))
            .map(participant_state)
            .collect();
        // Missing receipts must not turn incomplete participant evidence into proof.
        if report.observations.len() != 4 {
            participants.push(ParticipantState::Unknown);
        }
        assess_cleanup(CleanupEvidence {
            created_scope: Some(ScopeIdentity {
                unit,
                cgroup: group,
            }),
            unit_state: state,
            membership: membership.as_deref(),
            cgroup_absent,
            participants: &participants,
        })
    } else {
        false
    };
    report.cleanup_outcome = if empty {
        "verified-empty"
    } else {
        "unknown-hold"
    }
    .into();
    if !empty {
        report.disposition = Disposition::UnknownHold;
        report.reasons.push("scope-cleanup-not-verified".into());
    }
    Ok(())
}
// Trusted bounded fixture, not arbitrary agent code. Every descendant has its own
// lifetime bound independent of the launching parent; cwd/FD survive rename.
const FIXTURE: &str = r#"
import os, sys, time, json
root = sys.argv[1]
def payload(name, transient=False):
    os.chdir(root)
    fd = os.open(root, os.O_RDONLY)
    group = next(l[3:].strip() for l in open('/proc/self/cgroup') if l.startswith('0::'))
    path = root + '/' + name + '.json'
    with open(path + '.tmp', 'w') as f:
        json.dump(dict(fixture=name, pid=os.getpid(), cgroup=group), f)
    os.rename(path + '.tmp', path)
    if not transient: time.sleep(2)
    os.close(fd)
    os._exit(0)
for name in ['setsid', 'double_fork_parent_exit', 'cwd_fd', 'exit_during_inspection']:
    pid = os.fork()
    if pid == 0:
        if name in ['setsid', 'double_fork_parent_exit']: os.setsid()
        if name == 'double_fork_parent_exit':
            if os.fork() != 0: os._exit(0)
        payload(name, name == 'exit_during_inspection')
    os.waitpid(pid, 0) if name == 'double_fork_parent_exit' else None
end = time.monotonic() + 1
while time.monotonic() < end and len([p for p in os.listdir(root) if p.endswith('.json')]) < 4: time.sleep(.01)
open(root + '/ready', 'w').close()
time.sleep(3)
"#;
