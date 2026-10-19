//! Bounded scope inspector and exact-binding cancellation, not retirement authority.
//! Library IO injection is for controlled fixtures; production always uses fixed OS paths.
use crate::{bounded_process, runtime_scope::*};
use rustix::fs::{openat2, Dir, FileType, Mode, OFlags, ResolveFlags};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, &'static str>;
const HOLD: &str = "scope inspection incomplete";

/// Explicit supervisor context; never inferred from the CLI's environment.
pub struct RuntimeContext {
    directory: PathBuf,
    address: String,
}
impl RuntimeContext {
    pub fn new(directory: PathBuf, address: String) -> Result<Self> {
        let context = Self { directory, address };
        context.validate()?;
        Ok(context)
    }
    fn validate(&self) -> Result<()> {
        // Reject D-Bus address delimiters/escapes instead of accepting a different socket.
        if !self.directory.to_str().is_some_and(|p| {
            p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        }) {
            return Err(HOLD);
        }
        let d = canonical_dir(&self.directory)?;
        let m = d.metadata().map_err(|_| HOLD)?;
        let uid = rustix::process::getuid().as_raw();
        if m.uid() != uid || m.mode() & 0o777 != 0o700 {
            return Err(HOLD);
        }
        let bus = self.directory.join("bus");
        if self.address != format!("unix:path={}", bus.display()) {
            return Err(HOLD);
        }
        let m = fs::symlink_metadata(bus).map_err(|_| HOLD)?;
        if !m.file_type().is_socket() || m.uid() != uid {
            return Err(HOLD);
        }
        Ok(())
    }
}
/// Explicit library-only fixture injection. Never populated from environment or CLI flags.
pub struct LibraryIo {
    pub systemctl: PathBuf,
    pub proc_root: PathBuf,
    pub cgroup_root: PathBuf,
    /// Controlled snapshot transition for library fixtures; production uses None.
    pub between_censuses: Option<Box<dyn Fn()>>,
}
pub struct Limits {
    pub duration: Duration,
    pub total_bytes: usize,
    pub groups: usize,
    pub pids: usize,
    pub depth: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(2),
            total_bytes: 1_048_576,
            groups: 256,
            pids: 4096,
            depth: 32,
        }
    }
}
/// Complete roster/status evidence comes from the trusted store caller, never environment.
/// An identity is required even for a logically closed participant.
pub struct Participant {
    pub status: ParticipantStatus,
    pub identity: Option<ChildIdentity>,
}
pub struct Driver {
    context: RuntimeContext,
    io: LibraryIo,
    limits: Limits,
}
impl Driver {
    pub fn new(context: RuntimeContext) -> Result<Self> {
        let driver = Self::with_io(
            context,
            LibraryIo {
                systemctl: "/usr/bin/systemctl".into(),
                proc_root: "/proc".into(),
                cgroup_root: "/sys/fs/cgroup".into(),
                between_censuses: None,
            },
            Limits::default(),
        )?;
        let root = canonical_dir(&driver.io.cgroup_root)?;
        if rustix::fs::fstatfs(&root).map_err(|_| HOLD)?.f_type != 0x6367_7270
        /* CGROUP2_SUPER_MAGIC */
        {
            return Err(HOLD);
        }
        Ok(driver)
    }
    pub fn with_io(context: RuntimeContext, io: LibraryIo, limits: Limits) -> Result<Self> {
        context.validate()?;
        if !io.systemctl.is_absolute()
            || !io.proc_root.is_absolute()
            || !io.cgroup_root.is_absolute()
        {
            return Err(HOLD);
        }
        Ok(Self {
            context,
            io,
            limits,
        })
    }
    /// Bounded identity inspection only; grants no process or scope authority.
    pub fn identify(&self, pid: u32) -> Result<ChildIdentity> {
        let mut budget = Budget::new(&self.limits, Instant::now(), self.limits.duration);
        self.identify_with(pid, &mut budget)
    }
    pub(crate) fn enrollment_budget(&self, start: Instant) -> Budget<'_> {
        Budget::new(
            &self.limits,
            start,
            self.limits.duration.min(Duration::from_secs(2)),
        )
    }
    pub(crate) fn identify_with(&self, pid: u32, budget: &mut Budget<'_>) -> Result<ChildIdentity> {
        budget.check()?;
        identify_at(&self.io.proc_root, pid, budget)
    }
    pub fn observe(
        &self,
        intent: &LaunchIntent,
        binding: Option<&Binding>,
        roster: Option<&[Participant]>,
    ) -> Observation {
        self.observe_expected(intent, binding.map(|b| (b.identity(), b.boot_id())), roster)
    }
    pub(crate) fn observe_recorded(
        &self,
        intent: &LaunchIntent,
        expected: &crate::run_journal::RecordedScopeExpectation,
        roster: &[Participant],
    ) -> Observation {
        self.observe_expected(
            intent,
            Some((expected.identity(), expected.boot())),
            Some(roster),
        )
    }
    pub(crate) fn observe_recorded_with(
        &self,
        intent: &LaunchIntent,
        expected: &crate::run_journal::RecordedScopeExpectation,
        roster: &[Participant],
        budget: &mut Budget<'_>,
    ) -> Observation {
        self.observe_expected_with(
            intent,
            Some((expected.identity(), expected.boot())),
            Some(roster),
            budget,
        )
    }
    fn observe_expected(
        &self,
        intent: &LaunchIntent,
        binding: Option<(&ScopeIdentity, &str)>,
        roster: Option<&[Participant]>,
    ) -> Observation {
        let mut budget = Budget::new(&self.limits, Instant::now(), self.limits.duration);
        self.observe_expected_with(intent, binding, roster, &mut budget)
    }
    fn observe_expected_with(
        &self,
        intent: &LaunchIntent,
        binding: Option<(&ScopeIdentity, &str)>,
        roster: Option<&[Participant]>,
        budget: &mut Budget<'_>,
    ) -> Observation {
        let observed_at = budget.start;
        let mut obs = Observation {
            boot: String::new(),
            observed_at,
            unit: UnitPresence::Unknown,
            membership: Membership::Unknown,
            recursive_coverage: Coverage::Unknown,
            participant_coverage: Coverage::Unknown,
            participants: vec![],
        };
        // Keep partial evidence unknown on any error. Never infer absence from a query error.
        let _ = self.collect(intent, binding, roster, &mut obs, budget);
        obs
    }
    /// Freshly validate the private manager context. Never mutates process environment.
    pub(crate) fn apply_manager_context(&self, command: &mut Command) -> Result<()> {
        self.context.validate()?;
        command
            .env("XDG_RUNTIME_DIR", &self.context.directory)
            .env("DBUS_SESSION_BUS_ADDRESS", &self.context.address);
        Ok(())
    }
    /// Reobserve before signalling; errors never fall back to PID-based signalling.
    /// Successful manager exit is a request acknowledgement, not quiescence proof.
    pub(crate) fn cancel_bound(&self, intent: &LaunchIntent, binding: &Binding) -> Result<()> {
        let observation = self.observe(intent, Some(binding), None);
        self.context.validate()?;
        let cancellation = binding
            .authorize_cancel(&observation, Instant::now(), Duration::from_secs(2))
            .map_err(|_| HOLD)?;
        let mut command = Command::new(&self.io.systemctl);
        command
            .args([
                "--user",
                "--no-pager",
                "--no-ask-password",
                "kill",
                "--kill-whom=all",
                "--signal=SIGTERM",
                cancellation.unit_name(),
            ])
            .env("XDG_RUNTIME_DIR", &self.context.directory)
            .env("DBUS_SESSION_BUS_ADDRESS", &self.context.address);
        let output = bounded_process::output(&mut command, self.limits.duration, 16_384)
            .map_err(|_| HOLD)?;
        if !output.status.success() {
            return Err(HOLD);
        }
        Ok(())
    }
    fn manager(&self, intent: &LaunchIntent, budget: &mut Budget<'_>) -> Result<Manager> {
        budget.check()?;
        self.context.validate()?;
        budget.check()?;
        let mut command = Command::new(&self.io.systemctl);
        command
            .args([
                "--user",
                "--no-pager",
                "show",
                intent.unit_name(),
                "--property=Id,InvocationID,ControlGroup,LoadState,ActiveState",
            ])
            .env("XDG_RUNTIME_DIR", &self.context.directory)
            .env("DBUS_SESSION_BUS_ADDRESS", &self.context.address);
        let output = bounded_process::output_aggregate(
            &mut command,
            budget.remaining()?,
            (budget.limits.total_bytes - budget.bytes).min(16_384),
        )
        .map_err(|_| "scope manager command unavailable or exceeded capture/runtime limit")?;
        budget.charge(output.stdout.len() + output.stderr.len())?;
        let manager = Manager::parse(
            std::str::from_utf8(&output.stdout).map_err(|_| HOLD)?,
            intent,
        )?;
        if !output.status.success() && !manager.reaped {
            return Err(HOLD);
        }
        Ok(manager)
    }
    fn collect(
        &self,
        intent: &LaunchIntent,
        binding: Option<(&ScopeIdentity, &str)>,
        roster: Option<&[Participant]>,
        obs: &mut Observation,
        budget: &mut Budget<'_>,
    ) -> Result<()> {
        budget.check()?;
        let proc = canonical_dir(&self.io.proc_root)?;
        let cg = canonical_dir(&self.io.cgroup_root)?;
        let boot = read(&proc, "sys/kernel/random/boot_id", budget)?
            .trim()
            .to_owned();
        obs.boot = boot.clone();
        if boot != intent.boot_id()
            || binding.is_some_and(|(identity, expected_boot)| {
                expected_boot != boot || identity.unit != intent.unit_name()
            })
        {
            return Err(HOLD);
        }
        let manager = self.manager(intent, budget)?;
        let identity = if manager.reaped {
            let bound = binding.ok_or(HOLD)?.0;
            if (!manager.identity.invocation.is_empty()
                && manager.identity.invocation != bound.invocation)
                || (!manager.identity.cgroup.is_empty() && manager.identity.cgroup != bound.cgroup)
            {
                return Err(HOLD);
            }
            bound.clone()
        } else {
            if binding.is_some_and(|(identity, _)| identity != &manager.identity) {
                return Err(HOLD);
            }
            manager.identity.clone()
        };
        let first = census(&cg, &identity.cgroup, budget)?;
        if (manager.reaped && first.is_some())
            || (first.is_none() && (binding.is_none() || manager.active != ActiveStatus::Inactive))
        {
            return Err(HOLD);
        }
        let members = match &first {
            Some(c) => {
                let mut members = Vec::new();
                for (path, (_, _, pids)) in &c.groups {
                    for pid in pids {
                        let child = process(&proc, *pid, &boot, budget)?.ok_or(HOLD)?;
                        if child.cgroup != *path {
                            return Err(HOLD);
                        }
                        members.push(child);
                    }
                }
                members.sort_by_key(|p| p.pid);
                members
            }
            None => vec![],
        };
        let participants = participant_states(roster, &proc, &boot, &identity.cgroup, budget)?;
        if let Some(checkpoint) = &self.io.between_censuses {
            checkpoint();
        }
        let second = census(&cg, &identity.cgroup, budget)?;
        if first.as_ref().map(|c| &c.groups) != second.as_ref().map(|c| &c.groups) {
            return Err(HOLD);
        }
        // FDs retain directory identity across both walks; replacement cannot hide behind a path.
        if let Some(first) = &first {
            first.revalidate()?;
        }
        for child in &members {
            if process(&proc, child.pid, &boot, budget)?.as_ref() != Some(child) {
                return Err(HOLD);
            }
        }
        if participants != participant_states(roster, &proc, &boot, &identity.cgroup, budget)?
            || manager != self.manager(intent, budget)?
            || read(&proc, "sys/kernel/random/boot_id", budget)?.trim() != boot
        {
            return Err(HOLD);
        }
        budget.check()?;
        obs.unit = if manager.reaped {
            UnitPresence::AutoReaped(identity)
        } else {
            UnitPresence::Present {
                identity,
                load: LoadStatus::Loaded,
                active: manager.active,
            }
        };
        obs.membership = if first.is_none() {
            Membership::Absent
        } else {
            Membership::Present(members)
        };
        obs.recursive_coverage = Coverage::Complete;
        obs.participant_coverage = if roster.is_some_and(|r| !r.is_empty())
            && !participants.contains(&ParticipantStatus::Unknown)
        {
            Coverage::Complete
        } else {
            Coverage::Unknown
        };
        obs.participants = participants;
        Ok(())
    }
}
#[derive(PartialEq, Eq)]
struct Manager {
    identity: ScopeIdentity,
    active: ActiveStatus,
    reaped: bool,
}
impl Manager {
    fn parse(text: &str, intent: &LaunchIntent) -> Result<Self> {
        let mut fields = BTreeMap::new();
        for line in text.lines() {
            let (k, v) = line.split_once('=').ok_or(HOLD)?;
            if fields.insert(k, v).is_some() {
                return Err(HOLD);
            }
        }
        if fields.len() != 5 || fields.get("Id") != Some(&intent.unit_name()) {
            return Err(HOLD);
        }
        let get = |key| fields.get(key).copied().ok_or(HOLD);
        let invocation = get("InvocationID")?;
        let cgroup = get("ControlGroup")?;
        let active = match get("ActiveState")? {
            "active" => ActiveStatus::Active,
            "inactive" => ActiveStatus::Inactive,
            _ => return Err(HOLD),
        };
        let reaped = get("LoadState")? == "not-found" && active == ActiveStatus::Inactive;
        if !reaped && get("LoadState")? != "loaded" {
            return Err(HOLD);
        }
        if (!reaped || !invocation.is_empty())
            && !uuid::Uuid::parse_str(invocation)
                .is_ok_and(|u| !u.is_nil() && u.simple().to_string() == invocation)
        {
            return Err(HOLD);
        }
        if (!reaped || !cgroup.is_empty())
            && (!normalized(cgroup) || cgroup.rsplit('/').next() != Some(intent.unit_name()))
        {
            return Err(HOLD);
        }
        Ok(Self {
            identity: ScopeIdentity {
                unit: intent.unit_name().into(),
                invocation: invocation.into(),
                cgroup: cgroup.into(),
            },
            active,
            reaped,
        })
    }
}
fn normalized(path: &str) -> bool {
    path.starts_with('/')
        && path
            .split('/')
            .skip(1)
            .all(|p| !p.is_empty() && p != "." && p != ".." && !p.chars().any(char::is_control))
}
fn within(path: &str, group: &str) -> bool {
    path == group || path.strip_prefix(group).is_some_and(|p| p.starts_with('/'))
}
pub(crate) fn canonical_dir(path: &Path) -> Result<File> {
    if !path.is_absolute() || fs::canonicalize(path).map_err(|_| HOLD)? != path {
        return Err(HOLD);
    }
    let root = File::open("/").map_err(|_| HOLD)?;
    // NO_SYMLINKS covers ancestors, not just the final path component.
    openat2(
        &root,
        path.strip_prefix("/").map_err(|_| HOLD)?,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )
    .map(File::from)
    .map_err(|_| HOLD)
}
fn open(dir: &File, path: &str, directory: bool) -> std::result::Result<File, rustix::io::Errno> {
    openat2(
        dir,
        path,
        OFlags::RDONLY
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC
            | if directory {
                OFlags::DIRECTORY
            } else {
                OFlags::empty()
            },
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )
    .map(File::from)
}
pub(crate) struct Budget<'a> {
    start: Instant,
    limits: &'a Limits,
    bytes: usize,
    duration: Duration,
}
impl<'a> Budget<'a> {
    fn new(limits: &'a Limits, start: Instant, duration: Duration) -> Self {
        Self {
            start,
            limits,
            bytes: 0,
            duration,
        }
    }
    fn check(&self) -> Result<()> {
        self.remaining().map(|_| ())
    }
    fn remaining(&self) -> Result<Duration> {
        if self.bytes >= self.limits.total_bytes {
            return Err(HOLD);
        }
        self.duration
            .checked_sub(self.start.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or(HOLD)
    }
    fn charge(&mut self, n: usize) -> Result<()> {
        self.check()?;
        self.bytes = self.bytes.checked_add(n).ok_or(HOLD)?;
        if self.bytes > self.limits.total_bytes {
            return Err(HOLD);
        }
        Ok(())
    }
}
fn read(dir: &File, path: &str, budget: &mut Budget<'_>) -> Result<String> {
    budget.check()?;
    let mut file = open(dir, path, false).map_err(|_| HOLD)?;
    if !file.metadata().map_err(|_| HOLD)?.is_file() {
        return Err(HOLD);
    }
    let mut bytes = Vec::new();
    loop {
        let mut buf = [0; 4096];
        budget.check()?;
        let capacity = buf.len().min(budget.limits.total_bytes - budget.bytes);
        let n = file.read(&mut buf[..capacity]).map_err(|_| HOLD)?;
        budget.charge(n)?;
        if n == 0 {
            break;
        }
        if bytes.len() + n > 65_536 {
            return Err(HOLD);
        }
        bytes.extend_from_slice(&buf[..n]);
    }
    String::from_utf8(bytes).map_err(|_| HOLD)
}
type Group = (u64, u64, BTreeSet<u32>);
struct Census {
    groups: BTreeMap<String, Group>,
    held: Vec<(File, u64, u64)>,
}
impl Census {
    fn revalidate(&self) -> Result<()> {
        for (f, dev, ino) in &self.held {
            let m = f.metadata().map_err(|_| HOLD)?;
            if m.dev() != *dev || m.ino() != *ino || m.nlink() == 0 {
                return Err(HOLD);
            }
        }
        Ok(())
    }
}
fn census(root: &File, group: &str, budget: &mut Budget<'_>) -> Result<Option<Census>> {
    budget.check()?;
    let base = match open(root, group.trim_start_matches('/'), true) {
        Ok(f) => f,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(HOLD),
    };
    let mut census = Census {
        groups: BTreeMap::new(),
        held: vec![],
    };
    let mut stack = vec![(base, group.to_owned(), 0)];
    let mut all_pids = BTreeSet::new();
    while let Some((dir, path, depth)) = stack.pop() {
        budget.check()?;
        if depth > budget.limits.depth || census.groups.len() + stack.len() >= budget.limits.groups
        {
            return Err(HOLD);
        }
        let metadata = dir.metadata().map_err(|_| HOLD)?;
        let mut pids = BTreeSet::new();
        if read(&dir, "cgroup.type", budget)?.trim() != "domain" {
            return Err(HOLD);
        }
        for line in read(&dir, "cgroup.procs", budget)?.lines() {
            let pid: u32 = line.parse().map_err(|_| HOLD)?;
            if pid == 0 || pid > i32::MAX as u32 || !all_pids.insert(pid) {
                return Err(HOLD);
            }
            if all_pids.len() > budget.limits.pids {
                return Err(HOLD);
            }
            pids.insert(pid);
        }
        for entry in Dir::read_from(&dir).map_err(|_| HOLD)? {
            budget.check()?;
            let entry = entry.map_err(|_| HOLD)?;
            let name = entry.file_name().to_str().map_err(|_| HOLD)?;
            if name == "." || name == ".." {
                continue;
            }
            budget.charge(name.len() + 1)?;
            match entry.file_type() {
                FileType::Directory => {
                    if census.groups.len() + stack.len() + 1 >= budget.limits.groups {
                        return Err(HOLD);
                    }
                    stack.push((
                        open(&dir, name, true).map_err(|_| HOLD)?,
                        format!("{path}/{name}"),
                        depth + 1,
                    ));
                }
                FileType::RegularFile => {}
                _ => return Err(HOLD),
            }
        }
        census
            .groups
            .insert(path, (metadata.dev(), metadata.ino(), pids));
        census.held.push((dir, metadata.dev(), metadata.ino()));
    }
    Ok(Some(census))
}
fn process(
    proc: &File,
    pid: u32,
    boot: &str,
    budget: &mut Budget<'_>,
) -> Result<Option<ChildIdentity>> {
    budget.check()?;
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(HOLD);
    }
    let dir = match open(proc, &pid.to_string(), true) {
        Ok(f) => f,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(HOLD),
    };
    let stat = read(&dir, "stat", budget)?;
    let start_ticks = start_ticks(&stat, pid)?;
    if matches!(
        stat.rsplit_once(')')
            .ok_or(HOLD)?
            .1
            .split_whitespace()
            .next(),
        Some("Z" | "X" | "x")
    ) {
        return Err(HOLD);
    }
    let raw = read(&dir, "cgroup", budget)?;
    let mut lines = raw.lines();
    let cgroup = lines
        .next()
        .and_then(|l| l.strip_prefix("0::"))
        .filter(|p| *p == "/" || normalized(p))
        .ok_or(HOLD)?;
    if lines.next().is_some() {
        return Err(HOLD);
    }
    validate_stat_pair(&stat, &read(&dir, "stat", budget)?, pid)?;
    Ok(Some(ChildIdentity {
        pid,
        start_ticks,
        boot: boot.into(),
        cgroup: cgroup.into(),
    }))
}
/// Fixed production procfs reader shared with the pre-exec child. No caller roots.
pub(crate) fn live_process(pid: u32) -> Result<ChildIdentity> {
    let limits = Limits::default();
    let mut budget = Budget::new(&limits, Instant::now(), limits.duration);
    identify_at(Path::new("/proc"), pid, &mut budget)
}
fn identify_at(root: &Path, pid: u32, budget: &mut Budget<'_>) -> Result<ChildIdentity> {
    let proc = canonical_dir(root)?;
    let boot = read(&proc, "sys/kernel/random/boot_id", budget)?
        .trim()
        .to_owned();
    if !uuid::Uuid::parse_str(&boot)
        .is_ok_and(|id| !id.is_nil() && id.hyphenated().to_string() == boot)
    {
        return Err(HOLD);
    }
    let identity = process(&proc, pid, &boot, budget)?.ok_or(HOLD)?;
    let stat = read(&proc, &format!("{pid}/stat"), budget)?;
    let state = stat
        .rsplit_once(')')
        .ok_or(HOLD)?
        .1
        .split_whitespace()
        .next()
        .ok_or(HOLD)?;
    if matches!(state, "Z" | "X" | "x")
        || start_ticks(&stat, pid)? != identity.start_ticks
        || process(&proc, pid, &boot, budget)?.as_ref() != Some(&identity)
        || read(&proc, "sys/kernel/random/boot_id", budget)?.trim() != boot
    {
        return Err(HOLD);
    }
    budget.check()?;
    Ok(identity)
}
fn validate_stat_pair(first: &str, second: &str, pid: u32) -> Result<()> {
    if start_ticks(first, pid)? != start_ticks(second, pid)?
        || [first, second].iter().any(|stat| {
            matches!(
                stat.rsplit_once(')')
                    .and_then(|(_, fields)| fields.split_whitespace().next()),
                Some("Z" | "X" | "x")
            )
        })
    {
        return Err(HOLD);
    }
    Ok(())
}
fn start_ticks(stat: &str, pid: u32) -> Result<u64> {
    let prefix = format!("{pid} (");
    if !stat.starts_with(&prefix) {
        return Err(HOLD);
    }
    let end = stat.rfind(')').ok_or(HOLD)?;
    let fields: Vec<_> = stat[end + 1..].split_whitespace().collect();
    if fields.len() < 20
        || fields[0].len() != 1
        || !fields[0].bytes().all(|c| b"RSDZTtXxKWPI".contains(&c))
    {
        return Err(HOLD);
    }
    if fields[1..19].iter().any(|f| f.parse::<i128>().is_err()) {
        return Err(HOLD);
    }
    let ticks = fields[19].parse::<u64>().map_err(|_| HOLD)?;
    if ticks == 0 {
        return Err(HOLD);
    }
    Ok(ticks)
}
fn participant_states(
    roster: Option<&[Participant]>,
    proc: &File,
    boot: &str,
    group: &str,
    budget: &mut Budget<'_>,
) -> Result<Vec<ParticipantStatus>> {
    let Some(roster) = roster else {
        return Ok(vec![]);
    };
    if roster.len() > budget.limits.pids {
        return Err(HOLD);
    }
    roster
        .iter()
        .map(|p| {
            let Some(identity) = &p.identity else {
                return Ok(ParticipantStatus::Unknown);
            };
            if identity.boot != boot || identity.start_ticks == 0 {
                return Ok(ParticipantStatus::Unknown);
            }
            let current = process(proc, identity.pid, boot, budget)?;
            Ok(match current {
                Some(current) if current != *identity || !within(&current.cgroup, group) => {
                    ParticipantStatus::Unknown
                }
                Some(_) => match p.status {
                    ParticipantStatus::ProvenAbsent | ParticipantStatus::Closed => {
                        ParticipantStatus::Unknown
                    }
                    other => other,
                },
                None => p.status,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_manager_streams_exhaust_shared_budget_before_later_inspection() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let _bus = std::os::unix::net::UnixListener::bind(runtime.join("bus")).unwrap();
        let proc = root.path().join("proc");
        fs::create_dir_all(proc.join("sys/kernel/random")).unwrap();
        let boot = "550e8400-e29b-41d4-a716-446655440000";
        fs::write(proc.join("sys/kernel/random/boot_id"), boot).unwrap();
        let cg = root.path().join("cg");
        fs::create_dir(&cg).unwrap();
        let manager = root.path().join("manager");
        let called = root.path().join("called");
        fs::write(
            &manager,
            format!(
                "#!/bin/sh\nprintf 'called\\n' >> '{}'\nprintf '{}'\nprintf '{}' >&2\n",
                called.display(),
                "o".repeat(80),
                "e".repeat(80)
            ),
        )
        .unwrap();
        fs::set_permissions(&manager, fs::Permissions::from_mode(0o700)).unwrap();
        let driver = Driver::with_io(
            RuntimeContext::new(
                runtime.clone(),
                format!("unix:path={}/bus", runtime.display()),
            )
            .unwrap(),
            LibraryIo {
                systemctl: manager,
                proc_root: proc,
                cgroup_root: cg,
                between_censuses: Some(Box::new(|| panic!("later inspection must not start"))),
            },
            Limits {
                total_bytes: boot.len() + 100,
                ..Limits::default()
            },
        )
        .unwrap();
        let intent = LaunchIntent::new(work_contract::RunId::generate(), boot).unwrap();
        let mut budget = driver.enrollment_budget(Instant::now());
        let obs = driver.observe_expected_with(&intent, None, None, &mut budget);
        assert_eq!(obs.unit, UnitPresence::Unknown);
        assert_eq!(obs.membership, Membership::Unknown);
        assert_eq!(obs.recursive_coverage, Coverage::Unknown);
        assert_eq!(
            budget.bytes,
            boot.len(),
            "aggregate failure must precede charging oversized capture"
        );
        assert_eq!(
            fs::read(called).unwrap(),
            b"called\n",
            "no second manager query"
        );
    }

    #[test]
    fn enrollment_deadline_is_shared_and_stops_later_identification_and_manager() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let _bus = std::os::unix::net::UnixListener::bind(runtime.join("bus")).unwrap();
        let proc = root.path().join("proc");
        fs::create_dir_all(proc.join("sys/kernel/random")).unwrap();
        fs::create_dir(proc.join("42")).unwrap();
        let boot = "550e8400-e29b-41d4-a716-446655440000";
        fs::write(proc.join("sys/kernel/random/boot_id"), boot).unwrap();
        fs::write(
            proc.join("42/stat"),
            format!("42 (root) S {} 123 0\n", vec!["0"; 18].join(" ")),
        )
        .unwrap();
        fs::write(proc.join("42/cgroup"), "0::/\n").unwrap();
        let manager = root.path().join("manager");
        let called = root.path().join("called");
        fs::write(
            &manager,
            format!("#!/bin/sh\nprintf called > '{}'\n", called.display()),
        )
        .unwrap();
        fs::set_permissions(&manager, fs::Permissions::from_mode(0o700)).unwrap();
        let cg = root.path().join("cg");
        fs::create_dir(&cg).unwrap();
        let driver = Driver::with_io(
            RuntimeContext::new(
                runtime.clone(),
                format!("unix:path={}/bus", runtime.display()),
            )
            .unwrap(),
            LibraryIo {
                systemctl: manager,
                proc_root: proc,
                cgroup_root: cg,
                between_censuses: Some(Box::new(|| panic!("census must not start"))),
            },
            Limits {
                duration: Duration::from_secs(30),
                ..Limits::default()
            },
        )
        .unwrap();
        let mut budget = driver.enrollment_budget(Instant::now());
        assert_eq!(budget.duration, Duration::from_secs(2));
        driver.identify_with(42, &mut budget).unwrap();
        let bytes = budget.bytes;
        // Private deterministic seam: expire the same session after phase one.
        budget.start = Instant::now() - Duration::from_secs(3);
        assert!(driver.identify_with(42, &mut budget).is_err());
        let intent = LaunchIntent::new(work_contract::RunId::generate(), boot).unwrap();
        let obs = driver.observe_expected_with(&intent, None, None, &mut budget);
        assert_eq!(obs.recursive_coverage, Coverage::Unknown);
        assert_eq!(obs.observed_at, budget.start);
        assert_eq!(budget.bytes, bytes, "no later proc/cgroup reads");
        assert!(!called.exists(), "no manager command after deadline");
        let mut short = driver.enrollment_budget(Instant::now());
        short.bytes = short.limits.total_bytes;
        assert!(driver.identify_with(42, &mut short).is_err());
        assert_eq!(
            driver
                .observe_expected_with(&intent, None, None, &mut short)
                .recursive_coverage,
            Coverage::Unknown
        );
        assert!(!called.exists());
    }
    #[test]
    fn generic_process_reader_accepts_root_cgroup() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("42")).unwrap();
        fs::write(
            root.path().join("42/stat"),
            format!("42 (parent) S {} 123 0\n", vec!["0"; 18].join(" ")),
        )
        .unwrap();
        fs::write(root.path().join("42/cgroup"), "0::/\n").unwrap();
        let limits = Limits::default();
        let mut budget = Budget::new(&limits, Instant::now(), limits.duration);
        let identity = process(
            &canonical_dir(root.path()).unwrap(),
            42,
            "boot",
            &mut budget,
        )
        .unwrap()
        .unwrap();
        assert_eq!(identity.cgroup, "/");
    }
    #[test]
    fn stat_pair_validates_stable_identity_only() {
        let stat = |pid, state, ticks, fields: &[&str]| {
            format!(
                "{pid} (odd ) comm (x)) {state} {} {ticks} 0\n",
                fields.join(" ")
            )
        };
        let fields = ["0"; 18];
        let first = stat(42, "S", 123, &fields);
        let mut active_fields = fields;
        // Fields 10/12 are fault counters; fields 14/15 are CPU time.
        for index in [6, 8, 10, 11] {
            active_fields[index] = "1";
        }
        for (case, second, expected) in [
            ("unchanged", first.clone(), Ok(())),
            ("state", stat(42, "R", 123, &fields), Ok(())),
            ("reaped", stat(42, "Z", 123, &fields), Err(HOLD)),
            ("cpu and faults", stat(42, "S", 123, &active_fields), Ok(())),
            ("start time", stat(42, "S", 124, &fields), Err(HOLD)),
            ("pid", stat(43, "S", 123, &fields), Err(HOLD)),
            ("malformed", "42 (broken) S 0".into(), Err(HOLD)),
            ("invalid state", stat(42, "?", 123, &fields), Err(HOLD)),
        ] {
            assert_eq!(validate_stat_pair(&first, &second, 42), expected, "{case}");
        }
    }
}
