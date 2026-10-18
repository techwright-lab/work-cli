//! Pre-exec file gate only; no launcher, manager activation, signals or journal.
//! The future parent must observe real OS evidence and bind before releasing.
//! Library collectors support controlled tests, not production containment claims.
use crate::{
    runtime_scope::{Binding, ChildIdentity, LaunchIntent},
    scope_driver::{canonical_dir, live_process},
};
use rustix::fs::{openat2, renameat_with, Mode, OFlags, RenameFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::MetadataExt,
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};
use work_contract::RunId;
type Result<T> = std::result::Result<T, &'static str>;
const HOLD: &str = "scope child held";
const LIMIT: u64 = 32_768;

/// Capture BEFORE applying manager-only overrides. Only these two variables travel.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalRuntime {
    xdg: Option<Vec<u8>>,
    bus: Option<Vec<u8>>,
}
impl OriginalRuntime {
    pub fn new(xdg: Option<OsString>, bus: Option<OsString>) -> Self {
        Self {
            xdg: xdg.map(OsString::into_vec),
            bus: bus.map(OsString::into_vec),
        }
    }
    pub fn capture() -> Self {
        Self::new(
            std::env::var_os("XDG_RUNTIME_DIR"),
            std::env::var_os("DBUS_SESSION_BUS_ADDRESS"),
        )
    }
    fn apply(&self, command: &mut Command) {
        for (key, value) in [
            ("XDG_RUNTIME_DIR", &self.xdg),
            ("DBUS_SESSION_BUS_ADDRESS", &self.bus),
        ] {
            match value {
                Some(bytes) => {
                    command.env(key, OsString::from_vec(bytes.clone()));
                }
                None => {
                    command.env_remove(key);
                }
            }
        }
    }
}
/// Explicit library-only trusted fixture seam. Production CLI always uses /proc.
/// Return fresh current child and actual parent identities; errors mean unknown/dead.
pub trait LibraryCollector {
    fn identities(&self) -> Result<(ChildIdentity, ChildIdentity)>;
}
struct OsCollector;
impl LibraryCollector for OsCollector {
    fn identities(&self) -> Result<(ChildIdentity, ChildIdentity)> {
        let parent = rustix::process::getppid().ok_or(HOLD)?.as_raw_pid() as u32;
        Ok((live_process(std::process::id())?, live_process(parent)?))
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Process {
    pid: u32,
    start_ticks: u64,
    boot: String,
    cgroup: String,
}
impl Process {
    fn from(c: &ChildIdentity) -> Self {
        Self {
            pid: c.pid,
            start_ticks: c.start_ticks,
            boot: c.boot.clone(),
            cgroup: c.cgroup.clone(),
        }
    }
    fn child(&self) -> ChildIdentity {
        ChildIdentity {
            pid: self.pid,
            start_ticks: self.start_ticks,
            boot: self.boot.clone(),
            cgroup: self.cgroup.clone(),
        }
    }
    fn valid(&self, boot: &str) -> bool {
        self.pid > 1
            && self.pid <= i32::MAX as u32
            && self.start_ticks > 0
            && self.boot == boot
            && normalized(&self.cgroup)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cwd {
    path: PathBuf,
    dev: u64,
    ino: u64,
}
impl Cwd {
    fn collect(path: &Path) -> Result<Self> {
        let m = canonical_dir(path)?.metadata().map_err(|_| HOLD)?;
        Ok(Self {
            path: path.into(),
            dev: m.dev(),
            ino: m.ino(),
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    nonce: String,
    unit: String,
    boot: String,
    parent: Process,
    cwd: Cwd,
    original: OriginalRuntime,
    wait_ms: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyRecord {
    nonce: String,
    child: Process,
    cwd: Cwd,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Permit {
    nonce: String,
    child: Process,
    cwd: Cwd,
    unit: String,
    boot: String,
    group: String,
    invocation: String,
}
/// Nonserializable parent-side handle; the directory and its identity remain held.
pub struct Prepared {
    path: PathBuf,
    dir: File,
    dev: u64,
    ino: u64,
    context: Context,
}
pub struct Ready {
    child: ChildIdentity,
}
impl Ready {
    pub fn child(&self) -> &ChildIdentity {
        &self.child
    }
}

/// Directory must already be canonical, owned by this uid and exactly 0700.
/// Existing records are never removed, repaired or overwritten on failure.
pub fn prepare(
    directory: &Path,
    intent: &LaunchIntent,
    parent: &ChildIdentity,
    cwd: &Path,
    original: OriginalRuntime,
    timeout: Duration,
) -> Result<Prepared> {
    let wait_ms = u64::try_from(timeout.as_millis()).map_err(|_| HOLD)?;
    let context = Context {
        nonce: nonce()?,
        unit: intent.unit_name().into(),
        boot: intent.boot_id().into(),
        parent: Process::from(parent),
        cwd: Cwd::collect(cwd)?,
        original,
        wait_ms,
    };
    validate_context(&context)?;
    let gate = Prepared::open(directory, context)?;
    publish(&gate.dir, "context.json", &gate.context)?;
    Ok(gate)
}
impl Prepared {
    fn open(path: &Path, context: Context) -> Result<Self> {
        Self::from_dir(path, context, canonical_dir(path)?)
    }
    fn from_dir(path: &Path, context: Context, dir: File) -> Result<Self> {
        let m = dir.metadata().map_err(|_| HOLD)?;
        if m.uid() != rustix::process::getuid().as_raw() || m.mode() & 0o7777 != 0o700 {
            return Err(HOLD);
        }
        Ok(Self {
            path: path.into(),
            dir,
            dev: m.dev(),
            ino: m.ino(),
            context,
        })
    }
    fn revalidate(&self) -> Result<()> {
        let m = canonical_dir(&self.path)?.metadata().map_err(|_| HOLD)?;
        if m.dev() != self.dev
            || m.ino() != self.ino
            || m.uid() != rustix::process::getuid().as_raw()
            || m.mode() & 0o7777 != 0o700
        {
            return Err(HOLD);
        }
        Ok(())
    }
    pub fn context_path(&self) -> PathBuf {
        self.path.join("context.json")
    }
    fn ready(&self) -> Result<Option<ReadyRecord>> {
        self.revalidate()?;
        let record: Option<ReadyRecord> = read(&self.dir, "ready.json")?;
        if let Some(r) = &record {
            if r.nonce != self.context.nonce
                || r.cwd != self.context.cwd
                || !r.child.valid(&self.context.boot)
                || !in_unit(&r.child.cgroup, &self.context.unit)
            {
                return Err(HOLD);
            }
        }
        Ok(record)
    }
    pub fn read_ready(&self) -> Result<Option<Ready>> {
        Ok(self.ready()?.map(|r| Ready {
            child: r.child.child(),
        }))
    }
    /// Authority comes only from an opaque binding to this exact ready process.
    /// The caller must obtain that binding from fresh trusted driver observations.
    pub fn release(&self, binding: &Binding) -> Result<()> {
        let r = self.ready()?.ok_or(HOLD)?;
        let identity = binding.identity();
        if binding.trusted_child() != &r.child.child()
            || binding.boot_id() != self.context.boot
            || identity.unit != self.context.unit
            || !within(&r.child.cgroup, &identity.cgroup)
        {
            return Err(HOLD);
        }
        publish(
            &self.dir,
            "permit.json",
            &Permit {
                nonce: r.nonce,
                child: r.child,
                cwd: r.cwd,
                unit: identity.unit.clone(),
                boot: binding.boot_id().into(),
                group: identity.cgroup.clone(),
                invocation: identity.invocation.clone(),
            },
        )
    }
}
/// Hidden production entry point; collectors and kernel roots cannot be selected by CLI.
pub fn run(context: &Path, argv: &[OsString]) -> Result<()> {
    run_with_collector(context, argv, &OsCollector)
}
pub fn run_with_collector(
    context: &Path,
    argv: &[OsString],
    collector: &dyn LibraryCollector,
) -> Result<()> {
    let started = Instant::now();
    if argv.is_empty()
        || argv.iter().any(|a| a.as_bytes().contains(&0))
        || context.file_name().is_none_or(|n| n != "context.json")
    {
        return Err(HOLD);
    }
    let path = context.parent().ok_or(HOLD)?;
    let dir = canonical_dir(path)?;
    let ctx: Context = read(&dir, "context.json")?.ok_or(HOLD)?;
    validate_context(&ctx)?;
    let gate = Prepared::from_dir(path, ctx, dir)?;
    // Permanent exclusive start claim precedes all identity checks. Retries stay held.
    let mut claim = create(&gate.dir, "claimed")?;
    claim.write_all(b"{\"claimed\":true}\n").map_err(|_| HOLD)?;
    claim.sync_all().map_err(|_| HOLD)?;
    gate.dir.sync_all().map_err(|_| HOLD)?;
    if read::<Permit>(&gate.dir, "permit.json")?.is_some() {
        return Err(HOLD);
    }
    let current = || -> Result<Process> {
        gate.revalidate()?;
        let (child, parent) = collector.identities().map_err(|_| HOLD)?;
        let child = Process::from(&child);
        if Process::from(&parent) != gate.context.parent
            || !child.valid(&gate.context.boot)
            || !in_unit(&child.cgroup, &gate.context.unit)
            || Cwd::collect(&std::env::current_dir().map_err(|_| HOLD)?)? != gate.context.cwd
        {
            return Err(HOLD);
        }
        Ok(child)
    };
    let child = current()?;
    publish(
        &gate.dir,
        "ready.json",
        &ReadyRecord {
            nonce: gate.context.nonce.clone(),
            child: child.clone(),
            cwd: gate.context.cwd.clone(),
        },
    )?;
    let deadline = Duration::from_millis(gate.context.wait_ms);
    loop {
        if started.elapsed() >= deadline || current()? != child {
            return Err(HOLD);
        }
        if let Some(permit) = read::<Permit>(&gate.dir, "permit.json")? {
            if permit.nonce != gate.context.nonce
                || permit.child != child
                || permit.cwd != gate.context.cwd
                || permit.boot != gate.context.boot
                || permit.unit != gate.context.unit
                || !in_unit(&permit.group, &permit.unit)
                || permit.group.rsplit('/').next() != Some(&permit.unit)
                || !within(&child.cgroup, &permit.group)
                || !uuid::Uuid::parse_str(&permit.invocation)
                    .is_ok_and(|u| !u.is_nil() && u.simple().to_string() == permit.invocation)
            {
                return Err(HOLD);
            }
            if current()? != child || started.elapsed() >= deadline {
                return Err(HOLD);
            }
            let mut command = Command::new(&argv[0]);
            command.args(&argv[1..]);
            gate.context.original.apply(&mut command);
            let _error = command.exec();
            return Err(HOLD);
        }
        std::thread::sleep(
            Duration::from_millis(5).min(deadline.saturating_sub(started.elapsed())),
        );
    }
}
fn validate_context(c: &Context) -> Result<()> {
    let run = c
        .unit
        .strip_prefix("work-run-")
        .and_then(|v| v.strip_suffix(".scope"))
        .and_then(|v| RunId::parse(v).ok())
        .ok_or(HOLD)?;
    let intent = LaunchIntent::new(run, &c.boot).map_err(|_| HOLD)?;
    if intent.unit_name() != c.unit
        || !c.parent.valid(&c.boot)
        || c.wait_ms == 0
        || c.wait_ms > 30_000
        || c.nonce.len() != 64
        || !c.nonce.bytes().all(|b| b.is_ascii_hexdigit())
        || !c.cwd.path.is_absolute()
        || c.cwd.ino == 0
        || [&c.original.xdg, &c.original.bus]
            .iter()
            .any(|v| v.as_ref().is_some_and(|b| b.len() > 2048 || b.contains(&0)))
    {
        return Err(HOLD);
    }
    Ok(())
}
fn normalized(p: &str) -> bool {
    p.starts_with('/')
        && p.split('/')
            .skip(1)
            .all(|s| !s.is_empty() && s != "." && s != ".." && !s.chars().any(char::is_control))
}
fn in_unit(p: &str, unit: &str) -> bool {
    normalized(p) && p.split('/').any(|s| s == unit)
}
fn within(p: &str, group: &str) -> bool {
    normalized(group) && (p == group || p.strip_prefix(group).is_some_and(|s| s.starts_with('/')))
}
fn nonce() -> Result<String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|_| HOLD)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn create(dir: &File, name: &str) -> Result<File> {
    openat2(
        dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::from_raw_mode(0o600),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )
    .map(File::from)
    .map_err(|_| HOLD)
}
fn read<T: serde::de::DeserializeOwned>(dir: &File, name: &str) -> Result<Option<T>> {
    let file = match openat2(
        dir,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    ) {
        Ok(fd) => File::from(fd),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(HOLD),
    };
    let m = file.metadata().map_err(|_| HOLD)?;
    if !m.is_file()
        || m.uid() != rustix::process::getuid().as_raw()
        || m.mode() & 0o7777 != 0o600
        || m.nlink() != 1
        || m.len() > LIMIT
    {
        return Err(HOLD);
    }
    let mut bytes = vec![];
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| HOLD)?;
    if bytes.len() > LIMIT as usize {
        return Err(HOLD);
    }
    serde_json::from_slice(&bytes).map(Some).map_err(|_| HOLD)
}
fn publish<T: Serialize>(dir: &File, name: &str, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| HOLD)?;
    if bytes.len() > LIMIT as usize {
        return Err(HOLD);
    }
    let temporary = format!("pending-{}", nonce()?);
    let mut file = create(dir, &temporary)?;
    file.write_all(&bytes).map_err(|_| HOLD)?;
    file.sync_all().map_err(|_| HOLD)?;
    renameat_with(dir, temporary.as_str(), dir, name, RenameFlags::NOREPLACE).map_err(|_| HOLD)?;
    dir.sync_all().map_err(|_| HOLD)
}
