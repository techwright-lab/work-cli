//! Bounded, cooperative filesystem observation groundwork (A1/A2 only).
//!
//! Public inspection deliberately refuses completeness: registration, Git,
//! ignore/index/object proof and authoritative context are not implemented.
//! No child process, database read/write, receipt, or deletion authority here.
//! Descriptor protections apply only to inspector-owned reads. They do not
//! contain future native Git pathname opens or hostile same-UID writers, and
//! the operation clock cannot interrupt a syscall stuck in the kernel.
use crate::{disposal::ValidatedPolicies, store::Store};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[cfg(test)]
#[path = "inspection_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage { Complete, Incomplete }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncompleteReason {
    GitProofUnavailable, RegistrationEnvelopeOpen, ContextUnavailable,
    UnsupportedResolution, UntrustedProc, Unreadable, MountCrossing,
    Changed, Symlink, Hardlink, SpecialFile, NestedGit, GitMetadataUnproven,
    InvalidPath, EntryBudget, DepthBudget, FileBudget, ReadBudget,
    OutputBudget, ProcessBudget, Deadline, Io,
}
/// Exact file observations and conservative directory charges are distinct.
/// No exact directory-byte metric is available from RawDir.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub entries: u64,
    pub observed_file_bytes: u64,
    pub observed_process_bytes: u64,
    pub directory_reserved_bytes: u64,
    pub uncertain_file_reservation_bytes: u64,
    pub charged_read_bytes: u64,
    pub copied_name_bytes: u64,
    pub retained_output_bytes: u64,
    pub child_launches: u64,
    pub reserved_child_slots: u64,
    pub reserved_process_input_bytes: u64,
}
/// Nondurable and not deserializable; validation cannot restore fresh evidence.
#[derive(Debug)]
pub struct Observation { reasons: Vec<IncompleteReason>, counters: Counters }
impl Observation {
    pub fn coverage(&self) -> Coverage { Coverage::Incomplete }
    pub fn reasons(&self) -> &[IncompleteReason] { &self.reasons }
    pub fn counters(&self) -> &Counters { &self.counters }
}
#[derive(Debug, thiserror::Error)]
#[error("inspection unavailable")]
pub struct InspectionError;

/// Refusing integration seam. It intentionally does not look up a caller's
/// checkout, load paths, invoke Git or touch Store. A3/context integration must
/// replace this refusal under separate authorization, not infer proof from A2.
pub fn inspect(_store: &mut Store, _checkout: Uuid, _policies: &ValidatedPolicies) -> Result<Observation, InspectionError> {
    Ok(Observation { reasons:vec![IncompleteReason::GitProofUnavailable,
        IncompleteReason::RegistrationEnvelopeOpen, IncompleteReason::ContextUnavailable], counters:Counters::default() })
}

const MAX_ENTRIES: u64 = 4096;
const MAX_DEPTH: usize = 64;
const MAX_PATH_BYTES: usize = 4096;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CHARGED_BYTES: u64 = 128 * 1024 * 1024;
const MAX_OUTPUT_BYTES: u64 = 2 * 1024 * 1024;
const TERMINAL_RESERVE: u64 = 16 * 1024;
const DIRECTORY_BUFFER_BYTES: usize = 8192;

// Private groundwork is intentionally not reachable from public inspection
// until A3 supplies authoritative context. Do not expose a path/census bypass.
#[allow(dead_code)]
struct Budget {
    start: Instant,
    counters: Counters,
    stopped: Option<IncompleteReason>,
    #[cfg(test)]
    test_elapsed: Option<Duration>,
}
#[allow(dead_code)]
impl Budget {
    fn new() -> Self {
        Self { start:Instant::now(), counters:Counters::default(), stopped:None,
            #[cfg(test)] test_elapsed:None }
    }
    fn fail<T>(&mut self, reason: IncompleteReason) -> Result<T, IncompleteReason> {
        self.stopped = Some(reason); Err(reason)
    }
    fn elapsed(&self) -> Duration {
        let elapsed = self.start.elapsed();
        #[cfg(test)]
        let elapsed = self.test_elapsed.unwrap_or(elapsed);
        elapsed
    }
    fn check(&mut self) -> Result<(), IncompleteReason> {
        if let Some(reason) = self.stopped { return Err(reason); }
        if self.elapsed() >= Duration::from_secs(30) { return self.fail(IncompleteReason::Deadline); }
        Ok(())
    }
    // Accounting only: this reserves no OS resource and cannot launch a child.
    // A3 still needs an independently authorized byte runner and output budget.
    fn reserve_process(&mut self, stdin: u64, argv: u64) -> Result<ProcessReservation, IncompleteReason> {
        self.check()?;
        if self.counters.reserved_child_slots >= 96 || stdin > 1024 * 1024 || argv > 32 * 1024 {
            return self.fail(IncompleteReason::ProcessBudget);
        }
        let Some(input) = self.counters.reserved_process_input_bytes.checked_add(stdin).and_then(|n| n.checked_add(argv)) else {
            return self.fail(IncompleteReason::ProcessBudget);
        };
        if input > 8 * 1024 * 1024 { return self.fail(IncompleteReason::ProcessBudget); }
        let Some(remaining) = Duration::from_secs(30).checked_sub(self.elapsed()) else { return self.fail(IncompleteReason::Deadline); };
        if remaining.is_zero() { return self.fail(IncompleteReason::Deadline); }
        self.counters.reserved_child_slots += 1;
        self.counters.reserved_process_input_bytes = input;
        Ok(ProcessReservation { maximum_duration:remaining.min(Duration::from_secs(2)) })
    }
    fn entry(&mut self) -> Result<(), IncompleteReason> {
        self.check()?;
        if self.counters.entries >= MAX_ENTRIES { return self.fail(IncompleteReason::EntryBudget); }
        self.counters.entries += 1; Ok(())
    }
    fn file_length(&mut self, length: u64) -> Result<(), IncompleteReason> {
        self.check()?;
        if length > MAX_FILE_BYTES { return self.fail(IncompleteReason::FileBudget); }
        Ok(())
    }
    fn output(&mut self, length: u64) -> Result<(), IncompleteReason> {
        self.check()?;
        let Some(n) = self.counters.retained_output_bytes.checked_add(length) else { return self.fail(IncompleteReason::OutputBudget); };
        if n > MAX_OUTPUT_BYTES - TERMINAL_RESERVE { return self.fail(IncompleteReason::OutputBudget); }
        self.counters.retained_output_bytes = n; Ok(())
    }
    fn reserve(&mut self, bytes: u64) -> Result<(), IncompleteReason> {
        self.check()?;
        let Some(n) = self.counters.charged_read_bytes.checked_add(bytes) else { return self.fail(IncompleteReason::ReadBudget); };
        if n > MAX_CHARGED_BYTES { return self.fail(IncompleteReason::ReadBudget); }
        self.counters.charged_read_bytes = n; Ok(())
    }
    fn directory_refill(&mut self) -> Result<(), IncompleteReason> {
        self.reserve(DIRECTORY_BUFFER_BYTES as u64)?;
        self.counters.directory_reserved_bytes += DIRECTORY_BUFFER_BYTES as u64;
        Ok(())
    }
    fn reserve_file_read(&mut self, size: usize) -> Result<ReadReservation, IncompleteReason> {
        self.reserve(size as u64)?;
        self.counters.uncertain_file_reservation_bytes += size as u64;
        Ok(ReadReservation(size))
    }
    fn finish_file_read(&mut self, ticket: ReadReservation, actual: usize) -> Result<(), IncompleteReason> {
        if actual > ticket.0 { return self.fail(IncompleteReason::Io); }
        self.counters.uncertain_file_reservation_bytes -= ticket.0 as u64;
        self.counters.charged_read_bytes -= (ticket.0 - actual) as u64;
        self.counters.observed_file_bytes += actual as u64;
        self.check()
    }
}
#[allow(dead_code)]
struct ReadReservation(usize);
#[allow(dead_code)]
struct ProcessReservation { maximum_duration: Duration }

#[allow(dead_code)]
fn read_chunk(reader: &mut impl std::io::Read, buffer: &mut [u8], b: &mut Budget) -> Result<usize, IncompleteReason> {
    let ticket = b.reserve_file_read(buffer.len())?;
    match reader.read(buffer) {
        Ok(n) => { b.finish_file_read(ticket, n)?; Ok(n) }
        // Retain the full reservation when consumption is uncertain, but do
        // not falsely add it to exact observed bytes. Never retry this read.
        Err(_) => b.fail(IncompleteReason::Io),
    }
}

// The closure is not called when reservation fails, including EOF/error attempts.
// Rustix may trim for alignment: charge the full supplied array, not trimmed size.
#[allow(dead_code)]
fn directory_next<T>(b: &mut Budget, empty: bool, next: impl FnOnce() -> T) -> Result<T, IncompleteReason> {
    b.check()?;
    if empty { b.directory_refill()?; }
    Ok(next())
}

#[allow(dead_code)]
mod filesystem {
    use super::*;
    use crate::disposal::RawPath;
    use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, RawDir, ResolveFlags};
    use std::{collections::BTreeSet, ffi::CString, fs::File,
        mem::MaybeUninit, os::{fd::{AsRawFd, OwnedFd}, unix::ffi::OsStrExt}, path::Path};

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(super) struct Identity {
        device: u64, pub(super) inode: u64, pub(super) mode: u32,
        links: u64, uid: u32, gid: u32, size: i64,
        mtime: i64, mtime_ns: u64, ctime: i64, ctime_ns: u64,
    }
    impl Identity {
        fn from_stat(s: fs::Stat) -> Self {
            Self { device:s.st_dev, inode:s.st_ino, mode:s.st_mode, links:u64::from(s.st_nlink),
                uid:s.st_uid, gid:s.st_gid, size:s.st_size, mtime:s.st_mtime,
                mtime_ns:s.st_mtime_nsec, ctime:s.st_ctime, ctime_ns:s.st_ctime_nsec }
        }
        fn kind(&self) -> FileType { FileType::from_raw_mode(self.mode) }
    }
    fn stat(fd: &OwnedFd, b: &mut Budget) -> Result<Identity, IncompleteReason> {
        b.check()?; fs::fstat(fd).map(Identity::from_stat).map_err(os_error)
    }
    fn named(parent: &OwnedFd, name: &[u8], b: &mut Budget) -> Result<Identity, IncompleteReason> {
        b.check()?;
        fs::statat(parent, cstring(name)?.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map(Identity::from_stat).map_err(os_error)
    }
    fn equal(a: &Identity, b: &Identity) -> Result<(), IncompleteReason> {
        if a == b { Ok(()) } else { Err(IncompleteReason::Changed) }
    }
    // Traversal bindings outside the census are not content observations.
    // Child/FD churn may change size/nlink/timestamps without rebinding the
    // route. Preserve directory type, access/owner and actual object identity.
    // Never use this comparison for held census contents (including root).
    fn binding_equal(a: &Identity, b: &Identity) -> Result<(), IncompleteReason> {
        if a.device == b.device && a.inode == b.inode
            && a.kind() == FileType::Directory && b.kind() == FileType::Directory
            && a.mode == b.mode && a.uid == b.uid && a.gid == b.gid {
            Ok(())
        } else {
            Err(IncompleteReason::Changed)
        }
    }
    pub(super) fn os_error(e: rustix::io::Errno) -> IncompleteReason {
        match e {
            rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL | rustix::io::Errno::LOOP => IncompleteReason::UnsupportedResolution,
            rustix::io::Errno::XDEV => IncompleteReason::MountCrossing,
            rustix::io::Errno::ACCESS | rustix::io::Errno::PERM => IncompleteReason::Unreadable,
            rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR => IncompleteReason::Changed,
            _ => IncompleteReason::Io,
        }
    }
    fn cstring(bytes: &[u8]) -> Result<CString, IncompleteReason> {
        CString::new(bytes).map_err(|_| IncompleteReason::InvalidPath)
    }
    fn resolution(below: bool) -> ResolveFlags {
        let flags = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
        if below { flags | ResolveFlags::NO_XDEV } else { flags }
    }
    fn open_path(parent: &OwnedFd, name: &[u8], directory: bool, below: bool, b: &mut Budget) -> Result<OwnedFd, IncompleteReason> {
        b.check()?;
        let mut flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        if directory { flags |= OFlags::DIRECTORY; }
        fs::openat2(parent, cstring(name)?.as_c_str(), flags, Mode::empty(), resolution(below)).map_err(os_error)
    }
    struct Link { fd: OwnedFd, name: Vec<u8>, identity: Identity }
    struct Anchor { route: Vec<Link> }
    impl Anchor {
        fn open<H: Boundary>(path: &Path, b: &mut Budget, hooks: &mut H) -> Result<Self, IncompleteReason> {
            let raw = path.as_os_str().as_bytes();
            if raw.first() != Some(&b'/') || raw.len() > MAX_PATH_BYTES { return Err(IncompleteReason::InvalidPath); }
            let parts: Vec<&[u8]> = if raw == b"/" { vec![] } else { raw[1..].split(|c| *c == b'/').collect() };
            if parts.len() > MAX_DEPTH || parts.iter().any(|p| p.is_empty() || *p == b"." || *p == b".." || p.contains(&0)) {
                return Err(IncompleteReason::InvalidPath);
            }
            b.check()?;
            let fd = fs::openat(fs::CWD, c"/", OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(os_error)?;
            let identity = stat(&fd, b)?;
            let mut anchor = Self { route:vec![Link { fd, name:vec![], identity }] };
            for part in parts { anchor.descend(part, false, b, hooks)?; }
            Ok(anchor)
        }
        fn last(&self) -> &Link { self.route.last().expect("anchor always has root") }
        fn descend<H: Boundary>(&mut self, name: &[u8], below: bool, b: &mut Budget, _hooks: &mut H) -> Result<(), IncompleteReason> {
            let fd = match open_path(&self.last().fd, name, true, below, b) {
                Ok(fd) => fd,
                Err(reason) => {
                    #[cfg(test)]
                    _hooks.anchor_rejected(name, reason);
                    return Err(reason);
                }
            };
            let identity = stat(&fd, b)?;
            binding_equal(&identity, &named(&self.last().fd, name, b)?)?;
            self.route.push(Link { fd, name:name.to_vec(), identity }); Ok(())
        }
        fn recheck(&self, b: &mut Budget) -> Result<(), IncompleteReason> {
            for (i, link) in self.route.iter().enumerate() {
                binding_equal(&link.identity, &stat(&link.fd, b)?)?;
                if i > 0 { binding_equal(&link.identity, &named(&self.route[i-1].fd, &link.name, b)?)?; }
            }
            Ok(())
        }
    }
    struct TrustedProc { anchor: Anchor, proc_index: usize }
    impl TrustedProc {
        fn open<H: Boundary>(b: &mut Budget, hooks: &mut H) -> Result<Self, IncompleteReason> {
            let mut anchor = Anchor::open(Path::new("/proc"), b, hooks)?;
            let proc_index = anchor.route.len() - 1;
            b.check()?;
            let fs = fs::fstatfs(&anchor.last().fd).map_err(os_error)?;
            if fs.f_type != fs::PROC_SUPER_MAGIC || anchor.last().identity.uid != 0 || anchor.last().identity.mode & 0o022 != 0 {
                return Err(IncompleteReason::UntrustedProc);
            }
            let pid = rustix::process::getpid().as_raw_pid().to_string();
            for part in [pid.as_bytes(), b"fd".as_slice()] {
                anchor.descend(part, true, b, hooks)?;
                let identity = &anchor.last().identity;
                if identity.uid != rustix::process::geteuid().as_raw() || identity.mode & 0o022 != 0 {
                    return Err(IncompleteReason::UntrustedProc);
                }
            }
            let result = Self { anchor, proc_index }; result.recheck(b)?; Ok(result)
        }
        fn recheck(&self, b: &mut Budget) -> Result<(), IncompleteReason> {
            self.anchor.recheck(b)?; b.check()?;
            if fs::fstatfs(&self.anchor.route[self.proc_index].fd).map_err(os_error)?.f_type != fs::PROC_SUPER_MAGIC {
                return Err(IncompleteReason::UntrustedProc);
            }
            Ok(())
        }
        fn reopen<H: Boundary>(&self, retained: &OwnedFd, expected: &Identity, path: &[u8], b: &mut Budget, hooks: &mut H) -> Result<OwnedFd, IncompleteReason> {
            regular(expected)?; equal(expected, &stat(retained, b)?)?;
            self.recheck(b)?;
            let numeric = retained.as_raw_fd().to_string();
            hooks.event(Event::BeforeDataOpen, path, Some(expected))?;
            b.check()?;
            // The ONLY deliberate magic-link follow: a numeric fd in trusted
            // /proc/<our pid>/fd, with the original OwnedFd retained throughout.
            // Never reopen the original pathname; NOFOLLOW would defeat this.
            let fd = fs::openat(&self.anchor.last().fd, numeric.as_str(), OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK, Mode::empty()).map_err(os_error)?;
            let reopened = stat(&fd, b)?;
            hooks.event(Event::DataOpened, path, Some(&reopened))?;
            equal(expected, &reopened)?; Ok(fd)
        }
    }
    fn regular(i: &Identity) -> Result<(), IncompleteReason> {
        match i.kind() {
            FileType::Symlink => Err(IncompleteReason::Symlink),
            FileType::RegularFile if i.links != 1 => Err(IncompleteReason::Hardlink),
            FileType::RegularFile => Ok(()),
            _ => Err(IncompleteReason::SpecialFile),
        }
    }

    // No external implementation or runtime injection. Only private tests use
    // these dangerous-syscall/observation checkpoints; production is identity.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Event { BeforeChildOpen, BeforeDataOpen, DataOpened, BeforeFileRead, BeforeReenumerate, BeforeAnchorRecheck }
    pub(super) trait Boundary {
        fn event(&mut self, _e: Event, _path: &[u8], _i: Option<&Identity>) -> Result<(), IncompleteReason> { Ok(()) }
        fn child_identity(&mut self, identity: Identity) -> Identity { identity }
        // Test-only observations at actual decisions; no return value can
        // override refusal, and neither observer exists in production.
        #[cfg(test)]
        fn rejected(&mut self, _path: &[u8], _reason: IncompleteReason) {}
        #[cfg(test)]
        fn anchor_rejected(&mut self, _name: &[u8], _reason: IncompleteReason) {}
    }
    pub(super) struct SystemBoundary;
    impl Boundary for SystemBoundary {}

    #[derive(Debug)]
    pub(super) struct Entry {
        pub(super) path: RawPath,
        identity: Identity,
        pub(super) content_sha256: Option<[u8;32]>,
    }
    struct Held {
        fd: OwnedFd, parent: Option<usize>, name: Vec<u8>, path: Vec<u8>, identity: Identity,
        names: Option<Vec<Vec<u8>>>,
    }
    /// Filesystem-only seal. No membership/admin classification, no Deserialize,
    /// and no public conversion into complete inspection or persisted receipt.
    pub(super) struct Census {
        pub(super) entries: Vec<Entry>,
        _held: Vec<Held>, _anchor: Anchor, _proc: TrustedProc,
    }
    struct Walker<'a, H> {
        b: &'a mut Budget, hooks: &'a mut H, proc: TrustedProc,
        held: Vec<Held>, entries: Vec<Entry>,
    }
    pub(super) fn walk<H: Boundary>(path: &Path, b: &mut Budget, hooks: &mut H) -> Result<Census, IncompleteReason> {
        match walk_inner(path, b, hooks) {
            Ok(census) => Ok(census),
            Err(reason) => b.fail(reason),
        }
    }
    fn walk_inner<H: Boundary>(path: &Path, b: &mut Budget, hooks: &mut H) -> Result<Census, IncompleteReason> {
        let anchor = Anchor::open(path, b, hooks)?;
        let proc = TrustedProc::open(b, hooks)?;
        let fd = open_path(&anchor.last().fd, b".", true, true, b)?;
        let identity = stat(&fd, b)?; equal(&anchor.last().identity, &identity)?;
        b.entry()?; b.output(256)?;
        let mut w = Walker { b, hooks, proc, held:vec![Held { fd, parent:None, name:vec![], path:vec![], identity, names:None }], entries:vec![] };
        w.visit(0, 0)?;
        // Enter the final content AND binding recheck boundary. Root remains
        // a full held census object even though Anchor checks only bindings.
        w.hooks.event(Event::BeforeAnchorRecheck, &[], None)?;
        // Global recheck, not just a local check when leaving each subtree.
        for index in 0..w.held.len() {
            if w.held[index].names.is_some() {
                w.hooks.event(Event::BeforeReenumerate, &w.held[index].path, None)?;
                let now = enumerate(&w.held[index], w.b, false)?;
                if Some(&now) != w.held[index].names.as_ref() { return Err(IncompleteReason::Changed); }
            }
            w.check_held(index)?;
        }
        anchor.recheck(w.b)?; w.proc.recheck(w.b)?; w.b.check()?;
        w.entries.sort_by(|a,b| a.path.cmp(&b.path));
        Ok(Census { entries:w.entries, _held:w.held, _anchor:anchor, _proc:w.proc })
    }
    impl<H: Boundary> Walker<'_, H> {
        fn check_held(&mut self, index: usize) -> Result<(), IncompleteReason> {
            let held = &self.held[index];
            equal(&held.identity, &stat(&held.fd, self.b)?)?;
            if let Some(parent) = held.parent { equal(&held.identity, &named(&self.held[parent].fd, &held.name, self.b)?)?; }
            Ok(())
        }
        fn visit(&mut self, parent: usize, depth: usize) -> Result<(), IncompleteReason> {
            self.b.check()?;
            if depth > MAX_DEPTH { return self.b.fail(IncompleteReason::DepthBudget); }
            let names = enumerate(&self.held[parent], self.b, true)?;
            for name in &names {
                let mut path = self.held[parent].path.clone();
                if !path.is_empty() { path.push(b'/'); }
                path.extend_from_slice(name);
                let raw = RawPath::from_bytes(&path).map_err(|_| IncompleteReason::InvalidPath)?;
                if (name == b".git" && depth > 0) || name == b".gitmodules" {
                    #[cfg(test)]
                    self.hooks.rejected(&path, IncompleteReason::NestedGit);
                    return Err(IncompleteReason::NestedGit);
                }
                self.hooks.event(Event::BeforeChildOpen, &path, None)?;
                let fd = open_path(&self.held[parent].fd, name, false, true, self.b)?;
                let real = stat(&fd, self.b)?;
                let identity = self.hooks.child_identity(real);
                // Check type/link count BEFORE any readable data open.
                let directory = identity.kind() == FileType::Directory;
                if !directory {
                    if let Err(reason) = regular(&identity) {
                        #[cfg(test)]
                        self.hooks.rejected(&path, reason);
                        return Err(reason);
                    }
                }
                if identity.device != self.held[0].identity.device { return Err(IncompleteReason::MountCrossing); }
                if name == b".git" && directory {
                    #[cfg(test)]
                    self.hooks.rejected(&path, IncompleteReason::GitMetadataUnproven);
                    return Err(IncompleteReason::GitMetadataUnproven);
                }
                equal(&identity, &named(&self.held[parent].fd, name, self.b)?)?;
                let index = self.held.len();
                self.held.push(Held { fd, parent:Some(parent), name:name.clone(), path:path.clone(), identity:identity.clone(), names:None });
                let content_sha256 = if directory { self.visit(index, depth + 1)?; None } else { Some(self.hash_file(index)?) };
                self.check_held(index)?;
                self.entries.push(Entry { path:raw, identity, content_sha256 });
            }
            self.held[parent].names = Some(names);
            self.check_held(parent)
        }
        fn hash_file(&mut self, index: usize) -> Result<[u8;32], IncompleteReason> {
            let held = &self.held[index];
            regular(&held.identity)?;
            let length = u64::try_from(held.identity.size).map_err(|_| IncompleteReason::Changed)?;
            self.b.file_length(length)?;
            let fd = self.proc.reopen(&held.fd, &held.identity, &held.path, self.b, self.hooks)?;
            self.check_held(index)?;
            let held = &self.held[index];
            self.hooks.event(Event::BeforeFileRead, &held.path, Some(&held.identity))?;
            // Safe ownership conversion. No unsafe/from_raw_fd, no original path.
            let mut file = File::from(fd); let mut hasher = Sha256::new();
            let mut remaining = length; let mut buffer = [0u8; 8192];
            while remaining != 0 {
                let count = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| IncompleteReason::FileBudget)?;
                let n = read_chunk(&mut file, &mut buffer[..count], self.b)?;
                if n == 0 { return Err(IncompleteReason::Changed); }
                hasher.update(&buffer[..n]); remaining -= n as u64;
            }
            // Even an expected EOF requires a reserved byte. Growth is charged.
            let n = read_chunk(&mut file, &mut buffer[..1], self.b)?;
            if n != 0 { return Err(IncompleteReason::Changed); }
            self.b.check()?;
            let after = fs::fstat(&file).map(Identity::from_stat).map_err(os_error)?;
            equal(&held.identity, &after)?;
            self.check_held(index)?; self.proc.recheck(self.b)?;
            Ok(hasher.finalize().into())
        }
    }
    fn enumerate(held: &Held, b: &mut Budget, first: bool) -> Result<Vec<Vec<u8>>, IncompleteReason> {
        b.check()?;
        // A NEW readable open of '.' gives an independent directory cursor;
        // neither O_PATH nor dup of an exhausted cursor is used as RawDir input.
        let readable = fs::openat2(&held.fd, c".", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(), resolution(true)).map_err(os_error)?;
        equal(&held.identity, &stat(&readable, b)?)?;
        let mut buffer = [MaybeUninit::<u8>::uninit(); DIRECTORY_BUFFER_BYTES];
        let mut dir = RawDir::new(&readable, &mut buffer);
        let mut names = BTreeSet::new();
        loop {
            // The shared tested gate reserves BEFORE next(), including EOF
            // and errors. The closure returns only a bounded OWNED name; the
            // RawDir borrow cannot escape into a subsequent next()/refill.
            let next = directory_next(b, dir.is_buffer_empty(), || {
                match dir.next() {
                    None => Ok(None),
                    Some(Err(e)) => Err(os_error(e)),
                    Some(Ok(entry)) => {
                        let name = entry.file_name().to_bytes();
                        if name.len() > MAX_PATH_BYTES { return Err(IncompleteReason::InvalidPath); }
                        Ok(Some(name.to_vec()))
                    }
                }
            })??;
            let Some(name) = next else { break; };
            if name == b"." || name == b".." { continue; }
            let length = held.path.len() + usize::from(!held.path.is_empty()) + name.len();
            if name.is_empty() || name.contains(&b'/') || length > MAX_PATH_BYTES { return Err(IncompleteReason::InvalidPath); }
            if names.len() >= MAX_ENTRIES as usize { return b.fail(IncompleteReason::EntryBudget); }
            if first { b.entry()?; b.output((length as u64) * 2 + 256)?; }
            // Evidence of returned names, NOT the number of kernel bytes read.
            b.counters.copied_name_bytes = b.counters.copied_name_bytes.checked_add(name.len() as u64).ok_or(IncompleteReason::ReadBudget)?;
            if !names.insert(name) { return Err(IncompleteReason::Changed); }
        }
        equal(&held.identity, &stat(&held.fd, b)?)?;
        Ok(names.into_iter().collect())
    }
}
