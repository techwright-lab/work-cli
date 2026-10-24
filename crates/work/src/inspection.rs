//! Bounded cooperative inspection. Complete means coverage, never deletion safety.
//! Observations are nondurable; no lifecycle mutation or receipt persistence.
//! Inspector reads are descriptor anchored. Native Git reopens pathnames and is
//! NOT descriptor-race-contained: postchecks cannot prevent raced device opens.
//! Operation deadlines cannot interrupt a syscall stuck in the kernel.
use crate::disposal::RawPath;
use crate::{disposal::ValidatedPolicies, store::Store};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use uuid::Uuid;

#[cfg(test)]
#[path = "inspection_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    Complete,
    Incomplete,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncompleteReason {
    GitProofUnavailable,
    RegistrationEnvelopeOpen,
    ContextUnavailable,
    UnsupportedResolution,
    UntrustedProc,
    Unreadable,
    MountCrossing,
    Changed,
    Symlink,
    Hardlink,
    SpecialFile,
    NestedGit,
    GitMetadataUnproven,
    InvalidPath,
    EntryBudget,
    DepthBudget,
    FileBudget,
    ReadBudget,
    OutputBudget,
    ProcessBudget,
    Deadline,
    Io,
    UnsupportedGit,
    UnsupportedConfig,
    UnsupportedIndex,
    InvalidProtocol,
    InvalidObject,
    ContextConflict,
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
    pub repository_launches: u64,
    pub observed_process_input_bytes: u64,
    pub uncertain_process_reservation_bytes: u64,
    /// Conservative admitted input charge; not measured native Git disk reads.
    pub native_input_reserved_bytes: u64,
    pub reserved_child_slots: u64,
    pub reserved_process_input_bytes: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingKind {
    TrackedContent,
    StagedChange,
    Untracked,
    IgnoredUnclassified,
    PolicyMismatch,
}
#[derive(Clone, Debug)]
pub struct Finding {
    path: RawPath,
    kind: FindingKind,
}
impl Finding {
    pub fn path(&self) -> &RawPath {
        &self.path
    }
    pub fn kind(&self) -> FindingKind {
        self.kind
    }
}
#[derive(Clone, Debug)]
pub struct ObservedEntry {
    path: RawPath,
    mode: u32,
    length: u64,
    content: Option<[u8; 32]>,
    policy: Option<String>,
    tracked: bool,
    assume_unchanged: bool,
    skip_worktree: bool,
}
impl ObservedEntry {
    pub fn path(&self) -> &RawPath {
        &self.path
    }
    pub fn mode(&self) -> u32 {
        self.mode
    }
    pub fn length(&self) -> u64 {
        self.length
    }
    pub fn content_sha256(&self) -> Option<[u8; 32]> {
        self.content
    }
    pub fn policy_match(&self) -> Option<&str> {
        self.policy.as_deref()
    }
    pub fn tracked(&self) -> bool {
        self.tracked
    }
    pub fn assume_unchanged(&self) -> bool {
        self.assume_unchanged
    }
    pub fn skip_worktree(&self) -> bool {
        self.skip_worktree
    }
}
/// Passive, nondurable output. No Deserialize or constructor confers freshness.
#[derive(Debug)]
pub struct Observation {
    reasons: Vec<IncompleteReason>,
    counters: Counters,
    entries: Vec<ObservedEntry>,
    findings: Vec<Finding>,
    canonical: Vec<u8>,
    digest: [u8; 32],
    git_version: Option<String>,
}
impl Observation {
    pub fn coverage(&self) -> Coverage {
        if self.reasons.is_empty() {
            Coverage::Complete
        } else {
            Coverage::Incomplete
        }
    }
    pub fn reasons(&self) -> &[IncompleteReason] {
        &self.reasons
    }
    pub fn counters(&self) -> &Counters {
        &self.counters
    }
    pub fn entries(&self) -> &[ObservedEntry] {
        &self.entries
    }
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn git_version(&self) -> Option<&str> {
        self.git_version.as_deref()
    }
}
#[derive(Debug, thiserror::Error)]
#[error("inspection encoding unavailable")]
pub struct InspectionError;

/// Reads targeted authority in a bounded snapshot, drops SQL before filesystem
/// or Git I/O, and compares a new snapshot after all observations. No lease,
/// writer row, readiness update, identity refresh, migration or persistence.
pub fn inspect(
    store: &mut Store,
    checkout: Uuid,
    policies: &ValidatedPolicies,
) -> Result<Observation, InspectionError> {
    inspect_inner(
        store,
        checkout,
        policies,
        #[cfg(test)]
        None,
    )
}
fn inspect_inner(
    store: &mut Store,
    checkout: Uuid,
    policies: &ValidatedPolicies,
    #[cfg(test)] before_repeat: Option<&mut dyn FnMut(&mut Store)>,
) -> Result<Observation, InspectionError> {
    let mut b = Budget::new();
    let mut context_bytes = checkout.as_bytes().to_vec();
    let mut evidence = Vec::new();
    let mut entries = Vec::new();
    let mut findings = Vec::new();
    let result = (|| {
        let context = snapshot(store, checkout, &mut b)?;
        context_bytes = context.canonical.clone();
        let identity = context
            .allocation
            .identity
            .as_ref()
            .ok_or(IncompleteReason::ContextUnavailable)?;
        for path in [
            &identity.path,
            &identity.private_git_dir,
            &identity.common_git_dir,
        ] {
            native_anchor_path(path)?;
        }
        let first = filesystem::walk(&identity.path, &mut b, &mut filesystem::SystemBoundary)?;
        frame(&mut evidence, 1, &first.fingerprint());
        let before = GitInputs::capture(&context, &first, &mut b)?;
        frame(&mut evidence, 2, &before.fingerprint());
        let proof = GitProof::observe(&context, &first, &before, &mut b)?;
        frame(&mut evidence, 3, &proof.canonical);
        (entries, findings) = classify(&first, &proof, policies);
        #[cfg(test)]
        if let Some(hook) = before_repeat {
            hook(store);
        }
        let second = filesystem::walk(&identity.path, &mut b, &mut filesystem::SystemBoundary)?;
        let after = GitInputs::capture(&context, &second, &mut b)?;
        let repeated = GitProof::observe(&context, &second, &after, &mut b)?;
        frame(&mut evidence, 4, &second.fingerprint());
        frame(&mut evidence, 5, &after.fingerprint());
        frame(&mut evidence, 6, &repeated.canonical);
        first.recheck(&mut b)?;
        before.recheck(&mut b)?;
        second.recheck(&mut b)?;
        after.recheck(&mut b)?;
        if first.fingerprint() != second.fingerprint()
            || before.fingerprint() != after.fingerprint()
            || proof.canonical != repeated.canonical
        {
            return Err(IncompleteReason::Changed);
        }
        let current = snapshot(store, checkout, &mut b)?;
        if context.canonical != current.canonical {
            return Err(IncompleteReason::ContextConflict);
        }
        b.check()
    })();
    finish_observation(
        policies,
        &context_bytes,
        &evidence,
        entries,
        findings,
        result.err(),
        &b,
    )
}

fn frame(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    out.extend((value.len() as u64).to_be_bytes());
    out.extend(value);
}
#[allow(clippy::too_many_arguments)]
fn finish_observation(
    policies: &ValidatedPolicies,
    context: &[u8],
    evidence: &[u8],
    mut entries: Vec<ObservedEntry>,
    findings: Vec<Finding>,
    reason: Option<IncompleteReason>,
    b: &Budget,
) -> Result<Observation, InspectionError> {
    if reason.is_some() {
        for entry in &mut entries {
            entry.policy = None;
        }
    }
    let mut canonical = Vec::new();
    frame(
        &mut canonical,
        0,
        if reason.is_some() {
            b"work.inspection.incomplete.v1"
        } else {
            b"work.inspection.complete.v1"
        },
    );
    frame(&mut canonical, 1, policies.canonical_bytes());
    frame(&mut canonical, 2, &Sha256::digest(context));
    frame(&mut canonical, 3, &Sha256::digest(evidence));
    frame(&mut canonical, 14, &b.evidence.clone().finalize());
    frame(
        &mut canonical,
        16,
        b.git_version.as_deref().unwrap_or("").as_bytes(),
    );
    frame(&mut canonical, 4, &[reason.map_or(0, |r| r as u8 + 1)]);
    for n in [
        30,
        MAX_ENTRIES,
        MAX_DEPTH as u64,
        MAX_PATH_BYTES as u64,
        MAX_FILE_BYTES,
        MAX_CHARGED_BYTES,
        MAX_OUTPUT_BYTES,
        96,
        1024 * 1024,
        8 * 1024 * 1024,
        32 * 1024,
        2,
        256,
        256 * 1024,
        128,
        TERMINAL_RESERVE,
        DIRECTORY_BUFFER_BYTES as u64,
        MAX_FILE_BYTES + 65536,
    ] {
        frame(&mut canonical, 5, &n.to_be_bytes());
    }
    let c = &b.counters;
    for n in [
        c.entries,
        c.observed_file_bytes,
        c.observed_process_bytes,
        c.directory_reserved_bytes,
        c.uncertain_file_reservation_bytes,
        c.charged_read_bytes,
        c.copied_name_bytes,
        c.retained_output_bytes,
        c.child_launches,
        c.repository_launches,
        c.observed_process_input_bytes,
        c.uncertain_process_reservation_bytes,
        c.native_input_reserved_bytes,
        c.reserved_child_slots,
        c.reserved_process_input_bytes,
    ] {
        frame(&mut canonical, 6, &n.to_be_bytes());
    }
    for entry in &entries {
        frame(
            &mut canonical,
            15,
            &[
                u8::from(entry.tracked),
                u8::from(entry.assume_unchanged),
                u8::from(entry.skip_worktree),
            ],
        );
        frame(&mut canonical, 7, entry.path.as_bytes());
        frame(&mut canonical, 8, &entry.mode.to_be_bytes());
        frame(&mut canonical, 9, &entry.length.to_be_bytes());
        frame(
            &mut canonical,
            10,
            entry.content.as_ref().map_or(&[][..], |v| v.as_slice()),
        );
        frame(
            &mut canonical,
            11,
            entry.policy.as_deref().unwrap_or("").as_bytes(),
        );
    }
    for f in &findings {
        frame(&mut canonical, 12, f.path.as_bytes());
        frame(&mut canonical, 13, &[f.kind as u8]);
    }
    if canonical.len() as u64 > MAX_OUTPUT_BYTES {
        // Explicit omission of the root, with a commitment to the discarded
        // bounded body. Never truncate and label it complete.
        let omitted = Sha256::digest(&canonical);
        return finish_observation(
            policies,
            context,
            &omitted,
            vec![],
            vec![],
            Some(IncompleteReason::OutputBudget),
            b,
        );
    }
    let digest = Sha256::digest(&canonical).into();
    Ok(Observation {
        reasons: reason.into_iter().collect(),
        counters: c.clone(),
        entries,
        findings,
        canonical,
        digest,
        git_version: b.git_version.clone(),
    })
}

struct Context {
    allocation: crate::allocate::Allocation,
    canonical: Vec<u8>,
}
fn snapshot(
    store: &mut Store,
    checkout: Uuid,
    b: &mut Budget,
) -> Result<Context, IncompleteReason> {
    use rusqlite::types::ValueRef;
    fn unavailable<E>(_: E) -> IncompleteReason {
        IncompleteReason::ContextUnavailable
    }
    b.check()?;
    // This existing metadata-only guard rejects externally active SQL phases
    // as well as transactions. It does NOT acquire a lease or touch its file.
    // Read-only Store handles are conservatively unsupported by this API.
    store.may_acquire_lease().map_err(unavailable)?;
    let mut canonical = Vec::new();
    let authority = store.authority_identity();
    frame(
        &mut canonical,
        0,
        authority.registry().as_os_str().as_bytes(),
    );
    frame(
        &mut canonical,
        1,
        authority.directory.as_os_str().as_bytes(),
    );
    for n in [
        authority.directory_id.0,
        authority.directory_id.1,
        authority.database_id().0,
        authority.database_id().1,
    ] {
        frame(&mut canonical, 2, &n.to_be_bytes());
    }
    if let Some((dev, ino)) = authority.lock_id {
        frame(&mut canonical, 3, &dev.to_be_bytes());
        frame(&mut canonical, 3, &ino.to_be_bytes());
    }
    let _phase = store.sql_phase();
    let tx = store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
        .map_err(unavailable)?;
    let version: i64 = tx
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(unavailable)?;
    if version != 15 {
        return Err(IncompleteReason::ContextUnavailable);
    }
    frame(&mut canonical, 4, &version.to_be_bytes());
    let schema: i64 = tx
        .query_row("PRAGMA schema_version", [], |r| r.get(0))
        .map_err(unavailable)?;
    frame(&mut canonical, 12, &schema.to_be_bytes());
    let id = checkout.to_string();
    // Full exact nullable SQL values; no lossy JSON reconstruction of context.
    let queries = [
        "SELECT * FROM checkouts WHERE id=?1 ORDER BY id",
        "SELECT * FROM allocations WHERE checkout=?1 ORDER BY checkout",
        "SELECT * FROM repository_aliases WHERE alias=(SELECT repository FROM checkouts WHERE id=?1) OR common=(SELECT repository FROM checkouts WHERE id=?1) ORDER BY alias",
        "SELECT * FROM writers WHERE checkout=?1 ORDER BY checkout",
        "SELECT * FROM run_groups WHERE checkout=?1 ORDER BY id",
        "SELECT * FROM runs WHERE group_id IN (SELECT id FROM run_groups WHERE checkout=?1) ORDER BY id",
        "SELECT * FROM run_participants WHERE group_id IN (SELECT id FROM run_groups WHERE checkout=?1) ORDER BY id",
        "SELECT * FROM adopted_groups WHERE checkout=?1 ORDER BY id",
        "SELECT * FROM adopted_sessions WHERE group_id IN (SELECT id FROM adopted_groups WHERE checkout=?1) ORDER BY group_id,source,session,agent",
        "SELECT * FROM adopted_segments WHERE group_id IN (SELECT id FROM adopted_groups WHERE checkout=?1) ORDER BY group_id,source,session,agent,prompt,tool,kind,event_ref",
        "SELECT * FROM task_finishes WHERE checkout=?1 ORDER BY checkout",
        "SELECT * FROM capture_requirements WHERE checkout=?1 ORDER BY checkout",
        "SELECT * FROM capture_runs WHERE checkout=?1 ORDER BY run",
        "SELECT * FROM capture_finalizations WHERE run IN (SELECT run FROM capture_runs WHERE checkout=?1) ORDER BY run",
        "SELECT * FROM capture_readiness WHERE checkout=?1 ORDER BY checkout",
        "SELECT * FROM attribution_gaps WHERE checkout=?1 ORDER BY run",
        "SELECT * FROM gap_qualifications WHERE checkout=?1 ORDER BY run",
        "SELECT * FROM gap_eligibility WHERE checkout=?1 ORDER BY checkout",
    ];
    for query in queries {
        frame(&mut canonical, 5, query.as_bytes());
        let mut stmt = tx.prepare(query).map_err(unavailable)?;
        let columns = stmt.column_count();
        let mut rows = stmt.query([&id]).map_err(unavailable)?;
        while let Some(row) = rows.next().map_err(unavailable)? {
            b.check()?;
            frame(&mut canonical, 6, &(columns as u64).to_be_bytes());
            for column in 0..columns {
                let value = row.get_ref(column).map_err(unavailable)?;
                let (tag, bytes) = match value {
                    ValueRef::Null => (7, Vec::new()),
                    ValueRef::Integer(v) => (8, v.to_be_bytes().to_vec()),
                    ValueRef::Real(v) => (9, v.to_bits().to_be_bytes().to_vec()),
                    ValueRef::Text(v) => (10, v.to_vec()),
                    ValueRef::Blob(v) => (11, v.to_vec()),
                };
                if canonical
                    .len()
                    .saturating_add(bytes.len())
                    .saturating_add(9)
                    > MAX_FILE_BYTES as usize
                {
                    return Err(IncompleteReason::ContextUnavailable);
                }
                b.reserve(bytes.len() as u64 + 9)?;
                b.observe(tag, &bytes);
                frame(&mut canonical, tag, &bytes);
            }
        }
    }
    let (operation, repository, actor, task, request, record): (String,String,String,String,String,String) = tx.query_row(
        "SELECT c.operation,c.repository,c.actor,c.task,a.request,a.record FROM checkouts c JOIN allocations a ON a.checkout=c.id WHERE c.id=?1", [&id],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).map_err(unavailable)?;
    let allocation: crate::allocate::Allocation =
        serde_json::from_str(&record).map_err(|_| IncompleteReason::ContextUnavailable)?;
    let stored_request: crate::allocate::Start =
        serde_json::from_str(&request).map_err(|_| IncompleteReason::ContextUnavailable)?;
    let identity = allocation
        .identity
        .as_ref()
        .ok_or(IncompleteReason::ContextUnavailable)?;
    let common = identity
        .common_git_dir
        .to_str()
        .ok_or(IncompleteReason::ContextUnavailable)?;
    let alias_ok: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM repository_aliases WHERE common=?1 AND (alias=?2 OR common=?2))", (common, &repository), |r| r.get(0)).map_err(unavailable)?;
    let requested_repository = allocation
        .request
        .repository
        .as_ref()
        .and_then(|p| p.to_str())
        .ok_or(IncompleteReason::ContextUnavailable)?;
    let requested_alias: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM repository_aliases WHERE alias=?1 AND common=?2)",
            (requested_repository, common),
            |r| r.get(0),
        )
        .map_err(unavailable)?;
    if allocation.checkout != checkout
        || allocation.request != stored_request
        || operation != allocation.request.operation.to_string()
        || allocation.destination != identity.path
        || allocation.request.actor.as_deref() != Some(actor.as_str())
        || allocation.request.task != task
        || !alias_ok
        || !requested_alias
        || allocation
            .request
            .root
            .as_ref()
            .is_none_or(|root| root.join(&allocation.request.task) != allocation.destination)
        || identity.path == identity.common_git_dir
        || identity.private_git_dir == identity.common_git_dir
        || identity.boot_id.is_empty()
    {
        return Err(IncompleteReason::ContextUnavailable);
    }
    tx.rollback().map_err(unavailable)?;
    drop(_phase);
    Ok(Context {
        allocation,
        canonical,
    })
}

// Private streaming SHA1: Git format integrity only, not authenticity/crypto API.
struct Sha1 {
    state: [u32; 5],
    block: [u8; 64],
    used: usize,
    length: u64,
}
impl Sha1 {
    fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            block: [0; 64],
            used: 0,
            length: 0,
        }
    }
    fn compress(&mut self) {
        let mut w = [0u32; 80];
        for (i, bytes) in self.block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(bytes.try_into().expect("four bytes"));
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (i, word) in w.into_iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (slot, n) in self.state.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(n);
        }
    }
    fn update(&mut self, mut bytes: &[u8]) {
        self.length = self.length.wrapping_add(bytes.len() as u64);
        while !bytes.is_empty() {
            let n = (64 - self.used).min(bytes.len());
            self.block[self.used..self.used + n].copy_from_slice(&bytes[..n]);
            self.used += n;
            bytes = &bytes[n..];
            if self.used == 64 {
                self.compress();
                self.used = 0;
            }
        }
    }
    fn finish(mut self) -> [u8; 20] {
        let bits = self.length.wrapping_mul(8);
        self.update(&[0x80]);
        while self.used != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 20];
        for (dst, n) in out.chunks_exact_mut(4).zip(self.state) {
            dst.copy_from_slice(&n.to_be_bytes());
        }
        out
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObjectFormat {
    Sha1,
    Sha256,
}
impl ObjectFormat {
    fn width(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
    fn hash(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => {
                let mut h = Sha1::new();
                h.update(bytes);
                h.finish().to_vec()
            }
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
        }
    }
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}
fn oid(bytes: &[u8], format: ObjectFormat) -> Result<Vec<u8>, IncompleteReason> {
    if bytes.len() != format.width() * 2
        || !bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        || bytes.iter().all(|b| *b == b'0')
    {
        return Err(IncompleteReason::InvalidProtocol);
    }
    Ok(bytes.to_vec())
}
fn object_digest(format: ObjectFormat, kind: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut header = kind.to_vec();
    header.push(b' ');
    header.extend(bytes.len().to_string().bytes());
    header.push(0);
    match format {
        ObjectFormat::Sha1 => {
            let mut h = Sha1::new();
            h.update(&header);
            h.update(bytes);
            h.finish().to_vec()
        }
        ObjectFormat::Sha256 => {
            let mut h = Sha256::new();
            h.update(&header);
            h.update(bytes);
            h.finalize().to_vec()
        }
    }
}
fn decimal(bytes: &[u8]) -> Result<u64, IncompleteReason> {
    if bytes.is_empty()
        || (bytes.len() > 1 && bytes[0] == b'0')
        || !bytes.iter().all(u8::is_ascii_digit)
    {
        return Err(IncompleteReason::InvalidProtocol);
    }
    bytes.iter().try_fold(0u64, |n, c| {
        n.checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(*c - b'0')))
            .ok_or(IncompleteReason::InvalidProtocol)
    })
}
fn nul_records(bytes: &[u8]) -> Result<Vec<&[u8]>, IncompleteReason> {
    if bytes.is_empty() {
        return Ok(vec![]);
    }
    let body = bytes
        .strip_suffix(&[0])
        .ok_or(IncompleteReason::InvalidProtocol)?;
    let rows: Vec<_> = body.split(|b| *b == 0).collect();
    if rows.len() > MAX_ENTRIES as usize * 4 {
        return Err(IncompleteReason::EntryBudget);
    }
    Ok(rows)
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct IndexEntry {
    mode: u32,
    oid: Vec<u8>,
    assume_unchanged: bool,
    skip_worktree: bool,
}
type IndexMap = BTreeMap<RawPath, IndexEntry>;
fn regular_mode(bytes: &[u8]) -> Result<u32, IncompleteReason> {
    match bytes {
        b"100644" => Ok(0o100644),
        b"100755" => Ok(0o100755),
        _ => Err(IncompleteReason::UnsupportedIndex),
    }
}
fn parse_stage(bytes: &[u8], format: ObjectFormat) -> Result<IndexMap, IncompleteReason> {
    let mut map = BTreeMap::new();
    for row in nul_records(bytes)? {
        if map.len() >= MAX_ENTRIES as usize {
            return Err(IncompleteReason::EntryBudget);
        }
        let tab = row
            .iter()
            .position(|b| *b == b'\t')
            .ok_or(IncompleteReason::InvalidProtocol)?;
        let head: Vec<_> = row[..tab].split(|b| *b == b' ').collect();
        if head.len() != 3 || head[2] != b"0" {
            return Err(IncompleteReason::UnsupportedIndex);
        }
        let path =
            RawPath::from_bytes(&row[tab + 1..]).map_err(|_| IncompleteReason::InvalidPath)?;
        if map
            .insert(
                path,
                IndexEntry {
                    mode: regular_mode(head[0])?,
                    oid: oid(head[1], format)?,
                    assume_unchanged: false,
                    skip_worktree: false,
                },
            )
            .is_some()
        {
            return Err(IncompleteReason::InvalidProtocol);
        }
    }
    Ok(map)
}
fn apply_flags(bytes: &[u8], map: &mut IndexMap) -> Result<(), IncompleteReason> {
    let mut seen = BTreeSet::new();
    for row in nul_records(bytes)? {
        if row.len() < 3 || row[1] != b' ' || !b"HhSs".contains(&row[0]) {
            return Err(IncompleteReason::UnsupportedIndex);
        }
        let path = RawPath::from_bytes(&row[2..]).map_err(|_| IncompleteReason::InvalidPath)?;
        let entry = map
            .get_mut(&path)
            .ok_or(IncompleteReason::InvalidProtocol)?;
        entry.assume_unchanged = row[0].is_ascii_lowercase();
        entry.skip_worktree = matches!(row[0], b'S' | b's');
        if !seen.insert(path) {
            return Err(IncompleteReason::InvalidProtocol);
        }
    }
    if seen.len() != map.len() {
        return Err(IncompleteReason::InvalidProtocol);
    }
    Ok(())
}
fn parse_tree(bytes: &[u8], format: ObjectFormat) -> Result<IndexMap, IncompleteReason> {
    let mut map = BTreeMap::new();
    for row in nul_records(bytes)? {
        if map.len() >= MAX_ENTRIES as usize {
            return Err(IncompleteReason::EntryBudget);
        }
        let tab = row
            .iter()
            .position(|b| *b == b'\t')
            .ok_or(IncompleteReason::InvalidProtocol)?;
        let header: Vec<_> = row[..tab].split(|b| *b == b' ').collect();
        if header.len() != 3 || header[1] != b"blob" {
            return Err(IncompleteReason::UnsupportedIndex);
        }
        let path =
            RawPath::from_bytes(&row[tab + 1..]).map_err(|_| IncompleteReason::InvalidPath)?;
        if forbidden_path(&path) {
            return Err(IncompleteReason::UnsupportedGit);
        }
        if map
            .insert(
                path,
                IndexEntry {
                    mode: regular_mode(header[0])?,
                    oid: oid(header[2], format)?,
                    assume_unchanged: false,
                    skip_worktree: false,
                },
            )
            .is_some()
        {
            return Err(IncompleteReason::InvalidProtocol);
        }
    }
    Ok(map)
}
fn forbidden_path(path: &RawPath) -> bool {
    path.as_bytes()
        .split(|b| *b == b'/')
        .any(|p| matches!(p, b".git" | b".gitmodules" | b".gitattributes"))
}
struct Bytes<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Bytes<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], IncompleteReason> {
        let end = self
            .at
            .checked_add(n)
            .ok_or(IncompleteReason::InvalidProtocol)?;
        let out = self
            .bytes
            .get(self.at..end)
            .ok_or(IncompleteReason::InvalidProtocol)?;
        self.at = end;
        Ok(out)
    }
    fn until(&mut self, delimiter: u8) -> Result<&'a [u8], IncompleteReason> {
        let n = self.bytes[self.at..]
            .iter()
            .position(|b| *b == delimiter)
            .ok_or(IncompleteReason::InvalidProtocol)?;
        let out = self.take(n)?;
        self.take(1)?;
        Ok(out)
    }
    fn u32(&mut self) -> Result<u32, IncompleteReason> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("four")))
    }
    fn u16(&mut self) -> Result<u16, IncompleteReason> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("two")))
    }
}
fn parse_index(bytes: &[u8], format: ObjectFormat) -> Result<IndexMap, IncompleteReason> {
    if bytes.len() < 12 + format.width() {
        return Err(IncompleteReason::UnsupportedIndex);
    }
    let end = bytes.len() - format.width();
    if format.hash(&bytes[..end]) != bytes[end..] {
        return Err(IncompleteReason::UnsupportedIndex);
    }
    let mut r = Bytes {
        bytes: &bytes[..end],
        at: 0,
    };
    if r.take(4)? != b"DIRC" {
        return Err(IncompleteReason::UnsupportedIndex);
    }
    let version = r.u32()?;
    let count = r.u32()?;
    if !matches!(version, 2 | 3) || count > MAX_ENTRIES as u32 {
        return Err(IncompleteReason::UnsupportedIndex);
    }
    let mut map = IndexMap::new();
    let mut previous = None;
    for _ in 0..count {
        let start = r.at;
        let stat = r.take(40)?;
        let mode = u32::from_be_bytes(stat[24..28].try_into().expect("mode"));
        if !matches!(mode, 0o100644 | 0o100755) {
            return Err(IncompleteReason::UnsupportedIndex);
        }
        let object = oid(hex(r.take(format.width())?).as_bytes(), format)?;
        let flags = r.u16()?;
        if flags & 0x3000 != 0 {
            return Err(IncompleteReason::UnsupportedIndex);
        }
        let mut skip = false;
        if flags & 0x4000 != 0 {
            if version != 3 {
                return Err(IncompleteReason::UnsupportedIndex);
            }
            let extended = r.u16()?;
            if extended & !0x4000 != 0 {
                return Err(IncompleteReason::UnsupportedIndex);
            }
            skip = extended & 0x4000 != 0;
        }
        let raw = r.until(0)?;
        if (flags & 0xfff) as usize != raw.len().min(0xfff) {
            return Err(IncompleteReason::UnsupportedIndex);
        }
        let path = RawPath::from_bytes(raw).map_err(|_| IncompleteReason::InvalidPath)?;
        if forbidden_path(&path) || previous.as_ref().is_some_and(|p| p >= &path) {
            return Err(IncompleteReason::UnsupportedIndex);
        }
        previous = Some(path.clone());
        let padding = (8 - (r.at - start) % 8) % 8;
        if r.take(padding)?.iter().any(|b| *b != 0) {
            return Err(IncompleteReason::UnsupportedIndex);
        }
        map.insert(
            path,
            IndexEntry {
                mode,
                oid: object,
                assume_unchanged: flags & 0x8000 != 0,
                skip_worktree: skip,
            },
        );
    }
    let mut tree = false;
    while r.at < r.bytes.len() {
        if r.take(4)? != b"TREE" || tree {
            return Err(IncompleteReason::UnsupportedIndex);
        }
        tree = true;
        let size = r.u32()? as usize;
        let data = r.take(size)?;
        let mut cache = Bytes { bytes: data, at: 0 };
        let mut nodes = 0;
        cache_tree(&mut cache, format, 0, true, &mut nodes)?;
        if cache.at != data.len() {
            return Err(IncompleteReason::UnsupportedIndex);
        }
    }
    Ok(map)
}
fn cache_tree(
    r: &mut Bytes<'_>,
    format: ObjectFormat,
    depth: usize,
    root: bool,
    nodes: &mut u64,
) -> Result<(), IncompleteReason> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > MAX_ENTRIES {
        return Err(IncompleteReason::UnsupportedIndex);
    }
    let name = r.until(0)?;
    if root {
        if !name.is_empty() {
            return Err(IncompleteReason::UnsupportedIndex);
        }
    } else if name.is_empty() || name.contains(&b'/') || name == b"." || name == b".." {
        return Err(IncompleteReason::UnsupportedIndex);
    }
    let count = r.until(b' ')?;
    let children = decimal(r.until(b'\n')?)?;
    if count != b"-1" {
        if decimal(count)? > MAX_ENTRIES {
            return Err(IncompleteReason::UnsupportedIndex);
        }
        r.take(format.width())?;
    }
    if children > MAX_ENTRIES {
        return Err(IncompleteReason::UnsupportedIndex);
    }
    for _ in 0..children {
        cache_tree(r, format, depth + 1, false, nodes)?;
    }
    Ok(())
}
fn parse_ignored(
    bytes: &[u8],
    requested: &[RawPath],
) -> Result<BTreeMap<RawPath, bool>, IncompleteReason> {
    let rows = nul_records(bytes)?;
    if rows.len() != requested.len() * 4 {
        return Err(IncompleteReason::InvalidProtocol);
    }
    let mut result = BTreeMap::new();
    for (fields, path) in rows.chunks_exact(4).zip(requested) {
        // Git echoes the original stdin path, including our deliberate prefix.
        // Strip exactly that prefix; accept no normalization or alternate alias.
        let echoed = fields[3]
            .strip_prefix(b"./")
            .ok_or(IncompleteReason::InvalidProtocol)?;
        let echoed = RawPath::from_bytes(echoed).map_err(|_| IncompleteReason::InvalidProtocol)?;
        if &echoed != path {
            return Err(IncompleteReason::InvalidProtocol);
        }
        let ignored = if fields[..3].iter().all(|v| v.is_empty()) {
            false
        } else {
            if fields[0].is_empty() || fields[2].is_empty() || decimal(fields[1])? == 0 {
                return Err(IncompleteReason::InvalidProtocol);
            }
            // A final negative pattern is an explicit non-match, not ignored.
            fields[2].first() != Some(&b'!')
        };
        if result.insert(path.clone(), ignored).is_some() {
            return Err(IncompleteReason::InvalidProtocol);
        }
    }
    Ok(result)
}
type BlobMap = BTreeMap<Vec<u8>, (u64, [u8; 32])>;
fn parse_blobs(
    bytes: &[u8],
    expected: &[(Vec<u8>, u64)],
    format: ObjectFormat,
) -> Result<BlobMap, IncompleteReason> {
    let mut r = Bytes { bytes, at: 0 };
    let mut result = BTreeMap::new();
    for (id, length) in expected {
        let header = r.until(b'\n')?;
        let parts: Vec<_> = header.split(|b| *b == b' ').collect();
        if parts.len() != 3
            || parts[0] != id.as_slice()
            || parts[1] != b"blob"
            || decimal(parts[2])? != *length
            || *length > MAX_FILE_BYTES
        {
            return Err(IncompleteReason::InvalidObject);
        }
        let payload = r.take(*length as usize)?;
        if r.take(1)? != b"\n"
            || hex(&object_digest(format, b"blob", payload)).as_bytes() != id.as_slice()
        {
            return Err(IncompleteReason::InvalidObject);
        }
        if result
            .insert(id.clone(), (*length, Sha256::digest(payload).into()))
            .is_some()
        {
            return Err(IncompleteReason::InvalidObject);
        }
    }
    if r.at != bytes.len() {
        return Err(IncompleteReason::InvalidObject);
    }
    Ok(result)
}

struct ProcessOutput {
    code: i32,
    stdout: Vec<u8>,
}
fn run_command(
    command: &mut std::process::Command,
    input: &[u8],
    b: &mut Budget,
    repository: bool,
) -> Result<ProcessOutput, IncompleteReason> {
    use std::{
        io::{ErrorKind, Read, Write},
        os::unix::process::CommandExt,
        process::Stdio,
    };
    let argv =
        command
            .get_args()
            .try_fold(command.get_program().as_bytes().len() as u64, |n, s| {
                n.checked_add(s.as_bytes().len() as u64 + 1)
                    .ok_or(IncompleteReason::ProcessBudget)
            })?;
    let reservation = b.reserve_process(input.len() as u64, argv)?;
    b.observe(30, command.get_program().as_bytes());
    for arg in command.get_args() {
        b.observe(31, arg.as_bytes());
    }
    b.observe(32, &Sha256::digest(input));
    b.observe(33, &[u8::from(repository)]);
    command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let start = Instant::now();
    // Exactly one attempt; in particular no ETXTBSY retry.
    let mut child = command.spawn().map_err(|_| IncompleteReason::Io)?;
    b.counters.child_launches += 1;
    if repository {
        b.counters.repository_launches += 1;
    }
    #[cfg(test)]
    b.process_events.push("spawn");
    let group = rustix::process::Pid::from_child(&child);
    let mut stdout_hash = Sha256::new();
    let mut stdout_length = 0u64;
    let result = (|| {
        let mut stdout = child.stdout.take().ok_or(IncompleteReason::Io)?;
        let mut stderr = child.stderr.take().ok_or(IncompleteReason::Io)?;
        let mut stdin = child.stdin.take();
        for pipe in [
            &stdout as &dyn std::os::fd::AsFd,
            &stderr as &dyn std::os::fd::AsFd,
        ] {
            rustix::fs::fcntl_setfl(pipe, rustix::fs::OFlags::NONBLOCK)
                .map_err(|_| IncompleteReason::Io)?;
        }
        if let Some(pipe) = &stdin {
            rustix::fs::fcntl_setfl(pipe, rustix::fs::OFlags::NONBLOCK)
                .map_err(|_| IncompleteReason::Io)?;
        }
        let mut written = 0;
        let mut out = Vec::new();
        let mut eof = [false; 2];
        if input.is_empty() {
            drop(stdin.take());
        }
        loop {
            b.check()?;
            if start.elapsed() >= reservation.maximum_duration {
                return b.fail(IncompleteReason::Deadline);
            }
            let mut progressed = false;
            for (i, pipe) in [&mut stdout as &mut dyn Read, &mut stderr as &mut dyn Read]
                .into_iter()
                .enumerate()
            {
                if eof[i] {
                    continue;
                }
                let mut buffer = [0u8; 8192];
                let remaining = MAX_CHARGED_BYTES.saturating_sub(b.counters.charged_read_bytes);
                if remaining == 0 {
                    return b.fail(IncompleteReason::ReadBudget);
                }
                let count = buffer.len().min(remaining as usize);
                b.reserve(count as u64)?;
                b.counters.uncertain_process_reservation_bytes += count as u64;
                match pipe.read(&mut buffer[..count]) {
                    Ok(n) => {
                        b.counters.uncertain_process_reservation_bytes -= count as u64;
                        b.counters.charged_read_bytes -= (count - n) as u64;
                        b.counters.observed_process_bytes += n as u64;
                        if i == 0 {
                            stdout_hash.update(&buffer[..n]);
                            stdout_length += n as u64;
                        }
                        if n == 0 {
                            eof[i] = true;
                        } else {
                            // stderr is charged but never retained/exposed, even on errors.
                            if i == 0 {
                                if out.len().saturating_add(n) > MAX_FILE_BYTES as usize + 65536 {
                                    return b.fail(IncompleteReason::FileBudget);
                                }
                                out.extend_from_slice(&buffer[..n]);
                            }
                            progressed = true;
                        }
                    }
                    Err(e)
                        if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
                    {
                        b.counters.uncertain_process_reservation_bytes -= count as u64;
                        b.counters.charged_read_bytes -= count as u64;
                    }
                    Err(_) => return b.fail(IncompleteReason::Io),
                }
            }
            if let Some(pipe) = &mut stdin {
                let end = (written + 8192).min(input.len());
                match pipe.write(&input[written..end]) {
                    Ok(0) => return b.fail(IncompleteReason::Io),
                    Ok(n) => {
                        written += n;
                        b.counters.observed_process_input_bytes += n as u64;
                        progressed = true;
                    }
                    Err(e)
                        if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
                    {
                        ()
                    }
                    Err(_) => return b.fail(IncompleteReason::Io),
                }
                if written == input.len() {
                    drop(stdin.take());
                }
            }
            use rustix::process::{waitid, WaitId, WaitIdOptions};
            if eof == [true; 2]
                && waitid(
                    WaitId::Pid(group),
                    WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
                )
                .map_err(|_| IncompleteReason::Io)?
                .is_some()
            {
                #[cfg(test)]
                b.process_events.push("exit-nowait");
                if written != input.len() {
                    return Err(IncompleteReason::Io);
                }
                return Ok(out);
            }
            if !progressed {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    })();
    // Unreaped leader owns group identity through cleanup on every post-spawn
    // path. No try_wait, reader threads, detached retries, or recycled PID kill.
    #[cfg(test)]
    b.process_events.push("kill-group");
    let killed = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    if result.is_err() || killed.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|_| IncompleteReason::Io);
    #[cfg(test)]
    b.process_events.push("wait");
    b.observe(21, &stdout_length.to_be_bytes());
    b.observe(22, &stdout_hash.finalize());
    let stdout = result?;
    let status = status?;
    if killed.is_err() {
        return Err(IncompleteReason::Io);
    }
    Ok(ProcessOutput {
        code: status.code().ok_or(IncompleteReason::Io)?,
        stdout,
    })
}
fn git_command(cwd: Option<&Path>) -> std::process::Command {
    let mut command = std::process::Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_GRAFT_FILE", "/dev/null")
        .args([
            "--no-optional-locks",
            "--no-replace-objects",
            "--no-lazy-fetch",
            "--literal-pathspecs",
        ]);
    for value in [
        "core.hooksPath=/dev/null",
        "core.fsmonitor=false",
        "core.untrackedCache=false",
        "credential.helper=",
        "core.attributesFile=/dev/null",
        "core.excludesFile=/dev/null",
        "diff.external=",
        "diff.renames=false",
        "status.renames=false",
    ] {
        command.args(["-c", value]);
    }
    command.current_dir(cwd.unwrap_or(Path::new("/")));
    command
}
fn git(
    cwd: Option<&Path>,
    args: &[&str],
    input: &[u8],
    b: &mut Budget,
) -> Result<ProcessOutput, IncompleteReason> {
    run_command(git_command(cwd).args(args), input, b, cwd.is_some())
}
fn git_success(
    cwd: Option<&Path>,
    args: &[&str],
    input: &[u8],
    b: &mut Budget,
) -> Result<Vec<u8>, IncompleteReason> {
    let output = git(cwd, args, input, b)?;
    if output.code != 0 {
        return Err(IncompleteReason::UnsupportedGit);
    }
    Ok(output.stdout)
}

struct Registration {
    path: Vec<u8>,
    head: Vec<u8>,
    branch: Option<Vec<u8>>,
    locked: bool,
    missing: bool,
}
struct GitInputs {
    common: filesystem::Manifest,
    private: filesystem::Manifest,
    checkout: filesystem::Manifest,
    endpoints: Vec<filesystem::Endpoint>,
    boot: Vec<u8>,
    format: ObjectFormat,
    index: IndexMap,
    registrations: Vec<Registration>,
    head: Vec<u8>,
    version: Vec<u8>,
    checkout_bytes: u64,
}
fn joined(parent: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = parent.to_vec();
    if !path.is_empty() {
        path.push(b'/');
    }
    path.extend(name);
    path
}
fn ref_name(name: &[u8]) -> bool {
    name.starts_with(b"refs/heads/") && valid_ref(name)
}
fn valid_ref(name: &[u8]) -> bool {
    !name.is_empty()
        && !name.windows(2).any(|v| matches!(v, b".." | b"@{"))
        && !name
            .iter()
            .any(|c| *c <= b' ' || *c == 127 || b"~^:?*[\\".contains(c))
        && name.split(|c| *c == b'/').all(|p| {
            !p.is_empty() && !p.starts_with(b".") && !p.ends_with(b".") && !p.ends_with(b".lock")
        })
}
fn line(bytes: &[u8]) -> Result<&[u8], IncompleteReason> {
    let value = bytes
        .strip_suffix(b"\n")
        .ok_or(IncompleteReason::InvalidProtocol)?;
    if value.contains(&b'\n') || value.contains(&0) {
        return Err(IncompleteReason::InvalidProtocol);
    }
    Ok(value)
}
fn head_value(
    bytes: &[u8],
    refs: &BTreeMap<Vec<u8>, Vec<u8>>,
    format: ObjectFormat,
) -> Result<(Vec<u8>, Option<Vec<u8>>), IncompleteReason> {
    let value = line(bytes)?;
    if let Some(name) = value.strip_prefix(b"ref: ") {
        if !ref_name(name) {
            return Err(IncompleteReason::UnsupportedGit);
        }
        Ok((
            refs.get(name)
                .cloned()
                .ok_or(IncompleteReason::UnsupportedGit)?,
            Some(name.to_vec()),
        ))
    } else {
        Ok((oid(value, format)?, None))
    }
}
fn native_anchor_path(path: &Path) -> Result<(), IncompleteReason> {
    let raw = path.as_os_str().as_bytes();
    if raw.len() > MAX_PATH_BYTES
        || !raw.starts_with(b"/")
        || raw.contains(&b'\n')
        || raw.contains(&b'\r')
        || raw.last().is_none_or(u8::is_ascii_whitespace)
    {
        return Err(IncompleteReason::InvalidPath);
    }
    RawPath::from_bytes(&raw[1..]).map_err(|_| IncompleteReason::InvalidPath)?;
    Ok(())
}
fn absolute_gitdir(bytes: &[u8]) -> Result<PathBuf, IncompleteReason> {
    let raw = line(bytes)?;
    if raw.last().is_none_or(u8::is_ascii_whitespace)
        || !raw.starts_with(b"/")
        || !raw.ends_with(b"/.git")
    {
        return Err(IncompleteReason::UnsupportedGit);
    }
    RawPath::from_bytes(&raw[1..]).map_err(|_| IncompleteReason::InvalidPath)?;
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(raw)))
}
fn parse_config(bytes: &[u8], b: &mut Budget) -> Result<Option<ObjectFormat>, IncompleteReason> {
    if bytes.len() > 1024 * 1024 {
        return Err(IncompleteReason::ProcessBudget);
    }
    let output = git_success(
        None,
        &["config", "--null", "--no-includes", "--file", "-", "--list"],
        bytes,
        b,
    )?;
    let mut seen = BTreeSet::new();
    let mut format = None;
    for row in nul_records(&output)? {
        let n = row
            .iter()
            .position(|c| *c == b'\n')
            .ok_or(IncompleteReason::UnsupportedConfig)?;
        let key = &row[..n];
        let value = &row[n + 1..];
        if !seen.insert(key.to_vec()) {
            return Err(IncompleteReason::UnsupportedConfig);
        }
        let boolean = matches!(value, b"true" | b"false");
        let allowed = match key {
            b"core.repositoryformatversion" => matches!(value, b"0" | b"1"),
            b"core.bare" | b"core.autocrlf" | b"core.safecrlf" => value == b"false",
            b"core.filemode"
            | b"core.logallrefupdates"
            | b"core.ignorecase"
            | b"core.precomposeunicode" => boolean,
            b"core.eol" => value == b"lf",
            b"extensions.worktreeconfig" => value == b"true",
            b"extensions.objectformat" => {
                format = Some(match value {
                    b"sha1" => ObjectFormat::Sha1,
                    b"sha256" => ObjectFormat::Sha256,
                    _ => return Err(IncompleteReason::UnsupportedConfig),
                });
                true
            }
            b"user.name" | b"user.email" => true,
            _ => {
                (key.starts_with(b"remote.")
                    && (key.ends_with(b".url") || key.ends_with(b".fetch")))
                    || (key.starts_with(b"branch.")
                        && (key.ends_with(b".remote") || key.ends_with(b".merge")))
            }
        };
        if !allowed {
            return Err(IncompleteReason::UnsupportedConfig);
        }
    }
    Ok(format)
}
fn collect_refs(
    m: &mut filesystem::Manifest,
    parent: &[u8],
    depth: usize,
    format: ObjectFormat,
    b: &mut Budget,
    out: &mut BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<(), IncompleteReason> {
    if depth > MAX_DEPTH {
        return Err(IncompleteReason::DepthBudget);
    }
    for name in m.list(parent, b)? {
        let path = joined(parent, &name);
        if !valid_ref(&path) || path.starts_with(b"refs/replace") {
            return Err(IncompleteReason::UnsupportedGit);
        }
        if m.is_directory(&path, b)? {
            collect_refs(m, &path, depth + 1, format, b, out)?;
        } else {
            let data = m.required(&path, b)?;
            out.insert(path, oid(line(&data)?, format)?);
        }
    }
    Ok(())
}
fn packed_refs(
    bytes: &[u8],
    format: ObjectFormat,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, IncompleteReason> {
    let mut refs = BTreeMap::new();
    let mut prior = false;
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(IncompleteReason::UnsupportedGit);
    }
    if bytes.is_empty() {
        return Ok(refs);
    }
    for row in bytes[..bytes.len() - 1].split(|c| *c == b'\n') {
        if row.starts_with(b"# pack-refs with:") {
            continue;
        }
        if let Some(peeled) = row.strip_prefix(b"^") {
            if !prior {
                return Err(IncompleteReason::UnsupportedGit);
            }
            oid(peeled, format)?;
            prior = false;
            continue;
        }
        let space = row
            .iter()
            .position(|c| *c == b' ')
            .ok_or(IncompleteReason::UnsupportedGit)?;
        let name = &row[space + 1..];
        if !valid_ref(name) || !name.starts_with(b"refs/") || name.starts_with(b"refs/replace/") {
            return Err(IncompleteReason::UnsupportedGit);
        }
        if refs
            .insert(name.to_vec(), oid(&row[..space], format)?)
            .is_some()
        {
            return Err(IncompleteReason::UnsupportedGit);
        }
        prior = true;
        if refs.len() > MAX_ENTRIES as usize {
            return Err(IncompleteReason::EntryBudget);
        }
    }
    Ok(refs)
}
fn object_storage(
    m: &mut filesystem::Manifest,
    format: ObjectFormat,
    b: &mut Budget,
) -> Result<(), IncompleteReason> {
    let names = m.list(b"objects", b)?;
    for name in names {
        let path = joined(b"objects", &name);
        if name == b"info" {
            if !m.list(&path, b)?.is_empty() {
                return Err(IncompleteReason::UnsupportedGit);
            }
            continue;
        }
        if name == b"pack" {
            let names = m.list(&path, b)?;
            let set: BTreeSet<_> = names.iter().cloned().collect();
            for name in names {
                let Some(base) = name.strip_prefix(b"pack-") else {
                    return Err(IncompleteReason::UnsupportedGit);
                };
                let (id, suffix) = if let Some(id) = base.strip_suffix(b".pack") {
                    (id, b".idx".as_slice())
                } else if let Some(id) = base.strip_suffix(b".idx") {
                    (id, b".pack".as_slice())
                } else {
                    return Err(IncompleteReason::UnsupportedGit);
                };
                oid(id, format)?;
                let mut partner = b"pack-".to_vec();
                partner.extend(id);
                partner.extend(suffix);
                if !set.contains(&partner) {
                    return Err(IncompleteReason::UnsupportedGit);
                }
                m.required(&joined(&path, &name), b)?;
            }
            continue;
        }
        if name.len() != 2
            || !name
                .iter()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
        {
            return Err(IncompleteReason::UnsupportedGit);
        }
        for file in m.list(&path, b)? {
            let mut object = name.clone();
            object.extend(&file);
            oid(&object, format)?;
            m.required(&joined(&path, &file), b)?;
        }
    }
    Ok(())
}
impl GitInputs {
    fn capture(
        context: &Context,
        census: &filesystem::Census,
        b: &mut Budget,
    ) -> Result<Self, IncompleteReason> {
        let identity = context
            .allocation
            .identity
            .as_ref()
            .ok_or(IncompleteReason::ContextUnavailable)?;
        if !census.root_matches(identity.directory.device, identity.directory.inode) {
            return Err(IncompleteReason::Changed);
        }
        if census
            .entries
            .iter()
            .any(|e| e.path.as_bytes() != b".git" && forbidden_path(&e.path))
        {
            return Err(IncompleteReason::UnsupportedGit);
        }
        let mut common = filesystem::Manifest::new(&identity.common_git_dir, b)?;
        let mut private = filesystem::Manifest::new(&identity.private_git_dir, b)?;
        let mut checkout = filesystem::Manifest::new(&identity.path, b)?;
        let mut root_git = b"gitdir: ".to_vec();
        root_git.extend(identity.private_git_dir.as_os_str().as_bytes());
        root_git.push(b'\n');
        if checkout.required(b".git", b)? != root_git
            || private.required(b"commondir", b)? != b"../..\n"
        {
            return Err(IncompleteReason::UnsupportedGit);
        }
        let gitdir = absolute_gitdir(&private.required(b"gitdir", b)?)?;
        if gitdir != identity.path.join(".git") {
            return Err(IncompleteReason::UnsupportedGit);
        }
        let registration = identity
            .private_git_dir
            .strip_prefix(identity.common_git_dir.join("worktrees"))
            .map_err(|_| IncompleteReason::UnsupportedGit)?
            .as_os_str()
            .as_bytes();
        if registration.is_empty() || registration.contains(&b'/') {
            return Err(IncompleteReason::UnsupportedGit);
        }
        let marker: crate::recovery::Marker =
            serde_json::from_slice(&private.required(b"work-lease.json", b)?)
                .map_err(|_| IncompleteReason::UnsupportedGit)?;
        if marker != crate::recovery::Marker::from(&context.allocation) {
            return Err(IncompleteReason::Changed);
        }
        for name in [
            b"commondir".as_slice(),
            b"config.worktree",
            b"shallow",
            b"info/grafts",
            b"info/attributes",
            b"info/sparse-checkout",
            b"refs/replace",
            b"reftable",
        ] {
            common.absent(name, b)?;
        }
        for name in [
            b"shallow".as_slice(),
            b"info/sparse-checkout",
            b"info/attributes",
            b"packed-refs",
            b"objects",
            b"modules",
            b"reftable",
        ] {
            private.absent(name, b)?;
        }
        // Native files-backend creation leaves an empty private refs directory.
        // Admit only absence or an ordinary empty directory; the manifest retains
        // its descriptor identity and bounded names for repeated checks.
        match private.absent(b"refs", b) {
            Ok(()) => (),
            Err(IncompleteReason::UnsupportedGit) => {
                if !private.is_directory(b"refs", b)? || !private.list(b"refs", b)?.is_empty() {
                    return Err(IncompleteReason::UnsupportedGit);
                }
            }
            Err(reason) => return Err(reason),
        }
        common.optional(b"info/exclude", b)?;
        let config = common.required(b"config", b)?;
        let local = private.optional(b"config.worktree", b)?;
        let format = parse_config(&config, b)?.unwrap_or(ObjectFormat::Sha1);
        if let Some(local) = local {
            if parse_config(&local, b)?.is_some_and(|f| f != format) {
                return Err(IncompleteReason::UnsupportedConfig);
            }
        }
        let mut refs = match common.optional(b"packed-refs", b)? {
            Some(data) => packed_refs(&data, format)?,
            None => BTreeMap::new(),
        };
        collect_refs(&mut common, b"refs", 0, format, b, &mut refs)?;
        object_storage(&mut common, format, b)?;
        let index = parse_index(&private.required(b"index", b)?, format)?;
        let (head, _) = head_value(&private.required(b"HEAD", b)?, &refs, format)?;
        let (main_head, main_branch) = head_value(&common.required(b"HEAD", b)?, &refs, format)?;
        let main_path = identity
            .common_git_dir
            .parent()
            .ok_or(IncompleteReason::UnsupportedGit)?;
        // Conventional nonbare main .git only; no guessed bare/common path.
        if identity.common_git_dir.file_name() != Some(std::ffi::OsStr::new(".git")) {
            return Err(IncompleteReason::UnsupportedGit);
        }
        let mut registrations = vec![Registration {
            path: main_path.as_os_str().as_bytes().to_vec(),
            head: main_head,
            branch: main_branch,
            locked: false,
            missing: false,
        }];
        let mut endpoints = Vec::new();
        let mut target = 0;
        let mut paths = BTreeSet::new();
        paths.insert(main_path.as_os_str().as_bytes().to_vec());
        for name in common.list(b"worktrees", b)? {
            let prefix = joined(b"worktrees", &name);
            if !common.is_directory(&prefix, b)? {
                return Err(IncompleteReason::UnsupportedGit);
            }
            if common.required(&joined(&prefix, b"commondir"), b)? != b"../..\n" {
                return Err(IncompleteReason::UnsupportedGit);
            }
            let endpoint = absolute_gitdir(&common.required(&joined(&prefix, b"gitdir"), b)?)?;
            let path = endpoint
                .parent()
                .ok_or(IncompleteReason::UnsupportedGit)?
                .as_os_str()
                .as_bytes()
                .to_vec();
            if !paths.insert(path.clone()) {
                return Err(IncompleteReason::UnsupportedGit);
            }
            let (oid, branch) = head_value(
                &common.required(&joined(&prefix, b"HEAD"), b)?,
                &refs,
                format,
            )?;
            let locked = common.optional(&joined(&prefix, b"locked"), b)?.is_some();
            let mut missing = false;
            if !locked {
                let endpoint = filesystem::Endpoint::open(&endpoint, b)?;
                missing = endpoint.missing();
                if missing {
                    common.metadata(&joined(&prefix, b"index"), b)?;
                }
                endpoints.push(endpoint);
            }
            if name == registration {
                if path != identity.path.as_os_str().as_bytes() || oid != head {
                    return Err(IncompleteReason::UnsupportedGit);
                }
                target += 1;
            }
            registrations.push(Registration {
                path,
                head: oid,
                branch,
                locked,
                missing,
            });
        }
        if target != 1 {
            return Err(IncompleteReason::UnsupportedGit);
        }
        let boot = filesystem::boot_id(b)?;
        if boot.strip_suffix(b"\n") != Some(identity.boot_id.as_bytes()) {
            return Err(IncompleteReason::Changed);
        }
        let version = git_success(None, &["--version"], b"", b)?;
        if let Ok(value) = line(&version) {
            if value.len() <= 96
                && value.starts_with(b"git version ")
                && value
                    .iter()
                    .all(|c| c.is_ascii_alphanumeric() || b" .-()".contains(c))
            {
                b.git_version = std::str::from_utf8(value).ok().map(str::to_owned);
            }
        }
        // Only the source-qualified version is admitted, never inferred from a
        // broadly compatible major/minor. Isolated CI must provide this Git.
        if version != b"git version 2.55.0\n" {
            return Err(IncompleteReason::UnsupportedGit);
        }
        let result = Self {
            common,
            private,
            checkout,
            endpoints,
            boot,
            format,
            index,
            registrations,
            head,
            version,
            checkout_bytes: census
                .entries
                .iter()
                .filter(|e| !e.directory())
                .map(|e| e.length())
                .sum(),
        };
        result.recheck(b)?;
        Ok(result)
    }
    fn native_read_reservation(&self) -> Result<u64, IncompleteReason> {
        let size = self
            .common
            .read_size()
            .checked_add(self.private.read_size())
            .and_then(|n| n.checked_add(self.checkout.read_size()))
            .and_then(|n| n.checked_add(self.checkout_bytes))
            .ok_or(IncompleteReason::ReadBudget)?;
        size.checked_mul(self.registrations.len() as u64 + 1)
            .ok_or(IncompleteReason::ReadBudget)
    }
    fn fingerprint(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for bytes in [
            self.common.fingerprint(),
            self.private.fingerprint(),
            self.checkout.fingerprint(),
        ] {
            frame(&mut out, 1, &bytes);
        }
        for endpoint in &self.endpoints {
            frame(&mut out, 2, &endpoint.fingerprint());
        }
        frame(&mut out, 3, &self.boot);
        frame(&mut out, 4, &self.version);
        Sha256::digest(out).to_vec()
    }
    fn recheck(&self, b: &mut Budget) -> Result<(), IncompleteReason> {
        self.common.recheck(b)?;
        self.private.recheck(b)?;
        self.checkout.recheck(b)?;
        for e in &self.endpoints {
            e.recheck(b)?;
        }
        Ok(())
    }
}

fn check_registrations(
    bytes: &[u8],
    expected: &[Registration],
    format: ObjectFormat,
) -> Result<(), IncompleteReason> {
    let rows = nul_records(bytes)?;
    let mut at = 0;
    let mut seen = BTreeSet::new();
    while at < rows.len() {
        let path = rows[at]
            .strip_prefix(b"worktree ")
            .ok_or(IncompleteReason::InvalidProtocol)?;
        at += 1;
        let registration = expected
            .iter()
            .find(|r| r.path == path)
            .ok_or(IncompleteReason::InvalidProtocol)?;
        if !seen.insert(path.to_vec()) {
            return Err(IncompleteReason::InvalidProtocol);
        }
        let mut head = None;
        let mut branch = None;
        let mut detached = false;
        let mut locked = false;
        let mut prunable = false;
        while at < rows.len() && !rows[at].is_empty() {
            let row = rows[at];
            at += 1;
            if let Some(value) = row.strip_prefix(b"HEAD ") {
                if head.replace(oid(value, format)?).is_some() {
                    return Err(IncompleteReason::InvalidProtocol);
                }
            } else if let Some(value) = row.strip_prefix(b"branch ") {
                if branch.replace(value.to_vec()).is_some() || !ref_name(value) {
                    return Err(IncompleteReason::InvalidProtocol);
                }
            } else if row == b"detached" && !detached {
                detached = true;
            } else if (row == b"locked" || row.starts_with(b"locked ")) && !locked {
                locked = true;
            } else if row.starts_with(b"prunable ") && !prunable {
                prunable = true;
            } else {
                return Err(IncompleteReason::InvalidProtocol);
            }
        }
        if at == rows.len()
            || head.as_ref() != Some(&registration.head)
            || branch != registration.branch
            || detached != registration.branch.is_none()
            || locked != registration.locked
            || prunable != registration.missing
        {
            return Err(IncompleteReason::InvalidProtocol);
        }
        at += 1;
    }
    if seen.len() != expected.len() {
        return Err(IncompleteReason::InvalidProtocol);
    }
    Ok(())
}
fn check_status(
    bytes: &[u8],
    index: &IndexMap,
    tree: &IndexMap,
    format: ObjectFormat,
) -> Result<(), IncompleteReason> {
    let mut seen = BTreeSet::new();
    for row in nul_records(bytes)? {
        let path = if row.starts_with(b"? ") || row.starts_with(b"! ") {
            &row[2..]
        } else {
            let fields: Vec<_> = row.splitn(9, |c| *c == b' ').collect();
            if fields.len() != 9
                || fields[0] != b"1"
                || fields[1].len() != 2
                || !fields[1].iter().all(|c| b".MADT".contains(c))
                || fields[2] != b"N..."
            {
                return Err(IncompleteReason::InvalidProtocol);
            }
            for value in &fields[3..6] {
                if *value != b"000000" {
                    regular_mode(value)?;
                }
            }
            let path = RawPath::from_bytes(fields[8]).map_err(|_| IncompleteReason::InvalidPath)?;
            for (object, map) in [(fields[6], tree), (fields[7], index)] {
                if let Some(entry) = map.get(&path) {
                    if oid(object, format)? != entry.oid {
                        return Err(IncompleteReason::InvalidProtocol);
                    }
                } else if object.len() != format.width() * 2 || object.iter().any(|c| *c != b'0') {
                    return Err(IncompleteReason::InvalidProtocol);
                }
            }
            fields[8]
        };
        // Collapsed ignored directories have one trailing slash; it is a
        // protocol annotation, never a canonical raw-path identity.
        let path = path.strip_suffix(b"/").unwrap_or(path);
        let path = RawPath::from_bytes(path).map_err(|_| IncompleteReason::InvalidPath)?;
        if !seen.insert(path) {
            return Err(IncompleteReason::InvalidProtocol);
        }
    }
    Ok(())
}
struct GitProof {
    index: IndexMap,
    tree: IndexMap,
    ignored: BTreeMap<RawPath, bool>,
    blobs: BlobMap,
    canonical: Vec<u8>,
}
impl GitProof {
    fn observe(
        context: &Context,
        census: &filesystem::Census,
        inputs: &GitInputs,
        b: &mut Budget,
    ) -> Result<Self, IncompleteReason> {
        let path = &context
            .allocation
            .identity
            .as_ref()
            .ok_or(IncompleteReason::ContextUnavailable)?
            .path;
        let mut canonical = Vec::new();
        let mut command = |args: &[&str],
                           input: &[u8],
                           ignore_exit: bool,
                           b: &mut Budget|
         -> Result<Vec<u8>, IncompleteReason> {
            // Reserve the entire admitted native input envelope per command,
            // including repeated ref stores in worktree listing. This is a
            // conservative charge, NOT measurement of Git's internal reads.
            let charge = inputs.native_read_reservation()?;
            b.reserve(charge)?;
            b.counters.native_input_reserved_bytes += charge;
            let result = git(Some(path), args, input, b)?;
            if result.code != 0 && !(ignore_exit && result.code == 1) {
                return Err(IncompleteReason::UnsupportedGit);
            }
            for arg in args {
                frame(&mut canonical, 1, arg.as_bytes());
            }
            frame(&mut canonical, 2, &Sha256::digest(input));
            frame(&mut canonical, 3, &Sha256::digest(&result.stdout));
            Ok(result.stdout)
        };
        let format = command(&["rev-parse", "--show-object-format"], b"", false, b)?;
        if format
            != match inputs.format {
                ObjectFormat::Sha1 => b"sha1\n".as_slice(),
                ObjectFormat::Sha256 => b"sha256\n",
            }
        {
            return Err(IncompleteReason::InvalidProtocol);
        }
        let head = command(&["rev-parse", "--verify", "HEAD"], b"", false, b)?;
        if oid(line(&head)?, inputs.format)? != inputs.head {
            return Err(IncompleteReason::Changed);
        }
        check_registrations(
            &command(&["worktree", "list", "--porcelain", "-z"], b"", false, b)?,
            &inputs.registrations,
            inputs.format,
        )?;
        let mut index = parse_stage(
            &command(&["ls-files", "--stage", "-z"], b"", false, b)?,
            inputs.format,
        )?;
        apply_flags(
            &command(&["ls-files", "-v", "-z"], b"", false, b)?,
            &mut index,
        )?;
        if index != inputs.index {
            return Err(IncompleteReason::InvalidProtocol);
        }
        let head_str =
            std::str::from_utf8(&inputs.head).map_err(|_| IncompleteReason::InvalidProtocol)?;
        let tree = parse_tree(
            &command(
                &["ls-tree", "-r", "-z", "--full-tree", head_str],
                b"",
                false,
                b,
            )?,
            inputs.format,
        )?;
        check_status(
            &command(
                &[
                    "status",
                    "--porcelain=v2",
                    "-z",
                    "--untracked-files=all",
                    "--ignored=matching",
                    "--no-renames",
                    "--ignore-submodules=none",
                ],
                b"",
                false,
                b,
            )?,
            &index,
            &tree,
            inputs.format,
        )?;
        let paths: Vec<_> = census
            .entries
            .iter()
            .filter(|e| e.path.as_bytes() != b".git" && !index.contains_key(&e.path))
            .map(|e| e.path.clone())
            .collect();
        let mut ignored = BTreeMap::new();
        let mut offset = 0;
        while offset < paths.len() {
            let mut input = Vec::new();
            let start = offset;
            while offset < paths.len()
                && offset - start < 256
                && input.len() + paths[offset].as_bytes().len() + 3 <= 256 * 1024
            {
                // check-ignore rejects literal pathspec magic. Shield leading
                // colons with './'; --no-index leaves no index to glob-select,
                // and ignore matching treats each pathname as the lookup value.
                input.extend_from_slice(b"./");
                input.extend(paths[offset].as_bytes());
                input.push(0);
                offset += 1;
            }
            let output = command(
                &[
                    // Override only this fixed invocation; other commands retain
                    // the runner's --literal-pathspecs. env_clear forbids inherited
                    // pathspec settings, and every stdin path is prefixed above.
                    "--no-literal-pathspecs",
                    "check-ignore",
                    "--no-index",
                    "--stdin",
                    "-z",
                    "--verbose",
                    "--non-matching",
                ],
                &input,
                true,
                b,
            )?;
            ignored.extend(parse_ignored(&output, &paths[start..offset])?);
        }
        let ids: BTreeSet<_> = index.values().map(|entry| entry.oid.clone()).collect();
        let mut input = Vec::new();
        for id in &ids {
            input.extend(id);
            input.push(b'\n');
        }
        let mut expected = Vec::new();
        if !ids.is_empty() {
            let output = command(&["cat-file", "--batch-check"], &input, false, b)?;
            let body = output
                .strip_suffix(b"\n")
                .ok_or(IncompleteReason::InvalidProtocol)?;
            let rows: Vec<_> = body.split(|c| *c == b'\n').collect();
            if rows.len() != ids.len() {
                return Err(IncompleteReason::InvalidObject);
            }
            for (row, id) in rows.into_iter().zip(&ids) {
                let fields: Vec<_> = row.split(|c| *c == b' ').collect();
                if fields.len() != 3 || fields[0] != id.as_slice() || fields[1] != b"blob" {
                    return Err(IncompleteReason::InvalidObject);
                }
                let length = decimal(fields[2])?;
                b.file_length(length)?;
                expected.push((id.clone(), length));
            }
        }
        let mut blobs = BTreeMap::new();
        let mut offset = 0;
        while offset < expected.len() {
            let start = offset;
            let mut total = 0;
            let mut input = Vec::new();
            while offset < expected.len()
                && offset - start < 128
                && total + expected[offset].1 <= MAX_FILE_BYTES
            {
                total += expected[offset].1;
                input.extend(&expected[offset].0);
                input.push(b'\n');
                offset += 1;
            }
            let output = command(&["cat-file", "--batch"], &input, false, b)?;
            blobs.extend(parse_blobs(
                &output,
                &expected[start..offset],
                inputs.format,
            )?);
        }
        Ok(Self {
            index,
            tree,
            ignored,
            blobs,
            canonical,
        })
    }
}
// The only production constructor is classify(), after actual full Git proof.
// Crate-private accessors allow disposal comparison, never evidence creation.
pub(crate) struct PolicyEvidence {
    entries: Vec<PolicyEntry>,
}
pub(crate) struct PolicyEntry {
    path: RawPath,
    directory: bool,
    ignored: bool,
    tracked: bool,
    mode: u32,
    length: u64,
    sha256: Option<[u8; 32]>,
}
impl PolicyEvidence {
    pub(crate) fn entries(&self) -> &[PolicyEntry] {
        &self.entries
    }
}
impl PolicyEntry {
    pub(crate) fn path(&self) -> &RawPath {
        &self.path
    }
    pub(crate) fn directory(&self) -> bool {
        self.directory
    }
    pub(crate) fn ignored(&self) -> bool {
        self.ignored
    }
    pub(crate) fn tracked(&self) -> bool {
        self.tracked
    }
    pub(crate) fn mode(&self) -> u32 {
        self.mode
    }
    pub(crate) fn length(&self) -> u64 {
        self.length
    }
    pub(crate) fn sha256(&self) -> Option<[u8; 32]> {
        self.sha256
    }
}
fn classify(
    census: &filesystem::Census,
    proof: &GitProof,
    policies: &ValidatedPolicies,
) -> (Vec<ObservedEntry>, Vec<Finding>) {
    let policy_evidence = PolicyEvidence {
        entries: census
            .entries
            .iter()
            .filter(|e| e.path.as_bytes() != b".git")
            .map(|e| PolicyEntry {
                path: e.path.clone(),
                directory: e.directory(),
                ignored: proof.ignored.get(&e.path).copied().unwrap_or(false),
                tracked: proof.index.contains_key(&e.path) || proof.tree.contains_key(&e.path),
                mode: e.mode() & 0o7777,
                length: e.length(),
                sha256: e.content_sha256,
            })
            .collect(),
    };
    let (matched, mismatches) = crate::disposal::classify(policies, &policy_evidence);
    let mut entries = Vec::new();
    let mut findings: Vec<_> = mismatches
        .into_iter()
        .map(|path| Finding {
            path,
            kind: FindingKind::PolicyMismatch,
        })
        .collect();
    for e in &census.entries {
        entries.push(ObservedEntry {
            path: e.path.clone(),
            mode: e.mode(),
            length: e.length(),
            content: e.content_sha256,
            policy: matched.get(&e.path).cloned(),
            tracked: proof.index.contains_key(&e.path),
            assume_unchanged: proof.index.get(&e.path).is_some_and(|i| i.assume_unchanged),
            skip_worktree: proof.index.get(&e.path).is_some_and(|i| i.skip_worktree),
        });
        if e.path.as_bytes() == b".git" {
            continue;
        }
        if let Some(index) = proof.index.get(&e.path) {
            let blob = proof.blobs.get(&index.oid);
            if e.directory()
                || blob.is_none_or(|(length, hash)| {
                    *length != e.length() || Some(*hash) != e.content_sha256
                })
                || (index.mode == 0o100755) != (e.mode() & 0o100 != 0)
            {
                findings.push(Finding {
                    path: e.path.clone(),
                    kind: FindingKind::TrackedContent,
                });
            }
        } else if !matched.contains_key(&e.path) {
            // Tracked-parent directories are structural, not untracked payload.
            let tracked_parent = e.directory()
                && proof
                    .index
                    .keys()
                    .any(|p| p.as_bytes().starts_with(&joined(e.path.as_bytes(), b"")));
            if !tracked_parent {
                findings.push(Finding {
                    path: e.path.clone(),
                    kind: if proof.ignored.get(&e.path) == Some(&true) {
                        FindingKind::IgnoredUnclassified
                    } else {
                        FindingKind::Untracked
                    },
                });
            }
        }
    }
    let paths: BTreeSet<_> = proof
        .index
        .keys()
        .chain(proof.tree.keys())
        .cloned()
        .collect();
    for path in paths {
        let staged = match (proof.index.get(&path), proof.tree.get(&path)) {
            (Some(a), Some(b)) => a.mode != b.mode || a.oid != b.oid,
            (None, None) => false,
            _ => true,
        };
        if staged {
            findings.push(Finding {
                path: path.clone(),
                kind: FindingKind::StagedChange,
            });
        }
        if proof.index.contains_key(&path) && !census.entries.iter().any(|e| e.path == path) {
            findings.push(Finding {
                path,
                kind: FindingKind::TrackedContent,
            });
        }
    }
    findings.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then((a.kind as u8).cmp(&(b.kind as u8)))
    });
    (entries, findings)
}

const MAX_ENTRIES: u64 = 4096;
const MAX_DEPTH: usize = 64;
const MAX_PATH_BYTES: usize = 4096;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CHARGED_BYTES: u64 = 128 * 1024 * 1024;
const MAX_OUTPUT_BYTES: u64 = 2 * 1024 * 1024;
const TERMINAL_RESERVE: u64 = 16 * 1024;
const DIRECTORY_BUFFER_BYTES: usize = 8192;

// Private operation budget. No caller-supplied path/census/membership bypass.
struct Budget {
    start: Instant,
    counters: Counters,
    stopped: Option<IncompleteReason>,
    evidence: Sha256,
    git_version: Option<String>,
    #[cfg(test)]
    test_elapsed: Option<Duration>,
    #[cfg(test)]
    process_events: Vec<&'static str>,
}
impl Budget {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            counters: Counters::default(),
            stopped: None,
            evidence: Sha256::new(),
            git_version: None,
            #[cfg(test)]
            test_elapsed: None,
            #[cfg(test)]
            process_events: vec![],
        }
    }
    fn observe(&mut self, tag: u8, bytes: &[u8]) {
        self.evidence.update([tag]);
        self.evidence.update((bytes.len() as u64).to_be_bytes());
        self.evidence.update(bytes);
    }
    fn fail<T>(&mut self, reason: IncompleteReason) -> Result<T, IncompleteReason> {
        self.stopped = Some(reason);
        Err(reason)
    }
    fn elapsed(&self) -> Duration {
        let elapsed = self.start.elapsed();
        #[cfg(test)]
        let elapsed = self.test_elapsed.unwrap_or(elapsed);
        elapsed
    }
    fn check(&mut self) -> Result<(), IncompleteReason> {
        if let Some(reason) = self.stopped {
            return Err(reason);
        }
        if self.elapsed() >= Duration::from_secs(30) {
            return self.fail(IncompleteReason::Deadline);
        }
        Ok(())
    }
    // Accounting only: the single-attempt runner launches after reservation.
    fn reserve_process(
        &mut self,
        stdin: u64,
        argv: u64,
    ) -> Result<ProcessReservation, IncompleteReason> {
        self.check()?;
        if self.counters.reserved_child_slots >= 96 || stdin > 1024 * 1024 || argv > 32 * 1024 {
            return self.fail(IncompleteReason::ProcessBudget);
        }
        let Some(input) = self
            .counters
            .reserved_process_input_bytes
            .checked_add(stdin)
            .and_then(|n| n.checked_add(argv))
        else {
            return self.fail(IncompleteReason::ProcessBudget);
        };
        if input > 8 * 1024 * 1024 {
            return self.fail(IncompleteReason::ProcessBudget);
        }
        let Some(remaining) = Duration::from_secs(30).checked_sub(self.elapsed()) else {
            return self.fail(IncompleteReason::Deadline);
        };
        if remaining.is_zero() {
            return self.fail(IncompleteReason::Deadline);
        }
        self.counters.reserved_child_slots += 1;
        self.counters.reserved_process_input_bytes = input;
        Ok(ProcessReservation {
            maximum_duration: remaining.min(Duration::from_secs(2)),
        })
    }
    fn entry(&mut self) -> Result<(), IncompleteReason> {
        self.check()?;
        if self.counters.entries >= MAX_ENTRIES {
            return self.fail(IncompleteReason::EntryBudget);
        }
        self.counters.entries += 1;
        Ok(())
    }
    fn file_length(&mut self, length: u64) -> Result<(), IncompleteReason> {
        self.check()?;
        if length > MAX_FILE_BYTES {
            return self.fail(IncompleteReason::FileBudget);
        }
        Ok(())
    }
    fn output(&mut self, length: u64) -> Result<(), IncompleteReason> {
        self.check()?;
        let Some(n) = self.counters.retained_output_bytes.checked_add(length) else {
            return self.fail(IncompleteReason::OutputBudget);
        };
        if n > MAX_OUTPUT_BYTES - TERMINAL_RESERVE {
            return self.fail(IncompleteReason::OutputBudget);
        }
        self.counters.retained_output_bytes = n;
        Ok(())
    }
    fn reserve(&mut self, bytes: u64) -> Result<(), IncompleteReason> {
        self.check()?;
        let Some(n) = self.counters.charged_read_bytes.checked_add(bytes) else {
            return self.fail(IncompleteReason::ReadBudget);
        };
        if n > MAX_CHARGED_BYTES {
            return self.fail(IncompleteReason::ReadBudget);
        }
        self.counters.charged_read_bytes = n;
        Ok(())
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
    fn finish_file_read(
        &mut self,
        ticket: ReadReservation,
        actual: usize,
    ) -> Result<(), IncompleteReason> {
        if actual > ticket.0 {
            return self.fail(IncompleteReason::Io);
        }
        self.counters.uncertain_file_reservation_bytes -= ticket.0 as u64;
        self.counters.charged_read_bytes -= (ticket.0 - actual) as u64;
        self.counters.observed_file_bytes += actual as u64;
        self.check()
    }
}
struct ReadReservation(usize);
struct ProcessReservation {
    maximum_duration: Duration,
}

fn read_chunk(
    reader: &mut impl std::io::Read,
    buffer: &mut [u8],
    b: &mut Budget,
) -> Result<usize, IncompleteReason> {
    let ticket = b.reserve_file_read(buffer.len())?;
    match reader.read(buffer) {
        Ok(n) => {
            // Stream bytes without chunk framing: syscall partitioning is not
            // part of canonical identity. Callers bind file identity/length.
            b.evidence.update(&buffer[..n]);
            b.finish_file_read(ticket, n)?;
            Ok(n)
        }
        // Retain the full reservation when consumption is uncertain, but do
        // not falsely add it to exact observed bytes. Never retry this read.
        Err(_) => b.fail(IncompleteReason::Io),
    }
}

// The closure is not called when reservation fails, including EOF/error attempts.
// Rustix may trim for alignment: charge the full supplied array, not trimmed size.
fn directory_next<T>(
    b: &mut Budget,
    empty: bool,
    next: impl FnOnce() -> T,
) -> Result<T, IncompleteReason> {
    b.check()?;
    if empty {
        b.directory_refill()?;
    }
    Ok(next())
}

mod filesystem {
    use super::*;
    use crate::disposal::RawPath;
    use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, RawDir, ResolveFlags};
    use std::{
        collections::BTreeSet,
        ffi::CString,
        fs::File,
        mem::MaybeUninit,
        os::{
            fd::{AsRawFd, OwnedFd},
            unix::ffi::OsStrExt,
        },
        path::Path,
    };

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(super) struct Identity {
        device: u64,
        pub(super) inode: u64,
        pub(super) mode: u32,
        links: u64,
        uid: u32,
        gid: u32,
        size: i64,
        mtime: i64,
        mtime_ns: u64,
        ctime: i64,
        ctime_ns: u64,
    }
    impl Identity {
        // st_nlink has architecture-dependent width; retain the portable u64 conversion.
        #[allow(clippy::useless_conversion)]
        fn from_stat(s: fs::Stat) -> Self {
            Self {
                device: s.st_dev,
                inode: s.st_ino,
                mode: s.st_mode,
                links: u64::from(s.st_nlink),
                uid: s.st_uid,
                gid: s.st_gid,
                size: s.st_size,
                mtime: s.st_mtime,
                mtime_ns: s.st_mtime_nsec,
                ctime: s.st_ctime,
                ctime_ns: s.st_ctime_nsec,
            }
        }
        fn kind(&self) -> FileType {
            FileType::from_raw_mode(self.mode)
        }
        pub(super) fn encode(&self, out: &mut Vec<u8>) {
            for n in [
                self.device,
                self.inode,
                u64::from(self.mode),
                self.links,
                u64::from(self.uid),
                u64::from(self.gid),
                self.size as u64,
                self.mtime as u64,
                self.mtime_ns,
                self.ctime as u64,
                self.ctime_ns,
            ] {
                frame(out, 1, &n.to_be_bytes());
            }
        }
    }
    fn stat(fd: &OwnedFd, b: &mut Budget) -> Result<Identity, IncompleteReason> {
        b.check()?;
        fs::fstat(fd).map(Identity::from_stat).map_err(os_error)
    }
    fn named(parent: &OwnedFd, name: &[u8], b: &mut Budget) -> Result<Identity, IncompleteReason> {
        b.check()?;
        fs::statat(parent, cstring(name)?.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map(Identity::from_stat)
            .map_err(os_error)
    }
    fn equal(a: &Identity, b: &Identity) -> Result<(), IncompleteReason> {
        if a == b {
            Ok(())
        } else {
            Err(IncompleteReason::Changed)
        }
    }
    // Traversal bindings outside the census are not content observations.
    // Child/FD churn may change size/nlink/timestamps without rebinding the
    // route. Preserve directory type, access/owner and actual object identity.
    // Never use this comparison for held census contents (including root).
    fn binding_equal(a: &Identity, b: &Identity) -> Result<(), IncompleteReason> {
        if a.device == b.device
            && a.inode == b.inode
            && a.kind() == FileType::Directory
            && b.kind() == FileType::Directory
            && a.mode == b.mode
            && a.uid == b.uid
            && a.gid == b.gid
        {
            Ok(())
        } else {
            Err(IncompleteReason::Changed)
        }
    }
    pub(super) fn os_error(e: rustix::io::Errno) -> IncompleteReason {
        match e {
            rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL | rustix::io::Errno::LOOP => {
                IncompleteReason::UnsupportedResolution
            }
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
        if below {
            flags | ResolveFlags::NO_XDEV
        } else {
            flags
        }
    }
    fn open_path(
        parent: &OwnedFd,
        name: &[u8],
        directory: bool,
        below: bool,
        b: &mut Budget,
    ) -> Result<OwnedFd, IncompleteReason> {
        b.check()?;
        let mut flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        if directory {
            flags |= OFlags::DIRECTORY;
        }
        fs::openat2(
            parent,
            cstring(name)?.as_c_str(),
            flags,
            Mode::empty(),
            resolution(below),
        )
        .map_err(os_error)
    }
    struct Link {
        fd: OwnedFd,
        name: Vec<u8>,
        identity: Identity,
    }
    struct Anchor {
        route: Vec<Link>,
    }
    impl Anchor {
        fn open<H: Boundary>(
            path: &Path,
            b: &mut Budget,
            hooks: &mut H,
        ) -> Result<Self, IncompleteReason> {
            let raw = path.as_os_str().as_bytes();
            if raw.first() != Some(&b'/') || raw.len() > MAX_PATH_BYTES {
                return Err(IncompleteReason::InvalidPath);
            }
            let parts: Vec<&[u8]> = if raw == b"/" {
                vec![]
            } else {
                raw[1..].split(|c| *c == b'/').collect()
            };
            if parts.len() > MAX_DEPTH
                || parts
                    .iter()
                    .any(|p| p.is_empty() || *p == b"." || *p == b".." || p.contains(&0))
            {
                return Err(IncompleteReason::InvalidPath);
            }
            b.check()?;
            let fd = fs::openat(
                fs::CWD,
                c"/",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(os_error)?;
            let identity = stat(&fd, b)?;
            let mut anchor = Self {
                route: vec![Link {
                    fd,
                    name: vec![],
                    identity,
                }],
            };
            for part in parts {
                anchor.descend(part, false, b, hooks)?;
            }
            Ok(anchor)
        }
        fn last(&self) -> &Link {
            self.route.last().expect("anchor always has root")
        }
        fn descend<H: Boundary>(
            &mut self,
            name: &[u8],
            below: bool,
            b: &mut Budget,
            _hooks: &mut H,
        ) -> Result<(), IncompleteReason> {
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
            self.route.push(Link {
                fd,
                name: name.to_vec(),
                identity,
            });
            Ok(())
        }
        fn recheck(&self, b: &mut Budget) -> Result<(), IncompleteReason> {
            for (i, link) in self.route.iter().enumerate() {
                binding_equal(&link.identity, &stat(&link.fd, b)?)?;
                if i > 0 {
                    binding_equal(
                        &link.identity,
                        &named(&self.route[i - 1].fd, &link.name, b)?,
                    )?;
                }
            }
            Ok(())
        }
    }
    struct TrustedProc {
        anchor: Anchor,
        proc_index: usize,
    }
    impl TrustedProc {
        fn open<H: Boundary>(b: &mut Budget, hooks: &mut H) -> Result<Self, IncompleteReason> {
            let mut anchor = Anchor::open(Path::new("/proc"), b, hooks)?;
            let proc_index = anchor.route.len() - 1;
            b.check()?;
            let fs = fs::fstatfs(&anchor.last().fd).map_err(os_error)?;
            if fs.f_type != fs::PROC_SUPER_MAGIC
                || anchor.last().identity.uid != 0
                || anchor.last().identity.mode & 0o022 != 0
            {
                return Err(IncompleteReason::UntrustedProc);
            }
            let pid = rustix::process::getpid().as_raw_pid().to_string();
            for part in [pid.as_bytes(), b"fd".as_slice()] {
                anchor.descend(part, true, b, hooks)?;
                let identity = &anchor.last().identity;
                if identity.uid != rustix::process::geteuid().as_raw() || identity.mode & 0o022 != 0
                {
                    return Err(IncompleteReason::UntrustedProc);
                }
            }
            let result = Self { anchor, proc_index };
            result.recheck(b)?;
            Ok(result)
        }
        fn recheck(&self, b: &mut Budget) -> Result<(), IncompleteReason> {
            self.anchor.recheck(b)?;
            b.check()?;
            if fs::fstatfs(&self.anchor.route[self.proc_index].fd)
                .map_err(os_error)?
                .f_type
                != fs::PROC_SUPER_MAGIC
            {
                return Err(IncompleteReason::UntrustedProc);
            }
            Ok(())
        }
        fn reopen<H: Boundary>(
            &self,
            retained: &OwnedFd,
            expected: &Identity,
            path: &[u8],
            b: &mut Budget,
            hooks: &mut H,
        ) -> Result<OwnedFd, IncompleteReason> {
            regular(expected)?;
            equal(expected, &stat(retained, b)?)?;
            self.recheck(b)?;
            let numeric = retained.as_raw_fd().to_string();
            hooks.event(Event::BeforeDataOpen, path, Some(expected))?;
            b.check()?;
            // The ONLY deliberate magic-link follow: a numeric fd in trusted
            // /proc/<our pid>/fd, with the original OwnedFd retained throughout.
            // Never reopen the original pathname; NOFOLLOW would defeat this.
            let fd = fs::openat(
                &self.anchor.last().fd,
                numeric.as_str(),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(os_error)?;
            let reopened = stat(&fd, b)?;
            hooks.event(Event::DataOpened, path, Some(&reopened))?;
            equal(expected, &reopened)?;
            Ok(fd)
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
    pub(super) enum Event {
        BeforeChildOpen,
        BeforeDataOpen,
        DataOpened,
        BeforeFileRead,
        BeforeReenumerate,
        BeforeAnchorRecheck,
    }
    pub(super) trait Boundary {
        fn event(
            &mut self,
            _e: Event,
            _path: &[u8],
            _i: Option<&Identity>,
        ) -> Result<(), IncompleteReason> {
            Ok(())
        }
        fn child_identity(&mut self, identity: Identity) -> Identity {
            identity
        }
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
        pub(super) identity: Identity,
        pub(super) content_sha256: Option<[u8; 32]>,
    }
    impl Entry {
        pub(super) fn directory(&self) -> bool {
            self.identity.kind() == FileType::Directory
        }
        pub(super) fn length(&self) -> u64 {
            self.identity.size as u64
        }
        pub(super) fn mode(&self) -> u32 {
            self.identity.mode
        }
    }
    struct Held {
        fd: OwnedFd,
        parent: Option<usize>,
        name: Vec<u8>,
        path: Vec<u8>,
        identity: Identity,
        names: Option<Vec<Vec<u8>>>,
    }
    /// Filesystem-only seal. No membership/admin classification, no Deserialize,
    /// and no public conversion into complete inspection or persisted receipt.
    pub(super) struct Census {
        pub(super) entries: Vec<Entry>,
        _held: Vec<Held>,
        _anchor: Anchor,
        _proc: TrustedProc,
    }
    impl Census {
        pub(super) fn root_matches(&self, device: u64, inode: u64) -> bool {
            self._held[0].identity.device == device && self._held[0].identity.inode == inode
        }
        pub(super) fn fingerprint(&self) -> Vec<u8> {
            let mut out = Vec::new();
            self._held[0].identity.encode(&mut out);
            for e in &self.entries {
                frame(&mut out, 2, e.path.as_bytes());
                e.identity.encode(&mut out);
                frame(
                    &mut out,
                    3,
                    e.content_sha256.as_ref().map_or(&[][..], |v| v.as_slice()),
                );
            }
            Sha256::digest(out).to_vec()
        }
        pub(super) fn recheck(&self, b: &mut Budget) -> Result<(), IncompleteReason> {
            check_nodes(&self._held, b)?;
            self._anchor.recheck(b)?;
            self._proc.recheck(b)
        }
    }
    fn check_nodes(nodes: &[Held], b: &mut Budget) -> Result<(), IncompleteReason> {
        for held in nodes {
            equal(&held.identity, &stat(&held.fd, b)?)?;
            if let Some(parent) = held.parent {
                equal(&held.identity, &named(&nodes[parent].fd, &held.name, b)?)?;
            }
            if let Some(names) = &held.names {
                if &enumerate(held, b, false)? != names {
                    return Err(IncompleteReason::Changed);
                }
            }
        }
        Ok(())
    }
    /// Selective native-input manifest. Only explicitly requested paths or
    /// explicitly enumerated object/ref subtrees are read. Registration sibling
    /// directories are never recursively enumerated.
    pub(super) struct Manifest {
        anchor: Anchor,
        proc: TrustedProc,
        held: Vec<Held>,
        paths: BTreeMap<Vec<u8>, usize>,
        absent: BTreeMap<Vec<u8>, (usize, Vec<u8>)>,
        data: BTreeMap<Vec<u8>, Vec<u8>>,
    }
    impl Manifest {
        pub(super) fn new(path: &Path, b: &mut Budget) -> Result<Self, IncompleteReason> {
            let anchor = Anchor::open(path, b, &mut SystemBoundary)?;
            let proc = TrustedProc::open(b, &mut SystemBoundary)?;
            let fd = open_path(&anchor.last().fd, b".", true, true, b)?;
            let identity = stat(&fd, b)?;
            equal(&identity, &anchor.last().identity)?;
            b.entry()?;
            Ok(Self {
                anchor,
                proc,
                held: vec![Held {
                    fd,
                    parent: None,
                    name: vec![],
                    path: vec![],
                    identity,
                    names: None,
                }],
                paths: BTreeMap::from([(vec![], 0)]),
                absent: BTreeMap::new(),
                data: BTreeMap::new(),
            })
        }
        fn node(&mut self, path: &[u8], b: &mut Budget) -> Result<Option<usize>, IncompleteReason> {
            if path.is_empty() {
                return Ok(Some(0));
            }
            RawPath::from_bytes(path).map_err(|_| IncompleteReason::InvalidPath)?;
            if let Some(i) = self.paths.get(path) {
                return Ok(Some(*i));
            }
            if self.absent.contains_key(path) {
                return Ok(None);
            }
            let mut parent = 0;
            let mut prefix = Vec::new();
            let parts: Vec<_> = path.split(|c| *c == b'/').collect();
            for (part_index, name) in parts.iter().enumerate() {
                if !prefix.is_empty() {
                    prefix.push(b'/');
                }
                prefix.extend_from_slice(name);
                if let Some(i) = self.paths.get(&prefix) {
                    parent = *i;
                    continue;
                }
                if self.absent.contains_key(&prefix) {
                    return Ok(None);
                }
                b.entry()?;
                b.check()?;
                // A no-follow metadata lookup distinguishes absence, without a
                // speculative readable open of a link, FIFO, socket or device.
                let before = match fs::statat(
                    &self.held[parent].fd,
                    cstring(name)?.as_c_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                ) {
                    Ok(s) => Identity::from_stat(s),
                    Err(rustix::io::Errno::NOENT) => {
                        self.absent.insert(prefix, (parent, name.to_vec()));
                        return Ok(None);
                    }
                    Err(e) => return Err(os_error(e)),
                };
                let mut evidence = Vec::new();
                before.encode(&mut evidence);
                b.observe(25, &prefix);
                b.observe(26, &evidence);
                let directory = before.kind() == FileType::Directory;
                if !directory {
                    regular(&before)?;
                }
                if part_index + 1 < parts.len() && !directory {
                    return Err(IncompleteReason::UnsupportedGit);
                }
                let fd = open_path(&self.held[parent].fd, name, directory, true, b)?;
                equal(&before, &stat(&fd, b)?)?;
                if before.device != self.held[0].identity.device {
                    return Err(IncompleteReason::MountCrossing);
                }
                let i = self.held.len();
                self.held.push(Held {
                    fd,
                    parent: Some(parent),
                    name: name.to_vec(),
                    path: prefix.clone(),
                    identity: before,
                    names: None,
                });
                self.paths.insert(prefix.clone(), i);
                parent = i;
            }
            Ok(Some(parent))
        }
        pub(super) fn is_directory(
            &mut self,
            path: &[u8],
            b: &mut Budget,
        ) -> Result<bool, IncompleteReason> {
            let i = self
                .node(path, b)?
                .ok_or(IncompleteReason::UnsupportedGit)?;
            Ok(self.held[i].identity.kind() == FileType::Directory)
        }
        pub(super) fn metadata(
            &mut self,
            path: &[u8],
            b: &mut Budget,
        ) -> Result<bool, IncompleteReason> {
            let Some(i) = self.node(path, b)? else {
                return Ok(false);
            };
            regular(&self.held[i].identity)?;
            Ok(true)
        }
        pub(super) fn absent(
            &mut self,
            path: &[u8],
            b: &mut Budget,
        ) -> Result<(), IncompleteReason> {
            if self.node(path, b)?.is_some() {
                return Err(IncompleteReason::UnsupportedGit);
            }
            Ok(())
        }
        pub(super) fn list(
            &mut self,
            path: &[u8],
            b: &mut Budget,
        ) -> Result<Vec<Vec<u8>>, IncompleteReason> {
            let i = self
                .node(path, b)?
                .ok_or(IncompleteReason::UnsupportedGit)?;
            if self.held[i].identity.kind() != FileType::Directory {
                return Err(IncompleteReason::UnsupportedGit);
            }
            let names = enumerate(&self.held[i], b, true)?;
            if self.held[i].names.as_ref().is_some_and(|old| old != &names) {
                return Err(IncompleteReason::Changed);
            }
            self.held[i].names = Some(names.clone());
            Ok(names)
        }
        pub(super) fn optional(
            &mut self,
            path: &[u8],
            b: &mut Budget,
        ) -> Result<Option<Vec<u8>>, IncompleteReason> {
            let Some(i) = self.node(path, b)? else {
                return Ok(None);
            };
            if let Some(data) = self.data.get(path) {
                return Ok(Some(data.clone()));
            }
            let held = &self.held[i];
            regular(&held.identity)?;
            let length =
                u64::try_from(held.identity.size).map_err(|_| IncompleteReason::Changed)?;
            b.file_length(length)?;
            let fd = self
                .proc
                .reopen(&held.fd, &held.identity, path, b, &mut SystemBoundary)?;
            let mut identity_bytes = Vec::new();
            held.identity.encode(&mut identity_bytes);
            b.observe(23, path);
            b.observe(24, &identity_bytes);
            let mut file = File::from(fd);
            let mut data = Vec::with_capacity(length as usize);
            let mut buffer = [0u8; 8192];
            while (data.len() as u64) < length {
                let count = buffer.len().min(length as usize - data.len());
                let n = read_chunk(&mut file, &mut buffer[..count], b)?;
                if n == 0 {
                    return Err(IncompleteReason::Changed);
                }
                data.extend_from_slice(&buffer[..n]);
            }
            if read_chunk(&mut file, &mut buffer[..1], b)? != 0 {
                return Err(IncompleteReason::Changed);
            }
            equal(
                &held.identity,
                &Identity::from_stat(fs::fstat(&file).map_err(os_error)?),
            )?;
            equal(&held.identity, &stat(&held.fd, b)?)?;
            if let Some(parent) = held.parent {
                equal(
                    &held.identity,
                    &named(&self.held[parent].fd, &held.name, b)?,
                )?;
            }
            self.data.insert(path.to_vec(), data.clone());
            Ok(Some(data))
        }
        pub(super) fn required(
            &mut self,
            path: &[u8],
            b: &mut Budget,
        ) -> Result<Vec<u8>, IncompleteReason> {
            self.optional(path, b)?
                .ok_or(IncompleteReason::UnsupportedGit)
        }
        pub(super) fn recheck(&self, b: &mut Budget) -> Result<(), IncompleteReason> {
            check_nodes(&self.held, b)?;
            self.anchor.recheck(b)?;
            self.proc.recheck(b)?;
            for (parent, name) in self.absent.values() {
                b.check()?;
                match fs::statat(
                    &self.held[*parent].fd,
                    cstring(name)?.as_c_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                ) {
                    Err(rustix::io::Errno::NOENT) => (),
                    _ => return Err(IncompleteReason::Changed),
                }
            }
            Ok(())
        }
        pub(super) fn read_size(&self) -> u64 {
            self.data.values().map(|v| v.len() as u64).sum()
        }
        pub(super) fn fingerprint(&self) -> Vec<u8> {
            let mut out = Vec::new();
            for (path, i) in &self.paths {
                frame(&mut out, 1, path);
                self.held[*i].identity.encode(&mut out);
                if let Some(names) = &self.held[*i].names {
                    for name in names {
                        frame(&mut out, 2, name);
                    }
                }
            }
            for path in self.absent.keys() {
                frame(&mut out, 3, path);
            }
            for (path, data) in &self.data {
                frame(&mut out, 4, path);
                frame(&mut out, 5, &Sha256::digest(data));
            }
            Sha256::digest(out).to_vec()
        }
    }
    pub(super) struct Endpoint {
        anchor: Anchor,
        final_entry: Option<(OwnedFd, Vec<u8>, Identity)>,
        absent: Option<Vec<u8>>,
    }
    impl Endpoint {
        pub(super) fn open(path: &Path, b: &mut Budget) -> Result<Self, IncompleteReason> {
            let raw = path.as_os_str().as_bytes();
            let relative = raw
                .strip_prefix(b"/")
                .ok_or(IncompleteReason::InvalidPath)?;
            RawPath::from_bytes(relative).map_err(|_| IncompleteReason::InvalidPath)?;
            let mut anchor = Anchor::open(Path::new("/"), b, &mut SystemBoundary)?;
            let parts: Vec<_> = relative.split(|c| *c == b'/').collect();
            for (i, name) in parts.iter().enumerate() {
                b.entry()?;
                b.check()?;
                let identity = match fs::statat(
                    &anchor.last().fd,
                    cstring(name)?.as_c_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                ) {
                    Ok(s) => Identity::from_stat(s),
                    Err(rustix::io::Errno::NOENT) => {
                        return Ok(Self {
                            anchor,
                            final_entry: None,
                            absent: Some(name.to_vec()),
                        })
                    }
                    Err(e) => return Err(os_error(e)),
                };
                if i + 1 == parts.len() {
                    regular(&identity)?;
                    let fd = open_path(&anchor.last().fd, name, false, false, b)?;
                    equal(&identity, &stat(&fd, b)?)?;
                    return Ok(Self {
                        anchor,
                        final_entry: Some((fd, name.to_vec(), identity)),
                        absent: None,
                    });
                }
                if identity.kind() != FileType::Directory {
                    return Err(IncompleteReason::UnsupportedGit);
                }
                anchor.descend(name, false, b, &mut SystemBoundary)?;
            }
            Err(IncompleteReason::InvalidPath)
        }
        pub(super) fn missing(&self) -> bool {
            self.absent.is_some()
        }
        pub(super) fn recheck(&self, b: &mut Budget) -> Result<(), IncompleteReason> {
            self.anchor.recheck(b)?;
            if let Some((fd, name, identity)) = &self.final_entry {
                equal(identity, &stat(fd, b)?)?;
                equal(identity, &named(&self.anchor.last().fd, name, b)?)?;
            }
            if let Some(name) = &self.absent {
                b.check()?;
                match fs::statat(
                    &self.anchor.last().fd,
                    cstring(name)?.as_c_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                ) {
                    Err(rustix::io::Errno::NOENT) => (),
                    _ => return Err(IncompleteReason::Changed),
                }
            }
            Ok(())
        }
        pub(super) fn fingerprint(&self) -> Vec<u8> {
            let mut out = Vec::new();
            for link in &self.anchor.route {
                frame(&mut out, 1, &link.name);
                for n in [
                    link.identity.device,
                    link.identity.inode,
                    u64::from(link.identity.mode),
                    u64::from(link.identity.uid),
                    u64::from(link.identity.gid),
                ] {
                    frame(&mut out, 2, &n.to_be_bytes());
                }
            }
            if let Some((_, name, identity)) = &self.final_entry {
                frame(&mut out, 3, name);
                identity.encode(&mut out);
            }
            if let Some(name) = &self.absent {
                frame(&mut out, 4, name);
            }
            Sha256::digest(out).to_vec()
        }
    }
    pub(super) fn boot_id(b: &mut Budget) -> Result<Vec<u8>, IncompleteReason> {
        let anchor = Anchor::open(Path::new("/proc/sys/kernel/random"), b, &mut SystemBoundary)?;
        if fs::fstatfs(&anchor.last().fd).map_err(os_error)?.f_type != fs::PROC_SUPER_MAGIC {
            return Err(IncompleteReason::UntrustedProc);
        }
        let proc = TrustedProc::open(b, &mut SystemBoundary)?;
        let fd = open_path(&anchor.last().fd, b"boot_id", false, true, b)?;
        let identity = stat(&fd, b)?;
        regular(&identity)?;
        let readable = proc.reopen(&fd, &identity, b"boot_id", b, &mut SystemBoundary)?;
        b.observe(23, b"/proc/sys/kernel/random/boot_id");
        let mut file = File::from(readable);
        let mut out = Vec::new();
        let mut buffer = [0u8; 38];
        loop {
            let remaining = 38 - out.len();
            if remaining == 0 {
                return Err(IncompleteReason::UntrustedProc);
            }
            let n = read_chunk(&mut file, &mut buffer[..remaining], b)?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buffer[..n]);
        }
        if out.len() != 37 || out[36] != b'\n' || Uuid::try_parse_ascii(&out[..36]).is_err() {
            return Err(IncompleteReason::UntrustedProc);
        }
        equal(&identity, &stat(&fd, b)?)?;
        equal(&identity, &named(&anchor.last().fd, b"boot_id", b)?)?;
        anchor.recheck(b)?;
        proc.recheck(b)?;
        Ok(out)
    }
    struct Walker<'a, H> {
        b: &'a mut Budget,
        hooks: &'a mut H,
        proc: TrustedProc,
        held: Vec<Held>,
        entries: Vec<Entry>,
    }
    pub(super) fn walk<H: Boundary>(
        path: &Path,
        b: &mut Budget,
        hooks: &mut H,
    ) -> Result<Census, IncompleteReason> {
        match walk_inner(path, b, hooks) {
            Ok(census) => Ok(census),
            Err(reason) => b.fail(reason),
        }
    }
    fn walk_inner<H: Boundary>(
        path: &Path,
        b: &mut Budget,
        hooks: &mut H,
    ) -> Result<Census, IncompleteReason> {
        let anchor = Anchor::open(path, b, hooks)?;
        let proc = TrustedProc::open(b, hooks)?;
        let fd = open_path(&anchor.last().fd, b".", true, true, b)?;
        let identity = stat(&fd, b)?;
        equal(&anchor.last().identity, &identity)?;
        b.entry()?;
        b.output(256)?;
        let mut w = Walker {
            b,
            hooks,
            proc,
            held: vec![Held {
                fd,
                parent: None,
                name: vec![],
                path: vec![],
                identity,
                names: None,
            }],
            entries: vec![],
        };
        w.visit(0, 0)?;
        // Enter the final content AND binding recheck boundary. Root remains
        // a full held census object even though Anchor checks only bindings.
        w.hooks.event(Event::BeforeAnchorRecheck, &[], None)?;
        // Global recheck, not just a local check when leaving each subtree.
        for index in 0..w.held.len() {
            if w.held[index].names.is_some() {
                w.hooks
                    .event(Event::BeforeReenumerate, &w.held[index].path, None)?;
                let now = enumerate(&w.held[index], w.b, false)?;
                if Some(&now) != w.held[index].names.as_ref() {
                    return Err(IncompleteReason::Changed);
                }
            }
            w.check_held(index)?;
        }
        anchor.recheck(w.b)?;
        w.proc.recheck(w.b)?;
        w.b.check()?;
        w.entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(Census {
            entries: w.entries,
            _held: w.held,
            _anchor: anchor,
            _proc: w.proc,
        })
    }
    impl<H: Boundary> Walker<'_, H> {
        fn check_held(&mut self, index: usize) -> Result<(), IncompleteReason> {
            let held = &self.held[index];
            equal(&held.identity, &stat(&held.fd, self.b)?)?;
            if let Some(parent) = held.parent {
                equal(
                    &held.identity,
                    &named(&self.held[parent].fd, &held.name, self.b)?,
                )?;
            }
            Ok(())
        }
        fn visit(&mut self, parent: usize, depth: usize) -> Result<(), IncompleteReason> {
            self.b.check()?;
            if depth > MAX_DEPTH {
                return self.b.fail(IncompleteReason::DepthBudget);
            }
            let names = enumerate(&self.held[parent], self.b, true)?;
            for name in &names {
                let mut path = self.held[parent].path.clone();
                if !path.is_empty() {
                    path.push(b'/');
                }
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
                let mut evidence = Vec::new();
                identity.encode(&mut evidence);
                self.b.observe(25, &path);
                self.b.observe(26, &evidence);
                // Check type/link count BEFORE any readable data open.
                let directory = identity.kind() == FileType::Directory;
                if !directory {
                    let result = regular(&identity);
                    #[cfg(test)]
                    let result = result.inspect_err(|reason| self.hooks.rejected(&path, *reason));
                    result?;
                }
                if identity.device != self.held[0].identity.device {
                    return Err(IncompleteReason::MountCrossing);
                }
                if name == b".git" && directory {
                    #[cfg(test)]
                    self.hooks
                        .rejected(&path, IncompleteReason::GitMetadataUnproven);
                    return Err(IncompleteReason::GitMetadataUnproven);
                }
                equal(&identity, &named(&self.held[parent].fd, name, self.b)?)?;
                let index = self.held.len();
                self.held.push(Held {
                    fd,
                    parent: Some(parent),
                    name: name.clone(),
                    path: path.clone(),
                    identity: identity.clone(),
                    names: None,
                });
                let content_sha256 = if directory {
                    self.visit(index, depth + 1)?;
                    None
                } else {
                    Some(self.hash_file(index)?)
                };
                self.check_held(index)?;
                self.entries.push(Entry {
                    path: raw,
                    identity,
                    content_sha256,
                });
            }
            self.held[parent].names = Some(names);
            self.check_held(parent)
        }
        fn hash_file(&mut self, index: usize) -> Result<[u8; 32], IncompleteReason> {
            let held = &self.held[index];
            regular(&held.identity)?;
            let length =
                u64::try_from(held.identity.size).map_err(|_| IncompleteReason::Changed)?;
            self.b.file_length(length)?;
            let fd = self
                .proc
                .reopen(&held.fd, &held.identity, &held.path, self.b, self.hooks)?;
            self.check_held(index)?;
            let held = &self.held[index];
            self.hooks
                .event(Event::BeforeFileRead, &held.path, Some(&held.identity))?;
            // Safe ownership conversion. No unsafe/from_raw_fd, no original path.
            let mut identity_bytes = Vec::new();
            held.identity.encode(&mut identity_bytes);
            self.b.observe(23, &held.path);
            self.b.observe(24, &identity_bytes);
            let mut file = File::from(fd);
            let mut hasher = Sha256::new();
            let mut remaining = length;
            let mut buffer = [0u8; 8192];
            while remaining != 0 {
                let count = usize::try_from(remaining.min(buffer.len() as u64))
                    .map_err(|_| IncompleteReason::FileBudget)?;
                let n = read_chunk(&mut file, &mut buffer[..count], self.b)?;
                if n == 0 {
                    return Err(IncompleteReason::Changed);
                }
                hasher.update(&buffer[..n]);
                remaining -= n as u64;
            }
            // Even an expected EOF requires a reserved byte. Growth is charged.
            let n = read_chunk(&mut file, &mut buffer[..1], self.b)?;
            if n != 0 {
                return Err(IncompleteReason::Changed);
            }
            self.b.check()?;
            let after = fs::fstat(&file)
                .map(Identity::from_stat)
                .map_err(os_error)?;
            equal(&held.identity, &after)?;
            self.check_held(index)?;
            self.proc.recheck(self.b)?;
            Ok(hasher.finalize().into())
        }
    }
    fn enumerate(
        held: &Held,
        b: &mut Budget,
        first: bool,
    ) -> Result<Vec<Vec<u8>>, IncompleteReason> {
        b.check()?;
        // A NEW readable open of '.' gives an independent directory cursor;
        // neither O_PATH nor dup of an exhausted cursor is used as RawDir input.
        let readable = fs::openat2(
            &held.fd,
            c".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            resolution(true),
        )
        .map_err(os_error)?;
        equal(&held.identity, &stat(&readable, b)?)?;
        let mut buffer = [MaybeUninit::<u8>::uninit(); DIRECTORY_BUFFER_BYTES];
        let mut dir = RawDir::new(&readable, &mut buffer);
        let mut names = BTreeSet::new();
        loop {
            // The shared tested gate reserves BEFORE next(), including EOF
            // and errors. The closure returns only a bounded OWNED name; the
            // RawDir borrow cannot escape into a subsequent next()/refill.
            let next = directory_next(b, dir.is_buffer_empty(), || match dir.next() {
                None => Ok(None),
                Some(Err(e)) => Err(os_error(e)),
                Some(Ok(entry)) => {
                    let name = entry.file_name().to_bytes();
                    if name.len() > MAX_PATH_BYTES {
                        return Err(IncompleteReason::InvalidPath);
                    }
                    Ok(Some(name.to_vec()))
                }
            })??;
            let Some(name) = next else {
                break;
            };
            if name == b"." || name == b".." {
                continue;
            }
            let length = held.path.len() + usize::from(!held.path.is_empty()) + name.len();
            if name.is_empty() || name.contains(&b'/') || length > MAX_PATH_BYTES {
                return Err(IncompleteReason::InvalidPath);
            }
            if names.len() >= MAX_ENTRIES as usize {
                return b.fail(IncompleteReason::EntryBudget);
            }
            if first {
                b.entry()?;
                b.output((length as u64) * 2 + 256)?;
            }
            // Evidence of returned names, NOT the number of kernel bytes read.
            b.counters.copied_name_bytes = b
                .counters
                .copied_name_bytes
                .checked_add(name.len() as u64)
                .ok_or(IncompleteReason::ReadBudget)?;
            if !names.insert(name) {
                return Err(IncompleteReason::Changed);
            }
        }
        equal(&held.identity, &stat(&held.fd, b)?)?;
        Ok(names.into_iter().collect())
    }
}
