//! Private append-only receipt protocol. Tests authored before implementation;
//! no local execution or RED/GREEN claim.
use super::{frame, hex, Captured, Coverage, InspectionError, Observation, Store};
use crate::disposal::ValidatedPolicies;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, RawDir, RenameFlags, ResolveFlags};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    mem::MaybeUninit,
    os::unix::ffi::OsStrExt,
};
use uuid::Uuid;

const DIRECTORY: &str = "inspection-receipts-v1";
const MAX_RECEIPT: u64 = 2 * 1024 * 1024;
const MAX_TOTAL: u64 = 16 * 1024 * 1024;
const MAX_NAMES: usize = 4096;
const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptError {
    #[error("inspection context changed or unavailable")]
    Conflict,
    #[error("inspection receipt capacity full")]
    CapacityFull,
    #[error("unsafe inspection receipt store")]
    UnsafeReceiptStore,
    #[error("inspection authority busy or unavailable")]
    Busy,
    #[error("inspection receipt encoding limit")]
    EncodingLimit,
    #[error("inspection receipt I/O failure")]
    Io,
    #[error("inspection receipt missing")]
    Missing,
    #[error("inspection receipt corrupt")]
    Corrupt,
    #[error("inspection receipt publication durability unknown")]
    DurabilityUnknown { id: Uuid, digest: [u8; 32] },
    #[error("retirement intent fences receipt publication")]
    RetirementIntentActive,
}
impl ReceiptError {
    pub(super) fn label(&self) -> &'static str {
        match self {
            Self::Conflict => "conflict",
            Self::CapacityFull => "capacity_full",
            Self::UnsafeReceiptStore => "unsafe_receipt_store",
            Self::Busy => "busy",
            Self::EncodingLimit => "encoding_limit",
            Self::Io => "io_failure",
            Self::Missing => "missing",
            Self::Corrupt => "corrupt",
            Self::DurabilityUnknown { .. } => "durability_unknown",
            Self::RetirementIntentActive => "retirement_intent_active",
        }
    }
}
type Result<T> = std::result::Result<T, ReceiptError>;
/// Acknowledges file sync, no-replace publication and directory sync in this
/// invocation. Never a live filesystem, writer or retirement capability.
#[derive(Debug)]
pub struct PersistedReceipt {
    id: Uuid,
    digest: [u8; 32],
}
impl PersistedReceipt {
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
#[derive(Debug)]
pub struct RecordOutcome {
    pub observation: Observation,
    pub receipt: Result<PersistedReceipt>,
}
/// Passive historical bytes only. No constructor, Deserialize, freshness or
/// conversion into Captured/PersistedReceipt. A read is not an original ack.
#[derive(Debug)]
pub struct ReceiptData {
    id: Uuid,
    checkout: Uuid,
    digest: [u8; 32],
    coverage: Coverage,
    body: Vec<u8>,
    policy_digest: [u8; 32],
    findings: Vec<super::Finding>,
    approval: Option<super::approval::ApprovalRecord>,
}
impl ReceiptData {
    pub(super) fn approval_record(&self) -> Option<&super::approval::ApprovalRecord> {
        self.approval.as_ref()
    }
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn checkout(&self) -> Uuid {
        self.checkout
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn coverage(&self) -> Coverage {
        self.coverage
    }
    pub fn canonical_observation(&self) -> &[u8] {
        &self.body
    }
    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }
    pub fn findings(&self) -> &[super::Finding] {
        &self.findings
    }
}
/// Fresh capture only; callers cannot append arbitrary or previously decoded
/// observations. Incomplete provenance can persist only with retained inputs.
pub fn inspect_and_record(
    store: &mut Store,
    checkout: Uuid,
    policies: &ValidatedPolicies,
) -> std::result::Result<RecordOutcome, InspectionError> {
    let guard = crate::checkout_guard::CheckoutGuard::shared(store, checkout)
        .map_err(|_| InspectionError)?;
    if let Err(error) = guarded_checkpoint(
        store,
        &guard,
        checkout,
        crate::retirement_journal::Attempt::ReceiptPublication,
    ) {
        // No filesystem/Git collection on refusal, and no positive observation.
        let observation = super::finish_observation(
            policies,
            checkout.as_bytes(),
            &[],
            vec![],
            vec![],
            Some(super::IncompleteReason::ContextConflict),
            &super::Budget::new(),
        )?;
        return Ok(RecordOutcome {
            observation,
            receipt: Err(error),
        });
    }
    let mut captured = super::collect(
        store,
        checkout,
        policies,
        #[cfg(test)]
        None,
    )?;
    let receipt = persist_under_guard(store, &mut captured, &guard, Fault::None);
    Ok(RecordOutcome {
        observation: captured.observation,
        receipt,
    })
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    #[cfg(test)]
    Write,
    #[cfg(test)]
    FileSync,
    #[cfg(test)]
    Rename,
    #[cfg(test)]
    DirectorySync,
}
pub(super) fn store_error(error: crate::store::StoreError) -> ReceiptError {
    match error {
        crate::store::StoreError::RetirementFenced => ReceiptError::RetirementIntentActive,
        _ => ReceiptError::Conflict,
    }
}

pub(super) fn guarded_checkpoint(
    store: &mut Store,
    guard: &crate::checkout_guard::CheckoutGuard,
    checkout: Uuid,
    attempt: crate::retirement_journal::Attempt,
) -> Result<()> {
    guard
        .require_matching(store, checkout)
        .map_err(store_error)?;
    let lease = store.authority_lease().map_err(|_| ReceiptError::Busy)?;
    crate::retirement_journal::checkpoint(
        store,
        &lease,
        crate::retirement_journal::Scope::Checkout(checkout),
        attempt,
    )
    .map_err(store_error)
}

// Closed actual-evidence cases only, never a byte-append or public storage API.
enum Publication<'a> {
    CapturedInspection(&'a mut Captured, &'a crate::checkout_guard::CheckoutGuard),
    SealedApproval(&'a mut super::approval::SealedApproval),
}
impl Publication<'_> {
    fn require_guard(&self, store: &Store) -> Result<()> {
        match self {
            Self::CapturedInspection(c, guard) => guard
                .require_matching(
                    store,
                    c.context
                        .as_ref()
                        .ok_or(ReceiptError::Conflict)?
                        .allocation
                        .checkout,
                )
                .map_err(store_error),
            Self::SealedApproval(a) => a.require_guard(store),
        }
    }
    fn captured(&mut self) -> &mut Captured {
        match self {
            Self::CapturedInspection(c, _) => c,
            Self::SealedApproval(a) => a.captured(),
        }
    }
    fn id(&self) -> Uuid {
        match self {
            Self::CapturedInspection(..) => Uuid::now_v7(),
            Self::SealedApproval(a) => a.id(),
        }
    }
    fn extension(&self) -> Result<Option<Vec<u8>>> {
        match self {
            Self::CapturedInspection(..) => Ok(None),
            Self::SealedApproval(a) => a
                .extension()
                .map(Some)
                .map_err(|_| ReceiptError::EncodingLimit),
        }
    }
    fn recheck(&mut self) -> Result<()> {
        if let Self::SealedApproval(a) = self {
            a.recheck().map_err(|_| ReceiptError::Conflict)?;
        }
        Ok(())
    }
    fn context_matches(&self, tx: &rusqlite::Connection, context: &super::Context) -> Result<()> {
        if let Self::SealedApproval(a) = self {
            a.context_matches(tx, context)
                .map_err(|_| ReceiptError::Conflict)?;
        }
        Ok(())
    }
    fn publication_time(&mut self) -> Result<()> {
        if let Self::SealedApproval(a) = self {
            a.publication_time().map_err(|_| ReceiptError::Conflict)?;
        }
        Ok(())
    }
}
pub(super) fn publish_approval(
    store: &mut Store,
    sealed: &mut super::approval::SealedApproval,
) -> Result<PersistedReceipt> {
    publish(store, Publication::SealedApproval(sealed), Fault::None)
}
#[cfg(test)]
fn persist(store: &mut Store, captured: &mut Captured, fault: Fault) -> Result<PersistedReceipt> {
    let checkout = captured
        .context
        .as_ref()
        .ok_or(ReceiptError::Conflict)?
        .allocation
        .checkout;
    let guard =
        crate::checkout_guard::CheckoutGuard::shared(store, checkout).map_err(store_error)?;
    persist_under_guard(store, captured, &guard, fault)
}
fn persist_under_guard(
    store: &mut Store,
    captured: &mut Captured,
    guard: &crate::checkout_guard::CheckoutGuard,
    fault: Fault,
) -> Result<PersistedReceipt> {
    publish(
        store,
        Publication::CapturedInspection(captured, guard),
        fault,
    )
}
fn publish(
    store: &mut Store,
    mut publication: Publication<'_>,
    fault: Fault,
) -> Result<PersistedReceipt> {
    publication.require_guard(store)?;
    let checkout = publication
        .captured()
        .context
        .as_ref()
        .ok_or(ReceiptError::Conflict)?
        .allocation
        .checkout;
    {
        let lease = store.authority_lease().map_err(|_| ReceiptError::Busy)?;
        crate::retirement_journal::checkpoint(
            store,
            &lease,
            crate::retirement_journal::Scope::Checkout(checkout),
            crate::retirement_journal::Attempt::ReceiptPublication,
        )
        .map_err(store_error)?;
    }
    store.may_acquire_lease().map_err(|_| ReceiptError::Busy)?;
    let id = publication.id();
    let extension = publication.extension()?;
    let captured = publication.captured();
    captured.context.as_ref().ok_or(ReceiptError::Conflict)?;
    captured.physical.as_ref().ok_or(ReceiptError::Conflict)?;
    if captured.started > captured.ended
        || captured.observation.reasons().iter().any(|r| {
            matches!(
                r,
                super::IncompleteReason::Changed | super::IncompleteReason::ContextConflict
            )
        })
    {
        return Err(ReceiptError::Conflict);
    }
    captured
        .budget
        .check()
        .map_err(|_| ReceiptError::Conflict)?;
    // Encode before any lease or SQL. The immutable body includes its original
    // policy/version/context digest; later checks never rewrite it or its clock.
    let bytes = match extension.as_deref() {
        None => encode(store, id, captured)?,
        Some(extension) => encode_envelope(store, id, captured, Some(extension))?,
    };
    let mut reservation = reserve(store, id, bytes.len() as u64)?;
    #[cfg(test)]
    if fault == Fault::Write {
        // A failure-only seam: a real partial write, never synthetic evidence.
        reservation
            .file
            .write_all(&bytes[..bytes.len() / 2])
            .map_err(|_| ReceiptError::Io)?;
        return Err(ReceiptError::Io);
    }
    reservation
        .file
        .write_all(&bytes)
        .map_err(|_| ReceiptError::Io)?;
    #[cfg(test)]
    if fault == Fault::FileSync {
        return Err(ReceiptError::Io);
    }
    reservation.file.sync_all().map_err(|_| ReceiptError::Io)?;
    // Retained descriptor/Git evidence and ORIGINAL Budget: outside SQL/global
    // lease, but still inside the caller's checkout SH guard.
    captured
        .physical
        .as_ref()
        .ok_or(ReceiptError::Conflict)?
        .recheck(&mut captured.budget)
        .map_err(|_| ReceiptError::Conflict)?;
    publication.recheck()?;
    publication.require_guard(store)?;
    let lease = store.authority_lease().map_err(|_| ReceiptError::Busy)?;
    lease.check(store).map_err(|_| ReceiptError::Conflict)?;
    reservation.check(store, true)?;
    let authority = std::sync::Arc::clone(store.authority_identity());
    {
        let phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| ReceiptError::Conflict)?;
        let tx = crate::retirement_journal::fence(
            tx,
            &lease,
            &authority,
            crate::retirement_journal::Scope::Checkout(checkout),
            crate::retirement_journal::Attempt::ReceiptPublication,
        )
        .map_err(store_error)?;
        let captured = publication.captured();
        let context = captured.context.as_ref().ok_or(ReceiptError::Conflict)?;
        let current = super::snapshot_in_transaction(
            &tx,
            &authority,
            context.allocation.checkout,
            &mut captured.budget,
        )
        .map_err(|_| ReceiptError::Conflict)?;
        if current.canonical != context.canonical {
            return Err(ReceiptError::Conflict);
        }
        publication.context_matches(&tx, &current)?;
        tx.commit().map_err(|_| ReceiptError::Conflict)?;
        drop(phase);
    }
    publication
        .captured()
        .budget
        .check()
        .map_err(|_| ReceiptError::Conflict)?;
    // Lease stays held across SQL-off metadata publication. No payload I/O.
    reservation.check(store, true)?;
    publication
        .captured()
        .budget
        .check()
        .map_err(|_| ReceiptError::Conflict)?;
    publication.publication_time()?;
    #[cfg(test)]
    if fault == Fault::Rename {
        return Err(ReceiptError::Io);
    }
    let final_name = format!("{id}.receipt");
    rename_noreplace(&reservation.location.dir, &reservation.pending, &final_name)?;
    let digest = publication.captured().observation.digest();
    let unknown = || ReceiptError::DurabilityUnknown { id, digest };
    #[cfg(test)]
    if fault == Fault::DirectorySync {
        return Err(unknown());
    }
    let _ = fault;
    reservation.location.dir.sync_all().map_err(|_| unknown())?;
    // A rebind observed after rename cannot truthfully be reported not stored.
    reservation.location.check(store).map_err(|_| unknown())?;
    check_named(
        &reservation.location.dir,
        &final_name,
        &reservation.file,
        reservation.length,
        true,
    )
    .map_err(|_| unknown())?;
    publication.publication_time().map_err(|_| unknown())?;
    drop(lease);
    Ok(PersistedReceipt { id, digest })
}
fn rename_noreplace(dir: &File, from: &str, to: &str) -> Result<()> {
    fs::renameat_with(dir, from, dir, to, RenameFlags::NOREPLACE).map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            ReceiptError::Conflict
        } else {
            ReceiptError::Io
        }
    })
}
fn stat(file: &File) -> Result<fs::Stat> {
    fs::fstat(file).map_err(|_| ReceiptError::UnsafeReceiptStore)
}
fn identity(stat: &fs::Stat) -> (u64, u64) {
    (stat.st_dev, stat.st_ino)
}
fn validate_directory(stat: &fs::Stat) -> Result<()> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_mode & 0o7777 != 0o700
        || stat.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(ReceiptError::UnsafeReceiptStore);
    }
    Ok(())
}
fn validate_file(stat: &fs::Stat) -> Result<()> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size as u64 > MAX_RECEIPT
    {
        return Err(ReceiptError::UnsafeReceiptStore);
    }
    Ok(())
}
fn open_relative(parent: &File, name: &str, flags: OFlags) -> Result<File> {
    // openat2 rejects NONBLOCK with O_PATH. Metadata-only handles still use
    // the same no-follow/no-mount resolution; data opens remain nonblocking.
    let additional = if flags.contains(OFlags::PATH) {
        OFlags::empty()
    } else {
        OFlags::NONBLOCK
    };
    fs::openat2(
        parent,
        name,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW | additional,
        Mode::empty(),
        RESOLVE,
    )
    .map(File::from)
    .map_err(|e| {
        if e == rustix::io::Errno::NOENT {
            ReceiptError::Missing
        } else {
            ReceiptError::UnsafeReceiptStore
        }
    })
}
fn read_charged(file: &File, limit: u64, budget: &mut super::Budget) -> Result<Vec<u8>> {
    budget.check().map_err(|_| ReceiptError::Conflict)?;
    budget.entry().map_err(|_| ReceiptError::Conflict)?;
    budget
        .file_length(limit)
        .map_err(|_| ReceiptError::Conflict)?;
    let mut reader = file;
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        if bytes.len() as u64 > limit {
            return Err(ReceiptError::Corrupt);
        }
        let remaining = (limit + 1).saturating_sub(bytes.len() as u64);
        let n = remaining.min(buffer.len() as u64) as usize;
        if n == 0 {
            break;
        }
        let got = super::read_chunk(&mut reader, &mut buffer[..n], budget)
            .map_err(|_| ReceiptError::Conflict)?;
        if got == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..got]);
    }
    if bytes.len() as u64 > limit {
        return Err(ReceiptError::Corrupt);
    }
    Ok(bytes)
}
fn next_receipt_name(
    entries: &mut RawDir<'_, &File>,
    budget: Option<&mut super::Budget>,
) -> Result<Option<Vec<u8>>> {
    match budget {
        Some(b) => super::directory_next(b, entries.is_buffer_empty(), || match entries.next() {
            None => Ok(None),
            Some(Err(_)) => Err(ReceiptError::UnsafeReceiptStore),
            Some(Ok(entry)) => Ok(Some(entry.file_name().to_bytes().to_vec())),
        })
        .map_err(|_| ReceiptError::Conflict)?,
        None => match entries.next() {
            None => Ok(None),
            Some(Err(_)) => Err(ReceiptError::UnsafeReceiptStore),
            Some(Ok(entry)) => Ok(Some(entry.file_name().to_bytes().to_vec())),
        },
    }
}
fn open_authority(store: &Store) -> Result<File> {
    let authority = store.authority_identity();
    let directory = fs::openat2(
        fs::CWD,
        authority.directory.as_path(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(|_| ReceiptError::UnsafeReceiptStore)?;
    let metadata = stat(&directory)?;
    validate_directory(&metadata)?;
    if identity(&metadata) != authority.directory_id {
        return Err(ReceiptError::UnsafeReceiptStore);
    }
    // O_PATH checks names/types without reading SQLite or lock payloads.
    for (name, expected) in [
        ("store.sqlite", Some(authority.database_id())),
        ("allocation.lock", authority.lock_id),
    ] {
        let file = open_relative(&directory, name, OFlags::PATH)?;
        let metadata = stat(&file)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_uid != rustix::process::geteuid().as_raw()
            || metadata.st_mode & 0o7777 != 0o600
            || metadata.st_nlink != 1
            || Some(identity(&metadata)) != expected
        {
            return Err(ReceiptError::UnsafeReceiptStore);
        }
    }
    Ok(directory)
}
struct Location {
    parent: File,
    dir: File,
}
impl Location {
    fn open(store: &Store, create: bool) -> Result<Self> {
        let parent = open_authority(store)?;
        if create {
            match fs::mkdirat(&parent, DIRECTORY, Mode::from_raw_mode(0o700)) {
                Ok(()) => (),
                Err(rustix::io::Errno::EXIST) => (),
                Err(_) => return Err(ReceiptError::Io),
            }
        }
        let dir = open_relative(&parent, DIRECTORY, OFlags::RDONLY | OFlags::DIRECTORY)?;
        validate_directory(&stat(&dir)?)?;
        let location = Self { parent, dir };
        location.check(store)?;
        // Also sync an EXISTING directory entry: its first creation may have
        // been interrupted. Passive reads deliberately never do this.
        if create {
            location.parent.sync_all().map_err(|_| ReceiptError::Io)?;
        }
        Ok(location)
    }
    fn check(&self, store: &Store) -> Result<()> {
        let parent = open_authority(store)?;
        if identity(&stat(&parent)?) != identity(&stat(&self.parent)?) {
            return Err(ReceiptError::UnsafeReceiptStore);
        }
        let named = open_relative(&self.parent, DIRECTORY, OFlags::PATH | OFlags::DIRECTORY)?;
        let held = stat(&self.dir)?;
        validate_directory(&held)?;
        validate_directory(&stat(&named)?)?;
        if identity(&held) != identity(&stat(&named)?) {
            return Err(ReceiptError::UnsafeReceiptStore);
        }
        Ok(())
    }
}
pub(super) struct Reservation {
    location: Location,
    file: File,
    pending: String,
    length: u64,
    id: Uuid,
}
impl Reservation {
    fn check(&self, store: &Store, filled: bool) -> Result<()> {
        self.location.check(store)?;
        check_named(
            &self.location.dir,
            &self.pending,
            &self.file,
            self.length,
            filled,
        )
    }
}
fn check_named(dir: &File, name: &str, file: &File, length: u64, filled: bool) -> Result<()> {
    let held = stat(file)?;
    validate_file(&held)?;
    let named_file = open_relative(dir, name, OFlags::PATH)?;
    let named = stat(&named_file)?;
    validate_file(&named)?;
    if identity(&held) != identity(&named)
        || held.st_size != named.st_size
        || held.st_size as u64 > length
        || (filled && held.st_size as u64 != length)
    {
        return Err(ReceiptError::UnsafeReceiptStore);
    }
    Ok(())
}
fn uuid(bytes: &[u8]) -> Result<Uuid> {
    let text = std::str::from_utf8(bytes).map_err(|_| ReceiptError::Corrupt)?;
    let id = Uuid::parse_str(text).map_err(|_| ReceiptError::Corrupt)?;
    if id.get_version_num() != 7
        || id.get_variant() != uuid::Variant::RFC4122
        || id.to_string() != text
    {
        return Err(ReceiptError::Corrupt);
    }
    Ok(id)
}
fn name_charge(name: &[u8], size: u64) -> Result<(Uuid, u64)> {
    let invalid = || ReceiptError::UnsafeReceiptStore;
    if let Some(text) = name.strip_suffix(b".receipt") {
        let id = uuid(text).map_err(|_| invalid())?;
        if size == 0 || size > MAX_RECEIPT {
            return Err(invalid());
        }
        return Ok((id, size));
    }
    let pending = name.strip_prefix(b"pending-").ok_or_else(invalid)?;
    if pending.len() < 38 || pending[36] != b'-' {
        return Err(invalid());
    }
    let id = uuid(&pending[..36]).map_err(|_| invalid())?;
    let wire = std::str::from_utf8(&pending[37..]).map_err(|_| invalid())?;
    let length: u64 = wire.parse().map_err(|_| invalid())?;
    if length == 0 || length > MAX_RECEIPT || length.to_string() != wire || size > length {
        return Err(invalid());
    }
    Ok((id, length))
}
fn admit(count: usize, total: u64, length: u64) -> Result<()> {
    if count >= MAX_NAMES || total.checked_add(length).is_none_or(|n| n > MAX_TOTAL) {
        return Err(ReceiptError::CapacityFull);
    }
    Ok(())
}
pub(super) fn authority_bytes_for_recovery(store: &Store) -> Vec<u8> {
    authority_bytes(store)
}

pub(super) fn read_raw(store: &Store, id: Uuid, budget: &mut super::Budget) -> Result<Vec<u8>> {
    store.may_acquire_lease().map_err(|_| ReceiptError::Busy)?;
    budget.check().map_err(|_| ReceiptError::Conflict)?;
    uuid(id.to_string().as_bytes())?;
    let location = Location::open(store, false)?;
    let name = format!("{id}.receipt");
    let before = open_relative(&location.dir, &name, OFlags::PATH)?;
    let expected = stat(&before)?;
    validate_file(&expected)?;
    if expected.st_size == 0 {
        return Err(ReceiptError::Corrupt);
    }
    let file = open_relative(&location.dir, &name, OFlags::RDONLY)?;
    check_named(&location.dir, &name, &file, expected.st_size as u64, true)?;
    let bytes = read_charged(&file, expected.st_size as u64, budget)?;
    if bytes.len() != expected.st_size as usize {
        return Err(ReceiptError::Corrupt);
    }
    location.check(store)?;
    Ok(bytes)
}

#[cfg(test)]
thread_local! {
    static RESULT_PUBLISH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
fn reject_volatile(file: &File) -> Result<()> {
    let fs = fs::fstatfs(file).map_err(|_| ReceiptError::Io)?;
    let magic = fs.f_type as u64;
    if magic == 0x0102_1994 || magic == 0x8584_58f6 {
        return Err(ReceiptError::UnsafeReceiptStore);
    }
    Ok(())
}
pub(super) fn recovery_storage_persistent(
    store: &mut Store,
    guard: &crate::checkout_guard::CheckoutGuard,
    checkout: Uuid,
) -> Result<()> {
    guarded_checkpoint(
        store,
        guard,
        checkout,
        crate::retirement_journal::Attempt::RecoveryRefs,
    )?;
    let location = Location::open(store, false).or_else(|_| Location::open(store, true))?;
    reject_volatile(&location.dir)?;
    reject_volatile(&location.parent)?;
    Ok(())
}
pub(super) fn resync_recovery_published(
    store: &mut Store,
    guard: &crate::checkout_guard::CheckoutGuard,
    checkout: Uuid,
    id: Uuid,
    budget: &mut super::Budget,
) -> Result<()> {
    recovery_storage_persistent(store, guard, checkout)?;
    store.may_acquire_lease().map_err(|_| ReceiptError::Busy)?;
    budget.check().map_err(|_| ReceiptError::Conflict)?;
    budget.entry().map_err(|_| ReceiptError::Conflict)?;
    let location = Location::open(store, false)?;
    reject_volatile(&location.dir)?;
    reject_volatile(&location.parent)?;
    let name = format!("{id}.receipt");
    let file = open_relative(&location.dir, &name, OFlags::RDONLY)?;
    let expected = stat(&file)?;
    validate_file(&expected)?;
    file.sync_all().map_err(|_| ReceiptError::Io)?;
    location.dir.sync_all().map_err(|_| ReceiptError::Io)?;
    location.parent.sync_all().map_err(|_| ReceiptError::Io)?;
    budget.check().map_err(|_| ReceiptError::Conflict)?;
    check_named(&location.dir, &name, &file, expected.st_size as u64, true)?;
    location.check(store)?;
    Ok(())
}
pub(super) fn publish_recovery_intent(
    store: &mut Store,
    publication: &super::recovery_refs::RecoveryIntentPublication<'_>,
    reservation: Reservation,
    context: &super::Context,
    budget: &mut super::Budget,
) -> Result<PersistedReceipt> {
    publication
        .guard()
        .require_matching(store, context.allocation.checkout)
        .map_err(store_error)?;
    if publication.checkout() != context.allocation.checkout {
        return Err(ReceiptError::Conflict);
    }
    guarded_checkpoint(
        store,
        publication.guard(),
        publication.checkout(),
        crate::retirement_journal::Attempt::RecoveryRefs,
    )?;
    if reservation.id != publication.id() || reservation.length != publication.length() {
        return Err(ReceiptError::Conflict);
    }
    write_reserved(reservation, publication.bytes(), budget)?;
    publish_recovery_record(
        store,
        publication.guard(),
        publication.id(),
        publication.length(),
        context,
        budget,
    )
}
pub(super) fn publish_recovery_result(
    store: &mut Store,
    publication: &super::recovery_refs::RecoveryResultPublication<'_>,
    context: &super::Context,
    budget: &mut super::Budget,
) -> Result<PersistedReceipt> {
    publication
        .guard()
        .require_matching(store, context.allocation.checkout)
        .map_err(store_error)?;
    if publication.checkout() != context.allocation.checkout {
        return Err(ReceiptError::Conflict);
    }
    restart_recovery_result(store, publication, budget)?;
    #[cfg(test)]
    RESULT_PUBLISH.with(|flag| flag.set(true));
    let published = publish_recovery_record(
        store,
        publication.guard(),
        publication.id(),
        publication.length(),
        context,
        budget,
    );
    #[cfg(test)]
    RESULT_PUBLISH.with(|flag| flag.set(false));
    published
}
fn publish_recovery_record(
    store: &mut Store,
    guard: &crate::checkout_guard::CheckoutGuard,
    id: Uuid,
    length: u64,
    context: &super::Context,
    budget: &mut super::Budget,
) -> Result<PersistedReceipt> {
    recovery_storage_persistent(store, guard, context.allocation.checkout)?;
    publish_reserved(store, guard, id, length, context, budget)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RecoveryResultBinding {
    pub id: Uuid,
    pub length: u64,
    pub dev: u64,
    pub ino: u64,
}
pub(super) fn reservation_binding(reservation: &Reservation) -> Result<RecoveryResultBinding> {
    let held = stat(&reservation.file)?;
    validate_file(&held)?;
    Ok(RecoveryResultBinding {
        id: reservation.id,
        length: reservation.length,
        dev: held.st_dev,
        ino: held.st_ino,
    })
}

fn write_reserved(
    mut reservation: Reservation,
    bytes: &[u8],
    budget: &mut super::Budget,
) -> Result<()> {
    if bytes.len() as u64 != reservation.length {
        return Err(ReceiptError::EncodingLimit);
    }
    budget.check().map_err(|_| ReceiptError::Conflict)?;
    budget.entry().map_err(|_| ReceiptError::Conflict)?;
    budget
        .reserve(bytes.len() as u64)
        .map_err(|_| ReceiptError::Conflict)?;
    reservation
        .file
        .write_all(bytes)
        .map_err(|_| ReceiptError::Io)?;
    budget.check().map_err(|_| ReceiptError::Conflict)?;
    reservation.file.sync_all().map_err(|_| ReceiptError::Io)?;
    Ok(())
}

fn publish_reserved(
    store: &mut Store,
    guard: &crate::checkout_guard::CheckoutGuard,
    id: Uuid,
    length: u64,
    context: &super::Context,
    budget: &mut super::Budget,
) -> Result<PersistedReceipt> {
    guard
        .require_matching(store, context.allocation.checkout)
        .map_err(store_error)?;
    store.may_acquire_lease().map_err(|_| ReceiptError::Busy)?;
    uuid(id.to_string().as_bytes()).map_err(|_| ReceiptError::Conflict)?;
    budget.check().map_err(|_| ReceiptError::Conflict)?;
    budget.entry().map_err(|_| ReceiptError::Conflict)?;
    let location = Location::open(store, false)?;
    let pending = format!("pending-{id}-{length}");
    let file = open_relative(&location.dir, &pending, OFlags::RDONLY)?;
    check_named(&location.dir, &pending, &file, length, true)?;
    budget.check().map_err(|_| ReceiptError::Conflict)?;
    let lease = store.authority_lease().map_err(|_| ReceiptError::Busy)?;
    lease.check(store).map_err(|_| ReceiptError::Conflict)?;
    let authority = std::sync::Arc::clone(store.authority_identity());
    {
        let phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| ReceiptError::Conflict)?;
        let tx = crate::retirement_journal::fence(
            tx,
            &lease,
            &authority,
            crate::retirement_journal::Scope::Checkout(context.allocation.checkout),
            crate::retirement_journal::Attempt::RecoveryRefs,
        )
        .map_err(store_error)?;
        let current =
            super::snapshot_in_transaction(&tx, &authority, context.allocation.checkout, budget)
                .map_err(|_| ReceiptError::Conflict)?;
        if current.canonical != context.canonical {
            return Err(ReceiptError::Conflict);
        }
        tx.commit().map_err(|_| ReceiptError::Conflict)?;
        drop(phase);
    }
    let final_name = format!("{id}.receipt");
    rename_noreplace(&location.dir, &pending, &final_name)?;
    let digest = {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(id.as_bytes()));
        out
    };
    let unknown = || ReceiptError::DurabilityUnknown { id, digest };
    location.dir.sync_all().map_err(|_| unknown())?;
    location.check(store).map_err(|_| unknown())?;
    let published = {
        #[cfg(test)]
        if RESULT_PUBLISH.with(|flag| flag.get())
            && super::recovery_refs::active_fault_is_publish_reopen()
        {
            super::recovery_refs::note_active_fault();
            open_relative(&location.dir, ".__reopen_missing__", OFlags::RDONLY)
        } else {
            open_relative(&location.dir, &final_name, OFlags::RDONLY)
        }
        #[cfg(not(test))]
        open_relative(&location.dir, &final_name, OFlags::RDONLY)
    }
    .map_err(|_| unknown())?;
    check_named(&location.dir, &final_name, &published, length, true).map_err(|_| unknown())?;
    location.parent.sync_all().map_err(|_| unknown())?;
    location.check(store).map_err(|_| unknown())?;
    #[cfg(test)]
    if RESULT_PUBLISH.with(|flag| flag.get())
        && super::recovery_refs::active_fault_is_publish_deadline()
    {
        super::recovery_refs::note_active_fault();
        budget.test_elapsed = Some(std::time::Duration::from_secs(30));
    }
    budget.check().map_err(|_| unknown())?;
    lease.check(store).map_err(|_| unknown())?;
    #[cfg(test)]
    if !RESULT_PUBLISH.with(|flag| flag.get())
        && super::recovery_refs::active_fault_is_intent_durability()
    {
        super::recovery_refs::note_active_fault();
        return Err(unknown());
    }
    drop(lease);
    Ok(PersistedReceipt { id, digest })
}

fn restart_recovery_result(
    store: &mut Store,
    publication: &super::recovery_refs::RecoveryResultPublication<'_>,
    budget: &mut super::Budget,
) -> Result<()> {
    recovery_storage_persistent(store, publication.guard(), publication.checkout())?;
    let bound = publication.binding();
    let bytes = publication.bytes();
    if publication.id() != bound.id
        || publication.length() != bound.length
        || bytes.len() as u64 != bound.length
        || bound.length == 0
        || bound.length > MAX_RECEIPT
    {
        return Err(ReceiptError::EncodingLimit);
    }
    uuid(bound.id.to_string().as_bytes())?;
    store.may_acquire_lease().map_err(|_| ReceiptError::Busy)?;
    budget.check().map_err(|_| ReceiptError::Conflict)?;
    let location = Location::open(store, false)?;
    let final_name = format!("{}.receipt", bound.id);
    if open_relative(&location.dir, &final_name, OFlags::PATH).is_ok() {
        return Err(ReceiptError::Conflict);
    }
    let pending = format!("pending-{}-{}", bound.id, bound.length);
    let mut file = match open_relative(&location.dir, &pending, OFlags::RDWR) {
        Ok(file) => file,
        Err(ReceiptError::Missing) => return Err(ReceiptError::Missing),
        Err(error) => return Err(error),
    };
    let held = stat(&file)?;
    validate_file(&held)?;
    if identity(&held) != (bound.dev, bound.ino) {
        return Err(ReceiptError::Conflict);
    }
    check_named(&location.dir, &pending, &file, bound.length, false)?;
    let size = held.st_size as u64;
    if size > bound.length {
        return Err(ReceiptError::Corrupt);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ReceiptError::Io)?;
    let existing = read_charged(&file, size, budget)?;
    if existing.len() as u64 != size || !bytes.starts_with(&existing) {
        return Err(ReceiptError::Corrupt);
    }
    if size < bound.length {
        budget.check().map_err(|_| ReceiptError::Conflict)?;
        budget
            .reserve((bound.length - size) as u64)
            .map_err(|_| ReceiptError::Conflict)?;
        file.seek(SeekFrom::Start(size))
            .map_err(|_| ReceiptError::Io)?;
        file.write_all(&bytes[existing.len()..])
            .map_err(|_| ReceiptError::Io)?;
    }
    #[cfg(test)]
    if super::recovery_refs::active_fault_is_result_fsync() {
        super::recovery_refs::note_active_fault();
        return Err(ReceiptError::Io);
    }
    file.sync_all().map_err(|_| ReceiptError::Io)?;
    budget.check().map_err(|_| ReceiptError::Conflict)?;
    check_named(&location.dir, &pending, &file, bound.length, true)?;
    Ok(())
}

fn reserve(store: &Store, id: Uuid, length: u64) -> Result<Reservation> {
    reserve_with_budget(store, id, length, None)
}

pub(super) fn reserve_recovery(
    store: &mut Store,
    guard: &crate::checkout_guard::CheckoutGuard,
    checkout: Uuid,
    id: Uuid,
    length: u64,
    budget: &mut super::Budget,
) -> Result<Reservation> {
    guarded_checkpoint(
        store,
        guard,
        checkout,
        crate::retirement_journal::Attempt::RecoveryRefs,
    )?;
    reserve_with_budget(store, id, length, Some(budget))
}

fn reserve_with_budget(
    store: &Store,
    id: Uuid,
    length: u64,
    mut budget: Option<&mut super::Budget>,
) -> Result<Reservation> {
    if length == 0 || length > MAX_RECEIPT {
        return Err(ReceiptError::EncodingLimit);
    }
    uuid(id.to_string().as_bytes())?;
    if let Some(b) = budget.as_mut() {
        b.check().map_err(|_| ReceiptError::Conflict)?;
    }
    let lease = store.authority_lease().map_err(|_| ReceiptError::Busy)?;
    lease.check(store).map_err(|_| ReceiptError::Conflict)?;
    let location = Location::open(store, true)?;
    let cursor = open_relative(&location.dir, ".", OFlags::RDONLY | OFlags::DIRECTORY)?;
    let mut buffer = [MaybeUninit::<u8>::uninit(); 8192];
    let mut entries = RawDir::new(&cursor, &mut buffer);
    let mut count = 0usize;
    let mut total = 0u64;
    let mut ids = std::collections::BTreeSet::new();
    let mut duplicate = false;
    while let Some(name) = next_receipt_name(&mut entries, budget.as_deref_mut())? {
        if name == b"." || name == b".." {
            continue;
        }
        if let Some(b) = budget.as_mut() {
            b.entry().map_err(|_| ReceiptError::Conflict)?;
        }
        count += 1;
        if count > MAX_NAMES {
            return Err(ReceiptError::CapacityFull);
        }
        let c_name =
            std::ffi::CString::new(name.clone()).map_err(|_| ReceiptError::UnsafeReceiptStore)?;
        let metadata = fs::statat(&location.dir, c_name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ReceiptError::UnsafeReceiptStore)?;
        validate_file(&metadata)?;
        // O_PATH + NO_XDEV also refuses same-device bind mounts.
        let text = std::str::from_utf8(&name).map_err(|_| ReceiptError::UnsafeReceiptStore)?;
        let held = open_relative(&location.dir, text, OFlags::PATH)?;
        if identity(&stat(&held)?) != identity(&metadata) {
            return Err(ReceiptError::UnsafeReceiptStore);
        }
        let (existing, charge) = name_charge(&name, metadata.st_size as u64)?;
        if !ids.insert(existing) {
            return Err(ReceiptError::UnsafeReceiptStore);
        }
        duplicate |= existing == id;
        total = total
            .checked_add(charge)
            .ok_or(ReceiptError::CapacityFull)?;
    }
    // Finish discovery even when enough charged bytes were seen earlier: junk
    // and duplicates must never become available capacity.
    if duplicate {
        return Err(ReceiptError::Conflict);
    }
    admit(count, total, length)?;
    location.check(store)?;
    let pending = format!("pending-{id}-{length}");
    let file = fs::openat2(
        &location.dir,
        pending.as_str(),
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK,
        Mode::from_raw_mode(0o600),
        RESOLVE,
    )
    .map(File::from)
    .map_err(|e| {
        if e == rustix::io::Errno::EXIST {
            ReceiptError::Conflict
        } else {
            ReceiptError::Io
        }
    })?;
    let reservation = Reservation {
        location,
        file,
        pending,
        length,
        id,
    };
    reservation.check(store, false)?;
    // Make the declared reservation visible durably before payload work. No
    // automatic unlink on any subsequent error; a zero-byte pending is charged.
    reservation
        .location
        .dir
        .sync_all()
        .map_err(|_| ReceiptError::Io)?;
    drop(lease);
    Ok(reservation)
}
fn authority_bytes(store: &Store) -> Vec<u8> {
    let authority = store.authority_identity();
    let mut bytes = Vec::new();
    frame(&mut bytes, 0, authority.registry().as_os_str().as_bytes());
    frame(&mut bytes, 1, authority.directory.as_os_str().as_bytes());
    for n in [
        authority.directory_id.0,
        authority.directory_id.1,
        authority.database_id().0,
        authority.database_id().1,
    ] {
        frame(&mut bytes, 2, &n.to_be_bytes());
    }
    if let Some((dev, ino)) = authority.lock_id {
        frame(&mut bytes, 3, &dev.to_be_bytes());
        frame(&mut bytes, 3, &ino.to_be_bytes());
    }
    bytes
}
fn encode(store: &Store, id: Uuid, captured: &Captured) -> Result<Vec<u8>> {
    encode_envelope(store, id, captured, None)
}
fn encode_envelope(
    store: &Store,
    id: Uuid,
    captured: &Captured,
    extension: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let context = captured.context.as_ref().ok_or(ReceiptError::Conflict)?;
    uuid(id.to_string().as_bytes()).map_err(|_| ReceiptError::Conflict)?;
    uuid(context.allocation.checkout.to_string().as_bytes()).map_err(|_| ReceiptError::Conflict)?;
    let mut bytes = Vec::new();
    frame(
        &mut bytes,
        0,
        if extension.is_some() {
            b"work.inspection.receipt.v2"
        } else {
            b"work.inspection.receipt.v1"
        },
    );
    frame(&mut bytes, 1, id.to_string().as_bytes());
    frame(
        &mut bytes,
        2,
        context.allocation.checkout.to_string().as_bytes(),
    );
    frame(&mut bytes, 3, &authority_bytes(store));
    frame(&mut bytes, 4, &Sha256::digest(&context.canonical));
    frame(&mut bytes, 5, &captured.started.to_be_bytes());
    frame(&mut bytes, 6, &captured.ended.to_be_bytes());
    frame(
        &mut bytes,
        7,
        &[u8::from(
            captured.observation.coverage() == Coverage::Complete,
        )],
    );
    frame(&mut bytes, 8, &captured.observation.digest());
    frame(&mut bytes, 9, captured.observation.canonical_bytes());
    if let Some(extension) = extension {
        frame(&mut bytes, 11, extension);
    }
    let checksum = Sha256::digest(&bytes);
    frame(&mut bytes, 10, &checksum);
    if bytes.len() as u64 > MAX_RECEIPT {
        return Err(ReceiptError::EncodingLimit);
    }
    Ok(bytes)
}
/// Targeted passive read through an existing mutable-open Store (the inspector's
/// current-authority handle). No lease, SQL, creation, sync, repair or freshness.
pub fn read_receipt(store: &Store, id: Uuid) -> Result<ReceiptData> {
    store.may_acquire_lease().map_err(|_| ReceiptError::Busy)?;
    uuid(id.to_string().as_bytes())?;
    let location = Location::open(store, false)?;
    let name = format!("{id}.receipt");
    let before = open_relative(&location.dir, &name, OFlags::PATH)?;
    let expected = stat(&before)?;
    validate_file(&expected)?;
    if expected.st_size == 0 {
        return Err(ReceiptError::Corrupt);
    }
    let file = open_relative(&location.dir, &name, OFlags::RDONLY)?;
    check_named(&location.dir, &name, &file, expected.st_size as u64, true)?;
    if identity(&stat(&file)?) != identity(&expected) {
        return Err(ReceiptError::UnsafeReceiptStore);
    }
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_RECEIPT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReceiptError::Io)?;
    if bytes.len() != expected.st_size as usize {
        return Err(ReceiptError::Corrupt);
    }
    let result = decode(store, id, &bytes)?;
    check_named(&location.dir, &name, &file, expected.st_size as u64, true)?;
    let after = stat(&file)?;
    if expected.st_mtime != after.st_mtime
        || expected.st_mtime_nsec != after.st_mtime_nsec
        || expected.st_ctime != after.st_ctime
        || expected.st_ctime_nsec != after.st_ctime_nsec
    {
        return Err(ReceiptError::Corrupt);
    }
    location.check(store)?;
    Ok(result)
}

// Strict tagged/length-framed decoding, never an Observation/Captured decoder.
// Re-encode each consumed frame and validate the entire grammar; policy bytes
// additionally round-trip through the existing strict policy validator.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
    canonical: Vec<u8>,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            at: 0,
            canonical: Vec::new(),
        }
    }
    fn done(&self) -> bool {
        self.at == self.bytes.len()
    }
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }
    fn any(&mut self) -> Result<(u8, &'a [u8])> {
        let header = self
            .bytes
            .get(self.at..self.at.saturating_add(9))
            .ok_or(ReceiptError::Corrupt)?;
        let length = u64::from_be_bytes(header[1..].try_into().map_err(|_| ReceiptError::Corrupt)?);
        let length = usize::try_from(length).map_err(|_| ReceiptError::Corrupt)?;
        let start = self.at + 9;
        let end = start.checked_add(length).ok_or(ReceiptError::Corrupt)?;
        let value = self.bytes.get(start..end).ok_or(ReceiptError::Corrupt)?;
        let tag = header[0];
        self.at = end;
        frame(&mut self.canonical, tag, value);
        Ok((tag, value))
    }
    fn field(&mut self, expected: u8) -> Result<&'a [u8]> {
        let (tag, value) = self.any()?;
        if tag != expected {
            return Err(ReceiptError::Corrupt);
        }
        Ok(value)
    }
    fn number(&mut self, tag: u8) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.field(tag)?
                .try_into()
                .map_err(|_| ReceiptError::Corrupt)?,
        ))
    }
    fn end(self) -> Result<()> {
        if !self.done() || self.canonical != self.bytes {
            return Err(ReceiptError::Corrupt);
        }
        Ok(())
    }
}
fn hash(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| ReceiptError::Corrupt)
}
fn text(bytes: &[u8]) -> Result<String> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| ReceiptError::Corrupt)
}
fn policy(wire: &[u8]) -> Result<(ValidatedPolicies, std::collections::BTreeSet<String>)> {
    use crate::disposal::{Policy, PolicyDocument, PolicyFile};
    let mut c = Cursor::new(wire);
    if c.field(0)? != b"work.disposal.policy.v1" || c.number(1)? != 1 || c.number(2)? != 1 {
        return Err(ReceiptError::Corrupt);
    }
    let count = c.number(3)?;
    if count > 64 {
        return Err(ReceiptError::Corrupt);
    }
    let mut policies = Vec::new();
    let mut entry_count = 0u64;
    for _ in 0..count {
        let scope = hex(c.field(4)?);
        let id = text(c.field(5)?)?;
        let version = text(c.field(6)?)?;
        let max_files = c.number(7)?;
        let max_file_bytes = c.number(8)?;
        let max_total_bytes = c.number(9)?;
        let count = c.number(10)?;
        entry_count = entry_count
            .checked_add(count)
            .ok_or(ReceiptError::Corrupt)?;
        if entry_count > 4096 {
            return Err(ReceiptError::Corrupt);
        }
        let mut directories = Vec::new();
        for _ in 0..count {
            directories.push(hex(c.field(11)?));
        }
        let count = c.number(12)?;
        entry_count = entry_count
            .checked_add(count)
            .ok_or(ReceiptError::Corrupt)?;
        if entry_count > 4096 {
            return Err(ReceiptError::Corrupt);
        }
        let mut files = Vec::new();
        for _ in 0..count {
            files.push(PolicyFile {
                path: hex(c.field(13)?),
                sha256: hex(c.field(14)?),
                length: c.number(15)?,
                mode: u32::try_from(c.number(16)?).map_err(|_| ReceiptError::Corrupt)?,
            });
        }
        policies.push(Policy {
            id,
            version,
            scope,
            max_files,
            max_file_bytes,
            max_total_bytes,
            files,
            directories,
        });
    }
    c.end()?;
    let ids = policies.iter().map(|p| p.id.clone()).collect();
    let validated = crate::disposal::validate(PolicyDocument {
        format: 1,
        policies,
    })
    .map_err(|_| ReceiptError::Corrupt)?;
    if validated.canonical_bytes() != wire {
        return Err(ReceiptError::Corrupt);
    }
    Ok((validated, ids))
}
fn body_metadata(
    body: &[u8],
    coverage: Coverage,
    context: [u8; 32],
) -> Result<([u8; 32], Vec<super::Finding>)> {
    let mut c = Cursor::new(body);
    let domain: &[u8] = if coverage == Coverage::Complete {
        b"work.inspection.complete.v1"
    } else {
        b"work.inspection.incomplete.v1"
    };
    if c.field(0)? != domain {
        return Err(ReceiptError::Corrupt);
    }
    let (policy, policy_ids) = policy(c.field(1)?)?;
    if hash(c.field(2)?)? != context {
        return Err(ReceiptError::Corrupt);
    }
    hash(c.field(3)?)?;
    hash(c.field(14)?)?;
    let version = c.field(16)?;
    if version.len() > 96
        || (!version.is_empty()
            && (!version.starts_with(b"git version ")
                || !version
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b" .-()".contains(b))))
    {
        return Err(ReceiptError::Corrupt);
    }
    let reason = c.field(4)?;
    if reason.len() != 1
        || reason[0] > super::IncompleteReason::ContextConflict as u8 + 1
        || (reason[0] == 0) != (coverage == Coverage::Complete)
    {
        return Err(ReceiptError::Corrupt);
    }
    for n in [
        30,
        super::MAX_ENTRIES,
        super::MAX_DEPTH as u64,
        super::MAX_PATH_BYTES as u64,
        super::MAX_FILE_BYTES,
        super::MAX_CHARGED_BYTES,
        super::MAX_OUTPUT_BYTES,
        96,
        1024 * 1024,
        8 * 1024 * 1024,
        32 * 1024,
        2,
        256,
        256 * 1024,
        128,
        super::TERMINAL_RESERVE,
        super::DIRECTORY_BUFFER_BYTES as u64,
        super::MAX_FILE_BYTES + 65536,
    ] {
        if c.number(5)? != n {
            return Err(ReceiptError::Corrupt);
        }
    }
    for _ in 0..15 {
        c.number(6)?;
    }
    let mut paths = std::collections::BTreeSet::new();
    while c.peek() == Some(15) {
        let flags = c.field(15)?;
        if flags.len() != 3 || flags.iter().any(|b| *b > 1) {
            return Err(ReceiptError::Corrupt);
        }
        let path =
            crate::disposal::RawPath::from_bytes(c.field(7)?).map_err(|_| ReceiptError::Corrupt)?;
        if !paths.insert(path) || paths.len() > super::MAX_ENTRIES as usize {
            return Err(ReceiptError::Corrupt);
        }
        let mode = u32::from_be_bytes(c.field(8)?.try_into().map_err(|_| ReceiptError::Corrupt)?);
        if !matches!(
            FileType::from_raw_mode(mode),
            FileType::RegularFile | FileType::Directory
        ) {
            return Err(ReceiptError::Corrupt);
        }
        c.number(9)?;
        let content = c.field(10)?;
        if !(content.is_empty() || content.len() == 32) {
            return Err(ReceiptError::Corrupt);
        }
        let matched = c.field(11)?;
        if !matched.is_empty()
            && (coverage == Coverage::Incomplete
                || matched.len() > 128
                || !policy_ids.contains(&text(matched)?))
        {
            return Err(ReceiptError::Corrupt);
        }
    }
    let mut previous = None;
    let mut findings = Vec::new();
    let mut count = 0usize;
    while c.peek() == Some(12) {
        let path = crate::disposal::RawPath::from_bytes(c.field(12)?)
            .map_err(|_| ReceiptError::Corrupt)?;
        let kind = c.field(13)?;
        if kind.len() != 1 || kind[0] > super::FindingKind::PolicyMismatch as u8 {
            return Err(ReceiptError::Corrupt);
        }
        let finding_kind = match kind[0] {
            0 => super::FindingKind::TrackedContent,
            1 => super::FindingKind::StagedChange,
            2 => super::FindingKind::Untracked,
            3 => super::FindingKind::IgnoredUnclassified,
            4 => super::FindingKind::PolicyMismatch,
            _ => return Err(ReceiptError::Corrupt),
        };
        findings.push(super::Finding {
            path: path.clone(),
            kind: finding_kind,
        });
        let key = (path, kind[0]);
        if previous.as_ref().is_some_and(|p| p >= &key) {
            return Err(ReceiptError::Corrupt);
        }
        previous = Some(key);
        count += 1;
        if count > 3 * super::MAX_ENTRIES as usize + 64 {
            return Err(ReceiptError::Corrupt);
        }
    }
    c.end()?;
    Ok((policy.digest(), findings))
}
fn decode(store: &Store, expected_id: Uuid, bytes: &[u8]) -> Result<ReceiptData> {
    if bytes.len() as u64 > MAX_RECEIPT {
        return Err(ReceiptError::Corrupt);
    }
    let mut c = Cursor::new(bytes);
    let approval_version = match c.field(0)? {
        b"work.inspection.receipt.v1" => false,
        b"work.inspection.receipt.v2" => true,
        _ => return Err(ReceiptError::Corrupt),
    };
    let id = uuid(c.field(1)?)?;
    if id != expected_id {
        return Err(ReceiptError::Corrupt);
    }
    let checkout = uuid(c.field(2)?)?;
    if c.field(3)? != authority_bytes(store) {
        return Err(ReceiptError::Corrupt);
    }
    let context = hash(c.field(4)?)?;
    let started = c.number(5)?;
    let ended = c.number(6)?;
    if started == 0 || ended < started {
        return Err(ReceiptError::Corrupt);
    }
    let coverage = match c.field(7)? {
        [1] => Coverage::Complete,
        [0] => Coverage::Incomplete,
        _ => return Err(ReceiptError::Corrupt),
    };
    let digest = hash(c.field(8)?)?;
    let body = c.field(9)?;
    if hash(&Sha256::digest(body))? != digest {
        return Err(ReceiptError::Corrupt);
    }
    let approval = if approval_version {
        if coverage != Coverage::Complete {
            return Err(ReceiptError::Corrupt);
        }
        Some(
            super::approval::ApprovalRecord::decode(c.field(11)?, id, context, started, ended)
                .map_err(|_| ReceiptError::Corrupt)?,
        )
    } else {
        None
    };
    let checksum_at = c.at;
    if hash(c.field(10)?)? != hash(&Sha256::digest(&bytes[..checksum_at]))? {
        return Err(ReceiptError::Corrupt);
    }
    c.end()?;
    let (policy_digest, findings) = body_metadata(body, coverage, context)?;
    if approval.is_some() && !findings.is_empty() {
        return Err(ReceiptError::Corrupt);
    }
    Ok(ReceiptData {
        id,
        checkout,
        digest,
        coverage,
        body: body.to_vec(),
        policy_digest,
        findings,
        approval,
    })
}

#[cfg(test)]
use crate as work_cli_api;
#[cfg(test)]
#[path = "../../tests/support/inspection_fixture.rs"]
mod fixture;

// Private journal seed only: never a public prepare capability.
#[cfg(test)]
pub(super) fn seed_collector_intent(store: &Store, checkout: Uuid) -> Uuid {
    use crate::retirement_journal::{encode_record, ImmutableBinding, IntentRecord, Mode, Stage};
    let operation = Uuid::now_v7();
    let digest = hex(&[1; 32]);
    let record = IntentRecord {
        version: 1,
        operation: operation.to_string(),
        checkout: checkout.to_string(),
        mode: Mode::Supervised,
        revision: 1,
        stage: Stage::Prepared,
        assertion: None,
        declaration: None,
        predecessor_hex: digest.clone(),
        source_hex: digest.clone(),
        history_predecessor_hex: digest.clone(),
        prior_history_count: 0,
        immutable_binding: ImmutableBinding {
            version: 1,
            authority_allocation: digest.clone(),
            source_sql: digest.clone(),
            managed_physical: digest.clone(),
            census: digest.clone(),
            git_private: digest.clone(),
            local_git: digest.clone(),
            git_inputs: digest.clone(),
            source_commitment: digest.clone(),
            approval_semantic: digest.clone(),
            approval_invalidation: digest.clone(),
            protection: digest.clone(),
            protection_count: 0,
            config_manifests: [digest.clone(), digest.clone()],
            inspection_policy: digest.clone(),
            combined_policy: digest.clone(),
            operator: digest.clone(),
            source_repository: digest.clone(),
        },
        quiescence: "empty".into(),
        task_completion: "supervised_empty".into(),
        policy_digest: digest.clone(),
        combined_policy_digest: digest,
        prepared_wall_ms: 1,
        remote_cleanup: "not_required".into(),
    };
    store.conn.execute(
        "INSERT INTO retirement_intents(operation,checkout,revision,stage,mode,predecessor,source,record) VALUES(?1,?2,1,'prepared','supervised',?3,?3,?4)",
        rusqlite::params![operation.to_string(), checkout.to_string(), [1u8; 32].as_slice(), encode_record(&record).unwrap()],
    ).unwrap();
    operation
}

#[cfg(test)]
pub(super) fn collector_source(store: &mut Store, checkout: Uuid) -> Vec<u8> {
    super::snapshot(store, checkout, &mut super::Budget::new())
        .unwrap()
        .source
}

#[cfg(test)]
pub(super) fn assert_collector_held(store: &Store, checkout: Uuid, attempt: &str) {
    let row: (String, i64, String) = store
        .conn
        .query_row(
            "SELECT stage,revision,held_reason FROM retirement_intents WHERE checkout=?1",
            [checkout.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(row, ("held".into(), 2, attempt.into()));
    let events = store
        .pending_events(1000)
        .unwrap()
        .into_iter()
        .filter(|p| {
            matches!(
                &p.event, crate::events::Event::RetirementIntentChanged { checkout: id, stage, .. }
                if *id == checkout && stage == "held"
            )
        })
        .count();
    assert_eq!(events, 1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    fn empty() -> crate::disposal::ValidatedPolicies {
        crate::disposal::validate(crate::disposal::PolicyDocument {
            format: 1,
            policies: vec![],
        })
        .unwrap()
    }
    fn directory(f: &fixture::ManagedFixture) -> std::path::PathBuf {
        f.temp.path().join("authority/inspection-receipts-v1")
    }
    fn finals(f: &fixture::ManagedFixture) -> usize {
        std::fs::read_dir(directory(f))
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .as_encoded_bytes()
                    .ends_with(b".receipt")
            })
            .count()
    }
    #[test]
    fn recorded_inspection_holds_before_collection_or_pending_files() {
        let mut f = fixture::ManagedFixture::new("sha1", "2");
        seed_collector_intent(&f.store, f.allocation.checkout);
        let before = collector_source(&mut f.store, f.allocation.checkout);
        for _ in 0..2 {
            let outcome =
                inspect_and_record(&mut f.store, f.allocation.checkout, &empty()).unwrap();
            assert_eq!(
                outcome.receipt.unwrap_err(),
                ReceiptError::RetirementIntentActive
            );
            assert_ne!(outcome.observation.coverage(), Coverage::Complete);
            assert_collector_held(&f.store, f.allocation.checkout, "receipt_publication");
            assert_eq!(
                before,
                collector_source(&mut f.store, f.allocation.checkout)
            );
            assert!(!directory(&f).exists());
        }
    }

    #[test]
    fn borrowed_wrong_checkout_or_authority_refuses_before_reservation() {
        let mut f = fixture::ManagedFixture::new("sha1", "2");
        let other = fixture::ManagedFixture::new("sha1", "2");
        for guard in [
            crate::checkout_guard::CheckoutGuard::shared(&f.store, Uuid::now_v7()).unwrap(),
            crate::checkout_guard::CheckoutGuard::shared(&other.store, f.allocation.checkout)
                .unwrap(),
        ] {
            let mut captured =
                super::super::collect(&mut f.store, f.allocation.checkout, &empty(), None).unwrap();
            assert_eq!(
                persist_under_guard(&mut f.store, &mut captured, &guard, Fault::None).unwrap_err(),
                ReceiptError::Conflict
            );
            assert!(!directory(&f).exists());
        }
    }

    #[test]
    fn approval_v2_uses_same_pending_capacity_failure_and_unknown_durability_protocol() {
        let f = fixture::ManagedFixture::new("sha1", "2");
        let (path, _) = f.approval();
        for fault in [
            Fault::Write,
            Fault::FileSync,
            Fault::Rename,
            Fault::DirectorySync,
        ] {
            let (mut store, mut sealed) =
                super::super::approval::collect_for_receipt_test(&path, f.allocation.checkout);
            let id = sealed.id();
            let result = publish(&mut store, Publication::SealedApproval(&mut sealed), fault);
            if fault == Fault::DirectorySync {
                assert!(
                    matches!(result,Err(ReceiptError::DurabilityUnknown { id: actual,.. }) if actual==id)
                );
                assert!(read_receipt(&store, id)
                    .unwrap()
                    .approval_record()
                    .is_some());
            } else {
                assert_eq!(result.unwrap_err(), ReceiptError::Io);
                assert!(matches!(
                    read_receipt(&store, id),
                    Err(ReceiptError::Missing)
                ));
            }
            assert!(matches!(
                crate::checkout_guard::CheckoutGuard::exclusive(&store, f.allocation.checkout),
                Err(crate::store::StoreError::OperationsInFlight)
            ));
            // Same reserved UUID cannot overwrite or retry into a renewed assertion.
            assert_eq!(
                publish_approval(&mut store, &mut sealed).unwrap_err(),
                ReceiptError::Conflict
            );
            drop(sealed);
            assert!(
                crate::checkout_guard::CheckoutGuard::exclusive(&store, f.allocation.checkout)
                    .is_ok()
            );
        }
        let (mut store, mut sealed) =
            super::super::approval::collect_for_receipt_test(&path, f.allocation.checkout);
        for _ in 0..7 {
            reserve(&store, Uuid::now_v7(), MAX_RECEIPT).unwrap();
        }
        // Fill the final remaining reservation with its exact declared free capacity.
        let location = Location::open(&store, false).unwrap();
        let total: u64 = std::fs::read_dir(directory(&f))
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let metadata = entry.metadata().unwrap();
                name_charge(entry.file_name().as_encoded_bytes(), metadata.len())
                    .unwrap()
                    .1
            })
            .sum();
        reserve(&store, Uuid::now_v7(), MAX_TOTAL - total).unwrap();
        assert_eq!(
            publish_approval(&mut store, &mut sealed).unwrap_err(),
            ReceiptError::CapacityFull
        );
        location.check(&store).unwrap();
    }
    #[test]
    fn v2_envelope_checksums_all_extension_bytes_without_changing_v1_decoder() {
        let f = fixture::ManagedFixture::new("sha1", "2");
        let (path, _) = f.approval();
        let (store, mut sealed) =
            super::super::approval::collect_for_receipt_test(&path, f.allocation.checkout);
        let id = sealed.id();
        let extension = sealed.extension().unwrap();
        let bytes = encode_envelope(&store, id, sealed.captured(), Some(&extension)).unwrap();
        assert!(decode(&store, id, &bytes)
            .unwrap()
            .approval_record()
            .is_some());
        let mut corrupt = bytes.clone();
        let at = corrupt
            .windows(extension.len())
            .position(|v| v == extension)
            .unwrap();
        corrupt[at + 1] ^= 1;
        assert!(matches!(
            decode(&store, id, &corrupt),
            Err(ReceiptError::Corrupt)
        ));
        for invalid in [b"{}".as_slice(), b"{\"kind\":\"unknown\"}"] {
            let corrupt = encode_envelope(&store, id, sealed.captured(), Some(invalid)).unwrap();
            assert!(matches!(
                decode(&store, id, &corrupt),
                Err(ReceiptError::Corrupt)
            ));
        }
        let v1 = encode(&store, id, sealed.captured()).unwrap();
        assert!(decode(&store, id, &v1).unwrap().approval_record().is_none());
        let mut duplicate = bytes.clone();
        duplicate.extend_from_slice(&bytes);
        assert!(matches!(
            decode(&store, id, &duplicate),
            Err(ReceiptError::Corrupt)
        ));
    }
    #[test]
    fn native_authority_metadata_and_readable_opens_share_bound_identity() {
        let f = fixture::ManagedFixture::new("sha1", "2");
        let parent = File::open(f.temp.path().join("authority")).unwrap();
        let authority = f.store.authority_identity();
        for (name, expected) in [
            ("store.sqlite", authority.database_id()),
            ("allocation.lock", authority.lock_id.unwrap()),
        ] {
            for flags in [OFlags::PATH, OFlags::RDONLY] {
                let file = open_relative(&parent, name, flags)
                    .unwrap_or_else(|error| panic!("{name} {flags:?}: {error:?}"));
                assert_eq!(identity(&stat(&file).unwrap()), expected);
            }
        }
        assert_eq!(
            identity(&stat(&open_authority(&f.store).unwrap()).unwrap()),
            authority.directory_id
        );
        let reservation = reserve(&f.store, Uuid::now_v7(), 20).unwrap();
        for flags in [
            OFlags::PATH | OFlags::DIRECTORY,
            OFlags::RDONLY | OFlags::DIRECTORY,
        ] {
            let dir = open_relative(&parent, DIRECTORY, flags)
                .unwrap_or_else(|error| panic!("receipt directory {flags:?}: {error:?}"));
            assert_eq!(
                identity(&stat(&dir).unwrap()),
                identity(&stat(&reservation.location.dir).unwrap())
            );
        }
        // These are real native descriptors, not a synthetic freshness proof.
        reservation.check(&f.store, false).unwrap();
    }
    #[test]
    fn original_context_conflict_leaves_charged_pending_no_final() {
        let mut f = fixture::ManagedFixture::new("sha1", "2");
        let mut captured =
            super::super::collect(&mut f.store, f.allocation.checkout, &empty(), None).unwrap();
        assert_eq!(captured.observation.coverage(), Coverage::Complete);
        f.store
            .conn
            .execute(
                "UPDATE checkouts SET owner='changed' WHERE id=?1",
                [f.allocation.checkout.to_string()],
            )
            .unwrap();
        assert_eq!(
            persist(&mut f.store, &mut captured, Fault::None).unwrap_err(),
            ReceiptError::Conflict
        );
        assert_eq!(finals(&f), 0);
        assert_eq!(std::fs::read_dir(directory(&f)).unwrap().count(), 1);
    }
    #[test]
    fn physical_change_is_not_reinspected_until_match() {
        let mut f = fixture::ManagedFixture::new("sha1", "2");
        let mut captured =
            super::super::collect(&mut f.store, f.allocation.checkout, &empty(), None).unwrap();
        std::fs::write(f.path(b"tracked"), b"changed").unwrap();
        assert_eq!(
            persist(&mut f.store, &mut captured, Fault::None).unwrap_err(),
            ReceiptError::Conflict
        );
        assert_eq!(finals(&f), 0);
    }
    #[test]
    fn failures_before_and_after_rename_report_truthful_durability() {
        for fault in [
            Fault::Write,
            Fault::FileSync,
            Fault::Rename,
            Fault::DirectorySync,
        ] {
            let mut f = fixture::ManagedFixture::new("sha1", "2");
            let mut captured =
                super::super::collect(&mut f.store, f.allocation.checkout, &empty(), None).unwrap();
            let result = persist(&mut f.store, &mut captured, fault);
            if fault == Fault::DirectorySync {
                let (id, digest) = match result {
                    Err(ReceiptError::DurabilityUnknown { id, digest }) => (id, digest),
                    other => panic!("must report uncertain publication, got {other:?}"),
                };
                assert_eq!(digest, captured.observation.digest());
                assert_eq!(read_receipt(&f.store, id).unwrap().digest(), digest);
                assert_eq!(finals(&f), 1);
            } else {
                assert_eq!(result.unwrap_err(), ReceiptError::Io);
                assert_eq!(finals(&f), 0);
                assert_eq!(std::fs::read_dir(directory(&f)).unwrap().count(), 1);
            }
        }
    }
    #[test]
    fn pending_declared_bytes_not_empty_length_and_atomic_contention() {
        let f = fixture::ManagedFixture::new("sha1", "2");
        // Seven real zero-length exclusive reservations leave exactly one slot
        // of bytes. Two contenders cannot both reserve it. No stress/timing gate.
        for _ in 0..7 {
            reserve(&f.store, Uuid::now_v7(), MAX_RECEIPT).unwrap();
        }
        let root = f.root.clone();
        let base = f.temp.path().to_path_buf();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let (root, base, barrier) = (root.clone(), base.clone(), barrier.clone());
                std::thread::spawn(move || {
                    let store = Store::open_existing_registered_mut(
                        &base.join("registry"),
                        &base.join("authority"),
                        &[root],
                    )
                    .unwrap();
                    barrier.wait();
                    reserve(&store, Uuid::now_v7(), MAX_RECEIPT).map(|_| ())
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            1,
            "{results:?}"
        );
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(ReceiptError::CapacityFull)))
                .count(),
            1,
            "{results:?}"
        );
        assert_eq!(std::fs::read_dir(directory(&f)).unwrap().count(), 8);
        assert_eq!(
            reserve(&f.store, Uuid::now_v7(), 1).err(),
            Some(ReceiptError::CapacityFull)
        );
    }
    #[test]
    fn unsafe_names_modes_links_lengths_and_duplicate_ids_refuse() {
        for shape in [
            "unknown",
            "mode",
            "symlink",
            "hardlink",
            "oversize",
            "zero",
            "noncanonical",
            "directory",
            "owner",
        ] {
            let f = fixture::ManagedFixture::new("sha1", "2");
            let reservation = reserve(&f.store, Uuid::now_v7(), 20).unwrap();
            let path = directory(&f).join(&reservation.pending);
            match shape {
                "unknown" => {
                    std::fs::write(directory(&f).join("junk"), b"").unwrap();
                }
                "mode" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
                }
                "symlink" => {
                    symlink(
                        &path,
                        directory(&f).join(format!("{}.receipt", Uuid::now_v7())),
                    )
                    .unwrap();
                }
                "hardlink" => {
                    std::fs::hard_link(
                        &path,
                        directory(&f).join(format!("{}.receipt", Uuid::now_v7())),
                    )
                    .unwrap();
                }
                "oversize" => reservation.file.set_len(21).unwrap(),
                "zero" => {
                    std::fs::rename(
                        &path,
                        directory(&f).join(format!("pending-{}-0", Uuid::now_v7())),
                    )
                    .unwrap();
                }
                "noncanonical" => {
                    std::fs::rename(
                        &path,
                        directory(&f).join(format!("pending-{}-020", Uuid::now_v7())),
                    )
                    .unwrap();
                }
                "directory" => {
                    std::fs::create_dir(directory(&f).join(format!("{}.receipt", Uuid::now_v7())))
                        .unwrap();
                }
                "owner" => {
                    // Pure validation of the observed owner field, never host chown.
                    let mut stat = rustix::fs::fstat(&reservation.file).unwrap();
                    stat.st_uid = stat.st_uid.wrapping_add(1);
                    assert!(validate_file(&stat).is_err());
                    continue;
                }
                _ => unreachable!(),
            }
            assert_eq!(
                reserve(&f.store, Uuid::now_v7(), 20).err(),
                Some(ReceiptError::UnsafeReceiptStore),
                "shape={shape}"
            );
        }
        let f = fixture::ManagedFixture::new("sha1", "2");
        let id = Uuid::now_v7();
        let r = reserve(&f.store, id, 20).unwrap();
        assert_eq!(
            reserve(&f.store, id, 21).err(),
            Some(ReceiptError::Conflict)
        );
        std::fs::rename(
            directory(&f).join(&r.pending),
            directory(&f).join(format!("{id}.receipt")),
        )
        .unwrap();
        // A zero-length final is unsafe, not available capacity.
        assert!(reserve(&f.store, id, 20).is_err());
    }
    #[test]
    fn replaced_reservation_or_directory_and_no_replace_publication_refuse() {
        let f = fixture::ManagedFixture::new("sha1", "2");
        let r = reserve(&f.store, Uuid::now_v7(), 20).unwrap();
        let path = directory(&f).join(&r.pending);
        std::fs::rename(&path, directory(&f).join("displaced")).unwrap();
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(r.check(&f.store, false).is_err());
        let old = directory(&f).with_extension("old");
        std::fs::rename(directory(&f), &old).unwrap();
        std::fs::create_dir(directory(&f)).unwrap();
        std::fs::set_permissions(directory(&f), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(r.location.check(&f.store).is_err());
        // Exercise the actual kernel NOREPLACE, with two exclusively created
        // reservations, not a preflight-only duplicate test.
        let f = fixture::ManagedFixture::new("sha1", "2");
        let a = reserve(&f.store, Uuid::now_v7(), 20).unwrap();
        let b = reserve(&f.store, Uuid::now_v7(), 20).unwrap();
        let before = b.file.metadata().unwrap().ino();
        assert!(rename_noreplace(&a.location.dir, &a.pending, &b.pending).is_err());
        assert_eq!(
            before,
            std::fs::metadata(directory(&f).join(&b.pending))
                .unwrap()
                .ino()
        );
    }
    #[test]
    fn strict_envelope_rejects_rechecksummed_header_policy_and_body_changes() {
        let mut f = fixture::ManagedFixture::new("sha1", "2");
        let captured =
            super::super::collect(&mut f.store, f.allocation.checkout, &empty(), None).unwrap();
        let id = Uuid::now_v7();
        let bytes = encode(&f.store, id, &captured).unwrap();
        assert!(decode(&f.store, id, &bytes).is_ok());
        for tag in [4, 7, 8, 9] {
            let mut damaged = bytes.clone();
            let mut cursor = Cursor::new(&bytes);
            let mut changed = false;
            while !cursor.done() {
                let start = cursor.at;
                let (current, value) = cursor.any().unwrap();
                if current == tag {
                    damaged[start + 9 + value.len() - 1] ^= 1;
                    changed = true;
                    break;
                }
            }
            assert!(changed);
            let checksum_at = damaged.len() - 41;
            let checksum = Sha256::digest(&damaged[..checksum_at]);
            damaged[checksum_at + 9..].copy_from_slice(&checksum);
            assert!(decode(&f.store, id, &damaged).is_err());
        }
        assert!(decode(&f.store, Uuid::now_v7(), &bytes).is_err());
        assert!(decode(&f.store, id, &bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode(&f.store, id, &trailing).is_err());
    }
    #[test]
    fn passive_policy_decoder_checks_versions_and_canonical_order() {
        let validated = crate::disposal::validate(crate::disposal::PolicyDocument {
            format: 1,
            policies: vec![crate::disposal::Policy {
                id: "cache".into(),
                version: "v1".into(),
                scope: "6361636865".into(),
                max_files: 0,
                max_file_bytes: 0,
                max_total_bytes: 0,
                files: vec![],
                directories: vec!["6361636865".into()],
            }],
        })
        .unwrap();
        assert_eq!(
            policy(validated.canonical_bytes()).unwrap().0.digest(),
            validated.digest()
        );
        for target in [1, 2, 6] {
            let mut bytes = validated.canonical_bytes().to_vec();
            let mut cursor = Cursor::new(validated.canonical_bytes());
            while !cursor.done() {
                let start = cursor.at;
                let (tag, value) = cursor.any().unwrap();
                if tag == target {
                    bytes[start + 9 + value.len() - 1] = b'+';
                    break;
                }
            }
            assert!(policy(&bytes).is_err());
        }
        let mut trailing = validated.canonical_bytes().to_vec();
        frame(&mut trailing, 99, b"unknown");
        assert!(policy(&trailing).is_err());
    }
    #[test]
    fn finite_admission_edges_and_final_bytes_are_charged() {
        assert!(admit(4095, MAX_TOTAL - 1, 1).is_ok());
        assert!(matches!(admit(4096, 0, 1), Err(ReceiptError::CapacityFull)));
        assert!(matches!(
            admit(0, MAX_TOTAL, 1),
            Err(ReceiptError::CapacityFull)
        ));
        assert!(matches!(
            admit(0, u64::MAX, 1),
            Err(ReceiptError::CapacityFull)
        ));
        let id = Uuid::now_v7();
        assert_eq!(
            name_charge(format!("{id}.receipt").as_bytes(), 321)
                .unwrap()
                .1,
            321
        );
        assert_eq!(
            name_charge(format!("pending-{id}-321").as_bytes(), 0)
                .unwrap()
                .1,
            321
        );
        assert_eq!(
            name_charge(format!("pending-{id}-321").as_bytes(), 320)
                .unwrap()
                .1,
            321
        );
        assert!(name_charge(format!("pending-{id}-321").as_bytes(), 322).is_err());
    }
    #[test]
    fn original_deadline_is_not_reset_for_recording() {
        let mut f = fixture::ManagedFixture::new("sha1", "2");
        let mut captured =
            super::super::collect(&mut f.store, f.allocation.checkout, &empty(), None).unwrap();
        captured.budget.test_elapsed = Some(std::time::Duration::from_secs(31));
        assert_eq!(
            persist(&mut f.store, &mut captured, Fault::None).unwrap_err(),
            ReceiptError::Conflict
        );
        assert!(!directory(&f).exists());
    }
    #[test]
    fn active_sql_refused_before_receipt_io() {
        let f = fixture::ManagedFixture::new("sha1", "2");
        let _phase = f.store.sql_phase();
        assert!(reserve(&f.store, Uuid::now_v7(), 20).is_err());
        assert!(!directory(&f).exists());
        assert!(matches!(
            read_receipt(&f.store, Uuid::now_v7()),
            Err(ReceiptError::Busy)
        ));
        drop(_phase);
        let transaction = f.store.conn.unchecked_transaction().unwrap();
        assert!(reserve(&f.store, Uuid::now_v7(), 20).is_err());
        assert!(!directory(&f).exists());
        transaction.rollback().unwrap();
    }
}
