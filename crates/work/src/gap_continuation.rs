//! Private required-Gap continuation metadata. Decoded records are never live authority.
use crate::store::{Result, StoreError};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
const MAX_RECORD: usize = 2 * 1024 * 1024;

pub(crate) const SCHEMA: &str = "CREATE TABLE gap_qualifications(run TEXT PRIMARY KEY REFERENCES attribution_gaps(run), checkout TEXT NOT NULL REFERENCES checkouts(id), record TEXT NOT NULL, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32), successor_run TEXT UNIQUE REFERENCES attribution_gaps(run), successor_revision INTEGER, CHECK((successor_run IS NULL AND successor_revision IS NULL) OR (successor_run IS NOT NULL AND successor_revision IS NOT NULL AND successor_revision>0))); CREATE INDEX gap_qualifications_checkout ON gap_qualifications(checkout); CREATE TABLE gap_eligibility(checkout TEXT PRIMARY KEY REFERENCES checkouts(id), latest_run TEXT NOT NULL UNIQUE REFERENCES attribution_gaps(run), revision INTEGER NOT NULL CHECK(revision>0), disposition TEXT NOT NULL CHECK(disposition IN ('unavailable','awaiting_qualification','available','blocked')), qualification TEXT REFERENCES gap_qualifications(run), CHECK((disposition='available' AND qualification IS NOT NULL) OR (disposition<>'available' AND qualification IS NULL))); PRAGMA user_version=15;";

pub(crate) fn validate_schema(conn: &Connection) -> Result<()> {
    // Native schema15 stores these exact CREATE statements. Compare their
    // bytes, including quoted identifiers, literal contents and escapes; SQL
    // case/whitespace normalization inside quotes changes CHECK semantics.
    for ((name, kind), expected) in [
        ("gap_qualifications", "table"),
        ("gap_qualifications_checkout", "index"),
        ("gap_eligibility", "table"),
    ]
    .into_iter()
    .zip(SCHEMA.split(';'))
    {
        let ddl: String = conn.query_row(
            "SELECT sql FROM sqlite_schema WHERE name=?1 AND type=?2",
            (name, kind),
            |r| r.get(0),
        )?;
        if ddl != expected.trim() {
            return Err(StoreError::Invalid);
        }
    }
    // Include the implicit primary-key/unique indices and reject additional
    // partial/expression/declared indices rather than merely selecting columns.
    for (table, expected) in [
        (
            "gap_qualifications",
            vec![("c", false), ("pk", true), ("u", true)],
        ),
        ("gap_eligibility", vec![("pk", true), ("u", true)]),
    ] {
        let mut stmt = conn.prepare(&format!("PRAGMA index_list({table})"))?;
        let mut indices = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(3)?,
                    r.get::<_, bool>(2)?,
                    r.get::<_, bool>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        indices.sort();
        let expected = expected
            .into_iter()
            .map(|(origin, unique)| (origin.to_owned(), unique, false))
            .collect::<Vec<_>>();
        if indices != expected {
            return Err(StoreError::Invalid);
        }
    }
    Ok(())
}

/// Metadata-only Gap physical inspection against an actually admitted baseline.
/// Callers retain their original operation Instant across both observations and
/// contention; this local bound never extends that caller's proof lifetime.
pub(crate) fn inspect_physical(
    allocation: &crate::allocate::Allocation,
    charged_common: &std::path::Path,
    baseline: &crate::capture_setup::Physical,
    anchor: &str,
) -> Result<crate::capture_setup::Physical> {
    use std::os::unix::fs::MetadataExt;
    let observed = std::time::Instant::now();
    let source = allocation
        .request
        .repository
        .as_ref()
        .ok_or(StoreError::Invalid)?;
    let prior = allocation.identity.as_ref().ok_or(StoreError::Invalid)?;
    if baseline.directories.len() != 4 {
        return Err(StoreError::Invalid);
    }
    let mut directories = Vec::with_capacity(4);
    for (path, expected) in [
        source,
        &prior.path,
        &prior.private_git_dir,
        &prior.common_git_dir,
    ]
    .into_iter()
    .zip(&baseline.directories)
    {
        crate::config::validate_path(path, true).map_err(|_| StoreError::Unsafe)?;
        let metadata = std::fs::symlink_metadata(path)?;
        let actual = (metadata.dev(), metadata.ino());
        if !metadata.is_dir() || metadata.file_type().is_symlink() || actual != *expected {
            return Err(StoreError::Conflict);
        }
        directories.push(actual);
    }
    let checkout = crate::recovery::verify_gap(allocation)?;
    let common = crate::allocate::verify_source_authority(allocation, charged_common)?;
    let marker = crate::recovery::gap_metadata(&checkout.private_git_dir.join("work-lease.json"))?;
    if checkout.common_git_dir != common
        || checkout.private_git_dir == checkout.common_git_dir
        || checkout.path != baseline.checkout.path
        || checkout.private_git_dir != baseline.checkout.private_git_dir
        || checkout.common_git_dir != baseline.checkout.common_git_dir
        || checkout.directory != baseline.checkout.directory
        || checkout.boot_id != baseline.checkout.boot_id
        || marker != baseline.marker
    {
        return Err(StoreError::Conflict);
    }
    // Immutable object names only; never let a branch, replacement, tag or
    // unresolved/lazily fetched object stand in for either ancestry anchor.
    for object in [prior.head.as_str(), checkout.head.as_str(), anchor] {
        if !matches!(object.len(), 40 | 64)
            || !object
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || crate::identity::query(
                &checkout.path,
                &["rev-parse", &format!("{object}^{{commit}}")],
            )?
            .as_str()
                != object
        {
            return Err(StoreError::Invalid);
        }
    }
    for parent in [prior.head.as_str(), anchor] {
        crate::identity::query(
            &checkout.path,
            &["merge-base", "--is-ancestor", parent, &checkout.head],
        )?;
    }
    if observed.elapsed() > std::time::Duration::from_secs(2) {
        return Err(StoreError::Conflict);
    }
    Ok(crate::capture_setup::Physical {
        checkout,
        directories,
        marker,
    })
}

pub(crate) fn raw_presence(conn: &Connection, checkout: uuid::Uuid) -> Result<bool> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 15 {
        return Ok(false);
    }
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM gap_eligibility WHERE checkout=?1) OR EXISTS(SELECT 1 FROM gap_qualifications WHERE checkout=?1)",
        [checkout.to_string()], |r| r.get(0),
    )?)
}

/// Authority-wide structural checks never decode unrelated payload JSON.
pub(crate) fn validate_raw(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 15 {
        return Ok(());
    }
    let invalid: bool = conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM gap_eligibility e
            LEFT JOIN checkouts c ON c.id=e.checkout
            LEFT JOIN attribution_gaps a ON a.run=e.latest_run
            LEFT JOIN gap_qualifications q ON q.run=e.qualification
            WHERE c.id IS NULL OR a.run IS NULL OR a.checkout<>e.checkout
            OR typeof(e.revision)<>'integer' OR e.revision<=0
            OR e.disposition NOT IN ('unavailable','awaiting_qualification','available','blocked')
            OR (e.disposition='available' AND (q.run IS NULL OR q.run<>e.latest_run OR q.checkout<>e.checkout))
            OR (e.disposition<>'available' AND e.qualification IS NOT NULL)
        ) OR EXISTS(
            SELECT 1 FROM gap_qualifications q
            LEFT JOIN attribution_gaps a ON a.run=q.run
            LEFT JOIN checkouts c ON c.id=q.checkout
            LEFT JOIN gap_eligibility e ON e.checkout=q.checkout
            LEFT JOIN attribution_gaps s ON s.run=q.successor_run
            WHERE a.run IS NULL OR c.id IS NULL OR e.checkout IS NULL OR a.checkout<>q.checkout
            OR typeof(q.fingerprint)<>'blob' OR length(q.fingerprint)<>32
            OR typeof(q.record)<>'text' OR length(CAST(q.record AS BLOB))>2097152
            OR (q.successor_run IS NULL)<>(q.successor_revision IS NULL)
            OR (q.successor_run IS NOT NULL AND (s.run IS NULL OR s.checkout<>q.checkout
                OR typeof(q.successor_revision)<>'integer' OR q.successor_revision<=0))
        )", [], |r| r.get(0),
    )?;
    if invalid {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedAuthority {
    registry: PathBuf,
    directory: PathBuf,
    directory_id: (u64, u64),
    database_id: (u64, u64),
    lock_id: (u64, u64),
}
impl RecordedAuthority {
    fn from_cache(authority: &crate::store::AuthorityIdentity) -> Result<Self> {
        Ok(Self {
            registry: authority.registry().into(),
            directory: authority.directory.clone(),
            directory_id: authority.directory_id,
            database_id: authority.database_id(),
            lock_id: authority.lock_id.ok_or(StoreError::Invalid)?,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Qualification {
    format_version: u32,
    run: String,
    group: String,
    checkout: String,
    admission_revision: i64,
    close_revision: i64,
    publication_revision: i64,
    authority: RecordedAuthority,
    context_digest: [u8; 32],
    frontier: [u8; 32],
    boot: String,
    actor: String,
    destination: crate::attribution_gap::Destination,
    allocation_anchor: String,
    source_path: PathBuf,
    physical: crate::capture_setup::Physical,
}
fn canonical_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .to_str()
            .is_some_and(|s| !s.chars().any(char::is_control))
        && !path.components().any(|c| {
            matches!(
                c,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str()
}
fn object_name(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn encode_qualification(q: &Qualification) -> Result<String> {
    let text = serde_json::to_string(q).map_err(|_| StoreError::Invalid)?;
    if text.len() > MAX_RECORD {
        return Err(StoreError::Invalid);
    }
    Ok(text)
}
fn decode_qualification(bytes: &str, fingerprint: &[u8]) -> Result<Qualification> {
    #[cfg(test)]
    history_count(0);
    if bytes.len() > MAX_RECORD || Sha256::digest(bytes.as_bytes()).as_slice() != fingerprint {
        return Err(StoreError::Invalid);
    }
    let q: Qualification = serde_json::from_str(bytes).map_err(|_| StoreError::Invalid)?;
    if encode_qualification(&q)? != bytes
        || q.format_version != 1
        || q.admission_revision <= 0
        || q.admission_revision.checked_add(1) != Some(q.close_revision)
        || q.close_revision.checked_add(1) != Some(q.publication_revision)
        || !canonical_path(&q.authority.registry)
        || !canonical_path(&q.authority.directory)
        || !canonical_path(&q.source_path)
        || !object_name(&q.allocation_anchor)
        || !object_name(&q.physical.checkout.head)
        || q.physical.directories.len() != 4
    {
        return Err(StoreError::Invalid);
    }
    for id in [&q.run, &q.group, &q.checkout] {
        let parsed = uuid::Uuid::parse_str(id).map_err(|_| StoreError::Invalid)?;
        if parsed.get_version_num() != 7
            || parsed.get_variant() != uuid::Variant::RFC4122
            || parsed.to_string() != *id
        {
            return Err(StoreError::Invalid);
        }
    }
    for path in [
        &q.physical.checkout.path,
        &q.physical.checkout.private_git_dir,
        &q.physical.checkout.common_git_dir,
    ] {
        if !canonical_path(path) {
            return Err(StoreError::Invalid);
        }
    }
    q.destination.validate()?;
    Ok(q)
}
struct HashWriter(Sha256);
impl std::io::Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn json_digest(domain: &[u8], value: &impl Serialize) -> Result<[u8; 32]> {
    let mut writer = HashWriter(Sha256::new());
    writer.0.update(domain);
    serde_json::to_writer(&mut writer, value).map_err(|_| StoreError::Invalid)?;
    Ok(writer.0.finalize().into())
}
fn uuid_bytes(value: &impl ToString) -> Result<[u8; 16]> {
    Ok(*uuid::Uuid::parse_str(&value.to_string())
        .map_err(|_| StoreError::Invalid)?
        .as_bytes())
}
fn frontier_seed(gap: &crate::attribution_gap::GapRecord) -> Result<[u8; 32]> {
    let allocation = gap.allocation()?;
    let mut hash = Sha256::new();
    hash.update(b"work.required-gap.frontier.v1\0");
    hash.update(allocation.checkout.as_bytes());
    hash.update(json_digest(
        b"work.required-gap.allocation.v1\0",
        &allocation,
    )?);
    Ok(hash.finalize().into())
}
fn fold_node(
    previous: [u8; 32],
    root: &crate::run_journal::RunRecord,
    gap: &crate::attribution_gap::GapRecord,
) -> Result<[u8; 32]> {
    #[cfg(test)]
    history_count(2);
    use crate::run_journal::{RootOutcome, RunStage};
    use crate::run_participants::{ChildOutcome, Enrollment};
    let mut children = root.children.iter().collect::<Vec<_>>();
    children.sort_by_key(|c| c.request.run.to_string());
    let mut roster = Sha256::new();
    roster.update(b"work.required-gap.roster.v1\0");
    for child in children {
        if root.closed
            && (child.host.is_none()
                || child.outcome.is_none()
                || child.enrollment != Enrollment::Contained)
        {
            return Err(StoreError::Invalid);
        }
        roster.update(uuid_bytes(&child.request.run)?);
        roster.update(json_digest(
            b"work.required-gap.child-request.v1\0",
            &child.request,
        )?);
        roster.update([match child.enrollment {
            Enrollment::Pending => 0,
            Enrollment::Contained => 1,
            Enrollment::Unverified => 2,
        }]);
        roster.update(json_digest(b"work.required-gap.host.v1\0", &child.host)?);
        roster.update([
            match child.outcome {
                None => 0,
                Some(ChildOutcome::Completed) => 1,
                Some(ChildOutcome::Failed) => 2,
                Some(ChildOutcome::Cancelled) => 3,
                Some(ChildOutcome::Interrupted) => 4,
            },
            child.depth,
        ]);
    }
    let mut hash = Sha256::new();
    hash.update(b"work.required-gap.frontier-node.v1\0");
    hash.update(previous);
    hash.update(gap.fingerprint()?);
    hash.update(uuid_bytes(&root.request.identity().run)?);
    hash.update(uuid_bytes(&root.request.identity().group)?);
    hash.update(gap.request_digest());
    hash.update([match root.stage {
        RunStage::Intent => 0,
        RunStage::Bound => 1,
        RunStage::PermitAttempt => 2,
    }]);
    hash.update(json_digest(
        b"work.required-gap.binding.v1\0",
        &root.binding,
    )?);
    hash.update([
        match root.outcome {
            None => 0,
            Some(RootOutcome::Completed) => 1,
            Some(RootOutcome::Failed) => 2,
            Some(RootOutcome::Cancelled) => 3,
        },
        u8::from(root.closed),
        u8::from(root.recovery_hold),
    ]);
    hash.update(root.revision.to_be_bytes());
    hash.update(roster.finalize());
    Ok(hash.finalize().into())
}
fn validate_qualification(
    q: &Qualification,
    root: &crate::run_journal::RunRecord,
    gap: &crate::attribution_gap::GapRecord,
    frontier: [u8; 32],
    admission: i64,
) -> Result<()> {
    let allocation = gap.allocation()?;
    let prior = allocation.identity.as_ref().ok_or(StoreError::Invalid)?;
    let marker: crate::recovery::Marker =
        serde_json::from_slice(&q.physical.marker).map_err(|_| StoreError::Invalid)?;
    if !root.closed
        || root.recovery_hold
        || root.outcome.is_none()
        || root.binding.is_none()
        || q.run != root.request.identity().run.to_string()
        || q.group != root.request.identity().group.to_string()
        || q.checkout != root.request.identity().checkout.to_string()
        || q.admission_revision != admission
        || q.context_digest != gap.context_digest()?
        || q.frontier != frontier
        || q.boot != root.request.input().boot
        || q.boot != prior.boot_id
        || q.actor != gap.actor()
        || Some(&q.destination) != gap.destination()
        || q.allocation_anchor != prior.head
        || Some(&q.source_path) != allocation.request.repository.as_ref()
        || q.physical.checkout.path != prior.path
        || q.physical.checkout.private_git_dir != prior.private_git_dir
        || q.physical.checkout.common_git_dir != prior.common_git_dir
        || q.physical.checkout.directory != prior.directory
        || q.physical.checkout.boot_id != q.boot
        || q.physical.directories[1] != (prior.directory.device, prior.directory.inode)
        || q.physical.checkout.private_git_dir == q.physical.checkout.common_git_dir
        || marker != crate::recovery::Marker::from(&allocation)
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

/// Consumes the sole Changed-close seal. All filesystem/registry observations,
/// candidate bytes and their fingerprint are prepared before acquiring a lease.
pub(crate) fn publish(config: &crate::config::Config, seal: GapClosureSeal) -> Result<()> {
    let mut store = crate::store::Store::open_existing_registered_mut(
        config
            .trusted_registry
            .as_deref()
            .ok_or(StoreError::Invalid)?,
        config.store_dir.as_deref().ok_or(StoreError::Invalid)?,
        &config.roots,
    )?;
    if store.authority_identity().as_ref() != seal.context.authority() {
        return Err(StoreError::Conflict);
    }
    let observed = Instant::now();
    let fresh = || {
        if observed.elapsed() <= Duration::from_secs(2) {
            Ok(())
        } else {
            Err(StoreError::Conflict)
        }
    };
    let physical = seal.context.inspect()?;
    #[cfg(test)]
    observe_publication("before_second_physical");
    if seal.context.inspect()? != physical {
        return Err(StoreError::Conflict);
    }
    fresh()?;
    let gap = seal.context.record();
    let allocation = gap.allocation()?;
    let frontier = fold_node(seal.prefix, &seal.closed, gap)?;
    let q = Qualification {
        format_version: 1,
        run: seal.closed.request.identity().run.to_string(),
        group: seal.closed.request.identity().group.to_string(),
        checkout: seal.closed.request.identity().checkout.to_string(),
        admission_revision: seal
            .close_revision
            .checked_sub(1)
            .ok_or(StoreError::Invalid)?,
        close_revision: seal.close_revision,
        publication_revision: seal
            .close_revision
            .checked_add(1)
            .ok_or(StoreError::Invalid)?,
        authority: RecordedAuthority::from_cache(seal.context.authority())?,
        context_digest: gap.context_digest()?,
        frontier,
        boot: seal.closed.request.input().boot.clone(),
        actor: gap.actor().into(),
        destination: gap.destination().ok_or(StoreError::Invalid)?.clone(),
        allocation_anchor: allocation
            .identity
            .as_ref()
            .ok_or(StoreError::Invalid)?
            .head
            .clone(),
        source_path: allocation
            .request
            .repository
            .clone()
            .ok_or(StoreError::Invalid)?,
        physical,
    };
    let bytes = encode_qualification(&q)?;
    let fingerprint: [u8; 32] = Sha256::digest(bytes.as_bytes()).into();
    #[cfg(test)]
    observe_publication("before_lease");
    let lease = store.authority_lease()?;
    lease.check(&store)?;
    let authority = store.authority_identity().clone();
    {
        let _phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        lease.check_authority(&authority)?;
        let checkout = uuid::Uuid::parse_str(&q.checkout).map_err(|_| StoreError::Invalid)?;
        let tx = crate::retirement_journal::fence(
            tx,
            &lease,
            &authority,
            crate::retirement_journal::Scope::Checkout(checkout),
            crate::retirement_journal::Attempt::GapPublication,
        )?;
        fresh()?;
        with_history(&tx, checkout, |history| {
            if history
                .nodes
                .last()
                .is_none_or(|(root, record)| root != &seal.closed || record.as_ref() != Some(gap))
                || history.frontier != Some(q.frontier)
                || history.tail_prefix != Some(seal.prefix)
            {
                return Err(StoreError::Conflict);
            }
            Ok(())
        })?;
        let eligible: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM gap_eligibility WHERE checkout=?1 AND latest_run=?2 AND revision=?3 AND disposition='awaiting_qualification' AND qualification IS NULL)
             AND NOT EXISTS(SELECT 1 FROM writers WHERE checkout=?1)
             AND NOT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1)
             AND NOT EXISTS(SELECT 1 FROM capture_runs WHERE checkout=?1)
             AND NOT EXISTS(SELECT 1 FROM capture_readiness WHERE checkout=?1)
             AND NOT EXISTS(SELECT 1 FROM adopted_groups WHERE checkout=?1)",
            rusqlite::params![q.checkout, q.run, q.close_revision], |r| r.get(0))?;
        if !eligible || !seal.context.matches_closed(&tx, &seal.closed.request)? {
            return Err(StoreError::Conflict);
        }
        if tx.execute(
            "INSERT INTO gap_qualifications(run,checkout,record,fingerprint) VALUES(?1,?2,?3,?4)",
            rusqlite::params![q.run, q.checkout, bytes, fingerprint.as_slice()],
        )? != 1
        {
            return Err(StoreError::Conflict);
        }
        if tx.execute("UPDATE gap_eligibility SET revision=?3,disposition='available',qualification=?2 WHERE checkout=?1 AND latest_run=?2 AND revision=?4 AND disposition='awaiting_qualification' AND qualification IS NULL", rusqlite::params![q.checkout,q.run,q.publication_revision,q.close_revision])? != 1 { return Err(StoreError::Conflict); }
        fresh()?;
        tx.commit()?;
    }
    drop(lease);
    #[cfg(test)]
    observe_publication("after_commit");
    #[cfg(test)]
    if PUBLICATION_ACK_LOSS.with(|s| s.replace(false)) {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

#[cfg(test)]
thread_local! { static PUBLICATION_ACK_LOSS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
pub(crate) fn lose_publication_ack() {
    PUBLICATION_ACK_LOSS.with(|s| s.set(true));
}

#[cfg(test)]
type PublicationObserver = Box<dyn FnMut(&str)>;
#[cfg(test)]
thread_local! { static PUBLICATION_OBSERVER: std::cell::RefCell<Option<PublicationObserver>> = const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
pub(crate) struct PublicationObserverGuard;
#[cfg(test)]
impl Drop for PublicationObserverGuard {
    fn drop(&mut self) {
        PUBLICATION_OBSERVER.with(|s| *s.borrow_mut() = None);
    }
}
#[cfg(test)]
pub(crate) fn observing_publication(
    observer: impl FnMut(&str) + 'static,
) -> PublicationObserverGuard {
    PUBLICATION_OBSERVER.with(|s| *s.borrow_mut() = Some(Box::new(observer)));
    PublicationObserverGuard
}
#[cfg(test)]
fn observe_publication(stage: &str) {
    PUBLICATION_OBSERVER.with(|s| {
        if let Some(observer) = s.borrow_mut().as_mut() {
            observer(stage);
        }
    });
}

#[cfg(test)]
thread_local! { static HISTORY_COUNTS: std::cell::Cell<[usize; 3]> = const { std::cell::Cell::new([0; 3]) }; }
#[cfg(test)]
fn history_count(index: usize) {
    HISTORY_COUNTS.with(|s| {
        let mut counts = s.get();
        counts[index] += 1;
        s.set(counts);
    });
}
#[cfg(test)]
pub(crate) fn take_history_counts() -> (usize, usize, usize, usize) {
    let [q, claims, folds] = HISTORY_COUNTS.with(|s| s.replace([0; 3]));
    (take_decoded_nodes(), q, claims, folds)
}

#[cfg(test)]
thread_local! { static DECODED_NODES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(crate) fn decoded_node() {
    DECODED_NODES.with(|n| n.set(n.get() + 1));
}
#[cfg(test)]
pub(crate) fn take_decoded_nodes() -> usize {
    DECODED_NODES.with(|n| n.replace(0))
}

struct Cursor {
    latest: String,
    revision: i64,
    disposition: String,
    qualification: Option<String>,
}
struct QualifiedNode {
    record: Qualification,
    fingerprint: [u8; 32],
    successor: Option<(String, i64)>,
}
pub(crate) struct History {
    pub(crate) nodes: Vec<(
        crate::run_journal::RunRecord,
        Option<crate::attribution_gap::GapRecord>,
    )>,
    cursor: Option<Cursor>,
    qualifications: std::collections::HashMap<String, QualifiedNode>,
    frontier: Option<[u8; 32]>,
    tail_prefix: Option<[u8; 32]>,
    tail_admission: Option<i64>,
}
impl History {
    fn untracked(
        nodes: Vec<(
            crate::run_journal::RunRecord,
            Option<crate::attribution_gap::GapRecord>,
        )>,
    ) -> Self {
        Self {
            nodes,
            cursor: None,
            qualifications: Default::default(),
            frontier: None,
            tail_prefix: None,
            tail_admission: None,
        }
    }
}

fn same_non_head(a: &crate::capture_setup::Physical, b: &crate::capture_setup::Physical) -> bool {
    a.checkout.path == b.checkout.path
        && a.checkout.private_git_dir == b.checkout.private_git_dir
        && a.checkout.common_git_dir == b.checkout.common_git_dir
        && a.checkout.directory == b.checkout.directory
        && a.checkout.boot_id == b.checkout.boot_id
        && a.directories == b.directories
        && a.marker == b.marker
}

/// Transaction-local view. Owned metadata may escape for observations; this
/// witness itself is usable only on this actual transaction/checkout pre-write.
pub(crate) struct Related<'tx, 'conn> {
    tx: &'tx rusqlite::Transaction<'conn>,
    checkout: uuid::Uuid,
    history: History,
}
impl<'tx, 'conn> Related<'tx, 'conn> {
    pub(crate) fn qualify(
        tx: &'tx rusqlite::Transaction<'conn>,
        checkout: uuid::Uuid,
    ) -> Result<Self> {
        with_history(tx, checkout, |history| {
            Ok(Self {
                tx,
                checkout,
                history,
            })
        })
    }
    pub(crate) fn check(&self, conn: &Connection, checkout: uuid::Uuid) -> Result<()> {
        if !std::ptr::eq(&**self.tx, conn) || self.checkout != checkout {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn history(&self) -> &History {
        &self.history
    }
}

/// Only inspect_continuation constructs this fresh purpose proof. Q decoding
/// supplies metadata, not this proof or a live writer/launch capability.
pub(crate) struct ContinuationProof {
    link: Continuation,
    predecessor: Qualification,
    frontier: [u8; 32],
    physical: crate::capture_setup::Physical,
    observed: Instant,
    run: String,
}
impl std::fmt::Debug for ContinuationProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContinuationProof([redacted])")
    }
}
pub(crate) fn inspect_continuation(
    store: &crate::store::Store,
    root: &crate::run_journal::RootRunRequest,
    destination: &crate::attribution_gap::Destination,
    allocation: &crate::allocate::Allocation,
    charged_common: &Path,
) -> Result<ContinuationProof> {
    let checkout = allocation.checkout;
    let (q, fingerprint, frontier) = {
        let _phase = store.sql_phase();
        with_history(&store.conn, checkout, |mut history| {
            let cursor = history.cursor.as_ref().ok_or(StoreError::Invalid)?;
            if cursor.disposition != "available" || history.nodes.iter().any(|(r, _)| !r.closed) {
                return Err(StoreError::Invalid);
            }
            let q = history
                .qualifications
                .remove(&cursor.latest)
                .ok_or(StoreError::Invalid)?;
            if q.successor.is_some()
                || q.record.authority != RecordedAuthority::from_cache(store.authority_identity())?
                || q.record.boot != root.input().boot
                || q.record.actor != root.identity().actor.as_str()
                || &q.record.destination != destination
            {
                return Err(StoreError::Conflict);
            }
            Ok((
                q.record,
                q.fingerprint,
                history.frontier.ok_or(StoreError::Invalid)?,
            ))
        })?
    };
    let observed = Instant::now();
    let physical = inspect_physical(
        allocation,
        charged_common,
        &q.physical,
        &q.physical.checkout.head,
    )?;
    let link = Continuation {
        predecessor: q.run.clone(),
        fingerprint,
        publication_revision: q.publication_revision as u64,
        admission_revision: q
            .publication_revision
            .checked_add(1)
            .ok_or(StoreError::Invalid)? as u64,
    };
    link.validate()?;
    let proof = ContinuationProof {
        link,
        predecessor: q,
        frontier,
        physical,
        observed,
        run: root.identity().run.to_string(),
    };
    proof.fresh()?;
    Ok(proof)
}
impl ContinuationProof {
    fn fresh(&self) -> Result<()> {
        if self.observed.elapsed() > Duration::from_secs(2) {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn link(&self) -> &Continuation {
        &self.link
    }
    pub(crate) fn physical(&self) -> &crate::capture_setup::Physical {
        &self.physical
    }
    pub(crate) fn reinspect(
        &self,
        allocation: &crate::allocate::Allocation,
        charged_common: &Path,
    ) -> Result<()> {
        if inspect_physical(
            allocation,
            charged_common,
            &self.predecessor.physical,
            &self.predecessor.physical.checkout.head,
        )? != self.physical
        {
            return Err(StoreError::Conflict);
        }
        self.fresh()
    }
    pub(crate) fn validate(
        &self,
        related: &Related<'_, '_>,
        root: &crate::run_journal::RootRunRequest,
        authority: &crate::store::AuthorityIdentity,
    ) -> Result<()> {
        self.fresh()?;
        related.check(
            related.tx,
            uuid::Uuid::parse_str(&root.identity().checkout.to_string())
                .map_err(|_| StoreError::Invalid)?,
        )?;
        let history = related.history();
        let cursor = history.cursor.as_ref().ok_or(StoreError::Conflict)?;
        let q = history
            .qualifications
            .get(&self.link.predecessor)
            .ok_or(StoreError::Conflict)?;
        if root.identity().run.to_string() != self.run
            || self.predecessor.authority != RecordedAuthority::from_cache(authority)?
            || cursor.latest != self.link.predecessor
            || cursor.disposition != "available"
            || cursor.revision != self.link.publication_revision as i64
            || q.successor.is_some()
            || q.fingerprint != self.link.fingerprint
            || history.frontier != Some(self.frontier)
        {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn prepare<'tx, 'conn>(
        &self,
        related: &Related<'tx, 'conn>,
        root: &crate::run_journal::RootRunRequest,
        authority: &std::sync::Arc<crate::store::AuthorityIdentity>,
    ) -> Result<PreparedAdmission<'tx, 'conn>> {
        self.validate(related, root, authority)?;
        Ok(PreparedAdmission {
            transaction: related.tx,
            authority: authority.clone(),
            checkout: related.checkout,
            run: self.run.clone(),
            link: self.link.clone(),
        })
    }
}
pub(crate) struct PreparedAdmission<'tx, 'conn> {
    transaction: &'tx rusqlite::Transaction<'conn>,
    authority: std::sync::Arc<crate::store::AuthorityIdentity>,
    checkout: uuid::Uuid,
    run: String,
    link: Continuation,
}
pub(crate) fn consume(
    tx: &rusqlite::Transaction<'_>,
    authority: &std::sync::Arc<crate::store::AuthorityIdentity>,
    lease: &crate::allocate::AuthorityLease,
    admission: PreparedAdmission<'_, '_>,
) -> Result<()> {
    lease.check_authority(authority)?;
    lease.check_authority(&admission.authority)?;
    if !std::ptr::eq(admission.transaction, tx) {
        return Err(StoreError::Conflict);
    }
    let link = admission.link;
    if tx.execute("UPDATE gap_qualifications SET successor_run=?2,successor_revision=?3 WHERE run=?1 AND checkout=?4 AND fingerprint=?5 AND successor_run IS NULL AND successor_revision IS NULL",
        rusqlite::params![link.predecessor, admission.run, link.admission_revision as i64, admission.checkout.to_string(), link.fingerprint.as_slice()])? != 1 { return Err(StoreError::Conflict); }
    if tx.execute("UPDATE gap_eligibility SET latest_run=?2,revision=?3,disposition='unavailable',qualification=NULL WHERE checkout=?1 AND latest_run=?4 AND revision=?5 AND disposition='available' AND qualification=?4",
        rusqlite::params![admission.checkout.to_string(), admission.run, link.admission_revision as i64, link.predecessor, link.publication_revision as i64])? != 1 { return Err(StoreError::Conflict); }
    Ok(())
}

/// One target batch, retaining the existing base/global/roster/writer checks.
/// Its owned return values are metadata, not a transaction or live capability.
pub(crate) fn with_history<T>(
    conn: &Connection,
    checkout: uuid::Uuid,
    use_history: impl FnOnce(History) -> Result<T>,
) -> Result<T> {
    let _snapshot = crate::run_journal::read_transaction(conn)?;
    let nodes = crate::run_journal::gap_history_base(conn, checkout)?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 15 {
        return use_history(History::untracked(nodes));
    }
    let cursor = conn.query_row(
        "SELECT latest_run,revision,disposition,qualification FROM gap_eligibility WHERE checkout=?1",
        [checkout.to_string()], |r| Ok(Cursor { latest: r.get(0)?, revision: r.get(1)?, disposition: r.get(2)?, qualification: r.get(3)? }),
    ).optional()?;
    let mut statement = conn.prepare("SELECT run,checkout,record,fingerprint,successor_run,successor_revision FROM gap_qualifications WHERE checkout=?1")?;
    let rows = statement
        .query_map([checkout.to_string()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<i64>>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if cursor.is_none() {
        if !rows.is_empty()
            || nodes
                .iter()
                .any(|(_, g)| g.as_ref().is_some_and(|g| g.continuation().is_some()))
        {
            return Err(StoreError::Invalid);
        }
        return use_history(History::untracked(nodes));
    }
    let cursor = cursor.ok_or(StoreError::Invalid)?;
    let mut qualifications = std::collections::HashMap::new();
    for (run, owner, bytes, fingerprint, successor, successor_revision) in rows {
        #[cfg(test)]
        history_count(1);
        let record = decode_qualification(&bytes, &fingerprint)?;
        if record.run != run || record.checkout != owner || owner != checkout.to_string() {
            return Err(StoreError::Invalid);
        }
        let successor = match (successor, successor_revision) {
            (None, None) => None,
            (Some(run), Some(revision))
                if record.publication_revision.checked_add(1) == Some(revision) =>
            {
                Some((run, revision))
            }
            _ => return Err(StoreError::Invalid),
        };
        let fingerprint: [u8; 32] = fingerprint.try_into().map_err(|_| StoreError::Invalid)?;
        if qualifications
            .insert(
                run,
                QualifiedNode {
                    record,
                    fingerprint,
                    successor,
                },
            )
            .is_some()
        {
            return Err(StoreError::Invalid);
        }
    }
    let mut initial = None;
    let mut remaining = std::collections::HashMap::new();
    for (root, gap) in nodes {
        let gap = gap.ok_or(StoreError::Invalid)?;
        if !gap.required() {
            return Err(StoreError::Invalid);
        }
        let run = root.request.identity().run.to_string();
        if gap.required_initial() && initial.replace(run.clone()).is_some() {
            return Err(StoreError::Invalid);
        }
        if remaining.insert(run, (root, gap)).is_some() {
            return Err(StoreError::Invalid);
        }
    }
    let mut next = initial.ok_or(StoreError::Invalid)?;
    let initial_gap = &remaining.get(&next).ok_or(StoreError::Invalid)?.1;
    let expected_context = initial_gap.context_digest()?;
    let expected_actor = initial_gap.actor().to_owned();
    let expected_destination = initial_gap
        .destination()
        .cloned()
        .ok_or(StoreError::Invalid)?;
    let expected_boot = remaining[&next].0.request.input().boot.clone();
    let mut frontier = frontier_seed(initial_gap)?;
    let mut expected_link: Option<Continuation> = None;
    let mut previous_q: Option<&Qualification> = None;
    let mut admission = 1;
    let mut chain = Vec::with_capacity(remaining.len());
    let mut seen_q = 0;
    let tail_prefix;
    loop {
        // Removing each visited key detects cycles, duplicate successors and
        // missing nodes without sorted-UUID causality or per-prefix rescans.
        let (root, gap) = remaining.remove(&next).ok_or(StoreError::Invalid)?;
        if gap.continuation() != expected_link.as_ref()
            || gap.context_digest()? != expected_context
            || gap.actor() != expected_actor
            || gap.destination() != Some(&expected_destination)
            || root.request.input().boot != expected_boot
        {
            return Err(StoreError::Invalid);
        }
        let prefix = frontier;
        frontier = fold_node(prefix, &root, &gap)?;
        let q = qualifications.get(&next);
        if let Some(q) = q {
            seen_q += 1;
            validate_qualification(&q.record, &root, &gap, frontier, admission)?;
            if let Some(prior) = previous_q {
                if q.record.authority != prior.authority
                    || !same_non_head(&q.record.physical, &prior.physical)
                {
                    return Err(StoreError::Invalid);
                }
            }
            previous_q = Some(&q.record);
            if let Some((successor, revision)) = &q.successor {
                expected_link = Some(Continuation {
                    predecessor: next,
                    fingerprint: q.fingerprint,
                    publication_revision: q.record.publication_revision as u64,
                    admission_revision: *revision as u64,
                });
                admission = *revision;
                next = successor.clone();
                chain.push((root, Some(gap)));
                continue;
            }
        }
        let publication = q.map(|q| q.record.publication_revision);
        if next != cursor.latest || !remaining.is_empty() || seen_q != qualifications.len() {
            return Err(StoreError::Invalid);
        }
        let valid = match cursor.disposition.as_str() {
            "unavailable" => {
                !root.closed
                    && cursor.revision == admission
                    && publication.is_none()
                    && cursor.qualification.is_none()
            }
            "awaiting_qualification" => {
                root.closed
                    && root.outcome.is_some()
                    && !root.recovery_hold
                    && admission.checked_add(1) == Some(cursor.revision)
                    && publication.is_none()
                    && cursor.qualification.is_none()
            }
            "available" => {
                publication == Some(cursor.revision)
                    && cursor.qualification.as_deref() == Some(next.as_str())
                    && gap.closed_context_matches(conn)?
            }
            "blocked" => {
                cursor.revision > publication.unwrap_or(admission) && cursor.qualification.is_none()
            }
            _ => false,
        };
        if !valid {
            return Err(StoreError::Invalid);
        }
        tail_prefix = prefix;
        chain.push((root, Some(gap)));
        break;
    }
    use_history(History {
        nodes: chain,
        cursor: Some(cursor),
        qualifications,
        frontier: Some(frontier),
        tail_prefix: Some(tail_prefix),
        tail_admission: Some(admission),
    })
}

/// Owned pre-write classification. A database/grammar failure is an error,
/// never silently treated as ineligible. No SQL witness survives this call.
pub(crate) struct CloseClassification {
    required: bool,
    tracked: Option<(String, i64)>,
    awaiting: Option<(i64, [u8; 32], crate::attribution_gap::GapClosureContext)>,
}
impl CloseClassification {
    pub(crate) fn required(&self) -> bool {
        self.required
    }
}

/// Non-Clone/non-Serde and constructed only by an actual Changed close. Its
/// checked complete final node and admitted context remain private to this
/// module; a later publisher must consume it, never decode one from rows.
pub(crate) struct GapClosureSeal {
    context: crate::attribution_gap::GapClosureContext,
    closed: crate::run_journal::RunRecord,
    close_revision: i64,
    prefix: [u8; 32],
}
impl std::fmt::Debug for GapClosureSeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GapClosureSeal([redacted])")
    }
}

pub(crate) fn before_close(
    conn: &Connection,
    current: &crate::run_journal::RunRecord,
    live: Option<&crate::attribution_gap::CreatedOffLive>,
    authority: &crate::store::AuthorityIdentity,
) -> Result<CloseClassification> {
    let checkout = uuid::Uuid::parse_str(&current.request.identity().checkout.to_string())
        .map_err(|_| StoreError::Invalid)?;
    // Shared close has already performed its exact/global/base/writer checks.
    // Keep raw authority validation even for no-Gap targets, but do not decode
    // an unrelated captured/ordinary history a second time for classification.
    crate::attribution_gap::validate_raw(conn)?;
    if !crate::attribution_gap::raw_history(conn, checkout)? {
        return Ok(CloseClassification {
            required: false,
            tracked: None,
            awaiting: None,
        });
    }
    with_history(conn, checkout, |history| {
        classify_close(conn, history, current, live, authority)
    })
}

/// Consume the close reader's transaction-local history before any mutation.
/// This produces only owned classification; it cannot replace postwrite checks.
pub(crate) fn before_close_related(
    conn: &Connection,
    related: Related<'_, '_>,
    current: &crate::run_journal::RunRecord,
    live: Option<&crate::attribution_gap::CreatedOffLive>,
    authority: &crate::store::AuthorityIdentity,
) -> Result<CloseClassification> {
    let checkout = uuid::Uuid::parse_str(&current.request.identity().checkout.to_string())
        .map_err(|_| StoreError::Invalid)?;
    related.check(conn, checkout)?;
    if !related
        .history
        .nodes
        .iter()
        .any(|(root, _)| root == current)
    {
        return Err(StoreError::Conflict);
    }
    crate::attribution_gap::validate_raw(conn)?;
    classify_close(conn, related.history, current, live, authority)
}

fn classify_close(
    conn: &Connection,
    history: History,
    current: &crate::run_journal::RunRecord,
    live: Option<&crate::attribution_gap::CreatedOffLive>,
    authority: &crate::store::AuthorityIdentity,
) -> Result<CloseClassification> {
    let required = history
        .nodes
        .iter()
        .any(|(_, gap)| gap.as_ref().is_some_and(|g| g.required()));
    let context = live
        .map(|live| live.closure_context(conn, current, authority))
        .transpose()?
        .flatten();
    let tracked = history
        .cursor
        .as_ref()
        .map(|c| (c.latest.clone(), c.revision));
    if tracked
        .as_ref()
        .is_some_and(|(run, _)| run != &current.request.identity().run.to_string())
    {
        return Err(StoreError::Conflict);
    }
    let awaiting = match (
        history.cursor,
        context,
        history.tail_admission,
        history.tail_prefix,
    ) {
        (Some(cursor), Some(context), Some(admission), Some(prefix))
            if cursor.latest == current.request.identity().run.to_string()
                && cursor.revision == admission
                && cursor.disposition == "unavailable" =>
        {
            Some((admission, prefix, context))
        }
        _ => None,
    };
    Ok(CloseClassification {
        required,
        tracked,
        awaiting,
    })
}

pub(crate) fn after_changed_close(
    tx: &rusqlite::Transaction<'_>,
    authority: &std::sync::Arc<crate::store::AuthorityIdentity>,
    lease: &crate::allocate::AuthorityLease,
    receipt: &crate::run_journal::RunRecord,
    classification: CloseClassification,
) -> Result<Option<GapClosureSeal>> {
    lease.check_authority(authority)?;
    let Some((admission_revision, prefix, context)) = classification.awaiting else {
        // Owned PREWRITE classification, not a history read through partially
        // closed rows. Ineligible/recovery close preserves physical truth and
        // increments a tracked cursor even when it was already blocked.
        if let Some((run, revision)) = classification.tracked {
            let next = revision.checked_add(1).ok_or(StoreError::Invalid)?;
            if tx.execute("UPDATE gap_eligibility SET revision=?3,disposition='blocked',qualification=NULL WHERE checkout=?1 AND latest_run=?2 AND revision=?4",
                rusqlite::params![receipt.request.identity().checkout.to_string(), run, next, revision])? != 1 { return Err(StoreError::Conflict); }
        }
        return Ok(None);
    };
    if !receipt.closed
        || receipt.recovery_hold
        || receipt.outcome.is_none()
        || !context.matches_closed(tx, &receipt.request)?
    {
        return Err(StoreError::Conflict);
    }
    let close_revision = admission_revision
        .checked_add(1)
        .ok_or(StoreError::Invalid)?;
    let changed = tx.execute(
        "UPDATE gap_eligibility SET revision=?3,disposition='awaiting_qualification',qualification=NULL WHERE checkout=?1 AND latest_run=?2 AND revision=?4 AND disposition='unavailable' AND qualification IS NULL",
        rusqlite::params![receipt.request.identity().checkout.to_string(), receipt.request.identity().run.to_string(), close_revision, admission_revision],
    )?;
    if changed != 1 {
        return Err(StoreError::Conflict);
    }
    Ok(Some(GapClosureSeal {
        context,
        closed: receipt.clone(),
        close_revision,
        prefix,
    }))
}

/// A participating Changed context/safety mutation revokes in its SAME
/// transaction. Callers decide genuine no-op/Existing before reaching this seam.
pub(crate) fn revoke(
    tx: &rusqlite::Transaction<'_>,
    authority: &std::sync::Arc<crate::store::AuthorityIdentity>,
    lease: &crate::allocate::AuthorityLease,
    checkout: uuid::Uuid,
) -> Result<()> {
    lease.check_authority(authority)?;
    crate::retirement_journal::require_unfenced(tx, checkout)?;
    crate::attribution_gap::validate_raw(tx)?;
    if !crate::attribution_gap::raw_history(tx, checkout)? {
        return Ok(());
    }
    with_history(tx, checkout, |history| {
        let Some(cursor) = history.cursor else {
            return Ok(());
        };
        let next = cursor.revision.checked_add(1).ok_or(StoreError::Invalid)?;
        if tx.execute("UPDATE gap_eligibility SET revision=?2,disposition='blocked',qualification=NULL WHERE checkout=?1 AND revision=?3 AND latest_run=?4",
            rusqlite::params![checkout.to_string(),next,cursor.revision,cursor.latest])? != 1 { return Err(StoreError::Conflict); }
        Ok(())
    })
}

/// Final release uses the epoch carried by the private live admission, never a
/// caller-selected public policy. Normal journal progress does not change it.
pub(crate) fn release_current(
    conn: &Connection,
    root: &crate::run_journal::RootRunRequest,
    admission: i64,
) -> Result<()> {
    let current: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM gap_eligibility WHERE checkout=?1 AND latest_run=?2 AND revision=?3 AND disposition='unavailable' AND qualification IS NULL)",
        rusqlite::params![root.identity().checkout.to_string(),root.identity().run.to_string(),admission], |r| r.get(0))?;
    if !current {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

/// Called only after successful pre-mutation first-Root qualification and the
/// Root/Gap inserts in that same transaction. Never used by reads or Existing.
pub(crate) fn initialize_initial(
    tx: &rusqlite::Transaction<'_>,
    authority: &std::sync::Arc<crate::store::AuthorityIdentity>,
    lease: &crate::allocate::AuthorityLease,
    root: &crate::run_journal::RootRunRequest,
) -> Result<()> {
    lease.check_authority(authority)?;
    let changed = tx.execute(
        "INSERT INTO gap_eligibility(checkout,latest_run,revision,disposition,qualification) VALUES(?1,?2,1,'unavailable',NULL)",
        (root.identity().checkout.to_string(), root.identity().run.to_string()),
    )?;
    if changed != 1 {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

/// Immutable wire reference only. This does not provide admission, a closure
/// seal, or permission to construct any live capability.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Continuation {
    predecessor: String,
    fingerprint: [u8; 32],
    publication_revision: u64,
    admission_revision: u64,
}
impl Continuation {
    pub(crate) fn admission_revision(&self) -> i64 {
        self.admission_revision as i64
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let predecessor =
            uuid::Uuid::parse_str(&self.predecessor).map_err(|_| StoreError::Invalid)?;
        if predecessor.get_version_num() != 7
            || predecessor.get_variant() != uuid::Variant::RFC4122
            || predecessor.to_string() != self.predecessor
            || self.publication_revision < 3
            || self.publication_revision > i64::MAX as u64
            || self.admission_revision > i64::MAX as u64
            || self.publication_revision.checked_add(1) != Some(self.admission_revision)
        {
            return Err(StoreError::Invalid);
        }
        Ok(())
    }
}
