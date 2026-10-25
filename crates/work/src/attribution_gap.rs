//! Private non-session attribution decision and local queue.
use crate::store::{Result, StoreError};

pub(crate) const SCHEMA: &str = "CREATE TABLE attribution_gaps(run TEXT PRIMARY KEY REFERENCES runs(id), group_id TEXT NOT NULL UNIQUE REFERENCES run_groups(id), checkout TEXT NOT NULL REFERENCES checkouts(id), event_id TEXT NOT NULL UNIQUE, record TEXT NOT NULL, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32)); CREATE INDEX attribution_gaps_checkout ON attribution_gaps(checkout); PRAGMA user_version=14;";

pub(crate) fn validate_schema(conn: &rusqlite::Connection) -> Result<()> {
    let normalize = |s: &str| {
        s.chars()
            .filter(|c| !c.is_whitespace() && *c != '"')
            .collect::<String>()
            .to_ascii_lowercase()
    };
    for ((name, kind), expected) in [
        ("attribution_gaps", "table"),
        ("attribution_gaps_checkout", "index"),
    ]
    .into_iter()
    .zip(SCHEMA.split(';'))
    {
        let ddl: String = conn.query_row(
            "SELECT sql FROM sqlite_schema WHERE name=?1 AND type=?2",
            (name, kind),
            |r| r.get(0),
        )?;
        if normalize(&ddl) != normalize(expected) {
            return Err(StoreError::Invalid);
        }
    }
    Ok(())
}

use crate::{
    allocate::Allocation,
    config::Config,
    run_journal::{AttributionDecision, RootRunRequest},
    scope_spawn::ActorGitProfile,
    store::Store,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
const MAX_RECORD: usize = 2 * 1024 * 1024;
const MAX_AGE: Duration = Duration::from_secs(2);
const REASON: &str = "operator_attribution_off";
pub(crate) const REQUIRED_LIMITATIONS: &str = "continuation requires a live-close qualification and fresh same-boot/actor/target checks; closure retains held/not_ready and charge; recovery never qualifies; generic Ready, new finish and transport remain unsupported";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapDelivery {
    Pending,
    NotConfigured,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GapObservation {
    pub mode: AttributionDecision,
    pub event_recorded: bool,
    pub event_id: work_contract::EventId,
    pub delivery: GapDelivery,
    pub transport_deferred: bool,
    pub origin: &'static str,
}
pub(crate) fn observation(
    conn: &Connection,
    root: &RootRunRequest,
) -> Result<Option<GapObservation>> {
    validated_record(conn, root)?
        .map(|record| record.observation())
        .transpose()
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Origin {
    OrdinaryUnconfigured,
    RequiredInitial,
    RequiredContinuation,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Requirement {
    operation: String,
    revision: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Destination {
    family: String,
    endpoint: String,
    registry: PathBuf,
    pin: String,
    actor_ref: String,
    configured_names: Vec<String>,
    actual_name: String,
    removal_names: Vec<String>,
}
impl Destination {
    pub(crate) fn validate(&self) -> Result<()> {
        let scalar = |s: &str| {
            !s.trim().is_empty() && s.chars().count() <= 4096 && !s.chars().any(char::is_control)
        };
        if self.family != "devdiary"
            || !scalar(&self.endpoint)
            || !scalar(&self.actor_ref)
            || !self.registry.is_absolute()
            || self.registry.to_str().is_none_or(|s| !scalar(s))
            || self.registry.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
            || self.pin.len() != 64
            || !self
                .pin
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.configured_names.len() > 128
        {
            return Err(StoreError::Invalid);
        }
        let mut expected = self.configured_names.clone();
        expected.push(self.actual_name.clone());
        let policy = RemovalPolicy::validated(expected)?;
        if policy.receivers != self.removal_names {
            return Err(StoreError::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    allocation: String,
    allocation_request: String,
    operation: String,
    charge_digest: Vec<u8>,
    repository: PathBuf,
    actor: String,
    task: String,
    owner: String,
    state: String,
    ready: bool,
    requirement: Option<Requirement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    continuation: Option<crate::gap_continuation::Continuation>,
}
impl Context {
    fn read(conn: &Connection, checkout: Uuid) -> Result<Self> {
        let mut context = conn.query_row(
            "SELECT a.record,a.request,c.operation,c.digest,c.repository,c.actor,c.task,c.owner,c.state,c.ready FROM checkouts c JOIN allocations a ON a.checkout=c.id WHERE c.id=?1",
            [checkout.to_string()], |r| Ok(Self {
                allocation:r.get(0)?, allocation_request:r.get(1)?, operation:r.get(2)?, charge_digest:r.get(3)?,
                repository:PathBuf::from(r.get::<_,String>(4)?), actor:r.get(5)?, task:r.get(6)?, owner:r.get(7)?,
                state:r.get(8)?, ready:r.get(9)?, requirement:None, continuation:None,
            }),
        )?;
        context.requirement =
            crate::capture_requirement::read(conn, checkout)?.map(|r| Requirement {
                operation: r.operation,
                revision: r.revision,
            });
        Ok(context)
    }
    fn allocation(&self, checkout: Uuid) -> Result<Allocation> {
        let a: Allocation =
            serde_json::from_str(&self.allocation).map_err(|_| StoreError::Invalid)?;
        if a.checkout != checkout
            || a.request.operation.to_string() != self.operation
            || encode(&a.request)? != self.allocation_request
            || a.request.actor.as_deref() != Some(self.actor.as_str())
            || a.request.task != self.task
            || self.owner.is_empty()
        {
            return Err(StoreError::Conflict);
        }
        Ok(a)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GapRecord {
    format_version: u32,
    run: String,
    group: String,
    checkout: String,
    actor: String,
    request_digest: [u8; 32],
    origin: Origin,
    context: Context,
    event_id: String,
    reason: String,
    event: String,
    observed_ms: u64,
    destination: Option<Destination>,
    delivery: GapDelivery,
}
impl GapRecord {
    pub(crate) fn continuation(&self) -> Option<&crate::gap_continuation::Continuation> {
        self.context.continuation.as_ref()
    }
    pub(crate) fn actor(&self) -> &str {
        &self.actor
    }
    pub(crate) fn destination(&self) -> Option<&Destination> {
        self.destination.as_ref()
    }
    pub(crate) fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    pub(crate) fn fingerprint(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(encode(self)?.as_bytes()).into())
    }
    pub(crate) fn allocation(&self) -> Result<Allocation> {
        self.context.allocation(id(&self.checkout)?)
    }
    pub(crate) fn context_digest(&self) -> Result<[u8; 32]> {
        let c = &self.context;
        let mut hash = Sha256::new();
        hash.update(b"work.required-gap.context.v1\0");
        for bytes in [
            c.allocation.as_bytes(),
            c.allocation_request.as_bytes(),
            c.operation.as_bytes(),
            c.repository.to_str().ok_or(StoreError::Invalid)?.as_bytes(),
            c.actor.as_bytes(),
            c.task.as_bytes(),
            c.owner.as_bytes(),
            b"held",
        ] {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        hash.update(&c.charge_digest);
        hash.update([0]); // post-close not-ready
        let requirement = c.requirement.as_ref().ok_or(StoreError::Invalid)?;
        hash.update((requirement.operation.len() as u64).to_be_bytes());
        hash.update(requirement.operation.as_bytes());
        hash.update(requirement.revision.to_be_bytes());
        Ok(hash.finalize().into())
    }
    pub(crate) fn closed_context_matches(&self, conn: &Connection) -> Result<bool> {
        let mut expected = self.context.clone();
        expected.state = "held".into();
        expected.continuation = None;
        Ok(Context::read(conn, id(&self.checkout)?)? == expected)
    }
    pub(crate) fn required_initial(&self) -> bool {
        self.origin == Origin::RequiredInitial
    }
    pub(crate) fn required(&self) -> bool {
        matches!(
            self.origin,
            Origin::RequiredInitial | Origin::RequiredContinuation
        )
    }
    pub(crate) fn observation(&self) -> Result<GapObservation> {
        Ok(GapObservation {
            mode: AttributionDecision::Off,
            event_recorded: true,
            event_id: work_contract::EventId::parse(&self.event_id)
                .map_err(|_| StoreError::Invalid)?,
            delivery: self.delivery,
            transport_deferred: true,
            origin: match self.origin {
                Origin::OrdinaryUnconfigured => "ordinary_unconfigured",
                Origin::RequiredInitial => "required_initial",
                Origin::RequiredContinuation => "required_continuation",
            },
        })
    }
}
fn encode(value: &impl Serialize) -> Result<String> {
    let text = serde_json::to_string(value).map_err(|_| StoreError::Invalid)?;
    if text.len() > MAX_RECORD {
        return Err(StoreError::Invalid);
    }
    Ok(text)
}
fn id(value: &str) -> Result<Uuid> {
    let id = Uuid::parse_str(value).map_err(|_| StoreError::Invalid)?;
    if id.get_version_num() != 7 || id.get_variant() != uuid::Variant::RFC4122 {
        return Err(StoreError::Invalid);
    }
    Ok(id)
}
fn event(event_id: &str) -> Result<String> {
    encode(&work_contract::LifecycleEvent::AttributionGap {
        id: work_contract::EventId::parse(event_id).map_err(|_| StoreError::Invalid)?,
        reason: REASON.into(),
    })
}
/// Strict wire decoding is separate from related-history and live authority.
/// Extracted from the v1 reader so wire compatibility can be qualified alone.
pub(crate) fn decode_record(bytes: &str) -> Result<GapRecord> {
    if bytes.len() > MAX_RECORD {
        return Err(StoreError::Invalid);
    }
    let record: GapRecord = serde_json::from_str(bytes).map_err(|_| StoreError::Invalid)?;
    if encode(&record)? != bytes {
        return Err(StoreError::Invalid);
    }
    match (
        record.format_version,
        record.origin,
        &record.context.continuation,
    ) {
        (1, Origin::OrdinaryUnconfigured | Origin::RequiredInitial, None) => {}
        (2, Origin::RequiredContinuation, Some(link)) => {
            link.validate()?;
            if record.context.state != "held"
                || record.context.ready
                || record.context.requirement.is_none()
            {
                return Err(StoreError::Invalid);
            }
        }
        _ => return Err(StoreError::Invalid),
    }
    Ok(record)
}
pub(crate) fn read_record(conn: &Connection, root: &RootRunRequest) -> Result<GapRecord> {
    // Raw checkout presence wins even when the contradictory payload is invalid.
    if capture_history_present(conn, id(&root.identity().checkout.to_string())?)? {
        return Err(StoreError::Invalid);
    }
    let row: Option<(String,String,String,String,Vec<u8>)> = conn.query_row(
        "SELECT group_id,checkout,event_id,record,fingerprint FROM attribution_gaps WHERE run=?1",
        [root.identity().run.to_string()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    ).optional()?;
    let (group, checkout, event_id, bytes, fingerprint) = row.ok_or(StoreError::Invalid)?;
    if bytes.len() > MAX_RECORD || Sha256::digest(bytes.as_bytes()).as_slice() != fingerprint {
        return Err(StoreError::Invalid);
    }
    let record = decode_record(&bytes)?;
    if record.run != root.identity().run.to_string()
        || record.group != root.identity().group.to_string()
        || record.checkout != root.identity().checkout.to_string()
        || record.actor != root.identity().actor.as_str()
        || record.group != group
        || record.checkout != checkout
        || record.event_id != event_id
        || record.request_digest
            != <[u8; 32]>::from(Sha256::digest(
                serde_json::to_vec(root).map_err(|_| StoreError::Invalid)?,
            ))
        || record.reason != REASON
        || record.event != event(&event_id)?
        || root.input().attribution != Some(AttributionDecision::Off)
    {
        return Err(StoreError::Invalid);
    }
    id(&event_id)?;
    if let Some(destination) = &record.destination {
        destination.validate()?;
    }
    let checkout = id(&record.checkout)?;
    let allocation = record.context.allocation(checkout)?;
    if record.context.charge_digest.len() != 32 {
        return Err(StoreError::Invalid);
    }
    match record.origin {
        Origin::OrdinaryUnconfigured => {
            if record.destination.is_some()
                || record.delivery != GapDelivery::NotConfigured
                || record.context.requirement.is_some()
                || allocation.stage != "ready"
                || record.context.state != "active"
                || !record.context.ready
                || crate::capture_requirement::present(conn, checkout)?
            {
                return Err(StoreError::Invalid);
            }
        }
        Origin::RequiredInitial | Origin::RequiredContinuation => {
            if record.destination.is_none()
                || record.delivery != GapDelivery::Pending
                || record.context.requirement.is_none()
                || allocation.stage != "capture_pending"
                || allocation.reason.as_deref()
                    != Some("capture required; root preparation pending")
                || record.context.state
                    != if record.origin == Origin::RequiredInitial {
                        "partial"
                    } else {
                        "held"
                    }
                || record.context.ready
            {
                return Err(StoreError::Invalid);
            }
            let current = crate::capture_requirement::read(conn, checkout)?.map(|r| Requirement {
                operation: r.operation,
                revision: r.revision,
            });
            if current != record.context.requirement {
                return Err(StoreError::Invalid);
            }
        }
    }
    Ok(record)
}
/// Raw structural checks deliberately do not parse unrelated record JSON.
pub(crate) fn validate_raw(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 14 {
        return Ok(());
    }
    crate::gap_continuation::validate_raw(conn)?;
    let invalid: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM attribution_gaps a LEFT JOIN runs r ON r.id=a.run LEFT JOIN run_groups g ON g.id=a.group_id LEFT JOIN checkouts c ON c.id=a.checkout WHERE r.id IS NULL OR g.id IS NULL OR c.id IS NULL OR r.group_id<>a.group_id OR g.checkout<>a.checkout
        OR EXISTS(SELECT 1 FROM checkouts WHERE id=a.event_id OR operation=a.event_id)
        OR EXISTS(SELECT 1 FROM writers WHERE group_id=a.event_id)
        OR EXISTS(SELECT 1 FROM runs WHERE id=a.event_id OR group_id=a.event_id)
        OR EXISTS(SELECT 1 FROM run_groups WHERE id=a.event_id)
        OR EXISTS(SELECT 1 FROM run_participants WHERE id=a.event_id)
        OR EXISTS(SELECT 1 FROM adopted_groups WHERE id=a.event_id OR run_id=a.event_id OR operation=a.event_id)
        OR EXISTS(SELECT 1 FROM task_finishes WHERE operation=a.event_id)
        OR EXISTS(SELECT 1 FROM capture_runs WHERE operation=a.event_id))",
        [], |r| r.get(0),
    )?;
    if invalid {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
pub(crate) fn validated_record(
    conn: &Connection,
    root: &RootRunRequest,
) -> Result<Option<GapRecord>> {
    qualify_presence(conn, root)?;
    if root.input().attribution.is_some() {
        read_record(conn, root).map(Some)
    } else {
        Ok(None)
    }
}
pub(crate) fn qualify_root(conn: &Connection, root: &RootRunRequest) -> Result<()> {
    validated_record(conn, root).map(|_| ())
}
pub(crate) fn qualify_presence(conn: &Connection, root: &RootRunRequest) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 14 {
        return if root.input().attribution.is_none() {
            Ok(())
        } else {
            Err(StoreError::Invalid)
        };
    }
    let present: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM attribution_gaps WHERE run=?1)",
        [root.identity().run.to_string()],
        |r| r.get(0),
    )?;
    if present != root.input().attribution.is_some() {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

pub(crate) fn event_reserved(conn: &Connection, event: &str) -> Result<bool> {
    let version: i64 = conn
        .prepare_cached("PRAGMA user_version")?
        .query_row([], |r| r.get(0))?;
    if version < 14 {
        return Ok(false);
    }
    Ok(conn
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM attribution_gaps WHERE event_id=?1)")?
        .query_row([event], |r| r.get(0))?)
}
fn exclude_new_event(conn: &Connection, event: &str) -> Result<()> {
    let reserved: bool = conn.query_row(
        "SELECT
        EXISTS(SELECT 1 FROM checkouts WHERE id=?1 OR operation=?1)
        OR EXISTS(SELECT 1 FROM writers WHERE group_id=?1)
        OR EXISTS(SELECT 1 FROM runs WHERE id=?1 OR group_id=?1)
        OR EXISTS(SELECT 1 FROM run_groups WHERE id=?1)
        OR EXISTS(SELECT 1 FROM run_participants WHERE id=?1)
        OR EXISTS(SELECT 1 FROM adopted_groups WHERE id=?1 OR run_id=?1 OR operation=?1)
        OR EXISTS(SELECT 1 FROM task_finishes WHERE operation=?1)
        OR EXISTS(SELECT 1 FROM capture_runs WHERE operation=?1)",
        [event],
        |r| r.get(0),
    )?;
    if reserved || event_reserved(conn, event)? {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

pub(crate) fn capture_history_present(conn: &Connection, checkout: Uuid) -> Result<bool> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version >= 10 && crate::capture_journal::unresolved_checkout(conn, checkout)? {
        return Ok(true);
    }
    Ok(version >= 13
        && conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_readiness WHERE checkout=?1)",
            [checkout.to_string()],
            |r| r.get(0),
        )?)
}

pub(crate) fn raw_history(conn: &Connection, checkout: Uuid) -> Result<bool> {
    if crate::gap_continuation::raw_presence(conn, checkout)? {
        return Ok(true);
    }
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version >= 14
        && conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM attribution_gaps WHERE checkout=?1)",
            [checkout.to_string()],
            |r| r.get::<_, bool>(0),
        )?
    {
        return Ok(true);
    }
    Ok(conn.query_row("WITH inputs AS (
        SELECT CASE WHEN json_valid(r.request)=0 THEN NULL
            WHEN json_type(r.request)='object' AND (SELECT count(*) FROM json_each(r.request) WHERE key='input')=1 THEN r.request -> '$.input'
            WHEN json_type(r.request)='array' AND json_array_length(r.request)=2 THEN r.request -> '$[1]'
            ELSE NULL END AS input
        FROM runs r JOIN run_groups g ON g.id=r.group_id WHERE g.checkout=?1
    ) SELECT EXISTS(SELECT 1 FROM inputs WHERE CASE
        WHEN input IS NULL THEN 1
        WHEN json_type(input)='object' THEN EXISTS(SELECT 1 FROM json_each(input) WHERE key='attribution')
        WHEN json_type(input)='array' THEN json_array_length(input)<>5
        ELSE 1 END)", [checkout.to_string()], |r| r.get(0))?)
}
pub(crate) fn validate_related(conn: &Connection, checkout: Uuid) -> Result<()> {
    if raw_history(conn, checkout)? {
        crate::run_journal::gap_history(conn, checkout)?;
    }
    Ok(())
}
pub(crate) fn required_origin(conn: &Connection, checkout: Uuid) -> Result<bool> {
    if !raw_history(conn, checkout)? {
        return Ok(false);
    }
    let mut required = false;
    for (_, gap) in crate::run_journal::gap_history(conn, checkout)? {
        required |= gap.is_some_and(|record| record.required());
    }
    Ok(required)
}
pub(crate) fn guard_finish(conn: &Connection, checkout: Uuid, selected: bool) -> Result<()> {
    if required_origin(conn, checkout)? || (selected && raw_history(conn, checkout)?) {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

pub(crate) fn guard_legacy_allocation(conn: &Connection, checkout: Uuid) -> Result<()> {
    if required_origin(conn, checkout)? {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

fn eligible_context(conn: &Connection, checkout: Uuid) -> Result<()> {
    validate_raw(conn)?;
    crate::run_journal::validate_enrollment_rosters(conn)?;
    let forbidden: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM writers WHERE checkout=?1)
        OR EXISTS(SELECT 1 FROM capture_runs WHERE checkout=?1)
        OR EXISTS(SELECT 1 FROM capture_readiness WHERE checkout=?1)
        OR EXISTS(SELECT 1 FROM adopted_groups WHERE checkout=?1)
        OR EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1)
        OR EXISTS(SELECT 1 FROM run_groups g LEFT JOIN runs r ON r.group_id=g.id WHERE r.id IS NULL)
        OR EXISTS(SELECT 1 FROM runs r LEFT JOIN run_groups g ON g.id=r.group_id WHERE g.id IS NULL)",
        [checkout.to_string()], |r| r.get(0),
    )?;
    if forbidden {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn eligible_history(conn: &Connection, checkout: Uuid, origin: Origin) -> Result<()> {
    eligible_context(conn, checkout)?;
    let history = crate::run_journal::gap_history(conn, checkout)?;
    if origin == Origin::RequiredInitial && !history.is_empty() {
        return Err(StoreError::Invalid);
    }
    if history.iter().any(|(root, _)| !root.closed) {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

pub(crate) struct GapAdmissionProof {
    authority: std::sync::Arc<crate::store::AuthorityIdentity>,
    origin: Origin,
    registry: Option<crate::capture_artifacts::Registry>,
    root: RootRunRequest,
    request_bytes: String,
    context: Context,
    physical: crate::capture_setup::Physical,
    continuation: Option<crate::gap_continuation::ContinuationProof>,
    observed: Instant,
}
impl GapAdmissionProof {
    fn fresh(&self) -> Result<()> {
        if Instant::now()
            .checked_duration_since(self.observed)
            .is_none_or(|age| age > MAX_AGE)
        {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn validate_writer(
        &self,
        conn: &Connection,
        checkout: Uuid,
        group: Uuid,
        related: &crate::gap_continuation::Related<'_, '_>,
        lease: &crate::allocate::AuthorityLease,
        authority: &std::sync::Arc<crate::store::AuthorityIdentity>,
    ) -> Result<()> {
        lease.check_authority(authority)?;
        if self.authority.as_ref() != authority.as_ref() {
            return Err(StoreError::Conflict);
        }
        self.fresh()?;
        if self.root.identity().checkout.to_string() != checkout.to_string()
            || self.root.identity().group.to_string() != group.to_string()
            || Context::read(conn, checkout)? != self.context
        {
            return Err(StoreError::Conflict);
        }
        related.check(conn, checkout)?;
        eligible_context(conn, checkout)?;
        if (self.origin == Origin::RequiredInitial && !related.history().nodes.is_empty())
            || related.history().nodes.iter().any(|(root, _)| !root.closed)
        {
            return Err(StoreError::Invalid);
        }
        if let Some(proof) = &self.continuation {
            proof.validate(related, &self.root, authority)?;
        }
        Ok(())
    }
    pub(crate) fn request_bytes(&self, root: &RootRunRequest) -> Result<&str> {
        if root != &self.root {
            return Err(StoreError::Conflict);
        }
        Ok(&self.request_bytes)
    }
}
// No Clone/Serde: only the successful commit below creates this private value.
pub(crate) struct CreatedOffLive {
    root: RootRunRequest,
    record: GapRecord,
    proof: GapAdmissionProof,
    argv: Vec<OsString>,
    git: ActorGitProfile,
    nonce: Uuid,
}
/// Owned, checked live-close metadata, never a reconstructed capability. The
/// continuation module can retain it in a one-use seal but cannot assemble it.
pub(crate) struct GapClosureContext {
    authority: std::sync::Arc<crate::store::AuthorityIdentity>,
    record: GapRecord,
    context: Context,
    physical: crate::capture_setup::Physical,
}
impl GapClosureContext {
    pub(crate) fn authority(&self) -> &crate::store::AuthorityIdentity {
        &self.authority
    }
    pub(crate) fn record(&self) -> &GapRecord {
        &self.record
    }
    /// Actual public registry and complete physical observation; called only
    /// outside SQL/flock in the publisher's original observation window.
    pub(crate) fn inspect(&self) -> Result<crate::capture_setup::Physical> {
        let destination = self
            .record
            .destination
            .as_ref()
            .ok_or(StoreError::Invalid)?;
        let registry =
            crate::capture_artifacts::Registry::qualify(&destination.registry, &destination.pin)
                .map_err(|_| StoreError::Conflict)?;
        if registry.key_env != destination.actual_name {
            return Err(StoreError::Conflict);
        }
        let allocation = self.record.allocation()?;
        let physical = crate::gap_continuation::inspect_physical(
            &allocation,
            &self.context.repository,
            &self.physical,
            &self.physical.checkout.head,
        )?;
        registry.revalidate().map_err(|_| StoreError::Conflict)?;
        Ok(physical)
    }
    pub(crate) fn matches_closed(&self, conn: &Connection, root: &RootRunRequest) -> Result<bool> {
        let checkout = id(&self.record.checkout)?;
        let mut expected = self.context.clone();
        expected.state = "held".into();
        Ok(root.identity().run.to_string() == self.record.run
            && Context::read(conn, checkout)? == expected)
    }
}
pub(crate) struct RecoveryRemoval {
    policy: RemovalPolicy,
}
impl RecoveryRemoval {
    pub(crate) fn policy(&self) -> &RemovalPolicy {
        &self.policy
    }
}
pub(crate) fn recovery_removal(
    record: GapRecord,
    host: Option<&crate::capture_config::HostCaptureConfig>,
) -> Result<RecoveryRemoval> {
    let mut names = record
        .destination
        .map(|d| d.removal_names)
        .unwrap_or_default();
    if let Some(host) = host {
        let registry =
            crate::capture_artifacts::Registry::qualify(&host.registry, &host.registry_sha256)
                .map_err(|_| StoreError::Invalid)?;
        names.extend(host.receiver_credential_names.iter().cloned());
        names.push(registry.key_env);
    }
    Ok(RecoveryRemoval {
        policy: RemovalPolicy::validated(names)?,
    })
}
pub(crate) struct RemovalPolicy {
    receivers: Vec<String>,
}
#[derive(PartialEq, Eq)]
pub(crate) struct GapGuard {
    root: RootRunRequest,
    nonce: Uuid,
    cwd: PathBuf,
    argv: Vec<OsString>,
    git: ActorGitProfile,
}
pub(crate) struct GapReleaseProof {
    authority: std::sync::Arc<crate::store::AuthorityIdentity>,
    guard: GapGuard,
    record: GapRecord,
    context: Context,
    admission_revision: Option<i64>,
    observed: Instant,
}
impl GapReleaseProof {
    pub(crate) fn validate_authority(
        &self,
        store: &Store,
        lease: &crate::allocate::AuthorityLease,
    ) -> Result<()> {
        lease.check(store)?;
        if self.authority.as_ref() != store.authority_identity().as_ref() {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn validate(&self, guard: &GapGuard) -> Result<()> {
        if &self.guard != guard {
            return Err(StoreError::Conflict);
        }
        self.fresh()
    }
    pub(crate) fn fresh(&self) -> Result<()> {
        if Instant::now()
            .checked_duration_since(self.observed)
            .is_none_or(|age| age > MAX_AGE)
        {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn validate_current(
        &self,
        store: &Store,
        binding: &crate::runtime_scope::Binding,
        lease: &crate::allocate::AuthorityLease,
    ) -> Result<()> {
        self.validate_authority(store, lease)?;
        self.fresh()?;
        let _phase = store.sql_phase();
        let _snapshot = crate::run_journal::read_transaction(&store.conn)?;
        let root = &self.guard.root;
        let current = crate::run_journal::exact(&store.conn, root)?;
        let checkout = id(&root.identity().checkout.to_string())?;
        let mut expected = self.context.clone();
        expected.state = "active".into();
        if Context::read(&store.conn, checkout)? != expected
            || read_record(&store.conn, root)? != self.record
            || current.closed
            || current.recovery_hold
            || current.outcome.is_some()
            || current.stage != crate::run_journal::RunStage::PermitAttempt
        {
            return Err(StoreError::Conflict);
        }
        if let Some(admission) = self.admission_revision {
            crate::gap_continuation::release_current(&store.conn, root, admission)?;
        }
        let b = current.binding.as_ref().ok_or(StoreError::Invalid)?;
        let actual = binding.identity();
        let child = binding.trusted_child();
        if b.unit != actual.unit
            || b.invocation != actual.invocation
            || b.cgroup != actual.cgroup
            || b.boot != binding.boot_id()
            || b.root_pid != child.pid
            || b.root_start_ticks != child.start_ticks
            || b.root_cgroup != child.cgroup
        {
            return Err(StoreError::Conflict);
        }
        let eligible:bool=store.conn.query_row("SELECT NOT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1) AND (SELECT count(*) FROM writers WHERE checkout=?1 AND group_id=?2)=1",(checkout.to_string(),root.identity().group.to_string()),|r|r.get(0))?;
        if !eligible {
            return Err(StoreError::Conflict);
        }
        self.fresh()
    }
}
impl CreatedOffLive {
    /// Only metadata comparisons in the caller's pre-write SQL snapshot. No
    /// registry/physical observation or renewed admission clock occurs here.
    pub(crate) fn closure_context(
        &self,
        conn: &Connection,
        current: &crate::run_journal::RunRecord,
        authority: &crate::store::AuthorityIdentity,
    ) -> Result<Option<GapClosureContext>> {
        if current.request != self.root || self.proof.authority.as_ref() != authority {
            return Err(StoreError::Conflict);
        }
        if !self.record.required() {
            return Ok(None);
        }
        let checkout = id(&self.record.checkout)?;
        let mut expected = self.proof.context.clone();
        expected.state = "active".into();
        if read_record(conn, &self.root)? != self.record {
            return Err(StoreError::Conflict);
        }
        let barrier: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1)",
            [checkout.to_string()],
            |r| r.get(0),
        )?;
        if current.closed
            || current.recovery_hold
            || current.outcome.is_none()
            || barrier
            || Context::read(conn, checkout)? != expected
        {
            return Ok(None);
        }
        Ok(Some(GapClosureContext {
            authority: self.proof.authority.clone(),
            record: self.record.clone(),
            context: self.proof.context.clone(),
            physical: crate::capture_setup::Physical {
                checkout: self.proof.physical.checkout.clone(),
                directories: self.proof.physical.directories.clone(),
                marker: self.proof.physical.marker.clone(),
            },
        }))
    }
    pub(crate) fn guard(&self) -> GapGuard {
        GapGuard {
            root: self.root.clone(),
            nonce: self.nonce,
            cwd: self.proof.physical.checkout.path.clone(),
            argv: self.argv.clone(),
            git: self.git.clone(),
        }
    }
    pub(crate) fn validate_launch(
        &self,
        intent: &crate::runtime_scope::LaunchIntent,
        command: &crate::scope_spawn::AttributedCommand<'_>,
    ) -> Result<()> {
        let expected = crate::runtime_scope::LaunchIntent::new(
            self.root.identity().run.clone(),
            &self.root.input().boot,
        )
        .map_err(|_| StoreError::Invalid)?;
        if intent.unit_name() != expected.unit_name()
            || intent.boot_id() != expected.boot_id()
            || command.cwd != self.proof.physical.checkout.path
            || command.argv != self.argv
            || command.git != &self.git
        {
            return Err(StoreError::Conflict);
        }
        if let Some(registry) = &self.proof.registry {
            registry.revalidate().map_err(|_| StoreError::Conflict)?;
        }
        Ok(())
    }
    pub(crate) fn release_proof(&self) -> Result<GapReleaseProof> {
        let observed = Instant::now();
        let allocation = self.proof.context.allocation(id(&self.record.checkout)?)?;
        let physical = if self.proof.continuation.is_some() {
            crate::gap_continuation::inspect_physical(
                &allocation,
                &self.proof.context.repository,
                &self.proof.physical,
                &self.proof.physical.checkout.head,
            )?
        } else {
            crate::capture_setup::inspect_physical(&allocation, &self.proof.context.repository)?
        };
        if physical != self.proof.physical {
            return Err(StoreError::Conflict);
        }
        if let Some(registry) = &self.proof.registry {
            registry.revalidate().map_err(|_| StoreError::Conflict)?;
        }
        let proof = GapReleaseProof {
            authority: self.proof.authority.clone(),
            guard: self.guard(),
            record: self.record.clone(),
            context: self.proof.context.clone(),
            admission_revision: self.record.required().then(|| {
                self.proof
                    .continuation
                    .as_ref()
                    .map_or(1, |p| p.link().admission_revision())
            }),
            observed,
        };
        #[cfg(test)]
        tests::observe_release();
        proof.fresh()?;
        Ok(proof)
    }
    pub(crate) fn removal_policy(&self) -> RemovalPolicy {
        RemovalPolicy {
            receivers: self
                .record
                .destination
                .as_ref()
                .map(|d| d.removal_names.clone())
                .unwrap_or_default(),
        }
    }
}
impl RemovalPolicy {
    fn validated(mut receivers: Vec<String>) -> Result<Self> {
        receivers.sort();
        receivers.dedup();
        if receivers.len() > 129 {
            return Err(StoreError::Invalid);
        }
        for name in &receivers {
            crate::capture_artifacts::credential_name(name).map_err(|_| StoreError::Invalid)?;
        }
        Ok(Self { receivers })
    }
    pub(crate) fn receivers(&self) -> &[String] {
        &self.receivers
    }
}

pub(crate) enum BeginGap {
    Existing(Box<GapRecord>),
    Created(Box<CreatedOffLive>),
}
fn matching_committed(
    conn: &Connection,
    candidate: &RootRunRequest,
    committed: &RootRunRequest,
) -> Result<GapRecord> {
    // Group is generated per candidate, not caller intent. Every other durable
    // declaration must still match; immutable committed bytes always win.
    let mut identity = candidate.identity().clone();
    identity.group = committed.identity().group.clone();
    if RootRunRequest::new(identity, candidate.input().clone())? != *committed {
        return Err(StoreError::Conflict);
    }
    read_record(conn, committed)
}
pub(crate) fn begin(
    config: &Config,
    root: &RootRunRequest,
    argv: &[OsString],
) -> Result<(Store, BeginGap)> {
    if root.input().attribution != Some(AttributionDecision::Off) {
        return Err(StoreError::Invalid);
    }
    let checkout = id(&root.identity().checkout.to_string())?;
    let guard = crate::checkout_guard::CheckoutGuard::shared_known(config, checkout)?;
    let (store, lock) = crate::allocate::locked(config)?;
    guard.revalidate(&store)?;
    drop(lock);
    let result = begin_in_store(config, store, root, argv)?;
    guard.revalidate(&result.0)?;
    Ok(result)
}
// Private common core also lets owned contender tests preopen two native Stores
// before their timed observations. No public bypass, alternate authority, or
// caller-created proof is accepted.
fn begin_in_store(
    config: &Config,
    mut store: Store,
    root: &RootRunRequest,
    argv: &[OsString],
) -> Result<(Store, BeginGap)> {
    if root.input().attribution != Some(AttributionDecision::Off)
        || config.store_dir.as_deref() != Some(store.authority_identity().directory.as_path())
        || config.trusted_registry.as_deref() != Some(store.authority_identity().registry())
    {
        return Err(StoreError::Invalid);
    }
    let checkout = id(&root.identity().checkout.to_string())?;
    let context = {
        let _phase = store.sql_phase();
        let _snapshot = crate::run_journal::read_transaction(&store.conn)?;
        if let Some(old) = crate::run_journal::read(&store.conn, &root.identity().run)? {
            let record = matching_committed(&store.conn, root, &old.request)?;
            drop(_snapshot);
            return Ok((store, BeginGap::Existing(Box::new(record))));
        }
        Context::read(&store.conn, checkout)?
    };
    let allocation = context.allocation(checkout)?;
    let host = config.selected_capture().map_err(|_| StoreError::Invalid)?;
    let origin = match (host, &context.requirement) {
        (None, None)
            if context.state == "active" && context.ready && allocation.stage == "ready" =>
        {
            Origin::OrdinaryUnconfigured
        }
        (Some(_), Some(requirement))
            if context.state == "partial"
                && !context.ready
                && allocation.stage == "capture_pending"
                && allocation.reason.as_deref()
                    == Some("capture required; root preparation pending")
                && requirement.operation == context.operation =>
        {
            Origin::RequiredInitial
        }
        (Some(_), Some(requirement))
            if context.state == "held"
                && !context.ready
                && allocation.stage == "capture_pending"
                && allocation.reason.as_deref()
                    == Some("capture required; root preparation pending")
                && requirement.operation == context.operation =>
        {
            Origin::RequiredContinuation
        }
        _ => return Err(StoreError::Invalid),
    };
    {
        let _phase = store.sql_phase();
        let _snapshot = crate::run_journal::read_transaction(&store.conn)?;
        eligible_history(&store.conn, checkout, origin)?;
    }
    let git = config
        .supervisor
        .as_ref()
        .and_then(|s| s.actors.get(root.identity().actor.as_str()))
        .ok_or(StoreError::Invalid)?
        .clone();
    if crate::supervisor::command_digest(argv)? != root.input().command_digest {
        return Err(StoreError::Conflict);
    }
    let observed = Instant::now();
    let (registry, destination) = match host {
        None => (None, None),
        Some(host) => {
            let registry =
                crate::capture_artifacts::Registry::qualify(&host.registry, &host.registry_sha256)
                    .map_err(|_| StoreError::Invalid)?;
            let mut removal_names = host.receiver_credential_names.clone();
            removal_names.push(registry.key_env.clone());
            removal_names.sort();
            removal_names.dedup();
            if removal_names.len() > 129 {
                return Err(StoreError::Invalid);
            }
            for name in &removal_names {
                crate::capture_artifacts::credential_name(name).map_err(|_| StoreError::Invalid)?;
            }
            let destination = Destination {
                family: "devdiary".into(),
                endpoint: host.endpoint_identity.clone(),
                registry: host.registry.clone(),
                pin: host.registry_sha256.clone(),
                actor_ref: host
                    .actor_refs
                    .get(root.identity().actor.as_str())
                    .ok_or(StoreError::Invalid)?
                    .clone(),
                configured_names: host.receiver_credential_names.clone(),
                actual_name: registry.key_env.clone(),
                removal_names,
            };
            (Some(registry), Some(destination))
        }
    };
    #[cfg(test)]
    tests::observe_admission("inspect", &store.conn);
    let continuation = if origin == Origin::RequiredContinuation {
        Some(crate::gap_continuation::inspect_continuation(
            &store,
            root,
            destination.as_ref().ok_or(StoreError::Invalid)?,
            &allocation,
            &context.repository,
        )?)
    } else {
        None
    };
    let physical = if let Some(proof) = &continuation {
        let physical = proof.physical();
        crate::capture_setup::Physical {
            checkout: physical.checkout.clone(),
            directories: physical.directories.clone(),
            marker: physical.marker.clone(),
        }
    } else {
        crate::capture_setup::inspect_physical(&allocation, &context.repository)?
    };
    // inspect_physical delegates to Ready verification, including real Git
    // ancestry and immutable lease/registration identity checks. Ordinary
    // history may advance HEAD without refreshing the stored allocation. Keep
    // pending RequiredInitial exact; both origins retain exact reinspection and
    // release comparison against this fresh physical observation.
    if (origin == Origin::RequiredInitial
        && allocation.identity.as_ref() != Some(&physical.checkout))
        || physical.checkout.boot_id != root.input().boot
    {
        return Err(StoreError::Conflict);
    }
    let proof = GapAdmissionProof {
        authority: store.authority_identity().clone(),
        origin,
        registry,
        root: root.clone(),
        request_bytes: serde_json::to_string(root).map_err(|_| StoreError::Invalid)?,
        context: context.clone(),
        physical,
        continuation,
        observed,
    };
    let event_id = Uuid::now_v7().to_string();
    let nonce = Uuid::now_v7();
    let mut record_context = context;
    record_context.continuation = proof.continuation.as_ref().map(|p| p.link().clone());
    let record = GapRecord {
        format_version: if origin == Origin::RequiredContinuation {
            2
        } else {
            1
        },
        run: root.identity().run.to_string(),
        group: root.identity().group.to_string(),
        checkout: checkout.to_string(),
        actor: root.identity().actor.as_str().into(),
        request_digest: Sha256::digest(proof.request_bytes.as_bytes()).into(),
        origin,
        context: record_context,
        event: event(&event_id)?,
        event_id,
        reason: REASON.into(),
        observed_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StoreError::Invalid)?
            .as_millis()
            .try_into()
            .map_err(|_| StoreError::Invalid)?,
        delivery: if destination.is_some() {
            GapDelivery::Pending
        } else {
            GapDelivery::NotConfigured
        },
        destination,
    };
    let bytes = encode(&record)?;
    let fingerprint: [u8; 32] = Sha256::digest(bytes.as_bytes()).into();
    let notice = encode(&crate::events::Event::AttributionGapRecorded {
        checkout,
        group: id(&record.group)?,
        run: id(&record.run)?,
        event_id: id(&record.event_id)?,
    })?;
    #[cfg(test)]
    tests::observe_admission("reinspect", &store.conn);
    if let Some(continuation) = &proof.continuation {
        continuation.reinspect(&allocation, &proof.context.repository)?;
    } else if crate::capture_setup::inspect_physical(&allocation, &proof.context.repository)?
        != proof.physical
    {
        return Err(StoreError::Conflict);
    }
    if let Some(registry) = &proof.registry {
        registry.revalidate().map_err(|_| StoreError::Conflict)?;
    }
    let lock = store.authority_lease()?;
    let authority = store.authority_identity().clone();
    {
        let _phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let tx = crate::retirement_journal::fence(
            tx,
            &lock,
            &authority,
            crate::retirement_journal::Scope::Checkout(checkout),
            crate::retirement_journal::Attempt::GapAdmission,
        )?;
        if let Some(old) = crate::run_journal::read(&tx, &root.identity().run)? {
            let record = matching_committed(&tx, root, &old.request)?;
            tx.commit()?;
            drop(lock);
            return Ok((store, BeginGap::Existing(Box::new(record))));
        }
        // The private writer adapter validates this proof and complete history
        // once in this transaction, immediately before its first mutation.
        if [&record.run, &record.group, &record.checkout].contains(&&record.event_id) {
            return Err(StoreError::Conflict);
        }
        exclude_new_event(&tx, &record.event_id)?;
        let related = crate::gap_continuation::Related::qualify(&tx, checkout)?;
        let prepared = proof
            .continuation
            .as_ref()
            .map(|p| p.prepare(&related, root, &authority))
            .transpose()?;
        crate::run_journal::begin_run_context(
            &tx,
            root,
            crate::run_journal::WriterAdmission::Gap(&proof, &related),
            &lock,
            &authority,
        )?;
        drop(related);
        tx.execute("INSERT INTO attribution_gaps(run,group_id,checkout,event_id,record,fingerprint) VALUES(?1,?2,?3,?4,?5,?6)",
            rusqlite::params![record.run,record.group,record.checkout,record.event_id,bytes,fingerprint.as_slice()])?;
        tx.execute("INSERT INTO outbox(version,payload) VALUES(1,?1)", [notice])?;
        if origin == Origin::RequiredInitial {
            crate::gap_continuation::initialize_initial(&tx, &authority, &lock, root)?;
            if tx.execute("UPDATE checkouts SET state='active',ready=0 WHERE id=?1 AND state='partial' AND ready=0", [checkout.to_string()])? != 1 { return Err(StoreError::Conflict); }
        } else if let Some(prepared) = prepared {
            crate::gap_continuation::consume(&tx, &authority, &lock, prepared)?;
            if tx.execute("UPDATE checkouts SET state='active',ready=0 WHERE id=?1 AND state='held' AND ready=0", [checkout.to_string()])? != 1 { return Err(StoreError::Conflict); }
        }
        proof.fresh()?;
        tx.commit()?;
    }
    drop(lock);
    #[cfg(test)]
    if tests::take_ack_loss() {
        return Err(StoreError::Invalid);
    }
    Ok((
        store,
        BeginGap::Created(Box::new(CreatedOffLive {
            root: root.clone(),
            record,
            proof,
            argv: argv.to_vec(),
            git,
            nonce,
        })),
    ))
}

#[cfg(test)]
#[path = "attribution_gap_tests.rs"]
mod tests;
