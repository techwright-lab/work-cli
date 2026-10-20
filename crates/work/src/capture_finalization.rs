//! Terminal capture metadata only. Never grants writer or retirement authority.
use crate::{
    capture_bridge::{CaptureBinding, CaptureOutcome, EndedAt, FinishRequest},
    capture_journal::{json, CaptureRecord, CaptureSpec, MAX_RECORD_BYTES},
    config::Config,
    run_journal::{RootOutcome, RunRecord},
    sinks::ProcessSink,
    store::{Result, Store, StoreError},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use work_contract::RunId;

pub(crate) const SCHEMA: &str = "CREATE TABLE capture_finalizations(
 run TEXT PRIMARY KEY REFERENCES capture_runs(run),
 intent TEXT NOT NULL, confirmation TEXT,
 revision INTEGER NOT NULL CHECK(revision>=1)); PRAGMA user_version=12;";
pub(crate) fn validate_schema(conn: &Connection) -> Result<()> {
    let ddl: String = conn.query_row(
        "SELECT sql FROM sqlite_schema WHERE name='capture_finalizations' AND type='table'",
        [],
        |r| r.get(0),
    )?;
    let normalize = |s: &str| {
        s.chars()
            .filter(|c| !c.is_whitespace() && *c != '"')
            .collect::<String>()
            .to_ascii_lowercase()
    };
    if normalize(&ddl) != normalize(SCHEMA.split(';').next().ok_or(StoreError::Invalid)?) {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    Intent,
    Frozen,
    Delivery,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub capture_id: String,
    pub outcome: RootOutcome,
    pub ended_at: String,
    pub intent_wall: String,
    pub body: String,
    pub fingerprint: [u8; 32],
    pub context: ContextSeal,
}
/// Immutable terminal context, separate from the finalization journal's revision.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSeal {
    pub root_digest: [u8; 32],
    pub capture_digest: [u8; 32],
    pub spec_digest: [u8; 32],
    pub binding_digest: [u8; 32],
    pub operation: uuid::Uuid,
}
fn digest(value: &impl Serialize) -> Result<[u8; 32]> {
    // Stream the closed roster rather than impose a new roster-size restriction.
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
    let mut writer = HashWriter(Sha256::new());
    serde_json::to_writer(&mut writer, value).map_err(|_| StoreError::Invalid)?;
    Ok(writer.0.finalize().into())
}
fn binding_digest(binding: &CaptureBinding) -> Result<[u8; 32]> {
    digest(&(
        binding.capture_id().as_str(),
        binding.actor_ref(),
        binding.run_ref(),
    ))
}
pub(crate) fn context(
    root: &RunRecord,
    capture: &CaptureRecord,
    spec: &CaptureSpec,
) -> Result<ContextSeal> {
    Ok(ContextSeal {
        root_digest: digest(root)?,
        capture_digest: digest(capture)?,
        spec_digest: digest(spec)?,
        binding_digest: binding_digest(&binding(capture, spec)?)?,
        operation: capture.operation,
    })
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmation {
    pub delivered: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<crate::capture_bridge::Source>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<crate::capture_bridge::Receipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_precision: Option<EndPrecision>,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndPrecision {
    ExactInstant,
    SameMicrosecond,
}
fn date(s: &str) -> Result<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_rfc3339(s).map_err(|_| StoreError::Invalid)
}
fn facts(
    frozen: &crate::capture_bridge::LocalFrozen,
    intent: &Intent,
    spec: &CaptureSpec,
) -> Result<Confirmation> {
    let end = date(&intent.ended_at)?;
    let precision = frozen
        .ended_at()
        .map(|s| {
            let echo = date(s)?;
            if echo == end {
                Ok(EndPrecision::ExactInstant)
            } else if echo.timestamp_micros() == end.timestamp_micros()
                && echo.timestamp_subsec_nanos().is_multiple_of(1000)
            {
                Ok(EndPrecision::SameMicrosecond)
            } else {
                Err(StoreError::Conflict)
            }
        })
        .transpose()?;
    if frozen
        .started_at()
        .is_some_and(|s| date(s).is_ok_and(|start| start > end))
        || frozen
            .source()
            .is_some_and(|s| *s != spec.begin_request().source.unwrap_or_default())
    {
        return Err(StoreError::Conflict);
    }
    if let Some(attempt) = frozen.last_attempt_at() {
        if date(attempt)? < end {
            return Err(StoreError::Conflict);
        }
    }
    Ok(Confirmation {
        delivered: frozen.delivery() == crate::capture_bridge::DeliveryObservation::Delivered,
        started_at: frozen.started_at().map(str::to_owned),
        ended_at: frozen.ended_at().map(str::to_owned),
        source: frozen.source().cloned(),
        last_attempt_at: frozen.last_attempt_at().map(str::to_owned),
        error_code: frozen.error_code().map(str::to_owned),
        receipt: frozen.receipt().cloned(),
        end_precision: precision,
    })
}
fn binding(capture: &CaptureRecord, spec: &CaptureSpec) -> Result<CaptureBinding> {
    let d = spec.begin_request();
    CaptureBinding::new(
        &capture
            .prepared
            .as_ref()
            .ok_or(StoreError::Invalid)?
            .capture_id,
        &d.actor_ref,
        &d.run_ref,
    )
    .map_err(|_| StoreError::Invalid)
}
pub(crate) fn validate(
    conn: &Connection,
    root: &RunRecord,
    capture: &CaptureRecord,
    spec: &CaptureSpec,
) -> Result<Option<Snapshot>> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 12 {
        return Ok(None);
    }
    let Some(snapshot) = load(conn, &root.request.identity().run)? else {
        return Ok(None);
    };
    let req = request(capture, root)?;
    let bytes = req.encode().map_err(|_| StoreError::Invalid)?;
    if snapshot.intent.context != context(root, capture, spec)?
        || snapshot.intent.body.as_bytes() != bytes
        || snapshot.intent.fingerprint != <[u8; 32]>::from(Sha256::digest(&bytes))
        || snapshot.intent.capture_id != req.capture_id.as_str()
        || snapshot.intent.ended_at
            != capture
                .group_end
                .as_ref()
                .ok_or(StoreError::Invalid)?
                .observed_wall
        || Some(snapshot.intent.outcome) != root.outcome
        || snapshot.revision < 1
        || snapshot.revision > i64::MAX as u64
        || (snapshot.confirmation.is_some() && snapshot.revision < 2)
        || (snapshot.confirmation.is_none() && snapshot.revision != 1)
    {
        return Err(StoreError::Invalid);
    }
    if date(&snapshot.intent.intent_wall)? < date(&snapshot.intent.ended_at)? {
        return Err(StoreError::Invalid);
    }
    if let Some(c) = &snapshot.confirmation {
        let b = binding(capture, spec)?;
        let mut wire = serde_json::to_value(c).map_err(|_| StoreError::Invalid)?;
        let object = wire.as_object_mut().ok_or(StoreError::Invalid)?;
        object.remove("delivered");
        object.remove("end_precision");
        object.insert(
            "state".into(),
            serde_json::json!(if c.delivered { "delivered" } else { "pending" }),
        );
        object.insert(
            "capture_id".into(),
            serde_json::json!(b.capture_id().as_str()),
        );
        object.insert("actor_ref".into(), serde_json::json!(b.actor_ref()));
        object.insert("run_ref".into(), serde_json::json!(b.run_ref()));
        let terminal = crate::capture_bridge::decode_terminal(json(&wire)?.as_bytes(), &b)
            .map_err(|_| StoreError::Invalid)?;
        if facts(&terminal, &snapshot.intent, spec)? != *c {
            return Err(StoreError::Invalid);
        }
    }
    Ok(Some(snapshot))
}
#[derive(Clone, Serialize)]
pub struct Snapshot {
    pub intent: Intent,
    pub confirmation: Option<Confirmation>,
    pub revision: u64,
}
/// An actual FINISH acknowledgement, not readiness authority. No public constructor.
/// ```compile_fail
/// fn persist(x: &work_cli::capture_finalization::FreezeAcknowledgement) { let _ = serde_json::to_string(x); }
/// ```
/// ```compile_fail
/// fn copy(x: work_cli::capture_finalization::FreezeAcknowledgement) { let _ = x.clone(); }
/// ```
/// ```compile_fail
/// let _: work_cli::capture_finalization::FreezeAcknowledgement = serde_json::from_str("{}").unwrap();
/// ```
pub struct FreezeAcknowledgement {
    run: RunId,
    intent: Box<Intent>,
}
impl std::fmt::Debug for FreezeAcknowledgement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FreezeAcknowledgement([REDACTED])")
    }
}
impl FreezeAcknowledgement {
    pub fn run(&self) -> &RunId {
        &self.run
    }
    /// Exact acknowledged claims and context digests; not permission to resume writing.
    pub fn intent(&self) -> &Intent {
        &self.intent
    }
}
pub enum FinalizeResult {
    Existing(Snapshot),
    Confirmed {
        snapshot: Snapshot,
        acknowledgement: FreezeAcknowledgement,
    },
}
fn request(capture: &CaptureRecord, root: &RunRecord) -> Result<FinishRequest> {
    let end = capture.group_end.as_ref().ok_or(StoreError::Invalid)?;
    if !root.closed || end.clock_uncertain {
        return Err(StoreError::Invalid);
    }
    let outcome = match root.outcome.ok_or(StoreError::Invalid)? {
        RootOutcome::Completed => CaptureOutcome::Completed,
        RootOutcome::Failed => CaptureOutcome::Failed,
        RootOutcome::Cancelled => CaptureOutcome::Cancelled,
    };
    Ok(FinishRequest {
        capture_id: crate::capture_bridge::CaptureId::parse(
            &capture
                .prepared
                .as_ref()
                .ok_or(StoreError::Invalid)?
                .capture_id,
        )
        .map_err(|_| StoreError::Invalid)?,
        outcome,
        ended_at: EndedAt::parse(&end.observed_wall).map_err(|_| StoreError::Invalid)?,
    })
}
fn load(conn: &Connection, run: &RunId) -> Result<Option<Snapshot>> {
    let row: Option<(String, Option<String>, i64)> = conn
        .query_row(
            "SELECT intent,confirmation,revision FROM capture_finalizations WHERE run=?1",
            [run.to_string()],
            |r| {
                for i in [0, 1] {
                    if matches!(r.get_ref(i)?, rusqlite::types::ValueRef::Text(b) if b.len()>MAX_RECORD_BYTES)
                    {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                }
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            },
        )
        .optional()?;
    row.map(|(intent, confirmation, revision)| {
        Ok(Snapshot {
            intent: crate::capture_journal::strict(&intent)?,
            confirmation: confirmation
                .as_deref()
                .map(crate::capture_journal::strict)
                .transpose()?,
            revision: revision.try_into().map_err(|_| StoreError::Invalid)?,
        })
    })
    .transpose()
}
fn event(
    conn: &Connection,
    root: &RunRecord,
    capture: &CaptureRecord,
    revision: u64,
    change: Change,
) -> Result<()> {
    let parse = |v: String| uuid::Uuid::parse_str(&v).map_err(|_| StoreError::Invalid);
    let event = crate::events::Event::CaptureFinalizationChanged {
        checkout: parse(root.request.identity().checkout.to_string())?,
        run: parse(root.request.identity().run.to_string())?,
        operation: capture.operation,
        revision,
        change,
    };
    conn.execute(
        "INSERT INTO outbox(version,payload) VALUES(1,?1)",
        [json(&event)?],
    )?;
    Ok(())
}
fn target(conn: &Connection, run: &RunId) -> Result<(RunRecord, CaptureRecord, CaptureSpec)> {
    let root = crate::run_journal::read(conn, run)?.ok_or(StoreError::Invalid)?;
    let root = crate::run_journal::exact(conn, &root.request)?;
    let (capture, spec) =
        crate::capture_journal::qualified(conn, &root)?.ok_or(StoreError::Invalid)?;
    request(&capture, &root)?;
    Ok((root, capture, spec))
}
fn open(config: &Config) -> Result<Store> {
    Store::open_existing_registered_mut(
        config
            .trusted_registry
            .as_deref()
            .ok_or(StoreError::Invalid)?,
        config.store_dir.as_deref().ok_or(StoreError::Invalid)?,
        &config.roots,
    )
}
pub fn retry_delivery(config: &Config, run: &RunId) -> Result<(Store, Snapshot)> {
    let mut store = open(config)?;
    let (spec, binding, intent) = {
        let _phase = store.sql_phase();
        let _read = crate::run_journal::read_transaction(&store.conn)?;
        let (root, capture, spec) = target(&store.conn, run)?;
        let snapshot = validate(&store.conn, &root, &capture, &spec)?.ok_or(StoreError::Invalid)?;
        if snapshot.confirmation.is_none() {
            return Err(StoreError::Invalid);
        }
        let binding = binding(&capture, &spec)?;
        (spec, binding, snapshot.intent)
    };
    let frozen = ProcessSink::new(spec.sink().process_settings()?)
        .retry(&binding)
        .map_err(|_| StoreError::CaptureDeliveryUncertain)?;
    let snapshot = confirm(&mut store, run, &intent, &spec, &frozen)
        .map_err(|_| StoreError::CaptureDeliveryUncertain)?;
    Ok((store, snapshot))
}
pub fn finalize(config: &Config, run: &RunId) -> Result<(Store, FinalizeResult)> {
    finalize_observed(config, run, || {})
}
/// Runs the observer only after the intent commit and before process I/O, outside SQL phases and locks.
pub fn finalize_observed(
    config: &Config,
    run: &RunId,
    before_process: impl FnOnce(),
) -> Result<(Store, FinalizeResult)> {
    finalize_after_preflight(config, run, before_process, || {})
}
// The private boundary makes a competing commit between preflight and dispatch
// deterministic in tests. Both callbacks execute outside every SQL phase.
fn finalize_after_preflight(
    config: &Config,
    run: &RunId,
    before_process: impl FnOnce(),
    after_preflight: impl FnOnce(),
) -> Result<(Store, FinalizeResult)> {
    let mut store = open(config)?;
    let existing = {
        let _phase = store.sql_phase();
        let _read = crate::run_journal::read_transaction(&store.conn)?;
        let (root, capture, spec) = target(&store.conn, run)?;
        validate(&store.conn, &root, &capture, &spec)?
    };
    if let Some(snapshot) = existing.filter(|s| s.confirmation.is_some()) {
        return Ok((store, FinalizeResult::Existing(snapshot)));
    }
    after_preflight();
    let (spec, binding, intent) = {
        let _phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (root, capture, spec) = target(&tx, run)?;
        let request = request(&capture, &root)?;
        let body = String::from_utf8(request.encode().map_err(|_| StoreError::Invalid)?)
            .map_err(|_| StoreError::Invalid)?;
        let mut intent = Intent {
            capture_id: request.capture_id.as_str().into(),
            outcome: root.outcome.ok_or(StoreError::Invalid)?,
            ended_at: capture
                .group_end
                .as_ref()
                .ok_or(StoreError::Invalid)?
                .observed_wall
                .clone(),
            intent_wall: chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now())
                .to_rfc3339(),
            fingerprint: Sha256::digest(body.as_bytes()).into(),
            context: context(&root, &capture, &spec)?,
            body,
        };
        let declaration = spec.begin_request();
        let binding = CaptureBinding::new(
            &intent.capture_id,
            &declaration.actor_ref,
            &declaration.run_ref,
        )
        .map_err(|_| StoreError::Invalid)?;
        if let Some(existing) = validate(&tx, &root, &capture, &spec)? {
            if existing.confirmation.is_some() {
                tx.commit()?;
                drop(_phase);
                return Ok((store, FinalizeResult::Existing(existing)));
            }
            intent = existing.intent;
        } else {
            if date(&intent.intent_wall)? < date(&intent.ended_at)? {
                return Err(StoreError::Invalid);
            }
            tx.execute(
                "INSERT INTO capture_finalizations(run,intent,revision) VALUES(?1,?2,1)",
                (run.to_string(), json(&intent)?),
            )?;
            event(&tx, &root, &capture, 1, Change::Intent)?;
        }
        tx.commit()?;
        (spec, binding, intent)
    };
    before_process();
    let finish = FinishRequest {
        capture_id: binding.capture_id().clone(),
        outcome: match intent.outcome {
            RootOutcome::Completed => CaptureOutcome::Completed,
            RootOutcome::Failed => CaptureOutcome::Failed,
            RootOutcome::Cancelled => CaptureOutcome::Cancelled,
        },
        ended_at: EndedAt::parse(&intent.ended_at).map_err(|_| StoreError::Invalid)?,
    };
    let frozen = ProcessSink::new(spec.sink().process_settings()?)
        .finish(&binding, &finish)
        .map_err(|_| StoreError::CaptureFinishUncertain)?;
    let snapshot = confirm(&mut store, run, &intent, &spec, &frozen)
        .map_err(|_| StoreError::CaptureFinishUncertain)?;
    Ok((
        store,
        FinalizeResult::Confirmed {
            snapshot,
            acknowledgement: FreezeAcknowledgement {
                run: run.clone(),
                intent: Box::new(intent),
            },
        },
    ))
}
fn confirm(
    store: &mut Store,
    run: &RunId,
    intent: &Intent,
    spec: &CaptureSpec,
    frozen: &crate::capture_bridge::LocalFrozen,
) -> Result<Snapshot> {
    let mut confirmation = facts(frozen, intent, spec)?;
    let _phase = store.sql_phase();
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (root, capture, sealed) = target(&tx, run)?;
    let mut snapshot = validate(&tx, &root, &capture, &sealed)?.ok_or(StoreError::Invalid)?;
    if snapshot.intent != *intent
        || context(&root, &capture, spec)? != intent.context
        || binding_digest(frozen.binding())? != intent.context.binding_digest
    {
        return Err(StoreError::Conflict);
    }
    // Historical delivered state is not evidence that this attempt succeeded.
    let incoming_success = confirmation.delivered && confirmation.error_code.is_none();
    if let Some(old) = &snapshot.confirmation {
        if let (Some(a), Some(b)) = (&old.receipt, &confirmation.receipt) {
            if a.event_id() != b.event_id() || (!incoming_success && a != b) {
                return Err(StoreError::Conflict);
            }
        }
        if let (Some(a), Some(b)) = (&old.started_at, &confirmation.started_at) {
            if date(a)? != date(b)? {
                return Err(StoreError::Conflict);
            }
        }
        confirmation.delivered |= old.delivered;
        if confirmation.receipt.is_none() {
            confirmation.receipt = old.receipt.clone();
        }
        if confirmation.started_at.is_none() {
            confirmation.started_at = old.started_at.clone();
        }
        if confirmation.ended_at.is_none() {
            confirmation.ended_at = old.ended_at.clone();
            confirmation.end_precision = old.end_precision;
        }
        if confirmation.source.is_none() {
            confirmation.source = old.source.clone();
        }
        if confirmation.last_attempt_at.is_none()
            || old.last_attempt_at.as_ref().is_some_and(|a| {
                confirmation
                    .last_attempt_at
                    .as_ref()
                    .is_some_and(|b| date(a).ok() > date(b).ok())
            })
        {
            confirmation.last_attempt_at = old.last_attempt_at.clone();
        }
    }
    let change = if snapshot.confirmation.is_some() {
        Change::Delivery
    } else {
        Change::Frozen
    };
    if snapshot.confirmation.as_ref() != Some(&confirmation) {
        snapshot.revision = snapshot
            .revision
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(StoreError::Invalid)?;
        tx.execute(
            "UPDATE capture_finalizations SET confirmation=?2,revision=?3 WHERE run=?1",
            (
                run.to_string(),
                json(&confirmation)?,
                snapshot.revision as i64,
            ),
        )?;
        event(&tx, &root, &capture, snapshot.revision, change)?;
        snapshot.confirmation = Some(confirmation);
    }
    tx.commit()?;
    Ok(snapshot)
}
#[cfg(test)]
#[path = "capture_finalization_tests.rs"]
mod tests;

impl Store {
    pub fn capture_finalization_snapshot(&self, run: &RunId) -> Result<Option<Snapshot>> {
        let _phase = self.sql_phase();
        let _read = crate::run_journal::read_transaction(&self.conn)?;
        let root = crate::run_journal::read(&self.conn, run)?.ok_or(StoreError::Invalid)?;
        let Some((capture, spec)) = crate::capture_journal::qualified(&self.conn, &root)? else {
            return Ok(None);
        };
        validate(&self.conn, &root, &capture, &spec)
    }
}
