//! Explicit task completion, not run completion or preservation proof.
//! Retirement is deliberately disabled: no tree mutation or charge release.
use crate::{
    allocate,
    config::Config,
    store::{Result, Store, StoreError},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[path = "capture_finish.rs"]
mod captured;

pub(crate) const SCHEMA: &str = "CREATE TABLE task_finishes(
 checkout TEXT PRIMARY KEY REFERENCES checkouts(id), operation TEXT NOT NULL UNIQUE,
 record TEXT NOT NULL); PRAGMA user_version=9;";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freeze {
    NotConfigured,
    Pending,
    Frozen,
    Failed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    NotConfigured,
    Pending,
    Delivered,
    Failed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u32,
    checkout: Uuid,
    operation: Uuid,
    allocation_operation: Uuid,
    allocation_digest: [u8; 32],
    hold_reason: String,
    identity: crate::identity::CheckoutIdentity,
    capture_binding: [u8; 32],
    local_freeze: Freeze,
    delivery: Option<Delivery>,
    reason: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunOutcome {
    pub gap: Option<crate::supervisor::GapObservation>,
    pub run: work_contract::RunId,
    pub outcome: Option<crate::run_journal::RootOutcome>,
    /// Current passive per-run observation, not the recorded task receipt.
    pub capture: RunCapture,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RunCapture {
    AttributionOff,
    Missing,
    UnknownOutcome,
    UncertainClock,
    Incomplete,
    Unconfirmed,
    Frozen { delivery: Delivery },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub checkout: Uuid,
    pub operation: Uuid,
    pub task_finished: bool,
    pub task_completion: work_contract::TaskCompletion,
    pub run_outcomes: Vec<RunOutcome>,
    pub local_freeze: Freeze,
    pub delivery: Option<Delivery>,
    pub capture_incomplete: bool,
    pub lease_held: bool,
    pub charge_retained: bool,
    pub retirement: &'static str,
    pub action: &'static str,
    pub reasons: Vec<String>,
}
impl Report {
    pub fn is_held(&self) -> bool {
        self.capture_incomplete
    }
}
fn report(r: Receipt, run_outcomes: Vec<RunOutcome>) -> Report {
    let incomplete = matches!(r.local_freeze, Freeze::Pending | Freeze::Failed);
    let mut reasons = vec![r.hold_reason];
    if let Some(reason) = r.reason {
        reasons.push(reason);
    }
    Report {
        checkout: r.checkout,
        operation: r.operation,
        task_finished: true,
        task_completion: work_contract::TaskCompletion::Finished,
        run_outcomes,
        local_freeze: r.local_freeze,
        delivery: r.delivery,
        capture_incomplete: incomplete,
        lease_held: true,
        charge_retained: true,
        retirement: "disabled",
        action: "none",
        reasons,
    }
}
fn uuid7(id: Uuid) -> Result<()> {
    if id.get_version_num() != 7 || id.get_variant() != uuid::Variant::RFC4122 {
        Err(StoreError::Invalid)
    } else {
        Ok(())
    }
}
fn digest(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn json<T: Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(|_| StoreError::Invalid)
}
fn parse<T: serde::de::DeserializeOwned>(v: &str) -> Result<T> {
    serde_json::from_str(v).map_err(|_| StoreError::Invalid)
}
fn allocation(conn: &Connection, checkout: Uuid) -> Result<(allocate::Allocation, String, bool)> {
    let (operation,state,ready,request,body): (String,String,bool,String,String) = conn.query_row(
        "SELECT c.operation,c.state,c.ready,a.request,a.record FROM checkouts c JOIN allocations a ON a.checkout=c.id WHERE c.id=?1",
        [checkout.to_string()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
    let a: allocate::Allocation = parse(&body)?;
    if a.checkout != checkout
        || a.request.operation.to_string() != operation
        || parse::<allocate::Start>(&request)? != a.request
        || a.stage != "ready"
        || a.identity.is_none()
    {
        return Err(StoreError::Invalid);
    }
    let (repository, actor, task, reservation_digest): (String, String, String, Vec<u8>) = conn
        .query_row(
            "SELECT repository,actor,task,digest FROM checkouts WHERE id=?1",
            [checkout.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
    let identity = a.identity.as_ref().ok_or(StoreError::Invalid)?;
    if a.request.actor.as_deref() != Some(actor.as_str())
        || a.request.task != task
        || identity.common_git_dir != std::path::Path::new(&repository)
        || identity.path != a.destination
        || a.request
            .root
            .as_ref()
            .map(|root| root.join(&task))
            .as_ref()
            != Some(&a.destination)
    {
        return Err(StoreError::Invalid);
    }
    let mut hash = Sha256::new();
    for field in [
        "work-reservation-v1",
        &repository,
        &actor,
        a.request.owner.as_deref().ok_or(StoreError::Invalid)?,
        &task,
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    if hash.finalize().as_slice() != reservation_digest {
        return Err(StoreError::Invalid);
    }
    uuid7(a.request.operation)?;
    Ok((a, state, ready))
}
fn load(conn: &Connection, checkout: Uuid) -> Result<Option<Receipt>> {
    let receipt = receipt_only(conn, checkout)?;
    if receipt.is_some() {
        writer_free(conn, checkout)?;
    }
    Ok(receipt)
}
fn receipt_only(conn: &Connection, checkout: Uuid) -> Result<Option<Receipt>> {
    let value: Option<(String, String)> = conn
        .query_row(
            "SELECT operation,record FROM task_finishes WHERE checkout=?1",
            [checkout.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((operation, body)) = value else {
        return Ok(None);
    };
    let r: Receipt = parse(&body)?;
    uuid7(r.operation)?;
    crate::capture_journal::exclude_operation(conn, &r.operation)?;
    uuid7(r.checkout)?;
    let (a, state, ready) = allocation(conn, checkout)?;
    let events:i64 = conn.query_row("SELECT count(*) FROM outbox WHERE json_extract(payload,'$.type')='task_finished' AND json_extract(payload,'$.checkout')=?1 AND json_extract(payload,'$.operation')=?2",(checkout.to_string(),r.operation.to_string()),|row|row.get(0))?;
    let collision: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 OR operation=?1)
        OR EXISTS(SELECT 1 FROM writers WHERE group_id=?1)
        OR EXISTS(SELECT 1 FROM runs WHERE id=?1 OR group_id=?1)
        OR EXISTS(SELECT 1 FROM run_groups WHERE id=?1)
        OR EXISTS(SELECT 1 FROM adopted_groups WHERE id=?1 OR run_id=?1 OR operation=?1)
        OR EXISTS(SELECT 1 FROM run_participants WHERE id=?1)",
        [r.operation.to_string()],
        |row| row.get(0),
    )?;
    let canonical_capture = match r.local_freeze {
        Freeze::NotConfigured => {
            r.delivery == Some(Delivery::NotConfigured)
                && r.reason.is_none()
                && r.capture_binding == digest(json(&Option::<String>::None)?)
        }
        Freeze::Pending => r.delivery.is_none() && r.reason.is_none(),
        Freeze::Frozen => r.delivery != Some(Delivery::NotConfigured) && r.reason.is_none(),
        Freeze::Failed => {
            r.delivery.is_none()
                && matches!(
                    r.reason.as_deref(),
                    Some("capture-incomplete" | "capture-unsupported")
                )
        }
    };
    let no_binding = r.capture_binding == digest(json(&Option::<String>::None)?);
    if events != 1
        || collision
        || !canonical_capture
        || no_binding != (r.local_freeze == Freeze::NotConfigured)
    {
        return Err(StoreError::Invalid);
    }
    if r.version != 1
        || r.hold_reason != "retirement-disabled"
        || r.checkout != checkout
        || r.operation.to_string() != operation
        || r.allocation_operation != a.request.operation
        || r.allocation_digest != digest(json(&a)?)
        || Some(&r.identity) != a.identity.as_ref()
        || state != "held"
        || ready
    {
        return Err(StoreError::Invalid);
    }
    Ok(Some(r))
}
pub(crate) fn validate_schema(conn: &Connection) -> Result<()> {
    let table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='task_finishes' AND type='table')",
        [],
        |r| r.get(0),
    )?;
    if !table {
        return Err(StoreError::Invalid);
    }
    let ddl: String = conn.query_row(
        "SELECT sql FROM sqlite_schema WHERE name='task_finishes'",
        [],
        |r| r.get(0),
    )?;
    let normalize = |text: &str| {
        text.chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase()
    };
    if normalize(&ddl) != normalize(SCHEMA.split(';').next().ok_or(StoreError::Invalid)?) {
        return Err(StoreError::Invalid);
    }
    // Shape is authority-wide; receipt data is validated by load at every
    // targeted read/retry. Historical receipt count is not lifecycle policy,
    // and opening a store must not multiply outbox/roster scans by that count.
    Ok(())
}
pub(crate) fn operation_reserved(conn: &Connection, operation: &str) -> Result<bool> {
    let version: i64 = conn
        .prepare_cached("PRAGMA user_version")?
        .query_row([], |r| r.get(0))?;
    if version < 9 {
        return Ok(false);
    }
    Ok(conn
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM task_finishes WHERE operation=?1)")?
        .query_row([operation], |r| r.get(0))?)
}
pub(crate) fn task_open(conn: &Connection, checkout: Uuid) -> Result<bool> {
    Ok(load(conn, checkout)?.is_none())
}
pub(crate) fn capture_not_configured(conn: &Connection, checkout: Uuid) -> Result<bool> {
    Ok(load(conn, checkout)?.is_none_or(|r| r.local_freeze == Freeze::NotConfigured))
}
fn eligible(conn: &Connection, checkout: Uuid) -> Result<()> {
    let (a, state, ready) = allocation(conn, checkout)?;
    if state != "active" || !ready || a.checkout != checkout {
        return Err(StoreError::Invalid);
    }
    writer_free(conn, checkout)
}
fn writer_free(conn: &Connection, checkout: Uuid) -> Result<()> {
    writer_fence(conn, checkout)?;
    let target =
        work_contract::CheckoutId::parse(&checkout.to_string()).map_err(|_| StoreError::Invalid)?;
    crate::capture_journal::validate_related(conn, &target)
}
fn writer_fence(conn: &Connection, checkout: Uuid) -> Result<()> {
    let blocked: bool = conn.query_row("SELECT
        EXISTS(SELECT 1 FROM writers WHERE checkout=?1)
        OR EXISTS(SELECT 1 FROM adopted_groups WHERE checkout=?1)
        OR EXISTS(SELECT 1 FROM run_groups g LEFT JOIN runs r ON r.group_id=g.id
            WHERE g.checkout=?1 AND (g.mode!='supervised' OR g.closed!=1 OR g.recovery_hold!=0 OR r.id IS NULL))
        OR EXISTS(SELECT 1 FROM runs r LEFT JOIN run_groups g ON g.id=r.group_id WHERE g.id IS NULL)", [checkout.to_string()], |r|r.get(0))?;
    if blocked {
        return Err(StoreError::Writer);
    }
    crate::run_journal::validate_enrollment_rosters(conn)
}
/// Trusted library-only capture seam. Production never obtains a sink from CLI,
/// environment or a dynamic plugin. Implementations must deduplicate by operation.
pub trait LocalSink {
    fn freeze(&self, context: &CaptureContext) -> CaptureResult;
}
#[derive(Debug, Clone)]
pub struct CaptureContext {
    pub operation: Uuid,
    pub checkout: Uuid,
    pub identity: crate::identity::CheckoutIdentity,
}
#[derive(Debug, Clone)]
pub enum CaptureResult {
    Frozen {
        delivery: Option<Delivery>,
    },
    /// Local FINISH was attempted but durable confirmation is uncertain.
    Pending,
    Failed,
}
/// Boundary observer grants no policy or authority; intended for crash qualification.
pub fn finish_with_sink_observed(
    config: &Config,
    checkout: Uuid,
    sink: Option<&dyn LocalSink>,
    boundary: impl FnMut(&str),
) -> Result<Report> {
    finish_internal(config, checkout, Mode::Library(sink), boundary)
}
enum Mode<'a> {
    Library(Option<&'a dyn LocalSink>),
    Integrated,
}
fn finish_internal(
    config: &Config,
    checkout: Uuid,
    mode: Mode<'_>,
    mut boundary: impl FnMut(&str),
) -> Result<Report> {
    uuid7(checkout)?;
    let dir = config.store_dir.as_deref().ok_or(StoreError::Unsafe)?;
    let registry = config
        .trusted_registry
        .as_deref()
        .ok_or(StoreError::Unsafe)?;
    let mut store = Store::open_finish_authority(registry, dir, &config.roots)?;
    let integrated = matches!(mode, Mode::Integrated);
    {
        let _phase = store.sql_phase();
        let _snapshot = crate::run_journal::read_transaction(&store.conn)?;
        if load(&store.conn, checkout)?.is_none() {
            crate::attribution_gap::guard_finish(
                &store.conn,
                checkout,
                config
                    .allocation
                    .as_ref()
                    .is_some_and(|p| p.capture_sink.is_some()),
            )?;
        }
    }
    let captured_new = {
        let _phase = store.sql_phase();
        integrated
            && load(&store.conn, checkout)?.is_none()
            && crate::capture_journal::unresolved_checkout(&store.conn, checkout)?
    };
    let proof = if captured_new {
        Some(captured::Completion::inspect(&store, checkout)?)
    } else {
        None
    };
    let lock = allocate::lifecycle_lock(dir)?;
    let receipt = prepare(
        config,
        &mut store,
        checkout,
        &mode,
        proof.as_ref(),
        &mut boundary,
    )?;
    let compatible = receipt.capture_binding == digest(json(&Some("devdiary"))?);
    let capture_ready = !integrated
        || (compatible
            && (!matches!(receipt.local_freeze, Freeze::Pending | Freeze::Failed) || {
                let intents = captured::intents(&mut store, checkout);
                #[cfg(test)]
                if let Err(error) = &intents {
                    crate::capture_diagnostics::store_error("finish::intents-discard", error);
                }
                intents.is_ok()
            }));
    drop(lock);
    let adapter = CapturedFinish { config };
    let sink: Option<&dyn LocalSink> = match mode {
        Mode::Library(sink) => sink,
        Mode::Integrated if capture_ready => Some(&adapter),
        Mode::Integrated => None,
    };
    boundary("completion_committed");
    let configured = if integrated {
        Some("devdiary")
    } else {
        config
            .allocation
            .as_ref()
            .and_then(|a| a.capture_sink.as_deref())
    };
    let receipt = if matches!(receipt.local_freeze, Freeze::Pending | Freeze::Failed)
        && (integrated
            || (configured.is_some()
                && receipt.capture_binding == digest(json(&configured)?)
                && (sink.is_some() || receipt.local_freeze == Freeze::Pending)))
    {
        boundary("before_freeze");
        let result = sink.map(|s| {
            s.freeze(&CaptureContext {
                operation: receipt.operation,
                checkout: receipt.checkout,
                identity: receipt.identity.clone(),
            })
        });
        boundary("external_frozen");
        let mut updated = receipt.clone();
        match result {
            Some(CaptureResult::Pending) => {
                updated.local_freeze = Freeze::Pending;
                updated.delivery = None;
                updated.reason = None;
            }
            Some(CaptureResult::Frozen { delivery })
                if delivery != Some(Delivery::NotConfigured) =>
            {
                updated.local_freeze = Freeze::Frozen;
                updated.delivery = delivery;
                updated.reason = None;
            }
            _ => {
                updated.local_freeze = Freeze::Failed;
                updated.delivery = None;
                updated.reason = Some(
                    if integrated || sink.is_some() {
                        "capture-incomplete"
                    } else {
                        "capture-unsupported"
                    }
                    .into(),
                );
            }
        }
        let persisted = (|| -> Result<()> {
            let _phase = store.sql_phase();
            let tx = store
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let current = load(&tx, checkout)?.ok_or(StoreError::Invalid)?;
            if current != receipt {
                if current.operation != receipt.operation
                    || current.capture_binding != receipt.capture_binding
                {
                    return Err(StoreError::Conflict);
                }
                updated = current;
            } else {
                tx.execute(
                    "UPDATE task_finishes SET record=?2 WHERE checkout=?1",
                    (checkout.to_string(), json(&updated)?),
                )?;
                crate::store::emit(
                    &tx,
                    &crate::events::Event::FinishCaptureResult {
                        checkout,
                        operation: receipt.operation,
                    },
                )?;
            }
            tx.commit()?;
            Ok(())
        })();
        match persisted {
            Ok(()) => boundary("outcome_committed"),
            Err(_error @ StoreError::Database(_)) if integrated => {
                #[cfg(test)]
                crate::capture_diagnostics::store_error(
                    "finish::aggregate-persistence-fallback",
                    &_error,
                );
                updated = receipt.clone();
            }
            Err(error) => return Err(error),
        }
        updated
    } else {
        receipt
    };
    boundary("before_ack");
    let _phase = store.sql_phase();
    let _snapshot = crate::run_journal::read_transaction(&store.conn)?;
    let current = receipt_only(&store.conn, checkout)?.ok_or(StoreError::Invalid)?;
    writer_fence(&store.conn, checkout)?;
    if current.operation != receipt.operation {
        return Err(StoreError::Conflict);
    }
    // The complete writer fence validated every base root, roster and exact
    // writer. The projection below qualifies target capture history once in
    // this same snapshot; receipt-only validation never escapes this path.
    let mut stmt=store.conn.prepare("SELECT r.id,r.outcome,r.request FROM runs r JOIN run_groups g ON r.group_id=g.id WHERE g.checkout=?1 ORDER BY r.id")?;
    let roots = stmt
        .query_map([checkout.to_string()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut captured =
        crate::run_journal::with_capture_history(&store.conn, checkout, |history| {
            Ok(history
                .into_iter()
                .map(|(root, (capture, _, frozen))| {
                    let observation = if root.outcome.is_none() {
                        RunCapture::UnknownOutcome
                    } else if capture
                        .group_end
                        .as_ref()
                        .is_some_and(|e| e.clock_uncertain)
                    {
                        RunCapture::UncertainClock
                    } else {
                        match frozen {
                            Some(s) => match s.confirmation {
                                Some(c) => RunCapture::Frozen {
                                    delivery: if c.delivered {
                                        Delivery::Delivered
                                    } else {
                                        Delivery::Pending
                                    },
                                },
                                None => RunCapture::Unconfirmed,
                            },
                            None => RunCapture::Incomplete,
                        }
                    };
                    (
                        root.request.identity().run.to_string(),
                        (root.outcome, observation),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>())
        })?;
    let mut outcomes = Vec::new();
    for (id, outcome, request) in roots {
        let root: crate::run_journal::RootRunRequest = parse(&request)?;
        let gap = crate::attribution_gap::observation(&store.conn, &root)?;
        let run = work_contract::RunId::parse(&id).map_err(|_| StoreError::Invalid)?;
        let (outcome, capture) = if let Some(pair) = captured.remove(&id) {
            pair
        } else {
            (
                outcome.as_deref().map(parse).transpose()?,
                RunCapture::Missing,
            )
        };
        outcomes.push(RunOutcome {
            capture: if gap.is_some() {
                RunCapture::AttributionOff
            } else {
                capture
            },
            gap,
            run,
            outcome,
        });
    }
    Ok(report(current, outcomes))
}
/// Explicit completion observes original per-run capture facts, independently
/// of task completion and without delivery retries.
pub fn finish(config: &Config, checkout: Uuid) -> Result<Report> {
    finish_internal(config, checkout, Mode::Integrated, |_| {})
}
struct CapturedFinish<'a> {
    config: &'a Config,
}
impl LocalSink for CapturedFinish<'_> {
    fn freeze(&self, context: &CaptureContext) -> CaptureResult {
        match self.observe(context.checkout) {
            Ok(result) => result,
            Err(StoreError::CaptureFinishUncertain) => CaptureResult::Pending,
            Err(_) => CaptureResult::Failed,
        }
    }
}
impl CapturedFinish<'_> {
    fn observe(&self, checkout: Uuid) -> Result<CaptureResult> {
        let store = Store::open_existing_registered_mut(
            self.config
                .trusted_registry
                .as_deref()
                .ok_or(StoreError::Invalid)?,
            self.config
                .store_dir
                .as_deref()
                .ok_or(StoreError::Invalid)?,
            &self.config.roots,
        )?;
        let runs = {
            let _phase = store.sql_phase();
            crate::run_journal::with_capture_history(&store.conn, checkout, |history| {
                Ok(history
                    .into_iter()
                    .filter(|(r, (c, _, f))| {
                        r.outcome.is_some()
                            && c.group_end.as_ref().is_some_and(|e| !e.clock_uncertain)
                            && f.as_ref().is_some_and(|s| s.confirmation.is_none())
                    })
                    .map(|(r, _)| r.request.identity().run.clone())
                    .collect::<Vec<_>>())
            })?
        };
        let mut uncertain = false;
        let mut refused = false;
        for run in runs {
            match crate::capture_finalization::finalize(self.config, &run) {
                Ok(_) => {}
                Err(StoreError::CaptureFinishUncertain) => uncertain = true,
                Err(_) => refused = true,
            }
        }
        let _phase = store.sql_phase();
        let _snapshot = crate::run_journal::read_transaction(&store.conn)?;
        let total: i64 = store.conn.query_row(
            "SELECT count(*) FROM run_groups WHERE checkout=?1",
            [checkout.to_string()],
            |r| r.get(0),
        )?;
        crate::run_journal::with_capture_history(&store.conn, checkout, |history| {
            if refused
                || history.is_empty()
                || history.len() as i64 != total
                || history.iter().any(|(r, (c, _, _))| {
                    r.outcome.is_none() || c.group_end.as_ref().is_none_or(|e| e.clock_uncertain)
                })
            {
                return Ok(CaptureResult::Failed);
            }
            let mut delivered = true;
            for (_, (_, _, frozen)) in history {
                let Some(confirmation) = frozen.and_then(|f| f.confirmation) else {
                    return Ok(if uncertain {
                        CaptureResult::Pending
                    } else {
                        CaptureResult::Failed
                    });
                };
                delivered &= confirmation.delivered;
            }
            Ok(CaptureResult::Frozen {
                delivery: Some(if delivered {
                    Delivery::Delivered
                } else {
                    Delivery::Pending
                }),
            })
        })
    }
}
fn guard_unconfigured_capture(conn: &Connection, checkout: Uuid) -> Result<()> {
    if crate::capture_requirement::present(conn, checkout)?
        || crate::capture_journal::unresolved_checkout(conn, checkout)?
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn prepare(
    config: &Config,
    store: &mut Store,
    checkout: Uuid,
    mode: &Mode<'_>,
    proof: Option<&captured::Completion>,
    boundary: &mut impl FnMut(&str),
) -> Result<Receipt> {
    let configured = {
        let _phase = store.sql_phase();
        let current = config
            .allocation
            .as_ref()
            .and_then(|a| a.capture_sink.clone());
        if matches!(mode, Mode::Integrated)
            && current.is_none()
            && (crate::capture_requirement::present(&store.conn, checkout)?
                || crate::capture_journal::unresolved_checkout(&store.conn, checkout)?)
        {
            Some("devdiary".to_owned())
        } else {
            current
        }
    };
    let guard_capture = |conn: &Connection| -> Result<()> {
        // Current configuration cannot erase durable attribution obligations.
        // Only the integrated path derives a family from durable obligations;
        // generic no-sink callers cannot bypass the raw presence fence.
        if configured.is_none() {
            guard_unconfigured_capture(conn, checkout)?;
        }
        Ok(())
    };
    {
        let _phase = store.sql_phase();
        if let Some(r) = load(&store.conn, checkout)? {
            return Ok(r);
        }
        crate::attribution_gap::guard_finish(
            &store.conn,
            checkout,
            config
                .allocation
                .as_ref()
                .is_some_and(|p| p.capture_sink.is_some()),
        )?;
        guard_capture(&store.conn)?;
        if let Some(proof) = proof {
            proof.validate(&store.conn)?;
        } else {
            eligible(&store.conn, checkout)?;
        }
    }
    let a = if let Some(proof) = proof {
        proof.allocation()
    } else {
        allocate::verified_checkout(store, checkout).map_err(|_| StoreError::Invalid)?
    };
    let operation = Uuid::now_v7();
    #[cfg(test)]
    let operation = candidate_fixture::OPERATION
        .with(|slot| slot.take())
        .unwrap_or(operation);
    let receipt = Receipt {
        version: 1,
        checkout,
        operation,
        allocation_operation: a.request.operation,
        allocation_digest: digest(json(&a)?),
        hold_reason: "retirement-disabled".into(),
        identity: a.identity.clone().ok_or(StoreError::Invalid)?,
        capture_binding: digest(json(&configured)?),
        local_freeze: if configured.is_some() {
            Freeze::Pending
        } else {
            Freeze::NotConfigured
        },
        delivery: if configured.is_some() {
            None
        } else {
            Some(Delivery::NotConfigured)
        },
        reason: None,
    };
    {
        let _phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(receipt) = load(&tx, checkout)? {
            return Ok(receipt);
        }
        crate::attribution_gap::guard_finish(
            &tx,
            checkout,
            config
                .allocation
                .as_ref()
                .is_some_and(|p| p.capture_sink.is_some()),
        )?;
        guard_capture(&tx)?;
        if let Some(proof) = proof {
            proof.validate(&tx)?;
            tx.execute(
                "UPDATE allocations SET record=?2 WHERE checkout=?1",
                (checkout.to_string(), json(&a)?),
            )?;
        } else {
            eligible(&tx, checkout)?;
        }
        crate::store::exclude_journal_identity(&tx, operation)?;
        let collision: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 OR operation=?1) OR EXISTS(SELECT 1 FROM writers WHERE group_id=?1)",[operation.to_string()],|r|r.get(0))?;
        if collision {
            return Err(StoreError::Conflict);
        }
        let (current, _, _) = allocation(&tx, checkout)?;
        if json(&current)? != json(&a)? {
            return Err(StoreError::Conflict);
        }
        tx.execute(
            "INSERT INTO task_finishes VALUES(?1,?2,?3)",
            (checkout.to_string(), operation.to_string(), json(&receipt)?),
        )?;
        crate::capture_readiness::invalidate(&tx, checkout)?;
        tx.execute(
            "UPDATE checkouts SET state='held',ready=0 WHERE id=?1",
            [checkout.to_string()],
        )?;
        crate::store::emit(
            &tx,
            &crate::events::Event::TaskFinished {
                checkout,
                operation,
            },
        )?;
        boundary("before_commit");
        if let Some(proof) = proof {
            proof.fresh()?;
        }
        tx.commit()?;
    }
    Ok(receipt)
}
#[cfg(test)]
pub(crate) mod candidate_fixture {
    thread_local! {
        pub(crate) static OPERATION: std::cell::Cell<Option<uuid::Uuid>> = const { std::cell::Cell::new(None) };
    }
}
#[cfg(test)]
mod tests {
    fn closed_capture() -> (
        tempfile::TempDir,
        crate::config::Config,
        crate::allocate::Allocation,
        crate::run_journal::RootRunRequest,
        crate::capture_readiness::ClosureSeal,
    ) {
        closed_capture_with_timeout(50)
    }
    fn closed_capture_with_timeout(
        timeout_ms: u64,
    ) -> (
        tempfile::TempDir,
        crate::config::Config,
        crate::allocate::Allocation,
        crate::run_journal::RootRunRequest,
        crate::capture_readiness::ClosureSeal,
    ) {
        let (temp, cfg, a, root, seal) = closed_capture_case_with_timeout("known", timeout_ms);
        (temp, cfg, a, root, seal.unwrap())
    }
    fn closed_capture_case(
        case: &str,
    ) -> (
        tempfile::TempDir,
        crate::config::Config,
        crate::allocate::Allocation,
        crate::run_journal::RootRunRequest,
        Option<crate::capture_readiness::ClosureSeal>,
    ) {
        closed_capture_case_with_timeout(case, 50)
    }
    fn closed_capture_case_with_timeout(
        case: &str,
        timeout_ms: u64,
    ) -> (
        tempfile::TempDir,
        crate::config::Config,
        crate::allocate::Allocation,
        crate::run_journal::RootRunRequest,
        Option<crate::capture_readiness::ClosureSeal>,
    ) {
        let (temp, mut cfg, a, root, mut spec) =
            crate::capture_preparation::tests::qualified_fixture_with_timeout(timeout_ms);
        if case == "delay" {
            cfg.capture.as_mut().unwrap().timeout_ms = 2000;
            spec = cfg
                .capture_spec(&root, &a, spec.operation(), vec!["task".into()], None)
                .unwrap();
        }
        let (mut store, crate::capture_preparation::PreparationResult::Live(live)) =
            crate::capture_preparation::prepare(&cfg, &root, &spec).unwrap()
        else {
            panic!("live");
        };
        let binding = crate::test_run_fixture::binding(&root);
        store.record_bound(&root, &binding).unwrap();
        store.record_permit_attempt(&root, &binding).unwrap();
        if case != "unknown" {
            store
                .record_root_outcome(&root, crate::run_journal::RootOutcome::Completed)
                .unwrap();
        }
        if case == "clock" {
            store.conn.execute("UPDATE capture_runs SET intent_wall='2999-01-01T00:00:00+00:00',prepared=json_set(prepared,'$.observed_wall','2999-01-01T00:00:00+00:00')", []).unwrap();
        }
        let os = crate::test_run_fixture::ClosureOs::new(&root, &binding);
        let snapshot = store.group_snapshot(&root.identity().run).unwrap();
        let proof = snapshot.certify_empty(&os.driver, &binding).unwrap();
        let (_, seal) = store.close_live_capture(&snapshot, &proof, &live).unwrap();
        let declaration = spec.begin_request();
        std::fs::write(temp.path().join("response"), serde_json::to_vec(&serde_json::json!({"state":"pending","capture_id":"550e8400-e29b-41d4-a716-446655440001","actor_ref":declaration.actor_ref,"run_ref":declaration.run_ref})).unwrap()).unwrap();
        (temp, cfg, a, root, seal)
    }
    #[test]
    fn capture_delay_runs_outside_sql_and_lifecycle_lock() {
        let (temp, cfg, a, _, _) = closed_capture_case("delay");
        let dir = cfg.store_dir.as_ref().unwrap();
        let signal = temp.path().join("capturing");
        let progressed = temp.path().join("progressed");
        std::fs::write(
            temp.path().join("producer"),
            format!(
                r#"#!/usr/bin/python3
import json,sys,time,sqlite3,fcntl,os
json.load(sys.stdin)
c=sqlite3.connect({database:?},timeout=0)
c.execute('BEGIN IMMEDIATE');c.rollback()
f=open({lock:?},'r+');fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);f.close()
open({signal:?},'w').close()
time.sleep(0.65)
end=time.monotonic()+1
while not os.path.exists({progressed:?}) and time.monotonic()<end: time.sleep(.005)
assert os.path.exists({progressed:?})
json.dump(json.load(open({response:?})),sys.stdout)
"#,
                database = dir.join("store.sqlite"),
                lock = dir.join("allocation.lock"),
                response = temp.path().join("response")
            ),
        )
        .unwrap();
        let mut other_cfg = cfg.clone();
        other_cfg.allocation.as_mut().unwrap().capture_sink = None;
        let mut request = a.request.clone();
        request.operation = uuid::Uuid::now_v7();
        request.task = "independent".into();
        request.branch = Some("independent".into());
        let worker = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !signal.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert!(signal.exists());
            crate::allocate::start(&other_cfg, request).unwrap();
            std::fs::write(progressed, "ready").unwrap();
        });
        let report = super::finish(&cfg, a.checkout).unwrap();
        worker.join().unwrap();
        assert_eq!(report.local_freeze, super::Freeze::Frozen);
        assert!(report.task_finished);
    }
    #[test]
    fn late_completion_context_change_refuses_fence() {
        use super::*;
        for change in [
            "owner",
            "requirement",
            "hold",
            "root",
            "writer",
            "adopted",
            "open",
            "rootless",
            "orphan",
            "namespace",
            "expired",
            "near_commit",
        ] {
            let (_temp, cfg, a, _, _) = closed_capture();
            let mut store = Store::open_finish_authority(
                cfg.trusted_registry.as_ref().unwrap(),
                cfg.store_dir.as_ref().unwrap(),
                &cfg.roots,
            )
            .unwrap();
            let proof = captured::Completion::inspect(&store, a.checkout).unwrap();
            match change {
                "writer" => {
                    store
                        .conn
                        .execute(
                            "INSERT INTO writers VALUES(?1,?2)",
                            (a.checkout.to_string(), Uuid::now_v7().to_string()),
                        )
                        .unwrap();
                }
                "adopted" => {
                    store.conn.execute("INSERT INTO adopted_groups(id,checkout,run_id,run_ref,operation,request,revision) VALUES(?1,?2,?3,'adopted:race',?4,'{}',1)", rusqlite::params![Uuid::now_v7().to_string(), a.checkout.to_string(), Uuid::now_v7().to_string(), Uuid::now_v7().to_string()]).unwrap();
                }
                "open" => {
                    store
                        .conn
                        .execute("UPDATE run_groups SET closed=0", [])
                        .unwrap();
                }
                "rootless" => {
                    store.conn.execute("INSERT INTO run_groups(id,checkout,mode,revision) VALUES(?1,?2,'supervised',1)", (Uuid::now_v7().to_string(), a.checkout.to_string())).unwrap();
                }
                "orphan" => {
                    store.conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
                    store
                        .conn
                        .execute("UPDATE runs SET group_id=?1", [Uuid::now_v7().to_string()])
                        .unwrap();
                }
                "namespace" => {
                    store
                        .conn
                        .execute(
                            "UPDATE capture_runs SET operation=(SELECT operation FROM checkouts)",
                            [],
                        )
                        .unwrap();
                }
                "owner" => {
                    store
                        .conn
                        .execute("UPDATE checkouts SET owner='changed'", [])
                        .unwrap();
                }
                "requirement" => {
                    store
                        .conn
                        .execute("UPDATE capture_requirements SET revision=revision+1", [])
                        .unwrap();
                }
                "hold" => {
                    store
                        .conn
                        .execute(
                            "UPDATE allocations SET record=json_set(record,'$.reason','unrelated')",
                            [],
                        )
                        .unwrap();
                }
                "root" => {
                    store
                        .conn
                        .execute("UPDATE runs SET outcome='\"failed\"'", [])
                        .unwrap();
                }
                "expired" => std::thread::sleep(std::time::Duration::from_millis(2100)),
                _ => {}
            }
            let _lock = allocate::lifecycle_lock(cfg.store_dir.as_ref().unwrap()).unwrap();
            let result = prepare(
                &cfg,
                &mut store,
                a.checkout,
                &Mode::Integrated,
                Some(&proof),
                &mut |boundary| {
                    if change == "near_commit" && boundary == "before_commit" {
                        std::thread::sleep(std::time::Duration::from_millis(2100));
                    }
                },
            );
            assert!(result.is_err(), "{change}");
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT count(*) FROM task_finishes", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
            assert!(!store
                .conn
                .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
                .unwrap());
        }
    }
    #[test]
    fn completion_rechecks_rosters_and_frozen_context_before_task_fence() {
        use super::*;
        crate::capture_readiness::tests::many_closed_history(|cfg, _, a, _| {
            let mut store = Store::open_finish_authority(
                cfg.trusted_registry.as_ref().unwrap(),
                cfg.store_dir.as_ref().unwrap(),
                &cfg.roots,
            )
            .unwrap();
            for (table, column, replacement) in [
                ("run_participants", "host", "'{}'"),
                ("run_participants", "depth", "2"),
                (
                    "run_participants",
                    "id",
                    "(SELECT operation FROM capture_runs LIMIT 1)",
                ),
                (
                    "capture_finalizations",
                    "intent",
                    "json_set(intent,'$.context.operation','019b86f0-0000-7000-8000-000000000001')",
                ),
            ] {
                let proof = captured::Completion::inspect(&store, a.checkout).unwrap();
                let (rowid, original): (i64, rusqlite::types::Value) = store
                    .conn
                    .query_row(
                        &format!("SELECT rowid,{column} FROM {table} LIMIT 1"),
                        [],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .unwrap();
                store
                    .conn
                    .execute(
                        &format!("UPDATE {table} SET {column}={replacement} WHERE rowid=?1"),
                        [rowid],
                    )
                    .unwrap();
                let _lock = allocate::lifecycle_lock(cfg.store_dir.as_ref().unwrap()).unwrap();
                let result = prepare(
                    cfg,
                    &mut store,
                    a.checkout,
                    &Mode::Integrated,
                    Some(&proof),
                    &mut |_| {},
                );
                assert!(
                    matches!(result, Err(StoreError::Invalid)),
                    "{table}.{column}: {result:?}"
                );
                assert_eq!(
                    store
                        .conn
                        .query_row("SELECT count(*) FROM task_finishes", [], |r| r
                            .get::<_, i64>(0))
                        .unwrap(),
                    0
                );
                store
                    .conn
                    .execute(
                        &format!("UPDATE {table} SET {column}=?1 WHERE rowid=?2"),
                        rusqlite::params![original, rowid],
                    )
                    .unwrap();
            }
        });
    }
    #[test]
    fn captured_finish_refuses_changed_physical_identity() {
        for damage in ["marker", "branch", "source", "head"] {
            let (_temp, cfg, a, _, _) = closed_capture();
            let sql =
                rusqlite::Connection::open(cfg.store_dir.as_ref().unwrap().join("store.sqlite"))
                    .unwrap();
            let stored: String = sql
                .query_row("SELECT record FROM allocations", [], |r| r.get(0))
                .unwrap();
            let current: crate::allocate::Allocation = serde_json::from_str(&stored).unwrap();
            match damage {
                "marker" => std::fs::write(
                    current
                        .identity
                        .as_ref()
                        .unwrap()
                        .private_git_dir
                        .join("work-lease.json"),
                    "{}",
                )
                .unwrap(),
                "branch" => {
                    assert!(std::process::Command::new("git")
                        .current_dir(&a.destination)
                        .args(["symbolic-ref", "HEAD", "refs/heads/missing"])
                        .status()
                        .unwrap()
                        .success());
                }
                "source" => {
                    sql.execute("UPDATE allocations SET request=json_set(request,'$.repository','/missing'),record=json_set(record,'$.request.repository','/missing')", []).unwrap();
                }
                "head" => {
                    sql.execute(
                        "UPDATE allocations SET record=json_set(record,'$.identity.head',?1)",
                        ["a".repeat(40)],
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(super::finish(&cfg, a.checkout).is_err(), "{damage}");
            assert_eq!(
                sql.query_row("SELECT count(*) FROM task_finishes", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }
    #[test]
    fn binding_hashes_preserve_v1_exact_case_and_none() {
        use super::*;
        for (value, expected) in [
            (
                None,
                "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
            ),
            (
                Some("devdiary"),
                "ecb54e4a7d60dfeb3d4eeb764e8b362c822591c8586f8bf34c3dbc223cf4160a",
            ),
            (
                Some("DevDiary"),
                "98c0315c339d2c070ef569c41aba8d9592d0cb968d54aa37abb2feb6df71ded0",
            ),
        ] {
            let actual = digest(json(&value).unwrap())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            assert_eq!(actual, expected);
        }
    }
    #[test]
    fn historical_frozen_never_refreezes() {
        let (temp, mut cfg, a, root, _) = closed_capture();
        let first = super::finish(&cfg, a.checkout).unwrap();
        assert_eq!(first.delivery, Some(super::Delivery::Pending));
        let sql = rusqlite::Connection::open(cfg.store_dir.as_ref().unwrap().join("store.sqlite"))
            .unwrap();
        let before: String = sql
            .query_row("SELECT record FROM task_finishes", [], |r| r.get(0))
            .unwrap();
        let mut response: serde_json::Value =
            serde_json::from_slice(&std::fs::read(temp.path().join("response")).unwrap()).unwrap();
        response["state"] = "delivered".into();
        response["receipt"] = serde_json::json!({"actor_ref":response["actor_ref"],"run_ref":response["run_ref"],"event_id":"event:fixture","session_id":42});
        std::fs::write(temp.path().join("response"), response.to_string()).unwrap();
        crate::capture_finalization::retry_delivery(&cfg, &root.identity().run).unwrap();
        std::fs::remove_file(temp.path().join("producer")).unwrap();
        std::fs::remove_file(temp.path().join("actors.json")).unwrap();
        cfg.capture = None;
        cfg.supervisor = None;
        cfg.allocation.as_mut().unwrap().capture_sink = None;
        let replay = super::finish(&cfg, a.checkout).unwrap();
        assert_eq!(replay.operation, first.operation);
        assert_eq!(replay.delivery, Some(super::Delivery::Pending));
        assert_eq!(
            replay.run_outcomes[0].capture,
            super::RunCapture::Frozen {
                delivery: super::Delivery::Delivered
            }
        );
        assert_eq!(
            before,
            sql.query_row("SELECT record FROM task_finishes", [], |r| r
                .get::<_, String>(0))
                .unwrap()
        );
    }
    #[test]
    fn capture_outbox_fault_never_hides_committed_task_truth() {
        for event in ["capture_finalization_changed", "finish_capture_result"] {
            let (_temp, cfg, a, _, _) = closed_capture();
            let sql =
                rusqlite::Connection::open(cfg.store_dir.as_ref().unwrap().join("store.sqlite"))
                    .unwrap();
            sql.execute_batch(&format!("CREATE TRIGGER fail_capture BEFORE INSERT ON outbox WHEN json_extract(NEW.payload,'$.type')='{event}' BEGIN SELECT RAISE(FAIL,'injected'); END;")).unwrap();
            let report = super::finish(&cfg, a.checkout)
                .expect("known task completion survives capture outbox fault");
            assert!(report.task_finished && report.charge_retained && report.capture_incomplete);
            assert_eq!(
                sql.query_row("SELECT count(*) FROM task_finishes", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                1
            );
        }
    }
    #[test]
    fn family_mismatch_is_incomplete_without_calling_sealed_producer() {
        let (temp, mut cfg, a, _, _) = closed_capture();
        cfg.allocation.as_mut().unwrap().capture_sink = Some("DevDiary".into());
        std::fs::remove_file(temp.path().join("producer")).unwrap();
        let report = super::finish(&cfg, a.checkout).unwrap();
        assert!(report.task_finished);
        assert_eq!(report.local_freeze, super::Freeze::Failed);
        let sql = rusqlite::Connection::open(cfg.store_dir.as_ref().unwrap().join("store.sqlite"))
            .unwrap();
        assert_eq!(
            sql.query_row("SELECT count(*) FROM capture_finalizations", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn unknown_outcome_or_clock_finishes_task_but_never_invents_capture() {
        for case in ["unknown", "clock"] {
            let (temp, cfg, a, _root, _) = closed_capture_case(case);
            std::fs::remove_file(temp.path().join("producer")).unwrap();
            let report = super::finish(&cfg, a.checkout).unwrap();
            assert!(report.task_finished && report.capture_incomplete);
            assert_eq!(report.local_freeze, super::Freeze::Failed);
            assert_eq!(report.run_outcomes[0].outcome.is_none(), case == "unknown");
            let wire = serde_json::to_value(report).unwrap();
            assert_eq!(
                wire["run_outcomes"][0]["capture"]["state"],
                if case == "unknown" {
                    "unknown_outcome"
                } else {
                    "uncertain_clock"
                }
            );
        }
    }
    #[test]
    fn lost_finish_reply_replays_exact_intent_without_reexecuting_actor() {
        let _diagnostics = crate::capture_diagnostics::Guard::new();
        let (temp, mut cfg, a, root, _seal) = closed_capture();
        std::fs::write(temp.path().join("producer"), "#!/bin/sh\nexit 1\n").unwrap();
        let first = super::finish(&cfg, a.checkout).unwrap();
        assert!(first.task_finished && first.charge_retained);
        assert_eq!(first.local_freeze, super::Freeze::Pending);
        let sql = rusqlite::Connection::open(cfg.store_dir.as_ref().unwrap().join("store.sqlite"))
            .unwrap();
        let intent: String = sql
            .query_row("SELECT intent FROM capture_finalizations", [], |r| r.get(0))
            .unwrap();
        std::fs::write(temp.path().join("producer"), format!("#!/usr/bin/python3\nimport json,sys\nr=json.load(sys.stdin)\nassert r==json.loads({:?})\njson.dump(json.load(open({:?})),sys.stdout)\n", serde_json::from_str::<serde_json::Value>(&intent).unwrap()["body"].as_str().unwrap(), temp.path().join("response"))).unwrap();
        cfg.allocation.as_mut().unwrap().capture_sink = None;
        cfg.capture = None;
        let second = super::finish(&cfg, a.checkout).unwrap();
        assert_eq!(second.operation, first.operation);
        assert_eq!(second.local_freeze, super::Freeze::Frozen);
        assert_eq!(second.run_outcomes[0].run, root.identity().run);
        let after: String = sql
            .query_row("SELECT intent FROM capture_finalizations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(intent, after);
        assert_eq!(
            sql.query_row("SELECT count(*) FROM task_finishes", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn removed_selection_uses_sealed_captured_obligation() {
        let (_temp, mut cfg, a, _root, _seal) = closed_capture();
        cfg.allocation.as_mut().unwrap().capture_sink = None;
        cfg.capture = None;
        cfg.supervisor = None;
        let report = super::finish(&cfg, a.checkout).unwrap();
        assert_eq!(report.local_freeze, super::Freeze::Frozen);
        assert_eq!(report.delivery, Some(super::Delivery::Pending));
        let again = super::finish(&cfg, a.checkout).unwrap();
        assert_eq!(again.operation, report.operation);
    }
    #[test]
    fn held_known_capture_freezes_only_after_task_fence() {
        let _diagnostics = crate::capture_diagnostics::Guard::new();
        let (temp, cfg, a, root, _seal) = closed_capture_with_timeout(1000);
        assert_eq!(cfg.capture.as_ref().unwrap().timeout_ms, 1000);
        let sql = rusqlite::Connection::open_with_flags(
            cfg.store_dir.as_ref().unwrap().join("store.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let spec: String = sql
            .query_row(
                "SELECT spec FROM capture_runs WHERE run=?1",
                [root.identity().run.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        let spec: serde_json::Value = serde_json::from_str(&spec).unwrap();
        assert_eq!(spec["sink"]["timeout_ms"], 1000);
        drop(sql);
        std::fs::write(temp.path().join("producer"), format!("#!/usr/bin/python3\nimport json,sqlite3,sys\nr=json.load(sys.stdin)\nc=sqlite3.connect({:?})\nassert c.execute('SELECT count(*) FROM task_finishes').fetchone()[0]==1\nassert c.execute('SELECT count(*) FROM capture_finalizations').fetchone()[0]==1\njson.dump(json.load(open({:?})),sys.stdout)\n", cfg.store_dir.as_ref().unwrap().join("store.sqlite"), temp.path().join("response"))).unwrap();
        let report = super::finish(&cfg, a.checkout).unwrap();
        assert_eq!(report.local_freeze, super::Freeze::Frozen);
        assert!(report.task_finished && report.charge_retained);
    }
    #[test]
    fn ready_frozen_finish_is_passive_and_retains_charge() {
        let (temp, cfg, a, root, seal) = closed_capture();
        let (
            _,
            crate::capture_finalization::FinalizeResult::Confirmed {
                acknowledgement, ..
            },
        ) = crate::capture_finalization::finalize(&cfg, &root.identity().run).unwrap()
        else {
            panic!("confirmed");
        };
        crate::capture_readiness::restore(&cfg, seal, acknowledgement).unwrap();
        std::fs::remove_file(temp.path().join("producer")).unwrap();
        let report = super::finish(&cfg, a.checkout).unwrap();
        assert_eq!(report.local_freeze, super::Freeze::Frozen);
        assert_eq!(report.delivery, Some(super::Delivery::Pending));
        assert!(report.task_finished && report.charge_retained && !report.capture_incomplete);
    }
    #[test]
    fn missing_selection_fence_uses_raw_presence_including_v10_history() {
        use super::*;
        // Deliberately malformed payloads: this fence must never decode them.
        for (version, requirement, history) in [
            (13, false, false),
            (13, true, false),
            (13, false, true),
            (13, true, true),
            (10, false, true),
        ] {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch("CREATE TABLE capture_requirements(checkout TEXT); CREATE TABLE capture_runs(checkout TEXT, prepared TEXT);").unwrap();
            conn.pragma_update(None, "user_version", version).unwrap();
            let checkout = Uuid::now_v7();
            if requirement {
                conn.execute(
                    "INSERT INTO capture_requirements VALUES(?1)",
                    [checkout.to_string()],
                )
                .unwrap();
            }
            if history {
                conn.execute(
                    "INSERT INTO capture_runs VALUES(?1,'not-json')",
                    [checkout.to_string()],
                )
                .unwrap();
            }
            assert_eq!(
                guard_unconfigured_capture(&conn, checkout).is_err(),
                requirement || history
            );
            assert!(guard_unconfigured_capture(&conn, Uuid::now_v7()).is_ok());
        }
    }
    #[test]
    fn legal_finish_history_has_no_schema_quota_or_receipt_read_amplification() {
        use super::*;
        use crate::allocate::{Allocation, Start};
        use crate::identity::{CheckoutIdentity, DirectoryIdentity};
        for count in [512, 4097] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("r");
            std::fs::create_dir(&root).unwrap();
            let dir = temp.path().join("s");
            let mut store = Store::open(&dir, std::slice::from_ref(&root)).unwrap();
            let mut ids = Vec::new();
            let tx = store.conn.transaction().unwrap();
            for n in 0..count {
                let checkout = Uuid::now_v7();
                let operation = Uuid::now_v7();
                let task = n.to_string();
                let destination = root.join(&task);
                let identity = CheckoutIdentity {
                    path: destination.clone(),
                    private_git_dir: root.join(format!("g{n}")),
                    common_git_dir: root.clone(),
                    directory: DirectoryIdentity {
                        device: 1,
                        inode: n + 1,
                    },
                    head: "a".repeat(40),
                    boot_id: Uuid::now_v7().to_string(),
                };
                let a = Allocation {
                    checkout,
                    request: Start {
                        operation: Uuid::now_v7(),
                        repository: Some(root.clone()),
                        root: Some(root.clone()),
                        actor: Some("a".into()),
                        owner: Some("a".into()),
                        task: task.clone(),
                        branch: Some(task.clone()),
                        base: "main".into(),
                        reuse_branch: false,
                    },
                    destination,
                    base_commit: "a".repeat(40),
                    stage: "ready".into(),
                    reason: None,
                    identity: Some(identity.clone()),
                };
                let mut hash = Sha256::new();
                for field in [
                    "work-reservation-v1",
                    root.to_str().unwrap(),
                    "a",
                    "a",
                    &task,
                ] {
                    hash.update((field.len() as u64).to_be_bytes());
                    hash.update(field.as_bytes());
                }
                tx.execute(
                    "INSERT INTO checkouts VALUES(?1,?2,?3,?4,'a',?5,'a','held',0)",
                    (
                        checkout.to_string(),
                        a.request.operation.to_string(),
                        hash.finalize().to_vec(),
                        root.to_str(),
                        &task,
                    ),
                )
                .unwrap();
                tx.execute(
                    "INSERT INTO allocations VALUES(?1,?2,?3)",
                    (
                        checkout.to_string(),
                        json(&a.request).unwrap(),
                        json(&a).unwrap(),
                    ),
                )
                .unwrap();
                let r = Receipt {
                    version: 1,
                    checkout,
                    operation,
                    allocation_operation: a.request.operation,
                    allocation_digest: digest(json(&a).unwrap()),
                    hold_reason: "retirement-disabled".into(),
                    identity,
                    capture_binding: digest(json(&Option::<String>::None).unwrap()),
                    local_freeze: Freeze::NotConfigured,
                    delivery: Some(Delivery::NotConfigured),
                    reason: None,
                };
                tx.execute(
                    "INSERT INTO task_finishes VALUES(?1,?2,?3)",
                    (
                        checkout.to_string(),
                        operation.to_string(),
                        json(&r).unwrap(),
                    ),
                )
                .unwrap();
                crate::store::emit(
                    &tx,
                    &crate::events::Event::TaskFinished {
                        checkout,
                        operation,
                    },
                )
                .unwrap();
                ids.push(checkout);
            }
            tx.commit().unwrap();
            store
                .conn
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
                .unwrap();
            let bytes: u64 = ["store.sqlite", "store.sqlite-wal", "store.sqlite-shm"]
                .iter()
                .map(|name| std::fs::metadata(dir.join(name)).unwrap().len())
                .sum();
            assert!(
                bytes <= 16 * 1024 * 1024,
                "fixture exceeds technical file bound: {bytes}"
            );
            assert!(
                load(&store.conn, ids[0]).unwrap().is_some(),
                "fixture receipt is legal before schema check"
            );
            {
                let _phase = store.sql_phase();
                validate_schema(&store.conn).expect("schema validation must not read every historical receipt or impose a 4096 quota");
            }
            drop(store);
            let store = Store::open(&dir, std::slice::from_ref(&root)).unwrap();
            let middle = ids.len() / 2;
            for index in [0, middle, ids.len() - 1] {
                let _phase = store.sql_phase();
                assert_eq!(
                    load(&store.conn, ids[index]).unwrap().unwrap().checkout,
                    ids[index]
                );
            }
            store
                .conn
                .execute(
                    "UPDATE task_finishes SET record='{}' WHERE checkout=?1",
                    [ids[middle].to_string()],
                )
                .unwrap();
            assert!(
                load(&store.conn, ids[middle]).is_err(),
                "targeted corrupt history must not become None/Existing"
            );
        }
    }

    #[test]
    fn allocation_save_cannot_reopen_even_a_corrupt_finish_fence() {
        use crate::{
            admission::{Limits, Reservation},
            allocate::{Allocation, Start},
            store::Store,
        };
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let mut store =
            Store::open(&temp.path().join("private"), std::slice::from_ref(&root)).unwrap();
        let operation = uuid::Uuid::now_v7();
        let id = store
            .reserve(
                &Reservation {
                    operation,
                    repository: root.clone(),
                    actor: "actor".into(),
                    owner: "actor".into(),
                    task: "task".into(),
                },
                Limits {
                    repository: 2,
                    owner: 2,
                    available_bytes: Some(10),
                    floor_bytes: 0,
                    warn_bytes: 0,
                },
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO task_finishes VALUES(?1,?2,'{}')",
                (id.to_string(), uuid::Uuid::now_v7().to_string()),
            )
            .unwrap();
        let a = Allocation {
            checkout: id,
            request: Start {
                operation,
                repository: Some(root.clone()),
                root: Some(root.clone()),
                actor: Some("actor".into()),
                owner: Some("actor".into()),
                task: "task".into(),
                branch: Some("topic".into()),
                base: "main".into(),
                reuse_branch: false,
            },
            destination: root,
            base_commit: "base".into(),
            stage: "ready".into(),
            reason: None,
            identity: None,
        };
        let events = store.pending_events(100).unwrap();
        assert!(crate::allocate::save(&mut store, &a).is_err());
        assert_eq!(store.pending_events(100).unwrap(), events);
        assert_eq!(
            store
                .conn
                .query_row("SELECT state FROM checkouts", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "reserved"
        );
    }
}
