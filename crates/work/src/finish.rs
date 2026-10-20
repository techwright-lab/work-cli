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
    pub run: work_contract::RunId,
    pub outcome: Option<crate::run_journal::RootOutcome>,
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
    writer_free(conn, checkout)?;
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
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 9 {
        return Ok(false);
    }
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM task_finishes WHERE operation=?1)",
        [operation],
        |r| r.get(0),
    )?)
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
    let blocked: bool = conn.query_row("SELECT
        EXISTS(SELECT 1 FROM writers WHERE checkout=?1)
        OR EXISTS(SELECT 1 FROM adopted_groups WHERE checkout=?1)
        OR EXISTS(SELECT 1 FROM run_groups g LEFT JOIN runs r ON r.group_id=g.id
            WHERE g.checkout=?1 AND (g.mode!='supervised' OR g.closed!=1 OR g.recovery_hold!=0 OR r.id IS NULL))
        OR EXISTS(SELECT 1 FROM runs r LEFT JOIN run_groups g ON g.id=r.group_id WHERE g.id IS NULL)", [checkout.to_string()], |r|r.get(0))?;
    if blocked {
        return Err(StoreError::Writer);
    }
    crate::run_journal::validate_enrollment_rosters(conn)?;
    Ok(())
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
    Frozen { delivery: Option<Delivery> },
    Failed,
}
/// Boundary observer grants no policy or authority; intended for crash qualification.
pub fn finish_with_sink_observed(
    config: &Config,
    checkout: Uuid,
    sink: Option<&dyn LocalSink>,
    mut boundary: impl FnMut(&str),
) -> Result<Report> {
    uuid7(checkout)?;
    let dir = config.store_dir.as_deref().ok_or(StoreError::Unsafe)?;
    let registry = config
        .trusted_registry
        .as_deref()
        .ok_or(StoreError::Unsafe)?;
    let mut store = Store::open_finish_authority(registry, dir, &config.roots)?;
    let lock = allocate::lifecycle_lock(dir)?;
    let receipt = prepare(config, &mut store, checkout, &mut boundary)?;
    drop(lock);
    boundary("completion_committed");
    let configured = config
        .allocation
        .as_ref()
        .and_then(|a| a.capture_sink.as_ref());
    let receipt = if matches!(receipt.local_freeze, Freeze::Pending | Freeze::Failed)
        && configured.is_some()
        && receipt.capture_binding == digest(json(&configured)?)
        && (sink.is_some() || receipt.local_freeze == Freeze::Pending)
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
                    if sink.is_some() {
                        "capture-incomplete"
                    } else {
                        "capture-unsupported"
                    }
                    .into(),
                );
            }
        }
        {
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
        }
        boundary("outcome_committed");
        updated
    } else {
        receipt
    };
    boundary("before_ack");
    let _phase = store.sql_phase();
    let _snapshot = crate::run_journal::read_transaction(&store.conn)?;
    let current = load(&store.conn, checkout)?.ok_or(StoreError::Invalid)?;
    if current.operation != receipt.operation {
        return Err(StoreError::Conflict);
    }
    let mut stmt=store.conn.prepare("SELECT r.id FROM runs r JOIN run_groups g ON r.group_id=g.id WHERE g.checkout=?1 ORDER BY r.id")?;
    let ids = stmt
        .query_map([checkout.to_string()], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut outcomes = Vec::new();
    for id in ids {
        let run = work_contract::RunId::parse(&id).map_err(|_| StoreError::Invalid)?;
        let (record, _, _) = store.run_status_record(&run)?;
        outcomes.push(RunOutcome {
            run,
            outcome: record.outcome,
        });
    }
    Ok(report(current, outcomes))
}
/// Production has no local capture implementation. Configured capture is an
/// honest unsupported failure, never silently an attribution-off bypass.
pub fn finish(config: &Config, checkout: Uuid) -> Result<Report> {
    finish_with_sink_observed(config, checkout, None, |_| {})
}
fn prepare(
    config: &Config,
    store: &mut Store,
    checkout: Uuid,
    boundary: &mut impl FnMut(&str),
) -> Result<Receipt> {
    {
        let _phase = store.sql_phase();
        if let Some(r) = load(&store.conn, checkout)? {
            return Ok(r);
        }
        eligible(&store.conn, checkout)?;
    }
    let a = allocate::verified_checkout(store, checkout).map_err(|_| StoreError::Invalid)?;
    let configured = config
        .allocation
        .as_ref()
        .and_then(|a| a.capture_sink.as_ref());
    let operation = Uuid::now_v7();
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
        eligible(&tx, checkout)?;
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
        tx.commit()?;
    }
    Ok(receipt)
}
#[cfg(test)]
mod tests {
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
