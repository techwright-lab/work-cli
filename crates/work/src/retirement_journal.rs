//! Authoritative SQLite retirement intent journal. Persistent fence, not deletion.
use crate::allocate::AuthorityLease;
use crate::events::Event;
use crate::store::{emit, Result, Store, StoreError};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) const SCHEMA: &str = "CREATE TABLE retirement_intents(operation TEXT PRIMARY KEY, checkout TEXT NOT NULL REFERENCES checkouts(id), revision INTEGER NOT NULL CHECK(revision>=1), stage TEXT NOT NULL CHECK(stage IN ('prepared','held','aborted')), mode TEXT NOT NULL CHECK(mode IN ('supervised','adopted')), assertion TEXT, declared_task TEXT, declared_operator TEXT, predecessor BLOB NOT NULL CHECK(length(predecessor)=32), source BLOB NOT NULL CHECK(length(source)=32), record TEXT NOT NULL CHECK(length(CAST(record AS BLOB))<=8192), held_reason TEXT, aborted_from INTEGER, CHECK((mode='adopted' AND assertion IS NOT NULL AND declared_task IS NOT NULL AND declared_operator IS NOT NULL) OR (mode='supervised' AND assertion IS NULL AND declared_task IS NULL AND declared_operator IS NULL)), CHECK((stage='prepared' AND revision=1 AND held_reason IS NULL AND aborted_from IS NULL) OR (stage='held' AND revision=2 AND held_reason IS NOT NULL AND aborted_from IS NULL) OR (stage='aborted' AND ((revision=2 AND aborted_from=1 AND held_reason IS NULL) OR (revision=3 AND aborted_from=2 AND held_reason IS NOT NULL))))); CREATE INDEX retirement_intents_checkout ON retirement_intents(checkout); CREATE UNIQUE INDEX retirement_intents_active ON retirement_intents(checkout) WHERE stage IN ('prepared','held'); PRAGMA user_version=16;";

pub(crate) const MAX_RECORD_BYTES: usize = 8192;
pub(crate) const MAX_HISTORY_ROWS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Attempt {
    Reserve,
    AllocationStage,
    AllocationHold,
    AllocationIdentity,
    AliasPublication,
    OwnerTransfer,
    OwnerRetire,
    WriterAcquire,
    RunJournal,
    GroupClose,
    ChildJournal,
    AdoptedBegin,
    AdoptedActivity,
    FinishPrepare,
    FinishCaptureResult,
    CapturePreparation,
    CaptureAdmission,
    CaptureReconcile,
    CaptureReadiness,
    CaptureFinalization,
    CaptureDelivery,
    GapAdmission,
    GapPublication,
    ExecutionPermit,
    ReceiptPublication,
    RecoveryRefs,
    AbortValidationFailed,
}

impl Attempt {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Reserve => "reserve",
            Self::AllocationStage => "allocation_stage",
            Self::AllocationHold => "allocation_hold",
            Self::AllocationIdentity => "allocation_identity",
            Self::AliasPublication => "alias_publication",
            Self::OwnerTransfer => "owner_transfer",
            Self::OwnerRetire => "owner_retire",
            Self::WriterAcquire => "writer_acquire",
            Self::RunJournal => "run_journal",
            Self::GroupClose => "group_close",
            Self::ChildJournal => "child_journal",
            Self::AdoptedBegin => "adopted_begin",
            Self::AdoptedActivity => "adopted_activity",
            Self::FinishPrepare => "finish_prepare",
            Self::FinishCaptureResult => "finish_capture_result",
            Self::CapturePreparation => "capture_preparation",
            Self::CaptureAdmission => "capture_admission",
            Self::CaptureReconcile => "capture_reconcile",
            Self::CaptureReadiness => "capture_readiness",
            Self::CaptureFinalization => "capture_finalization",
            Self::CaptureDelivery => "capture_delivery",
            Self::GapAdmission => "gap_admission",
            Self::GapPublication => "gap_publication",
            Self::ExecutionPermit => "execution_permit",
            Self::ReceiptPublication => "receipt_publication",
            Self::RecoveryRefs => "recovery_refs",
            Self::AbortValidationFailed => "abort_validation_failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    Checkout(Uuid),
    Checkouts(Vec<Uuid>),
    Run(Uuid),
    Group(Uuid),
    Owner(String),
    Repositories(BTreeSet<String>),
    Allocation {
        checkouts: BTreeSet<Uuid>,
        repositories: BTreeSet<String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mode {
    Supervised,
    Adopted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
    Prepared,
    Held,
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdoptedDeclaration {
    pub(crate) task: String,
    pub(crate) operator: String,
    pub(crate) assertion: String,
    pub(crate) operation: String,
    pub(crate) checkout: String,
    pub(crate) predecessor_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImmutableBinding {
    pub(crate) version: u32,
    pub(crate) authority_allocation: String,
    pub(crate) source_sql: String,
    pub(crate) managed_physical: String,
    pub(crate) census: String,
    pub(crate) git_private: String,
    pub(crate) local_git: String,
    pub(crate) git_inputs: String,
    pub(crate) source_commitment: String,
    pub(crate) approval_semantic: String,
    pub(crate) approval_invalidation: String,
    pub(crate) protection: String,
    pub(crate) protection_count: u64,
    pub(crate) config_manifests: [String; 2],
    pub(crate) inspection_policy: String,
    pub(crate) combined_policy: String,
    pub(crate) operator: String,
    pub(crate) source_repository: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IntentRecord {
    pub(crate) version: u32,
    pub(crate) operation: String,
    pub(crate) checkout: String,
    pub(crate) mode: Mode,
    pub(crate) revision: u64,
    pub(crate) stage: Stage,
    pub(crate) assertion: Option<String>,
    pub(crate) declaration: Option<AdoptedDeclaration>,
    pub(crate) predecessor_hex: String,
    pub(crate) source_hex: String,
    pub(crate) history_predecessor_hex: String,
    pub(crate) prior_history_count: u64,
    pub(crate) immutable_binding: ImmutableBinding,
    pub(crate) quiescence: String,
    pub(crate) task_completion: String,
    pub(crate) policy_digest: String,
    pub(crate) combined_policy_digest: String,
    pub(crate) prepared_wall_ms: u64,
    pub(crate) remote_cleanup: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IntentRow {
    pub(crate) operation: Uuid,
    pub(crate) checkout: Uuid,
    pub(crate) revision: i64,
    pub(crate) stage: String,
    pub(crate) mode: String,
    pub(crate) assertion: Option<String>,
    pub(crate) declared_task: Option<String>,
    pub(crate) declared_operator: Option<String>,
    pub(crate) predecessor: Vec<u8>,
    pub(crate) source: Vec<u8>,
    pub(crate) record: String,
    pub(crate) held_reason: Option<String>,
    pub(crate) aborted_from: Option<i64>,
    pub(crate) decoded: IntentRecord,
}

pub(crate) fn validate_schema(conn: &Connection) -> Result<()> {
    for ((name, kind), expected) in [
        ("retirement_intents", "table"),
        ("retirement_intents_checkout", "index"),
        ("retirement_intents_active", "index"),
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
    let mut stmt = conn.prepare("PRAGMA index_list(retirement_intents)")?;
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
    let expected = vec![
        ("c".to_owned(), false, false),
        ("c".to_owned(), true, true),
        ("pk".to_owned(), true, false),
    ];
    if indices != expected {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

pub(crate) fn schema_version(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
}

pub(crate) fn operation_reserved(conn: &Connection, operation: &str) -> Result<bool> {
    if schema_version(conn)? < 16 {
        return Ok(false);
    }
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM retirement_intents WHERE operation=?1)",
        [operation],
        |r| r.get(0),
    )?)
}

pub(crate) fn exclude_operation(conn: &Connection, id: Uuid) -> Result<()> {
    if schema_version(conn)? < 16 {
        return Ok(());
    }
    let reserved: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM retirement_intents WHERE operation=?1 OR checkout=?1)",
        [id.to_string()],
        |r| r.get(0),
    )?;
    if reserved {
        Err(StoreError::Conflict)
    } else {
        Ok(())
    }
}

pub(crate) fn require_unfenced(conn: &Connection, checkout: Uuid) -> Result<()> {
    if schema_version(conn)? < 16 {
        return Ok(());
    }
    let active: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM retirement_intents WHERE checkout=?1 AND stage IN ('prepared','held'))",
        [checkout.to_string()],
        |r| r.get(0),
    )?;
    if active {
        Err(StoreError::RetirementFenced)
    } else {
        Ok(())
    }
}

pub(crate) fn fence<'c>(
    tx: Transaction<'c>,
    lease: &AuthorityLease,
    authority: &Arc<crate::store::AuthorityIdentity>,
    scope: Scope,
    attempt: Attempt,
) -> Result<Transaction<'c>> {
    lease.check_authority(authority)?;
    // Compatibility reads on old schemas cannot grant mutation permission,
    // including on an already-open Store whose version changed externally.
    if schema_version(&tx)? != 16 {
        return Err(StoreError::Invalid);
    }
    let checkouts = resolve_scope(&tx, &scope)?;
    let mut prepared = Vec::new();
    let mut held = false;
    for checkout in &checkouts {
        // Validate the complete bounded history before ANY update, including
        // tombstones and immutable-column bindings of already-held rows.
        for row in read_history(&tx, *checkout)? {
            match row.stage.as_str() {
                "prepared" => prepared.push((*checkout, row.operation.to_string())),
                "held" => held = true,
                "aborted" => {}
                _ => return Err(StoreError::Invalid),
            }
        }
    }
    if prepared.is_empty() {
        if held {
            return Err(StoreError::RetirementFenced);
        }
        return Ok(tx);
    }
    let reason = attempt.label();
    for (checkout, operation) in &prepared {
        let changed = tx.execute(
            "UPDATE retirement_intents SET revision=2, stage='held', held_reason=?3 WHERE operation=?1 AND checkout=?2 AND revision=1 AND stage='prepared' AND held_reason IS NULL AND aborted_from IS NULL",
            rusqlite::params![operation, checkout.to_string(), reason],
        )?;
        if changed != 1 {
            return Err(StoreError::Invalid);
        }
        let op = parse_uuid(operation)?;
        emit(
            &tx,
            &Event::RetirementIntentChanged {
                checkout: *checkout,
                operation: op,
                revision: 2,
                stage: "held".into(),
                reason: Some(reason.to_owned()),
            },
        )?;
    }
    tx.commit()?;
    Err(StoreError::RetirementFenced)
}

pub(crate) fn checkpoint(
    store: &mut Store,
    lease: &AuthorityLease,
    scope: Scope,
    attempt: Attempt,
) -> Result<()> {
    lease.check(store)?;
    let authority = store.authority_identity().clone();
    let _phase = store.sql_phase();
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let tx = fence(tx, lease, &authority, scope, attempt)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn begin_fenced<'s>(
    store: &'s mut Store,
    lease: &AuthorityLease,
    scope: Scope,
    attempt: Attempt,
) -> Result<Transaction<'s>> {
    lease.check(store)?;
    let authority = store.authority_identity().clone();
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    fence(tx, lease, &authority, scope, attempt)
}

fn resolve_scope(tx: &Connection, scope: &Scope) -> Result<Vec<Uuid>> {
    let mut ids = BTreeSet::new();
    match scope {
        Scope::Checkout(id) => {
            ids.insert(*id);
        }
        Scope::Checkouts(list) => ids.extend(list.iter().copied()),
        Scope::Run(id) => {
            let key = id.to_string();
            let mut stmt = tx.prepare(
                "SELECT checkout FROM run_groups WHERE id=?1
                 UNION SELECT g.checkout FROM run_groups g JOIN runs r ON r.group_id=g.id WHERE r.id=?1
                 UNION SELECT checkout FROM adopted_groups WHERE id=?1 OR run_id=?1",
            )?;
            for row in stmt.query_map([&key], |r| r.get::<_, String>(0))? {
                ids.insert(parse_uuid(&row?)?);
            }
        }
        Scope::Group(id) => {
            let key = id.to_string();
            let mut stmt = tx.prepare(
                "SELECT checkout FROM run_groups WHERE id=?1
                 UNION SELECT checkout FROM adopted_groups WHERE id=?1",
            )?;
            for row in stmt.query_map([&key], |r| r.get::<_, String>(0))? {
                ids.insert(parse_uuid(&row?)?);
            }
        }
        Scope::Owner(owner) => {
            let mut stmt = tx.prepare(
                "SELECT id FROM checkouts WHERE owner=?1 AND state!='retired' ORDER BY id",
            )?;
            for row in stmt.query_map([owner.as_str()], |r| r.get::<_, String>(0))? {
                ids.insert(parse_uuid(&row?)?);
            }
        }
        Scope::Repositories(repos) => {
            ids.extend(repository_checkouts(tx, repos)?);
        }
        Scope::Allocation {
            checkouts,
            repositories,
        } => {
            ids.extend(checkouts.iter().copied());
            ids.extend(repository_checkouts(tx, repositories)?);
        }
    }
    Ok(ids.into_iter().collect())
}

fn repository_checkouts(tx: &Connection, repos: &BTreeSet<String>) -> Result<BTreeSet<Uuid>> {
    let mut ids = BTreeSet::new();
    for repo in repos {
        let mut stmt = tx.prepare(
            "SELECT id FROM checkouts WHERE repository=?1
             OR repository IN (SELECT alias FROM repository_aliases WHERE alias=?1 OR common=?1)
             OR repository IN (SELECT common FROM repository_aliases WHERE alias=?1 OR common=?1)
             OR EXISTS (
                SELECT 1 FROM repository_aliases a
                WHERE (a.alias=checkouts.repository OR a.common=checkouts.repository)
                  AND (a.alias=?1 OR a.common=?1)
             )",
        )?;
        for row in stmt.query_map([repo.as_str()], |r| r.get::<_, String>(0))? {
            ids.insert(parse_uuid(&row?)?);
        }
    }
    Ok(ids)
}

pub(crate) fn encode_record(record: &IntentRecord) -> Result<String> {
    if record.version != 1 || record.revision != 1 || record.stage != Stage::Prepared {
        return Err(StoreError::Invalid);
    }
    validate_record(record)?;
    let bytes = serde_json::to_string(record).map_err(|_| StoreError::Invalid)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(StoreError::Invalid);
    }
    let roundtrip: IntentRecord = crate::capture_journal::strict(&bytes)?;
    if &roundtrip != record {
        return Err(StoreError::Invalid);
    }
    Ok(bytes)
}

pub(crate) fn decode_record(bytes: &str) -> Result<IntentRecord> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(StoreError::Invalid);
    }
    let record: IntentRecord = crate::capture_journal::strict(bytes)?;
    validate_record(&record)?;
    Ok(record)
}

fn validate_record(record: &IntentRecord) -> Result<()> {
    if record.version != 1 || record.prior_history_count >= MAX_HISTORY_ROWS as u64 {
        return Err(StoreError::Invalid);
    }
    parse_uuid(&record.operation)?;
    parse_uuid(&record.checkout)?;
    match record.mode {
        Mode::Adopted => {
            let assertion = record.assertion.as_deref().ok_or(StoreError::Invalid)?;
            parse_uuid(assertion)?;
            let declaration = record.declaration.as_ref().ok_or(StoreError::Invalid)?;
            if declaration.assertion != *assertion
                || declaration.operation != record.operation
                || declaration.checkout != record.checkout
                || declaration.predecessor_hex != record.predecessor_hex
            {
                return Err(StoreError::Invalid);
            }
            identity(&declaration.task)?;
            identity(&declaration.operator)?;
        }
        Mode::Supervised => {
            if record.assertion.is_some() || record.declaration.is_some() {
                return Err(StoreError::Invalid);
            }
        }
    }
    digest_hex(&record.predecessor_hex)?;
    digest_hex(&record.source_hex)?;
    digest_hex(&record.history_predecessor_hex)?;
    validate_binding(&record.immutable_binding)?;
    match record.mode {
        Mode::Supervised
            if record.quiescence == "empty" && record.task_completion == "supervised_empty" => {}
        Mode::Adopted
            if record.quiescence == "asserted" && record.task_completion == "adopted_declared" => {}
        _ => return Err(StoreError::Invalid),
    }
    if record.immutable_binding.source_sql != record.source_hex
        || record.immutable_binding.inspection_policy != record.policy_digest
        || record.immutable_binding.combined_policy != record.combined_policy_digest
    {
        return Err(StoreError::Invalid);
    }
    digest_hex(&record.policy_digest)?;
    digest_hex(&record.combined_policy_digest)?;
    allowlisted(
        &record.remote_cleanup,
        &["complete", "incomplete", "not_created", "not_required"],
    )?;
    if record.revision != 1 || record.stage != Stage::Prepared {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

fn validate_binding(binding: &ImmutableBinding) -> Result<()> {
    if binding.version != 1 {
        return Err(StoreError::Invalid);
    }
    for digest in [
        &binding.authority_allocation,
        &binding.source_sql,
        &binding.managed_physical,
        &binding.census,
        &binding.git_private,
        &binding.local_git,
        &binding.git_inputs,
        &binding.source_commitment,
        &binding.approval_semantic,
        &binding.approval_invalidation,
        &binding.protection,
        &binding.inspection_policy,
        &binding.combined_policy,
        &binding.operator,
        &binding.source_repository,
        &binding.config_manifests[0],
        &binding.config_manifests[1],
    ] {
        digest_hex(digest)?;
    }
    Ok(())
}

fn allowlisted(value: &str, allowed: &[&str]) -> Result<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(StoreError::Invalid)
    }
}

fn identity(value: &str) -> Result<()> {
    crate::store::identity(value)
}

fn digest_hex(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(StoreError::Invalid);
    }
    let mut out = [0u8; 32];
    for (i, chunk) in value.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(
            std::str::from_utf8(chunk).map_err(|_| StoreError::Invalid)?,
            16,
        )
        .map_err(|_| StoreError::Invalid)?;
    }
    Ok(out)
}

pub(crate) fn parse_uuid(value: &str) -> Result<Uuid> {
    let id = Uuid::parse_str(value).map_err(|_| StoreError::Invalid)?;
    if id.get_version_num() != 7
        || id.get_variant() != uuid::Variant::RFC4122
        || id.to_string() != value
    {
        return Err(StoreError::Invalid);
    }
    Ok(id)
}

pub(crate) fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

pub(crate) fn read_history(conn: &Connection, checkout: Uuid) -> Result<Vec<IntentRow>> {
    if schema_version(conn)? < 16 {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT operation,checkout,revision,stage,mode,assertion,declared_task,declared_operator,predecessor,source,record,held_reason,aborted_from,length(CAST(record AS BLOB)) FROM retirement_intents WHERE checkout=?1 ORDER BY operation LIMIT 65",
    )?;
    let mut cursor = stmt.query([checkout.to_string()])?;
    let mut rows = Vec::new();
    let mut active = false;
    while let Some(raw) = cursor.next()? {
        if rows.len() == MAX_HISTORY_ROWS {
            return Err(StoreError::Invalid);
        }
        let row = bounded_row(raw)?;
        if row.checkout != checkout {
            return Err(StoreError::Invalid);
        }
        if row.stage != "aborted" {
            if active {
                return Err(StoreError::Invalid);
            }
            active = true;
        }
        rows.push(row);
    }
    Ok(rows)
}

// Never get::<String/Vec<u8>> on an unbounded SQLite value. Check SQL byte
// length first, then borrowed raw types/lengths BEFORE allocating any column.
fn bounded_row(raw: &rusqlite::Row<'_>) -> Result<IntentRow> {
    use rusqlite::types::ValueRef;
    let length: i64 = raw.get(13)?;
    if !(0..=MAX_RECORD_BYTES as i64).contains(&length) {
        return Err(StoreError::Invalid);
    }
    fn text(raw: &rusqlite::Row<'_>, column: usize, limit: usize) -> Result<String> {
        match raw.get_ref(column)? {
            ValueRef::Text(bytes) if bytes.len() <= limit => Ok(std::str::from_utf8(bytes)
                .map_err(|_| StoreError::Invalid)?
                .to_owned()),
            _ => Err(StoreError::Invalid),
        }
    }
    fn optional(raw: &rusqlite::Row<'_>, column: usize, limit: usize) -> Result<Option<String>> {
        if matches!(raw.get_ref(column)?, ValueRef::Null) {
            Ok(None)
        } else {
            text(raw, column, limit).map(Some)
        }
    }
    fn digest(raw: &rusqlite::Row<'_>, column: usize) -> Result<Vec<u8>> {
        match raw.get_ref(column)? {
            ValueRef::Blob(bytes) if bytes.len() == 32 => Ok(bytes.to_vec()),
            _ => Err(StoreError::Invalid),
        }
    }
    let record = text(raw, 10, MAX_RECORD_BYTES)?;
    if record.len() as i64 != length {
        return Err(StoreError::Invalid);
    }
    let decoded = decode_record(&record)?;
    let row = IntentRow {
        operation: parse_uuid(&text(raw, 0, 36)?)?,
        checkout: parse_uuid(&text(raw, 1, 36)?)?,
        revision: raw.get(2)?,
        stage: text(raw, 3, 8)?,
        mode: text(raw, 4, 10)?,
        assertion: optional(raw, 5, 36)?,
        declared_task: optional(raw, 6, 1024)?,
        declared_operator: optional(raw, 7, 1024)?,
        predecessor: digest(raw, 8)?,
        source: digest(raw, 9)?,
        record,
        held_reason: optional(raw, 11, 32)?,
        aborted_from: raw.get(12)?,
        decoded,
    };
    validate_row(&row)?;
    Ok(row)
}

fn validate_row(row: &IntentRow) -> Result<()> {
    if row.decoded.operation != row.operation.to_string()
        || row.decoded.checkout != row.checkout.to_string()
        || row.predecessor.len() != 32
        || row.source.len() != 32
        || hex(&row.predecessor) != row.decoded.predecessor_hex
        || hex(&row.source) != row.decoded.source_hex
    {
        return Err(StoreError::Invalid);
    }
    match (row.mode.as_str(), row.decoded.mode) {
        ("supervised", Mode::Supervised) => {
            if row.assertion.is_some()
                || row.declared_task.is_some()
                || row.declared_operator.is_some()
            {
                return Err(StoreError::Invalid);
            }
        }
        ("adopted", Mode::Adopted) => {
            if row.assertion.as_deref() != row.decoded.assertion.as_deref()
                || row.declared_task.as_deref()
                    != row.decoded.declaration.as_ref().map(|d| d.task.as_str())
                || row.declared_operator.as_deref()
                    != row
                        .decoded
                        .declaration
                        .as_ref()
                        .map(|d| d.operator.as_str())
            {
                return Err(StoreError::Invalid);
            }
        }
        _ => return Err(StoreError::Invalid),
    }
    if let Some(reason) = &row.held_reason {
        allowlisted(
            reason,
            &[
                "reserve",
                "allocation_stage",
                "allocation_hold",
                "allocation_identity",
                "alias_publication",
                "owner_transfer",
                "owner_retire",
                "writer_acquire",
                "run_journal",
                "group_close",
                "child_journal",
                "adopted_begin",
                "adopted_activity",
                "finish_prepare",
                "finish_capture_result",
                "capture_preparation",
                "capture_admission",
                "capture_reconcile",
                "capture_readiness",
                "capture_finalization",
                "capture_delivery",
                "gap_admission",
                "gap_publication",
                "execution_permit",
                "receipt_publication",
                "recovery_refs",
                "abort_validation_failed",
            ],
        )?;
    }
    match (
        row.stage.as_str(),
        row.revision,
        row.held_reason.as_deref(),
        row.aborted_from,
    ) {
        ("prepared", 1, None, None) => Ok(()),
        ("held", 2, Some(_), None) => Ok(()),
        ("aborted", 2, None, Some(1)) | ("aborted", 3, Some(_), Some(2)) => Ok(()),
        _ => Err(StoreError::Invalid),
    }
}

fn frame_optional(out: &mut Vec<u8>, tag: u8, value: Option<&[u8]>) {
    frame(out, tag, &[u8::from(value.is_some())]);
    if let Some(value) = value {
        frame(out, tag, value);
    }
}

fn frame(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    out.extend((value.len() as u64).to_be_bytes());
    out.extend(value);
}

pub(crate) fn frame_history(
    tx: &Connection,
    checkout: Uuid,
    canonical: &mut Vec<u8>,
) -> Result<(Vec<u8>, u64)> {
    let rows = read_history(tx, checkout)?;
    frame_history_rows(&rows, canonical)
}

/// Validate ALL current rows before removing exactly the requested full frame.
/// Uses the identical framing as normal inspection, including the prior count.
pub(crate) fn frame_history_without(
    tx: &Connection,
    checkout: Uuid,
    operation: Uuid,
    canonical: &mut Vec<u8>,
) -> Result<(Vec<u8>, u64)> {
    let mut rows = read_history(tx, checkout)?;
    let index = rows
        .iter()
        .position(|row| row.operation == operation)
        .ok_or(StoreError::Conflict)?;
    rows.remove(index);
    frame_history_rows(&rows, canonical)
}

fn frame_history_rows(rows: &[IntentRow], canonical: &mut Vec<u8>) -> Result<(Vec<u8>, u64)> {
    let mut history = Vec::new();
    frame(&mut history, 13, b"retirement_history_v1");
    frame(&mut history, 14, &(rows.len() as u64).to_be_bytes());
    for row in rows {
        frame(&mut history, 15, row.operation.as_bytes());
        frame(&mut history, 16, &row.revision.to_be_bytes());
        frame(&mut history, 17, row.stage.as_bytes());
        frame(&mut history, 18, row.record.as_bytes());
        frame(&mut history, 19, &row.predecessor);
        frame(&mut history, 20, &row.source);
        frame(&mut history, 21, row.checkout.as_bytes());
        frame(&mut history, 22, row.mode.as_bytes());
        frame_optional(
            &mut history,
            23,
            row.assertion.as_deref().map(str::as_bytes),
        );
        frame_optional(
            &mut history,
            24,
            row.declared_task.as_deref().map(str::as_bytes),
        );
        frame_optional(
            &mut history,
            25,
            row.declared_operator.as_deref().map(str::as_bytes),
        );
        frame_optional(
            &mut history,
            26,
            row.held_reason.as_deref().map(str::as_bytes),
        );
        let aborted_from = row.aborted_from.map(i64::to_be_bytes);
        frame_optional(
            &mut history,
            27,
            aborted_from.as_ref().map(|bytes| bytes.as_slice()),
        );
    }
    // Preserve the inspection framing ceiling; the 64 * 8 KiB record bound is
    // neither disk reservation nor permission to exceed the full 16 MiB S cap.
    if canonical.len().saturating_add(history.len()) > 16 * 1024 * 1024 {
        return Err(StoreError::Invalid);
    }
    canonical.extend_from_slice(&history);
    Ok((history, rows.len() as u64))
}

pub(crate) struct PreparedInsert {
    pub(crate) operation: Uuid,
    pub(crate) checkout: Uuid,
    pub(crate) mode: Mode,
    pub(crate) assertion: Option<Uuid>,
    pub(crate) declared_task: Option<String>,
    pub(crate) declared_operator: Option<String>,
    pub(crate) predecessor: [u8; 32],
    pub(crate) source: [u8; 32],
    pub(crate) record: String,
}

pub(crate) fn exclude_prepare_operation(conn: &Connection, operation: Uuid) -> Result<()> {
    parse_uuid(&operation.to_string())?;
    crate::store::exclude_journal_identity(conn, operation)?;
    let collision: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 OR operation=?1)
             OR EXISTS(SELECT 1 FROM writers WHERE group_id=?1)",
        [operation.to_string()],
        |r| r.get(0),
    )?;
    if collision {
        Err(StoreError::Conflict)
    } else {
        Ok(())
    }
}

pub(crate) fn insert_prepared(tx: &Connection, insert: &PreparedInsert) -> Result<()> {
    exclude_prepare_operation(tx, insert.operation)?;
    let decoded = decode_record(&insert.record)?;
    let prior_count = decoded.prior_history_count;
    validate_row(&IntentRow {
        operation: insert.operation,
        checkout: insert.checkout,
        revision: 1,
        stage: "prepared".into(),
        mode: match insert.mode {
            Mode::Adopted => "adopted",
            Mode::Supervised => "supervised",
        }
        .into(),
        assertion: insert.assertion.map(|id| id.to_string()),
        declared_task: insert.declared_task.clone(),
        declared_operator: insert.declared_operator.clone(),
        predecessor: insert.predecessor.to_vec(),
        source: insert.source.to_vec(),
        record: insert.record.clone(),
        held_reason: None,
        aborted_from: None,
        decoded,
    })?;
    let history = read_history(tx, insert.checkout)?;
    if history.len() >= MAX_HISTORY_ROWS || prior_count != history.len() as u64 {
        return Err(StoreError::Invalid);
    }
    if history.iter().any(|row| row.operation == insert.operation) {
        return Err(StoreError::Conflict);
    }
    let active: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM retirement_intents WHERE checkout=?1 AND stage IN ('prepared','held'))",
        [insert.checkout.to_string()],
        |r| r.get(0),
    )?;
    if active {
        return Err(StoreError::Conflict);
    }
    tx.execute(
        "INSERT INTO retirement_intents(operation,checkout,revision,stage,mode,assertion,declared_task,declared_operator,predecessor,source,record,held_reason,aborted_from) VALUES(?1,?2,1,'prepared',?3,?4,?5,?6,?7,?8,?9,NULL,NULL)",
        rusqlite::params![
            insert.operation.to_string(),
            insert.checkout.to_string(),
            match insert.mode {
                Mode::Supervised => "supervised",
                Mode::Adopted => "adopted",
            },
            insert.assertion.map(|id| id.to_string()),
            insert.declared_task.as_deref(),
            insert.declared_operator.as_deref(),
            insert.predecessor.as_slice(),
            insert.source.as_slice(),
            insert.record.as_str(),
        ],
    )?;
    emit(
        tx,
        &Event::RetirementIntentChanged {
            checkout: insert.checkout,
            operation: insert.operation,
            revision: 1,
            stage: "prepared".into(),
            reason: None,
        },
    )?;
    Ok(())
}

pub(crate) fn abort_cas(
    tx: &Connection,
    checkout: Uuid,
    operation: Uuid,
    requested_revision: u64,
) -> Result<u64> {
    let history = read_history(tx, checkout)?;
    let row = history
        .into_iter()
        .find(|row| row.operation == operation)
        .ok_or(StoreError::Conflict)?;
    if requested_revision > 2 || requested_revision == 0 || row.checkout != checkout {
        return Err(StoreError::Conflict);
    }
    validate_row(&row)?;
    match (row.stage.as_str(), row.revision, requested_revision) {
        ("aborted", rev, req) if row.aborted_from == Some(req as i64) => Ok(rev as u64),
        ("prepared", 1, 1) => {
            let changed = tx.execute(
                "UPDATE retirement_intents SET revision=2, stage='aborted', aborted_from=1 WHERE operation=?1 AND checkout=?2 AND revision=1 AND stage='prepared' AND held_reason IS NULL AND aborted_from IS NULL",
                rusqlite::params![operation.to_string(), checkout.to_string()],
            )?;
            if changed != 1 {
                return Err(StoreError::Invalid);
            }
            emit(
                tx,
                &Event::RetirementIntentChanged {
                    checkout,
                    operation,
                    revision: 2,
                    stage: "aborted".into(),
                    reason: None,
                },
            )?;
            Ok(2)
        }
        ("held", 2, 2) => {
            let changed = tx.execute(
                "UPDATE retirement_intents SET revision=3, stage='aborted', aborted_from=2 WHERE operation=?1 AND checkout=?2 AND revision=2 AND stage='held' AND held_reason IS NOT NULL AND aborted_from IS NULL",
                rusqlite::params![operation.to_string(), checkout.to_string()],
            )?;
            if changed != 1 {
                return Err(StoreError::Invalid);
            }
            emit(
                tx,
                &Event::RetirementIntentChanged {
                    checkout,
                    operation,
                    revision: 3,
                    stage: "aborted".into(),
                    reason: row.held_reason.clone(),
                },
            )?;
            Ok(3)
        }
        _ => Err(StoreError::Conflict),
    }
}

pub(crate) fn hold_abort_validation(
    tx: &Connection,
    checkout: Uuid,
    operation: Uuid,
) -> Result<()> {
    let history = read_history(tx, checkout)?;
    let row = history
        .iter()
        .find(|row| row.operation == operation)
        .ok_or(StoreError::Conflict)?;
    if row.stage != "prepared" || row.revision != 1 {
        return Err(StoreError::Conflict);
    }
    let changed = tx.execute(
        "UPDATE retirement_intents SET revision=2, stage='held', held_reason=?3 WHERE operation=?1 AND checkout=?2 AND revision=1 AND stage='prepared' AND held_reason IS NULL AND aborted_from IS NULL",
        rusqlite::params![
            operation.to_string(),
            checkout.to_string(),
            Attempt::AbortValidationFailed.label()
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::Invalid);
    }
    emit(
        tx,
        &Event::RetirementIntentChanged {
            checkout,
            operation,
            revision: 2,
            stage: "held".into(),
            reason: Some(Attempt::AbortValidationFailed.label().to_owned()),
        },
    )?;
    Ok(())
}

pub(crate) fn find_operation(conn: &Connection, operation: Uuid) -> Result<Option<IntentRow>> {
    let mut stmt = conn.prepare(
        "SELECT operation,checkout,revision,stage,mode,assertion,declared_task,declared_operator,predecessor,source,record,held_reason,aborted_from,length(CAST(record AS BLOB)) FROM retirement_intents WHERE operation=?1",
    )?;
    let mut rows = stmt.query([operation.to_string()])?;
    match rows.next()? {
        Some(raw) => bounded_row(raw).map(Some),
        None => Ok(None),
    }
}

pub(crate) fn load_operation(conn: &Connection, operation: Uuid) -> Result<IntentRow> {
    find_operation(conn, operation)?.ok_or(StoreError::Invalid)
}

pub(crate) fn active_operation(conn: &Connection, checkout: Uuid) -> Result<Option<IntentRow>> {
    Ok(read_history(conn, checkout)?
        .into_iter()
        .find(|row| row.stage != "aborted"))
}

#[cfg(test)]
#[path = "retirement_journal_tests.rs"]
pub(crate) mod tests;
