//! Strict physical-action metadata, not permission to claim, move or acknowledge.
//! Complete bounded global history admission precedes scoped history/framing.
//! Decoded rows never manufacture a live operation owner.
use crate::store::{Result, StoreError};
use rusqlite::{types::ValueRef, Connection};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;

pub(crate) const MAX_ROW_BYTES: usize = 8192;
pub(crate) const MAX_PATH_BYTES: usize = 4096;
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_PARENT_ROWS: u64 = 64;
const NAMESPACE_LOCK: &[u8] = b".work-quarantine-namespace-v1.lock";

// No IF NOT EXISTS, user_version write or changes to schema16 objects. The
// migration owner must install this in its fully vetted atomic transaction.
pub(crate) const SCHEMA: &str = concat!(
    "CREATE TABLE quarantine_actions(operation TEXT PRIMARY KEY REFERENCES retirement_intents(operation), checkout TEXT NOT NULL REFERENCES checkouts(id), revision INTEGER NOT NULL, state TEXT NOT NULL, plan TEXT NOT NULL, result TEXT, CHECK(typeof(operation)='text' AND length(CAST(operation AS BLOB))=36), CHECK(typeof(checkout)='text' AND length(CAST(checkout AS BLOB))=36), CHECK(typeof(revision)='integer'), CHECK(typeof(state)='text'), CHECK(typeof(plan)='text' AND length(CAST(plan AS BLOB))>0), CHECK(result IS NULL OR typeof(result)='text'), CHECK((state='move_pending' AND revision=1 AND result IS NULL) OR (state='quarantined' AND revision=2 AND result IS NOT NULL) OR (state='move_uncertain' AND revision=2 AND result IS NOT NULL)), CHECK(length(CAST(operation AS BLOB))+length(CAST(checkout AS BLOB))+8+length(CAST(state AS BLOB))+length(CAST(plan AS BLOB))+coalesce(length(CAST(result AS BLOB)),0)<=8192)); ",
    "CREATE INDEX quarantine_actions_checkout ON quarantine_actions(checkout);"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ActionState {
    MovePending,
    Quarantined,
    MoveUncertain,
}
impl ActionState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::MovePending => "move_pending",
            Self::Quarantined => "quarantined",
            Self::MoveUncertain => "move_uncertain",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "move_pending" => Ok(Self::MovePending),
            "quarantined" => Ok(Self::Quarantined),
            "move_uncertain" => Ok(Self::MoveUncertain),
            _ => Err(StoreError::Invalid),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum NativeProfile {
    #[serde(rename = "git255_absolute_files_sha1_attached_v1")]
    Git255AbsoluteFilesSha1AttachedV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UncertainReason {
    PreDispatchDrift,
    NativeFailed,
    NativeTimeout,
    CleanupFailed,
    IdentityDrift,
    DurabilityFailed,
    ScopeExpired,
    AcknowledgmentUnknown,
    VerificationFailed,
}
impl UncertainReason {
    const ALL: [Self; 9] = [
        Self::PreDispatchDrift,
        Self::NativeFailed,
        Self::NativeTimeout,
        Self::CleanupFailed,
        Self::IdentityDrift,
        Self::DurabilityFailed,
        Self::ScopeExpired,
        Self::AcknowledgmentUnknown,
        Self::VerificationFailed,
    ];
}

/// Recorded Linux identity DATA. No open descriptor or freshness is implied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) mount: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PathIdentity {
    /// Lowercase hex of exact absolute Unix path bytes, never lossy UTF-8.
    pub(crate) path: String,
    pub(crate) identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PhysicalPlan {
    pub(crate) version: u32,
    pub(crate) operation: String,
    pub(crate) checkout: String,
    pub(crate) prepared_record_hash: String,
    /// Exact prepared predecessor P and full current snapshot S, respectively.
    pub(crate) predecessor: String,
    pub(crate) snapshot: String,
    pub(crate) source: String,
    pub(crate) intent_history: String,
    pub(crate) intent_count: u64,
    pub(crate) physical_history: String,
    pub(crate) physical_count: u64,
    pub(crate) schema_version: u32,
    pub(crate) schema_cookie: u32,
    pub(crate) store: String,
    pub(crate) config: [String; 2],
    pub(crate) policy: String,
    pub(crate) boot: String,
    pub(crate) allocation: String,
    pub(crate) marker: String,
    pub(crate) protected_inputs: String,
    pub(crate) expected_links: String,
    pub(crate) original: PathIdentity,
    pub(crate) original_parent: PathIdentity,
    pub(crate) target: String,
    pub(crate) target_parent: PathIdentity,
    pub(crate) administrative: PathIdentity,
    pub(crate) common: PathIdentity,
    pub(crate) namespace_lock: PathIdentity,
    pub(crate) profile: NativeProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResultRecord {
    pub(crate) version: u32,
    pub(crate) operation: String,
    pub(crate) checkout: String,
    pub(crate) revision: u64,
    pub(crate) state: ActionState,
    /// SHA-256 of the exact stored plan bytes, including any legal whitespace.
    pub(crate) plan_hash: String,
    pub(crate) reason: Option<UncertainReason>,
    pub(crate) native_exit: Option<i32>,
    pub(crate) observed_target: Option<FileIdentity>,
    pub(crate) observed_links: Option<String>,
    pub(crate) protected_inputs: Option<String>,
    pub(crate) observed_wall_ms: u64,
}

/// Complete encoded row envelope. Plan/result are the actual stored JSON TEXT,
/// not reserialized DTOs: their quotes/escaping count towards the 8 KiB ceiling.
/// `version` versions this envelope; it is not a seventh SQL column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActionRow {
    pub(crate) version: u32,
    pub(crate) operation: String,
    pub(crate) checkout: String,
    pub(crate) revision: u64,
    pub(crate) state: ActionState,
    pub(crate) plan: String,
    pub(crate) result: Option<String>,
}

// Bound input BEFORE serde allocates, then reuse the existing duplicate-key,
// missing-option, unknown-field and object-versus-positional shape checker.
fn strict<T: DeserializeOwned + Serialize>(bytes: &str) -> Result<T> {
    if bytes.is_empty() || bytes.len() > MAX_ROW_BYTES {
        return Err(StoreError::Invalid);
    }
    crate::capture_journal::strict(bytes)
}

// Bound serialization itself, including callers presenting oversized DATA.
// No unbounded to_string allocation followed by a late length check.
struct Encoded(Vec<u8>);
impl Write for Encoded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_ROW_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("physical row exceeds bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode<T: Serialize>(value: &T) -> Result<String> {
    let mut out = Encoded(Vec::new());
    serde_json::to_writer(&mut out, value).map_err(|_| StoreError::Invalid)?;
    String::from_utf8(out.0).map_err(|_| StoreError::Invalid)
}
fn digest(value: &str) -> Result<()> {
    if value.len() != 64 || !lower_hex(value) {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
fn uuid(value: &str) -> Result<()> {
    crate::retirement_journal::parse_uuid(value).map(|_| ())
}
fn identity(value: &FileIdentity) -> Result<()> {
    if value.inode == 0 || value.mount == 0 {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn path(value: &str) -> Result<Vec<u8>> {
    if value.len() < 2
        || value.len() > MAX_PATH_BYTES * 2
        || !value.len().is_multiple_of(2)
        || !lower_hex(value)
    {
        return Err(StoreError::Invalid);
    }
    fn nibble(byte: u8) -> u8 {
        if byte <= b'9' {
            byte - b'0'
        } else {
            byte - b'a' + 10
        }
    }
    let bytes: Vec<u8> = value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect();
    if bytes[0] != b'/' || bytes.contains(&0) {
        return Err(StoreError::Invalid);
    }
    if bytes.len() > 1
        && bytes[1..].split(|byte| *byte == b'/').any(|component| {
            component.is_empty()
                || component.len() > MAX_COMPONENT_BYTES
                || component == b"."
                || component == b".."
        })
    {
        return Err(StoreError::Invalid);
    }
    Ok(bytes)
}
fn path_identity(value: &PathIdentity) -> Result<Vec<u8>> {
    identity(&value.identity)?;
    path(&value.path)
}
fn parent(value: &[u8]) -> Result<&[u8]> {
    if value == b"/" {
        return Err(StoreError::Invalid);
    }
    let index = value
        .iter()
        .rposition(|byte| *byte == b'/')
        .ok_or(StoreError::Invalid)?;
    Ok(if index == 0 {
        &value[..1]
    } else {
        &value[..index]
    })
}
fn child(directory: &[u8], name: &[u8]) -> Vec<u8> {
    let mut out = directory.to_vec();
    if directory != b"/" {
        out.push(b'/');
    }
    out.extend_from_slice(name);
    out
}
fn overlaps(left: &[u8], right: &[u8]) -> bool {
    fn contains(parent: &[u8], child: &[u8]) -> bool {
        parent == child
            || (child.starts_with(parent)
                && (parent == b"/" || child.get(parent.len()) == Some(&b'/')))
    }
    contains(left, right) || contains(right, left)
}

fn validate_plan(plan: &PhysicalPlan) -> Result<()> {
    if plan.version != 1
        || plan.schema_version != 17
        || plan.schema_cookie > i32::MAX as u32
        || !(1..=MAX_PARENT_ROWS).contains(&plan.intent_count)
        || plan.physical_count >= plan.intent_count
    {
        return Err(StoreError::Invalid);
    }
    uuid(&plan.operation)?;
    uuid(&plan.checkout)?;
    if plan.operation == plan.checkout {
        return Err(StoreError::Invalid);
    }
    for value in [
        &plan.prepared_record_hash,
        &plan.predecessor,
        &plan.snapshot,
        &plan.source,
        &plan.intent_history,
        &plan.physical_history,
        &plan.store,
        &plan.config[0],
        &plan.config[1],
        &plan.policy,
        &plan.boot,
        &plan.allocation,
        &plan.marker,
        &plan.protected_inputs,
        &plan.expected_links,
    ] {
        digest(value)?;
    }
    let original = path_identity(&plan.original)?;
    let original_parent = path_identity(&plan.original_parent)?;
    let target = path(&plan.target)?;
    let target_parent = path_identity(&plan.target_parent)?;
    let administrative = path_identity(&plan.administrative)?;
    let common = path_identity(&plan.common)?;
    let namespace_lock = path_identity(&plan.namespace_lock)?;
    let leaf = format!("work-quarantine-v1-{}-{}", plan.checkout, plan.operation);
    if parent(&original)? != original_parent
        || parent(&target)? != target_parent
        || target != child(&target_parent, leaf.as_bytes())
        || namespace_lock != child(&target_parent, NAMESPACE_LOCK)
        || overlaps(&original, &target_parent)
        || overlaps(&original, &common)
        || overlaps(&original, &administrative)
        || overlaps(&target_parent, &common)
        || overlaps(&target_parent, &administrative)
    {
        return Err(StoreError::Invalid);
    }
    let moving = &plan.original.identity;
    for value in [
        &plan.original_parent.identity,
        &plan.target_parent.identity,
        &plan.namespace_lock.identity,
    ] {
        if value.device != moving.device || value.mount != moving.mount {
            return Err(StoreError::Invalid);
        }
    }
    let identities = [
        &plan.original.identity,
        &plan.original_parent.identity,
        &plan.target_parent.identity,
        &plan.administrative.identity,
        &plan.common.identity,
        &plan.namespace_lock.identity,
    ];
    for (index, first) in identities.iter().enumerate() {
        if identities[index + 1..]
            .iter()
            .any(|second| (first.device, first.inode) == (second.device, second.inode))
        {
            return Err(StoreError::Invalid);
        }
    }
    Ok(())
}

pub(crate) fn plan_hash(bytes: &str) -> String {
    crate::retirement_journal::hex(&Sha256::digest(bytes.as_bytes()))
}
pub(crate) fn encode_plan_with_result_capacity(plan: &PhysicalPlan) -> Result<String> {
    validate_plan(plan)?;
    let encoded = encode(plan)?;
    result_capacity(plan, &encoded)?;
    Ok(encoded)
}
pub(crate) fn decode_plan(bytes: &str) -> Result<PhysicalPlan> {
    let plan: PhysicalPlan = strict(bytes)?;
    validate_plan(&plan)?;
    result_capacity(&plan, bytes)?;
    Ok(plan)
}

fn validate_result(record: &ResultRecord) -> Result<()> {
    if record.version != 1 || record.revision != 2 {
        return Err(StoreError::Invalid);
    }
    uuid(&record.operation)?;
    uuid(&record.checkout)?;
    if record.operation == record.checkout {
        return Err(StoreError::Invalid);
    }
    digest(&record.plan_hash)?;
    if let Some(value) = &record.observed_target {
        identity(value)?;
    }
    for value in [&record.observed_links, &record.protected_inputs]
        .into_iter()
        .flatten()
    {
        digest(value)?;
    }
    match record.state {
        ActionState::Quarantined
            if record.reason.is_none()
                && record.native_exit == Some(0)
                && record.observed_target.is_some()
                && record.observed_links.is_some()
                && record.protected_inputs.is_some() =>
        {
            Ok(())
        }
        ActionState::MoveUncertain if record.reason.is_some() => Ok(()),
        _ => Err(StoreError::Invalid),
    }
}
pub(crate) fn encode_result(record: &ResultRecord) -> Result<String> {
    validate_result(record)?;
    encode(record)
}
pub(crate) fn decode_result(bytes: &str) -> Result<ResultRecord> {
    let record = strict(bytes)?;
    validate_result(&record)?;
    Ok(record)
}

fn raw_size(row: &ActionRow) -> Result<()> {
    let lengths = [
        row.operation.len(),
        row.checkout.len(),
        8,
        row.state.as_str().len(),
        row.plan.len(),
        row.result.as_ref().map_or(0, String::len),
    ];
    total_size(lengths)
}
fn total_size(lengths: [usize; 6]) -> Result<()> {
    let mut total = 0usize;
    for length in lengths {
        total = total.checked_add(length).ok_or(StoreError::Invalid)?;
        if total > MAX_ROW_BYTES {
            return Err(StoreError::Invalid);
        }
    }
    Ok(())
}

// This checks the ACTUAL plan TEXT in each complete encoded row, never a fixed
// estimate of result size. No disk/WAL headroom or live permission is reserved.
fn result_capacity(plan: &PhysicalPlan, bytes: &str) -> Result<()> {
    let mut row = ActionRow {
        version: 1,
        operation: plan.operation.clone(),
        checkout: plan.checkout.clone(),
        revision: 1,
        state: ActionState::MovePending,
        plan: bytes.to_owned(),
        result: None,
    };
    raw_size(&row)?;
    encode(&row)?;
    let mut record = ResultRecord {
        version: 1,
        operation: plan.operation.clone(),
        checkout: plan.checkout.clone(),
        revision: 2,
        state: ActionState::Quarantined,
        plan_hash: plan_hash(bytes),
        reason: None,
        native_exit: Some(0),
        observed_target: Some(plan.original.identity.clone()),
        observed_links: Some(plan.expected_links.clone()),
        protected_inputs: Some(plan.protected_inputs.clone()),
        observed_wall_ms: u64::MAX,
    };
    row.revision = 2;
    row.state = ActionState::Quarantined;
    row.result = Some(encode_result(&record)?);
    raw_size(&row)?;
    encode(&row)?;
    record.state = ActionState::MoveUncertain;
    record.observed_target = Some(FileIdentity {
        device: u64::MAX,
        inode: u64::MAX,
        mount: u64::MAX,
    });
    row.state = ActionState::MoveUncertain;
    for reason in UncertainReason::ALL {
        record.reason = Some(reason);
        // All optional slots present at largest widths dominate null. Hashes
        // have fixed lowercase-hex width; success IDs must match the actual plan.
        for exit in [i32::MIN, i32::MAX] {
            record.native_exit = Some(exit);
            row.result = Some(encode_result(&record)?);
            raw_size(&row)?;
            encode(&row)?;
        }
    }
    Ok(())
}

fn validate_row(row: &ActionRow) -> Result<()> {
    if row.version != 1 {
        return Err(StoreError::Invalid);
    }
    uuid(&row.operation)?;
    uuid(&row.checkout)?;
    raw_size(row)?;
    let plan = decode_plan(&row.plan)?;
    if row.operation != plan.operation || row.checkout != plan.checkout {
        return Err(StoreError::Invalid);
    }
    match (row.state, row.revision, row.result.as_deref()) {
        (ActionState::MovePending, 1, None) => Ok(()),
        (ActionState::Quarantined | ActionState::MoveUncertain, 2, Some(bytes)) => {
            let record = decode_result(bytes)?;
            if record.operation != row.operation
                || record.checkout != row.checkout
                || record.revision != row.revision
                || record.state != row.state
                || record.plan_hash != plan_hash(&row.plan)
            {
                return Err(StoreError::Invalid);
            }
            if row.state == ActionState::Quarantined
                && (record.observed_target.as_ref() != Some(&plan.original.identity)
                    || record.observed_links.as_ref() != Some(&plan.expected_links)
                    || record.protected_inputs.as_ref() != Some(&plan.protected_inputs))
            {
                return Err(StoreError::Invalid);
            }
            Ok(())
        }
        _ => Err(StoreError::Invalid),
    }
}
pub(crate) fn encode_row(row: &ActionRow) -> Result<String> {
    validate_row(row)?;
    encode(row)
}
pub(crate) fn decode_row(bytes: &str) -> Result<ActionRow> {
    let row = strict(bytes)?;
    validate_row(&row)?;
    // Noncanonical JSON whitespace/escapes can alter size in either direction.
    // Require BOTH supplied complete envelope and typed complete encoding fit.
    encode(&row)?;
    Ok(row)
}

/// Decode six borrowed SQLite values. No owned column or serde allocation until
/// every raw type/length and the aggregate column budget has been checked.
/// This is row metadata validation ONLY, never global/parent-history admission.
pub(crate) fn decode_columns(columns: [ValueRef<'_>; 6]) -> Result<ActionRow> {
    fn text(value: ValueRef<'_>, maximum: usize) -> Result<&str> {
        match value {
            ValueRef::Text(bytes) if bytes.len() <= maximum => {
                std::str::from_utf8(bytes).map_err(|_| StoreError::Invalid)
            }
            _ => Err(StoreError::Invalid),
        }
    }
    let operation = text(columns[0], 36)?;
    let checkout = text(columns[1], 36)?;
    let revision = match columns[2] {
        ValueRef::Integer(value @ (1 | 2)) => value as u64,
        _ => return Err(StoreError::Invalid),
    };
    let state = text(columns[3], 14)?;
    let plan = text(columns[4], MAX_ROW_BYTES)?;
    let result = match columns[5] {
        ValueRef::Null => None,
        value => Some(text(value, MAX_ROW_BYTES)?),
    };
    total_size([
        operation.len(),
        checkout.len(),
        8,
        state.len(),
        plan.len(),
        result.map_or(0, str::len),
    ])?;
    let row = ActionRow {
        version: 1,
        operation: operation.to_owned(),
        checkout: checkout.to_owned(),
        revision,
        state: ActionState::parse(state)?,
        plan: plan.to_owned(),
        result: result.map(str::to_owned),
    };
    validate_row(&row)?;
    encode(&row)?;
    Ok(row)
}

/// Exact stored DDL/index contract, without rewriting SQL, case-folding quoted
/// literals, repairing metadata, installing tables or changing user_version.
/// The caller owns the cumulative SQL budget and transactional version check.
pub(crate) fn validate_schema(conn: &Connection) -> Result<()> {
    let mut ddl = SCHEMA.split(';');
    let table_sql = ddl.next().ok_or(StoreError::Invalid)?;
    let index_sql = ddl.next().ok_or(StoreError::Invalid)?.trim_start();
    let mut statement = conn.prepare("SELECT type,name,sql FROM sqlite_schema WHERE tbl_name='quarantine_actions' ORDER BY type,name")?;
    let mut rows = statement.query([])?;
    let mut seen = [false; 3];
    while let Some(row) = rows.next()? {
        let (slot, kind, sql) = match row.get_ref(1)? {
            ValueRef::Text(b"quarantine_actions") => (0, b"table".as_slice(), Some(table_sql)),
            ValueRef::Text(b"quarantine_actions_checkout") => {
                (1, b"index".as_slice(), Some(index_sql))
            }
            ValueRef::Text(b"sqlite_autoindex_quarantine_actions_1") => {
                (2, b"index".as_slice(), None)
            }
            _ => return Err(StoreError::Invalid),
        };
        if seen[slot] || row.get_ref(0)? != ValueRef::Text(kind) {
            return Err(StoreError::Invalid);
        }
        match (row.get_ref(2)?, sql) {
            (ValueRef::Text(actual), Some(expected)) if actual == expected.as_bytes() => {}
            (ValueRef::Null, None) => {}
            _ => return Err(StoreError::Invalid),
        }
        seen[slot] = true;
    }
    if seen != [true; 3] {
        return Err(StoreError::Invalid);
    }
    drop(rows);
    drop(statement);
    let mut statement = conn.prepare("PRAGMA index_list(quarantine_actions)")?;
    let mut rows = statement.query([])?;
    let mut seen = [false; 2];
    while let Some(row) = rows.next()? {
        let (slot, unique, origin) = match row.get_ref(1)? {
            ValueRef::Text(b"quarantine_actions_checkout") => (0, 0, b"c".as_slice()),
            ValueRef::Text(b"sqlite_autoindex_quarantine_actions_1") => (1, 1, b"pk".as_slice()),
            _ => return Err(StoreError::Invalid),
        };
        if seen[slot]
            || row.get_ref(2)? != ValueRef::Integer(unique)
            || row.get_ref(3)? != ValueRef::Text(origin)
            || row.get_ref(4)? != ValueRef::Integer(0)
        {
            return Err(StoreError::Invalid);
        }
        seen[slot] = true;
    }
    if seen != [true; 2] {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

fn read_rows(conn: &Connection, checkout: uuid::Uuid) -> Result<Vec<ActionRow>> {
    let mut stmt = conn.prepare("SELECT operation,checkout,revision,state,plan,result FROM quarantine_actions WHERE checkout=?1 ORDER BY operation LIMIT 65")?;
    let mut cursor = stmt.query([checkout.to_string()])?;
    let mut rows = Vec::new();
    while let Some(raw) = cursor.next()? {
        if rows.len() == MAX_PARENT_ROWS as usize {
            return Err(StoreError::Invalid);
        }
        let row = decode_columns([
            raw.get_ref(0)?,
            raw.get_ref(1)?,
            raw.get_ref(2)?,
            raw.get_ref(3)?,
            raw.get_ref(4)?,
            raw.get_ref(5)?,
        ])?;
        if row.checkout != checkout.to_string() {
            return Err(StoreError::Invalid);
        }
        rows.push(row);
    }
    Ok(rows)
}

pub(crate) fn validate_all(conn: &Connection) -> Result<()> {
    use crate::retirement_journal as parent;
    crate::store::SchemaRole::HistoricalRead(crate::store::SupportedRetirementVersion::V17)
        .validate(conn)?;
    let orphan: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM quarantine_actions a LEFT JOIN retirement_intents r ON r.operation=a.operation LEFT JOIN checkouts c ON c.id=a.checkout WHERE r.operation IS NULL OR c.id IS NULL OR r.checkout!=a.checkout)", [], |r| r.get(0))?;
    if orphan {
        return Err(StoreError::Invalid);
    }
    for checkout in parent::parent_checkouts(conn)? {
        let parents = parent::read_history_rows(conn, checkout)?;
        let actions = read_rows(conn, checkout)?;
        if actions.len() > parents.len() {
            return Err(StoreError::Invalid);
        }
        for row in &parents {
            parent::validate_parent_namespace(conn, row)?;
            let action = actions
                .iter()
                .find(|action| action.operation == row.operation.to_string());
            let in_flight = row.held_reason.as_deref() == Some("quarantine_in_flight");
            if in_flight != action.is_some() {
                return Err(StoreError::Invalid);
            }
            if let Some(action) = action {
                if row.stage != "held"
                    || row.revision != 2
                    || row.mode != "supervised"
                    || row.aborted_from.is_some()
                {
                    return Err(StoreError::Invalid);
                }
                let plan = decode_plan(&action.plan)?;
                if plan.prepared_record_hash != plan_hash(&row.record)
                    || plan.predecessor != row.decoded.predecessor_hex
                    || plan.source != row.decoded.source_hex
                    || plan.intent_count != parents.len() as u64
                    || plan.intent_count != row.decoded.prior_history_count + 1
                    || plan.physical_count + 1 != actions.len() as u64
                    || plan.config != row.decoded.immutable_binding.config_manifests
                {
                    return Err(StoreError::Invalid);
                }
                // Reconstruct only relational preclaim stage; immutable v1 bytes
                // remain exact. This checks DATA commitments, not fresh authority.
                let mut before = parents.clone();
                let own = before
                    .iter_mut()
                    .find(|p| p.operation == row.operation)
                    .ok_or(StoreError::Invalid)?;
                own.stage = "prepared".into();
                own.revision = 1;
                own.held_reason = None;
                let (intent, _) = parent::frame_history_rows(&before, &mut Vec::new())?;
                let physical: Vec<_> = actions
                    .iter()
                    .filter(|a| a.operation != action.operation)
                    .collect();
                let physical =
                    frame_rows(physical.iter().copied(), physical.len(), &mut Vec::new())?.0;
                before.retain(|p| p.operation != row.operation);
                let (mut predecessor_history, _) =
                    parent::frame_history_rows(&before, &mut Vec::new())?;
                predecessor_history.extend_from_slice(&physical);
                if row.decoded.history_predecessor_hex
                    != parent::hex(&Sha256::digest(&predecessor_history))
                    || plan.intent_history != parent::hex(&Sha256::digest(&intent))
                    || plan.physical_history != parent::hex(&Sha256::digest(&physical))
                {
                    return Err(StoreError::Invalid);
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn read_history(conn: &Connection, checkout: uuid::Uuid) -> Result<Vec<ActionRow>> {
    validate_all(conn)?;
    read_rows(conn, checkout)
}

pub(crate) fn frame_history(
    conn: &Connection,
    checkout: uuid::Uuid,
    canonical: &mut Vec<u8>,
) -> Result<(Vec<u8>, u64)> {
    let rows = read_history(conn, checkout)?;
    frame_rows(rows.iter(), rows.len(), canonical)
}

fn frame_rows<'a>(
    rows: impl Iterator<Item = &'a ActionRow>,
    count: usize,
    canonical: &mut Vec<u8>,
) -> Result<(Vec<u8>, u64)> {
    fn frame(out: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
        out.push(tag);
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    let mut history = Vec::new();
    frame(&mut history, 0, b"work.quarantine.history.v1");
    frame(&mut history, 1, &(count as u64).to_be_bytes());
    for row in rows {
        frame(&mut history, 2, row.operation.as_bytes());
        frame(&mut history, 3, row.checkout.as_bytes());
        frame(&mut history, 4, &row.revision.to_be_bytes());
        frame(&mut history, 5, row.state.as_str().as_bytes());
        frame(&mut history, 6, row.plan.as_bytes());
        frame(&mut history, 7, &[u8::from(row.result.is_some())]);
        if let Some(result) = &row.result {
            frame(&mut history, 8, result.as_bytes());
        }
        // Full canonical envelope provides an additional complete-row boundary;
        // individual raw TEXT frames above preserve alternate legal JSON bytes.
        let encoded = encode_row(row)?;
        frame(&mut history, 9, encoded.as_bytes());
    }
    if canonical.len().saturating_add(history.len()) > 16 * 1024 * 1024 {
        return Err(StoreError::Invalid);
    }
    canonical.extend_from_slice(&history);
    Ok((history, count as u64))
}

#[cfg(test)]
#[path = "quarantine_journal_tests.rs"]
mod tests;
