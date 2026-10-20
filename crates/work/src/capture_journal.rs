//! Durable capture metadata, never execution, containment or retirement authority.
use crate::{
    capture_bridge::{BeginRequest, GitProfile, Source, WorkLifecycle},
    run_journal::{BeginRun, RootRunRequest, RunRecord},
    store::{Result, Store, StoreError},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;
use work_contract::{
    AllocationOperationId, CheckoutId, ExecutionChain, ExecutionMode, GroupId, RunId,
};

pub struct SinkSettings {
    pub executable: PathBuf,
    pub registry: PathBuf,
    pub state: PathBuf,
    pub timeout: Duration,
    pub response_cap: usize,
    /// Explicit trusted receiver identity, not inferred from a response.
    pub endpoint_identity: String,
    /// Trusted host identity label; this does not verify current registry bytes.
    pub registry_identity: String,
    pub receiver_credential_names: Vec<String>,
    pub registry_actor_ref: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkSnapshot {
    executable: PathBuf,
    registry: PathBuf,
    state: PathBuf,
    timeout_ms: u64,
    response_cap: usize,
    endpoint_identity: String,
    registry_identity: String,
    receiver_credential_names: Vec<String>,
    registry_actor_ref: String,
}
fn scalar(s: &str) -> Result<()> {
    if s.trim().is_empty() || s.chars().count() > 4096 || s.chars().any(char::is_control) {
        Err(StoreError::Invalid)
    } else {
        Ok(())
    }
}
fn absolute(p: &Path) -> Result<()> {
    scalar(p.to_str().ok_or(StoreError::Invalid)?)?;
    if !p.is_absolute()
        || p.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn uuid7(id: Uuid) -> Result<()> {
    if id.get_version_num() != 7 || id.get_variant() != uuid::Variant::RFC4122 {
        Err(StoreError::Invalid)
    } else {
        Ok(())
    }
}
fn id(v: &impl ToString) -> Result<Uuid> {
    Uuid::parse_str(&v.to_string()).map_err(|_| StoreError::Invalid)
}
// Per-record technical bound, not a history quota. Twice the 1 MiB wire
// allowance leaves room for sink paths/labels, 128 credential names and all
// four 4096-character Git identities, including full-width UTF-8/JSON escaping.
pub(crate) const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;
const MAX_CREDENTIAL_NAMES: usize = 128;
pub(crate) fn json<T: Serialize>(v: &T) -> Result<String> {
    struct Bounded(Vec<u8>);
    impl std::io::Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_RECORD_BYTES.saturating_sub(self.0.len()) {
                return Err(std::io::Error::other("capture record limit"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Bounded(Vec::new());
    serde_json::to_writer(&mut writer, v).map_err(|_| StoreError::Invalid)?;
    String::from_utf8(writer.0).map_err(|_| StoreError::Invalid)
}
fn digest(v: &impl Serialize) -> Result<[u8; 32]> {
    Ok(Sha256::digest(json(v)?).into())
}
impl SinkSnapshot {
    pub fn new(s: SinkSettings) -> Result<Self> {
        if s.timeout < Duration::from_millis(1)
            || s.timeout > Duration::from_millis(30000)
            || !s.timeout.subsec_nanos().is_multiple_of(1_000_000)
        {
            return Err(StoreError::Invalid);
        }
        let result = Self {
            executable: s.executable,
            registry: s.registry,
            state: s.state,
            timeout_ms: s.timeout.as_millis() as u64,
            response_cap: s.response_cap,
            endpoint_identity: s.endpoint_identity,
            registry_identity: s.registry_identity,
            receiver_credential_names: s.receiver_credential_names,
            registry_actor_ref: s.registry_actor_ref,
        };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<()> {
        for p in [&self.executable, &self.registry, &self.state] {
            absolute(p)?;
        }
        for s in [
            &self.endpoint_identity,
            &self.registry_identity,
            &self.registry_actor_ref,
        ] {
            scalar(s)?;
        }
        if !(1..=30000).contains(&self.timeout_ms)
            || !(1..=1048576).contains(&self.response_cap)
            || self.endpoint_identity.contains(['@', '?', '#'])
            || self.receiver_credential_names.len() > MAX_CREDENTIAL_NAMES
        {
            return Err(StoreError::Invalid);
        }
        let mut names = std::collections::HashSet::new();
        for name in &self.receiver_credential_names {
            if name.is_empty()
                || name.len() > 256
                || !name.bytes().enumerate().all(|(i, b)| {
                    b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit())
                })
                || !names.insert(name)
            {
                return Err(StoreError::Invalid);
            }
        }
        Ok(())
    }
    fn context_path(&self, capture_id: &str) -> PathBuf {
        self.state.join(format!("{capture_id}.context.json"))
    }
    pub fn process_settings(&self) -> Result<crate::sinks::ProcessSinkSettings> {
        self.validate()?;
        crate::sinks::ProcessSinkSettings::new(
            self.executable.clone(),
            self.registry.clone(),
            self.state.clone(),
            Duration::from_millis(self.timeout_ms),
            self.response_cap,
        )
        .map_err(|_| StoreError::Invalid)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedGit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    author_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    author_email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    committer_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    committer_email: Option<String>,
}
impl ExpectedGit {
    fn profile(&self) -> GitProfile {
        GitProfile {
            author_name: self.author_name.clone(),
            author_email: self.author_email.clone(),
            committer_name: self.committer_name.clone(),
            committer_email: self.committer_email.clone(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    actor_ref: String,
    run_ref: String,
    cwd: PathBuf,
    execution_chain: ExecutionChain,
    task_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_run_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<Source>,
    checkout: CheckoutId,
    group: GroupId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation_ref: Option<AllocationOperationId>,
}
/// Immutable host-selected metadata. No receiver keys, argv or arbitrary environment.
/// Deserialization is intentionally not public; stored bytes are strictly revalidated.
#[derive(Clone, Serialize)]
pub struct CaptureSpec {
    operation: Uuid,
    sink: SinkSnapshot,
    declaration: Declaration,
    expected_git: ExpectedGit,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SpecWire {
    operation: Uuid,
    sink: SinkSnapshot,
    declaration: Declaration,
    expected_git: ExpectedGit,
}
impl CaptureSpec {
    pub fn new(
        operation: Uuid,
        sink: SinkSnapshot,
        mut request: BeginRequest,
        git: GitProfile,
    ) -> Result<Self> {
        uuid7(operation)?;
        sink.validate()?;
        git.validate().map_err(|_| StoreError::Invalid)?;
        request.task_refs = crate::capture_bridge::canonical_task_refs(&request.task_refs)
            .map_err(|_| StoreError::Invalid)?
            .into_iter()
            .cloned()
            .collect();
        request.encode().map_err(|_| StoreError::Invalid)?;
        if request.lifecycle.mode != ExecutionMode::Supervised
            || request.actor_ref != sink.registry_actor_ref
        {
            return Err(StoreError::Invalid);
        }
        let group = request.lifecycle.group_id.ok_or(StoreError::Invalid)?;
        let spec = Self {
            operation,
            sink,
            declaration: Declaration {
                actor_ref: request.actor_ref,
                run_ref: request.run_ref,
                cwd: request.cwd,
                execution_chain: request.execution_chain,
                task_refs: request.task_refs,
                parent_run_ref: request.parent_run_ref,
                key_file: request.key_file,
                source: request.source,
                checkout: request.lifecycle.checkout_id,
                group,
                operation_ref: request.lifecycle.operation_id,
            },
            expected_git: ExpectedGit {
                author_name: git.author_name,
                author_email: git.author_email,
                committer_name: git.committer_name,
                committer_email: git.committer_email,
            },
        };
        if spec
            .declaration
            .operation_ref
            .as_ref()
            .is_some_and(|op| op.to_string() != operation.to_string())
        {
            return Err(StoreError::Invalid);
        }
        json(&spec)?;
        Ok(spec)
    }
    pub fn operation(&self) -> Uuid {
        self.operation
    }
    pub fn sink(&self) -> &SinkSnapshot {
        &self.sink
    }
    pub fn expected_git(&self) -> GitProfile {
        self.expected_git.profile()
    }
    pub fn begin_request(&self) -> BeginRequest {
        let d = &self.declaration;
        BeginRequest {
            actor_ref: d.actor_ref.clone(),
            run_ref: d.run_ref.clone(),
            cwd: d.cwd.clone(),
            execution_chain: d.execution_chain.clone(),
            task_refs: d.task_refs.clone(),
            parent_run_ref: d.parent_run_ref.clone(),
            key_file: d.key_file.clone(),
            source: d.source.clone(),
            lifecycle: WorkLifecycle {
                checkout_id: d.checkout.clone(),
                mode: ExecutionMode::Supervised,
                group_id: Some(d.group.clone()),
                operation_id: d.operation_ref.clone(),
            },
        }
    }
    fn decode(bytes: &str) -> Result<Self> {
        let w: SpecWire = strict(bytes)?;
        let candidate = Self {
            operation: w.operation,
            sink: w.sink,
            declaration: w.declaration,
            expected_git: w.expected_git,
        };
        Self::new(
            candidate.operation,
            candidate.sink.clone(),
            candidate.begin_request(),
            candidate.expected_git(),
        )
    }
    pub(crate) fn agrees(
        &self,
        conn: &Connection,
        r: &RootRunRequest,
    ) -> Result<crate::allocate::Allocation> {
        let row = AgreementRow::read(conn, &r.identity().checkout)?;
        self.agrees_with(&row, r)?;
        Ok(row.allocation)
    }
    fn agrees_with(&self, row: &AgreementRow, r: &RootRunRequest) -> Result<()> {
        let d = &self.declaration;
        let i = r.identity();
        let AgreementRow {
            task,
            operation,
            allocation,
            allocation_request,
        } = row;
        if allocation.checkout != id(&i.checkout)?
            || &allocation.request != allocation_request
            || &allocation.request.task != task
            || allocation.request.operation.to_string() != *operation
            || allocation.destination != d.cwd
            || allocation
                .identity
                .as_ref()
                .is_none_or(|identity| identity.path != d.cwd)
        {
            return Err(StoreError::Invalid);
        }
        if d.checkout != i.checkout
            || d.group != i.group
            || d.run_ref != i.run_ref.as_str()
            || d.execution_chain != i.execution_chain
            || d.parent_run_ref.as_deref() != i.parent_run_ref.as_ref().map(|s| s.as_str())
            || d.task_refs.first() != Some(task)
            || self.operation == id(&i.run)?
            || self.operation == id(&i.group)?
            || self.operation == id(&i.checkout)?
        {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }
}
struct AgreementRow {
    task: String,
    operation: String,
    allocation: crate::allocate::Allocation,
    allocation_request: crate::allocate::Start,
}
impl AgreementRow {
    fn read(conn: &Connection, checkout: &CheckoutId) -> Result<Self> {
        let (task,operation,request,record):(String,String,String,String)=conn.query_row(
            "SELECT c.task,c.operation,a.request,a.record FROM checkouts c JOIN allocations a ON a.checkout=c.id WHERE c.id=?1",
            [checkout.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?;
        let allocation = exact_json(&record)?;
        let allocation_request = exact_json(&request)?;
        Ok(Self {
            task,
            operation,
            allocation,
            allocation_request,
        })
    }
}
// Parse unique keys first (including objects in legitimate request arrays), then
// require the typed serializer's exact object/optional shape. Never let Value
// overwrite duplicate keys or serde accept positional representations of structs.
pub(crate) fn strict<T: serde::de::DeserializeOwned + Serialize>(bytes: &str) -> Result<T> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(StoreError::Invalid);
    }
    exact_json(bytes)
}
// Allocation history retains its existing typed domain, not the capture-record
// byte limit. Only the capture payload entry points use the bounded wrapper.
fn exact_json<T: serde::de::DeserializeOwned + Serialize>(bytes: &str) -> Result<T> {
    struct Unique;
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = Unique;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("unique JSON")
                }
                fn visit_map<M: serde::de::MapAccess<'de>>(
                    self,
                    mut m: M,
                ) -> std::result::Result<Unique, M::Error> {
                    let mut keys = std::collections::HashSet::new();
                    while let Some(k) = m.next_key::<String>()? {
                        if !keys.insert(k) {
                            return Err(serde::de::Error::custom("duplicate"));
                        }
                        m.next_value::<Unique>()?;
                    }
                    Ok(Unique)
                }
                fn visit_seq<S: serde::de::SeqAccess<'de>>(
                    self,
                    mut s: S,
                ) -> std::result::Result<Unique, S::Error> {
                    while s.next_element::<Unique>()?.is_some() {}
                    Ok(Unique)
                }
                fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_bool<E: serde::de::Error>(
                    self,
                    _: bool,
                ) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
            }
            d.deserialize_any(V)
        }
    }
    serde_json::from_str::<Unique>(bytes).map_err(|_| StoreError::Invalid)?;
    let value: serde_json::Value = serde_json::from_str(bytes).map_err(|_| StoreError::Invalid)?;
    let typed: T = T::deserialize(&value).map_err(|_| StoreError::Invalid)?;
    if serde_json::to_value(&typed).map_err(|_| StoreError::Invalid)? != value {
        return Err(StoreError::Invalid);
    }
    Ok(typed)
}
/// Created-only, nonserializable, non-Clone capability. Rows/DTOs cannot mint it.
/// ```compile_fail
/// let _: work_cli::capture_journal::PreparationHandle = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail
/// fn persist(handle: &work_cli::capture_journal::PreparationHandle) {
///     let _ = serde_json::to_string(handle);
/// }
/// ```
/// ```compile_fail
/// fn duplicate(handle: work_cli::capture_journal::PreparationHandle) {
///     let _ = handle.clone();
/// }
/// ```
pub struct PreparationHandle {
    request: RootRunRequest,
    spec: Box<CaptureSpec>,
    revision: u64,
    pending: Option<crate::capture_setup::PreparationContext>,
}
#[derive(Clone, Serialize)]
pub struct CaptureRecord {
    pub operation: Uuid,
    pub fingerprint: [u8; 32],
    pub intent_wall: String,
    pub prepared: Option<PreparationObservation>,
    pub group_end: Option<GroupEndObservation>,
}
pub use crate::capture_artifacts::ContextArtifactObservation;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationObservation {
    pub capture_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_artifact: Option<ContextArtifactObservation>,
    actor_ref: String,
    run_ref: String,
    context: PathBuf,
    git: ExpectedGit,
    projection_digest: [u8; 32],
    receiver_binding: [u8; 32],
    pub observed_wall: String,
    pub live_preparation: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupEndObservation {
    pub observed_wall: String,
    pub clock_uncertain: bool,
}
fn wall() -> String {
    chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now()).to_rfc3339()
}
fn date(s: &str) -> Result<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_rfc3339(s).map_err(|_| StoreError::Invalid)
}
pub(crate) fn observation(
    spec: &CaptureSpec,
    p: &crate::capture_bridge::Prepared,
    live: bool,
) -> Result<PreparationObservation> {
    let b = p.binding();
    let env = p.environment();
    if b.actor_ref() != spec.declaration.actor_ref
        || b.run_ref() != spec.declaration.run_ref
        || b.capture_id() != env.capture_id()
        || env.context_path() != spec.sink.context_path(b.capture_id().as_str())
        || !env.matches_git_profile(&spec.expected_git())
    {
        return Err(StoreError::Conflict);
    }
    let context = spec.sink.context_path(b.capture_id().as_str());
    let projection_digest = digest(&(b.capture_id().as_str(), &context, &spec.expected_git))?;
    Ok(PreparationObservation {
        capture_id: b.capture_id().as_str().into(),
        context_artifact: None,
        actor_ref: b.actor_ref().into(),
        run_ref: b.run_ref().into(),
        context,
        git: spec.expected_git.clone(),
        projection_digest,
        receiver_binding: digest(&spec.sink)?,
        observed_wall: wall(),
        live_preparation: live,
    })
}
/// Shared metadata transition only; callers own all eligibility and CAS decisions.
pub(crate) fn reconcile_hold(conn: &Connection, root: &RunRecord) -> Result<()> {
    let request = &root.request;
    let revision = root
        .revision
        .checked_add(1)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(StoreError::Invalid)?;
    conn.execute("UPDATE checkouts SET ready=0,state=CASE WHEN state='active' THEN 'held' ELSE state END WHERE id=?1", [request.identity().checkout.to_string()])?;
    if !root.closed {
        conn.execute(
            "UPDATE run_groups SET revision=?2,recovery_hold=1 WHERE id=?1",
            (request.identity().group.to_string(), revision as i64),
        )?;
    }
    crate::run_journal::journal_event(
        conn,
        request,
        revision,
        crate::run_journal::JournalChange::CaptureReconciled,
    )
}
pub enum BeginCapturedRun {
    Created(PreparationHandle),
    Existing(CaptureRecord),
}
impl Store {
    pub fn capture_snapshot(&self, run: &RunId) -> Result<Option<CaptureRecord>> {
        let _phase = self.sql_phase();
        let _snapshot = crate::run_journal::read_transaction(&self.conn)?;
        let root = crate::run_journal::read(&self.conn, run)?.ok_or(StoreError::Invalid)?;
        validate_related(&self.conn, &root.request.identity().checkout)?;
        let root = crate::run_journal::exact(&self.conn, &root.request)?;
        read(&self.conn, &root)
    }
    /// Consume a current Created-only capability after external I/O. SQL never
    /// spans that I/O; committing metadata cannot restore a runtime Binding.
    pub fn record_capture_prepared(
        &mut self,
        handle: PreparationHandle,
        prepared: &crate::capture_bridge::Prepared,
    ) -> Result<()> {
        self.commit_preparation(
            &handle.request,
            &handle.spec,
            prepared,
            Some(handle.revision),
            handle.pending.as_ref(),
            None,
        )
    }
    /// Only the actual qualified library path may attach an artifact observation.
    pub(crate) fn record_qualified_capture_prepared(
        &mut self,
        handle: PreparationHandle,
        prepared: &crate::capture_bridge::Prepared,
        context: &crate::capture_artifacts::Context,
    ) -> Result<()> {
        // Cached typed data only; all FD reads/revalidation precede this method.
        let artifact = context
            .observation(prepared.environment().context_path(), &handle.spec)
            .map_err(|_| StoreError::Conflict)?;
        self.commit_preparation(
            &handle.request,
            &handle.spec,
            prepared,
            Some(handle.revision),
            handle.pending.as_ref(),
            Some(artifact),
        )
    }
    /// A lost acknowledgement can attach matching metadata, never restore readiness.
    pub fn reconcile_capture_prepared(
        &mut self,
        request: &RootRunRequest,
        spec: &CaptureSpec,
        prepared: &crate::capture_bridge::Prepared,
    ) -> Result<()> {
        self.commit_preparation(request, spec, prepared, None, None, None)
    }
    fn commit_preparation(
        &mut self,
        request: &RootRunRequest,
        spec: &CaptureSpec,
        prepared: &crate::capture_bridge::Prepared,
        live_revision: Option<u64>,
        pending: Option<&crate::capture_setup::PreparationContext>,
        artifact: Option<ContextArtifactObservation>,
    ) -> Result<()> {
        let mut observation = observation(spec, prepared, live_revision.is_some())?;
        observation.context_artifact = artifact;
        let _phase = self.sql_phase();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_related(&tx, &request.identity().checkout)?;
        let root = crate::run_journal::exact(&tx, request)?;
        let record = read(&tx, &root)?.ok_or(StoreError::Invalid)?;
        if record.fingerprint != digest(spec)? || record.operation != spec.operation {
            return Err(StoreError::Conflict);
        }
        let (state, ready): (String, bool) = tx.query_row(
            "SELECT state,ready FROM checkouts WHERE id=?1",
            [request.identity().checkout.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if let Some(existing) = &record.prepared {
            if live_revision.is_some()
                || existing.capture_id != observation.capture_id
                || existing.projection_digest != observation.projection_digest
                || existing.receiver_binding != observation.receiver_binding
            {
                return Err(StoreError::Conflict);
            }
            // Closed historical acknowledgements cannot touch a newer writer or
            // readiness. Open resumed history is tightened, never made executable.
            if root.closed || (root.recovery_hold && state == "held" && !ready) {
                return Ok(());
            }
        }
        let fenced: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1)",
            [request.identity().checkout.to_string()],
            |r| r.get(0),
        )?;
        if fenced {
            return Err(StoreError::Invalid);
        }
        if live_revision.is_some()
            && (root.closed
                || root.stage != crate::run_journal::RunStage::Intent
                || root.outcome.is_some()
                || root.recovery_hold
                || live_revision != Some(root.revision)
                || state != "active"
                || ready
                || date(&observation.observed_wall)? < date(&record.intent_wall)?)
        {
            return Err(StoreError::Conflict);
        }
        let revision = root
            .revision
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(StoreError::Invalid)?;
        if record.prepared.is_none() {
            tx.execute(
                "UPDATE capture_runs SET prepared=?2 WHERE run=?1",
                (request.identity().run.to_string(), json(&observation)?),
            )?;
        }
        if live_revision.is_some() {
            if let Some(pending) = pending {
                pending.promote(&tx, id(&request.identity().checkout)?)?;
            }
            tx.execute(
                "UPDATE checkouts SET ready=1 WHERE id=?1",
                [request.identity().checkout.to_string()],
            )?;
        } else {
            reconcile_hold(&tx, &root)?;
            tx.commit()?;
            return Ok(());
        }
        if !root.closed {
            tx.execute("UPDATE run_groups SET revision=?2,recovery_hold=CASE WHEN ?3 THEN recovery_hold ELSE 1 END WHERE id=?1",(request.identity().group.to_string(),revision as i64,live_revision.is_some()))?;
        }
        crate::run_journal::journal_event(
            &tx,
            request,
            revision,
            if live_revision.is_some() {
                crate::run_journal::JournalChange::CapturePrepared
            } else {
                crate::run_journal::JournalChange::CaptureReconciled
            },
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Normal active/ready allocation without a capture requirement only.
    /// No capture-pending eligibility bypass; exact Existing remains metadata.
    /// Only a freshly committed Created result yields a preparation handle.
    pub fn begin_captured_run(
        &mut self,
        request: &RootRunRequest,
        spec: &CaptureSpec,
    ) -> Result<BeginCapturedRun> {
        self.begin_capture_context(request, spec, None)
    }
    pub(crate) fn begin_materialized_capture(
        &mut self,
        request: &RootRunRequest,
        spec: &CaptureSpec,
        proof: &crate::capture_setup::MaterializationProof,
    ) -> Result<BeginCapturedRun> {
        // Physical reinspection is outside every SQL phase/transaction. Only
        // sealed context and original-age checks run after IMMEDIATE locking.
        proof.reinspect(self)?;
        self.begin_capture_context(
            request,
            spec,
            Some(&crate::capture_setup::AdmissionProof::Pending(proof)),
        )
    }
    pub(crate) fn begin_certified_capture(
        &mut self,
        request: &RootRunRequest,
        spec: &CaptureSpec,
        proof: &crate::capture_readiness::ContinuationProof,
    ) -> Result<BeginCapturedRun> {
        self.begin_capture_context(
            request,
            spec,
            Some(&crate::capture_setup::AdmissionProof::Certified(proof)),
        )
    }
    fn begin_capture_context(
        &mut self,
        request: &RootRunRequest,
        spec: &CaptureSpec,
        proof: Option<&crate::capture_setup::AdmissionProof<'_>>,
    ) -> Result<BeginCapturedRun> {
        #[cfg(test)]
        use crate::capture_diagnostics::{span, ProfileRoot, Subphase};
        #[cfg(test)]
        let _profile = ProfileRoot::new();
        #[cfg(test)]
        let _total = span(Subphase::BeginCaptureTotal);
        #[cfg(test)]
        let before_sql = span(Subphase::BeforeSqlJson);
        // Bound the actual durable representation before acquiring SQL authority.
        let body = json(spec)?;
        #[cfg(test)]
        drop(before_sql);
        let _phase = self.sql_phase();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        #[cfg(test)]
        let agrees = span(Subphase::AdmissionAgrees);
        let allocation = spec.agrees(&tx, request)?;
        #[cfg(test)]
        drop(agrees);
        #[cfg(test)]
        let related_profile = span(Subphase::RelatedQualification);
        // Construct only for an actual private admission proof, at the old
        // validate_related position. No frontier check precedes Existing.
        let related = if proof.is_some() {
            Some(crate::capture_setup::Related::qualify(
                &tx,
                id(&request.identity().checkout)?,
            )?)
        } else {
            validate_related(&tx, &request.identity().checkout)?;
            None
        };
        #[cfg(test)]
        drop(related_profile);
        let admission = proof.zip(related.as_ref());
        #[cfg(test)]
        let existing_profile = span(Subphase::NamespaceExisting);
        exclude_operation(&tx, &request.identity().run)?;
        exclude_operation(&tx, &request.identity().group)?;
        if let Some(existing) = crate::run_journal::read(&tx, &request.identity().run)? {
            crate::run_journal::exact(&tx, request)?;
            let record = read(&tx, &existing)?.ok_or(StoreError::Conflict)?;
            if record.fingerprint != digest(spec)? {
                return Err(StoreError::Conflict);
            }
            return Ok(BeginCapturedRun::Existing(record));
        }
        #[cfg(test)]
        drop(existing_profile);
        #[cfg(test)]
        let capture_proof = span(Subphase::CaptureProof);
        if let Some((proof, related)) = admission {
            proof.validate_capture(&tx, request, spec, related)?;
        } else if allocation.stage != "ready" {
            return Err(StoreError::Invalid);
        }
        #[cfg(test)]
        drop(capture_proof);
        #[cfg(test)]
        let collision_profile = span(Subphase::OperationCollision);
        crate::store::exclude_journal_identity(&tx, spec.operation)?;
        let collision:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 OR operation=?1) OR EXISTS(SELECT 1 FROM writers WHERE group_id=?1)", [spec.operation.to_string()], |r|r.get(0))?;
        if collision {
            return Err(StoreError::Conflict);
        }
        #[cfg(test)]
        drop(collision_profile);
        #[cfg(test)]
        let writer_profile = span(Subphase::BeginRunWriter);
        if crate::run_journal::begin_run_context(&tx, request, admission)? != BeginRun::Created {
            return Err(StoreError::Conflict);
        }
        #[cfg(test)]
        drop(writer_profile);
        #[cfg(test)]
        let _tail = span(Subphase::WriteFreshCommitTail);
        // The last consumer was validate_writer, before INSERT INTO writers.
        // No qualified SQL fact is consulted after that mutation.
        drop(related);
        tx.execute("INSERT INTO capture_runs(run,group_id,checkout,operation,spec,fingerprint,intent_wall,preparation_revision) VALUES(?1,?2,?3,?4,?5,?6,?7,1)",rusqlite::params![request.identity().run.to_string(), request.identity().group.to_string(),request.identity().checkout.to_string(),spec.operation.to_string(),body,digest(spec)?.as_slice(),wall()])?;
        crate::run_journal::journal_event(
            &tx,
            request,
            1,
            crate::run_journal::JournalChange::CaptureIntent,
        )?;
        tx.execute(
            "UPDATE checkouts SET ready=0,state='active' WHERE id=?1",
            [request.identity().checkout.to_string()],
        )?;
        if let Some(proof) = proof {
            proof.fresh()?;
        }
        tx.commit()?;
        Ok(BeginCapturedRun::Created(PreparationHandle {
            request: request.clone(),
            spec: Box::new(spec.clone()),
            revision: 1,
            pending: proof.map(|p| p.preparation()),
        }))
    }
}
pub(crate) fn validate_related(conn: &Connection, checkout: &CheckoutId) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 10 {
        return Ok(());
    }
    crate::run_journal::with_capture_history(conn, id(checkout)?, |_| Ok(()))
}
/// Only the already-ready, live-prepared exact root may refresh allocation identity.
/// This cannot promote Preparing, reconciled, closed, held or malformed history.
pub(crate) fn guard_allocation_identity(conn: &Connection, checkout: Uuid) -> Result<()> {
    if !unresolved_checkout(conn, checkout)? {
        if crate::capture_requirement::present(conn, checkout)? {
            let ready:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 AND (state='active' OR ready=1))",[checkout.to_string()],|r|r.get(0))?;
            if ready {
                return Err(StoreError::Invalid);
            }
        }
        return Ok(());
    }
    let eligible:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 AND state='active' AND ready=1) AND NOT EXISTS(SELECT 1 FROM task_finishes WHERE checkout=?1)",[checkout.to_string()],|r|r.get(0))?;
    if !eligible {
        return Err(StoreError::Invalid);
    }
    let certified: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM capture_readiness WHERE checkout=?1)",
        [checkout.to_string()],
        |r| r.get(0),
    )?;
    if certified {
        return crate::capture_readiness::guard_certified_identity(conn, checkout);
    }
    let checkout = CheckoutId::parse(&checkout.to_string()).map_err(|_| StoreError::Invalid)?;
    validate_related(conn, &checkout)?;
    let mut stmt = conn.prepare("SELECT run FROM capture_runs WHERE checkout=?1")?;
    let ids = stmt
        .query_map([checkout.to_string()], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for run in ids {
        let run = RunId::parse(&run).map_err(|_| StoreError::Invalid)?;
        let root = crate::run_journal::read(conn, &run)?.ok_or(StoreError::Invalid)?;
        let root = crate::run_journal::exact(conn, &root.request)?;
        let capture = read(conn, &root)?.ok_or(StoreError::Invalid)?;
        if root.closed
            || root.recovery_hold
            || root.outcome.is_some()
            || !capture.prepared.is_some_and(|p| p.live_preparation)
        {
            return Err(StoreError::Invalid);
        }
    }
    Ok(())
}
/// Indexed presence fence, independent of JSON and stale checkout readiness.
/// All 8.2 rows are unresolved; no freeze API can release this barrier yet.
pub(crate) fn unresolved_checkout(conn: &Connection, checkout: Uuid) -> Result<bool> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 10 {
        return Ok(false);
    }
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM capture_runs WHERE checkout=?1)",
        [checkout.to_string()],
        |r| r.get(0),
    )?)
}
pub(crate) fn operation_reserved(conn: &Connection, operation: &str) -> Result<bool> {
    let version: i64 = conn
        .prepare_cached("PRAGMA user_version")?
        .query_row([], |r| r.get(0))?;
    if version < 10 {
        return Ok(false);
    }
    Ok(conn
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM capture_runs WHERE operation=?1)")?
        .query_row([operation], |r| r.get(0))?)
}
pub(crate) fn exclude_operation(conn: &Connection, value: &impl ToString) -> Result<()> {
    if operation_reserved(conn, &value.to_string())? {
        Err(StoreError::Conflict)
    } else {
        Ok(())
    }
}
pub(crate) fn observe_group_end(
    conn: &Connection,
    root: &RunRecord,
    observed: std::time::SystemTime,
) -> Result<()> {
    let Some(record) = read(conn, root)? else {
        return Ok(());
    };
    if record.group_end.is_some() {
        return Err(StoreError::Conflict);
    }
    let wall = chrono::DateTime::<chrono::Utc>::from(observed).to_rfc3339();
    let end = GroupEndObservation {
        clock_uncertain: date(&wall)? < date(&record.intent_wall)?
            || record.prepared.as_ref().is_some_and(|p| {
                date(&p.observed_wall).is_ok_and(|d| date(&wall).is_ok_and(|w| w < d))
            }),
        observed_wall: wall,
    };
    conn.execute(
        "UPDATE capture_runs SET group_end=?2 WHERE run=?1",
        (root.request.identity().run.to_string(), json(&end)?),
    )?;
    conn.execute("UPDATE checkouts SET ready=0,state=CASE WHEN state='active' THEN 'held' ELSE state END WHERE id=?1",[root.request.identity().checkout.to_string()])?;
    crate::run_journal::journal_event(
        conn,
        &root.request,
        root.revision + 1,
        crate::run_journal::JournalChange::CaptureGroupEnd,
    )
}
pub(crate) fn read(conn: &Connection, root: &RunRecord) -> Result<Option<CaptureRecord>> {
    Ok(qualified(conn, root)?.map(|(record, _)| record))
}
pub(crate) fn qualified(
    conn: &Connection,
    root: &RunRecord,
) -> Result<Option<(CaptureRecord, CaptureSpec)>> {
    Ok(qualified_terminal(conn, root)?.map(|(capture, spec, _)| (capture, spec)))
}
pub(crate) type QualifiedTerminal = (
    CaptureRecord,
    CaptureSpec,
    Option<crate::capture_finalization::Snapshot>,
);
pub(crate) fn qualified_terminal(
    conn: &Connection,
    root: &RunRecord,
) -> Result<Option<QualifiedTerminal>> {
    qualify_terminal(conn, root, |spec| {
        spec.agrees(conn, &root.request).map(|_| ())
    })
}
// The batch can only be constructed inside its own nested read snapshot. Its
// connection and checkout cannot be selected by a qualification consumer.
pub(crate) struct QualificationBatch<'a> {
    conn: &'a Connection,
    checkout: Uuid,
    agreement: Option<AgreementRow>,
}
pub(crate) fn with_qualification_batch<T>(
    conn: &Connection,
    checkout: Uuid,
    use_batch: impl FnOnce(&mut QualificationBatch<'_>) -> Result<T>,
) -> Result<T> {
    let _snapshot = crate::run_journal::read_transaction(conn)?;
    use_batch(&mut QualificationBatch {
        conn,
        checkout,
        agreement: None,
    })
}
impl QualificationBatch<'_> {
    pub(crate) fn terminal(&mut self, root: &RunRecord) -> Result<Option<QualifiedTerminal>> {
        if root.request.identity().checkout.to_string() != self.checkout.to_string() {
            return Err(StoreError::Invalid);
        }
        qualify_terminal(self.conn, root, |spec| {
            // Lazy at the original agrees point, AFTER this root's spec decode.
            if self.agreement.is_none() {
                self.agreement = Some(AgreementRow::read(
                    self.conn,
                    &root.request.identity().checkout,
                )?);
            }
            spec.agrees_with(
                self.agreement.as_ref().ok_or(StoreError::Invalid)?,
                &root.request,
            )
        })
    }
}
fn qualify_terminal(
    conn: &Connection,
    root: &RunRecord,
    agree: impl FnOnce(&CaptureSpec) -> Result<()>,
) -> Result<Option<QualifiedTerminal>> {
    #[cfg(test)]
    use crate::capture_diagnostics::{span, Subphase};
    #[cfg(test)]
    let row_profile = span(Subphase::TerminalRowVersion);
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 10 {
        return Ok(None);
    }
    type Row = (
        String,
        String,
        String,
        String,
        Vec<u8>,
        String,
        i64,
        Option<String>,
        Option<String>,
    );
    let row: Option<Row> = conn.query_row("SELECT group_id,checkout,operation,spec,fingerprint,intent_wall,preparation_revision,prepared,group_end FROM capture_runs WHERE run=?1", [root.request.identity().run.to_string()], |r| {
        // Inspect SQLite's borrowed bytes before allocating Strings or cloning JSON.
        for index in [3, 7, 8] {
            if matches!(r.get_ref(index)?, rusqlite::types::ValueRef::Text(bytes) if bytes.len() > MAX_RECORD_BYTES) {
                return Ok(Err(StoreError::Invalid));
            }
        }
        Ok(Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?)))
    }).optional()?.transpose()?;
    let Some((
        group,
        checkout,
        operation,
        body,
        fingerprint,
        intent_wall,
        revision,
        prepared,
        group_end,
    )) = row
    else {
        return Ok(None);
    };
    #[cfg(test)]
    drop(row_profile);
    #[cfg(test)]
    let decode_profile = span(Subphase::TerminalSpecDecode);
    let spec = CaptureSpec::decode(&body)?;
    #[cfg(test)]
    drop(decode_profile);
    #[cfg(test)]
    let agrees_profile = span(Subphase::TerminalAgrees);
    agree(&spec)?;
    #[cfg(test)]
    drop(agrees_profile);
    #[cfg(test)]
    let namespace_profile = span(Subphase::TerminalNamespaceHeaderDigest);
    let collision:bool=conn.prepare_cached("SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 OR operation=?1) OR EXISTS(SELECT 1 FROM writers WHERE group_id=?1) OR EXISTS(SELECT 1 FROM runs WHERE id=?1 OR group_id=?1) OR EXISTS(SELECT 1 FROM run_groups WHERE id=?1) OR EXISTS(SELECT 1 FROM adopted_groups WHERE id=?1 OR run_id=?1 OR operation=?1) OR EXISTS(SELECT 1 FROM run_participants WHERE id=?1) OR EXISTS(SELECT 1 FROM task_finishes WHERE operation=?1)")?.query_row([spec.operation.to_string()],|r|r.get(0))?;
    if collision {
        return Err(StoreError::Invalid);
    }
    // Preserve the original short-circuit order before computing the digest.
    if group != root.request.identity().group.to_string()
        || checkout != root.request.identity().checkout.to_string()
        || operation != spec.operation.to_string()
    {
        return Err(StoreError::Invalid);
    }
    let spec_digest = digest(&spec)?;
    if fingerprint != spec_digest {
        return Err(StoreError::Invalid);
    }
    #[cfg(test)]
    drop(namespace_profile);
    #[cfg(test)]
    let prepared_profile = span(Subphase::TerminalPreparedEndChecks);
    date(&intent_wall)?;
    if revision != 1 || root.revision < revision as u64 {
        return Err(StoreError::Invalid);
    }
    let prepared: Option<PreparationObservation> = prepared.as_deref().map(strict).transpose()?;
    let group_end: Option<GroupEndObservation> = group_end.as_deref().map(strict).transpose()?;
    if let Some(p) = &prepared {
        crate::capture_bridge::CaptureId::parse(&p.capture_id).map_err(|_| StoreError::Invalid)?;
        date(&p.observed_wall)?;
        if p.context_artifact
            .as_ref()
            .is_some_and(|a| !a.validate() || !p.live_preparation)
        {
            return Err(StoreError::Invalid);
        }
        if p.actor_ref != spec.declaration.actor_ref
            || p.run_ref != spec.declaration.run_ref
            || p.context != spec.sink.context_path(&p.capture_id)
            || p.git != spec.expected_git
            || p.receiver_binding != digest(&spec.sink)?
            || p.projection_digest != digest(&(&p.capture_id, &p.context, &p.git))?
            || (p.live_preparation && date(&p.observed_wall)? < date(&intent_wall)?)
        {
            return Err(StoreError::Invalid);
        }
    }
    if (prepared.as_ref().is_none_or(|p| !p.live_preparation)
        && root.stage != crate::run_journal::RunStage::Intent)
        || (prepared.is_some() && root.revision < 2)
    {
        return Err(StoreError::Invalid);
    }
    if group_end.is_some() != root.closed {
        return Err(StoreError::Invalid);
    }
    if let Some(end) = &group_end {
        let observed = date(&end.observed_wall)?;
        let uncertain = observed < date(&intent_wall)?
            || prepared
                .as_ref()
                .is_some_and(|p| date(&p.observed_wall).is_ok_and(|d| observed < d));
        if end.clock_uncertain != uncertain {
            return Err(StoreError::Invalid);
        }
    }
    let record = CaptureRecord {
        operation: spec.operation,
        fingerprint: spec_digest,
        intent_wall,
        prepared,
        group_end,
    };
    #[cfg(test)]
    drop(prepared_profile);
    #[cfg(test)]
    let _finalization = span(Subphase::TerminalFinalization);
    let terminal = crate::capture_finalization::validate(conn, root, &record, &spec)?;
    Ok(Some((record, spec, terminal)))
}

pub(crate) const SCHEMA: &str = "CREATE TABLE capture_runs(
 run TEXT PRIMARY KEY REFERENCES runs(id),
 group_id TEXT NOT NULL UNIQUE REFERENCES run_groups(id),
 checkout TEXT NOT NULL REFERENCES checkouts(id),
 operation TEXT NOT NULL UNIQUE,
 spec TEXT NOT NULL, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
 intent_wall TEXT NOT NULL, preparation_revision INTEGER NOT NULL CHECK(preparation_revision>=1),
 prepared TEXT, group_end TEXT);
 CREATE INDEX capture_checkout ON capture_runs(checkout);
 PRAGMA user_version=10;";

pub(crate) fn validate_schema(conn: &Connection) -> Result<()> {
    let normalize = |s: &str| {
        s.chars()
            .filter(|c| !c.is_whitespace() && *c != '"')
            .collect::<String>()
            .to_ascii_lowercase()
    };
    for (name, kind, expected) in [
        (
            "capture_runs",
            "table",
            SCHEMA.split(';').next().ok_or(StoreError::Invalid)?,
        ),
        (
            "capture_checkout",
            "index",
            SCHEMA.split(';').nth(1).ok_or(StoreError::Invalid)?,
        ),
    ] {
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
