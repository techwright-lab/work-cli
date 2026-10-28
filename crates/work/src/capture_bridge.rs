//! Portable capture declarations and observations, never writer/retirement authority.
//! Nothing here persists mappings, launches writers, or selects host configuration.
use serde::{
    de::{self, DeserializeOwned, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use std::{
    collections::HashSet,
    fmt,
    io::Write,
    path::{Path, PathBuf},
};
use work_contract::{AllocationOperationId, CheckoutId, ExecutionChain, ExecutionMode, GroupId};

pub const MAX_WIRE_BYTES: usize = 1024 * 1024;
/// Intentionally constant: no child stdout/stderr, argv, locator or JSON is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("capture transport refused")]
pub struct Refused;
macro_rules! redacted_debug {
    ($($name:ty),+ $(,)?) => {$(
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    )+};
}
fn scalar(value: &str) -> Result<(), Refused> {
    if value.trim().is_empty()
        || value.chars().take(4097).count() > 4096
        || value.chars().any(char::is_control)
    {
        Err(Refused)
    } else {
        Ok(())
    }
}
fn absolute(path: &Path) -> Result<&str, Refused> {
    let text = path.to_str().ok_or(Refused)?;
    scalar(text)?;
    if path.is_absolute() {
        Ok(text)
    } else {
        Err(Refused)
    }
}
/// A bounded serializer: rejects before allocating an unbounded encoded buffer.
struct WireBuffer(Vec<u8>);
impl Write for WireBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_WIRE_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("wire limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>, Refused> {
    let mut writer = WireBuffer(Vec::new());
    serde_json::to_writer(&mut writer, value).map_err(|_| Refused)?;
    Ok(writer.0)
}
#[derive(Clone)]
pub struct WorkLifecycle {
    pub checkout_id: CheckoutId,
    pub mode: ExecutionMode,
    pub group_id: Option<GroupId>,
    pub operation_id: Option<AllocationOperationId>,
}
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub system: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub company_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub agent_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub run_id: Option<String>,
}
impl Source {
    fn validate(&self) -> Result<(), Refused> {
        for s in [&self.system, &self.company_id, &self.agent_id, &self.run_id]
            .into_iter()
            .flatten()
        {
            scalar(s)?;
        }
        Ok(())
    }
}
pub struct BeginRequest {
    pub actor_ref: String,
    pub run_ref: String,
    pub cwd: PathBuf,
    pub execution_chain: ExecutionChain,
    pub task_refs: Vec<String>,
    pub parent_run_ref: Option<String>,
    pub key_file: Option<PathBuf>,
    pub source: Option<Source>,
    pub lifecycle: WorkLifecycle,
}
/// First-seen order is the portable protocol's primary/additional task order.
/// Validate the original count and every input, not just the deduplicated list.
pub(crate) fn canonical_task_refs(refs: &[String]) -> Result<Vec<&String>, Refused> {
    if refs.len() > 10000 {
        return Err(Refused);
    }
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for value in refs {
        scalar(value)?;
        if seen.insert(value) {
            result.push(value);
        }
    }
    Ok(result)
}
impl BeginRequest {
    pub fn encode(&self) -> Result<Vec<u8>, Refused> {
        scalar(&self.actor_ref)?;
        scalar(&self.run_ref)?;
        let cwd = absolute(&self.cwd)?;
        let key_file = self.key_file.as_deref().map(absolute).transpose()?;
        if let Some(s) = &self.source {
            s.validate()?;
        }
        if let Some(s) = &self.parent_run_ref {
            scalar(s)?;
        }
        let task_refs = canonical_task_refs(&self.task_refs)?;
        #[derive(Serialize)]
        struct Work {
            schema_version: u8,
            checkout_ref: String,
            mode: ExecutionMode,
            #[serde(skip_serializing_if = "Option::is_none")]
            group_ref: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            operation_ref: Option<String>,
        }
        #[derive(Serialize)]
        struct Lifecycle {
            work: Work,
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            actor_ref: &'a str,
            run_ref: &'a str,
            cwd: &'a str,
            execution_chain: &'a ExecutionChain,
            task_refs: Vec<&'a String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            parent_run_ref: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            key_file: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            source: Option<&'a Source>,
            git_scope: &'static str,
            lifecycle_context: Lifecycle,
        }
        encode(&Wire {
            actor_ref: &self.actor_ref,
            run_ref: &self.run_ref,
            cwd,
            execution_chain: &self.execution_chain,
            task_refs,
            parent_run_ref: self.parent_run_ref.as_deref(),
            key_file,
            source: self.source.as_ref(),
            git_scope: "checkout",
            lifecycle_context: Lifecycle {
                work: Work {
                    schema_version: 1,
                    checkout_ref: format!("urn:work:checkout:{}", self.lifecycle.checkout_id),
                    mode: self.lifecycle.mode,
                    group_ref: self
                        .lifecycle
                        .group_id
                        .as_ref()
                        .map(|id| format!("urn:work:group:{id}")),
                    operation_ref: self
                        .lifecycle
                        .operation_id
                        .as_ref()
                        .map(|id| format!("urn:work:operation:{id}")),
                },
            },
        })
    }
}
/// External opaque RFC4122 UUID, deliberately distinct from Work UUIDv7 IDs.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CaptureId(String);
impl CaptureId {
    pub fn parse(value: &str) -> Result<Self, Refused> {
        let uuid = uuid::Uuid::parse_str(value).map_err(|_| Refused)?;
        if uuid.get_variant() != uuid::Variant::RFC4122
            || !value.eq_ignore_ascii_case(&uuid.hyphenated().to_string())
        {
            return Err(Refused);
        }
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
#[derive(Clone)]
pub struct CaptureBinding {
    capture_id: CaptureId,
    actor_ref: String,
    run_ref: String,
}
impl CaptureBinding {
    pub fn new(capture: &str, actor: &str, run: &str) -> Result<Self, Refused> {
        scalar(actor)?;
        scalar(run)?;
        Ok(Self {
            capture_id: CaptureId::parse(capture)?,
            actor_ref: actor.into(),
            run_ref: run.into(),
        })
    }
    pub fn capture_id(&self) -> &CaptureId {
        &self.capture_id
    }
    pub fn actor_ref(&self) -> &str {
        &self.actor_ref
    }
    pub fn run_ref(&self) -> &str {
        &self.run_ref
    }
}
/// Expected optional Git identities supplied by the trusted caller.
/// `Default` means all four fields must be absent, not wildcard acceptance.
#[derive(Default, PartialEq, Eq)]
pub struct GitProfile {
    pub author_name: Option<String>,
    pub author_email: Option<String>,
    pub committer_name: Option<String>,
    pub committer_email: Option<String>,
}
impl GitProfile {
    pub(crate) fn validate(&self) -> Result<(), Refused> {
        for s in [
            &self.author_name,
            &self.author_email,
            &self.committer_name,
            &self.committer_email,
        ]
        .into_iter()
        .flatten()
        {
            scalar(s)?;
        }
        Ok(())
    }
}
/// Ephemeral allowlisted metadata. Not serializable and not execution authority.
///
/// ```compile_fail
/// fn persist(env: &work_cli::capture_bridge::EnvironmentProjection) {
///     let _ = serde_json::to_string(env);
/// }
/// ```
pub struct EnvironmentProjection {
    context: PathBuf,
    capture_id: CaptureId,
    git: GitProfile,
}
impl EnvironmentProjection {
    pub fn context_path(&self) -> &Path {
        &self.context
    }
    pub fn capture_id(&self) -> &CaptureId {
        &self.capture_id
    }
    pub fn git_profile(&self) -> &GitProfile {
        &self.git
    }
    /// Recheck metadata against a trusted profile; begin acceptance already requires this match.
    pub fn matches_git_profile(&self, expected: &GitProfile) -> bool {
        &self.git == expected
    }
}
pub struct Prepared {
    binding: CaptureBinding,
    environment: EnvironmentProjection,
}
impl Prepared {
    pub fn binding(&self) -> &CaptureBinding {
        &self.binding
    }
    pub fn environment(&self) -> &EnvironmentProjection {
        &self.environment
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryObservation {
    Pending,
    Delivered,
}
/// Exit zero plus validated terminal data reports local freeze, not task completion.
pub struct LocalFrozen {
    binding: CaptureBinding,
    delivery: DeliveryObservation,
    ended_at: Option<String>,
    started_at: Option<String>,
    last_attempt_at: Option<String>,
    source: Option<Source>,
    error_code: Option<String>,
    receipt: Option<Receipt>,
}
impl LocalFrozen {
    pub fn ended_at(&self) -> Option<&str> {
        self.ended_at.as_deref()
    }
    pub fn started_at(&self) -> Option<&str> {
        self.started_at.as_deref()
    }
    pub fn last_attempt_at(&self) -> Option<&str> {
        self.last_attempt_at.as_deref()
    }
    pub fn source(&self) -> Option<&Source> {
        self.source.as_ref()
    }
    pub fn error_code(&self) -> Option<&str> {
        self.error_code.as_deref()
    }
    pub fn receipt(&self) -> Option<&Receipt> {
        self.receipt.as_ref()
    }
    pub fn delivery(&self) -> DeliveryObservation {
        self.delivery
    }
    pub fn binding(&self) -> &CaptureBinding {
        &self.binding
    }
}
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BeginWire {
    capture_id: String,
    actor_ref: String,
    run_ref: String,
    state: String,
    environment: EnvWire,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvWire {
    #[serde(rename = "AGENT_ATTRIBUTION_CONTEXT")]
    agent: String,
    #[serde(rename = "DEVDIARY_ATTRIBUTION_CONTEXT")]
    diary: String,
    #[serde(rename = "DEVDIARY_CAPTURE_ID")]
    capture: String,
    #[serde(rename = "GIT_AUTHOR_NAME", default, deserialize_with = "present")]
    author_name: Option<String>,
    #[serde(rename = "GIT_AUTHOR_EMAIL", default, deserialize_with = "present")]
    author_email: Option<String>,
    #[serde(rename = "GIT_COMMITTER_NAME", default, deserialize_with = "present")]
    committer_name: Option<String>,
    #[serde(rename = "GIT_COMMITTER_EMAIL", default, deserialize_with = "present")]
    committer_email: Option<String>,
}
/// Accept only against the caller's trusted Git profile, including explicit absence.
/// Never construct the expected profile from receiver-provided values.
///
/// ```compile_fail
/// use work_cli::capture_bridge::{decode_begin, BeginRequest};
/// fn unchecked(bytes: &[u8], request: &BeginRequest) {
///     let _ = decode_begin(bytes, request); // trusted profile is mandatory
/// }
/// ```
pub fn decode_begin(
    bytes: &[u8],
    request: &BeginRequest,
    expected_git: &GitProfile,
) -> Result<Prepared, Refused> {
    expected_git.validate()?;
    let wire: BeginWire = decode(bytes)?;
    if wire.state != "open"
        || wire.actor_ref != request.actor_ref
        || wire.run_ref != request.run_ref
    {
        return Err(Refused);
    }
    let binding = CaptureBinding::new(&wire.capture_id, &wire.actor_ref, &wire.run_ref)?;
    let env = wire.environment;
    absolute(Path::new(&env.agent))?;
    if env.agent != env.diary || env.capture != wire.capture_id {
        return Err(Refused);
    }
    let git = GitProfile {
        author_name: env.author_name,
        author_email: env.author_email,
        committer_name: env.committer_name,
        committer_email: env.committer_email,
    };
    git.validate()?;
    if &git != expected_git {
        return Err(Refused);
    }
    let environment = EnvironmentProjection {
        context: env.agent.into(),
        capture_id: binding.capture_id.clone(),
        git,
    };
    Ok(Prepared {
        binding,
        environment,
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalWire {
    capture_id: String,
    actor_ref: String,
    run_ref: String,
    state: String,
    #[serde(default, deserialize_with = "present")]
    started_at: Option<String>,
    #[serde(default, deserialize_with = "present")]
    ended_at: Option<String>,
    #[serde(default, deserialize_with = "present")]
    source: Option<Source>,
    #[serde(default, deserialize_with = "present")]
    last_attempt_at: Option<String>,
    #[serde(default, deserialize_with = "present")]
    error_code: Option<String>,
    #[serde(default, deserialize_with = "present")]
    receipt: Option<Receipt>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    actor_ref: String,
    run_ref: String,
    event_id: String,
    session_id: u64,
}
impl Receipt {
    pub fn actor_ref(&self) -> &str {
        &self.actor_ref
    }
    pub fn run_ref(&self) -> &str {
        &self.run_ref
    }
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
    pub fn session_id(&self) -> u64 {
        self.session_id
    }
}
pub fn decode_terminal(bytes: &[u8], binding: &CaptureBinding) -> Result<LocalFrozen, Refused> {
    let wire: TerminalWire = decode(bytes)?;
    if wire.capture_id != binding.capture_id.as_str()
        || wire.actor_ref != binding.actor_ref
        || wire.run_ref != binding.run_ref
    {
        return Err(Refused);
    }
    for date in [&wire.started_at, &wire.ended_at, &wire.last_attempt_at]
        .into_iter()
        .flatten()
    {
        EndedAt::parse(date)?;
    }
    if let Some(source) = &wire.source {
        source.validate()?;
    }
    if let Some(error) = &wire.error_code {
        scalar(error)?;
        if error != "delivery_failed" {
            return Err(Refused);
        }
    }
    if let Some(receipt) = &wire.receipt {
        if receipt.actor_ref != binding.actor_ref
            || receipt.run_ref != binding.run_ref
            || receipt.session_id == 0
        {
            return Err(Refused);
        }
        scalar(&receipt.event_id)?;
    }
    let delivery = match wire.state.as_str() {
        "pending" => DeliveryObservation::Pending,
        "delivered" if wire.receipt.is_some() => DeliveryObservation::Delivered,
        _ => return Err(Refused),
    };
    Ok(LocalFrozen {
        binding: binding.clone(),
        delivery,
        ended_at: wire.ended_at,
        started_at: wire.started_at,
        last_attempt_at: wire.last_attempt_at,
        source: wire.source,
        error_code: wire.error_code,
        receipt: wire.receipt,
    })
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureOutcome {
    Completed,
    Failed,
    Cancelled,
}
impl CaptureOutcome {
    pub fn parse(value: &str) -> Result<Self, Refused> {
        match value {
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(Refused),
        }
    }
}
#[derive(Serialize)]
#[serde(transparent)]
pub struct EndedAt(String);
impl EndedAt {
    pub fn parse(value: &str) -> Result<Self, Refused> {
        scalar(value)?;
        chrono::DateTime::parse_from_rfc3339(value).map_err(|_| Refused)?;
        Ok(Self(value.into()))
    }
}
#[derive(Serialize)]
pub struct FinishRequest {
    pub capture_id: CaptureId,
    pub outcome: CaptureOutcome,
    pub ended_at: EndedAt,
}
impl FinishRequest {
    pub fn encode(&self) -> Result<Vec<u8>, Refused> {
        encode(self)
    }
}
#[derive(Serialize)]
pub struct RetryRequest {
    pub capture_id: CaptureId,
}
impl RetryRequest {
    pub fn encode(&self) -> Result<Vec<u8>, Refused> {
        encode(self)
    }
}
redacted_debug!(
    WorkLifecycle,
    Source,
    BeginRequest,
    CaptureId,
    CaptureBinding,
    GitProfile,
    EnvironmentProjection,
    Prepared,
    LocalFrozen,
    Receipt,
    EndedAt,
    FinishRequest,
    RetryRequest
);

// Validate every object before typed deserialization, including unknown objects.
// No serde_json::Value/map overwrite can erase a duplicate key. Depth is also
// bounded by serde_json's default recursion limit and input by MAX_WIRE_BYTES.
// Responses have no array-valued fields: omitting visit_seq rejects positional
// struct representations at every nesting level before typed deserialization.
// Request encoding (execution_chain/task_refs arrays) is a separate path.
struct Unique;
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Check;
        impl<'de> Visitor<'de> for Check {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("unique-key JSON")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Unique, M::Error> {
                let mut keys = HashSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    map.next_value::<Unique>()?;
                }
                Ok(Unique)
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique)
            }
        }
        d.deserialize_any(Check)
    }
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Refused> {
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(Refused);
    }
    serde_json::from_slice::<Unique>(bytes).map_err(|_| Refused)?;
    serde_json::from_slice(bytes).map_err(|_| Refused)
}
