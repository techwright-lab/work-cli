use std::path::PathBuf;

use crate::error::Error;

pub(crate) const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Host-supplied configuration. Compiled defaults do not include any machine,
/// user, or organization paths.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// Optional absolute executable spelling; qualification follows symlinks safely.
    pub git_path: Option<PathBuf>,
    /// Directory for the local lifecycle store, when the host has configured one.
    pub store_dir: Option<PathBuf>,
    pub trusted_registry: Option<PathBuf>,
    pub roots: Vec<PathBuf>,
    pub repositories: Vec<PathBuf>,
    pub allocation: Option<AllocationPolicy>,
    pub supervisor: Option<SupervisorConfig>,
    pub capture: Option<crate::capture_config::HostCaptureConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationPolicy {
    pub repository_limit: u64,
    pub owner_limit: u64,
    pub floor_bytes: u64,
    pub warn_bytes: u64,
    pub capture_sink: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorConfig {
    pub runtime_directory: PathBuf,
    pub bus_address: String,
    pub runtime_max_seconds: u64,
    pub preexec_ms: u64,
    pub closure_grace_ms: u64,
    pub cancel_grace_ms: u64,
    pub actors: std::collections::BTreeMap<String, crate::scope_spawn::ActorGitProfile>,
}
impl SupervisorConfig {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let invalid = || Error::Config("invalid supervisor policy".into());
        if !(1..=86_400).contains(&self.runtime_max_seconds)
            || !(1..=30_000).contains(&self.preexec_ms)
            || !(1..=30_000).contains(&self.closure_grace_ms)
            || !(1..=30_000).contains(&self.cancel_grace_ms)
            || self.actors.is_empty()
            || self.actors.len() > 128
            || self.actors.keys().any(|a| {
                a.is_empty()
                    || a.len() > 128
                    || !a
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            })
            || self.bus_address
                != format!("unix:path={}", self.runtime_directory.join("bus").display())
        {
            return Err(invalid());
        }
        validate_path(&self.runtime_directory, false).map_err(|_| invalid())?;
        Ok(())
    }
}
/// One immutable invocation snapshot, not execution or recovery authority.
pub(crate) struct ConfigDocument {
    value: toml::Value,
}
/// Setup-owned first-time document fields. Not an execution Config.
#[allow(dead_code)]
pub(crate) struct InstallDocument {
    pub git_path: Option<PathBuf>,
    pub actor: String,
    pub repositories: Vec<PathBuf>,
    pub roots: Vec<PathBuf>,
    pub store_dir: PathBuf,
    pub trusted_registry: PathBuf,
    pub allocation: AllocationPolicy,
}
impl ConfigDocument {
    pub(crate) fn git_path(&self) -> Result<Option<PathBuf>, Error> {
        git_path(&self.value)
    }
    pub(crate) fn set_git_path(&mut self, path: &std::path::Path) -> Result<(), Error> {
        let mut value = toml::Table::new();
        value.insert(
            "git_path".into(),
            toml::Value::String(path.to_str().ok_or_else(invalid_path)?.into()),
        );
        let path = git_path(&toml::Value::Table(value))?.expect("present selector");
        self.value.as_table_mut().ok_or_else(invalid_path)?.insert(
            "git_path".into(),
            toml::Value::String(path.to_str().ok_or_else(invalid_path)?.into()),
        );
        Ok(())
    }
    pub(crate) fn default_actor(&self) -> Result<Option<String>, Error> {
        self.value
            .get("actor")
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| Error::Config("actor must be a string".into()))
            })
            .transpose()
    }
    pub(crate) fn load() -> Result<Self, Error> {
        let text = Config::read_text()?.unwrap_or_default();
        Self::from_text(&text)
    }
    pub(crate) fn from_text(text: &str) -> Result<Self, Error> {
        Ok(Self {
            value: parse_toml(text)?,
        })
    }
    pub(crate) fn load_from_path(path: &std::path::Path) -> Result<Self, Error> {
        use std::{io::Read, os::unix::fs::OpenOptionsExt};
        let unreadable =
            || Error::Config("cannot read configuration safely within size limit".into());
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOFOLLOW).bits() as i32,
            )
            .open(path)
            .map_err(|_| unreadable())?;
        let metadata = file.metadata().map_err(|_| unreadable())?;
        if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
            return Err(unreadable());
        }
        let mut text = String::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|_| unreadable())?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err(unreadable());
        }
        Self::from_text(&text)
    }
    #[allow(dead_code)]
    pub(crate) fn repositories(&self) -> Result<Vec<PathBuf>, Error> {
        string_path_list(&self.value, "repositories")
    }
    #[allow(dead_code)]
    pub(crate) fn roots(&self) -> Result<Vec<PathBuf>, Error> {
        string_path_list(&self.value, "roots")
    }
    #[allow(dead_code)]
    pub(crate) fn allocation(&self) -> Result<Option<AllocationPolicy>, Error> {
        self.value
            .get("allocation")
            .map(|v| {
                v.clone()
                    .try_into()
                    .map_err(|_| Error::Config("invalid allocation policy".into()))
            })
            .transpose()
    }
    #[allow(dead_code)]
    pub(crate) fn render(&self) -> Result<String, Error> {
        let rendered = toml::to_string(&self.value)
            .map_err(|_| Error::Config("cannot render configuration".into()))?;
        if rendered.len() as u64 > MAX_CONFIG_BYTES {
            return Err(Error::Config("configuration exceeds size limit".into()));
        }
        Ok(rendered)
    }
    #[allow(dead_code)]
    pub(crate) fn add_repository(&mut self, path: PathBuf) -> Result<bool, Error> {
        let path = validate_path(&path, true)?;
        let displayed = path.to_str().ok_or_else(invalid_path)?.to_owned();
        let table = self
            .value
            .as_table_mut()
            .ok_or_else(|| Error::Config("expected configuration table".into()))?;
        if !table.contains_key("repositories") {
            table.insert(
                "repositories".into(),
                toml::Value::Array(vec![toml::Value::String(displayed)]),
            );
            return Ok(true);
        }
        let array = table
            .get_mut("repositories")
            .and_then(toml::Value::as_array_mut)
            .ok_or_else(|| Error::Config("repositories must be an array of strings".into()))?;
        let mut duplicate = false;
        for item in array.iter() {
            let existing = item
                .as_str()
                .ok_or_else(|| Error::Config("repositories must be an array of strings".into()))?;
            if existing == displayed {
                duplicate = true;
            }
        }
        if duplicate {
            return Ok(false);
        }
        array.push(toml::Value::String(displayed));
        Ok(true)
    }
    #[allow(dead_code)]
    pub(crate) fn validate_prospective_path(path: &std::path::Path) -> Result<PathBuf, Error> {
        validate_path(path, false)
    }
    #[allow(dead_code)]
    pub(crate) fn from_install(install: InstallDocument) -> Result<Self, Error> {
        if !crate::allocate::component(&install.actor) {
            return Err(Error::Config("unsafe actor/owner/task component".into()));
        }
        let mut table = toml::Table::new();
        table.insert("actor".into(), toml::Value::String(install.actor));
        table.insert(
            "repositories".into(),
            toml::Value::Array(path_values(&install.repositories, true)?),
        );
        table.insert(
            "roots".into(),
            toml::Value::Array(path_values(&install.roots, false)?),
        );
        table.insert("store_dir".into(), path_value(&install.store_dir, false)?);
        table.insert(
            "trusted_registry".into(),
            path_value(&install.trusted_registry, false)?,
        );
        table.insert("allocation".into(), allocation_value(&install.allocation)?);
        let mut document = Self {
            value: toml::Value::Table(table),
        };
        if let Some(path) = install.git_path {
            document.set_git_path(&path)?;
        }
        Ok(document)
    }
    pub(crate) fn retirement_prepare_intents(&self) -> Result<bool, Error> {
        let invalid = || Error::Config("invalid retirement policy".into());
        match self.value.get("retirement") {
            None => Ok(false),
            Some(value) => {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct RetirementPolicy {
                    prepare_intents: bool,
                }
                let policy: RetirementPolicy = value.clone().try_into().map_err(|_| invalid())?;
                Ok(policy.prepare_intents)
            }
        }
    }
    pub(crate) fn authority(&self) -> Result<Config, Error> {
        Ok(Config {
            git_path: self.git_path()?,
            store_dir: single_path(&self.value, "store_dir")?,
            trusted_registry: single_path(&self.value, "trusted_registry")?,
            roots: many_paths(&self.value, "roots")?,
            ..Config::default()
        })
    }
    /// Decode only the inspection subtree of this same bounded snapshot.
    /// Unrelated execution/capture declarations never confer or block policy.
    pub(crate) fn inspection_policies(&self) -> Result<crate::disposal::ValidatedPolicies, Error> {
        let invalid = || Error::Config("invalid inspection policy".into());
        let document = match self.value.get("inspection") {
            None => crate::disposal::PolicyDocument {
                format: 1,
                policies: vec![],
            },
            Some(value) => value.clone().try_into().map_err(|_| invalid())?,
        };
        crate::disposal::validate(document).map_err(|_| invalid())
    }
    /// Remote verification alone decodes this strict subtree. Absence is a hold.
    pub(crate) fn remote_preservation(&self) -> Result<RemotePolicy, Error> {
        let invalid = || Error::Config("invalid remote preservation policy".into());
        let policy: RemotePolicy = self
            .value
            .get("remote_preservation")
            .ok_or_else(invalid)?
            .clone()
            .try_into()
            .map_err(|_| invalid())?;
        policy.validate().map_err(|_| invalid())?;
        Ok(policy)
    }
    /// Approval alone reads this strict subtree. No inferred operator or defaults.
    pub(crate) fn approval(&self) -> Result<ApprovalPolicy, Error> {
        let invalid = || Error::Config("invalid approval policy".into());
        let policy: ApprovalPolicy = self
            .value
            .get("approval")
            .ok_or_else(invalid)?
            .clone()
            .try_into()
            .map_err(|_| invalid())?;
        policy.validate().map_err(|_| invalid())?;
        Ok(policy)
    }
    pub(crate) fn execution(&self) -> Result<Config, Error> {
        Config::from_value(&self.value)
    }
    pub(crate) fn recovery_target(
        &self,
    ) -> Result<Option<crate::capture_config::HostCaptureConfig>, Error> {
        let policy: Option<AllocationPolicy> = self
            .value
            .get("allocation")
            .map(|v| {
                v.clone()
                    .try_into()
                    .map_err(|_| Error::Config("invalid allocation policy".into()))
            })
            .transpose()?;
        match policy.as_ref().and_then(|p| p.capture_sink.as_deref()) {
            None => Ok(None),
            Some("devdiary") => {
                let host: crate::capture_config::HostCaptureConfig = self
                    .value
                    .get("capture")
                    .ok_or_else(|| Error::Config("invalid capture policy".into()))?
                    .clone()
                    .try_into()
                    .map_err(|_| Error::Config("invalid capture policy".into()))?;
                host.validate()?;
                Ok(Some(host))
            }
            _ => Err(Error::Config("invalid capture policy".into())),
        }
    }
    pub(crate) fn recovery_runtime(&self) -> Result<RecoveryRuntime, Error> {
        let invalid = || Error::Config("invalid supervisor policy".into());
        let wire: RecoveryRuntimeWire = self
            .value
            .get("supervisor")
            .ok_or_else(invalid)?
            .clone()
            .try_into()
            .map_err(|_| invalid())?;
        if !(1..=86_400).contains(&wire.runtime_max_seconds)
            || !(1..=30_000).contains(&wire.preexec_ms)
            || !(1..=30_000).contains(&wire.closure_grace_ms)
            || !(1..=30_000).contains(&wire.cancel_grace_ms)
            || wire.bus_address
                != format!("unix:path={}", wire.runtime_directory.join("bus").display())
        {
            return Err(invalid());
        }
        validate_path(&wire.runtime_directory, false).map_err(|_| invalid())?;
        Ok(RecoveryRuntime {
            runtime_directory: wire.runtime_directory,
            bus_address: wire.bus_address,
        })
    }
}
/// Removal-independent runtime declarations; never an execution Config carrier.
pub(crate) struct RecoveryRuntime {
    pub(crate) runtime_directory: PathBuf,
    pub(crate) bus_address: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryRuntimeWire {
    runtime_directory: PathBuf,
    bus_address: String,
    runtime_max_seconds: u64,
    preexec_ms: u64,
    closure_grace_ms: u64,
    cancel_grace_ms: u64,
    #[serde(rename = "actors")]
    _actors: Option<serde::de::IgnoredAny>,
}
impl Config {
    /// Parse host configuration without filesystem initialization or diagnostic values.
    pub fn from_text(text: &str) -> Result<Self, Error> {
        Self::from_toml(text)
    }
    /// Load configuration if a file already exists. Never creates files or directories.
    pub fn load() -> Result<Self, Error> {
        Self::read_text()?
            .map(|text| Self::from_toml(&text))
            .unwrap_or_else(|| Ok(Self::default()))
    }

    /// Historical capture operations use sealed policies, not current execution declarations.
    pub(crate) fn load_capture_authority() -> Result<Self, Error> {
        ConfigDocument::load()?.authority()
    }

    fn read_text() -> Result<Option<String>, Error> {
        let Some(path) = Self::discover_path() else {
            return Ok(None);
        };
        if !path.exists() && std::env::var_os("WORK_CONFIG").is_none() {
            return Ok(None);
        }
        use std::{io::Read, os::unix::fs::OpenOptionsExt};
        let unreadable =
            || Error::Config("cannot read configuration safely within size limit".into());
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOFOLLOW).bits() as i32,
            )
            .open(&path)
            .map_err(|_| unreadable())?;
        let metadata = file.metadata().map_err(|_| unreadable())?;
        if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
            return Err(unreadable());
        }
        let mut text = String::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|_| unreadable())?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err(unreadable());
        }
        Ok(Some(text))
    }

    pub(crate) fn discover_path() -> Option<PathBuf> {
        if let Some(explicit) = std::env::var_os("WORK_CONFIG") {
            if explicit.is_empty() {
                return None;
            }
            return Some(PathBuf::from(explicit));
        }
        if let Some(base) = std::env::var_os("XDG_CONFIG_HOME") {
            if !base.is_empty() {
                return Some(PathBuf::from(base).join("work").join("config.toml"));
            }
        }
        let home = std::env::var_os("HOME")?;
        if home.is_empty() {
            return None;
        }
        Some(
            PathBuf::from(home)
                .join(".config")
                .join("work")
                .join("config.toml"),
        )
    }

    fn from_toml(text: &str) -> Result<Self, Error> {
        Self::from_value(&parse_toml(text)?)
    }
    fn from_value(value: &toml::Value) -> Result<Self, Error> {
        Ok(Self {
            git_path: git_path(value)?,
            store_dir: single_path(value, "store_dir")?,
            trusted_registry: single_path(value, "trusted_registry")?,
            roots: many_paths(value, "roots")?,
            repositories: many_paths(value, "repositories")?,
            supervisor: value
                .get("supervisor")
                .map(|v| {
                    let policy: SupervisorConfig = v
                        .clone()
                        .try_into()
                        .map_err(|_| Error::Config("invalid supervisor policy".into()))?;
                    policy.validate()?;
                    Ok(policy)
                })
                .transpose()?,
            capture: value
                .get("capture")
                .map(|v| {
                    let host: crate::capture_config::HostCaptureConfig = v
                        .clone()
                        .try_into()
                        .map_err(|_| Error::Config("invalid capture policy".into()))?;
                    host.validate()?;
                    Ok(host)
                })
                .transpose()?,
            allocation: value
                .get("allocation")
                .map(|v| {
                    v.clone()
                        .try_into()
                        .map_err(|_| Error::Config("invalid allocation policy".into()))
                })
                .transpose()?,
        })
    }
}
// Unlike authority directories, an executable spelling may traverse installation
// symlinks. This validates only the selector; Git qualification proves its route.
fn git_path(value: &toml::Value) -> Result<Option<PathBuf>, Error> {
    value
        .get("git_path")
        .map(|value| {
            let invalid = || Error::Config("git_path must be an absolute executable path".into());
            let text = value.as_str().ok_or_else(invalid)?;
            if text.bytes().any(|b| matches!(b, 0 | b'\n' | b'\r'))
                || !std::path::Path::new(text).is_absolute()
            {
                return Err(invalid());
            }
            Ok(PathBuf::from(text))
        })
        .transpose()
}

fn parse_toml(text: &str) -> Result<toml::Value, Error> {
    if text.len() as u64 > MAX_CONFIG_BYTES {
        return Err(Error::Config("configuration exceeds size limit".into()));
    }
    let value: toml::Value = toml::from_str(text).map_err(|err: toml::de::Error| {
        // Parser diagnostics include source text and values; expose only location.
        let mut diagnostic = "invalid TOML".to_owned();
        if let Some(span) = err.span() {
            let prefix = &text[..span.start.min(text.len())];
            let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
            let column = prefix.rsplit('\n').next().unwrap_or("").chars().count() + 1;
            diagnostic.push_str(&format!(" at line {line}, column {column}"));
        }
        Error::Config(diagnostic)
    })?;
    if !value.is_table() {
        return Err(Error::Config("expected configuration table".into()));
    }
    Ok(value)
}

fn single_path(value: &toml::Value, key: &str) -> Result<Option<PathBuf>, Error> {
    value
        .get(key)
        .map(|v| {
            let s = v.as_str().ok_or_else(invalid_path)?;
            validate_path(std::path::Path::new(s), false)
        })
        .transpose()
}

fn many_paths(value: &toml::Value, key: &str) -> Result<Vec<PathBuf>, Error> {
    let Some(v) = value.get(key) else {
        return Ok(Vec::new());
    };
    v.as_array()
        .ok_or_else(invalid_path)?
        .iter()
        .map(|v| {
            validate_path(
                std::path::Path::new(v.as_str().ok_or_else(invalid_path)?),
                true,
            )
        })
        .collect()
}

fn invalid_path() -> Error {
    Error::Config("expected absolute canonical path(s) without symlinks".into())
}

#[allow(dead_code)]
fn string_path_list(value: &toml::Value, key: &str) -> Result<Vec<PathBuf>, Error> {
    let Some(v) = value.get(key) else {
        return Ok(Vec::new());
    };
    v.as_array()
        .ok_or_else(|| Error::Config(format!("{key} must be an array of strings")))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(PathBuf::from)
                .ok_or_else(|| Error::Config(format!("{key} must be an array of strings")))
        })
        .collect()
}

#[allow(dead_code)]
fn path_value(path: &std::path::Path, required: bool) -> Result<toml::Value, Error> {
    let path = validate_path(path, required)?;
    Ok(toml::Value::String(
        path.to_str().ok_or_else(invalid_path)?.to_owned(),
    ))
}

#[allow(dead_code)]
fn path_values(paths: &[PathBuf], required: bool) -> Result<Vec<toml::Value>, Error> {
    paths
        .iter()
        .map(|path| path_value(path, required))
        .collect()
}

#[allow(dead_code)]
fn allocation_value(policy: &AllocationPolicy) -> Result<toml::Value, Error> {
    if policy.warn_bytes < policy.floor_bytes {
        return Err(Error::Config("warn_bytes below floor_bytes".into()));
    }
    let mut table = toml::Table::new();
    for (key, value) in [
        ("repository_limit", policy.repository_limit),
        ("owner_limit", policy.owner_limit),
        ("floor_bytes", policy.floor_bytes),
        ("warn_bytes", policy.warn_bytes),
    ] {
        table.insert(
            key.to_owned(),
            toml::Value::Integer(
                i64::try_from(value)
                    .map_err(|_| Error::Config("invalid allocation policy".into()))?,
            ),
        );
    }
    Ok(toml::Value::Table(table))
}

/// Validate every existing component without following symlinks. Missing store
/// or inaccessible optional evidence is allowed (later reported unknown), not
/// manufactured or treated as canonical identity proof.
pub fn validate_path(path: &std::path::Path, required: bool) -> Result<PathBuf, Error> {
    use std::path::Component;
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid_path());
    }
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => (),
            Err(e)
                if !required
                    && matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                    ) => {}
            _ => return Err(invalid_path()),
        }
    }
    if path.exists() && path.canonicalize().map_err(|_| invalid_path())? != path {
        return Err(invalid_path());
    }
    Ok(path.to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovalPolicy {
    pub(crate) format: u32,
    pub(crate) version: String,
    pub(crate) operator_id: String,
    pub(crate) quiet_window_seconds: u64,
    pub(crate) expiry_seconds: u64,
}
impl ApprovalPolicy {
    pub(crate) fn validate(&self) -> Result<(), ()> {
        if self.format != 1
            || [&self.version, &self.operator_id]
                .iter()
                .any(|s| s.trim().is_empty() || s.len() > 256 || s.chars().any(char::is_control))
            || !(1..=1800).contains(&self.quiet_window_seconds)
            || !(1..=1800).contains(&self.expiry_seconds)
        {
            return Err(());
        }
        Ok(())
    }
}

/// Operator declarations, not remote evidence. Never exposed as proof constructors.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemotePolicy {
    pub(crate) format: u32,
    pub(crate) version: String,
    pub(crate) targets: Vec<RemoteTarget>,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteTarget {
    pub(crate) common_dir: PathBuf,
    pub(crate) remote: String,
    pub(crate) url: String,
    pub(crate) branch: String,
}
impl RemotePolicy {
    fn validate(&self) -> Result<(), ()> {
        let mut repositories = std::collections::BTreeSet::new();
        let mut urls = std::collections::BTreeSet::new();
        if self.format != 1
            || !remote_token(&self.version, 128)
            || self.targets.is_empty()
            || self.targets.len() > 32
        {
            return Err(());
        }
        for target in &self.targets {
            let common = target.common_dir.to_str().ok_or(())?;
            if !remote_absolute_path(common)
                || !remote_token(&target.remote, 64)
                || !remote_branch(&target.branch)
                || remote_transport(&target.url).is_none()
                || !repositories.insert(common)
                || !urls.insert(&target.url)
            {
                return Err(());
            }
        }
        Ok(())
    }
}
fn remote_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
pub(crate) fn remote_branch(value: &str) -> bool {
    value.len() <= 256
        && value.starts_with("refs/heads/")
        && value.is_ascii()
        && !value.contains("..")
        && !value.contains("@{")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
        && value.split('/').all(|p| {
            !p.is_empty() && !p.starts_with('.') && !p.ends_with('.') && !p.ends_with(".lock")
        })
}
fn remote_absolute_path(value: &str) -> bool {
    value.len() <= 4096
        && value.starts_with('/')
        && value.len() > 1
        && value[1..]
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
}
/// No userinfo, ports, escapes, queries, fragments or transport helper syntax.
/// LOCAL means same-host transport; it is expressly not an off-host backup.
pub(crate) fn remote_transport(url: &str) -> Option<&'static str> {
    if url.len() > 4096 {
        return None;
    }
    if let Some(path) = url.strip_prefix("file://") {
        return remote_absolute_path(path).then_some("LOCAL");
    }
    let (host, path) = url.strip_prefix("https://")?.split_once('/')?;
    if host.is_empty()
        || host.len() > 253
        || path.is_empty()
        || !host.split('.').all(|p| {
            !p.is_empty()
                && p.len() <= 63
                && p.as_bytes()[0].is_ascii_alphanumeric()
                && p.as_bytes()[p.len() - 1].is_ascii_alphanumeric()
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        || !path
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
        || !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.~".contains(&b))
    {
        return None;
    }
    Some("HTTPS")
}

#[cfg(test)]
mod approval_policy_tests {
    use super::*;
    const VALID: &str = "[approval]\nformat=1\nversion='v1'\noperator_id='explicit operator'\nquiet_window_seconds=1\nexpiry_seconds=1800\n";
    #[test]
    fn strict_lazy_approval_policy_requires_every_explicit_bounded_field() {
        assert!(ConfigDocument::from_text("").unwrap().approval().is_err());
        let good = ConfigDocument::from_text(&format!(
            "{VALID}[capture]\nexecutable=false\n[inspection]\nformat=false\n"
        ))
        .unwrap();
        assert!(good.approval().is_ok());
        assert!(good.authority().is_ok());
        assert!(good.inspection_policies().is_err());
        for (from, to) in [
            ("format=1", "format=2"),
            ("version='v1'", "version=''"),
            ("operator_id='explicit operator'", "operator_id='  '"),
            ("quiet_window_seconds=1", "quiet_window_seconds=0"),
            ("quiet_window_seconds=1", "quiet_window_seconds=1801"),
            ("expiry_seconds=1800", "expiry_seconds=1801"),
            ("expiry_seconds=1800", "expiry_seconds=-1"),
            ("format=1", "format=true"),
            ("format=1", "format=1\nunknown=true"),
        ] {
            let text = VALID.replace(from, to);
            let d = ConfigDocument::from_text(&text).unwrap();
            assert!(d.approval().is_err(), "{from}");
            assert!(d.authority().is_ok());
            assert!(d.inspection_policies().is_ok());
            assert!(Config::from_text(&text).is_ok());
        }
        for line in VALID.lines().skip(1) {
            assert!(ConfigDocument::from_text(&VALID.replace(line, ""))
                .unwrap()
                .approval()
                .is_err());
        }
        for key in ["version='v1'", "operator_id='explicit operator'"] {
            let replacement = format!("{}='{}'", key.split('=').next().unwrap(), "x".repeat(257));
            assert!(ConfigDocument::from_text(&VALID.replace(key, &replacement))
                .unwrap()
                .approval()
                .is_err());
        }
    }
}

#[cfg(test)]
mod remote_policy_tests {
    use super::*;
    fn text(url: &str, branch: &str) -> String {
        format!(
            "[remote_preservation]\nformat=1\nversion='v1'\n[[remote_preservation.targets]]\ncommon_dir='/owned/repository/.git'\nremote='backup'\nurl={url:?}\nbranch={branch:?}\n"
        )
    }
    #[test]
    fn strict_lazy_remote_policy_isolation() {
        let valid = text("https://example.invalid/repo.git", "refs/heads/main");
        let d = ConfigDocument::from_text(&format!(
            "{valid}\n[capture]\nexecutable=false\n[inspection]\nformat=false\n"
        ))
        .unwrap();
        assert!(d.remote_preservation().is_ok());
        assert!(d.authority().is_ok());
        assert!(d.inspection_policies().is_err());
        assert!(ConfigDocument::from_text("")
            .unwrap()
            .remote_preservation()
            .is_err());
        for value in [
            valid.replace("format=1", "format=2"),
            valid.replace("version='v1'", "version=''"),
            valid.replace("remote='backup'", "remote='backup'\nsecret='DO_NOT_ECHO'"),
            valid.replace(
                "common_dir='/owned/repository/.git'",
                "common_dir='/owned/../repository'",
            ),
            "remote_preservation=false".into(),
        ] {
            let d = ConfigDocument::from_text(&value).unwrap();
            assert!(d.authority().is_ok());
            assert!(d.execution().is_ok());
            assert!(d.inspection_policies().is_ok());
            assert!(!d
                .remote_preservation()
                .unwrap_err()
                .to_string()
                .contains("DO_NOT_ECHO"));
        }
    }
    #[test]
    fn remote_url_and_branch_grammar_is_narrow() {
        for url in [
            "ssh://example.invalid/a",
            "git@example.invalid:a",
            "http://example.invalid/a",
            "git://example.invalid/a",
            "ext::helper",
            "https://user@example.invalid/a",
            "https://example.invalid/a?secret",
            "https://example.invalid/a#fragment",
            "https://example.invalid/%61",
            "https://example.invalid/a/../b",
            "file://host/owned/remote",
            "file:///owned/../remote",
            "file:///owned/space name",
            "https://example.invalid:443/a",
        ] {
            assert!(
                ConfigDocument::from_text(&text(url, "refs/heads/main"))
                    .unwrap()
                    .remote_preservation()
                    .is_err(),
                "{url}"
            );
        }
        for branch in [
            "main",
            "HEAD",
            "refs/tags/v1",
            "refs/heads/*",
            "refs/heads/a..b",
            "refs/heads/a.lock",
            "refs/heads/.hidden",
            "refs/heads/x@{y",
            "refs/heads/x\ny",
        ] {
            assert!(
                ConfigDocument::from_text(&text("file:///owned/backup.git", branch))
                    .unwrap()
                    .remote_preservation()
                    .is_err()
            );
        }
        assert!(
            ConfigDocument::from_text(&text("file:///owned/backup.git", "refs/heads/main"))
                .unwrap()
                .remote_preservation()
                .is_ok()
        );
    }
    #[test]
    fn remote_policy_collisions_unknown_fields_and_bounds_hold() {
        let valid = text("file:///owned/backup.git", "refs/heads/main");
        let target = valid
            .split("[[remote_preservation.targets]]")
            .nth(1)
            .unwrap();
        for other in [
            target.to_string(),
            target.replace("/owned/repository/.git", "/another/.git"),
            target.replace("backup.git", "other.git"),
        ] {
            assert!(ConfigDocument::from_text(&format!(
                "{valid}\n[[remote_preservation.targets]]{other}"
            ))
            .unwrap()
            .remote_preservation()
            .is_err());
        }
        assert!(ConfigDocument::from_text(
            &valid.replace("version='v1'", "version='v1'\nunknown=1")
        )
        .unwrap()
        .remote_preservation()
        .is_err());
        assert!(ConfigDocument::from_text(
            &valid.replace("version='v1'", &format!("version='{}'", "a".repeat(129)))
        )
        .unwrap()
        .remote_preservation()
        .is_err());
        assert!(
            ConfigDocument::from_text(&valid.replace("format=1", "format=1\nformat=1")).is_err()
        );
    }
}

#[cfg(test)]
mod inspection_policy_tests {
    use super::*;
    #[test]
    fn lazy_inspection_policy_isolation_and_strictness() {
        let document = ConfigDocument::from_text("[capture]\nexecutable = 42\n[supervisor]\nactors = false\n[allocation]\ncapture_sink = false\n").unwrap();
        assert!(document.authority().is_ok());
        assert_eq!(document.inspection_policies().unwrap().policy_count(), 0);
        assert!(document.execution().is_err());
        let document =
            ConfigDocument::from_text("[inspection]\nformat = 1\npolicies = []\n").unwrap();
        assert_eq!(document.inspection_policies().unwrap().policy_count(), 0);
        for text in [
            "inspection = false",
            "[inspection]\nformat=2\npolicies=[]",
            "[inspection]\nformat=1\npolicies=[]\nsecret='DO_NOT_ECHO'",
            "[inspection]\nformat=1",
        ] {
            let error = ConfigDocument::from_text(text)
                .unwrap()
                .inspection_policies()
                .unwrap_err();
            assert!(!error.to_string().contains("DO_NOT_ECHO"));
        }
    }
}

#[cfg(test)]
mod document_helper_tests {
    #[test]
    fn git_path_rejects_relative_explicit_selection() {
        assert!(super::Config::from_text("git_path = 'relative/git'\n").is_err());
    }

    #[test]
    fn git_path_authority_rejects_malformed_selection() {
        assert!(super::ConfigDocument::from_text("git_path = 42\n")
            .unwrap()
            .authority()
            .is_err());
    }

    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn executable_symlink_spelling_survives_every_document_projection_and_install_render() {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("executable");
        std::fs::write(&executable, b"fixture").unwrap();
        let alias = temp.path().join("git-link");
        std::os::unix::fs::symlink(&executable, &alias).unwrap();
        let mut document =
            ConfigDocument::from_text("private = 'keep'\n[custom]\nvalue = 7\n").unwrap();
        document.set_git_path(&alias).unwrap();
        assert_eq!(document.git_path().unwrap(), Some(alias.clone()));
        assert_eq!(document.authority().unwrap().git_path, Some(alias.clone()));
        assert_eq!(document.execution().unwrap().git_path, Some(alias.clone()));
        let rendered = document.render().unwrap();
        let value: toml::Value = toml::from_str(&rendered).unwrap();
        assert_eq!(value["custom"]["value"].as_integer(), Some(7));
        let install = ConfigDocument::from_install(InstallDocument {
            git_path: Some(alias.clone()),
            actor: "alice".into(),
            repositories: vec![],
            roots: vec![],
            store_dir: temp.path().join("store"),
            trusted_registry: temp.path().join("registry"),
            allocation: policy(),
        })
        .unwrap();
        assert_eq!(
            ConfigDocument::from_text(&install.render().unwrap())
                .unwrap()
                .git_path()
                .unwrap(),
            Some(alias)
        );
    }

    fn dir(temp: &tempfile::TempDir, name: &str) -> PathBuf {
        let path = temp.path().join(name);
        std::fs::create_dir(&path).unwrap();
        path
    }

    fn policy() -> AllocationPolicy {
        AllocationPolicy {
            repository_limit: 8,
            owner_limit: 4,
            floor_bytes: 1,
            warn_bytes: 2,
            capture_sink: None,
        }
    }

    #[test]
    fn document_round_trips_protected_fields_unknown_tables_and_repository_addition() {
        let temp = tempfile::tempdir().unwrap();
        let repo_a = dir(&temp, "repo-a");
        let repo_b = dir(&temp, "repo-b");
        let root = dir(&temp, "root");
        let store = dir(&temp, "store");
        let registry = dir(&temp, "registry");
        let text = format!(
            "actor = \"alice\"\nrepositories = [{:?}]\nroots = [{:?}]\nstore_dir = {:?}\ntrusted_registry = {:?}\n[allocation]\nrepository_limit = 8\nowner_limit = 4\nfloor_bytes = 1\nwarn_bytes = 2\n[mystery]\nkeep = true\nflag = 7\n[inspection]\nformat = false\n",
            repo_a, root, store, registry
        );
        let mut document = ConfigDocument::from_text(&text).unwrap();
        assert_eq!(document.default_actor().unwrap().as_deref(), Some("alice"));
        assert_eq!(document.repositories().unwrap(), vec![repo_a.clone()]);
        assert_eq!(document.roots().unwrap(), vec![root.clone()]);
        assert_eq!(document.allocation().unwrap(), Some(policy()));
        assert!(document.execution().is_ok());
        assert!(document.inspection_policies().is_err());
        assert!(document.add_repository(repo_b.clone()).unwrap());
        assert!(!document.add_repository(repo_a.clone()).unwrap());
        assert_eq!(
            document.repositories().unwrap(),
            vec![repo_a.clone(), repo_b.clone()]
        );
        let rendered = document.render().unwrap();
        let round = ConfigDocument::from_text(&rendered).unwrap();
        let original = parse_toml(&text).unwrap();
        let updated = parse_toml(&rendered).unwrap();
        for key in [
            "actor",
            "roots",
            "store_dir",
            "trusted_registry",
            "allocation",
            "mystery",
            "inspection",
        ] {
            assert_eq!(updated.get(key), original.get(key), "{key}");
        }
        assert_eq!(round.default_actor().unwrap().as_deref(), Some("alice"));
        assert_eq!(round.repositories().unwrap(), vec![repo_a, repo_b]);
        assert_eq!(round.roots().unwrap(), vec![root]);
        assert_eq!(round.allocation().unwrap(), Some(policy()));
        assert!(round.execution().is_ok());
        assert!(round.inspection_policies().is_err());
    }

    #[test]
    fn add_repository_validates_every_entry_before_duplicate_noop() {
        let temp = tempfile::tempdir().unwrap();
        let repo = dir(&temp, "repo");
        let other = dir(&temp, "other");
        let text = format!(
            "actor = \"alice\"\nrepositories = [{:?}, 42]\n[mystery]\nkeep = true\n",
            repo
        );
        let mut document = ConfigDocument::from_text(&text).unwrap();
        let before = document.render().unwrap();
        let error = match document.add_repository(repo.clone()) {
            Err(error) => error,
            Ok(added) => panic!("duplicate no-op skipped later array validation: {added}"),
        };
        let message = error.to_string();
        assert!(
            message.contains("repositories must be an array of strings"),
            "{message}"
        );
        assert!(!message.contains("alice"), "{message}");
        assert!(!message.contains("keep"), "{message}");
        assert_eq!(document.render().unwrap(), before);
        assert_eq!(document.default_actor().unwrap().as_deref(), Some("alice"));
        assert!(document.add_repository(other.clone()).is_err());
        assert_eq!(document.render().unwrap(), before);

        let mut valid = ConfigDocument::from_text(&format!(
            "actor = \"alice\"\nrepositories = [{:?}]\n[mystery]\nkeep = true\n",
            repo
        ))
        .unwrap();
        assert!(!valid.add_repository(repo.clone()).unwrap());
        assert_eq!(valid.repositories().unwrap(), vec![repo.clone()]);
        assert_eq!(valid.default_actor().unwrap().as_deref(), Some("alice"));
        assert!(valid.add_repository(PathBuf::from("/x")).is_err());
        assert_eq!(valid.repositories().unwrap(), vec![repo]);
    }

    #[test]
    fn document_rejects_wrong_actor_and_repository_types() {
        for text in ["actor = 42\n", "actor = []\n"] {
            assert!(ConfigDocument::from_text(text)
                .unwrap()
                .default_actor()
                .is_err());
        }
        for text in ["repositories = \"/x\"\n", "repositories = [42]\n"] {
            let mut document = ConfigDocument::from_text(text).unwrap();
            assert!(document.repositories().is_err());
            assert!(document.add_repository(PathBuf::from("/x")).is_err());
        }
        assert!(ConfigDocument::from_install(InstallDocument {
            git_path: None,
            actor: String::new(),
            repositories: Vec::new(),
            roots: Vec::new(),
            store_dir: PathBuf::from("/store"),
            trusted_registry: PathBuf::from("/registry"),
            allocation: policy(),
        })
        .is_err());
    }

    #[test]
    fn prospective_missing_root_does_not_change_execution_required_paths() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("not-created");
        assert!(!missing.exists());
        assert_eq!(
            ConfigDocument::validate_prospective_path(&missing).unwrap(),
            missing
        );
        let document = ConfigDocument::from_text(&format!("roots = [{missing:?}]\n")).unwrap();
        assert_eq!(document.roots().unwrap(), vec![missing.clone()]);
        assert!(document.execution().is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn new_install_constructs_document_over_toml_values() {
        let temp = tempfile::tempdir().unwrap();
        let repo = dir(&temp, "repo");
        let root = temp.path().join("missing-root");
        let store = temp.path().join("store");
        let registry = temp.path().join("registry");
        let document = ConfigDocument::from_install(InstallDocument {
            git_path: None,
            actor: "alice".into(),
            repositories: vec![repo.clone()],
            roots: vec![root.clone()],
            store_dir: store.clone(),
            trusted_registry: registry.clone(),
            allocation: policy(),
        })
        .unwrap();
        assert_eq!(document.default_actor().unwrap().as_deref(), Some("alice"));
        assert_eq!(document.repositories().unwrap(), vec![repo]);
        assert_eq!(document.roots().unwrap(), vec![root.clone()]);
        assert_eq!(document.allocation().unwrap(), Some(policy()));
        assert!(document.execution().is_err());
        assert_eq!(
            ConfigDocument::validate_prospective_path(&root).unwrap(),
            root
        );
        assert!(!Path::new(&store).exists());
        let round = ConfigDocument::from_text(&document.render().unwrap()).unwrap();
        assert_eq!(
            round.default_actor().unwrap(),
            document.default_actor().unwrap()
        );
        assert_eq!(round.roots().unwrap(), document.roots().unwrap());
        assert_eq!(round.allocation().unwrap(), document.allocation().unwrap());
    }

    #[test]
    fn render_admits_exact_reader_byte_limit_and_rejects_utf8_overflow() {
        let mut document = ConfigDocument::from_text("private = \"\"\n").unwrap();
        let overhead = document.render().unwrap().len();
        let mut private = "x".repeat(MAX_CONFIG_BYTES as usize - overhead - "é".len());
        private.push('é');
        document.value["private"] = toml::Value::String(private.clone());
        let rendered = document.render().unwrap();
        assert_eq!(rendered.len() as u64, MAX_CONFIG_BYTES);
        assert!(ConfigDocument::from_text(&rendered).is_ok());
        private.push('é');
        document.value["private"] = toml::Value::String(private);
        assert_eq!(
            document.render().unwrap_err().to_string(),
            "config error: configuration exceeds size limit"
        );
    }

    #[test]
    fn new_install_rejects_warning_below_floor() {
        let temp = tempfile::tempdir().unwrap();
        let mut allocation = policy();
        allocation.floor_bytes = 2;
        allocation.warn_bytes = 1;
        let result = ConfigDocument::from_install(InstallDocument {
            git_path: None,
            actor: "alice".into(),
            repositories: vec![dir(&temp, "repo")],
            roots: vec![temp.path().join("missing-root")],
            store_dir: temp.path().join("store"),
            trusted_registry: temp.path().join("registry"),
            allocation,
        });
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("expected warning below floor to be refused"),
        };
        let message = error.to_string();
        assert!(message.contains("warn_bytes"), "{message}");
        assert!(message.contains("floor_bytes"), "{message}");
        assert!(!message.contains("alice"), "{message}");
    }

    #[test]
    fn new_install_does_not_emit_historical_capture_selection() {
        let temp = tempfile::tempdir().unwrap();
        let mut allocation = policy();
        allocation.capture_sink = Some("devdiary".into());
        let document = ConfigDocument::from_install(InstallDocument {
            git_path: None,
            actor: "alice".into(),
            repositories: vec![dir(&temp, "repo")],
            roots: vec![temp.path().join("missing-root")],
            store_dir: temp.path().join("store"),
            trusted_registry: temp.path().join("registry"),
            allocation,
        })
        .unwrap();
        let rendered = document.render().unwrap();
        assert!(!rendered.contains("capture_sink"), "{rendered}");
        assert!(!rendered.contains("devdiary"), "{rendered}");
        assert_eq!(document.allocation().unwrap(), Some(policy()));
    }
}
