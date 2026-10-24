use std::path::PathBuf;

use crate::error::Error;

/// Host-supplied configuration. Compiled defaults do not include any machine,
/// user, or organization paths.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
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
impl ConfigDocument {
    pub(crate) fn load() -> Result<Self, Error> {
        let text = Config::read_text()?.unwrap_or_default();
        Self::from_text(&text)
    }
    pub(crate) fn from_text(text: &str) -> Result<Self, Error> {
        Ok(Self {
            value: parse_toml(text)?,
        })
    }
    pub(crate) fn authority(&self) -> Result<Config, Error> {
        Ok(Config {
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
        const MAX_BYTES: u64 = 1024 * 1024;
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
        if !metadata.is_file() || metadata.len() > MAX_BYTES {
            return Err(unreadable());
        }
        let mut text = String::new();
        file.take(MAX_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|_| unreadable())?;
        if text.len() as u64 > MAX_BYTES {
            return Err(unreadable());
        }
        Ok(Some(text))
    }

    pub(crate) fn discover_path() -> Option<PathBuf> {
        if let Some(explicit) = std::env::var_os("WORK_CONFIG") {
            let path = PathBuf::from(explicit);
            if path.as_os_str().is_empty() {
                return None;
            }
            return Some(path);
        }
        let base = std::env::var_os("XDG_CONFIG_HOME")?;
        if base.is_empty() {
            return None;
        }
        Some(PathBuf::from(base).join("work").join("config.toml"))
    }

    fn from_toml(text: &str) -> Result<Self, Error> {
        Self::from_value(&parse_toml(text)?)
    }
    fn from_value(value: &toml::Value) -> Result<Self, Error> {
        Ok(Self {
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
fn parse_toml(text: &str) -> Result<toml::Value, Error> {
    if text.len() > 1024 * 1024 {
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
        format!("[remote_preservation]\nformat=1\nversion='v1'\n[[remote_preservation.targets]]\ncommon_dir='/owned/repository/.git'\nremote='backup'\nurl={url:?}\nbranch={branch:?}\n")
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
