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

impl Config {
    /// Load configuration if a file already exists. Never creates files or directories.
    pub fn load() -> Result<Self, Error> {
        let Some(path) = Self::discover_path() else {
            return Ok(Self::default());
        };
        if !path.exists() && std::env::var_os("WORK_CONFIG").is_none() {
            return Ok(Self::default());
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
        Self::from_toml(&text)
    }

    fn discover_path() -> Option<PathBuf> {
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
        let single = |key: &str| -> Result<Option<PathBuf>, Error> {
            value
                .get(key)
                .map(|v| {
                    let s = v.as_str().ok_or_else(invalid_path)?;
                    validate_path(std::path::Path::new(s), false)
                })
                .transpose()
        };
        let many = |key: &str| -> Result<Vec<PathBuf>, Error> {
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
        };
        Ok(Self {
            store_dir: single("store_dir")?,
            trusted_registry: single("trusted_registry")?,
            roots: many("roots")?,
            repositories: many("repositories")?,
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
