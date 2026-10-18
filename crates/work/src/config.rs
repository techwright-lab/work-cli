use std::path::PathBuf;

use crate::error::Error;

/// Host-supplied configuration. Compiled defaults do not include any machine,
/// user, or organization paths.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// Directory for the local lifecycle store, when the host has configured one.
    pub store_dir: Option<PathBuf>,
}

impl Config {
    /// Load configuration if a file already exists. Never creates files or directories.
    pub fn load() -> Result<Self, Error> {
        let Some(path) = Self::discover_path() else {
            return Ok(Self::default());
        };
        if !path.is_file() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path).map_err(|source| Error::io(path, source))?;
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
        let value: toml::Value =
            toml::from_str(text).map_err(|err| Error::Config(err.to_string()))?;
        let store_dir = value
            .get("store_dir")
            .and_then(toml::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);
        Ok(Self { store_dir })
    }
}
