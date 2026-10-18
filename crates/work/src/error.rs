use std::io;
use std::path::PathBuf;

/// Generic CLI errors. No host-specific paths or product names are embedded.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not initialized")]
    NotInitialized,
    #[error("config error: {0}")]
    Config(String),
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl Error {
    pub fn io(path: PathBuf, source: io::Error) -> Self {
        Self::Io { path, source }
    }
}
