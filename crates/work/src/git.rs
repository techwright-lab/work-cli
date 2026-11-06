//! Deterministic Git candidate planning and invocation-owned qualification.
//!
//! Candidates alone are not proof of executable safety.

use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct GitVersion {
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) patch: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GitVersionError {
    InvalidProtocol,
    BelowMinimum {
        found: GitVersion,
        minimum: GitVersion,
    },
}

/// Compatibility admission only; repository and executable checks are separate.
pub(crate) fn require_supported_git_version(output: &[u8]) -> Result<GitVersion, GitVersionError> {
    let invalid = GitVersionError::InvalidProtocol;
    let version = output
        .strip_prefix(b"git version ")
        .and_then(|v| v.strip_suffix(b"\n"))
        .ok_or(invalid)?;
    let mut components = version.split(|c| *c == b'.');
    let mut numbers = [0u32; 3];
    for number in &mut numbers {
        let digits = components.next().ok_or(invalid)?;
        if digits.is_empty()
            || !digits.iter().all(u8::is_ascii_digit)
            || (digits.len() > 1 && digits[0] == b'0')
        {
            return Err(invalid);
        }
        *number = std::str::from_utf8(digits)
            .map_err(|_| invalid)?
            .parse()
            .map_err(|_| invalid)?;
    }
    if components.next().is_some() {
        return Err(invalid);
    }
    let found = GitVersion {
        major: numbers[0],
        minor: numbers[1],
        patch: numbers[2],
    };
    let minimum = GitVersion {
        major: 2,
        minor: 55,
        patch: 0,
    };
    if found < minimum {
        return Err(GitVersionError::BelowMinimum { found, minimum });
    }
    Ok(found)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GitPlatform {
    Linux,
    MacOs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GitSelectionSource {
    Cli,
    Config,
    PlatformDefault,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GitCandidate {
    pub(crate) path: PathBuf,
    pub(crate) source: GitSelectionSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GitCandidateError {
    NotAbsolute(GitCandidate),
}

/// Plan only: do not resolve paths, probe files, execute Git or read environment.
/// An explicit choice produces one candidate, never a default fallback list.
pub(crate) fn git_candidates(
    platform: GitPlatform,
    cli: Option<&Path>,
    config: Option<&Path>,
) -> Result<Vec<GitCandidate>, GitCandidateError> {
    let explicit = cli
        .map(|path| (path, GitSelectionSource::Cli))
        .or_else(|| config.map(|path| (path, GitSelectionSource::Config)));
    if let Some((path, source)) = explicit {
        let candidate = GitCandidate {
            path: path.to_owned(),
            source,
        };
        if !candidate.path.is_absolute() {
            return Err(GitCandidateError::NotAbsolute(candidate));
        }
        return Ok(vec![candidate]);
    }
    let defaults: &[&str] = match platform {
        GitPlatform::Linux => &["/usr/bin/git"],
        GitPlatform::MacOs => &["/opt/homebrew/bin/git", "/usr/bin/git"],
    };
    Ok(defaults
        .iter()
        .map(|path| GitCandidate {
            path: PathBuf::from(path),
            source: GitSelectionSource::PlatformDefault,
        })
        .collect())
}

#[cfg(test)]
#[path = "git_tests.rs"]
mod tests;

include!("git_binding.rs");

#[cfg(test)]
#[path = "git_binding_tests.rs"]
mod binding_tests;
