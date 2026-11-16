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

impl std::fmt::Display for GitVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GitVersionError {
    InvalidProtocol,
}

/// Oldest Git version Work was run with. Doctor warns below it; nothing refuses.
pub(crate) const OLDEST_RUN_GIT_VERSION: GitVersion = GitVersion {
    major: 2,
    minor: 48,
    patch: 1,
};

/// `reason`, followed by the first non-empty line of Git's stderr that is not a
/// `hint:` line. The excerpt is bounded and has control characters replaced, so
/// it is safe to report.
pub(crate) fn failure_reason(reason: &str, stderr: &[u8]) -> String {
    const LIMIT: usize = 200;
    let text = String::from_utf8_lossy(stderr);
    let Some(line) = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("hint:"))
    else {
        return reason.to_owned();
    };
    let mut excerpt = String::new();
    for c in line.chars() {
        let c = if c.is_control() { '\u{fffd}' } else { c };
        if excerpt.len() + c.len_utf8() > LIMIT {
            break;
        }
        excerpt.push(c);
    }
    format!("{reason}: {excerpt}")
}

/// Parse `git version MAJOR.MINOR.PATCH` plus optional vendor text such as
/// ` (Apple Git-157)` or `.windows.1`. No version is refused; repository and
/// executable checks are separate.
pub(crate) fn parse_git_version(output: &[u8]) -> Result<GitVersion, GitVersionError> {
    let invalid = GitVersionError::InvalidProtocol;
    let line = output
        .strip_prefix(b"git version ")
        .and_then(|v| v.strip_suffix(b"\n"))
        .filter(|v| v.iter().all(|c| (b' '..=b'~').contains(c)))
        .ok_or(invalid)?;
    let mut components = line.splitn(3, |c| *c == b'.');
    let mut numbers = [0u32; 3];
    let mut vendor: &[u8] = b"";
    for (index, number) in numbers.iter_mut().enumerate() {
        let mut digits = components.next().ok_or(invalid)?;
        if index == 2 {
            let end = digits
                .iter()
                .position(|c| !c.is_ascii_digit())
                .unwrap_or(digits.len());
            (digits, vendor) = digits.split_at(end);
        }
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
    if !vendor.is_empty()
        && (!matches!(vendor[0], b' ' | b'.') || vendor.len() == 1 || vendor.ends_with(b" "))
    {
        return Err(invalid);
    }
    Ok(GitVersion {
        major: numbers[0],
        minor: numbers[1],
        patch: numbers[2],
    })
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
