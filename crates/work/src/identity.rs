//! Read/verify checkout identity and qualify Git's supported move operation.
//! This is not retirement authority: callers must establish quiescence and persist
//! intent first. Rename does not revoke cwd/open FDs. No removal or rename fallback.
use std::{
    fs, io,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectoryIdentity {
    pub device: u64,
    pub inode: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckoutIdentity {
    pub path: PathBuf,
    pub private_git_dir: PathBuf,
    pub common_git_dir: PathBuf,
    pub directory: DirectoryIdentity,
    pub head: String,
    pub boot_id: String,
}
fn hold(reason: &str) -> io::Error {
    io::Error::other(reason)
}
fn git(path: &Path, args: &[&std::ffi::OsStr]) -> io::Result<String> {
    let output = crate::bounded_process::output(
        Command::new("/usr/bin/git")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "credential.helper=",
            ])
            .args(args)
            .current_dir(path),
        std::time::Duration::from_secs(2),
        1024 * 1024,
    )
    .map_err(hold)?;
    if !output.status.success() {
        return Err(hold(
            "Git operation failed; hold for reconciliation (no fallback)",
        ));
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim_end_matches('\n').to_owned())
        .map_err(|_| hold("non-UTF8 Git identity unsupported"))
}
/// Open first, then validate the descriptor: no symlink/FIFO/device or unbounded reads.
pub(crate) fn read_metadata(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(hold("non-regular Git metadata"));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(hold("Git metadata exceeds byte limit"));
    }
    Ok(bytes)
}

/// Controlled creation: executable checkout filters (including LFS) are unsupported.
/// Inspect every effective value, including includes and worktree-local configuration.
pub(crate) fn preflight_creation(path: &Path) -> io::Result<()> {
    // --list succeeds for an empty filter set, unlike --get-regexp's ambiguous exit 1.
    let config = query(path, &["config", "--null", "--list"])?;
    for entry in config.split('\0') {
        if let Some((key, value)) = entry.split_once('\n') {
            let key = key.to_ascii_lowercase();
            // A new private gitdir/branch can activate previously inactive config.
            // Until target-context includes are qualified, fail closed, not override.
            if key.starts_with("includeif.") {
                return Err(hold(
                    "conditional Git configuration unsupported for controlled creation",
                ));
            }
            if key.starts_with("filter.")
                && (key.ends_with(".smudge") || key.ends_with(".process"))
                && !value.is_empty()
            {
                return Err(hold(
                    "executable checkout filters unsupported; no filter override is available",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn query(path: &Path, args: &[&str]) -> io::Result<String> {
    git(
        path,
        &args.iter().map(std::ffi::OsStr::new).collect::<Vec<_>>(),
    )
}
impl CheckoutIdentity {
    pub fn inspect(path: &Path) -> io::Result<Self> {
        if fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(hold("symlink checkout unsupported"));
        }
        let path = path.canonicalize()?;
        let meta = fs::metadata(&path)?;
        let top = PathBuf::from(query(&path, &["rev-parse", "--show-toplevel"])?).canonicalize()?;
        if top != path {
            return Err(hold("not a worktree root"));
        }
        let private_git_dir = PathBuf::from(query(
            &path,
            &["rev-parse", "--path-format=absolute", "--git-dir"],
        )?)
        .canonicalize()?;
        let common_git_dir = PathBuf::from(query(
            &path,
            &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        )?)
        .canonicalize()?;
        if private_git_dir != common_git_dir {
            let backlink =
                String::from_utf8(read_metadata(&private_git_dir.join("gitdir"), 16384)?)
                    .map_err(|_| hold("non-UTF8 backlink"))?;
            if Path::new(backlink.trim_end_matches('\n')) != path.join(".git") {
                return Err(hold("Git backlink mismatch"));
            }
            let registration = query(&path, &["worktree", "list", "--porcelain", "-z"])?;
            let expected = format!(
                "worktree {}",
                path.to_str()
                    .ok_or_else(|| hold("non-UTF8 path unsupported"))?
            );
            if !registration.split('\0').any(|field| field == expected) {
                return Err(hold("worktree registration mismatch"));
            }
        }
        Ok(Self {
            head: query(&path, &["rev-parse", "HEAD"])?,
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .to_owned(),
            path,
            private_git_dir,
            common_git_dir,
            directory: DirectoryIdentity {
                device: meta.dev(),
                inode: meta.ino(),
            },
        })
    }
}
/// Same-filesystem Git move only. Error after Git success means the destination
/// may exist: retain accounting and reconcile, never retry by deleting either name.
/// Cooperative guard, NOT race-free exclusion against same-UID concurrent mutation.
pub fn move_worktree(
    expected: &CheckoutIdentity,
    destination: &Path,
) -> io::Result<CheckoutIdentity> {
    let current = CheckoutIdentity::inspect(&expected.path)?;
    if &current != expected {
        return Err(hold("identity changed; reconcile"));
    }
    if current.private_git_dir == current.common_git_dir
        || current.path.join(".gitmodules").exists()
        || current.private_git_dir.join("modules").exists()
    {
        return Err(hold("main/submodule layout unsupported"));
    }
    if fs::symlink_metadata(destination).is_ok() {
        return Err(hold("destination exists"));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| hold("destination parent missing"))?
        .canonicalize()?;
    if fs::metadata(&parent)?.dev() != current.directory.device {
        return Err(hold("cross-filesystem move unsupported"));
    }
    let name = destination
        .file_name()
        .ok_or_else(|| hold("invalid destination"))?;
    let destination = parent.join(name);
    // Revalidate immediately before the only mutation. No force, no blind rename.
    if CheckoutIdentity::inspect(&expected.path)? != current {
        return Err(hold("identity changed before move"));
    }
    git(
        &current.path,
        &[
            "worktree".as_ref(),
            "move".as_ref(),
            "--".as_ref(),
            current.path.as_os_str(),
            destination.as_os_str(),
        ],
    )?;
    let moved = CheckoutIdentity::inspect(&destination)?;
    if moved.directory != current.directory
        || moved.private_git_dir != current.private_git_dir
        || moved.common_git_dir != current.common_git_dir
        || moved.head != current.head
        || moved.boot_id != current.boot_id
    {
        return Err(hold("post-move identity mismatch; reconcile both paths"));
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    #[test]
    fn git_child_environment_is_minimal() {
        if std::env::var_os("WORK_ENV_PROBE").is_some() {
            let temp = tempfile::tempdir().unwrap();
            let env = super::query(temp.path(), &["-c", "alias.probe=!env", "probe"]).unwrap();
            assert!(
                !env.contains("must-not-reach-git"),
                "credential leaked: {env}"
            );
            assert!(!env.contains("WORK_ENV_PROBE="));
            return;
        }
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "identity::tests::git_child_environment_is_minimal"
            ])
            .env("WORK_ENV_PROBE", "1")
            .env("AWS_SECRET_ACCESS_KEY", "must-not-reach-git")
            .env("GITHUB_TOKEN", "must-not-reach-git")
            .status()
            .unwrap()
            .success());
    }
}
