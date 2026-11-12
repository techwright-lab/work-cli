//! Read/verify checkout identity and qualify Git's supported move operation.
//! This is not retirement authority: callers must establish quiescence and persist
//! intent first. Rename does not revoke cwd/open FDs. No removal or rename fallback.
use std::{
    fs, io,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
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
fn git(
    invocation: &crate::git::GitInvocation,
    path: &Path,
    args: &[&std::ffi::OsStr],
) -> io::Result<String> {
    let binding = invocation.require()?;
    let command = binding
        .command(std::iter::empty::<&str>(), |command| {
            command
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("LC_ALL", "C")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_TERMINAL_PROMPT", "0")
                // Identity is the stored object graph, never user-supplied parents.
                // Override legacy grafts as well as modern replacement objects.
                .env("GIT_GRAFT_FILE", "/dev/null")
                // Unsupported Git versions fail closed before inspecting objects;
                // partial clones must not fetch missing objects during authority proof.
                .args(["--no-replace-objects", "--no-lazy-fetch"])
                .args([
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "credential.helper=",
                ])
                .args(args)
                .current_dir(path);
        })
        .map_err(|_| hold("Git binding changed before identity dispatch"))?;
    let output = command
        .dispatch(|command| {
            crate::bounded_process::output(command, std::time::Duration::from_secs(2), 1024 * 1024)
        })
        .map_err(std::io::Error::other)?
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
#[cfg(not(target_os = "macos"))]
fn boot_identity() -> io::Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned())
}
/// Two equal observations of the kernel boot session, or a hold. There is no
/// substitute identity when the observation is missing, malformed or nil.
#[cfg(target_os = "macos")]
fn boot_identity() -> io::Result<String> {
    let observe =
        || work_darwin::boot_session_uuid().map_err(|_| hold("boot session identity unavailable"));
    let first = observe()?;
    if observe()? != first {
        return Err(hold("boot session identity changed during observation"));
    }
    Ok(darwin_boot_id(&first))
}
#[cfg(target_os = "macos")]
const DARWIN_BOOT_PROVIDER: &str = "darwin-bootsession-v1:";
// PROVISIONAL, pending the record-compatibility decision (issue 54): the Darwin
// boot provider and its version travel as a prefix inside the existing boot_id
// string, so no record format changes. This is the only place that encodes it.
#[cfg(target_os = "macos")]
fn darwin_boot_id(session: &work_darwin::BootSessionUuid) -> String {
    let uuid = session.as_bytes().iter().copied().map(char::from);
    DARWIN_BOOT_PROVIDER.chars().chain(uuid).collect()
}
/// Whether a recorded boot identity came from this platform's provider. One
/// from another provider is incomparable: neither this boot nor an earlier one.
#[cfg(target_os = "macos")]
fn recorded_by_native_boot_provider(recorded: &str) -> bool {
    recorded
        .strip_prefix(DARWIN_BOOT_PROVIDER)
        .is_some_and(|uuid| {
            let frame = [uuid.as_bytes(), &[0]].concat();
            work_darwin::parse_boot_session_uuid(&frame)
                .is_ok_and(|session| session.as_bytes() == uuid.as_bytes())
        })
}
/// Whether the recorded device number still fits this checkout. A device
/// number may change only across a reboot, and only a boot identity from this
/// platform's provider can show one: a foreign record never reads as a reboot.
pub(crate) fn device_fits_record(current: &CheckoutIdentity, prior: &CheckoutIdentity) -> bool {
    #[cfg(target_os = "macos")]
    if !recorded_by_native_boot_provider(&prior.boot_id) {
        return false;
    }
    current.boot_id != prior.boot_id || current.directory.device == prior.directory.device
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
pub(crate) fn preflight_creation_with_git(
    invocation: &crate::git::GitInvocation,
    path: &Path,
) -> io::Result<()> {
    // --list succeeds for an empty filter set, unlike --get-regexp's ambiguous exit 1.
    let config = query_with_git(invocation, path, &["config", "--null", "--list"])?;
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

#[cfg(test)]
pub(crate) fn query(path: &Path, args: &[&str]) -> io::Result<String> {
    query_with_git(&crate::git::GitInvocation::new(None, None), path, args)
}
pub(crate) fn query_with_git(
    invocation: &crate::git::GitInvocation,
    path: &Path,
    args: &[&str],
) -> io::Result<String> {
    git(
        invocation,
        path,
        &args.iter().map(std::ffi::OsStr::new).collect::<Vec<_>>(),
    )
}
impl CheckoutIdentity {
    pub fn inspect(path: &Path) -> io::Result<Self> {
        Self::inspect_with_git(&crate::git::GitInvocation::new(None, None), path)
    }
    pub(crate) fn inspect_with_git(
        invocation: &crate::git::GitInvocation,
        path: &Path,
    ) -> io::Result<Self> {
        if fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(hold("symlink checkout unsupported"));
        }
        let path = path.canonicalize()?;
        let meta = fs::metadata(&path)?;
        let top = PathBuf::from(query_with_git(
            invocation,
            &path,
            &["rev-parse", "--show-toplevel"],
        )?)
        .canonicalize()?;
        if top != path {
            return Err(hold("not a worktree root"));
        }
        let private_git_dir = PathBuf::from(query_with_git(
            invocation,
            &path,
            &["rev-parse", "--path-format=absolute", "--git-dir"],
        )?)
        .canonicalize()?;
        let common_git_dir = PathBuf::from(query_with_git(
            invocation,
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
            let registration = query_with_git(
                invocation,
                &path,
                &["worktree", "list", "--porcelain", "-z"],
            )?;
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
            head: query_with_git(invocation, &path, &["rev-parse", "HEAD"])?,
            boot_id: boot_identity()?,
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
    move_worktree_with_git(
        &crate::git::GitInvocation::new(None, None),
        expected,
        destination,
    )
}
pub(crate) fn move_worktree_with_git(
    invocation: &crate::git::GitInvocation,
    expected: &CheckoutIdentity,
    destination: &Path,
) -> io::Result<CheckoutIdentity> {
    let current = CheckoutIdentity::inspect_with_git(invocation, &expected.path)?;
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
    if CheckoutIdentity::inspect_with_git(invocation, &expected.path)? != current {
        return Err(hold("identity changed before move"));
    }
    git(
        invocation,
        &current.path,
        &[
            "worktree".as_ref(),
            "move".as_ref(),
            "--".as_ref(),
            current.path.as_os_str(),
            destination.as_os_str(),
        ],
    )?;
    let moved = CheckoutIdentity::inspect_with_git(invocation, &destination)?;
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

#[cfg(all(test, target_os = "macos"))]
mod darwin_boot_tests {
    use super::*;

    #[test]
    fn boot_identity_is_stable_and_names_its_provider() {
        let boot = boot_identity().unwrap();
        assert_eq!(boot_identity().unwrap(), boot);
        let uuid = boot.strip_prefix("darwin-bootsession-v1:").unwrap();
        assert_eq!(uuid.len(), 36);
        assert!(uuid
            .bytes()
            .all(|b| b == b'-' || b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_ne!(uuid, "00000000-0000-0000-0000-000000000000");
        assert!(recorded_by_native_boot_provider(&boot));
    }

    #[test]
    fn records_from_another_provider_or_malformed_records_never_match() {
        let linux = "5f0c3b1e-8d2a-4c6f-9b1a-2e7d4f6a8c01";
        let tagged = format!("darwin-bootsession-v1:{linux}");
        assert!(recorded_by_native_boot_provider(&tagged));
        for recorded in [
            linux.to_owned(),
            String::new(),
            "darwin-bootsession-v1:".to_owned(),
            format!("darwin-bootsession-v2:{linux}"),
            tagged.to_uppercase(),
            format!("darwin-bootsession-v1:{}", linux.to_uppercase()),
            "darwin-bootsession-v1:00000000-0000-0000-0000-000000000000".to_owned(),
            format!("{tagged}\n"),
        ] {
            assert!(!recorded_by_native_boot_provider(&recorded), "{recorded}");
        }
    }

    fn checkout(boot_id: &str, device: u64) -> CheckoutIdentity {
        CheckoutIdentity {
            path: "/checkout".into(),
            private_git_dir: "/checkout/.git".into(),
            common_git_dir: "/checkout/.git".into(),
            directory: DirectoryIdentity { device, inode: 7 },
            head: "0".repeat(40),
            boot_id: boot_id.to_owned(),
        }
    }

    #[test]
    fn device_change_is_a_reboot_only_between_native_boot_identities() {
        let this_boot = "darwin-bootsession-v1:5f0c3b1e-8d2a-4c6f-9b1a-2e7d4f6a8c01";
        let earlier_boot = "darwin-bootsession-v1:0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
        let linux_boot = "5f0c3b1e-8d2a-4c6f-9b1a-2e7d4f6a8c01";
        let current = checkout(this_boot, 2);

        assert!(device_fits_record(&current, &checkout(this_boot, 2)));
        assert!(device_fits_record(&current, &checkout(earlier_boot, 1)));
        assert!(!device_fits_record(&current, &checkout(this_boot, 1)));
        assert!(!device_fits_record(&current, &checkout(linux_boot, 1)));
        assert!(!device_fits_record(&current, &checkout(linux_boot, 2)));
    }
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
