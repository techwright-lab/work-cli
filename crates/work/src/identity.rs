//! Read/verify checkout identity and qualify Git's supported move operation.
//! This is not retirement authority: callers must establish quiescence and persist
//! intent first. Rename does not revoke cwd/open FDs. No removal or rename fallback.
use std::{
    fs, io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryIdentity {
    pub device: u64,
    pub inode: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
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
    let output = Command::new("git")
        .args(args)
        .current_dir(path)
        // Repository-selection overrides must not redirect the identity query.
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env_remove("GIT_CONFIG_COUNT")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()?;
    if !output.status.success() {
        return Err(hold(
            "Git operation failed; hold for reconciliation (no fallback)",
        ));
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim_end_matches('\n').to_owned())
        .map_err(|_| hold("non-UTF8 Git identity unsupported"))
}
fn query(path: &Path, args: &[&str]) -> io::Result<String> {
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
            let backlink = fs::read_to_string(private_git_dir.join("gitdir"))?;
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
