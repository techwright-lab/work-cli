use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use work_cli::identity::{move_worktree, CheckoutIdentity};

struct Repo(PathBuf);
impl Repo {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "work-move-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        git(&root, &["init", "-q"]);
        git(
            &root,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--allow-empty",
                "-qm",
                "initial",
            ],
        );
        git(&root, &["worktree", "add", "-qb", "fixture", "source"]);
        Self(root)
    }
    fn source(&self) -> PathBuf {
        self.0.join("source")
    }
}
impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}
#[test]
fn git_move_updates_backlink_registration_and_retains_evidence() {
    let repo = Repo::new();
    let before = CheckoutIdentity::inspect(&repo.source()).unwrap();
    git(
        &repo.source(),
        &["update-ref", "refs/work/recovery/fixture", "HEAD"],
    );
    let reflog = git(&repo.source(), &["reflog", "--format=%H"]);
    let dest = repo.0.join("quarantine");
    let after = move_worktree(&before, &dest).unwrap();
    assert_eq!(before.private_git_dir, after.private_git_dir);
    assert_eq!(before.common_git_dir, after.common_git_dir);
    assert_eq!(before.directory, after.directory);
    assert_eq!(after.path, dest.canonicalize().unwrap());
    assert_eq!(
        fs::read_to_string(after.private_git_dir.join("gitdir"))
            .unwrap()
            .trim(),
        dest.join(".git").to_str().unwrap()
    );
    assert!(git(&repo.0, &["worktree", "list", "--porcelain"]).contains(dest.to_str().unwrap()));
    assert_eq!(git(&dest, &["reflog", "--format=%H"]), reflog);
    assert_eq!(
        git(&dest, &["rev-parse", "refs/work/recovery/fixture"]),
        before.head
    );
    fs::create_dir(repo.source()).unwrap();
    fs::write(repo.source().join("keep"), "recreated").unwrap();
    assert!(move_worktree(&before, &repo.0.join("other")).is_err());
    assert_eq!(
        fs::read_to_string(repo.source().join("keep")).unwrap(),
        "recreated"
    );
}
#[test]
fn collisions_locks_unsupported_layout_and_git_failure_hold_without_rename() {
    for case in ["collision", "locked", "main", "submodule", "missing-parent"] {
        let repo = Repo::new();
        let source = if case == "main" {
            repo.0.clone()
        } else {
            repo.source()
        };
        let before = CheckoutIdentity::inspect(&source).unwrap();
        let mut dest = repo.0.join("quarantine");
        match case {
            "collision" => {
                fs::create_dir(&dest).unwrap();
                fs::write(dest.join("keep"), "keep").unwrap();
            }
            "locked" => {
                git(&repo.0, &["worktree", "lock", "source"]);
            }
            "submodule" => {
                fs::write(
                    source.join(".gitmodules"),
                    "[submodule \"child\"]\npath=child\nurl=./child\n",
                )
                .unwrap();
            }
            "missing-parent" => dest = repo.0.join("absent/quarantine"),
            _ => {}
        }
        assert!(move_worktree(&before, &dest).is_err(), "{case}");
        assert!(source.exists(), "source survives {case}");
        if case == "collision" {
            assert_eq!(fs::read_to_string(dest.join("keep")).unwrap(), "keep");
        } else {
            assert!(!dest.exists(), "no fallback rename {case}");
        }
    }
}
#[test]
fn replacement_and_changed_git_registration_require_reconciliation() {
    for replace in [true, false] {
        let repo = Repo::new();
        let before = CheckoutIdentity::inspect(&repo.source()).unwrap();
        if replace {
            fs::rename(repo.source(), repo.0.join("old")).unwrap();
            fs::create_dir(repo.source()).unwrap();
            fs::copy(repo.0.join("old/.git"), repo.source().join(".git")).unwrap();
        } else {
            fs::write(
                before.private_git_dir.join("gitdir"),
                "/not-the-checkout/.git\n",
            )
            .unwrap();
        }
        assert!(move_worktree(&before, &repo.0.join("quarantine")).is_err());
        assert!(repo.source().exists());
    }
}
