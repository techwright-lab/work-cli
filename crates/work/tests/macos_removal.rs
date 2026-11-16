//! Simple removal on this Mac: Git's own safety check, then the charge is released.
#![cfg(target_os = "macos")]

use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const GIT: &str = "/usr/bin/git";

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new(GIT)
        .args([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
        ])
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

struct Fixture {
    _owned: tempfile::TempDir,
    root: PathBuf,
    repo: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let owned = tempfile::tempdir().unwrap();
        let root = owned.path().canonicalize().unwrap();
        let repo = root.join("repo");
        let managed = root.join("root");
        let state = root.join("home/state");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir(&repo).unwrap();
        fs::create_dir(&managed).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        fs::write(repo.join(".gitignore"), "*.log\n").unwrap();
        fs::write(repo.join("tracked.txt"), "tracked\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "initial"]);
        let f = Self {
            _owned: owned,
            root,
            repo,
        };
        let path = |p: &Path| p.to_str().unwrap().to_owned();
        let setup = f.work(&[
            "setup",
            "--git",
            GIT,
            "--actor",
            "accept",
            "--repository",
            &path(&f.repo),
            "--root",
            &path(&managed),
            "--store-dir",
            &path(&state.join("store")),
            "--trusted-registry",
            &path(&state.join("registry")),
            "--skills",
            "none",
            "--yes",
        ]);
        assert!(setup.status.success(), "{setup:?}");
        f
    }

    fn work(&self, args: &[&str]) -> Output {
        let home = self.root.join("home");
        Command::new(env!("CARGO_BIN_EXE_work"))
            .args(args)
            .current_dir(&self.root)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .output()
            .unwrap()
    }

    #[track_caller]
    fn json(&self, args: &[&str]) -> Value {
        let output = self.work(args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn start(&self, task: &str) -> PathBuf {
        let started = self.json(&["start", "--task", task, "--base", "main"]);
        PathBuf::from(started["destination"].as_str().unwrap())
    }

    fn charged(&self) -> u64 {
        self.json(&["status", "--json"])["charged"]
            .as_u64()
            .unwrap()
    }

    fn registered(&self, checkout: &Path) -> bool {
        git(&self.repo, &["worktree", "list", "--porcelain"])
            .lines()
            .any(|line| line == format!("worktree {}", checkout.display()))
    }
}

#[test]
fn clean_finished_checkout_is_removed_and_its_branch_kept() {
    let f = Fixture::new();
    let checkout = f.start("one");
    fs::write(checkout.join("change.txt"), "work\n").unwrap();
    git(&checkout, &["add", "change.txt"]);
    git(&checkout, &["commit", "-q", "-m", "change"]);
    let head = git(&checkout, &["rev-parse", "HEAD"]).trim().to_owned();
    f.json(&["finish", "one"]);

    let preview = f.json(&["remove", "one"]);
    assert_eq!(preview["outcome"], "preview");
    assert_eq!(preview["charge_retained"], true);
    assert!(preview.get("ignored_files").is_none(), "{preview}");
    assert!(checkout.is_dir());
    assert_eq!(f.charged(), 1);

    let removed = f.json(&["remove", "one", "--confirm-stopped"]);
    assert_eq!(removed["outcome"], "removed");
    assert_eq!(removed["charge_retained"], false);
    let checkout_id = removed["checkout"].as_str().unwrap();
    let preserved = format!("refs/work-preserved/{checkout_id}/{head}");
    assert_eq!(removed["preserved_refs"], serde_json::json!([preserved]));
    assert!(!checkout.exists());
    assert!(!f.registered(&checkout));
    assert_eq!(f.charged(), 0);
    assert_eq!(git(&f.repo, &["rev-parse", "one"]).trim(), head);
    assert_eq!(
        git(
            &f.repo,
            &[
                "for-each-ref",
                "--format=%(refname) %(objectname)",
                "refs/work-preserved"
            ]
        ),
        format!("{preserved} {head}\n")
    );
}

#[test]
fn modified_and_untracked_files_refuse_until_resolved() {
    let f = Fixture::new();
    let checkout = f.start("two");
    fs::write(checkout.join("tracked.txt"), "changed\n").unwrap();
    fs::write(checkout.join("notes.txt"), "draft\n").unwrap();
    f.json(&["finish", "two"]);

    let refused = f.work(&["remove", "two", "--confirm-stopped"]);
    assert!(!refused.status.success(), "{refused:?}");
    let stderr = String::from_utf8(refused.stderr).unwrap();
    assert!(stderr.contains("tracked.txt"), "{stderr}");
    assert!(stderr.contains("notes.txt"), "{stderr}");
    assert!(stderr.contains("capacity held"), "{stderr}");
    assert!(checkout.join("notes.txt").is_file());
    assert!(f.registered(&checkout));
    assert_eq!(f.charged(), 1);

    git(&checkout, &["commit", "-q", "-am", "keep the change"]);
    fs::remove_file(checkout.join("notes.txt")).unwrap();
    let removed = f.json(&["remove", "two", "--confirm-stopped"]);
    assert_eq!(removed["outcome"], "removed");
    assert!(!checkout.exists());
    assert_eq!(f.charged(), 0);
}

#[test]
fn ignored_files_are_listed_before_removal_deletes_them() {
    // The user's global excludes count as ignored: configured, or Git's default file.
    for configured in [true, false] {
        let f = Fixture::new();
        let home = f.root.join("home");
        let excludes = if configured {
            fs::write(
                home.join(".gitconfig"),
                "[core]\n\texcludesFile = ~/.gitignore\n",
            )
            .unwrap();
            home.join(".gitignore")
        } else {
            home.join(".config/git/ignore")
        };
        fs::create_dir_all(excludes.parent().unwrap()).unwrap();
        fs::write(&excludes, "*.tmp\n").unwrap();
        let checkout = f.start("three");
        fs::write(checkout.join("build.log"), "output\n").unwrap();
        fs::write(checkout.join("scratch.tmp"), "scratch\n").unwrap();
        fs::create_dir_all(checkout.join("target/debug")).unwrap();
        for name in ["a.log", "b.log", "debug/c.log"] {
            fs::write(checkout.join("target").join(name), "built\n").unwrap();
        }
        f.json(&["finish", "three"]);

        let preview = f.json(&["remove", "three"]);
        assert_eq!(preview["outcome"], "preview");
        assert_eq!(
            preview["ignored_files"],
            serde_json::json!(["build.log", "scratch.tmp", "target/"]),
            "configured {configured}"
        );
        assert!(
            preview["next_action"]
                .as_str()
                .unwrap()
                .contains("deletes the ignored files"),
            "{preview}"
        );
        assert!(checkout.join("build.log").is_file());

        let removed = f.json(&["remove", "three", "--confirm-stopped"]);
        assert_eq!(removed["outcome"], "removed", "configured {configured}");
        assert!(!checkout.exists());
        assert_eq!(f.charged(), 0);
    }
}

#[test]
fn git_refusal_after_intent_names_the_cause_and_a_rerun_completes() {
    let f = Fixture::new();
    let checkout = f.start("four");
    let start = git(&checkout, &["rev-parse", "HEAD"]).trim().to_owned();
    f.json(&["finish", "four"]);
    git(&f.repo, &["worktree", "lock", checkout.to_str().unwrap()]);

    let refused = f.work(&["remove", "four", "--confirm-stopped"]);
    assert!(!refused.status.success(), "{refused:?}");
    let stderr = String::from_utf8(refused.stderr).unwrap();
    assert!(stderr.contains("locked working tree"), "{stderr}");
    assert!(!stderr.contains(";;"), "{stderr}");
    assert!(stderr.contains("run the same command again"), "{stderr}");
    assert!(checkout.is_dir());
    let status = f.json(&["status", "--json"]);
    assert_eq!(status["charged"], 1);
    let next = status["checkouts"][0]["next_action"].as_str().unwrap();
    assert!(next.contains("--confirm-stopped"), "{next}");

    git(&f.repo, &["worktree", "unlock", checkout.to_str().unwrap()]);
    fs::write(checkout.join("late.txt"), "late\n").unwrap();
    git(&checkout, &["add", "late.txt"]);
    git(&checkout, &["commit", "-q", "-m", "late"]);
    let late = git(&checkout, &["rev-parse", "HEAD"]).trim().to_owned();
    let removed = f.json(&["remove", "four", "--confirm-stopped"]);
    assert_eq!(removed["outcome"], "removed");
    let preserved = format!(
        "refs/work-preserved/{}/{start}",
        removed["checkout"].as_str().unwrap()
    );
    assert_eq!(removed["preserved_refs"], serde_json::json!([preserved]));
    assert!(!checkout.exists());
    assert_eq!(f.charged(), 0);
    assert_eq!(git(&f.repo, &["rev-parse", "four"]).trim(), late);
}

#[test]
fn commits_named_only_by_per_worktree_refs_are_preserved() {
    let f = Fixture::new();
    let checkout = f.start("five");
    let commit = |name: &str| {
        fs::write(checkout.join(name), "kept\n").unwrap();
        git(&checkout, &["add", name]);
        git(&checkout, &["commit", "-q", "-m", name]);
        git(&checkout, &["rev-parse", "HEAD"]).trim().to_owned()
    };
    let kept = commit("kept.txt");
    git(&checkout, &["update-ref", "refs/worktree/keep", &kept]);
    let tagged = commit("tagged.txt");
    git(&checkout, &["tag", "-a", "-m", "tagged", "tagged"]);
    git(
        &checkout,
        &["update-ref", "refs/worktree/tag", "refs/tags/tagged"],
    );
    git(&checkout, &["tag", "-d", "tagged"]);
    git(
        &checkout,
        &["update-ref", "refs/worktree/tree", "HEAD^{tree}"],
    );
    git(&checkout, &["reset", "-q", "--hard", "HEAD~2"]);
    f.json(&["finish", "five"]);

    let refused = f.work(&["remove", "five", "--confirm-stopped"]);
    assert!(!refused.status.success(), "{refused:?}");
    let stderr = String::from_utf8(refused.stderr).unwrap();
    assert!(stderr.contains("refs/worktree/tree"), "{stderr}");
    assert!(stderr.contains("capacity held"), "{stderr}");
    assert!(checkout.is_dir());
    assert_eq!(f.charged(), 1);

    git(&checkout, &["update-ref", "-d", "refs/worktree/tree"]);
    let removed = f.json(&["remove", "five", "--confirm-stopped"]);
    assert_eq!(removed["outcome"], "removed");
    assert!(!checkout.exists());
    for oid in [&kept, &tagged] {
        let holders = git(
            &f.repo,
            &["for-each-ref", "--format=%(refname)", "--contains", oid],
        );
        assert!(holders.starts_with("refs/work-preserved/"), "{holders}");
    }
}

#[test]
fn commits_made_off_branch_after_a_refusal_must_be_put_on_a_branch() {
    let f = Fixture::new();
    let checkout = f.start("six");
    f.json(&["finish", "six"]);
    let path = checkout.to_str().unwrap();
    git(&f.repo, &["worktree", "lock", path]);
    assert!(!f
        .work(&["remove", "six", "--confirm-stopped"])
        .status
        .success());
    git(&f.repo, &["worktree", "unlock", path]);
    git(&checkout, &["checkout", "-q", "--detach"]);
    fs::write(checkout.join("detached.txt"), "detached\n").unwrap();
    git(&checkout, &["add", "detached.txt"]);
    git(&checkout, &["commit", "-q", "-m", "detached"]);
    let detached = git(&checkout, &["rev-parse", "HEAD"]).trim().to_owned();

    let refused = f.work(&["remove", "six", "--confirm-stopped"]);
    assert!(!refused.status.success(), "{refused:?}");
    let stderr = String::from_utf8(refused.stderr).unwrap();
    assert!(stderr.contains(&detached[..12]), "{stderr}");
    assert!(stderr.contains("put them on a branch"), "{stderr}");
    assert!(checkout.is_dir());
    assert_eq!(f.charged(), 1);

    git(&f.repo, &["branch", "keep", &detached]);
    let removed = f.json(&["remove", "six", "--confirm-stopped"]);
    assert_eq!(removed["outcome"], "removed");
    assert!(!checkout.exists());
    assert_eq!(f.charged(), 0);
}
