//! Public lifecycle on this Mac: setup, start, status, finish in an owned fixture.
#![cfg(target_os = "macos")]

use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const GIT: &str = "/usr/bin/git";

fn git(dir: &Path, args: &[&str]) {
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
}

struct Fixture {
    _owned: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
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
}

#[test]
fn setup_start_reuse_finish_and_status_work_on_this_mac() {
    let owned = tempfile::tempdir().unwrap();
    let root = owned.path().canonicalize().unwrap();
    let f = Fixture {
        _owned: owned,
        root: root.clone(),
    };
    let repo = root.join("repo");
    let managed = root.join("root");
    let state = root.join("home/state");
    fs::create_dir_all(&state).unwrap();
    fs::create_dir(&repo).unwrap();
    fs::create_dir(&managed).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["commit", "-q", "--allow-empty", "-m", "initial"]);

    let path = |p: &Path| p.to_str().unwrap().to_owned();
    let setup = f.work(&[
        "setup",
        "--git",
        GIT,
        "--actor",
        "accept",
        "--repository",
        &path(&repo),
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

    let first = f.json(&["start", "--task", "one", "--base", "main"]);
    let checkout = Path::new(first["destination"].as_str().unwrap()).to_owned();
    assert_eq!(checkout, managed.join("one"));
    let status = f.json(&["status", "--json"]);
    assert_eq!(status["charged"], 1);
    assert_eq!(status["checkouts"][0]["task"], "one");
    assert_eq!(status["checkouts"][0]["task_finished"], false);

    fs::write(checkout.join("change.txt"), b"work\n").unwrap();
    git(&checkout, &["add", "change.txt"]);
    git(&checkout, &["commit", "-q", "-m", "change"]);
    let again = f.json(&["start", "--task", "one", "--base", "main"]);
    assert_eq!(again["checkout"], first["checkout"]);

    let finished = f.json(&["finish", "one"]);
    assert_eq!(finished["task_finished"], true);
    let status = f.json(&["status", "--json"]);
    assert_eq!(status["charged"], 1);
    assert_eq!(status["checkouts"][0]["task_finished"], true);
    assert!(checkout.join("change.txt").is_file());
}
