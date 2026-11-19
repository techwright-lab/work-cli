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
        self.work_in(&self.root, args)
    }

    fn work_in(&self, dir: &Path, args: &[&str]) -> Output {
        let home = self.root.join("home");
        Command::new(env!("CARGO_BIN_EXE_work"))
            .args(args)
            .current_dir(dir)
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
    assert_eq!(checkout, managed.join("repo").join("one"));
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

/// A fixture with a repository, an empty managed root and a Git identity in HOME.
fn unconfigured(identity: &str) -> (Fixture, PathBuf, PathBuf) {
    let owned = tempfile::tempdir().unwrap();
    let root = owned.path().canonicalize().unwrap();
    let repo = root.join("project");
    let managed = root.join("root");
    fs::create_dir_all(root.join("home/state")).unwrap();
    fs::create_dir(&repo).unwrap();
    fs::create_dir(&managed).unwrap();
    fs::write(root.join("home/.gitconfig"), identity).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["commit", "-q", "--allow-empty", "-m", "initial"]);
    let f = Fixture {
        _owned: owned,
        root,
    };
    (f, repo, managed)
}

fn setup_without_actor_or_repository(f: &Fixture, managed: &Path) -> Output {
    let state = f.root.join("home/state");
    f.work(&[
        "setup",
        "--git",
        GIT,
        "--root",
        managed.to_str().unwrap(),
        "--store-dir",
        state.join("store").to_str().unwrap(),
        "--trusted-registry",
        state.join("registry").to_str().unwrap(),
        "--skills",
        "none",
        "--yes",
    ])
}

#[test]
fn setup_takes_the_actor_from_git_email_then_name_and_refuses_without_either() {
    for (identity, actor) in [
        (
            "[user]\n\tname = Ada Lovelace\n\temail = ada.l+work@example.invalid\n",
            Some("ada.l-work"),
        ),
        ("[user]\n\tname = Ada Lovelace\n", Some("ada-lovelace")),
        ("", None),
    ] {
        let (f, _repo, managed) = unconfigured(identity);
        let setup = setup_without_actor_or_repository(&f, &managed);
        let config = fs::read_to_string(f.root.join("home/.config/work/config.toml"));
        match actor {
            Some(actor) => {
                assert!(setup.status.success(), "{identity:?}: {setup:?}");
                assert!(config.unwrap().contains(&format!("actor = \"{actor}\"")));
            }
            None => {
                assert!(!setup.status.success(), "{setup:?}");
                assert!(String::from_utf8_lossy(&setup.stdout).contains("pass --actor"));
                assert!(config.is_err());
            }
        }
    }
}

#[test]
fn start_inside_an_unlisted_repository_adds_it_and_nests_the_checkout() {
    let (f, repo, managed) = unconfigured("[user]\n\temail = ada@example.invalid\n");
    let setup = setup_without_actor_or_repository(&f, &managed);
    assert!(setup.status.success(), "{setup:?}");

    let output = f.work_in(&repo, &["start", "--task", "one", "--base", "main"]);
    assert!(output.status.success(), "{output:?}");
    let started: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(started["request"]["repository"], repo.to_str().unwrap());
    assert_eq!(started["request"]["actor"], "ada");
    assert_eq!(
        started["destination"],
        managed.join("project/one").to_str().unwrap()
    );
    let config = fs::read_to_string(f.root.join("home/.config/work/config.toml")).unwrap();
    assert!(config.contains(repo.to_str().unwrap()), "{config}");
}

#[test]
fn a_symlinked_repository_folder_under_the_root_is_refused() {
    let (f, repo, managed) = unconfigured("[user]\n\temail = ada@example.invalid\n");
    let setup = setup_without_actor_or_repository(&f, &managed);
    assert!(setup.status.success(), "{setup:?}");
    let elsewhere = f.root.join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, managed.join("project")).unwrap();

    let output = f.work_in(&repo, &["start", "--task", "one", "--base", "main"]);
    assert!(!output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("checkout parent is not a directory"));
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
}
