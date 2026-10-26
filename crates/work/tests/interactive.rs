mod support;

use serde_json::Value;
use std::process::{Command, Output};
use support::Fixture;

fn command(f: &Fixture, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_work"))
        .args(args)
        .current_dir(&f.repo)
        .env("WORK_CONFIG", f.temp.path().join("config.toml"))
        .output()
        .unwrap()
}

#[track_caller]
fn json(output: Output) -> Value {
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn configured_interactive_task_can_start_reuse_list_and_finish() {
    let f = Fixture::new();
    let path = f.temp.path().join("config.toml");
    let config = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("actor = 'alice'\n{config}")).unwrap();
    let first = json(command(&f, &["start", "--task", "interactive"]));
    let again = json(command(&f, &["start", "--task", "interactive"]));
    assert_eq!(first["checkout"], again["checkout"]);
    let status = json(command(&f, &["status", "--json"]));
    assert_eq!(status["charged"], 1);
    assert_eq!(status["checkouts"].as_array().unwrap().len(), 1);
    assert_eq!(status["checkouts"][0]["task"], "interactive");
    assert_eq!(status["checkouts"][0]["owner"], "alice");
    assert_eq!(status["checkouts"][0]["task_finished"], false);
    let finished = json(command(&f, &["finish", "interactive"]));
    assert_eq!(finished["task_finished"], true);
    let status = json(command(&f, &["status", "--json"]));
    assert_eq!(status["charged"], 1);
    assert_eq!(status["checkouts"][0]["task_finished"], true);
    assert!(std::path::Path::new(first["destination"].as_str().unwrap()).is_dir());
    let human = command(&f, &["status"]);
    assert!(human.status.success());
    let human = String::from_utf8(human.stdout).unwrap();
    assert!(human.contains("interactive") && human.contains("alice"));
    assert!(!human.contains("placeholder"));
}

#[test]
fn explicit_removal_retains_commits_and_releases_one_capacity_slot() {
    let f = Fixture::new();
    f.config(1, false);
    let first = json(f.start(&uuid::Uuid::now_v7().to_string(), "first", "first", &[]));
    let id = first["checkout"].as_str().unwrap();
    let path = std::path::Path::new(first["destination"].as_str().unwrap());
    support::git(path, &["commit", "--allow-empty", "-m", "local work"]);
    let local = support::git(path, &["rev-parse", "HEAD"]);
    support::git(path, &["reset", "--hard", "HEAD~1"]);
    assert!(!command(&f, &["remove", id, "--confirm-stopped"])
        .status
        .success());
    json(command(&f, &["finish", "first"]));
    let preview = json(command(&f, &["remove", "first"]));
    assert_eq!(preview["outcome"], "preview");
    assert!(path.exists());
    assert_eq!(json(command(&f, &["status", "--json"]))["charged"], 1);
    assert!(!f
        .start(&uuid::Uuid::now_v7().to_string(), "second", "second", &[])
        .status
        .success());
    let removed = json(command(&f, &["remove", "first", "--confirm-stopped"]));
    assert_eq!(removed["outcome"], "removed");
    assert!(!path.exists());
    let refs = support::git(
        &f.repo,
        &[
            "for-each-ref",
            "--format=%(objectname)",
            "refs/work-preserved/",
        ],
    );
    assert!(refs.lines().any(|oid| oid == local));
    assert_eq!(
        support::git(&f.repo, &["rev-parse", "refs/heads/first"]),
        support::git(&f.repo, &["rev-parse", "main"])
    );
    assert_eq!(json(command(&f, &["status", "--json"]))["charged"], 0);
    let repeated = json(command(&f, &["remove", id, "--confirm-stopped"]));
    assert_eq!(repeated["outcome"], "removed");
    json(f.start(&uuid::Uuid::now_v7().to_string(), "second", "second", &[]));
    assert_eq!(json(command(&f, &["status", "--json"]))["charged"], 1);
}

#[test]
fn removal_refuses_payload_changes_and_preserves_capacity() {
    for kind in ["dirty", "untracked", "ignored", "draft", "foreign"] {
        let f = Fixture::new();
        std::fs::write(f.repo.join("tracked"), "committed\n").unwrap();
        std::fs::write(f.repo.join(".gitignore"), "cache\n").unwrap();
        support::git(&f.repo, &["add", "."]);
        support::git(&f.repo, &["commit", "-m", "tracked files"]);
        let a = json(f.start(&uuid::Uuid::now_v7().to_string(), "task", "task", &[]));
        let path = std::path::Path::new(a["destination"].as_str().unwrap());
        json(command(&f, &["finish", "task"]));
        let file = match kind {
            "dirty" => path.join("tracked"),
            "untracked" => path.join("notes"),
            "ignored" => path.join("cache"),
            "draft" => f.repo.join(".git/worktrees/task/COMMIT_EDITMSG"),
            "foreign" => f.repo.join(".git/worktrees/task/unknown-artifact"),
            _ => unreachable!(),
        };
        std::fs::write(&file, "keep this work\n").unwrap();
        let result = command(&f, &["remove", "task", "--confirm-stopped"]);
        assert!(!result.status.success(), "{kind}: {result:?}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "keep this work\n");
        assert_eq!(json(command(&f, &["status", "--json"]))["charged"], 1);
        assert!(path.is_dir());
        assert!(!f
            .store()
            .pending_events(100)
            .unwrap()
            .iter()
            .any(|e| matches!(e.event, work_cli::events::Event::InteractiveRemoval { .. })));
    }
}

#[test]
fn defaults_do_not_share_owners_and_missing_status_does_not_initialize() {
    let f = Fixture::new();
    let status = json(command(&f, &["status", "--json"]));
    assert_eq!(status["initialized"], false);
    assert!(!f.temp.path().join("private").exists());
    assert!(!f.temp.path().join("registry").exists());
    json(command(
        &f,
        &["start", "--task", "shared", "--actor", "alice"],
    ));
    assert!(
        !command(&f, &["start", "--task", "shared", "--actor", "bob"])
            .status
            .success()
    );
    let status = json(command(&f, &["status", "--json"]));
    assert_eq!(status["checkouts"][0]["owner"], "alice");
}
