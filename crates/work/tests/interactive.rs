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
    assert!(human.contains("qualification: runtime qualification not verified"));
}

#[test]
fn explicit_removal_retains_commits_and_releases_one_capacity_slot() {
    let mut f = Fixture::new();
    // A real clone creates native pack/reverse-index metadata, unlike the
    // loose-object fixture which previously hid the host-pilot refusal.
    let cloned = f.temp.path().join("cloned");
    support::git(
        f.temp.path(),
        &[
            "-c",
            "pack.writeReverseIndex=true",
            "clone",
            "--no-local",
            "--no-hardlinks",
            f.repo.to_str().unwrap(),
            cloned.to_str().unwrap(),
        ],
    );
    f.repo = cloned;
    // Match the isolated host pilot: no remote HEAD symref or remote routing.
    support::git(&f.repo, &["remote", "remove", "origin"]);
    support::git(&f.repo, &["config", "user.name", "Test"]);
    support::git(&f.repo, &["config", "user.email", "test@example.invalid"]);
    assert!(std::fs::read_dir(f.repo.join(".git/objects/pack"))
        .unwrap()
        .any(|entry| entry
            .unwrap()
            .path()
            .extension()
            .is_some_and(|e| e == "rev")));
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
    let blocked = f.start(&uuid::Uuid::now_v7().to_string(), "second", "second", &[]);
    assert!(!blocked.status.success());
    let explanation = String::from_utf8(blocked.stderr).unwrap();
    assert!(explanation.contains(id) && explanation.contains("owner=alice"));
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

#[test]
fn uuid_shaped_task_names_resolve_and_conflicting_ids_refuse() {
    for task in [
        "9b3de7f4-5ae4-4f23-a00d-dce2bacb52c0".to_string(),
        uuid::Uuid::now_v7().to_string(),
    ] {
        let f = Fixture::new();
        json(f.start(&uuid::Uuid::now_v7().to_string(), &task, "topic", &[]));
        json(command(&f, &["finish", &task]));
        assert_eq!(json(command(&f, &["remove", &task]))["outcome"], "preview");
    }
    let f = Fixture::new();
    let a = json(f.start(&uuid::Uuid::now_v7().to_string(), "first", "first", &[]));
    let id = a["checkout"].as_str().unwrap();
    json(f.start(&uuid::Uuid::now_v7().to_string(), id, "second", &[]));
    assert!(!command(&f, &["finish", id]).status.success());
    assert!(json(command(&f, &["status", "--json"]))["checkouts"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["task_finished"] == false));
}

#[test]
fn human_status_explains_allocation_holds() {
    let f = Fixture::new();
    let op = uuid::Uuid::now_v7().to_string();
    let a = json(f.start(&op, "task", "topic", &[]));
    support::git(
        std::path::Path::new(a["destination"].as_str().unwrap()),
        &["checkout", "-b", "changed"],
    );
    assert!(!f.start(&op, "task", "topic", &[]).status.success());
    let status = json(command(&f, &["status", "--json"]));
    let reason = status["checkouts"][0]["reason"].as_str().unwrap();
    let human = command(&f, &["status"]);
    assert!(human.status.success());
    assert!(String::from_utf8(human.stdout).unwrap().contains(reason));
}

#[test]
fn removal_requires_persistent_common_storage() {
    let mut f = Fixture::new();
    let volatile = tempfile::tempdir_in("/dev/shm").unwrap();
    let repo = volatile.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    support::git(&repo, &["init", "-b", "main"]);
    support::git(&repo, &["config", "user.name", "Test"]);
    support::git(&repo, &["config", "user.email", "test@example.invalid"]);
    support::git(&repo, &["commit", "--allow-empty", "-m", "initial"]);
    f.repo = repo;
    f.config(10, false);
    let a = json(f.start(&uuid::Uuid::now_v7().to_string(), "task", "topic", &[]));
    json(command(&f, &["finish", "task"]));
    let result = command(&f, &["remove", "task", "--confirm-stopped"]);
    assert!(!result.status.success(), "{result:?}");
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("nonpersistent_filesystem"),
        "{result:?}"
    );
    assert!(std::path::Path::new(a["destination"].as_str().unwrap()).is_dir());
    assert!(support::git(&f.repo, &["for-each-ref", "refs/work-preserved/"]).is_empty());
    assert_eq!(json(command(&f, &["status", "--json"]))["charged"], 1);
}

#[test]
fn detached_checkout_is_explicitly_unsupported_and_retained() {
    let f = Fixture::new();
    let a = json(f.start(&uuid::Uuid::now_v7().to_string(), "task", "topic", &[]));
    let path = std::path::Path::new(a["destination"].as_str().unwrap());
    support::git(path, &["checkout", "--detach"]);
    support::git(path, &["commit", "--allow-empty", "-m", "detached work"]);
    let head = support::git(path, &["rev-parse", "HEAD"]);
    assert!(!command(&f, &["finish", "task"]).status.success());
    assert!(!command(&f, &["remove", "task", "--confirm-stopped"])
        .status
        .success());
    assert_eq!(support::git(path, &["rev-parse", "HEAD"]), head);
    assert_eq!(json(command(&f, &["status", "--json"]))["charged"], 1);
}
