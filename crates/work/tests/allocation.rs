mod support;
use support::*;
use uuid::Uuid;

#[test]
fn start_is_durable_idempotent_policy_bound_and_not_a_writer() {
    let f = Fixture::new();
    let op = Uuid::now_v7().to_string();
    let first = f.start(&op, "task", "topic", &[]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(value["stage"], "ready");
    let path = f.root.join("task");
    assert!(path.join(".git").is_file());
    assert!(!path.join("work-lease.json").exists());
    f.config(0, false);
    assert!(f.start(&op, "task", "topic", &[]).status.success());
    assert!(!f.start(&op, "other", "topic", &[]).status.success());
    assert!(!f
        .start(&Uuid::now_v7().to_string(), "other", "other", &[])
        .status
        .success());
    let mut store = f.store();
    assert!(store.pending_events(100).unwrap().iter().any(|e| {
        let event = serde_json::to_value(&e.event).unwrap();
        event["type"] == "allocation_stage" && event["stage"] == "ready"
    }));
    let id = uuid::Uuid::parse_str(value["checkout"].as_str().unwrap()).unwrap();
    store.acquire_writer(id, Uuid::now_v7()).unwrap();
    assert!(store.acquire_writer(id, Uuid::now_v7()).is_err());
    assert_eq!(store.charged(&f.repo, None).unwrap(), 1);
    drop(store);
    f.config(10, true);
    assert!(!f.start(&op, "task", "topic", &[]).status.success());
    assert!(f.store().acquire_writer(id, Uuid::now_v7()).is_err());
}

#[test]
fn unsafe_names_collisions_and_unsupported_capture_never_grant_ready() {
    for name in ["../escape", "-option", "a/b", ".", "a..b"] {
        let f = Fixture::new();
        assert!(!f
            .start(&Uuid::now_v7().to_string(), name, "topic", &[])
            .status
            .success());
        assert_eq!(f.store().charged(&f.repo, None).unwrap(), 0);
    }
    let f = Fixture::new();
    std::fs::create_dir(f.root.join("task")).unwrap();
    std::fs::write(f.root.join("task/precious"), "keep").unwrap();
    assert!(!f
        .start(&Uuid::now_v7().to_string(), "task", "topic", &[])
        .status
        .success());
    assert_eq!(
        std::fs::read_to_string(f.root.join("task/precious")).unwrap(),
        "keep"
    );
    f.config(10, true);
    assert!(!f
        .start(&Uuid::now_v7().to_string(), "new", "new", &[])
        .status
        .success());
    assert!(!f.root.join("new").exists());
}

#[test]
fn existing_branch_requires_explicit_reuse_and_preserves_commits() {
    let f = Fixture::new();
    git(&f.repo, &["checkout", "-b", "local"]);
    std::fs::write(f.repo.join("extra"), "local").unwrap();
    git(&f.repo, &["add", "."]);
    git(&f.repo, &["commit", "-m", "local"]);
    let head = git(&f.repo, &["rev-parse", "HEAD"]);
    git(&f.repo, &["checkout", "main"]);
    assert!(!f
        .start(&Uuid::now_v7().to_string(), "task", "local", &[])
        .status
        .success());
    assert!(f
        .start(
            &Uuid::now_v7().to_string(),
            "task",
            "local",
            &["--reuse-branch"]
        )
        .status
        .success());
    assert_eq!(git(&f.root.join("task"), &["rev-parse", "HEAD"]), head);
}

#[test]
fn allocation_retry_never_reverses_later_lifecycle_state() {
    for state in [
        "expired",
        "interrupted",
        "held",
        "quarantined",
        "partially_deleted",
        "retired",
    ] {
        let f = Fixture::new();
        let op = Uuid::now_v7().to_string();
        let out = f.start(&op, "task", "topic", &[]);
        assert!(out.status.success());
        let conn = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
        conn.execute("UPDATE checkouts SET state=?1,ready=0", [state])
            .unwrap();
        assert!(
            !f.start(&op, "task", "topic", &[]).status.success(),
            "{state}"
        );
        let actual: String = conn
            .query_row("SELECT state FROM checkouts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(actual, state);
    }
}

#[test]
fn no_config_is_actionable_and_quota_cannot_be_overridden() {
    let f = Fixture::new();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_work"))
        .args(["start", "--task", "task"])
        .env("WORK_CONFIG", "")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("config"));
    assert!(!f
        .start(
            &Uuid::now_v7().to_string(),
            "task",
            "topic",
            &["--owner-limit", "999"]
        )
        .status
        .success());
    assert!(!f
        .start(
            &Uuid::now_v7().to_string(),
            "task",
            "topic",
            &["--owner", "someone-else"]
        )
        .status
        .success());
    assert_eq!(f.store().charged(&f.repo, None).unwrap(), 0);
}
