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
fn normal_start_reuses_key_under_reduced_capacity_and_changed_root_branch() {
    let f = Fixture::new();
    let run = |extra: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_work"))
            .args([
                "start",
                "--repository",
                f.repo.to_str().unwrap(),
                "--root",
                f.root.to_str().unwrap(),
                "--actor",
                "alice",
                "--task",
                "task",
            ])
            .args(extra)
            .env("WORK_CONFIG", f.temp.path().join("config.toml"))
            .output()
            .unwrap()
    };
    let first = run(&[]);
    assert!(first.status.success());
    let original: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let other = f.temp.path().join("other-root");
    std::fs::create_dir(&other).unwrap();
    let config_path = f.temp.path().join("config.toml");
    let config = std::fs::read_to_string(&config_path)
        .unwrap()
        .replace(
            &format!("roots = [{:?}]", f.root),
            &format!("roots = [{:?}, {:?}]", f.root, other),
        )
        .replace("repository_limit = 10", "repository_limit = 0")
        .replace("owner_limit = 10", "owner_limit = 0")
        .replace("floor_bytes = 0", "floor_bytes = 9223372036854775807")
        .replace("warn_bytes = 0", "warn_bytes = 9223372036854775807");
    std::fs::write(config_path, config).unwrap();
    let repeated = run(&["--branch", "different"]);
    assert!(
        repeated.status.success(),
        "{}",
        String::from_utf8_lossy(&repeated.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&repeated.stdout).unwrap();
    assert_eq!(value["checkout"], original["checkout"]);
    assert_eq!(
        value["request"]["operation"],
        original["request"]["operation"]
    );
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_work"))
        .args([
            "start",
            "--repository",
            f.repo.to_str().unwrap(),
            "--root",
            other.to_str().unwrap(),
            "--actor",
            "alice",
            "--task",
            "task",
            "--branch",
            "different",
        ])
        .env("WORK_CONFIG", f.temp.path().join("config.toml"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!other.join("task").exists());
}

#[test]
fn ready_descendant_commit_is_reused_but_changed_branch_is_held() {
    let f = Fixture::new();
    let op = Uuid::now_v7().to_string();
    assert!(f.start(&op, "task", "topic", &[]).status.success());
    let checkout = f.root.join("task");
    let identity = work_cli::identity::CheckoutIdentity::inspect(&checkout).unwrap();
    let marker = identity.private_git_dir.join("work-lease.json");
    let baseline = std::fs::read(&marker).unwrap();
    git(&checkout, &["commit", "--allow-empty", "-m", "work"]);
    let committed = git(&checkout, &["rev-parse", "HEAD"]);
    for operation in [&op, &Uuid::now_v7().to_string()] {
        let out = f.start(operation, "task", "topic", &[]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert_eq!(std::fs::read(&marker).unwrap(), baseline);
    assert!(f.store().pending_events(100).unwrap().iter().any(|event| matches!(
        &event.event, work_cli::events::Event::HeadAdvanced { old, new, .. } if old == &identity.head && new == &committed
    )));
    git(&checkout, &["checkout", "-b", "changed"]);
    assert!(!f.start(&op, "task", "topic", &[]).status.success());
    assert!(!f
        .start(&Uuid::now_v7().to_string(), "task", "topic", &[])
        .status
        .success());
}

#[test]
fn synthetic_git_parents_cannot_authorize_ready_descendant_reuse() {
    let mut accepted = Vec::new();
    for mechanism in ["replace", "graft"] {
        let f = Fixture::new();
        let op = Uuid::now_v7().to_string();
        assert!(f.start(&op, "task", "topic", &[]).status.success());
        let checkout = f.root.join("task");
        let prior = work_cli::identity::CheckoutIdentity::inspect(&checkout).unwrap();
        let marker = prior.private_git_dir.join("work-lease.json");
        let marker_bytes = std::fs::read(&marker).unwrap();
        let tree = git(&checkout, &["rev-parse", "HEAD^{tree}"]);
        let unrelated = git(&checkout, &["commit-tree", &tree, "-m", "unrelated"]);
        git(&checkout, &["update-ref", "refs/heads/topic", &unrelated]);
        match mechanism {
            "replace" => {
                git(&checkout, &["replace", "--graft", &unrelated, &prior.head]);
            }
            "graft" => {
                std::fs::create_dir_all(prior.common_git_dir.join("info")).unwrap();
                std::fs::write(
                    prior.common_git_dir.join("info/grafts"),
                    format!("{unrelated} {}\n", prior.head),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        // Default Git is fooled, while every non-graph anchor still matches.
        git(
            &checkout,
            &["merge-base", "--is-ancestor", &prior.head, &unrelated],
        );
        let current = work_cli::identity::CheckoutIdentity::inspect(&checkout).unwrap();
        assert_eq!(current.path, prior.path);
        assert_eq!(current.directory, prior.directory);
        assert_eq!(current.private_git_dir, prior.private_git_dir);
        assert_eq!(current.common_git_dir, prior.common_git_dir);
        assert_eq!(std::fs::read(&marker).unwrap(), marker_bytes);
        assert_eq!(
            git(&checkout, &["symbolic-ref", "HEAD"]),
            "refs/heads/topic"
        );
        let out = f.start(&op, "task", "topic", &[]);
        if out.status.success() {
            accepted.push(mechanism);
        }
        assert_eq!(f.store().charged(&f.repo, None).unwrap(), 1);
    }
    assert!(
        accepted.is_empty(),
        "synthetic ancestry authorized reuse: {accepted:?}"
    );
}

#[test]
fn sibling_alias_and_legacy_path_charge_share_capacity() {
    for legacy in [false, true] {
        let f = Fixture::new();
        let sibling = f.temp.path().join("sibling");
        git(
            &f.repo,
            &[
                "worktree",
                "add",
                "-b",
                "sibling",
                sibling.to_str().unwrap(),
            ],
        );
        if legacy {
            f.store()
                .reserve(
                    &work_cli::admission::Reservation {
                        operation: Uuid::now_v7(),
                        repository: f.repo.clone(),
                        actor: "old".into(),
                        owner: "old".into(),
                        task: "old".into(),
                    },
                    work_cli::admission::Limits {
                        repository: 10,
                        owner: 10,
                        available_bytes: Some(100),
                        floor_bytes: 0,
                        warn_bytes: 0,
                    },
                )
                .unwrap();
            // Recreate the actual pre-v2 schema, retaining the charge and digest.
            let conn =
                rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
            conn.execute_batch("DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; DROP TABLE attribution_gaps; DROP TABLE capture_readiness; DROP TABLE capture_finalizations; DROP TABLE capture_requirements; DROP TABLE capture_runs; DROP TABLE task_finishes; DROP TABLE run_participants; DROP TABLE adopted_segments; DROP TABLE adopted_sessions; DROP TABLE adopted_groups; DROP TABLE runs; DROP TABLE run_groups; DROP TABLE repository_aliases; DROP TABLE allocations; ALTER TABLE checkouts DROP COLUMN ready; PRAGMA user_version=1;").unwrap();
        } else {
            assert!(f
                .start(&Uuid::now_v7().to_string(), "first", "first", &[])
                .status
                .success());
        }
        f.config(1, false);
        let p = f.temp.path().join("config.toml");
        let config = std::fs::read_to_string(&p).unwrap().replace(
            &format!("repositories = [{:?}]", f.repo),
            &format!("repositories = [{:?}, {:?}]", f.repo, sibling),
        );
        std::fs::write(p, config).unwrap();
        let conn = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
        let charge: (String, Vec<u8>) = conn
            .query_row("SELECT repository,digest FROM checkouts", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_work"))
            .args([
                "start",
                "--repository",
                sibling.to_str().unwrap(),
                "--root",
                f.root.to_str().unwrap(),
                "--actor",
                "alice",
                "--task",
                "second",
            ])
            .env("WORK_CONFIG", f.temp.path().join("config.toml"))
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "legacy={legacy}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(!f.root.join("second").exists());
        assert_eq!(f.store().charged(&sibling, None).unwrap(), 1);
        let retained: (String, Vec<u8>) = conn
            .query_row("SELECT repository,digest FROM checkouts", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(
            charge, retained,
            "registration never rewrites legacy accounting evidence"
        );
    }
}

#[test]
fn unresolved_legacy_charge_fails_closed_without_changing_digest() {
    let f = Fixture::new();
    let unknown = f.temp.path().join("unknown");
    std::fs::create_dir(&unknown).unwrap();
    f.store()
        .reserve(
            &work_cli::admission::Reservation {
                operation: Uuid::now_v7(),
                repository: unknown,
                actor: "old".into(),
                owner: "old".into(),
                task: "old".into(),
            },
            work_cli::admission::Limits {
                repository: 10,
                owner: 10,
                available_bytes: Some(100),
                floor_bytes: 0,
                warn_bytes: 0,
            },
        )
        .unwrap();
    let conn = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
    let digest: Vec<u8> = conn
        .query_row("SELECT digest FROM checkouts", [], |r| r.get(0))
        .unwrap();
    let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
    assert!(!out.status.success());
    assert!(!f.root.join("task").exists());
    let retained: Vec<u8> = conn
        .query_row("SELECT digest FROM checkouts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(digest, retained);
}

#[test]
fn concurrent_same_key_starts_return_one_checkout() {
    let f = Fixture::new();
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    f.start(&Uuid::now_v7().to_string(), "task", "topic", &[])
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    let values: Vec<serde_json::Value> = results
        .iter()
        .map(|out| {
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            serde_json::from_slice(&out.stdout).unwrap()
        })
        .collect();
    assert_eq!(values[0]["checkout"], values[1]["checkout"]);
    assert_eq!(f.store().charged(&f.repo, None).unwrap(), 1);
}

#[test]
fn ambiguous_key_revokes_readiness_and_keeps_both_charges() {
    let f = Fixture::new();
    assert!(f
        .start(&Uuid::now_v7().to_string(), "task", "topic", &[])
        .status
        .success());
    f.store()
        .reserve(
            &work_cli::admission::Reservation {
                operation: Uuid::now_v7(),
                repository: f.repo.clone(),
                actor: "alice".into(),
                owner: "alice".into(),
                task: "task".into(),
            },
            work_cli::admission::Limits {
                repository: 10,
                owner: 10,
                available_bytes: Some(100),
                floor_bytes: 0,
                warn_bytes: 0,
            },
        )
        .unwrap();
    assert!(!f
        .start(&Uuid::now_v7().to_string(), "task", "topic", &[])
        .status
        .success());
    let conn = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
    let ready: i64 = conn
        .query_row("SELECT sum(ready) FROM checkouts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(ready, 0);
    assert_eq!(f.store().charged(&f.repo, None).unwrap(), 2);
    let path_keyed: i64 = conn
        .query_row(
            "SELECT count(*) FROM checkouts WHERE repository=?1",
            [f.repo.to_str().unwrap()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        path_keyed, 0,
        "new reservations use the registered common identity"
    );
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
fn persisted_holds_cannot_escape_through_start() {
    for damage in ["capture", "marker"] {
        let f = Fixture::new();
        let op = Uuid::now_v7().to_string();
        let out = f.start(&op, "task", "topic", &[]);
        assert!(out.status.success());
        let a: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let marker = std::path::PathBuf::from(a["identity"]["private_git_dir"].as_str().unwrap())
            .join("work-lease.json");
        let original = std::fs::read(&marker).unwrap();
        if damage == "capture" {
            f.config(10, true);
        } else {
            std::fs::write(&marker, "{}").unwrap();
        }
        assert!(!f.start(&op, "task", "topic", &[]).status.success());
        f.config(10, false);
        std::fs::write(&marker, original).unwrap();
        for operation in [&op, &Uuid::now_v7().to_string()] {
            assert!(
                !f.start(operation, "task", "topic", &[]).status.success(),
                "{damage}: hold escaped"
            );
        }
        let conn = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
        let state: (String, bool) = conn
            .query_row("SELECT state,ready FROM checkouts", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(state, ("held".into(), false));
        assert_eq!(f.store().charged(&f.repo, None).unwrap(), 1);
    }
}

#[test]
fn executable_checkout_filters_are_rejected_before_materialization() {
    for kind in ["smudge", "process", "conditional-smudge"] {
        let f = Fixture::new();
        std::fs::write(f.repo.join(".gitattributes"), "payload filter=sentinel\n").unwrap();
        std::fs::write(f.repo.join("payload"), "payload").unwrap();
        git(&f.repo, &["add", "."]);
        git(&f.repo, &["commit", "-m", "attributes"]);
        let sentinel = f.temp.path().join("executed");
        if kind == "conditional-smudge" {
            let included = f.temp.path().join("filter.config");
            std::fs::write(
                &included,
                format!(
                    "[filter \"sentinel\"]\nsmudge = touch {}; cat\n",
                    sentinel.display()
                ),
            )
            .unwrap();
            git(
                &f.repo,
                &[
                    "config",
                    &format!("includeIf.gitdir:{}/.git/worktrees/.path", f.repo.display()),
                    included.to_str().unwrap(),
                ],
            );
        } else {
            git(
                &f.repo,
                &[
                    "config",
                    &format!("filter.sentinel.{kind}"),
                    &format!("touch {}; cat", sentinel.display()),
                ],
            );
        }
        let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
        assert!(!sentinel.exists(), "{kind} executed");
        assert!(!out.status.success(), "{kind} was allowed");
        assert!(!f.root.join("task").exists());
    }
}

#[test]
fn git_configuration_environment_cannot_inject_checkout_commands() {
    let f = Fixture::new();
    let sentinel = f.temp.path().join("injected");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_work"))
        .args([
            "start",
            "--repository",
            f.repo.to_str().unwrap(),
            "--root",
            f.root.to_str().unwrap(),
            "--actor",
            "alice",
            "--task",
            "task",
            "--base",
            "main",
        ])
        .env("WORK_CONFIG", f.temp.path().join("config.toml"))
        .env("GIT_CONFIG_PARAMETERS", "malformed-untrusted-config")
        .env("AWS_SECRET_ACCESS_KEY", "must-not-reach-git")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(f.root.join("task/.git").exists());
    assert!(!sentinel.exists());
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
