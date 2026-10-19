mod support;
use support::*;
use uuid::Uuid;
use work_cli::{
    allocate::{start_observed, Start},
    config::Config,
};

#[test]
fn allocation_worker() {
    let Ok(base) = std::env::var("WORK_ALLOCATION_BASE") else {
        return;
    };
    let config = Config::load().unwrap();
    let request: Start = serde_json::from_slice(
        &std::fs::read(std::path::Path::new(&base).join("request.json")).unwrap(),
    )
    .unwrap();
    start_observed(&config, request, |boundary| {
        if std::env::var("WORK_ALLOCATION_BOUNDARY").as_deref() == Ok(boundary) {
            // Worker-local only: retain SIGABRT crash semantics without costly core dumps.
            use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
            setrlimit(
                Resource::Core,
                Rlimit {
                    current: Some(0),
                    ..getrlimit(Resource::Core)
                },
            )
            .unwrap();
            assert_eq!(
                getrlimit(Resource::Core).current,
                Some(0),
                "intentional fault worker must not dump core"
            );
            std::process::abort();
        }
    })
    .unwrap();
}

#[test]
fn subprocess_abort_boundaries_retain_exact_path_and_charge() {
    for boundary in [
        "charged", "reserved", "intent", "created", "identity", "marker", "ready",
    ] {
        let f = Fixture::new();
        let operation = Uuid::now_v7();
        let request = Start {
            operation,
            repository: Some(f.repo.clone()),
            root: Some(f.root.clone()),
            actor: Some("alice".into()),
            owner: None,
            task: "task".into(),
            branch: Some("topic".into()),
            base: "main".into(),
            reuse_branch: false,
        };
        std::fs::write(
            f.temp.path().join("request.json"),
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "allocation_worker"])
            .env("WORK_ALLOCATION_BASE", f.temp.path())
            .env("WORK_CONFIG", f.temp.path().join("config.toml"))
            .env("WORK_ALLOCATION_BOUNDARY", boundary)
            .current_dir(f.temp.path())
            .status()
            .unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(6), "{boundary}");
        assert_eq!(f.store().charged(&f.repo, None).unwrap(), 1);
        let out = f.start(&operation.to_string(), "task", "topic", &[]);
        assert_eq!(
            out.status.success(),
            matches!(boundary, "charged" | "reserved" | "marker" | "ready"),
            "{boundary}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(f.store().charged(&f.repo, None).unwrap(), 1);
        let entries: Vec<_> = std::fs::read_dir(&f.root).unwrap().collect();
        assert!(entries.len() <= 1, "{boundary}");
        let conn = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
        let (id, ready): (String, bool) = conn
            .query_row("SELECT id,ready FROM checkouts", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        if !out.status.success() {
            assert!(!ready);
            assert!(f
                .store()
                .acquire_writer(Uuid::parse_str(&id).unwrap(), Uuid::now_v7())
                .is_err());
        }
        if boundary == "created" {
            assert!(f.root.join("task/.git").exists());
        }
    }
}

#[test]
fn reserved_retry_rejects_replaced_source_authority() {
    let f = Fixture::new();
    let operation = Uuid::now_v7();
    let request = Start {
        operation,
        repository: Some(f.repo.clone()),
        root: Some(f.root.clone()),
        actor: Some("alice".into()),
        owner: None,
        task: "task".into(),
        branch: Some("topic".into()),
        base: "main".into(),
        reuse_branch: false,
    };
    std::fs::write(
        f.temp.path().join("request.json"),
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "allocation_worker"])
        .env("WORK_ALLOCATION_BASE", f.temp.path())
        .env("WORK_CONFIG", f.temp.path().join("config.toml"))
        .env("WORK_ALLOCATION_BOUNDARY", "reserved")
        .current_dir(f.temp.path())
        .status()
        .unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(6));
    let conn = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
    let before: (String, Vec<u8>) = conn
        .query_row("SELECT repository,digest FROM checkouts", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    let other = f.temp.path().join("other");
    git(
        f.temp.path(),
        &[
            "clone",
            "--no-local",
            f.repo.to_str().unwrap(),
            other.to_str().unwrap(),
        ],
    );
    std::fs::rename(&f.repo, f.temp.path().join("original")).unwrap();
    git(
        &other,
        &[
            "worktree",
            "add",
            "-b",
            "replacement",
            f.repo.to_str().unwrap(),
            "main",
        ],
    );
    let out = f.start(&operation.to_string(), "task", "topic", &[]);
    assert!(!out.status.success(), "reservation retargeted");
    assert!(!f.root.join("task").exists());
    assert!(!git(&other, &["worktree", "list", "--porcelain"]).contains(f.root.to_str().unwrap()));
    let after: (String, Vec<u8>) = conn
        .query_row("SELECT repository,digest FROM checkouts", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(before, after);
    let state: (String, bool) = conn
        .query_row("SELECT state,ready FROM checkouts", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(state, ("held".into(), false));
}

#[test]
fn reboot_reconciles_durable_evidence_but_marker_tampering_holds() {
    for damage in [
        "reboot",
        "malformed",
        "marker-fifo",
        "marker-oversized",
        "marker-symlink",
        "copied",
        "inode",
        "missing",
        "bad-record",
        "wrong-id",
        "missing-record",
        "gitdir",
        "registration",
        "replacement",
        "nonancestor",
    ] {
        let f = Fixture::new();
        let op = Uuid::now_v7().to_string();
        let out = f.start(&op, "task", "topic", &[]);
        assert!(out.status.success());
        let mut record: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let marker =
            std::path::PathBuf::from(record["identity"]["private_git_dir"].as_str().unwrap())
                .join("work-lease.json");
        match damage {
            "reboot" => {
                record["identity"]["boot_id"] = "previous-boot".into();
                record["identity"]["directory"]["device"] = 999999.into();
            }
            "inode" => record["identity"]["directory"]["inode"] = 0.into(),
            "gitdir" => std::fs::write(
                f.root.join("task/.git"),
                format!("gitdir: {}\n", f.repo.join(".git").display()),
            )
            .unwrap(),
            "registration" => std::fs::write(
                marker.parent().unwrap().join("gitdir"),
                f.root.join("wrong/.git").to_str().unwrap(),
            )
            .unwrap(),
            "replacement" => {
                std::fs::rename(f.root.join("task"), f.root.join("original")).unwrap();
                std::fs::create_dir(f.root.join("task")).unwrap();
                std::fs::copy(f.root.join("original/.git"), f.root.join("task/.git")).unwrap();
            }
            "nonancestor" => {
                let path = f.root.join("task");
                git(&path, &["checkout", "--orphan", "unrelated"]);
                git(&path, &["commit", "--allow-empty", "-m", "unrelated"]);
                let head = git(&path, &["rev-parse", "HEAD"]);
                git(&path, &["checkout", "topic"]);
                git(&path, &["reset", "--hard", &head]);
            }
            "bad-record" | "missing-record" => {}
            "wrong-id" => record["checkout"] = Uuid::now_v7().to_string().into(),
            "marker-fifo" => {
                std::fs::remove_file(&marker).unwrap();
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &marker,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                    0,
                )
                .unwrap();
            }
            "marker-oversized" => std::fs::write(&marker, vec![b' '; 16385]).unwrap(),
            "marker-symlink" => {
                let original = marker.with_extension("original");
                std::fs::rename(&marker, &original).unwrap();
                std::os::unix::fs::symlink(original, &marker).unwrap();
            }
            "malformed" => std::fs::write(&marker, b"{").unwrap(),
            "missing" => std::fs::remove_file(&marker).unwrap(),
            "copied" => {
                let other = f.start(&Uuid::now_v7().to_string(), "other", "other", &[]);
                assert!(other.status.success());
                let other: serde_json::Value = serde_json::from_slice(&other.stdout).unwrap();
                let source = std::path::PathBuf::from(
                    other["identity"]["private_git_dir"].as_str().unwrap(),
                )
                .join("work-lease.json");
                std::fs::copy(source, &marker).unwrap();
            }
            _ => unreachable!(),
        }
        let conn = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
        let original: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        conn.execute(
            "UPDATE allocations SET record=?1 WHERE checkout=?2",
            rusqlite::params![
                if damage == "bad-record" {
                    "{".into()
                } else {
                    record.to_string()
                },
                original["checkout"].as_str().unwrap()
            ],
        )
        .unwrap();
        if damage == "missing-record" {
            conn.execute("DELETE FROM allocations", []).unwrap();
        }
        assert_eq!(
            f.start(&op, "task", "topic", &[]).status.success(),
            damage == "reboot",
            "{damage}"
        );
        if damage != "reboot" {
            assert!(
                f.store()
                    .acquire_writer(
                        Uuid::parse_str(original["checkout"].as_str().unwrap()).unwrap(),
                        Uuid::now_v7()
                    )
                    .is_err(),
                "{damage}: writer eligibility not revoked"
            );
        }
        assert!(f.root.join("task").exists());
        assert_eq!(
            f.store().charged(&f.repo, None).unwrap(),
            if damage == "copied" { 2 } else { 1 }
        );
    }
}

#[test]
fn version_one_migration_preserves_charge_without_inventing_ready() {
    let f = Fixture::new();
    let mut s = f.store();
    let id = s
        .reserve(
            &work_cli::admission::Reservation {
                operation: Uuid::now_v7(),
                repository: f.repo.clone(),
                actor: "a".into(),
                owner: "a".into(),
                task: "t".into(),
            },
            work_cli::admission::Limits {
                repository: 10,
                owner: 10,
                available_bytes: Some(1),
                floor_bytes: 0,
                warn_bytes: 0,
            },
        )
        .unwrap();
    drop(s);
    let conn = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
    conn.execute_batch(
        "DROP TABLE runs; DROP TABLE run_groups; DROP TABLE repository_aliases; DROP TABLE allocations; ALTER TABLE checkouts DROP COLUMN ready; PRAGMA user_version=1;",
    )
    .unwrap();
    drop(conn);
    let mut s = f.store();
    assert_eq!(s.charged(&f.repo, None).unwrap(), 1);
    assert!(s.acquire_writer(id, Uuid::now_v7()).is_err());
}
#[test]
fn readiness_rechecks_marker_after_external_side_effects() {
    for damage in ["marker", "head"] {
        let f = Fixture::new();
        let config = Config {
            store_dir: Some(f.temp.path().join("private")),
            trusted_registry: Some(f.temp.path().join("registry")),
            roots: vec![f.root.clone()],
            repositories: vec![f.repo.clone()],
            supervisor: None,
            allocation: Some(work_cli::config::AllocationPolicy {
                repository_limit: 10,
                owner_limit: 10,
                floor_bytes: 0,
                warn_bytes: 0,
                capture_sink: None,
            }),
        };
        let request = Start {
            operation: Uuid::now_v7(),
            repository: Some(f.repo.clone()),
            root: Some(f.root.clone()),
            actor: Some("alice".into()),
            owner: None,
            task: "task".into(),
            branch: Some("topic".into()),
            base: "main".into(),
            reuse_branch: false,
        };
        let result = start_observed(&config, request, |boundary| {
            if boundary == "marker" {
                let i =
                    work_cli::identity::CheckoutIdentity::inspect(&f.root.join("task")).unwrap();
                if damage == "marker" {
                    std::fs::write(i.private_git_dir.join("work-lease.json"), "{}").unwrap();
                } else {
                    git(
                        &f.root.join("task"),
                        &["commit", "--allow-empty", "-m", "premature"],
                    );
                }
            }
        });
        assert!(result.is_err());
        let mut s = f.store();
        let ids = s.find_reusable("alice", &f.repo, "task").unwrap();
        assert_eq!(ids.len(), 1);
        assert!(s.acquire_writer(ids[0], Uuid::now_v7()).is_err());
    }
}

#[test]
fn fifo_backlink_is_not_opened_as_blocking_metadata() {
    let f = Fixture::new();
    let op = Uuid::now_v7().to_string();
    assert!(f.start(&op, "task", "topic", &[]).status.success());
    let identity = work_cli::identity::CheckoutIdentity::inspect(&f.root.join("task")).unwrap();
    let backlink = identity.private_git_dir.join("gitdir");
    std::fs::remove_file(&backlink).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &backlink,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_work"))
        .args([
            "start",
            "--operation",
            &op,
            "--repository",
            f.repo.to_str().unwrap(),
            "--root",
            f.root.to_str().unwrap(),
            "--actor",
            "alice",
            "--task",
            "task",
            "--branch",
            "topic",
            "--base",
            "main",
        ])
        .env("WORK_CONFIG", f.temp.path().join("config.toml"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let before = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success(), "FIFO backlink adopted");
            break;
        }
        if before.elapsed() > std::time::Duration::from_secs(4) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("metadata read blocked past deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(f.store().charged(&f.repo, None).unwrap(), 1);
    assert!(f.root.join("task").exists());
}

#[test]
fn blocked_git_on_reserved_retry_is_bounded_and_persistently_held() {
    let f = Fixture::new();
    let operation = Uuid::now_v7();
    let request = Start {
        operation,
        repository: Some(f.repo.clone()),
        root: Some(f.root.clone()),
        actor: Some("alice".into()),
        owner: None,
        task: "task".into(),
        branch: Some("topic".into()),
        base: "main".into(),
        reuse_branch: false,
    };
    std::fs::write(
        f.temp.path().join("request.json"),
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "allocation_worker"])
        .env("WORK_ALLOCATION_BASE", f.temp.path())
        .env("WORK_CONFIG", f.temp.path().join("config.toml"))
        .env("WORK_ALLOCATION_BOUNDARY", "reserved")
        .current_dir(f.temp.path())
        .status()
        .unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(6));
    let config = f.repo.join(".git/config");
    std::fs::rename(&config, config.with_extension("original")).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &config,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    let before = std::time::Instant::now();
    let out = f.start(&operation.to_string(), "task", "topic", &[]);
    assert!(!out.status.success());
    assert!(before.elapsed() < std::time::Duration::from_secs(4));
    assert!(!f.root.join("task").exists());
    let conn = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
    let state: (String, bool) = conn
        .query_row("SELECT state,ready FROM checkouts", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(state, ("held".into(), false));
    assert_eq!(f.store().charged(&f.repo, None).unwrap(), 1);
}

#[test]
fn moved_reuse_branch_boundary_is_persistently_held() {
    let f = Fixture::new();
    git(&f.repo, &["branch", "topic"]);
    let config = Config {
        store_dir: Some(f.temp.path().join("private")),
        trusted_registry: Some(f.temp.path().join("registry")),
        roots: vec![f.root.clone()],
        repositories: vec![f.repo.clone()],
        supervisor: None,
        allocation: Some(work_cli::config::AllocationPolicy {
            repository_limit: 10,
            owner_limit: 10,
            floor_bytes: 0,
            warn_bytes: 0,
            capture_sink: None,
        }),
    };
    let request = Start {
        operation: Uuid::now_v7(),
        repository: Some(f.repo.clone()),
        root: Some(f.root.clone()),
        actor: Some("alice".into()),
        owner: None,
        task: "task".into(),
        branch: Some("topic".into()),
        base: "main".into(),
        reuse_branch: true,
    };
    assert!(start_observed(&config, request, |boundary| {
        if boundary == "reserved" {
            git(&f.repo, &["commit", "--allow-empty", "-m", "advance"]);
            git(&f.repo, &["branch", "-f", "topic", "main"]);
        }
    })
    .is_err());
    assert!(!f.root.join("task").exists());
    let conn = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
    let state: (String, bool) = conn
        .query_row("SELECT state,ready FROM checkouts", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(state, ("held".into(), false));
    assert_eq!(f.store().charged(&f.repo, None).unwrap(), 1);
}

#[test]
fn reservations_are_not_writer_ready() {
    let f = Fixture::new();
    let mut s = f.store();
    let id = s
        .reserve(
            &work_cli::admission::Reservation {
                operation: Uuid::now_v7(),
                repository: f.repo.clone(),
                actor: "a".into(),
                owner: "a".into(),
                task: "t".into(),
            },
            work_cli::admission::Limits {
                repository: 10,
                owner: 10,
                available_bytes: Some(1),
                floor_bytes: 0,
                warn_bytes: 0,
            },
        )
        .unwrap();
    assert!(s.acquire_writer(id, Uuid::now_v7()).is_err());
}
