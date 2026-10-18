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
fn reboot_reconciles_durable_evidence_but_marker_tampering_holds() {
    for damage in [
        "reboot",
        "malformed",
        "copied",
        "inode",
        "missing",
        "bad-record",
        "wrong-id",
        "missing-record",
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
            "bad-record" | "missing-record" => {}
            "wrong-id" => record["checkout"] = Uuid::now_v7().to_string().into(),
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
        "DROP TABLE allocations; ALTER TABLE checkouts DROP COLUMN ready; PRAGMA user_version=1;",
    )
    .unwrap();
    drop(conn);
    let mut s = f.store();
    assert_eq!(s.charged(&f.repo, None).unwrap(), 1);
    assert!(s.acquire_writer(id, Uuid::now_v7()).is_err());
}
#[test]
fn readiness_rechecks_marker_after_external_side_effects() {
    let f = Fixture::new();
    let config = Config {
        store_dir: Some(f.temp.path().join("private")),
        trusted_registry: Some(f.temp.path().join("registry")),
        roots: vec![f.root.clone()],
        repositories: vec![f.repo.clone()],
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
            let i = work_cli::identity::CheckoutIdentity::inspect(&f.root.join("task")).unwrap();
            std::fs::write(i.private_git_dir.join("work-lease.json"), "{}").unwrap();
        }
    });
    assert!(result.is_err());
    let mut s = f.store();
    let ids = s.find_reusable("alice", &f.repo, "task").unwrap();
    assert_eq!(ids.len(), 1);
    assert!(s.acquire_writer(ids[0], Uuid::now_v7()).is_err());
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
