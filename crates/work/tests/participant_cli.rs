#[path = "support/run_fixture.rs"]
mod support;
use std::{
    io::Write,
    process::{Command, Output, Stdio},
};
use support::*;
use work_cli::run_participants::{ChildRequest, Enrollment, ExpectedHost};
use work_contract::{RunId, RunRef};

fn child(r: &work_cli::run_journal::RootRunRequest) -> ChildRequest {
    ChildRequest {
        checkout: r.identity().checkout.clone(),
        group: r.identity().group.clone(),
        run: RunId::generate(),
        run_ref: RunRef::parse("child").unwrap(),
        parent_run: r.identity().run.clone(),
        parent_run_ref: r.identity().run_ref.clone(),
        execution_chain: r.identity().execution_chain.clone(),
        source: None,
        session: None,
        agent: None,
        actor: None,
        expected_host: Some(ExpectedHost {
            boot: BOOT.into(),
            pid: 42,
            start_ticks: 10,
        }),
    }
}
fn config(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let p = dir.path().join("config.toml");
    std::fs::write(
        &p,
        format!(
            "store_dir={:?}\ntrusted_registry={:?}\nroots=[{:?}]\n",
            dir.path().join("private"),
            dir.path().join(".work-authorities"),
            dir.path().join("root")
        ),
    )
    .unwrap();
    p
}
fn cli(config: &std::path::Path, args: &[&str], input: &[u8]) -> Output {
    let mut p = Command::new(env!("CARGO_BIN_EXE_work"))
        .arg("participant")
        .args(args)
        .env_clear()
        .env("WORK_CONFIG", config)
        .env("WORK_LEASE_ID", "secret-env-only")
        .env("WORK_RUN_ID", "secret-env-only")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // An invalid command may exit before consuming its pipe.
    let _ = p.stdin.take().unwrap().write_all(input);
    p.wait_with_output().unwrap()
}
fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
        panic!(
            "stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}
#[test]
fn binary_register_close_status_are_metadata_only_without_runtime_or_profile() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let c = child(&r);
    let cfg = config(&dir);
    let mut body = serde_json::json!({"root_run":r.identity().run,"child":c});
    let out = cli(&cfg, &["register"], &serde_json::to_vec(&body).unwrap());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(json(&out)["state"], "changed");
    assert_eq!(json(&out)["no_execution_permission"], true);
    let events = store.pending_events(100).unwrap();
    let out = cli(&cfg, &["register"], &serde_json::to_vec(&body).unwrap());
    assert_eq!(json(&out)["state"], "existing");
    assert_eq!(store.pending_events(100).unwrap(), events);
    body["outcome"] = serde_json::json!("completed");
    let out = cli(&cfg, &["close"], &serde_json::to_vec(&body).unwrap());
    assert!(out.status.success());
    assert_eq!(json(&out)["state"], "changed");
    assert!(
        !store
            .run_snapshot(&r.identity().run)
            .unwrap()
            .unwrap()
            .closed
    );
    assert_eq!(store.charged(&dir.path().join("root"), None).unwrap(), 1);
    drop(store);
    let out = cli(&cfg, &["status", &r.identity().run.to_string()], &[]);
    assert!(out.status.success());
    let status = json(&out);
    assert_eq!(status["runtime"], "not_inspected");
    assert_eq!(
        status["record"]["children"][0]["request"],
        serde_json::to_value(c).unwrap()
    );
    assert_eq!(status["record"]["children"][0]["outcome"], "completed");
    assert_eq!(status["lease_charged"], true);
}
#[test]
fn participant_help_and_parse_errors_are_readonly_and_sanitized() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("missing");
    for args in [
        vec!["--help"],
        vec!["register", "--help"],
        vec!["enroll", "--help"],
        vec!["close", "--help"],
        vec!["status", "--help"],
    ] {
        assert!(cli(&cfg, &args, &[]).status.success());
    }
    for args in [
        vec!["--version"],
        vec!["register", "--version"],
        vec!["enroll", "--version"],
        vec!["close", "--version"],
        vec!["status", "--version"],
    ] {
        assert!(cli(&cfg, &args, &[]).status.success(), "{args:?}");
    }
    for args in [
        vec!["secret-argv"],
        vec!["status", "secret-argv"],
        vec!["register", "secret-argv"],
    ] {
        let out = cli(&cfg, &args, &[]);
        assert!(!out.status.success());
        assert!(!String::from_utf8_lossy(&out.stderr).contains("secret-argv"));
        assert!(out.stdout.is_empty());
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
#[test]
fn missing_runtime_enrollment_is_a_durable_irreversible_hold() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let c = child(&r);
    store.register_child(&r, &c).unwrap();
    let cfg = config(&dir);
    let body =
        serde_json::to_vec(&serde_json::json!({"root_run":r.identity().run,"child":c})).unwrap();
    let out = cli(&cfg, &["enroll"], &body);
    assert!(!out.status.success());
    assert_eq!(json(&out)["state"], "held");
    assert_eq!(
        store
            .run_snapshot(&r.identity().run)
            .unwrap()
            .unwrap()
            .children[0]
            .enrollment,
        Enrollment::Unverified
    );
    let events = store.pending_events(100).unwrap();
    let out = cli(&cfg, &["enroll"], &body);
    assert!(!out.status.success());
    assert_eq!(json(&out)["state"], "held");
    assert_eq!(store.pending_events(100).unwrap(), events);
}
#[test]
fn strict_input_and_context_rejections_do_not_change_authority() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let c = child(&r);
    let cfg = config(&dir);
    let body = serde_json::json!({"root_run":r.identity().run,"child":c});
    for case in [
        "unknown",
        "optional_missing",
        "root_missing",
        "wrong_root",
        "wrong_group",
        "wrong_parent",
        "interrupted",
        "malformed",
        "oversize",
        "trailing",
    ] {
        let mut v = body.clone();
        let args = if case == "interrupted" {
            vec!["close"]
        } else {
            vec!["register"]
        };
        match case {
            "unknown" => v["secret-token"] = serde_json::json!("secret-token"),
            "optional_missing" => {
                v["child"].as_object_mut().unwrap().remove("source");
            }
            "root_missing" => {
                v.as_object_mut().unwrap().remove("root_run");
            }
            "wrong_root" => v["root_run"] = serde_json::json!(RunId::generate()),
            "wrong_group" => {
                v["child"]["group"] = serde_json::json!(work_contract::GroupId::generate())
            }
            "wrong_parent" => v["child"]["parent_run"] = serde_json::json!(RunId::generate()),
            "interrupted" => v["outcome"] = serde_json::json!("interrupted"),
            _ => (),
        }
        let bytes = match case {
            "malformed" => b"secret-token{".to_vec(),
            "oversize" => vec![b' '; 4 * 1024 * 1024 + 1],
            "trailing" => {
                let mut b = serde_json::to_vec(&v).unwrap();
                b.extend(b" secret-token");
                b
            }
            _ => serde_json::to_vec(&v).unwrap(),
        };
        let before = store.pending_events(100).unwrap();
        let out = cli(&cfg, &args, &bytes);
        assert!(!out.status.success(), "{case}");
        assert!(out.stdout.is_empty(), "{case}");
        assert!(!String::from_utf8_lossy(&out.stderr).contains("secret-token"));
        assert_eq!(store.pending_events(100).unwrap(), before, "{case}");
    }
    assert!(store
        .run_snapshot(&r.identity().run)
        .unwrap()
        .unwrap()
        .children
        .is_empty());
    drop(store);
    let missing = tempfile::tempdir().unwrap();
    let cfg = config(&missing);
    assert!(
        !cli(&cfg, &["register"], &serde_json::to_vec(&body).unwrap())
            .status
            .success()
    );
    assert!(!missing.path().join("private").exists());
    assert!(!missing.path().join(".work-authorities").exists());
}

#[test]
fn bounded_cursor_accepts_full_unicode_chain_but_rejects_duplicate_fields_before_existing() {
    use work_cli::participant_cli::{command_with_driver, Command};
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let mut c = child(&r);
    let text = "\u{1f980}".repeat(4096);
    c.execution_chain = serde_json::from_value(serde_json::Value::Array(
        (0..32)
            .map(|_| serde_json::json!({"kind":"executor","system":text,"session_ref":text}))
            .collect(),
    ))
    .unwrap();
    let cfg = library_config(&dir);
    let body = bytes(&r, &c);
    assert!(body.len() > 1024 * 1024);
    command_with_driver(&cfg, Command::Register, std::io::Cursor::new(&body), || {
        panic!("registration never inspects")
    })
    .unwrap();
    let events = store.pending_events(100).unwrap();
    let valid = String::from_utf8(body).unwrap();
    for malformed in [
        valid.replacen("\"source\":null", "\"source\":null,\"source\":null", 1),
        valid.replacen(
            "\"root_run\":",
            &format!("\"root_run\":\"{}\",\"root_run\":", r.identity().run),
            1,
        ),
    ] {
        assert!(command_with_driver(
            &cfg,
            Command::Register,
            std::io::Cursor::new(malformed),
            || panic!("bad JSON never inspects")
        )
        .is_err());
    }
    assert_eq!(store.pending_events(100).unwrap(), events);
}

fn files(
    root: &std::path::Path,
) -> std::collections::BTreeMap<std::path::PathBuf, Option<Vec<u8>>> {
    fn visit(
        root: &std::path::Path,
        dir: &std::path::Path,
        out: &mut std::collections::BTreeMap<std::path::PathBuf, Option<Vec<u8>>>,
    ) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.file_name().unwrap().to_string_lossy().ends_with("-shm") {
                continue;
            }
            out.insert(
                p.strip_prefix(root).unwrap().to_path_buf(),
                if p.is_dir() {
                    None
                } else {
                    Some(std::fs::read(&p).unwrap())
                },
            );
            if p.is_dir() {
                visit(root, &p, out);
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    visit(root, root, &mut out);
    out
}
#[test]
fn status_preserves_files_wal_directory_and_events_after_normal_writer_drop() {
    use work_cli::participant_cli::{command_with_driver, Command};
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let c = child(&r);
    store.register_child(&r, &c).unwrap();
    let events = store.pending_events(100).unwrap();
    let cfg = config(&dir);
    drop(store);
    let before = files(dir.path());
    let out = cli(&cfg, &["status", &r.identity().run.to_string()], &[]);
    assert!(out.status.success());
    assert_eq!(files(dir.path()), before);
    command_with_driver(
        &library_config(&dir),
        Command::Status {
            root_run: r.identity().run.clone(),
        },
        std::io::empty(),
        || panic!("status never inspects"),
    )
    .unwrap();
    assert_eq!(files(dir.path()), before);
    let reader = work_cli::store::Store::open_existing_registered_readonly(
        &dir.path().join(".work-authorities"),
        &dir.path().join("private"),
        &[dir.path().join("root")],
    )
    .unwrap();
    assert_eq!(reader.pending_events(100).unwrap(), events);
    drop(reader);
    assert_eq!(files(dir.path()), before);
}
#[test]
fn exact_known_metadata_retries_after_physical_closure_do_not_grant_anything() {
    for declared in [true, false] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let b = binding(&r);
        store.begin_run(&r).unwrap();
        store.record_bound(&r, &b).unwrap();
        store.record_permit_attempt(&r, &b).unwrap();
        let c = child(&r);
        store.register_child(&r, &c).unwrap();
        if declared {
            store
                .record_child_outcome(&r, &c, work_cli::run_participants::ChildOutcome::Completed)
                .unwrap();
        }
        let os = ClosureOs::new(&r, &b);
        os.process_pid(42, 10, &b.identity().cgroup);
        let p = os.tmp.path().join("properties");
        std::fs::write(
            &p,
            std::fs::read_to_string(&p)
                .unwrap()
                .replace("ActiveState=inactive", "ActiveState=active"),
        )
        .unwrap();
        let cg = os
            .tmp
            .path()
            .join("cg")
            .join(b.identity().cgroup.trim_start_matches('/'))
            .join("cgroup.procs");
        std::fs::write(&cg, "42\n").unwrap();
        let proof = store
            .group_snapshot(&r.identity().run)
            .unwrap()
            .certify_child_enrollment(&os.driver, &c.run, Some(&b))
            .unwrap();
        store.record_child_enrollment(&r, &c, &proof).unwrap();
        std::fs::remove_dir_all(os.tmp.path().join("proc/42")).unwrap();
        std::fs::write(&cg, "").unwrap();
        std::fs::write(
            &p,
            std::fs::read_to_string(&p)
                .unwrap()
                .replace("ActiveState=active", "ActiveState=inactive"),
        )
        .unwrap();
        let snapshot = store.group_snapshot(&r.identity().run).unwrap();
        let proof = snapshot.certify_historical_empty(&os.driver).unwrap();
        store.close_supervised_group(&snapshot, &proof).unwrap();
        let cfg = config(&dir);
        let before = store.run_snapshot(&r.identity().run).unwrap();
        let events = store.pending_events(100).unwrap();
        let out = cli(&cfg, &["register"], &bytes(&r, &c));
        assert!(out.status.success());
        assert_eq!(json(&out)["state"], "existing");
        let out = cli(&cfg, &["enroll"], &bytes(&r, &c));
        assert!(out.status.success());
        assert_eq!(json(&out)["state"], "already_recorded");
        let mut v =
            serde_json::json!({"root_run":r.identity().run,"child":c,"outcome":"completed"});
        let out = cli(&cfg, &["close"], &serde_json::to_vec(&v).unwrap());
        if declared {
            assert_eq!(json(&out)["state"], "existing");
        } else {
            assert!(!out.status.success());
            assert_eq!(
                before.as_ref().unwrap().children[0].outcome,
                Some(work_cli::run_participants::ChildOutcome::Interrupted)
            );
        }
        for outcome in ["interrupted", "failed", "cancelled"] {
            v["outcome"] = serde_json::json!(outcome);
            assert!(!cli(&cfg, &["close"], &serde_json::to_vec(&v).unwrap())
                .status
                .success());
        }
        let mut new = child(&r);
        new.run_ref = RunRef::parse("new-child").unwrap();
        assert!(!cli(&cfg, &["register"], &bytes(&r, &new)).status.success());
        assert_eq!(store.run_snapshot(&r.identity().run).unwrap(), before);
        assert_eq!(store.pending_events(100).unwrap(), events);
        assert_eq!(store.charged(&dir.path().join("root"), None).unwrap(), 1);
    }
}
#[test]
fn adopted_roots_and_env_only_ids_never_resolve_to_supervised_children() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let c = child(&r);
    let adopted = work_cli::adopted::AdoptedRequest {
        operation: uuid::Uuid::now_v7(),
        identity: r.identity().clone(),
        source: work_cli::participants::Ref::new("sdk".into()).unwrap(),
        session: work_cli::participants::Ref::new("session".into()).unwrap(),
        agent: None,
    };
    store.begin_adopted(&adopted).unwrap();
    let cfg = config(&dir);
    let events = store.pending_events(100).unwrap();
    for command in ["register", "enroll", "close"] {
        let mut v = serde_json::json!({"root_run":r.identity().run,"child":c});
        if command == "close" {
            v["outcome"] = serde_json::json!("completed");
        }
        assert!(!cli(&cfg, &[command], &serde_json::to_vec(&v).unwrap())
            .status
            .success());
        v.as_object_mut().unwrap().remove("root_run");
        assert!(!cli(&cfg, &[command], &serde_json::to_vec(&v).unwrap())
            .status
            .success());
    }
    assert_eq!(store.pending_events(100).unwrap(), events);
}

fn library_config(dir: &tempfile::TempDir) -> work_cli::config::Config {
    work_cli::config::Config {
        store_dir: Some(dir.path().join("private")),
        trusted_registry: Some(dir.path().join(".work-authorities")),
        roots: vec![dir.path().join("root")],
        ..Default::default()
    }
}
fn bytes(r: &work_cli::run_journal::RootRunRequest, c: &ChildRequest) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"root_run":r.identity().run,"child":c})).unwrap()
}
#[test]
fn library_pending_enrollment_uses_actual_registrar_not_original_binding_and_preserves_outcomes() {
    use work_cli::{
        participant_cli::{command_with_driver, Command},
        run_journal::RootOutcome,
        run_participants::ChildOutcome,
    };
    for outcome in [
        ChildOutcome::Completed,
        ChildOutcome::Failed,
        ChildOutcome::Cancelled,
    ] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let b = binding(&r);
        store.begin_run(&r).unwrap();
        store.record_bound(&r, &b).unwrap();
        store.record_permit_attempt(&r, &b).unwrap();
        let parent = child(&r);
        store.register_child(&r, &parent).unwrap();
        store
            .record_child_outcome(&r, &parent, ChildOutcome::Completed)
            .unwrap();
        let mut c = child(&r);
        c.run_ref = RunRef::parse("nested-child").unwrap();
        c.parent_run = parent.run.clone();
        c.parent_run_ref = parent.run_ref.clone();
        store.register_child(&r, &c).unwrap();
        store.record_child_outcome(&r, &c, outcome).unwrap();
        store
            .record_root_outcome(&r, RootOutcome::Completed)
            .unwrap();
        store.record_recovery_hold(&r).unwrap();
        let os = ClosureOs::new(&r, &b);
        let cg = &b.identity().cgroup;
        let properties = os.tmp.path().join("properties");
        std::fs::write(
            &properties,
            std::fs::read_to_string(&properties)
                .unwrap()
                .replace("ActiveState=inactive", "ActiveState=active"),
        )
        .unwrap();
        os.process_pid(42, 10, cg);
        os.process_pid(std::process::id(), 77, cg);
        let cgpath = os.tmp.path().join("cg").join(cg.trim_start_matches('/'));
        std::fs::write(
            cgpath.join("cgroup.procs"),
            format!("42\n{}\n", std::process::id()),
        )
        .unwrap();
        let before = store.run_snapshot(&r.identity().run).unwrap().unwrap();
        let report = command_with_driver(
            &library_config(&dir),
            Command::Enroll,
            std::io::Cursor::new(bytes(&r, &c)),
            || Some(os.driver),
        )
        .unwrap();
        let report = serde_json::to_value(report).unwrap();
        assert_eq!(report["state"], "changed");
        assert_eq!(report["fresh_runtime_claim"], false);
        let after = store.run_snapshot(&r.identity().run).unwrap().unwrap();
        assert_eq!(after.children[1].enrollment, Enrollment::Contained);
        assert_eq!(after.children[1].outcome, Some(outcome));
        assert_eq!(after.children[0], before.children[0]);
        assert_eq!(after.outcome, before.outcome);
        assert_eq!(after.recovery_hold, before.recovery_hold);
        assert!(!after.closed);
        let events = store.pending_events(100).unwrap();
        let report = command_with_driver(
            &library_config(&dir),
            Command::Enroll,
            std::io::Cursor::new(bytes(&r, &c)),
            || panic!("history never constructs a driver"),
        )
        .unwrap();
        let report = serde_json::to_value(report).unwrap();
        assert_eq!(report["state"], "already_recorded");
        assert_eq!(report["reason"], "historical_enrollment_only");
        assert_eq!(report["fresh_runtime_claim"], false);
        assert_eq!(store.pending_events(100).unwrap(), events);
    }
}
#[test]
fn successful_inspection_with_concurrent_snapshot_change_keeps_pending_without_false_receipt() {
    use work_cli::{
        participant_cli::{command_with_driver, Command},
        scope_driver::{Driver, LibraryIo, Limits, RuntimeContext},
    };
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let c = child(&r);
    store.register_child(&r, &c).unwrap();
    let os = ClosureOs::new(&r, &b);
    let cg = &b.identity().cgroup;
    os.process_pid(42, 10, cg);
    os.process_pid(std::process::id(), 77, cg);
    let p = os.tmp.path().join("properties");
    std::fs::write(
        &p,
        std::fs::read_to_string(&p)
            .unwrap()
            .replace("ActiveState=inactive", "ActiveState=active"),
    )
    .unwrap();
    std::fs::write(
        os.tmp
            .path()
            .join("cg")
            .join(cg.trim_start_matches('/'))
            .join("cgroup.procs"),
        format!("42\n{}\n", std::process::id()),
    )
    .unwrap();
    let concurrent = std::cell::RefCell::new(reopen(&dir).unwrap());
    let root = r.clone();
    let driver = Driver::with_io(
        RuntimeContext::new(
            os.tmp.path().join("runtime"),
            format!("unix:path={}/runtime/bus", os.tmp.path().display()),
        )
        .unwrap(),
        LibraryIo {
            systemctl: os.tmp.path().join("manager"),
            proc_root: os.tmp.path().join("proc"),
            cgroup_root: os.tmp.path().join("cg"),
            between_censuses: Some(Box::new(move || {
                concurrent.borrow_mut().record_recovery_hold(&root).unwrap();
            })),
        },
        Limits::default(),
    )
    .unwrap();
    let report = command_with_driver(
        &library_config(&dir),
        Command::Enroll,
        std::io::Cursor::new(bytes(&r, &c)),
        || Some(driver),
    )
    .unwrap();
    let report = serde_json::to_value(report).unwrap();
    assert_eq!(report["state"], "held");
    assert_eq!(report["reason"], "snapshot_changed_retry_explicitly");
    let after = store.run_snapshot(&r.identity().run).unwrap().unwrap();
    assert!(after.recovery_hold);
    assert_eq!(after.children[0].enrollment, Enrollment::Pending);
    assert!(after.children[0].host.is_none());
}

#[test]
fn fake_host_and_registrar_failures_leave_durable_child_barriers() {
    use work_cli::participant_cli::{command_with_driver, Command};
    for case in [
        "missing_host",
        "reused_host",
        "wrong_boot",
        "outside_host",
        "missing_registrar",
        "outside_registrar",
    ] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let b = binding(&r);
        store.begin_run(&r).unwrap();
        store.record_bound(&r, &b).unwrap();
        store.record_permit_attempt(&r, &b).unwrap();
        let mut c = child(&r);
        if case == "wrong_boot" {
            c.expected_host.as_mut().unwrap().boot = "650e8400-e29b-41d4-a716-446655440000".into();
        }
        store.register_child(&r, &c).unwrap();
        let os = ClosureOs::new(&r, &b);
        let cg = &b.identity().cgroup;
        let properties = os.tmp.path().join("properties");
        std::fs::write(
            &properties,
            std::fs::read_to_string(&properties)
                .unwrap()
                .replace("ActiveState=inactive", "ActiveState=active"),
        )
        .unwrap();
        if case != "missing_host" {
            os.process_pid(
                42,
                if case == "reused_host" { 11 } else { 10 },
                if case == "outside_host" {
                    "/outside"
                } else {
                    cg
                },
            );
        }
        if case != "missing_registrar" {
            os.process_pid(
                std::process::id(),
                77,
                if case == "outside_registrar" {
                    "/outside"
                } else {
                    cg
                },
            );
        }
        std::fs::write(
            os.tmp
                .path()
                .join("cg")
                .join(cg.trim_start_matches('/'))
                .join("cgroup.procs"),
            format!("42\n{}\n", std::process::id()),
        )
        .unwrap();
        let report = command_with_driver(
            &library_config(&dir),
            Command::Enroll,
            std::io::Cursor::new(bytes(&r, &c)),
            || Some(os.driver),
        )
        .unwrap();
        assert!(report.is_held(), "{case}");
        let after = store.run_snapshot(&r.identity().run).unwrap().unwrap();
        assert_eq!(
            after.children[0].enrollment,
            Enrollment::Unverified,
            "{case}"
        );
        assert!(after.children[0].host.is_none());
        assert_eq!(store.charged(&dir.path().join("root"), None).unwrap(), 1);
        let events = store.pending_events(100).unwrap();
        assert!(command_with_driver(
            &library_config(&dir),
            Command::Enroll,
            std::io::Cursor::new(bytes(&r, &c)),
            || panic!("unverified cannot upgrade")
        )
        .unwrap()
        .is_held());
        assert_eq!(store.pending_events(100).unwrap(), events);
    }
}
#[test]
fn registration_and_logical_close_never_construct_driver_even_with_capture_sink() {
    use work_cli::participant_cli::{command_with_driver, Command};
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let b = binding(&r);
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let mut c = child(&r);
    c.expected_host = None;
    let mut cfg = library_config(&dir);
    cfg.allocation = Some(work_cli::config::AllocationPolicy {
        repository_limit: 10,
        owner_limit: 10,
        floor_bytes: 0,
        warn_bytes: 0,
        capture_sink: Some("unsupported".into()),
    });
    let report = command_with_driver(
        &cfg,
        Command::Register,
        std::io::Cursor::new(bytes(&r, &c)),
        || panic!("metadata must not inspect"),
    )
    .unwrap();
    assert!(!report.is_held());
    let mut v = serde_json::json!({"root_run":r.identity().run,"child":c,"outcome":"cancelled"});
    command_with_driver(
        &cfg,
        Command::Close,
        std::io::Cursor::new(serde_json::to_vec(&v).unwrap()),
        || panic!("close must not inspect"),
    )
    .unwrap();
    v["outcome"] = serde_json::json!("interrupted");
    assert!(command_with_driver(
        &cfg,
        Command::Close,
        std::io::Cursor::new(serde_json::to_vec(&v).unwrap()),
        || panic!("never inspect")
    )
    .is_err());
    assert!(command_with_driver(
        &cfg,
        Command::Enroll,
        std::io::Cursor::new(bytes(&r, &c)),
        || panic!("unverified stays held")
    )
    .unwrap()
    .is_held());
    assert_eq!(store.charged(&dir.path().join("root"), None).unwrap(), 1);
}
