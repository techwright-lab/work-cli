#[path = "support/run_fixture.rs"]
mod run_fixture;
mod support;
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
use support::Fixture;
use uuid::Uuid;
use work_cli::{
    capture_journal::CaptureSpec,
    capture_preparation::{self, PreparationResult},
    config::Config,
    run_journal::RootRunRequest,
};
const CAPTURE: &str = "550e8400-e29b-41d4-a716-446655440001";

#[test]
fn off_marker_refuses_before_preparation_artifacts() {
    let mut h = Harness::new();
    let mut value = serde_json::to_value(&h.root).unwrap();
    value["input"]["attribution"] = "off".into();
    let off: RootRunRequest = serde_json::from_value(value).unwrap();
    let untouched = h.f.temp.path().join("must-not-create-authority");
    h.cfg.store_dir = Some(untouched.clone());
    h.cfg.trusted_registry = Some(h.f.temp.path().join("must-not-create-registry"));
    let mut calls = 0;
    assert!(
        capture_preparation::prepare_observed(&h.cfg, &off, &h.spec, |_, _| calls += 1).is_err()
    );
    assert_eq!(calls, 0);
    assert!(
        !untouched.exists(),
        "Off must refuse before opening/creating authority artifacts"
    );
    assert!(!h.cfg.trusted_registry.as_ref().unwrap().exists());
    assert!(!h.f.temp.path().join("calls").exists());
}

struct Harness {
    f: Fixture,
    cfg: Config,
    root: RootRunRequest,
    spec: CaptureSpec,
    context: PathBuf,
}
fn file(path: &std::path::Path, bytes: impl AsRef<[u8]>, mode: u32) {
    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
impl Harness {
    fn new() -> Self {
        let f = Fixture::new();
        let registry = f.temp.path().join("actors.json");
        let state = f.temp.path().join("capture-state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let registry_bytes =
            br#"{"ingest":{"key_env":"RECEIVER_TOKEN","url":"https://receiver.invalid"}}"#;
        file(&registry, registry_bytes, 0o600);
        let executable = f.temp.path().join("producer");
        let mut text = fs::read_to_string(f.temp.path().join("config.toml"))
            .unwrap()
            .replace("[allocation]", "[allocation]\ncapture_sink='devdiary'");
        text += &format!("\n[capture]\nexecutable={executable:?}\nregistry={registry:?}\nstate_dir={state:?}\ntimeout_ms=1000\nresponse_cap=65536\nregistry_sha256='{:x}'\nendpoint_identity='label:not-url'\nreceiver_credential_names=['RECEIVER_TOKEN']\n[capture.actor_refs]\nalice='actor:alice'\n[supervisor]\nruntime_directory='/private/runtime'\nbus_address='unix:path=/private/runtime/bus'\nruntime_max_seconds=60\npreexec_ms=100\nclosure_grace_ms=100\ncancel_grace_ms=100\n[supervisor.actors.alice]\nauthor_name='Alice'\nauthor_email='alice@example.invalid'\ncommitter_name='Alice'\ncommitter_email='alice@example.invalid'\n", Sha256::digest(registry_bytes));
        fs::write(f.temp.path().join("config.toml"), &text).unwrap();
        let cfg = Config::from_text(&text).unwrap();
        let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
        assert!(out.status.success(), "{:?}", out);
        let a: work_cli::allocate::Allocation = serde_json::from_slice(&out.stdout).unwrap();
        let mut value = serde_json::to_value(run_fixture::request(a.checkout)).unwrap();
        value["identity"]["actor"] = "alice".into();
        value["input"]["boot"] = a.identity.as_ref().unwrap().boot_id.clone().into();
        let root: RootRunRequest = serde_json::from_value(value).unwrap();
        let spec = cfg
            .capture_spec(&root, &a, Uuid::now_v7(), vec!["task".into()], None)
            .unwrap();
        let context = state.join(format!("{CAPTURE}.context.json"));
        let d = spec.begin_request();
        let ctx = serde_json::json!({"schema_version":"1.0","actor":{"ref":d.actor_ref,"kind":"agent","display_name":"Alice","humanized_name":"Alice"},"principal":{"ref":"principal:operator"},"run":{"ref":d.run_ref,"parent_ref":d.parent_run_ref,"task_ref":"task"},"started_at":"2026-10-18T10:00:00Z","execution_chain":d.execution_chain,"command":{"classification":"unknown","argument_count":0},"working_directory":d.cwd});
        file(&context, serde_json::to_vec(&ctx).unwrap(), 0o400);
        let g = spec.expected_git();
        let response = serde_json::json!({"capture_id":CAPTURE,"state":"open","actor_ref":d.actor_ref,"run_ref":d.run_ref,"environment":{"AGENT_ATTRIBUTION_CONTEXT":context,"DEVDIARY_ATTRIBUTION_CONTEXT":context,"DEVDIARY_CAPTURE_ID":CAPTURE,"GIT_AUTHOR_NAME":g.author_name,"GIT_AUTHOR_EMAIL":g.author_email,"GIT_COMMITTER_NAME":g.committer_name,"GIT_COMMITTER_EMAIL":g.committer_email}});
        file(
            &f.temp.path().join("response"),
            serde_json::to_vec(&response).unwrap(),
            0o600,
        );
        file(&executable,format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}/argv'\n/usr/bin/cat > '{}/input'\nprintf called >> '{}/calls'\n/usr/bin/cat '{}/response'\n",f.temp.path().display(),f.temp.path().display(),f.temp.path().display(),f.temp.path().display()),0o700);
        Self {
            f,
            cfg,
            root,
            spec,
            context,
        }
    }
    fn reseal(&mut self) {
        let a: work_cli::allocate::Allocation = serde_json::from_str(
            &self
                .sql()
                .query_row("SELECT record FROM allocations", [], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap(),
        )
        .unwrap();
        self.spec = self
            .cfg
            .capture_spec(
                &self.root,
                &a,
                self.spec.operation(),
                vec!["task".into()],
                None,
            )
            .unwrap();
    }
    fn registry(&mut self, bytes: &[u8]) {
        let path = self.cfg.capture.as_ref().unwrap().registry.clone();
        file(&path, bytes, 0o600);
        self.cfg.capture.as_mut().unwrap().registry_sha256 = format!("{:x}", Sha256::digest(bytes));
        self.reseal();
    }
    fn sql(&self) -> rusqlite::Connection {
        let conn =
            rusqlite::Connection::open(self.f.temp.path().join("private/store.sqlite")).unwrap();
        // Match the native Store's close policy. A test-only last close must not
        // remove bookkeeping required by the production no-create preflight.
        conn.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            true,
        )
        .unwrap();
        conn
    }
    fn held(&self) {
        let db = self.sql();
        assert_eq!(
            db.query_row("SELECT state,ready FROM checkouts", [], |r| Ok((
                r.get::<_, String>(0)?,
                r.get::<_, bool>(1)?
            )))
            .unwrap(),
            ("active".into(), false)
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        let r = self
            .f
            .store()
            .run_snapshot(&self.root.identity().run)
            .unwrap()
            .unwrap();
        assert!(r.recovery_hold);
        assert!(r.outcome.is_none());
        assert!(r.binding.is_none());
        assert_eq!(self.f.store().charged(&self.f.repo, None).unwrap(), 1);
        assert_eq!(
            db.query_row("SELECT checkout,group_id FROM writers", [], |row| Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?
            )))
            .unwrap(),
            (
                self.root.identity().checkout.to_string(),
                self.root.identity().group.to_string()
            )
        );
        assert!(self.spec.begin_request().cwd.join(".git").is_file());
    }
}
#[test]
fn qualified_fake_begin_prepares_both_authorities_and_returns_only_ephemeral_metadata() {
    let h = Harness::new();
    let (store, result) =
        capture_preparation::prepare(&h.cfg, &h.root, &h.spec).expect("qualified begin");
    let PreparationResult::Live(live) = result else {
        panic!("new capture must be live")
    };
    assert_eq!(live.environment().context_path(), h.context);
    assert_eq!(live.receiver_removal_names(), ["RECEIVER_TOKEN"]);
    let snapshot = store
        .capture_snapshot(&h.root.identity().run)
        .unwrap()
        .unwrap();
    assert!(snapshot.prepared.unwrap().live_preparation);
    let db = h.sql();
    assert!(db
        .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
        .unwrap());
    assert_eq!(
        db.query_row(
            "SELECT json_extract(record,'$.stage') FROM allocations",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "ready"
    );
    assert_eq!(
        fs::read_to_string(h.f.temp.path().join("argv")).unwrap(),
        format!(
            "--config\n{}\ncapture\nbegin\n--state-dir\n{}\n--json\n",
            h.cfg.capture.as_ref().unwrap().registry.display(),
            h.cfg.capture.as_ref().unwrap().state_dir.display()
        )
    );
    assert_eq!(
        fs::read(h.f.temp.path().join("input")).unwrap(),
        h.spec.begin_request().encode().unwrap()
    );
}
#[test]
fn unsafe_registry_and_credential_metadata_refuse_before_receiver_with_exact_hold() {
    let mut accepted = Vec::new();
    for case in [
        "pin",
        "missing",
        "fifo",
        "symlink",
        "ancestor",
        "hardlink",
        "oversize",
        "mode",
        "unreadable",
        "directory",
        "duplicate",
        "ingest_array",
        "key_type",
        "key_grammar",
        "reserved",
        "coverage",
        "key_missing",
        "key_fifo",
        "key_link",
        "key_mode",
        "state_mode",
        "state_link",
    ] {
        let mut h = Harness::new();
        let registry = h.cfg.capture.as_ref().unwrap().registry.clone();
        match case {
            "pin" => file(&registry, b"{}", 0o600),
            "missing" => fs::remove_file(&registry).unwrap(),
            "fifo" => {
                fs::remove_file(&registry).unwrap();
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &registry,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                    0,
                )
                .unwrap();
            }
            "symlink" => {
                fs::rename(&registry, h.f.temp.path().join("real")).unwrap();
                std::os::unix::fs::symlink(h.f.temp.path().join("real"), &registry).unwrap();
            }
            "ancestor" => {
                let dir = h.f.temp.path().join("actual");
                fs::create_dir(&dir).unwrap();
                fs::rename(&registry, dir.join("actors")).unwrap();
                std::os::unix::fs::symlink(&dir, h.f.temp.path().join("alias")).unwrap();
                h.cfg.capture.as_mut().unwrap().registry = h.f.temp.path().join("alias/actors");
                h.reseal();
            }
            "hardlink" => fs::hard_link(&registry, h.f.temp.path().join("second")).unwrap(),
            "oversize" => h.registry(&vec![b' '; 1048577]),
            "mode" => fs::set_permissions(&registry, fs::Permissions::from_mode(0o644)).unwrap(),
            "unreadable" => {
                fs::set_permissions(&registry, fs::Permissions::from_mode(0o0)).unwrap()
            }
            "directory" => {
                fs::remove_file(&registry).unwrap();
                fs::create_dir(&registry).unwrap();
            }
            "duplicate" => {
                h.registry(br#"{"ingest":{"key_env":"RECEIVER_TOKEN","key_env":"OTHER"}}"#)
            }
            "ingest_array" => h.registry(br#"{"ingest":["RECEIVER_TOKEN"]}"#),
            "key_type" => h.registry(br#"{"ingest":{"key_env":null}}"#),
            "key_grammar" => h.registry(br#"{"ingest":{"key_env":"bad-name"}}"#),
            "reserved" => h.registry(br#"{"ingest":{"key_env":"GIT_AUTHOR_NAME"}}"#),
            "coverage" => h.registry(br#"{"ingest":{"key_env":"OTHER_TOKEN"}}"#),
            "state_mode" => fs::set_permissions(
                &h.cfg.capture.as_ref().unwrap().state_dir,
                fs::Permissions::from_mode(0o755),
            )
            .unwrap(),
            "state_link" => {
                let state = h.cfg.capture.as_ref().unwrap().state_dir.clone();
                let real = h.f.temp.path().join("real-state");
                fs::rename(&state, &real).unwrap();
                std::os::unix::fs::symlink(real, state).unwrap();
            }
            _ => {
                let key = h.f.temp.path().join("key");
                if case != "key_missing" {
                    file(&key, b"KEY_SENTINEL_NEVER_READ", 0o600);
                }
                match case {
                    "key_fifo" => {
                        fs::remove_file(&key).unwrap();
                        rustix::fs::mknodat(
                            rustix::fs::CWD,
                            &key,
                            rustix::fs::FileType::Fifo,
                            rustix::fs::Mode::RUSR,
                            0,
                        )
                        .unwrap();
                    }
                    "key_link" => fs::hard_link(&key, h.f.temp.path().join("key2")).unwrap(),
                    "key_mode" => {
                        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap()
                    }
                    _ => (),
                };
                h.cfg.capture.as_mut().unwrap().key_file = Some(key);
                h.reseal();
            }
        }
        let start = std::time::Instant::now();
        let result = capture_preparation::prepare(&h.cfg, &h.root, &h.spec);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3),
            "unbounded {case}"
        );
        if result.is_ok() {
            accepted.push(case);
            continue;
        }
        h.held();
        assert!(
            !h.f.temp.path().join("calls").exists(),
            "spawned for {case}"
        );
    }
    assert!(
        accepted.is_empty(),
        "unsafe metadata accepted: {accepted:?}"
    );
}
#[test]
fn registry_changed_during_begin_cannot_commit_prepared() {
    let h = Harness::new();
    let exe = &h.cfg.capture.as_ref().unwrap().executable;
    let script = fs::read_to_string(exe).unwrap();
    file(
        exe,
        format!(
            "{script}\nprintf ' ' >> '{}'\n",
            h.cfg.capture.as_ref().unwrap().registry.display()
        ),
        0o700,
    );
    assert!(
        capture_preparation::prepare(&h.cfg, &h.root, &h.spec).is_err(),
        "changed registry accepted"
    );
    h.held();
}
#[test]
fn key_file_mode_derives_actual_receiver_name_without_reading_secret() {
    let mut h = Harness::new();
    let key = h.f.temp.path().join("key");
    file(&key, b"SECRET_NOT_METADATA", 0o400);
    h.cfg.capture.as_mut().unwrap().key_file = Some(key.clone());
    h.cfg
        .capture
        .as_mut()
        .unwrap()
        .receiver_credential_names
        .clear();
    h.reseal();
    let before = fs::metadata(&key).unwrap();
    let (store, result) = capture_preparation::prepare(&h.cfg, &h.root, &h.spec).unwrap();
    let PreparationResult::Live(live) = result else {
        panic!("live")
    };
    assert_eq!(live.receiver_removal_names(), ["RECEIVER_TOKEN"]);
    use std::os::unix::fs::MetadataExt;
    let after = fs::metadata(&key).unwrap();
    assert_eq!(
        (before.atime(), before.atime_nsec()),
        (after.atime(), after.atime_nsec())
    );
    assert!(!format!("{live:?}").contains("SECRET"));
    assert!(!serde_json::to_string(
        &store
            .capture_snapshot(&h.root.identity().run)
            .unwrap()
            .unwrap()
    )
    .unwrap()
    .contains("SECRET_NOT_METADATA"));
}
#[test]
fn exact_existing_receipt_has_no_io_refresh_callback_or_new_live_result() {
    for initially_failed in [false, true] {
        let mut h = Harness::new();
        if initially_failed {
            fs::remove_file(&h.context).unwrap();
        }
        let first = capture_preparation::prepare(&h.cfg, &h.root, &h.spec);
        assert_eq!(first.is_err(), initially_failed);
        drop(first);
        let events = h.f.store().pending_events(100).unwrap();
        let before: bool = h
            .sql()
            .query_row("SELECT ready FROM checkouts", [], |r| r.get(0))
            .unwrap();
        fs::remove_file(h.f.temp.path().join("producer")).unwrap();
        fs::remove_file(&h.cfg.capture.as_ref().unwrap().registry).unwrap();
        fs::remove_dir_all(&h.cfg.capture.as_ref().unwrap().state_dir).unwrap();
        h.cfg.capture = None;
        h.cfg.supervisor = None;
        h.cfg.allocation.as_mut().unwrap().capture_sink = None;
        let (store, result) =
            capture_preparation::prepare_observed(&h.cfg, &h.root, &h.spec, |_, _| {
                panic!("existing performed external work")
            })
            .unwrap();
        assert!(matches!(result, PreparationResult::Existing(_)));
        assert_eq!(store.pending_events(100).unwrap(), events);
        assert_eq!(
            before,
            h.sql()
                .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
                .unwrap()
        );
        assert_eq!(
            fs::read_to_string(h.f.temp.path().join("calls")).unwrap(),
            "called"
        );
    }
}
#[test]
fn receiver_failures_retain_exact_intent_writer_charge_without_outcome_or_retry_launch() {
    for case in [
        "absent",
        "nonzero",
        "malformed",
        "oversize",
        "hang",
        "actor",
        "run",
        "profile",
        "locator",
    ] {
        let h = Harness::new();
        let exe = &h.cfg.capture.as_ref().unwrap().executable;
        match case {
            "absent" => fs::remove_file(exe).unwrap(),
            "nonzero" => file(
                exe,
                b"#!/bin/sh\necho PRIVATE_STDERR_SECRET >&2\nexit 2\n",
                0o700,
            ),
            "malformed" => file(
                &h.f.temp.path().join("response"),
                b"PRIVATE_RESPONSE_SECRET",
                0o600,
            ),
            "oversize" => file(&h.f.temp.path().join("response"), vec![b'x'; 65537], 0o600),
            "hang" => file(exe, b"#!/bin/sh\nexec /usr/bin/sleep 5\n", 0o700),
            _ => {
                let path = h.f.temp.path().join("response");
                let mut v: serde_json::Value =
                    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                match case {
                    "actor" => v["actor_ref"] = "substitute".into(),
                    "run" => v["run_ref"] = "substitute".into(),
                    "profile" => v["environment"]["GIT_AUTHOR_NAME"] = "substitute".into(),
                    _ => {
                        let wrong = h.f.temp.path().join("other.context.json");
                        v["environment"]["AGENT_ATTRIBUTION_CONTEXT"] =
                            wrong.to_string_lossy().as_ref().into();
                        v["environment"]["DEVDIARY_ATTRIBUTION_CONTEXT"] =
                            wrong.to_string_lossy().as_ref().into();
                    }
                }
                file(&path, serde_json::to_vec(&v).unwrap(), 0o600);
            }
        }
        let start = std::time::Instant::now();
        let error = capture_preparation::prepare(&h.cfg, &h.root, &h.spec)
            .err()
            .expect(case);
        assert!(start.elapsed() < std::time::Duration::from_secs(3));
        assert!(!error.to_string().contains("PRIVATE"));
        h.held();
        let calls = fs::read(h.f.temp.path().join("calls")).unwrap_or_default();
        assert!(matches!(
            capture_preparation::prepare(&h.cfg, &h.root, &h.spec)
                .unwrap()
                .1,
            PreparationResult::Existing(_)
        ));
        assert_eq!(
            fs::read(h.f.temp.path().join("calls")).unwrap_or_default(),
            calls
        );
    }
}
#[test]
fn live_context_revalidation_detects_actual_replacement_content_links_and_directory_changes() {
    for case in ["content", "replacement", "hardlink", "directory"] {
        let h = Harness::new();
        let (_, result) = capture_preparation::prepare(&h.cfg, &h.root, &h.spec).unwrap();
        let PreparationResult::Live(live) = result else {
            panic!("live")
        };
        assert!(live.revalidate_context().is_ok());
        match case {
            "content" => file(&h.context, b"{}", 0o400),
            "replacement" => {
                let bytes = fs::read(&h.context).unwrap();
                fs::remove_file(&h.context).unwrap();
                file(&h.context, bytes, 0o400);
            }
            "hardlink" => fs::hard_link(&h.context, h.f.temp.path().join("ctx2")).unwrap(),
            _ => {
                let state = h.cfg.capture.as_ref().unwrap().state_dir.clone();
                fs::rename(&state, h.f.temp.path().join("previous-state")).unwrap();
                fs::create_dir(&state).unwrap();
                fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
                file(&h.context, b"{}", 0o400);
            }
        }
        assert!(live.revalidate_context().is_err(), "{case}");
    }
}
#[test]
fn actual_receiver_delay_does_not_block_independent_checkout_allocation_or_sql_writer() {
    let h = Harness::new();
    let exe = &h.cfg.capture.as_ref().unwrap().executable;
    let script = fs::read_to_string(exe).unwrap();
    let entered = h.f.temp.path().join("entered");
    let release = h.f.temp.path().join("release");
    file(
        exe,
        script.replace(
            "/usr/bin/cat >",
            &format!(
                "touch '{}'\nwhile [ ! -f '{}' ]; do /usr/bin/sleep 0.01; done\n/usr/bin/cat >",
                entered.display(),
                release.display()
            ),
        ),
        0o700,
    );
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| capture_preparation::prepare(&h.cfg, &h.root, &h.spec));
        let start = std::time::Instant::now();
        while !entered.exists() && start.elapsed() < std::time::Duration::from_secs(2) {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(entered.exists(), "receiver never entered");
        let db = h.sql();
        db.busy_timeout(std::time::Duration::ZERO).unwrap();
        db.execute_batch("BEGIN IMMEDIATE; ROLLBACK")
            .expect("capture holds SQL writer lock");
        let other = h.f.start(
            &Uuid::now_v7().to_string(),
            "independent-task",
            "independent-branch",
            &[],
        );
        assert!(
            other.status.success(),
            "capture holds allocator flock: {other:?}"
        );
        file(&release, b"release", 0o600);
        assert!(worker.join().unwrap().is_ok());
    });
}
#[test]
fn non_sql_latency_at_every_artifact_boundary_does_not_poison_sql_budget() {
    let h = Harness::new();
    let mut seen = Vec::new();
    let (store, _) =
        capture_preparation::prepare_observed(&h.cfg, &h.root, &h.spec, |at, store| {
            seen.push(at);
            std::thread::sleep(std::time::Duration::from_millis(650));
            let db = h.sql();
            db.busy_timeout(std::time::Duration::ZERO).unwrap();
            db.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
            // Nested bounded SQL would inherit an outer 500ms deadline if any were armed.
            assert!(!store.pending_events(100).unwrap().is_empty());
        })
        .unwrap();
    assert_eq!(
        seen,
        vec![
            capture_preparation::Boundary::RegistryRead,
            capture_preparation::Boundary::Receiver,
            capture_preparation::Boundary::RegistryRecheck,
            capture_preparation::Boundary::ContextRead,
            capture_preparation::Boundary::BeforeCommit
        ]
    );
    assert!(store
        .capture_snapshot(&h.root.identity().run)
        .unwrap()
        .unwrap()
        .prepared
        .is_some());
}
#[test]
fn selected_key_env_defaults_and_explicit_union_preserve_unrelated_names() {
    for key_file in [false, true] {
        let mut h = Harness::new();
        h.registry(br#"{"ingest":{"url":"https://receiver.invalid"}}"#);
        h.cfg.capture.as_mut().unwrap().receiver_credential_names =
            vec!["DEVDIARY_INGEST_KEY".into(), "EXPLICIT_ADDITIONAL".into()];
        if key_file {
            let key = h.f.temp.path().join("key");
            file(&key, b"secret", 0o600);
            h.cfg.capture.as_mut().unwrap().key_file = Some(key);
        }
        h.reseal();
        let (_, r) = capture_preparation::prepare(&h.cfg, &h.root, &h.spec).unwrap();
        let PreparationResult::Live(l) = r else {
            panic!("live")
        };
        assert_eq!(
            l.receiver_removal_names(),
            ["DEVDIARY_INGEST_KEY", "EXPLICIT_ADDITIONAL"]
        );
    }
}
#[test]
fn key_rotation_is_metadata_only_and_derived_union_has_at_most_129_explicit_names() {
    let mut h = Harness::new();
    let key = h.f.temp.path().join("key");
    file(&key, b"original-secret", 0o600);
    h.cfg.capture.as_mut().unwrap().key_file = Some(key.clone());
    h.cfg.capture.as_mut().unwrap().receiver_credential_names =
        (0..128).map(|i| format!("EXPLICIT_{i}")).collect();
    h.reseal();
    let exe = &h.cfg.capture.as_ref().unwrap().executable;
    let script = fs::read_to_string(exe).unwrap();
    file(
        exe,
        format!("{script}\nprintf 'rotated-secret' > '{}'\n", key.display()),
        0o700,
    );
    let (_, result) = capture_preparation::prepare(&h.cfg, &h.root, &h.spec).unwrap();
    let PreparationResult::Live(live) = result else {
        panic!("live")
    };
    assert_eq!(live.receiver_removal_names().len(), 129);
    assert_eq!(
        live.receiver_removal_names().last().unwrap(),
        "RECEIVER_TOKEN"
    );
    assert_eq!(fs::read(&key).unwrap(), b"rotated-secret");
}
#[test]
fn artifact_descriptors_close_after_failure_or_live_result_drop() {
    fn count(h: &Harness) -> usize {
        fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|e| fs::read_link(e.ok()?.path()).ok())
            .filter(|p| {
                p.starts_with(h.f.temp.path())
                    && (p.to_string_lossy().contains("capture-state") || p.ends_with("actors.json"))
            })
            .count()
    }
    for failure in [false, true] {
        let h = Harness::new();
        assert_eq!(count(&h), 0);
        if failure {
            file(&h.context, b"{}", 0o400);
        }
        let result = capture_preparation::prepare(&h.cfg, &h.root, &h.spec);
        assert_eq!(result.is_err(), failure);
        if !failure {
            assert_eq!(count(&h), 2);
        }
        drop(result);
        assert_eq!(count(&h), 0);
    }
}
#[test]
fn qualified_path_persists_only_typed_context_artifact_observation() {
    let h = Harness::new();
    let (_store, _result) = capture_preparation::prepare(&h.cfg, &h.root, &h.spec).unwrap();
    let prepared: String = h
        .sql()
        .query_row("SELECT prepared FROM capture_runs", [], |r| r.get(0))
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&prepared).unwrap();
    assert_eq!(
        v["context_artifact"]["length"],
        fs::metadata(&h.context).unwrap().len()
    );
    assert_eq!(
        v["context_artifact"]["sha256"],
        serde_json::to_value(<[u8; 32]>::from(Sha256::digest(
            fs::read(&h.context).unwrap()
        )))
        .unwrap()
    );
    assert!(!prepared.contains("principal:operator"));
    assert!(!prepared.contains("argument_count"));
}
#[test]
fn final_artifact_or_durable_context_change_cannot_return_a_usable_live_result() {
    use capture_preparation::Boundary;
    let mut accepted = Vec::new();
    for case in ["context", "registry", "hold", "finish", "commit_fault"] {
        let h = Harness::new();
        let result = capture_preparation::prepare_observed(
            &h.cfg,
            &h.root,
            &h.spec,
            |at, _store| {
                if at != Boundary::BeforeCommit {
                    return;
                }
                match case {
    "context"=>file(&h.context,b"{}",0o400),
    "registry"=>file(&h.cfg.capture.as_ref().unwrap().registry,b"{}",0o600),
    "hold"=>{h.f.store().record_recovery_hold(&h.root).unwrap();},
    "finish"=>{h.sql().execute("INSERT INTO task_finishes VALUES(?1,?2,'{}')",(h.root.identity().checkout.to_string(),Uuid::now_v7().to_string())).unwrap();},
    _=>h.sql().execute_batch("CREATE TRIGGER reject_prepare BEFORE UPDATE ON capture_runs BEGIN SELECT RAISE(ABORT,'fixture'); END").unwrap()
   }
            },
        );
        if result.is_ok() {
            accepted.push(case);
            continue;
        }
        // A corrupt synthetic finish row can itself make targeted recovery-hold validation refuse.
        if case != "finish" {
            h.held();
        }
        if case == "commit_fault" {
            let calls = fs::read(h.f.temp.path().join("calls")).unwrap();
            assert!(matches!(
                capture_preparation::prepare(&h.cfg, &h.root, &h.spec)
                    .unwrap()
                    .1,
                PreparationResult::Existing(_)
            ));
            assert_eq!(fs::read(h.f.temp.path().join("calls")).unwrap(), calls);
        }
        assert!(h
            .sql()
            .query_row("SELECT prepared IS NULL FROM capture_runs", [], |r| r
                .get::<_, bool>(0))
            .unwrap());
    }
    assert!(accepted.is_empty(), "late change accepted: {accepted:?}");
}
#[test]
fn unsafe_context_never_becomes_ready() {
    let mut accepted = Vec::new();
    for case in [
        "missing",
        "fifo",
        "symlink",
        "hardlink",
        "mode",
        "oversize",
        "invalid_utf8",
        "malformed",
        "duplicate",
        "schema",
        "actor",
        "run",
        "parent",
        "task",
        "chain",
        "cwd",
        "time",
        "actor_array",
        "run_array",
        "principal_array",
        "command_array",
        "root_array",
    ] {
        let h = Harness::new();
        let mut v: serde_json::Value =
            serde_json::from_slice(&fs::read(&h.context).unwrap()).unwrap();
        match case {
            "missing" => fs::remove_file(&h.context).unwrap(),
            "fifo" => {
                fs::remove_file(&h.context).unwrap();
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &h.context,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR,
                    0,
                )
                .unwrap();
            }
            "symlink" => {
                let real = h.f.temp.path().join("real-context");
                fs::rename(&h.context, &real).unwrap();
                std::os::unix::fs::symlink(real, &h.context).unwrap();
            }
            "hardlink" => fs::hard_link(&h.context, h.f.temp.path().join("context2")).unwrap(),
            "mode" => fs::set_permissions(&h.context, fs::Permissions::from_mode(0o600)).unwrap(),
            "oversize" => file(&h.context, vec![b' '; 1048577], 0o400),
            "invalid_utf8" => file(&h.context, [255], 0o400),
            "malformed" => file(&h.context, b"{", 0o400),
            "duplicate" => {
                let text = String::from_utf8(fs::read(&h.context).unwrap())
                    .unwrap()
                    .replacen("\"ref\":", "\"ref\":\"substitute\",\"ref\":", 1);
                file(&h.context, text, 0o400);
            }
            _ => {
                match case {
                    "schema" => v["schema_version"] = 1.into(),
                    "actor" => v["actor"]["ref"] = "other".into(),
                    "run" => v["run"]["ref"] = "other".into(),
                    "parent" => v["run"]["parent_ref"] = serde_json::Value::Null,
                    "task" => v["run"]["task_ref"] = "other".into(),
                    "chain" => {
                        v["execution_chain"] =
                            serde_json::json!([{"kind":"executor","system":"other"}])
                    }
                    "cwd" => v["working_directory"] = "/other".into(),
                    "time" => v["started_at"] = "2026-10-18T10:00:00".into(),
                    "root_array" => v = serde_json::json!([]),
                    _ => {
                        let field = case.strip_suffix("_array").unwrap();
                        v[field] = serde_json::json!([]);
                    }
                }
                file(&h.context, serde_json::to_vec(&v).unwrap(), 0o400);
            }
        }
        if capture_preparation::prepare(&h.cfg, &h.root, &h.spec).is_ok() {
            accepted.push(case);
            continue;
        }
        h.held();
        assert!(h
            .sql()
            .query_row("SELECT prepared IS NULL FROM capture_runs", [], |r| r
                .get::<_, bool>(0))
            .unwrap());
    }
    assert!(
        accepted.is_empty(),
        "unsafe contexts accepted: {accepted:?}"
    );
}
// Structural negative-fence fixture, never a successful prepare capability.
fn seed_prepared_fence(sql: &rusqlite::Connection, checkout: &str, cfg: &Config) {
    let operation = Uuid::now_v7();
    let hex = |tag: u8| format!("{tag:02x}").repeat(32);
    let record = serde_json::json!({
        "version":1, "operation":operation, "checkout":checkout, "mode":"supervised",
        "revision":1, "stage":"prepared", "assertion":null, "declaration":null,
        "predecessor_hex":hex(1), "source_hex":hex(2), "history_predecessor_hex":hex(3),
        "prior_history_count":0,
        "immutable_binding":{
            "version":1, "authority_allocation":hex(4), "source_sql":hex(2),
            "managed_physical":hex(6), "census":hex(7), "git_private":hex(8),
            "local_git":hex(9), "git_inputs":hex(10), "source_commitment":hex(11),
            "approval_semantic":hex(12), "approval_invalidation":hex(13),
            "protection":hex(14), "protection_count":0, "config_manifests":[hex(15),hex(16)],
            "inspection_policy":hex(17), "combined_policy":hex(18),
            "operator":hex(19), "source_repository":hex(20)
        },
        "quiescence":"empty", "task_completion":"supervised_empty", "policy_digest":hex(17),
        "combined_policy_digest":hex(18), "prepared_wall_ms":1, "remote_cleanup":"not_required"
    })
    .to_string();
    sql.execute(
        "INSERT INTO retirement_intents(operation,checkout,revision,stage,mode,assertion,declared_task,declared_operator,predecessor,source,record,held_reason,aborted_from) VALUES(?1,?2,1,'prepared','supervised',NULL,NULL,NULL,?3,?4,?5,NULL,NULL)",
        rusqlite::params![operation.to_string(),checkout,[1u8;32].as_slice(),[2u8;32].as_slice(),record],
    ).unwrap();
    // Public passive status traverses the production strict read_history decoder.
    let config = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        config.path(),
        format!(
            "store_dir={:?}\ntrusted_registry={:?}\nroots={:?}\n",
            cfg.store_dir.as_ref().unwrap(),
            cfg.trusted_registry.as_ref().unwrap(),
            cfg.roots
        ),
    )
    .unwrap();
    let report = serde_json::to_value(work_cli::inspection::retirement_status(
        config.path(),
        Uuid::parse_str(checkout).unwrap(),
    ))
    .unwrap();
    assert_eq!(
        report["stage"], "prepared",
        "strict history did not decode: {report}"
    );
    assert_eq!(report["revision"], 1);
    assert_eq!(report["history_count"], 1);
    assert_eq!(report["fresh_commit"], false);
}
#[test]
fn prepared_intent_refuses_prepare_without_receiver() {
    let h = Harness::new();
    let checkout = h.root.identity().checkout.to_string();
    seed_prepared_fence(&h.sql(), &checkout, &h.cfg);
    let error = match capture_preparation::prepare(&h.cfg, &h.root, &h.spec) {
        Ok(_) => panic!("fenced capture preparation unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        "retirement intent fences cooperative writes"
    );
    assert!(!h.f.temp.path().join("calls").exists());
    let (revision, stage, reason): (i64, String, Option<String>) = h
        .sql()
        .query_row(
            "SELECT revision, stage, held_reason FROM retirement_intents WHERE checkout=?1",
            [&checkout],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (revision, stage.as_str(), reason.as_deref()),
        (2, "held", Some("capture_admission"))
    );
    let prepared_null: bool = h
        .sql()
        .query_row("SELECT NOT EXISTS(SELECT 1 FROM capture_runs)", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(prepared_null);
    assert_eq!(h.f.store().pending_events(1000).unwrap().iter().filter(|e|
        matches!(&e.event, work_cli::events::Event::RetirementIntentChanged { stage, .. } if stage == "held")
    ).count(), 1);
}
