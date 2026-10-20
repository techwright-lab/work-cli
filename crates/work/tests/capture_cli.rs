#[path = "support/capture_finalization_fixture.rs"]
mod capture_fixture;
#[path = "support/run_fixture.rs"]
mod fixture_support;
use capture_fixture::Fixture;
use std::{
    fs,
    process::{Command, Output},
};
use std::{
    os::unix::fs::PermissionsExt,
    time::{Duration, Instant},
};
use work_cli::run_journal::RootOutcome;

fn cli(f: &Fixture, action: &str) -> Output {
    let config = f.dir.path().join("cli.toml");
    fs::write(
        &config,
        format!(
            "store_dir = {:?}\ntrusted_registry = {:?}\nroots = [{:?}]\n",
            f.config.store_dir.as_ref().unwrap(),
            f.config.trusted_registry.as_ref().unwrap(),
            f.config.roots[0]
        ),
    )
    .unwrap();
    cli_config(f, action, &config)
}
fn cli_config(f: &Fixture, action: &str, config: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_work"))
        .env_clear()
        .env("WORK_CONFIG", config)
        .args(["capture", action, &f.root.identity().run.to_string()])
        .output()
        .unwrap()
}
fn report(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn authority_files(
    f: &Fixture,
) -> std::collections::BTreeMap<std::path::PathBuf, (u32, Option<Vec<u8>>)> {
    fn visit(
        path: &std::path::Path,
        result: &mut std::collections::BTreeMap<std::path::PathBuf, (u32, Option<Vec<u8>>)>,
    ) {
        let meta = fs::symlink_metadata(path).unwrap();
        let bytes = if meta.is_file() && !path.to_string_lossy().ends_with("-shm") {
            Some(fs::read(path).unwrap())
        } else {
            None
        };
        result.insert(path.to_owned(), (meta.permissions().mode(), bytes));
        if meta.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(&entry.unwrap().path(), result);
            }
        }
    }
    let mut result = std::collections::BTreeMap::new();
    visit(f.config.store_dir.as_ref().unwrap(), &mut result);
    visit(f.config.trusted_registry.as_ref().unwrap(), &mut result);
    result
}
fn calls(f: &Fixture) -> String {
    fs::read_to_string(f.dir.path().join("calls")).unwrap_or_default()
}
fn truth(f: &Fixture) -> Vec<String> {
    // Everything outside the capture-finalization rows and their own outbox events.
    let db = f.sql();
    let mut tables = db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT IN ('capture_finalizations','outbox','sqlite_sequence') ORDER BY name").unwrap();
    let mut truth: Vec<_> = tables
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|name| {
            let name = name.unwrap();
            let mut rows = db
                .prepare(&format!("SELECT * FROM {name} ORDER BY rowid"))
                .unwrap();
            let n = rows.column_count();
            let values = rows
                .query_map([], |r| {
                    Ok((0..n)
                        .map(|i| format!("{:?}", r.get_ref(i).unwrap()))
                        .collect::<Vec<_>>()
                        .join("|"))
                })
                .unwrap();
            format!(
                "{name}:{}",
                values.map(|r| r.unwrap()).collect::<Vec<_>>().join("\n")
            )
        })
        .collect();
    let mut events = db.prepare("SELECT version,payload FROM outbox WHERE json_extract(payload,'$.type') != 'capture_finalization_changed' ORDER BY rowid").unwrap();
    truth.extend(
        events
            .query_map([], |r| {
                Ok(format!(
                    "{}:{}",
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?
                ))
            })
            .unwrap()
            .map(|r| r.unwrap()),
    );
    truth
}
// Synthetic durable task receipt only; does not qualify the real finish/kernel path.
fn recorded_task_finish(f: &Fixture) -> String {
    use sha2::{Digest, Sha256};
    let db = f.sql();
    let body: String = db
        .query_row("SELECT record FROM allocations", [], |r| r.get(0))
        .unwrap();
    let a: work_cli::allocate::Allocation = serde_json::from_str(&body).unwrap();
    let operation = uuid::Uuid::now_v7();
    let digest: [u8; 32] = Sha256::digest(serde_json::to_vec(&a).unwrap()).into();
    let record = serde_json::json!({"version":1,"checkout":a.checkout,"operation":operation,"allocation_operation":a.request.operation,"allocation_digest":digest,"hold_reason":"retirement-disabled","identity":a.identity,"capture_binding":vec![1u8;32],"local_freeze":"frozen","delivery":"pending","reason":null}).to_string();
    db.execute(
        "INSERT INTO task_finishes VALUES(?1,?2,?3)",
        (a.checkout.to_string(), operation.to_string(), &record),
    )
    .unwrap();
    let event = work_cli::events::Event::TaskFinished {
        checkout: a.checkout,
        operation,
    };
    db.execute(
        "INSERT INTO outbox(version,payload) VALUES(1,?1)",
        [serde_json::to_string(&event).unwrap()],
    )
    .unwrap();
    record
}
fn delivered(f: &Fixture, event: &str) {
    f.respond("delivered", serde_json::json!({"receipt":{"actor_ref":"actor","run_ref":f.root.identity().run_ref.as_str(),"event_id":event,"session_id":12}}), false);
}
#[test]
fn capture_begin_reconciliation_holds_known_prebind_metadata_without_receiver() {
    // Synthetic known metadata only: deliberately nonexistent checkout and registry.
    let mut f = Fixture::prepared_only();
    let prepared: String = f
        .sql()
        .query_row("SELECT prepared FROM capture_runs", [], |r| r.get(0))
        .unwrap();
    let r = report(&cli(&f, "reconcile-begin"));
    assert_eq!(r["attempt"], "metadata_reconciled");
    assert_eq!(r["runtime"], "not_inspected");
    assert!(calls(&f).is_empty());
    assert_eq!(
        f.sql()
            .query_row("SELECT prepared FROM capture_runs", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        prepared
    );
    let root = f
        .store
        .run_snapshot(&f.root.identity().run)
        .unwrap()
        .unwrap();
    assert!(root.recovery_hold);
    assert!(f
        .store
        .record_bound(&f.root, &fixture_support::binding(&f.root))
        .is_err());
    let before = truth(&f);
    let r = report(&cli(&f, "reconcile-begin"));
    assert_eq!(r["attempt"], "existing_preparation");
    assert_eq!(truth(&f), before);
    assert!(calls(&f).is_empty());
}
#[test]
fn capture_begin_reconciliation_closed_history_is_passive_and_preserves_new_writer() {
    // Synthetic durable history, NOT admission or closure qualification.
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    recorded_task_finish(&f);
    let before = truth(&f);
    assert_eq!(
        report(&cli(&f, "reconcile-begin"))["attempt"],
        "existing_preparation"
    );
    assert_eq!(truth(&f), before);
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    let newer = uuid::Uuid::now_v7();
    f.sql()
        .execute("UPDATE checkouts SET state='active',ready=1", [])
        .unwrap();
    f.sql()
        .execute(
            "INSERT INTO writers(checkout,group_id) VALUES(?1,?2)",
            (f.root.identity().checkout.to_string(), newer.to_string()),
        )
        .unwrap();
    let before = truth(&f);
    assert_eq!(
        report(&cli(&f, "reconcile-begin"))["attempt"],
        "existing_preparation"
    );
    assert_eq!(truth(&f), before);
    assert!(calls(&f).is_empty());
}
#[test]
fn capture_begin_reconciliation_refuses_in_use_or_finished_open_intent() {
    for case in ["bound", "permit", "task", "writer", "mismatch", "held-task"] {
        let mut f = if case == "permit" {
            Fixture::new(false, None)
        } else {
            Fixture::prepared_only()
        };
        match case {
            "bound" => {
                f.store
                    .record_bound(&f.root, &fixture_support::binding(&f.root))
                    .unwrap();
            }
            "task" => {
                recorded_task_finish(&f);
            }
            "held-task" => {
                f.store.record_recovery_hold(&f.root).unwrap();
                recorded_task_finish(&f);
            }
            "writer" => {
                f.sql()
                    .execute(
                        "UPDATE writers SET group_id=?1",
                        [uuid::Uuid::now_v7().to_string()],
                    )
                    .unwrap();
            }
            "mismatch" => {
                f.sql()
                    .execute(
                        "UPDATE capture_runs SET prepared=json_set(prepared,'$.actor_ref','wrong')",
                        [],
                    )
                    .unwrap();
            }
            _ => (),
        }
        let before = truth(&f);
        assert_eq!(cli(&f, "reconcile-begin").status.code(), Some(1), "{case}");
        assert_eq!(truth(&f), before, "{case}");
        assert!(calls(&f).is_empty());
    }
}
#[test]
fn capture_finalize_replays_exact_intent_without_runtime_authority() {
    let f = Fixture::new(true, Some(RootOutcome::Failed));
    let before = truth(&f);
    f.respond("pending", serde_json::json!({}), true);
    let first = cli(&f, "finalize");
    assert_eq!(first.status.code(), Some(1));
    let uncertain: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(uncertain["attempt"], "finish_uncertain");
    assert_eq!(uncertain["local_freeze"], "unconfirmed");
    let input = fs::read(f.dir.path().join("input")).unwrap();
    let snapshot = f
        .store
        .capture_finalization_snapshot(&f.root.identity().run)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.intent.body.as_bytes(), input);
    f.respond(
        "pending",
        serde_json::json!({"error_code":"delivery_failed"}),
        false,
    );
    let r = report(&cli(&f, "finalize"));
    assert_eq!(r["local_freeze"], "frozen");
    assert_eq!(r["delivery"], "pending");
    assert_eq!(r["receiver_error_recorded"], true);
    assert!(!r.to_string().contains("delivery_failed"));
    let replay = fs::read(f.dir.path().join("input")).unwrap();
    assert_eq!(replay, [input.clone(), input].concat());
    assert_eq!(calls(&f), "finish\nfinish\n");
    fs::remove_file(f.dir.path().join("producer")).unwrap();
    let r = report(&cli(&f, "finalize"));
    assert_eq!(r["attempt"], "existing_confirmation");
    assert_eq!(truth(&f), before);
}
#[test]
fn capture_retry_requires_confirmed_freeze_and_never_refreezes() {
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    let before = truth(&f);
    assert_eq!(cli(&f, "retry").status.code(), Some(1));
    assert!(calls(&f).is_empty());
    f.respond("pending", serde_json::json!({}), true);
    assert_eq!(cli(&f, "finalize").status.code(), Some(1));
    assert_eq!(cli(&f, "retry").status.code(), Some(1));
    assert_eq!(calls(&f), "finish\n");
    f.respond("pending", serde_json::json!({}), false);
    report(&cli(&f, "finalize"));
    delivered(&f, "first-event");
    let r = report(&cli(&f, "retry"));
    assert_eq!(r["receipt"]["event_id"], "first-event");
    f.respond("delivered", serde_json::json!({"receipt":{"actor_ref":"actor","run_ref":f.root.identity().run_ref.as_str(),"event_id":"first-event","session_id":13}}), false);
    assert_eq!(report(&cli(&f, "retry"))["receipt"]["session_id"], 13);
    f.respond(
        "pending",
        serde_json::json!({"error_code":"delivery_failed"}),
        false,
    );
    let r = report(&cli(&f, "retry"));
    assert_eq!(r["attempt"], "response_recorded");
    assert_eq!(r["delivery"], "delivered");
    assert_eq!(r["receiver_error_recorded"], true);
    assert_eq!(r["receipt"]["event_id"], "first-event");
    assert_eq!(r["receipt"]["session_id"], 13);
    assert!(!r.to_string().contains("delivery_failed"));
    assert_eq!(calls(&f), "finish\nfinish\nretry\nretry\nretry\n");
    assert_eq!(truth(&f), before);
}
#[test]
fn capture_reconciliation_uses_sealed_settings_after_config_change() {
    let f = Fixture::new(true, Some(RootOutcome::Cancelled));
    // Replace the current host capture config, without changing sealed per-root settings.
    report(&cli(&f, "status"));
    let config = f.dir.path().join("cli.toml");
    let mut text = fs::read_to_string(&config).unwrap();
    text.push_str(&format!("\n[capture]\nexecutable = {:?}\nregistry = {:?}\nstate_dir = {:?}\ntimeout_ms = 1\nresponse_cap = 1\nregistry_sha256 = {:?}\nendpoint_identity = 'https://changed.invalid'\nreceiver_credential_names = ['CHANGED_TOKEN']\n[capture.actor_refs]\nother = 'different-actor'\n", f.dir.path().join("must-not-run"), f.dir.path().join("changed-registry"), f.dir.path().join("changed-state"), "f".repeat(64)));
    fs::write(&config, text).unwrap();
    let r = report(&cli_config(&f, "finalize", &config));
    assert_eq!(r["recorded_root_outcome"], "cancelled");
    delivered(&f, "sealed-receiver");
    assert_eq!(
        report(&cli_config(&f, "retry", &config))["receipt"]["event_id"],
        "sealed-receiver"
    );
    assert_eq!(calls(&f), "finish\nretry\n");
}
#[test]
fn capture_historical_commands_ignore_current_execution_policies() {
    let policies = [
        // Complete current supervisor declaration, but its last actor was removed.
        "[supervisor]\nruntime_directory = '/unused-runtime'\nbus_address = 'unix:path=/unused-runtime/bus'\nruntime_max_seconds = 1\npreexec_ms = 1\nclosure_grace_ms = 1\ncancel_grace_ms = 1\nactors = {}\n".to_owned(),
        // Complete current capture declaration, but its last actor was removed.
        format!("[capture]\nexecutable = '/unused-producer'\nregistry = '/unused-registry'\nstate_dir = '/unused-state'\ntimeout_ms = 1\nresponse_cap = 1\nregistry_sha256 = '{}'\nendpoint_identity = 'https://changed.invalid'\nreceiver_credential_names = ['CHANGED_TOKEN']\nactor_refs = {{}}\n", "f".repeat(64)),
        // Types, missing fields, relative locators and invalid limits are irrelevant here.
        "repositories = false\nallocation = 'SECRET invalid allocation'\ncapture = 7\n[supervisor]\nruntime_directory = 'SECRET relative runtime'\npreexec_ms = -1\nactors = false\n".to_owned(),
    ];
    for policy in policies {
        let f = Fixture::new(true, Some(RootOutcome::Completed));
        let task_receipt = recorded_task_finish(&f);
        let before = truth(&f);
        report(&cli(&f, "finalize"));
        let config = f.dir.path().join("cli.toml");
        let text = format!("{}\n{policy}", fs::read_to_string(&config).unwrap());
        assert!(work_cli::config::Config::from_text(&text).is_err());
        fs::write(&config, text).unwrap();
        let producer = fs::read(f.dir.path().join("producer")).unwrap();
        fs::remove_file(f.dir.path().join("producer")).unwrap();
        let files = authority_files(&f);
        let status = report(&cli_config(&f, "status", &config));
        assert_eq!(status["local_freeze"], "frozen");
        assert_eq!(status["runtime"], "not_inspected");
        assert_eq!(status["task_open"], false);
        assert_eq!(status["lease_charged"], true);
        assert_eq!(
            report(&cli_config(&f, "finalize", &config))["attempt"],
            "existing_confirmation"
        );
        assert_eq!(calls(&f), "finish\n");
        assert_eq!(authority_files(&f), files);
        fs::write(f.dir.path().join("producer"), producer).unwrap();
        fs::set_permissions(
            f.dir.path().join("producer"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        delivered(&f, "historical-sealed-retry");
        let retry = report(&cli_config(&f, "retry", &config));
        assert_eq!(retry["attempt"], "response_recorded");
        assert_eq!(retry["delivery"], "delivered");
        assert_eq!(retry["receipt"]["event_id"], "historical-sealed-retry");
        assert_eq!(calls(&f), "finish\nretry\n");
        assert_eq!(truth(&f), before);
        assert_eq!(
            f.sql()
                .query_row("SELECT record FROM task_finishes", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            task_receipt
        );
    }
}
#[test]
fn capture_authority_loader_rejects_unsafe_inputs_without_creation() {
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    report(&cli(&f, "status"));
    let config = f.dir.path().join("cli.toml");
    let valid = fs::read_to_string(&config).unwrap();
    let store = f.config.store_dir.as_ref().unwrap();
    let registry = f.config.trusted_registry.as_ref().unwrap();
    let root = &f.config.roots[0];
    let missing = f.dir.path().join("SECRET-missing");
    let link = f.dir.path().join("SECRET-link");
    std::os::unix::fs::symlink(root, &link).unwrap();
    let inputs = [
        "SECRET = [".to_owned(),
        format!("store_dir = 7\ntrusted_registry = {registry:?}\nroots = [{root:?}]"),
        format!("store_dir = {store:?}\ntrusted_registry = false\nroots = [{root:?}]"),
        format!("store_dir = {store:?}\ntrusted_registry = {registry:?}\nroots = 'SECRET'"),
        format!("store_dir = {store:?}\ntrusted_registry = {registry:?}\nroots = [7]"),
        format!(
            "store_dir = 'SECRET-relative'\ntrusted_registry = {registry:?}\nroots = [{root:?}]"
        ),
        format!("store_dir = {store:?}\ntrusted_registry = 'SECRET-relative'\nroots = [{root:?}]"),
        format!(
            "store_dir = {store:?}\ntrusted_registry = {registry:?}\nroots = ['SECRET-relative']"
        ),
        format!("store_dir = {link:?}\ntrusted_registry = {registry:?}\nroots = [{root:?}]"),
        format!("store_dir = {store:?}\ntrusted_registry = {link:?}\nroots = [{root:?}]"),
        format!("store_dir = {store:?}\ntrusted_registry = {registry:?}\nroots = [{link:?}]"),
        format!("store_dir = {store:?}\ntrusted_registry = {registry:?}\nroots = [{missing:?}]"),
        format!("store_dir = {missing:?}\ntrusted_registry = {registry:?}\nroots = [{root:?}]"),
        format!("trusted_registry = {registry:?}\nroots = [{root:?}]"),
        format!("store_dir = {store:?}\nroots = [{root:?}]"),
        format!("store_dir = {store:?}\ntrusted_registry = {registry:?}"),
        format!("# SECRET{}", "x".repeat(1024 * 1024)),
    ];
    let held = b"capture held: invalid_metadata_or_existing_authority; result unknown\n";
    let files = authority_files(&f);
    let before = truth(&f);
    for text in inputs {
        fs::write(&config, text).unwrap();
        for action in ["status", "finalize", "retry"] {
            let out = cli_config(&f, action, &config);
            assert_eq!(out.status.code(), Some(1));
            assert!(out.stdout.is_empty());
            assert_eq!(out.stderr, held);
        }
        assert!(!missing.exists());
        assert_eq!(authority_files(&f), files);
        assert_eq!(truth(&f), before);
    }
    fs::write(&config, &valid).unwrap();
    for kind in ["symlink", "fifo", "directory"] {
        let unsafe_config = f.dir.path().join(format!("SECRET-{kind}"));
        match kind {
            "symlink" => std::os::unix::fs::symlink(&config, &unsafe_config).unwrap(),
            "fifo" => rustix::fs::mkfifoat(rustix::fs::CWD, &unsafe_config, rustix::fs::Mode::RUSR)
                .unwrap(),
            "directory" => fs::create_dir(&unsafe_config).unwrap(),
            _ => unreachable!(),
        }
        for action in ["status", "finalize", "retry"] {
            let out = cli_config(&f, action, &unsafe_config);
            assert_eq!(out.status.code(), Some(1));
            assert!(out.stdout.is_empty());
            assert_eq!(out.stderr, held);
        }
    }
    assert_eq!(authority_files(&f), files);
    f.sql().execute_batch("PRAGMA user_version=12").unwrap();
    let legacy_files = authority_files(&f);
    for action in ["status", "finalize", "retry"] {
        let out = cli_config(&f, action, &config);
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        assert_eq!(
            out.stderr,
            b"capture held: authority schema upgrade required; result unknown\n"
        );
        assert_eq!(
            f.sql()
                .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            12
        );
    }
    assert_eq!(authority_files(&f), legacy_files);
    assert!(calls(&f).is_empty());
    assert_eq!(truth(&f), before);
    assert!(!missing.exists());
}
#[test]
fn capture_terminal_uncertainty_is_explicit_and_retains_task_truth() {
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    report(&cli(&f, "finalize"));
    let task_receipt = recorded_task_finish(&f);
    let pending_task_truth = truth(&f);
    delivered(&f, "kept-event");
    report(&cli(&f, "retry"));
    assert_eq!(truth(&f), pending_task_truth);
    assert_eq!(report(&cli(&f, "status"))["task_open"], false);
    let before = truth(&f);
    fs::write(
        f.dir.path().join("response"),
        "SECRET malformed receiver payload",
    )
    .unwrap();
    let out = cli(&f, "retry");
    assert_eq!(out.status.code(), Some(1));
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["attempt"], "delivery_uncertain");
    assert_eq!(r["local_freeze"], "frozen");
    assert_eq!(r["delivery"], "delivered");
    assert_eq!(r["receipt"]["event_id"], "kept-event");
    assert!(!format!("{out:?}").contains("SECRET"));
    assert_eq!(r["task_open"], false);
    assert_eq!(
        f.sql()
            .query_row("SELECT record FROM task_finishes", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        task_receipt
    );
    assert_eq!(truth(&f), before);
    let script = format!("#!/usr/bin/python3\nimport sqlite3,sys\nsys.stdin.read()\nc=sqlite3.connect({:?})\nc.execute('PRAGMA user_version=12')\nc.close()\nprint('SECRET invalid terminal response')\n", f.dir.path().join("private/store.sqlite").to_str().unwrap());
    fs::write(f.dir.path().join("producer"), script).unwrap();
    let out = cli(&f, "retry");
    assert_eq!(out.status.code(), Some(1));
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        r,
        serde_json::json!({"action":"retry","attempt":"delivery_uncertain","runtime":"not_inspected","result":"held_result_unknown"})
    );
    assert!(!format!("{out:?}").contains("SECRET"));
}
#[test]
fn capture_unknown_outcome_clock_or_open_root_never_invokes_receiver() {
    for (closed, outcome) in [(true, None), (false, Some(RootOutcome::Completed))] {
        let f = Fixture::new(closed, outcome);
        let before = truth(&f);
        assert_eq!(cli(&f, "finalize").status.code(), Some(1));
        assert_eq!(cli(&f, "retry").status.code(), Some(1));
        assert!(calls(&f).is_empty());
        assert_eq!(truth(&f), before);
        assert_eq!(
            f.sql()
                .query_row("SELECT count(*) FROM capture_finalizations", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    f.sql().execute("UPDATE capture_runs SET group_end=json_set(group_end,'$.clock_uncertain',json('true'))", []).unwrap();
    assert_eq!(cli(&f, "finalize").status.code(), Some(1));
    assert!(calls(&f).is_empty());
}
#[test]
fn capture_commands_require_current_existing_authority_and_sanitize_arguments() {
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    let config = f.dir.path().join("missing-config");
    for args in [
        vec!["capture", "status", "SECRET-token"],
        vec!["capture", "SECRET-token"],
        vec!["capture", "retry", "550e8400-e29b-41d4-a716-446655440001"],
        vec!["capture", "finalize", "--receiver=SECRET-token"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_work"))
            .env_clear()
            .env("WORK_CONFIG", &config)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(!format!("{out:?}").contains("SECRET-token"));
    }
    for args in [
        vec!["capture", "--help"],
        vec!["capture", "--version"],
        vec!["capture", "status", "--help"],
    ] {
        assert!(Command::new(env!("CARGO_BIN_EXE_work"))
            .env_clear()
            .env("WORK_CONFIG", &config)
            .args(args)
            .output()
            .unwrap()
            .status
            .success());
    }
    assert!(!config.exists());
    for action in ["status", "finalize", "retry"] {
        f.sql().execute_batch("PRAGMA user_version=12").unwrap();
        let out = cli(&f, action);
        assert_eq!(out.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&out.stderr).contains("upgrade required"));
        assert_eq!(
            f.sql()
                .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            12
        );
    }
    assert!(calls(&f).is_empty());
    for fault in [
        "missing_authority",
        "unregistered",
        "root",
        "capture",
        "schema",
    ] {
        let f = Fixture::new(true, Some(RootOutcome::Completed));
        match fault {
            "missing_authority" => {
                fs::rename(
                    f.dir.path().join("private/store.sqlite"),
                    f.dir.path().join("moved.sqlite"),
                )
                .unwrap();
            }
            "unregistered" => {
                fs::rename(
                    f.config.trusted_registry.as_ref().unwrap(),
                    f.dir.path().join("moved-registry"),
                )
                .unwrap();
            }
            "root" => {
                f.sql()
                    .execute("UPDATE runs SET outcome='SECRET corrupt root'", [])
                    .unwrap();
            }
            "capture" => {
                f.sql()
                    .execute("UPDATE capture_runs SET spec='SECRET corrupt capture'", [])
                    .unwrap();
            }
            "schema" => {
                f.sql()
                    .execute_batch("DROP TABLE capture_finalizations")
                    .unwrap();
            }
            _ => unreachable!(),
        }
        for action in ["status", "finalize", "retry"] {
            let out = cli(&f, action);
            assert_eq!(out.status.code(), Some(1), "{fault}:{action}");
            assert!(!format!("{out:?}").contains("SECRET"));
        }
        assert!(calls(&f).is_empty());
        if fault == "missing_authority" {
            assert!(!f.dir.path().join("private/store.sqlite").exists());
        }
        if fault == "unregistered" {
            assert!(!f.config.trusted_registry.as_ref().unwrap().exists());
        }
    }
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    report(&cli(&f, "status"));
    let out = Command::new(env!("CARGO_BIN_EXE_work"))
        .env_clear()
        .env("WORK_CONFIG", f.dir.path().join("cli.toml"))
        .args(["capture", "finalize", &uuid::Uuid::now_v7().to_string()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(calls(&f).is_empty());
}
#[test]
fn capture_receiver_delay_holds_neither_sql_nor_lifecycle_lock() {
    let mut f = Fixture::new(true, Some(RootOutcome::Completed));
    report(&cli(&f, "status"));
    let script = format!("#!/usr/bin/python3\nimport sqlite3,fcntl,time,json,sys,os\np={:?}\nc=sqlite3.connect(p+'/private/store.sqlite',timeout=0.5)\nassert c.execute('SELECT count(*) FROM capture_finalizations WHERE confirmation IS NULL').fetchone()[0]==1\nc.execute('BEGIN IMMEDIATE')\nc.rollback()\nlock=open(p+'/private/allocation.lock','a')\nfcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)\nlock.close()\nopen(p+'/unlocked','w').write('yes')\ntime.sleep(0.65)\nend=time.monotonic()+0.75\nwhile not os.path.exists(p+'/progressed') and time.monotonic()<end: time.sleep(0.005)\nassert os.path.exists(p+'/progressed')\nsys.stdin.read()\nprint(open(p+'/response').read())\n", f.dir.path().to_str().unwrap());
    fs::write(f.dir.path().join("producer"), script).unwrap();
    fs::set_permissions(
        f.dir.path().join("producer"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let start = Instant::now();
    let child = Command::new(env!("CARGO_BIN_EXE_work"))
        .env_clear()
        .env("WORK_CONFIG", f.dir.path().join("cli.toml"))
        .args(["capture", "finalize", &f.root.identity().run.to_string()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    while !f.dir.path().join("unlocked").exists() && start.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(f.dir.path().join("unlocked").exists());
    let checkout = f
        .store
        .reserve(
            &work_cli::admission::Reservation {
                operation: uuid::Uuid::now_v7(),
                repository: f.config.roots[0].clone(),
                actor: "independent".into(),
                owner: "independent".into(),
                task: "independent".into(),
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
    fs::write(f.dir.path().join("progressed"), checkout.to_string()).unwrap();
    report(&child.wait_with_output().unwrap());
    assert!(start.elapsed() >= Duration::from_millis(650));
    assert_eq!(
        fs::read_to_string(f.dir.path().join("unlocked")).unwrap(),
        "yes"
    );
}
#[test]
fn capture_status_is_readonly_without_runtime_or_receiver() {
    let f = Fixture::new(true, Some(RootOutcome::Completed));
    fs::remove_file(f.dir.path().join("producer")).unwrap();
    let files = authority_files(&f);
    let before = truth(&f);
    let r = report(&cli(&f, "status"));
    assert_eq!(r["runtime"], "not_inspected");
    assert_eq!(r["preparation"], "prepared");
    assert_eq!(r["local_freeze"], "unfrozen");
    assert_eq!(r["task_open"], true);
    assert_eq!(r["lease_charged"], true);
    assert!(f
        .store
        .capture_snapshot(&f.root.identity().run)
        .unwrap()
        .is_some());
    assert_eq!(before, truth(&f));
    assert_eq!(files, authority_files(&f));
    assert!(!f.dir.path().join("calls").exists());
    let text = String::from_utf8(cli(&f, "status").stdout).unwrap();
    for forbidden in [
        "context",
        "producer",
        "registry",
        "environment",
        "intent_wall",
        "body",
        "fingerprint",
    ] {
        assert!(!text.contains(forbidden), "{text}");
    }
    let unprepared = Fixture::unprepared();
    assert_eq!(
        report(&cli(&unprepared, "status"))["preparation"],
        "unprepared"
    );
    assert_eq!(cli(&unprepared, "finalize").status.code(), Some(1));
    assert!(!unprepared.dir.path().join("calls").exists());
    f.sql().execute("DELETE FROM capture_runs", []).unwrap();
    let missing = report(&cli(&f, "status"));
    assert_eq!(missing["preparation"], "missing");
    assert_eq!(missing["local_freeze"], "missing");
    assert_eq!(cli(&f, "finalize").status.code(), Some(1));
}
