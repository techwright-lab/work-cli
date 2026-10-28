//! Public retirement-intent fence acceptance. Source-authored; CI-only.
//! Native Git and child CLI commands below run only in owned persistent CI fixtures.
#[path = "support/inspection_fixture.rs"]
mod fixture;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
    time::Duration,
};
use uuid::Uuid;
use work_cli as work_cli_api;
use work_cli::inspection::{
    abort_retirement, prepare_retirement, retirement_status, RetirementIntentReport,
};
use work_cli::store::StoreError;

fn write_config(temp: &tempfile::TempDir, policy: &str) -> PathBuf {
    let path = temp.path().join("config.toml");
    fs::write(
        &path,
        format!(
            "store_dir = {store:?}\ntrusted_registry = {registry:?}\nroots = [{root:?}]\n{policy}",
            store = temp.path().join("private"),
            registry = temp.path().join("registry"),
            root = temp.path().join("root"),
        ),
    )
    .unwrap();
    path
}

fn cli(config: &Path, args: &[&str]) -> (Output, serde_json::Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_work"))
        .env_clear()
        .env("WORK_CONFIG", config)
        .args(args)
        .output()
        .unwrap();
    let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| panic!("{output:?}"));
    (output, value)
}

fn invariants(value: &serde_json::Value) {
    assert_eq!(value["execution_enabled"], false, "{value}");
    assert_eq!(value["retirement_authority"], false, "{value}");
    assert_eq!(value["writer_charges_retained"], true, "{value}");
    assert_eq!(value["protection_retained"], true, "{value}");
}

fn wire(report: RetirementIntentReport) -> serde_json::Value {
    let value = serde_json::to_value(report).unwrap();
    invariants(&value);
    value
}

fn unknown(value: &serde_json::Value, reason: &str) {
    invariants(value);
    assert_eq!(value["outcome"], "held", "{value}");
    assert_eq!(value["reason"], reason, "{value}");
    assert_eq!(value["stage"], "unknown", "{value}");
    assert_eq!(value["recorded"], "unknown", "{value}");
    assert!(
        value["revision"].is_null(),
        "requested revision is not observed: {value}"
    );
    assert_eq!(value["fence_active"], true, "{value}");
    assert_eq!(value["fresh_commit"], false, "{value}");
}

// Physical byte/identity witness, excluding atime (ordinary reads may update it).
// Covers payload, refs, objects, admin and receipts without invoking Git to inspect.
fn files(paths: &[&Path]) -> Vec<String> {
    fn visit(path: &Path, rows: &mut Vec<String>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        rows.push(format!(
            "{path:?}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            metadata.dev(),
            metadata.ino(),
            metadata.mode(),
            metadata.uid(),
            metadata.gid(),
            metadata.nlink(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ));
        if metadata.is_dir() {
            let mut children: Vec<_> = fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            children.sort();
            for child in children {
                visit(&child, rows);
            }
        } else if metadata.is_file() {
            rows.push(format!("{:?}", fs::read(path).unwrap()));
        } else if metadata.file_type().is_symlink() {
            rows.push(format!("{:?}", fs::read_link(path).unwrap()));
        }
    }
    let mut rows = Vec::new();
    for path in paths {
        visit(path, &mut rows);
    }
    rows
}

#[test]
fn disabled_prepare_touches_no_store_or_lock() {
    for policy in ["", "[retirement]\nprepare_intents=false\n"] {
        for sentinel in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = write_config(&temp, policy);
            if sentinel {
                fs::write(temp.path().join("private"), b"not an authority").unwrap();
            }
            let before = files(&[temp.path()]);
            let checkout = Uuid::now_v7().to_string();
            let operation = Uuid::now_v7().to_string();
            let report = wire(prepare_retirement(
                &path,
                Uuid::parse_str(&checkout).unwrap(),
                Uuid::parse_str(&operation).unwrap(),
                None,
                false,
            ));
            let (out, command) = cli(
                &path,
                &["retire", "prepare", &checkout, "--operation", &operation],
            );
            assert_eq!(out.status.code(), Some(1));
            for value in [report, command] {
                invariants(&value);
                assert_eq!(value["outcome"], "disabled");
                assert_eq!(value["reason"], "prepare_intents_disabled");
                assert_eq!(value["recorded"], "none");
                assert_eq!(value["fresh_commit"], false);
                assert_eq!(value["fence_active"], false);
            }
            assert_eq!(files(&[temp.path()]), before);
        }
    }
}

#[test]
fn invalid_policy_and_missing_authority_are_unknown_without_creation() {
    for policy in [
        "[retirement]\nprepare_intents='true'\n",
        "[retirement]\nprepare_intents=true\nextra=false\n",
        "[retirement]\n",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let config = write_config(&temp, policy);
        fs::write(temp.path().join("private"), b"sentinel").unwrap();
        let before = files(&[temp.path()]);
        unknown(
            &wire(prepare_retirement(
                &config,
                Uuid::now_v7(),
                Uuid::now_v7(),
                None,
                false,
            )),
            "configuration_unknown",
        );
        assert_eq!(files(&[temp.path()]), before);
    }
    for policy in [
        "",
        "[retirement]\nprepare_intents=false\n",
        "[retirement]\nprepare_intents=true\n",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let config = write_config(&temp, policy);
        let before = files(&[temp.path()]);
        let checkout = Uuid::now_v7();
        let operation = Uuid::now_v7();
        unknown(
            &wire(abort_retirement(&config, checkout, operation, 1)),
            "authority_unknown",
        );
        unknown(
            &wire(retirement_status(&config, checkout)),
            "authority_unknown",
        );
        for args in [
            vec![
                "retire".into(),
                "abort".into(),
                checkout.to_string(),
                "--operation".into(),
                operation.to_string(),
                "--revision".into(),
                "1".into(),
            ],
            vec!["retire".into(), "status".into(), checkout.to_string()],
        ] {
            let (out, value) = cli(
                &config,
                &args.iter().map(String::as_str).collect::<Vec<_>>(),
            );
            assert_eq!(out.status.code(), Some(1));
            unknown(&value, "authority_unknown");
        }
        assert_eq!(files(&[temp.path()]), before);
    }
}

#[test]
fn cli_help_exposes_retire_without_activation() {
    let output = Command::new(env!("CARGO_BIN_EXE_work"))
        .args(["retire", "--help"])
        .output()
        .expect("work retire help");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("prepare"));
    assert!(text.contains("abort"));
    assert!(text.contains("status"));
    let missing = Command::new(env!("CARGO_BIN_EXE_work"))
        .env_clear()
        .args(["retire", "status", &Uuid::now_v7().to_string()])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
    assert!(missing.stdout.is_empty());
}

fn db(f: &fixture::ManagedFixture) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        f.temp.path().join("authority/store.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
}

// Compare every caller-owned SQL table, not just counts or selected DTO fields.
fn source_rows(f: &fixture::ManagedFixture) -> Vec<String> {
    let conn = db(f);
    let mut tables = conn.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT IN ('retirement_intents','outbox') ORDER BY name").unwrap();
    let names: Vec<String> = tables
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let mut result = Vec::new();
    for table in names {
        let mut statement = conn
            .prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))
            .unwrap();
        let columns = statement.column_count();
        let mut rows = statement.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            let values: Vec<_> = (0..columns)
                .map(|col| format!("{:?}", row.get_ref(col).unwrap()))
                .collect();
            result.push(format!("{table}:{values:?}"));
        }
    }
    result.sort();
    result
}

fn sql_bytes(f: &fixture::ManagedFixture) -> Vec<Vec<u8>> {
    ["store.sqlite", "store.sqlite-wal"]
        .into_iter()
        .map(|name| fs::read(f.temp.path().join("authority").join(name)).unwrap())
        .collect()
}

fn retained_files(f: &fixture::ManagedFixture) -> Vec<String> {
    files(&[
        &f.allocation.destination,
        f.common(),
        &f.temp.path().join("authority/inspection-receipts-v1"),
    ])
}

fn events(f: &fixture::ManagedFixture) -> usize {
    f.store.pending_events(1000).unwrap().len()
}

fn intent_events(
    f: &fixture::ManagedFixture,
    operation: Uuid,
) -> Vec<(u64, String, Option<String>)> {
    f.store
        .pending_events(1000)
        .unwrap()
        .into_iter()
        .filter_map(|pending| match pending.event {
            work_cli::events::Event::RetirementIntentChanged {
                checkout,
                operation: id,
                revision,
                stage,
                reason,
            } if checkout == f.allocation.checkout && id == operation => {
                Some((revision, stage, reason))
            }
            _ => None,
        })
        .collect()
}

fn assertion(config: &Path, checkout: Uuid) -> Uuid {
    let (out, begin) = cli(config, &["approve", "begin", &checkout.to_string()]);
    assert!(out.status.success(), "{begin}");
    // Real configured one-second quiet interval, as in existing approval fixtures.
    std::thread::sleep(Duration::from_millis(1100));
    let (out, confirm) = cli(
        config,
        &[
            "approve",
            "confirm",
            &checkout.to_string(),
            "--observation",
            begin["receipt_id"].as_str().unwrap(),
            "--assert-quiescent",
        ],
    );
    assert!(out.status.success(), "{confirm}");
    Uuid::parse_str(confirm["receipt_id"].as_str().unwrap()).unwrap()
}

fn adopted() -> (fixture::ManagedFixture, PathBuf, Uuid) {
    let f = fixture::ManagedFixture::recovery("sha1", "2");
    let (config, _) = f.approval();
    let text = fs::read_to_string(&config).unwrap();
    fs::write(
        &config,
        format!("{text}\n[retirement]\nprepare_intents=true\n"),
    )
    .unwrap();
    let (out, protected) = cli(
        &config,
        &[
            "prepare-recovery",
            &f.allocation.checkout.to_string(),
            "--create",
            "--operation",
            &Uuid::now_v7().to_string(),
        ],
    );
    assert!(out.status.success(), "{protected}");
    assert_eq!(protected["outcome"], "prepared", "{protected}");
    assert!(f.common().join("refs/work-recovery").exists());
    let claim = assertion(&config, f.allocation.checkout);
    (f, config, claim)
}

fn committed(value: &serde_json::Value, operation: Uuid, stage: &str, revision: u64) {
    invariants(value);
    assert_eq!(value["operation"], operation.to_string(), "{value}");
    assert_eq!(value["outcome"], stage, "{value}");
    assert_eq!(value["stage"], stage, "{value}");
    assert_eq!(value["revision"], revision, "{value}");
    assert_eq!(value["fresh_commit"], true, "{value}");
    assert_eq!(value["recorded"], "committed", "{value}");
    assert_eq!(value["fence_active"], stage == "prepared", "{value}");
}

#[test]
fn passive_status_including_no_intent_has_no_sql_or_journal_writes() {
    let (f, config, claim) = adopted();
    let checkout = f.allocation.checkout;
    let operation = Uuid::now_v7();
    for stage in ["none", "prepared", "aborted"] {
        if stage == "prepared" {
            committed(
                &wire(prepare_retirement(
                    &config,
                    checkout,
                    operation,
                    Some(claim),
                    true,
                )),
                operation,
                stage,
                1,
            );
        } else if stage == "aborted" {
            committed(
                &wire(abort_retirement(&config, checkout, operation, 1)),
                operation,
                stage,
                2,
            );
        }
        let before = sql_bytes(&f);
        let before_events = events(&f);
        let before_files = retained_files(&f);
        let report = wire(retirement_status(&config, checkout));
        let (out, command) = cli(&config, &["retire", "status", &checkout.to_string()]);
        assert!(out.status.success(), "{command}");
        for value in [report, command] {
            invariants(&value);
            assert_eq!(value["outcome"], "observed");
            assert_eq!(value["stage"], stage);
            assert_eq!(value["fresh_commit"], false);
            assert_eq!(value["fence_active"], stage == "prepared");
        }
        assert_eq!(sql_bytes(&f), before);
        assert_eq!(events(&f), before_events);
        assert_eq!(retained_files(&f), before_files);
    }
}

#[test]
fn public_adopted_prepare_writer_hold_offline_abort_and_fresh_assertion() {
    for hold in [false, true] {
        let (mut f, config, claim) = adopted();
        let checkout = f.allocation.checkout;
        let operation = Uuid::now_v7();
        let before = source_rows(&f);
        let physical = retained_files(&f);
        let count = events(&f);
        assert_eq!(
            db(&f)
                .query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        let prepared = wire(prepare_retirement(
            &config,
            checkout,
            operation,
            Some(claim),
            true,
        ));
        committed(&prepared, operation, "prepared", 1);
        assert_eq!(prepared["mode"], "adopted");
        assert_eq!(events(&f), count + 1);
        let record: String = db(&f)
            .query_row(
                "SELECT record FROM retirement_intents WHERE operation=?1",
                [operation.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        let record: serde_json::Value = serde_json::from_str(&record).unwrap();
        let declaration = &record["declaration"];
        assert_eq!(declaration["operator"], "explicit-operator");
        assert_eq!(declaration["task"], f.allocation.request.task);
        assert_eq!(declaration["assertion"], claim.to_string());
        assert_eq!(declaration["operation"], operation.to_string());
        assert_eq!(declaration["checkout"], checkout.to_string());
        assert_eq!(declaration["predecessor_hex"], record["predecessor_hex"]);
        assert_eq!(source_rows(&f), before);
        assert_eq!(retained_files(&f), physical);

        // Competing prepare never holds the original intent or emits an event.
        unknown(
            &wire(prepare_retirement(
                &config,
                checkout,
                Uuid::now_v7(),
                Some(claim),
                true,
            )),
            "intent_conflict",
        );
        assert_eq!(events(&f), count + 1);
        assert_eq!(
            wire(retirement_status(&config, checkout))["stage"],
            "prepared"
        );
        let revision = if hold {
            for expected_events in [count + 2, count + 2] {
                assert!(matches!(
                    f.store.acquire_writer(checkout, Uuid::now_v7()),
                    Err(StoreError::RetirementFenced)
                ));
                assert_eq!(events(&f), expected_events);
                assert_eq!(source_rows(&f), before);
                assert_eq!(retained_files(&f), physical);
                let status = wire(retirement_status(&config, checkout));
                assert_eq!(status["stage"], "held");
                assert_eq!(status["revision"], 2);
            }
            2
        } else {
            1
        };
        let held_events = events(&f);
        let mut expected_events = vec![(1, "prepared".to_string(), None)];
        if hold {
            expected_events.push((2, "held".to_string(), Some("writer_acquire".to_string())));
            unknown(
                &wire(abort_retirement(&config, checkout, operation, 1)),
                "intent_conflict",
            );
        } else {
            unknown(
                &wire(abort_retirement(&config, checkout, operation, 2)),
                "intent_conflict",
            );
        }
        assert_eq!(intent_events(&f, operation), expected_events);
        assert_eq!(events(&f), held_events);
        let retry = wire(prepare_retirement(
            &config,
            checkout,
            operation,
            Some(claim),
            true,
        ));
        assert_eq!(retry["outcome"], "existing");
        assert_eq!(retry["fresh_commit"], false);
        assert_eq!(retry["fence_active"], true);
        assert_eq!(events(&f), held_events);
        // Make ONLY the disposable remote inaccessible. Do not change its parent
        // directory (which also anchors the config witness) or any local input.
        let remote = f.temp.path().join("approval-backup.git");
        let permissions = fs::metadata(&remote).unwrap().permissions();
        fs::set_permissions(&remote, fs::Permissions::from_mode(0o0)).unwrap();
        let aborted = wire(abort_retirement(&config, checkout, operation, revision));
        committed(&aborted, operation, "aborted", revision + 1);
        expected_events.push((
            revision + 1,
            "aborted".to_string(),
            hold.then(|| "writer_acquire".to_string()),
        ));
        assert_eq!(intent_events(&f, operation), expected_events);
        assert_eq!(source_rows(&f), before);
        assert_eq!(retained_files(&f), physical);
        assert_eq!(events(&f), held_events + 1);
        for retry in [
            wire(abort_retirement(&config, checkout, operation, revision)),
            wire(prepare_retirement(
                &config,
                checkout,
                operation,
                Some(claim),
                true,
            )),
        ] {
            assert_eq!(retry["outcome"], "existing");
            assert_eq!(retry["stage"], "aborted");
            assert_eq!(retry["fresh_commit"], false);
            assert_eq!(retry["fence_active"], false);
        }
        assert_eq!(events(&f), held_events + 1);
        fs::set_permissions(&remote, permissions).unwrap();
        let next = Uuid::now_v7();
        unknown(
            &wire(prepare_retirement(
                &config,
                checkout,
                next,
                Some(claim),
                true,
            )),
            "assertion_invalidated",
        );
        assert_eq!(events(&f), held_events + 1);
        let fresh = assertion(&config, checkout);
        assert_ne!(fresh, claim);
        committed(
            &wire(prepare_retirement(
                &config,
                checkout,
                next,
                Some(fresh),
                true,
            )),
            next,
            "prepared",
            1,
        );
        // Historical A must describe active B truth, not claim fence clearance.
        let count = events(&f);
        for historical in [
            wire(prepare_retirement(
                &config,
                checkout,
                operation,
                Some(claim),
                true,
            )),
            wire(abort_retirement(&config, checkout, operation, revision)),
        ] {
            assert_eq!(historical["outcome"], "existing");
            assert_eq!(historical["stage"], "aborted");
            assert_eq!(historical["fresh_commit"], false);
            assert_eq!(historical["fence_active"], true);
            assert_eq!(historical["history_count"], 2);
        }
        assert_eq!(events(&f), count);
        committed(
            &wire(abort_retirement(&config, checkout, next, 1)),
            next,
            "aborted",
            2,
        );
        assert_eq!(source_rows(&f), before);
    }
}

#[test]
fn public_declaration_operation_and_operator_refusals_follow_genuine_control() {
    let (f, config, claim) = adopted();
    let checkout = f.allocation.checkout;
    let control = Uuid::now_v7();
    committed(
        &wire(prepare_retirement(
            &config,
            checkout,
            control,
            Some(claim),
            true,
        )),
        control,
        "prepared",
        1,
    );
    committed(
        &wire(abort_retirement(&config, checkout, control, 1)),
        control,
        "aborted",
        2,
    );
    let claim = assertion(&config, checkout);
    let before = source_rows(&f);
    let count = events(&f);
    for (operation, complete, expected) in [
        (Uuid::now_v7(), false, "declaration_required"),
        (Uuid::nil(), true, "invalid_operation"),
        (f.allocation.request.operation, true, "intent_conflict"),
    ] {
        unknown(
            &wire(prepare_retirement(
                &config,
                checkout,
                operation,
                Some(claim),
                complete,
            )),
            expected,
        );
        assert_eq!(source_rows(&f), before);
        assert_eq!(events(&f), count);
    }
    let text = fs::read_to_string(&config)
        .unwrap()
        .replace("explicit-operator", "changed-operator");
    fs::write(&config, text).unwrap();
    let refused = wire(prepare_retirement(
        &config,
        checkout,
        Uuid::now_v7(),
        Some(claim),
        true,
    ));
    unknown(&refused, "assertion_invalidated");
    assert_eq!(source_rows(&f), before);
    assert_eq!(events(&f), count);
    // A genuinely new assertion by the current explicit operator is eligible.
    let fresh = assertion(&config, checkout);
    let operation = Uuid::now_v7();
    committed(
        &wire(prepare_retirement(
            &config,
            checkout,
            operation,
            Some(fresh),
            true,
        )),
        operation,
        "prepared",
        1,
    );
}

#[test]
fn cli_adopted_lifecycle_exit_codes_and_unknown_validation_report() {
    let (f, config, claim) = adopted();
    let checkout = f.allocation.checkout.to_string();
    let operation = Uuid::now_v7();
    let op = operation.to_string();
    let args = [
        "retire",
        "prepare",
        &checkout,
        "--operation",
        &op,
        "--assertion",
        &claim.to_string(),
        "--task-complete",
    ];
    let before = source_rows(&f);
    let (out, prepared) = cli(&config, &args);
    assert!(out.status.success(), "{prepared}");
    committed(&prepared, operation, "prepared", 1);
    let (out, retry) = cli(&config, &args);
    assert!(out.status.success(), "{retry}");
    assert_eq!(retry["outcome"], "existing");
    assert_eq!(retry["fresh_commit"], false);
    let (out, status) = cli(&config, &["retire", "status", &checkout]);
    assert!(out.status.success(), "{status}");
    assert_eq!(status["operation"], op);
    assert_eq!(status["revision"], 1);
    assert_eq!(status["fresh_commit"], false);
    let abort_args = [
        "retire",
        "abort",
        &checkout,
        "--operation",
        &op,
        "--revision",
        "1",
    ];
    let (out, aborted) = cli(&config, &abort_args);
    assert!(out.status.success(), "{aborted}");
    committed(&aborted, operation, "aborted", 2);
    let count = events(&f);
    let (out, historical) = cli(&config, &abort_args);
    assert!(out.status.success(), "{historical}");
    assert_eq!(historical["outcome"], "existing");
    assert_eq!(historical["fresh_commit"], false);
    assert_eq!(historical["revision"], 2);
    assert_eq!(events(&f), count);
    assert_eq!(source_rows(&f), before);

    let fresh = assertion(&config, f.allocation.checkout);
    let operation = Uuid::now_v7();
    committed(
        &wire(prepare_retirement(
            &config,
            f.allocation.checkout,
            operation,
            Some(fresh),
            true,
        )),
        operation,
        "prepared",
        1,
    );
    // Flag removal is not an abort bypass. Actual config binding fails and the
    // core may persist a hold; the error wrapper must not claim an absent fence.
    let text = fs::read_to_string(&config)
        .unwrap()
        .replace("prepare_intents=true", "prepare_intents=false");
    fs::write(&config, text).unwrap();
    let (out, refused) = cli(
        &config,
        &[
            "retire",
            "abort",
            &checkout,
            "--operation",
            &operation.to_string(),
            "--revision",
            "1",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    unknown(&refused, "local_binding_changed");
    let (out, held) = cli(&config, &["retire", "status", &checkout]);
    assert!(
        out.status.success(),
        "valid observed held fence is successful status: {held}"
    );
    assert_eq!(held["stage"], "held");
    assert_eq!(held["revision"], 2);
    assert_eq!(source_rows(&f), before);
    // Negative structural corruption is never used as positive prepare evidence.
    rusqlite::Connection::open(f.temp.path().join("authority/store.sqlite"))
        .unwrap()
        .execute(
            "UPDATE retirement_intents SET record='{}' WHERE operation=?1",
            [operation.to_string()],
        )
        .unwrap();
    let count = events(&f);
    let (out, status) = cli(&config, &["retire", "status", &checkout]);
    assert_eq!(out.status.code(), Some(1));
    unknown(&status, "history_unknown");
    let (out, abort) = cli(
        &config,
        &[
            "retire",
            "abort",
            &checkout,
            "--operation",
            &operation.to_string(),
            "--revision",
            "2",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    unknown(&abort, "history_unknown");
    assert_eq!(events(&f), count);
}
