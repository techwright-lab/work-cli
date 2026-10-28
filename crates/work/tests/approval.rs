//! Test source first; execution belongs exclusively to parent-owned isolated CI.
#[path = "support/inspection_fixture.rs"]
mod fixture;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
    time::Duration,
};
use uuid::Uuid;
use work_cli as work_cli_api;

fn command(config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_work"))
        .env_clear()
        .env("WORK_CONFIG", config)
        .args(args)
        .output()
        .unwrap()
}
fn report(config: &Path, args: &[&str]) -> (Output, serde_json::Value) {
    let out = command(config, args);
    let value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{out:?}"));
    (out, value)
}
fn baseline(f: &fixture::ManagedFixture, config: &Path) -> Uuid {
    let (out, value) = report(
        config,
        &["approve", "begin", &f.allocation.checkout.to_string()],
    );
    assert!(out.status.success(), "{value}");
    assert_eq!(value["retirement_authority"], false);
    assert_eq!(value["automatic_quiescence"], false);
    assert_eq!(value["preservation"]["remote_head"]["transport"], "LOCAL");
    assert_eq!(
        value["preservation"]["inspection_findings"],
        serde_json::json!([])
    );
    Uuid::parse_str(value["receipt_id"].as_str().unwrap()).unwrap()
}
fn confirm(f: &fixture::ManagedFixture, config: &Path, id: Uuid) -> (Output, serde_json::Value) {
    report(
        config,
        &[
            "approve",
            "confirm",
            &f.allocation.checkout.to_string(),
            "--observation",
            &id.to_string(),
            "--assert-quiescent",
        ],
    )
}
fn sql_bytes(f: &fixture::ManagedFixture) -> Vec<Vec<u8>> {
    ["store.sqlite", "store.sqlite-wal"]
        .into_iter()
        .map(|name| fs::read(f.temp.path().join("authority").join(name)).unwrap())
        .collect()
}
#[test]
fn adopted_two_observations_retain_writer_and_every_sql_byte_no_renewal() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let (config, request) = f.approval();
    let status = f.store.adopted_status(&request.identity.run).unwrap();
    let before = sql_bytes(&f);
    let id = baseline(&f, &config);
    // One bounded real CLI interval, not a minutes-long test or performance gate.
    std::thread::sleep(Duration::from_millis(1100));
    let (out, value) = confirm(&f, &config, id);
    assert!(out.status.success(), "{value}");
    assert_eq!(value["outcome"], "operator_assertion");
    assert_eq!(value["retirement_authority"], false);
    assert_eq!(value["automatic_quiescence"], false);
    assert_eq!(
        f.store.adopted_status(&request.identity.run).unwrap(),
        status
    );
    assert_eq!(sql_bytes(&f), before);
    let assertion = Uuid::parse_str(value["receipt_id"].as_str().unwrap()).unwrap();
    let bytes = fs::read(f.temp.path().join(format!(
        "authority/inspection-receipts-v1/{assertion}.receipt"
    )))
    .unwrap();
    assert!(bytes
        .windows(b"work.inspection.receipt.v2".len())
        .any(|v| v == b"work.inspection.receipt.v2"));
    assert!(!confirm(&f, &config, id).0.status.success());
    assert_eq!(
        fs::read(f.temp.path().join(format!(
            "authority/inspection-receipts-v1/{assertion}.receipt"
        )))
        .unwrap(),
        bytes
    );
    assert_eq!(sql_bytes(&f), before);
    assert!(!f.common().join("refs/work-recovery").exists());
}
#[test]
fn explicit_flag_canonical_ids_and_sanitized_help_without_config() {
    let t = tempfile::tempdir().unwrap();
    let config = t.path().join("missing");
    for args in [
        vec!["approve", "--help"],
        vec!["approve", "begin", "--help"],
        vec!["approve", "confirm", "--help"],
    ] {
        assert!(command(&config, &args).status.success());
    }
    let checkout = Uuid::now_v7().to_string();
    for args in [
        vec!["approve"],
        vec!["approve", "begin", "secret-invalid-id"],
        vec![
            "approve",
            "confirm",
            &checkout,
            "--observation",
            "secret-invalid-id",
            "--assert-quiescent",
        ],
    ] {
        let out = command(&config, &args);
        assert_eq!(out.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&out.stderr).contains("secret-invalid-id"));
    }
    let (_, value) = report(&config, &["approve", "begin", &checkout]);
    assert_eq!(value["recorded"], false);
    assert_eq!(value["retirement_authority"], false);
    assert!(!config.exists());
}
#[test]
fn missing_assertion_wrong_receipt_and_v1_are_ineligible() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    let (config, _) = f.approval();
    let id = baseline(&f, &config);
    let out = command(
        &config,
        &[
            "approve",
            "confirm",
            &f.allocation.checkout.to_string(),
            "--observation",
            &id.to_string(),
        ],
    );
    assert!(!out.status.success());
    assert!(!confirm(&f, &config, Uuid::now_v7()).0.status.success());
    let policies = work_cli::disposal::validate(work_cli::disposal::PolicyDocument {
        format: 1,
        policies: vec![],
    })
    .unwrap();
    let old =
        work_cli::inspection::inspect_and_record(&mut f.store, f.allocation.checkout, &policies)
            .unwrap()
            .receipt
            .unwrap();
    assert_eq!(
        work_cli::inspection::read_receipt(&f.store, old.id())
            .unwrap()
            .id(),
        old.id()
    );
    let (_, held) = confirm(&f, &config, old.id());
    assert_eq!(held["reason"], "baseline_ineligible");
}
#[test]
fn observed_activity_and_returned_bytes_invalidate_while_noop_does_not_write() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    let (config, request) = f.approval();
    let event = fixture::ManagedFixture::activity(&request);
    f.store.record_activity(&event).unwrap();
    let id = baseline(&f, &config);
    let before = sql_bytes(&f);
    let mut retry = event.clone();
    retry.observed_at += 1;
    assert_eq!(
        f.store.record_activity(&retry).unwrap(),
        work_cli::run_journal::Transition::Existing
    );
    assert_eq!(sql_bytes(&f), before);
    let original = fs::read(f.path(b"tracked")).unwrap();
    fs::write(f.path(b"tracked"), b"transient activity").unwrap();
    fs::write(f.path(b"tracked"), original).unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    assert!(!confirm(&f, &config, id).0.status.success());
    let fresh = baseline(&f, &config);
    retry.event_ref = work_cli::participants::Ref::new("stop-2".into()).unwrap();
    f.store.record_activity(&retry).unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    assert!(!confirm(&f, &config, fresh).0.status.success());
}
#[test]
fn content_holds_are_printed_and_unrelated_malformed_policy_stays_lazy() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let (config, _) = f.approval();
    fs::write(f.path(b"unpreserved"), b"not a disposable cache").unwrap();
    let (out, value) = report(
        &config,
        &["approve", "begin", &f.allocation.checkout.to_string()],
    );
    assert!(!out.status.success());
    assert_eq!(value["recorded"], false);
    assert!(!value["preservation"]["inspection_findings"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(!f
        .temp
        .path()
        .join("authority/inspection-receipts-v1")
        .exists());
    let text = fs::read_to_string(&config)
        .unwrap()
        .replace("quiet_window_seconds=1", "quiet_window_seconds=false");
    fs::write(&config, text).unwrap();
    assert!(command(
        &config,
        &["verify-remote", &f.allocation.checkout.to_string()]
    )
    .status
    .success());
}
#[test]
fn config_replacement_operator_change_and_other_checkout_refuse() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let (config, _) = f.approval();
    let id = baseline(&f, &config);
    let (out, _) = report(
        &config,
        &[
            "approve",
            "confirm",
            &Uuid::now_v7().to_string(),
            "--observation",
            &id.to_string(),
            "--assert-quiescent",
        ],
    );
    assert!(!out.status.success());
    let text = fs::read_to_string(&config).unwrap();
    fs::write(
        &config,
        text.replace("explicit-operator", "another-operator"),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    assert!(!confirm(&f, &config, id).0.status.success());
    fs::write(&config, text).unwrap();
    assert!(!confirm(&f, &config, id).0.status.success());
}
