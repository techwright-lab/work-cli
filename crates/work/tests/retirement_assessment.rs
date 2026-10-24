//! SOURCE FIRST: run only in the owned-fixture GitHub job, never on the authoring host.
//! Non-destructive assessment prerequisite; no local RED/GREEN claim.
#[path = "support/inspection_fixture.rs"]
mod fixture;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::Duration,
};
use uuid::Uuid;
use work_cli as work_cli_api;
use work_cli::inspection::{assess_retirement, RetirementAssessmentReport};

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
fn sql_bytes(f: &fixture::ManagedFixture) -> Vec<Vec<u8>> {
    ["store.sqlite", "store.sqlite-wal"]
        .into_iter()
        .map(|name| fs::read(f.temp.path().join("authority").join(name)).unwrap())
        .collect()
}
fn writer_count(f: &fixture::ManagedFixture) -> i64 {
    let sql = rusqlite::Connection::open(f.temp.path().join("authority/store.sqlite")).unwrap();
    sql.query_row("SELECT count(*) FROM writers", [], |r| r.get(0))
        .unwrap()
}
fn finish_count(f: &fixture::ManagedFixture) -> i64 {
    let sql = rusqlite::Connection::open(f.temp.path().join("authority/store.sqlite")).unwrap();
    sql.query_row("SELECT count(*) FROM task_finishes", [], |r| r.get(0))
        .unwrap()
}
fn recovery_refs(f: &fixture::ManagedFixture) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let root = f.common().join("refs/work-recovery");
    if !root.exists() {
        return out;
    }
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    walk(&root, &mut out);
    out.sort();
    out
}
fn prepare(config: &Path, checkout: Uuid) -> serde_json::Value {
    let (_out, value) = report(
        config,
        &[
            "prepare-recovery",
            &checkout.to_string(),
            "--create",
            "--operation",
            &Uuid::now_v7().to_string(),
        ],
    );
    value
}
fn assert_disabled(report: &RetirementAssessmentReport) {
    assert!(!report.execution_enabled());
    assert!(!report.retirement_authority());
    assert!(report.writer_charges_retained());
}

#[test]
fn public_wrapper_holds_unknown_configuration_without_driver() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing.toml");
    let report = assess_retirement(&missing, Uuid::now_v7(), None);
    assert_eq!(report.outcome(), "held");
    assert_disabled(&report);
}

#[test]
fn invalid_checkout_holds() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let path = f.temp.path().join("config.toml");
    fs::write(&path, "store_dir='/tmp'\n").unwrap();
    let report = assess_retirement(&path, Uuid::nil(), None);
    assert_eq!(report.reason(), "invalid_checkout");
    assert_disabled(&report);
}

#[test]
fn missing_allocation_lock_holds() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let (config, _) = f.approval();
    fs::remove_file(f.temp.path().join("authority/allocation.lock")).unwrap();
    let report = assess_retirement(&config, f.allocation.checkout, None);
    assert_eq!(report.outcome(), "held");
    assert_disabled(&report);
}

#[test]
fn missing_recovery_lock_holds_without_prepare() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let (config, _) = f.approval();
    let before_sql = sql_bytes(&f);
    let before_writers = writer_count(&f);
    let before_refs = recovery_refs(&f);
    let report = assess_retirement(&config, f.allocation.checkout, None);
    assert_eq!(report.outcome(), "held");
    assert_eq!(report.reason(), "preparation_required");
    assert_disabled(&report);
    assert_eq!(sql_bytes(&f), before_sql);
    assert_eq!(writer_count(&f), before_writers);
    assert_eq!(recovery_refs(&f), before_refs);
}

#[test]
fn adopted_after_prepare_begin_confirm_keeps_writer_and_requires_declaration() {
    let f = fixture::ManagedFixture::recovery("sha1", "2");
    let (config, request) = f.approval();
    let prepared = prepare(&config, f.allocation.checkout);
    assert_ne!(prepared["outcome"], "held", "{prepared}");
    let (out, begin) = report(
        &config,
        &["approve", "begin", &f.allocation.checkout.to_string()],
    );
    assert!(out.status.success(), "{begin}");
    std::thread::sleep(Duration::from_millis(1100));
    let (out, confirm) = report(
        &config,
        &[
            "approve",
            "confirm",
            &f.allocation.checkout.to_string(),
            "--observation",
            begin["receipt_id"].as_str().unwrap(),
            "--assert-quiescent",
        ],
    );
    assert!(out.status.success(), "{confirm}");
    let assertion = Uuid::parse_str(confirm["receipt_id"].as_str().unwrap()).unwrap();
    let before_sql = sql_bytes(&f);
    let before_writers = writer_count(&f);
    let before_finish = finish_count(&f);
    let before_refs = recovery_refs(&f);
    let before_status = f.store.adopted_status(&request.identity.run).unwrap();
    let report = assess_retirement(&config, f.allocation.checkout, Some(assertion));
    assert_disabled(&report);
    assert_eq!(report.mode(), "adopted", "{:?}", report.reason());
    assert_eq!(
        report.quiescence(),
        "operator_assertion",
        "{}",
        report.reason()
    );
    assert_eq!(report.task_completion(), "declaration_required");
    assert_eq!(
        report.outcome(),
        "prerequisites_complete",
        "{}",
        report.reason()
    );
    assert_eq!(sql_bytes(&f), before_sql);
    assert_eq!(writer_count(&f), before_writers);
    assert_eq!(finish_count(&f), before_finish);
    assert_eq!(recovery_refs(&f), before_refs);
    assert_eq!(
        f.store.adopted_status(&request.identity.run).unwrap(),
        before_status
    );
}

#[test]
fn adopted_without_assertion_holds() {
    let f = fixture::ManagedFixture::recovery("sha1", "2");
    let (config, _) = f.approval();
    let _ = prepare(&config, f.allocation.checkout);
    let report = assess_retirement(&config, f.allocation.checkout, None);
    assert_eq!(report.outcome(), "held");
    assert_eq!(report.reason(), "adopted_assertion_required");
    assert_disabled(&report);
}

#[test]
fn adopted_baseline_observation_is_ineligible() {
    let f = fixture::ManagedFixture::recovery("sha1", "2");
    let (config, _) = f.approval();
    let _ = prepare(&config, f.allocation.checkout);
    let (out, begin) = report(
        &config,
        &["approve", "begin", &f.allocation.checkout.to_string()],
    );
    assert!(out.status.success(), "{begin}");
    let baseline = Uuid::parse_str(begin["receipt_id"].as_str().unwrap()).unwrap();
    let report = assess_retirement(&config, f.allocation.checkout, Some(baseline));
    assert_eq!(report.outcome(), "held");
    assert_eq!(report.reason(), "assertion_ineligible");
    assert_disabled(&report);
}

#[test]
fn dirty_work_holds_and_does_not_mutate() {
    let f = fixture::ManagedFixture::recovery("sha1", "2");
    let (config, _) = f.approval();
    let _ = prepare(&config, f.allocation.checkout);
    fs::write(f.allocation.destination.join("untracked"), b"dirty").unwrap();
    let before_sql = sql_bytes(&f);
    let before_refs = recovery_refs(&f);
    let report = assess_retirement(&config, f.allocation.checkout, None);
    assert_eq!(report.outcome(), "held");
    assert_disabled(&report);
    assert_eq!(sql_bytes(&f), before_sql);
    assert_eq!(recovery_refs(&f), before_refs);
}

#[test]
fn pre_prepare_assertion_is_invalidated_by_recovery_creation() {
    let f = fixture::ManagedFixture::recovery("sha1", "2");
    let (config, _) = f.approval();
    let (out, begin) = report(
        &config,
        &["approve", "begin", &f.allocation.checkout.to_string()],
    );
    assert!(out.status.success(), "{begin}");
    std::thread::sleep(Duration::from_millis(1100));
    let (out, confirm) = report(
        &config,
        &[
            "approve",
            "confirm",
            &f.allocation.checkout.to_string(),
            "--observation",
            begin["receipt_id"].as_str().unwrap(),
            "--assert-quiescent",
        ],
    );
    assert!(out.status.success(), "{confirm}");
    let assertion = Uuid::parse_str(confirm["receipt_id"].as_str().unwrap()).unwrap();
    let _ = prepare(&config, f.allocation.checkout);
    let report = assess_retirement(&config, f.allocation.checkout, Some(assertion));
    assert_eq!(report.outcome(), "held");
    assert_eq!(report.reason(), "assertion_invalidated");
    assert_disabled(&report);
}
