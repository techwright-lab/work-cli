//! Public retirement-intent fence acceptance. Source-authored; CI-only.
use std::process::Command;
use uuid::Uuid;
use work_cli::inspection::{abort_retirement, prepare_retirement, retirement_status};

fn write_config(temp: &tempfile::TempDir, prepare: bool) -> std::path::PathBuf {
    let path = temp.path().join("config.toml");
    std::fs::write(
        &path,
        format!(
            "store_dir = {store:?}\ntrusted_registry = {registry:?}\nroots = [{root:?}]\n[retirement]\nprepare_intents = {prepare}\n",
            store = temp.path().join("private"),
            registry = temp.path().join(".work-authorities"),
            root = temp.path().join("root"),
        ),
    )
    .unwrap();
    path
}

#[test]
fn disabled_prepare_touches_no_store_or_lock() {
    let temp = tempfile::tempdir().unwrap();
    let path = write_config(&temp, false);
    let report = prepare_retirement(&path, Uuid::now_v7(), Uuid::now_v7(), None, false);
    assert_eq!(report.outcome(), "disabled");
    assert!(
        report.reason() == "implementation_incomplete"
            || report.reason() == "prepare_intents_disabled"
    );
    assert!(!report.fresh_commit());
    assert!(!temp.path().join("private").exists());
    assert!(!temp.path().join("checkout-operations-v1").exists());
}

#[test]
fn status_is_passive_and_abort_stays_inert_pending_local_validation() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("root")).unwrap();
    let path = write_config(&temp, false);
    let checkout = Uuid::now_v7();
    let status = retirement_status(&path, checkout);
    assert!(!status.fresh_commit());
    let aborted = abort_retirement(&path, checkout, Uuid::now_v7(), 1);
    assert_eq!(aborted.outcome(), "disabled");
    assert_eq!(aborted.reason(), "implementation_incomplete");
    assert!(!temp.path().join("private").exists());
    assert!(!aborted.fresh_commit());
}

#[test]
fn cli_help_exposes_retire_without_activation() {
    let output = Command::new(env!("CARGO_BIN_EXE_work"))
        .args(["retire", "--help"])
        .output()
        .expect("work retire help");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("prepare"));
    assert!(text.contains("abort"));
    assert!(text.contains("status"));
}
