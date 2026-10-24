//! SOURCE FIRST; native subprocess fixtures run only in isolated CI.
#[path = "support/inspection_fixture.rs"]
mod fixture;
use std::{
    fs,
    process::{Command, Output},
};
use work_cli as work_cli_api;
fn command(config: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_work"))
        .env_clear()
        .env("WORK_CONFIG", config)
        .args(args)
        .output()
        .unwrap()
}
fn config(f: &fixture::ManagedFixture) -> std::path::PathBuf {
    let path = f.temp.path().join("config.toml");
    fs::write(&path, format!("store_dir = {:?}\ntrusted_registry = {:?}\nroots = [{:?}]\n[supervisor]\nactors = false\n[capture]\nexecutable = 42\n[allocation]\ncapture_sink = false\n", f.temp.path().join("authority"), f.temp.path().join("registry"), f.root)).unwrap();
    path
}
#[test]
fn help_invalid_arguments_and_missing_authority_are_readonly_redacted() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("missing.toml");
    let help = command(&config, &["inspect", "--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--record"));
    for args in [
        vec!["inspect", "secret-token-invalid"],
        vec!["inspect", "--secret-token-invalid"],
        vec!["inspect", "00000000-0000-0000-0000-000000000000"],
    ] {
        let output = command(&config, &args);
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-token"));
        assert!(output.stdout.is_empty());
    }
    let id = uuid::Uuid::now_v7().to_string();
    assert!(!command(&config, &["inspect", &id, "--record"])
        .status
        .success());
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
}
#[test]
fn default_json_is_nondurable_record_is_explicit_and_findings_hold() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let config = config(&f);
    let id = f.allocation.checkout.to_string();
    let directory = f.temp.path().join("authority/inspection-receipts-v1");
    let output = command(&config, &["inspect", &id]);
    assert!(output.status.success(), "{:?}", output);
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["coverage"], "complete");
    assert_eq!(json["recorded"], false);
    assert!(json.get("receipt_id").is_none());
    assert!(!directory.exists());
    let keys: std::collections::BTreeSet<_> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "coverage",
            "counts",
            "digest",
            "findings",
            "recorded",
            "recording"
        ]
        .into_iter()
        .collect()
    );
    let output = command(&config, &["inspect", &id, "--record"]);
    assert!(output.status.success(), "{:?}", output);
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["recorded"], true);
    let receipt = uuid::Uuid::parse_str(json["receipt_id"].as_str().unwrap()).unwrap();
    assert!(directory.join(format!("{receipt}.receipt")).exists());
    fs::write(f.path(b"payload-secret-name"), b"payload-secret-value").unwrap();
    let output = command(&config, &["inspect", &id]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("payload-secret"));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["coverage"], "complete");
    assert!(json["findings"]["untracked"].as_u64().unwrap() > 0);
    // Unsafe receipt state must not silently turn --record into success.
    fs::write(directory.join("unknown"), b"x").unwrap();
    let output = command(&config, &["inspect", &id, "--record"]);
    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["recorded"], false);
    assert_eq!(json["recording"], "unsafe_receipt_store");
}
#[test]
fn incomplete_json_has_nonzero_status() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let config = config(&f);
    std::os::unix::fs::symlink("tracked", f.path(b"link")).unwrap();
    let output = command(&config, &["inspect", &f.allocation.checkout.to_string()]);
    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["coverage"], "incomplete");
    assert_eq!(json["recorded"], false);
}
