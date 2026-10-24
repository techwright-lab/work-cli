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
fn existing_authority_missing_lock_is_never_repaired_by_inspect() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let config = config(&f);
    let id = f.allocation.checkout.to_string();
    let authority = f.temp.path().join("authority");
    let registry = f.temp.path().join("registry");
    let lock = authority.join("allocation.lock");
    let receipts = authority.join("inspection-receipts-v1");
    // Close the real writable fixture Store BEFORE removing its lock. This is
    // an established current-schema database, not a missing-config substitute.
    drop(f.store);
    fs::remove_file(&lock).unwrap();
    let read = || {
        work_cli::store::Store::open_existing_registered_readonly(
            &registry,
            &authority,
            std::slice::from_ref(&f.root),
        )
        .unwrap()
    };
    let store = read();
    let events = store.pending_events(100).unwrap();
    let charged = store.charged(&f.repo, None).unwrap();
    assert_eq!(charged, 1);
    drop(store);
    let files: Vec<_> = [
        authority.join("store.sqlite"),
        authority.join("store.sqlite-wal"),
        registry.join("authorities.sqlite"),
        registry.join("authorities.sqlite-wal"),
    ]
    .into_iter()
    .map(|path| {
        let bytes = fs::read(&path).unwrap();
        (path, bytes)
    })
    .collect();
    let names = || {
        [&authority, &registry]
            .into_iter()
            .map(|dir| {
                fs::read_dir(dir)
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect::<std::collections::BTreeSet<_>>()
            })
            .collect::<Vec<_>>()
    };
    let before_names = names();
    for record in [false, true] {
        let output = if record {
            command(&config, &["inspect", &id, "--record"])
        } else {
            command(&config, &["inspect", &id])
        };
        assert_eq!(output.status.code(), Some(1), "record={record}: {output:?}");
        assert!(output.stdout.is_empty(), "record={record}: {output:?}");
        assert!(
            !lock.exists(),
            "inspect repaired a missing lock (record={record})"
        );
        assert!(
            !receipts.exists(),
            "inspect created receipts without an existing lock"
        );
        let store = read();
        assert_eq!(store.pending_events(100).unwrap(), events);
        assert_eq!(store.charged(&f.repo, None).unwrap(), charged);
        drop(store);
        // Exact DB/WAL bytes cover all persisted rows, including accounting;
        // existing SHM contents are deliberately not byte-immutability claims.
        for (path, bytes) in &files {
            assert_eq!(&fs::read(path).unwrap(), bytes);
        }
        assert_eq!(names(), before_names);
    }
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
