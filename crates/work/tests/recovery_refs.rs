//! SOURCE FIRST: run only in the owned-fixture GitHub job, never on the authoring host.
//! Prospective recovery-preparation cases; no local RED/GREEN claim.
#[path = "support/inspection_fixture.rs"]
mod fixture;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::Arc,
    thread,
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
fn configured(f: &fixture::ManagedFixture) -> PathBuf {
    let remote = f.temp.path().join("backup.git");
    fixture::git(
        f.temp.path(),
        &[
            "init".as_ref(),
            "--bare".as_ref(),
            "--template=".as_ref(),
            remote.as_os_str(),
        ],
    );
    let url = format!("file://{}", remote.display());
    f.git(&[
        "remote".as_ref(),
        "add".as_ref(),
        "backup".as_ref(),
        url.as_ref(),
    ]);
    f.git(&[
        "-c".as_ref(),
        "protocol.file.allow=always".as_ref(),
        "push".as_ref(),
        "backup".as_ref(),
        "HEAD:refs/heads/preserved".as_ref(),
    ]);
    let config = f.temp.path().join("config.toml");
    fs::write(&config, format!("store_dir={:?}\ntrusted_registry={:?}\nroots=[{:?}]\n[remote_preservation]\nformat=1\nversion='fixture-v1'\n[[remote_preservation.targets]]\ncommon_dir={:?}\nremote='backup'\nurl={url:?}\nbranch='refs/heads/preserved'\n[capture]\nexecutable=false\n", f.temp.path().join("authority"), f.temp.path().join("registry"), f.root, f.common())).unwrap();
    config
}
fn prepare(config: &Path, checkout: Uuid, operation: Uuid) -> (Output, serde_json::Value) {
    let out = command(
        config,
        &[
            "prepare-recovery",
            &checkout.to_string(),
            "--create",
            "--operation",
            &operation.to_string(),
        ],
    );
    let report = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{out:?}"));
    (out, report)
}
fn object_git(f: &fixture::ManagedFixture, args: &[&str], input: &[u8]) -> String {
    let mut child = Command::new("/usr/bin/git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "user.name=Owned Fixture",
            "-c",
            "user.email=fixture@invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "pack.writeReverseIndex=false",
        ])
        .args(args)
        .current_dir(&f.allocation.destination)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "owned object creation failed");
    String::from_utf8(output.stdout)
        .unwrap()
        .trim_end()
        .to_owned()
}
fn original(path: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = vec![];
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(original(&path));
        } else {
            out.push((path.clone(), fs::read(path).unwrap()));
        }
    }
    out.sort();
    out
}
fn sql_bytes(f: &fixture::ManagedFixture) -> Vec<Vec<u8>> {
    ["store.sqlite", "store.sqlite-wal"]
        .into_iter()
        .map(|name| fs::read(f.temp.path().join("authority").join(name)).unwrap())
        .collect()
}
fn recovery_ref(checkout: Uuid, format: &str, oid: &str) -> String {
    format!("refs/work-recovery/{checkout}/{format}/{oid}")
}
fn loose_ref(f: &fixture::ManagedFixture, name: &str) -> PathBuf {
    f.common().join(name)
}
fn assert_truth(report: &serde_json::Value) {
    assert_eq!(report["retirement_authority"], false);
    let limitation = report["limitation"].as_str().unwrap();
    assert!(limitation.contains("LOCAL"));
    assert!(!limitation.to_lowercase().contains("backup success"));
}

#[test]
fn missing_create_flag_does_not_mutate_and_directs_audit() {
    let f = fixture::ManagedFixture::recovery("sha1", "2");
    let config = configured(&f);
    let before = original(f.common());
    let authority = sql_bytes(&f);
    let checkout = f.allocation.checkout.to_string();
    let operation = Uuid::now_v7().to_string();
    for args in [
        vec!["prepare-recovery", &checkout],
        vec!["prepare-recovery", &checkout, "--operation", &operation],
        vec!["prepare-recovery", &checkout, "--create"],
    ] {
        let out = command(&config, &args);
        assert_eq!(out.status.code(), Some(1), "{args:?} {out:?}");
        let report: serde_json::Value =
            serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{out:?}"));
        assert_eq!(report["retirement_authority"], false);
        assert_ne!(report["outcome"], "prepared");
        let text = format!("{report}{}", String::from_utf8_lossy(&out.stderr));
        assert!(text.contains("audit-preservation"), "{args:?}: {text}");
        assert_eq!(original(f.common()), before);
        assert_eq!(sql_bytes(&f), authority);
        assert!(!f.common().join("refs/work-recovery").exists());
        assert!(!f
            .temp
            .path()
            .join("authority/inspection-receipts-v1")
            .exists());
    }
}

#[test]
fn sha1_create_protects_exact_oids_and_preserves_ordinary_git() {
    let f = fixture::ManagedFixture::recovery("sha1", "2");
    let config = configured(&f);
    let head = object_git(&f, &["rev-parse", "HEAD"], b"");
    let branch = fs::read(f.common().join("HEAD")).unwrap();
    let index = fs::read(f.private().join("index")).unwrap();
    let payload = fs::read(f.path(b"tracked")).unwrap();
    let logs = original(&f.private().join("logs"));
    let before_sql = sql_bytes(&f);
    let operation = Uuid::now_v7();
    let (out, report) = prepare(&config, f.allocation.checkout, operation);
    assert!(out.status.success(), "{report}");
    assert_eq!(report["outcome"], "prepared");
    assert_eq!(report["operation"], operation.to_string());
    assert_eq!(report["durability"], "acknowledged");
    assert_eq!(report["resume"], false);
    assert_truth(&report);
    let name = recovery_ref(f.allocation.checkout, "sha1", &head);
    assert_eq!(
        fs::read_to_string(loose_ref(&f, &name)).unwrap().trim(),
        head
    );
    assert!(!f.common().join(format!("logs/{name}")).exists());
    assert_eq!(fs::read(f.common().join("HEAD")).unwrap(), branch);
    assert_eq!(fs::read(f.private().join("index")).unwrap(), index);
    assert_eq!(fs::read(f.path(b"tracked")).unwrap(), payload);
    assert_eq!(original(&f.private().join("logs")), logs);
    assert_eq!(sql_bytes(&f), before_sql);
}

#[test]
fn sha256_create_uses_exact_format_in_generated_names() {
    let f = fixture::ManagedFixture::recovery("sha256", "2");
    let config = configured(&f);
    let head = object_git(&f, &["rev-parse", "HEAD"], b"");
    let operation = Uuid::now_v7();
    let (out, report) = prepare(&config, f.allocation.checkout, operation);
    assert!(out.status.success(), "{report}");
    let name = recovery_ref(f.allocation.checkout, "sha256", &head);
    assert!(report["created_refs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == &name));
    assert_eq!(
        fs::read_to_string(loose_ref(&f, &name)).unwrap().trim(),
        head
    );
}

#[test]
fn exact_retry_is_historical_and_does_not_rewrite() {
    let f = fixture::ManagedFixture::recovery("sha1", "2");
    let config = configured(&f);
    let operation = Uuid::now_v7();
    let (first_out, first) = prepare(&config, f.allocation.checkout, operation);
    assert!(first_out.status.success(), "{first}");
    let refs = original(&f.common().join("refs/work-recovery"));
    let receipts = original(&f.temp.path().join("authority/inspection-receipts-v1"));
    let (out, report) = prepare(&config, f.allocation.checkout, operation);
    assert!(out.status.success(), "{report}");
    assert_eq!(report["outcome"], "historical");
    assert_eq!(report["durability"], "historical");
    assert_eq!(report["resume"], true);
    assert_eq!(report["retirement_authority"], false);
    assert_eq!(original(&f.common().join("refs/work-recovery")), refs);
    assert_eq!(
        original(&f.temp.path().join("authority/inspection-receipts-v1")),
        receipts
    );
}

#[test]
fn packed_and_loose_unreachable_and_standalone_objects_are_protected() {
    let f = fixture::ManagedFixture::recovery("sha1", "2");
    let config = configured(&f);
    let tree = object_git(&f, &["rev-parse", "HEAD^{tree}"], b"");
    let packed = object_git(&f, &["commit-tree", &tree, "-m", "packed unreachable"], b"");
    let prefix = f.common().join("objects/pack/pack");
    object_git(
        &f,
        &["pack-objects", prefix.to_str().unwrap()],
        format!("{packed}\n").as_bytes(),
    );
    fs::remove_file(
        f.common()
            .join("objects")
            .join(&packed[..2])
            .join(&packed[2..]),
    )
    .unwrap();
    let loose = object_git(&f, &["commit-tree", &tree, "-m", "loose unreachable"], b"");
    let blob = object_git(
        &f,
        &["hash-object", "-w", "--stdin"],
        b"unclassified payload",
    );
    let standalone_tree = object_git(
        &f,
        &["mktree"],
        format!("100644 blob {blob}\tstandalone\n").as_bytes(),
    );
    let tag = object_git(
        &f,
        &["mktag"],
        format!("object {blob}\ntype blob\ntag unattached\ntagger Owned Fixture <fixture@invalid> 1 +0000\n\nstandalone tag\n").as_bytes(),
    );
    let inner = object_git(
        &f,
        &["mktag"],
        format!("object {tag}\ntype tag\ntag chain\ntagger Owned Fixture <fixture@invalid> 1 +0000\n\nchain\n").as_bytes(),
    );
    let (out, report) = prepare(&config, f.allocation.checkout, Uuid::now_v7());
    assert!(out.status.success(), "{report}");
    assert!(!report["additional_work_holds"]
        .as_array()
        .unwrap()
        .is_empty());
    for id in [&packed, &loose, &blob, &standalone_tree, &tag, &inner] {
        let name = recovery_ref(f.allocation.checkout, "sha1", id);
        assert_eq!(
            fs::read_to_string(loose_ref(&f, &name)).unwrap().trim(),
            *id,
            "{name}"
        );
        assert!(!f.common().join(format!("logs/{name}")).exists());
    }
}

#[test]
fn reflog_only_work_is_protected_while_remote_and_additional_holds_remain() {
    let f = fixture::ManagedFixture::recovery("sha1", "2");
    let config = configured(&f);
    let head = object_git(&f, &["rev-parse", "HEAD"], b"");
    let tree = object_git(&f, &["rev-parse", "HEAD^{tree}"], b"");
    let old = object_git(&f, &["commit-tree", &tree, "-m", "deleted work"], b"");
    f.git(&[
        "update-ref".as_ref(),
        "refs/heads/deleted".as_ref(),
        old.as_ref(),
    ]);
    f.git(&[
        "update-ref".as_ref(),
        "-d".as_ref(),
        "refs/heads/deleted".as_ref(),
    ]);
    let log = f.private().join("logs/HEAD");
    let mut bytes = fs::read(&log).unwrap();
    bytes.extend(
        format!("{old} {head} Owned Fixture <fixture@invalid> 1 +0000\tDO_NOT_ECHO\n").bytes(),
    );
    fs::write(&log, bytes).unwrap();
    let (out, report) = prepare(&config, f.allocation.checkout, Uuid::now_v7());
    assert!(out.status.success(), "{report}");
    assert!(report["additional_work_holds"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["reason"] == "unpreserved_object"));
    assert_eq!(
        fs::read_to_string(loose_ref(
            &f,
            &recovery_ref(f.allocation.checkout, "sha1", &old)
        ))
        .unwrap()
        .trim(),
        old
    );
    assert!(!report.to_string().contains("DO_NOT_ECHO"));
}

#[test]
fn ordinary_branch_index_payload_and_logs_are_invariant() {
    let f = fixture::ManagedFixture::recovery("sha1", "2");
    let config = configured(&f);
    let before_common = original(f.common());
    let before_private_logs = original(&f.private().join("logs"));
    let tracked = fs::read(f.path(b"tracked")).unwrap();
    let index = fs::read(f.private().join("index")).unwrap();
    let head = fs::read(f.common().join("HEAD")).unwrap();
    let (out, report) = prepare(&config, f.allocation.checkout, Uuid::now_v7());
    assert!(out.status.success(), "{report}");
    assert_eq!(fs::read(f.path(b"tracked")).unwrap(), tracked);
    assert_eq!(fs::read(f.private().join("index")).unwrap(), index);
    assert_eq!(fs::read(f.common().join("HEAD")).unwrap(), head);
    assert_eq!(original(&f.private().join("logs")), before_private_logs);
    let after = original(f.common());
    for (path, bytes) in &before_common {
        if path.starts_with(&f.common().join("refs/work-recovery")) {
            continue;
        }
        assert_eq!(
            after.iter().find(|(p, _)| p == path).map(|(_, b)| b),
            Some(bytes),
            "{path:?}"
        );
    }
}

#[test]
fn conflicts_symrefs_and_stale_locks_hold_without_overwrite() {
    let f = fixture::ManagedFixture::recovery("sha1", "2");
    let config = configured(&f);
    let head = object_git(&f, &["rev-parse", "HEAD"], b"");
    let name = recovery_ref(f.allocation.checkout, "sha1", &head);
    fs::create_dir_all(loose_ref(&f, &name).parent().unwrap()).unwrap();
    fs::write(loose_ref(&f, &name), b"ref: refs/heads/main\n").unwrap();
    let before = fs::read(loose_ref(&f, &name)).unwrap();
    let (out, report) = prepare(&config, f.allocation.checkout, Uuid::now_v7());
    assert_eq!(out.status.code(), Some(1), "{report}");
    assert_ne!(report["outcome"], "prepared");
    assert_eq!(fs::read(loose_ref(&f, &name)).unwrap(), before);
}

#[test]
fn missing_and_corrupt_inputs_hold_without_git_mutation() {
    let f = fixture::ManagedFixture::recovery("sha1", "2");
    let config = configured(&f);
    fs::write(f.private().join("logs/HEAD"), b"DO_NOT_ECHO\n").unwrap();
    let before = original(f.common());
    let (out, report) = prepare(&config, f.allocation.checkout, Uuid::now_v7());
    assert_eq!(out.status.code(), Some(1), "{report}");
    assert_eq!(original(f.common()), before);
    assert!(!f.common().join("refs/work-recovery").exists());
    assert!(!report.to_string().contains("DO_NOT_ECHO"));
}

#[test]
fn concurrent_preparers_serialize_on_the_same_store() {
    let f = fixture::ManagedFixture::recovery("sha1", "2");
    let config = configured(&f);
    let checkout = f.allocation.checkout;
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    let config = Arc::new(config);
    let left = {
        let config = Arc::clone(&config);
        thread::spawn(move || prepare(&config, checkout, a))
    };
    let right = {
        let config = Arc::clone(&config);
        thread::spawn(move || prepare(&config, checkout, b))
    };
    let (_, first) = left.join().unwrap();
    let (_, second) = right.join().unwrap();
    let prepared = [&first, &second]
        .iter()
        .filter(|r| r["outcome"] == "prepared")
        .count();
    let held = [&first, &second]
        .iter()
        .filter(|r| r["outcome"] != "prepared" && r["outcome"] != "historical")
        .count();
    assert_eq!(prepared + held, 2, "{first} {second}");
    assert!(prepared >= 1, "{first} {second}");
}

#[test]
fn cli_help_and_invalid_ids_are_sanitized_without_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("absent.toml");
    let help = command(&config, &["prepare-recovery", "--help"]);
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("--create"));
    assert!(text.contains("--operation"));
    for flag in ["--url", "--delete", "--approve", "--record"] {
        assert!(!text.contains(flag));
    }
    for args in [
        vec!["prepare-recovery", "DO_NOT_ECHO"],
        vec!["prepare-recovery", "--url", "DO_NOT_ECHO"],
        vec!["prepare-recovery", "00000000-0000-0000-0000-000000000000"],
    ] {
        let out = command(&config, &args);
        assert_eq!(out.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&out.stderr).contains("DO_NOT_ECHO"));
    }
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
}

#[test]
fn earlier_approval_is_invalidated_and_receipts_are_not_rewritten() {
    let f = fixture::ManagedFixture::recovery("sha1", "2");
    let (config, _) = f.approval();
    let begin = command(
        &config,
        &["approve", "begin", &f.allocation.checkout.to_string()],
    );
    let value: serde_json::Value = serde_json::from_slice(&begin.stdout).unwrap();
    assert!(begin.status.success(), "{value}");
    let id = Uuid::parse_str(value["receipt_id"].as_str().unwrap()).unwrap();
    let path = f
        .temp
        .path()
        .join(format!("authority/inspection-receipts-v1/{id}.receipt"));
    let bytes = fs::read(&path).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let (out, report) = prepare(&config, f.allocation.checkout, Uuid::now_v7());
    assert!(out.status.success(), "{report}");
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let confirm = command(
        &config,
        &[
            "approve",
            "confirm",
            &f.allocation.checkout.to_string(),
            "--observation",
            &id.to_string(),
            "--assert-quiescent",
        ],
    );
    assert!(!confirm.status.success());
    assert_eq!(fs::read(&path).unwrap(), bytes);
}
