//! SOURCE FIRST. Owned local bare remotes only; execute in isolated CI, not on the authoring host.
#[path = "support/inspection_fixture.rs"]
mod fixture;
use std::{
    fs,
    path::PathBuf,
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
fn configured(f: &fixture::ManagedFixture) -> (PathBuf, PathBuf) {
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
    let path = f.temp.path().join("config.toml");
    fs::write(&path, format!("store_dir={:?}\ntrusted_registry={:?}\nroots=[{:?}]\n[remote_preservation]\nformat=1\nversion='fixture-v1'\n[[remote_preservation.targets]]\ncommon_dir={:?}\nremote='backup'\nurl={:?}\nbranch='refs/heads/preserved'\n[supervisor]\nactors=false\n[capture]\nexecutable=42\n", f.temp.path().join("authority"), f.temp.path().join("registry"), f.root, f.common(), url)).unwrap();
    (path, remote)
}
fn observe(f: &fixture::ManagedFixture, config: &std::path::Path) -> Output {
    command(
        config,
        &["verify-remote", &f.allocation.checkout.to_string()],
    )
}
fn original(f: &fixture::ManagedFixture) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = vec![
        f.private().join("index"),
        f.private().join("HEAD"),
        f.common().join("config"),
        f.common().join("refs/heads/inspection"),
        f.common().join("refs/heads/main"),
    ];
    for name in ["store.sqlite", "store.sqlite-wal"] {
        let path = f.temp.path().join("authority").join(name);
        if path.exists() {
            files.push(path);
        }
    }
    files
        .into_iter()
        .map(|p| {
            let bytes = fs::read(&p).unwrap();
            (p, bytes)
        })
        .collect()
}
#[test]
fn native_local_observation_is_nondurable_and_does_not_mutate_original_inputs() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let (config, remote) = configured(&f);
    // Legitimately advance HEAD after allocation; the allocation HEAD is not current authority.
    fs::write(f.path(b"tracked"), b"advanced\n").unwrap();
    f.git(&["commit".as_ref(), "-am".as_ref(), "advance".as_ref()]);
    f.git(&[
        "-c".as_ref(),
        "protocol.file.allow=always".as_ref(),
        "push".as_ref(),
        "backup".as_ref(),
        "HEAD:refs/heads/preserved".as_ref(),
    ]);
    let before = original(&f);
    let output = observe(&f, &config);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["outcome"], "observed");
    assert_eq!(report["transport"], "LOCAL");
    assert_eq!(report["cleanup"], "complete");
    assert_eq!(report["recorded"], false);
    assert_eq!(report["retirement_authority"], false);
    assert_eq!(report["initial_remote_oid"], report["final_remote_oid"]);
    assert_eq!(report["local_oid"], report["fetched_local_oid"]);
    assert!(report["ended_ms"].as_u64().unwrap() >= report["started_ms"].as_u64().unwrap());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(remote.to_str().unwrap()));
    assert_eq!(original(&f), before);
    assert!(!f
        .temp
        .path()
        .join("authority/inspection-receipts-v1")
        .exists());
    assert!(!f.common().join("refs/work-verify").exists());
    // Serialized metadata is a historical statement, not an input accepted by the CLI.
    assert!(!command(&config, &["verify-remote", &report.to_string()])
        .status
        .success());
}
#[test]
fn nonancestor_missing_remote_objects_and_duplicate_effective_urls_hold() {
    for case in ["nonancestor", "missing", "duplicate"] {
        let f = fixture::ManagedFixture::new("sha1", "2");
        let (config, remote) = configured(&f);
        match case {
            "nonancestor" => {
                fs::write(f.path(b"tracked"), b"not preserved\n").unwrap();
                f.git(&["commit".as_ref(), "-am".as_ref(), "local only".as_ref()]);
            }
            "missing" => {
                fs::rename(remote.join("objects"), remote.join("unavailable-objects")).unwrap();
            }
            _ => {
                f.git(&[
                    "config".as_ref(),
                    "--add".as_ref(),
                    "remote.backup.url".as_ref(),
                    "file:///DO_NOT_ECHO".as_ref(),
                ]);
            }
        }
        let before = original(&f);
        let output = observe(&f, &config);
        assert_eq!(output.status.code(), Some(1), "{case}: {output:?}");
        assert_eq!(original(&f), before);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_ne!(report["outcome"], "observed", "{case}");
        if case == "nonancestor" {
            assert_eq!(report["reason"], "nonancestor");
        }
        assert!(!String::from_utf8_lossy(&output.stdout).contains("DO_NOT_ECHO"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("DO_NOT_ECHO"));
    }
}
#[test]
fn unsafe_features_and_wrong_policy_hold_without_repair() {
    for case in [
        "shallow",
        "wrong-common",
        "wrong-url",
        "duplicate-policy",
        "absent-policy",
    ] {
        let f = fixture::ManagedFixture::new("sha1", "2");
        let (config, _) = configured(&f);
        let text = fs::read_to_string(&config).unwrap();
        match case {
            "shallow" => fs::write(f.common().join("shallow"), b"unsafe\n").unwrap(),
            "wrong-common" => fs::write(
                &config,
                text.replace(
                    &format!("common_dir={:?}", f.common()),
                    &format!("common_dir={:?}", f.repo),
                ),
            )
            .unwrap(),
            "wrong-url" => fs::write(&config, text.replace("backup.git", "wrong.git")).unwrap(),
            "duplicate-policy" => {
                let target = text
                    .split("[[remote_preservation.targets]]")
                    .nth(1)
                    .unwrap()
                    .split("[supervisor]")
                    .next()
                    .unwrap();
                fs::write(
                    &config,
                    format!("{text}\n[[remote_preservation.targets]]{target}"),
                )
                .unwrap();
            }
            _ => fs::write(&config, text.split("[remote_preservation]").next().unwrap()).unwrap(),
        }
        let output = observe(&f, &config);
        assert_eq!(output.status.code(), Some(1), "{case}: {output:?}");
        assert!(!f.common().join("refs/work-verify").exists());
    }
}
#[test]
fn help_and_invalid_arguments_are_sanitized_and_readonly() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("missing.toml");
    let help = command(&config, &["verify-remote", "--help"]);
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(!help.contains("--url"));
    assert!(!help.contains("--record"));
    for args in [
        vec!["verify-remote", "secret-token"],
        vec!["verify-remote", "--url", "https://secret-token.invalid"],
        vec!["verify-remote", "00000000-0000-0000-0000-000000000000"],
    ] {
        let output = command(&config, &args);
        assert_eq!(output.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-token"));
    }
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
}
