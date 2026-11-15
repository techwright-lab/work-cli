//! Invocation selection controls use only owned fake installations and empty authority.
use std::os::unix::fs::PermissionsExt;
use std::{fs, path::Path, process::Command};

// macOS Git qualification compares route directory change times, so a sibling
// test creating a tempdir in the shared TMPDIR mid-qualification reads as a change.
static TMPDIR_WRITERS: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    TMPDIR_WRITERS.lock().unwrap_or_else(|e| e.into_inner())
}

fn work(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_work"));
    command.env_clear().env("HOME", home).env("WORK_CONFIG", "");
    command
}

#[test]
fn help_version_and_skill_install_do_not_qualify_git_or_initialize_config() {
    let _serial = serial();
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec!["--git", "/missing/git", "--help"],
        vec!["--git=/missing/git", "--version"],
        vec!["skill", "install", "--git", "/missing/git", "--help"],
        vec!["skill", "install", "--git", "/missing/git"],
    ] {
        let output = work(home.path()).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(!home.path().join(".config/work/config.toml").exists());
}

#[test]
fn global_placement_does_not_expose_sensitive_or_private_arguments() {
    let _serial = serial();
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec!["--git", "/missing/git", "run", "--secret-argv-canary"],
        vec![
            "--git=/missing/git",
            "__scope-child",
            "--secret-argv-canary",
        ],
    ] {
        let output = work(home.path()).args(args).output().unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("secret-argv-canary"), "{stderr}");
        assert!(!stderr.contains("/missing/git"), "{stderr}");
    }
}

fn fake_git(root: &Path, name: impl AsRef<Path>, version: &str) -> std::path::PathBuf {
    fake_git_with(root, name, version, "exit 1")
}

fn fake_git_with(
    root: &Path,
    name: impl AsRef<Path>,
    version: &str,
    otherwise: &str,
) -> std::path::PathBuf {
    let prefix = root.join(name);
    fs::create_dir(&prefix).unwrap();
    let helpers = prefix.join("helpers");
    fs::create_dir(&helpers).unwrap();
    for name in ["git-upload-pack", "git-receive-pack", "git-upload-archive"] {
        let path = helpers.join(name);
        fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let program = prefix.join("git");
    use std::os::unix::ffi::OsStrExt;
    let mut script = b"#!/bin/sh\nprintf x >> '".to_vec();
    script.extend_from_slice(prefix.as_os_str().as_bytes());
    script.extend_from_slice(b"/probes'\ncase \"$1\" in\n--version) echo 'git version ");
    script.extend_from_slice(version.as_bytes());
    script.extend_from_slice(b"';;\n--exec-path) printf '%s\\n' '");
    script.extend_from_slice(helpers.as_os_str().as_bytes());
    script.extend_from_slice(b"';;\n*)\n");
    script.extend_from_slice(otherwise.as_bytes());
    script.extend_from_slice(b"\n;;\nesac\n");
    fs::write(&program, script).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
    program
}

#[test]
fn doctor_warns_but_qualifies_git_older_than_any_version_work_was_run_with() {
    let _serial = serial();
    let home = tempfile::tempdir().unwrap();
    for (version, warning) in [
        (
            "2.30.1",
            Some("Git 2.30.1 is older than the oldest version Work was run with (2.48.1)"),
        ),
        ("2.48.1", None),
    ] {
        let git = fake_git(home.path(), version, version);
        let output = work(home.path())
            .args(["doctor", "--git", git.to_str().unwrap(), "--json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["git"]["status"], "qualified", "{value}");
        assert_eq!(value["git"]["version"], version, "{value}");
        let warnings: Vec<_> = value["uncertainties"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|v| v.starts_with("Git "))
            .collect();
        assert_eq!(warnings, Vec::from_iter(warning), "{value}");
    }
}

#[test]
fn doctor_shows_the_error_of_a_git_that_rejects_a_flag() {
    let _serial = serial();
    let home = tempfile::tempdir().unwrap();
    let root = home.path().canonicalize().unwrap();
    let repo = root.join("repo");
    fs::create_dir_all(root.join("managed")).unwrap();
    let setup = |args: &[&str]| {
        let status = Command::new("/usr/bin/git")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
            ])
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    };
    setup(&["init", "-q", "-b", "main", repo.to_str().unwrap()]);
    setup(&[
        "-C",
        repo.to_str().unwrap(),
        "commit",
        "--allow-empty",
        "-qm",
        "initial",
    ]);
    let git = fake_git_with(
        &root,
        "old",
        "2.30.1",
        "for a; do [ \"$a\" = -z ] && { echo \"error: unknown switch \\`z'\" >&2; exit 129; }; done\nexec /usr/bin/git \"$@\"",
    );
    let output = work(&root)
        .args([
            "doctor",
            "--json",
            "--git",
            git.to_str().unwrap(),
            "--repository",
        ])
        .arg(&repo)
        .arg("--managed-root")
        .arg(root.join("managed"))
        .arg("--store-dir")
        .arg(root.join("store"))
        .arg("--trusted-registry")
        .arg(root.join("registry"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        value["uncertainties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "Git command failed; inventory incomplete: error: unknown switch `z'"),
        "{value}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn doctor_reports_precedence_attempts_and_no_invalid_explicit_fallback_without_writes() {
    let _serial = serial();
    let home = tempfile::tempdir().unwrap();
    let configured = fake_git(home.path(), "configured", "2.55.0");
    let selected = fake_git(home.path(), "selected", "2.56.0");
    let config = home.path().join("config.toml");
    let bytes = format!("git_path = {configured:?}\nprivate = 'not-a-diagnostic'\n");
    fs::write(&config, &bytes).unwrap();
    for (args, source, canonical, version, status) in [
        (
            vec!["doctor", "--json"],
            "config",
            Some(&configured),
            Some("2.55.0"),
            "qualified",
        ),
        (
            vec!["doctor", "--git", selected.to_str().unwrap(), "--json"],
            "cli",
            Some(&selected),
            Some("2.56.0"),
            "qualified",
        ),
        (
            vec!["--git=/missing/git", "doctor", "--json"],
            "cli",
            None,
            None,
            "unavailable",
        ),
        (
            vec!["doctor", "--git=relative", "--json"],
            "cli",
            None,
            None,
            "unavailable",
        ),
    ] {
        let output = work(home.path())
            .env("WORK_CONFIG", &config)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let git = &value["git"];
        for field in [
            "canonical_path_bytes",
            "helper_directory_bytes",
            "helpers_bytes",
        ] {
            assert!(git.get(field).is_none());
        }
        assert!(git["attempts"][0].get("path_bytes").is_none());
        assert_eq!(git["selection_source"], source);
        assert_eq!(git["status"], status);
        assert_eq!(
            git["canonical_path"].as_str(),
            canonical.and_then(|p| p.to_str())
        );
        assert_eq!(git["version"].as_str(), version);
        assert_eq!(git["attempts"].as_array().unwrap().len(), 1);
        assert!(!git["attempts"][0]["reason"].as_str().unwrap().is_empty());
        assert!(value["uncertainties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap().contains("inventory unknown")));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("not-a-diagnostic"));
        assert_eq!(fs::read_to_string(&config).unwrap(), bytes);
    }
    assert_eq!(
        fs::read(configured.parent().unwrap().join("probes")).unwrap(),
        b"xx"
    );
    assert_eq!(
        fs::read(selected.parent().unwrap().join("probes")).unwrap(),
        b"xx"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn doctor_diagnostics_preserve_opaque_selected_program_and_helper_bytes() {
    let _serial = serial();
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let home = tempfile::tempdir().unwrap();
    let prefix = std::path::PathBuf::from(std::ffi::OsString::from_vec(b"selected-\xff".to_vec()));
    let selected = fake_git(home.path(), prefix, "2.56.0");
    let output = work(home.path())
        .args([
            std::ffi::OsString::from("--git"),
            selected.as_os_str().to_owned(),
            "doctor".into(),
            "--json".into(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let git = &value["git"];
    assert_eq!(git["status"], "qualified");
    assert_eq!(
        git["canonical_path"].as_str(),
        Some(selected.to_string_lossy().as_ref())
    );
    let raw: Vec<u8> = serde_json::from_value(git["canonical_path_bytes"].clone()).unwrap();
    assert_eq!(raw, selected.as_os_str().as_bytes());
    let raw: Vec<u8> = serde_json::from_value(git["attempts"][0]["path_bytes"].clone()).unwrap();
    assert_eq!(raw, selected.as_os_str().as_bytes());
    let helpers = selected.parent().unwrap().join("helpers");
    let raw: Vec<u8> = serde_json::from_value(git["helper_directory_bytes"].clone()).unwrap();
    assert_eq!(raw, helpers.as_os_str().as_bytes());
    let raw: Vec<Vec<u8>> = serde_json::from_value(git["helpers_bytes"].clone()).unwrap();
    assert_eq!(
        raw,
        ["git-upload-pack", "git-receive-pack", "git-upload-archive"].map(|name| helpers
            .join(name)
            .as_os_str()
            .as_bytes()
            .to_vec())
    );
    assert_eq!(
        fs::read(selected.parent().unwrap().join("probes")).unwrap(),
        b"xx"
    );
    let missing = home
        .path()
        .join(std::ffi::OsString::from_vec(b"missing-\xfe".to_vec()));
    let output = work(home.path())
        .args([
            std::ffi::OsString::from("--git"),
            missing.as_os_str().to_owned(),
            "doctor".into(),
            "--json".into(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let git = &value["git"];
    assert_eq!(git["status"], "unavailable");
    assert!(git["canonical_path"].is_null());
    assert!(git["helper_directory"].is_null());
    assert_eq!(git["helpers"].as_array().unwrap().len(), 0);
    for field in [
        "canonical_path_bytes",
        "helper_directory_bytes",
        "helpers_bytes",
    ] {
        assert!(git.get(field).is_none());
    }
    assert_eq!(git["attempts"].as_array().unwrap().len(), 1);
    let raw: Vec<u8> = serde_json::from_value(git["attempts"][0]["path_bytes"].clone()).unwrap();
    assert_eq!(raw, missing.as_os_str().as_bytes());
    let secret = std::ffi::OsString::from_vec(b"/secret-selector-\xff".to_vec());
    let output = work(home.path())
        .args([
            std::ffi::OsString::from("--git"),
            secret,
            "__scope-child".into(),
            "--secret-argv-canary".into(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-selector"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-argv-canary"));
}

#[test]
#[cfg(target_os = "macos")]
fn native_refusal_precedes_config_or_sensitive_parsing_at_global_positions() {
    let _serial = serial();
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec!["--git", "/secret-selector", "run", "--secret-argv-canary"],
        vec![
            "remove",
            "--git=/secret-selector",
            "secret-argv-canary",
            "--confirm-stopped",
        ],
        vec![
            "--git=/secret-selector",
            "__scope-child",
            "--secret-argv-canary",
        ],
    ] {
        let output = work(home.path()).args(args).output().unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unsupported on macOS") || stderr.contains("native backend incomplete")
        );
        assert!(!stderr.contains("secret-selector"));
        assert!(!stderr.contains("secret-argv-canary"));
    }
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}
