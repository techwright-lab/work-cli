//! Native development acceptance. Run only in the owned H2 Git fixture.
#![cfg(target_os = "macos")]

use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf, process::Command};

#[test]
fn native_doctor_qualifies_explicit_git_and_inventories_owned_repository() {
    let git =
        PathBuf::from(std::env::var_os("WORK_TEST_NATIVE_GIT").expect("H2 verified Git required"));
    let version = std::env::var("WORK_TEST_NATIVE_GIT_VERSION").expect("H2 Git version required");
    assert!(git.is_absolute());
    let root = tempfile::Builder::new()
        .prefix("native-git-doctor-")
        .tempdir_in(std::env::var_os("TMPDIR").expect("H2 owned TMPDIR required"))
        .unwrap()
        .keep();
    eprintln!("retained native doctor fixture: {}", root.display());
    let home = root.join("home");
    let managed = root.join("managed");
    let repo = root.join("repo");
    for path in [&home, &managed, &repo] {
        fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    }
    let init = Command::new(&git)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["init", "--quiet", "--initial-branch=main"])
        .arg(&repo)
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let repo = fs::canonicalize(repo).unwrap();
    let config = root.join("config.toml");
    let config_bytes = format!("repositories = [{repo:?}]\nroots = [{managed:?}]\n");
    fs::write(&config, &config_bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_work"))
        .env_clear()
        .env("HOME", &home)
        .env("WORK_CONFIG", &config)
        .args(["--git"])
        .arg(&git)
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["git"]["status"], "qualified", "{value}");
    assert_eq!(value["git"]["selection_source"], "cli");
    assert_eq!(value["git"]["version"], version);
    assert_eq!(
        value["git"]["canonical_path"],
        fs::canonicalize(git).unwrap().to_str().unwrap()
    );
    assert_eq!(value["git"]["helpers"].as_array().unwrap().len(), 3);
    assert!(value["git"]["helper_directory"]
        .as_str()
        .unwrap()
        .starts_with('/'));
    assert!(
        value["inventory"].as_array().unwrap().iter().any(|entry| {
            entry["path"].as_str() == repo.to_str() && entry["registered"] == true
        }),
        "{value}"
    );
    assert!(
        !value["uncertainties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| {
                let text = entry.as_str().unwrap();
                text.contains("registration inventory incomplete")
                    || text.contains("inventory unknown")
            }),
        "{value}"
    );
    assert_eq!(fs::read_to_string(config).unwrap(), config_bytes);
    assert!(!home.join(".config/work/config.toml").exists());
}

#[test]
fn native_doctor_accepts_benign_acl_and_symlink_but_refuses_unrelated_writer_before_probe() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = tempfile::Builder::new()
        .prefix("native-git-acl-")
        .tempdir_in(std::env::var_os("TMPDIR").expect("H2 owned TMPDIR required"))
        .unwrap()
        .keep();
    eprintln!("retained native ACL fixture: {}", root.display());
    let helpers = root.join("helpers");
    fs::DirBuilder::new().mode(0o700).create(&helpers).unwrap();
    for name in ["git-upload-pack", "git-receive-pack", "git-upload-archive"] {
        let path = helpers.join(name);
        fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let selected = root.join("git");
    // The owned fixture path is ASCII, but do not interpolate an unquoted path
    // into the script. Escape single quotes before using a shell literal.
    let quote = |p: &std::path::Path| p.to_str().unwrap().replace('\'', "'\\''");
    fs::write(&selected, format!(
        "#!/bin/sh\nprintf x >> '{}'\ncase \"$1\" in\n--version) echo 'git version 2.55.0';;\n--exec-path) printf '%s\\n' '{}';;\n*) exit 1;;\nesac\n",
        quote(&root.join("probes")), quote(&helpers))).unwrap();
    fs::set_permissions(&selected, fs::Permissions::from_mode(0o700)).unwrap();
    let link = root.join("linked-git");
    symlink("git", &link).unwrap();
    let chmod = |acl: &str| {
        let output = Command::new("/bin/chmod")
            .env_clear()
            .args(["+a", acl])
            .arg(&selected)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    let doctor = || {
        let output = Command::new(env!("CARGO_BIN_EXE_work"))
            .env_clear()
            .env("HOME", &root)
            .env("WORK_CONFIG", "")
            .arg("--git")
            .arg(&link)
            .args(["doctor", "--json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    chmod("everyone allow readattr,readsecurity");
    let benign = doctor();
    assert_eq!(benign["git"]["status"], "qualified", "{benign}");
    assert_eq!(benign["git"]["canonical_path"], selected.to_str().unwrap());
    let probes = fs::read(root.join("probes")).unwrap();
    assert_eq!(probes, b"xx");
    chmod("everyone allow write,append");
    let dangerous = doctor();
    assert_eq!(dangerous["git"]["status"], "unavailable", "{dangerous}");
    assert_eq!(
        fs::read(root.join("probes")).unwrap(),
        probes,
        "dangerous access must be refused before executing the candidate"
    );
}
