use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct IsolatedRoot {
    root: PathBuf,
}

impl IsolatedRoot {
    fn new() -> Self {
        let unique = format!(
            "work-cli-contract-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        for dir in ["home", "config", "data", "state", "cache", "tmp", "cwd"] {
            fs::create_dir_all(root.join(dir)).expect("create isolated dir");
        }
        Self { root }
    }

    fn cwd(&self) -> PathBuf {
        self.root.join("cwd")
    }

    fn snapshot(&self) -> BTreeSet<PathBuf> {
        let mut out = BTreeSet::new();
        collect_relative(&self.root, &self.root, &mut out);
        out
    }
}

impl Drop for IsolatedRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn collect_relative(root: &Path, current: &Path, out: &mut BTreeSet<PathBuf>) {
    let entries = match fs::read_dir(current) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if let Ok(relative) = path.strip_prefix(root) {
            out.insert(relative.to_path_buf());
        }
        if path.is_dir() {
            collect_relative(root, &path, out);
        }
    }
}

fn run_work(root: &IsolatedRoot, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_work"))
        .args(args)
        .current_dir(root.cwd())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root.root.join("home"))
        .env("XDG_CONFIG_HOME", root.root.join("config"))
        .env("XDG_DATA_HOME", root.root.join("data"))
        .env("XDG_STATE_HOME", root.root.join("state"))
        .env("XDG_CACHE_HOME", root.root.join("cache"))
        .env("TMPDIR", root.root.join("tmp"))
        .env("GITHUB_TOKEN", "ghp_secret_value_12345")
        .env("WORK_TOKEN", "work_secret_value_12345")
        .env("OPENAI_API_KEY", "sk-secret-value-12345")
        .envs(locale_env())
        .output()
        .expect("spawn work")
}

fn locale_env() -> Vec<(OsString, OsString)> {
    vec![
        (OsString::from("LC_ALL"), OsString::from("C")),
        (OsString::from("LANG"), OsString::from("C")),
    ]
}

fn stdout_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn combined(output: &Output) -> String {
    let mut text = stdout_str(output);
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

#[test]
fn help_exits_zero_and_names_the_work_binary() {
    let root = IsolatedRoot::new();
    let output = run_work(&root, &["--help"]);
    assert!(
        output.status.success(),
        "help should succeed: {}",
        combined(&output)
    );
    let stdout = stdout_str(&output);
    assert!(
        stdout.to_lowercase().contains("usage"),
        "help should include usage: {stdout}"
    );
    assert!(
        stdout.contains("work"),
        "help should name the work binary: {stdout}"
    );
    assert!(
        stdout.contains("status"),
        "help should describe status: {stdout}"
    );
}

#[test]
fn help_does_not_create_files_or_write_config() {
    let root = IsolatedRoot::new();
    let before = root.snapshot();
    let output = run_work(&root, &["--help"]);
    assert!(output.status.success(), "{}", combined(&output));
    assert_eq!(before, root.snapshot(), "help must not create files");
}

#[test]
fn status_reports_honest_uninitialized_state() {
    let root = IsolatedRoot::new();
    let output = run_work(&root, &["status"]);
    assert!(
        output.status.success(),
        "status should succeed when uninitialized: {}",
        combined(&output)
    );
    let stdout = stdout_str(&output).to_lowercase();
    assert!(
        stdout.contains("not initialized"),
        "status must report an honest uninitialized state: {stdout}"
    );
    assert!(
        !stdout.contains("allocated") && !stdout.contains("running") && !stdout.contains("retired"),
        "status must not pretend later lifecycle commands ran: {stdout}"
    );
}

#[test]
fn status_does_not_create_files_or_write_config() {
    let root = IsolatedRoot::new();
    let before = root.snapshot();
    let output = run_work(&root, &["status"]);
    assert!(output.status.success(), "{}", combined(&output));
    assert_eq!(before, root.snapshot(), "status must not create files");
}

#[test]
fn status_is_secret_free_and_has_no_host_defaults() {
    let root = IsolatedRoot::new();
    let output = run_work(&root, &["status"]);
    assert!(output.status.success(), "{}", combined(&output));
    let text = combined(&output);
    for secret in [
        "ghp_secret_value_12345",
        "work_secret_value_12345",
        "sk-secret-value-12345",
    ] {
        assert!(
            !text.contains(secret),
            "status leaked a secret value: {text}"
        );
    }
    let lowered = text.to_lowercase();
    assert!(
        !lowered.contains("techwright") && !lowered.contains("/home/sentinel"),
        "status must not bake in TechWright paths or host defaults: {text}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn status_reports_linux_qualification() {
    let root = IsolatedRoot::new();
    let output = run_work(&root, &["status"]);
    assert!(output.status.success(), "{}", combined(&output));
    let stdout = stdout_str(&output);
    assert!(
        stdout.contains("platform: linux"),
        "status should report linux platform: {stdout}"
    );
    assert!(
        stdout.contains("qualification: qualified"),
        "linux hosts are the qualified platform: {stdout}"
    );
}

#[test]
fn unimplemented_commands_do_not_silently_succeed() {
    let root = IsolatedRoot::new();
    for args in [
        &["run"][..],
        &["allocate"],
        &["finish"],
        &["reap"],
        &["doctor"],
        &["transfer"],
        &["start"],
    ] {
        let output = run_work(&root, args);
        assert!(
            !output.status.success(),
            "`work {}` must not silently succeed: {}",
            args.join(" "),
            combined(&output)
        );
    }
}
