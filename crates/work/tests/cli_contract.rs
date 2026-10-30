#[path = "support/run_fixture.rs"]
mod run_fixture;

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
fn attribution_off_is_per_run_and_default_remains_legacy() {
    use clap::Parser;
    #[derive(Parser)]
    struct ParseRun {
        #[command(flatten)]
        run: work_cli::supervisor::Run,
    }
    let isolated = IsolatedRoot::new();
    let help = run_work(&isolated, &["run", "--help"]);
    assert!(help.status.success());
    assert!(
        stdout_str(&help).contains("--attribution"),
        "run must expose the explicit per-invocation option"
    );
    assert!(!stdout_str(&run_work(&isolated, &["--help"])).contains("--attribution"));
    let checkout = "0194aabd-aaaa-7000-8000-000000000001";
    let run = "0194aabd-aaaa-7000-8000-000000000002";
    let base = [
        "fixture",
        checkout,
        "--run-id",
        run,
        "--execution-chain",
        "chain.json",
    ];
    let mut args = base.to_vec();
    args.extend(["--attribution", "off", "--", "/usr/bin/true"]);
    let parsed = ParseRun::try_parse_from(args).unwrap();
    assert!(format!("{:?}", parsed.run).contains("Some(Off)"));
    let mut args = base.to_vec();
    args.extend(["--", "/usr/bin/echo", "--attribution", "off"]);
    let parsed = ParseRun::try_parse_from(args).unwrap();
    assert!(format!("{:?}", parsed.run).contains("attribution: None"));
    assert_eq!(
        parsed.run.argv,
        vec![
            OsString::from("/usr/bin/echo"),
            "--attribution".into(),
            "off".into()
        ]
    );
    for invalid in [
        vec!["--attribution", "on"],
        vec!["--attribution", "null"],
        vec!["--attribution", "off", "--attribution", "off"],
    ] {
        let mut args = base.to_vec();
        args.extend(invalid);
        args.extend(["--", "/usr/bin/true"]);
        assert!(ParseRun::try_parse_from(args).is_err());
    }
    assert!(!run_work(&isolated, &["--attribution", "off", "status"])
        .status
        .success());

    // Built-work executable outer wiring: public ordinary unbound intent is
    // passive despite irrelevant current policy. No physical Gap-success claim.
    let (fixture, mut store, checkout) = run_fixture::fixture();
    let root = run_fixture::request(checkout);
    store.begin_run(&root).unwrap();
    let config = isolated.root.join("config/work");
    fs::create_dir(&config).unwrap();
    fs::write(config.join("config.toml"),format!("store_dir={:?}\ntrusted_registry={:?}\nroots=[{:?}]\nsupervisor=false\nallocation=42\ncapture=false\n",fixture.path().join("private"),fixture.path().join(".work-authorities"),fixture.path().join("root"))).unwrap();
    let before = store.run_snapshot(&root.identity().run).unwrap();
    let output = run_work(&isolated, &["recover", &root.identity().run.to_string()]);
    assert!(stdout_str(&output).contains("unbound intent: historical proof unsupported"));
    assert_eq!(store.run_snapshot(&root.identity().run).unwrap(), before);

    let chain = isolated.root.join("chain.json");
    fs::write(
        &chain,
        serde_json::to_vec(&root.identity().execution_chain).unwrap(),
    )
    .unwrap();
    let args = [
        "run",
        &checkout.to_string(),
        "--run-id",
        &root.identity().run.to_string(),
        "--execution-chain",
        chain.to_str().unwrap(),
        "--attribution",
        "off",
        "--",
        "/usr/bin/true",
    ];
    let output = run_work(&isolated, &args);
    assert!(!output.status.success());
    assert!(!combined(&output).contains("event_recorded=true"));
    assert_eq!(store.run_snapshot(&root.identity().run).unwrap(), before);
    // Corrupt historical marker without a record proves refusal only.
    let sql = rusqlite::Connection::open(fixture.path().join("private/store.sqlite")).unwrap();
    let mut value = serde_json::to_value(&root).unwrap();
    value["input"]["attribution"] = "off".into();
    let bytes = value.to_string();
    sql.execute("UPDATE runs SET request=?1", [&bytes]).unwrap();
    let output = run_work(&isolated, &args);
    assert!(!output.status.success());
    assert!(!combined(&output).contains("event_recorded=true"));
    assert_eq!(
        sql.query_row("SELECT request FROM runs", [], |r| r.get::<_, String>(0))
            .unwrap(),
        bytes
    );
    assert_eq!(
        sql.query_row("SELECT count(*) FROM attribution_gaps", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn historical_commands_are_explicit_sanitized_and_do_not_initialize_missing_authority() {
    let root = IsolatedRoot::new();
    let before = root.snapshot();
    let help = run_work(&root, &["status", "--help"]);
    assert!(help.status.success());
    assert!(stdout_str(&help).contains("--run"));
    let help = run_work(&root, &["recover", "--help"]);
    assert!(help.status.success());
    assert!(stdout_str(&help).contains("run-id"));
    for args in [
        vec!["status", "--run", "0194aabd-aaaa-7000-8000-000000000001"],
        vec!["recover", "0194aabd-aaaa-7000-8000-000000000001"],
    ] {
        let output = run_work(&root, &args);
        assert!(!output.status.success());
        assert!(combined(&output).contains("authority"));
    }
    for args in [
        vec!["status", "--run", "secret-not-an-id"],
        vec!["recover", "secret-not-an-id"],
    ] {
        let output = run_work(&root, &args);
        assert!(!output.status.success());
        assert!(!combined(&output).contains("secret-not-an-id"));
    }
    assert_eq!(before, root.snapshot());
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
fn configured_status_does_not_claim_initialization_or_runtime_qualification() {
    let root = IsolatedRoot::new();
    fs::create_dir_all(root.root.join("config/work")).unwrap();
    let config_path = root.root.join("config/work/config.toml");
    let config = format!(
        "store_dir={:?}\ntrusted_registry={:?}\n",
        root.root.join("state/not-created"),
        root.root.join("state/registry-not-created")
    );
    fs::write(&config_path, &config).unwrap();
    let before = root.snapshot();
    let output = run_work(&root, &["status"]);
    assert!(output.status.success(), "{}", combined(&output));
    let text = stdout_str(&output);
    assert!(text.contains("status: not initialized"));
    assert!(!text.contains("not inspected"));
    assert!(text.contains("runtime qualification not verified"));
    assert_eq!(before, root.snapshot());
    assert_eq!(fs::read_to_string(&config_path).unwrap(), config);
}

#[test]
fn configured_status_without_registry_refuses_without_initializing_or_leaking_paths() {
    let root = IsolatedRoot::new();
    fs::create_dir_all(root.root.join("config/work")).unwrap();
    let config_path = root.root.join("config/work/config.toml");
    let config = format!(
        "store_dir={:?}\n",
        root.root.join("state/private-store-secret")
    );
    fs::write(&config_path, &config).unwrap();
    let before = root.snapshot();
    for args in [&["status"][..], &["status", "--json"]] {
        let output = run_work(&root, args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            "status unavailable: invalid store record; existing authority was not initialized or repaired\n"
        );
        assert_eq!(before, root.snapshot());
        assert_eq!(fs::read_to_string(&config_path).unwrap(), config);
    }
}
#[test]
fn run_parse_errors_do_not_echo_raw_command_or_emit_protocol_stdout() {
    let root = IsolatedRoot::new();
    let before = root.snapshot();
    let output = run_work(
        &root,
        &[
            "run",
            "019281b2-67de-7000-8000-000000000001",
            "secret-delegate-argument",
        ],
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!combined(&output).contains("secret-delegate-argument"));
    assert_eq!(before, root.snapshot());
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

#[test]
fn malformed_config_reports_only_safe_location() {
    let root = IsolatedRoot::new();
    fs::create_dir_all(root.root.join("config/work")).unwrap();
    fs::write(
        root.root.join("config/work/config.toml"),
        "token = \"private-config-secret\" unexpected-secret\n",
    )
    .unwrap();
    let before = root.snapshot();
    let config_path = root.root.join("config/work/config.toml");
    let config = fs::read(&config_path).unwrap();
    for args in [&["status"][..], &["status", "--json"]] {
        let output = run_work(&root, args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            "config error: invalid TOML at line 1, column 33\n"
        );
        assert_eq!(before, root.snapshot());
        assert_eq!(fs::read(&config_path).unwrap(), config);
    }
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
        stdout.contains("qualification: runtime qualification not verified"),
        "Linux alone is not evidence of runtime qualification: {stdout}"
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
