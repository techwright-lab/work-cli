//! Public native setup CLI in disposable owned homes. Never uses live authority.
use serde_json::Value;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

struct Fixture {
    _owned: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    config_home: PathBuf,
    state: PathBuf,
    data: PathBuf,
    repo: PathBuf,
    extra_repo: PathBuf,
    root_dir: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    mode: u32,
    kind: &'static str,
    bytes: Option<Vec<u8>>,
    target: Option<PathBuf>,
    dev: u64,
    ino: u64,
    nlink: u64,
    uid: u32,
    gid: u32,
    // Reads themselves can advance atime; mutation timestamps must be preserved.
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Fixture {
    fn new() -> Self {
        let owned = tempfile::Builder::new()
            .prefix("work-cli-setup-")
            .tempdir()
            .expect("reserve isolated setup fixture");
        let root = owned.path().to_path_buf();
        let home = root.join("home");
        let config_home = root.join("config");
        let state = root.join("state");
        let data = root.join("data");
        let repo = root.join("repo");
        let extra_repo = root.join("extra-repo");
        let root_dir = root.join("worktrees");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&config_home).unwrap();
        fs::create_dir(&state).unwrap();
        fs::create_dir(&data).unwrap();
        fs::create_dir(root.join("tmp")).unwrap();
        init_repo(&repo);
        init_repo(&extra_repo);
        Self {
            _owned: owned,
            root,
            home,
            config_home,
            state,
            data,
            repo,
            extra_repo,
            root_dir,
        }
    }

    fn config_path(&self) -> PathBuf {
        self.config_home.join("work/config.toml")
    }

    fn store_parent(&self) -> PathBuf {
        self.state.join("work")
    }

    fn store_dir(&self) -> PathBuf {
        self.store_parent().join("store")
    }

    fn registry_dir(&self) -> PathBuf {
        self.store_parent().join("registry")
    }

    fn snapshot(&self) -> BTreeMap<PathBuf, Entry> {
        let mut out = BTreeMap::new();
        collect_snapshot(&self.root, &self.root, &mut out);
        out
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with(args, &[], b"")
    }

    fn run_stdin(&self, args: &[&str], stdin: &str) -> Output {
        self.run_with(args, &[], stdin.as_bytes())
    }

    fn run_with(&self, args: &[&str], env: &[(&str, Option<&str>)], stdin: &[u8]) -> Output {
        let mut command = Command::new("/usr/bin/timeout");
        command
            .arg("20")
            .arg(env!("CARGO_BIN_EXE_work"))
            .args(args)
            .current_dir(&self.root)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_STATE_HOME", &self.state)
            .env("XDG_DATA_HOME", &self.data)
            .env("TMPDIR", self.root.join("tmp"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .envs(locale_env())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        fs::create_dir_all(self.root.join("tmp")).ok();
        for (key, value) in env {
            match value {
                Some(value) => {
                    command.env(key, value);
                }
                None => {
                    command.env_remove(key);
                }
            }
        }
        let mut child = command.spawn().expect("spawn work setup");
        {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(stdin)
                .expect("write stdin");
        }
        child.wait_with_output().expect("wait for work setup")
    }

    fn create_args(&self) -> Vec<String> {
        vec![
            "setup".into(),
            "--actor".into(),
            "alice".into(),
            "--repository".into(),
            path_str(&self.repo),
            "--root".into(),
            path_str(&self.root_dir),
            "--store-dir".into(),
            path_str(&self.store_dir()),
            "--trusted-registry".into(),
            path_str(&self.registry_dir()),
            "--dry-run".into(),
        ]
    }

    fn apply_args(&self) -> Vec<String> {
        let mut args = self.create_args();
        args.retain(|arg| arg != "--dry-run");
        args.push("--yes".into());
        args
    }
}

fn locale_env() -> Vec<(OsString, OsString)> {
    vec![
        (OsString::from("LC_ALL"), OsString::from("C")),
        (OsString::from("LANG"), OsString::from("C")),
    ]
}

fn path_str(path: &Path) -> String {
    path.to_str().expect("utf8 path").to_owned()
}

fn init_repo(path: &Path) {
    fs::create_dir_all(path).unwrap();
    git(path, &["init", "-q", "-b", "main"]);
    git(
        path,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "initial",
        ],
    );
}

fn git_command(path: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("/usr/bin/git");
    command
        .args(["-c", "maintenance.auto=false"])
        .arg("-C")
        .arg(path)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", path)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0");
    command
}

fn git(path: &Path, args: &[&str]) {
    let output = git_command(path, args).output().expect("spawn git");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fixture_git_commands_suppress_automatic_maintenance_invocation() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    init_repo(&repo);
    for (name, override_args, expected_maintenance) in [
        ("isolated", Vec::new(), false),
        (
            "enabled-control",
            vec![
                "-c",
                "maintenance.auto=true",
                "-c",
                "maintenance.detach=false",
            ],
            true,
        ),
    ] {
        let trace = temp.path().join(format!("{name}.json"));
        let mut args = override_args;
        args.extend([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "fixture maintenance observation",
        ]);
        // The same scrubbed command builder used by init_repo; tracing is local
        // to this observation, and the enabled control cannot detach maintenance.
        let output = git_command(&repo, &args)
            .env("GIT_TRACE2_EVENT", &trace)
            .output()
            .unwrap();
        assert!(output.status.success(), "{name}: {output:?}");
        let events: Vec<Value> = fs::read_to_string(&trace)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(events.iter().any(|event| event["event"] == "start"));
        let maintenance = events.iter().any(|event| {
            event["event"] == "child_start"
                && event["argv"].as_array().is_some_and(|argv| {
                    argv.windows(2)
                        .any(|pair| pair[0] == "maintenance" && pair[1] == "run")
                })
        });
        assert_eq!(maintenance, expected_maintenance, "{name}: {events:?}");
    }
    let local = fs::read_to_string(repo.join(".git/config")).unwrap();
    assert!(
        !local.contains("maintenance"),
        "command-scoped only: {local}"
    );
}

fn collect_snapshot(root: &Path, current: &Path, out: &mut BTreeMap<PathBuf, Entry>) {
    let entries = fs::read_dir(current).expect("enumerate every fixture destination");
    for entry in entries {
        let path = entry.expect("read destination entry").path();
        let relative = path.strip_prefix(root).unwrap().to_path_buf();
        let entry = snapshot_entry(&path);
        let directory = entry.kind == "dir";
        out.insert(relative, entry);
        if directory {
            collect_snapshot(root, &path, out);
        }
    }
}

fn snapshot_entry(path: &Path) -> Entry {
    let meta = fs::symlink_metadata(path).expect("snapshot destination metadata");
    let file_type = meta.file_type();
    let (kind, bytes, target) = if file_type.is_symlink() {
        ("symlink", None, Some(fs::read_link(path).unwrap()))
    } else if file_type.is_dir() {
        ("dir", None, None)
    } else if file_type.is_file() {
        ("file", Some(fs::read(path).unwrap()), None)
    } else {
        ("other", None, None)
    };
    Entry {
        mode: meta.permissions().mode() & 0o7777,
        kind,
        bytes,
        target,
        dev: meta.dev(),
        ino: meta.ino(),
        nlink: meta.nlink(),
        uid: meta.uid(),
        gid: meta.gid(),
        modified: (meta.mtime(), meta.mtime_nsec()),
        changed: (meta.ctime(), meta.ctime_nsec()),
    }
}

fn stdout_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn report(output: &Output) -> Value {
    let text = stdout_str(output);
    let parsed: Value = serde_json::from_str(text.trim()).unwrap_or_else(|err| {
        panic!(
            "expected one JSON object on stdout: {err}; stdout={text:?} stderr={:?}",
            stderr_str(output)
        );
    });
    assert!(
        parsed.is_object(),
        "stdout JSON must be one object: {parsed}"
    );
    parsed
}

fn assert_unchanged(before: &BTreeMap<PathBuf, Entry>, after: &BTreeMap<PathBuf, Entry>) {
    let changed: Vec<_> = before
        .keys()
        .chain(after.keys())
        .filter(|key| before.get(*key) != after.get(*key))
        .collect();
    assert!(
        changed.is_empty(),
        "setup must not change fixture destinations: {changed:?}"
    );
}

// Only the two databases created by this fixture's successful public start can
// contribute coordination files. Identification reads raw files, never SQLite.
struct CoordinationFiles(BTreeMap<PathBuf, Entry>);

impl CoordinationFiles {
    fn identify(fixture: &Fixture, started: &Value) -> Self {
        assert_eq!(started["stage"], "ready");
        assert!(started["checkout"].as_str().is_some());
        let config_path = if fixture.config_path().is_file() {
            fixture.config_path()
        } else {
            fixture.home.join(".config/work/config.toml")
        };
        let config = parse_config(&config_path);
        assert_eq!(config.store_dir, Some(fixture.store_dir()));
        assert_eq!(config.trusted_registry, Some(fixture.registry_dir()));
        assert_eq!(config.roots, vec![fixture.root_dir.clone()]);
        let uid = fs::symlink_metadata(&fixture.home).unwrap().uid();
        let mut files = BTreeMap::new();
        for database in [
            fixture.store_dir().join("store.sqlite"),
            fixture.registry_dir().join("authorities.sqlite"),
        ] {
            let relative = database.strip_prefix(&fixture.root).unwrap();
            let db = snapshot_entry(&database);
            assert_eq!(db.kind, "file");
            assert_eq!(db.uid, uid);
            assert_eq!(db.nlink, 1);
            assert_eq!(db.mode & 0o077, 0);
            assert!(db.bytes.as_ref().unwrap().starts_with(b"SQLite format 3\0"));
            for suffix in ["-wal", "-shm"] {
                let path = PathBuf::from(format!("{}{suffix}", relative.display()));
                let entry = snapshot_entry(&fixture.root.join(&path));
                assert_eq!(entry.kind, "file");
                assert_eq!(entry.uid, uid);
                assert_eq!(entry.nlink, 1);
                assert_eq!(entry.mode & 0o077, 0);
                if suffix == "-shm" {
                    files.insert(path, entry);
                }
            }
        }
        assert_eq!(files.len(), 2);
        Self(files)
    }

    fn changes(
        &self,
        before: &BTreeMap<PathBuf, Entry>,
        after: &BTreeMap<PathBuf, Entry>,
    ) -> Vec<PathBuf> {
        let mut paths: Vec<_> = before.keys().chain(after.keys()).cloned().collect();
        paths.sort();
        paths.dedup();
        paths
            .into_iter()
            .filter(|path| {
                match (before.get(path), after.get(path), self.0.get(path)) {
                    (Some(old), Some(new), Some(identified))
                        if old == identified && old.kind == "file" =>
                    {
                        // Compare every field except precisely the admitted contents
                        // and associated mutation timestamps. No path is omitted.
                        let comparable = Entry {
                            bytes: old.bytes.clone(),
                            modified: old.modified,
                            changed: old.changed,
                            ..new.clone()
                        };
                        old != &comparable
                    }
                    _ => before.get(path) != after.get(path),
                }
            })
            .collect()
    }
}

fn assert_warm_unchanged(
    coordination: &CoordinationFiles,
    before: &BTreeMap<PathBuf, Entry>,
    after: &BTreeMap<PathBuf, Entry>,
) {
    assert!(coordination.changes(before, after).is_empty());
    // Retain the previous warm byte-equality assertions, including both SHMs;
    // timestamp collection now additionally constrains all other destinations.
    for (path, old) in before {
        assert_eq!(old.bytes, after[path].bytes, "warm bytes: {path:?}");
    }
}

#[test]
fn coordination_comparator_allows_only_identified_existing_file_contents_and_timestamps() {
    let fixture = Fixture::new();
    fs::write(fixture.home.join("foreign-shm"), b"not Work coordination").unwrap();
    apply(&fixture);
    let started = start_task(&fixture, "comparator");
    let coordination = CoordinationFiles::identify(&fixture, &started);
    let before = fixture.snapshot();
    assert!(coordination.changes(&before, &before).is_empty());
    let path = coordination.0.keys().next().unwrap().clone();
    let mut permitted = before.clone();
    let entry = permitted.get_mut(&path).unwrap();
    entry.bytes.as_mut().unwrap().push(1);
    entry.modified.0 += 1;
    entry.changed.0 += 1;
    assert!(
        coordination.changes(&before, &permitted).is_empty(),
        "existing identified coordination bytes/timestamps may change"
    );

    for mutation in [
        "missing",
        "new",
        "replacement",
        "device",
        "uid",
        "gid",
        "mode",
        "links",
        "type",
        "symlink-target",
    ] {
        let mut after = before.clone();
        let entry = after.get_mut(&path).unwrap();
        match mutation {
            "replacement" => entry.ino += 1,
            "device" => entry.dev += 1,
            "uid" => entry.uid += 1,
            "gid" => entry.gid += 1,
            "mode" => entry.mode ^= 0o040,
            "links" => entry.nlink += 1,
            "type" => entry.kind = "symlink",
            "symlink-target" => entry.target = Some(PathBuf::from("foreign")),
            "missing" => {
                after.remove(&path);
            }
            "new" => {
                let extra = entry.clone();
                after.insert(PathBuf::from("state/work/store/new-shm"), extra);
            }
            _ => unreachable!(),
        }
        assert!(
            !coordination.changes(&before, &after).is_empty(),
            "must reject {mutation}"
        );
    }
    // A path absent from the identification baseline cannot be allowlisted later.
    let mut missing_baseline = before.clone();
    missing_baseline.remove(&path);
    assert!(!coordination.changes(&missing_baseline, &before).is_empty());
    for path in before
        .keys()
        .filter(|path| !coordination.0.contains_key(*path))
    {
        let mut after = before.clone();
        let entry = after.get_mut(path).unwrap();
        // Every other family, including arbitrary/foreign -shm, DB and WAL,
        // remains byte- and mutation-timestamp-exact, not suffix-filtered.
        if let Some(bytes) = &mut entry.bytes {
            bytes.push(1);
        } else {
            entry.modified.0 += 1;
        }
        assert!(
            !coordination.changes(&before, &after).is_empty(),
            "must reject {path:?}"
        );
    }
}

#[test]
fn setup_help_is_readonly_and_lists_supported_options() {
    let fixture = Fixture::new();
    let before = fixture.snapshot();
    let output = fixture.run(&["setup", "--help"]);
    assert!(output.status.success(), "{output:?}");
    let help = stdout_str(&output);
    for needle in [
        "--actor",
        "--repository",
        "--root",
        "--store-dir",
        "--trusted-registry",
        "--repository-limit",
        "--owner-limit",
        "--floor-bytes",
        "--warn-bytes",
        "--skills",
        "--yes",
        "--interactive",
        "--dry-run",
        "--check",
        "--add-repository",
    ] {
        assert!(help.contains(needle), "missing {needle} in {help}");
    }
    assert_eq!(stdout_str(&output).matches('{').count(), 0);
    assert_unchanged(&before, &fixture.snapshot());
}

#[test]
fn complete_headless_dry_run_previews_without_destination_changes() {
    let fixture = Fixture::new();
    let before = fixture.snapshot();
    let args = fixture.create_args();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = fixture.run(&args);
    assert!(output.status.success(), "{output:?}");
    let parsed = report(&output);
    assert_eq!(parsed["action"], "create");
    assert_eq!(parsed["outcome"], "preview");
    assert_eq!(parsed["config_written"], false);
    assert_eq!(parsed["authority_modified"], false);
    assert_eq!(parsed["config_path"], path_str(&fixture.config_path()));
    assert!(parsed["created_directories"].as_array().unwrap().is_empty());
    assert!(parsed["error"].is_null());
    let stderr = stderr_str(&output);
    assert!(stderr.contains("alice"), "{stderr}");
    assert!(stderr.contains(&path_str(&fixture.repo)), "{stderr}");
    assert!(
        stderr.contains("repository_limit: 8"),
        "repository_limit missing from preview: {stderr}"
    );
    assert!(
        stderr.contains("owner_limit: 4"),
        "owner_limit missing from preview: {stderr}"
    );
    assert!(
        stderr.contains("1073741824") && stderr.contains("1 GiB"),
        "floor_bytes exact/readable missing from preview: {stderr}"
    );
    assert!(
        stderr.contains("5368709120") && stderr.contains("5 GiB"),
        "warn_bytes exact/readable missing from preview: {stderr}"
    );
    assert!(
        !stdout_str(&output).contains("actor ="),
        "preview belongs on stderr"
    );
    assert!(!fixture.config_path().exists());
    assert!(!fixture.root_dir.exists());
    assert!(!fixture.store_parent().exists());
    assert_unchanged(&before, &fixture.snapshot());
}

#[test]
fn missing_headless_actor_repository_or_confirmation_fails_without_changes() {
    let fixture = Fixture::new();
    let repo = path_str(&fixture.repo);
    let cases: [(&[&str], &str); 3] = [
        (
            &["setup", "--repository", repo.as_str(), "--yes"],
            "inspect",
        ),
        (&["setup", "--actor", "alice", "--yes"], "inspect"),
        (
            &["setup", "--actor", "alice", "--repository", repo.as_str()],
            "create",
        ),
    ];
    for (args, action) in cases {
        let before = fixture.snapshot();
        let output = fixture.run(args);
        assert!(!output.status.success(), "{args:?}: {output:?}");
        let parsed = report(&output);
        assert_eq!(parsed["action"], action, "{args:?}");
        assert_eq!(parsed["outcome"], "failed", "{args:?}");
        assert_eq!(parsed["config_written"], false);
        assert_eq!(parsed["authority_modified"], false);
        assert!(parsed["created_directories"].as_array().unwrap().is_empty());
        assert!(parsed["skills"]["actions"].as_array().unwrap().is_empty());
        assert!(parsed["error"].is_object(), "{args:?}: {parsed}");
        assert!(stderr_str(&output).is_empty() || !stdout_str(&output).is_empty());
        assert_eq!(
            stdout_str(&output).trim().matches('{').count(),
            stdout_str(&output).trim().matches('{').count()
        );
        let _: Value = serde_json::from_str(stdout_str(&output).trim()).unwrap();
        assert_unchanged(&before, &fixture.snapshot());
        assert!(!fixture.config_path().exists());
    }
}

#[test]
fn timeout_does_not_leave_piped_setup_blocked() {
    let fixture = Fixture::new();
    let started = Instant::now();
    let output = fixture.run(&["setup", "--actor", "alice"]);
    assert!(started.elapsed() < Duration::from_secs(20));
    assert!(!output.status.success());
}

fn apply(fixture: &Fixture) -> Value {
    let args = fixture.apply_args();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = fixture.run(&args);
    assert!(output.status.success(), "{output:?}");
    report(&output)
}

fn start_task(fixture: &Fixture, task: &str) -> Value {
    let output = fixture.run(&["start", "--task", task, "--base", "main", "--branch", task]);
    assert!(
        output.status.success(),
        "{output:?}\n{}",
        stderr_str(&output)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

// Warm coverage only: establish SQLite's normal read-side WAL coordination.
// Cold cases below MUST NOT call this (or any other authority reader) before
// their baseline. All entries, including SHM bytes, remain in warm comparisons.
fn prime_readonly(fixture: &Fixture, started: &Value) {
    let output = fixture.run(&["status", "--json"]);
    assert!(output.status.success(), "{output:?}");
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["initialized"], true);
    assert!(status["charged"].as_u64().unwrap() > 0);
    assert_eq!(status["checkouts"][0]["checkout"], started["checkout"]);
    assert!(status["checkouts"][0]["state"].as_str().is_some());
}

// The public start receipt is the only authority evidence before cold baselines.
// apply -> start -> raw identification -> baseline -> setup -> raw post-snapshot
// is intentional. identify reads config/raw filesystem data only; status/SQL below
// run AFTER the physical comparison, so they cannot prime or erase target effects.
fn registered_readonly_modes(warm: bool) {
    for mode in [
        "inspect",
        "yes-inspect",
        "selected-root",
        "check",
        "add-preview",
        "skills-preview",
        "cancel",
        "confirmation-eof",
        "repository-eof",
        "skills-eof",
    ] {
        let fixture = Fixture::new();
        // This unrelated suffix-bearing path must never gain SQLite's exception.
        fs::write(
            fixture.home.join("foreign-shm"),
            b"unrelated coordination-looking bytes",
        )
        .unwrap();
        apply(&fixture);
        let started = start_task(&fixture, "readonly");
        assert_eq!(started["stage"], "ready"); // ready => active, one retained charge
        assert_eq!(started["request"]["task"], "readonly");
        assert_eq!(
            started["destination"],
            path_str(&fixture.root_dir.join("readonly"))
        );
        if warm {
            prime_readonly(&fixture, &started);
        }
        let coordination = CoordinationFiles::identify(&fixture, &started);
        let before = fixture.snapshot();
        let extra = path_str(&fixture.extra_repo);
        let root = path_str(&fixture.root_dir);
        let (args, input, outcome) = match mode {
            "inspect" => (vec!["setup"], "", "success"),
            "yes-inspect" => (vec!["setup", "--yes"], "", "success"),
            "selected-root" => (vec!["setup", "--root", &root], "", "success"),
            "check" => (vec!["setup", "--check"], "", "success"),
            "add-preview" => (
                vec!["setup", "--add-repository", &extra, "--dry-run"],
                "",
                "preview",
            ),
            // Skills-only does not itself require admission; selecting the root does.
            "skills-preview" => (
                vec!["setup", "--root", &root, "--skills", "all", "--dry-run"],
                "",
                "preview",
            ),
            "cancel" | "confirmation-eof" => (
                vec![
                    "setup",
                    "--interactive",
                    "--add-repository",
                    &extra,
                    "--skills",
                    "none",
                ],
                if mode == "cancel" { "no\n" } else { "" },
                "cancelled",
            ),
            // Selecting a root admits authority before either collection prompt.
            "repository-eof" => (
                vec!["setup", "--interactive", "--root", &root],
                "",
                "cancelled",
            ),
            "skills-eof" => (
                vec!["setup", "--interactive", "--root", &root],
                "\n",
                "cancelled",
            ),
            _ => unreachable!(),
        };
        let output = fixture.run_stdin(&args, input);
        let after = fixture.snapshot(); // MUST precede status or SQLite validation
        let changed = coordination.changes(&before, &after);
        assert!(
            changed.is_empty(),
            "{warm}/{mode}: forbidden destinations: {changed:?}"
        );
        if warm {
            assert_warm_unchanged(&coordination, &before, &after);
        }
        let changed_bytes: Vec<_> = coordination
            .0
            .keys()
            .filter(|path| before[*path].bytes != after[*path].bytes)
            .collect();
        if !warm {
            // Bypass libtest capture solely to retain honest cold observations in
            // qualification output. No mutation is required to make a read pass.
            #[allow(
                clippy::explicit_write,
                reason = "eprintln is hidden by libtest on passing cold regressions"
            )]
            {
                use std::io::Write;
                writeln!(
                    std::io::stderr(),
                    "cold {mode}: changed existing coordination bytes: {changed_bytes:?}"
                )
                .unwrap();
            }
        }
        assert_eq!(
            output.status.success(),
            outcome != "cancelled",
            "{mode}: {output:?}"
        );
        let parsed = report(&output);
        assert_eq!(parsed["outcome"], outcome, "{mode}: {parsed}");
        assert_eq!(parsed["config_written"], false);
        assert_eq!(parsed["authority_modified"], false);
        assert!(parsed["created_directories"].as_array().unwrap().is_empty());
        assert!(parsed["backup_path"].is_null());
        assert!(parsed["skills"]["actions"].as_array().unwrap().is_empty());
        if mode == "selected-root" {
            assert!(
                parsed["next_steps"].as_array().unwrap().iter().any(|step| {
                    step.as_array()
                        .unwrap()
                        .windows(2)
                        .any(|pair| pair[0] == "--root" && pair[1] == root)
                }),
                "selected-root guidance: {parsed}"
            );
        }
        assert_durable_start_evidence(&fixture, &started, &before, &after);
    }
}

fn assert_durable_start_evidence(
    fixture: &Fixture,
    started: &Value,
    before: &BTreeMap<PathBuf, Entry>,
    after: &BTreeMap<PathBuf, Entry>,
) {
    for database in [
        fixture.store_dir().join("store.sqlite"),
        fixture.registry_dir().join("authorities.sqlite"),
    ] {
        for suffix in ["", "-wal"] {
            let path = PathBuf::from(format!(
                "{}{suffix}",
                database.strip_prefix(&fixture.root).unwrap().display()
            ));
            assert_eq!(
                before[&path], after[&path],
                "durable database/WAL: {path:?}"
            );
        }
    }
    // Public admission revalidates store/registry/root bindings and task charge.
    // Its expected state comes from successful start, never a pre-target read.
    let output = fixture.run(&["status", "--json"]);
    assert!(output.status.success(), "{output:?}");
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["initialized"], true);
    assert_eq!(status["charged"], 1);
    assert_eq!(status["checkouts"].as_array().unwrap().len(), 1);
    let checkout = &status["checkouts"][0];
    assert_eq!(checkout["checkout"], started["checkout"]);
    assert_eq!(checkout["path"], started["destination"]);
    assert_eq!(checkout["task"], started["request"]["task"]);
    assert_eq!(checkout["state"], "active");
    assert_eq!(checkout["charged"], true);
    assert_eq!(checkout["task_finished"], false);
    let destination = Path::new(started["destination"].as_str().unwrap());
    let directory = &after[destination.strip_prefix(&fixture.root).unwrap()];
    assert_eq!(
        directory.dev,
        started["identity"]["directory"]["device"].as_u64().unwrap()
    );
    assert_eq!(
        directory.ino,
        started["identity"]["directory"]["inode"].as_u64().unwrap()
    );
    // Read records only after physical post-state is captured and compared.
    // Ordinary readonly WAL semantics; no immutable=1, checkpoint or PRAGMA writes.
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
        | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let conn =
        rusqlite::Connection::open_with_flags(fixture.store_dir().join("store.sqlite"), flags)
            .unwrap();
    let record: String = conn
        .query_row(
            "SELECT record FROM allocations WHERE checkout=?1",
            [started["checkout"].as_str().unwrap()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&record).unwrap(), *started);
    let registry = rusqlite::Connection::open_with_flags(
        fixture.registry_dir().join("authorities.sqlite"),
        flags,
    )
    .unwrap();
    let claims: Vec<(String, String)> = registry
        .prepare("SELECT root,store FROM authorities ORDER BY root")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        claims,
        vec![(path_str(&fixture.root_dir), path_str(&fixture.store_dir()))]
    );
}

#[test]
fn cold_registered_readonly_modes_preserve_every_destination_except_narrow_coordination_effects() {
    registered_readonly_modes(false);
}

#[test]
fn warm_registered_readonly_modes_preserve_full_bytes_and_narrow_timestamp_effects() {
    registered_readonly_modes(true);
}

#[test]
fn unsafe_or_missing_coordination_is_refused_without_creation_or_foreign_effects() {
    for kind in [
        "missing",
        "symlink",
        "hardlink",
        "directory",
        "mode",
        "fifo",
        "socket",
    ] {
        let fixture = Fixture::new();
        apply(&fixture);
        start_task(&fixture, "unsafe-coordination");
        // Invalid owned fixture, prepared before baseline; registry admission
        // must refuse before following or recreating its unsafe/missing SHM.
        let shm = fixture.registry_dir().join("authorities.sqlite-shm");
        let foreign = fixture.home.join("foreign-shm");
        fs::write(&foreign, fs::read(&shm).unwrap()).unwrap();
        fs::set_permissions(&foreign, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&shm).unwrap();
        let _socket = if kind == "missing" {
            None
        } else {
            unsafe_artifact(&shm, kind, &foreign)
        };
        let before = fixture.snapshot();
        let output = fixture.run(&["setup", "--check"]);
        let after = fixture.snapshot();
        assert!(!output.status.success(), "{kind}: {output:?}");
        assert_eq!(report(&output)["outcome"], "failed");
        assert_eq!(report(&output)["authority_modified"], false);
        assert_unchanged(&before, &after); // NO exception for an unsafe fixture
    }
}

#[test]
fn threshold_beyond_toml_integer_range_refuses_without_mutation() {
    let fixture = Fixture::new();
    let mut args = fixture.create_args();
    args.extend([
        "--floor-bytes".into(),
        u64::MAX.to_string(),
        "--warn-bytes".into(),
        u64::MAX.to_string(),
    ]);
    let before = fixture.snapshot();
    let output = fixture.run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(!output.status.success(), "{output:?}");
    let parsed = report(&output);
    assert_eq!(parsed["error"]["field"], "config");
    assert_eq!(parsed["error"]["reason"], "invalid allocation policy");
    assert_eq!(parsed["config_written"], false);
    assert_unchanged(&before, &fixture.snapshot());
}

fn identity(path: &Path) -> (u64, u64) {
    let meta = fs::symlink_metadata(path).unwrap();
    (meta.dev(), meta.ino())
}

fn parse_config(path: &Path) -> work_cli::config::Config {
    work_cli::config::Config::from_text(&fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn clap_invalid_argv_is_parser_owned_not_setup_json() {
    let fixture = Fixture::new();
    let output = fixture.run(&["setup", "--skills", "maybe"]);
    assert!(!output.status.success());
    assert!(serde_json::from_str::<Value>(stdout_str(&output).trim()).is_err());
    assert!(stderr_str(&output).contains("error:") || stderr_str(&output).contains("invalid"));
}

#[test]
fn contradictory_flags_emit_failed_json_without_changes() {
    let fixture = Fixture::new();
    let repo = path_str(&fixture.repo);
    for args in [
        vec!["setup", "--interactive", "--yes"],
        vec!["setup", "--dry-run", "--yes"],
        vec![
            "setup",
            "--repository",
            repo.as_str(),
            "--add-repository",
            repo.as_str(),
        ],
        vec!["setup", "--check", "--yes"],
        vec!["setup", "--check", "--actor", "alice"],
    ] {
        let before = fixture.snapshot();
        let output = fixture.run(&args);
        assert!(!output.status.success(), "{args:?}");
        let parsed = report(&output);
        assert_eq!(parsed["outcome"], "failed");
        assert_eq!(parsed["action"], "inspect");
        assert_eq!(parsed["config_written"], false);
        assert_unchanged(&before, &fixture.snapshot());
    }
}

#[test]
fn headless_apply_writes_defaults_and_leaves_endpoints_uninitialized() {
    let fixture = Fixture::new();
    let parsed = apply(&fixture);
    assert_eq!(parsed["action"], "create");
    assert_eq!(parsed["outcome"], "success");
    assert_eq!(parsed["config_written"], true);
    assert_eq!(parsed["authority_modified"], false);
    assert!(parsed["backup_path"].is_null());
    let text = fs::read_to_string(fixture.config_path()).unwrap();
    let config = work_cli::config::Config::from_text(&text).unwrap();
    assert_eq!(config.repositories, vec![fixture.repo.clone()]);
    assert_eq!(config.roots, vec![fixture.root_dir.clone()]);
    assert_eq!(config.store_dir.as_ref(), Some(&fixture.store_dir()));
    assert_eq!(
        config.trusted_registry.as_ref(),
        Some(&fixture.registry_dir())
    );
    let allocation = config.allocation.expect("allocation");
    assert_eq!(allocation.repository_limit, 8);
    assert_eq!(allocation.owner_limit, 4);
    assert_eq!(allocation.floor_bytes, 1_073_741_824);
    assert_eq!(allocation.warn_bytes, 5_368_709_120);
    assert!(allocation.capture_sink.is_none());
    assert!(text.contains("actor = ") && text.contains("alice"));
    assert!(fixture.root_dir.is_dir());
    assert!(fixture.store_parent().is_dir());
    assert!(!fixture.store_dir().exists());
    assert!(!fixture.registry_dir().exists());
    assert_eq!(
        fs::symlink_metadata(fixture.config_path()).unwrap().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::symlink_metadata(&fixture.root_dir).unwrap().mode() & 0o777,
        0o700
    );
    let next = parsed["next_steps"].as_array().unwrap();
    assert!(next
        .iter()
        .any(|step| step[0] == "work" && step[1] == "start"));
    assert_eq!(parsed["skills"]["selection"], "none");
    assert_eq!(parsed["skills"]["status"], "skipped");
}

#[test]
fn threshold_preview_has_exact_bytes_and_units_across_admitted_range() {
    let fixture = Fixture::new();
    for (value, unit) in [
        (0, "0 GiB"),
        (1, "1 B"),
        (10, "10 B"),
        (1536, "1.50 KiB"),
        (1_048_577, "1.00 MiB"),
        (i64::MAX as u64, "8589934591.99 GiB"),
    ] {
        let mut args = fixture.create_args();
        args.extend([
            "--floor-bytes".into(),
            value.to_string(),
            "--warn-bytes".into(),
            value.to_string(),
        ]);
        let before = fixture.snapshot();
        let output = fixture.run(&args.iter().map(String::as_str).collect::<Vec<_>>());
        assert!(output.status.success(), "{output:?}");
        let stderr = stderr_str(&output);
        for field in ["floor_bytes", "warn_bytes"] {
            assert!(
                stderr.contains(&format!("{field}: {value} ({unit})")),
                "{stderr}"
            );
        }
        assert_eq!(report(&output)["outcome"], "preview");
        assert_unchanged(&before, &fixture.snapshot());
    }
}

#[test]
fn explicit_zero_capacity_is_a_hold_and_warn_below_floor_is_refused() {
    let fixture = Fixture::new();
    let mut args = fixture.apply_args();
    args.extend([
        "--repository-limit".into(),
        "0".into(),
        "--owner-limit".into(),
        "0".into(),
        "--floor-bytes".into(),
        "0".into(),
        "--warn-bytes".into(),
        "0".into(),
    ]);
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    let parsed = report(&fixture.run(&args_ref));
    assert_eq!(parsed["outcome"], "success");
    let config =
        work_cli::config::Config::from_text(&fs::read_to_string(fixture.config_path()).unwrap())
            .unwrap();
    let allocation = config.allocation.unwrap();
    assert_eq!(allocation.repository_limit, 0);
    assert_eq!(allocation.floor_bytes, 0);
    let fixture = Fixture::new();
    let mut args = fixture.apply_args();
    args.extend([
        "--floor-bytes".into(),
        "10".into(),
        "--warn-bytes".into(),
        "1".into(),
    ]);
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    let before = fixture.snapshot();
    let output = fixture.run(&args_ref);
    assert!(!output.status.success());
    assert_eq!(report(&output)["outcome"], "failed");
    assert!(report(&output)["error"]["reason"]
        .as_str()
        .unwrap()
        .contains("warn_bytes"));
    assert_unchanged(&before, &fixture.snapshot());
}

#[test]
fn discovery_disable_nonabsolute_and_explicit_missing_work_config() {
    let fixture = Fixture::new();
    let before = fixture.snapshot();
    let output = fixture.run_with(&["setup", "--check"], &[("WORK_CONFIG", Some(""))], b"");
    assert!(!output.status.success(), "{output:?}");
    let parsed = report(&output);
    assert_eq!(parsed["action"], "inspect");
    assert!(parsed["config_path"].is_null());
    assert_unchanged(&before, &fixture.snapshot());
    let output = fixture.run_with(
        &[
            "setup",
            "--actor",
            "alice",
            "--repository",
            &path_str(&fixture.repo),
            "--yes",
        ],
        &[("WORK_CONFIG", Some("relative.toml"))],
        b"",
    );
    assert!(!output.status.success());
    assert_eq!(report(&output)["outcome"], "failed");
    let explicit = fixture.root.join("explicit/config.toml");
    fs::create_dir(explicit.parent().unwrap()).unwrap();
    let output = fixture.run_with(
        &[
            "setup",
            "--actor",
            "alice",
            "--repository",
            &path_str(&fixture.repo),
            "--root",
            &path_str(&fixture.root_dir),
            "--store-dir",
            &path_str(&fixture.store_dir()),
            "--trusted-registry",
            &path_str(&fixture.registry_dir()),
            "--yes",
        ],
        &[("WORK_CONFIG", Some(explicit.to_str().unwrap()))],
        b"",
    );
    assert!(output.status.success(), "{output:?}");
    assert!(explicit.is_file());
    assert!(!fixture.config_path().exists());
}

#[test]
fn git_and_path_refusals_do_not_mutate() {
    let fixture = Fixture::new();
    let missing = fixture.root.join("missing-repo");
    let not_git = fixture.root.join("not-git");
    fs::create_dir(&not_git).unwrap();
    let bare = fixture.root.join("bare.git");
    git_init_bare(&bare);
    let under = fixture.root_dir.join("inside");
    let linked = fixture.root.join("linked");
    git(
        &fixture.repo,
        &["worktree", "add", "-qb", "linked", linked.to_str().unwrap()],
    );
    for (repo, _label) in [
        (missing.as_path(), "missing"),
        (not_git.as_path(), "not-git"),
        (bare.as_path(), "bare"),
        (under.as_path(), "under-root"),
    ] {
        if *repo == under {
            fs::create_dir_all(&fixture.root_dir).unwrap();
            init_repo(&under);
        }
        let before = fixture.snapshot();
        let output = fixture.run(&[
            "setup",
            "--actor",
            "alice",
            "--repository",
            repo.to_str().unwrap(),
            "--root",
            fixture.root_dir.to_str().unwrap(),
            "--yes",
        ]);
        assert!(!output.status.success(), "{repo:?}: {output:?}");
        assert_eq!(report(&output)["outcome"], "failed");
        assert_eq!(report(&output)["config_written"], false);
        assert_unchanged(&before, &fixture.snapshot());
    }
    let before = fixture.snapshot();
    let output = fixture.run(&[
        "setup",
        "--actor",
        "alice",
        "--repository",
        linked.to_str().unwrap(),
        "--root",
        fixture.root_dir.to_str().unwrap(),
        "--store-dir",
        fixture.store_dir().to_str().unwrap(),
        "--trusted-registry",
        fixture.registry_dir().to_str().unwrap(),
        "--dry-run",
    ]);
    assert!(
        output.status.success(),
        "unrelated linked worktree should be admitted: {output:?}"
    );
    assert_unchanged(&before, &fixture.snapshot());
}

#[test]
fn invalid_actor_and_oversized_toml_are_sanitized_refusals() {
    let fixture = Fixture::new();
    let before = fixture.snapshot();
    let output = fixture.run(&[
        "setup",
        "--actor",
        ".alice",
        "--repository",
        fixture.repo.to_str().unwrap(),
        "--yes",
    ]);
    assert!(!output.status.success());
    let parsed = report(&output);
    assert_eq!(parsed["error"]["field"], "actor");
    assert!(!parsed["error"]["reason"]
        .as_str()
        .unwrap()
        .contains(".alice"));
    assert_unchanged(&before, &fixture.snapshot());
    fs::create_dir_all(fixture.config_path().parent().unwrap()).unwrap();
    fs::write(fixture.config_path(), vec![b'a'; 1024 * 1024 + 2]).unwrap();
    let output = fixture.run(&["setup", "--check"]);
    assert!(!output.status.success(), "{output:?}");
    let parsed = report(&output);
    assert_eq!(parsed["outcome"], "failed");
    assert!(parsed["error"]["reason"]
        .as_str()
        .unwrap()
        .contains("size limit"));
}

#[test]
fn skills_all_keeps_earlier_registration_when_later_target_is_foreign() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.home.join(".claude/skills")).unwrap();
    fs::write(fixture.home.join(".claude/skills/work-cli"), "foreign").unwrap();
    let mut args = fixture.apply_args();
    args.extend(["--skills".into(), "all".into()]);
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = fixture.run(&args_ref);
    assert!(!output.status.success(), "{output:?}");
    let parsed = report(&output);
    assert_eq!(parsed["config_written"], true);
    assert_eq!(parsed["outcome"], "partial");
    assert!(matches!(
        parsed["skills"]["status"].as_str(),
        Some("failed" | "unknown")
    ));
    let actions = parsed["skills"]["actions"].as_array().unwrap();
    assert!(actions.iter().any(|action| action["status"] == "completed"));
    assert!(
        !actions
            .iter()
            .any(|action| { action["kind"] == "registration" && action["status"] == "completed" }),
        "foreign-target all must fail at preflight before registration: {parsed}"
    );
    assert_eq!(
        fs::read_to_string(fixture.home.join(".claude/skills/work-cli")).unwrap(),
        "foreign"
    );
}

fn git_init_bare(path: &Path) {
    fs::create_dir_all(path).unwrap();
    git(path, &["init", "-q", "--bare"]);
}

#[test]
fn empty_endpoint_and_malformed_toml_are_refused() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.store_dir()).unwrap();
    let before = fixture.snapshot();
    let args = fixture.apply_args();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = fixture.run(&args);
    assert!(!output.status.success(), "{output:?}");
    assert!(report(&output)["error"]["reason"]
        .as_str()
        .unwrap()
        .contains("endpoint"));
    assert_unchanged(&before, &fixture.snapshot());
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.config_path().parent().unwrap()).unwrap();
    fs::write(fixture.config_path(), "actor = [\n").unwrap();
    let output = fixture.run(&["setup", "--check"]);
    assert!(!output.status.success(), "{output:?}");
    let parsed = report(&output);
    assert_eq!(parsed["action"], "inspect");
    assert_eq!(parsed["outcome"], "failed");
    let reason = parsed["error"]["reason"].as_str().unwrap();
    assert!(
        reason.contains("TOML") || reason.contains("invalid"),
        "{parsed}"
    );
    assert!(!reason.contains("actor = ["));
}

#[test]
fn check_and_cancel_and_existing_yes_alone_do_not_write() {
    let fixture = Fixture::new();
    let before = fixture.snapshot();
    let output = fixture.run(&["setup", "--check"]);
    assert!(!output.status.success(), "{output:?}");
    assert_eq!(report(&output)["action"], "inspect");
    assert_eq!(report(&output)["outcome"], "failed");
    assert_eq!(report(&output)["config_written"], false);
    assert!(report(&output)["error"].is_object());
    assert_unchanged(&before, &fixture.snapshot());
    let output = fixture.run_stdin(
        &[
            "setup",
            "--interactive",
            "--actor",
            "alice",
            "--repository",
            &path_str(&fixture.repo),
            "--root",
            &path_str(&fixture.root_dir),
            "--store-dir",
            &path_str(&fixture.store_dir()),
            "--trusted-registry",
            &path_str(&fixture.registry_dir()),
        ],
        "\n\n\n\n\nnone\n\n",
    );
    assert!(!output.status.success(), "{output:?}");
    assert_eq!(report(&output)["outcome"], "cancelled");
    assert_unchanged(&before, &fixture.snapshot());
    apply(&fixture);
    let after_create = fixture.snapshot();
    let output = fixture.run(&["setup", "--yes"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(report(&output)["action"], "inspect");
    assert_eq!(report(&output)["config_written"], false);
    assert_unchanged(&after_create, &fixture.snapshot());
    let output = fixture.run(&["setup", "--check"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(report(&output)["outcome"], "success");
    assert!(report(&output)["error"].is_null());
    assert_unchanged(&after_create, &fixture.snapshot());
}

#[test]
fn guided_existing_refuses_prerequisites_before_offering_actions() {
    for kind in ["partial-store", "conflicting-endpoints"] {
        let fixture = Fixture::new();
        apply(&fixture);
        fs::create_dir(fixture.store_dir()).unwrap();
        if kind == "conflicting-endpoints" {
            fs::create_dir(fixture.registry_dir()).unwrap();
            fs::write(
                fixture.registry_dir().join("authorities.sqlite"),
                b"private foreign authority evidence",
            )
            .unwrap();
        }
        // These endpoints have no valid authority identity. Refusal must occur
        // before admission: no coordination-file exception is applicable.
        let before = fixture.snapshot();
        let output = fixture.run_stdin(&["setup", "--interactive"], "\nstandard\nyes\n");
        let after = fixture.snapshot();
        let stderr = stderr_str(&output);
        for forbidden in [
            "Additional repository",
            "Skills",
            "Type yes",
            "skill-current",
        ] {
            assert!(
                !stderr.contains(forbidden),
                "{kind}: action offered before prerequisite refusal: {stderr}"
            );
        }
        assert!(!output.status.success(), "{kind}: {output:?}");
        let parsed = report(&output);
        assert_eq!(parsed["action"], "inspect", "{kind}: {parsed}");
        assert_eq!(parsed["outcome"], "failed");
        assert_eq!(parsed["config_written"], false);
        assert_eq!(parsed["authority_modified"], false);
        assert!(parsed["created_directories"].as_array().unwrap().is_empty());
        assert!(parsed["backup_path"].is_null());
        assert_eq!(parsed["skills"]["status"], "skipped");
        assert!(parsed["skills"]["actions"].as_array().unwrap().is_empty());
        assert!(parsed["next_steps"].as_array().unwrap().is_empty());
        assert_eq!(
            parsed["error"]["reason"],
            "unresolved or conflicting authority data"
        );
        assert!(!stdout_str(&output).contains("private foreign authority evidence"));
        assert!(!stderr.contains("private foreign authority evidence"));
        assert_unchanged(&before, &after);
    }
}

#[test]
fn guided_existing_valid_inspection_reaches_actions_without_mutation() {
    for registered in [false, true] {
        let fixture = Fixture::new();
        apply(&fixture);
        let started = registered.then(|| start_task(&fixture, "guided-inspection"));
        for skills in ["none", "standard"] {
            let coordination = started
                .as_ref()
                .map(|started| CoordinationFiles::identify(&fixture, started));
            // The first registered row is cold; the later row retains warm coverage.
            let before = fixture.snapshot();
            let args = if skills == "none" {
                vec!["setup", "--interactive"]
            } else {
                vec!["setup", "--interactive", "--dry-run"]
            };
            let output = fixture.run_stdin(&args, &format!("\n{skills}\n"));
            let after = fixture.snapshot(); // before any validation reads
            if let Some(coordination) = &coordination {
                assert!(coordination.changes(&before, &after).is_empty());
            } else {
                assert_unchanged(&before, &after);
                assert!(!fixture.store_dir().exists());
                assert!(!fixture.registry_dir().exists());
            }
            assert!(output.status.success(), "{registered}/{skills}: {output:?}");
            let stderr = stderr_str(&output);
            let path = stderr.find("Existing configuration:").unwrap();
            let actor = stderr.find("actor: alice").unwrap();
            let additions = stderr.find("Additional repository").unwrap();
            let selection = stderr.find("Skills").unwrap();
            assert!(path < actor && actor < additions && additions < selection);
            let parsed = report(&output);
            assert_eq!(
                parsed["action"],
                if skills == "none" {
                    "inspect"
                } else {
                    "skills_only"
                }
            );
            assert_eq!(
                parsed["outcome"],
                if skills == "none" {
                    "success"
                } else {
                    "preview"
                }
            );
            assert_eq!(parsed["config_written"], false);
            assert_eq!(parsed["authority_modified"], false);
            assert!(parsed["created_directories"].as_array().unwrap().is_empty());
            assert!(parsed["backup_path"].is_null());
            assert!(parsed["skills"]["actions"].as_array().unwrap().is_empty());
            if let Some(started) = &started {
                assert_durable_start_evidence(&fixture, started, &before, &after);
            }
        }
    }
}

#[test]
fn guided_interactive_accepts_displayed_defaults_and_prefills() {
    let fixture = Fixture::new();
    let stdin = format!(
        "alice\n{}\n\n\n\n\n\n\n\n\nnone\nyes\n",
        path_str(&fixture.repo)
    );
    let output = fixture.run_stdin(&["setup", "--interactive"], &stdin);
    assert!(
        output.status.success(),
        "{output:?}\n{}",
        stderr_str(&output)
    );
    let parsed = report(&output);
    assert_eq!(parsed["outcome"], "success");
    assert_eq!(parsed["config_written"], true);
    let stderr = stderr_str(&output);
    assert!(
        stderr.contains("repository_limit: 8")
            && stderr.contains("1073741824")
            && stderr.contains("1 GiB")
            && stderr.contains("5368709120")
            && stderr.contains("5 GiB"),
        "guided preview must show allocation values: {stderr}"
    );
    let config =
        work_cli::config::Config::from_text(&fs::read_to_string(fixture.config_path()).unwrap())
            .unwrap();
    assert_eq!(config.roots, vec![fixture.home.join("worktrees")]);
    assert_eq!(config.store_dir.unwrap(), fixture.store_dir());
}

#[test]
fn setup_then_add_before_start_refuses_without_mutation() {
    let fixture = Fixture::new();
    apply(&fixture);
    let before = fixture.snapshot();
    let bytes = fs::read(fixture.config_path()).unwrap();
    for guided in [false, true] {
        let output = if guided {
            fixture.run_stdin(
                &["setup", "--interactive"],
                &format!("{}\n\nnone\nyes\n", path_str(&fixture.extra_repo)),
            )
        } else {
            fixture.run(&[
                "setup",
                "--add-repository",
                fixture.extra_repo.to_str().unwrap(),
                "--yes",
            ])
        };
        assert!(!output.status.success(), "{guided}: {output:?}");
        let parsed = report(&output);
        assert_eq!(parsed["config_written"], false);
        assert!(parsed["error"]["reason"]
            .as_str()
            .unwrap()
            .contains("registered-root evidence"));
        assert_eq!(fs::read(fixture.config_path()).unwrap(), bytes);
        assert_unchanged(&before, &fixture.snapshot());
    }
}

#[test]
fn duplicate_add_is_noop_and_skills_only_does_not_rewrite() {
    let fixture = Fixture::new();
    apply(&fixture);
    let bytes = fs::read(fixture.config_path()).unwrap();
    let identity = fs::symlink_metadata(fixture.config_path()).unwrap();
    let before = fixture.snapshot();
    let output = fixture.run(&[
        "setup",
        "--add-repository",
        fixture.repo.to_str().unwrap(),
        "--yes",
    ]);
    assert!(output.status.success(), "{output:?}");
    let parsed = report(&output);
    assert_eq!(parsed["outcome"], "no_op");
    assert_eq!(parsed["config_written"], false);
    assert!(parsed["backup_path"].is_null());
    assert_eq!(fs::read(fixture.config_path()).unwrap(), bytes);
    assert_eq!(
        fs::symlink_metadata(fixture.config_path()).unwrap().ino(),
        identity.ino()
    );
    assert_unchanged(&before, &fixture.snapshot());
    let output = fixture.run(&["setup", "--skills", "none", "--yes"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(report(&output)["action"], "inspect");
    assert_eq!(fs::read(fixture.config_path()).unwrap(), bytes);
    assert_unchanged(&before, &fixture.snapshot());
}

#[test]
fn appearing_config_during_interactive_confirm_is_not_clobbered() {
    let fixture = Fixture::new();
    let store = fixture.store_dir();
    let registry = fixture.registry_dir();
    let args = [
        "setup",
        "--interactive",
        "--actor",
        "alice",
        "--repository",
        fixture.repo.to_str().unwrap(),
        "--root",
        fixture.root_dir.to_str().unwrap(),
        "--store-dir",
        store.to_str().unwrap(),
        "--trusted-registry",
        registry.to_str().unwrap(),
        "--skills",
        "none",
        "--repository-limit",
        "8",
        "--owner-limit",
        "4",
        "--floor-bytes",
        "1073741824",
        "--warn-bytes",
        "5368709120",
    ];
    let mut child = spawn(&fixture, &args);
    let mut stderr = child.stderr.take().unwrap();
    let text = read_until(&mut stderr, "Type yes", Duration::from_secs(10));
    assert!(text.contains("Type yes"), "{text}");
    fs::create_dir_all(fixture.config_path().parent().unwrap()).unwrap();
    fs::write(fixture.config_path(), "keep = true\n").unwrap();
    {
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(b"yes\n").unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(fixture.config_path()).unwrap(),
        "keep = true\n"
    );
}

#[test]
fn later_public_start_succeeds_after_fresh_setup() {
    let fixture = Fixture::new();
    apply(&fixture);
    assert!(!fixture.store_dir().exists());
    assert!(!fixture.registry_dir().exists());
    let output = fixture.run(&[
        "start",
        "--task",
        "setup-proof",
        "--base",
        "main",
        "--branch",
        "setup-proof",
    ]);
    assert!(
        output.status.success(),
        "{output:?}\n{}",
        stderr_str(&output)
    );
    let started: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(started["checkout"].as_str().is_some());
    assert!(fixture.store_dir().join("store.sqlite").exists() || fixture.store_dir().exists());
}

#[test]
fn existing_add_preserves_unknown_toml_and_charged_task() {
    let fixture = Fixture::new();
    apply(&fixture);
    let first = start_task(&fixture, "charged");
    let checkout = first["checkout"].as_str().unwrap().to_owned();
    let before_config = parse_config(&fixture.config_path());
    let before_text = fs::read_to_string(fixture.config_path()).unwrap();
    let root_id = identity(&fixture.root_dir);
    let store_id = identity(&fixture.store_dir());
    let registry_id = identity(&fixture.registry_dir());
    let mut raw = fs::read_to_string(fixture.config_path()).unwrap();
    if !raw.starts_with("mystery") {
        raw = format!("mystery = \"keep\"\n{raw}");
    }
    fs::write(fixture.config_path(), &raw).unwrap();
    let status = fixture.run(&["status", "--json"]);
    assert!(
        status.status.success(),
        "{status:?}\n{}",
        stderr_str(&status)
    );
    let before_status: Value = serde_json::from_slice(&status.stdout).unwrap();
    let coordination = CoordinationFiles::identify(&fixture, &first);
    let before_destinations = fixture.snapshot();
    let output = fixture.run(&[
        "setup",
        "--add-repository",
        fixture.extra_repo.to_str().unwrap(),
        "--root",
        fixture.root_dir.to_str().unwrap(),
        "--yes",
    ]);
    assert!(
        output.status.success(),
        "{output:?}\n{}",
        stderr_str(&output)
    );
    // Capture before report processing or subsequent authority validation reads.
    let after_destinations = fixture.snapshot();
    let authority_paths = |snapshot: &BTreeMap<PathBuf, Entry>| {
        snapshot
            .iter()
            .filter(|(path, _)| path.starts_with("state") || path.starts_with("worktrees"))
            .map(|(path, entry)| (path.clone(), entry.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let changes = coordination.changes(
        &authority_paths(&before_destinations),
        &authority_paths(&after_destinations),
    );
    assert!(
        changes.is_empty(),
        "addition must preserve authority families: {changes:?}"
    );
    assert_durable_start_evidence(&fixture, &first, &before_destinations, &after_destinations);
    let parsed = report(&output);
    assert_eq!(parsed["action"], "add_repositories");
    assert_eq!(parsed["config_written"], true);
    assert_eq!(parsed["authority_modified"], false);
    let backup = PathBuf::from(parsed["backup_path"].as_str().unwrap());
    assert_eq!(fs::read_to_string(&backup).unwrap(), raw);
    let updated = fs::read_to_string(fixture.config_path()).unwrap();
    assert!(updated.contains("mystery"));
    assert!(updated.contains(&path_str(&fixture.extra_repo)));
    let after_config = parse_config(&fixture.config_path());
    assert!(
        before_text.contains("actor = ") && updated.contains("actor = \"alice\""),
        "actor must be preserved: {updated}"
    );
    assert_eq!(after_config.roots, before_config.roots);
    assert_eq!(after_config.store_dir, before_config.store_dir);
    assert_eq!(
        after_config.trusted_registry,
        before_config.trusted_registry
    );
    assert_eq!(
        after_config.allocation.as_ref().map(|a| (
            a.repository_limit,
            a.owner_limit,
            a.floor_bytes,
            a.warn_bytes
        )),
        before_config.allocation.as_ref().map(|a| (
            a.repository_limit,
            a.owner_limit,
            a.floor_bytes,
            a.warn_bytes
        ))
    );
    assert_eq!(identity(&fixture.root_dir), root_id);
    assert_eq!(identity(&fixture.store_dir()), store_id);
    assert_eq!(identity(&fixture.registry_dir()), registry_id);
    let next = parsed["next_steps"].as_array().unwrap();
    assert!(
        next.iter().any(|step| {
            let argv = step.as_array().unwrap();
            argv.windows(2)
                .any(|pair| pair[0] == "--root" && pair[1] == path_str(&fixture.root_dir))
        }),
        "selected registered root must govern next-step guidance: {parsed}"
    );
    let status = fixture.run(&["status", "--json"]);
    let after_status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(after_status["charged"], before_status["charged"]);
    assert_eq!(after_status["checkouts"][0]["checkout"], checkout);
    assert_eq!(
        after_status["checkouts"][0]["state"],
        before_status["checkouts"][0]["state"]
    );
    assert_eq!(
        after_status["checkouts"][0]["path"],
        before_status["checkouts"][0]["path"]
    );
}

#[test]
fn skills_standard_after_create_and_foreign_target_is_partial() {
    let fixture = Fixture::new();
    let mut args = fixture.apply_args();
    args.extend(["--skills".into(), "standard".into()]);
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = fixture.run(&args_ref);
    assert!(
        output.status.success(),
        "{output:?}\n{}",
        stderr_str(&output)
    );
    let parsed = report(&output);
    assert_eq!(parsed["config_written"], true);
    assert_eq!(parsed["skills"]["selection"], "standard");
    assert_eq!(parsed["skills"]["status"], "succeeded");
    assert!(fixture.home.join(".agents/skills/work-cli").exists());
    assert!(parsed["next_steps"].as_array().unwrap().iter().any(|step| {
        step.as_array().is_some_and(|argv| {
            argv.iter()
                .any(|part| part.as_str() == Some("reload-skill-catalog"))
        })
    }));
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.home.join(".agents/skills")).unwrap();
    fs::write(fixture.home.join(".agents/skills/work-cli"), "foreign").unwrap();
    let mut args = fixture.apply_args();
    args.extend(["--skills".into(), "standard".into()]);
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = fixture.run(&args_ref);
    assert!(!output.status.success(), "{output:?}");
    let parsed = report(&output);
    assert_eq!(parsed["config_written"], true);
    assert_eq!(parsed["outcome"], "partial");
    assert!(fixture.config_path().is_file());
    assert_eq!(
        fs::read_to_string(fixture.home.join(".agents/skills/work-cli")).unwrap(),
        "foreign"
    );
}

#[test]
fn ancestor_symlink_config_can_inspect_but_write_refuses() {
    let fixture = Fixture::new();
    apply(&fixture);
    let started = start_task(&fixture, "registered");
    let real = fixture.root.join("real-config");
    fs::rename(&fixture.config_home, &real).unwrap();
    std::os::unix::fs::symlink(&real, &fixture.config_home).unwrap();
    let output = fixture.run(&["setup", "--check"]);
    assert!(
        output.status.success(),
        "{output:?}\n{}",
        stderr_str(&output)
    );
    let bytes = fs::read(fixture.config_path()).unwrap();
    let coordination = CoordinationFiles::identify(&fixture, &started);
    let before = fixture.snapshot();
    let output = fixture.run(&[
        "setup",
        "--add-repository",
        fixture.extra_repo.to_str().unwrap(),
        "--dry-run",
    ]);
    assert!(
        !output.status.success(),
        "dry-run must refuse writer-ineligible ancestor symlink: {output:?}"
    );
    assert_eq!(report(&output)["outcome"], "failed");
    assert_eq!(fs::read(fixture.config_path()).unwrap(), bytes);
    let output = fixture.run(&[
        "setup",
        "--add-repository",
        fixture.extra_repo.to_str().unwrap(),
        "--yes",
    ]);
    assert!(!output.status.success(), "{output:?}");
    assert_eq!(fs::read(fixture.config_path()).unwrap(), bytes);
    assert_warm_unchanged(&coordination, &before, &fixture.snapshot());
}

#[test]
fn first_time_overrides_user_suggestion_and_home_state_fallback() {
    let fixture = Fixture::new();
    let mut args = fixture.create_args();
    args.extend([
        "--repository-limit".into(),
        "3".into(),
        "--owner-limit".into(),
        "2".into(),
        "--floor-bytes".into(),
        "1048576".into(),
        "--warn-bytes".into(),
        "2097152".into(),
    ]);
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = fixture.run(&args_ref);
    assert!(output.status.success(), "{output:?}");
    let stderr = stderr_str(&output);
    assert!(
        stderr.contains("repository_limit: 3")
            && stderr.contains("owner_limit: 2")
            && stderr.contains("1048576")
            && stderr.contains("1 MiB")
            && stderr.contains("2097152")
            && stderr.contains("2 MiB"),
        "override preview incomplete: {stderr}"
    );

    let stdin = format!("\n{}\n\n\n\n\n\n\n\n\nnone\nyes\n", path_str(&fixture.repo));
    let output = fixture.run_with(
        &["setup", "--interactive"],
        &[("USER", Some("alice"))],
        stdin.as_bytes(),
    );
    assert!(
        output.status.success(),
        "valid USER suggestion: {output:?}\n{}",
        stderr_str(&output)
    );
    assert!(stderr_str(&output).contains("alice"));

    let fixture = Fixture::new();
    let before = fixture.snapshot();
    let stdin = format!("\n{}\n\n\n\n\n\n\n\n\nnone\nyes\n", path_str(&fixture.repo));
    let output = fixture.run_with(
        &["setup", "--interactive"],
        &[("USER", Some(".bad"))],
        stdin.as_bytes(),
    );
    assert!(
        !output.status.success(),
        "invalid USER must not be suggested"
    );
    assert!(!stderr_str(&output).contains("[.bad]"));
    assert_unchanged(&before, &fixture.snapshot());

    let fixture = Fixture::new();
    let output = fixture.run_with(
        &[
            "setup",
            "--actor",
            "alice",
            "--repository",
            &path_str(&fixture.repo),
            "--root",
            &path_str(&fixture.root_dir),
            "--dry-run",
        ],
        &[("XDG_STATE_HOME", None)],
        b"",
    );
    assert!(
        output.status.success(),
        "{output:?}\n{}",
        stderr_str(&output)
    );
    let expected = fixture.home.join(".local/state/work/store");
    assert!(
        stderr_str(&output).contains(&path_str(&expected)),
        "HOME state fallback missing: {}",
        stderr_str(&output)
    );

    let explicit = fixture.root.join("explicit/config.toml");
    fs::create_dir(explicit.parent().unwrap()).unwrap();
    let before = fixture.snapshot();
    let output = fixture.run_with(
        &[
            "setup",
            "--actor",
            "alice",
            "--repository",
            &path_str(&fixture.repo),
            "--yes",
        ],
        &[
            ("WORK_CONFIG", Some(explicit.to_str().unwrap())),
            ("HOME", None),
            ("XDG_CONFIG_HOME", None),
            ("XDG_STATE_HOME", None),
        ],
        b"",
    );
    assert!(
        !output.status.success(),
        "missing bases must not be guessed"
    );
    assert_eq!(report(&output)["outcome"], "failed");
    assert_unchanged(&before, &fixture.snapshot());
}

#[test]
fn eof_cancellation_preserves_write_families() {
    let fixture = Fixture::new();
    let before = fixture.snapshot();
    let store = path_str(&fixture.store_dir());
    let registry = path_str(&fixture.registry_dir());
    let repo = path_str(&fixture.repo);
    let root = path_str(&fixture.root_dir);
    let args = [
        "setup",
        "--interactive",
        "--actor",
        "alice",
        "--repository",
        repo.as_str(),
        "--root",
        root.as_str(),
        "--store-dir",
        store.as_str(),
        "--trusted-registry",
        registry.as_str(),
        "--repository-limit",
        "8",
        "--owner-limit",
        "4",
        "--floor-bytes",
        "1073741824",
        "--warn-bytes",
        "5368709120",
        "--skills",
        "none",
    ];
    let output = fixture.run_stdin(&args, "");
    assert!(!output.status.success(), "{output:?}");
    let parsed = report(&output);
    assert_eq!(
        parsed["outcome"],
        "cancelled",
        "{parsed}\nstderr={}",
        stderr_str(&output)
    );
    assert_unchanged(&before, &fixture.snapshot());
    let output = fixture.run_stdin(&args, "alice\n");
    assert!(!output.status.success(), "{output:?}");
    let parsed = report(&output);
    assert_eq!(
        parsed["outcome"],
        "cancelled",
        "{parsed}\nstderr={}",
        stderr_str(&output)
    );
    assert_unchanged(&before, &fixture.snapshot());
}

#[test]
fn brand_new_home_with_missing_parents_is_usable_for_later_start() {
    let fixture = Fixture::new();
    let env = [("XDG_CONFIG_HOME", None), ("XDG_STATE_HOME", None)];
    let output = fixture.run_with(
        &[
            "setup",
            "--actor",
            "alice",
            "--repository",
            &path_str(&fixture.repo),
            "--yes",
        ],
        &env,
        b"",
    );
    assert!(
        output.status.success(),
        "{output:?}\n{}",
        stderr_str(&output)
    );
    let config = fixture.home.join(".config/work/config.toml");
    assert!(config.is_file());
    assert!(fixture.home.join("worktrees").is_dir());
    let store = fixture.home.join(".local/state/work/store");
    let registry = fixture.home.join(".local/state/work/registry");
    assert!(store.parent().unwrap().is_dir());
    assert!(!store.exists());
    assert!(!registry.exists());
    let output = fixture.run_with(
        &[
            "start",
            "--task",
            "fresh-home",
            "--base",
            "main",
            "--branch",
            "fresh-home",
        ],
        &env,
        b"",
    );
    assert!(
        output.status.success(),
        "{output:?}\n{}",
        stderr_str(&output)
    );
    assert!(store.exists() || store.join("store.sqlite").exists());
}

#[test]
fn enumerated_validation_refusals_do_not_mutate() {
    let fixture = Fixture::new();
    apply(&fixture);
    let bytes = fs::read(fixture.config_path()).unwrap();
    let before = fixture.snapshot();
    let missing_root = fixture.root.join("missing-root");
    let missing_root = path_str(&missing_root);
    for args in [
        vec!["setup", "--actor", "bob", "--yes"],
        vec!["setup", "--repository-limit", "1", "--yes"],
        vec!["setup", "--root", missing_root.as_str(), "--yes"],
    ] {
        let output = fixture.run(&args);
        assert!(!output.status.success(), "{args:?}: {output:?}");
        assert_eq!(report(&output)["outcome"], "failed", "{args:?}");
        assert_eq!(fs::read(fixture.config_path()).unwrap(), bytes);
        assert_unchanged(&before, &fixture.snapshot());
    }

    fs::create_dir_all(fixture.store_parent()).unwrap();
    let fixture_prepared = Fixture::new();
    fs::create_dir_all(fixture_prepared.store_parent()).unwrap();
    let parsed = apply(&fixture_prepared);
    assert_eq!(parsed["outcome"], "success");
    assert!(!fixture_prepared.store_dir().exists());
    assert!(!fixture_prepared.registry_dir().exists());

    let fixture = Fixture::new();
    apply(&fixture);
    fs::create_dir_all(fixture.store_dir()).unwrap();
    let before = fixture.snapshot();
    let output = fixture.run(&["setup", "--check"]);
    assert!(
        !output.status.success(),
        "partial authority must not validate: {output:?}"
    );
    assert_eq!(report(&output)["outcome"], "failed");
    assert_unchanged(&before, &fixture.snapshot());
    let output = fixture.run(&["setup"]);
    assert!(
        !output.status.success(),
        "inspect must refuse partial authority: {output:?}"
    );
    assert_eq!(report(&output)["outcome"], "failed");

    let fixture = Fixture::new();
    apply(&fixture);
    fs::create_dir_all(fixture.store_dir()).unwrap();
    fs::create_dir_all(fixture.registry_dir()).unwrap();
    let before = fixture.snapshot();
    let output = fixture.run(&["setup", "--check"]);
    assert!(
        !output.status.success(),
        "conflicting empty endpoints must not validate: {output:?}"
    );
    assert_eq!(report(&output)["outcome"], "failed");
    assert_unchanged(&before, &fixture.snapshot());

    let fixture = Fixture::new();
    apply(&fixture);
    let parent = fixture.store_parent();
    fs::create_dir_all(&parent).unwrap();
    let mut permissions = fs::metadata(&parent).unwrap().permissions();
    permissions.set_mode(0o000);
    fs::set_permissions(&parent, permissions).unwrap();
    let output = fixture.run(&["setup", "--check"]);
    let mut permissions = fs::metadata(&parent)
        .ok()
        .map(|m| m.permissions())
        .unwrap_or_else(|| fs::Permissions::from_mode(0o700));
    permissions.set_mode(0o700);
    fs::set_permissions(&parent, permissions).unwrap();
    assert!(
        !output.status.success(),
        "permission-denied ancestry must not prove absence: {output:?}"
    );
    assert_eq!(report(&output)["outcome"], "failed");

    let source = Fixture::new();
    apply(&source);
    let started = start_task(&source, "managed-src");
    let destination = PathBuf::from(started["destination"].as_str().unwrap());
    let other = Fixture::new();
    let other_root = other.root.join("other-worktrees");
    let before = other.snapshot();
    let output = other.run(&[
        "setup",
        "--actor",
        "alice",
        "--repository",
        destination.to_str().unwrap(),
        "--root",
        other_root.to_str().unwrap(),
        "--store-dir",
        other.store_dir().to_str().unwrap(),
        "--trusted-registry",
        other.registry_dir().to_str().unwrap(),
        "--yes",
    ]);
    assert!(
        !output.status.success(),
        "linked managed checkout must be refused: {output:?}"
    );
    assert_eq!(report(&output)["outcome"], "failed");
    assert_eq!(report(&output)["config_written"], false);
    assert_unchanged(&before, &other.snapshot());
}

#[test]
fn selected_root_requires_registration_and_skills_paths_are_covered() {
    let fixture = Fixture::new();
    apply(&fixture);
    let before = fixture.snapshot();
    let output = fixture.run(&["setup", "--root", fixture.root_dir.to_str().unwrap()]);
    assert!(
        !output.status.success(),
        "unregistered --root must not inspect as valid: {output:?}"
    );
    assert_eq!(report(&output)["outcome"], "failed");
    assert_unchanged(&before, &fixture.snapshot());
    let started = start_task(&fixture, "rooted");
    prime_readonly(&fixture, &started);
    let coordination = CoordinationFiles::identify(&fixture, &started);
    let before = fixture.snapshot();
    let output = fixture.run(&["setup", "--root", fixture.root_dir.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
    let parsed = report(&output);
    assert_eq!(parsed["action"], "inspect");
    assert_eq!(parsed["config_written"], false);
    assert!(
        parsed["next_steps"].as_array().unwrap().iter().any(|step| {
            let argv = step.as_array().unwrap();
            argv[0] == "work"
                && argv[1] == "start"
                && argv
                    .windows(2)
                    .any(|pair| pair[0] == "--root" && pair[1] == path_str(&fixture.root_dir))
        }),
        "selected registered inspection root must govern guidance: {parsed}"
    );
    assert_warm_unchanged(&coordination, &before, &fixture.snapshot());
    let output = fixture.run(&["setup", "--skills", "standard", "--yes"]);
    assert!(
        output.status.success(),
        "{output:?}\n{}",
        stderr_str(&output)
    );
    assert_eq!(report(&output)["action"], "skills_only");
    assert_eq!(report(&output)["config_written"], false);
    assert!(fixture.home.join(".agents/skills/work-cli").exists());
    let bytes = fs::read(fixture.config_path()).unwrap();
    let ino = fs::symlink_metadata(fixture.config_path()).unwrap().ino();
    let output = fixture.run(&[
        "setup",
        "--add-repository",
        fixture.repo.to_str().unwrap(),
        "--skills",
        "standard",
        "--yes",
    ]);
    assert!(
        output.status.success(),
        "{output:?}\n{}",
        stderr_str(&output)
    );
    assert_eq!(report(&output)["action"], "skills_only");
    assert_eq!(report(&output)["config_written"], false);
    assert_eq!(fs::read(fixture.config_path()).unwrap(), bytes);
    assert_eq!(
        fs::symlink_metadata(fixture.config_path()).unwrap().ino(),
        ino
    );
}

#[test]
fn explicit_all_skills_succeeds_without_foreign_targets() {
    let fixture = Fixture::new();
    let mut args = fixture.apply_args();
    args.extend(["--skills".into(), "all".into()]);
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = fixture.run(&args_ref);
    assert!(
        output.status.success(),
        "{output:?}\n{}",
        stderr_str(&output)
    );
    let parsed = report(&output);
    assert_eq!(parsed["skills"]["selection"], "all");
    assert_eq!(parsed["skills"]["status"], "succeeded");
    assert!(fixture.home.join(".agents/skills/work-cli").exists());
    assert!(fixture.home.join(".claude/skills/work-cli").exists());
    assert!(fixture.home.join(".codex/skills/work-cli").exists());
    let fixture = Fixture::new();
    apply(&fixture);
    start_task(&fixture, "skills-all");
    let output = fixture.run(&["setup", "--skills", "all", "--yes"]);
    assert!(
        output.status.success(),
        "{output:?}\n{}",
        stderr_str(&output)
    );
    assert_eq!(report(&output)["action"], "skills_only");
    assert_eq!(report(&output)["skills"]["status"], "succeeded");
}

#[test]
fn public_stale_preview_lock_and_unsafe_writer_artifacts_are_refused() {
    let fixture = Fixture::new();
    apply(&fixture);
    start_task(&fixture, "stale");
    let extra = path_str(&fixture.extra_repo);
    let mut child = spawn(
        &fixture,
        &[
            "setup",
            "--interactive",
            "--add-repository",
            extra.as_str(),
            "--skills",
            "none",
        ],
    );
    let mut stderr = child.stderr.take().unwrap();
    let text = read_until(&mut stderr, "Type yes", Duration::from_secs(10));
    assert!(text.contains("Type yes"), "{text}");
    fs::write(fixture.config_path(), "keep = true\n").unwrap();
    {
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(b"yes\n").unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(fixture.config_path()).unwrap(),
        "keep = true\n"
    );

    let fixture = Fixture::new();
    apply(&fixture);
    let allocation = start_task(&fixture, "locked");
    let parent = fixture.config_path().parent().unwrap().to_path_buf();
    let lock = parent.join(".work-setup.lock");
    fs::write(&lock, b"").unwrap();
    // The acknowledgment is emitted only after the cooperating process owns flock.
    let mut holder = Command::new("/usr/bin/timeout")
        .args(["20", "/usr/bin/python3", "-c", "import fcntl,sys; f=open(sys.argv[1],'r+'); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB); print('lock acquired',flush=True); sys.stdin.read(1)", lock.to_str().unwrap()])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("hold setup lock");
    let ack = read_until(
        &mut holder.stdout.take().unwrap(),
        "lock acquired",
        Duration::from_secs(10),
    );
    assert!(
        ack.contains("lock acquired"),
        "holder did not acquire lock: {ack}"
    );
    let started = fixture.run(&["status", "--json"]);
    assert!(started.status.success(), "{started:?}");
    let coordination = CoordinationFiles::identify(&fixture, &allocation);
    let before = fixture.snapshot();
    let output = fixture.run(&[
        "setup",
        "--add-repository",
        fixture.extra_repo.to_str().unwrap(),
        "--yes",
    ]);
    {
        use std::io::Write;
        holder.stdin.as_mut().unwrap().write_all(b"x").unwrap();
    }
    assert!(holder.wait().unwrap().success());
    assert!(!output.status.success(), "{output:?}");
    assert_eq!(report(&output)["error"]["field"], "lock");
    assert_eq!(
        report(&output)["error"]["reason"],
        "another setup writer holds the lock"
    );
    assert_warm_unchanged(&coordination, &before, &fixture.snapshot());

    let fixture = Fixture::new();
    apply(&fixture);
    start_task(&fixture, "hardlink");
    let alias = fixture.root.join("config-alias.toml");
    fs::hard_link(fixture.config_path(), &alias).unwrap();
    let output = fixture.run(&[
        "setup",
        "--add-repository",
        fixture.extra_repo.to_str().unwrap(),
        "--yes",
    ]);
    assert!(
        !output.status.success(),
        "hardlink config must be refused: {output:?}"
    );
    fs::remove_file(&alias).unwrap();

    let fixture = Fixture::new();
    apply(&fixture);
    start_task(&fixture, "backup-unsafe");
    let backup_dir = fixture
        .config_path()
        .parent()
        .unwrap()
        .join(".work-setup-backups");
    fs::write(&backup_dir, "not-a-dir").unwrap();
    let unknown = fixture
        .config_path()
        .parent()
        .unwrap()
        .join("unknown-artifact");
    fs::write(&unknown, "keep").unwrap();
    let output = fixture.run(&[
        "setup",
        "--add-repository",
        fixture.extra_repo.to_str().unwrap(),
        "--yes",
    ]);
    assert!(
        !output.status.success(),
        "unsafe backup destination: {output:?}"
    );
    assert_eq!(fs::read_to_string(&unknown).unwrap(), "keep");
    assert_eq!(fs::read_to_string(&backup_dir).unwrap(), "not-a-dir");
}

// Real fixture types, not injected I/O errors. The returned socket keeps its
// endpoint alive across the public invocation; no fixture path is followed here.
fn unsafe_artifact(
    path: &Path,
    kind: &str,
    target: &Path,
) -> Option<std::os::unix::net::UnixListener> {
    match kind {
        "symlink" => std::os::unix::fs::symlink(target, path).unwrap(),
        "hardlink" => fs::hard_link(target, path).unwrap(),
        "directory" => fs::create_dir(path).unwrap(),
        "mode" => {
            fs::write(path, b"unknown private artifact").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        "fifo" => rustix::fs::mknodat(
            rustix::fs::CWD,
            path,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap(),
        "socket" => return Some(std::os::unix::net::UnixListener::bind(path).unwrap()),
        _ => panic!("unknown artifact fixture: {kind}"),
    }
    None
}

#[test]
fn unsafe_lock_types_links_and_modes_preserve_all_destinations() {
    for kind in ["symlink", "hardlink", "directory", "mode", "fifo", "socket"] {
        let fixture = Fixture::new();
        apply(&fixture);
        let started = start_task(&fixture, "unsafe-lock");
        prime_readonly(&fixture, &started);
        let lock = fixture
            .config_path()
            .parent()
            .unwrap()
            .join(".work-setup.lock");
        fs::remove_file(&lock).unwrap();
        let target = fixture.root.join("unknown-lock-target");
        fs::write(&target, b"unknown lock bytes").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let _socket = unsafe_artifact(&lock, kind, &target);
        let coordination = CoordinationFiles::identify(&fixture, &started);
        let before = fixture.snapshot();
        let output = fixture.run(&[
            "setup",
            "--add-repository",
            fixture.extra_repo.to_str().unwrap(),
            "--yes",
        ]);
        assert!(!output.status.success(), "{kind}: {output:?}");
        let parsed = report(&output);
        assert_eq!(parsed["error"]["field"], "lock", "{kind}: {parsed}");
        assert!(
            parsed["error"]["reason"]
                .as_str()
                .unwrap()
                .contains("setup-writer lock"),
            "{kind}: {parsed}"
        );
        assert_eq!(parsed["config_written"], false);
        assert!(parsed["backup_path"].is_null());
        assert!(parsed["created_directories"].as_array().unwrap().is_empty());
        assert_warm_unchanged(&coordination, &before, &fixture.snapshot());
    }
}

#[test]
fn unsafe_backup_directory_types_links_and_modes_preserve_all_destinations() {
    for kind in ["symlink", "hardlink", "file", "mode", "fifo", "socket"] {
        let fixture = Fixture::new();
        apply(&fixture);
        let started = start_task(&fixture, "unsafe-backup");
        prime_readonly(&fixture, &started);
        let backup = fixture
            .config_path()
            .parent()
            .unwrap()
            .join(".work-setup-backups");
        let target = fixture.root.join("unknown-backup-target");
        let _socket = match kind {
            "symlink" => {
                fs::create_dir(&target).unwrap();
                fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
                fs::write(target.join("retained"), b"unknown backup bytes").unwrap();
                unsafe_artifact(&backup, kind, &target)
            }
            "mode" => {
                fs::create_dir(&backup).unwrap();
                fs::set_permissions(&backup, fs::Permissions::from_mode(0o755)).unwrap();
                fs::write(backup.join("retained"), b"unknown backup bytes").unwrap();
                None
            }
            "file" => {
                fs::write(&backup, b"unknown backup bytes").unwrap();
                None
            }
            _ => {
                fs::write(&target, b"unknown backup bytes").unwrap();
                unsafe_artifact(&backup, kind, &target)
            }
        };
        let coordination = CoordinationFiles::identify(&fixture, &started);
        let before = fixture.snapshot();
        let output = fixture.run(&[
            "setup",
            "--add-repository",
            fixture.extra_repo.to_str().unwrap(),
            "--yes",
        ]);
        assert!(!output.status.success(), "{kind}: {output:?}");
        let parsed = report(&output);
        assert_eq!(parsed["error"]["field"], "backup_path", "{kind}: {parsed}");
        assert_eq!(
            parsed["error"]["reason"], "backup directory is unsafe",
            "{kind}: {parsed}"
        );
        assert_eq!(parsed["config_written"], false);
        assert!(parsed["backup_path"].is_null());
        assert!(parsed["created_directories"].as_array().unwrap().is_empty());
        assert_warm_unchanged(&coordination, &before, &fixture.snapshot());
    }
}

#[test]
fn unsafe_final_config_types_and_links_preserve_all_destinations() {
    for kind in ["symlink", "hardlink", "directory", "fifo", "socket"] {
        let fixture = Fixture::new();
        apply(&fixture);
        let started = start_task(&fixture, "unsafe-config");
        prime_readonly(&fixture, &started);
        let config = fixture.config_path();
        let target = fixture.root.join("unknown-config-target");
        fs::rename(&config, &target).unwrap();
        let _socket = unsafe_artifact(&config, kind, &target);
        let before = fixture.snapshot();
        let output = fixture.run(&[
            "setup",
            "--add-repository",
            fixture.extra_repo.to_str().unwrap(),
            "--yes",
        ]);
        assert!(!output.status.success(), "{kind}: {output:?}");
        let parsed = report(&output);
        assert_eq!(parsed["error"]["field"], "config_path", "{kind}: {parsed}");
        assert!(
            parsed["error"]["reason"]
                .as_str()
                .unwrap()
                .contains(if kind == "hardlink" {
                    "hard link"
                } else {
                    "regular file"
                }),
            "{kind}: {parsed}"
        );
        assert_eq!(parsed["config_written"], false);
        assert!(parsed["created_directories"].as_array().unwrap().is_empty());
        assert_unchanged(&before, &fixture.snapshot());
    }
}

#[test]
fn noncanonical_and_symlinked_data_and_root_paths_refuse_before_mutation() {
    let fixture = Fixture::new();
    let real = fixture.root.join("real-path-parent");
    fs::create_dir(&real).unwrap();
    let alias = fixture.root.join("symlink-path-parent");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    for flag in ["--root", "--store-dir", "--trusted-registry"] {
        for (path, reason) in [
            (real.join("../noncanonical"), "absolute and canonical"),
            (alias.join("missing"), "symlink ancestors"),
            (alias.clone(), "symlink ancestors"),
        ] {
            for mode in ["--dry-run", "--yes"] {
                let mut args = fixture.create_args();
                let index = args.iter().position(|arg| arg == flag).unwrap();
                args[index + 1] = path_str(&path);
                *args.last_mut().unwrap() = mode.into();
                let before = fixture.snapshot();
                let output = fixture.run(&args.iter().map(String::as_str).collect::<Vec<_>>());
                assert!(!output.status.success(), "{flag} {path:?}: {output:?}");
                let parsed = report(&output);
                let field = match flag {
                    "--root" => "root",
                    "--store-dir" => "store_dir",
                    _ => "trusted_registry",
                };
                assert_eq!(parsed["error"]["field"], field, "{parsed}");
                assert!(
                    parsed["error"]["reason"].as_str().unwrap().contains(reason),
                    "{parsed}"
                );
                assert_eq!(parsed["config_written"], false);
                assert!(parsed["created_directories"].as_array().unwrap().is_empty());
                assert_unchanged(&before, &fixture.snapshot());
            }
        }
    }
}

#[test]
fn overlapping_authority_destinations_refuse_before_mutation() {
    let fixture = Fixture::new();
    let store = fixture.store_dir();
    let registry = fixture.registry_dir();
    for (label, proposed_store, proposed_registry, config, field, reason) in [
        (
            "same endpoints",
            store.clone(),
            store.clone(),
            fixture.config_path(),
            "store_dir",
            "distinct paths",
        ),
        (
            "nested registry",
            store.clone(),
            store.join("registry"),
            fixture.config_path(),
            "store_dir",
            "distinct paths",
        ),
        (
            "nested store",
            registry.join("store"),
            registry.clone(),
            fixture.config_path(),
            "store_dir",
            "distinct paths",
        ),
        (
            "store in repository",
            fixture.repo.join("store"),
            registry.clone(),
            fixture.config_path(),
            "store_dir",
            "outside repositories and managed roots",
        ),
        (
            "registry in root",
            store.clone(),
            fixture.root_dir.join("registry"),
            fixture.config_path(),
            "store_dir",
            "outside repositories and managed roots",
        ),
        (
            "config in store",
            store.clone(),
            registry.clone(),
            store.join("config.toml"),
            "config_path",
            "inside authority data",
        ),
        (
            "config in registry",
            store.clone(),
            registry.clone(),
            registry.join("config.toml"),
            "config_path",
            "inside authority data",
        ),
        (
            "skill in store",
            fixture.home.clone(),
            registry.clone(),
            fixture.config_path(),
            "store_dir",
            "skill destinations",
        ),
        (
            "skill in registry",
            store.clone(),
            fixture.data.clone(),
            fixture.config_path(),
            "store_dir",
            "skill destinations",
        ),
    ] {
        for mode in ["--dry-run", "--yes"] {
            let mut args = fixture.create_args();
            for (flag, value) in [
                ("--store-dir", &proposed_store),
                ("--trusted-registry", &proposed_registry),
            ] {
                let index = args.iter().position(|arg| arg == flag).unwrap();
                args[index + 1] = path_str(value);
            }
            *args.last_mut().unwrap() = mode.into();
            let before = fixture.snapshot();
            let output = fixture.run_with(
                &args.iter().map(String::as_str).collect::<Vec<_>>(),
                &[("WORK_CONFIG", Some(config.to_str().unwrap()))],
                b"",
            );
            assert!(!output.status.success(), "{label}: {output:?}");
            let parsed = report(&output);
            assert_eq!(parsed["error"]["field"], field, "{label}: {parsed}");
            assert!(
                parsed["error"]["reason"].as_str().unwrap().contains(reason),
                "{label}: {parsed}"
            );
            assert_eq!(parsed["config_written"], false);
            assert!(parsed["created_directories"].as_array().unwrap().is_empty());
            assert_unchanged(&before, &fixture.snapshot());
        }
    }
}

#[test]
fn managed_root_inside_absent_authority_endpoint_refuses_before_mutation() {
    let mut observations = Vec::new();
    for endpoint in ["store", "registry"] {
        for mode in ["--dry-run", "--yes"] {
            let fixture = Fixture::new();
            let authority = if endpoint == "store" {
                fixture.store_dir()
            } else {
                fixture.registry_dir()
            };
            let mut args = fixture.create_args();
            let index = args.iter().position(|arg| arg == "--root").unwrap();
            args[index + 1] = path_str(&authority.join("tasks"));
            *args.last_mut().unwrap() = mode.into();
            let before = fixture.snapshot();
            let output = fixture.run(&args.iter().map(String::as_str).collect::<Vec<_>>());
            let parsed = report(&output);
            let after = fixture.snapshot();
            eprintln!(
                "root in absent {endpoint} {mode}: success={}, report={parsed}, unchanged={}",
                output.status.success(),
                before == after
            );
            observations.push((endpoint, mode, output, parsed, before, after));
        }
    }
    for (endpoint, mode, output, parsed, before, after) in observations {
        assert!(!output.status.success(), "{endpoint} {mode}: {output:?}");
        assert_eq!(parsed["error"]["field"], "store_dir", "{parsed}");
        assert!(
            parsed["error"]["reason"]
                .as_str()
                .unwrap()
                .contains("outside repositories and managed roots"),
            "{parsed}"
        );
        assert_eq!(parsed["config_written"], false);
        assert!(parsed["created_directories"].as_array().unwrap().is_empty());
        assert!(parsed["backup_path"].is_null());
        assert_unchanged(&before, &after);
    }
}

#[test]
fn actual_home_dot_config_fallback_symlink_reads_but_refuses_writes() {
    let fixture = Fixture::new();
    let env = [("WORK_CONFIG", None), ("XDG_CONFIG_HOME", None)];
    let args = fixture.apply_args();
    let output = fixture.run_with(
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        &env,
        b"",
    );
    assert!(output.status.success(), "{output:?}");
    let output = fixture.run_with(
        &[
            "start", "--task", "fallback", "--base", "main", "--branch", "fallback",
        ],
        &env,
        b"",
    );
    assert!(output.status.success(), "{output:?}");
    let started: Value = serde_json::from_slice(&output.stdout).unwrap();
    let output = fixture.run_with(&["status", "--json"], &env, b"");
    assert!(output.status.success(), "{output:?}");
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["initialized"], true);
    assert!(status["charged"].as_u64().unwrap() > 0);
    assert_eq!(status["checkouts"][0]["checkout"], started["checkout"]);
    let real = fixture.root.join("real-home-config");
    fs::rename(fixture.home.join(".config"), &real).unwrap();
    std::os::unix::fs::symlink(&real, fixture.home.join(".config")).unwrap();
    let config = fixture.home.join(".config/work/config.toml");
    let coordination = CoordinationFiles::identify(&fixture, &started);
    let before = fixture.snapshot();
    for args in [vec!["setup"], vec!["setup", "--check"]] {
        let output = fixture.run_with(&args, &env, b"");
        assert!(output.status.success(), "{output:?}");
        assert_eq!(report(&output)["config_path"], path_str(&config));
        assert_warm_unchanged(&coordination, &before, &fixture.snapshot());
    }
    for mode in ["--dry-run", "--yes"] {
        let output = fixture.run_with(
            &[
                "setup",
                "--add-repository",
                fixture.extra_repo.to_str().unwrap(),
                mode,
            ],
            &env,
            b"",
        );
        assert!(!output.status.success(), "{output:?}");
        let parsed = report(&output);
        assert_eq!(parsed["config_path"], path_str(&config));
        assert_eq!(parsed["error"]["field"], "config_path");
        assert!(
            parsed["error"]["reason"]
                .as_str()
                .unwrap()
                .contains("symlink ancestors"),
            "{parsed}"
        );
        assert_eq!(parsed["config_written"], false);
        assert!(parsed["created_directories"].as_array().unwrap().is_empty());
        assert!(parsed["backup_path"].is_null());
        assert_warm_unchanged(&coordination, &before, &fixture.snapshot());
    }
}

fn spawn(fixture: &Fixture, args: &[&str]) -> std::process::Child {
    Command::new("/usr/bin/timeout")
        .arg("20")
        .arg(env!("CARGO_BIN_EXE_work"))
        .args(args)
        .current_dir(&fixture.root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &fixture.home)
        .env("XDG_CONFIG_HOME", &fixture.config_home)
        .env("XDG_STATE_HOME", &fixture.state)
        .env("XDG_DATA_HOME", &fixture.data)
        .env("TMPDIR", fixture.root.join("tmp"))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .envs(locale_env())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn setup")
}

fn read_until(stderr: &mut impl Read, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    while Instant::now() < deadline {
        match stderr.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if String::from_utf8_lossy(&buf).contains(needle) {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}
