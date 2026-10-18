//! Fixture evidence proves gate logic, NOT actual OS/systemd containment.
use std::{
    ffi::OsString,
    fs,
    io::Write,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use work_cli::{runtime_scope::*, scope_child::*};
use work_contract::RunId;
const BOOT: &str = "f312459a-9346-4d02-9139-c80a7017d962";
fn intent() -> LaunchIntent {
    LaunchIntent::new(
        RunId::parse("019281b2-67de-7000-8000-000000000001").unwrap(),
        BOOT,
    )
    .unwrap()
}
fn identity(pid: u32) -> ChildIdentity {
    ChildIdentity {
        pid,
        start_ticks: 123,
        boot: BOOT.into(),
        cgroup: format!("/user.slice/{}", intent().unit_name()),
    }
}
fn setup(timeout: Duration, original: OriginalRuntime) -> (tempfile::TempDir, Prepared) {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let gate = prepare(
        dir.path(),
        &intent(),
        &identity(777),
        &std::env::current_dir().unwrap(),
        original,
        timeout,
    )
    .unwrap();
    (dir, gate)
}
fn binding(child: &ChildIdentity) -> Binding {
    let now = Instant::now();
    bind(
        &intent(),
        child,
        &Observation {
            boot: BOOT.into(),
            observed_at: now,
            unit: UnitPresence::Present {
                identity: ScopeIdentity {
                    unit: intent().unit_name().into(),
                    invocation: "b312459a93464d029139c80a7017d962".into(),
                    cgroup: identity(1).cgroup,
                },
                load: LoadStatus::Loaded,
                active: ActiveStatus::Active,
            },
            membership: Membership::Present(vec![child.clone()]),
            recursive_coverage: Coverage::Complete,
            participant_coverage: Coverage::Unknown,
            participants: vec![],
        },
        now,
        Duration::from_secs(1),
    )
    .unwrap()
}
struct Fixture;
impl LibraryCollector for Fixture {
    fn identities(&self) -> Result<(ChildIdentity, ChildIdentity), &'static str> {
        let mut child = identity(std::process::id());
        let mut parent = identity(777);
        let case = std::env::var("CASE").unwrap_or_default();
        if case.starts_with("late-")
            && std::path::Path::new(&std::env::var_os("CHILD_CONTEXT").unwrap())
                .parent()
                .unwrap()
                .join("trigger")
                .exists()
        {
            match case.as_str() {
                "late-parent" => parent.start_ticks += 1,
                "late-start" => child.start_ticks += 1,
                "late-boot" => child.boot = "other".into(),
                "late-cgroup" => child.cgroup.push_str("/moved"),
                "late-dead" => return Err("fixture absent"),
                _ => unreachable!(),
            }
        }
        match case.as_str() {
            "boot" => child.boot = "other".into(),
            "cgroup" => child.cgroup = "/outside".into(),
            "parent" => parent.start_ticks += 1,
            "dead" => return Err("fixture absent"),
            _ => (),
        }
        Ok((child, parent))
    }
}
#[test]
fn local_child() {
    let Some(context) = std::env::var_os("CHILD_CONTEXT") else {
        return;
    };
    let args: Vec<OsString> = vec!["/bin/sh".into(), "-c".into(), "printf '%s\\n' \"$1\"; /bin/cat; printf '%s:%s\\n' \"${XDG_RUNTIME_DIR-unset}\" \"${DBUS_SESSION_BUS_ADDRESS-unset}\"".into(), "test".into(), "a b;secret-argv".into()];
    if let Err(e) = run_with_collector(std::path::Path::new(&context), &args, &Fixture) {
        eprintln!("{e}");
        std::process::exit(42);
    }
}
fn spawn(gate: &Prepared, case: &str) -> std::process::Child {
    let mut command = Command::new(std::env::current_exe().unwrap());
    if case == "cwd" {
        command.current_dir("/");
    }
    command
        .args(["--exact", "local_child", "--nocapture"])
        .env("CHILD_CONTEXT", gate.context_path())
        .env("CASE", case)
        .env("XDG_RUNTIME_DIR", "manager-only")
        .env("DBUS_SESSION_BUS_ADDRESS", "manager-only")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}
fn wait_ready(gate: &Prepared) -> Ready {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(r) = gate.read_ready().unwrap() {
            return r;
        }
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn waits_for_matching_binding_preserves_streams_argv_and_original_runtime() {
    for (original, expected) in [
        (
            OriginalRuntime::new(
                Some(OsString::from("original secret")),
                Some(OsString::from("address secret")),
            ),
            b"original secret:address secret".to_vec(),
        ),
        (OriginalRuntime::new(None, None), b"unset:unset".to_vec()),
        (
            OriginalRuntime::new(Some(OsString::new()), Some(OsString::new())),
            b":".to_vec(),
        ),
        (
            OriginalRuntime::new(Some(OsString::from_vec(vec![0xff])), None),
            b"\xff:unset".to_vec(),
        ),
    ] {
        let (dir, gate) = setup(Duration::from_secs(3), original);
        let mut child = spawn(&gate, "");
        child.stdin.take().unwrap().write_all(b"input\n").unwrap();
        let ready = wait_ready(&gate);
        std::thread::sleep(Duration::from_millis(20));
        assert!(child.try_wait().unwrap().is_none(), "delegation must wait");
        assert!(gate.release(&binding(&identity(999))).is_err());
        gate.release(&binding(ready.child())).unwrap();
        assert!(gate.release(&binding(ready.child())).is_err());
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut suffix = b"a b;secret-argv\ninput\n".to_vec();
        suffix.extend(expected);
        suffix.push(b'\n');
        assert!(output.stdout.ends_with(&suffix));
        for entry in fs::read_dir(dir.path()).unwrap() {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            assert!(!bytes
                .windows(b"secret-argv".len())
                .any(|w| w == b"secret-argv"));
            assert!(!bytes
                .windows(b"manager-only".len())
                .any(|w| w == b"manager-only"));
        }
    }
}
#[test]
fn invalid_identity_timeout_and_repeat_claim_never_delegate() {
    for case in ["boot", "cgroup", "parent", "dead", "timeout", "cwd"] {
        let (_dir, gate) = setup(Duration::from_millis(60), OriginalRuntime::new(None, None));
        let output = spawn(&gate, case).wait_with_output().unwrap();
        assert!(!output.status.success(), "{case}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("secret-argv"));
        let retry = spawn(&gate, "").wait_with_output().unwrap();
        assert!(!retry.status.success(), "repeat {case}");
    }
}
#[test]
fn hidden_cli_uses_real_os_and_fixed_safe_error() {
    let (dir, gate) = setup(Duration::from_millis(50), OriginalRuntime::new(None, None));
    let output = Command::new(env!("CARGO_BIN_EXE_work"))
        .arg("__scope-child")
        .arg("--context")
        .arg(gate.context_path())
        .args(["--", "/bin/echo", "credential-never-print"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"scope child held\n");
    assert!(!dir.path().join("ready.json").exists());
}

fn replace_json(path: &std::path::Path, change: impl FnOnce(&mut serde_json::Value)) {
    let mut record = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    change(&mut record);
    fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
}
#[test]
fn corrupt_ready_or_different_binding_cannot_release() {
    for case in [
        "nonce",
        "pid",
        "start",
        "boot",
        "cgroup",
        "cwd",
        "malformed",
        "oversize",
        "mode",
        "symlink",
        "hardlink",
    ] {
        let (dir, gate) = setup(Duration::from_millis(300), OriginalRuntime::new(None, None));
        let child = spawn(&gate, "");
        let ready = wait_ready(&gate);
        let path = dir.path().join("ready.json");
        match case {
            "malformed" => fs::write(&path, b"{").unwrap(),
            "oversize" => fs::write(&path, vec![b' '; 32769]).unwrap(),
            "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            "symlink" => {
                fs::rename(&path, dir.path().join("original")).unwrap();
                std::os::unix::fs::symlink("original", &path).unwrap();
            }
            "hardlink" => fs::hard_link(&path, dir.path().join("linked")).unwrap(),
            _ => replace_json(&path, |r| match case {
                "nonce" => r["nonce"] = "0".repeat(64).into(),
                "pid" => r["child"]["pid"] = 999.into(),
                "start" => r["child"]["start_ticks"] = 124.into(),
                "boot" => r["child"]["boot"] = "other".into(),
                "cgroup" => r["child"]["cgroup"] = "/outside".into(),
                "cwd" => r["cwd"]["ino"] = 1.into(),
                _ => unreachable!(),
            }),
        }
        assert!(gate.release(&binding(ready.child())).is_err(), "{case}");
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("secret-argv"));
    }
}
#[test]
fn forged_or_stale_permits_never_delegate() {
    for case in [
        "nonce",
        "pid",
        "start",
        "boot",
        "cgroup",
        "cwd",
        "unit",
        "invocation",
        "malformed",
        "stale",
    ] {
        let (dir, gate) = setup(Duration::from_millis(500), OriginalRuntime::new(None, None));
        if case == "stale" {
            fs::write(dir.path().join("permit.json"), b"{}").unwrap();
        }
        let child = spawn(&gate, "");
        if case != "stale" {
            let ready = wait_ready(&gate);
            let r: serde_json::Value =
                serde_json::from_slice(&fs::read(dir.path().join("ready.json")).unwrap()).unwrap();
            let mut p = serde_json::json!({"nonce": r["nonce"], "child": r["child"], "cwd": r["cwd"], "boot": BOOT, "unit": intent().unit_name(), "group": ready.child().cgroup, "invocation": "b312459a93464d029139c80a7017d962"});
            match case {
                "nonce" => p["nonce"] = "0".repeat(64).into(),
                "pid" => p["child"]["pid"] = 999.into(),
                "start" => p["child"]["start_ticks"] = 124.into(),
                "boot" => p["boot"] = "other".into(),
                "cgroup" => p["group"] = "/outside".into(),
                "cwd" => p["cwd"]["ino"] = 1.into(),
                "unit" => p["unit"] = "other.scope".into(),
                "invocation" => p["invocation"] = "invalid".into(),
                "malformed" => p = serde_json::json!({}),
                _ => unreachable!(),
            }
            // Publish complete malformed evidence atomically, as a corrupt writer might.
            let temporary = dir.path().join("test-permit");
            fs::write(&temporary, serde_json::to_vec(&p).unwrap()).unwrap();
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
            fs::rename(temporary, dir.path().join("permit.json")).unwrap();
        }
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success(), "{case}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("secret-argv"));
    }
}
#[test]
fn identity_change_after_ready_holds_even_with_valid_permit() {
    for case in [
        "late-parent",
        "late-start",
        "late-boot",
        "late-cgroup",
        "late-dead",
    ] {
        let (dir, gate) = setup(Duration::from_secs(1), OriginalRuntime::new(None, None));
        let child = spawn(&gate, case);
        let ready = wait_ready(&gate);
        fs::write(dir.path().join("trigger"), b"changed").unwrap();
        gate.release(&binding(ready.child())).unwrap();
        assert!(
            !child.wait_with_output().unwrap().status.success(),
            "{case}"
        );
    }
}
#[test]
fn private_directory_no_symlink_components_and_context_collision() {
    let (dir, _gate) = setup(Duration::from_secs(1), OriginalRuntime::new(None, None));
    assert!(prepare(
        dir.path(),
        &intent(),
        &identity(777),
        &std::env::current_dir().unwrap(),
        OriginalRuntime::new(None, None),
        Duration::from_secs(1)
    )
    .is_err());
    let alias = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(dir.path(), alias.path().join("link")).unwrap();
    assert!(prepare(
        &alias.path().join("link"),
        &intent(),
        &identity(777),
        &std::env::current_dir().unwrap(),
        OriginalRuntime::new(None, None),
        Duration::from_secs(1)
    )
    .is_err());
}
