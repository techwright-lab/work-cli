//! Library-only snapshots exercise handoff guards, not OS containment proof.
#[path = "support/scope_spawn.rs"]
mod owned;
use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::PathBuf,
    process::{Child, Command},
    time::{Duration, Instant},
};
use work_cli::{runtime_scope::*, scope_child::*, scope_driver::*, scope_launch::*};
use work_contract::RunId;
const BOOT: &str = "f312459a-9346-4d02-9139-c80a7017d962";
const INV: &str = "b312459a93464d029139c80a7017d962";
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
struct Collector;
impl LibraryCollector for Collector {
    fn identities(&self) -> Result<(ChildIdentity, ChildIdentity), &'static str> {
        Ok((
            identity(std::process::id()),
            identity(rustix::process::getppid().unwrap().as_raw_pid() as u32),
        ))
    }
}
#[test]
fn local_child() {
    let Some(context) = std::env::var_os("LAUNCH_FIXTURE_CONTEXT") else {
        return;
    };
    let argv = [
        "/usr/bin/touch".into(),
        std::env::var_os("LAUNCH_FIXTURE_MARKER").unwrap(),
    ];
    if run_with_collector(std::path::Path::new(&context), &argv, &Collector).is_err() {
        std::process::exit(42);
    }
}
struct Fixture {
    _tmp: tempfile::TempDir,
    _bus: UnixListener,
    root: PathBuf,
    driver: Driver,
    launch: GuardedLaunch,
    child: Child,
}
impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_owned();
        for name in ["runtime", "gate"] {
            fs::create_dir(root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bus = UnixListener::bind(root.join("runtime/bus")).unwrap();
        let gate = prepare(
            &root.join("gate"),
            &intent(),
            &identity(std::process::id()),
            &std::env::current_dir().unwrap(),
            OriginalRuntime::new(None, None),
            Duration::from_secs(3),
        )
        .unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "local_child", "--nocapture"])
            .env("LAUNCH_FIXTURE_CONTEXT", gate.context_path())
            .env("LAUNCH_FIXTURE_MARKER", root.join("delegate"))
            .spawn()
            .unwrap();
        let pid = child.id();
        fs::create_dir_all(root.join("proc/sys/kernel/random")).unwrap();
        fs::write(root.join("proc/sys/kernel/random/boot_id"), BOOT).unwrap();
        fs::create_dir_all(root.join(format!("proc/{pid}"))).unwrap();
        fs::write(
            root.join(format!("proc/{pid}/stat")),
            format!("{pid} (fixture) S {} 123 0\n", vec!["0"; 18].join(" ")),
        )
        .unwrap();
        fs::write(
            root.join(format!("proc/{pid}/cgroup")),
            format!("0::{}\n", identity(pid).cgroup),
        )
        .unwrap();
        let group = root.join("cg/user.slice").join(intent().unit_name());
        fs::create_dir_all(&group).unwrap();
        fs::write(group.join("cgroup.type"), "domain\n").unwrap();
        fs::write(group.join("cgroup.procs"), format!("{pid}\n")).unwrap();
        fs::write(root.join("properties"), format!("Id={}\nInvocationID={INV}\nControlGroup={}\nLoadState=loaded\nActiveState=active\n", intent().unit_name(), identity(pid).cgroup)).unwrap();
        fs::write(root.join("manager"), format!("#!/bin/sh\ncase \" $* \" in *' kill '*) printf '%s\\n' \"$@\" \"$XDG_RUNTIME_DIR\" \"$DBUS_SESSION_BUS_ADDRESS\" > '{0}/cancel';; *) /usr/bin/cat '{0}/properties';; esac\n", root.display())).unwrap();
        fs::set_permissions(root.join("manager"), fs::Permissions::from_mode(0o700)).unwrap();
        let driver = Driver::with_io(
            RuntimeContext::new(
                root.join("runtime"),
                format!("unix:path={}/runtime/bus", root.display()),
            )
            .unwrap(),
            LibraryIo {
                systemctl: root.join("manager"),
                proc_root: root.join("proc"),
                cgroup_root: root.join("cg"),
                between_censuses: None,
            },
            Limits::default(),
        )
        .unwrap();
        let mut launch = GuardedLaunch::adopt_prepared(intent(), gate);
        let until = Instant::now() + Duration::from_secs(2);
        while !launch.poll_blocked().unwrap() {
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(5));
        }
        Self {
            _tmp: tmp,
            _bus: bus,
            root,
            driver,
            launch,
            child,
        }
    }
    fn bind(&mut self) {
        self.launch.bind(&self.driver).unwrap();
    }
    fn replace(&self, file: &str, old: &str, new: &str) {
        let path = self.root.join(file);
        fs::write(&path, fs::read_to_string(&path).unwrap().replace(old, new)).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
#[test]
fn blocked_bound_and_released_are_separate_persistence_boundaries() {
    let mut f = Fixture::new();
    assert_eq!(f.launch.phase(), Phase::Blocked);
    assert!(f.launch.binding().is_none());
    assert!(f.launch.release(&f.driver).is_err());
    assert!(!f.root.join("gate/permit.json").exists());
    f.bind();
    assert_eq!(f.launch.phase(), Phase::Bound);
    assert_eq!(
        f.launch.binding().unwrap().trusted_child().pid,
        f.child.id()
    );
    assert!(!f.root.join("delegate").exists());
    assert!(!f.root.join("gate/permit.json").exists());
    f.launch.release(&f.driver).unwrap();
    assert_eq!(f.launch.phase(), Phase::Released);
    assert!(f.child.wait().unwrap().success());
    assert!(f.root.join("delegate").exists());
    assert!(f.launch.release(&f.driver).is_err());
    assert!(f.root.join("gate/context.json").exists());
}
#[test]
fn release_reobserves_identity_and_complete_recursive_membership() {
    for case in [
        "invocation",
        "cgroup",
        "boot",
        "source",
        "pid-reuse",
        "missing-member",
    ] {
        let mut f = Fixture::new();
        f.bind();
        match case {
            "invocation" => f.replace("properties", INV, "a312459a93464d029139c80a7017d962"),
            "cgroup" => f.replace("properties", "/user.slice/", "/other.slice/"),
            "boot" => fs::write(
                f.root.join("proc/sys/kernel/random/boot_id"),
                "a312459a-9346-4d02-9139-c80a7017d962",
            )
            .unwrap(),
            "source" => f.replace("properties", intent().unit_name(), "wrong.scope"),
            "pid-reuse" => f.replace(&format!("proc/{}/stat", f.child.id()), "123", "124"),
            _ => fs::write(
                f.root
                    .join("cg/user.slice")
                    .join(intent().unit_name())
                    .join("cgroup.procs"),
                "",
            )
            .unwrap(),
        }
        assert!(f.launch.release(&f.driver).is_err(), "{case}");
        assert_eq!(f.launch.outcome(), Outcome::RecoveryHold, "{case}");
        assert!(!f.root.join("gate/permit.json").exists(), "{case}");
        assert!(!f.root.join("delegate").exists(), "{case}");
        assert!(f.root.join("gate/context.json").exists());
    }
}
#[test]
fn cancellation_rejects_unknown_or_replaced_units_without_signalling() {
    for case in ["unbound", "wrong-unit", "wrong-invocation", "boot"] {
        let mut f = Fixture::new();
        if case != "unbound" {
            f.bind();
        }
        match case {
            "wrong-unit" => f.replace("properties", intent().unit_name(), "wrong.scope"),
            "wrong-invocation" => f.replace("properties", INV, "a312459a93464d029139c80a7017d962"),
            "boot" => fs::write(
                f.root.join("proc/sys/kernel/random/boot_id"),
                "a312459a-9346-4d02-9139-c80a7017d962",
            )
            .unwrap(),
            _ => (),
        }
        assert!(f.launch.cancel(&f.driver).is_err(), "{case}");
        assert_eq!(f.launch.outcome(), Outcome::RecoveryHold);
        assert!(!f.root.join("cancel").exists(), "{case}");
    }
}
#[test]
fn post_release_failure_and_drop_preserve_recovery_records() {
    let mut f = Fixture::new();
    f.bind();
    f.launch.release(&f.driver).unwrap();
    assert!(f.child.wait().unwrap().success());
    f.replace("properties", INV, "a312459a93464d029139c80a7017d962");
    assert!(f.launch.cancel(&f.driver).is_err());
    assert_eq!(f.launch.phase(), Phase::Released);
    assert_eq!(f.launch.outcome(), Outcome::RecoveryHold);
    fs::create_dir(f.root.join("unused")).unwrap();
    fs::set_permissions(f.root.join("unused"), fs::Permissions::from_mode(0o700)).unwrap();
    let spare = prepare(
        &f.root.join("unused"),
        &intent(),
        &identity(std::process::id()),
        &std::env::current_dir().unwrap(),
        OriginalRuntime::new(None, None),
        Duration::from_secs(1),
    )
    .unwrap();
    drop(std::mem::replace(
        &mut f.launch,
        GuardedLaunch::adopt_prepared(intent(), spare),
    ));
    for record in ["context.json", "claimed", "ready.json", "permit.json"] {
        assert!(f.root.join("gate").join(record).exists(), "{record}");
    }
    assert!(!f.root.join("cancel").exists());
}
#[test]
fn cancellation_backend_failures_are_bounded_recovery_holds() {
    for backend in ["exit 7", "exec /usr/bin/sleep 10", "exec /usr/bin/yes"] {
        let mut f = Fixture::new();
        f.bind();
        fs::write(f.root.join("manager"), format!("#!/bin/sh\ncase \" $* \" in *' kill '*) {backend};; *) /usr/bin/cat '{}/properties';; esac\n", f.root.display())).unwrap();
        let driver = Driver::with_io(
            RuntimeContext::new(
                f.root.join("runtime"),
                format!("unix:path={}/runtime/bus", f.root.display()),
            )
            .unwrap(),
            LibraryIo {
                systemctl: f.root.join("manager"),
                proc_root: f.root.join("proc"),
                cgroup_root: f.root.join("cg"),
                between_censuses: None,
            },
            Limits {
                duration: Duration::from_millis(100),
                ..Limits::default()
            },
        )
        .unwrap();
        let started = Instant::now();
        assert!(f.launch.cancel(&driver).is_err(), "{backend}");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(f.launch.outcome(), Outcome::RecoveryHold);
        assert!(!f.root.join("gate/permit.json").exists());
        assert!(!f.root.join("delegate").exists());
    }
}
#[test]
fn cancellation_requests_exact_unit_with_manager_context_but_never_claims_closed() {
    let mut f = Fixture::new();
    f.bind();
    f.launch.cancel(&f.driver).unwrap();
    assert_eq!(f.launch.outcome(), Outcome::CancellationRequested);
    assert_eq!(f.launch.phase(), Phase::Bound);
    let args = fs::read_to_string(f.root.join("cancel")).unwrap();
    assert!(args.contains(&format!(
        "--user\n--no-pager\n--no-ask-password\nkill\n--kill-whom=all\n--signal=SIGTERM\n{}\n",
        intent().unit_name()
    )));
    assert!(args.contains(&format!(
        "{}\nunix:path={}/runtime/bus\n",
        f.root.join("runtime").display(),
        f.root.display()
    )));
    assert!(!f.root.join("gate/permit.json").exists());
}
