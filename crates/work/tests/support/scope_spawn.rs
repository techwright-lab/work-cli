// EXEC-style launcher fixtures only: no real manager or containment claim.
use super::*;
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use work_cli::scope_spawn::*;
struct SpawnCollector {
    parent: ChildIdentity,
    boot: String,
}
impl LibraryCollector for SpawnCollector {
    fn identities(&self) -> Result<(ChildIdentity, ChildIdentity), &'static str> {
        let mut child = identity(std::process::id());
        child.boot.clone_from(&self.boot);
        // Deliberately trust fixture context for parent, even in fork mode: the
        // OwnedLaunch PID guard must independently reject the unexpected fork.
        Ok((child, self.parent.clone()))
    }
}
#[test]
fn owned_fixture_child() {
    let Some(root) = std::env::var_os("OWNED_FIXTURE_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let context: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("gate/context.json")).unwrap()).unwrap();
    let parent = &context["parent"];
    let parent = ChildIdentity {
        pid: parent["pid"].as_u64().unwrap() as u32,
        start_ticks: parent["start_ticks"].as_u64().unwrap(),
        boot: parent["boot"].as_str().unwrap().into(),
        cgroup: parent["cgroup"].as_str().unwrap().into(),
    };
    let argv = fs::read(root.join("delegate-argv")).unwrap();
    let argv: Vec<_> = argv
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
        .map(|b| OsString::from_vec(b.to_vec()))
        .collect();
    let collector = SpawnCollector {
        boot: parent.boot.clone(),
        parent,
    };
    if run_with_collector(&root.join("gate/context.json"), &argv, &collector).is_err() {
        std::process::exit(42);
    }
}
struct SpawnFixture {
    _tmp: tempfile::TempDir,
    _bus: UnixListener,
    root: PathBuf,
    driver: Driver,
    boot: String,
}
impl SpawnFixture {
    fn new(mode: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_owned();
        for name in ["runtime", "gate"] {
            fs::create_dir(root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bus = UnixListener::bind(root.join("runtime/bus")).unwrap();
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap()
            .trim()
            .to_owned();
        fs::create_dir_all(root.join("proc/sys/kernel/random")).unwrap();
        fs::write(root.join("proc/sys/kernel/random/boot_id"), &boot).unwrap();
        let group = root.join("cg/user.slice").join(intent().unit_name());
        fs::create_dir_all(&group).unwrap();
        fs::write(group.join("cgroup.type"), "domain\n").unwrap();
        fs::write(group.join("cgroup.procs"), "").unwrap();
        fs::write(root.join("properties"), format!("Id={}\nInvocationID={INV}\nControlGroup={}\nLoadState=loaded\nActiveState=active\n", intent().unit_name(), identity(1).cgroup)).unwrap();
        let script = |name: &str, body: String| {
            fs::write(root.join(name), format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        };
        script(
            "manager",
            format!("exec /usr/bin/cat '{}/properties'", root.display()),
        );
        script("systemd-run", format!("printf '%s\\0' \"$@\" > '{0}/launch-argv'\nprintf '%s\\n' \"$XDG_RUNTIME_DIR\" \"$DBUS_SESSION_BUS_ADDRESS\" > '{0}/launch-env'\npwd > '{0}/launch-cwd'\nwhile [ \"$1\" != -- ]; do shift; done\nshift\n{1}", root.display(), match mode { "fork" => "\"$@\" & wait", "exit" => "exit 7", "timeout" => "exec /usr/bin/sleep 10", _ => "exec \"$@\"" }));
        script("self", format!("[ \"$1\" = __scope-child ] && [ \"$2\" = --context ] && [ \"$4\" = -- ] || exit 9\nshift 4\nprintf '%s\\0' \"$@\" > '{0}/delegate-argv'\nexport OWNED_FIXTURE_ROOT='{0}'\nexec '{1}' --exact owned::owned_fixture_child --nocapture", root.display(), std::env::current_exe().unwrap().display()));
        script("delegate", format!("printf '%s\\0' \"$@\" > '{0}/actual-argv'\nprintf '%s\\n' \"${{XDG_RUNTIME_DIR-unset}}\" \"${{DBUS_SESSION_BUS_ADDRESS-unset}}\" > '{0}/actual-env'\n/usr/bin/touch '{0}/delegate-executed'", root.display()));
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
        Self {
            _tmp: tmp,
            _bus: bus,
            root,
            driver,
            boot,
        }
    }
    fn spawn(&self, timeout: Duration) -> OwnedLaunch {
        let argv = [
            self.root.join("delegate").into_os_string(),
            "$SECRET no-expand ; ' literal".into(),
            OsString::from_vec(vec![0xff]),
        ];
        OwnedLaunch::spawn_with_io(
            &self.driver,
            LaunchIntent::new(
                RunId::parse("019281b2-67de-7000-8000-000000000001").unwrap(),
                &self.boot,
            )
            .unwrap(),
            &self.root.join("gate"),
            &self.root,
            &argv,
            LaunchPolicy::new(Duration::from_secs(60), timeout).unwrap(),
            LaunchIo {
                systemd_run: self.root.join("systemd-run"),
                self_binary: self.root.join("self"),
            },
        )
        .expect("EXEC-style fixture must actually spawn")
    }
    fn evidence(&self, pid: u32) {
        fs::create_dir_all(self.root.join(format!("proc/{pid}"))).unwrap();
        fs::write(
            self.root.join(format!("proc/{pid}/stat")),
            format!("{pid} (fixture) S {} 123 0\n", vec!["0"; 18].join(" ")),
        )
        .unwrap();
        fs::write(
            self.root.join(format!("proc/{pid}/cgroup")),
            format!("0::{}\n", identity(pid).cgroup),
        )
        .unwrap();
        fs::write(
            self.root
                .join("cg/user.slice")
                .join(intent().unit_name())
                .join("cgroup.procs"),
            format!("{pid}\n"),
        )
        .unwrap();
    }
}
fn poll_owned(launch: &mut OwnedLaunch) -> Result<(), &'static str> {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        if launch.poll_blocked()? {
            return Ok(());
        }
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn exec_launcher_owns_exact_ready_pid_and_preserves_literal_command_policy() {
    let f = SpawnFixture::new("exec");
    let original = serde_json::to_value(OriginalRuntime::capture()).unwrap();
    let mut launch = f.spawn(Duration::from_secs(2));
    assert_eq!(launch.phase(), Phase::Prepared);
    poll_owned(&mut launch).unwrap();
    f.evidence(launch.pid());
    launch.bind(&f.driver).unwrap();
    assert_eq!(launch.binding().unwrap().trusted_child().pid, launch.pid());
    assert!(!f.root.join("gate/permit.json").exists());
    assert!(!f.root.join("delegate-executed").exists());
    let args = fs::read(f.root.join("launch-argv")).unwrap();
    let args: Vec<_> = args.split(|b| *b == 0).filter(|b| !b.is_empty()).collect();
    let expected = [
        "--user",
        "--scope",
        "--quiet",
        "--no-ask-password",
        "--expand-environment=no",
    ];
    assert_eq!(&args[..5], expected.map(str::as_bytes).as_slice());
    assert_eq!(
        args[5],
        format!("--unit={}", intent().unit_name()).as_bytes()
    );
    assert_eq!(args[6], b"--description=work managed execution");
    assert_eq!(args[7], b"--property=RuntimeMaxSec=60s");
    assert_eq!(args[8], b"--");
    assert_eq!(args[9], f.root.join("self").as_os_str().as_bytes());
    assert_eq!(args[10], b"__scope-child");
    assert_eq!(args[11], b"--context");
    assert_eq!(
        args[12],
        f.root.join("gate/context.json").as_os_str().as_bytes()
    );
    assert_eq!(args[13], b"--");
    assert_eq!(args[15], b"$SECRET no-expand ; ' literal");
    assert_eq!(args[16], &[0xff]);
    let context = fs::read(f.root.join("gate/context.json")).unwrap();
    assert!(!context.windows(7).any(|w| w == b"$SECRET"));
    let context: serde_json::Value = serde_json::from_slice(&context).unwrap();
    assert_eq!(context["original"], original);
    assert_eq!(context["parent"]["pid"], std::process::id());
    assert_eq!(
        fs::read_to_string(f.root.join("launch-cwd"))
            .unwrap()
            .trim(),
        f.root.to_str().unwrap()
    );
    assert_eq!(
        fs::read_to_string(f.root.join("launch-env")).unwrap(),
        format!(
            "{}\nunix:path={}/runtime/bus\n",
            f.root.join("runtime").display(),
            f.root.display()
        )
    );
    launch.release(&f.driver).unwrap();
    assert!(launch.wait().unwrap().success());
    assert!(launch.try_wait().unwrap().unwrap().success());
    assert!(f.root.join("delegate-executed").exists());
    assert_eq!(
        fs::read(f.root.join("actual-argv")).unwrap(),
        b"$SECRET no-expand ; ' literal\0\xff\0"
    );
    let mut original_bytes = Vec::new();
    for key in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
        original_bytes.extend_from_slice(
            std::env::var_os(key)
                .as_deref()
                .map_or(b"unset".as_slice(), |v| v.as_bytes()),
        );
        original_bytes.push(b'\n');
    }
    assert_eq!(fs::read(f.root.join("actual-env")).unwrap(), original_bytes);
    assert_eq!(launch.phase(), Phase::Released);
    assert!(launch.release(&f.driver).is_err());
    assert!(launch.binding().is_some()); // root exit is not scope quiescence
}
#[test]
fn unexpected_fork_exit_and_timeout_hold_and_reap_only_owned_launcher() {
    for mode in ["fork", "exit", "timeout"] {
        let f = SpawnFixture::new(mode);
        let mut launch = f.spawn(Duration::from_millis(300));
        assert!(poll_owned(&mut launch).is_err(), "{mode}");
        assert_eq!(launch.outcome(), Outcome::RecoveryHold, "{mode}");
        assert!(
            launch.try_wait().unwrap().is_some(),
            "owned launcher not reaped: {mode}"
        );
        assert!(launch.release(&f.driver).is_err());
        assert!(!f.root.join("gate/permit.json").exists());
        assert!(!f.root.join("delegate-executed").exists());
        assert!(f.root.join("gate/context.json").exists());
    }
}
#[test]
fn drop_before_permit_reaps_owned_launcher_and_preserves_records() {
    let f = SpawnFixture::new("exec");
    let mut launch = f.spawn(Duration::from_secs(2));
    poll_owned(&mut launch).unwrap();
    let pid = rustix::process::Pid::from_raw(launch.pid() as i32).unwrap();
    drop(launch);
    assert!(matches!(
        rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG),
        Err(rustix::io::Errno::CHILD)
    ));
    for record in ["context.json", "claimed", "ready.json"] {
        assert!(f.root.join("gate").join(record).exists());
    }
    assert!(!f.root.join("gate/permit.json").exists());
    assert!(!f.root.join("delegate-executed").exists());
}
#[test]
fn drop_after_permit_does_not_kill_root_or_delete_context() {
    let f = SpawnFixture::new("exec");
    fs::write(f.root.join("delegate"), format!("#!/bin/sh\nfor n in $(/usr/bin/seq 1 100); do\nif [ -e '{0}/finish' ]; then /usr/bin/touch '{0}/survived-drop'; exit 0; fi\n/usr/bin/sleep 0.01\ndone\nexit 8\n", f.root.display())).unwrap();
    let mut launch = f.spawn(Duration::from_secs(2));
    poll_owned(&mut launch).unwrap();
    f.evidence(launch.pid());
    launch.bind(&f.driver).unwrap();
    launch.release(&f.driver).unwrap();
    drop(launch);
    fs::write(f.root.join("finish"), "").unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    while !f.root.join("survived-drop").exists() {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(f.root.join("gate/context.json").exists());
    assert!(f.root.join("gate/permit.json").exists());
}
#[test]
fn spawn_error_preserves_durable_intent_context_without_claiming_exec() {
    let f = SpawnFixture::new("exec");
    fs::remove_file(f.root.join("systemd-run")).unwrap();
    let result = OwnedLaunch::spawn_with_io(
        &f.driver,
        LaunchIntent::new(
            RunId::parse("019281b2-67de-7000-8000-000000000001").unwrap(),
            &f.boot,
        )
        .unwrap(),
        &f.root.join("gate"),
        &f.root,
        &["/usr/bin/true".into()],
        LaunchPolicy::new(Duration::from_secs(60), Duration::from_secs(1)).unwrap(),
        LaunchIo {
            systemd_run: f.root.join("systemd-run"),
            self_binary: f.root.join("self"),
        },
    );
    assert_eq!(result.err(), Some("scope launch held"));
    assert!(f.root.join("gate/context.json").exists());
    assert!(!f.root.join("gate/claimed").exists());
    assert!(!f.root.join("gate/permit.json").exists());
}
#[test]
fn root_exit_with_remaining_member_is_not_quiescence() {
    let f = SpawnFixture::new("exec");
    let mut launch = f.spawn(Duration::from_secs(2));
    poll_owned(&mut launch).unwrap();
    f.evidence(launch.pid());
    launch.bind(&f.driver).unwrap();
    launch.release(&f.driver).unwrap();
    assert!(launch.wait().unwrap().success());
    // A separately owned local process supplies liveness only. Its scope placement
    // below is an explicit fixture snapshot, not an OS containment assertion.
    let mut remaining = Command::new("/usr/bin/sleep").arg("10").spawn().unwrap();
    f.evidence(remaining.id());
    fs::remove_dir_all(f.root.join(format!("proc/{}", launch.pid()))).unwrap();
    let binding = launch.binding().unwrap();
    let roster = [Participant {
        status: ParticipantStatus::Closed,
        identity: Some(binding.trusted_child().clone()),
    }];
    let observation = f.driver.observe(
        &LaunchIntent::new(
            RunId::parse("019281b2-67de-7000-8000-000000000001").unwrap(),
            &f.boot,
        )
        .unwrap(),
        Some(binding),
        Some(&roster),
    );
    let result = binding.verify_empty(&observation, Instant::now(), Duration::from_secs(2));
    let alive = remaining.try_wait().unwrap().is_none();
    remaining.kill().unwrap();
    remaining.wait().unwrap();
    assert!(alive);
    assert!(matches!(result, Err(HoldReason::Populated)));
    assert_eq!(launch.phase(), Phase::Released);
}
#[test]
fn owned_cancellation_before_permit_stops_and_reaps_only_owned_root() {
    let f = SpawnFixture::new("exec");
    let mut launch = f.spawn(Duration::from_secs(2));
    poll_owned(&mut launch).unwrap();
    f.evidence(launch.pid());
    launch.bind(&f.driver).unwrap();
    launch.cancel(&f.driver).unwrap();
    assert_eq!(launch.outcome(), Outcome::CancellationRequested);
    assert!(launch.try_wait().unwrap().is_some());
    assert!(launch.release(&f.driver).is_err());
    assert!(!f.root.join("gate/permit.json").exists());
    assert!(!f.root.join("delegate-executed").exists());
}
#[test]
fn explicit_preexec_wait_honors_deadline_and_reports_hold() {
    let f = SpawnFixture::new("timeout");
    let mut launch = f.spawn(Duration::from_millis(100));
    let started = Instant::now();
    assert!(!launch.wait().unwrap().success());
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(launch.outcome(), Outcome::RecoveryHold);
    assert!(!f.root.join("gate/permit.json").exists());
}
#[test]
fn out_of_order_release_is_terminal_preexec_failure() {
    let f = SpawnFixture::new("timeout");
    let mut launch = f.spawn(Duration::from_secs(2));
    assert!(launch.release(&f.driver).is_err());
    assert_eq!(launch.outcome(), Outcome::RecoveryHold);
    assert!(launch.try_wait().unwrap().is_some());
    assert!(!f.root.join("gate/permit.json").exists());
}
#[test]
fn launch_policy_rejects_unbounded_or_ambiguous_deadlines() {
    for (runtime, preexec) in [
        (Duration::ZERO, Duration::from_secs(1)),
        (Duration::from_secs(86401), Duration::from_secs(1)),
        (Duration::from_millis(1500), Duration::from_secs(1)),
        (Duration::from_secs(60), Duration::ZERO),
        (Duration::from_secs(60), Duration::from_secs(31)),
    ] {
        assert!(LaunchPolicy::new(runtime, preexec).is_err());
    }
}
