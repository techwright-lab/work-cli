mod support;
use std::{
    ffi::OsString,
    fs,
    os::unix::net::UnixListener,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt},
    path::PathBuf,
    process::Command,
};
use support::*;
use uuid::Uuid;
use work_cli::{
    config::{Config, SupervisorConfig},
    run_journal::RootOutcome,
    runtime_scope::ChildIdentity,
    scope_child::{run_with_collector, LibraryCollector},
    scope_driver::{Driver, LibraryIo, Limits, RuntimeContext},
    scope_spawn::LaunchIo,
    supervisor::*,
};

#[path = "support/run_fixture.rs"]
mod gap_wire_fixture;
#[test]
fn default_history_never_acknowledges_off() {
    let (dir, mut store, checkout) = gap_wire_fixture::fixture();
    let root = gap_wire_fixture::request(checkout);
    store.begin_run(&root).unwrap();
    let mut malformed = serde_json::to_value(&root).unwrap();
    malformed["input"]["attribution"] = "off".into();
    let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute(
        "UPDATE runs SET request=?1",
        [serde_json::to_string(&malformed).unwrap()],
    )
    .unwrap();
    let config = Config {
        store_dir: Some(dir.path().join("private")),
        trusted_registry: Some(dir.path().join(".work-authorities")),
        roots: vec![dir.path().join("root")],
        ..Default::default()
    };
    let command = RootCommand {
        checkout,
        actor: None,
        run_id: Uuid::parse_str(&root.identity().run.to_string()).unwrap(),
        execution_chain: root.identity().execution_chain.clone(),
        argv: vec!["/usr/bin/true".into()],
    };
    let os = gap_wire_fixture::ClosureOs::new(&root, &gap_wire_fixture::binding(&root));
    let before = store.pending_events(100).unwrap();
    assert!(existing_report(&config, &command).is_err());
    for route in 0..3 {
        let io = LaunchIo {
            systemd_run: dir.path().join("must-not-run"),
            self_binary: dir.path().join("must-not-run"),
        };
        let result = match route {
            0 => supervise_with_io(
                &config,
                command.clone(),
                &os.driver,
                io,
                &CancelToken::default(),
                |_, _| panic!("runtime"),
            ),
            1 => supervise_captured_with_io(
                &config,
                command.clone(),
                &os.driver,
                io,
                &CancelToken::default(),
                |_, _| panic!("runtime"),
            ),
            _ => supervise_captured_integrated_with_io(
                &config,
                command.clone(),
                &os.driver,
                io,
                &CancelToken::default(),
                |_, _| panic!("runtime"),
            ),
        };
        assert!(result.is_err());
    }
    assert_eq!(store.pending_events(100).unwrap(), before);
}

#[test]
fn run_is_a_public_command_with_explicit_chain_and_retry_identity() {
    let output = Command::new(env!("CARGO_BIN_EXE_work"))
        .args(["run", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success(), "run command is missing");
    let help = String::from_utf8(output.stdout).unwrap();
    for option in ["--run-id", "--actor", "--execution-chain", "<CHECKOUT>"] {
        assert!(help.contains(option), "missing {option}");
    }
}
struct Collector {
    root: PathBuf,
    context: serde_json::Value,
    initialized: std::cell::Cell<bool>,
}
impl LibraryCollector for Collector {
    fn identities(&self) -> Result<(ChildIdentity, ChildIdentity), &'static str> {
        let pid = std::process::id();
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let start_ticks = stat
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap()
            .parse()
            .unwrap();
        let unit = self.context["unit"].as_str().unwrap();
        let group = format!("/user.slice/{unit}");
        let cg = self.root.join("cg").join(group.trim_start_matches('/'));
        // Collector is called again immediately before exec. Rewriting the
        // synthetic kernel files then would create impossible truncation races
        // with the parent's census (real proc/cgroup files are not truncated).
        if !self.initialized.replace(true) {
            fs::create_dir_all(&cg).unwrap();
            fs::write(cg.join("cgroup.type"), "domain\n").unwrap();
            fs::write(cg.join("cgroup.procs"), format!("{pid}\n")).unwrap();
            fs::create_dir_all(self.root.join(format!("proc/{pid}"))).unwrap();
            fs::write(self.root.join(format!("proc/{pid}/stat")), stat).unwrap();
            fs::write(
                self.root.join(format!("proc/{pid}/cgroup")),
                format!("0::{group}\n"),
            )
            .unwrap();
            fs::write(self.root.join("properties"), format!("Id={unit}\nInvocationID=1234567890abcdef1234567890abcdef\nControlGroup={group}\nLoadState=loaded\nActiveState=active\n")).unwrap();
        }
        let p = &self.context["parent"];
        let parent = ChildIdentity {
            pid: p["pid"].as_u64().unwrap() as u32,
            start_ticks: p["start_ticks"].as_u64().unwrap(),
            boot: p["boot"].as_str().unwrap().into(),
            cgroup: p["cgroup"].as_str().unwrap().into(),
        };
        Ok((
            ChildIdentity {
                pid,
                start_ticks,
                boot: parent.boot.clone(),
                cgroup: group,
            },
            parent,
        ))
    }
}
#[test]
fn collector_initializes_synthetic_kernel_once_even_after_pid_tree_removed() {
    let temp = tempfile::tempdir().unwrap();
    let collector = Collector {
        root: temp.path().into(),
        initialized: std::cell::Cell::new(false),
        context: serde_json::json!({"unit":"work-fixture.scope", "parent":{"pid":std::process::id(),"start_ticks":1,"boot":"fixture","cgroup":"/"}}),
    };
    let first = collector.identities().unwrap();
    let pid_tree = temp.path().join(format!("proc/{}", std::process::id()));
    assert!(pid_tree.exists());
    fs::remove_dir_all(&pid_tree).unwrap();
    let second = collector.identities().unwrap();
    assert_eq!(first, second);
    assert!(
        !pid_tree.exists(),
        "collector recreated synthetic kernel after cleanup"
    );
}
#[test]
fn fixture_child() {
    let Some(context) = std::env::var_os("SUPERVISOR_CONTEXT") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("SUPERVISOR_FIXTURE").unwrap());
    let context = PathBuf::from(context);
    let value = serde_json::from_slice(&fs::read(&context).unwrap()).unwrap();
    let bytes = fs::read(root.join("argv")).unwrap();
    let mut argv: Vec<_> = bytes
        .split(|b| *b == 0)
        .map(|v| OsString::from_vec(v.to_vec()))
        .collect();
    argv.pop(); // trailing delimiter only; empty arguments retained
    let collector = Collector {
        root,
        context: value,
        initialized: std::cell::Cell::new(false),
    };
    if run_with_collector(&context, &argv, &collector).is_err() {
        std::process::exit(42);
    }
}
struct Harness {
    f: Fixture,
    config: Config,
    driver: Driver,
    _bus: UnixListener,
    checkout: Uuid,
    run: Uuid,
    allocation: work_cli::allocate::Allocation,
}
impl Harness {
    fn new() -> Self {
        let f = Fixture::new();
        let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
        assert!(out.status.success());
        let allocation: work_cli::allocate::Allocation =
            serde_json::from_slice(&out.stdout).unwrap();
        let root = f.temp.path();
        fs::create_dir(root.join("runtime")).unwrap();
        fs::set_permissions(root.join("runtime"), fs::Permissions::from_mode(0o700)).unwrap();
        let bus = UnixListener::bind(root.join("runtime/bus")).unwrap();
        fs::create_dir_all(root.join("proc/sys/kernel/random")).unwrap();
        fs::copy(
            "/proc/sys/kernel/random/boot_id",
            root.join("proc/sys/kernel/random/boot_id"),
        )
        .unwrap();
        fs::create_dir(root.join("cg")).unwrap();
        let script = |name: &str, body: String| {
            fs::write(root.join(name), format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        };
        script("manager", format!("if [ \"$4\" = kill ]; then printf signal >> '{0}/signals'; exit 0; fi\nexec /usr/bin/cat '{0}/properties'", root.display()));
        script(
            "launcher",
            "while [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"".into(),
        );
        script("self", format!("export SUPERVISOR_CONTEXT=\"$3\" SUPERVISOR_FIXTURE='{0}'\nshift 4\nprintf '%s\\0' \"$@\" > '{0}/argv'\nexec '{1}' --exact fixture_child --nocapture", root.display(), std::env::current_exe().unwrap().display()));
        script("delegate", format!("printf '%s\\n' \"$GIT_AUTHOR_NAME\" \"$GIT_AUTHOR_EMAIL\" \"$GIT_COMMITTER_NAME\" \"$GIT_COMMITTER_EMAIL\" > '{0}/git-env'\nprintf '%s\\0' \"$@\" > '{0}/actual-argv'\npwd > '{0}/cwd'\n/usr/bin/touch '{0}/executed'\n", root.display()));
        let config =
            Config::from_text(&fs::read_to_string(root.join("config.toml")).unwrap()).unwrap();
        let mut config = config;
        config.supervisor = Some(SupervisorConfig {
            runtime_directory: root.join("runtime"),
            bus_address: format!("unix:path={}/runtime/bus", root.display()),
            runtime_max_seconds: 5,
            preexec_ms: 2000,
            closure_grace_ms: 50,
            cancel_grace_ms: 50,
            actors: ["alice", "other"]
                .map(|actor| {
                    (
                        actor.into(),
                        work_cli::scope_spawn::ActorGitProfile::new(
                            "Sol",
                            "sol@example.invalid",
                            "Sol Committer",
                            "commit@example.invalid",
                        )
                        .unwrap(),
                    )
                })
                .into(),
        });
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
            f,
            config,
            driver,
            _bus: bus,
            checkout: allocation.checkout,
            run: Uuid::now_v7(),
            allocation,
        }
    }
    fn request(&self) -> RootCommand {
        RootCommand {
            checkout: self.checkout,
            actor: None,
            run_id: self.run,
            execution_chain: serde_json::from_str(r#"[{"kind":"executor","system":"fixture"}]"#)
                .unwrap(),
            argv: vec![
                self.f.temp.path().join("delegate").into_os_string(),
                "".into(),
                OsString::from_vec(vec![0xff]),
                "secret-argument".into(),
            ],
        }
    }
    fn io(&self) -> LaunchIo {
        LaunchIo {
            systemd_run: self.f.temp.path().join("launcher"),
            self_binary: self.f.temp.path().join("self"),
        }
    }
    fn execute(
        &self,
        request: RootCommand,
        token: &CancelToken,
        observer: impl FnMut(Boundary, &work_cli::run_journal::RunRecord),
    ) -> std::io::Result<RunReport> {
        supervise_with_io(
            &self.config,
            request,
            &self.driver,
            self.io(),
            token,
            observer,
        )
    }
    fn empty(&self, record: &work_cli::run_journal::RunRecord) {
        let b = record.binding.as_ref().unwrap();
        fs::remove_dir_all(self.f.temp.path().join(format!("proc/{}", b.root_pid))).unwrap();
        fs::write(
            self.f
                .temp
                .path()
                .join("cg")
                .join(b.cgroup.trim_start_matches('/'))
                .join("cgroup.procs"),
            "",
        )
        .unwrap();
    }
}
#[test]
fn actual_pipeline_projects_git_identity_commits_before_exec_and_closes_only_scope_empty() {
    let h = Harness::new();
    let global_before = fs::read(h.f.repo.join(".git/config")).unwrap();
    let runtime_before =
        serde_json::to_vec(&work_cli::scope_child::OriginalRuntime::capture()).unwrap();
    let mut boundaries = Vec::new();
    let report = h
        .execute(h.request(), &CancelToken::default(), |boundary, r| {
            boundaries.push(boundary);
            let persisted =
                h.f.store()
                    .run_snapshot(&r.request.identity().run)
                    .unwrap()
                    .unwrap();
            assert_eq!(&persisted, r);
            if boundary == Boundary::RootTerminal {
                h.empty(r);
            } else if boundary != Boundary::Closed {
                assert!(!h.f.temp.path().join("executed").exists());
            }
        })
        .unwrap();
    assert!(report.record.closed);
    assert_eq!(report.record.outcome, Some(RootOutcome::Completed));
    assert_eq!(report.exit_code, Some(0));
    assert!(report.lease_charged && report.task_open && report.attribution_not_configured);
    assert_eq!(
        boundaries,
        vec![
            Boundary::Intent,
            Boundary::Bound,
            Boundary::PermitAttempt,
            Boundary::RootTerminal,
            Boundary::Closed
        ]
    );
    assert_eq!(
        fs::read(h.f.temp.path().join("git-env")).unwrap(),
        b"Sol\nsol@example.invalid\nSol Committer\ncommit@example.invalid\n"
    );
    assert_eq!(
        fs::read(h.f.temp.path().join("actual-argv")).unwrap(),
        b"\0\xff\0secret-argument\0"
    );
    assert_eq!(
        fs::read_to_string(h.f.temp.path().join("cwd"))
            .unwrap()
            .trim(),
        h.f.root.join("task").to_str().unwrap()
    );
    assert_eq!(
        fs::read(h.f.repo.join(".git/config")).unwrap(),
        global_before
    );
    assert_eq!(
        serde_json::to_vec(&work_cli::scope_child::OriginalRuntime::capture()).unwrap(),
        runtime_before
    );
    assert_eq!(h.f.store().charged(&h.f.repo, None).unwrap(), 1);
    let db = fs::read(h.f.temp.path().join("private/store.sqlite")).unwrap_or_default();
    assert!(!db.windows(15).any(|b| b == b"secret-argument"));
}
#[test]
fn full_roster_coordinator_closes_only_after_enrolled_host_disappears_even_on_cancellation() {
    for (cancelled, contained, gone) in [
        (false, false, true),
        (true, false, true),
        (false, true, true),
        (true, true, true),
        (false, true, false),
        (true, true, false),
    ] {
        let h = Harness::new();
        let token = CancelToken::default();
        let worker = if cancelled {
            let root = h.f.temp.path();
            fs::write(root.join("delegate"), format!("#!/bin/sh\n/usr/bin/touch '{0}/executed'\nwhile [ ! -e '{0}/stop' ]; do /usr/bin/sleep 0.005; done\n",root.display())).unwrap();
            fs::write(root.join("manager"), format!("#!/bin/sh\nif [ \"$4\" = kill ]; then /usr/bin/touch '{0}/stop' '{0}/signals'; exit 0; fi\nexec /usr/bin/cat '{0}/properties'\n",root.display())).unwrap();
            let marker = root.join("executed");
            let requested = token.clone();
            Some(std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                while !marker.exists() {
                    assert!(std::time::Instant::now() < deadline);
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                requested.request();
            }))
        } else {
            None
        };
        let result = h.execute(h.request(), &token, |boundary, record| {
            if boundary == Boundary::PermitAttempt {
                let i = record.request.identity();
                let child = work_cli::run_participants::ChildRequest {
                    checkout: i.checkout.clone(),
                    group: i.group.clone(),
                    run: work_contract::RunId::generate(),
                    run_ref: work_contract::RunRef::parse("fixture-child").unwrap(),
                    parent_run: i.run.clone(),
                    parent_run_ref: i.run_ref.clone(),
                    execution_chain: i.execution_chain.clone(),
                    source: None,
                    session: None,
                    agent: None,
                    actor: None,
                    expected_host: contained.then(|| {
                        let b = record.binding.as_ref().unwrap();
                        work_cli::run_participants::ExpectedHost {
                            boot: b.boot.clone(),
                            pid: 43,
                            start_ticks: 20,
                        }
                    }),
                };
                let mut store = h.f.store();
                store.register_child(&record.request, &child).unwrap();
                if contained {
                    // Controlled fixture IO: actual registrar PID in the same
                    // synthetic root scope; no Binding reconstructed from JSON.
                    let b = record.binding.as_ref().unwrap();
                    let pid = std::process::id();
                    let p = h.f.temp.path().join(format!("proc/{pid}"));
                    fs::create_dir_all(&p).unwrap();
                    fs::write(
                        p.join("stat"),
                        format!("{pid} (registrar) S {} 10 0\n", vec!["0"; 18].join(" ")),
                    )
                    .unwrap();
                    fs::write(p.join("cgroup"), format!("0::{}\n", b.cgroup)).unwrap();
                    let host = h.f.temp.path().join("proc/43");
                    fs::create_dir_all(&host).unwrap();
                    fs::write(
                        host.join("stat"),
                        format!("43 (host) S {} 20 0\n", vec!["0"; 18].join(" ")),
                    )
                    .unwrap();
                    fs::write(host.join("cgroup"), format!("0::{}\n", b.cgroup)).unwrap();
                    fs::write(
                        h.f.temp
                            .path()
                            .join("cg")
                            .join(b.cgroup.trim_start_matches('/'))
                            .join("cgroup.procs"),
                        format!("{}\n{pid}\n43\n", b.root_pid),
                    )
                    .unwrap();
                    let proof = store
                        .group_snapshot(&i.run)
                        .unwrap()
                        .certify_child_enrollment(&h.driver, &child.run, None)
                        .unwrap();
                    store
                        .record_child_enrollment(&record.request, &child, &proof)
                        .unwrap();
                    if !gone {
                        store
                            .record_child_outcome(
                                &record.request,
                                &child,
                                work_cli::run_participants::ChildOutcome::Completed,
                            )
                            .unwrap();
                    }
                }
            }
            if boundary == Boundary::RootTerminal {
                h.empty(record);
                if contained && gone {
                    fs::remove_dir_all(h.f.temp.path().join("proc/43")).unwrap();
                }
            }
        });
        if let Some(worker) = worker {
            worker.join().unwrap();
        }
        let report = result.unwrap();
        assert_eq!(
            report.record.outcome,
            Some(if cancelled {
                RootOutcome::Cancelled
            } else {
                RootOutcome::Completed
            })
        );
        assert_eq!(report.record.closed, contained && gone);
        assert_eq!(report.record.recovery_hold, !(contained && gone));
        if contained && gone {
            assert_eq!(
                report.record.children[0].outcome,
                Some(work_cli::run_participants::ChildOutcome::Interrupted)
            );
            let retry = h
                .execute(h.request(), &CancelToken::default(), |_, _| {
                    panic!("closed child receipt relaunched")
                })
                .unwrap();
            assert!(retry.existing && retry.record.closed);
        }
        assert_eq!(report.record.children.len(), 1);
        assert_eq!(
            report.record.children[0].enrollment,
            if contained {
                work_cli::run_participants::Enrollment::Contained
            } else {
                work_cli::run_participants::Enrollment::Unverified
            }
        );
        assert_eq!(h.f.store().charged(&h.f.repo, None).unwrap(), 1);
    }
}

#[test]
fn root_exit_with_descendants_holds_writer_and_exact_retry_never_executes() {
    let h = Harness::new();
    let delegate = h.f.temp.path().join("delegate");
    let mut body = fs::read_to_string(&delegate).unwrap();
    body.push_str(&format!(
        "/usr/bin/sleep 10 &\nprintf '%s' $! > '{}/grandchild'\n",
        h.f.temp.path().display()
    ));
    fs::write(&delegate, body).unwrap();
    let mut remaining = None;
    let report = h
        .execute(h.request(), &CancelToken::default(), |b, r| {
            if b == Boundary::RootTerminal {
                h.empty(r);
                let pid: u32 = fs::read_to_string(h.f.temp.path().join("grandchild"))
                    .unwrap()
                    .parse()
                    .unwrap();
                let stat = fs::read(format!("/proc/{pid}/stat")).unwrap();
                let path = h.f.temp.path().join(format!("proc/{pid}"));
                fs::create_dir(&path).unwrap();
                fs::write(path.join("stat"), stat).unwrap();
                let group = &r.binding.as_ref().unwrap().cgroup;
                fs::write(path.join("cgroup"), format!("0::{group}\n")).unwrap();
                fs::write(
                    h.f.temp
                        .path()
                        .join("cg")
                        .join(group.trim_start_matches('/'))
                        .join("cgroup.procs"),
                    format!("{pid}\n"),
                )
                .unwrap();
                remaining = Some(pid);
            }
        })
        .unwrap();
    let pid = remaining.unwrap();
    assert!(std::path::Path::new(&format!("/proc/{pid}/stat")).exists());
    // Fixture-only cleanup of the actual grandchild created above. No production
    // scope authority or containment claim comes from these synthetic cgroups.
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(pid as i32).unwrap(),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    assert_eq!(report.record.outcome, Some(RootOutcome::Completed));
    assert!(!report.record.closed);
    assert!(report.record.recovery_hold);
    fs::remove_file(h.f.temp.path().join("executed")).unwrap();
    let retry = h
        .execute(h.request(), &CancelToken::default(), |_, _| {
            panic!("retry launched")
        })
        .unwrap();
    assert!(retry.existing);
    assert_eq!(retry.record.request, report.record.request);
    assert!(!h.f.temp.path().join("executed").exists());
    for changed in ["command", "actor", "chain"] {
        let mut request = h.request();
        match changed {
            "command" => request.argv.push("changed".into()),
            "actor" => request.actor = Some("other".into()),
            _ => {
                request.execution_chain =
                    serde_json::from_str(r#"[{"kind":"executor","system":"changed"}]"#).unwrap()
            }
        }
        assert!(h
            .execute(request, &CancelToken::default(), |_, _| panic!(
                "conflict launched"
            ))
            .is_err());
    }
    assert!(h
        .f
        .store()
        .acquire_writer(h.checkout, Uuid::now_v7())
        .is_err());
}
#[test]
fn configured_policy_rejects_unbounded_values_without_echoing_config() {
    for field in [
        "runtime_max_seconds",
        "preexec_ms",
        "closure_grace_ms",
        "cancel_grace_ms",
    ] {
        let text = format!("[supervisor]\nruntime_directory='/not-secret-runtime'\nbus_address='unix:path=/not-secret-runtime/bus'\nruntime_max_seconds={}\npreexec_ms={}\nclosure_grace_ms={}\ncancel_grace_ms={}\n[supervisor.actors.alice]\nauthor_name='private-secret'\nauthor_email='a@example.invalid'\ncommitter_name='private-secret'\ncommitter_email='a@example.invalid'", if field == "runtime_max_seconds" {0} else {60}, if field == "preexec_ms" {0} else {1000}, if field == "closure_grace_ms" {0} else {1000}, if field == "cancel_grace_ms" {0} else {1000});
        let error = Config::from_text(&text)
            .expect_err("unbounded/zero runtime policy accepted")
            .to_string();
        assert!(!error.contains("private-secret") && !error.contains("not-secret-runtime"));
    }
}
#[test]
fn root_uses_own_process_group_without_protocol_capture() {
    let h = Harness::new();
    fs::write(
        h.f.temp.path().join("delegate"),
        format!(
            "#!/bin/sh\n/usr/bin/cat /proc/$$/stat > '{}/process-stat'\n",
            h.f.temp.path().display()
        ),
    )
    .unwrap();
    let report = h
        .execute(h.request(), &CancelToken::default(), |b, r| {
            if b == Boundary::RootTerminal {
                h.empty(r);
            }
        })
        .unwrap();
    let stat = fs::read_to_string(h.f.temp.path().join("process-stat")).unwrap();
    let group: u32 = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(2)
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        group,
        report.record.binding.unwrap().root_pid,
        "delegate inherited controller process group"
    );
}
#[test]
fn explicit_cancel_while_blocked_records_cancelled_root_not_an_invented_failure() {
    let h = Harness::new();
    let token = CancelToken::default();
    let report = h
        .execute(h.request(), &token, |b, _| {
            if b == Boundary::Bound {
                token.request();
            }
        })
        .unwrap();
    assert_eq!(report.record.outcome, Some(RootOutcome::Cancelled));
    assert!(report.record.recovery_hold && !report.record.closed);
    assert_ne!(report.process_exit_code(), 0);
    assert!(!h.f.temp.path().join("executed").exists());
    assert!(h.f.temp.path().join("signals").exists());
}
#[test]
fn replaced_scope_cancellation_never_signals_and_retains_writer() {
    let h = Harness::new();
    let token = CancelToken::default();
    let result = h.execute(h.request(), &token, |boundary, _| {
        if boundary == Boundary::RootTerminal {
            let path = h.f.temp.path().join("properties");
            fs::write(
                &path,
                fs::read_to_string(&path).unwrap().replace(
                    "1234567890abcdef1234567890abcdef",
                    "abcdef1234567890abcdef1234567890",
                ),
            )
            .unwrap();
            token.request();
        }
    });
    assert!(result.is_err());
    assert!(!h.f.temp.path().join("signals").exists());
    let r =
        h.f.store()
            .run_snapshot(&work_contract::RunId::parse(&h.run.to_string()).unwrap())
            .unwrap()
            .unwrap();
    assert!(r.recovery_hold && !r.closed);
    assert_eq!(r.outcome, Some(RootOutcome::Completed));
}
#[test]
fn closed_group_allows_sequential_run_without_new_charge_and_retries_are_receipts() {
    let mut h = Harness::new();
    let first = h
        .execute(h.request(), &CancelToken::default(), |b, r| {
            if b == Boundary::RootTerminal {
                h.empty(r);
            }
        })
        .unwrap();
    assert!(first.record.closed);
    let retry = h
        .execute(h.request(), &CancelToken::default(), |_, _| {
            panic!("receipt launched")
        })
        .unwrap();
    assert!(retry.existing);
    assert_eq!(retry.record.request, first.record.request);
    h.run = Uuid::now_v7();
    fs::write(h.f.temp.path().join("delegate"), "#!/bin/sh\nexit 7\n").unwrap();
    let second = h
        .execute(h.request(), &CancelToken::default(), |b, r| {
            if b == Boundary::RootTerminal {
                h.empty(r);
            }
        })
        .unwrap();
    assert!(second.record.closed);
    assert_eq!(second.record.outcome, Some(RootOutcome::Failed));
    assert_eq!(second.process_exit_code(), 7);
    assert_ne!(
        first.record.request.identity().group,
        second.record.request.identity().group
    );
    assert_eq!(h.f.store().charged(&h.f.repo, None).unwrap(), 1);
}
#[test]
fn release_boundary_rechecks_lease_and_journal_holds_before_gate_publication() {
    for damage in ["marker", "hold"] {
        let h = Harness::new();
        let result = h.execute(h.request(), &CancelToken::default(), |b, r| {
            if b == Boundary::PermitAttempt {
                if damage == "marker" {
                    fs::write(
                        h.allocation
                            .identity
                            .as_ref()
                            .unwrap()
                            .private_git_dir
                            .join("work-lease.json"),
                        "{}",
                    )
                    .unwrap();
                } else {
                    h.f.store().record_recovery_hold(&r.request).unwrap();
                }
            }
        });
        assert!(result.is_err());
        let r =
            h.f.store()
                .run_snapshot(&work_contract::RunId::parse(&h.run.to_string()).unwrap())
                .unwrap()
                .unwrap();
        assert!(r.recovery_hold && !r.closed);
        assert_eq!(r.stage, work_cli::run_journal::RunStage::PermitAttempt);
        assert!(!h.f.temp.path().join("executed").exists());
        assert!(!h
            .f
            .temp
            .path()
            .join(format!("private/runs/{}/permit.json", h.run))
            .exists());
    }
}
#[test]
fn coordinator_crash_worker() {
    let Some(manifest) = std::env::var_os("COORDINATOR_CRASH_MANIFEST") else {
        return;
    };
    let stage = std::env::var("COORDINATOR_CRASH_STAGE").unwrap();
    let h = Harness::new();
    fs::write(
        manifest,
        serde_json::to_vec(
            &serde_json::json!({"root":h.f.temp.path(),"run":h.run,"checkout":h.checkout}),
        )
        .unwrap(),
    )
    .unwrap();
    h.execute(h.request(), &CancelToken::default(), |b, _| {
        if format!("{b:?}") == stage {
            use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
            setrlimit(
                Resource::Core,
                Rlimit {
                    current: Some(0),
                    ..getrlimit(Resource::Core)
                },
            )
            .unwrap();
            assert_eq!(getrlimit(Resource::Core).current, Some(0));
            std::process::abort();
        }
    })
    .unwrap();
    panic!("crash boundary not reached");
}
#[test]
fn four_parent_abort_boundaries_keep_durable_writer_and_do_not_relaunch() {
    use std::os::unix::process::ExitStatusExt;
    for stage in ["Intent", "Bound", "PermitAttempt", "RootTerminal"] {
        let temp = tempfile::tempdir().unwrap();
        let manifest = temp.path().join("manifest");
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "coordinator_crash_worker"])
            .env("COORDINATOR_CRASH_MANIFEST", &manifest)
            .env("COORDINATOR_CRASH_STAGE", stage)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(6), "worker did not abort at {stage}");
        let m: serde_json::Value = serde_json::from_slice(&fs::read(manifest).unwrap()).unwrap();
        let root = PathBuf::from(m["root"].as_str().unwrap());
        let mut store = work_cli::store::Store::open_registered(
            &root.join("registry"),
            &root.join("private"),
            &[root.join("root")],
        )
        .unwrap();
        let run = work_contract::RunId::parse(m["run"].as_str().unwrap()).unwrap();
        let r = store.run_snapshot(&run).unwrap().unwrap();
        assert!(!r.closed);
        assert_eq!(store.recovery_runs().unwrap().len(), 1);
        assert_eq!(
            store.begin_run(&r.request).unwrap(),
            work_cli::run_journal::BeginRun::Existing
        );
        assert!(store
            .acquire_writer(
                Uuid::parse_str(m["checkout"].as_str().unwrap()).unwrap(),
                Uuid::now_v7()
            )
            .is_err());
        assert_eq!(store.charged(&root.join("repo"), None).unwrap(), 1);
        if stage != "RootTerminal" {
            assert!(!root.join("executed").exists());
        }
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
}
#[test]
fn malformed_ready_allocation_without_source_is_refused_not_panicked() {
    let h = Harness::new();
    let mut allocation = h.allocation.clone();
    allocation.request.repository = None;
    let conn = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
    conn.execute(
        "UPDATE allocations SET request=?1,record=?2",
        (
            serde_json::to_string(&allocation.request).unwrap(),
            serde_json::to_string(&allocation).unwrap(),
        ),
    )
    .unwrap();
    drop(conn);
    assert!(h
        .execute(h.request(), &CancelToken::default(), |_, _| panic!(
            "invalid source accepted"
        ))
        .is_err());
    assert!(!h.f.temp.path().join("executed").exists());
}
#[test]
fn released_root_cancellation_records_actual_exit_and_only_closes_on_fresh_empty_scope() {
    let h = Harness::new();
    let root = h.f.temp.path();
    fs::write(root.join("delegate"), format!("#!/bin/sh\n/usr/bin/touch '{0}/executed'\nwhile [ ! -e '{0}/stop' ]; do /usr/bin/sleep 0.005; done\nexit 0\n",root.display())).unwrap();
    fs::write(root.join("manager"), format!("#!/bin/sh\nif [ \"$4\" = kill ]; then /usr/bin/touch '{0}/stop' '{0}/signals'; exit 0; fi\nexec /usr/bin/cat '{0}/properties'\n",root.display())).unwrap();
    let token = CancelToken::default();
    let thread_token = token.clone();
    let marker = root.join("executed");
    let worker = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !marker.exists() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        thread_token.request();
    });
    let result = h.execute(h.request(), &token, |b, r| {
        if b == Boundary::RootTerminal {
            h.empty(r);
        }
    });
    worker.join().unwrap();
    let report = result.unwrap();
    assert_eq!(report.record.outcome, Some(RootOutcome::Cancelled));
    assert_eq!(report.exit_code, Some(0));
    assert!(report.record.closed && !report.record.recovery_hold);
    assert_ne!(report.process_exit_code(), 0);
    let retry = h
        .execute(h.request(), &CancelToken::default(), |_, _| {
            panic!("cancelled receipt launched")
        })
        .unwrap();
    assert!(retry.existing && retry.record.closed);
    assert_eq!(retry.record.outcome, Some(RootOutcome::Cancelled));
    assert_ne!(retry.process_exit_code(), 0);
    assert!(root.join("signals").exists());
}
#[test]
fn lease_lock_is_not_held_during_actor_lifetime() {
    let h = Harness::new();
    let report = h
        .execute(h.request(), &CancelToken::default(), |b, r| {
            if b == Boundary::Bound {
                let output = h.f.start(
                    &Uuid::now_v7().to_string(),
                    "independent",
                    "independent",
                    &[],
                );
                assert!(
                    output.status.success(),
                    "allocator lock held through actor lifetime: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if b == Boundary::RootTerminal {
                h.empty(r);
            }
        })
        .unwrap();
    assert!(report.record.closed);
    assert_eq!(h.f.store().charged(&h.f.repo, None).unwrap(), 2);
}
#[test]
fn changed_git_profile_conflicts_without_executing_again() {
    let mut h = Harness::new();
    h.execute(h.request(), &CancelToken::default(), |b, r| {
        if b == Boundary::RootTerminal {
            h.empty(r);
        }
    })
    .unwrap();
    h.config.supervisor.as_mut().unwrap().actors.insert(
        "alice".into(),
        work_cli::scope_spawn::ActorGitProfile::new(
            "Changed",
            "changed@example.invalid",
            "Changed",
            "changed@example.invalid",
        )
        .unwrap(),
    );
    assert!(h
        .execute(h.request(), &CancelToken::default(), |_, _| panic!(
            "profile conflict launched"
        ))
        .is_err());
}
#[test]
fn existing_receipt_preserves_original_context_references_instead_of_minting_them() {
    let h = Harness::new();
    let r = h
        .execute(h.request(), &CancelToken::default(), |b, r| {
            if b == Boundary::RootTerminal {
                h.empty(r);
            }
        })
        .unwrap();
    let mut value = serde_json::to_value(&r.record.request).unwrap();
    value["input"]["context_ref"] = "urn:original:context".into();
    value["input"]["intent_ref"] = "urn:original:intent".into();
    let sidecar_state = || {
        let wal = fs::symlink_metadata(h.f.temp.path().join("private/store.sqlite-wal"));
        let shm = fs::symlink_metadata(h.f.temp.path().join("private/store.sqlite-shm"));
        (
            wal.is_ok(),
            wal.as_ref().is_ok_and(|m| m.file_type().is_file()),
            shm.is_ok(),
            shm.as_ref().is_ok_and(|m| m.file_type().is_file()),
        )
    };
    let conn = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
    // Match native writers: closing this fixture client must not delete the
    // legitimate WAL bookkeeping required by strict read-only receipt lookup.
    conn.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        true,
    )
    .unwrap();
    conn.execute(
        "UPDATE runs SET request=?1",
        [serde_json::to_string(&value).unwrap()],
    )
    .unwrap();
    assert_eq!(sidecar_state(), (true, true, true, true));
    drop(conn);
    assert_eq!(sidecar_state(), (true, true, true, true));
    let receipt = h
        .execute(h.request(), &CancelToken::default(), |_, _| {
            panic!("existing launched")
        })
        .unwrap();
    assert!(receipt.existing);
    assert_eq!(
        receipt.record.request.input().context_ref.as_str(),
        "urn:original:context"
    );
    assert_eq!(
        receipt.record.request.input().intent_ref.as_str(),
        "urn:original:intent"
    );
}
#[test]
fn blocked_cancellation_still_collects_whole_scope_before_closing_writer() {
    let h = Harness::new();
    let token = CancelToken::default();
    let report = h
        .execute(h.request(), &token, |b, r| {
            if b == Boundary::Bound {
                token.request();
            }
            if b == Boundary::RootTerminal {
                h.empty(r);
            }
        })
        .unwrap();
    assert_eq!(report.record.outcome, Some(RootOutcome::Cancelled));
    assert!(report.record.closed && !report.record.recovery_hold);
    assert!(!h.f.temp.path().join("executed").exists());
    assert_eq!(h.f.store().charged(&h.f.repo, None).unwrap(), 1);
}
#[test]
fn ready_preflights_atomically_refresh_descendant_head_without_changing_lease_base_or_receipt() {
    let mut h = Harness::new();
    let old_command = h.request();
    let first = h
        .execute(old_command.clone(), &CancelToken::default(), |b, r| {
            if b == Boundary::RootTerminal {
                h.empty(r);
            }
        })
        .unwrap();
    let path = h.f.root.join("task");
    let marker_path = h
        .allocation
        .identity
        .as_ref()
        .unwrap()
        .private_git_dir
        .join("work-lease.json");
    let marker = fs::read(&marker_path).unwrap();
    git(&path, &["commit", "--allow-empty", "-m", "between runs"]);
    let advanced = git(&path, &["rev-parse", "HEAD"]);
    let mut release_head = None;
    h.run = Uuid::now_v7();
    fs::remove_file(h.f.temp.path().join("executed")).unwrap();
    let second = h.execute(h.request(), &CancelToken::default(), |b,r| {
        if b==Boundary::Intent || b==Boundary::PermitAttempt {
            assert!(!h.f.temp.path().join("executed").exists());
            let conn = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
            let record: String = conn.query_row("SELECT record FROM allocations WHERE checkout=?1",[h.checkout.to_string()],|row|row.get(0)).unwrap();
            let allocation: work_cli::allocate::Allocation = serde_json::from_str(&record).unwrap();
            assert_eq!(allocation.identity.as_ref().unwrap().head, advanced, "preflight discarded fresh HEAD identity");
            assert_eq!(allocation.stage,"ready");
            assert_eq!(allocation.base_commit,h.allocation.base_commit);
            assert!(h.f.store().pending_events(1000).unwrap().iter().any(|e| matches!(&e.event, work_cli::events::Event::HeadAdvanced {checkout,old,new} if *checkout==h.checkout && old==&h.allocation.identity.as_ref().unwrap().head && new==&advanced)));
        }
        if b==Boundary::PermitAttempt {
            git(&path, &["commit", "--allow-empty", "-m", "near release"]);
            release_head = Some(git(&path, &["rev-parse", "HEAD"]));
        }
        if b==Boundary::RootTerminal {h.empty(r);}
    }).unwrap();
    assert!(second.record.closed);
    let conn = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
    let record: String = conn
        .query_row(
            "SELECT record FROM allocations WHERE checkout=?1",
            [h.checkout.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let allocation: work_cli::allocate::Allocation = serde_json::from_str(&record).unwrap();
    assert_eq!(
        allocation.identity.as_ref().unwrap().head,
        release_head.unwrap()
    );
    assert_eq!(allocation.base_commit, h.allocation.base_commit);
    assert_eq!(fs::read(marker_path).unwrap(), marker);
    let heads = h.f.store().pending_events(1000).unwrap().into_iter().filter(|e| matches!(&e.event,work_cli::events::Event::HeadAdvanced {checkout,..} if *checkout==h.checkout)).count();
    assert_eq!(heads, 2);
    let receipt = h
        .execute(old_command, &CancelToken::default(), |_, _| {
            panic!("old receipt launched")
        })
        .unwrap();
    assert!(receipt.existing);
    assert_eq!(receipt.record.request, first.record.request);
}
#[test]
fn fresh_lease_damage_refuses_before_intent_and_never_revives_holds() {
    for damage in ["marker", "path", "held", "source", "capture"] {
        let mut h = Harness::new();
        let allocation = h.allocation.clone();
        match damage {
            "marker" => fs::write(
                allocation
                    .identity
                    .unwrap()
                    .private_git_dir
                    .join("work-lease.json"),
                "{}",
            )
            .unwrap(),
            "path" => {
                fs::rename(h.f.root.join("task"), h.f.root.join("moved")).unwrap();
            }
            "held" => {
                let conn = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite"))
                    .unwrap();
                conn.execute("UPDATE checkouts SET state='held',ready=0", [])
                    .unwrap();
            }
            "source" => {
                fs::rename(h.f.repo.join(".git"), h.f.repo.join("gone")).unwrap();
            }
            _ => h.config.allocation.as_mut().unwrap().capture_sink = Some("unsupported".into()),
        }
        assert!(
            h.execute(h.request(), &CancelToken::default(), |_, _| panic!(
                "bad lease got intent"
            ))
            .is_err(),
            "{damage}"
        );
        assert!(h
            .f
            .store()
            .run_snapshot(&work_contract::RunId::parse(&h.run.to_string()).unwrap())
            .unwrap()
            .is_none());
        assert!(!h.f.temp.path().join("executed").exists());
    }
}
