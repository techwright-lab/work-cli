use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::PathBuf,
    time::{Duration, Instant},
};
use work_cli::{runtime_scope::*, scope_driver::*};
use work_contract::RunId;
const BOOT: &str = "f312459a-9346-4d02-9139-c80a7017d962";
const INV: &str = "b312459a93464d029139c80a7017d962";
struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    intent: LaunchIntent,
    _bus: UnixListener,
}
impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_owned();
        fs::create_dir(root.join("runtime")).unwrap();
        fs::set_permissions(root.join("runtime"), fs::Permissions::from_mode(0o700)).unwrap();
        let bus = UnixListener::bind(root.join("runtime/bus")).unwrap();
        let intent = LaunchIntent::new(
            RunId::parse("019281b2-67de-7000-8000-000000000001").unwrap(),
            BOOT,
        )
        .unwrap();
        fs::create_dir_all(root.join("proc/sys/kernel/random")).unwrap();
        fs::write(root.join("proc/sys/kernel/random/boot_id"), BOOT).unwrap();
        fs::create_dir_all(root.join("cg/user.slice").join(intent.unit_name())).unwrap();
        let f = Self {
            _tmp: tmp,
            root,
            intent,
            _bus: bus,
        };
        f.properties(INV, "loaded", "active");
        f.members("", "42\n");
        f.process(42, 123, &f.group());
        fs::write(f.root.join("manager"),format!("#!/bin/sh\nprintf '%s\\n' \"$XDG_RUNTIME_DIR\" \"$DBUS_SESSION_BUS_ADDRESS\" \"$@\" > '{0}/called'\n/usr/bin/cat '{0}/properties'\n",f.root.display())).unwrap();
        fs::set_permissions(f.root.join("manager"), fs::Permissions::from_mode(0o700)).unwrap();
        f
    }
    fn group(&self) -> String {
        format!("/user.slice/{}", self.intent.unit_name())
    }
    fn path(&self) -> PathBuf {
        self.root
            .join("cg")
            .join(self.group().trim_start_matches('/'))
    }
    fn properties(&self, inv: &str, load: &str, active: &str) {
        fs::write(self.root.join("properties"),format!("Id={}\nInvocationID={inv}\nControlGroup={}\nLoadState={load}\nActiveState={active}\n",self.intent.unit_name(),if load=="not-found" {"".into()} else {self.group()})).unwrap();
    }
    fn members(&self, sub: &str, pids: &str) {
        fs::create_dir_all(self.path().join(sub)).unwrap();
        fs::write(self.path().join(sub).join("cgroup.procs"), pids).unwrap();
        fs::write(self.path().join(sub).join("cgroup.type"), "domain\n").unwrap();
    }
    fn process(&self, pid: u32, ticks: u64, group: &str) {
        let p = self.root.join("proc").join(pid.to_string());
        fs::create_dir_all(&p).unwrap();
        fs::write(
            p.join("stat"),
            format!(
                "{pid} (odd ) comm (x)) S {} {ticks} 0\n",
                vec!["0"; 18].join(" ")
            ),
        )
        .unwrap();
        fs::write(p.join("cgroup"), format!("0::{group}\n")).unwrap();
    }
    fn driver(&self, limits: Limits) -> Driver {
        Driver::with_io(
            self.context(),
            LibraryIo {
                systemctl: self.root.join("manager"),
                proc_root: self.root.join("proc"),
                cgroup_root: self.root.join("cg"),
                between_censuses: None,
            },
            limits,
        )
        .unwrap()
    }
    fn context(&self) -> RuntimeContext {
        RuntimeContext::new(
            self.root.join("runtime"),
            format!("unix:path={}/runtime/bus", self.root.display()),
        )
        .unwrap()
    }
    fn observe(&self) -> Observation {
        self.driver(Limits::default())
            .observe(&self.intent, None, None)
    }
    fn binding(&self) -> Binding {
        let obs = self.observe();
        let Membership::Present(m) = &obs.membership else {
            panic!("{obs:?}")
        };
        bind(
            &self.intent,
            &m[0],
            &obs,
            Instant::now(),
            Duration::from_secs(2),
        )
        .unwrap()
    }
}
#[test]
fn stable_census_rejects_membership_identity_and_process_churn() {
    for case in ["birth", "exit", "replacement", "reuse", "boot", "subgroup"] {
        let f = Fixture::new();
        let root = f.root.clone();
        let path = f.path();
        let driver = Driver::with_io(
            f.context(),
            LibraryIo {
                systemctl: f.root.join("manager"),
                proc_root: f.root.join("proc"),
                cgroup_root: f.root.join("cg"),
                between_censuses: Some(Box::new(move || match case {
                    "birth" => fs::write(path.join("cgroup.procs"), "42\n43\n").unwrap(),
                    "exit" => fs::write(path.join("cgroup.procs"), "").unwrap(),
                    "replacement" => {
                        fs::rename(&path, path.with_extension("old")).unwrap();
                        fs::create_dir(&path).unwrap();
                        fs::write(path.join("cgroup.procs"), "42\n").unwrap();
                        fs::write(path.join("cgroup.type"), "domain\n").unwrap();
                    }
                    "reuse" => {
                        let p = root.join("proc/42/stat");
                        let s = fs::read_to_string(&p).unwrap();
                        fs::write(p, s.replace("123", "999")).unwrap();
                    }
                    "boot" => fs::write(
                        root.join("proc/sys/kernel/random/boot_id"),
                        "a312459a-9346-4d02-9139-c80a7017d962",
                    )
                    .unwrap(),
                    _ => {
                        fs::create_dir(path.join("new")).unwrap();
                        fs::write(path.join("new/cgroup.procs"), "").unwrap();
                        fs::write(path.join("new/cgroup.type"), "domain\n").unwrap();
                    }
                })),
            },
            Limits::default(),
        )
        .unwrap();
        let o = driver.observe(&f.intent, None, None);
        assert_eq!(o.membership, Membership::Unknown, "{case}");
        assert_ne!(o.recursive_coverage, Coverage::Complete, "{case}");
    }
}
#[test]
fn absent_or_incomplete_roster_cannot_claim_participant_coverage() {
    let f = Fixture::new();
    for roster in [
        vec![],
        vec![Participant {
            status: ParticipantStatus::Closed,
            identity: None,
        }],
        vec![Participant {
            status: ParticipantStatus::Unknown,
            identity: None,
        }],
    ] {
        let o = f
            .driver(Limits::default())
            .observe(&f.intent, None, Some(&roster));
        assert_eq!(o.recursive_coverage, Coverage::Complete);
        assert_eq!(o.participant_coverage, Coverage::Unknown);
    }
}
#[test]
fn recursive_membership_and_robust_start_ticks() {
    let f = Fixture::new();
    f.members("nested", "43\n");
    f.process(43, 456, &format!("{}/nested", f.group()));
    let before = Instant::now();
    let o = f.observe();
    assert!(o.observed_at >= before);
    assert_eq!(o.recursive_coverage, Coverage::Complete);
    let Membership::Present(m) = o.membership else {
        panic!()
    };
    assert_eq!(
        m.iter().map(|p| (p.pid, p.start_ticks)).collect::<Vec<_>>(),
        vec![(42, 123), (43, 456)]
    );
    assert_eq!(o.participant_coverage, Coverage::Unknown);
}
#[test]
fn invalid_manager_metadata_never_becomes_absence() {
    for case in [
        "wrong-unit",
        "bad-invocation",
        "duplicate",
        "dotdot",
        "suffix",
        "failure",
    ] {
        let f = Fixture::new();
        let mut s = fs::read_to_string(f.root.join("properties")).unwrap();
        match case {
            "wrong-unit" => s = s.replace(f.intent.unit_name(), "other.scope"),
            "bad-invocation" => s = s.replace(INV, "invalid"),
            "duplicate" => s.push_str("ActiveState=active\n"),
            "dotdot" => s = s.replace("/user.slice/", "/../"),
            "suffix" => {
                s = s.replace(
                    &format!("ControlGroup={}\n", f.group()),
                    &format!("ControlGroup={}-suffix\n", f.group()),
                )
            }
            _ => s.clear(),
        };
        fs::write(f.root.join("properties"), s).unwrap();
        assert_eq!(f.observe().unit, UnitPresence::Unknown, "{case}");
    }
}
#[test]
fn invalid_group_type_and_stat_fields_hold() {
    for case in ["type", "stat-field", "stat-state"] {
        let f = Fixture::new();
        match case {
            "type" => fs::write(f.path().join("cgroup.type"), "threaded\n").unwrap(),
            "stat-field" => {
                let p = f.root.join("proc/42/stat");
                let s = fs::read_to_string(&p).unwrap();
                fs::write(p, s.replacen(" S 0 ", " S nope ", 1)).unwrap();
            }
            _ => {
                let p = f.root.join("proc/42/stat");
                let s = fs::read_to_string(&p).unwrap();
                fs::write(p, s.replace(" S ", " ? ")).unwrap();
            }
        }
        assert_eq!(f.observe().membership, Membership::Unknown, "{case}");
    }
}
#[test]
fn collector_errors_and_budgets_hold() {
    for case in [
        "stat",
        "missing",
        "symlink",
        "fifo",
        "depth",
        "groups",
        "pids",
        "bytes",
        "deadline",
        "wrong-type",
        "unreadable",
        "per-file",
        "group-link",
        "proc-link",
    ] {
        let f = Fixture::new();
        let mut limits = Limits::default();
        match case {
            "stat" => fs::write(f.root.join("proc/42/stat"), "42 (broken) S 0").unwrap(),
            "missing" => fs::remove_file(f.root.join("proc/42/cgroup")).unwrap(),
            "symlink" => {
                fs::remove_file(f.path().join("cgroup.procs")).unwrap();
                std::os::unix::fs::symlink(
                    f.root.join("properties"),
                    f.path().join("cgroup.procs"),
                )
                .unwrap();
            }
            "fifo" => {
                fs::remove_file(f.path().join("cgroup.procs")).unwrap();
                rustix::fs::mkfifoat(
                    rustix::fs::CWD,
                    f.path().join("cgroup.procs"),
                    rustix::fs::Mode::RUSR,
                )
                .unwrap();
            }
            "depth" => {
                f.members("nested", "");
                limits.depth = 0;
            }
            "groups" => limits.groups = 0,
            "pids" => limits.pids = 0,
            "bytes" => limits.total_bytes = 1,
            "deadline" => limits.duration = Duration::ZERO,
            "unreadable" => fs::set_permissions(
                f.path().join("cgroup.procs"),
                fs::Permissions::from_mode(0o000),
            )
            .unwrap(),
            "per-file" => fs::write(f.root.join("proc/42/stat"), "x".repeat(65_537)).unwrap(),
            "group-link" => {
                std::os::unix::fs::symlink(f.root.join("proc"), f.path().join("linked")).unwrap()
            }
            "proc-link" => {
                fs::remove_file(f.root.join("proc/42/stat")).unwrap();
                std::os::unix::fs::symlink(f.root.join("properties"), f.root.join("proc/42/stat"))
                    .unwrap();
            }
            _ => {
                fs::remove_file(f.path().join("cgroup.procs")).unwrap();
                fs::create_dir(f.path().join("cgroup.procs")).unwrap();
            }
        }
        let o = f.driver(limits).observe(&f.intent, None, None);
        assert_ne!(o.recursive_coverage, Coverage::Complete, "{case}");
        assert_eq!(o.membership, Membership::Unknown, "{case}");
    }
}
#[test]
fn loaded_active_unit_with_missing_group_is_not_absence_proof() {
    let f = Fixture::new();
    let bound = f.binding();
    fs::remove_dir_all(f.path()).unwrap();
    fs::remove_dir_all(f.root.join("proc/42")).unwrap();
    let roster = [Participant {
        status: ParticipantStatus::Closed,
        identity: Some(ChildIdentity {
            pid: 42,
            start_ticks: 123,
            boot: BOOT.into(),
            cgroup: f.group(),
        }),
    }];
    let o = f
        .driver(Limits::default())
        .observe(&f.intent, Some(&bound), Some(&roster));
    assert!(bound
        .verify_empty(&o, Instant::now(), Duration::from_secs(2))
        .is_err());
}
#[test]
fn reaped_scope_still_checks_known_participant_identity() {
    for case in ["alive-elsewhere", "reuse", "unknown", "open", "absent"] {
        let f = Fixture::new();
        let bound = f.binding();
        let child = ChildIdentity {
            pid: 42,
            start_ticks: 123,
            boot: BOOT.into(),
            cgroup: f.group(),
        };
        fs::remove_dir_all(f.path()).unwrap();
        f.properties("", "not-found", "inactive");
        let status = match case {
            "unknown" => ParticipantStatus::Unknown,
            "open" => ParticipantStatus::Open,
            _ => ParticipantStatus::Closed,
        };
        if case == "alive-elsewhere" {
            f.process(42, 123, "/elsewhere");
        } else if case == "reuse" {
            f.process(42, 999, &f.group());
        } else {
            fs::remove_dir_all(f.root.join("proc/42")).unwrap();
        }
        let roster = [Participant {
            status,
            identity: Some(child),
        }];
        let o = f
            .driver(Limits::default())
            .observe(&f.intent, Some(&bound), Some(&roster));
        assert!(matches!(o.unit, UnitPresence::AutoReaped(_)));
        let empty = bound.verify_empty(&o, Instant::now(), Duration::from_secs(2));
        assert_eq!(empty.is_ok(), case == "absent", "{case}: {o:?}");
    }
}
#[test]
fn bound_replacement_and_cross_boot_hold() {
    for case in ["invocation", "boot", "query-failure"] {
        let f = Fixture::new();
        let b = f.binding();
        match case {
            "invocation" => f.properties("c312459a93464d029139c80a7017d962", "loaded", "active"),
            "boot" => fs::write(
                f.root.join("proc/sys/kernel/random/boot_id"),
                "a312459a-9346-4d02-9139-c80a7017d962",
            )
            .unwrap(),
            _ => {
                fs::remove_dir_all(f.path()).unwrap();
                fs::write(f.root.join("properties"), "").unwrap();
            }
        }
        let o = f
            .driver(Limits::default())
            .observe(&f.intent, Some(&b), None);
        assert!(b
            .verify_empty(&o, Instant::now(), Duration::from_secs(2))
            .is_err());
        assert!(!matches!(o.unit, UnitPresence::AutoReaped(_)));
    }
}
#[test]
fn runtime_address_cannot_decode_or_select_another_socket() {
    for name in ["runtime,other", "runtime%2fother", "runtime;other"] {
        let f = Fixture::new();
        let dir = f.root.join(name);
        fs::rename(f.root.join("runtime"), &dir).unwrap();
        assert!(
            RuntimeContext::new(dir.clone(), format!("unix:path={}/bus", dir.display())).is_err()
        );
    }
}
#[test]
fn explicit_context_validation_and_manager_only_environment() {
    let f = Fixture::new();
    let old = std::env::var_os("XDG_RUNTIME_DIR");
    let old_bus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS");
    f.observe();
    assert_eq!(std::env::var_os("XDG_RUNTIME_DIR"), old);
    assert_eq!(std::env::var_os("DBUS_SESSION_BUS_ADDRESS"), old_bus);
    let call = fs::read_to_string(f.root.join("called")).unwrap();
    assert!(call.starts_with(&format!(
        "{0}/runtime\nunix:path={0}/runtime/bus\n--user\n",
        f.root.display()
    )));
    assert!(call.contains(f.intent.unit_name()));
    assert!(!call.contains("stop"));
    for case in ["public", "address", "symlink", "nonsocket"] {
        let f = Fixture::new();
        let runtime = f.root.join("runtime");
        let mut address = format!("unix:path={}/bus", runtime.display());
        match case {
            "public" => fs::set_permissions(&runtime, fs::Permissions::from_mode(0o755)).unwrap(),
            "address" => address.push_str(",guid=bad"),
            "symlink" => {
                std::os::unix::fs::symlink(&runtime, f.root.join("link")).unwrap();
                assert!(RuntimeContext::new(f.root.join("link"), address).is_err());
                continue;
            }
            _ => {
                fs::remove_file(runtime.join("bus")).unwrap();
                fs::write(runtime.join("bus"), "").unwrap();
            }
        }
        assert!(RuntimeContext::new(runtime, address).is_err(), "{case}");
    }
}
