#![allow(dead_code)]
use rusqlite::Connection;
use uuid::Uuid;
use work_cli::{
    admission::{Limits, Reservation},
    store::Store,
};

pub fn fixture() -> (tempfile::TempDir, Store, Uuid) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let mut store = Store::open(&dir.path().join("private"), std::slice::from_ref(&root)).unwrap();
    let checkout = store
        .reserve(
            &Reservation {
                operation: Uuid::now_v7(),
                repository: root,
                actor: "allocator".into(),
                owner: "owner".into(),
                task: "task".into(),
            },
            Limits {
                repository: 10,
                owner: 10,
                available_bytes: Some(100),
                floor_bytes: 0,
                warn_bytes: 0,
            },
        )
        .unwrap();
    // Synthetic durable allocation-readiness fixture, no Git or scope backend.
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute(
        "UPDATE checkouts SET state='active',ready=1 WHERE id=?1",
        [checkout.to_string()],
    )
    .unwrap();
    (dir, store, checkout)
}
pub fn reopen(dir: &tempfile::TempDir) -> work_cli::store::Result<Store> {
    Store::open(&dir.path().join("private"), &[dir.path().join("root")])
}
use std::time::{Duration, Instant};
use work_cli::run_journal::{RootRunRequest, RunIdentity, RunInput};
use work_cli::runtime_scope::{
    self, ActiveStatus, Binding, ChildIdentity, Coverage, LaunchIntent, LoadStatus, Membership,
    Observation, ScopeIdentity, UnitPresence,
};
use work_contract::{ActorId, ChainText, CheckoutId, GroupId, RunId, RunRef};
pub const BOOT: &str = "550e8400-e29b-41d4-a716-446655440000";
pub fn request(checkout: Uuid) -> RootRunRequest {
    RootRunRequest::new(
        RunIdentity {
            checkout: CheckoutId::parse(&checkout.to_string()).unwrap(),
            group: GroupId::generate(),
            run: RunId::generate(),
            run_ref: RunRef::parse(&format!("run:{}", Uuid::now_v7())).unwrap(),
            actor: ActorId::parse("reviewer-not-owner").unwrap(),
            parent_run_ref: Some(RunRef::parse("external:parent").unwrap()),
            execution_chain: serde_json::from_value(
                serde_json::json!([{"kind":"executor","system":"test"}]),
            )
            .unwrap(),
        },
        RunInput {
            attribution: None,
            command_digest: [1; 32],
            input_digest: [2; 32],
            context_ref: ChainText::new("context".into()).unwrap(),
            intent_ref: ChainText::new("intent".into()).unwrap(),
            boot: BOOT.into(),
        },
    )
    .unwrap()
}
pub fn changed(r: &RootRunRequest, field: &str, value: serde_json::Value) -> RootRunRequest {
    let mut json = serde_json::to_value(r).unwrap();
    json["identity"][field] = value;
    serde_json::from_value(json).unwrap()
}
pub fn binding(r: &RootRunRequest) -> Binding {
    binding_child(r, 42, 10)
}
pub fn binding_child(r: &RootRunRequest, pid: u32, start_ticks: u64) -> Binding {
    let intent = LaunchIntent::new(r.identity().run.clone(), &r.input().boot).unwrap();
    let identity = ScopeIdentity {
        unit: intent.unit_name().into(),
        invocation: "550e8400e29b41d4a716446655440000".into(),
        cgroup: format!("/test/{}", intent.unit_name()),
    };
    let child = ChildIdentity {
        pid,
        start_ticks,
        boot: r.input().boot.clone(),
        cgroup: identity.cgroup.clone(),
    };
    let now = Instant::now();
    runtime_scope::bind(
        &intent,
        &child,
        &Observation {
            boot: child.boot.clone(),
            observed_at: now,
            unit: UnitPresence::Present {
                identity,
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

// Private fake manager/proc/cgroup fixture: never contacts a real user manager.
pub struct ClosureOs {
    pub tmp: tempfile::TempDir,
    _bus: std::os::unix::net::UnixListener,
    pub driver: work_cli::scope_driver::Driver,
}
impl ClosureOs {
    pub fn new(r: &RootRunRequest, b: &Binding) -> Self {
        use std::{fs, os::unix::fs::PermissionsExt};
        use work_cli::scope_driver::{Driver, LibraryIo, Limits, RuntimeContext};
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir(root.join("runtime")).unwrap();
        fs::set_permissions(root.join("runtime"), fs::Permissions::from_mode(0o700)).unwrap();
        let bus = std::os::unix::net::UnixListener::bind(root.join("runtime/bus")).unwrap();
        fs::create_dir_all(root.join("proc/sys/kernel/random")).unwrap();
        fs::write(root.join("proc/sys/kernel/random/boot_id"), &r.input().boot).unwrap();
        let cg = root
            .join("cg")
            .join(b.identity().cgroup.trim_start_matches('/'));
        fs::create_dir_all(&cg).unwrap();
        fs::write(cg.join("cgroup.procs"), "").unwrap();
        fs::write(cg.join("cgroup.type"), "domain\n").unwrap();
        fs::write(
            root.join("properties"),
            format!(
                "Id={}\nInvocationID={}\nControlGroup={}\nLoadState=loaded\nActiveState=inactive\n",
                b.identity().unit,
                b.identity().invocation,
                b.identity().cgroup
            ),
        )
        .unwrap();
        fs::write(
            root.join("manager"),
            format!(
                "#!/bin/sh\nexec /usr/bin/cat '{}'\n",
                root.join("properties").display()
            ),
        )
        .unwrap();
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
        Self {
            tmp,
            _bus: bus,
            driver,
        }
    }
    pub fn process(&self, b: &Binding, ticks: u64, group: &str) {
        self.process_pid(b.trusted_child().pid, ticks, group);
    }
    pub fn process_pid(&self, pid: u32, ticks: u64, group: &str) {
        use std::fs;
        let p = self.tmp.path().join("proc").join(pid.to_string());
        fs::create_dir_all(&p).unwrap();
        fs::write(
            p.join("stat"),
            format!("{pid} (root) S {} {ticks} 0\n", vec!["0"; 18].join(" ")),
        )
        .unwrap();
        fs::write(p.join("cgroup"), format!("0::{group}\n")).unwrap();
    }
}
