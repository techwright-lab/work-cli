use super::fixture_support;
use std::{fs, os::unix::fs::PermissionsExt, time::Duration};
use uuid::Uuid;
use work_cli::{
    capture_bridge::*,
    capture_journal::*,
    config::Config,
    run_journal::{RootOutcome, RootRunRequest},
    store::Store,
};
pub const CAPTURE: &str = "550e8400-e29b-41d4-a716-446655440001";
pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub store: Store,
    pub root: RootRunRequest,
    pub config: Config,
}
impl Fixture {
    pub fn new(closed: bool, outcome: Option<RootOutcome>) -> Self {
        Self::with_source(closed, outcome, None)
    }
    pub fn with_source(closed: bool, outcome: Option<RootOutcome>, source: Option<Source>) -> Self {
        let (dir, mut store, checkout) = fixture_support::fixture();
        let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        let operation: String = sql
            .query_row("SELECT operation FROM checkouts", [], |r| r.get(0))
            .unwrap();
        let start = work_cli::allocate::Start {
            operation: Uuid::parse_str(&operation).unwrap(),
            repository: Some(dir.path().join("root")),
            root: Some("/private".into()),
            actor: Some("allocator".into()),
            owner: Some("owner".into()),
            task: "task".into(),
            branch: Some("task".into()),
            base: "main".into(),
            reuse_branch: false,
        };
        let allocation = work_cli::allocate::Allocation {
            checkout,
            request: start.clone(),
            destination: "/private/task".into(),
            base_commit: "a".repeat(40),
            stage: "ready".into(),
            reason: None,
            identity: Some(work_cli::identity::CheckoutIdentity {
                path: "/private/task".into(),
                private_git_dir: "/private/git".into(),
                common_git_dir: dir.path().join("root"),
                directory: work_cli::identity::DirectoryIdentity {
                    device: 1,
                    inode: 1,
                },
                head: "a".repeat(40),
                boot_id: fixture_support::BOOT.into(),
            }),
        };
        sql.execute(
            "INSERT INTO allocations VALUES(?1,?2,?3)",
            (
                checkout.to_string(),
                serde_json::to_string(&start).unwrap(),
                serde_json::to_string(&allocation).unwrap(),
            ),
        )
        .unwrap();
        let root = fixture_support::request(checkout);
        let declaration = BeginRequest {
            actor_ref: "actor".into(),
            run_ref: root.identity().run_ref.as_str().into(),
            cwd: "/private/task".into(),
            execution_chain: root.identity().execution_chain.clone(),
            task_refs: vec!["task".into()],
            parent_run_ref: root
                .identity()
                .parent_run_ref
                .as_ref()
                .map(|r| r.as_str().into()),
            key_file: None,
            source,
            lifecycle: WorkLifecycle {
                checkout_id: root.identity().checkout.clone(),
                mode: work_contract::ExecutionMode::Supervised,
                group_id: Some(root.identity().group.clone()),
                operation_id: None,
            },
        };
        let spec = CaptureSpec::new(
            Uuid::now_v7(),
            SinkSnapshot::new(SinkSettings {
                executable: dir.path().join("producer"),
                registry: dir.path().join("missing-registry"),
                state: dir.path().join("state"),
                timeout: Duration::from_secs(2),
                response_cap: 1024 * 1024,
                endpoint_identity: "https://receiver.invalid".into(),
                registry_identity: "registry".into(),
                receiver_credential_names: vec![],
                registry_actor_ref: "actor".into(),
            })
            .unwrap(),
            declaration,
            GitProfile::default(),
        )
        .unwrap();
        let BeginCapturedRun::Created(handle) = store.begin_captured_run(&root, &spec).unwrap()
        else {
            panic!("created")
        };
        let context = dir.path().join(format!("state/{CAPTURE}.context.json"));
        let prepared = decode_begin(&serde_json::to_vec(&serde_json::json!({"capture_id":CAPTURE,"actor_ref":"actor","run_ref":root.identity().run_ref.as_str(),"state":"open","environment":{"AGENT_ATTRIBUTION_CONTEXT":context,"DEVDIARY_ATTRIBUTION_CONTEXT":context,"DEVDIARY_CAPTURE_ID":CAPTURE}})).unwrap(), &spec.begin_request(), &GitProfile::default()).unwrap();
        store.record_capture_prepared(handle, &prepared).unwrap();
        let binding = fixture_support::binding(&root);
        store.record_bound(&root, &binding).unwrap();
        store.record_permit_attempt(&root, &binding).unwrap();
        if let Some(outcome) = outcome {
            store.record_root_outcome(&root, outcome).unwrap();
        }
        if closed {
            let os = fixture_support::ClosureOs::new(&root, &binding);
            let snapshot = store.group_snapshot(&root.identity().run).unwrap();
            let proof = snapshot.certify_empty(&os.driver, &binding).unwrap();
            store.close_supervised_group(&snapshot, &proof).unwrap();
        }
        let config = Config {
            store_dir: Some(dir.path().join("private")),
            trusted_registry: Some(dir.path().join(".work-authorities")),
            roots: vec![dir.path().join("root")],
            ..Config::default()
        };
        let f = Self {
            dir,
            store,
            root,
            config,
        };
        f.respond("pending", serde_json::json!({}), false);
        f
    }
    pub fn sql(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.dir.path().join("private/store.sqlite")).unwrap()
    }
    pub fn respond(&self, state: &str, extra: serde_json::Value, fail: bool) {
        let mut response = serde_json::json!({"capture_id":CAPTURE,"actor_ref":"actor","run_ref":self.root.identity().run_ref.as_str(),"state":state});
        response
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        fs::write(self.dir.path().join("response"), response.to_string()).unwrap();
        fs::write(self.dir.path().join("producer"), format!("#!/bin/sh\nprintf '%s\\n' \"$4\" >> '{0}/calls'\n/usr/bin/cat >> '{0}/input'\n{1}\nexec /usr/bin/cat '{0}/response'\n", self.dir.path().display(), if fail { "exit 1" } else { ":" })).unwrap();
        fs::set_permissions(
            self.dir.path().join("producer"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
}
