use rusqlite::Connection;
#[path = "support/run_fixture.rs"]
mod fixture_support;
mod support;
use fixture_support::*;

use std::time::Duration;
use uuid::Uuid;
use work_cli::{
    capture_bridge::{BeginRequest, GitProfile, WorkLifecycle},
    capture_journal::{BeginCapturedRun, CaptureSpec, SinkSettings, SinkSnapshot},
    run_journal::RootRunRequest,
};
use work_contract::ExecutionMode;
// Extend the shared synthetic run fixture with a typed durable ready allocation.
// No Git or external process is needed to exercise this SQL/library boundary.
fn fixture() -> (tempfile::TempDir, work_cli::store::Store, Uuid) {
    let (dir, store, checkout) = fixture_support::fixture();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
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
            boot_id: BOOT.into(),
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
    (dir, store, checkout)
}
fn settings() -> SinkSettings {
    SinkSettings {
        executable: "/private/capture".into(),
        registry: "/private/registry".into(),
        state: "/private/state".into(),
        timeout: Duration::from_millis(50),
        response_cap: 65536,
        endpoint_identity: "https://receiver.invalid".into(),
        registry_identity: "registry:v1".into(),
        receiver_credential_names: vec!["RECEIVER_TOKEN".into()],
        registry_actor_ref: "actor:registered".into(),
    }
}
fn declaration(r: &RootRunRequest) -> BeginRequest {
    BeginRequest {
        actor_ref: "actor:registered".into(),
        run_ref: r.identity().run_ref.as_str().into(),
        cwd: "/private/task".into(),
        execution_chain: r.identity().execution_chain.clone(),
        task_refs: vec!["task".into()],
        parent_run_ref: r
            .identity()
            .parent_run_ref
            .as_ref()
            .map(|p| p.as_str().into()),
        key_file: Some("/private/key".into()),
        source: None,
        lifecycle: WorkLifecycle {
            checkout_id: r.identity().checkout.clone(),
            mode: ExecutionMode::Supervised,
            group_id: Some(r.identity().group.clone()),
            operation_id: None,
        },
    }
}
fn spec(r: &RootRunRequest) -> CaptureSpec {
    CaptureSpec::new(
        Uuid::now_v7(),
        SinkSnapshot::new(settings()).unwrap(),
        declaration(r),
        GitProfile::default(),
    )
    .unwrap()
}

#[test]
fn canonical_capture_snapshot_matches_transport_without_duplicate_amplification() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let mut d = declaration(&r);
    let extra = "x".repeat(4096);
    d.task_refs.extend(std::iter::repeat_n(extra.clone(), 9998));
    d.task_refs.push("last".into());
    let wire = d.encode().unwrap();
    let op = Uuid::now_v7();
    let s = CaptureSpec::new(
        op,
        SinkSnapshot::new(settings()).unwrap(),
        d,
        GitProfile::default(),
    )
    .unwrap();
    let bytes = serde_json::to_vec(&s).unwrap();
    assert!(
        bytes.len() <= 2 * 1024 * 1024,
        "accepted snapshot amplified to {} bytes",
        bytes.len()
    );
    assert_eq!(s.begin_request().task_refs, vec!["task", &extra, "last"]);
    assert_eq!(s.begin_request().encode().unwrap(), wire);
    let mut canonical = declaration(&r);
    canonical.task_refs = vec!["task".into(), extra, "last".into()];
    let canonical = CaptureSpec::new(
        op,
        SinkSnapshot::new(settings()).unwrap(),
        canonical,
        GitProfile::default(),
    )
    .unwrap();
    assert_eq!(serde_json::to_vec(&canonical).unwrap(), bytes);
    drop(store.begin_captured_run(&r, &s).unwrap());
    let fingerprint = store
        .capture_snapshot(&r.identity().run)
        .unwrap()
        .unwrap()
        .fingerprint;
    drop(store);
    let mut store = reopen(&dir).unwrap();
    let BeginCapturedRun::Existing(record) = store.begin_captured_run(&r, &canonical).unwrap()
    else {
        panic!("existing")
    };
    assert_eq!(record.fingerprint, fingerprint);
}

#[test]
fn credential_metadata_has_a_finite_positive_bound_without_authority_mutation() {
    let (dir, store, _checkout) = fixture();
    let events = store.pending_events(100).unwrap();
    for count in [128, 129] {
        let mut s = settings();
        s.receiver_credential_names = (0..count).map(|n| format!("TOKEN_{n}")).collect();
        assert_eq!(
            SinkSnapshot::new(s).is_ok(),
            count == 128,
            "credential count {count}"
        );
    }
    drop(store);
    let store = reopen(&dir).unwrap();
    assert_eq!(store.pending_events(100).unwrap(), events);
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    assert_eq!(
        sql.query_row("SELECT count(*) FROM capture_runs", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn oversized_target_capture_payloads_are_refused_even_when_json_is_valid() {
    let mut accepted = Vec::new();
    for column in ["spec", "prepared", "group_end"] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let s = spec(&r);
        let BeginCapturedRun::Created(h) = store.begin_captured_run(&r, &s).unwrap() else {
            panic!("created")
        };
        let p = prepared(
            &s,
            "/private/state/context.json",
            "actor:registered",
            r.identity().run_ref.as_str(),
            &GitProfile::default(),
        );
        store.record_capture_prepared(h, &p).unwrap();
        let b = binding(&r);
        store.record_bound(&r, &b).unwrap();
        let os = ClosureOs::new(&r, &b);
        let snap = store.group_snapshot(&r.identity().run).unwrap();
        let proof = snap.certify_empty(&os.driver, &b).unwrap();
        store.close_supervised_group(&snap, &proof).unwrap();
        let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        let body: String = sql
            .query_row(&format!("SELECT {column} FROM capture_runs"), [], |r| {
                r.get(0)
            })
            .unwrap();
        let oversized = body + &" ".repeat(2 * 1024 * 1024);
        sql.execute(
            &format!("UPDATE capture_runs SET {column}=?1"),
            [&oversized],
        )
        .unwrap();
        let events = store.pending_events(100).unwrap();
        if store.capture_snapshot(&r.identity().run).is_ok() {
            accepted.push(column);
        }
        if store.begin_captured_run(&r, &s).is_ok() {
            accepted.push(column);
        }
        assert_eq!(store.pending_events(100).unwrap(), events);
        drop(store);
        let store = reopen(&dir).unwrap();
        if store.capture_snapshot(&r.identity().run).is_ok() {
            accepted.push(column);
        }
        assert_eq!(
            sql.query_row(&format!("SELECT {column} FROM capture_runs"), [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap(),
            oversized
        );
    }
    assert!(
        accepted.is_empty(),
        "oversized valid JSON accepted: {accepted:?}"
    );
}

#[test]
fn leading_additional_task_cannot_replace_the_durable_primary() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let mut d = declaration(&r);
    d.task_refs = vec!["other".into(), "task".into()];
    let s = CaptureSpec::new(
        Uuid::now_v7(),
        SinkSnapshot::new(settings()).unwrap(),
        d,
        GitProfile::default(),
    )
    .unwrap();
    let events = store.pending_events(100).unwrap();
    assert!(
        store.begin_captured_run(&r, &s).is_err(),
        "nonprimary membership accepted"
    );
    assert_eq!(store.pending_events(100).unwrap(), events);
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    assert_eq!(
        sql.query_row("SELECT count(*) FROM runs", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    let mut d = declaration(&r);
    d.task_refs.push("other".into());
    let s = CaptureSpec::new(
        Uuid::now_v7(),
        SinkSnapshot::new(settings()).unwrap(),
        d,
        GitProfile::default(),
    )
    .unwrap();
    let wire: serde_json::Value =
        serde_json::from_slice(&s.begin_request().encode().unwrap()).unwrap();
    assert_eq!(wire["task_refs"], serde_json::json!(["task", "other"]));
    drop(store.begin_captured_run(&r, &s).unwrap());
}

// Synthetic independent capture checkouts reuse a legal allocation's immutable
// metadata; no extra Git worktrees or OS scopes are involved.
fn unrelated_capture(
    f: &support::Fixture,
    store: &mut work_cli::store::Store,
    a: &work_cli::allocate::Allocation,
    extra: Option<String>,
) -> RootRunRequest {
    let sql = Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
    let checkout = Uuid::now_v7();
    let operation = Uuid::now_v7();
    sql.execute("INSERT INTO checkouts SELECT ?1,?2,digest,repository,actor,task,owner,'active',1 FROM checkouts WHERE id=?3", (checkout.to_string(), operation.to_string(), a.checkout.to_string())).unwrap();
    sql.execute("INSERT INTO allocations SELECT ?1,json_set(request,'$.operation',?2),json_set(record,'$.checkout',?1,'$.request.operation',?2) FROM allocations WHERE checkout=?3", (checkout.to_string(), operation.to_string(), a.checkout.to_string())).unwrap();
    let r = request(checkout);
    let mut d = declaration(&r);
    d.cwd = a.destination.clone();
    if let Some(extra) = extra {
        d.task_refs.push(extra);
    }
    let s = CaptureSpec::new(
        Uuid::now_v7(),
        SinkSnapshot::new(settings()).unwrap(),
        d,
        GitProfile::default(),
    )
    .unwrap();
    drop(store.begin_captured_run(&r, &s).unwrap());
    r
}

#[test]
fn unrelated_corrupt_capture_does_not_poison_no_sink_finish() {
    let f = support::Fixture::new();
    let output = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
    assert!(output.status.success());
    let a: work_cli::allocate::Allocation = serde_json::from_slice(&output.stdout).unwrap();
    let cfg = work_cli::config::Config::from_text(
        &std::fs::read_to_string(f.temp.path().join("config.toml")).unwrap(),
    )
    .unwrap();
    let mut store = f.store();
    let r = unrelated_capture(&f, &mut store, &a, None);
    let sql = Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
    sql.execute("UPDATE capture_runs SET spec='{}'", [])
        .unwrap();
    assert!(store.capture_snapshot(&r.identity().run).is_err());
    let result = work_cli::finish::finish(&cfg, a.checkout);
    assert!(
        result.is_ok(),
        "unrelated capture poisoned finish: {result:?}"
    );
    assert!(store.capture_snapshot(&r.identity().run).is_err());
}

#[test]
fn unrelated_legacy_root_writer_and_child_corruption_still_blocks_finish() {
    for case in ["root", "writer", "child_count"] {
        let f = support::Fixture::new();
        let output = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
        assert!(output.status.success());
        let a: work_cli::allocate::Allocation = serde_json::from_slice(&output.stdout).unwrap();
        let cfg = work_cli::config::Config::from_text(
            &std::fs::read_to_string(f.temp.path().join("config.toml")).unwrap(),
        )
        .unwrap();
        let mut store = f.store();
        let r = unrelated_capture(&f, &mut store, &a, None);
        let sql = Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
        match case {
            "root" => {
                sql.execute("UPDATE runs SET request='{}'", []).unwrap();
            }
            "writer" => {
                sql.execute("DELETE FROM writers", []).unwrap();
            }
            _ => {
                sql.execute("UPDATE run_groups SET child_count=1", [])
                    .unwrap();
            }
        }
        assert!(
            work_cli::finish::finish(&cfg, a.checkout).is_err(),
            "legacy {case}"
        );
        assert!(store.run_snapshot(&r.identity().run).is_err() || case == "writer");
        assert_eq!(
            sql.query_row("SELECT count(*) FROM task_finishes", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}

#[test]
fn substantial_legal_capture_history_does_not_amplify_finish_validation() {
    let f = support::Fixture::new();
    let output = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
    assert!(output.status.success());
    let a: work_cli::allocate::Allocation = serde_json::from_slice(&output.stdout).unwrap();
    let cfg = work_cli::config::Config::from_text(
        &std::fs::read_to_string(f.temp.path().join("config.toml")).unwrap(),
    )
    .unwrap();
    let mut store = f.store();
    // 128 legal captures, each with twelve distinct 4096-character references.
    for n in 0..128 {
        let r = unrelated_capture(&f, &mut store, &a, None);
        let sql = Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
        let body: String = sql
            .query_row(
                "SELECT spec FROM capture_runs WHERE run=?1",
                [r.identity().run.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&body).unwrap();
        let mut d = declaration(&r);
        d.cwd = a.destination.clone();
        d.task_refs
            .extend((0..12).map(|i| format!("{n:03}{i:02}{}", "x".repeat(4091))));
        let op = Uuid::parse_str(value["operation"].as_str().unwrap()).unwrap();
        let s = CaptureSpec::new(
            op,
            SinkSnapshot::new(settings()).unwrap(),
            d,
            GitProfile::default(),
        )
        .unwrap();
        value = serde_json::to_value(&s).unwrap();
        use sha2::{Digest, Sha256};
        let fingerprint = Sha256::digest(serde_json::to_vec(&s).unwrap());
        sql.execute(
            "UPDATE capture_runs SET spec=?2,fingerprint=?3 WHERE run=?1",
            rusqlite::params![
                r.identity().run.to_string(),
                value.to_string(),
                fingerprint.as_slice()
            ],
        )
        .unwrap();
        assert!(store.capture_snapshot(&r.identity().run).unwrap().is_some());
    }
    let sql = Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let bytes: u64 = ["store.sqlite", "store.sqlite-wal", "store.sqlite-shm"]
        .iter()
        .map(|name| {
            std::fs::metadata(f.temp.path().join("private").join(name))
                .unwrap()
                .len()
        })
        .sum();
    assert!(bytes < 16 * 1024 * 1024, "fixture file bytes {bytes}");
    let result = work_cli::finish::finish(&cfg, a.checkout);
    assert!(
        result.is_ok(),
        "legal capture history poisoned finish: {result:?}"
    );
}

#[test]
fn immutable_snapshots_refuse_invalid_settings_declarations_and_git() {
    for case in [
        "relative",
        "timeout_zero",
        "timeout_high",
        "cap_zero",
        "cap_high",
        "credential",
        "duplicate",
        "endpoint",
        "actor",
    ] {
        let mut s = settings();
        match case {
            "relative" => s.executable = "relative".into(),
            "timeout_zero" => s.timeout = Duration::ZERO,
            "timeout_high" => s.timeout = Duration::from_millis(30001),
            "cap_zero" => s.response_cap = 0,
            "cap_high" => s.response_cap = 1048577,
            "credential" => s.receiver_credential_names = vec!["TOKEN=value".into()],
            "duplicate" => s.receiver_credential_names = vec!["TOKEN".into(), "TOKEN".into()],
            "endpoint" => s.endpoint_identity = "https://user:secret@receiver.invalid".into(),
            _ => s.registry_actor_ref = "".into(),
        }
        assert!(SinkSnapshot::new(s).is_err(), "{case}");
    }
    let (_dir, _store, checkout) = fixture();
    let r = request(checkout);
    for case in ["declaration", "git", "mode", "operation"] {
        let mut d = declaration(&r);
        let mut git = GitProfile::default();
        let mut op = Uuid::now_v7();
        match case {
            "declaration" => d.actor_ref.clear(),
            "git" => git.author_name = Some("bad\n".into()),
            "mode" => d.lifecycle.mode = ExecutionMode::Adopted,
            _ => op = Uuid::nil(),
        }
        assert!(
            CaptureSpec::new(op, SinkSnapshot::new(settings()).unwrap(), d, git).is_err(),
            "{case}"
        );
    }
}

#[test]
fn captured_begin_is_atomic_and_only_fresh_creation_returns_preparation_handle() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let spec = spec(&r);
    let created = store.begin_captured_run(&r, &spec).unwrap();
    assert!(matches!(created, BeginCapturedRun::Created(_)));
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    assert_eq!(
        sql.query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    let events = store.pending_events(100).unwrap();
    assert!(matches!(
        store.begin_captured_run(&r, &spec).unwrap(),
        BeginCapturedRun::Existing(_)
    ));
    assert_eq!(store.pending_events(100).unwrap(), events);
    assert!(store.record_bound(&r, &binding(&r)).is_err());
}

fn prepared(
    spec: &CaptureSpec,
    context: &str,
    actor: &str,
    run: &str,
    git: &GitProfile,
) -> work_cli::capture_bridge::Prepared {
    let capture = "550e8400-e29b-41d4-a716-446655440001";
    // This fixture's default label resolves to the public per-capture locator.
    // Overrides (including outside-state paths) remain literal negative fixtures.
    let context = if context == "/private/state/context.json" {
        "/private/state/550e8400-e29b-41d4-a716-446655440001.context.json"
    } else {
        context
    };
    let mut response = serde_json::json!({"capture_id":capture,"actor_ref":actor,"run_ref":run,"state":"open","environment":{"AGENT_ATTRIBUTION_CONTEXT":context,"DEVDIARY_ATTRIBUTION_CONTEXT":context,"DEVDIARY_CAPTURE_ID":capture}});
    for (name, value) in [
        ("GIT_AUTHOR_NAME", &git.author_name),
        ("GIT_AUTHOR_EMAIL", &git.author_email),
        ("GIT_COMMITTER_NAME", &git.committer_name),
        ("GIT_COMMITTER_EMAIL", &git.committer_email),
    ] {
        if let Some(value) = value {
            response["environment"][name] = serde_json::json!(value);
        }
    }
    let mut request = spec.begin_request();
    request.actor_ref = actor.into();
    request.run_ref = run.into();
    work_cli::capture_bridge::decode_begin(&serde_json::to_vec(&response).unwrap(), &request, git)
        .unwrap()
}

#[test]
fn matched_preparation_commits_readiness_but_never_binding_or_permission() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let s = spec(&r);
    let BeginCapturedRun::Created(handle) = store.begin_captured_run(&r, &s).unwrap() else {
        panic!("fresh handle")
    };
    let p = prepared(
        &s,
        "/private/state/context.json",
        "actor:registered",
        r.identity().run_ref.as_str(),
        &GitProfile::default(),
    );
    store.record_capture_prepared(handle, &p).unwrap();
    let record = store.capture_snapshot(&r.identity().run).unwrap().unwrap();
    assert!(record.prepared.is_some());
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    assert_eq!(
        sql.query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .run_snapshot(&r.identity().run)
            .unwrap()
            .unwrap()
            .stage,
        work_cli::run_journal::RunStage::Intent
    );
    store.record_bound(&r, &binding(&r)).unwrap();
}

#[test]
fn mismatched_or_late_preparation_cannot_revive_readiness_or_remove_writer() {
    for case in [
        "actor", "run", "context", "git", "hold", "outcome", "finish", "lease",
    ] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let s = spec(&r);
        let BeginCapturedRun::Created(handle) = store.begin_captured_run(&r, &s).unwrap() else {
            panic!("fresh handle")
        };
        let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        match case {
            "hold" => {
                store.record_recovery_hold(&r).unwrap();
            }
            "outcome" => {
                store
                    .record_root_outcome(&r, work_cli::run_journal::RootOutcome::Failed)
                    .unwrap();
            }
            "finish" => {
                sql.execute(
                    "INSERT INTO task_finishes VALUES(?1,?2,'malformed')",
                    (checkout.to_string(), Uuid::now_v7().to_string()),
                )
                .unwrap();
            }
            "lease" => {
                sql.execute("UPDATE checkouts SET state='held'", [])
                    .unwrap();
            }
            _ => {}
        }
        let p = prepared(
            &s,
            if case == "context" {
                "/other/context"
            } else {
                "/private/state/context.json"
            },
            if case == "actor" {
                "actor:other"
            } else {
                "actor:registered"
            },
            if case == "run" {
                "run:other"
            } else {
                r.identity().run_ref.as_str()
            },
            &if case == "git" {
                GitProfile {
                    author_name: Some("Other".into()),
                    ..Default::default()
                }
            } else {
                GitProfile::default()
            },
        );
        let events = store.pending_events(100).unwrap();
        assert!(store.record_capture_prepared(handle, &p).is_err(), "{case}");
        assert_eq!(store.pending_events(100).unwrap(), events, "{case}");
        assert_eq!(
            sql.query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0,
            "{case}"
        );
        assert_eq!(
            sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1,
            "{case}"
        );
    }
}

#[test]
fn lost_response_reconciliation_is_metadata_only_after_reopen() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let s = spec(&r);
    drop(store.begin_captured_run(&r, &s).unwrap());
    drop(store);
    let mut store = reopen(&dir).unwrap();
    assert!(matches!(
        store.begin_captured_run(&r, &s).unwrap(),
        BeginCapturedRun::Existing(_)
    ));
    let p = prepared(
        &s,
        "/private/state/context.json",
        "actor:registered",
        r.identity().run_ref.as_str(),
        &GitProfile::default(),
    );
    store.reconcile_capture_prepared(&r, &s, &p).unwrap();
    assert!(store
        .capture_snapshot(&r.identity().run)
        .unwrap()
        .unwrap()
        .prepared
        .is_some());
    assert!(
        store
            .run_snapshot(&r.identity().run)
            .unwrap()
            .unwrap()
            .recovery_hold
    );
    assert!(store.record_bound(&r, &binding(&r)).is_err());
    let events = store.pending_events(100).unwrap();
    store.reconcile_capture_prepared(&r, &s, &p).unwrap();
    assert_eq!(store.pending_events(100).unwrap(), events);
}

#[test]
fn intent_and_preparation_sql_failures_roll_back_the_entire_transition() {
    for case in ["intent", "event", "prepared", "prepared_event"] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let s = spec(&r);
        let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        let handle = if case.starts_with("prepared") {
            let BeginCapturedRun::Created(h) = store.begin_captured_run(&r, &s).unwrap() else {
                panic!("created")
            };
            Some(h)
        } else {
            None
        };
        let events = store.pending_events(100).unwrap();
        let before:(i64,i64,i64,i64)=sql.query_row("SELECT (SELECT count(*) FROM writers),(SELECT count(*) FROM runs),(SELECT count(*) FROM capture_runs),(SELECT ready FROM checkouts)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        let ddl=match case {
            "intent"=>"CREATE TRIGGER reject_capture BEFORE INSERT ON capture_runs BEGIN SELECT RAISE(ABORT,'fixture'); END",
            "event"=>"CREATE TRIGGER reject_capture BEFORE INSERT ON outbox WHEN json_extract(NEW.payload,'$.change')='capture_intent' BEGIN SELECT RAISE(ABORT,'fixture'); END",
            "prepared"=>"CREATE TRIGGER reject_capture BEFORE UPDATE ON capture_runs BEGIN SELECT RAISE(ABORT,'fixture'); END",
            _=>"CREATE TRIGGER reject_capture BEFORE INSERT ON outbox WHEN json_extract(NEW.payload,'$.change')='capture_prepared' BEGIN SELECT RAISE(ABORT,'fixture'); END",
        };
        sql.execute_batch(ddl).unwrap();
        let failed = if let Some(h) = handle {
            let p = prepared(
                &s,
                "/private/state/context.json",
                "actor:registered",
                r.identity().run_ref.as_str(),
                &GitProfile::default(),
            );
            store.record_capture_prepared(h, &p).is_err()
        } else {
            store.begin_captured_run(&r, &s).is_err()
        };
        assert!(failed, "{case}");
        let after=sql.query_row("SELECT (SELECT count(*) FROM writers),(SELECT count(*) FROM runs),(SELECT count(*) FROM capture_runs),(SELECT ready FROM checkouts)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(before, after, "{case}");
        assert_eq!(store.pending_events(100).unwrap(), events);
        assert_eq!(
            store
                .charged(&dir.path().join("root"), Some("owner"))
                .unwrap(),
            1
        );
    }
}

#[test]
fn capture_operation_is_reserved_before_all_existing_and_new_namespace_acknowledgements() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let s = spec(&r);
    drop(store.begin_captured_run(&r, &s).unwrap());
    let op = s.operation();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let other = Uuid::now_v7();
    sql.execute("INSERT INTO checkouts SELECT ?1,?2,digest,repository,actor,task,owner,'active',1 FROM checkouts WHERE id=?3",(other.to_string(),Uuid::now_v7().to_string(),checkout.to_string())).unwrap();
    assert!(store.acquire_writer(other, op).is_err());
    for field in ["run", "group"] {
        assert!(
            store
                .begin_run(&changed(&request(other), field, serde_json::json!(op)))
                .is_err(),
            "{field}"
        );
    }
    sql.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    // Even corrupt pre-existing overlaps cannot receive idempotent acknowledgement.
    sql.execute(
        "UPDATE runs SET id=?1, request=json_set(request,'$.identity.run',?1)",
        [op.to_string()],
    )
    .unwrap();
    let overlap = changed(&r, "run", serde_json::json!(op));
    assert!(
        store.begin_run(&overlap).is_err(),
        "overlapping Existing root"
    );
}

#[test]
fn closure_retains_capture_hold_and_unknown_outcome_and_immutable_group_boundary() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let s = spec(&r);
    let BeginCapturedRun::Created(h) = store.begin_captured_run(&r, &s).unwrap() else {
        panic!("created")
    };
    let p = prepared(
        &s,
        "/private/state/context.json",
        "actor:registered",
        r.identity().run_ref.as_str(),
        &GitProfile::default(),
    );
    store.record_capture_prepared(h, &p).unwrap();
    let b = binding(&r);
    store.record_bound(&r, &b).unwrap();
    let os = ClosureOs::new(&r, &b);
    let snap = store.group_snapshot(&r.identity().run).unwrap();
    let proof = snap.certify_empty(&os.driver, &b).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let events = store.pending_events(100).unwrap();
    sql.execute_batch("CREATE TRIGGER reject_group_end BEFORE INSERT ON outbox WHEN json_extract(NEW.payload,'$.change')='capture_group_end' BEGIN SELECT RAISE(ABORT,'fixture'); END").unwrap();
    assert!(store.close_supervised_group(&snap, &proof).is_err());
    assert!(store
        .capture_snapshot(&r.identity().run)
        .unwrap()
        .unwrap()
        .group_end
        .is_none());
    assert_eq!(store.pending_events(100).unwrap(), events);
    assert_eq!(
        sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    sql.execute_batch("DROP TRIGGER reject_group_end").unwrap();
    store.close_supervised_group(&snap, &proof).unwrap();
    let closed = store.capture_snapshot(&r.identity().run).unwrap().unwrap();
    assert!(closed.group_end.is_some());
    assert!(store
        .run_snapshot(&r.identity().run)
        .unwrap()
        .unwrap()
        .outcome
        .is_none());
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let state: (String, bool) = sql
        .query_row("SELECT state,ready FROM checkouts", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(state, ("held".into(), false));
    assert!(store.begin_run(&request(checkout)).is_err());
    assert_eq!(
        sql.query_row("SELECT count(*) FROM task_finishes", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .charged(&dir.path().join("root"), Some("owner"))
            .unwrap(),
        1
    );
    let first = serde_json::to_string(&closed).unwrap();
    // Synthetic newer-writer corruption must not be mutated by an old close receipt.
    let newer = Uuid::now_v7();
    sql.execute("UPDATE checkouts SET state='active',ready=1", [])
        .unwrap();
    sql.execute(
        "INSERT INTO writers VALUES(?1,?2)",
        (checkout.to_string(), newer.to_string()),
    )
    .unwrap();
    let events = store.pending_events(100).unwrap();
    store.close_supervised_group(&snap, &proof).unwrap();
    assert_eq!(
        first,
        serde_json::to_string(&store.capture_snapshot(&r.identity().run).unwrap().unwrap())
            .unwrap()
    );
    assert_eq!(
        sql.query_row("SELECT group_id FROM writers", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        newer.to_string()
    );
    assert!(sql
        .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
        .unwrap());
    assert_eq!(store.pending_events(100).unwrap(), events);
}

#[test]
fn every_sealed_setting_and_declaration_conflicts_without_rewriting_existing_intent() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let s = spec(&r);
    drop(store.begin_captured_run(&r, &s).unwrap());
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let before: String = sql
        .query_row("SELECT spec||intent_wall FROM capture_runs", [], |r| {
            r.get(0)
        })
        .unwrap();
    let events = store.pending_events(100).unwrap();
    for case in [
        "executable",
        "registry",
        "state",
        "timeout",
        "cap",
        "endpoint",
        "registry_identity",
        "credentials",
        "actor",
        "cwd",
        "tasks",
        "chain",
        "parent",
        "key_file",
        "source",
        "git",
        "operation",
    ] {
        let mut settings = settings();
        let mut d = s.begin_request();
        let mut git = GitProfile::default();
        let mut op = s.operation();
        match case {
            "executable" => settings.executable = "/other/executable".into(),
            "registry" => settings.registry = "/other/registry".into(),
            "state" => settings.state = "/other/state".into(),
            "timeout" => settings.timeout = Duration::from_millis(51),
            "cap" => settings.response_cap = 65537,
            "endpoint" => settings.endpoint_identity = "https://other.invalid".into(),
            "registry_identity" => settings.registry_identity = "registry:v2".into(),
            "credentials" => settings.receiver_credential_names = vec!["OTHER_TOKEN".into()],
            "actor" => {
                settings.registry_actor_ref = "actor:other".into();
                d.actor_ref = "actor:other".into();
            }
            "cwd" => d.cwd = "/other/checkout".into(),
            "tasks" => d.task_refs.push("declared:extra".into()),
            "chain" => {
                d.execution_chain = serde_json::from_value(
                    serde_json::json!([{"kind":"executor","system":"other"}]),
                )
                .unwrap()
            }
            "parent" => d.parent_run_ref = Some("parent:other".into()),
            "key_file" => d.key_file = Some("/other/key".into()),
            "source" => {
                d.source = Some(work_cli::capture_bridge::Source {
                    system: Some("other".into()),
                    ..Default::default()
                })
            }
            "git" => git.author_email = Some("actor@example.invalid".into()),

            _ => op = Uuid::now_v7(),
        }
        let changed = CaptureSpec::new(op, SinkSnapshot::new(settings).unwrap(), d, git).unwrap();
        assert!(store.begin_captured_run(&r, &changed).is_err(), "{case}");
    }
    assert_eq!(
        sql.query_row("SELECT spec||intent_wall FROM capture_runs", [], |r| r
            .get::<_, String>(
            0
        ))
        .unwrap(),
        before
    );
    assert_eq!(store.pending_events(100).unwrap(), events);
}

#[test]
fn captured_begin_never_adds_capture_to_old_no_sink_root_or_bypasses_readiness() {
    for case in ["existing", "not_ready", "held", "finish"] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let s = spec(&r);
        let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        match case {
            "existing" => {
                store.begin_run(&r).unwrap();
            }
            "not_ready" => {
                sql.execute("UPDATE checkouts SET ready=0", []).unwrap();
            }
            "held" => {
                sql.execute("UPDATE checkouts SET state='held'", [])
                    .unwrap();
            }
            _ => {
                sql.execute(
                    "INSERT INTO task_finishes VALUES(?1,?2,'malformed')",
                    (checkout.to_string(), Uuid::now_v7().to_string()),
                )
                .unwrap();
            }
        }
        let events = store.pending_events(100).unwrap();
        assert!(store.begin_captured_run(&r, &s).is_err(), "{case}");
        assert_eq!(
            sql.query_row("SELECT count(*) FROM capture_runs", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(store.pending_events(100).unwrap(), events);
    }
}

#[test]
fn independent_connections_contend_for_one_atomic_capture_root() {
    let (dir, mut a, checkout) = fixture();
    let mut b = reopen(&dir).unwrap();
    let r = request(checkout);
    let s = spec(&r);
    let r2 = request(checkout);
    let s2 = spec(&r2);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let start = barrier.clone();
    let thread = std::thread::spawn(move || {
        start.wait();
        b.begin_captured_run(&r2, &s2).is_ok()
    });
    barrier.wait();
    let first = a.begin_captured_run(&r, &s).is_ok();
    assert_ne!(first, thread.join().unwrap());
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    for table in ["runs", "run_groups", "capture_runs", "writers"] {
        assert_eq!(
            sql.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1,
            "{table}"
        );
    }
}

#[test]
fn strict_typed_capture_history_is_validated_even_on_existing_and_related_closed_receipts() {
    for case in [
        "unknown",
        "duplicate",
        "positional",
        "nested_positional",
        "null",
        "fingerprint",
        "binding",
        "clock",
        "related_closed",
    ] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let s = spec(&r);
        let BeginCapturedRun::Created(h) = store.begin_captured_run(&r, &s).unwrap() else {
            panic!("created")
        };
        let p = prepared(
            &s,
            "/private/state/context.json",
            "actor:registered",
            r.identity().run_ref.as_str(),
            &GitProfile::default(),
        );
        store.record_capture_prepared(h, &p).unwrap();
        let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        let body: String = sql
            .query_row("SELECT spec FROM capture_runs", [], |r| r.get(0))
            .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&body).unwrap();
        match case {
            "unknown" => {
                value["surprise"] = true.into();
            }
            "duplicate" => {
                let bad = body.replacen('{', "{\"operation\":\"duplicate\",", 1);
                sql.execute("UPDATE capture_runs SET spec=?1", [bad])
                    .unwrap();
            }
            "positional" => {
                value = serde_json::json!([]);
            }
            "nested_positional" => {
                value["sink"] = serde_json::json!([]);
            }
            "null" => {
                value["expected_git"]["author_name"] = serde_json::Value::Null;
            }
            "fingerprint" => {
                sql.execute("UPDATE capture_runs SET fingerprint=zeroblob(32)", [])
                    .unwrap();
            }
            "binding" => {
                sql.execute("UPDATE capture_runs SET prepared=json_set(prepared,'$.actor_ref','actor:other')",[]).unwrap();
            }
            "clock" => {
                sql.execute("UPDATE capture_runs SET intent_wall='not-a-time'", [])
                    .unwrap();
            }
            "related_closed" => {
                let b = binding(&r);
                store.record_bound(&r, &b).unwrap();
                let os = ClosureOs::new(&r, &b);
                let snap = store.group_snapshot(&r.identity().run).unwrap();
                let proof = snap.certify_empty(&os.driver, &b).unwrap();
                store.close_supervised_group(&snap, &proof).unwrap();
                // Recreate a newer normal root as a corruption fixture, then break the older capture.
                sql.execute("UPDATE checkouts SET state='active',ready=1", [])
                    .unwrap();
                let next = request(checkout);
                sql.execute("INSERT INTO run_groups(id,checkout,mode,revision) VALUES(?1,?2,'supervised',1)",(next.identity().group.to_string(),checkout.to_string())).unwrap();
                sql.execute("INSERT INTO runs(id,group_id,run_ref,request,stage) VALUES(?1,?2,?3,?4,'intent')",(next.identity().run.to_string(),next.identity().group.to_string(),next.identity().run_ref.as_str(),serde_json::to_string(&next).unwrap())).unwrap();
                sql.execute(
                    "INSERT INTO writers VALUES(?1,?2)",
                    (checkout.to_string(), next.identity().group.to_string()),
                )
                .unwrap();
                sql.execute("UPDATE capture_runs SET spec='{}'", [])
                    .unwrap();
                assert!(
                    store.begin_run(&next).is_err(),
                    "corrupt related closed root"
                );
                continue;
            }
            _ => unreachable!(),
        }
        if ["unknown", "positional", "nested_positional", "null"].contains(&case) {
            sql.execute("UPDATE capture_runs SET spec=?1", [value.to_string()])
                .unwrap();
        }
        assert!(store.begin_captured_run(&r, &s).is_err(), "{case}");
        assert!(store.capture_snapshot(&r.identity().run).is_err(), "{case}");
        assert!(store.begin_run(&r).is_err(), "{case}");
    }
}

#[test]
fn v9_upgrade_preserves_receipt_bytes_and_missing_v10_shapes_fail_closed() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let original: String = sql
        .query_row("SELECT request FROM runs", [], |r| r.get(0))
        .unwrap();
    let events = store.pending_events(100).unwrap();
    sql.execute_batch(
        "DROP TABLE capture_finalizations; DROP TABLE capture_requirements; DROP TABLE capture_runs; PRAGMA user_version=9",
    )
    .unwrap();
    drop(store);
    let store = reopen(&dir).unwrap();
    assert_eq!(store.pending_events(100).unwrap(), events);
    assert_eq!(
        sql.query_row("SELECT request FROM runs", [], |r| r.get::<_, String>(0))
            .unwrap(),
        original
    );
    assert_eq!(
        sql.query_row("SELECT count(*) FROM capture_runs", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    for corrupt in ["DROP INDEX capture_checkout", "ALTER TABLE capture_runs RENAME TO saved_capture; CREATE VIEW capture_runs AS SELECT * FROM saved_capture"] {
        sql.execute_batch(corrupt).unwrap();
        assert!(reopen(&dir).is_err(),"{corrupt}");
        if corrupt.starts_with("DROP INDEX") {sql.execute_batch("CREATE INDEX capture_checkout ON capture_runs(checkout)").unwrap();} else {sql.execute_batch("DROP VIEW capture_runs; ALTER TABLE saved_capture RENAME TO capture_runs").unwrap();}
    }
}

#[test]
fn same_capture_binding_cannot_be_rebound_or_use_reconciliation_to_reanimate_live_handle() {
    let (_dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let s = spec(&r);
    let BeginCapturedRun::Created(h) = store.begin_captured_run(&r, &s).unwrap() else {
        panic!("created")
    };
    let p = prepared(
        &s,
        "/private/state/context.json",
        "actor:registered",
        r.identity().run_ref.as_str(),
        &GitProfile::default(),
    );
    store.reconcile_capture_prepared(&r, &s, &p).unwrap();
    assert!(
        store.record_capture_prepared(h, &p).is_err(),
        "a retained live handle must lose authority after metadata reconciliation"
    );
}

#[test]
fn v9_capture_migration_failure_rolls_back_version_and_all_existing_rows() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch("DROP TABLE capture_finalizations; DROP TABLE capture_requirements; DROP TABLE capture_runs; PRAGMA user_version=9; CREATE VIEW capture_runs AS SELECT 1 AS obstruction").unwrap();
    let body: String = sql
        .query_row("SELECT request FROM runs", [], |r| r.get(0))
        .unwrap();
    let events = store.pending_events(100).unwrap();
    drop(store);
    assert!(reopen(&dir).is_err());
    assert_eq!(
        sql.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        9
    );
    assert_eq!(
        sql.query_row("SELECT request FROM runs", [], |r| r.get::<_, String>(0))
            .unwrap(),
        body
    );
    sql.execute_batch("DROP VIEW capture_runs").unwrap();
    let store = reopen(&dir).unwrap();
    assert_eq!(store.pending_events(100).unwrap(), events);
}

#[test]
fn backward_whole_group_clock_is_explicit_uncertainty_without_inventing_outcome() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let s = spec(&r);
    let BeginCapturedRun::Created(h) = store.begin_captured_run(&r, &s).unwrap() else {
        panic!("created")
    };
    let p = prepared(
        &s,
        "/private/state/context.json",
        "actor:registered",
        r.identity().run_ref.as_str(),
        &GitProfile::default(),
    );
    store.record_capture_prepared(h, &p).unwrap();
    let b = binding(&r);
    store.record_bound(&r, &b).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute("UPDATE capture_runs SET intent_wall='2999-01-01T00:00:00Z', prepared=json_set(prepared,'$.observed_wall','2999-01-01T00:00:01Z')",[]).unwrap();
    let os = ClosureOs::new(&r, &b);
    let snap = store.group_snapshot(&r.identity().run).unwrap();
    let proof = snap.certify_empty(&os.driver, &b).unwrap();
    store.close_supervised_group(&snap, &proof).unwrap();
    assert!(
        store
            .capture_snapshot(&r.identity().run)
            .unwrap()
            .unwrap()
            .group_end
            .unwrap()
            .clock_uncertain
    );
    assert!(store
        .run_snapshot(&r.identity().run)
        .unwrap()
        .unwrap()
        .outcome
        .is_none());
    assert!(store.begin_run(&request(checkout)).is_err());
}

#[test]
fn additional_declared_task_and_execution_arrays_survive_strict_targeted_reads() {
    let (_dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let mut d = declaration(&r);
    d.task_refs.push("task:secondary".into());
    let s = CaptureSpec::new(
        Uuid::now_v7(),
        SinkSnapshot::new(settings()).unwrap(),
        d,
        GitProfile::default(),
    )
    .unwrap();
    drop(store.begin_captured_run(&r, &s).unwrap());
    assert!(matches!(
        store.begin_captured_run(&r, &s).unwrap(),
        BeginCapturedRun::Existing(_)
    ));
    assert_eq!(s.begin_request().task_refs, vec!["task", "task:secondary"]);
}

fn child_request(r: &RootRunRequest, run: Uuid) -> work_cli::run_participants::ChildRequest {
    serde_json::from_value(serde_json::json!({"checkout":r.identity().checkout,"group":r.identity().group,"run":run,"run_ref":format!("child:{run}"),"parent_run":r.identity().run,"parent_run_ref":r.identity().run_ref,"execution_chain":r.identity().execution_chain,"source":null,"session":null,"agent":null,"actor":null,"expected_host":null})).unwrap()
}
fn adopted_request(r: &RootRunRequest) -> work_cli::adopted::AdoptedRequest {
    work_cli::adopted::AdoptedRequest {
        operation: Uuid::now_v7(),
        identity: r.identity().clone(),
        source: work_cli::participants::Ref::new("sdk".into()).unwrap(),
        session: work_cli::participants::Ref::new("session".into()).unwrap(),
        agent: None,
    }
}

#[test]
fn capture_operations_are_excluded_in_both_orders_across_all_work_namespaces() {
    for kind in [
        "checkout",
        "allocation",
        "bare",
        "root",
        "group",
        "adopted_operation",
        "adopted_run",
        "adopted_group",
        "child",
        "finish",
    ] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        let other = Uuid::now_v7();
        sql.execute("INSERT INTO checkouts SELECT ?1,?2,digest,repository,actor,task,owner,'active',1 FROM checkouts",(other.to_string(),Uuid::now_v7().to_string())).unwrap();
        let op = match kind {
            "checkout" => checkout,
            "allocation" => Uuid::parse_str(
                &sql.query_row(
                    "SELECT operation FROM checkouts WHERE id=?1",
                    [checkout.to_string()],
                    |r| r.get::<_, String>(0),
                )
                .unwrap(),
            )
            .unwrap(),
            "bare" => {
                let group = Uuid::now_v7();
                store.acquire_writer(checkout, group).unwrap();
                group
            }
            "root" | "group" => {
                store.begin_run(&r).unwrap();
                Uuid::parse_str(&if kind == "root" {
                    r.identity().run.to_string()
                } else {
                    r.identity().group.to_string()
                })
                .unwrap()
            }
            "adopted_operation" | "adopted_run" | "adopted_group" => {
                let a = adopted_request(&r);
                store.begin_adopted(&a).unwrap();
                if kind == "adopted_operation" {
                    a.operation
                } else {
                    Uuid::parse_str(&if kind == "adopted_run" {
                        a.identity.run.to_string()
                    } else {
                        a.identity.group.to_string()
                    })
                    .unwrap()
                }
            }
            "child" => {
                store.begin_run(&r).unwrap();
                let b = binding(&r);
                store.record_bound(&r, &b).unwrap();
                store.record_permit_attempt(&r, &b).unwrap();
                let child = child_request(&r, Uuid::now_v7());
                store.register_child(&r, &child).unwrap();
                Uuid::parse_str(&child.run.to_string()).unwrap()
            }
            _ => {
                let operation = Uuid::now_v7();
                sql.execute(
                    "INSERT INTO task_finishes VALUES(?1,?2,'malformed')",
                    (checkout.to_string(), operation.to_string()),
                )
                .unwrap();
                operation
            }
        };
        let target = request(other);
        let other_operation: String = sql
            .query_row(
                "SELECT operation FROM checkouts WHERE id=?1",
                [other.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        sql.execute("INSERT INTO allocations SELECT ?1,json_set(request,'$.operation',?2),json_set(record,'$.checkout',?1,'$.request.operation',?2) FROM allocations WHERE checkout=?3",(other.to_string(),other_operation,checkout.to_string())).unwrap();
        let s = CaptureSpec::new(
            op,
            SinkSnapshot::new(settings()).unwrap(),
            declaration(&target),
            GitProfile::default(),
        )
        .unwrap();
        let events = store.pending_events(100).unwrap();
        assert!(
            matches!(
                store.begin_captured_run(&target, &s),
                Err(work_cli::store::StoreError::Conflict)
            ),
            "existing {kind}"
        );
        assert_eq!(store.pending_events(100).unwrap(), events);
    }
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let s = spec(&r);
    let op = s.operation();
    let BeginCapturedRun::Created(h) = store.begin_captured_run(&r, &s).unwrap() else {
        panic!("created")
    };
    let p = prepared(
        &s,
        "/private/state/context.json",
        "actor:registered",
        r.identity().run_ref.as_str(),
        &GitProfile::default(),
    );
    store.record_capture_prepared(h, &p).unwrap();
    let b = binding(&r);
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    assert!(store.register_child(&r, &child_request(&r, op)).is_err());
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let other = Uuid::now_v7();
    sql.execute("INSERT INTO checkouts SELECT ?1,?2,digest,repository,actor,task,owner,'active',1 FROM checkouts",(other.to_string(),Uuid::now_v7().to_string())).unwrap();
    for field in ["operation", "run", "group"] {
        let mut a = adopted_request(&request(other));
        if field == "operation" {
            a.operation = op
        } else {
            a.identity = changed(&request(other), field, serde_json::json!(op))
                .identity()
                .clone();
        }
        assert!(store.begin_adopted(&a).is_err(), "capture first {field}");
    }
    let reservation = work_cli::admission::Reservation {
        operation: op,
        repository: dir.path().join("root"),
        actor: "allocator".into(),
        owner: "owner".into(),
        task: "task".into(),
    };
    let limits = work_cli::admission::Limits {
        repository: 10,
        owner: 10,
        available_bytes: Some(100),
        floor_bytes: 0,
        warn_bytes: 0,
    };
    assert!(store.reserve(&reservation, limits).is_err());
    sql.execute(
        "UPDATE checkouts SET operation=?1 WHERE id=?2",
        (op.to_string(), other.to_string()),
    )
    .unwrap();
    assert!(
        store.reserve(&reservation, limits).is_err(),
        "even exact immutable allocation overlap must refuse acknowledgement"
    );
}

#[test]
fn prepared_context_must_be_the_public_capture_id_locator_under_snapshotted_state() {
    let (_dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let s = spec(&r);
    let BeginCapturedRun::Created(h) = store.begin_captured_run(&r, &s).unwrap() else {
        panic!("created")
    };
    let p = prepared(
        &s,
        "/private/state/550e8400-e29b-41d4-a716-446655440001.context.json",
        "actor:registered",
        r.identity().run_ref.as_str(),
        &GitProfile::default(),
    );
    store
        .record_capture_prepared(h, &p)
        .expect("public per-capture context path");
}

#[test]
fn unresolved_capture_presence_fences_every_writer_even_after_corrupt_readiness_or_mapping() {
    for malformed in [false, true] {
        for api in ["legacy", "legacy_existing", "root", "adopted"] {
            let (dir, mut store, checkout) = fixture();
            let r = request(checkout);
            let s = spec(&r);
            let BeginCapturedRun::Created(h) = store.begin_captured_run(&r, &s).unwrap() else {
                panic!("created")
            };
            let p = prepared(
                &s,
                "/private/state/context.json",
                "actor:registered",
                r.identity().run_ref.as_str(),
                &GitProfile::default(),
            );
            store.record_capture_prepared(h, &p).unwrap();
            let b = binding(&r);
            store.record_bound(&r, &b).unwrap();
            let os = ClosureOs::new(&r, &b);
            let snap = store.group_snapshot(&r.identity().run).unwrap();
            let proof = snap.certify_empty(&os.driver, &b).unwrap();
            store.close_supervised_group(&snap, &proof).unwrap();
            let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
            sql.execute("UPDATE checkouts SET state='active',ready=1", [])
                .unwrap();
            if malformed {
                sql.execute("UPDATE capture_runs SET spec='malformed'", [])
                    .unwrap();
            }
            let group = Uuid::now_v7();
            if api == "legacy_existing" {
                sql.execute(
                    "INSERT INTO writers VALUES(?1,?2)",
                    (checkout.to_string(), group.to_string()),
                )
                .unwrap();
            }
            let rows = || {
                [
                    "checkouts",
                    "writers",
                    "runs",
                    "run_groups",
                    "capture_runs",
                    "outbox",
                    "task_finishes",
                ]
                .iter()
                .map(|name| {
                    let mut stmt = sql
                        .prepare(&format!("SELECT * FROM {name} ORDER BY rowid"))
                        .unwrap();
                    let n = stmt.column_count();
                    stmt.query_map([], |r| {
                        (0..n)
                            .map(|c| r.get::<_, rusqlite::types::Value>(c))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap()
                })
                .collect::<Vec<_>>()
            };
            let before = rows();
            let result = match api {
                "root" => store.begin_run(&request(checkout)).map(|_| ()),
                "adopted" => store
                    .begin_adopted(&adopted_request(&request(checkout)))
                    .map(|_| ()),
                _ => store.acquire_writer(checkout, group),
            };
            assert!(result.is_err(), "malformed={malformed} {api}");
            assert_eq!(rows(), before, "malformed={malformed} {api}");
        }
    }
}

#[test]
fn captured_declaration_requires_the_durable_allocation_primary_task_and_checkout_path() {
    for case in ["missing", "request_task", "record_task", "cwd", "stage"] {
        let (dir, mut store, checkout) = fixture();
        let r = request(checkout);
        let s = spec(&r);
        let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        match case {
            "missing" => {
                sql.execute("DELETE FROM allocations", []).unwrap();
            }
            "request_task" => {
                sql.execute(
                    "UPDATE allocations SET request=json_set(request,'$.task','other')",
                    [],
                )
                .unwrap();
            }
            "record_task" => {
                sql.execute(
                    "UPDATE allocations SET record=json_set(record,'$.request.task','other')",
                    [],
                )
                .unwrap();
            }
            "cwd" => {
                sql.execute(
                    "UPDATE allocations SET record=json_set(record,'$.destination','/other')",
                    [],
                )
                .unwrap();
            }
            _ => {
                sql.execute(
                    "UPDATE allocations SET record=json_set(record,'$.stage','held')",
                    [],
                )
                .unwrap();
            }
        }
        let events = store.pending_events(100).unwrap();
        assert!(store.begin_captured_run(&r, &s).is_err(), "{case}");
        assert_eq!(store.pending_events(100).unwrap(), events);
    }
}

#[test]
fn genuine_allocation_retries_and_preflight_never_revive_capture_pending_or_incomplete() {
    for state in ["preparing", "reconciled", "closed", "prepared"] {
        for api in ["exact", "matching", "verified_preflight"] {
            let f = support::Fixture::new();
            let output = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
            assert!(output.status.success());
            let a: work_cli::allocate::Allocation = serde_json::from_slice(&output.stdout).unwrap();
            let cfg = work_cli::config::Config::from_text(
                &std::fs::read_to_string(f.temp.path().join("config.toml")).unwrap(),
            )
            .unwrap();
            let mut store = f.store();
            let r = request(a.checkout);
            let mut d = declaration(&r);
            d.cwd = a.destination.clone();
            let s = CaptureSpec::new(
                Uuid::now_v7(),
                SinkSnapshot::new(settings()).unwrap(),
                d,
                GitProfile::default(),
            )
            .unwrap();
            let BeginCapturedRun::Created(h) = store.begin_captured_run(&r, &s).unwrap() else {
                panic!("created")
            };
            let p = prepared(
                &s,
                "/private/state/context.json",
                "actor:registered",
                r.identity().run_ref.as_str(),
                &GitProfile::default(),
            );
            match state {
                "preparing" => drop(h),
                "reconciled" => {
                    drop(h);
                    store.reconcile_capture_prepared(&r, &s, &p).unwrap();
                }
                _ => {
                    store.record_capture_prepared(h, &p).unwrap();
                    if state == "closed" {
                        let b = binding(&r);
                        store.record_bound(&r, &b).unwrap();
                        let os = ClosureOs::new(&r, &b);
                        let snap = store.group_snapshot(&r.identity().run).unwrap();
                        let proof = snap.certify_empty(&os.driver, &b).unwrap();
                        store.close_supervised_group(&snap, &proof).unwrap();
                    }
                }
            }
            support::git(
                &a.destination,
                &["commit", "--allow-empty", "-m", "advance"],
            );
            let sql = Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
            let before: String = sql
                .query_row("SELECT record FROM allocations", [], |r| r.get(0))
                .unwrap();
            let events = store.pending_events(100).unwrap();
            let result = match api {
                "verified_preflight" => {
                    work_cli::adopted::begin(&cfg, &adopted_request(&r)).map(|_| ())
                }
                _ => {
                    let mut req = a.request.clone();
                    if api == "matching" {
                        req.operation = Uuid::now_v7();
                    }
                    work_cli::allocate::start(&cfg, req).map(|_| ())
                }
            };
            let after: String = sql
                .query_row("SELECT record FROM allocations", [], |r| r.get(0))
                .unwrap();
            if state == "prepared" {
                assert_ne!(
                    before, after,
                    "own-root ready Prepared must retain identity refresh: {api}"
                );
                assert!(sql
                    .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
                    .unwrap());
            } else {
                assert!(result.is_err(), "{state} {api}");
                assert_eq!(before, after, "{state} {api}");
                assert_eq!(store.pending_events(100).unwrap(), events, "{state} {api}");
                assert!(!sql
                    .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
                    .unwrap());
            }
        }
    }
}

#[test]
fn reconciling_a_lost_preparation_commit_acknowledgement_never_leaves_resume_readiness() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    let s = spec(&r);
    let BeginCapturedRun::Created(h) = store.begin_captured_run(&r, &s).unwrap() else {
        panic!("created")
    };
    let p = prepared(
        &s,
        "/private/state/context.json",
        "actor:registered",
        r.identity().run_ref.as_str(),
        &GitProfile::default(),
    );
    store.record_capture_prepared(h, &p).unwrap();
    let observed = serde_json::to_string(
        &store
            .capture_snapshot(&r.identity().run)
            .unwrap()
            .unwrap()
            .prepared,
    )
    .unwrap();
    drop(store);
    let mut store = reopen(&dir).unwrap();
    assert!(matches!(
        store.begin_captured_run(&r, &s).unwrap(),
        BeginCapturedRun::Existing(_)
    ));
    store.reconcile_capture_prepared(&r, &s, &p).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let state: (String, bool) = sql
        .query_row("SELECT state,ready FROM checkouts", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(state, ("held".into(), false));
    assert!(
        store
            .run_snapshot(&r.identity().run)
            .unwrap()
            .unwrap()
            .recovery_hold
    );
    assert_eq!(
        serde_json::to_string(
            &store
                .capture_snapshot(&r.identity().run)
                .unwrap()
                .unwrap()
                .prepared
        )
        .unwrap(),
        observed,
        "original local preparation observation remains immutable"
    );
    let events = store.pending_events(100).unwrap();
    store.reconcile_capture_prepared(&r, &s, &p).unwrap();
    assert_eq!(store.pending_events(100).unwrap(), events);
}

#[test]
fn schema_ten_adds_empty_capture_journal_without_rewriting_no_sink_history() {
    let (dir, mut store, checkout) = fixture();
    let r = request(checkout);
    store.begin_run(&r).unwrap();
    let events = store.pending_events(100).unwrap();
    let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let original: String = sql
        .query_row("SELECT request FROM runs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        sql.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        12
    );
    assert_eq!(
        sql.query_row("SELECT count(*) FROM capture_runs", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(store.pending_events(100).unwrap(), events);
    assert_eq!(
        sql.query_row("SELECT request FROM runs", [], |r| r.get::<_, String>(0))
            .unwrap(),
        original
    );
}
