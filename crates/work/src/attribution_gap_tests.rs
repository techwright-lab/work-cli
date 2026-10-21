use crate::{store::Store, test_run_fixture};
use rusqlite::Connection;
use sha2::Digest;

use crate::test_lifecycle_fixture as physical_fixture;

fn ordinary() -> (
    tempfile::TempDir,
    crate::config::Config,
    crate::allocate::Allocation,
    crate::run_journal::RootRunRequest,
    Vec<std::ffi::OsString>,
) {
    materialized(false)
}
fn materialized(
    required: bool,
) -> (
    tempfile::TempDir,
    crate::config::Config,
    crate::allocate::Allocation,
    crate::run_journal::RootRunRequest,
    Vec<std::ffi::OsString>,
) {
    materialized_mode(required, false)
}
fn materialized_mode(
    required: bool,
    execution: bool,
) -> (
    tempfile::TempDir,
    crate::config::Config,
    crate::allocate::Allocation,
    crate::run_journal::RootRunRequest,
    Vec<std::ffi::OsString>,
) {
    use std::os::unix::fs::PermissionsExt;
    let (temp, repo, root) = physical_fixture::git_fixture();
    // New fixture policy is chosen before Config construction and immutable admission.
    let runtime = if execution {
        temp.path().join("runtime")
    } else {
        "/private/runtime".into()
    };
    let preexec = if execution { 5000 } else { 100 };
    let grace = if execution { 500 } else { 100 };
    let bus_address = format!("unix:path={}/bus", runtime.display());
    let registry = temp.path().join("registry.json");
    let registry_bytes = br#"{"ingest":{"key_env":"ACTUAL_RECEIVER_TOKEN"}}"#;
    std::fs::write(&registry, registry_bytes).unwrap();
    std::fs::set_permissions(&registry, std::fs::Permissions::from_mode(0o600)).unwrap();
    let selection = if required {
        "capture_sink='devdiary'\n"
    } else {
        ""
    };
    let host = if required {
        format!("\n[capture]\nexecutable='/unavailable/producer'\nregistry={registry:?}\nstate_dir='/unavailable/state'\ntimeout_ms=50\nresponse_cap=65536\nregistry_sha256='{:x}'\nendpoint_identity='receiver:gap-fixture'\nreceiver_credential_names=['DECLARED_RECEIVER_TOKEN']\n[capture.actor_refs]\nalice='actor:alice'\n", sha2::Sha256::digest(registry_bytes))
    } else {
        String::new()
    };
    let config = crate::config::Config::from_text(&format!(
        "store_dir={:?}\ntrusted_registry={:?}\nroots=[{:?}]\nrepositories=[{:?}]\n[allocation]\nrepository_limit=10\nowner_limit=10\nfloor_bytes=0\nwarn_bytes=0\n{selection}[supervisor]\nruntime_directory={runtime:?}\nbus_address={bus_address:?}\nruntime_max_seconds=60\npreexec_ms={preexec}\nclosure_grace_ms={grace}\ncancel_grace_ms={grace}\n[supervisor.actors.alice]\nauthor_name='Alice'\nauthor_email='alice@example.invalid'\ncommitter_name='Alice'\ncommitter_email='alice@example.invalid'\n{host}",
        temp.path().join("private"), temp.path().join(".work-authorities"), root, repo,
    )).unwrap();
    let allocation = crate::allocate::start(
        &config,
        crate::allocate::Start {
            operation: uuid::Uuid::now_v7(),
            repository: Some(repo),
            root: Some(root),
            actor: Some("alice".into()),
            owner: None,
            task: "task".into(),
            branch: Some("topic".into()),
            base: "main".into(),
            reuse_branch: false,
        },
    )
    .unwrap();
    assert_eq!(
        allocation.stage,
        if required { "capture_pending" } else { "ready" }
    );
    let argv = vec![std::ffi::OsString::from("/usr/bin/true")];
    let mut request = serde_json::to_value(test_run_fixture::request(allocation.checkout)).unwrap();
    request["identity"]["actor"] = "alice".into();
    request["input"]["attribution"] = "off".into();
    request["input"]["boot"] = allocation.identity.as_ref().unwrap().boot_id.clone().into();
    request["input"]["command_digest"] =
        serde_json::to_value(crate::supervisor::command_digest(&argv).unwrap()).unwrap();
    (
        temp,
        config,
        allocation,
        serde_json::from_value(request).unwrap(),
        argv,
    )
}

// Public capture declarations/codecs only. Injection below is deliberately
// contradictory persisted history, never a preparation or execution capability.
fn mixed_history_spec(
    temp: &std::path::Path,
    config: &crate::config::Config,
    allocation: &crate::allocate::Allocation,
    root: &crate::run_journal::RootRunRequest,
) -> crate::capture_journal::CaptureSpec {
    let operation = uuid::Uuid::now_v7();
    let sink = crate::capture_journal::SinkSnapshot::new(crate::capture_journal::SinkSettings {
        executable: temp.join("negative-producer"),
        registry: temp.join("registry.json"),
        state: temp.join("negative-state"),
        timeout: std::time::Duration::from_millis(50),
        response_cap: 65536,
        endpoint_identity: "receiver:mixed-history-fixture".into(),
        registry_identity: "fixture-registry".into(),
        receiver_credential_names: vec!["ACTUAL_RECEIVER_TOKEN".into()],
        registry_actor_ref: "actor:alice".into(),
    })
    .unwrap();
    crate::capture_journal::CaptureSpec::new(
        operation,
        sink,
        crate::capture_bridge::BeginRequest {
            actor_ref: "actor:alice".into(),
            run_ref: root.identity().run_ref.as_str().into(),
            cwd: allocation.destination.clone(),
            execution_chain: root.identity().execution_chain.clone(),
            task_refs: vec![allocation.request.task.clone()],
            parent_run_ref: root
                .identity()
                .parent_run_ref
                .as_ref()
                .map(|r| r.as_str().into()),
            key_file: None,
            source: None,
            lifecycle: crate::capture_bridge::WorkLifecycle {
                checkout_id: root.identity().checkout.clone(),
                mode: work_contract::ExecutionMode::Supervised,
                group_id: Some(root.identity().group.clone()),
                operation_id: Some(
                    work_contract::AllocationOperationId::parse(&operation.to_string()).unwrap(),
                ),
            },
        },
        config.supervisor.as_ref().unwrap().actors["alice"].capture_profile(),
    )
    .unwrap()
}
fn inject_unprepared_capture(
    store: &Store,
    root: &crate::run_journal::RootRunRequest,
    spec: &crate::capture_journal::CaptureSpec,
) {
    let body = serde_json::to_string(spec).unwrap();
    store.conn.execute("INSERT INTO capture_runs(run,group_id,checkout,operation,spec,fingerprint,intent_wall,preparation_revision) VALUES(?1,?2,?3,?4,?5,?6,'2026-10-21T00:00:00Z',1)",
        rusqlite::params![root.identity().run.to_string(), root.identity().group.to_string(), root.identity().checkout.to_string(), spec.operation().to_string(), body, sha2::Sha256::digest(body.as_bytes()).as_slice()]).unwrap();
}

#[test]
fn historical_gap_capture_coexistence_refuses_before_receiver() {
    let mut violations = Vec::new();
    for case in [
        "mapping",
        "bad_mapping",
        "certificate_only",
        "bad_gap",
        "off_without_gap",
    ] {
        let (temp, config, allocation, root, argv) = materialized(true);
        let (store, created) = super::begin(&config, &root, &argv).unwrap();
        assert!(matches!(created, super::BeginGap::Created(_)));
        let gap_root = store.run_snapshot(&root.identity().run).unwrap().unwrap();
        assert!(gap_root.binding.is_none() && !gap_root.closed);
        assert!(store
            .capture_snapshot(&root.identity().run)
            .unwrap()
            .is_none());
        assert!(crate::capture_journal::qualified(&store.conn, &gap_root)
            .unwrap()
            .is_none());
        assert!(crate::capture_journal::with_qualification_batch(
            &store.conn,
            allocation.checkout,
            |batch| batch.terminal(&gap_root)
        )
        .unwrap()
        .is_none());

        // A genuine captured sibling in the SAME authority is the isolation
        // control; no receiver call or prepared response is needed to create it.
        let mut start = allocation.request.clone();
        start.operation = uuid::Uuid::now_v7();
        start.task = "capture-control".into();
        start.branch = Some("capture-control".into());
        let sibling = crate::allocate::start(&config, start).unwrap();
        let mut identity = root.identity().clone();
        identity.checkout =
            work_contract::CheckoutId::parse(&sibling.checkout.to_string()).unwrap();
        identity.run = work_contract::RunId::generate();
        identity.group = work_contract::GroupId::generate();
        identity.run_ref = work_contract::RunRef::parse("capture-control").unwrap();
        let mut input = root.input().clone();
        input.attribution = None;
        let sibling_root = crate::run_journal::RootRunRequest::new(identity, input).unwrap();
        let sibling_spec = config
            .capture_spec(
                &sibling_root,
                &sibling,
                uuid::Uuid::now_v7(),
                vec!["capture-control".into()],
                None,
            )
            .unwrap();
        let (_, capture) =
            crate::capture_setup::begin(&config, &sibling_root, &sibling_spec).unwrap();
        assert!(matches!(
            capture,
            crate::capture_journal::BeginCapturedRun::Created(_)
        ));
        let sibling_record = store
            .run_snapshot(&sibling_root.identity().run)
            .unwrap()
            .unwrap();

        let spec = mixed_history_spec(temp.path(), &config, &allocation, &root);
        // Validate all public wire fields before introducing the contradiction.
        spec.begin_request().encode().unwrap();
        spec.expected_git().validate().unwrap();
        executable(&temp.path().join("negative-producer"), format!("#!/bin/sh\nprintf 'begin\\n' >> '{}'\n/usr/bin/cat >/dev/null\nprintf '{{\"error\":\"fixture_refusal\"}}\\n'\nexit 1\n", temp.path().join("producer-calls").display()));
        if case == "certificate_only" {
            // Certificate presence alone is a raw contradiction, even with an
            // invalid payload/missing mapping. Do not mint a fake certificate.
            store.conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            store
                .conn
                .execute(
                    "INSERT INTO capture_readiness VALUES(?1,?2,'{',0)",
                    (
                        allocation.checkout.to_string(),
                        root.identity().run.to_string(),
                    ),
                )
                .unwrap();
            store.conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        } else {
            inject_unprepared_capture(&store, &root, &spec);
            if case == "bad_mapping" {
                store
                    .conn
                    .execute(
                        "UPDATE capture_runs SET spec='{' WHERE run=?1",
                        [root.identity().run.to_string()],
                    )
                    .unwrap();
            } else if case == "bad_gap" {
                store
                    .conn
                    .execute("UPDATE attribution_gaps SET record='{'", [])
                    .unwrap();
            } else if case == "off_without_gap" {
                store
                    .conn
                    .execute("DELETE FROM attribution_gaps", [])
                    .unwrap();
            }
        }
        let before = durable_rows(&store);
        let checks = [
            (
                "Gap record",
                super::read_record(&store.conn, &root).is_err(),
            ),
            (
                "public Root",
                store.run_snapshot(&root.identity().run).is_err(),
            ),
            (
                "public capture",
                store.capture_snapshot(&root.identity().run).is_err(),
            ),
            (
                "direct capture read",
                crate::capture_journal::read(&store.conn, &gap_root).is_err(),
            ),
            (
                "direct capture qualified",
                crate::capture_journal::qualified(&store.conn, &gap_root).is_err(),
            ),
            (
                "direct terminal",
                crate::capture_journal::qualified_terminal(&store.conn, &gap_root).is_err(),
            ),
            (
                "batch terminal",
                crate::capture_journal::with_qualification_batch(
                    &store.conn,
                    allocation.checkout,
                    |batch| batch.terminal(&gap_root),
                )
                .is_err(),
            ),
            (
                "capture status",
                crate::capture_cli::command(
                    &config,
                    crate::capture_cli::Command::Status {
                        run: root.identity().run.clone(),
                    },
                )
                .is_err(),
            ),
            (
                "reconcile-begin command",
                crate::capture_cli::command(
                    &config,
                    crate::capture_cli::Command::ReconcileBegin {
                        run: root.identity().run.clone(),
                    },
                )
                .is_err(),
            ),
            (
                "direct reconcile",
                crate::capture_recovery::reconcile(&config, &root.identity().run).is_err(),
            ),
            ("Existing Gap", super::begin(&config, &root, &argv).is_err()),
        ];
        for (route, refused) in checks {
            if !refused {
                violations.push(format!("{case}: {route} accepted contradiction"));
            }
        }
        let calls = std::fs::read_to_string(temp.path().join("producer-calls"))
            .unwrap_or_default()
            .lines()
            .count();
        if calls != 0 {
            violations.push(format!("{case}: producer BEGIN calls={calls}"));
        }
        assert_eq!(
            durable_rows(&store),
            before,
            "{case}: refusal changed durable authority"
        );
        assert!(
            store
                .run_snapshot(&sibling_root.identity().run)
                .unwrap()
                .is_some(),
            "{case}: unrelated Root poisoned"
        );
        assert!(
            store
                .capture_snapshot(&sibling_root.identity().run)
                .unwrap()
                .is_some(),
            "{case}: unrelated capture poisoned"
        );
        assert!(
            crate::capture_journal::qualified(&store.conn, &sibling_record)
                .unwrap()
                .is_some()
        );
        assert!(crate::capture_journal::with_qualification_batch(
            &store.conn,
            sibling.checkout,
            |batch| batch.terminal(&sibling_record)
        )
        .unwrap()
        .is_some());
    }
    // A default Root on a checkout with OTHER Gap history must not hide the raw
    // checkout fence, even when that unrelated-to-the-root Gap payload is bad.
    for bad_gap in [false, true] {
        let h = ScopeHarness::new(false);
        let closed = crate::supervisor::supervise_off(
            &h.config,
            h.command.clone(),
            &h.driver,
            Some(h.io()),
            &crate::supervisor::CancelToken::default(),
            |boundary, root| {
                if boundary == crate::supervisor::Boundary::RootTerminal {
                    h.empty(root);
                }
            },
        )
        .unwrap();
        assert!(closed.record.closed);
        let (mut store, lock) = crate::allocate::locked(&h.config).unwrap();
        drop(lock);
        let next = test_run_fixture::request(h.allocation.checkout);
        store.begin_run(&next).unwrap();
        let default_root = store.run_snapshot(&next.identity().run).unwrap().unwrap();
        let spec = mixed_history_spec(h.temp.path(), &h.config, &h.allocation, &next);
        inject_unprepared_capture(&store, &next, &spec);
        if bad_gap {
            store
                .conn
                .execute("UPDATE attribution_gaps SET record='{'", [])
                .unwrap();
        }
        let before = durable_rows(&store);
        for (route, refused) in [
            (
                "default direct",
                crate::capture_journal::qualified(&store.conn, &default_root).is_err(),
            ),
            (
                "default batch",
                crate::capture_journal::with_qualification_batch(
                    &store.conn,
                    h.allocation.checkout,
                    |batch| batch.terminal(&default_root),
                )
                .is_err(),
            ),
            (
                "default public",
                store.run_snapshot(&next.identity().run).is_err(),
            ),
        ] {
            if !refused {
                violations.push(format!(
                    "other Gap bad={bad_gap}: {route} accepted contradiction"
                ));
            }
        }
        assert_eq!(durable_rows(&store), before);
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[test]
fn ordinary_off_continuation_accepts_verified_descendant_heads() {
    for prior_ordinary in [false, true] {
        let mut h = ScopeHarness::new(false);
        if prior_ordinary {
            let ordinary = crate::supervisor::supervise_with_io(
                &h.config,
                h.command.clone(),
                &h.driver,
                h.io(),
                &crate::supervisor::CancelToken::default(),
                |boundary, root| {
                    if boundary == crate::supervisor::Boundary::RootTerminal {
                        h.empty(root);
                    }
                },
            )
            .unwrap();
            assert!(ordinary.record.closed);
            h.command.run_id = uuid::Uuid::now_v7();
        }
        let closed = crate::supervisor::supervise_off(
            &h.config,
            h.command.clone(),
            &h.driver,
            Some(h.io()),
            &crate::supervisor::CancelToken::default(),
            |boundary, root| {
                if boundary == crate::supervisor::Boundary::RootTerminal {
                    h.empty(root);
                }
            },
        )
        .unwrap();
        assert!(closed.record.closed);
        let (store, lock) = crate::allocate::locked(&h.config).unwrap();
        drop(lock);
        let old = &closed.record.request;
        let gap_bytes: String = store
            .conn
            .query_row(
                "SELECT record FROM attribution_gaps WHERE run=?1",
                [old.identity().run.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        let allocation_bytes: String = store
            .conn
            .query_row("SELECT record FROM allocations", [], |r| r.get(0))
            .unwrap();
        let marker_path = h
            .allocation
            .identity
            .as_ref()
            .unwrap()
            .private_git_dir
            .join("work-lease.json");
        let marker = std::fs::read(&marker_path).unwrap();
        // Real committed descendant BEFORE admission. No Work refresh/load path
        // or rewritten allocation HEAD may disguise this valid stale snapshot.
        crate::identity::query(
            &h.allocation.destination,
            &["commit", "--allow-empty", "-m", "legitimate descendant"],
        )
        .unwrap();
        let current = crate::recovery::verify(&h.allocation).unwrap();
        assert_ne!(current.head, h.allocation.identity.as_ref().unwrap().head);
        let mut identity = old.identity().clone();
        identity.run = work_contract::RunId::generate();
        identity.group = work_contract::GroupId::generate();
        identity.run_ref = work_contract::RunRef::parse("next-off-descendant").unwrap();
        let next = crate::run_journal::RootRunRequest::new(identity, old.input().clone()).unwrap();
        let (_, admitted) = super::begin(&h.config, &next, &h.command.argv).expect(
            "closed ordinary Gap history must admit a verified preexisting descendant HEAD",
        );
        let super::BeginGap::Created(live) = admitted else {
            panic!("new root must carry private authority")
        };
        assert_eq!(live.proof.physical.checkout, current);
        assert_eq!(live.record.delivery, super::GapDelivery::NotConfigured);
        live.release_proof()
            .expect("release must reverify the same descendant, not stale allocation equality");
        assert_eq!(std::fs::read(marker_path).unwrap(), marker);
        assert_eq!(
            store
                .conn
                .query_row("SELECT record FROM allocations", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            allocation_bytes
        );
        assert_eq!(
            store
                .conn
                .query_row(
                    "SELECT record FROM attribution_gaps WHERE run=?1",
                    [old.identity().run.to_string()],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            gap_bytes
        );
        assert_eq!(
            store.run_snapshot(&old.identity().run).unwrap().unwrap(),
            closed.record
        );
        assert_eq!(
            store
                .charged(h.allocation.request.repository.as_ref().unwrap(), None)
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM capture_runs", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        // New private release proof still fences drift after successful admission.
        crate::identity::query(
            &h.allocation.destination,
            &["commit", "--allow-empty", "-m", "after admission"],
        )
        .unwrap();
        assert!(live.release_proof().is_err());
    }
    for case in [
        "pending_head",
        "non_descendant",
        "rewind",
        "directory",
        "branch",
        "marker",
        "root_boot",
        "during_reinspection",
    ] {
        let (_temp, config, mut allocation, mut root, argv) = materialized(case == "pending_head");
        if case == "rewind" {
            // Allocate a NEW disposable checkout at a commit with a real parent;
            // rewind below its stored head without rewriting any lease evidence.
            let repository = allocation.request.repository.as_ref().unwrap();
            crate::identity::query(
                repository,
                &["commit", "--allow-empty", "-m", "new allocation base"],
            )
            .unwrap();
            let mut start = allocation.request.clone();
            start.operation = uuid::Uuid::now_v7();
            start.task = "rewind-control".into();
            start.branch = Some("rewind-control".into());
            allocation = crate::allocate::start(&config, start).unwrap();
            let mut identity = root.identity().clone();
            identity.checkout =
                work_contract::CheckoutId::parse(&allocation.checkout.to_string()).unwrap();
            root = crate::run_journal::RootRunRequest::new(identity, root.input().clone()).unwrap();
            let parent =
                crate::identity::query(&allocation.destination, &["rev-parse", "HEAD^"]).unwrap();
            crate::identity::query(&allocation.destination, &["update-ref", "HEAD", &parent])
                .unwrap();
        } else if case == "non_descendant" {
            let tree =
                crate::identity::query(&allocation.destination, &["rev-parse", "HEAD^{tree}"])
                    .unwrap();
            let unrelated = crate::identity::query(
                &allocation.destination,
                &["commit-tree", &tree, "-m", "unrelated root"],
            )
            .unwrap();
            crate::identity::query(&allocation.destination, &["update-ref", "HEAD", &unrelated])
                .unwrap();
        } else {
            crate::identity::query(
                &allocation.destination,
                &["commit", "--allow-empty", "-m", "preexisting descendant"],
            )
            .unwrap();
            match case {
                "directory" => physical_fixture::replace_directory(&allocation.destination),
                "branch" => {
                    crate::identity::query(
                        &allocation.destination,
                        &["symbolic-ref", "HEAD", "refs/heads/main"],
                    )
                    .unwrap();
                }
                "marker" => std::fs::write(
                    allocation
                        .identity
                        .as_ref()
                        .unwrap()
                        .private_git_dir
                        .join("work-lease.json"),
                    "{}",
                )
                .unwrap(),
                "root_boot" => {
                    let mut input = root.input().clone();
                    input.boot = test_run_fixture::BOOT.into();
                    assert_ne!(input.boot, allocation.identity.as_ref().unwrap().boot_id);
                    root = crate::run_journal::RootRunRequest::new(root.identity().clone(), input)
                        .unwrap();
                }
                _ => (),
            }
        }
        let reinspections = std::rc::Rc::new(std::cell::Cell::new(0));
        let count = reinspections.clone();
        let path = allocation.destination.clone();
        let _observer = observing_admission(move |stage, _| {
            if stage == "reinspect" && case == "during_reinspection" {
                count.set(count.get() + 1);
                crate::identity::query(
                    &path,
                    &["commit", "--allow-empty", "-m", "concurrent descendant"],
                )
                .unwrap();
            }
        });
        let (store, lock) = crate::allocate::locked(&config).unwrap();
        drop(lock);
        let before = durable_rows(&store);
        assert!(
            super::begin(&config, &root, &argv).is_err(),
            "{case} must refuse"
        );
        assert_eq!(durable_rows(&store), before, "{case} changed authority");
        if case == "during_reinspection" {
            assert_eq!(reinspections.get(), 1);
        }
    }
}

#[test]
fn atomic_queue_creation_and_existing_are_not_live() {
    {
        let (_temp, config, _a, root, argv) = ordinary();
        let mut identity = root.identity().clone();
        identity.parent_run_ref =
            Some(work_contract::RunRef::parse(&"p".repeat(super::MAX_RECORD + 1)).unwrap());
        let root = crate::run_journal::RootRunRequest::new(identity, root.input().clone()).unwrap();
        let expected = serde_json::to_vec(&root).unwrap();
        assert!(expected.len() > super::MAX_RECORD);
        let (store, result) = super::begin(&config, &root, &argv)
            .expect("Gap digest must retain the legacy Root aggregate domain");
        let super::BeginGap::Created(live) = result else {
            panic!("Created expected")
        };
        assert_eq!(
            live.record.request_digest,
            <[u8; 32]>::from(sha2::Sha256::digest(&expected))
        );
        assert_eq!(
            store
                .run_snapshot(&root.identity().run)
                .unwrap()
                .unwrap()
                .request,
            root
        );
        let bytes: String = store
            .conn
            .query_row("SELECT record FROM attribution_gaps", [], |r| r.get(0))
            .unwrap();
        assert!(bytes.len() <= super::MAX_RECORD);
    }
    {
        let (_temp, config, _a, root, argv) = ordinary();
        let mut competing_identity = root.identity().clone();
        competing_identity.group =
            work_contract::GroupId::parse(&uuid::Uuid::now_v7().to_string()).unwrap();
        let competing =
            crate::run_journal::RootRunRequest::new(competing_identity, root.input().clone())
                .unwrap();
        let competing_config = config.clone();
        let competing_argv = argv.clone();
        let winner = std::rc::Rc::new(std::cell::RefCell::new(None));
        let observed = winner.clone();
        let _observer = observing_admission(move |stage, _| {
            if stage != "reinspect" {
                return;
            }
            let cfg = competing_config.clone();
            let request = competing.clone();
            let argv = competing_argv.clone();
            let event = std::thread::spawn(move || {
                let (_store, result) = super::begin(&cfg, &request, &argv).unwrap();
                let super::BeginGap::Created(live) = result else {
                    panic!("competing first commit expected")
                };
                live.record.event_id
            })
            .join()
            .unwrap();
            *observed.borrow_mut() = Some(event);
        });
        let (store, result) = super::begin(&config, &root, &argv).expect(
            "independently generated group must acknowledge matching committed immutable intent",
        );
        let super::BeginGap::Existing(record) = result else {
            panic!("losing candidate cannot become live")
        };
        assert_eq!(Some(record.event_id.clone()), *winner.borrow());
        let before = durable_rows(&store);
        let (_store, replay) = super::begin(&config, &root, &argv).unwrap();
        assert!(matches!(replay,super::BeginGap::Existing(ref old) if old==&record));
        assert_eq!(durable_rows(&store), before);
    }
    let (temp, config, allocation, root, argv) = ordinary();
    let (mut ordinary_store, lock) = crate::allocate::locked(&config).unwrap();
    drop(lock);
    assert!(
        ordinary_store.begin_run(&root).is_err(),
        "a declaration must not enter the ordinary writer path"
    );
    drop(ordinary_store);
    let before = physical_fixture::files(temp.path());
    let (store, result) = super::begin(&config, &root, &argv)
        .expect("genuine ready unconfigured allocation must create an atomic Gap intent");
    let super::BeginGap::Created(live) = result else {
        panic!("first creation must be Created")
    };
    assert_eq!(live.root, root);
    assert_eq!(live.argv, argv);
    assert_eq!(live.nonce.get_version_num(), 7);
    assert_eq!(
        live.git,
        config.supervisor.as_ref().unwrap().actors["alice"]
    );
    assert_eq!(
        live.record.request_digest,
        <[u8; 32]>::from(sha2::Sha256::digest(serde_json::to_vec(&root).unwrap()))
    );
    assert_eq!(
        live.proof.physical.checkout,
        *allocation.identity.as_ref().unwrap()
    );
    for table in ["runs", "run_groups", "writers", "attribution_gaps"] {
        let count: i64 = store
            .conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "{table}");
    }
    let captures: i64 = store
        .conn
        .query_row("SELECT count(*) FROM capture_runs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(captures, 0);
    let (event, record): (String, String) = store
        .conn
        .query_row("SELECT event_id,record FROM attribution_gaps", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&record).unwrap();
    assert_eq!(value["delivery"], "not_configured");
    assert_eq!(value["reason"], "operator_attribution_off");
    assert_eq!(value["destination"], serde_json::Value::Null);
    assert_ne!(physical_fixture::files(temp.path()), before);
    let notices: i64 = store.conn.query_row("SELECT count(*) FROM outbox WHERE json_extract(payload,'$.type')='attribution_gap_recorded'", [], |r| r.get(0)).unwrap();
    assert_eq!(notices, 1);
    let events = store.pending_events(100).unwrap();
    drop(store);
    let (store, replay) = super::begin(&config, &root, &argv).unwrap();
    let super::BeginGap::Existing(existing) = replay else {
        panic!("retry must be metadata only")
    };
    assert_eq!(existing.event_id, event);
    let after: (String, String) = store
        .conn
        .query_row("SELECT event_id,record FROM attribution_gaps", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(after, (event, record));
    assert_eq!(store.pending_events(100).unwrap(), events);
    assert_eq!(
        store
            .charged(allocation.request.repository.as_ref().unwrap(), None)
            .unwrap(),
        1
    );

    let (_temp, config, _allocation, root, argv) = ordinary();
    let (store, lock) = crate::allocate::locked(&config).unwrap();
    drop(lock);
    store.conn.execute_batch("CREATE TRIGGER refuse_gap BEFORE INSERT ON attribution_gaps BEGIN SELECT RAISE(ABORT,'fixture rollback'); END;").unwrap();
    assert!(super::begin(&config, &root, &argv).is_err());
    for table in ["runs", "run_groups", "writers", "attribution_gaps"] {
        let count: i64 = store
            .conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "failed insert must roll back {table}");
    }
    store.conn.execute_batch("DROP TRIGGER refuse_gap").unwrap();
    ACK_LOSS.with(|slot| slot.set(true));
    assert!(
        super::begin(&config, &root, &argv).is_err(),
        "a lost acknowledgement must return no live handle"
    );
    assert!(matches!(
        super::begin(&config, &root, &argv).unwrap().1,
        super::BeginGap::Existing(_)
    ));
}

type AdmissionObserver = Box<dyn FnMut(&str, &Connection)>;
thread_local! {
    static ACK_LOSS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static ADMISSION_OBSERVER: std::cell::RefCell<Option<AdmissionObserver>> = const { std::cell::RefCell::new(None) };
    static RELEASE_OBSERVER: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}
pub(super) fn observe_release() {
    RELEASE_OBSERVER.with(|slot| {
        if let Some(observer) = slot.borrow_mut().as_mut() {
            observer();
        }
    });
}
struct ReleaseObserverGuard;
impl Drop for ReleaseObserverGuard {
    fn drop(&mut self) {
        RELEASE_OBSERVER.with(|slot| *slot.borrow_mut() = None);
    }
}
pub(super) fn observe_admission(stage: &str, conn: &Connection) {
    ADMISSION_OBSERVER.with(|slot| {
        if let Some(observer) = slot.borrow_mut().as_mut() {
            observer(stage, conn);
        }
    });
}
struct AdmissionObserverGuard;
impl Drop for AdmissionObserverGuard {
    fn drop(&mut self) {
        ADMISSION_OBSERVER.with(|slot| *slot.borrow_mut() = None);
    }
}
fn observing_admission(
    observer: impl FnMut(&str, &Connection) + 'static,
) -> AdmissionObserverGuard {
    ADMISSION_OBSERVER.with(|slot| *slot.borrow_mut() = Some(Box::new(observer)));
    AdmissionObserverGuard
}
pub(super) fn take_ack_loss() -> bool {
    ACK_LOSS.with(|slot| slot.replace(false))
}

fn durable_rows(store: &Store) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    [
        "checkouts",
        "allocations",
        "writers",
        "run_groups",
        "runs",
        "run_participants",
        "adopted_groups",
        "attribution_gaps",
        "capture_requirements",
        "capture_runs",
        "capture_finalizations",
        "capture_readiness",
        "task_finishes",
        "outbox",
    ]
    .into_iter()
    .map(|table| {
        let mut stmt = store
            .conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let columns = stmt.column_count();
        stmt.query_map([], |r| (0..columns).map(|i| r.get(i)).collect())
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    })
    .collect()
}

use crate::test_capture_collector as capture_collector;
#[test]
fn fixture_child() {
    use std::os::unix::ffi::OsStringExt;
    if std::env::var_os("GAP_ENV_FIXTURE").is_some()
        && std::env::var_os("GAP_SCOPE_CONTEXT").is_none()
    {
        isolated_environment();
        return;
    }
    if let Some(channel) = std::env::var_os("GAP_CLI_ARGUMENTS") {
        let bytes =
            crate::identity::read_metadata(std::path::Path::new(&channel), 1024 * 1024).unwrap();
        let args: Vec<String> = serde_json::from_slice(&bytes).unwrap();
        if args
            .first()
            .is_some_and(|arg| arg == "fixture-document-snapshot")
        {
            let document = crate::config::ConfigDocument::load().unwrap();
            let authority = document.authority().unwrap();
            let runtime = document.recovery_runtime().unwrap();
            let host = document.recovery_target().unwrap().unwrap();
            let registry =
                crate::capture_artifacts::Registry::qualify(&host.registry, &host.registry_sha256)
                    .unwrap();
            std::fs::write(std::env::var_os("WORK_CONFIG").unwrap(), "invalid TOML = [").unwrap();
            assert!(crate::config::Config::load().is_err());
            assert_eq!(document.authority().unwrap(), authority);
            assert_eq!(
                document.recovery_runtime().unwrap().runtime_directory,
                runtime.runtime_directory
            );
            assert_eq!(document.recovery_target().unwrap().as_ref(), Some(&host));
            assert!(
                document.execution().is_err(),
                "absent execution actors remain invalid even before file replacement"
            );
            registry.revalidate().unwrap();
            std::fs::write(&host.registry, "{}").unwrap();
            assert!(registry.revalidate().is_err());
            assert!(crate::capture_artifacts::Registry::qualify(
                &host.registry,
                &host.registry_sha256
            )
            .is_err());
            println!("snapshot preserved; actual registry replacement refused");
            return;
        }
        crate::cli::dispatch_public(
            &args
                .into_iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>(),
        );
        return;
    }
    let Some(context) = std::env::var_os("GAP_SCOPE_CONTEXT") else {
        return;
    };
    let root = std::path::PathBuf::from(std::env::var_os("GAP_SCOPE_FIXTURE").unwrap());
    let path = std::path::PathBuf::from(context);
    let collector = capture_collector::Collector {
        root: root.clone(),
        context: serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap(),
        initialized: std::cell::Cell::new(false),
    };
    let bytes = std::fs::read(root.join("argv")).unwrap();
    let mut argv = bytes
        .split(|b| *b == 0)
        .map(|v| std::ffi::OsString::from_vec(v.to_vec()))
        .collect::<Vec<_>>();
    argv.pop();
    if crate::scope_child::run_with_collector(&path, &argv, &collector).is_err() {
        std::process::exit(42);
    }
}
fn executable(path: &std::path::Path, text: String) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}
struct ScopeHarness {
    temp: tempfile::TempDir,
    config: crate::config::Config,
    allocation: crate::allocate::Allocation,
    command: crate::supervisor::RootCommand,
    driver: crate::scope_driver::Driver,
    _bus: std::os::unix::net::UnixListener,
}
impl ScopeHarness {
    fn new(required: bool) -> Self {
        Self::with_inspection_duration(required, std::time::Duration::from_secs(2))
    }
    fn with_inspection_duration(required: bool, duration: std::time::Duration) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let limits = crate::scope_driver::Limits {
            duration,
            ..crate::scope_driver::Limits::default()
        };
        let (temp, config, allocation, root, _) = materialized_mode(required, true);
        let p = temp.path();
        std::fs::create_dir(p.join("runtime")).unwrap();
        std::fs::set_permissions(p.join("runtime"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let bus = std::os::unix::net::UnixListener::bind(p.join("runtime/bus")).unwrap();
        std::fs::create_dir_all(p.join("proc/sys/kernel/random")).unwrap();
        std::fs::write(p.join("proc/sys/kernel/random/boot_id"), &root.input().boot).unwrap();
        std::fs::create_dir(p.join("cg")).unwrap();
        executable(
            &p.join("manager"),
            format!(
                "#!/bin/sh\nexec /usr/bin/cat '{}/properties'\n",
                p.display()
            ),
        );
        executable(
            &p.join("launcher"),
            "#!/bin/sh\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n".into(),
        );
        executable(&p.join("self"), format!("#!/bin/sh\nexport GAP_SCOPE_CONTEXT=\"$3\" GAP_SCOPE_FIXTURE='{0}'\nshift 4\nprintf '%s\\0' \"$@\" > '{0}/argv'\nexec '{1}' --exact attribution_gap::tests::fixture_child --nocapture\n",p.display(),std::env::current_exe().unwrap().display()));
        executable(
            &p.join("delegate"),
            format!("#!/bin/sh\nprintf executed > '{}/executed'\n", p.display()),
        );
        let command = crate::supervisor::RootCommand {
            checkout: allocation.checkout,
            actor: Some("alice".into()),
            run_id: uuid::Uuid::parse_str(&root.identity().run.to_string()).unwrap(),
            execution_chain: root.identity().execution_chain.clone(),
            argv: vec![p.join("delegate").into_os_string()],
        };
        let driver = crate::scope_driver::Driver::with_io(
            crate::scope_driver::RuntimeContext::new(
                p.join("runtime"),
                format!("unix:path={}/runtime/bus", p.display()),
            )
            .unwrap(),
            crate::scope_driver::LibraryIo {
                systemctl: p.join("manager"),
                proc_root: p.join("proc"),
                cgroup_root: p.join("cg"),
                between_censuses: None,
            },
            limits,
        )
        .unwrap();
        Self {
            temp,
            config,
            allocation,
            command,
            driver,
            _bus: bus,
        }
    }
    fn io(&self) -> crate::scope_spawn::LaunchIo {
        crate::scope_spawn::LaunchIo {
            systemd_run: self.temp.path().join("launcher"),
            self_binary: self.temp.path().join("self"),
        }
    }
    fn empty(&self, root: &crate::run_journal::RunRecord) {
        let binding = root.binding.as_ref().unwrap();
        std::fs::remove_dir_all(self.temp.path().join(format!("proc/{}", binding.root_pid)))
            .unwrap();
        self.empty_cgroup(root);
    }
    fn empty_cgroup(&self, root: &crate::run_journal::RunRecord) {
        let binding = root.binding.as_ref().unwrap();
        std::fs::write(
            self.temp
                .path()
                .join("cg")
                .join(binding.cgroup.trim_start_matches('/'))
                .join("cgroup.procs"),
            "",
        )
        .unwrap();
    }
}
#[test]
fn gap_guard_cannot_use_generic_or_captured_release() {
    for case in [
        "generic",
        "captured",
        "cross_root",
        "nonce",
        "cwd",
        "argv",
        "git",
    ] {
        let h = ScopeHarness::new(true);
        let mut root =
            serde_json::to_value(test_run_fixture::request(h.allocation.checkout)).unwrap();
        root["identity"]["actor"] = "alice".into();
        root["input"]["boot"] = h
            .allocation
            .identity
            .as_ref()
            .unwrap()
            .boot_id
            .clone()
            .into();
        root["input"]["attribution"] = "off".into();
        root["input"]["command_digest"] =
            serde_json::to_value(crate::supervisor::command_digest(&h.command.argv).unwrap())
                .unwrap();
        let root: crate::run_journal::RootRunRequest = serde_json::from_value(root).unwrap();
        let (mut store, super::BeginGap::Created(live)) =
            super::begin(&h.config, &root, &h.command.argv).unwrap()
        else {
            panic!("Created required")
        };
        let driver = h.driver.for_gap(&live.removal_policy());
        let directory = h.temp.path().join("owned-gate");
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let mut launch = crate::scope_spawn::OwnedLaunch::spawn_gap(
            &driver,
            crate::runtime_scope::LaunchIntent::new(
                root.identity().run.clone(),
                &root.input().boot,
            )
            .unwrap(),
            &directory,
            crate::scope_spawn::AttributedCommand {
                cwd: &h.allocation.destination,
                argv: &h.command.argv,
                git: &h.config.supervisor.as_ref().unwrap().actors["alice"],
            },
            crate::scope_spawn::LaunchPolicy::new(
                std::time::Duration::from_secs(60),
                std::time::Duration::from_secs(5),
            )
            .unwrap(),
            Some(h.io()),
            &live,
        )
        .expect("valid Gap must create an exclusively owned blocked child");
        while !launch.poll_blocked().unwrap() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        launch.bind(&driver).unwrap();
        store
            .record_bound(&root, launch.binding().unwrap())
            .unwrap();
        if case == "captured" {
            let (_temp, cfg, _a, other, spec) =
                crate::capture_preparation::tests::qualified_fixture();
            let (_, crate::capture_preparation::PreparationResult::Live(capture)) =
                crate::capture_preparation::prepare(&cfg, &other, &spec).unwrap()
            else {
                panic!("actual capture preparation required")
            };
            assert!(launch
                .release_captured(&driver, capture.release_proof().unwrap())
                .is_err());
        } else if case == "generic" {
            assert!(launch.release(&driver).is_err());
        } else if case == "cross_root" {
            let (_temp, cfg, _a, other, argv) = ordinary();
            let (_store, super::BeginGap::Created(other_live)) =
                super::begin(&cfg, &other, &argv).unwrap()
            else {
                panic!("actual other live required")
            };
            assert!(launch
                .release_gap(&driver, other_live.release_proof().unwrap())
                .is_err());
        } else {
            // Test-only tampering with an actually observed proof checks private
            // guard bindings, not successful physical authority from synthetic data.
            let mut proof = live.release_proof().unwrap();
            match case {
                "nonce" => proof.guard.nonce = uuid::Uuid::now_v7(),
                "cwd" => proof.guard.cwd = h.temp.path().to_owned(),
                "argv" => proof.guard.argv.push("changed".into()),
                "git" => {
                    proof.guard.git = crate::scope_spawn::ActorGitProfile::new(
                        "Alice",
                        "changed@example.invalid",
                        "Alice",
                        "alice@example.invalid",
                    )
                    .unwrap()
                }
                _ => unreachable!(),
            }
            assert!(
                launch.release_gap(&driver, proof).is_err(),
                "{case} swapped guard permitted release"
            );
        }
        assert!(!h.temp.path().join("executed").exists());
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}

#[test]
fn release_cas_and_original_age_survive_contention_and_kernel_gate() {
    for case in [
        "binding",
        "stage",
        "missing_writer",
        "target",
        "root",
        "registry_spawn",
        "owner",
        "requirement",
        "allocation",
        "state",
        "writer",
        "finish",
        "outcome",
        "hold",
        "registry",
        "kernel_age",
        "contention",
        "age",
    ] {
        let h = ScopeHarness::new(true);
        let private = h.config.store_dir.clone().unwrap();
        let waiter = std::rc::Rc::new(std::cell::RefCell::new(None));
        let join = waiter.clone();
        RELEASE_OBSERVER.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let sql = Connection::open(private.join("store.sqlite")).unwrap();
                sql.busy_timeout(std::time::Duration::ZERO).unwrap();
                sql.execute_batch("BEGIN IMMEDIATE; ROLLBACK;").unwrap();
                drop(crate::allocate::lifecycle_lock(&private).unwrap());
                match case {
                    "kernel_age" => std::thread::sleep(std::time::Duration::from_millis(1200)),
                    "age" => std::thread::sleep(std::time::Duration::from_millis(2100)),
                    "contention" => {
                        std::thread::sleep(std::time::Duration::from_millis(1850));
                        let path = private.clone();
                        let (ready, wait) = std::sync::mpsc::channel();
                        *join.borrow_mut() = Some(std::thread::spawn(move || {
                            let lock = crate::allocate::lifecycle_lock(&path).unwrap();
                            ready.send(()).unwrap();
                            std::thread::sleep(std::time::Duration::from_millis(300));
                            drop(lock);
                        }));
                        wait.recv().unwrap();
                    }
                    _ => (),
                }
            }))
        });
        let _observer = ReleaseObserverGuard;
        let result = crate::supervisor::supervise_off(
            &h.config,
            h.command.clone(),
            &h.driver,
            Some(h.io()),
            &crate::supervisor::CancelToken::default(),
            |boundary, root| {
                if boundary == crate::supervisor::Boundary::Intent && case == "registry_spawn" {
                    std::fs::write(&h.config.capture.as_ref().unwrap().registry, "{}").unwrap();
                }
                if boundary != crate::supervisor::Boundary::PermitAttempt {
                    return;
                }
                let sql = Connection::open(h.temp.path().join("private/store.sqlite")).unwrap();
                sql.busy_timeout(std::time::Duration::ZERO).unwrap();
                sql.execute_batch("BEGIN IMMEDIATE; ROLLBACK;").unwrap();
                match case {
                    "binding" => {
                        let mut binding = root.binding.clone().unwrap();
                        binding.root_start_ticks += 1;
                        sql.execute(
                            "UPDATE runs SET binding=?1",
                            [serde_json::to_string(&binding).unwrap()],
                        )
                        .unwrap();
                    }
                    "stage" => {
                        sql.execute("UPDATE runs SET stage='bound'", []).unwrap();
                    }
                    "missing_writer" => {
                        sql.execute("DELETE FROM writers", []).unwrap();
                    }
                    "target" | "root" => {
                        let mut record = super::read_record(&sql, &root.request).unwrap();
                        if case == "target" {
                            record.destination.as_mut().unwrap().endpoint =
                                "different-target".into();
                        } else {
                            let mut input = root.request.input().clone();
                            input.command_digest = [91; 32];
                            let changed = crate::run_journal::RootRunRequest::new(
                                root.request.identity().clone(),
                                input,
                            )
                            .unwrap();
                            let bytes = serde_json::to_string(&changed).unwrap();
                            record.request_digest = sha2::Sha256::digest(bytes.as_bytes()).into();
                            sql.execute("UPDATE runs SET request=?1", [bytes]).unwrap();
                        }
                        let bytes = super::encode(&record).unwrap();
                        let fingerprint = sha2::Sha256::digest(bytes.as_bytes());
                        sql.execute(
                            "UPDATE attribution_gaps SET record=?1,fingerprint=?2",
                            rusqlite::params![bytes, fingerprint.as_slice()],
                        )
                        .unwrap();
                    }
                    "owner" => {
                        sql.execute("UPDATE checkouts SET owner='changed'", [])
                            .unwrap();
                    }
                    "requirement" => {
                        sql.execute("UPDATE capture_requirements SET revision=2", [])
                            .unwrap();
                    }
                    "allocation" => {
                        sql.execute("UPDATE allocations SET record='{}'", [])
                            .unwrap();
                    }
                    "state" => {
                        sql.execute("UPDATE checkouts SET state='held'", [])
                            .unwrap();
                    }
                    "writer" => {
                        sql.execute(
                            "UPDATE writers SET group_id=?1",
                            [uuid::Uuid::now_v7().to_string()],
                        )
                        .unwrap();
                    }
                    "finish" => {
                        sql.execute(
                            "INSERT INTO task_finishes VALUES(?1,?2,'{}')",
                            (
                                root.request.identity().checkout.to_string(),
                                uuid::Uuid::now_v7().to_string(),
                            ),
                        )
                        .unwrap();
                    }
                    "outcome" => {
                        sql.execute(
                            "UPDATE runs SET outcome=?1",
                            [
                                serde_json::to_string(&crate::run_journal::RootOutcome::Failed)
                                    .unwrap(),
                            ],
                        )
                        .unwrap();
                    }
                    "hold" => {
                        sql.execute("UPDATE run_groups SET recovery_hold=1", [])
                            .unwrap();
                    }
                    "registry" => {
                        std::fs::write(&h.config.capture.as_ref().unwrap().registry, "{}").unwrap()
                    }
                    "kernel_age" => executable(
                        &h.temp.path().join("manager"),
                        format!(
                            "#!/bin/sh\n/usr/bin/sleep 0.55\nexec /usr/bin/cat '{}/properties'\n",
                            h.temp.path().display()
                        ),
                    ),
                    "contention" | "age" => (),
                    _ => unreachable!(),
                }
            },
        );
        if let Some(waiter) = waiter.borrow_mut().take() {
            waiter.join().unwrap();
        }
        assert!(result.is_err(), "{case} published a permit");
        let sql = Connection::open(h.temp.path().join("private/store.sqlite")).unwrap();
        assert_eq!(
            sql.query_row("SELECT count(*) FROM attribution_gaps", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1,
            "{case}: no admitted intent"
        );
        assert_eq!(
            sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            if case == "missing_writer" { 0 } else { 1 },
            "{case}: writer changed beyond fixture mutation"
        );
        assert!(!h.temp.path().join("executed").exists(), "{case}");
    }
}

fn declared_child(
    root: &crate::run_journal::RootRunRequest,
    expected_host: Option<crate::run_participants::ExpectedHost>,
) -> crate::run_participants::ChildRequest {
    crate::run_participants::ChildRequest {
        checkout: root.identity().checkout.clone(),
        group: root.identity().group.clone(),
        run: work_contract::RunId::generate(),
        run_ref: work_contract::RunRef::parse(&format!("child:{}", uuid::Uuid::now_v7())).unwrap(),
        parent_run: root.identity().run.clone(),
        parent_run_ref: root.identity().run_ref.clone(),
        execution_chain: root.identity().execution_chain.clone(),
        source: None,
        session: None,
        agent: None,
        actor: None,
        expected_host,
    }
}
struct OwnedSleeper(Option<std::process::Child>);
impl Drop for OwnedSleeper {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
#[test]
fn physical_closure_preserves_required_hold_charge_and_later_truth() {
    for case in ["cancel_blocked", "unknown_outcome", "later_finish_fence"] {
        let h = ScopeHarness::new(true);
        let cancel = crate::supervisor::CancelToken::default();
        let result = crate::supervisor::supervise_off(
            &h.config,
            h.command.clone(),
            &h.driver,
            Some(h.io()),
            &cancel,
            |boundary, record| {
                if boundary == crate::supervisor::Boundary::Bound && case == "cancel_blocked" {
                    cancel.request();
                }
                if boundary == crate::supervisor::Boundary::RootTerminal {
                    h.empty(record);
                    let sql = Connection::open(h.temp.path().join("private/store.sqlite")).unwrap();
                    if case == "unknown_outcome" {
                        sql.execute("UPDATE runs SET outcome=NULL", []).unwrap();
                    }
                    if case == "later_finish_fence" {
                        // Synthetic later raw fence, not an impossible new RequiredInitial
                        // finish receipt or an encoder masquerading as physical proof.
                        sql.execute(
                            "INSERT INTO task_finishes VALUES(?1,?2,'{}')",
                            (
                                h.allocation.checkout.to_string(),
                                uuid::Uuid::now_v7().to_string(),
                            ),
                        )
                        .unwrap();
                        sql.execute("UPDATE checkouts SET state='quarantined',ready=0", [])
                            .unwrap();
                    }
                }
            },
        );
        let (store, lock) = crate::allocate::locked(&h.config).unwrap();
        drop(lock);
        if case == "later_finish_fence" {
            // An intentionally undecodable fence is not a valid finish receipt:
            // report refusal is required even after physical closure commits.
            assert!(result.is_err());
            assert!(store
                .conn
                .query_row("SELECT closed FROM run_groups", [], |r| r.get::<_, bool>(0))
                .unwrap());
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                0
            );
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT record FROM task_finishes", [], |r| r
                        .get::<_, String>(0))
                    .unwrap(),
                "{}"
            );
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT state FROM checkouts", [], |r| r.get::<_, String>(0))
                    .unwrap(),
                "quarantined"
            );
            assert!(!store
                .conn
                .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
                .unwrap());
            assert_eq!(
                store
                    .charged(h.allocation.request.repository.as_ref().unwrap(), None)
                    .unwrap(),
                1
            );
        } else {
            let result = result.unwrap();
            assert!(result.record.closed && result.lease_charged && !result.checkout_ready);
            if case == "cancel_blocked" {
                assert_eq!(
                    result.record.outcome,
                    Some(crate::run_journal::RootOutcome::Cancelled)
                );
                assert!(!h.temp.path().join("executed").exists());
            } else {
                assert!(result.record.outcome.is_none());
            }
        }
    }
    for case in [
        "pending",
        "unverified",
        "surviving",
        "escaped",
        "reused",
        "boot",
        "invocation",
        "cgroup",
        "absent",
    ] {
        let h = ScopeHarness::new(true);
        let mut sleeper = OwnedSleeper(None);
        let mut child_pid = None;
        let mut original_properties = None;
        let report = crate::supervisor::supervise_off(
            &h.config,
            h.command.clone(),
            &h.driver,
            Some(h.io()),
            &crate::supervisor::CancelToken::default(),
            |boundary, record| {
                if boundary == crate::supervisor::Boundary::PermitAttempt {
                    let binding = record.binding.as_ref().unwrap();
                    let contained = !matches!(case, "pending" | "unverified");
                    let expected = if contained {
                        let child = std::process::Command::new("/usr/bin/sleep")
                            .arg("30")
                            .spawn()
                            .unwrap();
                        let pid = child.id();
                        sleeper.0 = Some(child);
                        child_pid = Some(pid);
                        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
                        let start_ticks = stat
                            .rsplit_once(") ")
                            .unwrap()
                            .1
                            .split_whitespace()
                            .nth(19)
                            .unwrap()
                            .parse()
                            .unwrap();
                        let proc = h.temp.path().join(format!("proc/{pid}"));
                        std::fs::create_dir(&proc).unwrap();
                        std::fs::write(proc.join("stat"), stat).unwrap();
                        std::fs::write(proc.join("cgroup"), format!("0::{}\n", binding.cgroup))
                            .unwrap();
                        std::fs::write(
                            h.temp
                                .path()
                                .join("cg")
                                .join(binding.cgroup.trim_start_matches('/'))
                                .join("cgroup.procs"),
                            format!("{}\n{pid}\n", binding.root_pid),
                        )
                        .unwrap();
                        Some(crate::run_participants::ExpectedHost {
                            pid,
                            start_ticks,
                            boot: binding.boot.clone(),
                        })
                    } else if case == "pending" {
                        Some(crate::run_participants::ExpectedHost {
                            pid: binding.root_pid,
                            start_ticks: binding.root_start_ticks,
                            boot: binding.boot.clone(),
                        })
                    } else {
                        None
                    };
                    let child = declared_child(&record.request, expected);
                    let (mut store, lock) = crate::allocate::locked(&h.config).unwrap();
                    drop(lock);
                    store.register_child(&record.request, &child).unwrap();
                    if contained {
                        // Public self-enrollment also verifies its registrar. Populate
                        // the fake OS with this owned test process's real PID/start.
                        let registrar = std::process::id();
                        let proc = h.temp.path().join(format!("proc/{registrar}"));
                        std::fs::create_dir(&proc).unwrap();
                        std::fs::write(
                            proc.join("stat"),
                            std::fs::read(format!("/proc/{registrar}/stat")).unwrap(),
                        )
                        .unwrap();
                        std::fs::write(proc.join("cgroup"), format!("0::{}\n", binding.cgroup))
                            .unwrap();
                        let members = h
                            .temp
                            .path()
                            .join("cg")
                            .join(binding.cgroup.trim_start_matches('/'))
                            .join("cgroup.procs");
                        std::fs::write(
                            &members,
                            format!(
                                "{}\n{}\n{registrar}\n",
                                binding.root_pid,
                                child_pid.unwrap()
                            ),
                        )
                        .unwrap();
                        let proof = store
                            .group_snapshot(&record.request.identity().run)
                            .unwrap()
                            .certify_child_enrollment(&h.driver, &child.run, None)
                            .unwrap();
                        store
                            .record_child_enrollment(&record.request, &child, &proof)
                            .unwrap();
                        std::fs::remove_dir_all(proc).unwrap();
                        std::fs::write(
                            members,
                            format!("{}\n{}\n", binding.root_pid, child_pid.unwrap()),
                        )
                        .unwrap();
                    }
                    store
                        .record_child_outcome(
                            &record.request,
                            &child,
                            crate::run_participants::ChildOutcome::Completed,
                        )
                        .unwrap();
                }
                if boundary == crate::supervisor::Boundary::RootTerminal {
                    h.empty(record);
                    if let Some(pid) = child_pid {
                        let proc = h.temp.path().join(format!("proc/{pid}"));
                        match case {
                            "surviving" => std::fs::write(
                                h.temp
                                    .path()
                                    .join("cg")
                                    .join(
                                        record
                                            .binding
                                            .as_ref()
                                            .unwrap()
                                            .cgroup
                                            .trim_start_matches('/'),
                                    )
                                    .join("cgroup.procs"),
                                format!("{pid}\n"),
                            )
                            .unwrap(),
                            "escaped" => {
                                std::fs::write(proc.join("cgroup"), "0::/escaped\n").unwrap()
                            }
                            "reused" => {
                                let stat = std::fs::read_to_string(proc.join("stat")).unwrap();
                                let (prefix, fields) = stat.rsplit_once(") ").unwrap();
                                let mut fields = fields
                                    .split_whitespace()
                                    .map(str::to_owned)
                                    .collect::<Vec<_>>();
                                fields[19] = (fields[19].parse::<u64>().unwrap() + 1).to_string();
                                std::fs::write(
                                    proc.join("stat"),
                                    format!("{prefix}) {}", fields.join(" ")),
                                )
                                .unwrap();
                            }
                            "boot" => std::fs::write(
                                h.temp.path().join("proc/sys/kernel/random/boot_id"),
                                uuid::Uuid::now_v7().to_string(),
                            )
                            .unwrap(),
                            "invocation" | "cgroup" => {
                                let path = h.temp.path().join("properties");
                                let bytes = std::fs::read_to_string(&path).unwrap();
                                let binding = record.binding.as_ref().unwrap();
                                let changed = if case == "invocation" {
                                    bytes.replace(
                                        &binding.invocation,
                                        "abcdef1234567890abcdef1234567890",
                                    )
                                } else {
                                    bytes.replace(&binding.cgroup, "/different-scope")
                                };
                                std::fs::write(path, changed).unwrap();
                                original_properties = Some(bytes);
                            }
                            "absent" => {
                                if let Some(mut child) = sleeper.0.take() {
                                    child.kill().unwrap();
                                    child.wait().unwrap();
                                }
                                std::fs::remove_dir_all(proc).unwrap();
                            }
                            _ => unreachable!(),
                        }
                    }
                }
            },
        )
        .unwrap();
        assert_eq!(
            report.record.closed,
            case == "absent",
            "{case}: declared completion is not physical absence"
        );
        assert!(report.lease_charged && !report.checkout_ready);
        let (mut store, lock) = crate::allocate::locked(&h.config).unwrap();
        drop(lock);
        let writers: i64 = store
            .conn
            .query_row("SELECT count(*) FROM writers", [], |r| r.get(0))
            .unwrap();
        assert_eq!(writers, if case == "absent" { 0 } else { 1 });
        if matches!(case, "pending" | "unverified") {
            let text = format!(
                "{}\nallocation=42\nsupervisor=false\n",
                authority_text(&h.config)
            );
            let result = shared_cli(
                h.temp.path(),
                &text,
                &[
                    "recover".into(),
                    report.record.request.identity().run.to_string(),
                ],
            );
            assert!(
                String::from_utf8_lossy(&result.stdout).contains("unverified child execution host")
            );
        } else if case != "absent" {
            if let Some(mut child) = sleeper.0.take() {
                child.kill().unwrap();
                child.wait().unwrap();
            }
            std::fs::remove_dir_all(h.temp.path().join(format!("proc/{}", child_pid.unwrap())))
                .unwrap();
            h.empty_cgroup(&report.record);
            std::fs::write(
                h.temp.path().join("proc/sys/kernel/random/boot_id"),
                &report.record.request.input().boot,
            )
            .unwrap();
            if let Some(properties) = original_properties {
                std::fs::write(h.temp.path().join("properties"), properties).unwrap();
            }
            assert_eq!(
                crate::run_recovery::recover_with_config(
                    &mut store,
                    &report.record.request.identity().run,
                    &h.driver,
                    &h.config
                )
                .unwrap(),
                crate::run_recovery::RecoveryState::Closed
            );
        }
    }
    {
        let h = ScopeHarness::new(true);
        let report = crate::supervisor::supervise_off(
            &h.config,
            h.command.clone(),
            &h.driver,
            Some(h.io()),
            &crate::supervisor::CancelToken::default(),
            |_, _| {},
        )
        .unwrap();
        assert!(!report.record.closed);
        h.empty(&report.record);
        let (mut store, lock) = crate::allocate::locked(&h.config).unwrap();
        drop(lock);
        let snapshot = store
            .group_snapshot(&report.record.request.identity().run)
            .unwrap();
        let proof = snapshot.certify_historical_empty(&h.driver).unwrap();
        let before = durable_rows(&store);
        std::thread::sleep(std::time::Duration::from_millis(2100));
        assert!(
            store.close_supervised_group(&snapshot, &proof).is_err(),
            "stale closure evidence cannot release writer"
        );
        assert_eq!(durable_rows(&store), before);
        assert_eq!(
            crate::run_recovery::recover_with_config(
                &mut store,
                &report.record.request.identity().run,
                &h.driver,
                &h.config
            )
            .unwrap(),
            crate::run_recovery::RecoveryState::Closed
        );
    }
    for state in ["safety_hold", "partial", "held", "quarantined", "retired"] {
        let h = ScopeHarness::new(true);
        let report = crate::supervisor::supervise_off(
            &h.config,
            h.command.clone(),
            &h.driver,
            Some(h.io()),
            &crate::supervisor::CancelToken::default(),
            |boundary, root| {
                if boundary != crate::supervisor::Boundary::RootTerminal {
                    return;
                }
                h.empty(root);
                let (mut store, lock) = crate::allocate::locked(&h.config).unwrap();
                drop(lock);
                if state == "safety_hold" {
                    let mut a = h.allocation.clone();
                    crate::recovery::hold(&mut store, &mut a, "independent preservation hold")
                        .expect("independent conservative hold must remain possible");
                    crate::recovery::hold(
                        &mut store,
                        &mut a,
                        "must not overwrite independent reason",
                    )
                    .unwrap();
                } else {
                    store
                        .conn
                        .execute("UPDATE checkouts SET state=?1,ready=0", [state])
                        .unwrap();
                }
            },
        )
        .unwrap();
        assert!(report.record.closed);
        let sql = Connection::open(h.temp.path().join("private/store.sqlite")).unwrap();
        let (actual, ready): (String, bool) = sql
            .query_row("SELECT state,ready FROM checkouts", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(
            actual,
            if matches!(state, "quarantined" | "retired") {
                state
            } else {
                "held"
            }
        );
        assert!(!ready);
        let a: crate::allocate::Allocation = serde_json::from_str(
            &sql.query_row("SELECT record FROM allocations", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(a.stage, "capture_pending");
        if state == "safety_hold" {
            assert_eq!(a.reason.as_deref(), Some("independent preservation hold"));
        }
        assert_eq!(
            sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            sql.query_row("SELECT count(*) FROM attribution_gaps", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    for required in [true, false] {
        let h = ScopeHarness::new(required);
        let result = crate::supervisor::supervise_off(
            &h.config,
            h.command.clone(),
            &h.driver,
            Some(h.io()),
            &crate::supervisor::CancelToken::default(),
            |boundary, root| {
                if boundary == crate::supervisor::Boundary::RootTerminal {
                    h.empty(root);
                }
            },
        )
        .expect("supported Off must execute through the owned runtime");
        assert!(result.record.closed);
        assert!(result.lease_charged && result.task_open);
        assert_eq!(result.checkout_ready, !required);
        assert!(h.temp.path().join("executed").exists());
        let sql = Connection::open(h.temp.path().join("private/store.sqlite")).unwrap();
        let (state, ready): (String, bool) = sql
            .query_row("SELECT state,ready FROM checkouts", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(state, if required { "held" } else { "active" });
        assert_eq!(ready, !required);
        let stored: String = sql
            .query_row("SELECT record FROM allocations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stored, serde_json::to_string(&h.allocation).unwrap());
    }
}

#[test]
fn gap_reports_are_journal_only_allowlisted_observations() {
    for required in [false, true] {
        let (_temp, config, a, root, argv) = materialized(required);
        let (mut store, _) = super::begin(&config, &root, &argv).unwrap();
        let status = crate::run_recovery::status(&store, &root.identity().run).unwrap();
        if required {
            let value = serde_json::to_value(&status).unwrap();
            assert_eq!(value["checkout_state"], "active");
            assert_eq!(
                value["checkout_ready"], false,
                "required Gap status must report not_ready truth"
            );
            assert_eq!(value["gap_limitations"],"physical closure leaves held/not_ready; charge retained; next root and new finish unsupported");
        }
        let gap = status
            .gap
            .expect("status must distinguish recorded Off from ordinary attribution");
        assert!(gap.event_recorded && gap.transport_deferred);
        assert_eq!(gap.mode, crate::run_journal::AttributionDecision::Off);
        assert_eq!(
            gap.delivery,
            if required {
                super::GapDelivery::Pending
            } else {
                super::GapDelivery::NotConfigured
            }
        );
        assert_eq!(status.record.stage, crate::run_journal::RunStage::Intent);
        assert!(status.record.binding.is_none() && status.record.outcome.is_none());
        let value = serde_json::to_value(&gap).unwrap();
        let keys = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                "delivery",
                "event_id",
                "event_recorded",
                "mode",
                "origin",
                "transport_deferred"
            ]
        );
        let text = serde_json::to_string(&gap).unwrap();
        for forbidden in [
            "TOKEN",
            "registry",
            "destination",
            "session",
            "capture_id",
            "key_file",
            "environment",
        ] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
        let before = super::read_record(&store.conn, &root).unwrap();
        for notice in store.pending_events(100).unwrap() {
            store.acknowledge(notice.sequence).unwrap();
        }
        assert!(
            super::read_record(&store.conn, &root).unwrap() == before,
            "generic notification ACK must not consume typed queue"
        );
        let command = crate::supervisor::RootCommand {
            checkout: a.checkout,
            actor: Some("alice".into()),
            run_id: uuid::Uuid::parse_str(&root.identity().run.to_string()).unwrap(),
            execution_chain: root.identity().execution_chain.clone(),
            argv,
        };
        assert_eq!(
            crate::supervisor::off_existing_report(&config, &command)
                .unwrap()
                .unwrap()
                .gap,
            Some(gap)
        );
    }
    let h = ScopeHarness::new(false);
    let report = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &crate::supervisor::CancelToken::default(),
        |boundary, root| {
            if boundary == crate::supervisor::Boundary::RootTerminal {
                h.empty(root);
            }
        },
    )
    .unwrap();
    let finish = crate::finish::finish(&h.config, h.allocation.checkout).unwrap();
    assert_eq!(finish.run_outcomes.len(), 1);
    assert_eq!(finish.run_outcomes[0].gap, report.gap);
    assert!(report.gap.is_some());
    assert_eq!(finish.local_freeze, crate::finish::Freeze::NotConfigured);
}

#[test]
fn historical_recovery_qualifies_current_union_without_live_authority() {
    use std::os::unix::fs::PermissionsExt;
    for closed in [false, true] {
        let h = ScopeHarness::new(true);
        let root = if closed {
            crate::supervisor::supervise_off(
                &h.config,
                h.command.clone(),
                &h.driver,
                Some(h.io()),
                &crate::supervisor::CancelToken::default(),
                |boundary, root| {
                    if boundary == crate::supervisor::Boundary::RootTerminal {
                        h.empty(root);
                    }
                },
            )
            .unwrap()
            .record
            .request
        } else {
            let mut root =
                serde_json::to_value(test_run_fixture::request(h.allocation.checkout)).unwrap();
            root["identity"]["actor"] = "alice".into();
            root["input"]["boot"] = h
                .allocation
                .identity
                .as_ref()
                .unwrap()
                .boot_id
                .clone()
                .into();
            root["input"]["attribution"] = "off".into();
            root["input"]["command_digest"] =
                serde_json::to_value(crate::supervisor::command_digest(&h.command.argv).unwrap())
                    .unwrap();
            let root = serde_json::from_value(root).unwrap();
            super::begin(&h.config, &root, &h.command.argv).unwrap();
            root
        };
        let (store, lock) = crate::allocate::locked(&h.config).unwrap();
        drop(lock);
        let before = durable_rows(&store);
        let text = format!(
            "{}\nallocation=42\ncapture=false\nsupervisor='unusable'\n",
            authority_text(&h.config)
        );
        let result = shared_cli(
            h.temp.path(),
            &text,
            &["recover".into(), root.identity().run.to_string()],
        );
        let output = String::from_utf8_lossy(&result.stdout);
        let expected = if closed {
            "already_closed"
        } else {
            "unbound intent: historical proof unsupported"
        };
        assert!(
            output.contains(expected),
            "passive {expected} blocked by irrelevant declarations: {} / {output}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(durable_rows(&store), before);
    }
    // After-green qualification of document-derived open-bound policy through
    // the shared preflight and actual owned-child/fake-OS physical core.
    for mode in ["gap_selected", "gap_none", "ordinary"] {
        let h = ScopeHarness::new(mode != "ordinary");
        let report = if mode == "ordinary" {
            crate::supervisor::supervise_with_io(
                &h.config,
                h.command.clone(),
                &h.driver,
                h.io(),
                &crate::supervisor::CancelToken::default(),
                |_, _| {},
            )
            .unwrap()
        } else {
            crate::supervisor::supervise_off(
                &h.config,
                h.command.clone(),
                &h.driver,
                Some(h.io()),
                &crate::supervisor::CancelToken::default(),
                |_, _| {},
            )
            .unwrap()
        };
        assert!(!report.record.closed);
        h.empty(&report.record);
        let (mut store, lock) = crate::allocate::locked(&h.config).unwrap();
        drop(lock);
        let run = &report.record.request.identity().run;
        let before = durable_rows(&store);
        if mode != "ordinary" {
            for selection in ["allocation=42\ncapture=false\n", "[allocation]\nrepository_limit=10\nowner_limit=10\nfloor_bytes=0\nwarn_bytes=0\ncapture_sink=42\n", "[allocation]\nrepository_limit=10\nowner_limit=10\nfloor_bytes=0\nwarn_bytes=0\ncapture_sink='unknown'\n"] {
                let text=format!("{}\nsupervisor=false\n{selection}",authority_text(&h.config));
                let result=shared_cli(h.temp.path(),&text,&["recover".into(),run.to_string()]);
                assert!(String::from_utf8_lossy(&result.stdout).contains("verified Gap recovery environment unavailable"));
                assert_eq!(durable_rows(&store),before);
            }
            let text = format!(
                "{}\nsupervisor=false\ncapture=false\n",
                authority_text(&h.config)
            );
            let result = shared_cli(h.temp.path(), &text, &["recover".into(), run.to_string()]);
            assert!(
                String::from_utf8_lossy(&result.stdout).contains("runtime inspection unavailable"),
                "genuine None skips unused capture; malformed runtime stays Held"
            );
            assert_eq!(durable_rows(&store), before);
        }
        let target = match mode {
            "gap_selected" => recovery_target_text(h.config.capture.as_ref().unwrap()),
            "gap_none" => {
                std::fs::remove_file(&h.config.capture.as_ref().unwrap().registry).unwrap();
                "\ncapture=false\n".into()
            }
            _ => "\nallocation=42\ncapture=false\n".into(),
        };
        let text = format!(
            "{}{target}{}",
            authority_text(&h.config),
            recovery_runtime_text(&h.config)
        );
        assert!(
            crate::config::Config::from_text(&text).is_err(),
            "actor-free runtime must not become execution Config"
        );
        let document = crate::config::ConfigDocument::from_text(&text).unwrap();
        assert_eq!(
            crate::run_recovery::document_fixture::recover(&mut store, run, &document, &h.driver)
                .unwrap(),
            crate::run_recovery::RecoveryState::Closed,
            "{mode}"
        );
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    {
        let (temp, config, _, _, _) = materialized(true);
        let text = format!(
            "{}{}{}",
            authority_text(&config),
            recovery_target_text(config.capture.as_ref().unwrap()),
            recovery_runtime_text(&config)
        );
        let result = shared_cli(temp.path(), &text, &["fixture-document-snapshot".into()]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stdout)
            .contains("snapshot preserved; actual registry replacement refused"));
        for actors in ["", "actors={}", "actors=42"] {
            let text = format!("{}{actors}\n", recovery_runtime_text(&config));
            let doc = crate::config::ConfigDocument::from_text(&text).unwrap();
            assert!(doc.recovery_runtime().is_ok());
            assert!(doc.execution().is_err());
        }
        for (field, bad) in [
            ("runtime_max_seconds", 0),
            ("runtime_max_seconds", 86401),
            ("preexec_ms", 0),
            ("preexec_ms", 30001),
            ("closure_grace_ms", 0),
            ("closure_grace_ms", 30001),
            ("cancel_grace_ms", 0),
            ("cancel_grace_ms", 30001),
        ] {
            let mut value: toml::Value = toml::from_str(&recovery_runtime_text(&config)).unwrap();
            value["supervisor"][field] = toml::Value::Integer(bad);
            assert!(
                crate::config::ConfigDocument::from_text(&toml::to_string(&value).unwrap())
                    .unwrap()
                    .recovery_runtime()
                    .is_err(),
                "{field}={bad}"
            );
        }
    }
    {
        // Actual prepared captured control, real owned blocked child and fake OS.
        // Current malformed capture selection must remain irrelevant to recovery.
        let h = ScopeHarness::new(false);
        let (_temp, cfg, a, root, spec) = crate::capture_preparation::tests::qualified_fixture();
        let (mut store, crate::capture_preparation::PreparationResult::Live(live)) =
            crate::capture_preparation::prepare(&cfg, &root, &spec).unwrap()
        else {
            panic!("actual capture preparation required")
        };
        use std::os::unix::fs::DirBuilderExt;
        let directory = h.temp.path().join("captured-control");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let argv = [std::ffi::OsString::from("/usr/bin/true")];
        let mut launch = crate::scope_spawn::OwnedLaunch::spawn_captured(
            &h.driver,
            crate::runtime_scope::LaunchIntent::new(
                root.identity().run.clone(),
                &root.input().boot,
            )
            .unwrap(),
            &directory,
            &root,
            crate::scope_spawn::AttributedCommand {
                cwd: &a.destination,
                argv: &argv,
                git: &cfg.supervisor.as_ref().unwrap().actors["alice"],
            },
            crate::scope_spawn::LaunchPolicy::new(
                std::time::Duration::from_secs(60),
                std::time::Duration::from_secs(5),
            )
            .unwrap(),
            Some(h.io()),
            &live,
        )
        .unwrap();
        while !launch.poll_blocked().unwrap() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        launch.bind(&h.driver).unwrap();
        store
            .record_bound(&root, launch.binding().unwrap())
            .unwrap();
        let text = format!(
            "{}\nallocation=42\ncapture=false\n{}",
            authority_text(&cfg),
            recovery_runtime_text(&h.config)
        );
        let doc = crate::config::ConfigDocument::from_text(&text).unwrap();
        assert!(matches!(
            crate::run_recovery::document_fixture::recover(
                &mut store,
                &root.identity().run,
                &doc,
                &h.driver
            )
            .unwrap(),
            crate::run_recovery::RecoveryState::Held {
                reason: "runtime active or uncertain; charges retained",
                ..
            }
        ));
        drop(launch); // Exclusively owned blocked child is killed/reaped, no permit.
        let record = store.run_snapshot(&root.identity().run).unwrap().unwrap();
        h.empty(&record);
        assert_eq!(
            crate::run_recovery::document_fixture::recover(
                &mut store,
                &root.identity().run,
                &doc,
                &h.driver
            )
            .unwrap(),
            crate::run_recovery::RecoveryState::Closed
        );
    }
    let mut h = ScopeHarness::new(true);
    let report = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &crate::supervisor::CancelToken::default(),
        |_, _| {},
    )
    .unwrap();
    assert!(!report.record.closed);
    h.empty(&report.record);
    executable(&h.temp.path().join("manager"),format!("#!/bin/sh\nprintf called >> '{0}/recovery-calls'\nexec /usr/bin/cat '{0}/properties'\n",h.temp.path().display()));
    let (mut store, lock) = crate::allocate::locked(&h.config).unwrap();
    drop(lock);
    let before = durable_rows(&store);
    assert!(
        matches!(
            crate::run_recovery::recover(
                &mut store,
                &report.record.request.identity().run,
                &h.driver
            )
            .unwrap(),
            crate::run_recovery::RecoveryState::Held { .. }
        ),
        "configurationless recovery inspected/closed a bound Gap"
    );
    assert!(!h.temp.path().join("recovery-calls").exists());
    assert_eq!(durable_rows(&store), before);
    let old = h.config.capture.as_ref().unwrap().registry.clone();
    let current = h.temp.path().join("current-registry.json");
    let bytes = br#"{"ingest":{"key_env":"CURRENT_RECEIVER_TOKEN"}}"#;
    std::fs::write(&current, bytes).unwrap();
    std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o600)).unwrap();
    h.config.capture.as_mut().unwrap().registry = current.clone();
    h.config.capture.as_mut().unwrap().registry_sha256 =
        format!("{:x}", sha2::Sha256::digest(bytes));
    h.config.supervisor = None;
    let metadata=super::recovery_removal(super::read_record(&store.conn,&report.record.request).unwrap(),h.config.selected_capture().unwrap()).expect("current host registry plus sealed names must qualify without current actor/profile/producer");
    assert_eq!(
        metadata.policy.receivers(),
        [
            "ACTUAL_RECEIVER_TOKEN",
            "CURRENT_RECEIVER_TOKEN",
            "DECLARED_RECEIVER_TOKEN"
        ]
    );
    assert!(!h.temp.path().join("recovery-calls").exists());
    for bad in [
        "AGENT_ATTRIBUTION_CONTEXT",
        "DEVDIARY_ATTRIBUTION_CONTEXT",
        "DEVDIARY_CAPTURE_ID",
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "BAD=NAME",
        "BAD-NAME",
        "",
    ] {
        let malicious = serde_json::to_vec(&serde_json::json!({"ingest":{"key_env":bad}})).unwrap();
        std::fs::write(&current, &malicious).unwrap();
        h.config.capture.as_mut().unwrap().registry_sha256 =
            format!("{:x}", sha2::Sha256::digest(&malicious));
        assert!(
            matches!(
                crate::run_recovery::recover_with_config(
                    &mut store,
                    &report.record.request.identity().run,
                    &h.driver,
                    &h.config
                )
                .unwrap(),
                crate::run_recovery::RecoveryState::Held {
                    reason: "verified Gap recovery environment unavailable",
                    ..
                }
            ),
            "malicious actual name {bad}"
        );
        assert!(!h.temp.path().join("recovery-calls").exists());
        assert_eq!(durable_rows(&store), before);
    }
    std::fs::write(&current, bytes).unwrap();
    h.config.capture.as_mut().unwrap().registry_sha256 =
        format!("{:x}", sha2::Sha256::digest(bytes));
    let declared = h
        .config
        .capture
        .as_ref()
        .unwrap()
        .receiver_credential_names
        .clone();
    h.config.capture.as_mut().unwrap().receiver_credential_names =
        std::iter::once("DECLARED_RECEIVER_TOKEN".into())
            .chain((0..126).map(|n| format!("NEW_TOKEN_{n}")))
            .collect();
    let full = super::recovery_removal(
        super::read_record(&store.conn, &report.record.request).unwrap(),
        h.config.selected_capture().unwrap(),
    )
    .unwrap();
    assert_eq!(
        full.policy.receivers().len(),
        129,
        "complete union at129, with duplicate old/current declaration, remains usable"
    );
    h.config.capture.as_mut().unwrap().receiver_credential_names =
        (0..128).map(|n| format!("NEW_TOKEN_{n}")).collect();
    assert!(
        super::recovery_removal(
            super::read_record(&store.conn, &report.record.request).unwrap(),
            h.config.selected_capture().unwrap()
        )
        .is_err(),
        "complete historical/current union over129 must refuse"
    );
    h.config.capture.as_mut().unwrap().receiver_credential_names = declared;
    std::fs::write(&current, "{}").unwrap();
    assert!(super::recovery_removal(
        super::read_record(&store.conn, &report.record.request).unwrap(),
        h.config.selected_capture().unwrap()
    )
    .is_err());
    assert!(matches!(
        crate::run_recovery::recover_with_config(
            &mut store,
            &report.record.request.identity().run,
            &h.driver,
            &h.config
        )
        .unwrap(),
        crate::run_recovery::RecoveryState::Held { .. }
    ));
    assert!(!h.temp.path().join("recovery-calls").exists());
    h.config.allocation.as_mut().unwrap().capture_sink = None;
    std::fs::remove_file(old).unwrap();
    let metadata = super::recovery_removal(
        super::read_record(&store.conn, &report.record.request).unwrap(),
        h.config.selected_capture().unwrap(),
    )
    .unwrap();
    assert_eq!(
        metadata.policy.receivers(),
        ["ACTUAL_RECEIVER_TOKEN", "DECLARED_RECEIVER_TOKEN"]
    );
    assert_eq!(
        crate::run_recovery::recover_with_config(
            &mut store,
            &report.record.request.identity().run,
            &h.driver,
            &h.config
        )
        .unwrap(),
        crate::run_recovery::RecoveryState::Closed
    );
    assert!(h.temp.path().join("recovery-calls").exists());
    std::fs::remove_file(h.temp.path().join("recovery-calls")).unwrap();
    h.config.allocation.as_mut().unwrap().capture_sink = Some("devdiary".into());
    assert_eq!(
        crate::run_recovery::recover_with_config(
            &mut store,
            &report.record.request.identity().run,
            &h.driver,
            &h.config
        )
        .unwrap(),
        crate::run_recovery::RecoveryState::AlreadyClosed
    );
    assert!(!h.temp.path().join("recovery-calls").exists());
}

#[test]
fn public_history_and_finish_use_genuine_created_gap_records() {
    struct Sink(std::cell::Cell<usize>);
    impl crate::finish::LocalSink for Sink {
        fn freeze(&self, _: &crate::finish::CaptureContext) -> crate::finish::CaptureResult {
            self.0.set(self.0.get() + 1);
            crate::finish::CaptureResult::Frozen {
                delivery: Some(crate::finish::Delivery::Pending),
            }
        }
    }
    for integrated in [false, true] {
        for required in [false, true] {
            let mut h = ScopeHarness::new(required);
            let report = crate::supervisor::supervise_off(
                &h.config,
                h.command.clone(),
                &h.driver,
                Some(h.io()),
                &crate::supervisor::CancelToken::default(),
                |boundary, root| {
                    if boundary == crate::supervisor::Boundary::RootTerminal {
                        h.empty(root);
                    }
                },
            )
            .unwrap();
            assert!(report.record.closed);
            assert!(crate::supervisor::existing_report(&h.config, &h.command).is_err());
            for route in 0..3 {
                let result = match route {
                    0 => crate::supervisor::supervise_with_io(
                        &h.config,
                        h.command.clone(),
                        &h.driver,
                        h.io(),
                        &crate::supervisor::CancelToken::default(),
                        |_, _| panic!("default entered runtime"),
                    ),
                    1 => crate::supervisor::supervise_captured_with_io(
                        &h.config,
                        h.command.clone(),
                        &h.driver,
                        h.io(),
                        &crate::supervisor::CancelToken::default(),
                        |_, _| panic!("capture entered runtime"),
                    ),
                    _ => crate::supervisor::supervise_captured_integrated_with_io(
                        &h.config,
                        h.command.clone(),
                        &h.driver,
                        h.io(),
                        &crate::supervisor::CancelToken::default(),
                        |_, _| panic!("capture entered runtime"),
                    ),
                };
                assert!(result.is_err(), "default route {route} accepted Off");
            }
            let (_current_temp, current, _, _, _) = materialized(true);
            h.config.capture = current.capture;
            h.config.allocation.as_mut().unwrap().capture_sink = Some("devdiary".into());
            let sink = Sink(std::cell::Cell::new(0));
            let mut boundaries = 0;
            let result = if integrated {
                crate::finish::finish(&h.config, h.allocation.checkout)
            } else {
                crate::finish::finish_with_sink_observed(
                    &h.config,
                    h.allocation.checkout,
                    Some(&sink),
                    |_| boundaries += 1,
                )
            };
            assert!(
                result.is_err(),
                "new sink cannot finish Gap: required={required}, integrated={integrated}"
            );
            assert_eq!(sink.0.get(), 0);
            assert_eq!(boundaries, 0);
            let sql = Connection::open(h.temp.path().join("private/store.sqlite")).unwrap();
            assert_eq!(
                sql.query_row("SELECT count(*) FROM task_finishes", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
            assert_eq!(
                sql.query_row("SELECT count(*) FROM capture_runs", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
            h.config.allocation.as_mut().unwrap().capture_sink = None;
            let finish = crate::finish::finish_with_sink_observed(
                &h.config,
                h.allocation.checkout,
                None,
                |_| {},
            );
            if required {
                assert!(finish.is_err());
                continue;
            }
            let finish = finish.unwrap();
            assert_eq!(finish.local_freeze, crate::finish::Freeze::NotConfigured);
            assert_eq!(
                finish.delivery,
                Some(crate::finish::Delivery::NotConfigured)
            );
            let receipt: String = sql
                .query_row("SELECT record FROM task_finishes", [], |r| r.get(0))
                .unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&receipt).unwrap()["version"],
                1
            );
            h.config.allocation.as_mut().unwrap().capture_sink = Some("devdiary".into());
            assert!(crate::finish::finish(&h.config, h.allocation.checkout).is_ok());
            assert!(crate::finish::finish_with_sink_observed(
                &h.config,
                h.allocation.checkout,
                Some(&sink),
                |_| {}
            )
            .is_ok());
            assert_eq!(sink.0.get(), 0);
            assert_eq!(
                sql.query_row("SELECT record FROM task_finishes", [], |r| r
                    .get::<_, String>(0))
                    .unwrap(),
                receipt
            );
        }
    }
}

#[test]
fn historical_finish_receipts_refuse_raw_gap_corruption() {
    struct Sink(std::cell::Cell<usize>);
    impl crate::finish::LocalSink for Sink {
        fn freeze(&self, _: &crate::finish::CaptureContext) -> crate::finish::CaptureResult {
            self.0.set(self.0.get() + 1);
            crate::finish::CaptureResult::Failed
        }
    }
    let mut h = ScopeHarness::new(false);
    let report = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &crate::supervisor::CancelToken::default(),
        |boundary, root| {
            if boundary == crate::supervisor::Boundary::RootTerminal {
                h.empty(root);
            }
        },
    )
    .unwrap();
    assert!(report.record.closed);
    let root = &report.record.request;
    // Keep a native Store alive through every raw client mutation and finish
    // reopen: last-close WAL/SHM cleanup is not the behavior under test.
    let store = Store::open_existing_registered_mut(
        h.config.trusted_registry.as_ref().unwrap(),
        h.config.store_dir.as_ref().unwrap(),
        &h.config.roots,
    )
    .unwrap();
    let finished = crate::finish::finish(&h.config, h.allocation.checkout).unwrap();
    assert_eq!(finished.local_freeze, crate::finish::Freeze::NotConfigured);
    assert_eq!(
        finished.delivery,
        Some(crate::finish::Delivery::NotConfigured)
    );
    assert!(finished.task_finished && finished.charge_retained && finished.lease_held);
    let original = super::read_record(&store.conn, root).unwrap();
    let original_bytes = super::encode(&original).unwrap();
    let receipt = || {
        store
            .conn
            .query_row("SELECT record FROM task_finishes", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap()
    };
    let original_receipt = receipt();
    let pristine = durable_rows(&store);
    let sql = Connection::open(h.temp.path().join("private/store.sqlite")).unwrap();
    // Fixture-only corruption, never admission, recovery or live authority.
    sql.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    let stray_run = uuid::Uuid::now_v7().to_string();
    let stray_group = uuid::Uuid::now_v7().to_string();
    let stray_event = uuid::Uuid::now_v7().to_string();
    let insert_stray = || {
        sql.execute(
            "INSERT INTO attribution_gaps VALUES(?1,?2,?3,?4,'{}',zeroblob(32))",
            rusqlite::params![
                stray_run,
                stray_group,
                h.allocation.checkout.to_string(),
                stray_event
            ],
        )
        .unwrap();
    };
    let remove_stray = || {
        assert_eq!(
            sql.execute("DELETE FROM attribution_gaps WHERE run=?1", [&stray_run])
                .unwrap(),
            1
        );
    };
    let replace_event = |event: &str, bytes: &str| {
        let fingerprint = sha2::Sha256::digest(bytes.as_bytes());
        assert_eq!(
            sql.execute(
                "UPDATE attribution_gaps SET event_id=?1,record=?2,fingerprint=?3 WHERE run=?4",
                rusqlite::params![event, bytes, fingerprint.as_slice(), original.run],
            )
            .unwrap(),
            1
        );
    };
    let sink = Sink(std::cell::Cell::new(0));
    let mut unexpected = Vec::new();
    for case in ["orphan", "checkout-event-collision"] {
        if case == "orphan" {
            insert_stray();
        } else {
            let mut corrupt = original.clone();
            corrupt.event_id = h.allocation.checkout.to_string();
            corrupt.event = super::event(&corrupt.event_id).unwrap();
            replace_event(&corrupt.event_id, &super::encode(&corrupt).unwrap());
        }
        // The genuine record still passes strict per-record checks; only raw
        // structure/namespace validation detects the intended invalidity.
        assert!(super::read_record(&store.conn, root).is_ok(), "{case}");
        assert!(super::validate_raw(&store.conn).is_err(), "{case}");
        let before = durable_rows(&store);
        assert!(store.run_snapshot(&root.identity().run).is_err(), "{case}");
        for integrated in [true, false] {
            let result = if integrated {
                crate::finish::finish(&h.config, h.allocation.checkout)
            } else {
                crate::finish::finish_with_sink_observed(
                    &h.config,
                    h.allocation.checkout,
                    Some(&sink),
                    |_| {},
                )
            };
            if result.is_ok() {
                unexpected.push(format!("{case}: integrated={integrated}"));
            }
            assert_eq!(
                durable_rows(&store),
                before,
                "{case}: integrated={integrated}"
            );
            assert_eq!(receipt(), original_receipt);
            assert_eq!(sink.0.get(), 0);
        }
        if case == "orphan" {
            remove_stray();
        } else {
            replace_event(&original.event_id, &original_bytes);
        }
        assert_eq!(durable_rows(&store), pristine);
        assert_eq!(
            crate::finish::finish(&h.config, h.allocation.checkout).unwrap(),
            finished
        );
    }
    let mut late_snapshot = None;
    let result = crate::finish::finish_with_sink_observed(
        &h.config,
        h.allocation.checkout,
        Some(&sink),
        |boundary| {
            if boundary == "before_ack" {
                assert!(late_snapshot.is_none());
                assert_eq!(durable_rows(&store), pristine);
                // Observer runs after SQL phases and the allocator lock drop.
                // Autocommit makes the corruption visible to the final snapshot.
                insert_stray();
                late_snapshot = Some(durable_rows(&store));
            }
        },
    );
    if result.is_ok() {
        unexpected.push("late-orphan: before_ack library".into());
    }
    assert_eq!(
        durable_rows(&store),
        late_snapshot.expect("reached before_ack")
    );
    assert_eq!(receipt(), original_receipt);
    assert_eq!(sink.0.get(), 0);
    remove_stray();
    assert_eq!(durable_rows(&store), pristine);

    // Existing receipts stay passive despite later selection and irrelevant
    // missing profile/host settings and malformed current registry contents.
    h.config.allocation.as_mut().unwrap().capture_sink = Some("devdiary".into());
    h.config.supervisor.as_mut().unwrap().actors.clear();
    assert!(h.config.capture.is_none());
    std::fs::write(h.temp.path().join("registry.json"), "malformed registry").unwrap();
    assert_eq!(
        crate::finish::finish(&h.config, h.allocation.checkout).unwrap(),
        finished
    );
    assert_eq!(
        crate::finish::finish_with_sink_observed(
            &h.config,
            h.allocation.checkout,
            Some(&sink),
            |_| {},
        )
        .unwrap(),
        finished
    );
    assert_eq!(sink.0.get(), 0);
    assert_eq!(receipt(), original_receipt);
    assert_eq!(durable_rows(&store), pristine);
    assert!(
        unexpected.is_empty(),
        "historical finish acknowledged corrupt raw Gap authority: {unexpected:?}"
    );
}

fn isolated_environment() {
    use std::os::unix::ffi::OsStrExt;
    let required = std::env::var_os("GAP_ENV_FIXTURE").unwrap() == "required";
    let original_runtime = std::env::var_os("XDG_RUNTIME_DIR");
    let original_bus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS");
    let h = ScopeHarness::new(required);
    let p = h.temp.path();
    executable(&p.join("launcher"),format!("#!/bin/sh\n/usr/bin/env -0 > '{0}/launcher.env'\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n",p.display()));
    executable(
        &p.join("delegate"),
        format!(
            "#!/bin/sh\n/usr/bin/env -0 > '{0}/actor.env'\nprintf executed > '{0}/executed'\n",
            p.display()
        ),
    );
    executable(&p.join("manager"),format!("#!/bin/sh\ncase \" $* \" in *' kill '*) /usr/bin/env -0 > '{0}/cancel.env'; exit 0;; esac\n/usr/bin/env -0 > '{0}/inspection.env'\nexec /usr/bin/cat '{0}/properties'\n",p.display()));
    let cancel = crate::supervisor::CancelToken::default();
    let report = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &cancel,
        |boundary, _| {
            if boundary == crate::supervisor::Boundary::RootTerminal {
                cancel.request();
            }
        },
    )
    .unwrap();
    assert!(
        !report.record.closed,
        "root exit/cancel without full-roster absence cannot close"
    );
    for helper in ["launcher", "actor", "inspection", "cancel"] {
        let bytes = std::fs::read(p.join(format!("{helper}.env")))
            .unwrap_or_else(|e| panic!("{helper}: {e}"));
        let fields = bytes.split(|b| *b == 0).collect::<Vec<_>>();
        for name in [
            "AGENT_ATTRIBUTION_CONTEXT",
            "DEVDIARY_ATTRIBUTION_CONTEXT",
            "DEVDIARY_CAPTURE_ID",
        ] {
            assert!(
                !fields
                    .iter()
                    .any(|f| f.starts_with(format!("{name}=").as_bytes())),
                "{helper} retained {name}"
            );
        }
        for name in ["DECLARED_RECEIVER_TOKEN", "ACTUAL_RECEIVER_TOKEN"] {
            assert_eq!(
                fields
                    .iter()
                    .any(|f| f.starts_with(format!("{name}=").as_bytes())),
                !required,
                "{helper}: {name}"
            );
        }
        assert!(
            fields.contains(&b"UNRELATED_FIXTURE=x\xff".as_slice()),
            "{helper} lost unrelated raw bytes"
        );
        for (name, value) in [
            ("GIT_AUTHOR_NAME", "Alice"),
            ("GIT_AUTHOR_EMAIL", "alice@example.invalid"),
            ("GIT_COMMITTER_NAME", "Alice"),
            ("GIT_COMMITTER_EMAIL", "alice@example.invalid"),
        ] {
            let expected = if helper == "actor" || helper == "launcher" {
                value
            } else {
                "inherited@example.invalid"
            };
            assert!(
                fields.contains(&format!("{name}={expected}").as_bytes()),
                "{helper}: {name}"
            );
        }
        if helper == "actor" {
            for (name, value) in [
                ("XDG_RUNTIME_DIR", &original_runtime),
                ("DBUS_SESSION_BUS_ADDRESS", &original_bus),
            ] {
                let prefix = format!("{name}=").into_bytes();
                let actual = fields
                    .iter()
                    .find(|v| v.starts_with(&prefix))
                    .map(|v| &v[prefix.len()..]);
                assert_eq!(
                    actual,
                    value.as_ref().map(|v| v.as_bytes()),
                    "actor runtime {name}"
                );
            }
        } else {
            assert!(fields
                .contains(&format!("XDG_RUNTIME_DIR={}", p.join("runtime").display()).as_bytes()));
            assert!(fields.contains(
                &format!(
                    "DBUS_SESSION_BUS_ADDRESS=unix:path={}/runtime/bus",
                    p.display()
                )
                .as_bytes()
            ));
        }
    }
    h.empty(&report.record);
    let (mut store, lock) = crate::allocate::locked(&h.config).unwrap();
    drop(lock);
    assert_eq!(
        crate::run_recovery::recover_with_config(
            &mut store,
            &report.record.request.identity().run,
            &h.driver,
            &h.config
        )
        .unwrap(),
        crate::run_recovery::RecoveryState::Closed
    );
}
#[test]
fn all_off_commands_filter_credentials_without_resetting_io() {
    use std::os::unix::ffi::OsStringExt;
    for required in [false, true] {
        for runtime in [
            None,
            Some(std::ffi::OsString::from("original-runtime")),
            Some(std::ffi::OsString::from_vec(vec![b'x', 0xff])),
        ] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("LC_ALL", "C")
                .args([
                    "--exact",
                    "attribution_gap::tests::fixture_child",
                    "--nocapture",
                ])
                .env(
                    "GAP_ENV_FIXTURE",
                    if required { "required" } else { "ordinary" },
                )
                .env_remove("GAP_SCOPE_CONTEXT")
                .env_remove("GAP_CLI_ARGUMENTS")
                .env(
                    "UNRELATED_FIXTURE",
                    std::ffi::OsString::from_vec(vec![b'x', 0xff]),
                );
            for name in [
                "DECLARED_RECEIVER_TOKEN",
                "ACTUAL_RECEIVER_TOKEN",
                "AGENT_ATTRIBUTION_CONTEXT",
                "DEVDIARY_ATTRIBUTION_CONTEXT",
                "DEVDIARY_CAPTURE_ID",
                "GIT_AUTHOR_NAME",
                "GIT_AUTHOR_EMAIL",
                "GIT_COMMITTER_NAME",
                "GIT_COMMITTER_EMAIL",
            ] {
                child.env(name, "inherited@example.invalid");
            }
            for name in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
                if let Some(value) = &runtime {
                    child.env(name, value);
                } else {
                    child.env_remove(name);
                }
            }
            let result = child.output().unwrap();
            assert!(
                result.status.success(),
                "isolated helper environment required={required} runtime={runtime:?}: {} {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
    for required in [false, true] {
        let (_temp, config, _a, root, argv) = materialized(required);
        let (_store, result) = super::begin(&config, &root, &argv).unwrap();
        let super::BeginGap::Created(live) = result else {
            panic!("Created required")
        };
        let binding = test_run_fixture::binding(&root);
        let os = test_run_fixture::ClosureOs::new(&root, &binding);
        let filtered = os.driver.for_gap(&live.removal_policy());
        os.driver.assert_same_gap_io_and_limits(&filtered);
        let mut command = std::process::Command::new("/usr/bin/env");
        command.arg("-0").env_clear();
        for name in [
            "DECLARED_RECEIVER_TOKEN",
            "ACTUAL_RECEIVER_TOKEN",
            "AGENT_ATTRIBUTION_CONTEXT",
            "DEVDIARY_ATTRIBUTION_CONTEXT",
            "DEVDIARY_CAPTURE_ID",
        ] {
            command.env(name, "fixture-only");
        }
        let unrelated = std::ffi::OsString::from_vec(vec![b'x', 0xff]);
        command.env("UNRELATED_FIXTURE", &unrelated);
        for name in [
            "GIT_AUTHOR_NAME",
            "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME",
            "GIT_COMMITTER_EMAIL",
        ] {
            command.env(name, "declared-git");
        }
        filtered.apply_manager_context(&mut command).unwrap();
        let output = command.output().unwrap();
        assert!(output.status.success());
        let entries = output.stdout.split(|byte| *byte == 0).collect::<Vec<_>>();
        for name in [
            "AGENT_ATTRIBUTION_CONTEXT",
            "DEVDIARY_ATTRIBUTION_CONTEXT",
            "DEVDIARY_CAPTURE_ID",
        ] {
            assert!(
                !entries
                    .iter()
                    .any(|entry| entry.starts_with(format!("{name}=").as_bytes())),
                "Off retained {name}"
            );
        }
        for name in ["DECLARED_RECEIVER_TOKEN", "ACTUAL_RECEIVER_TOKEN"] {
            assert_eq!(
                entries
                    .iter()
                    .any(|entry| entry.starts_with(format!("{name}=").as_bytes())),
                !required
            );
        }
        assert!(entries.contains(&b"UNRELATED_FIXTURE=x\xff".as_slice()));
        for name in [
            "GIT_AUTHOR_NAME",
            "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME",
            "GIT_COMMITTER_EMAIL",
        ] {
            assert!(entries.contains(&format!("{name}=declared-git").as_bytes()));
        }
    }
}

#[test]
fn event_namespace_is_reserved_in_both_orders() {
    for route in [
        "generated_checkout",
        "finish_operation",
        "ordinary_run",
        "ordinary_group",
        "adopted_run",
        "adopted_group",
        "adopted_operation",
        "capture_operation",
    ] {
        let h = ScopeHarness::new(false);
        let report = crate::supervisor::supervise_off(
            &h.config,
            h.command.clone(),
            &h.driver,
            Some(h.io()),
            &crate::supervisor::CancelToken::default(),
            |boundary, record| {
                if boundary == crate::supervisor::Boundary::RootTerminal {
                    h.empty(record);
                }
            },
        )
        .unwrap();
        let event = uuid::Uuid::parse_str(&report.gap.unwrap().event_id.to_string()).unwrap();
        let mut start = h.allocation.request.clone();
        start.operation = uuid::Uuid::now_v7();
        start.task = "namespace-target".into();
        start.branch = Some("namespace-target".into());
        let target = crate::allocate::start(&h.config, start).unwrap();
        let (mut store, lock) = crate::allocate::locked(&h.config).unwrap();
        drop(lock);
        let before = durable_rows(&store);
        let mut identity = test_run_fixture::request(target.checkout)
            .identity()
            .clone();
        identity.actor = work_contract::ActorId::parse("alice").unwrap();
        if route.ends_with("_run") {
            identity.run = work_contract::RunId::parse(&event.to_string()).unwrap();
        }
        if route.ends_with("_group") {
            identity.group = work_contract::GroupId::parse(&event.to_string()).unwrap();
        }
        let mut input = test_run_fixture::request(target.checkout).input().clone();
        input.boot = target.identity.as_ref().unwrap().boot_id.clone();
        let root = crate::run_journal::RootRunRequest::new(identity.clone(), input).unwrap();
        match route {
            "generated_checkout" => {
                crate::admission::candidate_fixture::CHECKOUT.with(|slot| slot.set(Some(event)));
                assert!(store
                    .reserve(
                        &crate::admission::Reservation {
                            operation: uuid::Uuid::now_v7(),
                            repository: target.request.repository.clone().unwrap(),
                            actor: "alice".into(),
                            owner: "alice".into(),
                            task: "reserved-collision".into()
                        },
                        crate::admission::Limits {
                            repository: 10,
                            owner: 10,
                            available_bytes: Some(100),
                            floor_bytes: 0,
                            warn_bytes: 0
                        }
                    )
                    .is_err());
                assert!(
                    crate::admission::candidate_fixture::CHECKOUT
                        .with(|slot| slot.take())
                        .is_none(),
                    "generated seam not reached"
                );
            }
            "finish_operation" => {
                crate::finish::candidate_fixture::OPERATION.with(|slot| slot.set(Some(event)));
                assert!(crate::finish::finish(&h.config, target.checkout).is_err());
                assert!(
                    crate::finish::candidate_fixture::OPERATION
                        .with(|slot| slot.take())
                        .is_none(),
                    "finish candidate seam not reached"
                );
            }
            "ordinary_run" | "ordinary_group" => {
                assert!(store.begin_run(&root).is_err());
            }
            "adopted_run" | "adopted_group" | "adopted_operation" => {
                let request:crate::adopted::AdoptedRequest=serde_json::from_value(serde_json::json!({"identity":identity,"operation":if route=="adopted_operation" {event}else{uuid::Uuid::now_v7()},"source":"sdk","session":"namespace-session","agent":null})).unwrap();
                assert!(store.begin_adopted(&request).is_err());
            }
            "capture_operation" => {
                let (_temp, mut cfg, _, _, _) = materialized(true);
                cfg.supervisor = h.config.supervisor.clone();
                let spec = cfg
                    .capture_spec(
                        &root,
                        &target,
                        event,
                        vec![target.request.task.clone()],
                        None,
                    )
                    .unwrap();
                assert!(store.begin_captured_run(&root, &spec).is_err());
            }
            _ => unreachable!(),
        }
        assert_eq!(
            durable_rows(&store),
            before,
            "reverse public {route} mutated state"
        );
    }
    {
        let h = ScopeHarness::new(false);
        crate::supervisor::supervise_off(
            &h.config,
            h.command.clone(),
            &h.driver,
            Some(h.io()),
            &crate::supervisor::CancelToken::default(),
            |boundary, record| {
                if boundary == crate::supervisor::Boundary::PermitAttempt {
                    let (mut store, lock) = crate::allocate::locked(&h.config).unwrap();
                    drop(lock);
                    let event = super::read_record(&store.conn, &record.request)
                        .unwrap()
                        .event_id;
                    let mut child = declared_child(&record.request, None);
                    child.run = work_contract::RunId::parse(&event).unwrap();
                    let before = durable_rows(&store);
                    assert!(store.register_child(&record.request, &child).is_err());
                    assert_eq!(durable_rows(&store), before);
                }
                if boundary == crate::supervisor::Boundary::RootTerminal {
                    h.empty(record);
                }
            },
        )
        .unwrap();
    }
    for collision in ["checkout", "operation", "run", "group"] {
        let (_temp, config, a, root, argv) = ordinary();
        let (store, _) = super::begin(&config, &root, &argv).unwrap();
        let mut record = super::read_record(&store.conn, &root).unwrap();
        record.event_id = match collision {
            "checkout" => a.checkout.to_string(),
            "operation" => a.request.operation.to_string(),
            "run" => root.identity().run.to_string(),
            _ => root.identity().group.to_string(),
        };
        record.event = super::event(&record.event_id).unwrap();
        let bytes = super::encode(&record).unwrap();
        let hash = sha2::Sha256::digest(bytes.as_bytes());
        store
            .conn
            .execute(
                "UPDATE attribution_gaps SET event_id=?1,record=?2,fingerprint=?3",
                rusqlite::params![record.event_id, bytes, hash.as_slice()],
            )
            .unwrap();
        assert!(
            store.run_snapshot(&root.identity().run).is_err(),
            "global Gap event namespace collision with {collision} must refuse historical reads"
        );
    }
    for column in [
        "checkout",
        "allocation",
        "writer",
        "run",
        "run_group",
        "group",
        "child",
        "adopted_group",
        "adopted_run",
        "adopted_operation",
        "finish",
        "capture",
    ] {
        let (_temp, store, checkout) = test_run_fixture::fixture();
        store.conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        let event = uuid::Uuid::now_v7().to_string();
        let other = uuid::Uuid::now_v7().to_string();
        match column {
            "checkout" => {
                store
                    .conn
                    .execute("UPDATE checkouts SET id=?1", [&event])
                    .unwrap();
            }
            "allocation" => {
                store
                    .conn
                    .execute("UPDATE checkouts SET operation=?1", [&event])
                    .unwrap();
            }
            "writer" => {
                store
                    .conn
                    .execute(
                        "INSERT INTO writers VALUES(?1,?2)",
                        (checkout.to_string(), &event),
                    )
                    .unwrap();
            }
            "run" | "run_group" => {
                let (run, group) = if column == "run" {
                    (&event, &other)
                } else {
                    (&other, &event)
                };
                store.conn.execute("INSERT INTO runs(id,group_id,run_ref,request,stage) VALUES(?1,?2,'fixture','{}','intent')", (run,group)).unwrap();
            }
            "group" => {
                store.conn.execute("INSERT INTO run_groups(id,checkout,mode,revision) VALUES(?1,?2,'supervised',1)", (&event,checkout.to_string())).unwrap();
            }
            "child" => {
                store.conn.execute("INSERT INTO run_participants(id,group_id,run_ref,parent_run,request,enrollment,depth) VALUES(?1,?2,'fixture',?2,'{}','pending',1)", (&event,&other)).unwrap();
            }
            "adopted_group" | "adopted_run" | "adopted_operation" => {
                let group = if column == "adopted_group" {
                    event.clone()
                } else {
                    uuid::Uuid::now_v7().to_string()
                };
                let run = if column == "adopted_run" {
                    event.clone()
                } else {
                    uuid::Uuid::now_v7().to_string()
                };
                let operation = if column == "adopted_operation" {
                    event.clone()
                } else {
                    uuid::Uuid::now_v7().to_string()
                };
                store.conn.execute("INSERT INTO adopted_groups(id,checkout,run_id,run_ref,operation,request,revision) VALUES(?1,?2,?3,'fixture',?4,'{}',1)", rusqlite::params![group,checkout.to_string(),run,operation]).unwrap();
            }
            "finish" => {
                store
                    .conn
                    .execute(
                        "INSERT INTO task_finishes VALUES(?1,?2,'{}')",
                        (checkout.to_string(), &event),
                    )
                    .unwrap();
            }
            "capture" => {
                store.conn.execute("INSERT INTO capture_runs(run,group_id,checkout,operation,spec,fingerprint,intent_wall,preparation_revision) VALUES(?1,?2,?3,?4,'{}',zeroblob(32),'fixture',1)", rusqlite::params![other,uuid::Uuid::now_v7().to_string(),checkout.to_string(),event]).unwrap();
            }
            _ => unreachable!(),
        }
        let changes = store.conn.total_changes();
        assert!(
            super::exclude_new_event(&store.conn, &event).is_err(),
            "event collides with {column}"
        );
        assert_eq!(store.conn.total_changes(), changes);
    }
    let (_temp, config, a, root, argv) = ordinary();
    let (mut store, _) = super::begin(&config, &root, &argv).unwrap();
    let event = super::read_record(&store.conn, &root).unwrap().event_id;
    store
        .conn
        .execute("UPDATE attribution_gaps SET record='{'", [])
        .unwrap();
    let event_id = uuid::Uuid::parse_str(&event).unwrap();
    let before = durable_rows(&store);
    assert!(crate::store::exclude_journal_identity(&store.conn, event_id).is_err());
    assert!(crate::capture_journal::exclude_operation(&store.conn, &event).is_err());
    assert!(store.acquire_writer(a.checkout, event_id).is_err());
    assert!(store
        .reserve(
            &crate::admission::Reservation {
                operation: event_id,
                repository: a.request.repository.clone().unwrap(),
                actor: "alice".into(),
                owner: "alice".into(),
                task: "other".into(),
            },
            crate::admission::Limits {
                repository: 10,
                owner: 10,
                available_bytes: Some(100),
                floor_bytes: 0,
                warn_bytes: 0
            }
        )
        .is_err());
    assert_eq!(
        durable_rows(&store),
        before,
        "corrupt payload must still reserve event namespace"
    );
}

fn recovery_runtime_text(config: &crate::config::Config) -> String {
    let p = config.supervisor.as_ref().unwrap();
    format!("\n[supervisor]\nruntime_directory={:?}\nbus_address={:?}\nruntime_max_seconds={}\npreexec_ms={}\nclosure_grace_ms={}\ncancel_grace_ms={}\n",p.runtime_directory,p.bus_address,p.runtime_max_seconds,p.preexec_ms,p.closure_grace_ms,p.cancel_grace_ms)
}
fn recovery_target_text(host: &crate::capture_config::HostCaptureConfig) -> String {
    format!("\n[allocation]\nrepository_limit=10\nowner_limit=10\nfloor_bytes=0\nwarn_bytes=0\ncapture_sink='devdiary'\n[capture]\nexecutable={:?}\nregistry={:?}\nstate_dir={:?}\ntimeout_ms={}\nresponse_cap={}\nregistry_sha256={:?}\nendpoint_identity={:?}\nreceiver_credential_names={:?}\n[capture.actor_refs]\nalice='actor:alice'\n",host.executable,host.registry,host.state_dir,host.timeout_ms,host.response_cap,host.registry_sha256,host.endpoint_identity,host.receiver_credential_names)
}
fn authority_text(config: &crate::config::Config) -> String {
    format!(
        "store_dir={:?}\ntrusted_registry={:?}\nroots={:?}\n",
        config.store_dir.as_ref().unwrap(),
        config.trusted_registry.as_ref().unwrap(),
        config.roots
    )
}
fn shared_cli(temp: &std::path::Path, text: &str, args: &[String]) -> std::process::Output {
    let config = temp.join("cli-config.toml");
    let channel = temp.join("cli-argv.json");
    std::fs::write(&config, text).unwrap();
    let bytes = serde_json::to_vec(args).unwrap();
    assert!(bytes.len() <= 1024 * 1024);
    std::fs::write(&channel, bytes).unwrap();
    std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "attribution_gap::tests::fixture_child",
            "--nocapture",
        ])
        .env("WORK_CONFIG", config)
        .env("GAP_CLI_ARGUMENTS", channel)
        .env_remove("GAP_SCOPE_CONTEXT")
        .output()
        .unwrap()
}
fn off_argv(temp: &std::path::Path, command: &crate::supervisor::RootCommand) -> Vec<String> {
    let chain = temp.join("cli-chain.json");
    std::fs::write(
        &chain,
        serde_json::to_vec(&command.execution_chain).unwrap(),
    )
    .unwrap();
    let mut args = vec![
        "run".into(),
        command.checkout.to_string(),
        "--run-id".into(),
        command.run_id.to_string(),
        "--actor".into(),
        "alice".into(),
        "--execution-chain".into(),
        chain.to_str().unwrap().into(),
        "--attribution".into(),
        "off".into(),
        "--".into(),
    ];
    args.extend(command.argv.iter().map(|a| a.to_str().unwrap().to_owned()));
    args
}
#[test]
fn off_existing_precedes_profiles_registry_and_identifier_generation() {
    // Genuine durable A/B histories through the same public parser/dispatcher
    // used by cli::run, in isolated current-test-executable children (not work binary E2E).
    for required in [false, true] {
        let (temp, config, a, root, argv) = materialized(required);
        let (store, _) = super::begin(&config, &root, &argv).unwrap();
        let command = crate::supervisor::RootCommand {
            checkout: a.checkout,
            actor: Some("alice".into()),
            run_id: uuid::Uuid::parse_str(&root.identity().run.to_string()).unwrap(),
            execution_chain: root.identity().execution_chain.clone(),
            argv,
        };
        let event = super::read_record(&store.conn, &root).unwrap().event_id;
        let before = durable_rows(&store);
        let args = off_argv(temp.path(), &command);
        for actors in ["", "actors={}", "actors=42"] {
            let text = format!(
                "{}{}{actors}\n",
                authority_text(&config),
                recovery_runtime_text(&config)
            );
            assert!(
                crate::config::Config::from_text(&text).is_err(),
                "normal execution loader must remain strict"
            );
            let result = shared_cli(temp.path(), &text, &args);
            let diagnostic = String::from_utf8_lossy(&result.stderr);
            assert!(
                diagnostic.contains(&format!("event_id={event}")),
                "Existing lost behind irrelevant execution policy ({actors}): {diagnostic}"
            );
            assert!(diagnostic.contains("receipt=true"));
            assert_eq!(durable_rows(&store), before);
            let mut fresh = args.clone();
            fresh[3] = uuid::Uuid::now_v7().to_string();
            let result = shared_cli(temp.path(), &text, &fresh);
            assert!(!result.status.success());
            assert!(!String::from_utf8_lossy(&result.stderr).contains("event_recorded=true"));
            assert_eq!(durable_rows(&store), before);
        }
    }
    for required in [false, true] {
        let h = ScopeHarness::new(required);
        let report = crate::supervisor::supervise_off(
            &h.config,
            h.command.clone(),
            &h.driver,
            Some(h.io()),
            &crate::supervisor::CancelToken::default(),
            |boundary, record| {
                if boundary == crate::supervisor::Boundary::RootTerminal {
                    h.empty(record);
                }
            },
        )
        .unwrap();
        assert!(report.record.closed);
        let (store, lock) = crate::allocate::locked(&h.config).unwrap();
        drop(lock);
        let before = durable_rows(&store);
        let text = format!(
            "{}{}actors=42\n",
            authority_text(&h.config),
            recovery_runtime_text(&h.config)
        );
        let args = off_argv(h.temp.path(), &h.command);
        let result = shared_cli(h.temp.path(), &text, &args);
        assert!(String::from_utf8_lossy(&result.stderr)
            .contains(&format!("event_id={}", report.gap.unwrap().event_id)));
        assert_eq!(durable_rows(&store), before);
        let mut conflict = args.clone();
        conflict.push("different".into());
        let result = shared_cli(h.temp.path(), &text, &conflict);
        assert!(!result.status.success());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("event_recorded=true"));
        assert_eq!(durable_rows(&store), before);
        store
            .conn
            .execute("UPDATE attribution_gaps SET record='{'", [])
            .unwrap();
        let before = durable_rows(&store);
        let result = shared_cli(h.temp.path(), &text, &args);
        assert!(!result.status.success());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("event_recorded=true"));
        assert_eq!(durable_rows(&store), before);
    }
    for required in [false, true] {
        let (_temp, mut config, a, root, argv) = materialized(required);
        let (store, _) = super::begin(&config, &root, &argv).unwrap();
        let command = crate::supervisor::RootCommand {
            checkout: a.checkout,
            actor: Some("alice".into()),
            run_id: uuid::Uuid::parse_str(&root.identity().run.to_string()).unwrap(),
            execution_chain: root.identity().execution_chain.clone(),
            argv,
        };
        assert!(
            crate::supervisor::existing_report(&config, &command).is_err(),
            "default history must not acknowledge Off even while task is open"
        );
        let before = durable_rows(&store);
        if let Some(host) = &config.capture {
            std::fs::remove_file(&host.registry).unwrap();
        }
        config.supervisor = None;
        config.capture = None;
        let result = crate::supervisor::off_existing_report(&config, &command)
            .unwrap()
            .expect("matching Off must return before current profiles/registry/runtime");
        assert!(result.existing);
        assert_eq!(result.record.request, root);
        assert_eq!(durable_rows(&store), before);
        let mut conflict = command.clone();
        conflict.argv.push("different".into());
        assert!(crate::supervisor::off_existing_report(&config, &conflict).is_err());
    }
}

#[test]
fn admission_reobserves_physical_identity_outside_guards() {
    use std::time::Duration;
    for case in [
        "unchanged",
        "branch",
        "head",
        "directory",
        "marker",
        "registry",
        "source",
        "owner",
        "requirement",
        "age",
    ] {
        let (temp, config, a, root, argv) = materialized(case == "registry");
        let sql = Connection::open(temp.path().join("private/store.sqlite")).unwrap();
        sql.busy_timeout(Duration::ZERO).unwrap();
        let lock_path = config.store_dir.clone().unwrap();
        let registry = config.capture.as_ref().map(|h| h.registry.clone());
        let observations = std::rc::Rc::new(std::cell::Cell::new(0));
        let count = observations.clone();
        let _guard = observing_admission(move |stage, conn| {
            assert!(
                conn.is_autocommit(),
                "physical observation retains SQL snapshot"
            );
            sql.execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
                .expect("physical observation retains SQL writer");
            drop(
                crate::allocate::lifecycle_lock(&lock_path)
                    .expect("physical observation retains allocator lock"),
            );
            count.set(count.get() + 1);
            if stage != "reinspect" {
                return;
            }
            match case {
                "branch" => {
                    crate::identity::query(
                        &a.destination,
                        &["symbolic-ref", "HEAD", "refs/heads/changed"],
                    )
                    .unwrap();
                }
                "head" => {
                    crate::identity::query(
                        &a.destination,
                        &["commit", "--allow-empty", "-m", "changed"],
                    )
                    .unwrap();
                }
                "directory" => physical_fixture::replace_directory(&a.destination),
                "marker" => std::fs::write(
                    a.identity
                        .as_ref()
                        .unwrap()
                        .private_git_dir
                        .join("work-lease.json"),
                    "{}",
                )
                .unwrap(),
                "registry" => std::fs::write(registry.as_ref().unwrap(), "{}").unwrap(),
                "source" => {
                    sql.execute("UPDATE checkouts SET repository='/different/source'", [])
                        .unwrap();
                }
                "owner" => {
                    sql.execute("UPDATE checkouts SET owner='different'", [])
                        .unwrap();
                }
                "requirement" => {
                    sql.execute("INSERT INTO capture_requirements SELECT id,operation,'portable-capture',1,1 FROM checkouts", []).unwrap();
                }
                "age" => std::thread::sleep(Duration::from_millis(2100)),
                "unchanged" => (),
                _ => unreachable!(),
            }
        });
        let result = super::begin(&config, &root, &argv);
        assert_eq!(result.is_ok(), case == "unchanged", "{case}");
        assert_eq!(observations.get(), 2, "{case}");
        if case != "unchanged" {
            let sql = Connection::open(temp.path().join("private/store.sqlite")).unwrap();
            for table in ["runs", "run_groups", "writers", "attribution_gaps"] {
                let count: i64 = sql
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                    .unwrap();
                assert_eq!(count, 0, "{case}: {table}");
            }
        }
    }
}

#[test]
fn required_gap_vetoes_both_allocation_retries_before_mutation() {
    for case in [
        "malformed_operation",
        "malformed_checkout",
        "malformed_load",
        "missing_operation",
        "operation",
        "checkout",
        "source_operation",
        "source_checkout",
        "reconcile",
        "save_pending",
        "save_ready",
        "corrupt_requirement",
        "corrupt_gap",
        "corrupt_marker",
    ] {
        let (_temp, config, mut a, root, argv) = materialized(true);
        let (mut store, _) = super::begin(&config, &root, &argv).unwrap();
        if case.contains("checkout") {
            store
                .conn
                .execute("UPDATE checkouts SET state='partial'", [])
                .unwrap();
        }
        if case.starts_with("source_") {
            std::fs::write(
                a.identity
                    .as_ref()
                    .unwrap()
                    .private_git_dir
                    .join("work-lease.json"),
                "{}",
            )
            .unwrap();
        }
        match case {
            "malformed_operation" | "malformed_checkout" | "malformed_load" => {
                store
                    .conn
                    .execute("UPDATE allocations SET record='{'", [])
                    .unwrap();
            }
            "missing_operation" => {
                store.conn.execute("DELETE FROM allocations", []).unwrap();
            }
            "corrupt_requirement" => {
                store
                    .conn
                    .execute("UPDATE capture_requirements SET revision=2", [])
                    .unwrap();
            }
            "corrupt_gap" => {
                store
                    .conn
                    .execute("UPDATE attribution_gaps SET record='{}'", [])
                    .unwrap();
            }
            "corrupt_marker" => {
                store
                    .conn
                    .execute("UPDATE runs SET request='{'", [])
                    .unwrap();
            }
            _ => (),
        }
        let before = durable_rows(&store);
        let result = match case {
            "malformed_load" => crate::allocate::load(&mut store, a.request.operation).map(|_| ()),
            "reconcile" => crate::recovery::reconcile(&mut store, &mut a),
            "save_pending" => crate::allocate::save(&mut store, &a),
            "save_ready" => {
                a.stage = "ready".into();
                a.reason = None;
                crate::allocate::save(&mut store, &a)
            }
            _ => {
                let mut request = a.request.clone();
                if case.contains("checkout") {
                    request.operation = uuid::Uuid::now_v7();
                }
                crate::allocate::start(&config, request).map(|_| ())
            }
        };
        assert!(
            result.is_err(),
            "legacy {case} must refuse RequiredInitial Gap"
        );
        assert_eq!(
            durable_rows(&store),
            before,
            "{case} mutated durable state before refusal"
        );
    }
}

#[test]
fn supported_classes_and_complete_history_fences() {
    for case in [
        "selected_ready",
        "unknown_sink",
        "missing_host",
        "missing_profile",
        "missing_actor_mapping",
        "declared_reserved",
        "declared_overcap",
        "union_atcap",
    ] {
        let (_temp, mut config, _a, root, argv) = materialized(case != "selected_ready");
        let selected = (case == "selected_ready").then(|| materialized(true));
        match case {
            "selected_ready" => {
                config.capture = selected.as_ref().unwrap().1.capture.clone();
                config.allocation.as_mut().unwrap().capture_sink = Some("devdiary".into());
            }
            "unknown_sink" => {
                config.allocation.as_mut().unwrap().capture_sink = Some("unknown".into())
            }
            "missing_host" => config.capture = None,
            "missing_profile" => config.supervisor.as_mut().unwrap().actors.clear(),
            "missing_actor_mapping" => config.capture.as_mut().unwrap().actor_refs.clear(),
            "declared_reserved" => {
                config.capture.as_mut().unwrap().receiver_credential_names =
                    vec!["GIT_AUTHOR_NAME".into()]
            }
            "declared_overcap" => {
                config.capture.as_mut().unwrap().receiver_credential_names =
                    (0..129).map(|i| format!("DECLARED_{i}")).collect()
            }
            "union_atcap" => {
                config.capture.as_mut().unwrap().receiver_credential_names =
                    (0..128).map(|i| format!("DECLARED_{i}")).collect()
            }
            _ => unreachable!(),
        }
        let (store, lock) = crate::allocate::locked(&config).unwrap();
        drop(lock);
        let before = durable_rows(&store);
        let result = super::begin(&config, &root, &argv);
        if case == "union_atcap" {
            let (_, super::BeginGap::Created(live)) = result.unwrap() else {
                panic!("new supported128+1 union must admit")
            };
            assert_eq!(live.removal_policy().receivers().len(), 129);
        } else {
            assert!(result.is_err(), "unsupported declaration {case} admitted");
            assert_eq!(durable_rows(&store), before, "{case} mutated authority");
        }
    }
    for corruption in ["root", "writer", "gap_json"] {
        let (_temp, config, a, first, argv) = ordinary();
        let (store, _) = super::begin(&config, &first, &argv).unwrap();
        let mut start = a.request.clone();
        start.operation = uuid::Uuid::now_v7();
        start.task = "other-task".into();
        start.branch = Some("other-topic".into());
        let second = crate::allocate::start(&config, start).unwrap();
        let mut identity = first.identity().clone();
        identity.checkout = work_contract::CheckoutId::parse(&second.checkout.to_string()).unwrap();
        identity.run = work_contract::RunId::parse(&uuid::Uuid::now_v7().to_string()).unwrap();
        identity.group = work_contract::GroupId::parse(&uuid::Uuid::now_v7().to_string()).unwrap();
        identity.run_ref = work_contract::RunRef::parse("unrelated-target").unwrap();
        let root =
            crate::run_journal::RootRunRequest::new(identity, first.input().clone()).unwrap();
        match corruption {
            "root" => {
                store
                    .conn
                    .execute("UPDATE runs SET request='{}'", [])
                    .unwrap();
            }
            "writer" => {
                store.conn.execute("DELETE FROM writers", []).unwrap();
            }
            _ => {
                store
                    .conn
                    .execute("UPDATE attribution_gaps SET record='{'", [])
                    .unwrap();
            }
        }
        let before = durable_rows(&store);
        let result = super::begin(&config, &root, &argv);
        if corruption == "gap_json" {
            assert!(result.is_ok(), "unrelated Gap payloads must not be parsed");
        } else {
            assert!(
                result.is_err(),
                "global base/{corruption} corruption was ignored by Gap admission"
            );
            assert_eq!(durable_rows(&store), before);
        }
    }
    // Raw fences must see markers in every preserved outer Root wire shape,
    // including malformed positional-marker attempts, without a Gap row.
    for outer_sequence in [false, true] {
        for marker in [
            serde_json::json!("off"),
            serde_json::Value::Null,
            serde_json::json!({}),
        ] {
            let (_temp, mut store, checkout) = test_run_fixture::fixture();
            let root = test_run_fixture::request(checkout);
            store.begin_run(&root).unwrap();
            let mut value = serde_json::to_value(&root).unwrap();
            value["input"]["attribution"] = marker;
            if outer_sequence {
                value = serde_json::json!([value["identity"], value["input"]]);
            }
            store
                .conn
                .execute("UPDATE runs SET request=?1", [value.to_string()])
                .unwrap();
            let before = durable_rows(&store);
            assert!(
                super::raw_history(&store.conn, checkout).unwrap(),
                "raw marker hidden by outer sequence={outer_sequence}"
            );
            assert!(super::guard_legacy_allocation(&store.conn, checkout).is_err());
            assert_eq!(durable_rows(&store), before);
        }
    }
    for outer_sequence in [false, true] {
        for sixth in [false, true] {
            let (_temp, mut store, checkout) = test_run_fixture::fixture();
            let root = test_run_fixture::request(checkout);
            store.begin_run(&root).unwrap();
            let mut value = serde_json::to_value(&root).unwrap();
            let input = &value["input"];
            let mut sequence = vec![
                input["command_digest"].clone(),
                input["input_digest"].clone(),
                input["context_ref"].clone(),
                input["intent_ref"].clone(),
                input["boot"].clone(),
            ];
            if sixth {
                sequence.push(serde_json::Value::Null);
            }
            value["input"] = sequence.into();
            if outer_sequence {
                value = serde_json::json!([value["identity"], value["input"]]);
            }
            store
                .conn
                .execute("UPDATE runs SET request=?1", [value.to_string()])
                .unwrap();
            assert_eq!(
                super::raw_history(&store.conn, checkout).unwrap(),
                sixth,
                "legacy five-field sequences remain marker absent"
            );
        }
    }
    for required in [true, false] {
        let (_temp, config, allocation, root, argv) = materialized(required);
        let (store, result) =
            super::begin(&config, &root, &argv).expect("supported actual allocation must admit");
        assert!(matches!(result, super::BeginGap::Created(_)));
        let (state, ready): (String, bool) = store
            .conn
            .query_row("SELECT state,ready FROM checkouts", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(state, "active");
        assert_eq!(ready, !required);
        let record = super::read_record(&store.conn, &root).unwrap();
        assert_eq!(
            record.delivery,
            if required {
                super::GapDelivery::Pending
            } else {
                super::GapDelivery::NotConfigured
            }
        );
        assert_eq!(record.destination.is_some(), required);
        let stored: String = store
            .conn
            .query_row("SELECT record FROM allocations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            stored,
            serde_json::to_string(&allocation).unwrap(),
            "Off must not promote or rewrite allocation"
        );
        assert_eq!(
            store
                .charged(allocation.request.repository.as_ref().unwrap(), None)
                .unwrap(),
            1
        );
        let captures: i64 = store
            .conn
            .query_row("SELECT count(*) FROM capture_runs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(captures, 0);
    }
    {
        let h = ScopeHarness::new(false);
        let closed = crate::supervisor::supervise_off(
            &h.config,
            h.command.clone(),
            &h.driver,
            Some(h.io()),
            &crate::supervisor::CancelToken::default(),
            |boundary, root| {
                if boundary == crate::supervisor::Boundary::RootTerminal {
                    h.empty(root);
                }
            },
        )
        .unwrap();
        assert!(closed.record.closed);
        let (mut store, lock) = crate::allocate::locked(&h.config).unwrap();
        drop(lock);
        let next = test_run_fixture::request(h.allocation.checkout);
        store
            .begin_run(&next)
            .expect("ordinary root may follow valid closed ordinary Gap");
        store
            .conn
            .execute("UPDATE attribution_gaps SET record='{'", [])
            .unwrap();
        assert!(
            store.run_snapshot(&next.identity().run).is_err(),
            "related Gap corruption was hidden by a different requested root"
        );
    }
    for case in [
        "held",
        "partial",
        "requirement_removed_selection",
        "writer",
        "rootless",
        "orphan",
        "adopted",
        "finish",
        "certificate",
    ] {
        let (_temp, mut config, a, root, argv) =
            materialized(case == "requirement_removed_selection");
        let (store, lock) = crate::allocate::locked(&config).unwrap();
        drop(lock);
        let other = uuid::Uuid::now_v7().to_string();
        match case {
            "held" => {
                store
                    .conn
                    .execute("UPDATE checkouts SET state='held',ready=0", [])
                    .unwrap();
            }
            "partial" => {
                store
                    .conn
                    .execute("UPDATE checkouts SET state='partial',ready=0", [])
                    .unwrap();
            }
            "requirement_removed_selection" => {
                config.allocation.as_mut().unwrap().capture_sink = None
            }
            "writer" => {
                store
                    .conn
                    .execute(
                        "INSERT INTO writers VALUES(?1,?2)",
                        (a.checkout.to_string(), &other),
                    )
                    .unwrap();
            }
            "rootless" => {
                store.conn.execute("INSERT INTO run_groups(id,checkout,mode,revision,closed) VALUES(?1,?2,'supervised',1,1)", (&other,a.checkout.to_string())).unwrap();
            }
            "orphan" => {
                store.conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
                store.conn.execute("INSERT INTO runs(id,group_id,run_ref,request,stage) VALUES(?1,?2,'orphan','{}','intent')", (&other,uuid::Uuid::now_v7().to_string())).unwrap();
            }
            "adopted" => {
                store.conn.execute("INSERT INTO adopted_groups(id,checkout,run_id,run_ref,operation,request,revision) VALUES(?1,?2,?3,'adopted',?4,'{}',1)", rusqlite::params![other,a.checkout.to_string(),uuid::Uuid::now_v7().to_string(),uuid::Uuid::now_v7().to_string()]).unwrap();
            }
            "finish" => {
                store
                    .conn
                    .execute(
                        "INSERT INTO task_finishes VALUES(?1,?2,'{}')",
                        (a.checkout.to_string(), other),
                    )
                    .unwrap();
            }
            "certificate" => {
                store.conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
                store
                    .conn
                    .execute(
                        "INSERT INTO capture_readiness VALUES(?1,?2,'{}',1)",
                        (a.checkout.to_string(), other),
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let events = store.pending_events(100).unwrap();
        assert!(super::begin(&config, &root, &argv).is_err(), "{case}");
        let gaps: i64 = store
            .conn
            .query_row("SELECT count(*) FROM attribution_gaps", [], |r| r.get(0))
            .unwrap();
        assert_eq!(gaps, 0, "{case}");
        assert_eq!(store.pending_events(100).unwrap(), events, "{case}");
    }
}

#[test]
fn strict_gap_shape_binding_and_schema14_migration() {
    // Existing unchanged 2/48-root, contained-child durable fixture. Its extra
    // roots are synthetic history, not claims of separate physical executions.
    crate::capture_readiness::tests::many_closed_history(|config, store, allocation, prior| {
        // Reuse populated frozen/certified history before a finish fence exists.
        let before = durable_rows(store);
        let mut identity = prior.identity().clone();
        identity.run = work_contract::RunId::generate();
        identity.group = work_contract::GroupId::generate();
        identity.run_ref = work_contract::RunRef::parse("forbidden-off-after-capture").unwrap();
        let mut input = prior.input().clone();
        input.attribution = Some(crate::run_journal::AttributionDecision::Off);
        let root = crate::run_journal::RootRunRequest::new(identity, input).unwrap();
        for selected in [false, true] {
            let mut invocation = config.clone();
            if !selected {
                invocation.allocation.as_mut().unwrap().capture_sink = None;
            }
            assert!(super::begin(&invocation, &root, &["/usr/bin/true".into()]).is_err());
            assert_eq!(
                durable_rows(store),
                before,
                "frozen/certified history must never become Off"
            );
        }
        crate::finish::finish(config, allocation.checkout).unwrap();
        let tables = [
            "runs",
            "run_groups",
            "run_participants",
            "capture_runs",
            "capture_requirements",
            "capture_finalizations",
            "capture_readiness",
            "task_finishes",
            "allocations",
            "checkouts",
            "outbox",
        ];
        let snapshot = || {
            tables
                .iter()
                .map(|table| {
                    let mut stmt = store
                        .conn
                        .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                        .unwrap();
                    let columns = stmt.column_count();
                    stmt.query_map([], |row| {
                        (0..columns)
                            .map(|i| row.get::<_, rusqlite::types::Value>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap()
                })
                .collect::<Vec<_>>()
        };
        let before = snapshot();
        for (table, rows) in tables.iter().zip(&before) {
            assert!(
                !rows.is_empty(),
                "populated migration evidence missing {table}"
            );
        }
        store
            .conn
            .execute_batch("DROP TABLE attribution_gaps; PRAGMA user_version=13;")
            .unwrap();
        let migrated = Store::open_registered(
            config.trusted_registry.as_ref().unwrap(),
            config.store_dir.as_ref().unwrap(),
            &config.roots,
        )
        .unwrap();
        assert_eq!(
            snapshot(),
            before,
            "migration rewrote existing durable bytes"
        );
        assert_eq!(
            migrated
                .conn
                .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            14
        );
        assert_eq!(
            migrated
                .conn
                .query_row("SELECT count(*) FROM attribution_gaps", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    });
    for case in [
        "missing",
        "absent_marker",
        "delivery",
        "origin",
        "event",
        "version",
        "fingerprint",
        "unknown",
        "positional",
        "stray",
        "reserved_name",
        "missing_actual",
        "bad_pin",
    ] {
        let (_temp, config, _a, root, argv) = materialized(matches!(
            case,
            "reserved_name" | "missing_actual" | "bad_pin"
        ));
        let (store, _) = super::begin(&config, &root, &argv).unwrap();
        let bytes: String = store
            .conn
            .query_row("SELECT record FROM attribution_gaps", [], |r| r.get(0))
            .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&bytes).unwrap();
        match case {
            "missing" => {
                store
                    .conn
                    .execute("DELETE FROM attribution_gaps", [])
                    .unwrap();
            }
            "absent_marker" => {
                let mut value = serde_json::to_value(&root).unwrap();
                value["input"]
                    .as_object_mut()
                    .unwrap()
                    .remove("attribution");
                store
                    .conn
                    .execute(
                        "UPDATE runs SET request=?1",
                        [serde_json::to_string(&value).unwrap()],
                    )
                    .unwrap();
            }
            "stray" => {
                store
                    .conn
                    .execute_batch("PRAGMA foreign_keys=OFF; DELETE FROM runs;")
                    .unwrap();
            }
            "fingerprint" => {
                store
                    .conn
                    .execute("UPDATE attribution_gaps SET fingerprint=zeroblob(32)", [])
                    .unwrap();
            }
            _ => {
                match case {
                    "delivery" => value["delivery"] = "pending".into(),
                    "origin" => value["origin"] = "required_initial".into(),
                    "event" => value["event"] = "{}".into(),
                    "version" => value["format_version"] = 2.into(),
                    "unknown" => value["extra"] = true.into(),
                    "positional" => value = serde_json::json!([]),
                    "reserved_name" => {
                        value["destination"]["actual_name"] = "GIT_AUTHOR_NAME".into();
                        value["destination"]["removal_names"] =
                            serde_json::json!(["DECLARED_RECEIVER_TOKEN", "GIT_AUTHOR_NAME"]);
                    }
                    "missing_actual" => {
                        value["destination"]["removal_names"] =
                            serde_json::json!(["DECLARED_RECEIVER_TOKEN"])
                    }
                    "bad_pin" => value["destination"]["pin"] = "not-a-pin".into(),
                    _ => unreachable!(),
                }
                // Recompute the outer fingerprint: semantic validation must stand alone.
                let bytes = if matches!(case, "unknown" | "positional") {
                    serde_json::to_string(&value).unwrap()
                } else {
                    let typed: super::GapRecord = serde_json::from_value(value).unwrap();
                    serde_json::to_string(&typed).unwrap()
                };
                let fingerprint = sha2::Sha256::digest(bytes.as_bytes());
                store
                    .conn
                    .execute(
                        "UPDATE attribution_gaps SET record=?1,fingerprint=?2",
                        rusqlite::params![bytes, fingerprint.as_slice()],
                    )
                    .unwrap();
            }
        }
        assert!(
            store.run_snapshot(&root.identity().run).is_err(),
            "public Root read accepted {case}"
        );
    }
    let (dir, mut store, checkout) = test_run_fixture::fixture();
    let root = test_run_fixture::request(checkout);
    store.begin_run(&root).unwrap();
    let version: i64 = store
        .conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        version, 14,
        "new authorities must install the additive Gap schema"
    );
    let original: String = store
        .conn
        .query_row("SELECT request FROM runs", [], |r| r.get(0))
        .unwrap();
    let events = store.pending_events(100).unwrap();
    // Construct an authentic schema13 authority, retaining its original payloads.
    store
        .conn
        .execute_batch("DROP TABLE attribution_gaps; PRAGMA user_version=13;")
        .unwrap();
    drop(store);
    let store = test_run_fixture::reopen(&dir).unwrap();
    let migrated: String = store
        .conn
        .query_row("SELECT request FROM runs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(migrated.as_bytes(), original.as_bytes());
    assert_eq!(store.pending_events(100).unwrap(), events);
    let count: i64 = store
        .conn
        .query_row("SELECT count(*) FROM attribution_gaps", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0, "migration must not invent decisions");
    drop(store);
    for malformed in [
        "CREATE VIEW attribution_gaps AS SELECT id AS run FROM runs",
        "CREATE TABLE attribution_gaps(run TEXT PRIMARY KEY, group_id TEXT, checkout TEXT, event_id TEXT, record TEXT, fingerprint BLOB)",
    ] {
        let sql = Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        sql.execute_batch("DROP TABLE attribution_gaps; PRAGMA user_version=13;").unwrap();
        sql.execute_batch(malformed).unwrap();
        assert!(Store::open(&dir.path().join("private"), &[dir.path().join("root")]).is_err());
        let version: i64 = sql.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(version, 13, "failed migration must be atomic");
        if malformed.starts_with("CREATE VIEW") {
            sql.execute_batch("DROP VIEW attribution_gaps").unwrap();
        } else {
            sql.execute_batch("DROP TABLE attribution_gaps").unwrap();
        }
        drop(sql);
        drop(test_run_fixture::reopen(&dir).unwrap());
    }
}
