use super::*;

#[test]
fn identity_refresh_transaction_refuses_durable_fence_inserted_after_preflight() {
    fn git(path: &std::path::Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .current_dir(path)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }
    for fence in ["finish", "capture"] {
        for malformed in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let repo = temp.path().join("repo");
            let root = temp.path().join("root");
            fs::create_dir(&repo).unwrap();
            fs::create_dir(&root).unwrap();
            git(&repo, &["init", "-b", "main"]);
            git(&repo, &["config", "user.name", "Test"]);
            git(&repo, &["config", "user.email", "test@example.invalid"]);
            git(&repo, &["commit", "--allow-empty", "-m", "initial"]);
            let config = Config::from_text(&format!(
            "store_dir = {:?}\ntrusted_registry = {:?}\nroots = [{:?}]\nrepositories = [{:?}]\n[allocation]\nrepository_limit = 10\nowner_limit = 10\nfloor_bytes = 0\nwarn_bytes = 0\n",
            temp.path().join("private"), temp.path().join("registry"), root, repo
        )).unwrap();
            let mut a = start(
                &config,
                Start {
                    operation: Uuid::now_v7(),
                    repository: Some(repo),
                    root: Some(root),
                    actor: Some("actor".into()),
                    owner: None,
                    task: "task".into(),
                    branch: Some("topic".into()),
                    base: "main".into(),
                    reuse_branch: false,
                },
            )
            .unwrap();
            let (mut store, lock) = locked(&config).unwrap();
            drop(lock);
            let guard = crate::checkout_guard::CheckoutGuard::shared(&store, a.checkout).unwrap();
            let observed = observe_checkout(&mut store, a.checkout, &guard).unwrap();
            let lock = lifecycle_lock(&store).unwrap();
            a = verified_checkout_under_lease(&mut store, observed, &lock).unwrap();
            drop(lock);
            // The receipt arrives after successful preflight, but before its final
            // identity transaction. Readiness corruption must not bypass that CAS.
            if fence == "finish" {
                crate::finish::finish(&config, a.checkout).unwrap();
            } else {
                let run = work_contract::RunId::generate();
                let group = work_contract::GroupId::generate();
                let request:crate::run_journal::RootRunRequest=serde_json::from_value(serde_json::json!({"identity":{"checkout":a.checkout,"group":group,"run":run,"run_ref":"run:allocation-race","actor":"root-actor","parent_run_ref":null,"execution_chain":[{"kind":"executor","system":"test"}]},"input":{"command_digest":vec![0;32],"input_digest":vec![0;32],"context_ref":"context","intent_ref":"intent","boot":a.identity.as_ref().unwrap().boot_id}})).unwrap();
                let sink = crate::capture_journal::SinkSnapshot::new(
                    crate::capture_journal::SinkSettings {
                        executable: "/private/capture".into(),
                        registry: "/private/registry".into(),
                        state: "/private/state".into(),
                        timeout: std::time::Duration::from_millis(10),
                        response_cap: 1024,
                        endpoint_identity: "https://receiver.invalid".into(),
                        registry_identity: "registry:v1".into(),
                        receiver_credential_names: vec![],
                        registry_actor_ref: "actor:registered".into(),
                    },
                )
                .unwrap();
                let declaration = crate::capture_bridge::BeginRequest {
                    actor_ref: "actor:registered".into(),
                    run_ref: request.identity().run_ref.as_str().into(),
                    cwd: a.destination.clone(),
                    execution_chain: request.identity().execution_chain.clone(),
                    task_refs: vec![a.request.task.clone()],
                    parent_run_ref: None,
                    key_file: None,
                    source: None,
                    lifecycle: crate::capture_bridge::WorkLifecycle {
                        checkout_id: request.identity().checkout.clone(),
                        mode: work_contract::ExecutionMode::Supervised,
                        group_id: Some(group),
                        operation_id: None,
                    },
                };
                let spec = crate::capture_journal::CaptureSpec::new(
                    Uuid::now_v7(),
                    sink,
                    declaration,
                    crate::capture_bridge::GitProfile::default(),
                )
                .unwrap();
                drop(store.begin_captured_run(&request, &spec).unwrap());
            }
            store
                .conn
                .execute("UPDATE checkouts SET state='active',ready=1", [])
                .unwrap();
            if malformed {
                store
                    .conn
                    .execute(
                        if fence == "finish" {
                            "UPDATE task_finishes SET record='{}'"
                        } else {
                            "UPDATE capture_runs SET spec='{}'"
                        },
                        [],
                    )
                    .unwrap();
            }
            git(
                &a.destination,
                &["commit", "--allow-empty", "-m", "advance"],
            );
            let current = CheckoutIdentity::inspect(&a.destination).unwrap();
            assert_ne!(current.head, a.identity.as_ref().unwrap().head);
            let prior = serde_json::to_string(&a).unwrap();
            let events: i64 = store
                .conn
                .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
                .unwrap();
            assert!(
                refresh_ready_identity(&mut store, &mut a, current).is_err(),
                "{fence} malformed={malformed}"
            );
            assert_eq!(serde_json::to_string(&a).unwrap(), prior);
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT record FROM allocations", [], |r| r
                        .get::<_, String>(0))
                    .unwrap(),
                prior
            );
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                events
            );
            assert!(
                save(&mut store, &a).is_err(),
                "{fence} stale save cannot restore readiness"
            );
        }
    }
}
