use super::*;
use uuid::Uuid;
#[path = "../tests/support/lifecycle_regressions.rs"]
mod fixture;
fn materialized() -> (
    tempfile::TempDir,
    Config,
    Store,
    Allocation,
    RootRunRequest,
    CaptureSpec,
) {
    let (temp, repo, root) = fixture::git_fixture();
    let config=Config::from_text(&format!("store_dir={:?}\ntrusted_registry={:?}\nroots=[{:?}]\nrepositories=[{:?}]\n[allocation]\nrepository_limit=10\nowner_limit=10\nfloor_bytes=0\nwarn_bytes=0\ncapture_sink='devdiary'\n[capture]\nexecutable='/private/capture'\nregistry='/private/registry'\nstate_dir='/private/state'\ntimeout_ms=50\nresponse_cap=65536\nregistry_sha256='{}'\nendpoint_identity='receiver:fixture'\nreceiver_credential_names=['TOKEN']\n[capture.actor_refs]\nalice='actor:alice'\n[supervisor]\nruntime_directory='/private/runtime'\nbus_address='unix:path=/private/runtime/bus'\nruntime_max_seconds=60\npreexec_ms=100\nclosure_grace_ms=100\ncancel_grace_ms=100\n[supervisor.actors.alice]\nauthor_name='Alice'\nauthor_email='alice@example.invalid'\ncommitter_name='Alice'\ncommitter_email='alice@example.invalid'\n",temp.path().join("private"),temp.path().join(".work-authorities"),root,repo,"a".repeat(64))).unwrap();
    let a = crate::allocate::start(
        &config,
        crate::allocate::Start {
            operation: Uuid::now_v7(),
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
    let root:RootRunRequest=serde_json::from_value(serde_json::json!({"identity":{
        "checkout":a.checkout,"group":Uuid::now_v7(),"run":Uuid::now_v7(),"run_ref":"run:physical-proof","actor":"alice","parent_run_ref":null,"execution_chain":[{"kind":"executor","system":"test"}]},
        "input":{"command_digest":vec![1;32],"input_digest":vec![2;32],"context_ref":"context","intent_ref":"intent","boot":a.identity.as_ref().unwrap().boot_id}
    })).unwrap();
    let spec = config
        .capture_spec(&root, &a, Uuid::now_v7(), vec!["task".into()], None)
        .unwrap();
    let (store, lock) = crate::allocate::locked(&config).unwrap();
    drop(lock);
    (temp, config, store, a, root, spec)
}
#[test]
fn genuine_materialization_proofs_refuse_changed_physical_or_durable_context() {
    for case in [
        "marker",
        "branch",
        "head",
        "source",
        "private",
        "common",
        "tree",
        "finish",
        "hold",
        "requirement",
        "allocation",
        "writer",
        "ready",
    ] {
        let (temp, _cfg, mut store, a, r, s) = materialized();
        let proof = MaterializationProof::inspect(&store, &r, &s).unwrap();
        let i = a.identity.as_ref().unwrap();
        match case {
            "marker" => std::fs::write(i.private_git_dir.join("work-lease.json"), "{}").unwrap(),
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
                    &["commit", "--allow-empty", "-m", "premature"],
                )
                .unwrap();
            }
            "source" => fixture::replace_directory(a.request.repository.as_ref().unwrap()),
            "private" => fixture::replace_directory(&i.private_git_dir),
            "common" => fixture::replace_directory(&i.common_git_dir),
            "tree" => fixture::replace_directory(&a.destination),
            "finish" => {
                store
                    .conn
                    .execute(
                        "INSERT INTO task_finishes VALUES(?1,?2,'{}')",
                        (a.checkout.to_string(), Uuid::now_v7().to_string()),
                    )
                    .unwrap();
            }
            "hold" => {
                store
                    .conn
                    .execute("UPDATE checkouts SET state='held'", [])
                    .unwrap();
            }
            "requirement" => {
                store
                    .conn
                    .execute("UPDATE capture_requirements SET revision=revision+1", [])
                    .unwrap();
            }
            "allocation" => {
                store
                    .conn
                    .execute(
                        "UPDATE allocations SET record=json_set(record,'$.reason','changed')",
                        [],
                    )
                    .unwrap();
            }
            "writer" => {
                store
                    .conn
                    .execute(
                        "INSERT INTO writers VALUES(?1,?2)",
                        (a.checkout.to_string(), Uuid::now_v7().to_string()),
                    )
                    .unwrap();
            }
            _ => {
                store
                    .conn
                    .execute("UPDATE checkouts SET state='active',ready=1", [])
                    .unwrap();
            }
        }
        let before = fixture::files(temp.path());
        let events = store.pending_events(100).unwrap();
        assert!(
            store.begin_materialized_capture(&r, &s, &proof).is_err(),
            "{case}"
        );
        assert_eq!(fixture::files(temp.path()), before, "{case}");
        assert_eq!(store.pending_events(100).unwrap(), events, "{case}");
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM runs", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0,
            "{case}"
        );
    }
}
#[test]
fn materialization_proof_cannot_authorize_a_different_capture_spec() {
    let (_temp, _cfg, mut store, _a, r, s) = materialized();
    let proof = MaterializationProof::inspect(&store, &r, &s).unwrap();
    let mut d = s.begin_request();
    d.task_refs.push("other:declared".into());
    let changed = CaptureSpec::new(s.operation(), s.sink().clone(), d, s.expected_git()).unwrap();
    let events = store.pending_events(100).unwrap();
    assert!(
        store
            .begin_materialized_capture(&r, &changed, &proof)
            .is_err(),
        "proof accepted changed sealed declaration"
    );
    assert_eq!(store.pending_events(100).unwrap(), events);
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM runs", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}
#[test]
fn physical_proof_expiration_is_checked_after_immediate_lock_and_before_handoff() {
    for wait in [false, true] {
        let (temp, _cfg, mut store, _a, r, s) = materialized();
        let mut proof = MaterializationProof::inspect(&store, &r, &s).unwrap();
        // Age only a genuinely inspected private proof; no fake inspection backend.
        proof.observed = Instant::now() - Duration::from_millis(if wait { 1900 } else { 2100 });
        let sql = Connection::open(temp.path().join("private/store.sqlite")).unwrap();
        let events = store.pending_events(100).unwrap();
        let result = if wait {
            sql.execute_batch("BEGIN IMMEDIATE").unwrap();
            let thread =
                std::thread::spawn(move || store.begin_materialized_capture(&r, &s, &proof));
            std::thread::sleep(Duration::from_millis(250));
            sql.execute_batch("COMMIT").unwrap();
            thread.join().unwrap()
        } else {
            store.begin_materialized_capture(&r, &s, &proof)
        };
        assert!(matches!(result, Err(StoreError::Conflict)), "wait={wait}");
        let store = Store::open(&temp.path().join("private"), &[temp.path().join("root")]).unwrap();
        assert_eq!(store.pending_events(100).unwrap(), events);
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM runs", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(!store
            .conn
            .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
            .unwrap());
    }
}
