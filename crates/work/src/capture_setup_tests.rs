use super::*;
use std::{cell::RefCell, rc::Rc};
use uuid::Uuid;
type PhysicalObserver = Box<dyn FnMut(&Connection)>;
thread_local! {
    static PHYSICAL_OBSERVER: RefCell<Option<PhysicalObserver>> = RefCell::new(None);
}
pub(super) fn observe_physical(conn: &Connection) {
    PHYSICAL_OBSERVER.with(|observer| {
        if let Some(observer) = observer.borrow_mut().as_mut() {
            observer(conn);
        }
    });
}
struct ObserverGuard;
impl Drop for ObserverGuard {
    fn drop(&mut self) {
        PHYSICAL_OBSERVER.with(|observer| *observer.borrow_mut() = None);
    }
}
fn observing(observer: impl FnMut(&Connection) + 'static) -> ObserverGuard {
    PHYSICAL_OBSERVER.with(|slot| *slot.borrow_mut() = Some(Box::new(observer)));
    ObserverGuard
}
use crate::test_lifecycle_fixture as fixture;
pub(crate) fn materialized() -> (
    tempfile::TempDir,
    Config,
    Store,
    Allocation,
    RootRunRequest,
    CaptureSpec,
) {
    materialized_with_timeout(50)
}
pub(crate) fn materialized_with_timeout(
    timeout_ms: u64,
) -> (
    tempfile::TempDir,
    Config,
    Store,
    Allocation,
    RootRunRequest,
    CaptureSpec,
) {
    let (temp, repo, root) = fixture::git_fixture();
    let config=Config::from_text(&format!("store_dir={:?}\ntrusted_registry={:?}\nroots=[{:?}]\nrepositories=[{:?}]\n[allocation]\nrepository_limit=10\nowner_limit=10\nfloor_bytes=0\nwarn_bytes=0\ncapture_sink='devdiary'\n[capture]\nexecutable='/private/capture'\nregistry='/private/registry'\nstate_dir='/private/state'\ntimeout_ms={timeout_ms}\nresponse_cap=65536\nregistry_sha256='{}'\nendpoint_identity='receiver:fixture'\nreceiver_credential_names=['TOKEN']\n[capture.actor_refs]\nalice='actor:alice'\n[supervisor]\nruntime_directory='/private/runtime'\nbus_address='unix:path=/private/runtime/bus'\nruntime_max_seconds=60\npreexec_ms=100\nclosure_grace_ms=100\ncancel_grace_ms=100\n[supervisor.actors.alice]\nauthor_name='Alice'\nauthor_email='alice@example.invalid'\ncommitter_name='Alice'\ncommitter_email='alice@example.invalid'\n",temp.path().join("private"),temp.path().join(".work-authorities"),root,repo,"a".repeat(64))).unwrap();
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
fn actual_physical_inspection_never_holds_sql_or_global_lease_but_retains_checkout_guard() {
    let (temp, cfg, store, a, r, s) = materialized();
    let sql = Connection::open(temp.path().join("private/store.sqlite")).unwrap();
    sql.busy_timeout(Duration::ZERO).unwrap();
    let observations = Rc::new(RefCell::new(Vec::new()));
    let seen = observations.clone();
    let _observer = observing(move |conn| {
        let writer = sql.execute_batch("BEGIN IMMEDIATE").is_ok();
        if writer {
            sql.execute_batch("ROLLBACK").unwrap();
        }
        let lock = crate::store::AuthorityIdentity::open_lock(
            &store.authority_identity().directory,
            false,
        )
        .unwrap();
        let global_free =
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_ok();
        let checkout_excluded = matches!(
            crate::checkout_guard::CheckoutGuard::exclusive(&store, a.checkout),
            Err(StoreError::OperationsInFlight)
        );
        seen.borrow_mut()
            .push((conn.is_autocommit(), writer, global_free, checkout_excluded));
    });
    let (_store, result) = begin(&cfg, &r, &s).unwrap();
    assert!(matches!(result, BeginCapturedRun::Created(_)));
    let seen = observations.borrow();
    assert!(
        seen.len() >= 2,
        "initial inspection and pre-admission reinspection must both run"
    );
    assert!(
        seen.iter()
            .all(|&(autocommit, writer, global_free, checkout_excluded)| {
                autocommit && writer && global_free && checkout_excluded
            }),
        "physical boundary held SQL authority: {seen:?}"
    );
}
#[test]
fn genuine_physical_delay_does_not_consume_sql_phase_budget_or_poison_later_operations() {
    let (_temp, cfg, _store, _a, r, s) = materialized();
    let mut first = true;
    let _observer = observing(move |conn| {
        if first {
            first = false;
            std::thread::sleep(Duration::from_millis(650));
            let scan=conn.query_row("WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<5000) SELECT sum(x) FROM n",[],|r|r.get::<_,i64>(0));
            assert!(
                scan.is_ok(),
                "external physical delay was charged to SQL: {scan:?}"
            );
        }
    });
    let (store, result) = begin(&cfg, &r, &s).unwrap();
    assert!(matches!(result, BeginCapturedRun::Created(_)));
    // Later ordinary SQL must have its own unchanged bounded phase.
    assert_eq!(
        store
            .pending_events(100)
            .unwrap()
            .iter()
            .filter(|e| matches!(e.event, crate::events::Event::WriterAcquired { .. }))
            .count(),
        1
    );
}
#[test]
fn new_pending_setup_refuses_closed_or_orphan_supervised_journal_without_repair() {
    let mut admitted = Vec::new();
    for case in ["closed_rootless", "orphan_run", "closed_history"] {
        let (temp, cfg, store, a, r, s) = materialized();
        let sql = Connection::open(temp.path().join("private/store.sqlite")).unwrap();
        sql.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        let mut value = serde_json::to_value(&r).unwrap();
        let group = Uuid::now_v7();
        let run = Uuid::now_v7();
        value["identity"]["group"] = group.to_string().into();
        value["identity"]["run"] = run.to_string().into();
        value["identity"]["run_ref"] = "run:disconnected-history".into();
        let old: RootRunRequest = serde_json::from_value(value).unwrap();
        if case != "orphan_run" {
            sql.execute("INSERT INTO run_groups(id,checkout,mode,revision,closed) VALUES(?1,?2,'supervised',1,1)",(group.to_string(),a.checkout.to_string())).unwrap();
        }
        if case != "closed_rootless" {
            sql.execute(
                "INSERT INTO runs(id,group_id,run_ref,request,stage) VALUES(?1,?2,?3,?4,'intent')",
                (
                    run.to_string(),
                    group.to_string(),
                    old.identity().run_ref.as_str(),
                    serde_json::to_string(&old).unwrap(),
                ),
            )
            .unwrap();
        }
        let events = store.pending_events(100).unwrap();
        let before = fixture::files(temp.path());
        if begin(&cfg, &r, &s).is_ok() {
            admitted.push(case);
            continue;
        }
        assert_eq!(
            fixture::files(temp.path()),
            before,
            "{case}: authority was repaired or mutated"
        );
        assert_eq!(store.pending_events(100).unwrap(), events, "{case}");
        assert_eq!(
            store
                .charged(a.request.repository.as_ref().unwrap(), None)
                .unwrap(),
            1
        );
        assert_eq!(
            sql.query_row(
                "SELECT count(*) FROM runs WHERE id=?1",
                [r.identity().run.to_string()],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            sql.query_row("SELECT count(*) FROM capture_runs", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(!sql
            .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
            .unwrap());
    }
    assert!(
        admitted.is_empty(),
        "orphan/closed journal admitted fresh roots: {admitted:?}"
    );
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
        "closed_rootless",
        "orphan_run",
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
            "closed_rootless" => {
                let sql = Connection::open(temp.path().join("private/store.sqlite")).unwrap();
                sql.execute("INSERT INTO run_groups(id,checkout,mode,revision,closed) VALUES(?1,?2,'supervised',1,1)",(Uuid::now_v7().to_string(),a.checkout.to_string())).unwrap();
            }
            "orphan_run" => {
                let sql = Connection::open(temp.path().join("private/store.sqlite")).unwrap();
                sql.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
                sql.execute("INSERT INTO runs(id,group_id,run_ref,request,stage) VALUES(?1,?2,'orphan:metadata','{}','intent')",(Uuid::now_v7().to_string(),Uuid::now_v7().to_string())).unwrap();
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
            if case == "orphan_run" { 1 } else { 0 },
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
        proof.observed = Instant::now() - Duration::from_millis(if wait { 1800 } else { 2100 });
        let sql = Connection::open(temp.path().join("private/store.sqlite")).unwrap();
        let events = store.pending_events(100).unwrap();
        let result = if wait {
            use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
            let (begin_send, begin_recv) = std::sync::mpsc::channel();
            let (locked_send, locked_recv) = std::sync::mpsc::channel();
            let mut begun = false;
            let mut locked = false;
            store
                .conn
                .authorizer(Some(move |ctx: AuthContext<'_>| {
                    if matches!(
                        ctx.action,
                        AuthAction::Transaction {
                            operation: TransactionOperation::Begin
                        }
                    ) {
                        begun = true;
                        begin_send.send(Instant::now()).unwrap();
                    }
                    if begun
                        && !locked
                        && matches!(
                            ctx.action,
                            AuthAction::Read {
                                table_name: "allocations",
                                ..
                            }
                        )
                    {
                        locked = true;
                        locked_send.send(Instant::now()).unwrap();
                    }
                    Authorization::Allow
                }))
                .unwrap();
            let expires = proof.observed + MAX_AGE;
            sql.execute_batch("BEGIN IMMEDIATE").unwrap();
            let thread =
                std::thread::spawn(move || store.begin_materialized_capture(&r, &s, &proof));
            let began = begin_recv
                .recv_timeout(Duration::from_secs(2))
                .expect("must reach BEGIN after genuine pre-TX reinspection");
            assert!(
                began < expires,
                "proof was already expired before the writer-lock wait"
            );
            let until_expired =
                (expires + Duration::from_millis(25)).saturating_duration_since(Instant::now());
            assert!(
                until_expired < Duration::from_millis(300),
                "fixture must remain within the unchanged SQLite busy/phase budgets"
            );
            std::thread::sleep(until_expired);
            sql.execute_batch("COMMIT").unwrap();
            let acquired = locked_recv
                .recv_timeout(Duration::from_secs(2))
                .expect("admission must read its context after acquiring IMMEDIATE");
            assert!(
                acquired >= expires,
                "test must expire the original observation during actual lock contention"
            );
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
fn seed_prepared_fence(store: &Store, checkout: Uuid) {
    crate::retirement_journal::tests::seed_prepared(store, checkout, Uuid::now_v7());
    let rows = crate::retirement_journal::read_history(&store.conn, checkout).unwrap();
    assert_eq!(
        (rows.len(), rows[0].revision, rows[0].stage.as_str()),
        (1, 1, "prepared")
    );
}
#[test]
fn materialization_reinspection_stage_is_bound_to_original_store_and_request() {
    let (_temp, cfg, mut store, _a, root, spec) = materialized();
    let proof = MaterializationProof::inspect(&store, &root, &spec).unwrap();
    let other = Store::open_existing_registered_mut(
        cfg.trusted_registry.as_ref().unwrap(),
        cfg.store_dir.as_ref().unwrap(),
        &cfg.roots,
    )
    .unwrap();
    assert!(
        proof.reinspect(&other).is_err(),
        "reopened Store must not borrow another instance's inspection"
    );
    let inspected = proof.reinspect(&store).unwrap();
    let foreign = other.authority_lease().unwrap();
    assert!(inspected.checked(&store, &foreign).is_err());
    drop(foreign);
    let mut changed = serde_json::to_value(&root).unwrap();
    changed["identity"]["run"] = Uuid::now_v7().to_string().into();
    let changed: RootRunRequest = serde_json::from_value(changed).unwrap();
    let lease = store.authority_lease().unwrap();
    assert!(store
        .begin_materialized_capture_under_lease(&changed, &spec, inspected, &lease)
        .is_err());
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM runs", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}
#[test]
fn begin_under_guard_refuses_unrelated_checkout_guard() {
    let (_temp, cfg, store, _a, r, s) = materialized();
    let other = Uuid::now_v7();
    let guard = crate::checkout_guard::CheckoutGuard::shared(&store, other).unwrap();
    assert!(super::begin_under_guard(&cfg, &r, &s, &guard).is_err());
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM runs", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}
#[test]
fn begin_holds_prepared_intent_before_admission_rows() {
    let (_temp, cfg, store, a, r, s) = materialized();
    seed_prepared_fence(&store, a.checkout);
    let before = crate::retirement_journal::tests::source_rows(&store);
    let error = match super::begin(&cfg, &r, &s) {
        Ok(_) => panic!("fenced capture setup unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        crate::store::StoreError::RetirementFenced.to_string()
    );
    let (revision, stage, reason): (i64, String, Option<String>) = store
        .conn
        .query_row(
            "SELECT revision, stage, held_reason FROM retirement_intents WHERE checkout=?1",
            [a.checkout.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (revision, stage.as_str(), reason.as_deref()),
        (2, "held", Some("capture_admission"))
    );
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM runs", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    let events = store
        .pending_events(100)
        .unwrap()
        .into_iter()
        .filter(|pending| {
            matches!(
                &pending.event,
                crate::events::Event::RetirementIntentChanged { stage, .. } if stage == "held"
            )
        })
        .count();
    assert_eq!(events, 1);
    assert_eq!(
        crate::retirement_journal::tests::source_rows(&store),
        before
    );
}

#[test]
fn malformed_intent_refuses_without_fabricating_a_hold() {
    let (_temp, cfg, store, a, root, spec) = materialized();
    seed_prepared_fence(&store, a.checkout);
    store
        .conn
        .execute("UPDATE retirement_intents SET record='{}'", [])
        .unwrap();
    assert!(crate::retirement_journal::read_history(&store.conn, a.checkout).is_err());
    let before = crate::retirement_journal::tests::source_rows(&store);
    let events = store.pending_events(1000).unwrap();
    assert!(super::begin(&cfg, &root, &spec).is_err());
    assert_eq!(
        crate::retirement_journal::tests::source_rows(&store),
        before
    );
    assert_eq!(store.pending_events(1000).unwrap(), events);
    assert_eq!(
        store
            .conn
            .query_row(
                "SELECT revision,stage,record FROM retirement_intents",
                [],
                |r| Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?
                ))
            )
            .unwrap(),
        (1, "prepared".into(), "{}".into())
    );
}
