use super::*;
use crate::admission::{Limits, Reservation};
use crate::events::Event;
use crate::store::{Store, StoreError};
use rusqlite::Connection;
use std::path::PathBuf;
use uuid::Uuid;

type SqlRows = Vec<Vec<rusqlite::types::Value>>;
type SourceRows = Vec<(String, SqlRows)>;

// Structural negative-fence fixtures, never owned retirement capabilities.
pub(crate) fn source_rows(store: &Store) -> SourceRows {
    let names = store.conn.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT IN ('retirement_intents','outbox') ORDER BY name")
        .unwrap().query_map([], |r| r.get::<_, String>(0)).unwrap()
        .collect::<rusqlite::Result<Vec<_>>>().unwrap();
    names
        .into_iter()
        .map(|name| {
            let mut stmt = store
                .conn
                .prepare(&format!("SELECT * FROM \"{name}\" ORDER BY rowid"))
                .unwrap();
            let columns = stmt.column_count();
            let rows = stmt
                .query_map([], |r| (0..columns).map(|c| r.get(c)).collect())
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            (name, rows)
        })
        .collect()
}

// One-shot negative injection at actual late writer boundaries. This test-only
// observer cannot authorize a writer, return evidence, skip a fence, or reset a budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LateBoundary {
    RequiredGapHold,
    ReconcileHead,
    RefreshIdentity,
    ReusePublication,
    FinishInsert,
}
#[derive(Clone, Copy)]
pub(crate) enum LateFault {
    None,
    Outbox,
    Commit,
}
type LateCallback = Box<dyn FnOnce(&Store)>;
thread_local! {
    static LATE_WRITER: std::cell::RefCell<Option<(LateBoundary, LateCallback)>> = const { std::cell::RefCell::new(None) };
}
pub(crate) fn observe_late(boundary: LateBoundary, store: &Store) {
    let callback = LATE_WRITER.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .is_some_and(|(expected, _)| *expected == boundary)
        {
            slot.take().map(|(_, callback)| callback)
        } else {
            None
        }
    });
    if let Some(callback) = callback {
        callback(store);
    }
}
struct LateSnapshot {
    source: SourceRows,
    events: Vec<crate::events::PendingEvent>,
    intents: Vec<(Uuid, Uuid, String, bool)>,
}
pub(crate) struct LateFence {
    boundary: LateBoundary,
    snapshot: std::rc::Rc<std::cell::RefCell<Option<LateSnapshot>>>,
    commit_reached: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl LateFence {
    pub(crate) fn install(boundary: LateBoundary, checkouts: Vec<Uuid>) -> Self {
        Self::with_fault(boundary, checkouts, LateFault::None, false)
    }
    pub(crate) fn with_fault(
        boundary: LateBoundary,
        checkouts: Vec<Uuid>,
        fault: LateFault,
        already_held: bool,
    ) -> Self {
        let snapshot = std::rc::Rc::new(std::cell::RefCell::new(None));
        let captured = snapshot.clone();
        let commit_reached = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let commit_observer = commit_reached.clone();
        LATE_WRITER.with(|slot| {
            assert!(slot.borrow().is_none(), "overlapping negative writer observer");
            *slot.borrow_mut() = Some((boundary, Box::new(move |store| {
                assert!(store.conn.is_autocommit(), "injection must precede the actual transaction");
                let mut intents = Vec::new();
                for (index, checkout) in checkouts.into_iter().enumerate() {
                    assert!(read_history(&store.conn, checkout).unwrap().is_empty(), "entry must be clear before this seam");
                    let operation = Uuid::now_v7();
                    let record = seed_prepared(store, checkout, operation);
                    let held = already_held && index == 0;
                    if held {
                        store.conn.execute("UPDATE retirement_intents SET stage='held',revision=2,held_reason='allocation_hold' WHERE operation=?1", [operation.to_string()]).unwrap();
                        crate::store::emit(&store.conn, &Event::RetirementIntentChanged {
                            checkout, operation, revision: 2, stage: "held".into(), reason: Some("allocation_hold".into()),
                        }).unwrap();
                    }
                    read_history(&store.conn, checkout).unwrap();
                    intents.push((checkout, operation, record, held));
                }
                *captured.borrow_mut() = Some(LateSnapshot { source: source_rows(store), events: store.pending_events(1000).unwrap(), intents });
                match fault {
                    LateFault::None => {}
                    LateFault::Outbox => store.conn.execute_batch("CREATE TEMP TRIGGER late_outbox_fault BEFORE INSERT ON outbox WHEN (SELECT count(*) FROM retirement_intents WHERE stage='held')>=2 BEGIN SELECT RAISE(ABORT,'late outbox fault'); END;").unwrap(),
                    LateFault::Commit => {
                        store.conn.commit_hook(Some(move || {
                            commit_observer.store(true, std::sync::atomic::Ordering::SeqCst);
                            true
                        }));
                    }
                }
            })));
        });
        Self {
            boundary,
            snapshot,
            commit_reached,
        }
    }
    pub(crate) fn assert_held(&self, store: &Store, reason: &str) {
        let captured = self.snapshot.borrow();
        let snapshot = captured.as_ref().unwrap_or_else(|| {
            panic!(
                "{:?} actual pretransaction boundary not reached",
                self.boundary
            )
        });
        assert_eq!(source_rows(store), snapshot.source);
        let events = store.pending_events(1000).unwrap();
        assert_eq!(&events[..snapshot.events.len()], snapshot.events.as_slice());
        let new_holds = snapshot
            .intents
            .iter()
            .filter(|(_, _, _, held)| !held)
            .count();
        assert_eq!(events.len(), snapshot.events.len() + new_holds);
        for (checkout, operation, record, already_held) in &snapshot.intents {
            let row = load_operation(&store.conn, *operation).unwrap();
            let reason = if *already_held {
                "allocation_hold"
            } else {
                reason
            };
            assert_eq!(
                (
                    row.stage.as_str(),
                    row.revision,
                    row.held_reason.as_deref(),
                    row.record.as_str()
                ),
                ("held", 2, Some(reason), record.as_str())
            );
            assert_eq!(
                held_events(store, *checkout),
                vec![Event::RetirementIntentChanged {
                    checkout: *checkout,
                    operation: *operation,
                    revision: 2,
                    stage: "held".into(),
                    reason: Some(reason.into()),
                }]
            );
        }
    }
    pub(crate) fn assert_rollback(&self, store: &Store) {
        let captured = self.snapshot.borrow();
        let snapshot = captured
            .as_ref()
            .expect("actual late batch boundary reached");
        assert_eq!(source_rows(store), snapshot.source);
        assert_eq!(store.pending_events(1000).unwrap(), snapshot.events);
        for (_, operation, record, held) in &snapshot.intents {
            let row = load_operation(&store.conn, *operation).unwrap();
            assert_eq!(
                (row.stage.as_str(), row.revision, row.record.as_str()),
                (
                    if *held { "held" } else { "prepared" },
                    if *held { 2 } else { 1 },
                    record.as_str()
                )
            );
        }
    }
    pub(crate) fn assert_commit_fault_reached(&self) {
        assert!(
            self.commit_reached
                .load(std::sync::atomic::Ordering::SeqCst),
            "actual final commit veto must be reached"
        );
    }
}
impl Drop for LateFence {
    fn drop(&mut self) {
        LATE_WRITER.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

fn assert_writer_fenced(
    store: &mut Store,
    checkout: Uuid,
    mut writer: impl FnMut(&mut Store) -> crate::store::Result<()>,
) {
    let operation = Uuid::now_v7();
    let record = seed_prepared(store, checkout, operation);
    let before = source_rows(store);
    let events = store.pending_events(1000).unwrap().len();
    for _ in 0..2 {
        assert!(matches!(writer(store), Err(StoreError::RetirementFenced)));
        assert_eq!(source_rows(store), before);
        let row = load_operation(&store.conn, operation).unwrap();
        assert_eq!(
            (row.stage.as_str(), row.revision, row.record.as_str()),
            ("held", 2, record.as_str())
        );
        assert_eq!(
            held_events(store, checkout),
            vec![Event::RetirementIntentChanged {
                checkout,
                operation,
                revision: 2,
                stage: "held".into(),
                reason: row.held_reason.clone(),
            }]
        );
        assert_eq!(store.pending_events(1000).unwrap().len(), events + 1);
    }
    // A distinct ordinary attempt against already-held state emits nothing.
    assert!(matches!(
        store.transfer(checkout, "different-owner", limits()),
        Err(StoreError::RetirementFenced)
    ));
    assert_eq!(source_rows(store), before);
    assert_eq!(store.pending_events(1000).unwrap().len(), events + 1);
}

fn adopted_request(root: &crate::run_journal::RootRunRequest) -> crate::adopted::AdoptedRequest {
    crate::adopted::AdoptedRequest {
        operation: Uuid::now_v7(),
        identity: root.identity().clone(),
        source: crate::participants::Ref::new("source".into()).unwrap(),
        session: crate::participants::Ref::new("session".into()).unwrap(),
        agent: None,
    }
}

fn child_request(
    root: &crate::run_journal::RootRunRequest,
    run: Uuid,
) -> crate::run_participants::ChildRequest {
    crate::run_participants::ChildRequest {
        checkout: root.identity().checkout.clone(),
        group: root.identity().group.clone(),
        run: work_contract::RunId::parse(&run.to_string()).unwrap(),
        run_ref: work_contract::RunRef::parse(&format!("child:{run}")).unwrap(),
        parent_run: root.identity().run.clone(),
        parent_run_ref: root.identity().run_ref.clone(),
        execution_chain: root.identity().execution_chain.clone(),
        source: None,
        session: None,
        agent: None,
        actor: None,
        expected_host: None,
    }
}

#[test]
fn opened_store_rejects_schema_downgrade_and_future_on_retry_and_mutation() {
    for version in [15, 17] {
        for retry in [false, true] {
            let (temp, mut store, root) = open_store();
            let request = Reservation {
                operation: Uuid::now_v7(),
                repository: root,
                actor: "allocator".into(),
                owner: "owner".into(),
                task: "task".into(),
            };
            let checkout = store.reserve(&request, limits()).unwrap();
            let intent = Uuid::now_v7();
            seed_prepared(&store, checkout, intent);
            let before = source_rows(&store);
            let history = load_operation(&store.conn, intent).unwrap();
            let events = store.pending_events(1000).unwrap();
            // Only the pragma changes; all retirement DDL and canonical evidence remain.
            let other = Connection::open(temp.path().join("private/store.sqlite")).unwrap();
            other.pragma_update(None, "user_version", version).unwrap();
            let result = if retry {
                store.reserve(&request, limits()).map(|_| ())
            } else {
                store.transfer(checkout, "other", limits())
            };
            assert!(
                matches!(result, Err(StoreError::Invalid)),
                "version {version}, retry {retry}"
            );
            assert_eq!(schema_version(&store.conn).unwrap(), version);
            assert_eq!(source_rows(&store), before);
            assert_eq!(load_operation(&store.conn, intent).unwrap(), history);
            assert_eq!(store.pending_events(1000).unwrap(), events);
        }
    }
}

#[test]
fn child_namespace_reserves_active_and_aborted_retirement_operations_on_other_checkout() {
    for aborted in [false, true] {
        let (_temp, mut store, _) = open_store();
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        insert_checkout(&store, a, Uuid::now_v7(), "owner");
        insert_checkout(&store, b, Uuid::now_v7(), "owner");
        let operation = Uuid::now_v7();
        seed_prepared(&store, a, operation);
        if aborted {
            abort_cas(&store.conn, a, operation, 1).unwrap();
        }
        let root = crate::test_run_fixture::request(b);
        let binding = crate::test_run_fixture::binding(&root);
        store.begin_run(&root).unwrap();
        store.record_bound(&root, &binding).unwrap();
        store.record_permit_attempt(&root, &binding).unwrap();
        // A control proves B is otherwise eligible, including Existing ACK.
        let control = child_request(&root, Uuid::now_v7());
        assert_eq!(
            store.register_child(&root, &control).unwrap(),
            crate::run_journal::BeginRun::Created
        );
        assert_eq!(
            store.register_child(&root, &control).unwrap(),
            crate::run_journal::BeginRun::Existing
        );
        let before = source_rows(&store);
        let history = load_operation(&store.conn, operation).unwrap();
        let events = store.pending_events(1000).unwrap();
        let collision = child_request(&root, operation);
        for _ in 0..2 {
            assert!(matches!(
                store.register_child(&root, &collision),
                Err(StoreError::Conflict)
            ));
            assert_eq!(source_rows(&store), before);
            assert_eq!(load_operation(&store.conn, operation).unwrap(), history);
            assert_eq!(store.pending_events(1000).unwrap(), events);
        }
    }
}

#[test]
fn child_existing_ack_rejects_retirement_namespace_collision() {
    for aborted in [false, true] {
        let (_temp, mut store, _) = open_store();
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        insert_checkout(&store, a, Uuid::now_v7(), "owner");
        insert_checkout(&store, b, Uuid::now_v7(), "owner");
        let root = crate::test_run_fixture::request(b);
        let binding = crate::test_run_fixture::binding(&root);
        store.begin_run(&root).unwrap();
        store.record_bound(&root, &binding).unwrap();
        store.record_permit_attempt(&root, &binding).unwrap();
        let operation = Uuid::now_v7();
        let child = child_request(&root, operation);
        store.register_child(&root, &child).unwrap();
        // Model conflicting historical SQL, not a public prepare capability.
        seed_prepared(&store, a, operation);
        if aborted {
            abort_cas(&store.conn, a, operation, 1).unwrap();
        }
        let before = source_rows(&store);
        let history = load_operation(&store.conn, operation).unwrap();
        let events = store.pending_events(1000).unwrap();
        assert!(matches!(
            store.register_child(&root, &child),
            Err(StoreError::Invalid)
        ));
        assert_eq!(source_rows(&store), before);
        assert_eq!(load_operation(&store.conn, operation).unwrap(), history);
        assert_eq!(store.pending_events(1000).unwrap(), events);
    }
}

#[test]
fn public_reserve_new_checkout_does_not_fence_independent_same_repository() {
    let (_temp, mut store, root) = open_store();
    let mut request = Reservation {
        operation: Uuid::now_v7(),
        repository: root,
        actor: "allocator".into(),
        owner: "owner".into(),
        task: "a".into(),
    };
    let a = store.reserve(&request, limits()).unwrap();
    let intent = Uuid::now_v7();
    seed_prepared(&store, a, intent);
    let before = load_operation(&store.conn, intent).unwrap();
    request.operation = Uuid::now_v7();
    request.task = "b".into();
    let b = store.reserve(&request, limits()).unwrap();
    assert_ne!(a, b);
    assert_eq!(store.reserve(&request, limits()).unwrap(), b);
    assert_eq!(load_operation(&store.conn, intent).unwrap(), before);
    assert!(held_events(&store, a).is_empty());
}

#[test]
fn run_transitions_and_existing_acknowledgments_are_fenced() {
    for variant in ["bound", "permit", "outcome", "hold"] {
        for existing in [false, true] {
            let (_temp, mut store, _) = open_store();
            let checkout = Uuid::now_v7();
            insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
            let root = crate::test_run_fixture::request(checkout);
            let binding = crate::test_run_fixture::binding(&root);
            store.begin_run(&root).unwrap();
            if variant != "bound" {
                store.record_bound(&root, &binding).unwrap();
            }
            if variant == "outcome" {
                store.record_permit_attempt(&root, &binding).unwrap();
            }
            let change = |store: &mut Store| match variant {
                "bound" => store.record_bound(&root, &binding),
                "permit" => store.record_permit_attempt(&root, &binding),
                "outcome" => {
                    store.record_root_outcome(&root, crate::run_journal::RootOutcome::Completed)
                }
                "hold" => store.record_recovery_hold(&root),
                _ => unreachable!(),
            };
            if existing {
                change(&mut store).unwrap();
            }
            assert_writer_fenced(&mut store, checkout, |store| change(store).map(|_| ()));
        }
    }
}

#[test]
fn child_register_outcome_hold_and_existing_are_fenced() {
    for variant in ["register", "outcome", "hold"] {
        for existing in [false, true] {
            let (_temp, mut store, _) = open_store();
            let checkout = Uuid::now_v7();
            insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
            let root = crate::test_run_fixture::request(checkout);
            let binding = crate::test_run_fixture::binding(&root);
            store.begin_run(&root).unwrap();
            store.record_bound(&root, &binding).unwrap();
            store.record_permit_attempt(&root, &binding).unwrap();
            let mut child = child_request(&root, Uuid::now_v7());
            child.expected_host = Some(crate::run_participants::ExpectedHost {
                boot: root.input().boot.clone(),
                pid: 42,
                start_ticks: 10,
            });
            if variant != "register" {
                store.register_child(&root, &child).unwrap();
            }
            let change = |store: &mut Store| match variant {
                "register" => store.register_child(&root, &child).map(|_| ()),
                "outcome" => store
                    .record_child_outcome(
                        &root,
                        &child,
                        crate::run_participants::ChildOutcome::Completed,
                    )
                    .map(|_| ()),
                "hold" => store.record_child_hold(&root, &child).map(|_| ()),
                _ => unreachable!(),
            };
            if existing {
                change(&mut store).unwrap();
            }
            assert_writer_fenced(&mut store, checkout, change);
        }
    }
}

#[test]
fn supervised_closure_is_fenced_with_owned_empty_proof() {
    let (_temp, mut store, _) = open_store();
    let checkout = Uuid::now_v7();
    insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
    let root = crate::test_run_fixture::request(checkout);
    let binding = crate::test_run_fixture::binding(&root);
    store.begin_run(&root).unwrap();
    store.record_bound(&root, &binding).unwrap();
    store.record_permit_attempt(&root, &binding).unwrap();
    store
        .record_root_outcome(&root, crate::run_journal::RootOutcome::Completed)
        .unwrap();
    let os = crate::test_run_fixture::ClosureOs::new(&root, &binding);
    let snapshot = store.group_snapshot(&root.identity().run).unwrap();
    let proof = snapshot.certify_empty(&os.driver, &binding).unwrap();
    assert_writer_fenced(&mut store, checkout, |store| {
        store.close_supervised_group(&snapshot, &proof).map(|_| ())
    });
}

#[test]
fn child_enrollment_is_fenced_with_owned_fixture_observation() {
    for existing in [false, true] {
        let (_temp, mut store, _) = open_store();
        let checkout = Uuid::now_v7();
        insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
        let root = crate::test_run_fixture::request(checkout);
        let binding = crate::test_run_fixture::binding(&root);
        store.begin_run(&root).unwrap();
        store.record_bound(&root, &binding).unwrap();
        store.record_permit_attempt(&root, &binding).unwrap();
        let mut child = child_request(&root, Uuid::now_v7());
        child.expected_host = Some(crate::run_participants::ExpectedHost {
            boot: root.input().boot.clone(),
            pid: 42,
            start_ticks: 10,
        });
        store.register_child(&root, &child).unwrap();
        let os = crate::test_run_fixture::ClosureOs::new(&root, &binding);
        os.process(&binding, 10, &binding.identity().cgroup);
        let properties = os.tmp.path().join("properties");
        let body = std::fs::read_to_string(&properties)
            .unwrap()
            .replace("ActiveState=inactive", "ActiveState=active");
        std::fs::write(properties, body).unwrap();
        std::fs::write(
            os.tmp
                .path()
                .join("cg")
                .join(binding.identity().cgroup.trim_start_matches('/'))
                .join("cgroup.procs"),
            "42\n",
        )
        .unwrap();
        let snapshot = store.group_snapshot(&root.identity().run).unwrap();
        let proof = snapshot
            .certify_child_enrollment(&os.driver, &child.run, Some(&binding))
            .unwrap();
        if existing {
            store
                .record_child_enrollment(&root, &child, &proof)
                .unwrap();
        }
        assert_writer_fenced(&mut store, checkout, |store| {
            store
                .record_child_enrollment(&root, &child, &proof)
                .map(|_| ())
        });
    }
}

#[test]
fn adopted_activity_variants_and_existing_are_fenced() {
    use crate::participants::{Activity, ActivityKind, ParticipantKey, Ref};
    for kind in [
        ActivityKind::Stop,
        ActivityKind::SubagentStart,
        ActivityKind::SubagentStop,
        ActivityKind::SessionEnd,
        ActivityKind::Reconcile,
    ] {
        for existing in [false, true] {
            let (_temp, mut store, _) = open_store();
            let checkout = Uuid::now_v7();
            insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
            let request = adopted_request(&crate::test_run_fixture::request(checkout));
            store.begin_adopted(&request).unwrap();
            let parent = ParticipantKey {
                session: request.session.clone(),
                agent: None,
            };
            let child = ParticipantKey {
                session: request.session.clone(),
                agent: Some(Ref::new("child".into()).unwrap()),
            };
            let mut event = Activity {
                run: request.identity.run.clone(),
                group: request.identity.group.clone(),
                source: request.source.clone(),
                participant: parent.clone(),
                parent: None,
                actor: None,
                prompt: None,
                tool: None,
                event_ref: Ref::new("event".into()).unwrap(),
                kind,
                observed_at: 1,
            };
            if matches!(
                kind,
                ActivityKind::SubagentStart | ActivityKind::SubagentStop
            ) {
                event.participant = child;
                event.parent = Some(parent);
            }
            if kind == ActivityKind::SubagentStop {
                let mut start = event.clone();
                start.kind = ActivityKind::SubagentStart;
                start.event_ref = Ref::new("start".into()).unwrap();
                store.record_activity(&start).unwrap();
            }
            if existing {
                store.record_activity(&event).unwrap();
            }
            assert_writer_fenced(&mut store, checkout, |store| {
                store.record_activity(&event).map(|_| ())
            });
        }
    }
}

#[test]
fn malformed_allocation_load_commits_hold_without_rewriting_corrupt_source() {
    let (_temp, mut store, _) = open_store();
    let checkout = Uuid::now_v7();
    let operation = Uuid::now_v7();
    insert_checkout(&store, checkout, operation, "owner");
    store
        .conn
        .execute(
            "INSERT INTO allocations VALUES(?1,'{}','{malformed')",
            [checkout.to_string()],
        )
        .unwrap();
    let intent = Uuid::now_v7();
    let record = seed_prepared(&store, checkout, intent);
    let before = source_rows(&store);
    let events = store.pending_events(1000).unwrap().len();
    for _ in 0..2 {
        let error = crate::allocate::load(&mut store, operation).unwrap_err();
        assert!(error.to_string().contains("retirement intent"));
        assert_eq!(source_rows(&store), before);
        let row = load_operation(&store.conn, intent).unwrap();
        assert_eq!(
            (row.stage.as_str(), row.revision, row.record.as_str()),
            ("held", 2, record.as_str())
        );
        assert_eq!(store.pending_events(1000).unwrap().len(), events + 1);
    }
}

#[test]
fn reserve_retry_hold_write_and_commit_failures_roll_back_and_still_exclude() {
    for commit in [false, true] {
        let (_temp, mut store, root) = open_store();
        let request = Reservation {
            operation: Uuid::now_v7(),
            repository: root,
            actor: "allocator".into(),
            owner: "owner".into(),
            task: "task".into(),
        };
        let checkout = store.reserve(&request, limits()).unwrap();
        let intent = Uuid::now_v7();
        seed_prepared(&store, checkout, intent);
        let before = source_rows(&store);
        let history = load_operation(&store.conn, intent).unwrap();
        let events = store.pending_events(1000).unwrap();
        if commit {
            store.conn.commit_hook(Some(|| true)).unwrap();
        } else {
            store.conn.execute_batch("CREATE TRIGGER refuse_event BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'retirement event fault'); END;").unwrap();
        }
        let error = store.reserve(&request, limits()).unwrap_err();
        assert!(matches!(error, StoreError::Database(_)), "{error:?}");
        store.conn.commit_hook(None::<fn() -> bool>).unwrap();
        if !commit {
            store
                .conn
                .execute_batch("DROP TRIGGER refuse_event;")
                .unwrap();
        }
        assert_eq!(source_rows(&store), before);
        assert_eq!(load_operation(&store.conn, intent).unwrap(), history);
        assert_eq!(store.pending_events(1000).unwrap(), events);
        for _ in 0..2 {
            assert!(matches!(
                store.reserve(&request, limits()),
                Err(StoreError::RetirementFenced)
            ));
            assert_eq!(source_rows(&store), before);
            assert_eq!(held_events(&store, checkout).len(), 1);
            assert_eq!(store.pending_events(1000).unwrap().len(), events.len() + 1);
        }
    }
}

fn digest32(tag: u8) -> [u8; 32] {
    let mut bytes = [tag; 32];
    bytes[0] = tag;
    bytes
}

fn hex32(tag: u8) -> String {
    hex(&digest32(tag))
}

fn sample_record(operation: Uuid, checkout: Uuid) -> IntentRecord {
    IntentRecord {
        version: 1,
        operation: operation.to_string(),
        checkout: checkout.to_string(),
        mode: Mode::Supervised,
        revision: 1,
        stage: Stage::Prepared,
        assertion: None,
        declaration: None,
        predecessor_hex: hex32(1),
        source_hex: hex32(2),
        history_predecessor_hex: hex32(3),
        prior_history_count: 0,
        immutable_binding: ImmutableBinding {
            version: 1,
            authority_allocation: hex32(4),
            source_sql: hex32(2),
            managed_physical: hex32(6),
            census: hex32(7),
            git_private: hex32(8),
            local_git: hex32(9),
            git_inputs: hex32(10),
            source_commitment: hex32(11),
            approval_semantic: hex32(12),
            approval_invalidation: hex32(13),
            protection: hex32(14),
            protection_count: 0,
            config_manifests: [hex32(15), hex32(16)],
            inspection_policy: hex32(17),
            combined_policy: hex32(18),
            operator: hex32(19),
            source_repository: hex32(20),
        },
        quiescence: "empty".into(),
        task_completion: "supervised_empty".into(),
        policy_digest: hex32(17),
        combined_policy_digest: hex32(18),
        prepared_wall_ms: 1,
        remote_cleanup: "not_required".into(),
    }
}

fn open_store() -> (tempfile::TempDir, Store, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let dir = temp.path().join("private");
    let store = Store::open(&dir, std::slice::from_ref(&root)).unwrap();
    (temp, store, root)
}

fn insert_checkout(store: &Store, checkout: Uuid, operation: Uuid, owner: &str) {
    store
        .conn
        .execute(
            "INSERT INTO checkouts(id,operation,digest,repository,actor,task,owner,state,ready) VALUES(?1,?2,zeroblob(32),'repo','actor','task',?3,'active',1)",
            rusqlite::params![checkout.to_string(), operation.to_string(), owner],
        )
        .unwrap();
}

pub(crate) fn seed_prepared(store: &Store, checkout: Uuid, operation: Uuid) -> String {
    let record = encode_record(&sample_record(operation, checkout)).unwrap();
    store
        .conn
        .execute(
            "INSERT INTO retirement_intents(operation,checkout,revision,stage,mode,assertion,declared_task,declared_operator,predecessor,source,record,held_reason,aborted_from) VALUES(?1,?2,1,'prepared','supervised',NULL,NULL,NULL,?3,?4,?5,NULL,NULL)",
            rusqlite::params![
                operation.to_string(),
                checkout.to_string(),
                digest32(1).as_slice(),
                digest32(2).as_slice(),
                record.as_str()
            ],
        )
        .unwrap();
    record
}

#[test]
fn abort_history_removes_only_own_frame_and_keeps_prior_tombstones() {
    let (_temp, store, _root) = open_store();
    let checkout = Uuid::now_v7();
    insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
    let first = Uuid::now_v7();
    seed_prepared(&store, checkout, first);
    abort_cas(&store.conn, checkout, first, 1).unwrap();
    let mut predecessor = b"exact-source-frame".to_vec();
    let (history, count) = frame_history(&store.conn, checkout, &mut predecessor).unwrap();
    let second = Uuid::now_v7();
    seed_prepared(&store, checkout, second);
    for held in [false, true] {
        if held {
            hold_abort_validation(&store.conn, checkout, second).unwrap();
        }
        let mut reconstructed = b"exact-source-frame".to_vec();
        assert_eq!(
            frame_history_without(&store.conn, checkout, second, &mut reconstructed).unwrap(),
            (history.clone(), count)
        );
        assert_eq!(reconstructed, predecessor);
    }
    store.conn.execute("UPDATE retirement_intents SET revision=3,aborted_from=2,held_reason='reserve' WHERE operation=?1", [first.to_string()]).unwrap();
    let mut reconstructed = b"exact-source-frame".to_vec();
    frame_history_without(&store.conn, checkout, second, &mut reconstructed).unwrap();
    assert_ne!(reconstructed, predecessor);
    store
        .conn
        .execute(
            "UPDATE retirement_intents SET record='{}' WHERE operation=?1",
            [first.to_string()],
        )
        .unwrap();
    let mut unchanged = b"exact-source-frame".to_vec();
    assert!(frame_history_without(&store.conn, checkout, second, &mut unchanged).is_err());
    assert_eq!(unchanged, b"exact-source-frame");
}

fn limits() -> Limits {
    Limits {
        repository: 10,
        owner: 10,
        available_bytes: Some(100),
        floor_bytes: 0,
        warn_bytes: 0,
    }
}

fn held_events(store: &Store, checkout: Uuid) -> Vec<Event> {
    store
        .pending_events(1000)
        .unwrap()
        .into_iter()
        .map(|pending| pending.event)
        .filter(|event| matches!(event, Event::RetirementIntentChanged { checkout: id, stage, .. } if *id == checkout && stage == "held"))
        .collect()
}

#[test]
fn strict_operation_reader_bounds_raw_columns_and_never_hides_corruption() {
    for mutation in [
        "record=printf('%.*c',8193,'x')",
        "held_reason='untrusted',stage='held',revision=2",
        "record=replace(record,'supervised_empty','unknown')",
        "predecessor=zeroblob(31)",
        "declared_operator=printf('%.*c',8193,'x')",
        "stage='aborted',revision=3,aborted_from=1,held_reason='reserve'",
    ] {
        let (_temp, store, _) = open_store();
        let checkout = Uuid::now_v7();
        let operation = Uuid::now_v7();
        insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
        seed_prepared(&store, checkout, operation);
        store
            .conn
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        store
            .conn
            .execute(&format!("UPDATE retirement_intents SET {mutation}"), [])
            .unwrap();
        assert!(
            load_operation(&store.conn, operation).is_err(),
            "{mutation}"
        );
        assert!(
            find_operation(&store.conn, operation).is_err(),
            "{mutation}"
        );
        assert!(read_history(&store.conn, checkout).is_err(), "{mutation}");
    }
    let (_temp, store, _) = open_store();
    assert!(find_operation(&store.conn, Uuid::now_v7())
        .unwrap()
        .is_none());
}

#[test]
fn canonical_history_commits_held_reason_and_aborted_from() {
    let (_temp, store, _) = open_store();
    let checkout = Uuid::now_v7();
    let operation = Uuid::now_v7();
    insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
    seed_prepared(&store, checkout, operation);
    store
        .conn
        .execute(
            "UPDATE retirement_intents SET stage='held',revision=2,held_reason='reserve'",
            [],
        )
        .unwrap();
    let first = frame_history(&store.conn, checkout, &mut Vec::new())
        .unwrap()
        .0;
    store
        .conn
        .execute(
            "UPDATE retirement_intents SET held_reason='writer_acquire'",
            [],
        )
        .unwrap();
    let second = frame_history(&store.conn, checkout, &mut Vec::new())
        .unwrap()
        .0;
    assert_ne!(first, second);
    store
        .conn
        .execute(
            "UPDATE retirement_intents SET stage='aborted',revision=3,aborted_from=2",
            [],
        )
        .unwrap();
    let third = frame_history(&store.conn, checkout, &mut Vec::new())
        .unwrap()
        .0;
    assert_ne!(second, third);
    let row = load_operation(&store.conn, operation).unwrap();
    assert_eq!(row.decoded.stage, Stage::Prepared);
    assert_eq!(row.decoded.revision, 1);
    let mut full_context = vec![0; 16 * 1024 * 1024];
    assert!(frame_history(&store.conn, checkout, &mut full_context).is_err());
    assert_eq!(full_context.len(), 16 * 1024 * 1024);
}

#[test]
fn corrupt_batch_member_rolls_back_all_holds_and_events() {
    let (_temp, mut store, _) = open_store();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    insert_checkout(&store, a, Uuid::now_v7(), "owner");
    insert_checkout(&store, b, Uuid::now_v7(), "owner");
    let first = Uuid::now_v7();
    let second = Uuid::now_v7();
    seed_prepared(&store, a, first);
    seed_prepared(&store, b, second);
    store
        .conn
        .execute(
            "UPDATE retirement_intents SET record='{}' WHERE operation=?1",
            [second.to_string()],
        )
        .unwrap();
    let events = store.pending_events(1000).unwrap().len();
    let lease = store.authority_lease().unwrap();
    assert!(matches!(
        checkpoint(
            &mut store,
            &lease,
            Scope::Owner("owner".into()),
            Attempt::OwnerRetire
        ),
        Err(StoreError::Invalid)
    ));
    assert_eq!(
        load_operation(&store.conn, first).unwrap().stage,
        "prepared"
    );
    assert_eq!(events, store.pending_events(1000).unwrap().len());
}

#[test]
fn prepare_namespace_checks_checkout_operation_writer_and_journal_ids() {
    let (_temp, store, _) = open_store();
    let checkout = Uuid::now_v7();
    let allocation = Uuid::now_v7();
    let writer = Uuid::now_v7();
    insert_checkout(&store, checkout, allocation, "owner");
    store
        .conn
        .execute(
            "INSERT INTO writers(checkout,group_id) VALUES(?1,?2)",
            (checkout.to_string(), writer.to_string()),
        )
        .unwrap();
    let intent = Uuid::now_v7();
    seed_prepared(&store, checkout, intent);
    for id in [checkout, allocation, writer, intent] {
        assert!(
            matches!(
                exclude_prepare_operation(&store.conn, id),
                Err(StoreError::Conflict)
            ),
            "{id}"
        );
    }
    // Real journal fixture supplies run/group IDs; no positive retirement proof is seeded.
    let other = Uuid::now_v7();
    insert_checkout(&store, other, Uuid::now_v7(), "owner");
    let request = crate::test_run_fixture::request(other);
    let mut store = store;
    store.begin_run(&request).unwrap();
    for id in [
        request.identity().run.to_string(),
        request.identity().group.to_string(),
    ] {
        assert!(matches!(
            exclude_prepare_operation(&store.conn, parse_uuid(&id).unwrap()),
            Err(StoreError::Conflict)
        ));
    }
    exclude_prepare_operation(&store.conn, Uuid::now_v7()).unwrap();
}

#[test]
fn cas_tombstones_are_strict_and_hold_is_once() {
    for hold in [false, true] {
        let (_temp, mut store, _) = open_store();
        let checkout = Uuid::now_v7();
        let operation = Uuid::now_v7();
        insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
        seed_prepared(&store, checkout, operation);
        let lease = store.authority_lease().unwrap();
        if hold {
            for _ in 0..2 {
                assert!(matches!(
                    checkpoint(
                        &mut store,
                        &lease,
                        Scope::Checkout(checkout),
                        Attempt::Reserve
                    ),
                    Err(StoreError::RetirementFenced)
                ));
            }
            assert_eq!(held_events(&store, checkout).len(), 1);
        }
        let revision = if hold { 2 } else { 1 };
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        assert!(abort_cas(&tx, checkout, operation, revision + 1).is_err());
        assert_eq!(
            abort_cas(&tx, checkout, operation, revision).unwrap(),
            revision + 1
        );
        tx.commit().unwrap();
        let events = store.pending_events(1000).unwrap().len();
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            abort_cas(&tx, checkout, operation, revision).unwrap(),
            revision + 1
        );
        assert!(hold_abort_validation(&tx, checkout, operation).is_err());
        tx.commit().unwrap();
        assert_eq!(events, store.pending_events(1000).unwrap().len());
        assert_eq!(
            read_history(&store.conn, checkout).unwrap()[0].stage,
            "aborted"
        );
    }
}

#[test]
fn schema_ddl_and_indexes_match_canonical_bytes() {
    let (_temp, store, _) = open_store();
    let version: i64 = store
        .conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 16);
    validate_schema(&store.conn).unwrap();
}

#[test]
fn schema15_migrates_atomically_to_16() {
    let (temp, store, root) = open_store();
    store
        .conn
        .execute_batch("DROP TABLE retirement_intents; PRAGMA user_version=15;")
        .unwrap();
    drop(store);
    let store = Store::open(&temp.path().join("private"), std::slice::from_ref(&root)).unwrap();
    let version: i64 = store
        .conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 16);
    validate_schema(&store.conn).unwrap();
}

#[test]
fn current_only_openers_reject_schema15() {
    let (temp, store, root) = open_store();
    let dir = temp.path().join("private");
    let registry = temp.path().join(".work-authorities");
    store
        .conn
        .execute_batch("DROP TABLE retirement_intents; PRAGMA user_version=15;")
        .unwrap();
    drop(store);
    assert!(matches!(
        Store::open_existing_registered_readonly(&registry, &dir, std::slice::from_ref(&root)),
        Err(StoreError::UpgradeRequired)
    ));
    assert!(matches!(
        Store::open_existing_registered_mut(&registry, &dir, std::slice::from_ref(&root)),
        Err(StoreError::UpgradeRequired)
    ));
}

#[test]
fn leftover_retirement_objects_fail_migration() {
    for leftover in [
        "CREATE TABLE retirement_intents(x INTEGER)",
        "CREATE VIEW retirement_intents AS SELECT 1 AS operation",
        "CREATE INDEX retirement_intents_active ON checkouts(id)",
    ] {
        let (temp, store, root) = open_store();
        store
            .conn
            .execute_batch("DROP TABLE retirement_intents;")
            .unwrap();
        store.conn.execute_batch(leftover).unwrap();
        store.conn.execute_batch("PRAGMA user_version=15;").unwrap();
        drop(store);
        assert!(
            Store::open(&temp.path().join("private"), std::slice::from_ref(&root)).is_err(),
            "{leftover}"
        );
    }
}

#[test]
fn interrupted_migration_rolls_back() {
    let (temp, mut store, root) = open_store();
    insert_checkout(&store, Uuid::now_v7(), Uuid::now_v7(), "owner");
    store
        .conn
        .execute_batch("DROP TABLE retirement_intents; PRAGMA user_version=15;")
        .unwrap();
    let before = source_rows(&store);
    let events = store.pending_events(1000).unwrap();
    {
        let _phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        // The identical production DDL, including all indexes and user_version,
        // executes successfully BEFORE the cumulative production VM budget fires.
        tx.execute_batch(SCHEMA).unwrap();
        assert_eq!(schema_version(&tx).unwrap(), 16);
        validate_schema(&tx).unwrap();
        let error = tx.query_row(
            "WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<20000) SELECT sum(x) FROM n",
            [], |r| r.get::<_, i64>(0),
        ).unwrap_err();
        assert!(
            matches!(error, rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::OperationInterrupted)
        );
        // Dropping an uncommitted transaction rolls back even if interruption
        // already caused SQLite to abort it. Do not retry or commit this tx.
    }
    assert_eq!(schema_version(&store.conn).unwrap(), 15);
    let objects: i64 = store
        .conn
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name LIKE 'retirement_intents%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(objects, 0);
    assert_eq!(source_rows(&store), before);
    assert_eq!(store.pending_events(1000).unwrap(), events);
    drop(store);
    let store = Store::open(&temp.path().join("private"), &[root]).unwrap();
    assert_eq!(schema_version(&store.conn).unwrap(), 16);
    validate_schema(&store.conn).unwrap();
    assert_eq!(source_rows(&store), before);
    assert_eq!(store.pending_events(1000).unwrap(), events);
}

#[test]
fn strict_codec_rejects_unknown_duplicate_and_oversized_fields() {
    let operation = Uuid::now_v7();
    let checkout = Uuid::now_v7();
    let record = sample_record(operation, checkout);
    let encoded = encode_record(&record).unwrap();
    assert!(encoded.len() <= MAX_RECORD_BYTES);
    decode_record(&encoded).unwrap();
    assert!(decode_record(&encoded.replace('}', ",\"extra\":1}")).is_err());
    assert!(
        decode_record(&encoded.replacen("\"version\":1", "\"version\":1,\"version\":1", 1))
            .is_err()
    );
    let mut wrong_binding = record.clone();
    wrong_binding.immutable_binding.source_sql = hex32(99);
    assert!(encode_record(&wrong_binding).is_err());
    let mut exhausted = record.clone();
    exhausted.prior_history_count = 64;
    assert!(encode_record(&exhausted).is_err());
    let mut huge = sample_record(operation, checkout);
    huge.quiescence = "empty".to_owned();
    huge.immutable_binding.operator = "aa".repeat(5000);
    assert!(encode_record(&huge).is_err());
    let mut adopted = sample_record(operation, checkout);
    adopted.mode = Mode::Adopted;
    assert!(encode_record(&adopted).is_err());
}

#[test]
fn relational_mismatch_and_stage_cas_are_strict() {
    let (_temp, mut store, _) = open_store();
    let checkout = Uuid::now_v7();
    let operation = Uuid::now_v7();
    insert_checkout(&store, checkout, operation, "owner");
    seed_prepared(&store, checkout, operation);
    let lease = store.authority_lease().unwrap();
    let authority = store.authority_identity().clone();
    let tx = store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    let err = fence(
        tx,
        &lease,
        &authority,
        Scope::Checkout(checkout),
        Attempt::Reserve,
    )
    .unwrap_err();
    assert!(matches!(err, StoreError::RetirementFenced));
    let row = load_operation(&store.conn, operation).unwrap();
    assert_eq!(row.stage, "held");
    assert_eq!(row.revision, 2);
    assert_eq!(row.held_reason.as_deref(), Some("reserve"));
}

#[test]
fn one_active_intent_and_operation_collisions() {
    let (_temp, store, _) = open_store();
    let checkout = Uuid::now_v7();
    let first = Uuid::now_v7();
    let second = Uuid::now_v7();
    insert_checkout(&store, checkout, first, "owner");
    seed_prepared(&store, checkout, first);
    let record = encode_record(&sample_record(second, checkout)).unwrap();
    assert!(store
        .conn
        .execute(
            "INSERT INTO retirement_intents(operation,checkout,revision,stage,mode,assertion,declared_task,declared_operator,predecessor,source,record,held_reason,aborted_from) VALUES(?1,?2,1,'prepared','supervised',NULL,NULL,NULL,?3,?4,?5,NULL,NULL)",
            rusqlite::params![
                second.to_string(),
                checkout.to_string(),
                digest32(1).as_slice(),
                digest32(2).as_slice(),
                record
            ],
        )
        .is_err());
}

#[test]
fn history_row_and_byte_bounds_fail_closed() {
    let (_temp, store, _) = open_store();
    let checkout = Uuid::now_v7();
    insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
    for _ in 0..64 {
        let operation = Uuid::now_v7();
        let encoded = encode_record(&sample_record(operation, checkout)).unwrap();
        store
            .conn
            .execute(
                "INSERT INTO retirement_intents(operation,checkout,revision,stage,mode,assertion,declared_task,declared_operator,predecessor,source,record,held_reason,aborted_from) VALUES(?1,?2,2,'aborted','supervised',NULL,NULL,NULL,?3,?4,?5,NULL,1)",
                rusqlite::params![
                    operation.to_string(),
                    checkout.to_string(),
                    digest32(1).as_slice(),
                    digest32(2).as_slice(),
                    encoded
                ],
            )
            .unwrap();
    }
    assert_eq!(read_history(&store.conn, checkout).unwrap().len(), 64);
    let extra = Uuid::now_v7();
    let encoded = encode_record(&sample_record(extra, checkout)).unwrap();
    store
        .conn
        .execute(
            "INSERT INTO retirement_intents(operation,checkout,revision,stage,mode,assertion,declared_task,declared_operator,predecessor,source,record,held_reason,aborted_from) VALUES(?1,?2,2,'aborted','supervised',NULL,NULL,NULL,?3,?4,?5,NULL,1)",
            rusqlite::params![
                extra.to_string(),
                checkout.to_string(),
                digest32(1).as_slice(),
                digest32(2).as_slice(),
                encoded
            ],
        )
        .unwrap();
    assert!(read_history(&store.conn, checkout).is_err());
}

#[test]
fn all_history_rows_are_validated_not_only_active() {
    let (_temp, store, _) = open_store();
    let checkout = Uuid::now_v7();
    let aborted = Uuid::now_v7();
    let active = Uuid::now_v7();
    insert_checkout(&store, checkout, active, "owner");
    let encoded = encode_record(&sample_record(aborted, checkout)).unwrap();
    store
        .conn
        .execute(
            "INSERT INTO retirement_intents(operation,checkout,revision,stage,mode,assertion,declared_task,declared_operator,predecessor,source,record,held_reason,aborted_from) VALUES(?1,?2,2,'aborted','supervised',NULL,NULL,NULL,?3,?4,?5,NULL,1)",
            rusqlite::params![
                aborted.to_string(),
                checkout.to_string(),
                digest32(1).as_slice(),
                digest32(2).as_slice(),
                encoded.replace("empty", "bogus")
            ],
        )
        .ok();
    seed_prepared(&store, checkout, active);
    assert!(read_history(&store.conn, checkout).is_err());
}

#[test]
fn repeated_hold_emits_nothing() {
    let (_temp, mut store, _) = open_store();
    let checkout = Uuid::now_v7();
    let operation = Uuid::now_v7();
    insert_checkout(&store, checkout, operation, "owner");
    seed_prepared(&store, checkout, operation);
    let lease = store.authority_lease().unwrap();
    let authority = store.authority_identity().clone();
    let tx = store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert!(matches!(
        fence(
            tx,
            &lease,
            &authority,
            Scope::Checkout(checkout),
            Attempt::Reserve
        ),
        Err(StoreError::RetirementFenced)
    ));
    let first = held_events(&store, checkout).len();
    let tx = store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert!(matches!(
        fence(
            tx,
            &lease,
            &authority,
            Scope::Checkout(checkout),
            Attempt::Reserve
        ),
        Err(StoreError::RetirementFenced)
    ));
    assert_eq!(held_events(&store, checkout).len(), first);
}

#[test]
fn batch_holds_all_prepared_before_any_caller_write() {
    let (_temp, mut store, _) = open_store();
    let first = Uuid::now_v7();
    let second = Uuid::now_v7();
    let held = Uuid::now_v7();
    insert_checkout(&store, first, Uuid::now_v7(), "owner");
    insert_checkout(&store, second, Uuid::now_v7(), "owner");
    insert_checkout(&store, held, Uuid::now_v7(), "owner");
    seed_prepared(&store, first, Uuid::now_v7());
    seed_prepared(&store, second, Uuid::now_v7());
    let held_op = Uuid::now_v7();
    seed_prepared(&store, held, held_op);
    store
        .conn
        .execute(
            "UPDATE retirement_intents SET revision=2, stage='held', held_reason='reserve' WHERE operation=?1",
            [held_op.to_string()],
        )
        .unwrap();
    let lease = store.authority_lease().unwrap();
    let authority = store.authority_identity().clone();
    let tx = store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert!(matches!(
        fence(
            tx,
            &lease,
            &authority,
            Scope::Owner("owner".into()),
            Attempt::OwnerRetire
        ),
        Err(StoreError::RetirementFenced)
    ));
    for checkout in [first, second, held] {
        let row = active_operation(&store.conn, checkout).unwrap().unwrap();
        assert_eq!(row.stage, "held");
        assert_eq!(row.revision, 2);
    }
    assert_eq!(held_events(&store, first).len(), 1);
    assert_eq!(held_events(&store, second).len(), 1);
    assert_eq!(held_events(&store, held).len(), 0);
}

#[test]
fn namespace_helpers_ignore_retirement_on_old_schema_only() {
    let (_temp, store, _) = open_store();
    let operation = Uuid::now_v7();
    let checkout = Uuid::now_v7();
    insert_checkout(&store, checkout, operation, "owner");
    seed_prepared(&store, checkout, operation);
    assert!(operation_reserved(&store.conn, &operation.to_string()).unwrap());
    store.conn.pragma_update(None, "user_version", 15).unwrap();
    assert!(!operation_reserved(&store.conn, &operation.to_string()).unwrap());
    store.conn.pragma_update(None, "user_version", 16).unwrap();
}

#[test]
fn reserve_retry_commits_hold_before_existing() {
    let (_temp, mut store, root) = open_store();
    let operation = Uuid::now_v7();
    let checkout = store
        .reserve(
            &Reservation {
                operation,
                repository: root.clone(),
                actor: "allocator".into(),
                owner: "owner".into(),
                task: "task".into(),
            },
            limits(),
        )
        .unwrap();
    seed_prepared(&store, checkout, Uuid::now_v7());
    let err = store
        .reserve(
            &Reservation {
                operation,
                repository: root,
                actor: "allocator".into(),
                owner: "owner".into(),
                task: "task".into(),
            },
            limits(),
        )
        .unwrap_err();
    assert!(matches!(err, StoreError::RetirementFenced));
    let active = active_operation(&store.conn, checkout).unwrap().unwrap();
    assert_eq!(active.stage, "held");
}

#[test]
fn writer_acquire_and_owner_transfer_are_fenced() {
    for acquire in [false, true] {
        for existing in [false, true] {
            let (_temp, mut store, _) = open_store();
            let checkout = Uuid::now_v7();
            insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
            let group = Uuid::now_v7();
            if acquire && existing {
                store.acquire_writer(checkout, group).unwrap();
            }
            let recipient = if existing { "owner" } else { "other" };
            assert_writer_fenced(&mut store, checkout, |store| {
                if acquire {
                    store.acquire_writer(checkout, group)
                } else {
                    store.transfer(checkout, recipient, limits())
                }
            });
        }
    }
}

#[test]
fn owner_retire_holds_every_prepared_intent() {
    let (_temp, mut store, _) = open_store();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    insert_checkout(&store, a, Uuid::now_v7(), "owner");
    insert_checkout(&store, b, Uuid::now_v7(), "owner");
    seed_prepared(&store, a, Uuid::now_v7());
    seed_prepared(&store, b, Uuid::now_v7());
    assert!(matches!(
        store.retire_owner("owner", Some("operator"), limits()),
        Err(StoreError::RetirementFenced)
    ));
    assert_eq!(
        active_operation(&store.conn, a).unwrap().unwrap().stage,
        "held"
    );
    assert_eq!(
        active_operation(&store.conn, b).unwrap().unwrap().stage,
        "held"
    );
    let owners: i64 = store
        .conn
        .query_row("SELECT count(*) FROM retired_owners", [], |r| r.get(0))
        .unwrap();
    assert_eq!(owners, 0);
}

#[test]
fn run_begin_and_adopted_begin_are_fenced() {
    for adopted in [false, true] {
        for existing in [false, true] {
            let (_temp, mut store, _) = open_store();
            let checkout = Uuid::now_v7();
            insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
            let root = crate::test_run_fixture::request(checkout);
            let request = adopted_request(&root);
            let begin = |store: &mut Store| {
                if adopted {
                    store.begin_adopted(&request)
                } else {
                    store.begin_run(&root)
                }
            };
            if existing {
                begin(&mut store).unwrap();
            }
            assert_writer_fenced(&mut store, checkout, |store| begin(store).map(|_| ()));
        }
    }
}

#[test]
fn save_under_lease_is_fenced() {
    let (_temp, mut store, _) = open_store();
    let checkout = Uuid::now_v7();
    let operation = Uuid::now_v7();
    insert_checkout(&store, checkout, operation, "owner");
    seed_prepared(&store, checkout, Uuid::now_v7());
    let allocation = crate::allocate::Allocation {
        checkout,
        request: crate::allocate::Start {
            operation,
            repository: None,
            root: None,
            actor: None,
            owner: None,
            task: "task".into(),
            branch: None,
            base: "HEAD".into(),
            reuse_branch: false,
        },
        destination: PathBuf::from("/tmp/work-retirement-fence"),
        base_commit: "0".repeat(40),
        stage: "held".into(),
        reason: None,
        identity: None,
    };
    let err = crate::allocate::save(&mut store, &allocation).unwrap_err();
    assert!(err.to_string().contains("retirement intent"));
}

#[test]
fn abort_cas_is_idempotent_and_does_not_hold_competitor() {
    let (_temp, mut store, _) = open_store();
    let checkout = Uuid::now_v7();
    let operation = Uuid::now_v7();
    let other = Uuid::now_v7();
    insert_checkout(&store, checkout, operation, "owner");
    insert_checkout(&store, other, Uuid::now_v7(), "owner");
    seed_prepared(&store, checkout, operation);
    seed_prepared(&store, other, Uuid::now_v7());
    let tx = store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert_eq!(abort_cas(&tx, checkout, operation, 1).unwrap(), 2);
    tx.commit().unwrap();
    let tx = store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert_eq!(abort_cas(&tx, checkout, operation, 1).unwrap(), 2);
    tx.commit().unwrap();
    let competitor = active_operation(&store.conn, other).unwrap().unwrap();
    assert_eq!(competitor.stage, "prepared");
}

#[test]
fn central_helper_attempt_labels_commit_hold() {
    let attempts = [
        Attempt::Reserve,
        Attempt::AllocationStage,
        Attempt::AllocationHold,
        Attempt::AllocationIdentity,
        Attempt::AliasPublication,
        Attempt::OwnerTransfer,
        Attempt::OwnerRetire,
        Attempt::WriterAcquire,
        Attempt::RunJournal,
        Attempt::GroupClose,
        Attempt::ChildJournal,
        Attempt::AdoptedBegin,
        Attempt::AdoptedActivity,
        Attempt::FinishPrepare,
        Attempt::FinishCaptureResult,
        Attempt::CapturePreparation,
        Attempt::CaptureAdmission,
        Attempt::CaptureReconcile,
        Attempt::CaptureReadiness,
        Attempt::CaptureFinalization,
        Attempt::CaptureDelivery,
        Attempt::GapAdmission,
        Attempt::GapPublication,
        Attempt::ExecutionPermit,
        Attempt::ReceiptPublication,
        Attempt::RecoveryRefs,
        Attempt::AbortValidationFailed,
    ];
    for attempt in attempts {
        let (_temp, mut store, _) = open_store();
        let checkout = Uuid::now_v7();
        insert_checkout(&store, checkout, Uuid::now_v7(), "owner");
        seed_prepared(&store, checkout, Uuid::now_v7());
        let lease = store.authority_lease().unwrap();
        let authority = store.authority_identity().clone();
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        assert!(
            matches!(
                fence(tx, &lease, &authority, Scope::Checkout(checkout), attempt),
                Err(StoreError::RetirementFenced)
            ),
            "{}",
            attempt.label()
        );
        let row = active_operation(&store.conn, checkout).unwrap().unwrap();
        assert_eq!(row.stage, "held");
        assert_eq!(row.held_reason.as_deref(), Some(attempt.label()));
    }
}
