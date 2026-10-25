#[path = "../tests/support/capture_finalization_fixture.rs"]
mod capture_fixture;
use crate::store::Store;
use crate::test_run_fixture as fixture_support;
use std::cell::RefCell;

type Observer = Box<dyn FnMut(&str, &crate::store::Store)>;
thread_local! {
    static OBSERVER: RefCell<Option<Observer>> = RefCell::new(None);
}
pub(super) fn observe(stage: &str, store: &crate::store::Store) {
    OBSERVER.with(|slot| {
        if let Some(f) = slot.borrow_mut().as_mut() {
            f(stage, store);
        }
    });
}
struct ObserveGuard;
impl Drop for ObserveGuard {
    fn drop(&mut self) {
        OBSERVER.with(|s| *s.borrow_mut() = None);
    }
}
fn observing(f: impl FnMut(&str, &crate::store::Store) + 'static) -> ObserveGuard {
    OBSERVER.with(|s| *s.borrow_mut() = Some(Box::new(f)));
    ObserveGuard
}

fn seed_prepared_fence(store: &crate::store::Store, checkout: uuid::Uuid) {
    crate::retirement_journal::tests::seed_prepared(store, checkout, uuid::Uuid::now_v7());
    let rows = crate::retirement_journal::read_history(&store.conn, checkout).unwrap();
    assert_eq!(
        (rows.len(), rows[0].revision, rows[0].stage.as_str()),
        (1, 1, "prepared")
    );
}

fn run_checkout(root: &crate::run_journal::RootRunRequest) -> uuid::Uuid {
    uuid::Uuid::parse_str(&root.identity().checkout.to_string()).unwrap()
}

#[test]
fn competitor_confirmation_before_dispatch_is_passive() {
    let f = capture_fixture::Fixture::new(true, Some(crate::run_journal::RootOutcome::Completed));
    let mut called = false;
    let checkout = run_checkout(&f.root);
    let guard = crate::checkout_guard::CheckoutGuard::shared_known(&f.config, checkout).unwrap();
    let (_, result) = super::finalize_after_preflight(
        &f.config,
        &f.root.identity().run,
        || called = true,
        || {
            assert!(super::finalize(&f.config, &f.root.identity().run).is_ok());
        },
        &guard,
    )
    .unwrap();
    assert!(
        !called,
        "confirmed competitor must suppress callback and dispatch"
    );
    assert!(matches!(result, super::FinalizeResult::Existing(_)));
    assert_eq!(
        std::fs::read_to_string(f.dir.path().join("calls")).unwrap(),
        "finish\n"
    );
    assert_eq!(
        f.store
            .capture_finalization_snapshot(&f.root.identity().run)
            .unwrap()
            .unwrap()
            .revision,
        2
    );
    assert_eq!(
        f.sql()
            .query_row("SELECT count(*) FROM capture_finalizations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
#[test]
fn finalize_under_guard_refuses_mismatched_checkout() {
    let f = capture_fixture::Fixture::new(true, Some(crate::run_journal::RootOutcome::Completed));
    let store = Store::open_existing_registered_mut(
        f.config.trusted_registry.as_ref().unwrap(),
        f.config.store_dir.as_ref().unwrap(),
        &f.config.roots,
    )
    .unwrap();
    let guard = crate::checkout_guard::CheckoutGuard::shared(&store, uuid::Uuid::now_v7()).unwrap();
    assert!(matches!(
        super::finalize_under_guard(&f.config, &f.root.identity().run, || {}, || {}, &guard,),
        Err(crate::store::StoreError::Invalid)
    ));
    assert!(
        !f.dir.path().join("calls").exists()
            || f.dir
                .path()
                .join("calls")
                .metadata()
                .map(|m| m.len())
                .unwrap_or(0)
                == 0
    );
}
#[test]
fn finalize_holds_prepared_intent_before_finish() {
    let f = capture_fixture::Fixture::new(true, Some(crate::run_journal::RootOutcome::Completed));
    let checkout = run_checkout(&f.root);
    seed_prepared_fence(&f.store, checkout);
    let source_before = crate::retirement_journal::tests::source_rows(&f.store);
    let before: i64 = f
        .sql()
        .query_row("SELECT count(*) FROM capture_finalizations", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(matches!(
        super::finalize(&f.config, &f.root.identity().run),
        Err(crate::store::StoreError::RetirementFenced)
    ));
    assert!(!f.dir.path().join("calls").exists());
    let (revision, stage, reason): (i64, String, Option<String>) = f
        .store
        .conn
        .query_row(
            "SELECT revision, stage, held_reason FROM retirement_intents WHERE checkout=?1",
            [checkout.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (revision, stage.as_str(), reason.as_deref()),
        (2, "held", Some("capture_finalization"))
    );
    let after: i64 = f
        .sql()
        .query_row("SELECT count(*) FROM capture_finalizations", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(
        crate::retirement_journal::tests::source_rows(&f.store),
        source_before
    );
    assert_eq!(f.store.pending_events(1000).unwrap().iter().filter(|e|
        matches!(&e.event, crate::events::Event::RetirementIntentChanged { stage, .. } if stage == "held")
    ).count(), 1);
}
#[test]
fn retry_holds_prepared_intent_before_receiver() {
    let f = capture_fixture::Fixture::new(true, Some(crate::run_journal::RootOutcome::Completed));
    super::finalize(&f.config, &f.root.identity().run).unwrap();
    let checkout = run_checkout(&f.root);
    seed_prepared_fence(&f.store, checkout);
    let source_before = crate::retirement_journal::tests::source_rows(&f.store);
    let calls_before = std::fs::read(f.dir.path().join("calls")).unwrap();
    f.respond("pending", serde_json::json!({}), false);
    let saw = std::rc::Rc::new(std::cell::Cell::new(false));
    let flag = saw.clone();
    let _observe = observing(move |stage, _| {
        if stage == "pre_retry" {
            flag.set(true);
        }
    });
    assert!(matches!(
        super::retry_delivery(&f.config, &f.root.identity().run),
        Err(crate::store::StoreError::RetirementFenced)
    ));
    assert!(!saw.get());
    let reason: String = f
        .store
        .conn
        .query_row(
            "SELECT held_reason FROM retirement_intents WHERE checkout=?1",
            [checkout.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(reason, "capture_delivery");
    assert_eq!(
        crate::retirement_journal::tests::source_rows(&f.store),
        source_before
    );
    assert_eq!(
        std::fs::read(f.dir.path().join("calls")).unwrap(),
        calls_before
    );
    let rows = crate::retirement_journal::read_history(&f.store.conn, checkout).unwrap();
    assert_eq!((rows[0].revision, rows[0].stage.as_str()), (2, "held"));
    assert_eq!(f.store.pending_events(1000).unwrap().iter().filter(|e|
        matches!(&e.event, crate::events::Event::RetirementIntentChanged { stage, .. } if stage == "held")
    ).count(), 1);
}
#[test]
fn delivery_commit_fences_after_receiver_without_mutating_caller_rows() {
    let f = capture_fixture::Fixture::new(true, Some(crate::run_journal::RootOutcome::Completed));
    super::finalize(&f.config, &f.root.identity().run).unwrap();
    f.respond("pending", serde_json::json!({}), false);
    let checkout = run_checkout(&f.root);
    let before = std::rc::Rc::new(RefCell::new(None));
    let observed = before.clone();
    let _observer = observing(move |stage, store| {
        if stage == "pre_retry" {
            seed_prepared_fence(store, checkout);
            *observed.borrow_mut() = Some(crate::retirement_journal::tests::source_rows(store));
        }
    });
    let calls_before = std::fs::read(f.dir.path().join("calls")).unwrap();
    assert!(super::retry_delivery(&f.config, &f.root.identity().run).is_err());
    assert!(before.borrow().is_some(), "retry boundary not reached");
    assert_ne!(
        std::fs::read(f.dir.path().join("calls")).unwrap(),
        calls_before,
        "receiver retry must actually precede confirmation fencing"
    );
    assert_eq!(
        crate::retirement_journal::tests::source_rows(&f.store),
        before.borrow().as_ref().unwrap().clone()
    );
    let rows = crate::retirement_journal::read_history(&f.store.conn, checkout).unwrap();
    assert_eq!(
        (
            rows[0].revision,
            rows[0].stage.as_str(),
            rows[0].held_reason.as_deref()
        ),
        (2, "held", Some("capture_delivery"))
    );
    assert_eq!(f.store.pending_events(1000).unwrap().iter().filter(|e|
        matches!(&e.event, crate::events::Event::RetirementIntentChanged { stage, .. } if stage == "held")
    ).count(), 1);
}
#[test]
fn finalize_shared_guard_excludes_exclusive_until_drain() {
    let f = capture_fixture::Fixture::new(true, Some(crate::run_journal::RootOutcome::Completed));
    let checkout = run_checkout(&f.root);
    let registry = f.config.trusted_registry.clone().unwrap();
    let dir = f.config.store_dir.clone().unwrap();
    let roots = f.config.roots.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let handle = std::thread::spawn(move || {
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("finalization never reached pre-dispatch boundary");
        let other = Store::open_existing_registered_mut(&registry, &dir, &roots).unwrap();
        assert!(matches!(
            crate::checkout_guard::CheckoutGuard::exclusive(&other, checkout),
            Err(crate::store::StoreError::OperationsInFlight)
        ));
        crate::checkout_guard::CheckoutGuard::shared(&other, uuid::Uuid::now_v7()).unwrap();
        let lock = crate::store::AuthorityIdentity::open_lock(
            &other.authority_identity().directory,
            false,
        )
        .unwrap();
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        drop(lock);
        release_tx.send(()).unwrap();
    });
    let mut reached = false;
    let result = super::finalize_observed(&f.config, &f.root.identity().run, || {
        reached = true;
        ready_tx.send(()).unwrap();
        release_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("finalization guard worker did not acknowledge");
    });
    drop(ready_tx);
    let worker = handle.join();
    assert!(reached, "finalization boundary not reached");
    worker.unwrap();
    assert!(result.is_ok());
    let other = Store::open_existing_registered_mut(
        f.config.trusted_registry.as_ref().unwrap(),
        f.config.store_dir.as_ref().unwrap(),
        &f.config.roots,
    )
    .unwrap();
    crate::checkout_guard::CheckoutGuard::exclusive(&other, checkout).unwrap();
}
#[test]
fn unknown_run_finalize_does_not_invent_fence() {
    let f = capture_fixture::Fixture::new(true, Some(crate::run_journal::RootOutcome::Completed));
    let unknown = work_contract::RunId::parse(&uuid::Uuid::now_v7().to_string()).unwrap();
    assert!(matches!(
        super::finalize(&f.config, &unknown),
        Err(crate::store::StoreError::Invalid)
    ));
    let count: i64 = f
        .sql()
        .query_row("SELECT count(*) FROM retirement_intents", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}
