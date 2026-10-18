use uuid::Uuid;
use work_cli::{
    admission::{Limits, Reservation},
    store::Store,
};

fn fixture() -> (tempfile::TempDir, Store, Reservation) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let store = Store::open(&dir.path().join("private"), std::slice::from_ref(&root)).unwrap();
    let request = Reservation {
        operation: Uuid::now_v7(),
        repository: root,
        actor: "actor".into(),
        owner: "alice".into(),
        task: "task".into(),
    };
    (dir, store, request)
}
fn limits() -> Limits {
    Limits {
        repository: 2,
        owner: 1,
        available_bytes: Some(300),
        floor_bytes: 200,
        warn_bytes: 250,
    }
}

#[test]
fn reservation_retry_precedes_capacity_checks_but_changed_request_conflicts() {
    let (_dir, mut store, mut request) = fixture();
    let first = store.reserve(&request, limits()).unwrap();
    let mut lowered = limits();
    lowered.repository = 0;
    lowered.available_bytes = None;
    assert_eq!(store.reserve(&request, lowered).unwrap(), first);
    request.task = "changed".into();
    assert!(store.reserve(&request, limits()).is_err());
    assert_eq!(store.charged(&request.repository, None).unwrap(), 1);
    assert_eq!(store.pending_events(100).unwrap().len(), 1);
}

#[test]
fn invalid_request_identities_are_refused() {
    for non_rfc in [false, true] {
        let (_dir, mut store, mut request) = fixture();
        if non_rfc {
            request.operation = Uuid::parse_str("00000000-0000-7000-0000-000000000000").unwrap();
        } else {
            request.owner = " alice ".into();
        }
        assert!(
            store.reserve(&request, limits()).is_err(),
            "non_rfc={non_rfc}"
        );
    }
}

#[test]
fn invalid_writer_identity_cannot_hold_a_checkout() {
    let (_dir, mut store, request) = fixture();
    let checkout = store.reserve(&request, limits()).unwrap();
    assert!(store.acquire_writer(checkout, Uuid::nil()).is_err());
}

#[test]
fn disk_and_owner_limits_fail_closed_without_new_charges() {
    let (_dir, mut store, mut request) = fixture();
    for available in [None, Some(199)] {
        let mut l = limits();
        l.available_bytes = available;
        assert!(store.reserve(&request, l).is_err());
    }
    store.reserve(&request, limits()).unwrap();
    request.operation = Uuid::now_v7();
    assert!(store.reserve(&request, limits()).is_err());
    request.owner = "bob".into();
    store.reserve(&request, limits()).unwrap();
    request.operation = Uuid::now_v7();
    request.owner = "carol".into();
    assert!(store.reserve(&request, limits()).is_err());
    assert_eq!(store.charged(&request.repository, None).unwrap(), 2);
}

#[test]
fn independent_connections_serialize_last_slot() {
    let (dir, mut first, request) = fixture();
    let mut second = Store::open(
        &dir.path().join("private"),
        std::slice::from_ref(&request.repository),
    )
    .unwrap();
    let mut other = request.clone();
    other.operation = Uuid::now_v7();
    let a = std::thread::spawn(move || first.reserve(&request, limits()));
    let b = std::thread::spawn(move || second.reserve(&other, limits()));
    assert_eq!(
        usize::from(a.join().unwrap().is_ok()) + usize::from(b.join().unwrap().is_ok()),
        1
    );
}

#[test]
fn reuse_lookup_does_not_grant_an_independent_writer() {
    let (_dir, mut store, request) = fixture();
    let checkout = store.reserve(&request, limits()).unwrap();
    assert_eq!(
        store
            .find_reusable(&request.actor, &request.repository, &request.task)
            .unwrap(),
        vec![checkout]
    );
    let group = Uuid::now_v7();
    store.acquire_writer(checkout, group).unwrap();
    store.acquire_writer(checkout, group).unwrap();
    assert!(store.acquire_writer(checkout, Uuid::now_v7()).is_err());
}
