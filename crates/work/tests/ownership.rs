use uuid::Uuid;
use work_cli::{
    admission::{Limits, Reservation},
    store::Store,
};
#[test]
fn transfer_is_capacity_checked_and_retirement_escalates_without_losing_charge() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let mut store = Store::open(&dir.path().join("private"), std::slice::from_ref(&root)).unwrap();
    let limits = Limits {
        repository: 10,
        owner: 1,
        available_bytes: Some(500),
        floor_bytes: 200,
        warn_bytes: 250,
    };
    let mut r = Reservation {
        operation: Uuid::now_v7(),
        repository: root.clone(),
        actor: "a".into(),
        owner: "alice".into(),
        task: "t".into(),
    };
    let alice = store.reserve(&r, limits).unwrap();
    r.operation = Uuid::now_v7();
    r.owner = "operator".into();
    store.reserve(&r, limits).unwrap();
    assert!(store.transfer(alice, "operator", limits).is_err());
    assert!(store.retire_owner("alice", None, limits).is_err());
    assert_eq!(store.charged(&root, Some("alice")).unwrap(), 1);
    assert_eq!(
        store
            .retire_owner("alice", Some("operator"), limits)
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .retire_owner("alice", Some("operator"), limits)
            .unwrap(),
        0
    );
    assert_eq!(store.charged(&root, Some("operator")).unwrap(), 2);
    r.operation = Uuid::now_v7();
    assert!(store.reserve(&r, limits).is_err());
    assert!(store.transfer(alice, "", limits).is_err());
    store.transfer(alice, "bob", limits).unwrap();
    store.transfer(alice, "bob", limits).unwrap();
    assert_eq!(store.charged(&root, None).unwrap(), 2);
    assert!(store.pending_events(100).unwrap().iter().any(|e| matches!(
        e.event,
        work_cli::events::Event::OwnerEscalated {
            over_quota: true,
            ..
        }
    )));
}
