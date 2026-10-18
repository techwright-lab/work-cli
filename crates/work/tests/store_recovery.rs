use std::{
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
    process::Command,
};
use uuid::Uuid;
use work_cli::{
    admission::{Limits, Reservation},
    store::Store,
};

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    private: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let private = dir.path().join("private");
        Self {
            _dir: dir,
            root,
            private,
        }
    }
    fn open(&self) -> Store {
        Store::open(&self.private, std::slice::from_ref(&self.root)).unwrap()
    }
    fn request(&self) -> Reservation {
        Reservation {
            operation: Uuid::now_v7(),
            repository: self.root.clone(),
            actor: "a".into(),
            owner: "o".into(),
            task: "t".into(),
        }
    }
    fn connection(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.private.join("store.sqlite")).unwrap()
    }
}
fn limits() -> Limits {
    Limits {
        repository: 1,
        owner: 1,
        available_bytes: Some(100),
        floor_bytes: 0,
        warn_bytes: 0,
    }
}

#[test]
fn crash_worker() {
    let Ok(path) = std::env::var("WORK_TEST_CRASH_DB") else {
        return;
    };
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch("BEGIN IMMEDIATE; DELETE FROM outbox; DELETE FROM checkouts;")
        .unwrap();
    std::process::abort();
}

#[test]
fn committed_outbox_survives_process_death_and_ack_is_idempotent() {
    let f = Fixture::new();
    let mut store = f.open();
    let request = f.request();
    let checkout = store.reserve(&request, limits()).unwrap();
    let events = store.pending_events(100).unwrap();
    drop(store);
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_worker"])
        .env("WORK_TEST_CRASH_DB", f.private.join("store.sqlite"))
        .current_dir(f._dir.path())
        .status()
        .unwrap();
    assert!(!status.success());
    let mut store = f.open();
    assert_eq!(
        store
            .charged(&request.repository, Some(&request.owner))
            .unwrap(),
        1
    );
    assert_eq!(store.reserve(&request, limits()).unwrap(), checkout);
    assert_eq!(events.len(), 1);
    assert_eq!(store.pending_events(100).unwrap(), events);
    store.acknowledge(events[0].sequence).unwrap();
    store.acknowledge(events[0].sequence).unwrap();
    assert!(store.pending_events(100).unwrap().is_empty());
    drop(store);
    assert!(f.open().pending_events(100).unwrap().is_empty());
}

#[test]
fn one_registry_refuses_a_second_store_even_for_disjoint_roots() {
    let f = Fixture::new();
    let registry = f._dir.path().join("registry");
    let other_root = f._dir.path().join("other-root");
    let repository = f._dir.path().join("repository");
    std::fs::create_dir(&other_root).unwrap();
    std::fs::create_dir(&repository).unwrap();
    let roots = vec![f.root.clone(), other_root.clone()];
    let mut request = f.request();
    // The canonical repository is independent of the managed checkout roots.
    request.repository = repository;
    let mut first =
        Store::open_registered(&registry, &f.private, std::slice::from_ref(&f.root)).unwrap();
    first.reserve(&request, limits()).unwrap();
    assert!(matches!(
        Store::open_registered(
            &registry,
            &f._dir.path().join("second-store"),
            &[other_root]
        ),
        Err(work_cli::store::StoreError::Unsafe)
    ));
    drop(first);
    // The same authority can expand its scope and reopen without losing charges.
    drop(Store::open_registered(&registry, &f.private, &roots).unwrap());
    let mut reopened = Store::open_registered(&registry, &f.private, &roots).unwrap();
    assert_eq!(
        reopened
            .charged(&request.repository, Some(&request.owner))
            .unwrap(),
        1
    );
    request.operation = Uuid::now_v7();
    assert!(matches!(
        reopened.reserve(&request, limits()),
        Err(work_cli::store::StoreError::Capacity)
    ));
}

#[test]
fn authority_and_private_storage_fail_closed() {
    let f = Fixture::new();
    let registry = f._dir.path().join("registry");
    let b = f._dir.path().join("b");
    let roots = std::slice::from_ref(&f.root);
    Store::open_registered(&registry, &f.private, roots).unwrap();
    assert!(Store::open_registered(&registry, &b, roots).is_err());
    let child = f.root.join("child");
    std::fs::create_dir(&child).unwrap();
    assert!(Store::open_registered(&registry, &b, &[child]).is_err());
    let link = f._dir.path().join("link");
    symlink(&f.private, &link).unwrap();
    assert!(Store::open(&link, roots).is_err());
    std::fs::set_permissions(
        f.private.join("store.sqlite"),
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(Store::open_registered(&registry, &f.private, roots).is_err());
}

#[test]
fn versioned_database_with_missing_accounting_is_not_reinitialized() {
    let f = Fixture::new();
    drop(f.open());
    let conn = f.connection();
    conn.execute_batch("PRAGMA foreign_keys=OFF; DROP TABLE checkouts;")
        .unwrap();
    drop(conn);
    assert!(Store::open(&f.private, std::slice::from_ref(&f.root)).is_err());
}

#[test]
fn lost_registry_database_is_not_silently_reinitialized() {
    let f = Fixture::new();
    drop(f.open());
    std::fs::remove_file(f._dir.path().join(".work-authorities/authorities.sqlite")).unwrap();
    assert!(Store::open(&f.private, std::slice::from_ref(&f.root)).is_err());
}

#[test]
fn versioned_registry_with_missing_claims_is_not_reinitialized() {
    let f = Fixture::new();
    drop(f.open());
    let conn =
        rusqlite::Connection::open(f._dir.path().join(".work-authorities/authorities.sqlite"))
            .unwrap();
    conn.execute_batch("DROP TABLE authorities;").unwrap();
    drop(conn);
    assert!(Store::open(&f.private, std::slice::from_ref(&f.root)).is_err());
}

#[test]
fn a_claimed_authority_never_recreates_a_lost_database() {
    let f = Fixture::new();
    drop(f.open());
    std::fs::remove_file(f.private.join("store.sqlite")).unwrap();
    assert!(Store::open(&f.private, std::slice::from_ref(&f.root)).is_err());
}

#[test]
fn every_nonretired_state_retains_its_charge() {
    let f = Fixture::new();
    let mut store = f.open();
    let r = f.request();
    store.reserve(&r, limits()).unwrap();
    let conn = f.connection();
    for state in [
        "reserved",
        "partial",
        "active",
        "expired",
        "interrupted",
        "held",
        "quarantined",
        "partially_deleted",
    ] {
        conn.execute("UPDATE checkouts SET state=?1", [state])
            .unwrap();
        assert_eq!(store.charged(&f.root, None).unwrap(), 1, "{state}");
        let mut next = r.clone();
        next.operation = Uuid::now_v7();
        assert!(store.reserve(&next, limits()).is_err(), "{state}");
    }
}

#[test]
fn bounded_busy_and_unknown_schema_are_errors() {
    let f = Fixture::new();
    let mut store = f.open();
    let conn = f.connection();
    assert_eq!(
        conn.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "wal"
    );
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let start = std::time::Instant::now();
    assert!(store.reserve(&f.request(), limits()).is_err());
    assert!(start.elapsed().as_secs() < 3);
    conn.execute_batch("ROLLBACK; PRAGMA user_version=999;")
        .unwrap();
    drop(store);
    drop(conn);
    assert!(Store::open(&f.private, std::slice::from_ref(&f.root)).is_err());
}
