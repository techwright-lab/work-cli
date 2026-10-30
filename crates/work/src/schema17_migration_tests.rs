//! W2A existing-API witnesses: behavioral RED observed by parent in CI40214735773.
//! Additional W2B cases are AUTHORED_ONLY until parent isolated CI.
//! This smoke does not replace the later counterfeit-DDL/codec/role matrix.
use super::Store;
use crate::{
    admission::{Limits, Reservation},
    events::Event,
};
use rusqlite::types::Value;
use std::{collections::BTreeMap, path::PathBuf};
use uuid::Uuid;

fn initialized() -> (tempfile::TempDir, PathBuf, Store) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let store = Store::open_registered(
        &temp.path().join("registry"),
        &temp.path().join("private"),
        std::slice::from_ref(&root),
    )
    .unwrap();
    (temp, root, store)
}

#[test]
fn schema17_current_open_is_exact() {
    let (_temp, _root, store) = initialized();
    let _phase = store.sql_phase();
    let version: i64 = store
        .conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    // Deliberately first: native schema16 must fail here, not in later SQL setup.
    assert_eq!(version, 17, "fresh current Store must publish schema17");

    let table_count: i64 = store
        .conn
        .query_row(
            "SELECT count(*) FROM sqlite_schema
             WHERE type='table' AND name='quarantine_actions' AND sql IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(table_count, 1);
    let mut statement = store
        .conn
        .prepare(
            "SELECT name,type,\"notnull\",pk FROM pragma_table_info('quarantine_actions')
             ORDER BY cid",
        )
        .unwrap();
    let columns = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let expected = [
        ("operation", "TEXT", 1),
        ("checkout", "TEXT", 0),
        ("revision", "INTEGER", 0),
        ("state", "TEXT", 0),
        ("plan", "TEXT", 0),
        ("result", "TEXT", 0),
    ];
    assert_eq!(columns.len(), expected.len(), "exactly six action columns");
    for ((name, kind, not_null, primary_key), (expected_name, expected_kind, expected_pk)) in
        columns.iter().zip(expected)
    {
        assert_eq!(name, expected_name);
        assert!(kind.eq_ignore_ascii_case(expected_kind), "{name}: {kind}");
        assert_eq!(*primary_key, expected_pk, "{name} primary-key position");
        match name.as_str() {
            "checkout" | "revision" | "state" | "plan" => assert!(*not_null, "{name}"),
            "result" => assert!(!not_null, "pending result must permit NULL"),
            _ => {}
        }
    }

    let mut statement = store
        .conn
        .prepare(
            "SELECT \"table\",\"from\",\"to\" FROM pragma_foreign_key_list('quarantine_actions')",
        )
        .unwrap();
    let foreign_keys = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(foreign_keys.contains(&(
        "retirement_intents".into(),
        "operation".into(),
        "operation".into(),
    )));
    assert!(foreign_keys.contains(&("checkouts".into(), "checkout".into(), "id".into())));

    // Inspect explicit, nonpartial indexes without prescribing an index name or SQL spelling.
    let mut statement = store
        .conn
        .prepare(
            "SELECT i.name FROM pragma_index_list('quarantine_actions') AS i
             JOIN sqlite_schema AS s ON s.type='index' AND s.name=i.name
             WHERE i.origin='c' AND i.partial=0 AND s.tbl_name='quarantine_actions'
             AND s.sql IS NOT NULL ORDER BY i.name",
        )
        .unwrap();
    let indexes = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let mut has_checkout_index = false;
    for index in indexes {
        let mut statement = store
            .conn
            .prepare("SELECT name FROM pragma_index_info(?1) ORDER BY seqno")
            .unwrap();
        let indexed_columns = statement
            .query_map([index], |row| row.get::<_, Option<String>>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        has_checkout_index |= indexed_columns == [Some("checkout".to_owned())];
    }
    assert!(has_checkout_index, "missing explicit checkout index");
}

#[test]
fn identity_preflight_releases_sql_and_schema_before_return() {
    use super::schema_participation_tests::{probe_initialization_exclusive, ExclusiveProbe};
    let (temp, root, mut store) = initialized();
    let registry = temp.path().join("registry");
    let directory = temp.path().join("private");
    let (request, _) = reserve_event(&mut store, root.clone());
    let before = snapshot(&store, &request);
    drop(store);
    assert_eq!(
        probe_initialization_exclusive(&registry).unwrap(),
        ExclusiveProbe::Acquired
    );

    // Keep the successful result alive at the probe. Returning an old temporary
    // Store would retain its readonly BEGIN and actual SH, not merely identity DATA.
    let result = Store::preflight_existing_identity(
        &registry,
        &directory,
        std::slice::from_ref(&root),
        |version| version == before.user_version,
    );
    assert!(result.is_ok());
    let returned = probe_initialization_exclusive(&registry);
    drop(result);
    assert_eq!(returned.unwrap(), ExclusiveProbe::Acquired);

    let reopened =
        Store::open_existing_registered_readonly(&registry, &directory, &[root]).unwrap();
    assert_eq!(snapshot(&reopened, &request), before);
}

#[test]
fn identity_preflight_refusal_releases_sql_and_schema() {
    use super::schema_participation_tests::{probe_initialization_exclusive, ExclusiveProbe};
    let (temp, root, mut store) = initialized();
    let registry = temp.path().join("registry");
    let directory = temp.path().join("private");
    let (request, _) = reserve_event(&mut store, root.clone());
    let before = snapshot(&store, &request);
    drop(store);

    let result = Store::preflight_existing_identity(
        &registry,
        &directory,
        std::slice::from_ref(&root),
        |_| false,
    );
    assert!(matches!(result, Err(super::StoreError::UpgradeRequired)));
    assert_eq!(
        probe_initialization_exclusive(&registry).unwrap(),
        ExclusiveProbe::Acquired
    );
    let reopened =
        Store::open_existing_registered_readonly(&registry, &directory, &[root]).unwrap();
    assert_eq!(snapshot(&reopened, &request), before);
}

#[test]
fn shared_known_retains_current_readonly_schema_owner() {
    use super::schema_participation_tests::{probe_initialization_exclusive, ExclusiveProbe};
    use crate::checkout_guard::CheckoutGuard;
    let (temp, root, mut store) = initialized();
    let registry = temp.path().join("registry");
    let directory = temp.path().join("private");
    let (request, _) = reserve_event(&mut store, root.clone());
    let checkout = match store.pending_events(2).unwrap().remove(0).event {
        Event::Reserved { checkout, .. } => checkout,
        _ => panic!("expected actual reservation event"),
    };
    let before = snapshot(&store, &request);
    drop(store);
    let config = crate::config::Config {
        trusted_registry: Some(registry.clone()),
        store_dir: Some(directory.clone()),
        roots: vec![root.clone()],
        ..crate::config::Config::default()
    };
    assert_eq!(
        probe_initialization_exclusive(&registry).unwrap(),
        ExclusiveProbe::Acquired
    );
    // shared_known must close its readonly BEGIN before taking checkout SH,
    // while retaining the actual initialization owner after its Store closes.
    let first = CheckoutGuard::shared_known(&config, checkout).unwrap();
    let first_alive = probe_initialization_exclusive(&registry);
    let second = CheckoutGuard::shared_known(&config, checkout).unwrap();
    let both_alive = probe_initialization_exclusive(&registry);
    drop(first);
    let second_alive = probe_initialization_exclusive(&registry);
    drop(second);
    let all_dropped = probe_initialization_exclusive(&registry);
    assert_eq!(first_alive.unwrap(), ExclusiveProbe::Blocked);
    assert_eq!(both_alive.unwrap(), ExclusiveProbe::Blocked);
    assert_eq!(second_alive.unwrap(), ExclusiveProbe::Blocked);
    assert_eq!(all_dropped.unwrap(), ExclusiveProbe::Acquired);
    let reopened =
        Store::open_existing_registered_readonly(&registry, &directory, &[root]).unwrap();
    assert_eq!(snapshot(&reopened, &request), before);
}

fn reserve_event(store: &mut Store, root: PathBuf) -> (Reservation, i64) {
    let request = Reservation {
        operation: Uuid::now_v7(),
        repository: root,
        actor: "actor".into(),
        owner: "actor".into(),
        task: "task".into(),
    };
    let checkout = store
        .reserve(
            &request,
            Limits {
                repository: 10,
                owner: 10,
                available_bytes: Some(100),
                floor_bytes: 0,
                warn_bytes: 0,
            },
        )
        .unwrap();
    let events = store.pending_events(2).unwrap();
    assert_eq!(events.len(), 1, "reservation must emit one genuine event");
    assert_eq!(
        events[0].event,
        Event::Reserved {
            checkout,
            low_disk: false,
        }
    );
    (request, events[0].sequence)
}

#[test]
fn historical_v17_rejects_pinned_version_drift() {
    let (temp, root, store) = initialized();
    let historical = Store::open_retirement_readonly(
        &temp.path().join("registry"),
        &temp.path().join("private"),
        &[root],
    )
    .unwrap();
    assert_eq!(
        historical.schema_role(),
        super::SchemaRole::HistoricalRead(super::SupportedRetirementVersion::V17)
    );
    historical.conn.execute_batch("ROLLBACK;").unwrap();
    store.conn.pragma_update(None, "user_version", 16).unwrap();
    let _phase = historical.sql_phase();
    historical.conn.execute_batch("BEGIN;").unwrap();
    assert!(historical.schema_role().validate(&historical.conn).is_err());
    historical.conn.execute_batch("ROLLBACK;").unwrap();
}

#[test]
fn readonly_roles_refuse_authority_mutation() {
    let (temp, root, mut store) = initialized();
    let (request, sequence) = reserve_event(&mut store, root.clone());
    let before = snapshot(&store, &request);
    for historical in [false, true] {
        let mut reader = if historical {
            Store::open_retirement_readonly(
                &temp.path().join("registry"),
                &temp.path().join("private"),
                std::slice::from_ref(&root),
            )
            .map_err(super::RetirementAdmissionError::into_store_error)
        } else {
            Store::open_existing_registered_readonly(
                &temp.path().join("registry"),
                &temp.path().join("private"),
                std::slice::from_ref(&root),
            )
        }
        .unwrap();
        assert_eq!(
            reader
                .conn
                .query_row("PRAGMA query_only", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        reader.conn.execute_batch("ROLLBACK;").unwrap();
        assert!(reader.authority_lease().is_err());
        assert!(reader.acknowledge(sequence).is_err());
        assert_eq!(snapshot(&store, &request), before);
    }
}

#[test]
fn outbox_ack_rejects_global_orphan_even_for_missing_sequence() {
    let (_temp, root, mut store) = initialized();
    let (request, sequence) = reserve_event(&mut store, root);
    // Negative SQL injection only: deliberately NOT a valid parent/action fixture.
    store
        .conn
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .unwrap();
    store
        .conn
        .execute(
            "INSERT INTO quarantine_actions VALUES(?1,?2,1,'move_pending','{}',NULL)",
            (Uuid::now_v7().to_string(), Uuid::now_v7().to_string()),
        )
        .unwrap();
    store.conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    let before = snapshot(&store, &request);
    for id in [sequence, i64::MAX] {
        assert!(store.acknowledge(id).is_err());
        assert_eq!(snapshot(&store, &request), before);
    }
}

#[test]
fn direct_writer_rejects_actual_version_drift_before_existing_shortcut() {
    // Native allocation publishes readiness; a reservation alone would make the
    // eligibility check reject independently of version admission.
    let mut fixture = crate::inspection::fixture::ManagedFixture::new("sha1", "2");
    let checkout = fixture.allocation.checkout;
    let request = Reservation {
        operation: fixture.allocation.request.operation,
        repository: fixture.repo.clone(),
        actor: "fixture".into(),
        owner: "fixture".into(),
        task: "inspection".into(),
    };
    let store = &mut fixture.store;
    let eligible: (String, bool) = store
        .conn
        .query_row(
            "SELECT state,ready FROM checkouts WHERE id=?1",
            [checkout.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(eligible, ("active".into(), true));
    let lease = store.authority_lease().unwrap();
    lease.check(store).unwrap();
    let authority = store.authority_identity().clone();
    let group = Uuid::now_v7();
    {
        let _phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        super::acquire_writer_tx(&tx, checkout, group, false, &lease, &authority).unwrap();
        tx.commit().unwrap();
    }
    let admitted = snapshot(store, &request);
    assert_eq!(admitted.repository_charge, 1);
    assert_eq!(admitted.owner_charge, 1);
    assert_eq!(
        store
            .conn
            .query_row(
                "SELECT group_id FROM writers WHERE checkout=?1",
                [checkout.to_string()],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        group.to_string()
    );
    {
        // SAME admitted group: prove the real Existing branch succeeds without
        // another event or row change before fault injection.
        let _phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        super::acquire_writer_tx(&tx, checkout, group, true, &lease, &authority).unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(snapshot(store, &request), admitted);
    store.conn.pragma_update(None, "user_version", 16).unwrap();
    let before = snapshot(store, &request);
    assert_eq!(before.user_version, 16);
    assert_eq!(before.schema_version, admitted.schema_version);
    assert_eq!(before.tables, admitted.tables);
    assert_eq!(before.repository_charge, admitted.repository_charge);
    assert_eq!(before.owner_charge, admitted.owner_charge);
    let phase = store.sql_phase();
    let tx = store
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    let result = super::acquire_writer_tx(&tx, checkout, group, true, &lease, &authority);
    tx.rollback().unwrap();
    drop(phase);
    let after = snapshot(store, &request);
    assert!(
        result.is_err(),
        "version drift must reject the proven Existing writer: {result:?}"
    );
    assert_eq!(after, before);
}

#[test]
fn empty_physical_history_has_explicit_current_domain() {
    let (_temp, _root, store) = initialized();
    let _phase = store.sql_phase();
    let mut canonical = b"source".to_vec();
    let (history, count) =
        crate::quarantine_journal::frame_history(&store.conn, Uuid::now_v7(), &mut canonical)
            .unwrap();
    assert_eq!(count, 0);
    assert!(history
        .windows(b"work.quarantine.history.v1".len())
        .any(|part| part == b"work.quarantine.history.v1"));
    assert_eq!(&canonical[6..], history);
}

#[test]
fn migration_children_retain_actual_ex_and_refuse_ordinary_authority() {
    use super::schema_participation_tests::{probe_initialization_exclusive, ExclusiveProbe};
    let (temp, root, mut store) = initialized();
    let (_request, _) = reserve_event(&mut store, root);
    let checkout: String = store
        .conn
        .query_row("SELECT id FROM checkouts", [], |r| r.get(0))
        .unwrap();
    let checkout = Uuid::parse_str(&checkout).unwrap();
    let authority = store.authority_identity().clone();
    drop(store);
    let registry = temp.path().join("registry");
    let initialization = super::ExclusiveInitialization::acquire(&registry, false).unwrap();
    let guard = crate::checkout_guard::CheckoutGuard::exclusive_for_migration(
        &authority,
        &initialization,
        checkout,
    )
    .unwrap();
    let lease = crate::allocate::migration_lease(&authority, &initialization).unwrap();
    assert!(lease.check_authority(&authority).is_err());
    lease.check_migration(&authority).unwrap();
    drop(initialization);
    assert_eq!(
        probe_initialization_exclusive(&registry).unwrap(),
        ExclusiveProbe::Blocked
    );
    drop(guard);
    assert_eq!(
        probe_initialization_exclusive(&registry).unwrap(),
        ExclusiveProbe::Blocked
    );
    drop(lease);
    assert_eq!(
        probe_initialization_exclusive(&registry).unwrap(),
        ExclusiveProbe::Acquired
    );
}

#[test]
fn outbox_ack_commit_veto_rolls_back_without_history_mutation() {
    let (_temp, root, mut store) = initialized();
    let (request, sequence) = reserve_event(&mut store, root);
    let before = snapshot(&store, &request);
    let reached = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = reached.clone();
    store
        .conn
        .commit_hook(Some(move || {
            observed.store(true, std::sync::atomic::Ordering::SeqCst);
            true
        }))
        .unwrap();
    let result = store.acknowledge(sequence);
    store.conn.commit_hook(None::<fn() -> bool>).unwrap();
    assert!(reached.load(std::sync::atomic::Ordering::SeqCst));
    assert!(result.is_err());
    assert_eq!(snapshot(&store, &request), before);
}

#[test]
fn pending_empty_bootstrap_without_sidecars_resumes() {
    use std::os::unix::process::ExitStatusExt;
    for (boundary, database) in [
        ("registry_db", ".work-authorities/authorities.sqlite"),
        ("store_db", "private/store.sqlite"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        // Actual initialization owner/marker and original crash hook, not
        // copied bootstrap proof. No Store or live owner escaped the child.
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "store::tests::initialization_worker"])
            .env("WORK_INIT_TEST_BASE", temp.path())
            .env("WORK_INIT_TEST_BOUNDARY", boundary)
            .current_dir(temp.path())
            .status()
            .unwrap();
        assert_eq!(
            status.signal(),
            Some(6),
            "unreached bootstrap boundary {boundary}"
        );
        let path = temp.path().join(database);
        let header = std::fs::read(&path).unwrap();
        assert!(header.len() >= 100);
        assert_eq!(&header[..16], b"SQLite format 3\0");
        assert_eq!(&header[40..44], &[0; 4]);
        assert_eq!(&header[60..64], &[0; 4]);
        for suffix in ["-wal", "-shm", "-journal"] {
            assert!(!temp.path().join(format!("{database}{suffix}")).exists());
        }
        let store = Store::open(&temp.path().join("private"), std::slice::from_ref(&root)).unwrap();
        assert_eq!(store.schema_role(), super::SchemaRole::Current17);
        assert_eq!(store.charged(&root, None).unwrap(), 0);
        assert!(store.pending_events(1).unwrap().is_empty());
    }
}

#[test]
fn pending_existing_storage_refuses_before_either_journal_transition() {
    use super::schema_participation_tests::{probe_initialization_exclusive, ExclusiveProbe};
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;

    // Include directory entries/identities and every native fixture file. Any
    // new WAL/SHM/journal, replaced inode, cookie, claim or history write changes
    // this baseline. Read-atime and ephemeral SHM read marks are not compared;
    // complete logical equality below still protects data, journals and quotas.
    fn files(path: &std::path::Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let meta = std::fs::symlink_metadata(path).unwrap();
        let mut value = Vec::new();
        // SQLite readers legitimately update WAL-index read marks in SHM.
        // Keep its identity/type/mode/size and the exact sidecar set, but do not
        // treat transient read-mark bytes/timestamps as durable user state.
        let shm = path
            .file_name()
            .is_some_and(|name| name == "store.sqlite-shm" || name == "authorities.sqlite-shm");
        for number in [
            meta.dev(),
            meta.ino(),
            meta.mode() as u64,
            meta.uid() as u64,
            meta.gid() as u64,
            meta.nlink(),
            meta.len(),
            if shm { 0 } else { meta.mtime() as u64 },
            if shm { 0 } else { meta.mtime_nsec() as u64 },
            if shm { 0 } else { meta.ctime() as u64 },
            if shm { 0 } else { meta.ctime_nsec() as u64 },
        ] {
            value.extend_from_slice(&number.to_be_bytes());
        }
        if meta.is_file() && !shm {
            value.extend_from_slice(&Sha256::digest(std::fs::read(path).unwrap()));
        }
        out.insert(path.to_owned(), value);
        if meta.is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                files(&entry.unwrap().path(), out);
            }
        }
    }
    fn deltas(
        phase: &str,
        case: (i64, bool),
        before: &BTreeMap<PathBuf, Vec<u8>>,
        after: &BTreeMap<PathBuf, Vec<u8>>,
    ) {
        let paths: std::collections::BTreeSet<_> = before.keys().chain(after.keys()).collect();
        eprintln!(
            "pending-storage case={case:?} phase={phase} equal={}",
            before == after
        );
        for path in paths {
            if before.get(path) == after.get(path) {
                continue;
            }
            eprintln!("pending-storage case={case:?} phase={phase} path={path:?}");
            match (before.get(path), after.get(path)) {
                (Some(old), Some(new)) => {
                    for (index, field) in [
                        "dev",
                        "ino",
                        "mode",
                        "uid",
                        "gid",
                        "nlink",
                        "len",
                        "mtime",
                        "mtime_nsec",
                        "ctime",
                        "ctime_nsec",
                    ]
                    .iter()
                    .enumerate()
                    {
                        let start = index * 8;
                        let old = u64::from_be_bytes(old[start..start + 8].try_into().unwrap());
                        let new = u64::from_be_bytes(new[start..start + 8].try_into().unwrap());
                        if old != new {
                            eprintln!("  {field}: {old} -> {new}");
                        }
                    }
                    if old[88..] != new[88..] {
                        eprintln!(
                            "  content_sha256: {:02x?} -> {:02x?}",
                            &old[88..],
                            &new[88..]
                        );
                    }
                }
                (old, new) => eprintln!("  entry: {old:?} -> {new:?}"),
            }
        }
    }
    for (version, store_wal) in [
        (16, false),
        (16, true),
        (0, false),
        (0, true),
        (17, false),
        (18, false),
    ] {
        let crate::inspection::fixture::ManagedFixture {
            temp,
            repo,
            root,
            allocation,
            store,
        } = crate::inspection::fixture::ManagedFixture::new("sha1", "2");
        let request = Reservation {
            operation: allocation.request.operation,
            repository: repo,
            actor: "fixture".into(),
            owner: "fixture".into(),
            task: "inspection".into(),
        };
        let registry = temp.path().join("registry");
        let directory = temp.path().join("authority");
        drop(store);
        assert_eq!(
            probe_initialization_exclusive(&registry).unwrap(),
            ExclusiveProbe::Acquired
        );
        // Deliberate faults only AFTER actual owners drain. All17 objects and
        // native allocation history remain:16/0 are counterfeit, not genuine
        // legacy or empty bootstrap fixtures. Valid17 is also not bootstrap
        // permission to convert an existing DELETE journal. Never restore schema_version.
        {
            let conn = rusqlite::Connection::open(directory.join("store.sqlite")).unwrap();
            conn.set_db_config(
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                true,
            )
            .unwrap();
            conn.pragma_update(None, "user_version", version).unwrap();
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .unwrap();
            if !store_wal {
                let mode: String = conn
                    .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(mode, "delete");
            }
        }
        {
            let reg = rusqlite::Connection::open(registry.join("authorities.sqlite")).unwrap();
            let mode: String = reg
                .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
                .unwrap();
            assert_eq!(mode, "delete");
        }
        let marker = registry.join("initialization.json");
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
        record["initialized"] = serde_json::Value::Bool(false);
        std::fs::write(&marker, serde_json::to_vec(&record).unwrap()).unwrap();
        let observe = || {
            let conn = rusqlite::Connection::open_with_flags(
                directory.join("store.sqlite"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            conn.set_db_config(
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                true,
            )
            .unwrap();
            let snapshot = snapshot_connection(&conn, &request);
            let store_mode: String = conn
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .unwrap();
            let reg = rusqlite::Connection::open_with_flags(
                registry.join("authorities.sqlite"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            let registry_mode: String = reg
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .unwrap();
            let claims = reg
                .prepare("SELECT root,store FROM authorities ORDER BY root")
                .unwrap()
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            (snapshot, store_mode, registry_mode, claims)
        };
        // Fault injection is finished. Measure the initial observer separately;
        // no product call or intentional filesystem write occurs in this window.
        let mut native_setup = BTreeMap::new();
        files(temp.path(), &mut native_setup);
        let before = observe();
        assert_eq!(before.0.user_version, version);
        assert_eq!(before.0.repository_charge, 1);
        assert_eq!(before.0.owner_charge, 1);
        assert_eq!(before.1, if store_wal { "wal" } else { "delete" });
        assert_eq!(before.2, "delete");
        let mut native_before = BTreeMap::new();
        files(temp.path(), &mut native_before);
        // Observer-only control, with the same connection open/read/close path
        // and native owner state as the post-refusal observer. Keep the original
        // native_before baseline unchanged even if this control changes SHM.
        let control = observe();
        let mut native_control = BTreeMap::new();
        files(temp.path(), &mut native_control);
        let result = Store::open_registered(&registry, &directory, &[root]);
        let refused = result.is_err();
        drop(result);
        // Filesystem ONLY, immediately after product cleanup and before opening
        // either after-observer. This isolates product from observer effects.
        let mut native_refused = BTreeMap::new();
        files(temp.path(), &mut native_refused);
        let after = observe();
        let mut native_after = BTreeMap::new();
        files(temp.path(), &mut native_after);
        let case = (version, store_wal);
        deltas("initial-observer", case, &native_setup, &native_before);
        deltas("observer-only", case, &native_before, &native_control);
        deltas("product-only", case, &native_control, &native_refused);
        deltas("after-observer", case, &native_refused, &native_after);
        deltas(
            "original-baseline-to-final",
            case,
            &native_before,
            &native_after,
        );
        assert!(
            refused,
            "pending case {case:?} must not gain bootstrap admission"
        );
        assert_eq!(control, before, "observer-only logical equality: {case:?}");
        assert_eq!(
            after, before,
            "journal/header/cookies/history/outbox/accounting/claims: {case:?}"
        );
        assert_eq!(
            native_after, native_before,
            "native inodes/bytes and sidecar set must not change: {case:?}"
        );
        assert_eq!(
            native_refused, native_control,
            "product-only native equality: {case:?}"
        );
        assert_eq!(
            native_control, native_before,
            "observer-only native equality: {case:?}"
        );
    }
}

// Negative DATA only: none of these rows can construct a fresh preparation.
#[test]
fn legacy16_constructor_rejects_every_nonempty_history_without_mutation() {
    use super::schema_participation_tests::{probe_initialization_exclusive, ExclusiveProbe};
    for case in ["prepared", "tombstone", "orphan_intent", "orphan_physical"] {
        let (temp, root, mut store) = initialized();
        let (request, _) = reserve_event(&mut store, root.clone());
        let checkout = match store.pending_events(2).unwrap().remove(0).event {
            Event::Reserved { checkout, .. } => checkout,
            _ => panic!("reservation event"),
        };
        let operation = Uuid::now_v7();
        store
            .conn
            .execute_batch("PRAGMA foreign_keys=OFF;")
            .unwrap();
        if case == "orphan_physical" {
            store
                .conn
                .execute(
                    "INSERT INTO quarantine_actions VALUES(?1,?2,1,'move_pending','{}',NULL)",
                    (operation.to_string(), Uuid::now_v7().to_string()),
                )
                .unwrap();
        } else {
            crate::retirement_journal::tests::seed_prepared(
                &store,
                if case == "orphan_intent" {
                    Uuid::now_v7()
                } else {
                    checkout
                },
                operation,
            );
            if case == "tombstone" {
                store.conn.execute(
                    "UPDATE retirement_intents SET revision=2,stage='aborted',aborted_from=1 WHERE operation=?1",
                    [operation.to_string()],
                ).unwrap();
            }
        }
        store.conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        let before = snapshot(&store, &request);
        let registry = temp.path().join("registry");
        let directory = temp.path().join("private");
        drop(store);
        assert_eq!(
            probe_initialization_exclusive(&registry).unwrap(),
            ExclusiveProbe::Acquired,
            "{case}"
        );
        let result =
            Store::construct_legacy16_preobservation_fixture(&registry, &directory, &[root]);
        assert!(
            matches!(result, Err(super::StoreError::Invalid)),
            "{case}: must reject history, not self-contention"
        );
        assert_eq!(
            probe_initialization_exclusive(&registry).unwrap(),
            ExclusiveProbe::Acquired,
            "{case}"
        );
        let (conn, budget) = super::existing_database(&directory, "store.sqlite").unwrap();
        let _phase = budget.enter();
        assert_eq!(snapshot_connection(&conn, &request), before, "{case}");
    }
}

#[test]
fn legacy16_constructor_requires_complete_checkout_exclusion() {
    use super::schema_participation_tests::{probe_initialization_exclusive, ExclusiveProbe};
    let (temp, root, mut store) = initialized();
    let (request, _) = reserve_event(&mut store, root.clone());
    let checkout = match store.pending_events(2).unwrap().remove(0).event {
        Event::Reserved { checkout, .. } => checkout,
        _ => panic!("reservation event"),
    };
    let second = store
        .reserve(
            &Reservation {
                operation: Uuid::now_v7(),
                repository: root.clone(),
                actor: "actor".into(),
                owner: "actor".into(),
                task: "second".into(),
            },
            Limits {
                repository: 10,
                owner: 10,
                available_bytes: Some(100),
                floor_bytes: 0,
                warn_bytes: 0,
            },
        )
        .unwrap();
    assert_ne!(checkout, second);
    // Establish genuine guard metadata for BOTH rows, then block the last
    // sorted checkout through an independent OFD, without initialization SH.
    // A first-checkout-only implementation would incorrectly construct16.
    let guards = [
        crate::checkout_guard::CheckoutGuard::shared(&store, checkout).unwrap(),
        crate::checkout_guard::CheckoutGuard::shared(&store, second).unwrap(),
    ];
    let blocked = checkout.max(second);
    let registry = temp.path().join("registry");
    let directory = temp.path().join("private");
    let lock =
        std::fs::File::open(directory.join(format!("checkout-operations-v1/{blocked}.lock")))
            .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockShared).unwrap();
    let before = snapshot(&store, &request);
    drop(guards);
    drop(store);
    assert_eq!(
        probe_initialization_exclusive(&registry).unwrap(),
        ExclusiveProbe::Acquired
    );
    let result = Store::construct_legacy16_preobservation_fixture(
        &registry,
        &directory,
        std::slice::from_ref(&root),
    );
    assert!(matches!(result, Err(super::StoreError::OperationsInFlight)));
    assert_eq!(
        probe_initialization_exclusive(&registry).unwrap(),
        ExclusiveProbe::Acquired
    );
    {
        let (conn, budget) = super::existing_database(&directory, "store.sqlite").unwrap();
        let _phase = budget.enter();
        assert_eq!(snapshot_connection(&conn, &request), before);
    }
    drop(lock);
    let legacy =
        Store::construct_legacy16_preobservation_fixture(&registry, &directory, &[root]).unwrap();
    assert_eq!(legacy.schema_role(), super::SchemaRole::Legacy16Abort);
    drop(legacy);
    assert_eq!(
        probe_initialization_exclusive(&registry).unwrap(),
        ExclusiveProbe::Acquired
    );
}

fn acknowledged(store: &Store, sequence: i64) -> bool {
    let _phase = store.sql_phase();
    store
        .conn
        .query_row(
            "SELECT acknowledged FROM outbox WHERE sequence=?1",
            [sequence],
            |row| row.get(0),
        )
        .unwrap()
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    user_version: i64,
    schema_version: i64,
    tables: BTreeMap<String, Vec<Vec<Value>>>,
    repository_charge: u64,
    owner_charge: u64,
}

fn snapshot(store: &Store, request: &Reservation) -> Snapshot {
    let _phase = store.sql_phase();
    snapshot_connection(&store.conn, request)
}

// Raw negative-fixture observation after every actual Store owner has drained.
// This does not construct a Store, role, readiness or mutation permission.
fn snapshot_connection(conn: &rusqlite::Connection, request: &Reservation) -> Snapshot {
    let mut statement = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap();
    let mut names = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    names.push("sqlite_schema".into());
    let mut tables = BTreeMap::new();
    // Complete raw rows, including acknowledged outbox rows, allocations, checkouts,
    // accounting and every retained history table (including future action history).
    // No seeded intent/action/receipt and no filtering that could hide an ACK mutation.
    for name in names {
        let quoted = name.replace('"', "\"\"");
        let mut statement = conn
            .prepare(&format!("SELECT * FROM \"{quoted}\""))
            .unwrap();
        let columns = statement.column_count();
        let ordering = (1..=columns)
            .map(|column| column.to_string())
            .collect::<Vec<_>>()
            .join(",");
        // Column ordering also works for WITHOUT ROWID tables; no rowid assumption.
        statement = conn
            .prepare(&format!("SELECT * FROM \"{quoted}\" ORDER BY {ordering}"))
            .unwrap();
        let rows = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|column| row.get::<_, Value>(column))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        tables.insert(name, rows);
    }
    let repository = request.repository.to_str().unwrap();
    Snapshot {
        user_version: conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap(),
        schema_version: conn
            .query_row("PRAGMA schema_version", [], |row| row.get(0))
            .unwrap(),
        tables,
        repository_charge: super::count(conn, repository, None).unwrap(),
        owner_charge: super::count(conn, repository, Some(&request.owner)).unwrap(),
    }
}

#[test]
fn outbox_ack_rejects_version_drift() {
    // Independent unchanged-version positive control: prove the actual event was ACKed.
    {
        let (_temp, root, mut store) = initialized();
        let (_request, sequence) = reserve_event(&mut store, root);
        assert!(!acknowledged(&store, sequence));
        store.acknowledge(sequence).unwrap();
        assert!(acknowledged(&store, sequence));
        assert!(store.pending_events(2).unwrap().is_empty());
    }

    let (_temp, root, mut store) = initialized();
    let (request, sequence) = reserve_event(&mut store, root);
    assert!(!acknowledged(&store, sequence));
    let native = snapshot(&store, &request);
    assert_eq!(native.repository_charge, 1);
    assert_eq!(native.owner_charge, 1);
    let drifted = native.user_version.checked_sub(1).unwrap();
    {
        let _phase = store.sql_phase();
        // Only this header value changes: native16 -> 15, eventual native17 -> 16.
        store
            .conn
            .pragma_update(None, "user_version", drifted)
            .unwrap();
    }
    let before = snapshot(&store, &request);
    assert_eq!(before.user_version, drifted);
    assert_eq!(before.schema_version, native.schema_version);
    assert_eq!(
        before.tables, native.tables,
        "drift setup must leave all DDL/rows intact"
    );
    assert_eq!(before.repository_charge, native.repository_charge);
    assert_eq!(before.owner_charge, native.owner_charge);

    let result = store.acknowledge(sequence);
    // Capture after-state BEFORE asserting the result, so the predicted unexpected Ok
    // exposes its actual mutation rather than hiding it behind an early panic.
    let after = snapshot(&store, &request);
    assert!(
        result.is_err(),
        "ACK must reject version drift; result={result:?}; before={before:?}; after={after:?}"
    );
    assert_eq!(
        after.user_version, drifted,
        "ACK must not repair version drift"
    );
    assert_eq!(after.schema_version, before.schema_version);
    assert_eq!(
        after, before,
        "rejected ACK must preserve every raw row and charge"
    );
}
