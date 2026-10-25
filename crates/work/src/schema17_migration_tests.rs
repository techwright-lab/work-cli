//! W2A existing-API witnesses: authored only, pending parent isolated CI.
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
    let mut statement = store
        .conn
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
        let mut statement = store
            .conn
            .prepare(&format!("SELECT * FROM \"{quoted}\""))
            .unwrap();
        let columns = statement.column_count();
        let ordering = (1..=columns)
            .map(|column| column.to_string())
            .collect::<Vec<_>>()
            .join(",");
        // Column ordering also works for WITHOUT ROWID tables; no rowid assumption.
        statement = store
            .conn
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
        user_version: store
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap(),
        schema_version: store
            .conn
            .query_row("PRAGMA schema_version", [], |row| row.get(0))
            .unwrap(),
        tables,
        repository_charge: super::count(&store.conn, repository, None).unwrap(),
        owner_charge: super::count(&store.conn, repository, Some(&request.owner)).unwrap(),
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
