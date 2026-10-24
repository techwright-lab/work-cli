#[path = "support/capture_finalization_fixture.rs"]
mod capture_fixture;
#[path = "support/run_fixture.rs"]
mod fixture_support;

#[test]
fn schema_thirteen_is_additive_and_does_not_backfill_readiness() {
    let f =
        capture_fixture::Fixture::new(true, Some(work_cli::run_journal::RootOutcome::Completed));
    work_cli::capture_finalization::finalize(&f.config, &f.root.identity().run).unwrap();
    assert_eq!(
        f.store.charged(&f.dir.path().join("root"), None).unwrap(),
        1
    );
    let sql = f.sql();
    // Works both before and after the additive migration implementation.
    sql.execute_batch("DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; DROP TABLE attribution_gaps; DROP TABLE IF EXISTS capture_readiness; PRAGMA user_version=12;")
        .unwrap();
    let tables = [
        "capture_runs",
        "capture_requirements",
        "capture_finalizations",
        "runs",
        "run_groups",
        "allocations",
        "checkouts",
        "task_finishes",
        "outbox",
    ];
    let snapshot = || {
        tables
            .iter()
            .map(|table| {
                let mut query = sql
                    .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                    .unwrap();
                let n = query.column_count();
                query
                    .query_map([], |row| {
                        (0..n)
                            .map(|i| row.get::<_, rusqlite::types::Value>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap()
            })
            .collect::<Vec<_>>()
    };
    let before = snapshot();
    let reopened = fixture_support::reopen(&f.dir).unwrap();
    assert_eq!(
        sql.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        15
    );
    assert_eq!(
        sql.query_row("SELECT count(*) FROM capture_readiness", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(snapshot(), before);
    assert!(reopened
        .capture_finalization_snapshot(&f.root.identity().run)
        .unwrap()
        .unwrap()
        .confirmation
        .is_some());
}
