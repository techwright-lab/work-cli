//! Public finish regressions; physical captured qualification is tested at its
//! private unit boundary with real disposable Git and the existing fake kernel.
#[path = "support/run_fixture.rs"]
mod run_fixture;
mod support;
use support::Fixture;
use uuid::Uuid;
use work_cli::{
    allocate::Allocation,
    config::Config,
    finish::{self, Freeze},
};
fn allocate(f: &Fixture) -> Allocation {
    let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
    assert!(out.status.success());
    serde_json::from_slice(&out.stdout).unwrap()
}
fn config(f: &Fixture) -> Config {
    Config::from_text(&std::fs::read_to_string(f.temp.path().join("config.toml")).unwrap()).unwrap()
}
#[test]
fn zero_or_missing_capture_is_incomplete() {
    for root_present in [false, true] {
        let f = Fixture::new();
        let a = allocate(&f);
        if root_present {
            let r = run_fixture::request(a.checkout);
            let mut store = f.store();
            store.begin_run(&r).unwrap();
            let b = run_fixture::binding(&r);
            store.record_bound(&r, &b).unwrap();
            store
                .record_root_outcome(&r, work_cli::run_journal::RootOutcome::Failed)
                .unwrap();
            let os = run_fixture::ClosureOs::new(&r, &b);
            let snapshot = store.group_snapshot(&r.identity().run).unwrap();
            let proof = snapshot.certify_empty(&os.driver, &b).unwrap();
            store.close_supervised_group(&snapshot, &proof).unwrap();
        }
        f.config(10, true);
        let report = finish::finish(&config(&f), a.checkout).unwrap();
        assert!(report.task_finished && report.capture_incomplete && report.charge_retained);
        assert_eq!(report.local_freeze, Freeze::Failed);
        assert_eq!(report.run_outcomes.len(), usize::from(root_present));
        if root_present {
            assert_eq!(report.run_outcomes[0].capture, finish::RunCapture::Missing);
        }
        let sql = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
        assert_eq!(
            sql.query_row("SELECT count(*) FROM capture_runs", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            sql.query_row("SELECT count(*) FROM capture_finalizations", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
#[test]
fn genuine_no_sink_receipt_never_rebinds_after_selection_changes() {
    let f = Fixture::new();
    let a = allocate(&f);
    let first = finish::finish(&config(&f), a.checkout).unwrap();
    let sql = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
    let before: String = sql
        .query_row("SELECT record FROM task_finishes", [], |r| r.get(0))
        .unwrap();
    f.config(10, true);
    let replay = finish::finish(&config(&f), a.checkout).unwrap();
    assert_eq!(replay.operation, first.operation);
    assert_eq!(replay.local_freeze, Freeze::NotConfigured);
    let after: String = sql
        .query_row("SELECT record FROM task_finishes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, after);
}
