#[path = "../tests/support/capture_finalization_fixture.rs"]
mod capture_fixture;
use crate::test_run_fixture as fixture_support;

#[test]
fn competitor_confirmation_before_dispatch_is_passive() {
    let f = capture_fixture::Fixture::new(true, Some(crate::run_journal::RootOutcome::Completed));
    let mut called = false;
    let (_, result) = super::finalize_after_preflight(
        &f.config,
        &f.root.identity().run,
        || called = true,
        || {
            assert!(super::finalize(&f.config, &f.root.identity().run).is_ok());
        },
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
