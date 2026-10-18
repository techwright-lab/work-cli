use work_cli::linux_scope::{
    assess_membership, inspect_host, qualify, Disposition, QualificationOptions,
};

#[test]
fn absence_of_user_bus_is_explicit_unknown_not_operational_evidence() {
    assert_eq!(
        assess_membership(
            false,
            Some("/user.slice/test.scope"),
            &["/user.slice/test.scope".into()]
        ),
        Disposition::UnknownHold
    );
    assert_eq!(assess_membership(true, None, &[]), Disposition::UnknownHold);
    assert_eq!(
        assess_membership(true, Some("/scope"), &["/escaped".into()]),
        Disposition::UnknownHold
    );
    assert_eq!(
        assess_membership(true, Some("/scope"), &["/scope".into()]),
        Disposition::Accounted
    );
}
#[test]
fn default_probe_is_read_only_and_never_qualifies_paperclip() {
    let report = qualify(QualificationOptions {
        run_id: "test-run",
        adapter: "ci-report-only",
        opt_in_fixture: false,
    })
    .unwrap();
    assert_eq!(report.disposition, Disposition::UnknownHold);
    assert!(!report.fixture_executed);
    assert!(!report.paperclip_qualified);
    assert!(report.observations.is_empty());
    assert!(!report.limitations.is_empty());
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("PATH="));
    assert!(!json.contains("environ"));
    assert!(json.contains("test-run"));
    let host = inspect_host();
    assert!(host.uid.is_some());
    assert!(host.current_cgroup.is_some());
}
#[test]
fn unsafe_report_identifiers_are_rejected() {
    assert!(qualify(QualificationOptions {
        run_id: "secret\nvalue",
        adapter: "ci",
        opt_in_fixture: false
    })
    .is_err());
}
#[test]
fn opt_in_disposable_scope_accounts_for_escape_fixtures_or_explicitly_holds() {
    if std::env::var("WORK_TEST_REAL_USER_SCOPE").as_deref() != Ok("1") {
        // CI still exercises the failed qualification contract; this is NOT scope evidence.
        let report = qualify(QualificationOptions {
            run_id: "ci-unqualified",
            adapter: "ci",
            opt_in_fixture: false,
        })
        .unwrap();
        assert_eq!(report.disposition, Disposition::UnknownHold);
        assert!(!report.paperclip_qualified);
        return;
    }
    let report = qualify(QualificationOptions {
        run_id: "disposable-test",
        adapter: "explicit-ci-opt-in",
        opt_in_fixture: true,
    })
    .unwrap();
    if report.disposition == Disposition::Accounted {
        for case in [
            "setsid",
            "double_fork_parent_exit",
            "cwd_fd",
            "exit_during_inspection",
        ] {
            assert!(report.observations.iter().any(|o| o.fixture == case));
        }
        assert_eq!(report.cleanup_outcome, "verified-empty");
        assert!(report.unit_owner_uid.is_some());
    } else {
        assert!(!report.reasons.is_empty());
    }
    assert!(!report.paperclip_qualified);
}

use work_cli::linux_scope::{
    assess_cleanup, CleanupEvidence, ParticipantState, ScopeIdentity, UnitState,
};

#[test]
fn bounded_cleanup_state_table() {
    let scope = ScopeIdentity {
        unit: "work-qualification-test.scope",
        cgroup: "/user.slice/work-qualification-test.scope",
    };
    let inactive = UnitState {
        id: scope.unit,
        load: "not-found",
        active: "inactive",
        cgroup: "",
    };
    let absent = [ParticipantState::Absent; 4];
    let live = [ParticipantState::Absent, ParticipantState::Present];
    let unknown = [ParticipantState::Unknown];
    let nonempty = [42];
    let wrong = ScopeIdentity {
        unit: scope.unit,
        cgroup: "/user.slice/other.scope",
    };
    let cases = [
        (
            "stop failed, autoreaped",
            Some(scope),
            Some(inactive),
            None,
            true,
            absent.as_slice(),
            true,
        ),
        (
            "verified empty",
            Some(scope),
            None,
            Some([].as_slice()),
            false,
            unknown.as_slice(),
            true,
        ),
        (
            "members remain",
            Some(scope),
            Some(inactive),
            Some(nonempty.as_slice()),
            true,
            absent.as_slice(),
            false,
        ),
        (
            "live participant",
            Some(scope),
            Some(inactive),
            None,
            true,
            live.as_slice(),
            false,
        ),
        (
            "unit unavailable",
            Some(scope),
            None,
            None,
            true,
            absent.as_slice(),
            false,
        ),
        (
            "unknown pid",
            Some(scope),
            Some(inactive),
            None,
            true,
            unknown.as_slice(),
            false,
        ),
        (
            "no participant evidence",
            Some(scope),
            Some(inactive),
            None,
            true,
            [].as_slice(),
            false,
        ),
        (
            "no creation authority",
            None,
            Some(inactive),
            Some([].as_slice()),
            true,
            absent.as_slice(),
            false,
        ),
        (
            "wrong scoped identity",
            Some(wrong),
            Some(inactive),
            Some([].as_slice()),
            true,
            absent.as_slice(),
            false,
        ),
        (
            "no absence proof",
            Some(scope),
            Some(inactive),
            None,
            false,
            absent.as_slice(),
            false,
        ),
        (
            "stop alone grants nothing",
            Some(scope),
            None,
            None,
            false,
            absent.as_slice(),
            false,
        ),
        (
            "different unit",
            Some(scope),
            Some(UnitState {
                id: "other.scope",
                ..inactive
            }),
            None,
            true,
            absent.as_slice(),
            false,
        ),
        (
            "active unit",
            Some(scope),
            Some(UnitState {
                active: "active",
                ..inactive
            }),
            None,
            true,
            absent.as_slice(),
            false,
        ),
    ];
    for (name, created_scope, unit_state, membership, cgroup_absent, participants, expected) in
        cases
    {
        assert_eq!(
            assess_cleanup(CleanupEvidence {
                created_scope,
                unit_state,
                membership,
                cgroup_absent,
                participants
            }),
            expected,
            "{name}"
        );
    }
}
