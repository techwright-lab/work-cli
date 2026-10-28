use std::time::{Duration, Instant};
use work_cli::run_participants::ExpectedHost;
use work_cli::runtime_scope::*;
use work_contract::RunId;
const BOOT: &str = "550e8400-e29b-41d4-a716-446655440000";
#[test]
fn positive_enrollment_requires_complete_exact_open_evidence_not_singleton_membership() {
    let now = Instant::now();
    let intent = LaunchIntent::new(RunId::generate(), BOOT).unwrap();
    let scope = ScopeIdentity {
        unit: intent.unit_name().into(),
        invocation: "550e8400e29b41d4a716446655440000".into(),
        cgroup: format!("/test/{}", intent.unit_name()),
    };
    let host = ChildIdentity {
        pid: 42,
        start_ticks: 10,
        boot: BOOT.into(),
        cgroup: format!("{}/nested", scope.cgroup),
    };
    let other = ChildIdentity {
        pid: 43,
        ..host.clone()
    };
    let expected = ExpectedHost {
        pid: 42,
        start_ticks: 10,
        boot: BOOT.into(),
    };
    let obs = Observation {
        boot: BOOT.into(),
        observed_at: now,
        unit: UnitPresence::Present {
            identity: scope.clone(),
            load: LoadStatus::Loaded,
            active: ActiveStatus::Active,
        },
        membership: Membership::Present(vec![host.clone(), other.clone()]),
        recursive_coverage: Coverage::Complete,
        participant_coverage: Coverage::Complete,
        participants: vec![ParticipantStatus::Open, ParticipantStatus::Open],
    };
    for case in [
        "valid",
        "outside",
        "missing",
        "ticks",
        "boot",
        "inactive",
        "reaped",
        "coverage",
        "participants",
        "counts",
        "identity",
        "future",
        "stale",
        "duplicate",
    ] {
        let mut o = obs.clone();
        let mut h = host.clone();
        let mut roster = vec![host.clone(), other.clone()];
        match case {
            "outside" => h.cgroup = "/outside".into(),
            "missing" => o.membership = Membership::Present(vec![other.clone()]),
            "ticks" => h.start_ticks = 11,
            "boot" => o.boot = "650e8400-e29b-41d4-a716-446655440000".into(),
            "inactive" => {
                if let UnitPresence::Present { active, .. } = &mut o.unit {
                    *active = ActiveStatus::Inactive
                }
            }
            "reaped" => o.unit = UnitPresence::AutoReaped(scope.clone()),
            "coverage" => o.recursive_coverage = Coverage::Incomplete,
            "participants" => o.participants[1] = ParticipantStatus::Unknown,
            "counts" => {
                o.participants.pop();
            }
            "identity" => roster[1].start_ticks = 100,
            "future" => o.observed_at = now + Duration::from_secs(1),
            "stale" => o.observed_at = now - Duration::from_secs(3),
            "duplicate" => roster[1] = host.clone(),
            _ => (),
        }
        let result = validate_enrollment_host(
            &intent,
            &scope,
            &expected,
            &h,
            &roster,
            &o,
            now,
            Duration::from_secs(2),
        );
        assert_eq!(result.is_ok(), case == "valid", "{case}: {result:?}");
    }
}
