use std::time::{Duration, Instant};
use work_cli::runtime_scope::*;
use work_contract::RunId;

const BOOT: &str = "f312459a-9346-4d02-9139-c80a7017d962";
const INVOCATION: &str = "b312459a93464d029139c80a7017d962";
const MAX_AGE: Duration = Duration::from_secs(2);

fn fixture(now: Instant) -> (LaunchIntent, ChildIdentity, Observation) {
    let intent = LaunchIntent::new(
        RunId::parse("019281b2-67de-7000-8000-000000000001").unwrap(),
        BOOT,
    )
    .unwrap();
    let identity = ScopeIdentity {
        unit: intent.unit_name().into(),
        invocation: INVOCATION.into(),
        cgroup: format!("/user.slice/{}", intent.unit_name()),
    };
    let child = ChildIdentity {
        pid: 42,
        start_ticks: 123,
        boot: BOOT.into(),
        cgroup: identity.cgroup.clone(),
    };
    let observation = Observation {
        boot: BOOT.into(),
        observed_at: now,
        unit: UnitPresence::Present {
            identity,
            load: LoadStatus::Loaded,
            active: ActiveStatus::Active,
        },
        membership: Membership::Present(vec![child.clone()]),
        recursive_coverage: Coverage::Complete,
        participant_coverage: Coverage::Complete,
        participants: vec![ParticipantStatus::Closed],
    };
    (intent, child, observation)
}

#[test]
fn valid_pre_exec_evidence_binds_exact_scope() {
    let now = Instant::now();
    let (intent, child, obs) = fixture(now);
    let bound = bind(&intent, &child, &obs, now, MAX_AGE).unwrap();
    assert_eq!(
        bound
            .authorize_cancel(&obs, now, MAX_AGE)
            .unwrap()
            .unit_name(),
        intent.unit_name()
    );
}

#[test]
fn invalid_bind_evidence_holds() {
    let now = Instant::now();
    for case in [
        "id",
        "invocation",
        "nil-invocation",
        "pid",
        "start",
        "reuse",
        "boot",
        "child-boot",
        "cgroup",
        "child-group",
        "path",
        "missing-child",
        "absent",
        "incomplete",
        "unknown-coverage",
        "stale",
        "future",
        "load",
        "active",
        "unit-unknown",
    ] {
        let (intent, mut child, mut obs) = fixture(now);
        match case {
            "id" => {
                if let UnitPresence::Present { identity, .. } = &mut obs.unit {
                    identity.unit = "arbitrary.scope".into();
                }
            }
            "invocation" => {
                if let UnitPresence::Present { identity, .. } = &mut obs.unit {
                    identity.invocation = "bad".into();
                }
            }
            "nil-invocation" => {
                if let UnitPresence::Present { identity, .. } = &mut obs.unit {
                    identity.invocation = "0".repeat(32);
                }
            }
            "pid" => child.pid = 0,
            "start" => child.start_ticks = 0,
            "reuse" => child.start_ticks += 1,
            "boot" => obs.boot = "different".into(),
            "child-boot" => child.boot = "different".into(),
            "cgroup" => {
                if let UnitPresence::Present { identity, .. } = &mut obs.unit {
                    identity.cgroup = "/other.scope".into();
                }
            }
            "child-group" => child.cgroup = "/escaped".into(),
            "path" => {
                if let UnitPresence::Present { identity, .. } = &mut obs.unit {
                    identity.cgroup = format!("/user.slice/../{}", intent.unit_name());
                }
            }
            "missing-child" => obs.membership = Membership::Present(vec![]),
            "absent" => obs.membership = Membership::Absent,
            "incomplete" => obs.recursive_coverage = Coverage::Incomplete,
            "unknown-coverage" => obs.recursive_coverage = Coverage::Unknown,
            "stale" => {
                obs.observed_at = now.checked_sub(MAX_AGE + Duration::from_nanos(1)).unwrap()
            }
            "future" => obs.observed_at = now + Duration::from_nanos(1),
            "load" => {
                if let UnitPresence::Present { load, .. } = &mut obs.unit {
                    *load = LoadStatus::Unknown;
                }
            }
            "active" => {
                if let UnitPresence::Present { active, .. } = &mut obs.unit {
                    *active = ActiveStatus::Inactive;
                }
            }
            "unit-unknown" => obs.unit = UnitPresence::Unknown,
            _ => unreachable!(),
        }
        assert!(bind(&intent, &child, &obs, now, MAX_AGE).is_err(), "{case}");
    }
}

#[test]
fn cancellation_revalidates_identity_and_never_targets_unknown_units() {
    let now = Instant::now();
    for case in [
        "boot",
        "invocation",
        "cgroup",
        "unit",
        "unknown",
        "load",
        "active",
        "reaped",
        "stale",
        "future",
    ] {
        let (intent, child, mut obs) = fixture(now);
        let bound = bind(&intent, &child, &obs, now, MAX_AGE).unwrap();
        match case {
            "boot" => obs.boot = "another".into(),
            "invocation" => {
                if let UnitPresence::Present { identity, .. } = &mut obs.unit {
                    identity.invocation = "c".repeat(32);
                }
            }
            "cgroup" => {
                if let UnitPresence::Present { identity, .. } = &mut obs.unit {
                    identity.cgroup = format!("/other/{}", intent.unit_name());
                }
            }
            "unit" => {
                if let UnitPresence::Present { identity, .. } = &mut obs.unit {
                    identity.unit = "other.scope".into();
                }
            }
            "unknown" => obs.unit = UnitPresence::Unknown,
            "load" => {
                if let UnitPresence::Present { load, .. } = &mut obs.unit {
                    *load = LoadStatus::Unknown;
                }
            }
            "active" => {
                if let UnitPresence::Present { active, .. } = &mut obs.unit {
                    *active = ActiveStatus::Unknown;
                }
            }
            "reaped" => {
                if let UnitPresence::Present { identity, .. } = obs.unit.clone() {
                    obs.unit = UnitPresence::AutoReaped(identity);
                }
            }
            "stale" => obs.observed_at = now.checked_sub(Duration::from_secs(3)).unwrap(),
            "future" => obs.observed_at = now + Duration::from_secs(1),
            _ => unreachable!(),
        }
        assert!(
            bound.authorize_cancel(&obs, now, MAX_AGE).is_err(),
            "{case}"
        );
    }
}

#[test]
fn empty_kernel_does_not_override_participant_or_evidence_uncertainty() {
    let now = Instant::now();
    for case in [
        "open",
        "unknown",
        "roster",
        "roster-incomplete",
        "recursive",
        "incomplete",
        "membership",
        "populated",
        "boot",
        "identity",
        "stale",
        "future",
        "unit-unknown",
    ] {
        let (intent, child, mut obs) = fixture(now);
        let bound = bind(&intent, &child, &obs, now, MAX_AGE).unwrap();
        obs.membership = Membership::Present(vec![]);
        match case {
            "open" => obs.participants.push(ParticipantStatus::Open),
            "unknown" => obs.participants.push(ParticipantStatus::Unknown),
            "roster" => obs.participant_coverage = Coverage::Unknown,
            "roster-incomplete" => obs.participant_coverage = Coverage::Incomplete,
            "recursive" => obs.recursive_coverage = Coverage::Unknown,
            "incomplete" => obs.recursive_coverage = Coverage::Incomplete,
            "membership" => obs.membership = Membership::Unknown,
            "populated" => obs.membership = Membership::Present(vec![child]),
            "boot" => obs.boot = "another".into(),
            "identity" => {
                if let UnitPresence::Present { identity, .. } = &mut obs.unit {
                    identity.invocation = "c".repeat(32);
                }
            }
            "stale" => obs.observed_at = now.checked_sub(Duration::from_secs(3)).unwrap(),
            "future" => obs.observed_at = now + Duration::from_secs(1),
            "unit-unknown" => obs.unit = UnitPresence::Unknown,
            _ => unreachable!(),
        }
        assert!(bound.verify_empty(&obs, now, MAX_AGE).is_err(), "{case}");
    }
}

#[test]
fn verified_empty_requires_known_identity_even_after_autoreaping() {
    let now = Instant::now();
    let (intent, child, mut obs) = fixture(now);
    let bound = bind(&intent, &child, &obs, now, MAX_AGE).unwrap();
    obs.membership = Membership::Present(vec![]);
    obs.participants.push(ParticipantStatus::ProvenAbsent);
    assert!(bound.verify_empty(&obs, now, MAX_AGE).is_ok());
    let UnitPresence::Present { identity, .. } = obs.unit.clone() else {
        unreachable!()
    };
    obs.unit = UnitPresence::AutoReaped(identity.clone());
    assert!(bound.verify_empty(&obs, now, MAX_AGE).is_err()); // missing group proof
    obs.membership = Membership::Absent;
    assert!(bound.verify_empty(&obs, now, MAX_AGE).is_ok());
    obs.participants.push(ParticipantStatus::Unknown);
    assert!(bound.verify_empty(&obs, now, MAX_AGE).is_err());
    obs.participants.pop();
    let mut replacement = identity;
    replacement.invocation = "d".repeat(32);
    obs.unit = UnitPresence::AutoReaped(replacement);
    assert!(bound.verify_empty(&obs, now, MAX_AGE).is_err());
    obs.unit = UnitPresence::Unknown;
    assert!(bound.verify_empty(&obs, now, MAX_AGE).is_err());
}

#[test]
fn launch_boot_boundary_rejects_noncanonical_and_missing_identity() {
    for boot in ["", "unknown", "00000000-0000-0000-0000-000000000000"] {
        assert!(LaunchIntent::new(RunId::generate(), boot).is_err());
    }
}
