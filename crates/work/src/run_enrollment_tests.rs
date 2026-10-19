use super::*;
use crate::{
    admission::{Limits, Reservation},
    run_journal::{BoundSnapshot, RunIdentity, RunInput},
    runtime_scope::*,
};
use std::time::{Duration, Instant};
use uuid::Uuid;
fn fixture() -> (
    tempfile::TempDir,
    Store,
    RootRunRequest,
    ChildRequest,
    EnrollmentProof,
) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let mut store = Store::open(&dir.path().join("private"), std::slice::from_ref(&root)).unwrap();
    let id = store
        .reserve(
            &Reservation {
                operation: Uuid::now_v7(),
                repository: root,
                actor: "a".into(),
                owner: "o".into(),
                task: "t".into(),
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
    store
        .conn
        .execute("UPDATE checkouts SET state='active',ready=1", [])
        .unwrap();
    let boot = "550e8400-e29b-41d4-a716-446655440000";
    let r = RootRunRequest::new(
        RunIdentity {
            checkout: CheckoutId::parse(&id.to_string()).unwrap(),
            group: GroupId::generate(),
            run: RunId::generate(),
            run_ref: RunRef::parse("root").unwrap(),
            actor: ActorId::parse("a").unwrap(),
            parent_run_ref: None,
            execution_chain: serde_json::from_value(
                serde_json::json!([{"kind":"executor","system":"fixture"}]),
            )
            .unwrap(),
        },
        RunInput {
            boot: boot.into(),
            command_digest: [1; 32],
            input_digest: [2; 32],
            context_ref: work_contract::ChainText::new("c".into()).unwrap(),
            intent_ref: work_contract::ChainText::new("i".into()).unwrap(),
        },
    )
    .unwrap();
    let intent = LaunchIntent::new(r.identity().run.clone(), boot).unwrap();
    let scope = ScopeIdentity {
        unit: intent.unit_name().into(),
        invocation: "550e8400e29b41d4a716446655440000".into(),
        cgroup: format!("/fixture/{}", intent.unit_name()),
    };
    let host = ChildIdentity {
        pid: 42,
        start_ticks: 10,
        boot: boot.into(),
        cgroup: scope.cgroup.clone(),
    };
    let now = Instant::now();
    let obs = Observation {
        boot: boot.into(),
        observed_at: now,
        unit: UnitPresence::Present {
            identity: scope,
            load: LoadStatus::Loaded,
            active: ActiveStatus::Active,
        },
        membership: Membership::Present(vec![host.clone()]),
        recursive_coverage: Coverage::Complete,
        participant_coverage: Coverage::Complete,
        participants: vec![ParticipantStatus::Open],
    };
    let b = bind(&intent, &host, &obs, now, Duration::from_secs(2)).unwrap();
    store.begin_run(&r).unwrap();
    store.record_bound(&r, &b).unwrap();
    store.record_permit_attempt(&r, &b).unwrap();
    let c = ChildRequest {
        checkout: r.identity().checkout.clone(),
        group: r.identity().group.clone(),
        run: RunId::generate(),
        run_ref: RunRef::parse("child").unwrap(),
        parent_run: r.identity().run.clone(),
        parent_run_ref: r.identity().run_ref.clone(),
        execution_chain: r.identity().execution_chain.clone(),
        source: None,
        session: None,
        agent: None,
        actor: None,
        expected_host: Some(ExpectedHost {
            boot: boot.into(),
            pid: 42,
            start_ticks: 10,
        }),
    };
    store.register_child(&r, &c).unwrap();
    // Private test construction exercises the SQL seam only, never an OS claim.
    let proof = EnrollmentProof {
        record: store.run_snapshot(&r.identity().run).unwrap().unwrap(),
        child: c.clone(),
        enrollment: EnrollmentRecord {
            root: BoundSnapshot::capture(&r, &b).unwrap(),
            host: HostSnapshot {
                pid: 42,
                start_ticks: 10,
                boot: boot.into(),
                cgroup: host.cgroup,
            },
        },
        observed_at: now,
    };
    (dir, store, r, c, proof)
}
#[test]
fn expired_and_future_proofs_cannot_mutate_and_exact_receipts_never_refresh() {
    for age in ["expired", "future", "receipt"] {
        let (_dir, mut store, r, c, mut proof) = fixture();
        if age == "receipt" {
            store.record_child_enrollment(&r, &c, &proof).unwrap();
        }
        proof.observed_at = if age == "future" {
            Instant::now() + Duration::from_secs(5)
        } else {
            Instant::now() - Duration::from_secs(5)
        };
        let before = store.run_snapshot(&r.identity().run).unwrap().unwrap();
        let events = store.pending_events(100).unwrap();
        let result = store.record_child_enrollment(&r, &c, &proof);
        assert_eq!(result.is_ok(), age == "receipt", "{age}");
        assert_eq!(
            store.run_snapshot(&r.identity().run).unwrap().unwrap(),
            before
        );
        assert_eq!(store.pending_events(100).unwrap(), events);
    }
}
#[test]
fn enrollment_freshness_is_evaluated_after_immediate_lock_at_the_two_second_boundary() {
    for seconds in [2, 3] {
        let (dir, mut store, r, c, proof) = fixture();
        let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        sql.busy_timeout(Duration::ZERO).unwrap();
        let before = store.run_snapshot(&r.identity().run).unwrap().unwrap();
        let events = store.pending_events(100).unwrap();
        let mut called = false;
        let result=store.record_child_enrollment_using(&r,&c,&proof,|| {
            called=true;
            assert!(matches!(sql.execute_batch("BEGIN IMMEDIATE"),Err(rusqlite::Error::SqliteFailure(e,_)) if e.code==rusqlite::ErrorCode::DatabaseBusy),"freshness clock runs only while the enrollment writer lock is held");
            proof.observed_at+Duration::from_secs(seconds)
        });
        assert!(called);
        assert_eq!(result.is_ok(), seconds == 2);
        if seconds == 3 {
            assert_eq!(
                store.run_snapshot(&r.identity().run).unwrap().unwrap(),
                before
            );
            assert_eq!(store.pending_events(100).unwrap(), events);
        }
    }
}
#[test]
fn enrollment_event_failure_rolls_back_host_revision_and_every_durable_row() {
    let (_dir, mut store, r, c, proof) = fixture();
    let before = store.run_snapshot(&r.identity().run).unwrap().unwrap();
    let events = store.pending_events(100).unwrap();
    store.conn.execute_batch("CREATE TRIGGER reject_enrollment BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(store.record_child_enrollment(&r, &c, &proof).is_err());
    assert_eq!(
        store.run_snapshot(&r.identity().run).unwrap().unwrap(),
        before
    );
    assert_eq!(store.pending_events(100).unwrap(), events);
}
