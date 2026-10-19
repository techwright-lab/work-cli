#[path = "support/run_fixture.rs"]
mod fixture;
use fixture::*;
use uuid::Uuid;
use work_cli::{
    adopted::AdoptedRequest,
    participants::{Activity, ActivityKind, ParticipantKey, Ref},
    run_journal::{BeginRun, Transition},
};
fn text(s: &str) -> Ref {
    Ref::new(s.into()).unwrap()
}
fn adopted(checkout: Uuid) -> AdoptedRequest {
    AdoptedRequest {
        operation: Uuid::now_v7(),
        identity: request(checkout).identity().clone(),
        source: text("test-sdk"),
        session: text("session"),
        agent: text("root"),
    }
}
fn event(r: &AdoptedRequest, kind: ActivityKind) -> Activity {
    Activity {
        run: r.identity.run.clone(),
        group: r.identity.group.clone(),
        source: r.source.clone(),
        participant: ParticipantKey {
            session: r.session.clone(),
            agent: r.agent.clone(),
        },
        parent: None,
        actor: Some(r.identity.actor.clone()),
        prompt: text("prompt"),
        tool: text("tool"),
        event_ref: text("event"),
        kind,
        observed_at: 100,
    }
}
#[test]
fn stop_is_idempotent_metadata_not_completion() {
    let (dir, mut store, checkout) = fixture();
    let r = adopted(checkout);
    assert_eq!(store.begin_adopted(&r).unwrap(), BeginRun::Created);
    let e = event(&r, ActivityKind::Stop);
    assert_eq!(store.record_activity(&e).unwrap(), Transition::Changed);
    let before = store.adopted_status(&r.identity.run).unwrap();
    let events = store.pending_events(1000).unwrap();
    assert_eq!(store.record_activity(&e).unwrap(), Transition::Existing);
    assert_eq!(store.adopted_status(&r.identity.run).unwrap(), before);
    assert_eq!(store.pending_events(1000).unwrap(), events);
    let mut changed = e.clone();
    changed.observed_at += 1;
    assert!(store.record_activity(&changed).is_err());
    let mut repeated = e.clone();
    repeated.prompt = text("next-prompt");
    assert_eq!(
        store.record_activity(&repeated).unwrap(),
        Transition::Changed
    );
    repeated.tool = text("next-tool");
    assert_eq!(
        store.record_activity(&repeated).unwrap(),
        Transition::Changed
    );
    let end = event(&r, ActivityKind::SessionEnd);
    store.record_activity(&end).unwrap();
    let status = store.adopted_status(&r.identity.run).unwrap();
    assert_eq!(status.revision, 5);
    assert!(status.writer_held && status.reconciliation_requested);
    assert!(!status.automatic_quiescence && !status.git_identity_controlled);
    assert_eq!(status.runtime, "unknown");
    assert_eq!(status.participants[0].heartbeat, Some(100));
    assert!(status.participants[0].declared_closed);
    assert!(store.begin_run(&request(checkout)).is_err());
    assert_eq!(
        store
            .charged(&dir.path().join("root"), Some("owner"))
            .unwrap(),
        1
    );
    let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    assert_eq!(
        sql.query_row("SELECT state FROM checkouts", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "active"
    );
}
#[test]
fn children_tombstones_parent_context_and_session_end_never_release_writer() {
    let (_dir, mut store, checkout) = fixture();
    let r = adopted(checkout);
    store.begin_adopted(&r).unwrap();
    let root = event(&r, ActivityKind::Stop).participant;
    let mut child = event(&r, ActivityKind::SubagentStop);
    child.participant.agent = text("child");
    child.parent = Some(root.clone());
    child.actor = None;
    store.record_activity(&child).unwrap();
    child.kind = ActivityKind::SubagentStart;
    store.record_activity(&child).unwrap();
    assert!(
        store
            .adopted_status(&r.identity.run)
            .unwrap()
            .participants
            .iter()
            .find(|p| p.key.agent == text("child"))
            .unwrap()
            .declared_closed
    );
    let mut other = child.clone();
    other.participant.agent = text("other");
    other.participant.session = text("another-session");
    store.record_activity(&other).unwrap();
    store
        .record_activity(&event(&r, ActivityKind::SessionEnd))
        .unwrap();
    let status = store.adopted_status(&r.identity.run).unwrap();
    assert!(status.writer_held);
    assert!(status.participants.iter().any(|p| !p.declared_closed));
    let mut bad = other.clone();
    bad.event_ref = text("new-self-cycle");
    bad.parent = Some(other.participant.clone());
    assert!(store.record_activity(&bad).is_err());
    bad.event_ref = text("new-reparent");
    bad.parent = Some(child.participant.clone());
    assert!(store.record_activity(&bad).is_err());
    bad = other.clone();
    bad.source = text("foreign");
    assert!(store.record_activity(&bad).is_err());
    bad = other.clone();
    bad.group = work_contract::GroupId::generate();
    assert!(store.record_activity(&bad).is_err());
    bad = other.clone();
    bad.event_ref = text("new-actor-forgery");
    bad.actor = Some(work_contract::ActorId::parse("forged").unwrap());
    assert!(store.record_activity(&bad).is_err());
    let mut unknown = event(&r, ActivityKind::Stop);
    unknown.participant.agent = text("not-registered");
    assert!(store.record_activity(&unknown).is_err());
    unknown.kind = ActivityKind::SubagentStart;
    unknown.parent = Some(ParticipantKey {
        session: text("foreign-session"),
        agent: text("missing-parent"),
    });
    assert!(store.record_activity(&unknown).is_err());
    let before = store.adopted_status(&r.identity.run).unwrap();
    assert_eq!(store.adopted_status(&r.identity.run).unwrap(), before);
    other.kind = ActivityKind::SubagentStop;
    store.record_activity(&other).unwrap();
    assert!(store.adopted_status(&r.identity.run).unwrap().writer_held);
}
#[test]
fn same_session_can_span_checkouts_but_silence_reconcile_is_not_activity_or_exit() {
    let (dir, mut store, checkout) = fixture();
    let r = adopted(checkout);
    store.begin_adopted(&r).unwrap();
    let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    let other = Uuid::now_v7();
    sql.execute("INSERT INTO checkouts(id,operation,digest,repository,actor,task,owner,state,ready) SELECT ?1,?2,digest,repository,actor,task,owner,state,ready FROM checkouts WHERE id=?3",(other.to_string(),Uuid::now_v7().to_string(),checkout.to_string())).unwrap();
    let another = adopted(other);
    store.begin_adopted(&another).unwrap();
    let before = store.adopted_status(&r.identity.run).unwrap();
    drop(store);
    let mut store = reopen(&dir).unwrap();
    assert_eq!(store.adopted_status(&r.identity.run).unwrap(), before);
    let reconcile = event(&r, ActivityKind::Reconcile);
    store.record_activity(&reconcile).unwrap();
    let after = store.adopted_status(&r.identity.run).unwrap();
    assert_eq!(after.participants[0].heartbeat, None);
    assert!(!after.participants[0].declared_closed);
    assert!(after.writer_held && after.reconciliation_requested);
    assert_eq!(after.runtime, "unknown");
    assert_eq!(
        store
            .adopted_status(&another.identity.run)
            .unwrap()
            .revision,
        1
    );
}
#[test]
fn all_session_ends_are_declarations_without_any_writer_delete_or_checkout_update() {
    let (dir, mut store, checkout) = fixture();
    let r = adopted(checkout);
    store.begin_adopted(&r).unwrap();
    let mut child = event(&r, ActivityKind::SubagentStart);
    child.parent = Some(child.participant.clone());
    child.participant = ParticipantKey {
        session: text("child-session"),
        agent: text("child"),
    };
    child.actor = None;
    store.record_activity(&child).unwrap();
    let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch("CREATE TRIGGER forbid_writer_delete BEFORE DELETE ON writers BEGIN SELECT RAISE(ABORT,'writer deletion forbidden'); END; CREATE TRIGGER forbid_checkout_change BEFORE UPDATE ON checkouts BEGIN SELECT RAISE(ABORT,'checkout change forbidden'); END;").unwrap();
    store
        .record_activity(&event(&r, ActivityKind::SessionEnd))
        .unwrap();
    child.kind = ActivityKind::SessionEnd;
    store.record_activity(&child).unwrap();
    let status = store.adopted_status(&r.identity.run).unwrap();
    assert!(status.participants.iter().all(|p| p.declared_closed));
    assert!(status.writer_held);
    assert!(!status.automatic_quiescence);
    assert_eq!(status.runtime, "unknown");
    let state: (String, String, String) = sql
        .query_row("SELECT state,owner,task FROM checkouts", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(state, ("active".into(), "owner".into(), "task".into()));
    let before = store.pending_events(1000).unwrap();
    drop(store);
    let store = reopen(&dir).unwrap();
    assert_eq!(store.adopted_status(&r.identity.run).unwrap(), status);
    assert_eq!(store.pending_events(1000).unwrap(), before);
}
#[test]
fn explicit_parent_depth_and_child_count_are_bounded() {
    let (_dir, mut store, checkout) = fixture();
    let r = adopted(checkout);
    store.begin_adopted(&r).unwrap();
    let mut child = event(&r, ActivityKind::SubagentStart);
    child.actor = None;
    for depth in 1..=16 {
        child.parent = Some(child.participant.clone());
        child.participant.agent = text(&format!("depth-{depth}"));
        store.record_activity(&child).unwrap();
    }
    child.parent = Some(child.participant.clone());
    child.participant.agent = text("too-deep");
    assert!(store.record_activity(&child).is_err());
    child.parent = Some(event(&r, ActivityKind::Stop).participant);
    for n in 17..256 {
        child.participant.agent = text(&format!("child-{n}"));
        store.record_activity(&child).unwrap();
    }
    child.participant.agent = text("too-many");
    assert!(store.record_activity(&child).is_err());
    assert_eq!(
        store
            .adopted_status(&r.identity.run)
            .unwrap()
            .participants
            .len(),
        256
    );
}
#[test]
fn supervised_groups_reject_adopted_activity_and_bad_refs_fail_closed() {
    let (_dir, mut store, checkout) = fixture();
    let r = adopted(checkout);
    let sup = request(checkout);
    store.begin_run(&sup).unwrap();
    let mut e = event(&r, ActivityKind::Stop);
    e.run = sup.identity().run.clone();
    e.group = sup.identity().group.clone();
    assert!(store.record_activity(&e).is_err());
    for invalid in ["", "  ", "x\ny", "x\u{0000}", &"x".repeat(257)] {
        assert!(Ref::new(invalid.into()).is_err());
    }
    let mut json = serde_json::to_value(event(&r, ActivityKind::Stop)).unwrap();
    json["prompt_raw"] = "SECRET".into();
    assert!(serde_json::from_value::<Activity>(json).is_err());
}
