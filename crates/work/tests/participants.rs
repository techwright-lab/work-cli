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
        agent: Some(text("root")),
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
        actor: None,
        prompt: Some(text("prompt")),
        tool: Some(text("tool")),
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
    for observed_at in [99, 101] {
        let mut changed = e.clone();
        changed.observed_at = observed_at;
        assert_eq!(
            store.record_activity(&changed).unwrap(),
            Transition::Existing
        );
        assert_eq!(store.adopted_status(&r.identity.run).unwrap(), before);
        assert_eq!(store.pending_events(1000).unwrap(), events);
    }
    for field in ["actor", "parent"] {
        let mut changed = serde_json::to_value(&e).unwrap();
        changed[field] = if field == "actor" {
            serde_json::json!("different-actor")
        } else {
            serde_json::json!({"session":"other", "agent":"other"})
        };
        let changed = serde_json::from_value(changed).unwrap();
        assert!(store.record_activity(&changed).is_err());
    }
    let mut repeated = e.clone();
    repeated.prompt = Some(text("next-prompt"));
    assert_eq!(
        store.record_activity(&repeated).unwrap(),
        Transition::Changed
    );
    repeated.tool = Some(text("next-tool"));
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
    child.participant.agent = Some(text("child"));
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
            .find(|p| p.key.agent == Some(text("child")))
            .unwrap()
            .declared_closed
    );
    let mut other = child.clone();
    other.participant.agent = Some(text("other"));
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
    unknown.participant.agent = Some(text("not-registered"));
    assert!(store.record_activity(&unknown).is_err());
    unknown.kind = ActivityKind::SubagentStart;
    unknown.parent = Some(ParticipantKey {
        session: text("foreign-session"),
        agent: Some(text("missing-parent")),
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
        agent: Some(text("child")),
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
        child.participant.agent = Some(text(&format!("depth-{depth}")));
        store.record_activity(&child).unwrap();
    }
    child.parent = Some(child.participant.clone());
    child.participant.agent = Some(text("too-deep"));
    assert!(store.record_activity(&child).is_err());
    child.parent = Some(event(&r, ActivityKind::Stop).participant);
    for n in 17..256 {
        child.participant.agent = Some(text(&format!("child-{n}")));
        store.record_activity(&child).unwrap();
    }
    child.participant.agent = Some(text("too-many"));
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
fn session_only_root_metadata_parses_stores_and_remains_absent() {
    for omit in [false, true] {
        let (dir, mut store, checkout) = fixture();
        let mut value = serde_json::to_value(adopted(checkout)).unwrap();
        value["agent"] = serde_json::Value::Null;
        if omit {
            value.as_object_mut().unwrap().remove("agent");
        }
        let r: AdoptedRequest = serde_json::from_value(value).unwrap();
        store.begin_adopted(&r).unwrap();
        for kind in [
            ActivityKind::Stop,
            ActivityKind::SessionEnd,
            ActivityKind::Reconcile,
        ] {
            let mut value = serde_json::to_value(event(&r, kind)).unwrap();
            value["participant"]["agent"] = serde_json::Value::Null;
            value["actor"] = serde_json::Value::Null;
            for field in ["prompt", "tool"] {
                value[field] = serde_json::Value::Null;
                if omit {
                    value.as_object_mut().unwrap().remove(field);
                }
            }
            if omit {
                value["participant"]
                    .as_object_mut()
                    .unwrap()
                    .remove("agent");
            }
            let e: Activity = serde_json::from_value(value).unwrap();
            store.record_activity(&e).unwrap();
            assert_eq!(store.record_activity(&e).unwrap(), Transition::Existing);
        }
        let status = serde_json::to_value(store.adopted_status(&r.identity.run).unwrap()).unwrap();
        assert!(status["request"]["agent"].is_null());
        assert!(status["participants"][0]["key"]["agent"].is_null());
        assert!(status["participants"][0]["actor"].is_null());
        assert_eq!(status["participants"][0]["heartbeat"], 100);
        assert_eq!(status["runtime"], "unknown");
        let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        assert_eq!(
            sql.query_row(
                "SELECT count(*) FROM adopted_segments WHERE agent='' AND prompt='' AND tool=''",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            3
        );
        assert_eq!(
            sql.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            12
        );
    }
}
#[test]
fn v6_string_requests_parents_and_bodies_are_not_rewritten_by_retries() {
    let (dir, mut store, checkout) = fixture();
    let r = adopted(checkout);
    store.begin_adopted(&r).unwrap();
    let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
    // Exact pre-fix v6 JSON representations: string refs, an explicit root actor,
    // and noncanonical whitespace. There is no migration or historical row rewrite.
    let historical_request = serde_json::to_string_pretty(&r).unwrap();
    assert!(
        serde_json::from_str::<serde_json::Value>(&historical_request).unwrap()["agent"]
            .is_string()
    );
    sql.execute(
        "UPDATE adopted_groups SET request=?1",
        [&historical_request],
    )
    .unwrap();
    sql.execute(
        "UPDATE adopted_sessions SET actor=?1 WHERE depth=0",
        [r.identity.actor.as_str()],
    )
    .unwrap();
    let mut e = event(&r, ActivityKind::Stop);
    e.actor = Some(r.identity.actor.clone());
    store.record_activity(&e).unwrap();
    let historical_body = serde_json::to_string_pretty(&e).unwrap();
    sql.execute("UPDATE adopted_segments SET body=?1", [&historical_body])
        .unwrap();
    let mut child = event(&r, ActivityKind::SubagentStop);
    child.parent = Some(child.participant.clone());
    child.participant.agent = Some(text("historical-child"));
    store.record_activity(&child).unwrap();
    let historical_parent: String = sql
        .query_row(
            "SELECT parent FROM adopted_sessions WHERE depth=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        serde_json::from_str::<serde_json::Value>(&historical_parent).unwrap()["agent"].is_string()
    );
    let before = durable_rows(&sql);
    let status = store.adopted_status(&r.identity.run).unwrap();
    drop(store);
    let mut store = reopen(&dir).unwrap();
    assert_eq!(store.begin_adopted(&r).unwrap(), BeginRun::Existing);
    for observed_at in [99, 101] {
        e.observed_at = observed_at;
        assert_eq!(store.record_activity(&e).unwrap(), Transition::Existing);
        child.observed_at = observed_at;
        assert_eq!(store.record_activity(&child).unwrap(), Transition::Existing);
    }
    assert_eq!(store.adopted_status(&r.identity.run).unwrap(), status);
    assert_eq!(durable_rows(&sql), before);
    let mut invalid = e.clone();
    invalid.observed_at = u64::MAX;
    assert!(store.record_activity(&invalid).is_err());
    invalid = e.clone();
    invalid.event_ref = text("different-transport-event");
    assert_eq!(
        store.record_activity(&invalid).unwrap(),
        Transition::Changed
    );
    assert_eq!(
        store.adopted_status(&r.identity.run).unwrap().revision,
        status.revision + 1
    );
}
#[test]
fn agentless_children_require_distinct_sessions_and_absence_keys_do_not_collide() {
    let (_dir, mut store, checkout) = fixture();
    let r = adopted(checkout);
    store.begin_adopted(&r).unwrap();
    let mut child = event(&r, ActivityKind::SubagentStart);
    child.parent = Some(child.participant.clone());
    child.participant.agent = None;
    child.actor = None;
    assert!(store.record_activity(&child).is_err());
    child.participant.session = text("distinct-child-session");
    store.record_activity(&child).unwrap();
    let status = store.adopted_status(&r.identity.run).unwrap();
    let record = status
        .participants
        .iter()
        .find(|p| p.key == child.participant)
        .unwrap();
    assert!(record.actor.is_none() && record.key.agent.is_none());
    let mut e = event(&r, ActivityKind::Stop);
    for (prompt, tool) in [
        (None, None),
        (Some(text("prompt")), None),
        (None, Some(text("tool"))),
        (Some(text("prompt")), Some(text("tool"))),
    ] {
        e.prompt = prompt;
        e.tool = tool;
        assert_eq!(store.record_activity(&e).unwrap(), Transition::Changed);
        assert_eq!(store.record_activity(&e).unwrap(), Transition::Existing);
    }
    let mut same_session = child.clone();
    same_session.participant.agent = Some(text("actual-child-agent"));
    assert_eq!(
        store.record_activity(&same_session).unwrap(),
        Transition::Changed
    );
    assert_eq!(
        store
            .adopted_status(&r.identity.run)
            .unwrap()
            .participants
            .len(),
        3
    );
}
fn durable_rows(sql: &rusqlite::Connection) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let names: Vec<String> = sql
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    names
        .into_iter()
        .map(|name| {
            let mut stmt = sql
                .prepare(&format!("SELECT * FROM \"{name}\" ORDER BY rowid"))
                .unwrap();
            let count = stmt.column_count();
            let rows = stmt
                .query_map([], |r| {
                    (0..count)
                        .map(|i| r.get(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .map(Result::unwrap)
                .collect();
            (name, rows)
        })
        .collect()
}
#[test]
fn corrupt_rosters_reject_all_retries_without_mutation() {
    for corruption in [
        "UPDATE adopted_sessions SET actor='another-valid-actor' WHERE depth=0",
        "UPDATE adopted_sessions SET parent='{\"session\":\"elsewhere\",\"agent\":null}' WHERE depth=0",
        "DELETE FROM adopted_sessions WHERE depth=0",
        "UPDATE adopted_sessions SET actor='another-valid-actor' WHERE depth=1",
        "UPDATE adopted_sessions SET parent='{\"session\":\"elsewhere\",\"agent\":null}' WHERE depth=1",
        "DELETE FROM adopted_sessions WHERE depth=1",
    ] {
        let (dir, mut store, checkout) = fixture();
        let r = adopted(checkout);
        store.begin_adopted(&r).unwrap();
        let root = event(&r, ActivityKind::Stop);
        store.record_activity(&root).unwrap();
        let mut child = event(&r, ActivityKind::SubagentStop);
        child.parent = Some(child.participant.clone());
        child.participant.agent = Some(text("child"));
        child.actor = None;
        store.record_activity(&child).unwrap();
        let sql = rusqlite::Connection::open(dir.path().join("private/store.sqlite")).unwrap();
        sql.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        sql.execute_batch(corruption).unwrap();
        let before = durable_rows(&sql);
        assert!(store.record_activity(&child).is_err(), "duplicate accepted: {corruption}");
        assert_eq!(durable_rows(&sql), before);
        assert!(store.adopted_status(&r.identity.run).is_err(), "{corruption}");
        assert!(store.record_activity(&root).is_err(), "{corruption}");
        assert!(store.begin_adopted(&r).is_err(), "begin accepted: {corruption}");
        assert_eq!(durable_rows(&sql), before);
    }
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
