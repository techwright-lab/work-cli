use crate::{
    admission::{Limits, Reservation},
    run_journal::RootRunRequest,
    store::Store,
};
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use std::{sync::mpsc, time::Duration};
use uuid::Uuid;

#[test]
fn root_revision_and_child_tree_share_one_snapshot_and_preserve_caller_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let private = dir.path().join("private");
    let mut store = Store::open(&private, std::slice::from_ref(&root)).unwrap();
    let checkout = store
        .reserve(
            &Reservation {
                operation: Uuid::now_v7(),
                repository: root.clone(),
                actor: "allocator".into(),
                owner: "owner".into(),
                task: "task".into(),
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
    let request: RootRunRequest = serde_json::from_value(serde_json::json!({
        "identity":{"checkout":checkout,"group":Uuid::now_v7(),"run":Uuid::now_v7(),"run_ref":"snapshot-root","actor":"root","parent_run_ref":null,"execution_chain":[{"kind":"executor","system":"fixture"}]},
        "input":{"command_digest":vec![1;32],"input_digest":vec![2;32],"context_ref":"context","intent_ref":"intent","boot":"550e8400-e29b-41d4-a716-446655440000"}
    })).unwrap();
    store.begin_run(&request).unwrap();
    // Synthetic journal stage only; never create runtime authority or a process.
    store.conn.execute("UPDATE runs SET stage='permit_attempt',binding=?1", [serde_json::json!({
        "unit":format!("work-run-{}.scope",request.identity().run),"invocation":"550e8400e29b41d4a716446655440000",
        "cgroup":format!("/fixture/work-run-{}.scope",request.identity().run),"boot":request.input().boot,"root_pid":42,"root_start_ticks":10,"root_cgroup":format!("/fixture/work-run-{}.scope",request.identity().run)
    }).to_string()]).unwrap();
    let child = super::ChildRequest {
        checkout: request.identity().checkout.clone(),
        group: request.identity().group.clone(),
        run: work_contract::RunId::generate(),
        run_ref: work_contract::RunRef::parse("snapshot-child").unwrap(),
        parent_run: request.identity().run.clone(),
        parent_run_ref: request.identity().run_ref.clone(),
        execution_chain: request.identity().execution_chain.clone(),
        source: None,
        session: None,
        agent: None,
        actor: None,
        expected_host: None,
    };
    let mut writer = Store::open(&private, &[root]).unwrap();
    let writer_root = request.clone();
    let (go, start) = mpsc::channel();
    let (done, ack) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        start.recv_timeout(Duration::from_secs(2)).unwrap();
        writer.register_child(&writer_root, &child).unwrap();
        done.send(()).unwrap();
    });
    let mut fired = false;
    store
        .conn
        .authorizer(Some(move |ctx: AuthContext<'_>| {
            if !fired
                && matches!(
                    ctx.action,
                    AuthAction::Read {
                        table_name: "run_participants",
                        ..
                    }
                )
            {
                fired = true;
                go.send(()).unwrap();
                ack.recv_timeout(Duration::from_secs(2)).unwrap();
            }
            Authorization::Allow
        }))
        .unwrap();
    let old = store.run_snapshot(&request.identity().run);
    store
        .conn
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .unwrap();
    thread.join().unwrap();
    let old = old.unwrap().unwrap();
    assert_eq!(old.revision, 1);
    assert!(old.children.is_empty());
    assert!(store.conn.is_autocommit());
    let new = store
        .run_snapshot(&request.identity().run)
        .unwrap()
        .unwrap();
    assert_eq!(new.revision, 2);
    assert_eq!(new.children.len(), 1);
    store.conn.execute_batch("BEGIN").unwrap();
    store.group_snapshot(&request.identity().run).unwrap();
    assert!(!store.conn.is_autocommit());
    store.conn.execute_batch("ROLLBACK").unwrap();
    store
        .conn
        .execute_batch("UPDATE run_participants SET request='{}'")
        .unwrap();
    assert!(store.run_snapshot(&request.identity().run).is_err());
    assert!(
        store.conn.is_autocommit(),
        "owned read transaction rolls back on errors"
    );
    store.conn.execute_batch("BEGIN").unwrap();
    assert!(store.run_snapshot(&request.identity().run).is_err());
    assert!(
        !store.conn.is_autocommit(),
        "errors never consume caller-owned read transaction"
    );
}
