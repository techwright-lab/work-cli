use super::*;
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, time::Duration};
#[test]
fn artifact_and_receiver_boundaries_have_no_read_transaction_or_armed_sql_phase() {
    let (temp, mut cfg, _store, a, root, old) = crate::capture_setup::tests::materialized();
    let host = cfg.capture.as_mut().unwrap();
    host.registry = temp.path().join("actors.json");
    host.state_dir = temp.path().join("capture-state");
    host.executable = temp.path().join("producer");
    let registry = br#"{"ingest":{"key_env":"TOKEN"}}"#;
    host.registry_sha256 = format!("{:x}", Sha256::digest(registry));
    fs::write(&host.registry, registry).unwrap();
    fs::set_permissions(&host.registry, fs::Permissions::from_mode(0o600)).unwrap();
    fs::create_dir(&host.state_dir).unwrap();
    fs::set_permissions(&host.state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let capture = "550e8400-e29b-41d4-a716-446655440001";
    let context = host.state_dir.join(format!("{capture}.context.json"));
    let exe = host.executable.clone();
    let spec = cfg
        .capture_spec(&root, &a, old.operation(), vec!["task".into()], None)
        .unwrap();
    let d = spec.begin_request();
    let g = spec.expected_git();
    fs::write(&context,serde_json::to_vec(&serde_json::json!({"schema_version":"1.0","actor":{"ref":d.actor_ref},"run":{"ref":d.run_ref,"parent_ref":d.parent_run_ref,"task_ref":"task"},"working_directory":d.cwd,"execution_chain":d.execution_chain,"started_at":"2026-10-18T00:00:00Z"})).unwrap()).unwrap();
    fs::set_permissions(&context, fs::Permissions::from_mode(0o400)).unwrap();
    let response = temp.path().join("response");
    fs::write(&response,serde_json::to_vec(&serde_json::json!({"capture_id":capture,"actor_ref":d.actor_ref,"run_ref":d.run_ref,"state":"open","environment":{"AGENT_ATTRIBUTION_CONTEXT":context,"DEVDIARY_ATTRIBUTION_CONTEXT":context,"DEVDIARY_CAPTURE_ID":capture,"GIT_AUTHOR_NAME":g.author_name,"GIT_AUTHOR_EMAIL":g.author_email,"GIT_COMMITTER_NAME":g.committer_name,"GIT_COMMITTER_EMAIL":g.committer_email}})).unwrap()).unwrap();
    fs::write(
        &exe,
        format!(
            "#!/bin/sh\n/usr/bin/cat >/dev/null\nexec /usr/bin/cat '{}'\n",
            response.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o700)).unwrap();
    let sql = rusqlite::Connection::open(temp.path().join("private/store.sqlite")).unwrap();
    sql.busy_timeout(Duration::ZERO).unwrap();
    let mut boundaries = 0;
    let (_store,result)=prepare_observed(&cfg,&root,&spec,|_,store| {
        boundaries+=1;assert!(store.conn.is_autocommit(),"external boundary holds a read transaction");sql.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
        // A real >1000-op scan reaches the installed progress handler after 650ms.
        // With any surrounding SQL phase it would inherit the expired 500ms budget.
        std::thread::sleep(Duration::from_millis(650));
        let sum:i64=store.conn.query_row("WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<5000) SELECT sum(x) FROM n",[],|r|r.get(0)).expect("external delay was charged to SQL");assert_eq!(sum,12_502_500);
        let record=store.capture_snapshot(&root.identity().run).unwrap().unwrap();assert!(record.prepared.is_none(),"ready before qualification");assert!(store.run_snapshot(&root.identity().run).unwrap().unwrap().binding.is_none());
    }).unwrap();
    assert_eq!(boundaries, 5);
    assert!(matches!(result, PreparationResult::Live(_)));
}
