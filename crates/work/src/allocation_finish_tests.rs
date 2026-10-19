use super::*;

#[test]
fn identity_refresh_transaction_refuses_finish_inserted_after_preflight() {
    fn git(path: &std::path::Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .current_dir(path)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }
    for malformed in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        let root = temp.path().join("root");
        fs::create_dir(&repo).unwrap();
        fs::create_dir(&root).unwrap();
        git(&repo, &["init", "-b", "main"]);
        git(&repo, &["config", "user.name", "Test"]);
        git(&repo, &["config", "user.email", "test@example.invalid"]);
        git(&repo, &["commit", "--allow-empty", "-m", "initial"]);
        let config = Config::from_text(&format!(
            "store_dir = {:?}\ntrusted_registry = {:?}\nroots = [{:?}]\nrepositories = [{:?}]\n[allocation]\nrepository_limit = 10\nowner_limit = 10\nfloor_bytes = 0\nwarn_bytes = 0\n",
            temp.path().join("private"), temp.path().join("registry"), root, repo
        )).unwrap();
        let mut a = start(
            &config,
            Start {
                operation: Uuid::now_v7(),
                repository: Some(repo),
                root: Some(root),
                actor: Some("actor".into()),
                owner: None,
                task: "task".into(),
                branch: Some("topic".into()),
                base: "main".into(),
                reuse_branch: false,
            },
        )
        .unwrap();
        let (mut store, lock) = locked(&config).unwrap();
        a = verified_checkout(&mut store, a.checkout).unwrap();
        drop(lock);
        // The receipt arrives after successful preflight, but before its final
        // identity transaction. Readiness corruption must not bypass that CAS.
        crate::finish::finish(&config, a.checkout).unwrap();
        store
            .conn
            .execute("UPDATE checkouts SET state='active',ready=1", [])
            .unwrap();
        if malformed {
            store
                .conn
                .execute("UPDATE task_finishes SET record='{}'", [])
                .unwrap();
        }
        git(
            &a.destination,
            &["commit", "--allow-empty", "-m", "advance"],
        );
        let current = CheckoutIdentity::inspect(&a.destination).unwrap();
        assert_ne!(current.head, a.identity.as_ref().unwrap().head);
        let prior = serde_json::to_string(&a).unwrap();
        let events: i64 = store
            .conn
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert!(
            refresh_ready_identity(&mut store, &mut a, current).is_err(),
            "malformed={malformed}"
        );
        assert_eq!(serde_json::to_string(&a).unwrap(), prior);
        assert_eq!(
            store
                .conn
                .query_row("SELECT record FROM allocations", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            prior
        );
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            events
        );
    }
}
