use super::*;
use crate as collector_target;
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, time::Duration};
pub(crate) fn qualified_fixture() -> (
    tempfile::TempDir,
    Config,
    crate::allocate::Allocation,
    RootRunRequest,
    crate::capture_journal::CaptureSpec,
) {
    qualified_fixture_with_timeout(50)
}
pub(crate) fn qualified_fixture_with_timeout(
    timeout_ms: u64,
) -> (
    tempfile::TempDir,
    Config,
    crate::allocate::Allocation,
    RootRunRequest,
    crate::capture_journal::CaptureSpec,
) {
    let (temp, mut cfg, _store, a, root, old) =
        crate::capture_setup::tests::materialized_with_timeout(timeout_ms);
    let mut value = serde_json::to_value(&root).unwrap();
    let bytes = b"/usr/bin/true";
    let mut hash = Sha256::new();
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    value["input"]["command_digest"] =
        serde_json::to_value(<[u8; 32]>::from(hash.finalize())).unwrap();
    let root: RootRunRequest = serde_json::from_value(value).unwrap();
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
    (temp, cfg, a, root, spec)
}
#[test]
fn artifact_and_receiver_boundaries_have_no_read_transaction_or_armed_sql_phase() {
    let (temp, cfg, _a, root, spec) = qualified_fixture();
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

#[test]
fn live_launch_binding_refuses_command_root_profile_cwd_and_proof_swaps() {
    use crate::scope_spawn::{ActorGitProfile, AttributedCommand};
    let (_temp, cfg, a, root, spec) = qualified_fixture();
    let (_, PreparationResult::Live(live)) = prepare(&cfg, &root, &spec).unwrap() else {
        panic!("new live")
    };
    let profile = &cfg.supervisor.as_ref().unwrap().actors["alice"];
    let argv = ["/usr/bin/true".into()];
    let other_argv = ["/usr/bin/false".into()];
    let mut value = serde_json::to_value(&root).unwrap();
    value["identity"]["run"] = uuid::Uuid::now_v7().to_string().into();
    let other_root: RootRunRequest = serde_json::from_value(value).unwrap();
    let other_profile = ActorGitProfile::new(
        "Other",
        "other@example.invalid",
        "Other",
        "other@example.invalid",
    )
    .unwrap();
    for (name, r, cwd, args, git) in [
        ("argv", &root, a.destination.as_path(), &other_argv, profile),
        ("root", &other_root, a.destination.as_path(), &argv, profile),
        (
            "cwd",
            &root,
            a.request.repository.as_ref().unwrap().as_path(),
            &argv,
            profile,
        ),
        (
            "profile",
            &root,
            a.destination.as_path(),
            &argv,
            &other_profile,
        ),
    ] {
        assert!(
            live.validate_launch(
                r,
                &AttributedCommand {
                    cwd,
                    argv: args,
                    git
                }
            )
            .is_err(),
            "live accepted {name} swap"
        );
    }
    let (_other_temp, other_cfg, _other_a, other_root, other_spec) = qualified_fixture();
    let (_, PreparationResult::Live(other_live)) =
        prepare(&other_cfg, &other_root, &other_spec).unwrap()
    else {
        panic!("new live")
    };
    let proof = live.release_proof().unwrap();
    assert!(proof.validate(&other_live.guard()).is_err());
    assert!(other_live
        .validate_launch(
            &root,
            &AttributedCommand {
                cwd: &a.destination,
                argv: &argv,
                git: profile
            }
        )
        .is_err());
    let debug = format!("{live:?}");
    assert_eq!(debug, "LiveCapture([REDACTED])");
}
#[path = "../tests/support/capture_collector.rs"]
mod collector;
#[test]
fn scope_fixture_child() {
    let Some(context) = std::env::var_os("B2_UNIT_CONTEXT") else {
        return;
    };
    let path = std::path::PathBuf::from(context);
    let root = std::path::PathBuf::from(std::env::var_os("B2_UNIT_FIXTURE").unwrap());
    let collector = collector::Collector {
        root,
        context: serde_json::from_slice(&fs::read(&path).unwrap()).unwrap(),
        initialized: std::cell::Cell::new(false),
    };
    if crate::scope_child::run_with_collector(&path, &["/usr/bin/true".into()], &collector).is_err()
    {
        std::process::exit(42);
    }
}
#[test]
fn generic_owned_release_refuses_captured_launch_without_fresh_private_proof() {
    use crate::{
        runtime_scope::LaunchIntent,
        scope_driver::{Driver, LibraryIo, Limits, RuntimeContext},
        scope_spawn::{AttributedCommand, LaunchIo, LaunchPolicy, OwnedLaunch},
    };
    for forged in [false, true] {
        let (temp, cfg, a, root, spec) = qualified_fixture();
        let (_, PreparationResult::Live(live)) = prepare(&cfg, &root, &spec).unwrap() else {
            panic!("new live")
        };
        let p = temp.path();
        fs::create_dir(p.join("runtime")).unwrap();
        fs::set_permissions(p.join("runtime"), fs::Permissions::from_mode(0o700)).unwrap();
        let _bus = std::os::unix::net::UnixListener::bind(p.join("runtime/bus")).unwrap();
        fs::create_dir_all(p.join("proc/sys/kernel/random")).unwrap();
        fs::copy(
            "/proc/sys/kernel/random/boot_id",
            p.join("proc/sys/kernel/random/boot_id"),
        )
        .unwrap();
        fs::create_dir(p.join("cg")).unwrap();
        let script = |name: &str, text: String| {
            fs::write(p.join(name), format!("#!/bin/sh\n{text}\n")).unwrap();
            fs::set_permissions(p.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        };
        script(
            "manager",
            format!("exec /usr/bin/cat '{}/properties'", p.display()),
        );
        script(
            "launcher",
            "while [ \"$1\" != -- ]; do shift; done; shift; exec \"$@\"".into(),
        );
        script("self",format!("export B2_UNIT_CONTEXT=\"$3\" B2_UNIT_FIXTURE='{0}'\nexec '{1}' --exact capture_preparation::tests::scope_fixture_child --nocapture",p.display(),std::env::current_exe().unwrap().display()));
        let driver = Driver::with_io(
            RuntimeContext::new(
                p.join("runtime"),
                format!("unix:path={}/runtime/bus", p.display()),
            )
            .unwrap(),
            LibraryIo {
                systemctl: p.join("manager"),
                proc_root: p.join("proc"),
                cgroup_root: p.join("cg"),
                between_censuses: None,
            },
            Limits::default(),
        )
        .unwrap();
        let dir = p.join("gate");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let argv = ["/usr/bin/true".into()];
        let mut launch = OwnedLaunch::spawn_captured(
            &driver,
            LaunchIntent::new(root.identity().run.clone(), &root.input().boot).unwrap(),
            &dir,
            &root,
            AttributedCommand {
                cwd: &a.destination,
                argv: &argv,
                git: &cfg.supervisor.as_ref().unwrap().actors["alice"],
            },
            LaunchPolicy::new(Duration::from_secs(5), Duration::from_secs(5)).unwrap(),
            Some(LaunchIo {
                systemd_run: p.join("launcher"),
                self_binary: p.join("self"),
            }),
            &live,
        )
        .unwrap();
        while !launch.poll_blocked().unwrap() {
            std::thread::sleep(Duration::from_millis(5));
        }
        launch.bind(&driver).unwrap();
        if forged {
            let (_other_temp, other_cfg, _other_a, other_root, other_spec) = qualified_fixture();
            let (_, PreparationResult::Live(other_live)) =
                prepare(&other_cfg, &other_root, &other_spec).unwrap()
            else {
                panic!("new live")
            };
            assert!(launch
                .release_captured(&driver, other_live.release_proof().unwrap())
                .is_err());
        } else {
            assert!(
                launch.release(&driver).is_err(),
                "generic release published captured permit without private fresh proof"
            );
        }
        assert!(!dir.join("permit.json").exists());
        assert_eq!(
            launch.outcome(),
            crate::scope_launch::Outcome::RecoveryHold,
            "refused captured release must stop and hold owned blocked child"
        );
    }
}
