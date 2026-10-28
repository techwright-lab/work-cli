#[path = "support/run_fixture.rs"]
mod run_fixture;
mod support;
use work_cli as collector_target;
#[path = "support/capture_collector.rs"]
mod capture_collector;
#[test]
fn fixture_child() {
    let Some(context) = std::env::var_os("CAPTURE_SCOPE_CONTEXT") else {
        return;
    };
    let root = std::path::PathBuf::from(std::env::var_os("CAPTURE_SCOPE_FIXTURE").unwrap());
    let path = std::path::PathBuf::from(context);
    let collector = capture_collector::Collector {
        root: root.clone(),
        context: serde_json::from_slice(&fs::read(&path).unwrap()).unwrap(),
        initialized: std::cell::Cell::new(false),
    };
    use std::os::unix::ffi::OsStringExt;
    let bytes = fs::read(root.join("argv")).unwrap();
    let mut argv: Vec<_> = bytes
        .split(|b| *b == 0)
        .map(|v| std::ffi::OsString::from_vec(v.to_vec()))
        .collect();
    argv.pop();
    if work_cli::scope_child::run_with_collector(&path, &argv, &collector).is_err() {
        std::process::exit(42)
    }
}
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener},
};
use support::Fixture;
use uuid::Uuid;
use work_cli::{config::Config, supervisor::*};

const CAPTURE: &str = "550e8400-e29b-41d4-a716-446655440001";
fn file(path: &std::path::Path, text: impl AsRef<[u8]>, mode: u32) {
    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
struct Harness {
    f: Fixture,
    cfg: Config,
    command: RootCommand,
    _bus: UnixListener,
}
impl Harness {
    fn new() -> Self {
        let f = Fixture::new();
        let p = f.temp.path();
        fs::create_dir(p.join("runtime")).unwrap();
        fs::set_permissions(p.join("runtime"), fs::Permissions::from_mode(0o700)).unwrap();
        let bus = UnixListener::bind(p.join("runtime/bus")).unwrap();
        fs::create_dir_all(p.join("proc/sys/kernel/random")).unwrap();
        fs::copy(
            "/proc/sys/kernel/random/boot_id",
            p.join("proc/sys/kernel/random/boot_id"),
        )
        .unwrap();
        fs::create_dir(p.join("cg")).unwrap();
        let registry = p.join("actors.json");
        let state = p.join("capture-state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let bytes = br#"{"ingest":{"key_env":"RECEIVER_TOKEN"}}"#;
        file(&registry, bytes, 0o600);
        let producer = p.join("producer");
        // Synthetic receiver writes only the public contract using stdlib JSON.
        file(
            &producer,
            format!(
                r#"#!/usr/bin/python3
import json,sys,os
r=json.load(sys.stdin)
open({calls:?},'a').write('called\n')
c={state:?}+'/{CAPTURE}.context.json'
v={{'schema_version':'1.0','actor':{{'ref':r['actor_ref']}},'run':{{'ref':r['run_ref'],'parent_ref':r.get('parent_run_ref'),'task_ref':r['task_refs'][0]}},'execution_chain':r['execution_chain'],'working_directory':r['cwd'],'started_at':'2026-10-18T00:00:00Z'}}
with open(c,'w') as f: json.dump(v,f)
os.chmod(c,0o400)
e={{'AGENT_ATTRIBUTION_CONTEXT':c,'DEVDIARY_ATTRIBUTION_CONTEXT':c,'DEVDIARY_CAPTURE_ID':'{CAPTURE}','GIT_AUTHOR_NAME':'Sol','GIT_AUTHOR_EMAIL':'sol@example.invalid','GIT_COMMITTER_NAME':'Sol','GIT_COMMITTER_EMAIL':'sol@example.invalid'}}
json.dump({{'capture_id':'{CAPTURE}','state':'open','actor_ref':r['actor_ref'],'run_ref':r['run_ref'],'environment':e}},sys.stdout)
"#,
                calls = p.join("calls").to_str().unwrap(),
                state = state.to_str().unwrap()
            ),
            0o700,
        );
        let mut text = fs::read_to_string(p.join("config.toml"))
            .unwrap()
            .replace("[allocation]", "[allocation]\ncapture_sink='devdiary'");
        text += &format!("\n[capture]\nexecutable={producer:?}\nregistry={registry:?}\nstate_dir={state:?}\ntimeout_ms=1000\nresponse_cap=65536\nregistry_sha256='{:x}'\nendpoint_identity='fixture'\nreceiver_credential_names=['RECEIVER_TOKEN']\n[capture.actor_refs]\nalice='actor:alice'\n[supervisor]\nruntime_directory={:?}\nbus_address='unix:path={}/runtime/bus'\nruntime_max_seconds=5\npreexec_ms=5000\nclosure_grace_ms=50\ncancel_grace_ms=50\n[supervisor.actors.alice]\nauthor_name='Sol'\nauthor_email='sol@example.invalid'\ncommitter_name='Sol'\ncommitter_email='sol@example.invalid'\n",Sha256::digest(bytes),p.join("runtime"),p.display());
        fs::write(p.join("config.toml"), &text).unwrap();
        let cfg = Config::from_text(&text).unwrap();
        let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
        assert!(out.status.success(), "{out:?}");
        let a: work_cli::allocate::Allocation = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(a.stage, "capture_pending");
        let command = RootCommand {
            checkout: a.checkout,
            actor: None,
            run_id: Uuid::now_v7(),
            execution_chain: serde_json::from_str(r#"[{"kind":"executor","system":"fixture"}]"#)
                .unwrap(),
            argv: vec!["/usr/bin/true".into()],
        };
        Self {
            f,
            cfg,
            command,
            _bus: bus,
        }
    }
    fn driver(&self) -> work_cli::scope_driver::Driver {
        use work_cli::scope_driver::{Driver, LibraryIo, Limits, RuntimeContext};
        let p = self.f.temp.path();
        Driver::with_io(
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
        .unwrap()
    }
    fn execute(&self) -> std::io::Result<RunReport> {
        self.observed(|_, _| {})
    }
    fn observed(
        &self,
        observer: impl FnMut(Boundary, &work_cli::run_journal::RunRecord),
    ) -> std::io::Result<RunReport> {
        supervise_captured_with_io(
            &self.cfg,
            self.command.clone(),
            &self.driver(),
            work_cli::scope_spawn::LaunchIo {
                systemd_run: self.f.temp.path().join("launcher"),
                self_binary: self.f.temp.path().join("self"),
            },
            &CancelToken::default(),
            observer,
        )
    }
    fn launcher(&mut self) {
        let p = self.f.temp.path();
        file(
            &p.join("manager"),
            format!(
                "#!/bin/sh\nexec /usr/bin/cat '{}/properties'\n",
                p.display()
            ),
            0o700,
        );
        file(&p.join("launcher"),format!("#!/bin/sh\nprintf started > '{0}/manager-started'\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n",p.display()),0o700);
        file(&p.join("self"),format!("#!/bin/sh\nexport CAPTURE_SCOPE_CONTEXT=\"$3\" CAPTURE_SCOPE_FIXTURE='{0}'\nshift 4\nprintf '%s\\0' \"$@\" > '{0}/argv'\nexec '{1}' --exact fixture_child --nocapture\n",p.display(),std::env::current_exe().unwrap().display()),0o700);
        file(&p.join("delegate"),format!("#!/bin/sh\nprintf '%s\\n' \"$AGENT_ATTRIBUTION_CONTEXT\" \"$DEVDIARY_ATTRIBUTION_CONTEXT\" \"$DEVDIARY_CAPTURE_ID\" \"$GIT_AUTHOR_NAME\" \"$GIT_AUTHOR_EMAIL\" \"$GIT_COMMITTER_NAME\" \"$GIT_COMMITTER_EMAIL\" > '{0}/actor-env'\nprintf actor > '{0}/executed'\n",p.display()),0o700);
        self.command.argv = vec![p.join("delegate").into_os_string()];
    }
    fn empty(&self, r: &work_cli::run_journal::RunRecord) {
        let b = r.binding.as_ref().unwrap();
        let p = self.f.temp.path();
        fs::remove_dir_all(p.join(format!("proc/{}", b.root_pid))).unwrap();
        fs::write(
            p.join("cg")
                .join(b.cgroup.trim_start_matches('/'))
                .join("cgroup.procs"),
            "",
        )
        .unwrap();
    }
}
#[test]
fn integrated_two_distinct_captures_restore_ready_without_recharging() {
    let mut h = Harness::new();
    h.launcher();
    let producer = fs::read_to_string(h.f.temp.path().join("producer")).unwrap();
    let delegate = fs::read_to_string(h.f.temp.path().join("delegate")).unwrap();
    file(&h.f.temp.path().join("delegate"), format!("{delegate}\n/usr/bin/git commit --allow-empty -m \"$1\" >/dev/null\nprintf 'run\\n' >> '{}'\n",h.f.temp.path().join("actor-runs").display()),0o700);
    for capture in [CAPTURE.to_owned(), Uuid::now_v7().to_string()] {
        h.command.run_id = Uuid::now_v7();
        h.command.argv.truncate(1);
        h.command.argv.push(capture.clone().into());
        file(
            &h.f.temp.path().join("producer"),
            producer.replace(CAPTURE, &capture),
            0o700,
        );
        let report=supervise_captured_integrated_with_io(&h.cfg,h.command.clone(),&h.driver(),work_cli::scope_spawn::LaunchIo { systemd_run:h.f.temp.path().join("launcher"),self_binary:h.f.temp.path().join("self") },&CancelToken::default(), |boundary,r| {
            if boundary==Boundary::RootTerminal { h.empty(r); }
            if boundary==Boundary::Closed {
                file(&h.f.temp.path().join("response"),serde_json::json!({"capture_id":capture,"actor_ref":"actor:alice","run_ref":r.request.identity().run_ref.as_str(),"state":"pending"}).to_string(),0o600);
                file(&h.f.temp.path().join("producer"),format!("#!/bin/sh\n/usr/bin/cat >/dev/null\n/usr/bin/sleep 0.65\nexec /usr/bin/cat '{}'\n",h.f.temp.path().join("response").display()),0o700);
            }
        }).unwrap_or_else(|e| panic!("integrated capture {capture} must succeed: {e}"));
        assert!(report.record.closed && report.task_open && report.lease_charged);
        assert!(
            !report.capture_unfrozen,
            "integrated closure must actually FINISH capture"
        );
        assert!(
            report.checkout_ready,
            "integrated report omitted durable Ready despite successful certification"
        );
        assert_eq!(
            report.record.outcome,
            Some(work_cli::run_journal::RootOutcome::Completed)
        );
        let keeper = h.f.store();
        let sql = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
        assert_eq!(
            sql.query_row("SELECT state,ready FROM checkouts", [], |r| Ok((
                r.get::<_, String>(0)?,
                r.get::<_, bool>(1)?
            )))
            .unwrap(),
            ("active".into(), true)
        );
        assert_eq!(
            sql.query_row("SELECT count(*) FROM capture_readiness", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        let body: String = sql
            .query_row("SELECT certificate FROM capture_readiness", [], |r| {
                r.get(0)
            })
            .unwrap();
        let certificate: serde_json::Value = serde_json::from_str(&body).unwrap();
        let actual = work_cli::identity::CheckoutIdentity::inspect(&h.f.root.join("task")).unwrap();
        assert_eq!(certificate["physical"]["checkout"]["head"], actual.head);
        assert_eq!(keeper.charged(&h.f.repo, None).unwrap(), 1);
    }
    assert_eq!(
        fs::read_to_string(h.f.temp.path().join("actor-runs")).unwrap(),
        "run\nrun\n"
    );
}

#[test]
fn newer_frozen_but_uncertified_root_invalidates_old_certificate_despite_ready_flags() {
    let mut h = Harness::new();
    h.launcher();
    let producer = fs::read_to_string(h.f.temp.path().join("producer")).unwrap();
    for certify in [true, false] {
        let capture = Uuid::now_v7().to_string();
        h.command.run_id = Uuid::now_v7();
        file(
            &h.f.temp.path().join("producer"),
            producer.replace(CAPTURE, &capture),
            0o700,
        );
        let observer = |boundary: Boundary, r: &work_cli::run_journal::RunRecord| {
            if boundary == Boundary::RootTerminal {
                h.empty(r);
            }
            if boundary == Boundary::Closed {
                file(&h.f.temp.path().join("response"),serde_json::json!({"state":"pending","capture_id":capture,"actor_ref":"actor:alice","run_ref":r.request.identity().run_ref.as_str()}).to_string(),0o600);
                file(
                    &h.f.temp.path().join("producer"),
                    format!(
                        "#!/bin/sh\n/usr/bin/cat >/dev/null\nexec /usr/bin/cat '{}'\n",
                        h.f.temp.path().join("response").display()
                    ),
                    0o700,
                );
            }
        };
        let report = if certify {
            supervise_captured_integrated_with_io(
                &h.cfg,
                h.command.clone(),
                &h.driver(),
                work_cli::scope_spawn::LaunchIo {
                    systemd_run: h.f.temp.path().join("launcher"),
                    self_binary: h.f.temp.path().join("self"),
                },
                &CancelToken::default(),
                observer,
            )
            .unwrap()
        } else {
            h.observed(observer).unwrap()
        };
        assert!(report.record.closed);
        if !certify {
            work_cli::capture_finalization::finalize(&h.cfg, &report.record.request.identity().run)
                .unwrap();
        }
    }
    let keeper = h.f.store();
    let sql = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
    assert!(!sql
        .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
        .unwrap());
    assert_eq!(
        sql.query_row(
            "SELECT count(*) FROM capture_finalizations WHERE confirmation IS NOT NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    sql.execute("UPDATE checkouts SET state='active',ready=1", [])
        .unwrap();
    let before = keeper.pending_events(100).unwrap();
    h.command.run_id = Uuid::now_v7();
    assert!(
        h.execute().is_err(),
        "old certificate authorized a newer frozen but uncertified frontier"
    );
    assert_eq!(keeper.pending_events(100).unwrap(), before);
    assert_eq!(
        sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        sql.query_row("SELECT count(*) FROM capture_runs", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn passive_finish_existing_never_restores_ready_from_a_live_closure() {
    let mut h = Harness::new();
    h.launcher();
    let report=supervise_captured_integrated_with_io(&h.cfg,h.command.clone(),&h.driver(),work_cli::scope_spawn::LaunchIo {systemd_run:h.f.temp.path().join("launcher"),self_binary:h.f.temp.path().join("self")},&CancelToken::default(),|boundary,r| {
        if boundary==Boundary::RootTerminal {h.empty(r);}
        if boundary==Boundary::Closed {
            file(&h.f.temp.path().join("response"),serde_json::json!({"state":"pending","capture_id":CAPTURE,"actor_ref":"actor:alice","run_ref":r.request.identity().run_ref.as_str()}).to_string(),0o600);
            file(&h.f.temp.path().join("producer"),format!("#!/bin/sh\n/usr/bin/cat >/dev/null\nexec /usr/bin/cat '{}'\n",h.f.temp.path().join("response").display()),0o700);
            let (_,result)=work_cli::capture_finalization::finalize(&h.cfg,&r.request.identity().run).unwrap();
            assert!(matches!(result,work_cli::capture_finalization::FinalizeResult::Confirmed {..}));
            // Drop the actual acknowledgement. The coordinator's subsequent
            // passive Existing lookup cannot reconstruct the lost authority.
        }
    }).unwrap();
    assert!(
        report.record.closed
            && !report.capture_unfrozen
            && report.lease_charged
            && report.task_open
    );
    let _keeper = h.f.store();
    let sql = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
    assert!(!sql
        .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
        .unwrap());
    assert_eq!(
        sql.query_row("SELECT count(*) FROM capture_readiness", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn post_close_capture_failure_never_claims_an_unrecorded_kernel_hold() {
    let mut h = Harness::new();
    h.launcher();
    let result = supervise_captured_integrated_with_io(
        &h.cfg,
        h.command.clone(),
        &h.driver(),
        work_cli::scope_spawn::LaunchIo {
            systemd_run: h.f.temp.path().join("launcher"),
            self_binary: h.f.temp.path().join("self"),
        },
        &CancelToken::default(),
        |boundary, r| {
            if boundary == Boundary::RootTerminal {
                h.empty(r);
            }
            if boundary == Boundary::Closed {
                let sql = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite"))
                    .unwrap();
                sql.execute("UPDATE capture_runs SET spec='{}'", [])
                    .unwrap();
            }
        },
    );
    let error = result
        .expect_err("corrupt capture must refuse finalization")
        .to_string();
    assert!(
        !error.contains("recovery hold uncertain"),
        "known committed closure was masked: {error}"
    );
    let keeper = h.f.store();
    let sql = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
    assert_eq!(
        sql.query_row("SELECT closed FROM run_groups", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(!sql
        .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
        .unwrap());
    assert_eq!(keeper.charged(&h.f.repo, None).unwrap(), 1);
}

#[test]
fn cli_captured_existing_precedes_runtime_profile_receiver_and_artifacts() {
    let mut h = Harness::new();
    h.launcher();
    let report = h
        .observed(|b, r| {
            if b == Boundary::RootTerminal {
                h.empty(r)
            }
        })
        .unwrap();
    h.cfg.supervisor = None;
    h.cfg.capture = None;
    h.cfg.allocation.as_mut().unwrap().capture_sink = None;
    fs::remove_file(h.f.temp.path().join("producer")).unwrap();
    fs::remove_dir_all(h.f.temp.path().join("capture-state")).unwrap();
    let chain = h.f.temp.path().join("chain.json");
    fs::write(
        &chain,
        serde_json::to_vec(&h.command.execution_chain).unwrap(),
    )
    .unwrap();
    let before = h.f.store().pending_events(100).unwrap();
    let result = work_cli::supervisor::command(
        &h.cfg,
        Run {
            attribution: None,
            checkout: h.command.checkout,
            actor: None,
            run_id: h.command.run_id,
            execution_chain: chain,
            argv: h.command.argv.clone(),
        },
    );
    assert!(
        result.is_ok(),
        "captured CLI receipt must not require current runtime: {result:?}"
    );
    assert_eq!(h.f.store().pending_events(100).unwrap(), before);
    assert_eq!(
        h.f.store()
            .run_snapshot(&report.record.request.identity().run)
            .unwrap()
            .unwrap(),
        report.record
    );
}

#[test]
fn terminal_finalization_changes_only_observational_report() {
    let mut h = Harness::new();
    h.launcher();
    let report = h
        .observed(|b, r| {
            if b == Boundary::RootTerminal {
                h.empty(r)
            }
        })
        .unwrap();
    let response = serde_json::json!({"capture_id":CAPTURE,"actor_ref":"actor:alice","run_ref":report.record.request.identity().run_ref.as_str(),"state":"pending"});
    file(
        &h.f.temp.path().join("response"),
        response.to_string(),
        0o600,
    );
    file(
        &h.f.temp.path().join("producer"),
        format!(
            "#!/bin/sh\n/usr/bin/cat >/dev/null\nexec /usr/bin/cat '{}'\n",
            h.f.temp.path().join("response").display()
        ),
        0o700,
    );
    work_cli::capture_finalization::finalize(&h.cfg, &report.record.request.identity().run)
        .unwrap();
    let after = h.execute().unwrap();
    assert!(
        !after.capture_unfrozen,
        "confirmed frozen still reported unfrozen"
    );
    assert!(!after.attribution_not_configured);
    assert!(after.task_open && after.lease_charged && after.existing);
    assert_eq!(after.record, report.record);
}

#[test]
fn qualified_capture_runs_attributed_actor_and_closes_group_but_retains_capture_hold() {
    let mut h = Harness::new();
    h.launcher();
    let report = h
        .observed(|boundary, r| {
            if boundary == Boundary::RootTerminal {
                h.empty(r)
            }
        })
        .expect("qualified capture must execute");
    assert!(report.record.closed && report.task_open && report.lease_charged);
    assert!(!report.attribution_not_configured);
    assert_eq!(
        report.record.outcome,
        Some(work_cli::run_journal::RootOutcome::Completed)
    );
    let context =
        h.f.temp
            .path()
            .join(format!("capture-state/{CAPTURE}.context.json"));
    assert_eq!(
        fs::read_to_string(h.f.temp.path().join("actor-env")).unwrap(),
        format!(
            "{0}\n{0}\n{CAPTURE}\nSol\nsol@example.invalid\nSol\nsol@example.invalid\n",
            context.display()
        )
    );
    let capture =
        h.f.store()
            .capture_snapshot(&report.record.request.identity().run)
            .unwrap()
            .unwrap();
    assert!(capture.prepared.unwrap().live_preparation && capture.group_end.is_some());
    let db = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
    assert_eq!(
        db.query_row("SELECT state,ready FROM checkouts", [], |r| Ok((
            r.get::<_, String>(0)?,
            r.get::<_, bool>(1)?
        )))
        .unwrap(),
        ("held".into(), false)
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM capture_requirements", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    // Already-existing permanent requirement fences remain in force after closure.
    let before = h.f.store().pending_events(100).unwrap();
    assert!(h
        .f
        .store()
        .begin_run(&run_fixture::request(h.command.checkout))
        .is_err());
    h.command.run_id = Uuid::now_v7();
    assert!(
        h.execute().is_err(),
        "b2 must not continue to a second captured root"
    );
    assert_eq!(h.f.store().pending_events(100).unwrap(), before);
    assert_eq!(h.f.store().charged(&h.f.repo, None).unwrap(), 1);
}
#[test]
fn late_context_replacement_at_bound_or_permit_never_releases_actor() {
    for at in [Boundary::Bound, Boundary::PermitAttempt] {
        let mut h = Harness::new();
        h.launcher();
        let result = h.observed(|boundary, _| {
            if boundary == at {
                let path =
                    h.f.temp
                        .path()
                        .join(format!("capture-state/{CAPTURE}.context.json"));
                fs::rename(&path, h.f.temp.path().join("old-context")).unwrap();
                file(&path, b"{}", 0o400);
            }
        });
        assert!(
            result.is_err(),
            "late context change at {at:?} released actor"
        );
        assert!(!h.f.temp.path().join("executed").exists());
        let run = work_contract::RunId::parse(&h.command.run_id.to_string()).unwrap();
        let store = h.f.store();
        let r = store.run_snapshot(&run).unwrap().unwrap();
        assert!(r.recovery_hold && r.outcome.is_none() && !r.closed);
        assert_eq!(store.charged(&h.f.repo, None).unwrap(), 1);
    }
}
#[test]
fn captured_open_and_closed_history_ignores_current_profile_sink_and_artifacts() {
    for closed in [false, true] {
        let mut h = Harness::new();
        h.launcher();
        let first = h.observed(|b, r| {
            if b == Boundary::RootTerminal {
                h.empty(r)
            }
            if !closed && b == Boundary::Intent {
                let path =
                    h.f.temp
                        .path()
                        .join(format!("capture-state/{CAPTURE}.context.json"));
                fs::remove_file(path).unwrap();
            }
        });
        assert_eq!(first.is_ok(), closed);
        let before = h.f.store().pending_events(100).unwrap();
        let run = work_contract::RunId::parse(&h.command.run_id.to_string()).unwrap();
        let root = h.f.store().run_snapshot(&run).unwrap().unwrap();
        h.cfg.supervisor = None;
        h.cfg.capture = None;
        h.cfg.allocation = None;
        for name in ["producer", "actors.json", "launcher", "self", "manager"] {
            fs::remove_file(h.f.temp.path().join(name)).unwrap();
        }
        let mut calls = 0;
        let report = h
            .observed(|_, _| calls += 1)
            .expect("historic capture is observation, not execution");
        assert_eq!(calls, 0);
        assert!(report.existing && report.capture_unfrozen);
        assert_eq!(report.record, root);
        assert_eq!(report.record.closed, closed);
        assert_eq!(h.f.store().pending_events(100).unwrap(), before);
        assert_eq!(h.f.store().charged(&h.f.repo, None).unwrap(), 1);
        let mut wrong = h.command.clone();
        wrong.argv.push("different".into());
        h.command = wrong;
        assert!(h.execute().is_err(), "mismatched history must refuse");
    }
}
#[test]
fn original_context_proof_expires_during_allocator_contention_or_final_kernel_gate() {
    for slow_kernel in [false, true] {
        let mut h = Harness::new();
        h.launcher();
        if slow_kernel {
            file(&h.f.temp.path().join("manager"),format!("#!/bin/sh\nif [ -e '{0}/slow' ]; then /usr/bin/sleep 0.7; fi\nexec /usr/bin/cat '{0}/properties'\n",h.f.temp.path().display()),0o700);
        }
        let mut worker = None;
        let result = h.observed(|b, _| {
            if b == Boundary::CapturedPreflight {
                if slow_kernel {
                    fs::write(h.f.temp.path().join("slow"), "").unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(1500));
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(1850));
                    let path = h.f.temp.path().join("private/allocation.lock");
                    let (tx, rx) = std::sync::mpsc::channel();
                    worker = Some(std::thread::spawn(move || {
                        let lock = fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(path)
                            .unwrap();
                        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
                            .unwrap();
                        tx.send(()).unwrap();
                        std::thread::sleep(std::time::Duration::from_millis(300));
                    }));
                    rx.recv().unwrap();
                }
            }
        });
        if let Some(worker) = worker {
            worker.join().unwrap();
        }
        assert!(
            result.is_err(),
            "expired original proof released actor (kernel={slow_kernel})"
        );
        assert!(!h.f.temp.path().join("executed").exists());
    }
}
#[test]
fn environment_worker() {
    if std::env::var_os("B2_ENV_WORKER").is_none() {
        return;
    }
    use std::os::unix::ffi::OsStringExt;
    let mut h = Harness::new();
    h.launcher();
    let p = h.f.temp.path();
    let key = p.join("key-locator");
    file(&key, b"synthetic locator", 0o600);
    let host = h.cfg.capture.as_mut().unwrap();
    host.key_file = Some(key);
    host.receiver_credential_names = vec!["RECEIVER_EXTRA".into()];
    // Inspect only known synthetic names, never dump the host environment.
    let check = |stage: &str| {
        format!("printf '%s|%s|%s|%s' \"${{RECEIVER_TOKEN+present}}\" \"${{RECEIVER_EXTRA+present}}\" \"$RECEIVER_TOKEN_LIKE\" \"$UNRELATED_AGENT_KEY\" > '{}/{stage}-credentials'\n",p.display())
    };
    for (name, stage) in [
        ("launcher", "launcher"),
        ("self", "helper"),
        ("delegate", "actor"),
        ("manager", "manager"),
    ] {
        let script = fs::read_to_string(p.join(name)).unwrap();
        file(
            &p.join(name),
            script.replacen("#!/bin/sh\n", &format!("#!/bin/sh\n{}", check(stage)), 1),
            0o700,
        );
    }
    let producer = fs::read_to_string(p.join("producer")).unwrap();
    file(&p.join("producer"),producer.replacen("r=json.load(sys.stdin)",&format!("r=json.load(sys.stdin)\nassert os.environ.get('RECEIVER_TOKEN')=='synthetic-receiver'\nopen({:?},'w').write('intended')",p.join("receiver-key").to_str().unwrap()),1),0o700);
    let script = fs::read_to_string(p.join("delegate")).unwrap();
    file(&p.join("delegate"),format!("{script}\nprintf '%s\\0' \"$@\" > '{0}/actual-argv'\nprintf '%s\\0%s\\0' \"$XDG_RUNTIME_DIR\" \"$DBUS_SESSION_BUS_ADDRESS\" > '{0}/runtime-bytes'\nprintf 'delegate-protocol:'\n/usr/bin/cat\n",p.display()),0o700);
    h.command.argv.extend([
        "".into(),
        std::ffi::OsString::from_vec(vec![0xff]),
        "literal $argument".into(),
    ]);
    let report = h
        .observed(|b, r| {
            if b == Boundary::RootTerminal {
                h.empty(r)
            }
        })
        .unwrap();
    assert!(report.record.closed && report.capture_unfrozen);
    assert_eq!(fs::read(p.join("receiver-key")).unwrap(), b"intended");
    for stage in ["launcher", "helper", "actor", "manager"] {
        assert_eq!(
            fs::read(p.join(format!("{stage}-credentials"))).unwrap(),
            b"||lookalike|agent",
            "credential leakage at {stage}"
        );
    }
    assert_eq!(
        fs::read(p.join("actual-argv")).unwrap(),
        b"\0\xff\0literal $argument\0"
    );
    assert_eq!(fs::read(p.join("runtime-bytes")).unwrap(), b"\xff\0\xfe\0");
}
#[test]
fn captured_environment_strips_exact_credentials_before_every_helper_and_preserves_protocol() {
    use std::{
        io::Write,
        os::unix::ffi::OsStringExt,
        process::{Command, Stdio},
    };
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "environment_worker", "--nocapture"])
        .env("B2_ENV_WORKER", "1")
        .env("RECEIVER_TOKEN", "synthetic-receiver")
        .env("RECEIVER_EXTRA", "synthetic-extra")
        .env("RECEIVER_TOKEN_LIKE", "lookalike")
        .env("UNRELATED_AGENT_KEY", "agent")
        .env("XDG_RUNTIME_DIR", std::ffi::OsString::from_vec(vec![0xff]))
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            std::ffi::OsString::from_vec(vec![0xfe]),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"EOF-payload\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out
        .stdout
        .windows(b"delegate-protocol:EOF-payload\n".len())
        .any(|b| b == b"delegate-protocol:EOF-payload\n"));
}
#[test]
fn durable_boundary_failure_explicitly_reports_uncertain_hold_persistence() {
    let mut h = Harness::new();
    h.launcher();
    let error=h.observed(|b,_|if b==Boundary::Bound {
        let sql=rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
        sql.execute_batch("CREATE TRIGGER reject_group_update BEFORE UPDATE ON run_groups BEGIN SELECT RAISE(FAIL,'fixture durable refusal'); END;").unwrap();
    }).unwrap_err();
    assert!(
        error.to_string().contains("hold uncertain"),
        "failure concealed uncertain recovery hold: {error}"
    );
    assert!(!h.f.temp.path().join("executed").exists());
    assert_eq!(h.f.store().charged(&h.f.repo, None).unwrap(), 1);
    let sql = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
    assert_eq!(
        sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}
// Supplemental coverage of existing fences/shared-loop behavior; not new RED evidence.
#[test]
fn explicit_root_actor_is_independent_of_allocation_quota_owner() {
    let mut h = Harness::new();
    h.launcher();
    h.command.actor = Some("bob".into());
    h.cfg
        .capture
        .as_mut()
        .unwrap()
        .actor_refs
        .insert("bob".into(), "actor:bob".into());
    let settings = h.cfg.supervisor.as_mut().unwrap();
    settings
        .actors
        .insert("bob".into(), settings.actors["alice"].clone());
    let report = h
        .observed(|b, r| {
            if b == Boundary::RootTerminal {
                h.empty(r)
            }
        })
        .unwrap();
    assert!(report.record.closed);
    assert_eq!(report.record.request.identity().actor.as_str(), "bob");
    let sql = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
    assert_eq!(
        sql.query_row("SELECT actor,owner FROM checkouts", [], |r| Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?
        )))
        .unwrap(),
        ("alice".into(), "alice".into())
    );
    assert_eq!(h.f.store().charged(&h.f.repo, Some("alice")).unwrap(), 1);
}
#[test]
fn historic_corruption_refuses_without_preparation_or_repair() {
    for mutation in [
        "UPDATE capture_runs SET fingerprint=zeroblob(32)",
        "UPDATE capture_runs SET prepared='{}'",
        "DELETE FROM capture_runs",
    ] {
        let mut h = Harness::new();
        h.launcher();
        h.observed(|b, r| {
            if b == Boundary::RootTerminal {
                h.empty(r)
            }
        })
        .unwrap();
        let sql = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
        sql.execute_batch(mutation).unwrap();
        h.cfg.supervisor = None;
        h.cfg.capture = None;
        assert!(h
            .observed(|_, _| panic!("corrupt history reached execution"))
            .is_err());
        assert_eq!(
            fs::read_to_string(h.f.temp.path().join("calls")).unwrap(),
            "called\n"
        );
    }
}
#[test]
fn ordinary_root_history_cannot_be_upgraded_to_capture() {
    let h = Harness::new();
    let f = Fixture::new();
    let out = f.start(&Uuid::now_v7().to_string(), "task", "ordinary", &[]);
    assert!(out.status.success());
    let a: work_cli::allocate::Allocation = serde_json::from_slice(&out.stdout).unwrap();
    let root = run_fixture::request(a.checkout);
    let mut store = f.store();
    store.begin_run(&root).unwrap();
    let cfg =
        Config::from_text(&fs::read_to_string(f.temp.path().join("config.toml")).unwrap()).unwrap();
    let before = store.pending_events(100).unwrap();
    let mut command = h.command.clone();
    command.checkout = a.checkout;
    command.run_id = Uuid::parse_str(&root.identity().run.to_string()).unwrap();
    command.execution_chain = root.identity().execution_chain.clone();
    let error = supervise_captured_with_io(
        &cfg,
        command,
        &h.driver(),
        work_cli::scope_spawn::LaunchIo {
            systemd_run: h.f.temp.path().join("absent"),
            self_binary: h.f.temp.path().join("absent-self"),
        },
        &CancelToken::default(),
        |_, _| panic!("ordinary root upgraded"),
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("ordinary root cannot acquire capture"));
    assert_eq!(store.pending_events(100).unwrap(), before);
    assert!(store
        .capture_snapshot(&root.identity().run)
        .unwrap()
        .is_none());
}
#[test]
fn captured_boundaries_allow_external_delay_without_carrying_sql_budget() {
    let mut h = Harness::new();
    h.launcher();
    let mut boundaries = 0;
    let report = h
        .observed(|b, r| {
            boundaries += 1;
            let sql =
                rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
            sql.busy_timeout(std::time::Duration::ZERO).unwrap();
            sql.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
            std::thread::sleep(std::time::Duration::from_millis(650));
            if b == Boundary::RootTerminal {
                h.empty(r)
            }
        })
        .unwrap();
    assert!(report.record.closed);
    assert_eq!(boundaries, 6);
}
#[test]
fn captured_release_keeps_original_lease_journal_and_finish_fences() {
    for damage in ["marker", "hold", "finish", "notready"] {
        let mut h = Harness::new();
        h.launcher();
        let result = h.observed(|b, r| {
            if b == Boundary::PermitAttempt {
                let sql = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite"))
                    .unwrap();
                match damage {
                    "marker" => {
                        let text: String = sql
                            .query_row("SELECT record FROM allocations", [], |r| r.get(0))
                            .unwrap();
                        let a: work_cli::allocate::Allocation =
                            serde_json::from_str(&text).unwrap();
                        fs::write(
                            a.identity.unwrap().private_git_dir.join("work-lease.json"),
                            b"damaged",
                        )
                        .unwrap();
                    }
                    "hold" => {
                        h.f.store().record_recovery_hold(&r.request).unwrap();
                    }
                    "finish" => {
                        sql.execute(
                            "INSERT INTO task_finishes VALUES(?1,?2,'{}')",
                            (h.command.checkout.to_string(), Uuid::now_v7().to_string()),
                        )
                        .unwrap();
                    }
                    "notready" => {
                        sql.execute("UPDATE checkouts SET ready=0", []).unwrap();
                    }
                    _ => unreachable!(),
                }
            }
        });
        assert!(result.is_err(), "{damage} bypassed final captured release");
        assert!(!h.f.temp.path().join("executed").exists());
        let sql = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
        assert_eq!(
            sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(h.f.store().charged(&h.f.repo, None).unwrap(), 1);
    }
}
#[test]
fn independent_checkouts_are_admitted_while_receiver_and_actor_are_delayed() {
    use std::time::{Duration, Instant};
    let mut h = Harness::new();
    h.launcher();
    let p = h.f.temp.path();
    let producer = fs::read_to_string(p.join("producer")).unwrap();
    file(&p.join("producer"),producer.replacen("r=json.load(sys.stdin)",&format!("r=json.load(sys.stdin)\nimport time\nopen({:?},'w').close()\nwhile not os.path.exists({:?}): time.sleep(0.005)",p.join("receiver-entered").to_str().unwrap(),p.join("receiver-proceed").to_str().unwrap()),1),0o700);
    let actor = fs::read_to_string(p.join("delegate")).unwrap();
    file(&p.join("delegate"),format!("{actor}\n/usr/bin/touch '{0}/actor-entered'\nwhile [ ! -e '{0}/actor-proceed' ]; do /usr/bin/sleep 0.005; done\n",p.display()),0o700);
    std::thread::scope(|scope| {
        let f = &h.f;
        let worker = scope.spawn(move || {
            for stage in ["receiver", "actor"] {
                let deadline = Instant::now() + Duration::from_secs(5);
                while !f.temp.path().join(format!("{stage}-entered")).exists() {
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(5));
                }
                let task = format!("{stage}-admission");
                let out = f.start(&Uuid::now_v7().to_string(), &task, &task, &[]);
                assert!(
                    out.status.success(),
                    "admission blocked during {stage}: {out:?}"
                );
                let a: work_cli::allocate::Allocation =
                    serde_json::from_slice(&out.stdout).unwrap();
                assert_eq!(a.stage, "capture_pending");
                fs::write(f.temp.path().join(format!("{stage}-proceed")), "").unwrap();
            }
        });
        let report = h
            .observed(|b, r| {
                if b == Boundary::RootTerminal {
                    h.empty(r)
                }
            })
            .unwrap();
        assert!(report.record.closed);
        worker.join().unwrap();
    });
    assert_eq!(h.f.store().charged(&h.f.repo, None).unwrap(), 3);
}
#[test]
fn captured_pending_or_unverified_child_prevents_writer_release_even_after_root_exit() {
    use work_cli::run_participants::{ChildOutcome, ChildRequest, ExpectedHost};
    for pending in [false, true] {
        let mut h = Harness::new();
        h.launcher();
        let report = h
            .observed(|b, r| {
                if b == Boundary::PermitAttempt {
                    let i = r.request.identity();
                    let child = ChildRequest {
                        checkout: i.checkout.clone(),
                        group: i.group.clone(),
                        run: work_contract::RunId::generate(),
                        run_ref: work_contract::RunRef::parse("fixture-child").unwrap(),
                        parent_run: i.run.clone(),
                        parent_run_ref: i.run_ref.clone(),
                        execution_chain: i.execution_chain.clone(),
                        source: None,
                        session: None,
                        agent: None,
                        actor: None,
                        expected_host: pending.then(|| ExpectedHost {
                            boot: r.request.input().boot.clone(),
                            pid: 43,
                            start_ticks: 20,
                        }),
                    };
                    let mut store = h.f.store();
                    store.register_child(&r.request, &child).unwrap();
                    store
                        .record_child_outcome(&r.request, &child, ChildOutcome::Completed)
                        .unwrap();
                }
                if b == Boundary::RootTerminal {
                    h.empty(r)
                }
            })
            .unwrap();
        assert_eq!(
            report.record.outcome,
            Some(work_cli::run_journal::RootOutcome::Completed)
        );
        assert!(!report.record.closed && report.record.recovery_hold && report.capture_unfrozen);
        assert!(h
            .f
            .store()
            .capture_snapshot(&report.record.request.identity().run)
            .unwrap()
            .unwrap()
            .group_end
            .is_none());
        let sql = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
        assert_eq!(
            sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
#[test]
fn receiver_failure_records_intent_writer_hold_without_starting_launcher() {
    let h = Harness::new();
    file(
        &h.f.temp.path().join("producer"),
        "#!/bin/sh\nexit 1\n",
        0o700,
    );
    // Deliberately nonexistent launcher/manager: preparation must precede them.
    assert!(h.execute().is_err());
    let store = h.f.store();
    let run = work_contract::RunId::parse(&h.command.run_id.to_string()).unwrap();
    let r = store
        .run_snapshot(&run)
        .unwrap()
        .expect("receiver failure must retain actual root intent");
    assert!(r.recovery_hold && r.outcome.is_none() && r.binding.is_none());
    assert_eq!(store.charged(&h.f.repo, None).unwrap(), 1);
    let sql = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
    assert_eq!(
        sql.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(!sql
        .query_row("SELECT ready FROM checkouts", [], |r| r.get::<_, bool>(0))
        .unwrap());
}
// Structural negative-fence fixture, never a successful prepare capability.
fn seed_prepared_fence(sql: &rusqlite::Connection, checkout: Uuid, cfg: &Config) {
    let operation = Uuid::now_v7();
    let hex = |tag: u8| format!("{tag:02x}").repeat(32);
    let record = serde_json::json!({
        "version":1, "operation":operation, "checkout":checkout, "mode":"supervised",
        "revision":1, "stage":"prepared", "assertion":null, "declaration":null,
        "predecessor_hex":hex(1), "source_hex":hex(2), "history_predecessor_hex":hex(3),
        "prior_history_count":0,
        "immutable_binding":{
            "version":1, "authority_allocation":hex(4), "source_sql":hex(2),
            "managed_physical":hex(6), "census":hex(7), "git_private":hex(8),
            "local_git":hex(9), "git_inputs":hex(10), "source_commitment":hex(11),
            "approval_semantic":hex(12), "approval_invalidation":hex(13),
            "protection":hex(14), "protection_count":0, "config_manifests":[hex(15),hex(16)],
            "inspection_policy":hex(17), "combined_policy":hex(18),
            "operator":hex(19), "source_repository":hex(20)
        },
        "quiescence":"empty", "task_completion":"supervised_empty", "policy_digest":hex(17),
        "combined_policy_digest":hex(18), "prepared_wall_ms":1, "remote_cleanup":"not_required"
    })
    .to_string();
    sql.execute(
        "INSERT INTO retirement_intents(operation,checkout,revision,stage,mode,assertion,declared_task,declared_operator,predecessor,source,record,held_reason,aborted_from) VALUES(?1,?2,1,'prepared','supervised',NULL,NULL,NULL,?3,?4,?5,NULL,NULL)",
        rusqlite::params![operation.to_string(),checkout.to_string(),[1u8;32].as_slice(),[2u8;32].as_slice(),record],
    ).unwrap();
    // Public passive status traverses the production strict read_history decoder.
    let config = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        config.path(),
        format!(
            "store_dir={:?}\ntrusted_registry={:?}\nroots={:?}\n",
            cfg.store_dir.as_ref().unwrap(),
            cfg.trusted_registry.as_ref().unwrap(),
            cfg.roots
        ),
    )
    .unwrap();
    let report = serde_json::to_value(work_cli::inspection::retirement_status(
        config.path(),
        checkout,
    ))
    .unwrap();
    assert_eq!(
        report["stage"], "prepared",
        "strict history did not decode: {report}"
    );
    assert_eq!(report["revision"], 1);
    assert_eq!(report["history_count"], 1);
    assert_eq!(report["fresh_commit"], false);
}
#[test]
fn prepared_intent_refuses_captured_supervise_without_receiver() {
    let h = Harness::new();
    let sql = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
    seed_prepared_fence(&sql, h.command.checkout, &h.cfg);
    assert!(h.execute().is_err());
    assert!(!h.f.temp.path().join("calls").exists());
    let (revision, stage, reason): (i64, String, Option<String>) = sql
        .query_row(
            "SELECT revision, stage, held_reason FROM retirement_intents WHERE checkout=?1",
            [h.command.checkout.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (revision, stage.as_str(), reason.as_deref()),
        (2, "held", Some("execution_permit"))
    );
    assert_eq!(h.f.store().pending_events(1000).unwrap().iter().filter(|e|
        matches!(&e.event, work_cli::events::Event::RetirementIntentChanged { stage, .. } if stage == "held")
    ).count(), 1);
}

#[test]
fn captured_entry_holds_before_bad_profile_or_spec() {
    for case in ["profile", "spec"] {
        let mut h = Harness::new();
        if case == "profile" {
            h.cfg.supervisor.as_mut().unwrap().actors.clear();
        } else {
            h.cfg.capture.as_mut().unwrap().actor_refs.clear();
        }
        let sql = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
        seed_prepared_fence(&sql, h.command.checkout, &h.cfg);
        assert!(h.execute().is_err(), "{case}");
        assert_eq!(
            sql.query_row(
                "SELECT revision,stage,held_reason FROM retirement_intents",
                [],
                |r| Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?
                ))
            )
            .unwrap(),
            (2, "held".into(), "execution_permit".into())
        );
        assert!(!h.f.temp.path().join("calls").exists());
        assert!(!h.f.temp.path().join("manager-started").exists());
        assert!(!h.f.temp.path().join("private/runs").exists());
        assert_eq!(
            sql.query_row("SELECT count(*) FROM runs", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}

#[test]
fn captured_intent_checkpoint_precedes_control_directory_and_launcher() {
    let h = Harness::new();
    let sql = rusqlite::Connection::open(h.f.temp.path().join("private/store.sqlite")).unwrap();
    let mut reached = false;
    let result = h.observed(|boundary, _| {
        if boundary == Boundary::Intent {
            reached = true;
            seed_prepared_fence(&sql, h.command.checkout, &h.cfg);
        }
    });
    assert!(reached, "capture never reached Intent");
    assert!(result.is_err());
    assert_eq!(
        sql.query_row(
            "SELECT revision,stage,held_reason FROM retirement_intents",
            [],
            |r| Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?
            ))
        )
        .unwrap(),
        (2, "held".into(), "execution_permit".into())
    );
    assert!(!h.f.temp.path().join("manager-started").exists());
    assert!(!h.f.temp.path().join("private/runs").exists());
    assert_eq!(
        sql.query_row(
            "SELECT count(*) FROM runs WHERE binding IS NOT NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(h.f.store().pending_events(1000).unwrap().iter().filter(|e|
        matches!(&e.event, work_cli::events::Event::RetirementIntentChanged { stage, .. } if stage == "held")
    ).count(), 1);
}
