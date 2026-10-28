use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    time::{Duration, Instant},
};
use work_cli::{
    capture_bridge::*,
    sinks::{ProcessSink, ProcessSinkSettings},
};
use work_contract::{ChainText, CheckoutId, ExecutionChain, ExecutionEntry, ExecutionMode};
const CAPTURE: &str = "12345678-1234-4234-8234-123456789abc";
struct Fake {
    temp: tempfile::TempDir,
    executable: PathBuf,
}
impl Fake {
    fn new(body: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("fake capture ; executable");
        let this = Self { temp, executable };
        this.body(body);
        this
    }
    fn body(&self, body: &str) {
        fs::write(
            &self.executable,
            format!(
                "#!/bin/sh\ncd '{}' || exit 90\n{body}\n",
                self.temp.path().display()
            ),
        )
        .unwrap();
        fs::set_permissions(&self.executable, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn sink(&self, timeout: Duration, cap: usize) -> ProcessSink {
        ProcessSink::new(
            ProcessSinkSettings::new(
                self.executable.clone(),
                self.temp.path().join("registry ; literal"),
                self.temp.path().join("state ; literal"),
                timeout,
                cap,
            )
            .unwrap(),
        )
    }
    fn respond(&self, response: &str) {
        fs::write(self.temp.path().join("response"), response).unwrap();
    }
}
fn request() -> BeginRequest {
    BeginRequest {
        actor_ref: "actor ; literal".into(),
        run_ref: "run ; literal".into(),
        cwd: "/checkout ; literal".into(),
        execution_chain: ExecutionChain::new(vec![ExecutionEntry::Executor {
            system: ChainText::new("local".into()).unwrap(),
            session_ref: None,
        }])
        .unwrap(),
        task_refs: vec![],
        parent_run_ref: None,
        key_file: Some("/private/locator ; literal".into()),
        source: None,
        lifecycle: WorkLifecycle {
            checkout_id: CheckoutId::generate(),
            mode: ExecutionMode::Supervised,
            group_id: None,
            operation_id: None,
        },
    }
}
fn open() -> String {
    format!(
        r#"{{"capture_id":"{CAPTURE}","actor_ref":"actor ; literal","run_ref":"run ; literal","state":"open","environment":{{"AGENT_ATTRIBUTION_CONTEXT":"/private/context","DEVDIARY_ATTRIBUTION_CONTEXT":"/private/context","DEVDIARY_CAPTURE_ID":"{CAPTURE}"}}}}"#
    )
}
fn pending() -> String {
    format!(
        r#"{{"capture_id":"{CAPTURE}","actor_ref":"actor ; literal","run_ref":"run ; literal","state":"pending","error_code":"delivery_failed"}}"#
    )
}
const RECORDER: &str = "printf '%s\\n' \"$@\" > args; /usr/bin/cat > input; /usr/bin/cat response";
#[test]
fn literal_executable_argv_and_exact_stdin_json_reach_eof() {
    let fake = Fake::new(RECORDER);
    fake.respond(&open());
    let sink = fake.sink(Duration::from_secs(2), 4096);
    let r = request();
    let prepared = sink.begin(&r, &GitProfile::default()).unwrap();
    assert_eq!(
        fs::read(fake.temp.path().join("input")).unwrap(),
        r.encode().unwrap()
    );
    let args = fs::read_to_string(fake.temp.path().join("args")).unwrap();
    assert_eq!(
        args,
        format!(
            "--config\n{}\ncapture\nbegin\n--state-dir\n{}\n--json\n",
            fake.temp.path().join("registry ; literal").display(),
            fake.temp.path().join("state ; literal").display()
        )
    );
    assert!(!args.contains("locator"));
    assert!(!args.contains("actor"));
    fake.respond(&pending());
    let finish = FinishRequest {
        capture_id: prepared.binding().capture_id().clone(),
        outcome: CaptureOutcome::Failed,
        ended_at: EndedAt::parse("2026-10-18T10:00:00Z").unwrap(),
    };
    assert_eq!(
        sink.finish(prepared.binding(), &finish).unwrap().delivery(),
        DeliveryObservation::Pending
    );
    assert_eq!(
        fs::read(fake.temp.path().join("input")).unwrap(),
        finish.encode().unwrap()
    );
    assert!(fs::read_to_string(fake.temp.path().join("args"))
        .unwrap()
        .contains("\nfinish\n"));
    assert_eq!(
        sink.retry(prepared.binding()).unwrap().delivery(),
        DeliveryObservation::Pending
    );
    assert!(fs::read_to_string(fake.temp.path().join("args"))
        .unwrap()
        .contains("\nretry\n"));
}
#[test]
fn process_begin_refuses_git_identity_substitutions_before_prepared() {
    let fake = Fake::new(RECORDER);
    let sink = fake.sink(Duration::from_secs(2), 4096);
    let mut good: serde_json::Value = serde_json::from_str(&open()).unwrap();
    let fields = [
        ("GIT_AUTHOR_NAME", "Author"),
        ("GIT_AUTHOR_EMAIL", "author@example.test"),
        ("GIT_COMMITTER_NAME", "Committer"),
        ("GIT_COMMITTER_EMAIL", "committer@example.test"),
    ];
    let expected = GitProfile {
        author_name: Some("Author".into()),
        author_email: Some("author@example.test".into()),
        committer_name: Some("Committer".into()),
        committer_email: Some("committer@example.test".into()),
    };
    for (key, value) in fields {
        good["environment"][key] = value.into();
    }
    fake.respond(&good.to_string());
    assert!(sink
        .begin(&request(), &expected)
        .unwrap()
        .environment()
        .matches_git_profile(&expected));
    let mut accepted = Vec::new();
    for (key, _) in fields {
        for absent in [false, true] {
            let mut value = good.clone();
            if absent {
                value["environment"].as_object_mut().unwrap().remove(key);
            } else {
                value["environment"][key] = "wrong-identity".into();
            }
            fake.respond(&value.to_string());
            if sink.begin(&request(), &expected).is_ok() {
                accepted.push(format!("{key} absent={absent}"));
            }
        }
    }
    fake.respond(&good.to_string());
    if sink.begin(&request(), &GitProfile::default()).is_ok() {
        accepted.push("expected absence".into());
    }
    assert!(
        accepted.is_empty(),
        "prepared mismatched process profiles: {accepted:?}"
    );
}

#[test]
fn invalid_trusted_git_scalars_refuse_before_process_spawn() {
    let fake = Fake::new("touch called; /usr/bin/cat > input; /usr/bin/cat response");
    fake.respond(&open());
    let sink = fake.sink(Duration::from_secs(2), 4096);
    let mut spawned = Vec::new();
    for field in 0..4 {
        for (kind, invalid) in [
            ("blank", " ".into()),
            ("control", "secret\n".into()),
            ("overbound", "x".repeat(4097)),
        ] {
            let mut expected = GitProfile::default();
            let fields = [
                &mut expected.author_name,
                &mut expected.author_email,
                &mut expected.committer_name,
                &mut expected.committer_email,
            ];
            *fields.into_iter().nth(field).unwrap() = Some(invalid);
            assert!(decode_begin(open().as_bytes(), &request(), &expected).is_err());
            assert!(sink.begin(&request(), &expected).is_err());
            let marker = fake.temp.path().join("called");
            if marker.exists() {
                spawned.push(format!("field={field} {kind}"));
                fs::remove_file(marker).unwrap();
            }
        }
    }
    assert!(
        spawned.is_empty(),
        "invalid expected profiles spawned: {spawned:?}"
    );
}

#[test]
fn settings_reject_relative_paths_and_out_of_budget_limits() {
    for (exe, registry, state, timeout, cap) in [
        ("relative", "/r", "/s", Duration::from_secs(1), 1),
        ("/e", "relative", "/s", Duration::from_secs(1), 1),
        ("/e", "/r", "relative", Duration::from_secs(1), 1),
        ("/e", "/r", "/s", Duration::ZERO, 1),
        ("/e", "/r", "/s", Duration::from_millis(30001), 1),
        ("/e", "/r", "/s", Duration::from_secs(1), 0),
        ("/e", "/r", "/s", Duration::from_secs(1), MAX_WIRE_BYTES + 1),
    ] {
        assert!(
            ProcessSinkSettings::new(exe.into(), registry.into(), state.into(), timeout, cap)
                .is_err()
        );
    }
}
#[test]
fn malformed_nonzero_oversized_timeout_missing_are_sanitized_refusals() {
    for body in [
        "printf secret-sentinel >&2; printf not-json",
        "printf secret-sentinel >&2; /usr/bin/cat response; exit 2",
        "head -c 8192 /dev/zero",
        "head -c 8192 /dev/zero >&2",
        "printf secret-sentinel >&2; exec sleep 30",
        "/usr/bin/cat response; printf secret-sentinel",
    ] {
        let fake = Fake::new(body);
        fake.respond(&open());
        let sink = fake.sink(Duration::from_millis(100), 4096);
        let now = Instant::now();
        let error = sink.begin(&request(), &GitProfile::default()).unwrap_err();
        assert!(now.elapsed() < Duration::from_secs(2));
        assert_eq!(error.to_string(), "capture transport refused");
        assert!(!format!("{error:?} {sink:?}").contains("secret-sentinel"));
    }
    let fake = Fake::new(RECORDER);
    fs::remove_file(&fake.executable).unwrap();
    assert!(fake
        .sink(Duration::from_secs(1), 4096)
        .begin(&request(), &GitProfile::default())
        .is_err());
}
#[test]
fn invalid_request_and_conflicting_capture_never_spawn() {
    let fake = Fake::new("touch called");
    let sink = fake.sink(Duration::from_secs(1), 4096);
    let mut r = request();
    r.actor_ref = "secret\n".into();
    assert!(sink.begin(&r, &GitProfile::default()).is_err());
    assert!(!fake.temp.path().join("called").exists());
    let binding = CaptureBinding::new(CAPTURE, "actor ; literal", "run ; literal").unwrap();
    let finish = FinishRequest {
        capture_id: CaptureId::parse("22345678-1234-4234-8234-123456789abc").unwrap(),
        outcome: CaptureOutcome::Cancelled,
        ended_at: EndedAt::parse("2026-10-18T10:00:00Z").unwrap(),
    };
    assert!(sink.finish(&binding, &finish).is_err());
    assert!(!fake.temp.path().join("called").exists());
}
