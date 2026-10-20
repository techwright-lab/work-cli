use std::path::PathBuf;
use work_cli::capture_bridge::*;
use work_contract::{
    AllocationOperationId, ChainText, CheckoutId, ExecutionChain, ExecutionEntry, ExecutionMode,
    GroupId,
};

const CAPTURE: &str = "12345678-1234-4234-8234-123456789abc";
fn request() -> BeginRequest {
    BeginRequest {
        actor_ref: "urn:test:actor:a".into(),
        run_ref: "urn:test:run:r".into(),
        cwd: PathBuf::from("/checkout with ; literal"),
        execution_chain: ExecutionChain::new(vec![ExecutionEntry::Executor {
            system: ChainText::new("local".into()).unwrap(),
            session_ref: None,
        }])
        .unwrap(),
        task_refs: vec!["urn:test:task:t".into()],
        parent_run_ref: None,
        key_file: Some(PathBuf::from("/private/key ; literal")),
        source: None,
        lifecycle: WorkLifecycle {
            checkout_id: CheckoutId::generate(),
            mode: ExecutionMode::Supervised,
            group_id: Some(GroupId::generate()),
            operation_id: Some(AllocationOperationId::generate()),
        },
    }
}
fn open() -> String {
    format!(
        r#"{{"capture_id":"{CAPTURE}","actor_ref":"urn:test:actor:a","run_ref":"urn:test:run:r","state":"open","environment":{{"AGENT_ATTRIBUTION_CONTEXT":"/private/context","DEVDIARY_ATTRIBUTION_CONTEXT":"/private/context","DEVDIARY_CAPTURE_ID":"{CAPTURE}"}}}}"#
    )
}
fn binding() -> CaptureBinding {
    CaptureBinding::new(CAPTURE, "urn:test:actor:a", "urn:test:run:r").unwrap()
}
fn terminal(state: &str, extra: &str) -> String {
    format!(
        r#"{{"capture_id":"{CAPTURE}","actor_ref":"urn:test:actor:a","run_ref":"urn:test:run:r","state":"{state}"{extra}}}"#
    )
}
#[test]
fn valid_positional_response_objects_are_rejected_at_every_boundary() {
    use serde_json::json;
    let env = serde_json::from_str::<serde_json::Value>(&open()).unwrap()["environment"].clone();
    let mut nested_env: serde_json::Value = serde_json::from_str(&open()).unwrap();
    nested_env["environment"] = json!([
        "/private/context",
        "/private/context",
        CAPTURE,
        "Author",
        "author@example.test",
        "Committer",
        "committer@example.test"
    ]);
    let cases = [
        ("begin", json!([CAPTURE, "urn:test:actor:a", "urn:test:run:r", "open", env]).to_string(), true),
        ("environment", nested_env.to_string(), true),
        ("terminal", json!([CAPTURE, "urn:test:actor:a", "urn:test:run:r", "pending", "2026-10-18T09:00:00Z", "2026-10-18T10:00:00Z", {}, "2026-10-18T10:00:01Z", "delivery_failed", {"actor_ref":"urn:test:actor:a","run_ref":"urn:test:run:r","event_id":"event","session_id":1}]).to_string(), false),
        ("source", terminal("pending", r#", "source":["local","company","agent","run"]"#), false),
        ("receipt", terminal("delivered", r#", "receipt":["urn:test:actor:a","urn:test:run:r","event",1]"#), false),
    ];
    let mut accepted = Vec::new();
    for (name, frame, begin) in cases {
        let refused = if begin {
            decode_begin(
                frame.as_bytes(),
                &request(),
                &if name == "environment" {
                    expected_profile()
                } else {
                    GitProfile::default()
                },
            )
            .is_err()
        } else {
            decode_terminal(frame.as_bytes(), &binding()).is_err()
        };
        if !refused {
            accepted.push(name);
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted positional objects: {accepted:?}"
    );
}

fn expected_profile() -> GitProfile {
    GitProfile {
        author_name: Some("Author".into()),
        author_email: Some("author@example.test".into()),
        committer_name: Some("Committer".into()),
        committer_email: Some("committer@example.test".into()),
    }
}
fn profiled_open() -> serde_json::Value {
    let mut value: serde_json::Value = serde_json::from_str(&open()).unwrap();
    for (key, text) in [
        ("GIT_AUTHOR_NAME", "Author"),
        ("GIT_AUTHOR_EMAIL", "author@example.test"),
        ("GIT_COMMITTER_NAME", "Committer"),
        ("GIT_COMMITTER_EMAIL", "committer@example.test"),
    ] {
        value["environment"][key] = text.into();
    }
    value
}
#[test]
fn accepting_begin_requires_exact_trusted_git_values_and_presence() {
    let expected = expected_profile();
    let good = profiled_open();
    let mut accepted = Vec::new();
    for key in [
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
    ] {
        for absent in [false, true] {
            let mut value = good.clone();
            if absent {
                value["environment"].as_object_mut().unwrap().remove(key);
            } else {
                value["environment"][key] = "wrong-identity".into();
            }
            // Acceptance itself must enforce the trusted profile.
            if decode_begin(value.to_string().as_bytes(), &request(), &expected).is_ok() {
                accepted.push(format!("{key} absent={absent}"));
            }
        }
    }
    assert!(
        decode_begin(good.to_string().as_bytes(), &request(), &expected)
            .unwrap()
            .environment()
            .matches_git_profile(&expected)
    );
    // Explicit expected absence must reject unexpected presence too.
    if decode_begin(
        good.to_string().as_bytes(),
        &request(),
        &GitProfile::default(),
    )
    .is_ok()
    {
        accepted.push("expected absence".into());
    }
    assert!(
        accepted.is_empty(),
        "prepared mismatched profiles: {accepted:?}"
    );
}

#[test]
fn begin_encodes_only_declared_checkout_scope_and_literal_values() {
    let r = request();
    let wire = r.encode().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    assert_eq!(value["cwd"], "/checkout with ; literal");
    assert_eq!(value["key_file"], "/private/key ; literal");
    assert_eq!(value["git_scope"], "checkout");
    assert_eq!(value["lifecycle_context"]["work"]["schema_version"], 1);
    assert!(value["lifecycle_context"]["work"]["checkout_ref"]
        .as_str()
        .unwrap()
        .starts_with("urn:work:checkout:"));
    assert_eq!(value["lifecycle_context"]["work"]["mode"], "supervised");
    assert!(value.get("environment").is_none());
}
#[test]
fn begin_response_is_identity_bound_and_projection_is_redacted() {
    let prepared = decode_begin(open().as_bytes(), &request(), &GitProfile::default()).unwrap();
    assert_eq!(prepared.binding().capture_id().as_str(), CAPTURE);
    assert_eq!(
        prepared.environment().context_path(),
        std::path::Path::new("/private/context")
    );
    assert!(!format!("{prepared:?}").contains("/private/context"));
    assert!(prepared
        .environment()
        .matches_git_profile(&GitProfile::default()));
    assert!(!prepared.environment().matches_git_profile(&GitProfile {
        author_name: Some("a".into()),
        ..Default::default()
    }));
}
#[test]
fn begin_strict_rejection_matrix() {
    let good = open();
    let cases = [
        good.replace("urn:test:actor:a", "other"),
        good.replace("urn:test:run:r", "other"),
        good.replace(CAPTURE, "not-a-uuid"),
        good.replace("\"open\"", "\"pending\""),
        good.replace("/private/context", "relative"),
        good.replacen("/private/context", "/other", 1),
        good.replace("\"DEVDIARY_CAPTURE_ID\"", "\"SECRET_KEY\""),
        good.replace(
            "\"state\":\"open\"",
            "\"state\":\"open\",\"state\":\"open\"",
        ),
        good.replace(
            "\"state\":\"open\"",
            "\"unknown\":0,\"unknown\":1,\"state\":\"open\"",
        ),
        good.replace(
            "\"AGENT_ATTRIBUTION_CONTEXT\":",
            "\"AGENT_ATTRIBUTION_CONTEXT\":\"/private/context\",\"AGENT_ATTRIBUTION_CONTEXT\":",
        ),
        good.replace("/private/context", "/private/\\ncontext"),
        format!("{good}{{}}"),
        "[]".into(),
        good.replace(
            "\"environment\":{",
            "\"environment\":{\"GIT_AUTHOR_NAME\":true,",
        ),
        good.replace(
            "\"environment\":{",
            "\"environment\":{\"GIT_AUTHOR_NAME\":\"\",",
        ),
        good.replace(
            "\"environment\":{",
            "\"environment\":{\"UNEXPECTED_KEY\":\"secret-sentinel\",",
        ),
        good.replace(
            "\"environment\":{",
            "\"environment\":{\"UNEXPECTED_KEY\":0,\"UNEXPECTED_KEY\":1,",
        ),
        good.replace(
            &format!("\"DEVDIARY_CAPTURE_ID\":\"{CAPTURE}\""),
            "\"DEVDIARY_CAPTURE_ID\":\"22345678-1234-4234-8234-123456789abc\"",
        ),
        good.replace(&format!(",\"DEVDIARY_CAPTURE_ID\":\"{CAPTURE}\""), ""),
        good.replace("\"state\":\"open\"", "\"state\":null"),
        good.replace(
            "\"environment\":{",
            "\"environment\":{\"GIT_AUTHOR_EMAIL\":null,",
        ),
        good.replace("\"state\":\"open\"", "\"state\":\"open\\n\""),
    ];
    for (i, case) in cases.iter().enumerate() {
        assert!(
            decode_begin(case.as_bytes(), &request(), &GitProfile::default()).is_err(),
            "row {i}"
        );
    }
}
#[test]
fn request_validation_is_bounded_and_preserves_non_utf8_refusal() {
    for i in 0..6 {
        let mut r = request();
        match i {
            0 => r.actor_ref = "x".repeat(4097),
            1 => r.run_ref = "secret\n".into(),
            2 => r.cwd = "relative".into(),
            3 => r.task_refs = vec!["task".into(); 10001],
            4 => r.key_file = Some("relative".into()),
            _ => {
                r.task_refs = (0..1000)
                    .map(|i| format!("{i:04}{}", "x".repeat(4092)))
                    .collect()
            }
        }
        assert!(r.encode().is_err(), "row {i}");
    }
    use std::os::unix::ffi::OsStringExt;
    let mut r = request();
    r.cwd = std::ffi::OsString::from_vec(vec![b'/', 0xff]).into();
    assert!(r.encode().is_err());
}
#[test]
fn terminal_pending_and_valid_delivered_are_distinct_observations() {
    let pending = decode_terminal(
        terminal("pending", ",\"error_code\":\"delivery_failed\"").as_bytes(),
        &binding(),
    )
    .unwrap();
    assert_eq!(pending.delivery(), DeliveryObservation::Pending);
    let receipt = r#", "receipt":{"actor_ref":"urn:test:actor:a","run_ref":"urn:test:run:r","event_id":"event-1","session_id":1}"#;
    let delivered = decode_terminal(terminal("delivered", receipt).as_bytes(), &binding()).unwrap();
    assert_eq!(delivered.delivery(), DeliveryObservation::Delivered);
}
#[test]
fn terminal_receipt_and_nested_shapes_are_strict() {
    let receipt = r#", "receipt":{"actor_ref":"urn:test:actor:a","run_ref":"urn:test:run:r","event_id":"event-1","session_id":1}"#;
    let good = terminal("delivered", receipt);
    let cases = [
        terminal("delivered", ""),
        terminal("open", ""),
        good.replace("\"session_id\":1", "\"session_id\":true"),
        good.replace("\"session_id\":1", "\"session_id\":0"),
        good.replace("\"session_id\":1", "\"session_id\":1.5"),
        good.replace("\"session_id\":1", "\"session_id\":-1"),
        good.replace(
            "\"session_id\":1",
            "\"session_id\":1,\"unknown\":{\"nested\":1,\"nested\":2}",
        ),
        good.replace(
            "\"run_ref\":\"urn:test:run:r\",\"event_id\"",
            "\"run_ref\":\"other\",\"event_id\"",
        ),
        good.replace("\"event-1\"", "\" \""),
        good.replacen("\"urn:test:run:r\"", "\"other\"", 1),
        good.replace("\"session_id\":1", "\"session_id\":1,\"session_id\":1"),
        good.replace(
            "\"session_id\":1",
            "\"session_id\":1,\"url\":\"https://secret\"",
        ),
        terminal("pending", r#", "source":{"system":"x","system":"x"}"#),
        terminal("pending", r#", "source":{"secret":"x"}"#),
        terminal("pending", r#", "source":{"system":true}"#),
        terminal("pending", r#", "receipt":{}"#),
        terminal("pending", r#", "unknown":[{"nested":0,"nested":1}]"#),
        format!("{} trailing-secret", terminal("pending", "")),
        terminal("pending", r#", "source":{"system":"secret\n"}"#),
        terminal("pending", r#", "ended_at":"yesterday""#),
        terminal("pending", r#", "error_code":"secret\n""#),
    ];
    for (i, case) in cases.iter().enumerate() {
        assert!(
            decode_terminal(case.as_bytes(), &binding()).is_err(),
            "row {i}"
        );
    }
}
#[test]
fn finish_requires_authoritative_typed_time_and_exact_outcome() {
    assert!(EndedAt::parse("2026-10-18T10:00:00Z").is_ok());
    for bad in ["yesterday", "2026-10-18T10:00:00", "2026-02-30T10:00:00Z"] {
        assert!(EndedAt::parse(bad).is_err());
    }
    for outcome in ["held", "expired", "unknown"] {
        assert!(CaptureOutcome::parse(outcome).is_err());
    }
    let r = FinishRequest {
        capture_id: binding().capture_id().clone(),
        outcome: CaptureOutcome::Completed,
        ended_at: EndedAt::parse("2026-10-18T10:00:00Z").unwrap(),
    };
    let value: serde_json::Value = serde_json::from_slice(&r.encode().unwrap()).unwrap();
    assert_eq!(value["outcome"], "completed");
    assert_eq!(value["ended_at"], "2026-10-18T10:00:00Z");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &RetryRequest {
                capture_id: r.capture_id
            }
            .encode()
            .unwrap()
        )
        .unwrap()["capture_id"],
        CAPTURE
    );
}
