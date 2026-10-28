use super::*;
use std::cell::RefCell;
type Observer = Box<dyn FnMut(&Path, &File, &str)>;
thread_local! {static OBSERVER: RefCell<Option<Observer>> = RefCell::new(None);}
pub(super) fn observe_read(path: &Path, file: &File, at: &str) {
    OBSERVER.with(|slot| {
        if let Some(f) = slot.borrow_mut().as_mut() {
            f(path, file, at);
        }
    });
}
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        OBSERVER.with(|slot| *slot.borrow_mut() = None);
    }
}
fn observing(f: impl FnMut(&Path, &File, &str) + 'static) -> Guard {
    OBSERVER.with(|slot| *slot.borrow_mut() = Some(Box::new(f)));
    Guard
}
#[test]
fn real_descriptor_reads_reject_growth_same_length_churn_and_path_replacement() {
    for case in ["growth", "churn", "after_eof", "replacement"] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("artifact");
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let _guard = observing(move |path, _file, at| {
            let target = match case {
                "after_eof" => "after_read",
                "replacement" => "before_path",
                _ => "before_read",
            };
            if at != target {
                return;
            }
            if case == "replacement" {
                let bytes = fs::read(path).unwrap();
                fs::remove_file(path).unwrap();
                fs::write(path, bytes).unwrap();
            } else {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
                fs::write(
                    path,
                    if case == "churn" {
                        b"[]".to_vec()
                    } else {
                        vec![b' '; MAX_WIRE_BYTES + 1]
                    },
                )
                .unwrap();
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
        });
        assert!(
            Artifact::read(&path, true).is_err(),
            "descriptor mutation accepted: {case}"
        );
    }
}
#[test]
fn regular_metadata_rejects_foreign_uid_even_with_otherwise_safe_shape() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("file");
    fs::write(&path, b"metadata").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let mut s = stamp(&open(&path, OFlags::PATH).unwrap()).unwrap();
    assert!(regular(&s, true).is_ok());
    s.uid = s.uid.wrapping_add(1);
    assert!(regular(&s, true).is_err());
    assert!(regular(&s, false).is_err());
}

use crate::{
    capture_bridge::{self, BeginRequest, GitProfile, WorkLifecycle},
    capture_journal::{CaptureSpec, SinkSettings, SinkSnapshot},
};
use std::{fs, os::unix::fs::PermissionsExt, time::Duration};
use work_contract::{CheckoutId, ExecutionMode, GroupId};
fn fixture() -> (tempfile::TempDir, CaptureSpec, Prepared) {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let request = BeginRequest {
        actor_ref: "actor:test".into(),
        run_ref: "run:test".into(),
        cwd: temp.path().into(),
        execution_chain: serde_json::from_value(
            serde_json::json!([{"kind":"executor","system":"test"}]),
        )
        .unwrap(),
        task_refs: vec!["task".into()],
        parent_run_ref: None,
        key_file: None,
        source: None,
        lifecycle: WorkLifecycle {
            checkout_id: CheckoutId::generate(),
            group_id: Some(GroupId::generate()),
            operation_id: None,
            mode: ExecutionMode::Supervised,
        },
    };
    let sink = SinkSnapshot::new(SinkSettings {
        executable: "/private/producer".into(),
        registry: "/private/registry".into(),
        state: temp.path().into(),
        timeout: Duration::from_millis(50),
        response_cap: 4096,
        endpoint_identity: "label".into(),
        registry_identity: format!("sha256:{}", "a".repeat(64)),
        receiver_credential_names: vec!["TOKEN".into()],
        registry_actor_ref: "actor:test".into(),
    })
    .unwrap();
    let spec =
        CaptureSpec::new(uuid::Uuid::now_v7(), sink, request, GitProfile::default()).unwrap();
    let capture = "550e8400-e29b-41d4-a716-446655440001";
    let path = temp.path().join(format!("{capture}.context.json"));
    let r = spec.begin_request();
    fs::write(&path,serde_json::to_vec(&serde_json::json!({"schema_version":"1.0","actor":{"ref":r.actor_ref},"run":{"ref":r.run_ref,"task_ref":"task"},"execution_chain":r.execution_chain,"working_directory":r.cwd,"started_at":"2026-10-18T00:00:00Z"})).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let prepared=capture_bridge::decode_begin(&serde_json::to_vec(&serde_json::json!({"capture_id":capture,"state":"open","actor_ref":r.actor_ref,"run_ref":r.run_ref,"environment":{"AGENT_ATTRIBUTION_CONTEXT":path,"DEVDIARY_ATTRIBUTION_CONTEXT":path,"DEVDIARY_CAPTURE_ID":capture}})).unwrap(),&spec.begin_request(),&GitProfile::default()).unwrap();
    (temp, spec, prepared)
}
#[test]
fn cached_artifact_observation_is_bound_to_exact_spec_not_only_context_locator() {
    let (temp, spec, prepared) = fixture();
    let proof =
        Context::qualify(Directory::qualify(temp.path()).unwrap(), &prepared, &spec).unwrap();
    let substituted = CaptureSpec::new(
        uuid::Uuid::now_v7(),
        spec.sink().clone(),
        spec.begin_request(),
        spec.expected_git(),
    )
    .unwrap();
    assert!(proof
        .observation(prepared.environment().context_path(), &spec)
        .is_ok());
    assert!(
        proof
            .observation(prepared.environment().context_path(), &substituted)
            .is_err(),
        "another capture spec reused the artifact proof"
    );
}
