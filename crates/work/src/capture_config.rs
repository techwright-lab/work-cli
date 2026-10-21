//! Host declarations only. Registry pins are not verification of registry bytes.
use crate::{
    capture_journal::{SinkSettings, SinkSnapshot},
    error::Error,
};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCaptureConfig {
    pub executable: PathBuf,
    pub registry: PathBuf,
    pub state_dir: PathBuf,
    pub timeout_ms: u64,
    pub response_cap: usize,
    pub registry_sha256: String,
    pub endpoint_identity: String,
    pub key_file: Option<PathBuf>,
    pub receiver_credential_names: Vec<String>,
    pub actor_refs: BTreeMap<String, String>,
}
fn invalid() -> Error {
    Error::Config("invalid capture policy".into())
}
fn locator(p: &std::path::Path) -> bool {
    p.is_absolute()
        && p.to_str().is_some_and(|s| {
            !s.trim().is_empty() && s.chars().count() <= 4096 && !s.chars().any(char::is_control)
        })
        && !p.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}
impl HostCaptureConfig {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if ![&self.executable, &self.registry, &self.state_dir]
            .into_iter()
            .all(|p| locator(p))
            || self.key_file.as_ref().is_some_and(|p| !locator(p))
            || (self.key_file.is_none() && self.receiver_credential_names.is_empty())
            || self.registry_sha256.len() != 64
            || !self
                .registry_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.actor_refs.is_empty()
            || self.actor_refs.len() > 128
            || self.actor_refs.iter().any(|(label, value)| {
                label.is_empty()
                    || label.len() > 128
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                    || value.trim().is_empty()
                    || value.chars().count() > 4096
                    || value.chars().any(char::is_control)
            })
            || self.receiver_credential_names.iter().any(|name| {
                matches!(
                    name.as_str(),
                    "AGENT_ATTRIBUTION_CONTEXT"
                        | "DEVDIARY_ATTRIBUTION_CONTEXT"
                        | "DEVDIARY_CAPTURE_ID"
                        | "GIT_AUTHOR_NAME"
                        | "GIT_AUTHOR_EMAIL"
                        | "GIT_COMMITTER_NAME"
                        | "GIT_COMMITTER_EMAIL"
                        | "XDG_RUNTIME_DIR"
                        | "DBUS_SESSION_BUS_ADDRESS"
                )
            })
        {
            return Err(invalid());
        }
        // Reuse the existing snapshot domain, including name/count, scalar and byte limits.
        for actor in self.actor_refs.keys() {
            self.sink(actor)?;
        }
        Ok(())
    }
    pub(crate) fn sink(&self, actor: &str) -> Result<SinkSnapshot, Error> {
        let registry_actor_ref = self.actor_refs.get(actor).ok_or_else(invalid)?.clone();
        SinkSnapshot::new(SinkSettings {
            executable: self.executable.clone(),
            registry: self.registry.clone(),
            state: self.state_dir.clone(),
            timeout: Duration::from_millis(self.timeout_ms),
            response_cap: self.response_cap,
            endpoint_identity: self.endpoint_identity.clone(),
            registry_identity: format!("sha256:{}", self.registry_sha256),
            receiver_credential_names: self.receiver_credential_names.clone(),
            registry_actor_ref,
        })
        .map_err(|_| invalid())
    }
}
impl crate::config::Config {
    /// Construct a selected root snapshot from host declarations, without inspecting
    /// registry/key bytes or runtime services. The pin remains declared metadata.
    pub fn capture_spec(
        &self,
        root: &crate::run_journal::RootRunRequest,
        allocation: &crate::allocate::Allocation,
        operation: uuid::Uuid,
        task_refs: Vec<String>,
        source: Option<crate::capture_bridge::Source>,
    ) -> crate::store::Result<crate::capture_journal::CaptureSpec> {
        use crate::{
            capture_bridge::{BeginRequest, WorkLifecycle},
            store::StoreError,
        };
        if root.input().attribution.is_some() {
            return Err(StoreError::Invalid);
        }
        let host = self
            .selected_capture()
            .map_err(|_| StoreError::Invalid)?
            .ok_or(StoreError::Invalid)?;
        let i = root.identity();
        if i.checkout.to_string() != allocation.checkout.to_string()
            || task_refs.first() != Some(&allocation.request.task)
        {
            return Err(StoreError::Conflict);
        }
        let actor = i.actor.as_str();
        let git = self
            .supervisor
            .as_ref()
            .and_then(|s| s.actors.get(actor))
            .ok_or(StoreError::Invalid)?
            .capture_profile();
        crate::capture_journal::CaptureSpec::new(
            operation,
            host.sink(actor).map_err(|_| StoreError::Invalid)?,
            BeginRequest {
                actor_ref: host
                    .actor_refs
                    .get(actor)
                    .ok_or(StoreError::Invalid)?
                    .clone(),
                run_ref: i.run_ref.as_str().into(),
                cwd: allocation.destination.clone(),
                execution_chain: i.execution_chain.clone(),
                task_refs,
                parent_run_ref: i.parent_run_ref.as_ref().map(|p| p.as_str().into()),
                key_file: host.key_file.clone(),
                source,
                lifecycle: WorkLifecycle {
                    checkout_id: i.checkout.clone(),
                    mode: work_contract::ExecutionMode::Supervised,
                    group_id: Some(i.group.clone()),
                    operation_id: Some(
                        work_contract::AllocationOperationId::parse(&operation.to_string())
                            .map_err(|_| StoreError::Invalid)?,
                    ),
                },
            },
            git,
        )
    }
    /// Explicit opt-in only; a definition alone never enables capture. No filesystem or process I/O.
    pub(crate) fn selected_capture(&self) -> Result<Option<&HostCaptureConfig>, Error> {
        match self
            .allocation
            .as_ref()
            .and_then(|p| p.capture_sink.as_deref())
        {
            None => Ok(None),
            Some("devdiary") => {
                let host = self.capture.as_ref().ok_or_else(invalid)?;
                host.validate()?;
                Ok(Some(host))
            }
            _ => Err(invalid()),
        }
    }
}
