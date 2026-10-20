//! Trusted preparation only; never launches an actor.
use crate::{
    capture_bridge::{EnvironmentProjection, Prepared},
    capture_journal::{CaptureRecord, CaptureSpec},
    config::Config,
    run_journal::RootRunRequest,
    store::Store,
};

#[cfg(test)]
#[path = "capture_preparation_tests.rs"]
mod tests;

pub enum PreparationResult {
    Existing(CaptureRecord),
    Live(LiveCapture),
}
/// Created-only ephemeral metadata, not a kernel binding or launch permit.
/// Rows, decoded responses and historical receipts cannot reconstruct this value.
/// ```compile_fail
/// fn duplicate(live: work_cli::capture_preparation::LiveCapture) {
///     let _ = live.clone();
/// }
/// ```
/// ```compile_fail
/// fn persist(live: &work_cli::capture_preparation::LiveCapture) {
///     let _ = serde_json::to_string(live);
/// }
/// ```
/// ```compile_fail
/// let _: work_cli::capture_preparation::LiveCapture = serde_json::from_str("{}").unwrap();
/// ```
pub struct LiveCapture {
    prepared: Prepared,
    removal_names: Vec<String>,
    context: crate::capture_artifacts::Context,
}
impl LiveCapture {
    pub fn environment(&self) -> &EnvironmentProjection {
        self.prepared.environment()
    }
    pub fn receiver_removal_names(&self) -> &[String] {
        &self.removal_names
    }
    /// Actual descriptor/path/hash reobservation; call outside SQL before any future execution.
    pub fn revalidate_context(&self) -> Result<(), crate::capture_bridge::Refused> {
        self.context.revalidate()
    }
}
impl std::fmt::Debug for LiveCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LiveCapture([REDACTED])")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boundary {
    RegistryRead,
    Receiver,
    RegistryRecheck,
    ContextRead,
    BeforeCommit,
}
/// Physically qualify and prepare a new captured root, outside SQL/flock.
/// Exact Existing returns metadata without consulting current profiles/artifacts.
/// Errors contain constant failure classes only; a post-intent failure records a
/// recovery hold, or explicitly reports that persistence of that hold is uncertain.
/// Neither success nor a ready flag authorizes actor execution.
pub fn prepare(
    config: &Config,
    root: &RootRunRequest,
    spec: &CaptureSpec,
) -> std::io::Result<(Store, PreparationResult)> {
    prepare_observed(config, root, spec, |_, _| {})
}
/// Trusted boundary observation only; cannot replace physical/process operations.
/// Observer callbacks run without SQL phases/transactions or the allocator flock.
pub fn prepare_observed(
    config: &Config,
    root: &RootRunRequest,
    spec: &CaptureSpec,
    mut observer: impl FnMut(Boundary, &Store),
) -> std::io::Result<(Store, PreparationResult)> {
    let (mut store, result) = crate::capture_setup::begin(config, root, spec)
        .map_err(|_| std::io::Error::other("capture setup refused"))?;
    let crate::capture_journal::BeginCapturedRun::Created(handle) = result else {
        let crate::capture_journal::BeginCapturedRun::Existing(record) = result else {
            unreachable!()
        };
        return Ok((store, PreparationResult::Existing(record)));
    };
    let attempt = (|| {
        use crate::capture_artifacts::{
            credential_name, key_metadata, Context, Directory, Registry,
        };
        let host = config.capture.as_ref().ok_or("configuration")?;
        observer(Boundary::RegistryRead, &store);
        let registry =
            Registry::qualify(&host.registry, &host.registry_sha256).map_err(|_| "registry")?;
        let directory = Directory::qualify(&host.state_dir).map_err(|_| "state directory")?;
        let mut removal_names = host.receiver_credential_names.clone();
        for name in &removal_names {
            credential_name(name).map_err(|_| "credential name")?;
        }
        if let Some(path) = &host.key_file {
            key_metadata(path).map_err(|_| "credential locator")?;
        } else if !removal_names.contains(&registry.key_env) {
            return Err("credential coverage");
        }
        if !removal_names.contains(&registry.key_env) {
            removal_names.push(registry.key_env.clone());
        }
        let settings = spec
            .sink()
            .process_settings()
            .map_err(|_| "process settings")?;
        let request = spec.begin_request();
        observer(Boundary::Receiver, &store);
        let prepared = crate::sinks::ProcessSink::new(settings)
            .begin(&request, &spec.expected_git())
            .map_err(|_| "receiver")?;
        observer(Boundary::RegistryRecheck, &store);
        registry.revalidate().map_err(|_| "changed registry")?;
        observer(Boundary::ContextRead, &store);
        let context = Context::qualify(directory, &prepared, spec).map_err(|_| "context")?;
        observer(Boundary::BeforeCommit, &store);
        registry.revalidate().map_err(|_| "changed registry")?;
        context.revalidate().map_err(|_| "changed context")?;
        store
            .record_qualified_capture_prepared(handle, &prepared, &context)
            .map_err(|_| "prepared commit")?;
        Ok::<_, &'static str>(LiveCapture {
            prepared,
            removal_names,
            context,
        })
    })();
    match attempt {
        Ok(live) => Ok((store, PreparationResult::Live(live))),
        Err(class) => {
            let held = store.record_recovery_hold(root).is_ok();
            Err(std::io::Error::other(format!(
                "capture preparation refused ({class}); recovery hold {}",
                if held { "recorded" } else { "uncertain" }
            )))
        }
    }
}
