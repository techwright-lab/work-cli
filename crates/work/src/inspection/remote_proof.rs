//! Configured, non-destructive remote observation. No retirement capability.
//! Native Git pathname opens have Task9's cooperative race boundary, not hostile
//! same-UID containment. Two advertisements cannot detect an away-and-back move.
use super::*;
use crate::config::{Config, ConfigDocument, RemoteTarget};
use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags, ResolveFlags};
use std::{
    ffi::CString, mem::MaybeUninit, os::fd::OwnedFd, os::unix::ffi::OsStrExt, process::Command,
};

type Held<T> = Result<T, &'static str>;
const PROCESS_OUTPUT: usize = 1024 * 1024;

/// Historical, nondurable metadata only. No Deserialize, freshness constructor,
/// action-time check, recovery-ref assertion or retirement permission exists.
#[derive(Debug, serde::Serialize)]
pub struct RemoteReport {
    checkout: Uuid,
    observation_id: Uuid,
    outcome: &'static str,
    reason: &'static str,
    transport: Option<&'static str>,
    branch: Option<String>,
    policy_digest: Option<String>,
    endpoint_digest: Option<String>,
    context_digest: Option<String>,
    evidence_digest: Option<String>,
    local_oid: Option<String>,
    initial_remote_oid: Option<String>,
    fetched_remote_oid: Option<String>,
    fetched_local_oid: Option<String>,
    final_remote_oid: Option<String>,
    git_version: Option<String>,
    started_ms: u64,
    ended_ms: u64,
    cleanup: &'static str,
    recorded: bool,
    retirement_authority: bool,
}
impl RemoteReport {
    pub fn observed(&self) -> bool {
        self.outcome == "observed" && self.cleanup == "complete"
    }
    pub fn reason(&self) -> &str {
        self.reason
    }
    pub fn cleanup(&self) -> &str {
        self.cleanup
    }
    pub fn transport(&self) -> Option<&str> {
        self.transport
    }
    pub fn checkout(&self) -> Uuid {
        self.checkout
    }
    pub fn local_oid(&self) -> Option<&str> {
        self.local_oid.as_deref()
    }
    fn held(checkout: Uuid) -> Self {
        Self {
            checkout,
            observation_id: Uuid::now_v7(),
            outcome: "held",
            reason: "configuration_unknown",
            transport: None,
            branch: None,
            policy_digest: None,
            endpoint_digest: None,
            context_digest: None,
            evidence_digest: None,
            local_oid: None,
            initial_remote_oid: None,
            fetched_remote_oid: None,
            fetched_local_oid: None,
            final_remote_oid: None,
            git_version: None,
            started_ms: 0,
            ended_ms: 0,
            cleanup: "not_created",
            recorded: false,
            retirement_authority: false,
        }
    }
}

/// Observe the actual existing authority and configured target for this checkout.
/// No caller-supplied URL, ref, advertisement, receipt or context can enter here.
pub fn verify_remote(checkout: Uuid) -> RemoteReport {
    match Config::discover_path() {
        Some(path) => verify_path(
            &path,
            checkout,
            #[cfg(test)]
            None,
        ),
        None => RemoteReport::held(checkout),
    }
}
fn input<T>(result: Result<T, IncompleteReason>) -> Held<T> {
    result.map_err(|_| "local_inputs_unknown")
}
fn load_document(path: &Path, b: &mut Budget) -> Held<(ConfigDocument, filesystem::Manifest)> {
    input(native_anchor_path(path))?;
    let mut manifest = input(filesystem::Manifest::new(
        path.parent().ok_or("configuration_unknown")?,
        b,
    ))?;
    let name = path.file_name().ok_or("configuration_unknown")?.as_bytes();
    let bytes = input(manifest.required_limited(name, PROCESS_OUTPUT as u64, b))?;
    if bytes.len() > PROCESS_OUTPUT {
        return Err("configuration_unknown");
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "configuration_unknown")?;
    let document = ConfigDocument::from_text(text).map_err(|_| "configuration_unknown")?;
    Ok((document, manifest))
}
fn readonly_context(config: &Config, checkout: Uuid, b: &mut Budget) -> Held<Context> {
    input(b.check())?;
    let store = Store::open_existing_registered_readonly(
        config
            .trusted_registry
            .as_deref()
            .ok_or("authority_unknown")?,
        config.store_dir.as_deref().ok_or("authority_unknown")?,
        &config.roots,
    )
    .map_err(|_| "authority_unknown")?;
    // The read-only opener RETAINS BEGIN. Collect inside that transaction;
    // never may_acquire_lease(), begin another transaction or open a writer.
    let phase = store.sql_phase();
    let authority = std::sync::Arc::clone(store.authority_identity());
    let result = if store.conn.is_autocommit() {
        Err("authority_unknown")
    } else {
        input(snapshot_in_transaction(
            &store.conn,
            &authority,
            checkout,
            b,
        ))
    };
    drop(phase);
    // Dropping the entire connection ends BEGIN, including on a failed snapshot.
    drop(store);
    drop(authority);
    result
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    AfterAdvertisement,
    BeforeFinalAdvertisement,
    BeforeRecheck,
    BeforeCleanup,
}
#[cfg(test)]
type Observer<'a> = Option<&'a mut dyn FnMut(Phase, &Scratch)>;

fn verify_path(path: &Path, checkout: Uuid, #[cfg(test)] observer: Observer<'_>) -> RemoteReport {
    verify_with_audit(
        path,
        checkout,
        None,
        None,
        None,
        None,
        #[cfg(test)]
        observer,
        #[cfg(test)]
        None,
    )
}
pub(super) fn audit_configured(
    checkout: Uuid,
    audit: &mut super::preservation::Audit,
) -> RemoteReport {
    match Config::discover_path() {
        Some(path) => audit_path(
            &path,
            checkout,
            audit,
            #[cfg(test)]
            None,
        ),
        None => RemoteReport::held(checkout),
    }
}
pub(super) fn audit_path(
    path: &Path,
    checkout: Uuid,
    audit: &mut super::preservation::Audit,
    #[cfg(test)] before_recheck: Option<&mut dyn FnMut()>,
) -> RemoteReport {
    verify_with_audit(
        path,
        checkout,
        Some(audit),
        None,
        None,
        None,
        #[cfg(test)]
        None,
        #[cfg(test)]
        before_recheck,
    )
}
pub(super) fn approval_path(
    path: &Path,
    checkout: Uuid,
    audit: &mut super::preservation::Audit,
    collector: &mut super::approval::Collector,
) -> RemoteReport {
    verify_with_audit(
        path,
        checkout,
        Some(audit),
        Some(collector),
        None,
        None,
        #[cfg(test)]
        None,
        #[cfg(test)]
        None,
    )
}
pub(super) fn recovery_path(
    path: &Path,
    checkout: Uuid,
    audit: &mut super::preservation::Audit,
    collector: &mut super::recovery_refs::Collector,
) -> RemoteReport {
    verify_with_audit(
        path,
        checkout,
        Some(audit),
        None,
        Some(collector),
        None,
        #[cfg(test)]
        None,
        #[cfg(test)]
        None,
    )
}
pub(super) fn retirement_path(
    path: &Path,
    checkout: Uuid,
    audit: &mut super::preservation::Audit,
    collector: &mut super::retirement::Collector,
) -> RemoteReport {
    verify_with_audit(
        path,
        checkout,
        Some(audit),
        None,
        None,
        Some(collector),
        #[cfg(test)]
        None,
        #[cfg(test)]
        None,
    )
}
fn verify_with_audit(
    path: &Path,
    checkout: Uuid,
    mut audit: Option<&mut super::preservation::Audit>,
    mut approval: Option<&mut super::approval::Collector>,
    mut recovery: Option<&mut super::recovery_refs::Collector>,
    mut retirement: Option<&mut super::retirement::Collector>,
    #[cfg(test)] mut observer: Observer<'_>,
    #[cfg(test)] before_recheck: Option<&mut dyn FnMut()>,
) -> RemoteReport {
    let mut b = Budget::new();
    let mut audit_nonancestor = false;
    let mut approval_retained = None;
    let mut recovery_retained = None;
    let mut retirement_retained = None;
    let mut report = RemoteReport::held(checkout);
    let mut scratch = None;
    let result = (|| -> Held<()> {
        if checkout.get_version_num() != 7 || checkout.get_variant() != uuid::Variant::RFC4122 {
            return Err("invalid_checkout");
        }
        report.started_ms = wall_time().map_err(|_| "clock_unknown")?;
        if let Some(collector) = approval.as_deref_mut() {
            collector.start(&mut b)?;
        }
        let (document, config_manifest) = load_document(path, &mut b)?;
        let config = document.authority().map_err(|_| "configuration_unknown")?;
        let policy = document
            .remote_preservation()
            .map_err(|_| "policy_unknown")?;
        let context = if let Some(collector) = approval.as_deref_mut() {
            collector.configure(&document, &config)?;
            collector.context(&mut b)?
        } else if let Some(collector) = recovery.as_deref_mut() {
            collector.configure(&document, &config)?;
            collector.context(&mut b)?
        } else if let Some(collector) = retirement.as_deref_mut() {
            collector.configure(&document, &config)?;
            collector.context(&mut b)?
        } else {
            readonly_context(&config, checkout, &mut b)?
        };
        let identity = context
            .allocation
            .identity
            .as_ref()
            .ok_or("identity_unknown")?;
        for path in [
            &identity.path,
            &identity.common_git_dir,
            &identity.private_git_dir,
        ] {
            input(native_anchor_path(path))?;
        }
        if let Some(collector) = recovery.as_deref_mut() {
            collector.lock_common(&context, &mut b)?;
        }
        if let Some(collector) = retirement.as_deref_mut() {
            collector.lock_common(&context, &mut b)?;
        }
        let targets: Vec<_> = policy
            .targets
            .iter()
            .filter(|t| t.common_dir == identity.common_git_dir)
            .collect();
        if targets.len() != 1 {
            return Err("target_unknown");
        }
        let target = targets[0];
        crate::config::validate_path(&target.common_dir, true).map_err(|_| "target_unknown")?;
        let transport = crate::config::remote_transport(&target.url).ok_or("target_unknown")?;
        // Conservatively unknown if creation fails after mkdir but before a
        // retained descriptor is established; never claim no remainder then.
        report.cleanup = "incomplete";
        scratch = Some(Scratch::create(
            &config,
            &context,
            report.observation_id,
            &mut b,
        )?);
        let scratch = scratch.as_ref().expect("created scratch");
        b.remote_home = Some(scratch.path.clone());
        report.transport = Some(transport);
        report.branch = Some(target.branch.clone());
        report.policy_digest = Some(hex(&Sha256::digest(
            serde_json::to_vec(&policy).map_err(|_| "policy_unknown")?,
        )));
        report.endpoint_digest = Some(hex(&Sha256::digest(target.url.as_bytes())));
        report.context_digest = Some(hex(&Sha256::digest(&context.canonical)));
        let census = input(filesystem::walk(
            &identity.path,
            &mut b,
            &mut filesystem::SystemBoundary,
        ))?;
        let inputs = input(GitInputs::capture(&context, &census, &mut b))?;
        if let Some(collector) = recovery.as_deref_mut() {
            collector.confirm_common(
                &inputs.common,
                identity.common_git_dir.as_os_str().as_bytes(),
            )?;
        }
        if let Some(collector) = retirement.as_deref_mut() {
            collector.confirm_common(
                &inputs.common,
                identity.common_git_dir.as_os_str().as_bytes(),
            )?;
        }
        let proof = input(GitProof::observe(&context, &census, &inputs, &mut b))?;
        report.git_version = b.git_version.clone();
        let head = std::str::from_utf8(&inputs.head)
            .map_err(|_| "identity_unknown")?
            .to_string();
        report.local_oid = Some(head.clone());
        if let Some(audit) = audit.as_deref_mut() {
            audit.begin(&document, &context, &census, &inputs, &proof, &mut b)?;
        }
        let urls = native(
            &identity.path,
            &[
                "config",
                "--null",
                "--get-all",
                &format!("remote.{}.url", target.remote),
            ],
            None,
            &mut b,
        )?;
        let mut expected = target.url.as_bytes().to_vec();
        expected.push(0);
        if urls != expected {
            return Err("target_unknown");
        }
        // Reject local upload-pack inputs before launching any file transport.
        let local_remote = if transport == "LOCAL" {
            Some(validate_local_remote(target, inputs.format, &mut b)?)
        } else {
            None
        };
        let format = match inputs.format {
            ObjectFormat::Sha1 => "sha1",
            ObjectFormat::Sha256 => "sha256",
        };
        native(
            &scratch.path,
            &[
                "init",
                "--bare",
                "--template=",
                &format!("--object-format={format}"),
                "--",
                "verification.git",
            ],
            None,
            &mut b,
        )?;
        let verification = scratch.path.join("verification.git");
        let first = advertisement(&verification, target, inputs.format, &mut b)?;
        report.initial_remote_oid = Some(first.clone());
        #[cfg(test)]
        if let Some(hook) = observer.as_deref_mut() {
            hook(Phase::AfterAdvertisement, scratch);
        }
        fetch(
            &verification,
            &target.url,
            &target.branch,
            "refs/work-verify/remote",
            transport,
            &mut b,
        )?;
        let remote = verified_commit(
            &verification,
            "refs/work-verify/remote",
            inputs.format,
            &mut b,
        )?;
        report.fetched_remote_oid = Some(remote.clone());
        if remote != first {
            return Err("remote_changed");
        }
        // Crucially, fsck runs BEFORE local objects can mask an incomplete remote.
        validate_objects(&verification, &remote, &mut b)?;
        validate_scratch_repository(&verification, inputs.format, &mut b)?;
        if let Some(audit) = audit.as_deref_mut() {
            // Fixed Git 2.55.0 graph query in the VERIFIED REMOTE repository,
            // before importing local objects. The consumer gets bytes, never
            // a scratch path, fetch selector or externally supplied report.
            let graph = native(
                &verification,
                &["rev-list", "--objects", "--no-object-names", &remote],
                None,
                &mut b,
            )?;
            audit.remote_graph(&graph, &remote, inputs.format, &mut b)?;
        }
        let local_url = format!(
            "file://{}",
            identity.path.to_str().ok_or("identity_unknown")?
        );
        if crate::config::remote_transport(&local_url) != Some("LOCAL") {
            return Err("local_transport_unknown");
        }
        input(census.recheck(&mut b))?;
        input(inputs.recheck(&mut b))?;
        fetch(
            &verification,
            &local_url,
            "HEAD",
            "refs/work-verify/local",
            "LOCAL",
            &mut b,
        )?;
        let local = verified_commit(
            &verification,
            "refs/work-verify/local",
            inputs.format,
            &mut b,
        )?;
        report.fetched_local_oid = Some(local.clone());
        if local != head {
            return Err("local_changed");
        }
        validate_objects(&verification, &local, &mut b)?;
        validate_scratch_repository(&verification, inputs.format, &mut b)?;
        let ancestry = run(
            &verification,
            &["merge-base", "--is-ancestor", &local, &remote],
            None,
            &mut b,
        )?;
        match ancestry.code {
            0 => (),
            1 if audit.is_some() => audit_nonancestor = true,
            1 => return Err("nonancestor"),
            _ => return Err("ancestry_unknown"),
        }
        if !ancestry.stdout.is_empty() {
            return Err("protocol_unknown");
        }
        #[cfg(test)]
        if let Some(hook) = observer.as_deref_mut() {
            hook(Phase::BeforeFinalAdvertisement, scratch);
        }
        let final_oid = advertisement(&verification, target, inputs.format, &mut b)?;
        report.final_remote_oid = Some(final_oid.clone());
        if final_oid != first {
            return Err("remote_changed");
        }
        #[cfg(test)]
        if let Some(hook) = observer.as_deref_mut() {
            hook(Phase::BeforeRecheck, scratch);
        }
        #[cfg(test)]
        if let Some(hook) = before_recheck {
            hook();
        }
        let (current_document, current_config_manifest) = load_document(path, &mut b)?;
        if current_document
            .authority()
            .map_err(|_| "configuration_unknown")?
            != config
            || current_document
                .remote_preservation()
                .map_err(|_| "policy_unknown")?
                != policy
        {
            return Err("configuration_changed");
        }
        input(config_manifest.recheck(&mut b))?;
        input(current_config_manifest.recheck(&mut b))?;
        let last_census = input(filesystem::walk(
            &identity.path,
            &mut b,
            &mut filesystem::SystemBoundary,
        ))?;
        let last_inputs = input(GitInputs::capture(&context, &last_census, &mut b))?;
        let last_proof = input(GitProof::observe(
            &context,
            &last_census,
            &last_inputs,
            &mut b,
        ))?;
        input(census.recheck(&mut b))?;
        input(inputs.recheck(&mut b))?;
        input(last_census.recheck(&mut b))?;
        input(last_inputs.recheck(&mut b))?;
        if census.fingerprint() != last_census.fingerprint()
            || inputs.fingerprint() != last_inputs.fingerprint()
            || proof.canonical != last_proof.canonical
            || inputs.head != last_inputs.head
        {
            return Err("local_changed");
        }
        if let Some(audit) = audit.as_deref_mut() {
            audit.recheck(&current_document, &context, &last_inputs, &mut b)?;
        }
        if let Some(remote_manifest) = local_remote {
            input(remote_manifest.recheck(&mut b))?;
        }
        input(config_manifest.recheck(&mut b))?;
        input(current_config_manifest.recheck(&mut b))?;
        let last_context = if let Some(collector) = approval.as_deref_mut() {
            collector.context(&mut b)?
        } else if let Some(collector) = recovery.as_deref_mut() {
            collector.context(&mut b)?
        } else if let Some(collector) = retirement.as_deref_mut() {
            collector.context(&mut b)?
        } else {
            readonly_context(&config, checkout, &mut b)?
        };
        if context.canonical != last_context.canonical {
            return Err("context_changed");
        }
        scratch.check()?;
        let mut evidence = Vec::new();
        frame(&mut evidence, 0, b"work.remote-observation.v1");
        for bytes in [
            &context.canonical,
            &inputs.fingerprint(),
            &last_inputs.fingerprint(),
            &census.fingerprint(),
            &last_census.fingerprint(),
            &proof.canonical,
            &last_proof.canonical,
            &serde_json::to_vec(&policy).map_err(|_| "policy_unknown")?,
        ] {
            frame(&mut evidence, 1, bytes);
        }
        for value in [
            &target.url,
            &target.remote,
            &target.branch,
            &head,
            &first,
            &remote,
            &local,
            &final_oid,
        ] {
            frame(&mut evidence, 2, value.as_bytes());
        }
        frame(&mut evidence, 3, report.observation_id.as_bytes());
        frame(&mut evidence, 4, &report.started_ms.to_be_bytes());
        report.evidence_digest = Some(hex(&Sha256::digest(evidence)));
        if approval.is_some() {
            // Retain THESE actual inputs; no disconnected inspector or report promotion.
            let policies = document
                .inspection_policies()
                .map_err(|_| "inspection_policy_unknown")?;
            let (entries, findings) = classify(&census, &proof, &policies);
            let mut evidence = Vec::new();
            frame(&mut evidence, 1, &census.fingerprint());
            frame(&mut evidence, 2, &inputs.fingerprint());
            frame(&mut evidence, 3, &proof.canonical);
            frame(&mut evidence, 4, &last_census.fingerprint());
            frame(&mut evidence, 5, &last_inputs.fingerprint());
            frame(&mut evidence, 6, &last_proof.canonical);
            approval_retained = Some(super::approval::Retained {
                context,
                physical: Physical {
                    first: census,
                    before: inputs,
                    last: Some((last_census, last_inputs)),
                },
                manifests: [config_manifest, current_config_manifest],
                entries,
                findings,
                evidence,
            });
        } else if recovery.is_some() {
            let policies = document
                .inspection_policies()
                .map_err(|_| "inspection_policy_unknown")?;
            let mut policy_bytes = Vec::new();
            frame(&mut policy_bytes, 0, b"work.recovery.policy.v1");
            frame(&mut policy_bytes, 1, policies.canonical_bytes());
            frame(
                &mut policy_bytes,
                2,
                &serde_json::to_vec(&policy).map_err(|_| "policy_unknown")?,
            );
            recovery_retained = Some(super::recovery_refs::Retained {
                context,
                physical: Physical {
                    first: census,
                    before: inputs,
                    last: Some((last_census, last_inputs)),
                },
                document_policy: policy_bytes,
                config: current_config_manifest,
            });
        } else if retirement.is_some() {
            let policies = document
                .inspection_policies()
                .map_err(|_| "inspection_policy_unknown")?;
            let (entries, findings) = classify(&census, &proof, &policies);
            let mut evidence = Vec::new();
            frame(&mut evidence, 1, &census.fingerprint());
            frame(&mut evidence, 2, &inputs.fingerprint());
            frame(&mut evidence, 3, &proof.canonical);
            frame(&mut evidence, 4, &last_census.fingerprint());
            frame(&mut evidence, 5, &last_inputs.fingerprint());
            frame(&mut evidence, 6, &last_proof.canonical);
            retirement_retained = Some(super::retirement::RetainedRetirement {
                context,
                physical: Physical {
                    first: census,
                    before: inputs,
                    last: Some((last_census, last_inputs)),
                },
                manifests: [config_manifest, current_config_manifest],
                entries,
                findings,
                evidence,
            });
        }
        input(b.check())
    })();
    report.reason = result.err().unwrap_or("consistent_observation");
    if let Some(scratch) = scratch {
        #[cfg(test)]
        if let Some(hook) = observer {
            hook(Phase::BeforeCleanup, &scratch);
        }
        // Removal requires successful helper returns; an ambiguous helper
        // error (including unknown wait outcome) leaves scratch untouched.
        report.cleanup = if scratch.cleanup(&mut b).is_ok() {
            "complete"
        } else {
            "incomplete"
        };
    }
    match wall_time() {
        Ok(ended) if report.started_ms != 0 && ended >= report.started_ms => {
            report.ended_ms = ended
        }
        _ => report.reason = "clock_unknown",
    }
    if report.reason == "consistent_observation" && report.cleanup != "complete" {
        report.reason = "cleanup_unknown";
    }
    if report.reason == "consistent_observation" && b.check().is_err() {
        report.reason = "deadline";
    }
    if report.reason == "consistent_observation" {
        report.outcome = "observed";
        // Only this actual completed invocation can seal audit coverage. Public
        // RemoteReport accessors/serialization cannot reconstruct this path.
        if let Some(audit) = audit.as_deref_mut() {
            if let Err(reason) = audit.complete(&mut b) {
                report.outcome = "held";
                report.reason = reason;
            }
        }
        if audit_nonancestor && report.reason == "consistent_observation" {
            report.outcome = "held";
            report.reason = "nonancestor";
        }
    }
    if let Some(digest) = &report.evidence_digest {
        let mut closing = Vec::new();
        frame(&mut closing, 0, digest.as_bytes());
        frame(&mut closing, 1, &report.ended_ms.to_be_bytes());
        frame(&mut closing, 2, report.reason.as_bytes());
        frame(&mut closing, 3, report.cleanup.as_bytes());
        report.evidence_digest = Some(hex(&Sha256::digest(closing)));
    }
    if let Some(collector) = approval {
        let seal = if report.observed() {
            match (approval_retained, audit) {
                (Some(retained), Some(audit)) => audit
                    .take_approval_local()
                    .and_then(|local| collector.seal(retained, local, b)),
                _ => Err("approval_sequence_unknown"),
            }
        } else {
            Err(report.reason)
        };
        if let Err(reason) = seal {
            collector.failed(reason);
        }
    } else if let Some(collector) = recovery {
        let seal = if report.cleanup() == "complete" {
            match (recovery_retained, audit) {
                (Some(retained), Some(audit)) => audit
                    .take_recovery_plan()
                    .and_then(|census| collector.seal(retained, census, b, &report)),
                _ => Err("recovery_sequence_unknown"),
            }
        } else {
            Err(report.reason)
        };
        if let Err(reason) = seal {
            collector.failed(reason);
        }
    } else if let Some(collector) = retirement {
        let seal = if report.observed() {
            match (retirement_retained, audit) {
                (Some(retained), Some(audit)) => audit
                    .take_retirement_evidence()
                    .and_then(|evidence| collector.seal(retained, evidence, b)),
                _ => Err("retirement_sequence_unknown"),
            }
        } else {
            Err(report.reason)
        };
        if let Err(reason) = seal {
            collector.failed(reason);
        }
    }
    report
}

// Protected invocation configuration plus an empty owned HOME. File services
// also receive the scrubbed environment; their actual repository config and
// object/ref layouts are preflighted rather than assuming client -c propagation.
// env_clear in git_command prevents host proxy/auth/SSH variables.
fn configure(command: &mut Command, home: &Path, transport: Option<&str>) {
    command
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env("GIT_PROTOCOL_FROM_USER", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null");
    for option in [
        "protocol.allow=never",
        "protocol.file.allow=never",
        "protocol.https.allow=never",
        "credential.helper=",
        "credential.interactive=false",
        "http.sslVerify=true",
        "http.followRedirects=false",
        "http.proxy=",
        "http.extraHeader=",
        "http.cookieFile=",
        "http.saveCookies=false",
        "transfer.bundleURI=false",
        "fetch.recurseSubmodules=false",
        "submodule.recurse=false",
        "fetch.writeCommitGraph=false",
        "pack.writeReverseIndex=false",
        "fetch.fsckObjects=true",
        "transfer.fsckObjects=true",
        "gc.auto=0",
        "maintenance.auto=false",
        "core.hooksPath=/dev/null",
        "core.fsmonitor=false",
    ] {
        command.args(["-c", option]);
    }
    if let Some(transport) = transport {
        command.args([
            "-c",
            if transport == "LOCAL" {
                "protocol.file.allow=always"
            } else {
                "protocol.https.allow=always"
            },
        ]);
    }
}
fn bounded(
    command: &mut Command,
    input_bytes: &[u8],
    b: &mut Budget,
    repository: bool,
) -> Result<ProcessOutput, IncompleteReason> {
    let argv: usize = command.get_args().map(|s| s.as_bytes().len() + 1).sum();
    // Reuse the input/slot reservation, NOT Task9's two-second per-child cap.
    // All Task10 children share the one invocation start and remaining deadline.
    let _reservation = b.reserve_process(input_bytes.len() as u64, argv as u64)?;
    let remaining = Duration::from_secs(30)
        .checked_sub(b.elapsed())
        .filter(|d| !d.is_zero())
        .ok_or(IncompleteReason::Deadline)?;
    let capacity = PROCESS_OUTPUT
        .checked_sub(b.counters.observed_process_bytes as usize)
        .filter(|n| *n > 0)
        .ok_or(IncompleteReason::OutputBudget)?;
    b.counters.child_launches += 1;
    b.counters.repository_launches += u64::from(repository);
    let output = if input_bytes.is_empty() {
        crate::bounded_process::output_aggregate(command, remaining, capacity)
    } else {
        crate::bounded_process::output_with_input_aggregate(
            command,
            remaining,
            capacity,
            input_bytes,
        )
    }
    .map_err(|_| {
        // The shared helper attempts kill/wait on every spawned-child error,
        // but its error type does not distinguish wait failure. Do not infer
        // reaping or authorize scratch removal from that ambiguous result.
        b.remote_reap_unknown = true;
        IncompleteReason::Io
    })?;
    let length = output.stdout.len() + output.stderr.len();
    b.counters.observed_process_bytes += length as u64;
    b.reserve(length as u64)?;
    b.check()?;
    Ok(ProcessOutput {
        code: output.status.code().unwrap_or(-1),
        stdout: output.stdout,
    })
}
// The parent calls this only with its opt-in remote budget. Other inspection
// invocations retain the original runner, limits, environment and semantics.
pub(super) fn run_inspection_command(
    command: &mut Command,
    input_bytes: &[u8],
    b: &mut Budget,
    repository: bool,
) -> Result<ProcessOutput, IncompleteReason> {
    let home = b
        .remote_home
        .as_ref()
        .ok_or(IncompleteReason::ContextUnavailable)?;
    // Parent has already appended the subcommand. Command-line -c must precede
    // it: install equivalent protected configuration through GIT_CONFIG_COUNT.
    let mut settings = git_command(None);
    configure(&mut settings, home, None);
    let args: Vec<_> = settings.get_args().collect();
    let mut config = Vec::new();
    for pair in args.windows(2) {
        if pair[0] == "-c" {
            config.push(pair[1]);
        }
    }
    for (key, value) in settings.get_envs() {
        if let Some(value) = value {
            command.env(key, value);
        }
    }
    command.env("GIT_CONFIG_COUNT", config.len().to_string());
    for (i, setting) in config.into_iter().enumerate() {
        let (key, value) = setting
            .to_str()
            .ok_or(IncompleteReason::UnsupportedConfig)?
            .split_once('=')
            .ok_or(IncompleteReason::UnsupportedConfig)?;
        command
            .env(format!("GIT_CONFIG_KEY_{i}"), key)
            .env(format!("GIT_CONFIG_VALUE_{i}"), value);
    }
    bounded(command, input_bytes, b, repository)
}
fn run(cwd: &Path, args: &[&str], transport: Option<&str>, b: &mut Budget) -> Held<ProcessOutput> {
    let mut command = git_command(Some(cwd));
    configure(
        &mut command,
        b.remote_home.as_deref().ok_or("scratch_unknown")?,
        transport,
    );
    command.args(args);
    bounded(&mut command, b"", b, true).map_err(|_| "git_unknown")
}
fn native(cwd: &Path, args: &[&str], transport: Option<&str>, b: &mut Budget) -> Held<Vec<u8>> {
    let output = run(cwd, args, transport, b)?;
    if output.code != 0 {
        return Err("git_unknown");
    }
    Ok(output.stdout)
}
fn advertised(bytes: &[u8], branch: &str, format: ObjectFormat) -> Held<String> {
    let value = line(bytes).map_err(|_| "advertisement_unknown")?;
    let tab = value
        .iter()
        .position(|b| *b == b'\t')
        .ok_or("advertisement_unknown")?;
    let (id, name) = (&value[..tab], &value[tab + 1..]);
    if name != branch.as_bytes() {
        return Err("advertisement_unknown");
    }
    oid(id, format).map_err(|_| "advertisement_unknown")?;
    String::from_utf8(id.to_vec()).map_err(|_| "advertisement_unknown")
}
fn advertisement(
    cwd: &Path,
    target: &RemoteTarget,
    format: ObjectFormat,
    b: &mut Budget,
) -> Held<String> {
    let bytes = native(
        cwd,
        &[
            "ls-remote",
            "--quiet",
            "--exit-code",
            "--refs",
            "--branches",
            "--",
            &target.url,
            &target.branch,
        ],
        crate::config::remote_transport(&target.url),
        b,
    )?;
    advertised(&bytes, &target.branch, format)
}
fn fetch(
    cwd: &Path,
    url: &str,
    source: &str,
    destination: &str,
    transport: &str,
    b: &mut Budget,
) -> Held<()> {
    let refspec = format!("{source}:{destination}");
    native(
        cwd,
        &[
            "fetch",
            "--quiet",
            "--no-tags",
            "--no-recurse-submodules",
            "--no-write-fetch-head",
            "--no-auto-maintenance",
            "--no-write-commit-graph",
            "--refmap=",
            "--upload-pack=/usr/bin/git-upload-pack",
            "--",
            url,
            &refspec,
        ],
        Some(transport),
        b,
    )?;
    Ok(())
}
fn verified_commit(
    cwd: &Path,
    reference: &str,
    format: ObjectFormat,
    b: &mut Budget,
) -> Held<String> {
    let bytes = native(cwd, &["rev-parse", "--verify", reference], None, b)?;
    let id = input(oid(input(line(&bytes))?, format))?;
    let id = std::str::from_utf8(&id).map_err(|_| "object_unknown")?;
    if native(cwd, &["cat-file", "-t", id], None, b)? != b"commit\n" {
        return Err("object_unknown");
    }
    Ok(id.to_string())
}
fn validate_objects(cwd: &Path, id: &str, b: &mut Budget) -> Held<()> {
    native(
        cwd,
        &["fsck", "--full", "--no-reflogs", "--no-dangling", id],
        None,
        b,
    )?;
    Ok(())
}
fn bare_manifest(path: &Path, format: ObjectFormat, b: &mut Budget) -> Held<filesystem::Manifest> {
    let mut manifest = input(filesystem::Manifest::new(path, b))?;
    let bytes = input(manifest.required(b"config", b))?;
    let output = input(git_success(
        None,
        &["config", "--null", "--no-includes", "--file", "-", "--list"],
        &bytes,
        b,
    ))?;
    let mut seen = BTreeSet::new();
    let mut bare = false;
    let mut actual_format = ObjectFormat::Sha1;
    for row in input(nul_records(&output))? {
        let newline = row
            .iter()
            .position(|b| *b == b'\n')
            .ok_or("remote_layout_unknown")?;
        let (key, value) = (&row[..newline], &row[newline + 1..]);
        if !seen.insert(key) {
            return Err("remote_layout_unknown");
        }
        let allowed = match key {
            b"core.repositoryformatversion" => matches!(value, b"0" | b"1"),
            b"core.bare" => {
                bare = value == b"true";
                bare
            }
            b"core.filemode" | b"core.logallrefupdates" => matches!(value, b"true" | b"false"),
            b"extensions.objectformat" => {
                actual_format = match value {
                    b"sha1" => ObjectFormat::Sha1,
                    b"sha256" => ObjectFormat::Sha256,
                    _ => return Err("remote_layout_unknown"),
                };
                true
            }
            _ => false,
        };
        if !allowed {
            return Err("remote_layout_unknown");
        }
    }
    if !bare || actual_format != format {
        return Err("remote_layout_unknown");
    }
    for name in [
        b"shallow".as_slice(),
        b"commondir",
        b"config.worktree",
        b"info/grafts",
        b"refs/replace",
        b"reftable",
        b"worktrees",
        b"modules",
    ] {
        input(manifest.absent(name, b))?;
    }
    input(object_storage(&mut manifest, format, b))?;
    let mut refs = match input(manifest.optional(b"packed-refs", b))? {
        Some(bytes) => input(packed_refs(&bytes, format))?,
        None => BTreeMap::new(),
    };
    input(collect_refs(
        &mut manifest,
        b"refs",
        0,
        format,
        b,
        &mut refs,
    ))?;
    // Bare init's symbolic HEAD may be unborn, but must still have safe grammar.
    let head = input(manifest.required(b"HEAD", b))?;
    let head = input(line(&head))?;
    if let Some(name) = head.strip_prefix(b"ref: ") {
        if !ref_name(name) {
            return Err("remote_layout_unknown");
        }
    } else {
        input(oid(head, format))?;
    }
    input(manifest.recheck(b))?;
    Ok(manifest)
}
fn validate_local_remote(
    target: &RemoteTarget,
    format: ObjectFormat,
    b: &mut Budget,
) -> Held<filesystem::Manifest> {
    use std::os::unix::fs::MetadataExt;
    let path = Path::new(target.url.strip_prefix("file://").ok_or("target_unknown")?);
    crate::config::validate_path(path, true).map_err(|_| "target_unknown")?;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "target_unknown")?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err("target_unknown");
    }
    bare_manifest(path, format, b)
}
fn validate_scratch_repository(path: &Path, format: ObjectFormat, b: &mut Budget) -> Held<()> {
    let mut manifest = bare_manifest(path, format, b)?;
    input(manifest.absent(b"FETCH_HEAD", b))?;
    input(manifest.recheck(b))
}

// The ONLY removal authority below is this invocation's freshly created UUID
// directory. No Drop cleanup, prefix scan, store/checkout deletion or rm -rf.
struct Scratch {
    parent: OwnedFd,
    directory: OwnedFd,
    name: String,
    path: PathBuf,
    identity: (u64, u64),
    parent_identity: (u64, u64),
}
fn stat_id(stat: &rfs::Stat) -> (u64, u64) {
    (stat.st_dev, stat.st_ino)
}
fn beneath(parent: &OwnedFd, name: &std::ffi::CStr, flags: OFlags) -> Held<OwnedFd> {
    rfs::openat2(
        parent,
        name,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| "scratch_unknown")
}
impl Scratch {
    fn create(config: &Config, context: &Context, id: Uuid, b: &mut Budget) -> Held<Self> {
        input(b.check())?;
        let name = format!("work-verify-{id}");
        let path = Path::new("/tmp").join(&name);
        let identity = context
            .allocation
            .identity
            .as_ref()
            .ok_or("identity_unknown")?;
        for excluded in [
            Some(&identity.path),
            Some(&identity.common_git_dir),
            Some(&identity.private_git_dir),
            config.store_dir.as_ref(),
            config.trusted_registry.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if path.starts_with(excluded) || excluded.starts_with(&path) {
                return Err("scratch_unknown");
            }
        }
        crate::config::validate_path(Path::new("/tmp"), true).map_err(|_| "scratch_unknown")?;
        let parent = rfs::openat(
            rfs::CWD,
            c"/tmp",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| "scratch_unknown")?;
        let parent_stat = rfs::fstat(&parent).map_err(|_| "scratch_unknown")?;
        if parent_stat.st_uid != 0 || parent_stat.st_mode & 0o1000 == 0 {
            return Err("scratch_unknown");
        }
        rfs::mkdirat(&parent, name.as_str(), Mode::from_raw_mode(0o700))
            .map_err(|_| "scratch_unknown")?;
        // Failure after mkdir leaves an owned remainder rather than guessing a
        // deletion target whose descriptor identity was never established.
        let directory = beneath(
            &parent,
            CString::new(name.as_bytes())
                .map_err(|_| "scratch_unknown")?
                .as_c_str(),
            OFlags::PATH | OFlags::DIRECTORY,
        )?;
        let stat = rfs::fstat(&directory).map_err(|_| "scratch_unknown")?;
        let result = Self {
            parent,
            directory,
            name,
            path,
            identity: stat_id(&stat),
            parent_identity: stat_id(&parent_stat),
        };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Held<()> {
        let parent = rfs::fstat(&self.parent).map_err(|_| "scratch_unknown")?;
        let named_parent = rfs::statat(rfs::CWD, c"/tmp", AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| "scratch_unknown")?;
        let retained = rfs::fstat(&self.directory).map_err(|_| "scratch_unknown")?;
        let named = rfs::statat(&self.parent, self.name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| "scratch_unknown")?;
        if stat_id(&parent) != self.parent_identity
            || stat_id(&named_parent) != self.parent_identity
            || stat_id(&retained) != self.identity
            || stat_id(&named) != self.identity
            || retained.st_uid != rustix::process::geteuid().as_raw()
            || named.st_uid != retained.st_uid
            || retained.st_mode & 0o7777 != 0o700
            || named.st_mode != retained.st_mode
            || FileType::from_raw_mode(retained.st_mode) != FileType::Directory
        {
            return Err("scratch_unknown");
        }
        // Reject a bind mount at the name even if device/inode happen to match.
        let opened = beneath(
            &self.parent,
            CString::new(self.name.as_bytes())
                .map_err(|_| "scratch_unknown")?
                .as_c_str(),
            OFlags::PATH | OFlags::DIRECTORY,
        )?;
        if stat_id(&rfs::fstat(&opened).map_err(|_| "scratch_unknown")?) != self.identity {
            return Err("scratch_unknown");
        }
        Ok(())
    }
    fn cleanup(&self, b: &mut Budget) -> Held<()> {
        if b.remote_reap_unknown {
            return Err("cleanup_unknown");
        }
        self.check()?;
        // Plan before unlinking: reject links, mounts and unsupported entries
        // without descending into them. Keep every ancestor descriptor so a
        // nested rebound is checked, not merely the scratch root's name.
        let root = beneath(&self.directory, c".", OFlags::PATH | OFlags::DIRECTORY)?;
        let stat = rfs::fstat(&root).map_err(|_| "cleanup_unknown")?;
        let mut nodes = vec![CleanupNode {
            fd: root,
            name: c".".to_owned(),
            parent: None,
            stat,
            directory: true,
            depth: 0,
        }];
        let mut index = 0;
        while index < nodes.len() {
            cleanup_time(b)?;
            self.check()?;
            if !nodes[index].directory {
                index += 1;
                continue;
            }
            if nodes[index].depth >= MAX_DEPTH {
                return Err("cleanup_unknown");
            }
            let readable = beneath(&nodes[index].fd, c".", OFlags::RDONLY | OFlags::DIRECTORY)?;
            let mut buffer = [MaybeUninit::<u8>::uninit(); DIRECTORY_BUFFER_BYTES];
            let mut entries = rfs::RawDir::new(&readable, &mut buffer);
            loop {
                cleanup_time(b)?;
                let Some(entry) = entries.next() else {
                    break;
                };
                let entry = entry.map_err(|_| "cleanup_unknown")?;
                let name = entry.file_name();
                if name.to_bytes() == b"." || name.to_bytes() == b".." {
                    continue;
                }
                if nodes.len() >= MAX_ENTRIES as usize {
                    return Err("cleanup_unknown");
                }
                let fd = beneath(&nodes[index].fd, name, OFlags::PATH)?;
                let stat = rfs::fstat(&fd).map_err(|_| "cleanup_unknown")?;
                if stat.st_dev != self.identity.0
                    || stat.st_uid != rustix::process::geteuid().as_raw()
                {
                    return Err("cleanup_unknown");
                }
                let directory = match FileType::from_raw_mode(stat.st_mode) {
                    FileType::Directory if stat.st_mode & 0o022 == 0 => true,
                    FileType::RegularFile if stat.st_nlink == 1 => false,
                    _ => return Err("cleanup_unknown"),
                };
                let depth = nodes[index].depth + 1;
                nodes.push(CleanupNode {
                    fd,
                    name: name.to_owned(),
                    parent: Some(index),
                    stat,
                    directory,
                    depth,
                });
            }
            index += 1;
        }
        // Reverse breadth-first order removes descendants before their parents.
        for index in (1..nodes.len()).rev() {
            cleanup_time(b)?;
            self.check()?;
            let mut ancestor = Some(index);
            while let Some(at) = ancestor {
                cleanup_time(b)?;
                let node = &nodes[at];
                let retained = rfs::fstat(&node.fd).map_err(|_| "cleanup_unknown")?;
                cleanup_binding(&retained, node)?;
                if let Some(parent) = node.parent {
                    let current = beneath(&nodes[parent].fd, node.name.as_c_str(), OFlags::PATH)?;
                    cleanup_binding(&rfs::fstat(&current).map_err(|_| "cleanup_unknown")?, node)?;
                }
                ancestor = node.parent;
            }
            let node = &nodes[index];
            let parent = &nodes[node.parent.expect("nonroot")].fd;
            rfs::unlinkat(
                parent,
                node.name.as_c_str(),
                if node.directory {
                    AtFlags::REMOVEDIR
                } else {
                    AtFlags::empty()
                },
            )
            .map_err(|_| "cleanup_unknown")?;
        }
        cleanup_time(b)?;
        self.check()?;
        rfs::unlinkat(&self.parent, self.name.as_str(), AtFlags::REMOVEDIR)
            .map_err(|_| "cleanup_unknown")
    }
}

struct CleanupNode {
    fd: OwnedFd,
    name: CString,
    parent: Option<usize>,
    stat: rfs::Stat,
    directory: bool,
    depth: usize,
}
fn cleanup_time(b: &Budget) -> Held<()> {
    // A failed observation does not prevent safe owned cleanup, but cleanup
    // never receives a fresh deadline or clears the observation's failure.
    if b.elapsed() >= Duration::from_secs(30) {
        Err("cleanup_unknown")
    } else {
        Ok(())
    }
}
fn cleanup_binding(actual: &rfs::Stat, node: &CleanupNode) -> Held<()> {
    if stat_id(actual) != stat_id(&node.stat)
        || actual.st_uid != node.stat.st_uid
        || actual.st_mode != node.stat.st_mode
        || (!node.directory && actual.st_nlink != 1)
    {
        Err("cleanup_unknown")
    } else {
        Ok(())
    }
}

#[cfg(test)]
use crate as work_cli_api;
#[cfg(test)]
#[path = "../../tests/support/inspection_fixture.rs"]
mod fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup() -> (fixture::ManagedFixture, PathBuf, PathBuf) {
        setup_format("sha1")
    }
    fn setup_format(format: &str) -> (fixture::ManagedFixture, PathBuf, PathBuf) {
        let f = fixture::ManagedFixture::new(format, "2");
        let remote = f.temp.path().join("backup.git");
        fixture::git(
            f.temp.path(),
            &[
                "init".as_ref(),
                "--bare".as_ref(),
                "--template=".as_ref(),
                format!("--object-format={format}").as_ref(),
                remote.as_os_str(),
            ],
        );
        let url = format!("file://{}", remote.display());
        f.git(&[
            "remote".as_ref(),
            "add".as_ref(),
            "backup".as_ref(),
            url.as_ref(),
        ]);
        f.git(&[
            "-c".as_ref(),
            "protocol.file.allow=always".as_ref(),
            "push".as_ref(),
            "backup".as_ref(),
            "HEAD:refs/heads/preserved".as_ref(),
        ]);
        let config = f.temp.path().join("config.toml");
        fs::write(&config, format!("store_dir={:?}\ntrusted_registry={:?}\nroots=[{:?}]\n[remote_preservation]\nformat=1\nversion='fixture-v1'\n[[remote_preservation.targets]]\ncommon_dir={:?}\nremote='backup'\nurl={url:?}\nbranch='refs/heads/preserved'\n", f.temp.path().join("authority"), f.temp.path().join("registry"), f.root, f.common())).unwrap();
        (f, config, remote)
    }
    #[test]
    fn actual_protocol_positive_and_readonly_snapshot_released() {
        let (f, config, _) = setup();
        let mut saw = false;
        let mut hook = |phase, _: &Scratch| {
            if phase == Phase::AfterAdvertisement {
                // WAL permits a writer alongside readers, so BEGIN alone would
                // not test snapshot release. TRUNCATE must also find no reader
                // pinned to this fixture's WAL. This is a state assertion, not
                // a performance threshold; only this test owns the authority.
                let conn = rusqlite::Connection::open(f.temp.path().join("authority/store.sqlite"))
                    .unwrap();
                conn.execute_batch("BEGIN EXCLUSIVE; COMMIT;").unwrap();
                let busy: i64 = conn
                    .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(busy, 0, "collector retained its read snapshot during Git");
                saw = true;
            }
        };
        let report = verify_path(&config, f.allocation.checkout, Some(&mut hook));
        assert!(report.observed(), "{report:?}");
        assert!(saw);
        assert_eq!(report.cleanup(), "complete");
        assert_eq!(report.transport(), Some("LOCAL"));
    }
    #[test]
    fn native_sha256_full_flow_uses_matching_object_format() {
        let (f, config, _) = setup_format("sha256");
        let report = verify_path(&config, f.allocation.checkout, None);
        assert!(report.observed(), "{report:?}");
        assert_eq!(report.local_oid().unwrap().len(), 64);
    }
    #[test]
    fn capture_error_does_not_claim_known_reaping() {
        let temp = tempfile::tempdir().unwrap();
        let mut budget = Budget::new();
        budget.remote_home = Some(temp.path().to_owned());
        // A finite capacity fault, not forged command output or a timing gate.
        budget.counters.observed_process_bytes = (PROCESS_OUTPUT - 1) as u64;
        assert!(native(temp.path(), &["--version"], None, &mut budget).is_err());
        assert!(budget.remote_reap_unknown);
    }
    #[test]
    fn command_envelope_is_explicit_without_launching_children() {
        for transport in [None, Some("LOCAL"), Some("HTTPS")] {
            let mut command = git_command(None);
            configure(&mut command, Path::new("/owned-scratch"), transport);
            let args: Vec<_> = command.get_args().map(|v| v.to_str().unwrap()).collect();
            for setting in [
                "protocol.allow=never",
                "http.sslVerify=true",
                "http.followRedirects=false",
                "credential.helper=",
                "transfer.bundleURI=false",
            ] {
                assert!(args.contains(&setting));
            }
            assert_eq!(
                args.contains(&"protocol.file.allow=always"),
                transport == Some("LOCAL")
            );
            assert_eq!(
                args.contains(&"protocol.https.allow=always"),
                transport == Some("HTTPS")
            );
            let environment: BTreeMap<_, _> = command.get_envs().collect();
            assert_eq!(
                environment.get(std::ffi::OsStr::new("GIT_PROTOCOL_FROM_USER")),
                Some(&Some(std::ffi::OsStr::new("0")))
            );
            assert_eq!(
                environment.get(std::ffi::OsStr::new("HOME")),
                Some(&Some(std::ffi::OsStr::new("/owned-scratch")))
            );
        }
    }
    #[test]
    fn exact_advertisement_parser_rejects_ambiguity_without_network() {
        let id = "1".repeat(40);
        let row = format!("{id}\trefs/heads/preserved\n");
        assert_eq!(
            advertised(row.as_bytes(), "refs/heads/preserved", ObjectFormat::Sha1).unwrap(),
            id
        );
        for invalid in [
            format!("{row}{row}"),
            row.replace("preserved", "other"),
            row.trim_end().to_string(),
            row.replace('\t', " "),
            row.replace('1', "0"),
            format!("{row}junk\n"),
        ] {
            assert!(advertised(
                invalid.as_bytes(),
                "refs/heads/preserved",
                ObjectFormat::Sha1
            )
            .is_err());
        }
    }
    #[test]
    fn moving_remote_local_head_and_config_never_leave_positive_metadata() {
        for case in [
            "remote-before-fetch",
            "remote-at-close",
            "local",
            "config",
            "fetch-failure",
        ] {
            let (f, config, remote) = setup();
            let mut fired = false;
            let mut hook = |phase, _: &Scratch| {
                let trigger = match case {
                    "remote-at-close" => Phase::BeforeFinalAdvertisement,
                    "local" | "config" => Phase::BeforeRecheck,
                    _ => Phase::AfterAdvertisement,
                };
                if phase != trigger || fired {
                    return;
                }
                fired = true;
                match case {
                    "remote-before-fetch" | "remote-at-close" => {
                        fs::write(f.repo.join("tracked"), b"remote change\n").unwrap();
                        fixture::git(
                            &f.repo,
                            &["commit".as_ref(), "-am".as_ref(), "new remote tip".as_ref()],
                        );
                        fixture::git(
                            &f.repo,
                            &[
                                "-c".as_ref(),
                                "protocol.file.allow=always".as_ref(),
                                "push".as_ref(),
                                "backup".as_ref(),
                                "HEAD:refs/heads/preserved".as_ref(),
                            ],
                        );
                    }
                    "local" => {
                        fs::write(f.path(b"tracked"), b"new local head\n").unwrap();
                        f.git(&["commit".as_ref(), "-am".as_ref(), "local change".as_ref()]);
                    }
                    "config" => {
                        let text = fs::read_to_string(&config)
                            .unwrap()
                            .replace("fixture-v1", "fixture-v2");
                        fs::write(&config, text).unwrap();
                    }
                    _ => {
                        fs::rename(remote.join("objects"), remote.join("missing")).unwrap();
                    }
                }
            };
            let report = verify_path(&config, f.allocation.checkout, Some(&mut hook));
            assert!(fired, "{case}: {report:?}");
            assert!(!report.observed(), "{case}: {report:?}");
            assert_eq!(report.cleanup(), "complete");
        }
    }
    #[test]
    fn changed_boot_authority_is_not_a_historical_receipt_substitute() {
        let (f, config, _) = setup();
        let mut hook = |phase, _: &Scratch| {
            if phase == Phase::BeforeRecheck {
                let conn = rusqlite::Connection::open(f.temp.path().join("authority/store.sqlite"))
                    .unwrap();
                let mut allocation = f.allocation.clone();
                allocation.identity.as_mut().unwrap().boot_id = "different-boot".into();
                conn.execute(
                    "UPDATE allocations SET record=?1 WHERE checkout=?2",
                    (
                        serde_json::to_string(&allocation).unwrap(),
                        allocation.checkout.to_string(),
                    ),
                )
                .unwrap();
            }
        };
        let report = verify_path(&config, f.allocation.checkout, Some(&mut hook));
        assert!(!report.observed(), "{report:?}");
        assert_eq!(report.reason(), "context_changed");
    }
    #[test]
    fn scratch_replacement_and_unsafe_cleanup_leave_foreign_paths_intact() {
        for replace in [true, false] {
            let (f, config, _) = setup();
            let foreign = f.temp.path().join("foreign");
            fs::create_dir(&foreign).unwrap();
            fs::write(foreign.join("keep"), b"foreign").unwrap();
            let mut remainder = None;
            let mut hook = |phase, scratch: &Scratch| {
                if phase == Phase::BeforeCleanup {
                    if replace {
                        let renamed = scratch.path.with_extension("retained");
                        fs::rename(&scratch.path, &renamed).unwrap();
                        fs::create_dir(&scratch.path).unwrap();
                        fs::write(scratch.path.join("keep"), b"replacement").unwrap();
                        remainder = Some((scratch.path.clone(), renamed));
                    } else {
                        std::os::unix::fs::symlink(&foreign, scratch.path.join("unexpected-link"))
                            .unwrap();
                        remainder = Some((scratch.path.clone(), scratch.path.clone()));
                    }
                }
            };
            let report = verify_path(&config, f.allocation.checkout, Some(&mut hook));
            assert!(!report.observed(), "{report:?}");
            assert_eq!(report.cleanup(), "incomplete");
            assert_eq!(fs::read(foreign.join("keep")).unwrap(), b"foreign");
            let (named, retained) = remainder.unwrap();
            if replace {
                assert_eq!(fs::read(named.join("keep")).unwrap(), b"replacement");
            }
            // Test harness alone removes its explicitly owned fault artifacts.
            fs::remove_dir_all(&retained).unwrap();
            if named != retained {
                fs::remove_dir_all(named).unwrap();
            }
        }
    }
}
