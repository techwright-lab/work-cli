//! Non-destructive retirement-assessment prerequisite. Never deletion authority.
//! Public output is historical metadata only; the private assessment is the
//! future transaction seam and is dropped by the library wrapper.
use super::*;
use crate::config::ConfigDocument;
use crate::run_journal::{terminal_candidates, TerminalCandidate, TerminalObservation};
use crate::runtime_scope::HoldReason;
use crate::scope_driver::{Driver, RuntimeContext};
use std::{
    path::Path,
    time::{Duration, Instant},
};

type Held<T> = Result<T, &'static str>;
const LIMITATION: &str = "Assessment is a cooperative LOCAL observation, not retirement, deletion, writer release or charge release. execution_enabled remains false. Supervised emptiness is recorded-scope OS observation; adopted success is an operator assertion and still requires an explicit task-completion declaration. Recovery refs are extra local protection, never ownership attribution or remote backup.";

#[derive(Debug, serde::Serialize)]
pub struct RetirementAssessmentReport {
    checkout: Uuid,
    coverage: &'static str,
    outcome: &'static str,
    reason: &'static str,
    mode: &'static str,
    quiescence: &'static str,
    task_completion: &'static str,
    execution_enabled: bool,
    retirement_authority: bool,
    writer_charges_retained: bool,
    recorded: bool,
    assertion_id: Option<Uuid>,
    cleanup: &'static str,
    limitation: &'static str,
    preservation: Option<PreservationReport>,
}
impl RetirementAssessmentReport {
    pub fn outcome(&self) -> &str {
        self.outcome
    }
    pub fn reason(&self) -> &str {
        self.reason
    }
    pub fn mode(&self) -> &str {
        self.mode
    }
    pub fn quiescence(&self) -> &str {
        self.quiescence
    }
    pub fn task_completion(&self) -> &str {
        self.task_completion
    }
    pub fn execution_enabled(&self) -> bool {
        self.execution_enabled
    }
    pub fn retirement_authority(&self) -> bool {
        self.retirement_authority
    }
    pub fn writer_charges_retained(&self) -> bool {
        self.writer_charges_retained
    }
    fn held(checkout: Uuid) -> Self {
        Self {
            checkout,
            coverage: "incomplete",
            outcome: "held",
            reason: "configuration_unknown",
            mode: "unknown",
            quiescence: "held",
            task_completion: "unknown",
            execution_enabled: false,
            retirement_authority: false,
            writer_charges_retained: true,
            recorded: false,
            assertion_id: None,
            cleanup: "not_created",
            limitation: LIMITATION,
            preservation: None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ModeKind {
    Supervised,
    Adopted,
}

/// Private retained assessment. Not Clone/Deserialize or caller-constructible.
struct Assessment {
    context: Context,
    physical: Physical,
    budget: Budget,
    census: preservation::RecoveryCensus,
    manifests: [filesystem::Manifest; 2],
    entries: Vec<ObservedEntry>,
    findings: Vec<Finding>,
    evidence: Vec<u8>,
    approval_semantic: Vec<u8>,
    approval_invalidation: Vec<u8>,
    mode: ModeKind,
    adopted: Option<approval::AdoptedMode>,
    terminals: Vec<TerminalCandidate>,
    task_completed: bool,
    approval_policy_digest: Option<String>,
    policies: ValidatedPolicies,
    lock: recovery_refs::ExistingLock,
    store: Store,
    assertion: Option<Uuid>,
    runtime: Option<(std::path::PathBuf, String)>,
}

pub(super) struct Collector {
    checkout: Uuid,
    assertion: Option<Uuid>,
    store: Option<Store>,
    lock: Option<recovery_refs::ExistingLock>,
    mode: Option<ModeKind>,
    adopted: Option<approval::AdoptedMode>,
    terminals: Option<Vec<TerminalCandidate>>,
    task_completed: Option<bool>,
    approval_policy_digest: Option<String>,
    policies: Option<ValidatedPolicies>,
    runtime: Option<(std::path::PathBuf, String)>,
    sealed: Option<Assessment>,
    failure: Option<&'static str>,
}
impl Collector {
    fn new(checkout: Uuid, assertion: Option<Uuid>) -> Self {
        Self {
            checkout,
            assertion,
            store: None,
            lock: None,
            mode: None,
            adopted: None,
            terminals: None,
            task_completed: None,
            approval_policy_digest: None,
            policies: None,
            runtime: None,
            sealed: None,
            failure: None,
        }
    }
    pub(super) fn failed(&mut self, reason: &'static str) {
        self.failure = Some(reason);
        self.sealed = None;
    }
    pub(super) fn configure(
        &mut self,
        document: &ConfigDocument,
        config: &crate::config::Config,
    ) -> Held<()> {
        let policies = document
            .inspection_policies()
            .map_err(|_| "inspection_policy_unknown")?;
        let approval_policy_digest = match document.approval() {
            Ok(policy) => {
                let mut approval = Vec::new();
                frame(&mut approval, 0, b"work.approval.policy.v1");
                frame(
                    &mut approval,
                    1,
                    &serde_json::to_vec(&policy).map_err(|_| "approval_policy_unknown")?,
                );
                frame(&mut approval, 2, policies.canonical_bytes());
                frame(
                    &mut approval,
                    3,
                    &serde_json::to_vec(
                        &document
                            .remote_preservation()
                            .map_err(|_| "policy_unknown")?,
                    )
                    .map_err(|_| "policy_unknown")?,
                );
                Some(hex(&Sha256::digest(approval)))
            }
            Err(_) => None,
        };
        let store = open_configured_store(config).map_err(|_| "authority_unknown")?;
        self.runtime = document
            .recovery_runtime()
            .ok()
            .map(|runtime| (runtime.runtime_directory, runtime.bus_address));
        self.approval_policy_digest = approval_policy_digest;
        self.policies = Some(policies);
        self.store = Some(store);
        Ok(())
    }
    pub(super) fn context(&mut self, b: &mut Budget) -> Held<Context> {
        let store = self.store.as_mut().ok_or("authority_unknown")?;
        store.may_acquire_lease().map_err(|_| "authority_unknown")?;
        let authority = std::sync::Arc::clone(store.authority_identity());
        let phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|_| "authority_unknown")?;
        let context = snapshot_in_transaction(&tx, &authority, self.checkout, b)
            .map_err(|_| "context_unknown")?;
        let checkout = self.checkout.to_string();
        let (adopted, supervised, capture, gap, writers): (bool, bool, bool, bool, i64) = tx
            .query_row(
                "SELECT
                    EXISTS(SELECT 1 FROM adopted_groups WHERE checkout=?1),
                    EXISTS(SELECT 1 FROM run_groups WHERE checkout=?1),
                    EXISTS(SELECT 1 FROM capture_runs WHERE checkout=?1),
                    EXISTS(SELECT 1 FROM attribution_gaps WHERE checkout=?1),
                    (SELECT count(*) FROM writers WHERE checkout=?1)",
                [&checkout],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .map_err(|_| "mode_unknown")?;
        if capture {
            return Err("captured_history_unsupported");
        }
        if gap {
            return Err("gap_history_unsupported");
        }
        if adopted && supervised {
            return Err("mixed_mode");
        }
        let mode = if adopted {
            ModeKind::Adopted
        } else if supervised {
            ModeKind::Supervised
        } else {
            return Err("mode_unknown");
        };
        if self.mode.as_ref().is_some_and(|m| *m != mode) {
            return Err("mode_changed");
        }
        match mode {
            ModeKind::Adopted => {
                if self.assertion.is_none() {
                    return Err("adopted_assertion_required");
                }
                if self.approval_policy_digest.is_none() {
                    return Err("approval_policy_unknown");
                }
                if writers != 1 {
                    return Err("writer_state_unknown");
                }
                let adopted = approval::AdoptedMode::read(&tx, &context)?;
                if self.adopted.as_ref().is_some_and(|m| m != &adopted) {
                    return Err("mode_changed");
                }
                self.adopted = Some(adopted);
                self.task_completed = Some(false);
            }
            ModeKind::Supervised => {
                if self.assertion.is_some() {
                    return Err("unexpected_assertion");
                }
                if writers != 0 {
                    return Err("writer_present");
                }
                let terminals = terminal_candidates(&tx, self.checkout)
                    .map_err(|_| "terminal_candidate_unknown")?;
                let completed = !crate::finish::task_open(&tx, self.checkout)
                    .map_err(|_| "task_completion_unknown")?;
                self.terminals = Some(terminals);
                self.task_completed = Some(completed);
            }
        }
        self.mode = Some(mode);
        tx.rollback().map_err(|_| "context_unknown")?;
        drop(phase);
        Ok(context)
    }
    pub(super) fn lock_common(&mut self, context: &Context, b: &mut Budget) -> Held<()> {
        let store = self.store.as_ref().ok_or("authority_unknown")?;
        self.lock = Some(recovery_refs::ExistingLock::retain(store, context, b)?);
        Ok(())
    }
    pub(super) fn confirm_common(&self, common: &filesystem::Manifest, path: &[u8]) -> Held<()> {
        let lock = self.lock.as_ref().ok_or("lock_unknown")?;
        let store = self.store.as_ref().ok_or("authority_unknown")?;
        lock.confirm(store, common, path)
    }
    pub(super) fn seal(
        &mut self,
        retained: RetainedRetirement,
        evidence: preservation::RetirementEvidence,
        budget: Budget,
    ) -> Held<()> {
        let lock = self.lock.take().ok_or("lock_unknown")?;
        lock.matches_census(&evidence.census)?;
        let store = self.store.take().ok_or("authority_unknown")?;
        let mode = self.mode.take().ok_or("mode_unknown")?;
        self.sealed = Some(Assessment {
            context: retained.context,
            physical: retained.physical,
            budget,
            census: evidence.census,
            manifests: retained.manifests,
            entries: retained.entries,
            findings: retained.findings,
            evidence: retained.evidence,
            approval_semantic: evidence.approval_semantic,
            approval_invalidation: evidence.approval_invalidation,
            mode,
            adopted: self.adopted.take(),
            terminals: self.terminals.take().unwrap_or_default(),
            task_completed: self.task_completed.take().unwrap_or(false),
            approval_policy_digest: self.approval_policy_digest.take(),
            policies: self.policies.take().ok_or("inspection_policy_unknown")?,
            lock,
            store,
            assertion: self.assertion,
            runtime: self.runtime.take(),
        });
        Ok(())
    }
}

pub(super) struct RetainedRetirement {
    pub(super) context: Context,
    pub(super) physical: Physical,
    pub(super) manifests: [filesystem::Manifest; 2],
    pub(super) entries: Vec<ObservedEntry>,
    pub(super) findings: Vec<Finding>,
    pub(super) evidence: Vec<u8>,
}

/// Bounded no-follow trusted configuration path. No caller Driver, clock, OID,
/// roster or positive proof field. Always reports execution disabled.
pub fn assess_retirement(
    config_path: &Path,
    checkout: Uuid,
    assertion: Option<Uuid>,
) -> RetirementAssessmentReport {
    assess_path(
        config_path,
        checkout,
        assertion,
        #[cfg(test)]
        None,
    )
}

#[cfg(test)]
pub(super) fn assess_path_with_driver(
    config_path: &Path,
    checkout: Uuid,
    assertion: Option<Uuid>,
    driver: &Driver,
) -> RetirementAssessmentReport {
    assess_path(config_path, checkout, assertion, Some(driver))
}

fn assess_path(
    path: &Path,
    checkout: Uuid,
    assertion: Option<Uuid>,
    #[cfg(test)] driver: Option<&Driver>,
) -> RetirementAssessmentReport {
    if checkout.get_version_num() != 7 || checkout.get_variant() != uuid::Variant::RFC4122 {
        let mut report = RetirementAssessmentReport::held(checkout);
        report.reason = "invalid_checkout";
        return report;
    }
    if let Some(id) = assertion {
        if id.get_version_num() != 7 || id.get_variant() != uuid::Variant::RFC4122 {
            let mut report = RetirementAssessmentReport::held(checkout);
            report.reason = "assertion_ineligible";
            report.assertion_id = Some(id);
            return report;
        }
    }
    let mut collector = Collector::new(checkout, assertion);
    let mut audit = preservation::Audit::new(checkout);
    let remote = remote_proof::retirement_path(path, checkout, &mut audit, &mut collector);
    let preservation = audit.finish(remote);
    let mut report = RetirementAssessmentReport::held(checkout);
    report.assertion_id = assertion;
    report.preservation = Some(preservation);
    report.reason = collector.failure.unwrap_or("observation_held");
    let Some(mut assessment) = collector.sealed.take() else {
        return report;
    };
    report.mode = match assessment.mode {
        ModeKind::Supervised => "supervised",
        ModeKind::Adopted => "adopted",
    };
    match decide(
        &mut assessment,
        &mut report,
        #[cfg(test)]
        driver,
    ) {
        Ok(()) => {
            report.coverage = "complete";
            report.outcome = "prerequisites_complete";
            report.reason = "prerequisites_complete";
            report.cleanup = "complete";
        }
        Err(reason) => {
            report.outcome = "held";
            report.reason = reason;
        }
    }
    report.execution_enabled = false;
    report.retirement_authority = false;
    report.writer_charges_retained = true;
    report.recorded = false;
    report
}

fn decide(
    assessment: &mut Assessment,
    report: &mut RetirementAssessmentReport,
    #[cfg(test)] injected: Option<&Driver>,
) -> Held<()> {
    if !assessment.findings.is_empty() {
        return Err("inspection_held");
    }
    let identity = assessment
        .context
        .allocation
        .identity
        .as_ref()
        .ok_or("identity_unknown")?;
    let common_path = identity.common_git_dir.as_os_str().as_bytes().to_vec();
    assessment
        .lock
        .revalidate(&assessment.store, &common_path)?;
    let targets = recovery_refs::verify_existing_protection(
        &assessment.census,
        assessment.context.allocation.checkout,
    )?;
    let observation = finish_observation(
        &assessment.policies,
        &assessment.context.canonical,
        &assessment.evidence,
        std::mem::take(&mut assessment.entries),
        std::mem::take(&mut assessment.findings),
        None,
        &assessment.budget,
    )
    .map_err(|_| "inspection_unknown")?;
    if observation.coverage() != Coverage::Complete || !observation.findings().is_empty() {
        return Err("inspection_held");
    }
    let mut assertion = None;
    if assessment.mode == ModeKind::Adopted {
        let mode = assessment.adopted.as_ref().ok_or("mode_unknown")?;
        let id = assessment.assertion.ok_or("adopted_assertion_required")?;
        let policy_digest = assessment
            .approval_policy_digest
            .as_deref()
            .ok_or("approval_policy_unknown")?;
        let validated = approval::consume_operator_assertion(
            &assessment.store,
            assessment.context.allocation.checkout,
            id,
            &assessment.context,
            &assessment.physical,
            &assessment.manifests,
            &assessment.approval_semantic,
            &assessment.approval_invalidation,
            &observation,
            mode,
            policy_digest,
            &mut assessment.budget,
        )?;
        report.quiescence = "operator_assertion";
        report.task_completion = "declaration_required";
        #[cfg(test)]
        let mut validated = validated;
        #[cfg(test)]
        if take_expire_after_io() {
            validated.expire_for_test();
        }
        assertion = Some(validated);
    }
    #[cfg(test)]
    if let Some(hook) = take_after_protection() {
        hook();
    }
    recovery_refs::sync_existing_protection(
        &assessment.physical.before.common,
        &mut assessment.census,
        &targets,
        &mut assessment.budget,
    )?;
    assessment
        .lock
        .revalidate(&assessment.store, &common_path)?;
    let (fresh, census, inputs) =
        preservation::RecoveryCensus::recapture(&assessment.context, &mut assessment.budget)?;
    assessment
        .physical
        .recheck(&mut assessment.budget)
        .map_err(|_| "census_changed")?;
    assessment.census.recheck(&mut assessment.budget)?;
    let current_plan = fresh.plan(assessment.context.allocation.checkout)?;
    let current_targets: Vec<(String, String)> = current_plan
        .into_iter()
        .map(|row| (row.reference, row.oid))
        .collect();
    if current_targets != targets {
        return Err("census_changed");
    }
    fresh.verify_closure(&assessment.census, &targets)?;
    fresh.recheck(&mut assessment.budget)?;
    census
        .recheck(&mut assessment.budget)
        .map_err(|_| "census_changed")?;
    inputs
        .recheck(&mut assessment.budget)
        .map_err(|_| "census_changed")?;
    for manifest in &assessment.manifests {
        manifest
            .recheck(&mut assessment.budget)
            .map_err(|_| "configuration_changed")?;
    }
    let mut observations = Vec::new();
    if assessment.mode == ModeKind::Supervised {
        if !assessment.task_completed {
            return Err("task_completion_missing");
        }
        if assessment.terminals.is_empty() {
            return Err("terminal_candidate_unknown");
        }
        let owned;
        let driver = {
            #[cfg(test)]
            if let Some(driver) = injected {
                driver
            } else {
                owned = production_driver(assessment)?;
                &owned
            }
            #[cfg(not(test))]
            {
                owned = production_driver(assessment)?;
                &owned
            }
        };
        for candidate in &assessment.terminals {
            assessment.budget.check().map_err(|_| "deadline")?;
            observations.push(
                candidate
                    .observe(driver)
                    .map_err(|_| "observation_incomplete")?,
            );
            assessment.budget.check().map_err(|_| "deadline")?;
        }
        report.task_completion = "recorded";
    }
    assessment.budget.check().map_err(|_| "deadline")?;
    #[cfg(test)]
    if let Some(hook) = take_before_final() {
        hook();
    }
    assessment
        .lock
        .revalidate(&assessment.store, &common_path)?;
    let current = {
        let lease = assessment
            .store
            .authority_lease()
            .map_err(|_| "authority_unknown")?;
        lease
            .check(&assessment.store)
            .map_err(|_| "authority_unknown")?;
        let authority = std::sync::Arc::clone(assessment.store.authority_identity());
        let phase = assessment.store.sql_phase();
        let tx = assessment
            .store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|_| "authority_unknown")?;
        let current = snapshot_in_transaction(
            &tx,
            &authority,
            assessment.context.allocation.checkout,
            &mut assessment.budget,
        )
        .map_err(|_| "context_changed")?;
        match assessment.mode {
            ModeKind::Adopted => {
                let mode = approval::AdoptedMode::read(&tx, &current)?;
                if assessment.adopted.as_ref() != Some(&mode) {
                    return Err("mode_changed");
                }
            }
            ModeKind::Supervised => {
                let _ = terminal_candidates(&tx, assessment.context.allocation.checkout)
                    .map_err(|_| "terminal_candidate_unknown")?;
                let completed =
                    !crate::finish::task_open(&tx, assessment.context.allocation.checkout)
                        .map_err(|_| "task_completion_unknown")?;
                if completed != assessment.task_completed {
                    return Err("context_changed");
                }
            }
        }
        #[cfg(test)]
        if take_age_first_observation() {
            if let Some(first) = observations.first_mut() {
                first.age_for_test();
            }
        }
        tx.rollback().map_err(|_| "context_changed")?;
        drop(phase);
        drop(lease);
        current
    };
    if current.canonical != assessment.context.canonical {
        return Err("context_changed");
    }
    if let Some(mut assertion) = assertion {
        assertion.recheck_expiry(&mut assessment.budget)?;
    }
    if assessment.mode == ModeKind::Supervised {
        seal_terminal_observations(&observations, Instant::now())?;
        report.quiescence = "supervised_observed_empty";
    }
    assessment.budget.check().map_err(|_| "deadline")?;
    Ok(())
}

fn seal_terminal_observations(observations: &[TerminalObservation], now: Instant) -> Held<()> {
    let oldest = observations
        .iter()
        .map(TerminalObservation::observed_at)
        .min()
        .ok_or("observation_incomplete")?;
    if now.saturating_duration_since(oldest) >= Duration::from_secs(2) {
        return Err("observation_stale");
    }
    for observed in observations {
        if !observed.completed() {
            return Err("terminal_outcome_incomplete");
        }
        observed.verify_empty(now).map_err(hold_reason)?;
    }
    Ok(())
}

fn production_driver(assessment: &Assessment) -> Held<Driver> {
    let (directory, address) = assessment
        .runtime
        .as_ref()
        .ok_or("supervisor_runtime_unknown")?;
    let context = RuntimeContext::new(directory.clone(), address.clone())
        .map_err(|_| "supervisor_runtime_unknown")?;
    Driver::new(context).map_err(|_| "supervisor_runtime_unknown")
}

fn hold_reason(reason: HoldReason) -> &'static str {
    match reason {
        HoldReason::InvalidBoot | HoldReason::BootMismatch => "boot_mismatch",
        HoldReason::StaleObservation | HoldReason::FutureObservation => "observation_stale",
        HoldReason::UnitUnknown => "unknown_manager",
        HoldReason::UnitMismatch | HoldReason::InvalidInvocation | HoldReason::InvalidCgroup => {
            "scope_identity_unknown"
        }
        HoldReason::ChildIdentity => "pid_reuse",
        HoldReason::MembershipUnknown | HoldReason::IncompleteMembership => {
            "observation_incomplete"
        }
        HoldReason::ParticipantUncertain => "missing_enrollment",
        HoldReason::Populated | HoldReason::ReapedGroupNotAbsent => "populated",
    }
}

#[cfg(test)]
thread_local! {
    static AFTER_PROTECTION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static BEFORE_FINAL: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static EXPIRE_AFTER_IO: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static AGE_FIRST_OBSERVATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn take_after_protection() -> Option<Box<dyn FnOnce()>> {
    AFTER_PROTECTION.with(|slot| slot.borrow_mut().take())
}

#[cfg(test)]
fn take_before_final() -> Option<Box<dyn FnOnce()>> {
    BEFORE_FINAL.with(|slot| slot.borrow_mut().take())
}

#[cfg(test)]
fn take_expire_after_io() -> bool {
    EXPIRE_AFTER_IO.with(|hit| hit.replace(false))
}

#[cfg(test)]
fn take_age_first_observation() -> bool {
    AGE_FIRST_OBSERVATION.with(|hit| hit.replace(false))
}

#[cfg(test)]
pub(super) fn set_after_protection<F: FnOnce() + 'static>(hook: F) {
    AFTER_PROTECTION.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
pub(super) fn set_before_final<F: FnOnce() + 'static>(hook: F) {
    BEFORE_FINAL.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
pub(super) fn set_expire_after_io() {
    EXPIRE_AFTER_IO.with(|hit| hit.set(true));
}

#[cfg(test)]
pub(super) fn set_age_first_observation() {
    AGE_FIRST_OBSERVATION.with(|hit| hit.set(true));
}

#[cfg(test)]
use crate as work_cli_api;
#[cfg(test)]
#[path = "../../tests/support/inspection_fixture.rs"]
mod fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_journal::{RootOutcome, RootRunRequest, TerminalObservation};
    use crate::run_participants::{ChildOutcome, ChildRequest, ExpectedHost};
    use crate::runtime_scope::Binding;
    use crate::scope_driver::{LibraryIo, Limits};
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::Command,
    };
    use work_contract::{RunId, RunRef};

    const BOOT: &str = "550e8400-e29b-41d4-a716-446655440000";

    struct Manager {
        tmp: tempfile::TempDir,
        _bus: std::os::unix::net::UnixListener,
        driver: Driver,
    }
    impl Manager {
        fn empty(r: &RootRunRequest, b: &Binding) -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            fs::create_dir(root.join("runtime")).unwrap();
            fs::set_permissions(root.join("runtime"), fs::Permissions::from_mode(0o700)).unwrap();
            let bus = std::os::unix::net::UnixListener::bind(root.join("runtime/bus")).unwrap();
            fs::create_dir_all(root.join("proc/sys/kernel/random")).unwrap();
            fs::write(root.join("proc/sys/kernel/random/boot_id"), &r.input().boot).unwrap();
            let cg = root
                .join("cg")
                .join(b.identity().cgroup.trim_start_matches('/'));
            fs::create_dir_all(&cg).unwrap();
            fs::write(cg.join("cgroup.procs"), "").unwrap();
            fs::write(cg.join("cgroup.type"), "domain\n").unwrap();
            fs::write(
                root.join("properties"),
                format!(
                    "Id={}\nInvocationID={}\nControlGroup={}\nLoadState=loaded\nActiveState=inactive\n",
                    b.identity().unit,
                    b.identity().invocation,
                    b.identity().cgroup
                ),
            )
            .unwrap();
            fs::write(
                root.join("manager"),
                format!(
                    "#!/bin/sh\nexec /usr/bin/cat '{}'\n",
                    root.join("properties").display()
                ),
            )
            .unwrap();
            fs::set_permissions(root.join("manager"), fs::Permissions::from_mode(0o700)).unwrap();
            let driver = Driver::with_io(
                RuntimeContext::new(
                    root.join("runtime"),
                    format!("unix:path={}/runtime/bus", root.display()),
                )
                .unwrap(),
                LibraryIo {
                    systemctl: root.join("manager"),
                    proc_root: root.join("proc"),
                    cgroup_root: root.join("cg"),
                    between_censuses: None,
                },
                Limits::default(),
            )
            .unwrap();
            Self {
                tmp,
                _bus: bus,
                driver,
            }
        }
        fn process_pid(&self, pid: u32, ticks: u64, group: &str) {
            let p = self.tmp.path().join("proc").join(pid.to_string());
            fs::create_dir_all(&p).unwrap();
            fs::write(
                p.join("stat"),
                format!("{pid} (root) S {} {ticks} 0\n", vec!["0"; 18].join(" ")),
            )
            .unwrap();
            fs::write(p.join("cgroup"), format!("0::{group}\n")).unwrap();
        }
        fn populate(&self, b: &Binding) {
            self.process_pid(4242, 12, &b.identity().cgroup);
            fs::write(
                self.tmp
                    .path()
                    .join("cg")
                    .join(b.identity().cgroup.trim_start_matches('/'))
                    .join("cgroup.procs"),
                "4242\n",
            )
            .unwrap();
        }
        fn clear_members(&self, b: &Binding) {
            fs::write(
                self.tmp
                    .path()
                    .join("cg")
                    .join(b.identity().cgroup.trim_start_matches('/'))
                    .join("cgroup.procs"),
                "",
            )
            .unwrap();
        }
        fn activate(&self) {
            let properties = self.tmp.path().join("properties");
            let text = fs::read_to_string(&properties)
                .unwrap()
                .replace("ActiveState=inactive", "ActiveState=active");
            fs::write(properties, text).unwrap();
        }
        fn deactivate(&self) {
            let properties = self.tmp.path().join("properties");
            let text = fs::read_to_string(&properties)
                .unwrap()
                .replace("ActiveState=active", "ActiveState=inactive");
            fs::write(properties, text).unwrap();
        }
    }

    fn request(checkout: Uuid) -> RootRunRequest {
        serde_json::from_value(serde_json::json!({
            "identity": {
                "checkout": checkout,
                "group": Uuid::now_v7(),
                "run": Uuid::now_v7(),
                "run_ref": format!("run:{}", Uuid::now_v7()),
                "actor": "reviewer-not-owner",
                "parent_run_ref": "external:parent",
                "execution_chain": [{"kind":"executor","system":"test"}]
            },
            "input": {
                "command_digest": vec![1; 32],
                "input_digest": vec![2; 32],
                "context_ref": "context",
                "intent_ref": "intent",
                "boot": BOOT
            }
        }))
        .unwrap()
    }
    fn binding(r: &RootRunRequest) -> Binding {
        use crate::runtime_scope::{
            self, ActiveStatus, ChildIdentity, Coverage, LaunchIntent, LoadStatus, Membership,
            Observation, ScopeIdentity, UnitPresence,
        };
        use std::time::Instant;
        let intent = LaunchIntent::new(r.identity().run.clone(), &r.input().boot).unwrap();
        let identity = ScopeIdentity {
            unit: intent.unit_name().into(),
            invocation: "550e8400e29b41d4a716446655440000".into(),
            cgroup: format!("/test/{}", intent.unit_name()),
        };
        let child = ChildIdentity {
            pid: 42,
            start_ticks: 10,
            boot: r.input().boot.clone(),
            cgroup: identity.cgroup.clone(),
        };
        let now = Instant::now();
        runtime_scope::bind(
            &intent,
            &child,
            &Observation {
                boot: child.boot.clone(),
                observed_at: now,
                unit: UnitPresence::Present {
                    identity,
                    load: LoadStatus::Loaded,
                    active: ActiveStatus::Active,
                },
                membership: Membership::Present(vec![child.clone()]),
                recursive_coverage: Coverage::Complete,
                participant_coverage: Coverage::Unknown,
                participants: vec![],
            },
            now,
            Duration::from_secs(1),
        )
        .unwrap()
    }
    fn remote_config(f: &fixture::ManagedFixture, runtime: &Path) -> PathBuf {
        let remote = f.temp.path().join("backup.git");
        fixture::git(
            f.temp.path(),
            &[
                "init".as_ref(),
                "--bare".as_ref(),
                "--template=".as_ref(),
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
        let path = f.temp.path().join("retirement.toml");
        let bus = format!("unix:path={}/bus", runtime.display());
        fs::write(
            &path,
            format!(
                "store_dir={:?}\ntrusted_registry={:?}\nroots=[{:?}]\n[remote_preservation]\nformat=1\nversion='fixture-v1'\n[[remote_preservation.targets]]\ncommon_dir={:?}\nremote='backup'\nurl={url:?}\nbranch='refs/heads/preserved'\n[supervisor]\nruntime_directory={:?}\nbus_address={bus:?}\nruntime_max_seconds=60\npreexec_ms=100\nclosure_grace_ms=100\ncancel_grace_ms=100\n[capture]\nexecutable=false\n",
                f.temp.path().join("authority"),
                f.temp.path().join("registry"),
                f.root,
                f.common(),
                runtime
            ),
        )
        .unwrap();
        path
    }
    fn close_completed(f: &mut fixture::ManagedFixture) -> (RootRunRequest, Binding, Manager) {
        let r = request(f.allocation.checkout);
        f.store.begin_run(&r).unwrap();
        let b = binding(&r);
        f.store.record_bound(&r, &b).unwrap();
        f.store.record_permit_attempt(&r, &b).unwrap();
        f.store
            .record_root_outcome(&r, RootOutcome::Completed)
            .unwrap();
        let os = Manager::empty(&r, &b);
        let snap = f.store.group_snapshot(&r.identity().run).unwrap();
        let proof = snap.certify_empty(&os.driver, &b).unwrap();
        f.store.close_supervised_group(&snap, &proof).unwrap();
        (r, b, os)
    }
    fn finish_task(f: &fixture::ManagedFixture) {
        let config = crate::config::Config {
            store_dir: Some(f.temp.path().join("authority")),
            trusted_registry: Some(f.temp.path().join("registry")),
            roots: vec![f.root.clone()],
            ..Default::default()
        };
        crate::finish::finish(&config, f.allocation.checkout).unwrap();
    }
    fn git_text(f: &fixture::ManagedFixture, args: &[&str]) -> String {
        let out = Command::new("/usr/bin/git")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(args)
            .current_dir(&f.allocation.destination)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }
    fn enroll(
        f: &mut fixture::ManagedFixture,
        r: &RootRunRequest,
        b: &Binding,
        os: &Manager,
        pid: u32,
        ticks: u64,
    ) -> ChildRequest {
        let c = ChildRequest {
            checkout: r.identity().checkout.clone(),
            group: r.identity().group.clone(),
            run: RunId::generate(),
            run_ref: RunRef::parse(&format!("child:{}", Uuid::now_v7())).unwrap(),
            parent_run: r.identity().run.clone(),
            parent_run_ref: r.identity().run_ref.clone(),
            execution_chain: r.identity().execution_chain.clone(),
            source: None,
            session: None,
            agent: None,
            actor: None,
            expected_host: Some(ExpectedHost {
                boot: BOOT.into(),
                pid,
                start_ticks: ticks,
            }),
        };
        f.store.register_child(r, &c).unwrap();
        os.process_pid(pid, ticks, &b.identity().cgroup);
        os.activate();
        fs::write(
            os.tmp
                .path()
                .join("cg")
                .join(b.identity().cgroup.trim_start_matches('/'))
                .join("cgroup.procs"),
            format!("{pid}\n"),
        )
        .unwrap();
        let proof = f
            .store
            .group_snapshot(&r.identity().run)
            .unwrap()
            .certify_child_enrollment(&os.driver, &c.run, Some(b))
            .unwrap();
        f.store.record_child_enrollment(r, &c, &proof).unwrap();
        fs::remove_dir_all(os.tmp.path().join(format!("proc/{pid}"))).unwrap();
        os.clear_members(b);
        os.deactivate();
        c
    }
    fn pack_recovery_refs(f: &fixture::ManagedFixture) {
        f.git(&["pack-refs".as_ref(), "--all".as_ref()]);
        let root = f.common().join("refs/work-recovery");
        if !root.exists() {
            return;
        }
        fn walk(dir: &Path) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path);
                } else {
                    fs::remove_file(&path).unwrap();
                }
            }
        }
        walk(&root);
    }
    fn first_recovery_ref(f: &fixture::ManagedFixture) -> String {
        git_text(
            f,
            &["for-each-ref", "--format=%(refname)", "refs/work-recovery"],
        )
        .lines()
        .next()
        .expect("recovery ref")
        .to_owned()
    }
    fn prepared_supervised(
        f: &mut fixture::ManagedFixture,
    ) -> (RootRunRequest, Binding, Manager, PathBuf) {
        let (r, b, os) = close_completed(f);
        finish_task(f);
        let config = remote_config(f, &os.tmp.path().join("runtime"));
        let prepared = recovery_refs::prepare_for_assessment(&config, f.allocation.checkout);
        assert!(prepared.prepared(), "{prepared:?}");
        (r, b, os, config)
    }

    #[test]
    fn closed_ordinary_supervised_success_from_public_journal_and_finish() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (r, b, os) = close_completed(&mut f);
        finish_task(&f);
        let config = remote_config(&f, &os.tmp.path().join("runtime"));
        let prepared = recovery_refs::prepare_for_assessment(&config, f.allocation.checkout);
        assert!(prepared.prepared(), "{prepared:?}");
        let before_writers: i64 = {
            let sql =
                rusqlite::Connection::open(f.temp.path().join("authority/store.sqlite")).unwrap();
            sql.query_row("SELECT count(*) FROM writers", [], |row| row.get(0))
                .unwrap()
        };
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert_eq!(
            report.outcome(),
            "prerequisites_complete",
            "{}",
            report.reason()
        );
        assert_eq!(report.mode(), "supervised");
        assert_eq!(report.quiescence(), "supervised_observed_empty");
        assert_eq!(report.task_completion(), "recorded");
        assert!(!report.execution_enabled());
        assert!(!report.retirement_authority());
        assert!(report.writer_charges_retained());
        let after_writers: i64 = {
            let sql =
                rusqlite::Connection::open(f.temp.path().join("authority/store.sqlite")).unwrap();
            sql.query_row("SELECT count(*) FROM writers", [], |row| row.get(0))
                .unwrap()
        };
        assert_eq!(after_writers, before_writers);
        assert!(f.store.group_snapshot(&r.identity().run).is_err());
        let _ = (r, b);
    }

    #[test]
    fn missing_finish_receipt_holds() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os) = close_completed(&mut f);
        let config = remote_config(&f, &os.tmp.path().join("runtime"));
        let _ = recovery_refs::prepare_for_assessment(&config, f.allocation.checkout);
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert_eq!(report.outcome(), "held");
        assert_eq!(report.reason(), "task_completion_missing");
    }

    #[test]
    fn populated_descendants_hold() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, b, os) = close_completed(&mut f);
        finish_task(&f);
        let config = remote_config(&f, &os.tmp.path().join("runtime"));
        let _ = recovery_refs::prepare_for_assessment(&config, f.allocation.checkout);
        os.populate(&b);
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert_eq!(report.outcome(), "held");
        assert_eq!(report.reason(), "populated");
    }

    #[test]
    fn unknown_manager_holds() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os) = close_completed(&mut f);
        finish_task(&f);
        let config = remote_config(&f, &os.tmp.path().join("runtime"));
        let _ = recovery_refs::prepare_for_assessment(&config, f.allocation.checkout);
        fs::write(os.tmp.path().join("manager"), "#!/bin/sh\nexit 1\n").unwrap();
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert_eq!(report.outcome(), "held");
        assert_ne!(report.reason(), "prerequisites_complete");
    }

    #[test]
    fn closing_protection_mutation_holds() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os) = close_completed(&mut f);
        finish_task(&f);
        let config = remote_config(&f, &os.tmp.path().join("runtime"));
        let _ = recovery_refs::prepare_for_assessment(&config, f.allocation.checkout);
        let dest = f.allocation.destination.join("mutated-after-protection");
        set_after_protection(move || {
            fs::write(&dest, b"closing mutation").unwrap();
        });
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert_eq!(report.outcome(), "held");
        assert_ne!(report.reason(), "prerequisites_complete");
    }

    #[test]
    fn assertion_expiry_after_protection_io_holds() {
        let f = fixture::ManagedFixture::recovery("sha1", "2");
        let (config, _) = f.approval();
        let prepared = recovery_refs::prepare_for_assessment(&config, f.allocation.checkout);
        assert!(prepared.prepared(), "{prepared:?}");
        let begin = approval::begin_path(&config, f.allocation.checkout);
        assert_eq!(begin.reason(), "stored", "{}", begin.reason());
        std::thread::sleep(Duration::from_millis(1100));
        let observation = begin.test_receipt_id().expect("baseline");
        let confirm = approval::confirm_path(&config, f.allocation.checkout, observation);
        assert_eq!(confirm.reason(), "stored", "{}", confirm.reason());
        let assertion = confirm.test_receipt_id().expect("assertion");
        set_expire_after_io();
        let report = assess_retirement(&config, f.allocation.checkout, Some(assertion));
        assert_eq!(report.outcome(), "held");
        assert_eq!(report.reason(), "approval_expired");
    }

    #[test]
    fn ordinary_ref_to_existing_head_tree_after_protection_holds() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        let dest = f.allocation.destination.clone();
        let tree = git_text(&f, &["rev-parse", "HEAD^{tree}"]);
        set_after_protection(move || {
            fixture::git(
                &dest,
                &[
                    "update-ref".as_ref(),
                    "refs/heads/extra-tree".as_ref(),
                    tree.as_ref(),
                ],
            );
        });
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert_eq!(report.outcome(), "held");
        assert_ne!(report.reason(), "prerequisites_complete");
    }

    #[test]
    fn config_mutation_after_protection_holds_for_supervised_and_adopted() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        let path = config.clone();
        set_after_protection(move || {
            let text = fs::read_to_string(&path)
                .unwrap()
                .replace("fixture-v1", "fixture-v2");
            fs::write(&path, text).unwrap();
        });
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert_eq!(report.outcome(), "held");
        assert_eq!(report.reason(), "configuration_changed");
        let f = fixture::ManagedFixture::recovery("sha1", "2");
        let (config, _) = f.approval();
        let prepared = recovery_refs::prepare_for_assessment(&config, f.allocation.checkout);
        assert!(prepared.prepared(), "{prepared:?}");
        let begin = approval::begin_path(&config, f.allocation.checkout);
        std::thread::sleep(Duration::from_millis(1100));
        let confirm = approval::confirm_path(
            &config,
            f.allocation.checkout,
            begin.test_receipt_id().expect("baseline"),
        );
        let assertion = confirm.test_receipt_id().expect("assertion");
        let path = config.clone();
        set_after_protection(move || {
            let text = fs::read_to_string(&path)
                .unwrap()
                .replace("fixture-v1", "fixture-v2");
            fs::write(&path, text).unwrap();
        });
        let report = assess_retirement(&config, f.allocation.checkout, Some(assertion));
        assert_eq!(report.outcome(), "held");
        assert_eq!(report.reason(), "configuration_changed");
    }

    #[test]
    fn first_of_two_observations_stale_at_final_sql_holds() {
        let now = Instant::now();
        let mut first = TerminalObservation::timed_for_test(now);
        let second = TerminalObservation::timed_for_test(now);
        first.age_for_test();
        assert_eq!(
            seal_terminal_observations(&[first, second], Instant::now()),
            Err("observation_stale")
        );
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        set_age_first_observation();
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert_eq!(report.outcome(), "held");
        assert_eq!(report.reason(), "observation_stale");
        assert_ne!(report.quiescence(), "supervised_observed_empty");
    }

    #[test]
    fn allocation_lock_replacement_and_recovery_namespace_change_hold() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        let lock = f.temp.path().join("authority/allocation.lock");
        set_before_final(move || {
            let bytes = fs::read(&lock).unwrap();
            let tmp = lock.with_extension("lock.replaced");
            fs::write(&tmp, bytes).unwrap();
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600)).unwrap();
            fs::rename(&tmp, &lock).unwrap();
        });
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert_eq!(report.outcome(), "held");
        assert_eq!(report.reason(), "authority_unknown");
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        let ns = f
            .temp
            .path()
            .join("authority/recovery-preparation-locks-v1");
        set_before_final(move || {
            fs::rename(&ns, ns.with_extension("moved")).unwrap();
        });
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert_eq!(report.outcome(), "held");
        assert_ne!(report.reason(), "prerequisites_complete");
    }

    #[test]
    fn packed_mixed_and_conflicting_recovery_refs() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        pack_recovery_refs(&f);
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert_eq!(
            report.outcome(),
            "prerequisites_complete",
            "{}",
            report.reason()
        );
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        pack_recovery_refs(&f);
        let name = first_recovery_ref(&f);
        let oid = git_text(&f, &["rev-parse", &name]);
        f.git(&["update-ref".as_ref(), name.as_ref(), oid.as_ref()]);
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert_eq!(
            report.outcome(),
            "prerequisites_complete",
            "{}",
            report.reason()
        );
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        let name = first_recovery_ref(&f);
        let tree = git_text(&f, &["rev-parse", "HEAD^{tree}"]);
        f.git(&["update-ref".as_ref(), name.as_ref(), tree.as_ref()]);
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert_eq!(report.outcome(), "held");
        assert!(
            report.reason() == "recovery_ref_conflict"
                || report.reason() == "recovery_namespace_unknown",
            "{}",
            report.reason()
        );
    }

    #[test]
    fn enrolled_child_still_present_escaped_reused_reboot_and_missing() {
        for case in ["present", "escaped", "reused", "reboot"] {
            let mut f = fixture::ManagedFixture::recovery("sha1", "2");
            let r = request(f.allocation.checkout);
            f.store.begin_run(&r).unwrap();
            let b = binding(&r);
            f.store.record_bound(&r, &b).unwrap();
            f.store.record_permit_attempt(&r, &b).unwrap();
            f.store
                .record_root_outcome(&r, RootOutcome::Completed)
                .unwrap();
            let os = Manager::empty(&r, &b);
            let child = enroll(&mut f, &r, &b, &os, 43, 20);
            f.store
                .record_child_outcome(&r, &child, ChildOutcome::Completed)
                .unwrap();
            let snap = f.store.group_snapshot(&r.identity().run).unwrap();
            let proof = snap.certify_empty(&os.driver, &b).unwrap();
            f.store.close_supervised_group(&snap, &proof).unwrap();
            finish_task(&f);
            let config = remote_config(&f, &os.tmp.path().join("runtime"));
            let prepared = recovery_refs::prepare_for_assessment(&config, f.allocation.checkout);
            assert!(prepared.prepared(), "{prepared:?}");
            match case {
                "present" => {
                    os.process_pid(43, 20, &b.identity().cgroup);
                    fs::write(
                        os.tmp
                            .path()
                            .join("cg")
                            .join(b.identity().cgroup.trim_start_matches('/'))
                            .join("cgroup.procs"),
                        "43\n",
                    )
                    .unwrap();
                }
                "escaped" => os.process_pid(43, 20, "/escaped"),
                "reused" => os.process_pid(43, 21, &b.identity().cgroup),
                "reboot" => fs::write(
                    os.tmp.path().join("proc/sys/kernel/random/boot_id"),
                    "650e8400-e29b-41d4-a716-446655440000",
                )
                .unwrap(),
                _ => unreachable!(),
            }
            let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
            assert_eq!(report.outcome(), "held", "{case}");
            let expected = match case {
                "present" => "missing_enrollment",
                "escaped" => "missing_enrollment",
                "reused" => "missing_enrollment",
                "reboot" => "boot_mismatch",
                _ => unreachable!(),
            };
            assert_eq!(report.reason(), expected, "{case}");
        }
    }

    #[test]
    fn shared_remote_change_before_cleanup_holds() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        let dest = f.allocation.destination.clone();
        super::super::remote_proof::set_retirement_observer(move |phase, scratch| {
            if phase != super::super::remote_proof::Phase::BeforeCleanup {
                return;
            }
            fs::write(dest.join("tracked"), b"shared remote change\n").unwrap();
            fixture::git(
                &dest,
                &["commit".as_ref(), "-am".as_ref(), "shared tip".as_ref()],
            );
            fixture::git(
                &dest,
                &[
                    "-c".as_ref(),
                    "protocol.file.allow=always".as_ref(),
                    "push".as_ref(),
                    "backup".as_ref(),
                    "HEAD:refs/heads/preserved".as_ref(),
                ],
            );
            std::os::unix::fs::symlink(&dest, scratch.join("unexpected-link")).unwrap();
        });
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert_eq!(report.outcome(), "held");
        assert_ne!(report.reason(), "prerequisites_complete");
    }
}
