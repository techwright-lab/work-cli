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
    // None only for passive assessment. Future prepare retains its EX owner.
    guard: Option<crate::checkout_guard::CheckoutGuard>,
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
    binding_policy_digest: String,
    policies: ValidatedPolicies,
    lock: recovery_refs::ExistingLock,
    store: Store,
    assertion: Option<Uuid>,
    runtime: Option<(std::path::PathBuf, String)>,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
enum AssessmentReportPhase {
    NegativeDecision(&'static str),
    NoAssessment,
    MetadataComplete,
}

pub(super) struct Collector {
    checkout: Uuid,
    assertion: Option<Uuid>,
    store: Option<Store>,
    guard: Option<crate::checkout_guard::CheckoutGuard>,
    lock: Option<recovery_refs::ExistingLock>,
    mode: Option<ModeKind>,
    adopted: Option<approval::AdoptedMode>,
    terminals: Option<Vec<TerminalCandidate>>,
    task_completed: Option<bool>,
    approval_policy_digest: Option<String>,
    binding_policy_digest: Option<String>,
    policies: Option<ValidatedPolicies>,
    runtime: Option<(std::path::PathBuf, String)>,
    sealed: Option<Assessment>,
    failure: Option<&'static str>,
    // Scoped to this actual collection; never supplies evidence or ownership.
    #[cfg(test)]
    report_observer: Option<Box<dyn FnMut(AssessmentReportPhase)>>,
}
impl Collector {
    fn new(checkout: Uuid, assertion: Option<Uuid>) -> Self {
        Self {
            checkout,
            assertion,
            store: None,
            guard: None,
            lock: None,
            mode: None,
            adopted: None,
            terminals: None,
            task_completed: None,
            approval_policy_digest: None,
            binding_policy_digest: None,
            policies: None,
            runtime: None,
            sealed: None,
            failure: None,
            #[cfg(test)]
            report_observer: None,
        }
    }
    #[cfg(test)]
    fn observe_report(&mut self, phase: AssessmentReportPhase) {
        if let Some(observer) = self.report_observer.as_mut() {
            observer(phase);
        }
    }
    // Private future prepare seam. Does not prepare an intent, mint authority,
    // acquire another guard, or alter the inert public prepare entrypoint.
    pub(super) fn with_exclusive(
        checkout: Uuid,
        assertion: Option<Uuid>,
        store: Store,
        guard: crate::checkout_guard::CheckoutGuard,
    ) -> Held<Self> {
        if !guard.exclusive_held() {
            return Err("exclusive_guard_required");
        }
        guard
            .require_matching(&store, checkout)
            .map_err(|_| "checkout_guard_unavailable")?;
        let mut collector = Self::new(checkout, assertion);
        collector.store = Some(store);
        collector.guard = Some(guard);
        Ok(collector)
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
        let readonly = Store::open_existing_registered_readonly(
            config
                .trusted_registry
                .as_deref()
                .ok_or("authority_unknown")?,
            config.store_dir.as_deref().ok_or("authority_unknown")?,
            &config.roots,
        )
        .map_err(|_| "authority_unknown")?;
        if let Some(guard) = &self.guard {
            // This separate readonly connection must not keep BEGIN open while
            // the retained Store's guard performs filesystem metadata checks.
            {
                let _phase = readonly.sql_phase();
                readonly
                    .conn
                    .execute_batch("ROLLBACK;")
                    .map_err(|_| "authority_unknown")?;
            }
            // Configuration must match the retained guarded authority; never
            // reopen a replacement mutable Store for the prepare collector.
            let retained = self.store.as_ref().ok_or("authority_unknown")?;
            guard
                .require_matching(retained, self.checkout)
                .map_err(|_| "authority_unknown")?;
            let expected = retained.authority_identity();
            let current = readonly.authority_identity();
            if expected.registry() != current.registry()
                || expected.directory != current.directory
                || expected.directory_id != current.directory_id
                || expected.database_id() != current.database_id()
            {
                return Err("authority_unknown");
            }
        } else {
            crate::retirement_journal::require_unfenced(&readonly.conn, self.checkout)
                .map_err(|error| receipts::store_error(error).label())?;
        }
        drop(readonly);
        let (policies, approval_policy_digest, binding_policy_digest) =
            configuration_bindings(document)?;
        let store = match self.store.take() {
            Some(store) => {
                self.guard
                    .as_ref()
                    .ok_or("checkout_guard_unavailable")?
                    .require_matching(&store, self.checkout)
                    .map_err(|_| "authority_unknown")?;
                store
            }
            None => open_configured_store(config).map_err(|_| "authority_unknown")?,
        };
        self.runtime = document
            .recovery_runtime()
            .ok()
            .map(|runtime| (runtime.runtime_directory, runtime.bus_address));
        self.binding_policy_digest = Some(binding_policy_digest);
        self.approval_policy_digest = approval_policy_digest;
        self.policies = Some(policies);
        self.store = Some(store);
        Ok(())
    }
    pub(super) fn context(&mut self, b: &mut Budget) -> Held<Context> {
        let store = self.store.as_mut().ok_or("authority_unknown")?;
        if let Some(guard) = &self.guard {
            guard
                .require_matching(store, self.checkout)
                .map_err(|_| "checkout_guard_unavailable")?;
        }
        store.may_acquire_lease().map_err(|_| "authority_unknown")?;
        let authority = std::sync::Arc::clone(store.authority_identity());
        let schema = store.schema_participation();
        let role = store.schema_role();
        let phase = store.sql_phase();
        let tx = store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|_| "authority_unknown")?;
        // Passive refusal only; never commits an ordinary-activity hold.
        crate::retirement_journal::require_unfenced(&tx, self.checkout).map_err(|error| {
            if self.guard.is_some() && matches!(error, crate::store::StoreError::RetirementFenced) {
                "intent_conflict"
            } else {
                receipts::store_error(error).label()
            }
        })?;
        let context = snapshot_in_transaction(&tx, &authority, &schema, role, self.checkout, b)
            .map_err(|_| "context_unknown")?;
        b.reserve(context.history.len() as u64)
            .map_err(|_| "deadline")?;
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
        if self.guard.is_some() {
            require_prepare_predecessor(&tx, &context, mode)?;
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
            guard: self.guard.take(),
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
            binding_policy_digest: self.binding_policy_digest.take().ok_or("policy_unknown")?,
            policies: self.policies.take().ok_or("inspection_policy_unknown")?,
            lock,
            store,
            assertion: self.assertion,
            runtime: self.runtime.take(),
        });
        Ok(())
    }
}

/// Shared pure policy framing for fresh collection and offline local recapture.
/// The adopted digest is byte-for-byte the existing approval policy convention.
fn configuration_bindings(
    document: &ConfigDocument,
) -> Held<(ValidatedPolicies, Option<String>, String)> {
    let policies = document
        .inspection_policies()
        .map_err(|_| "inspection_policy_unknown")?;
    let remote = serde_json::to_vec(
        &document
            .remote_preservation()
            .map_err(|_| "policy_unknown")?,
    )
    .map_err(|_| "policy_unknown")?;
    let approval_digest = match document.approval() {
        Ok(policy) => {
            let mut bytes = Vec::new();
            frame(&mut bytes, 0, b"work.approval.policy.v1");
            frame(
                &mut bytes,
                1,
                &serde_json::to_vec(&policy).map_err(|_| "approval_policy_unknown")?,
            );
            frame(&mut bytes, 2, policies.canonical_bytes());
            frame(&mut bytes, 3, &remote);
            Some(hex(&Sha256::digest(bytes)))
        }
        Err(_) => None,
    };
    let combined = match &approval_digest {
        Some(digest) => digest.clone(),
        None => {
            let mut bytes = Vec::new();
            frame(&mut bytes, 0, b"work.retirement.policy.without-approval.v1");
            frame(&mut bytes, 1, policies.canonical_bytes());
            frame(&mut bytes, 2, &remote);
            hex(&Sha256::digest(bytes))
        }
    };
    Ok((policies, approval_digest, combined))
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
    // Same pipeline; public assessment drops the private retained outcome.
    collect_retained(
        path,
        Collector::new(checkout, assertion),
        #[cfg(test)]
        driver,
    )
    .0
}

fn collect_retained(
    path: &Path,
    mut collector: Collector,
    #[cfg(test)] driver: Option<&Driver>,
) -> (RetirementAssessmentReport, Option<RetainedDecision>) {
    let checkout = collector.checkout;
    let assertion = collector.assertion;
    let mut audit = preservation::Audit::new(checkout);
    let remote = remote_proof::retirement_path(path, checkout, &mut audit, &mut collector);
    // Audit owns the actual collected Context's participation even when sealing
    // failed. Retain it before finish consumes Audit and decide may drop every
    // Assessment owner; report data must never reconstruct this capability.
    let schema = audit.schema_participation();
    let preservation = audit.finish(remote);
    let mut report = RetirementAssessmentReport::held(checkout);
    report.assertion_id = assertion;
    report.preservation = Some(preservation);
    report.reason = collector.failure.unwrap_or("observation_held");
    let Some(assessment) = collector.sealed.take() else {
        #[cfg(test)]
        {
            collector.observe_report(AssessmentReportPhase::NoAssessment);
            collector.observe_report(AssessmentReportPhase::MetadataComplete);
        }
        drop(schema);
        return (report, None);
    };
    report.mode = match assessment.mode {
        ModeKind::Supervised => "supervised",
        ModeKind::Adopted => "adopted",
    };
    let retained = match decide(
        assessment,
        &mut report,
        #[cfg(test)]
        driver,
    ) {
        Ok(retained) => {
            report.coverage = "complete";
            report.outcome = "prerequisites_complete";
            report.reason = "prerequisites_complete";
            report.cleanup = "complete";
            Some(retained)
        }
        Err(reason) => {
            #[cfg(test)]
            collector.observe_report(AssessmentReportPhase::NegativeDecision(reason));
            report.outcome = "held";
            report.reason = reason;
            None
        }
    };
    report.execution_enabled = false;
    report.retirement_authority = false;
    report.writer_charges_retained = true;
    report.recorded = false;
    #[cfg(test)]
    collector.observe_report(AssessmentReportPhase::MetadataComplete);
    drop(schema);
    (report, retained)
}

/// Owns the decision inputs and their original clocks, including the final
/// recapture previously dropped by decide. Not a receipt or report capability.
struct RetainedDecision {
    assessment: Assessment,
    assertion: Option<approval::AssertionAssessment>,
    observations: Vec<TerminalObservation>,
    closing_census: filesystem::Census,
    closing_inputs: GitInputs,
    closing_recovery: preservation::RecoveryCensus,
}

fn decide(
    mut assessment: Assessment,
    report: &mut RetirementAssessmentReport,
    #[cfg(test)] injected: Option<&Driver>,
) -> Held<RetainedDecision> {
    if let Some(guard) = &assessment.guard {
        guard
            .require_matching(&assessment.store, assessment.context.allocation.checkout)
            .map_err(|_| "checkout_guard_unavailable")?;
    }
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
    recovery_refs::sync_existing_protection(
        &assessment.physical.before.common,
        &mut assessment.census,
        &targets,
        &mut assessment.budget,
    )?;
    #[cfg(test)]
    if let Some(hook) = take_after_protection() {
        hook();
    }
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
                owned = production_driver(&assessment)?;
                &owned
            }
            #[cfg(not(test))]
            {
                owned = production_driver(&assessment)?;
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
    if let Some(guard) = &assessment.guard {
        guard
            .require_matching(&assessment.store, assessment.context.allocation.checkout)
            .map_err(|_| "checkout_guard_unavailable")?;
    }
    {
        let lease = assessment
            .store
            .authority_lease()
            .map_err(|_| "authority_unknown")?;
        lease
            .check(&assessment.store)
            .map_err(|_| "authority_unknown")?;
        let authority = std::sync::Arc::clone(assessment.store.authority_identity());
        let schema = assessment.store.schema_participation();
        let role = assessment.store.schema_role();
        let phase = assessment.store.sql_phase();
        let tx = assessment
            .store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|_| "authority_unknown")?;
        let current = snapshot_in_transaction(
            &tx,
            &authority,
            &schema,
            role,
            assessment.context.allocation.checkout,
            &mut assessment.budget,
        )
        .map_err(|_| "context_changed")?;
        assessment
            .budget
            .reserve(current.history.len() as u64)
            .map_err(|_| "deadline")?;
        if assessment.guard.is_some() {
            require_prepare_predecessor(&tx, &current, assessment.mode)?;
        }
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
        if current.canonical != assessment.context.canonical {
            return Err("context_changed");
        }
        tx.rollback().map_err(|_| "context_changed")?;
        drop(phase);
        drop(lease);
    }
    if let Some(assertion) = assertion.as_mut() {
        assertion.recheck_expiry(&mut assessment.budget)?;
    }
    if assessment.mode == ModeKind::Supervised {
        seal_terminal_observations(&observations, Instant::now())?;
        report.quiescence = "supervised_observed_empty";
    }
    assessment.budget.check().map_err(|_| "deadline")?;
    Ok(RetainedDecision {
        assessment,
        assertion,
        observations,
        closing_census: census,
        closing_inputs: inputs,
        closing_recovery: fresh,
    })
}

fn require_prepare_predecessor(
    tx: &rusqlite::Connection,
    context: &Context,
    mode: ModeKind,
) -> Held<()> {
    crate::retirement_journal::require_unfenced(tx, context.allocation.checkout).map_err(
        |error| {
            if matches!(error, crate::store::StoreError::RetirementFenced) {
                "intent_conflict"
            } else {
                receipts::store_error(error).label()
            }
        },
    )?;
    let (state, ready): (String, bool) = tx
        .query_row(
            "SELECT state,ready FROM checkouts WHERE id=?1",
            [context.allocation.checkout.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| "context_unknown")?;
    // Public finish retains a ready Allocation record but deliberately holds
    // the checkout and clears readiness. This is a retirement-only predecessor
    // check, not ordinary allocation/execution eligibility or quiescence proof.
    // Supervised callers also validate the actual finish receipt and closed
    // roster in this snapshot, then retain/check original driver observations.
    let eligible = match mode {
        ModeKind::Adopted => state == "active" && ready,
        ModeKind::Supervised => state == "held" && !ready,
    };
    if !eligible || context.allocation.stage != "ready" {
        return Err("allocation_not_active");
    }
    Ok(())
}

/// Fresh prepare owner. No Clone/Deserialize, public fields or DTO constructor.
/// Owns EX, Store, common lock and every census through acknowledged commit;
/// all checks spend the original collection Budget. Never deletion authority.
pub(super) struct FreshRetirementAssessment {
    retained: RetainedDecision,
    source_repository: SourceRepository,
    binding: crate::retirement_journal::ImmutableBinding,
}

pub(super) fn collect_fresh_prepare(
    config_path: &Path,
    checkout: Uuid,
    assertion: Option<Uuid>,
    store: Store,
    guard: crate::checkout_guard::CheckoutGuard,
) -> Held<FreshRetirementAssessment> {
    collect_fresh_prepare_inner(
        config_path,
        checkout,
        assertion,
        store,
        guard,
        #[cfg(test)]
        None,
    )
}

pub(super) fn collect_fresh_prepare_inner(
    path: &Path,
    checkout: Uuid,
    assertion: Option<Uuid>,
    store: Store,
    guard: crate::checkout_guard::CheckoutGuard,
    #[cfg(test)] driver: Option<&Driver>,
) -> Held<FreshRetirementAssessment> {
    parse_checkout(&checkout.to_string()).map_err(|_| "invalid_checkout")?;
    if let Some(id) = assertion {
        parse_checkout(&id.to_string()).map_err(|_| "assertion_ineligible")?;
    }
    let collector = Collector::with_exclusive(checkout, assertion, store, guard)?;
    let (report, retained) = collect_retained(
        path,
        collector,
        #[cfg(test)]
        driver,
    );
    // The report cannot create this owner. Only the actual private decide result
    // can cross the seam; report.reason is used solely for negative diagnostics.
    let mut retained = retained.ok_or(report.reason)?;
    let a = &mut retained.assessment;
    if a.context.allocation.stage != "ready" {
        return Err("allocation_not_active");
    }
    let (local, source_repository) = capture_local_binding(
        &a.context,
        a.store.authority_identity(),
        LocalBindingInputs {
            first: &a.physical.first,
            before: &a.physical.before,
            closing_census: &retained.closing_census,
            closing_inputs: &retained.closing_inputs,
            // The final LOCAL capture has a reproducible witness shape; the
            // earlier census also retains synchronization-only absence probes.
            recovery: &retained.closing_recovery,
            manifests: &a.manifests,
            policies: &a.policies,
            combined_policy: &a.binding_policy_digest,
            operator: retained
                .assertion
                .as_ref()
                .map(approval::AssertionAssessment::operator),
        },
        &mut a.budget,
    )?;
    let binding = local.with_history(&a.approval_semantic, &a.approval_invalidation);
    let mut owner = FreshRetirementAssessment {
        retained,
        source_repository,
        binding,
    };
    owner.recheck_before_transaction()?;
    owner.check_commit_freshness()?;
    Ok(owner)
}

impl FreshRetirementAssessment {
    /// Metadata only; copying this fixed-shape record never copies the owner.
    pub(super) fn binding(&self) -> &crate::retirement_journal::ImmutableBinding {
        &self.binding
    }
    pub(super) fn checkout(&self) -> Uuid {
        self.retained.assessment.context.allocation.checkout
    }
    /// Declaration inputs come from the validated assertion and bound SQL task,
    /// never a caller string or allocation owner substituted for the operator.
    pub(super) fn declaration_context(&self) -> Option<(Uuid, &str, &str)> {
        self.retained.assertion.as_ref().map(|assertion| {
            (
                assertion.assertion_id(),
                assertion.operator(),
                self.retained
                    .assessment
                    .context
                    .allocation
                    .request
                    .task
                    .as_str(),
            )
        })
    }
    pub(super) fn context_bindings(&self) -> ([u8; 32], [u8; 32], [u8; 32], u64) {
        let c = &self.retained.assessment.context;
        (
            Sha256::digest(&c.canonical).into(),
            Sha256::digest(&c.source).into(),
            Sha256::digest(&c.history).into(),
            c.history_count,
        )
    }
    /// Recheck the enabled flag against the actually retained configuration,
    /// spending the original Budget outside lease/SQL. No replacement clock.
    pub(super) fn recheck_prepare_configuration(&mut self, path: &Path) -> Held<()> {
        let a = &mut self.retained.assessment;
        let (document, manifest) = remote_proof::load_document(path, &mut a.budget)?;
        if !document
            .retirement_prepare_intents()
            .map_err(|_| "configuration_unknown")?
        {
            return Err("prepare_intents_disabled");
        }
        if manifest.fingerprint() != a.manifests[0].fingerprint()
            || manifest.fingerprint() != a.manifests[1].fingerprint()
        {
            return Err("configuration_changed");
        }
        manifest
            .recheck(&mut a.budget)
            .map_err(|_| "configuration_changed")
    }
    /// Physical/configuration/boot checks belong OUTSIDE the transaction.
    pub(super) fn recheck_before_transaction(&mut self) -> Held<()> {
        let a = &mut self.retained.assessment;
        a.budget.check().map_err(|_| "deadline")?;
        let guard = a.guard.as_ref().ok_or("exclusive_guard_required")?;
        if !guard.exclusive_held() {
            return Err("exclusive_guard_required");
        }
        guard
            .require_matching(&a.store, a.context.allocation.checkout)
            .map_err(|_| "checkout_guard_unavailable")?;
        let identity = a
            .context
            .allocation
            .identity
            .as_ref()
            .ok_or("identity_unknown")?;
        a.lock
            .revalidate(&a.store, identity.common_git_dir.as_os_str().as_bytes())?;
        a.physical
            .recheck(&mut a.budget)
            .map_err(|_| "census_changed")?;
        a.census.recheck(&mut a.budget)?;
        self.retained
            .closing_census
            .recheck(&mut a.budget)
            .map_err(|_| "census_changed")?;
        self.retained
            .closing_inputs
            .recheck(&mut a.budget)
            .map_err(|_| "census_changed")?;
        self.retained.closing_recovery.recheck(&mut a.budget)?;
        for manifest in &a.manifests {
            manifest
                .recheck(&mut a.budget)
                .map_err(|_| "configuration_changed")?;
        }
        self.source_repository.recheck(&mut a.budget)?;
        let boot = filesystem::boot_id(&mut a.budget).map_err(|_| "boot_mismatch")?;
        if boot != a.physical.before.boot || boot != self.retained.closing_inputs.boot {
            return Err("boot_mismatch");
        }
        if let Some(assertion) = &mut self.retained.assertion {
            assertion.recheck_expiry(&mut a.budget)?;
        }
        a.budget.check().map_err(|_| "deadline")
    }
    /// Pure rejection gate for the eventual IMMEDIATE commit boundary. Uses an
    /// actual new Instant, never retimestamps observations or returns a proof DTO.
    pub(super) fn check_commit_freshness(&mut self) -> Held<()> {
        check_commit_freshness(
            self.retained.assessment.mode,
            &mut self.retained.assessment.budget,
            &mut self.retained.assertion,
            &self.retained.observations,
        )
    }

    fn prepare_record(
        &self,
        operation: Uuid,
        task_complete: bool,
    ) -> Held<crate::retirement_journal::IntentRecord> {
        use crate::retirement_journal::{AdoptedDeclaration, IntentRecord, Mode, Stage};
        crate::retirement_journal::parse_uuid(&operation.to_string())
            .map_err(|_| "invalid_operation")?;
        let (predecessor, source, history, count) = self.context_bindings();
        let declaration = match self.declaration_context() {
            Some((assertion, operator, task)) if task_complete => Some(AdoptedDeclaration {
                task: task.to_owned(),
                operator: operator.to_owned(),
                assertion: assertion.to_string(),
                operation: operation.to_string(),
                checkout: self.checkout().to_string(),
                predecessor_hex: hex(&predecessor),
            }),
            Some(_) => return Err("declaration_required"),
            None if task_complete => return Err("declaration_invalid"),
            None => None,
        };
        let mode = match self.retained.assessment.mode {
            ModeKind::Adopted if declaration.is_some() => Mode::Adopted,
            ModeKind::Supervised if declaration.is_none() => Mode::Supervised,
            _ => return Err("mode_changed"),
        };
        Ok(IntentRecord {
            version: 1,
            operation: operation.to_string(),
            checkout: self.checkout().to_string(),
            mode,
            revision: 1,
            stage: Stage::Prepared,
            assertion: declaration.as_ref().map(|d| d.assertion.clone()),
            declaration,
            predecessor_hex: hex(&predecessor),
            source_hex: hex(&source),
            history_predecessor_hex: hex(&history),
            prior_history_count: count,
            immutable_binding: self.binding().clone(),
            quiescence: match mode {
                Mode::Adopted => "asserted",
                Mode::Supervised => "empty",
            }
            .into(),
            task_completion: match mode {
                Mode::Adopted => "adopted_declared",
                Mode::Supervised => "supervised_empty",
            }
            .into(),
            policy_digest: self.binding().inspection_policy.clone(),
            combined_policy_digest: self.binding().combined_policy.clone(),
            prepared_wall_ms: wall_time().map_err(|_| "clock_anomaly")?,
            // collect_retained yields a retained decision only after complete
            // remote cleanup. This is not caller-supplied positive evidence.
            remote_cleanup: "complete".into(),
        })
    }

    pub(super) fn commit_prepared(
        mut self,
        operation: Uuid,
        task_complete: bool,
        #[cfg(test)] fault: PrepareFault,
    ) -> Held<PrepareCommit> {
        use super::retirement_intent::{historical_operation, prepare_store_error};
        use crate::retirement_journal::{self as journal, PreparedInsert};
        let record = self.prepare_record(operation, task_complete)?;
        // Encode once before acquiring the lease; no reservation of disk space.
        let encoded = journal::encode_record(&record).map_err(|_| "record_invalid")?;
        let (predecessor, source, _, count) = self.context_bindings();
        let checkout = self.checkout();
        self.recheck_before_transaction()?;
        {
            // Split actual disjoint owner fields, not a new Store/Budget/clock.
            // The transaction borrows ONLY the retained Store connection, while
            // the pure final rejection gate borrows the original timing inputs.
            let RetainedDecision {
                assessment,
                assertion,
                observations,
                ..
            } = &mut self.retained;
            let Assessment {
                store,
                budget,
                context,
                mode,
                adopted,
                task_completed,
                ..
            } = assessment;
            let lease = store.authority_lease().map_err(|_| "authority_unknown")?;
            lease.check(store).map_err(|_| "authority_unknown")?;
            let authority = std::sync::Arc::clone(store.authority_identity());
            let schema = store.schema_participation();
            let role = store.schema_role();
            let _phase = store.sql_phase();
            let tx = store
                .conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|_| "commit_unknown")?;
            lease
                .check_authority(&authority)
                .map_err(|_| "authority_unknown")?;
            role.validate(&tx).map_err(|_| "authority_unknown")?;
            if let Some((row, count, fence_active)) =
                historical_operation(&tx, checkout, operation)?
            {
                tx.rollback().map_err(|_| "commit_unknown")?;
                return Ok(PrepareCommit::Historical(
                    Box::new(row),
                    count,
                    fence_active,
                ));
            }
            journal::exclude_prepare_operation(&tx, operation).map_err(prepare_store_error)?;
            #[cfg(test)]
            if fault == PrepareFault::ContextMutation {
                tx.execute(
                    "UPDATE checkouts SET task='changed-at-immediate' WHERE id=?1",
                    [checkout.to_string()],
                )
                .unwrap();
            }
            let current = snapshot_in_transaction(&tx, &authority, &schema, role, checkout, budget)
                .map_err(|_| "context_changed")?;
            budget
                .reserve(current.history.len() as u64)
                .map_err(|_| "deadline")?;
            if current.canonical != context.canonical {
                return Err("context_changed");
            }
            require_prepare_predecessor(&tx, &current, *mode)?;
            match mode {
                ModeKind::Adopted => {
                    let current_mode = approval::AdoptedMode::read(&tx, &current)?;
                    if adopted.as_ref() != Some(&current_mode) {
                        return Err("mode_changed");
                    }
                    let declaration = record.declaration.as_ref().ok_or("declaration_required")?;
                    let validated = assertion.as_ref().ok_or("assertion_ineligible")?;
                    if declaration.task != current.allocation.request.task
                        || declaration.operator != validated.operator()
                        || declaration.assertion != validated.assertion_id().to_string()
                        || declaration.operation != operation.to_string()
                        || declaration.checkout != checkout.to_string()
                        || declaration.predecessor_hex != hex(&predecessor)
                    {
                        return Err("declaration_invalid");
                    }
                }
                ModeKind::Supervised => {
                    let terminals = terminal_candidates(&tx, checkout)
                        .map_err(|_| "terminal_candidate_unknown")?;
                    if terminals.is_empty() || terminals.len() != observations.len() {
                        return Err("terminal_candidate_unknown");
                    }
                    if !*task_completed
                        || crate::finish::task_open(&tx, checkout)
                            .map_err(|_| "task_completion_unknown")?
                    {
                        return Err("task_completion_missing");
                    }
                    let invalid: bool = tx
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM writers WHERE checkout=?1)
                            OR EXISTS(SELECT 1 FROM adopted_groups WHERE checkout=?1)
                            OR EXISTS(SELECT 1 FROM capture_runs WHERE checkout=?1)
                            OR EXISTS(SELECT 1 FROM attribution_gaps WHERE checkout=?1)",
                            [checkout.to_string()],
                            |r| r.get(0),
                        )
                        .map_err(|_| "mode_unknown")?;
                    if invalid {
                        return Err("mode_changed");
                    }
                }
            }
            journal::insert_prepared(
                &tx,
                &PreparedInsert {
                    operation,
                    checkout,
                    mode: record.mode,
                    assertion: assertion
                        .as_ref()
                        .map(approval::AssertionAssessment::assertion_id),
                    declared_task: record.declaration.as_ref().map(|d| d.task.clone()),
                    declared_operator: record.declaration.as_ref().map(|d| d.operator.clone()),
                    predecessor,
                    source,
                    record: encoded.clone(),
                },
                &lease,
                &authority,
            )
            .map_err(prepare_store_error)?;
            // Read back every immutable binding/declaration column. The new row
            // never participates in its OWN predecessor/hash; only successor S.
            let inserted = journal::load_operation(&tx, operation).map_err(|_| "record_invalid")?;
            if inserted.record != encoded
                || inserted.checkout != checkout
                || inserted.revision != 1
                || inserted.stage != "prepared"
            {
                return Err("record_invalid");
            }
            #[cfg(test)]
            match fault {
                PrepareFault::ExpireAssertion => assertion
                    .as_mut()
                    .expect("adopted fault")
                    .script_commit_fault_for_test("expiry"),
                PrepareFault::AgeTerminal => observations
                    .first_mut()
                    .expect("supervised fault")
                    .age_for_test(),
                PrepareFault::Deadline => budget.test_elapsed = Some(Duration::from_secs(30)),
                _ => {}
            }
            // NO filesystem/config/Git/driver work between lease acquisition and
            // commit. This is the same pure check used by the owner method above.
            check_commit_freshness(*mode, budget, assertion, observations)?;
            tx.commit().map_err(|_| "commit_unknown")?;
        }
        #[cfg(test)]
        if fault == PrepareFault::LostAck {
            return Err("commit_unknown");
        }
        // The sole constructor is AFTER acknowledged commit. No row decoder,
        // historical retry or uncertainty branch can construct this owner.
        Ok(PrepareCommit::Prepared(Box::new(PreparedRetirement {
            owner: self,
            operation,
            revision: 1,
            mode: record.mode,
            history_count: count + 1,
        })))
    }
}

fn check_commit_freshness(
    mode: ModeKind,
    budget: &mut Budget,
    assertion: &mut Option<approval::AssertionAssessment>,
    observations: &[TerminalObservation],
) -> Held<()> {
    budget.check().map_err(|_| "deadline")?;
    match mode {
        ModeKind::Adopted => assertion
            .as_mut()
            .ok_or("assertion_ineligible")?
            .commit_time(budget)?,
        ModeKind::Supervised => seal_terminal_observations(observations, Instant::now())?,
    }
    budget.check().map_err(|_| "deadline")
}

pub(super) enum PrepareCommit {
    Prepared(Box<PreparedRetirement>),
    Historical(Box<crate::retirement_journal::IntentRow>, u64, bool),
}

/// Non-Clone/non-Serialize/non-Deserialize. Its fresh owner transitively owns EX,
/// the original Store/Budget, common lock, assertion and every observation.
pub(super) struct PreparedRetirement {
    owner: FreshRetirementAssessment,
    operation: Uuid,
    revision: u64,
    mode: crate::retirement_journal::Mode,
    history_count: u64,
}
impl PreparedRetirement {
    pub(super) fn into_report(self) -> super::retirement_intent::RetirementIntentReport {
        let report = super::retirement_intent::committed_report(
            self.owner.checkout(),
            self.operation,
            self.revision,
            self.mode,
            self.history_count,
        );
        // EX remains owned through report construction; no other consumer exists.
        drop(self);
        report
    }
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PrepareFault {
    None,
    ExpireAssertion,
    AgeTerminal,
    Deadline,
    ContextMutation,
    LostAck,
}

/// An abort owns its actual mutable authority and EX from preflight to report.
/// Its one original Budget covers configuration, SQL framing and all LOCAL I/O.
struct OfflineAbort {
    store: Store,
    guard: crate::checkout_guard::CheckoutGuard,
    budget: Budget,
    original: crate::retirement_journal::IntentRow,
}

struct OfflineWitness {
    context: Context,
    lock: recovery_refs::ExistingLock,
    physical: Physical,
    first_recovery: preservation::RecoveryCensus,
    closing_census: filesystem::Census,
    closing_inputs: GitInputs,
    recovery: preservation::RecoveryCensus,
    manifests: [filesystem::Manifest; 2],
    source: SourceRepository,
    policies: ValidatedPolicies,
    combined_policy: String,
    operator: Option<String>,
    local: LocalBinding,
}

pub(super) enum AbortCommit {
    Historical(Box<crate::retirement_journal::IntentRow>, u64, bool),
    Aborted(Box<AbortedRetirement>),
}

/// Acknowledged abort, never a retirement/deletion/readiness capability.
pub(super) struct AbortedRetirement {
    owner: OfflineAbort,
    witness: OfflineWitness,
    row: crate::retirement_journal::IntentRow,
    count: u64,
}
impl AbortedRetirement {
    pub(super) fn into_report(self) -> super::retirement_intent::RetirementIntentReport {
        // Keep both physical/common and EX owners alive through report creation.
        let report = super::retirement_intent::aborted_report(&self.row, self.count);
        let _retained = (&self.owner, &self.witness);
        drop(self);
        report
    }
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AbortFault {
    None,
    Deadline,
    BootChanged,
    LostAck,
    HoldBeforeCommit,
    SourceBeforeCommit,
    CorruptBeforeCommit,
}

/// Strict target selection precedes all physical work. Revision errors and a
/// competitor are NOT validation failures and cannot hold another operation.
fn abort_target(
    conn: &rusqlite::Connection,
    checkout: Uuid,
    operation: Uuid,
    revision: u64,
) -> Held<(crate::retirement_journal::IntentRow, u64, bool)> {
    use crate::retirement_journal as journal;
    journal::require_no_physical_action(conn, operation).map_err(|_| "physical_action_present")?;
    let history = journal::read_history(conn, checkout).map_err(|_| "history_unknown")?;
    let row = journal::find_operation(conn, operation)
        .map_err(|_| "history_unknown")?
        .ok_or("intent_conflict")?;
    if row.checkout != checkout || !(1..=2).contains(&revision) {
        return Err("intent_conflict");
    }
    if row.stage == "aborted" {
        if row.aborted_from != Some(revision as i64) {
            return Err("intent_conflict");
        }
    } else if row.revision != revision as i64 {
        return Err("intent_conflict");
    }
    if !history.iter().any(|entry| entry == &row) {
        return Err("history_unknown");
    }
    let fence_active = history.iter().any(|row| row.stage != "aborted");
    Ok((row, history.len() as u64, fence_active))
}

pub(super) fn abort_offline(
    path: &Path,
    checkout: Uuid,
    operation: Uuid,
    revision: u64,
    #[cfg(test)] fault: AbortFault,
) -> Held<AbortCommit> {
    use crate::retirement_journal::parse_uuid;
    let mut budget = Budget::new();
    // Deliberately do not inspect prepare_intents: routing is independent of it.
    // Its bytes still participate in both unchanged configuration commitments.
    let (document, first_config) = remote_proof::load_document(path, &mut budget)?;
    parse_uuid(&checkout.to_string()).map_err(|_| "invalid_checkout")?;
    parse_uuid(&operation.to_string()).map_err(|_| "invalid_operation")?;
    if !(1..=2).contains(&revision) {
        return Err("intent_conflict");
    }
    let config = document.authority().map_err(|_| "authority_unknown")?;
    let registry = config
        .trusted_registry
        .as_deref()
        .ok_or("authority_unknown")?;
    let dir = config.store_dir.as_deref().ok_or("authority_unknown")?;
    let readonly = Store::open_retirement_readonly(registry, dir, &config.roots)
        .map_err(|_| "authority_unknown")?;
    let (original, count, fence_active) = {
        let _phase = readonly.sql_phase();
        let selected = abort_target(&readonly.conn, checkout, operation, revision)?;
        if selected.0.stage != "aborted" {
            // Keep the actual schema owner and selected DATA, not its BEGIN,
            // across checkout EX. Close within the same bounded SQL phase.
            readonly
                .conn
                .execute_batch("ROLLBACK;")
                .map_err(|_| "history_unknown")?;
        }
        selected
    };
    if original.stage == "aborted" {
        return Ok(AbortCommit::Historical(
            Box::new(original),
            count,
            fence_active,
        ));
    }
    let guard =
        crate::checkout_guard::CheckoutGuard::exclusive(&readonly, checkout).map_err(|error| {
            match error {
                crate::store::StoreError::OperationsInFlight => "operations_in_flight",
                _ => "lock_unknown",
            }
        })?;
    let store = Store::open_retirement_abort_existing(registry, dir, &config.roots)
        .map_err(|_| "authority_unknown")?;
    guard
        .require_matching(&store, checkout)
        .map_err(|_| "lock_unknown")?;
    drop(readonly);
    let mut owner = OfflineAbort {
        store,
        guard,
        budget,
        original,
    };
    // Close the preflight/EX race before treating anything as failed evidence.
    {
        let role = owner.store.schema_role();
        let _phase = owner.store.sql_phase();
        let tx = owner
            .store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|_| "history_unknown")?;
        role.validate(&tx).map_err(|_| "history_unknown")?;
        let (current, count, fence_active) = abort_target(&tx, checkout, operation, revision)?;
        if current.stage == "aborted" {
            tx.rollback().map_err(|_| "history_unknown")?;
            return Ok(AbortCommit::Historical(
                Box::new(current),
                count,
                fence_active,
            ));
        }
        if current != owner.original {
            return Err("intent_conflict");
        }
        tx.rollback().map_err(|_| "history_unknown")?;
    }
    let collected = owner.collect(path, document, first_config);
    let witness = match collected {
        Ok(witness) => witness,
        Err(reason) => {
            owner.hold_failed_validation()?;
            return Err(reason);
        }
    };
    #[cfg(test)]
    let mut witness = witness;
    #[cfg(test)]
    if fault == AbortFault::BootChanged {
        // Corrupt only this invocation's retained observation, then exercise the
        // real boot equality gate. Never provide a caller-positive boot proof.
        witness.closing_inputs.boot = b"changed-boot\n".to_vec();
    }
    if let Err(reason) = owner.recheck(&witness) {
        owner.hold_failed_validation()?;
        return Err(reason);
    }
    #[cfg(test)]
    match fault {
        AbortFault::HoldBeforeCommit => {
            assert!(matches!(
                owner.store.transfer(
                    checkout,
                    "racing-owner",
                    crate::admission::Limits {
                        repository: 10,
                        owner: 10,
                        available_bytes: Some(1 << 30),
                        floor_bytes: 0,
                        warn_bytes: 0,
                    }
                ),
                Err(crate::store::StoreError::RetirementFenced)
            ));
        }
        AbortFault::SourceBeforeCommit => {
            owner
                .store
                .conn
                .execute(
                    "UPDATE checkouts SET task='changed-after-local-capture' WHERE id=?1",
                    [checkout.to_string()],
                )
                .unwrap();
        }
        AbortFault::CorruptBeforeCommit => {
            owner
                .store
                .conn
                .execute(
                    "UPDATE retirement_intents SET record='{}' WHERE operation=?1",
                    [operation.to_string()],
                )
                .unwrap();
        }
        _ => (),
    }
    let result = owner.commit(
        &witness,
        #[cfg(test)]
        fault,
    );
    let (row, count) = match result {
        Ok(result) => result,
        Err(reason) => {
            // Only binding failures qualify. Never swallow a revision conflict,
            // budget/SQL failure or uncertain commit as validation failure.
            if matches!(reason, "history_changed" | "context_changed") {
                owner.hold_failed_validation()?;
            }
            return Err(reason);
        }
    };
    Ok(AbortCommit::Aborted(Box::new(AbortedRetirement {
        owner,
        witness,
        row,
        count,
    })))
}

impl OfflineAbort {
    fn collect(
        &mut self,
        path: &Path,
        document: ConfigDocument,
        first_config: filesystem::Manifest,
    ) -> Held<OfflineWitness> {
        self.budget.check().map_err(|_| "deadline")?;
        let context = {
            let authority = self.guard_authority();
            let schema = self.store.schema_participation();
            let role = self.store.schema_role();
            let _phase = self.store.sql_phase();
            let tx = self
                .store
                .conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
                .map_err(|_| "history_unknown")?;
            role.validate(&tx).map_err(|_| "history_unknown")?;
            let (target, _, _) = abort_target(
                &tx,
                self.original.checkout,
                self.original.operation,
                self.original.revision as u64,
            )?;
            if target != self.original {
                return Err("intent_conflict");
            }
            let context = snapshot_in_transaction(
                &tx,
                &authority,
                &schema,
                role,
                self.original.checkout,
                &mut self.budget,
            )
            .map_err(|_| "context_changed")?;
            self.budget
                .reserve(context.history.len() as u64)
                .map_err(|_| "deadline")?;
            validate_abort_context(&tx, &context, &self.original, &mut self.budget)?;
            tx.rollback().map_err(|_| "history_unknown")?;
            context
        };
        // Acquire existing common lock only after EX, outside any global lease.
        let lock = recovery_refs::ExistingLock::retain(&self.store, &context, &mut self.budget)?;
        let (first_recovery, first, before) =
            preservation::RecoveryCensus::recapture(&context, &mut self.budget)?;
        lock.confirm(
            &self.store,
            &before.common,
            context
                .allocation
                .identity
                .as_ref()
                .ok_or("identity_unknown")?
                .common_git_dir
                .as_os_str()
                .as_bytes(),
        )?;
        lock.matches_census(&first_recovery)?;
        let (recovery, closing_census, closing_inputs) =
            preservation::RecoveryCensus::recapture(&context, &mut self.budget)?;
        let (closing_document, closing_config) =
            remote_proof::load_document(path, &mut self.budget)?;
        let manifests = [first_config, closing_config];
        if manifests[0].fingerprint() != manifests[1].fingerprint() {
            return Err("configuration_changed");
        }
        let (policies, _, combined_policy) = configuration_bindings(&document)?;
        let (_, _, closing_policy) = configuration_bindings(&closing_document)?;
        if combined_policy != closing_policy {
            return Err("configuration_changed");
        }
        let operator = match self.original.decoded.mode {
            crate::retirement_journal::Mode::Adopted => Some(
                document
                    .approval()
                    .map_err(|_| "approval_policy_unknown")?
                    .operator_id,
            ),
            crate::retirement_journal::Mode::Supervised => None,
        };
        let (local, source) = capture_local_binding(
            &context,
            self.store.authority_identity(),
            LocalBindingInputs {
                first: &first,
                before: &before,
                closing_census: &closing_census,
                closing_inputs: &closing_inputs,
                recovery: &recovery,
                manifests: &manifests,
                policies: &policies,
                combined_policy: &combined_policy,
                operator: operator.as_deref(),
            },
            &mut self.budget,
        )?;
        if local != LocalBinding::from_record(&self.original.decoded.immutable_binding) {
            return Err("local_binding_changed");
        }
        let witness = OfflineWitness {
            context,
            lock,
            physical: Physical {
                first,
                before,
                last: None,
            },
            first_recovery,
            closing_census,
            closing_inputs,
            recovery,
            manifests,
            source,
            policies,
            combined_policy,
            operator,
            local,
        };
        self.recheck(&witness)?;
        Ok(witness)
    }

    fn guard_authority(&self) -> std::sync::Arc<crate::store::AuthorityIdentity> {
        std::sync::Arc::clone(self.store.authority_identity())
    }

    fn recheck(&mut self, witness: &OfflineWitness) -> Held<()> {
        self.budget.check().map_err(|_| "deadline")?;
        self.guard
            .require_matching(&self.store, self.original.checkout)
            .map_err(|_| "checkout_guard_unavailable")?;
        if !self.guard.exclusive_held() {
            return Err("exclusive_guard_required");
        }
        let identity = witness
            .context
            .allocation
            .identity
            .as_ref()
            .ok_or("identity_unknown")?;
        witness
            .lock
            .revalidate(&self.store, identity.common_git_dir.as_os_str().as_bytes())?;
        let boot = filesystem::boot_id(&mut self.budget).map_err(|_| "boot_mismatch")?;
        if boot != witness.physical.before.boot || boot != witness.closing_inputs.boot {
            return Err("boot_mismatch");
        }
        witness
            .physical
            .recheck(&mut self.budget)
            .map_err(|_| "census_changed")?;
        witness.first_recovery.recheck(&mut self.budget)?;
        witness
            .closing_census
            .recheck(&mut self.budget)
            .map_err(|_| "census_changed")?;
        witness
            .closing_inputs
            .recheck(&mut self.budget)
            .map_err(|_| "census_changed")?;
        witness.recovery.recheck(&mut self.budget)?;
        for manifest in &witness.manifests {
            manifest
                .recheck(&mut self.budget)
                .map_err(|_| "configuration_changed")?;
        }
        witness.source.recheck(&mut self.budget)?;
        // Retained policies are the same actual decoded inputs used to capture
        // the projection, not historical values substituted for fresh config.
        if witness.local.inspection_policy
            != binding_hash(b"inspection-policy", witness.policies.canonical_bytes())
            || witness.local.combined_policy
                != binding_hash(b"combined-policy", witness.combined_policy.as_bytes())
            || witness.operator.as_deref()
                != self
                    .original
                    .decoded
                    .declaration
                    .as_ref()
                    .map(|d| d.operator.as_str())
        {
            return Err("local_binding_changed");
        }
        self.budget.check().map_err(|_| "deadline")
    }

    fn commit(
        &mut self,
        witness: &OfflineWitness,
        #[cfg(test)] fault: AbortFault,
    ) -> Held<(crate::retirement_journal::IntentRow, u64)> {
        use crate::retirement_journal as journal;
        // No FS/boot/Git/config/driver calls from here through commit. The owned
        // guard and common descriptors remain retained, not reacquired in SQL.
        let schema = self.store.schema_participation();
        let role = self.store.schema_role();
        let lease = crate::allocate::retirement_abort_lease(&self.store)
            .map_err(|_| "authority_unknown")?;
        lease
            .check_abort(&self.store)
            .map_err(|_| "authority_unknown")?;
        let authority = self.guard_authority();
        let _phase = self.store.sql_phase();
        let tx = self
            .store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| "commit_unknown")?;
        lease
            .check_abort_transaction(&tx, &authority)
            .map_err(|_| "authority_unknown")?;
        let (current, count, _) = abort_target(
            &tx,
            self.original.checkout,
            self.original.operation,
            self.original.revision as u64,
        )?;
        if current != self.original {
            return Err("intent_conflict");
        }
        let context = snapshot_in_transaction(
            &tx,
            &authority,
            &schema,
            role,
            self.original.checkout,
            &mut self.budget,
        )
        .map_err(|_| "context_changed")?;
        self.budget
            .reserve(context.history.len() as u64)
            .map_err(|_| "deadline")?;
        if context.canonical != witness.context.canonical {
            return Err("context_changed");
        }
        validate_abort_context(&tx, &context, &self.original, &mut self.budget)?;
        journal::abort_validated(
            &tx,
            self.original.checkout,
            self.original.operation,
            self.original.revision as u64,
            &lease,
            &authority,
        )
        .map_err(super::retirement_intent::prepare_store_error)?;
        let aborted =
            journal::load_operation(&tx, self.original.operation).map_err(|_| "record_invalid")?;
        #[cfg(test)]
        if fault == AbortFault::Deadline {
            self.budget.test_elapsed = Some(Duration::from_secs(30));
        }
        // Pure original-budget rejection immediately before the atomic commit.
        self.budget.check().map_err(|_| "deadline")?;
        tx.commit().map_err(|_| "commit_unknown")?;
        #[cfg(test)]
        if fault == AbortFault::LostAck {
            return Err("commit_unknown");
        }
        Ok((aborted, count))
    }

    fn hold_failed_validation(&mut self) -> Held<()> {
        if self.original.stage != "prepared" {
            return Ok(());
        }
        self.guard
            .require_matching(&self.store, self.original.checkout)
            .map_err(|_| "checkout_guard_unavailable")?;
        let lease = crate::allocate::retirement_abort_lease(&self.store)
            .map_err(|_| "authority_unknown")?;
        lease
            .check_abort(&self.store)
            .map_err(|_| "authority_unknown")?;
        let authority = self.guard_authority();
        let _phase = self.store.sql_phase();
        let tx = self
            .store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| "commit_unknown")?;
        lease
            .check_abort_transaction(&tx, &authority)
            .map_err(|_| "authority_unknown")?;
        let (current, _, _) =
            abort_target(&tx, self.original.checkout, self.original.operation, 1)?;
        // Full strict equality, including immutable bytes and mutable original
        // stage. No rebind, stale-revision hold, competitor hold or corrupt write.
        if current != self.original {
            return Err("intent_conflict");
        }
        crate::retirement_journal::hold_abort_validated(
            &tx,
            current.checkout,
            current.operation,
            &lease,
            &authority,
        )
        .map_err(super::retirement_intent::prepare_store_error)?;
        self.budget.check().map_err(|_| "deadline")?;
        tx.commit().map_err(|_| "commit_unknown")
    }
}

fn validate_abort_context(
    conn: &rusqlite::Connection,
    context: &Context,
    original: &crate::retirement_journal::IntentRow,
    budget: &mut Budget,
) -> Held<()> {
    context.role.validate(conn).map_err(|_| "context_changed")?;
    // Offline abort never projects away a physical fence; even an otherwise
    // well-formed action requires the separate unresolved-physical protocol.
    if context.physical_count != 0 {
        return Err("physical_action_present");
    }
    budget
        .reserve(context.physical_history.len() as u64)
        .map_err(|_| "deadline")?;
    if hex(&Sha256::digest(&context.source)) != original.decoded.source_hex {
        return Err("context_changed");
    }
    let mut predecessor = context.source.clone();
    let (history, count) = crate::retirement_journal::frame_history_without(
        conn,
        original.checkout,
        original.operation,
        &mut predecessor,
    )
    .map_err(|_| "history_unknown")?;
    budget
        .reserve(predecessor.len() as u64)
        .map_err(|_| "deadline")?;
    if count != original.decoded.prior_history_count
        || hex(&Sha256::digest(&history)) != original.decoded.history_predecessor_hex
        || hex(&Sha256::digest(&predecessor)) != original.decoded.predecessor_hex
    {
        return Err("history_changed");
    }
    budget.check().map_err(|_| "deadline")
}

/// Fixed local projection: deliberately NO historical remote-graph hashes.
/// Offline abort must reproduce these fields, not the two approval history hashes.
#[derive(Debug, PartialEq, Eq)]
struct LocalBinding {
    authority_allocation: String,
    source_sql: String,
    managed_physical: String,
    census: String,
    git_private: String,
    local_git: String,
    git_inputs: String,
    source_commitment: String,
    protection: String,
    protection_count: u64,
    config_manifests: [String; 2],
    inspection_policy: String,
    combined_policy: String,
    operator: String,
    source_repository: String,
}
impl LocalBinding {
    fn from_record(binding: &crate::retirement_journal::ImmutableBinding) -> Self {
        Self {
            authority_allocation: binding.authority_allocation.clone(),
            source_sql: binding.source_sql.clone(),
            managed_physical: binding.managed_physical.clone(),
            census: binding.census.clone(),
            git_private: binding.git_private.clone(),
            local_git: binding.local_git.clone(),
            git_inputs: binding.git_inputs.clone(),
            source_commitment: binding.source_commitment.clone(),
            protection: binding.protection.clone(),
            protection_count: binding.protection_count,
            config_manifests: binding.config_manifests.clone(),
            inspection_policy: binding.inspection_policy.clone(),
            combined_policy: binding.combined_policy.clone(),
            operator: binding.operator.clone(),
            source_repository: binding.source_repository.clone(),
        }
    }

    fn with_history(
        &self,
        semantic: &[u8],
        invalidation: &[u8],
    ) -> crate::retirement_journal::ImmutableBinding {
        crate::retirement_journal::ImmutableBinding {
            version: 1,
            authority_allocation: self.authority_allocation.clone(),
            source_sql: self.source_sql.clone(),
            managed_physical: self.managed_physical.clone(),
            census: self.census.clone(),
            git_private: self.git_private.clone(),
            local_git: self.local_git.clone(),
            git_inputs: self.git_inputs.clone(),
            source_commitment: self.source_commitment.clone(),
            approval_semantic: binding_hash(b"approval-semantic", semantic),
            approval_invalidation: binding_hash(b"approval-invalidation", invalidation),
            protection: self.protection.clone(),
            protection_count: self.protection_count,
            config_manifests: self.config_manifests.clone(),
            inspection_policy: self.inspection_policy.clone(),
            combined_policy: self.combined_policy.clone(),
            operator: self.operator.clone(),
            source_repository: self.source_repository.clone(),
        }
    }
}

fn binding_hash(field: &[u8], bytes: &[u8]) -> String {
    let mut framed = Vec::new();
    frame(&mut framed, 0, b"work.retirement.immutable-binding.v1");
    frame(&mut framed, 1, field);
    frame(&mut framed, 2, bytes);
    hex(&Sha256::digest(framed))
}

struct LocalBindingInputs<'a> {
    first: &'a filesystem::Census,
    before: &'a GitInputs,
    closing_census: &'a filesystem::Census,
    closing_inputs: &'a GitInputs,
    recovery: &'a preservation::RecoveryCensus,
    manifests: &'a [filesystem::Manifest; 2],
    policies: &'a ValidatedPolicies,
    combined_policy: &'a str,
    operator: Option<&'a str>,
}

/// Reusable LOCAL collector/projection for the later offline abort stage. Takes
/// actual native inputs, never remote evidence or a reconstructed positive DTO.
/// No fetch, protection creation, synchronization, receipt or SQL mutation.
fn capture_local_binding(
    context: &Context,
    authority: &crate::store::AuthorityIdentity,
    inputs: LocalBindingInputs<'_>,
    budget: &mut Budget,
) -> Held<(LocalBinding, SourceRepository)> {
    budget.check().map_err(|_| "deadline")?;
    let source_repository = SourceRepository::capture(context, inputs.before, budget)?;
    inputs.first.recheck(budget).map_err(|_| "census_changed")?;
    inputs
        .before
        .recheck(budget)
        .map_err(|_| "census_changed")?;
    inputs
        .closing_census
        .recheck(budget)
        .map_err(|_| "census_changed")?;
    inputs
        .closing_inputs
        .recheck(budget)
        .map_err(|_| "census_changed")?;
    inputs.recovery.recheck(budget)?;
    for manifest in inputs.manifests {
        manifest
            .recheck(budget)
            .map_err(|_| "configuration_changed")?;
    }
    let mut authority_bytes = Vec::new();
    frame(
        &mut authority_bytes,
        1,
        authority.registry().as_os_str().as_bytes(),
    );
    frame(
        &mut authority_bytes,
        2,
        authority.directory.as_os_str().as_bytes(),
    );
    let lock = authority.lock_id.ok_or("authority_unknown")?;
    // Only stable authority identity: never authority-dir mtime, DB contents/stat
    // timestamps or checkout-guard metadata, all of which our own commit changes.
    for pair in [authority.directory_id, authority.database_id(), lock] {
        frame(&mut authority_bytes, 3, &pair.0.to_be_bytes());
        frame(&mut authority_bytes, 4, &pair.1.to_be_bytes());
    }
    let a = &context.allocation;
    let allocation = serde_json::to_vec(&(
        a.checkout,
        &a.request,
        &a.destination,
        &a.base_commit,
        &a.identity,
    ))
    .map_err(|_| "identity_unknown")?;
    budget
        .reserve(allocation.len() as u64)
        .map_err(|_| "binding_budget")?;
    frame(&mut authority_bytes, 5, &allocation);
    let mut targets = recovery_refs::verify_existing_protection(inputs.recovery, a.checkout)?;
    targets.sort();
    let mut protection = Vec::new();
    frame(
        &mut protection,
        1,
        inputs.recovery.object_format().as_bytes(),
    );
    let (dev, ino) = inputs.recovery.common_dev_ino();
    frame(&mut protection, 2, &dev.to_be_bytes());
    frame(&mut protection, 3, &ino.to_be_bytes());
    for (reference, oid) in &targets {
        frame(&mut protection, 4, reference.as_bytes());
        frame(&mut protection, 5, oid.as_bytes());
    }
    let mut operator = Vec::new();
    frame(&mut operator, 1, &[u8::from(inputs.operator.is_some())]);
    if let Some(id) = inputs.operator {
        frame(&mut operator, 2, id.as_bytes());
    }
    let result = LocalBinding {
        authority_allocation: binding_hash(b"authority-allocation", &authority_bytes),
        // P_source is the established complete SQL framing, also used by the
        // journal's source column; do not change its hash convention here.
        source_sql: hex(&Sha256::digest(&context.source)),
        managed_physical: binding_hash(b"managed-physical", &inputs.first.fingerprint()),
        census: binding_hash(b"closing-census", &inputs.closing_census.fingerprint()),
        git_private: binding_hash(b"git-private", &inputs.before.private.fingerprint()),
        local_git: binding_hash(b"local-git", &inputs.before.fingerprint()),
        git_inputs: binding_hash(b"closing-git-inputs", &inputs.closing_inputs.fingerprint()),
        source_commitment: binding_hash(
            b"local-source",
            &inputs.recovery.source_commitment(
                inputs.first,
                inputs.before,
                Some(&inputs.manifests[0]),
            ),
        ),
        protection: binding_hash(b"protection", &protection),
        protection_count: targets.len() as u64,
        config_manifests: [
            binding_hash(b"config-first", &inputs.manifests[0].fingerprint()),
            binding_hash(b"config-closing", &inputs.manifests[1].fingerprint()),
        ],
        inspection_policy: binding_hash(b"inspection-policy", inputs.policies.canonical_bytes()),
        combined_policy: binding_hash(b"combined-policy", inputs.combined_policy.as_bytes()),
        operator: binding_hash(b"operator", &operator),
        source_repository: source_repository.digest.clone(),
    };
    source_repository.recheck(budget)?;
    budget.check().map_err(|_| "deadline")?;
    Ok((result, source_repository))
}

/// Forward .git markers name administrative directories, not reverse /.git
/// endpoints. Parse one LF-terminated canonical absolute byte path only; the
/// caller's retained Manifest/Endpoints open and recheck every route no-follow.
fn absolute_admin_directory(bytes: &[u8]) -> Result<PathBuf, IncompleteReason> {
    let raw = line(bytes)?;
    let path = Path::new(std::ffi::OsStr::from_bytes(raw));
    native_anchor_path(path)?;
    Ok(path.to_path_buf())
}

/// Original request.repository, not the managed checkout. Selective identity and
/// link/marker metadata only: no source payload walk or source object traversal.
struct SourceRepository {
    root: filesystem::Manifest,
    private: filesystem::Manifest,
    common: filesystem::Manifest,
    routes: Vec<filesystem::Endpoint>,
    digest: String,
}
impl SourceRepository {
    fn capture(context: &Context, inputs: &GitInputs, budget: &mut Budget) -> Held<Self> {
        let identity = context
            .allocation
            .identity
            .as_ref()
            .ok_or("identity_unknown")?;
        let path = context
            .allocation
            .request
            .repository
            .as_deref()
            .ok_or("source_repository_unknown")?;
        native_anchor_path(path).map_err(|_| "source_repository_unknown")?;
        // snapshot_in_transaction already proves requested alias -> charged common.
        // Independently prove the current source root resolves to that same common.
        if !inputs
            .registrations
            .iter()
            .any(|r| r.path == path.as_os_str().as_bytes() && !r.missing)
        {
            return Err("source_repository_unknown");
        }
        let checked =
            |result: Result<_, IncompleteReason>| result.map_err(|_| "source_repository_changed");
        let mut root = checked(filesystem::Manifest::new(path, budget))?;
        let is_main = root
            .is_directory(b".git", budget)
            .map_err(|_| "source_repository_unknown")?;
        let private_path = if is_main {
            let common = path.join(".git");
            if common != identity.common_git_dir {
                return Err("source_repository_unknown");
            }
            common
        } else {
            let marker = root
                .required_limited(
                    b".git",
                    (MAX_PATH_BYTES + b"gitdir: ".len() + 1) as u64,
                    budget,
                )
                .map_err(|_| "source_repository_unknown")?;
            absolute_admin_directory(
                marker
                    .strip_prefix(b"gitdir: ")
                    .ok_or("source_repository_unknown")?,
            )
            .map_err(|_| "source_repository_unknown")?
        };
        let mut private = checked(filesystem::Manifest::new(&private_path, budget))?;
        let common = checked(filesystem::Manifest::new(&identity.common_git_dir, budget))?;
        if common.root_dev_ino() != inputs.common.root_dev_ino() {
            return Err("source_repository_changed");
        }
        if !is_main {
            let registration = private_path
                .strip_prefix(identity.common_git_dir.join("worktrees"))
                .map_err(|_| "source_repository_unknown")?;
            if registration.as_os_str().is_empty()
                || registration.components().count() != 1
                || private
                    .required(b"commondir", budget)
                    .map_err(|_| "source_repository_unknown")?
                    != b"../..\n"
                || absolute_gitdir(
                    &private
                        .required(b"gitdir", budget)
                        .map_err(|_| "source_repository_unknown")?,
                )
                .map_err(|_| "source_repository_unknown")?
                    != path.join(".git")
            {
                return Err("source_repository_unknown");
            }
        }
        private
            .optional(b"work-lease.json", budget)
            .map_err(|_| "source_repository_unknown")?;
        // Endpoint fingerprints bind route ancestors by identity only, excluding
        // unrelated parent directory churn. The actual roots retain full stats.
        let route_paths = [
            if is_main {
                path.join(".git/HEAD")
            } else {
                path.join(".git")
            },
            private_path.join("HEAD"),
            identity.common_git_dir.join("HEAD"),
        ];
        let mut routes = Vec::new();
        for path in route_paths {
            let route = filesystem::Endpoint::open(&path, budget)
                .map_err(|_| "source_repository_unknown")?;
            if route.missing() {
                return Err("source_repository_unknown");
            }
            routes.push(route);
        }
        let mut bytes = Vec::new();
        for path in [
            path,
            private_path.as_path(),
            identity.common_git_dir.as_path(),
        ] {
            frame(&mut bytes, 1, path.as_os_str().as_bytes());
        }
        for manifest in [&root, &private, &common] {
            frame(&mut bytes, 2, &manifest.fingerprint());
        }
        for route in &routes {
            frame(&mut bytes, 3, &route.fingerprint());
        }
        let result = Self {
            root,
            private,
            common,
            routes,
            digest: binding_hash(b"source-repository", &bytes),
        };
        result.recheck(budget)?;
        Ok(result)
    }
    fn recheck(&self, budget: &mut Budget) -> Held<()> {
        for manifest in [&self.root, &self.private, &self.common] {
            manifest
                .recheck(budget)
                .map_err(|_| "source_repository_changed")?;
        }
        for route in &self.routes {
            route
                .recheck(budget)
                .map_err(|_| "source_repository_changed")?;
        }
        Ok(())
    }
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
use crate::inspection::fixture;

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
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
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
        git_at(&f.allocation.destination, args)
    }
    fn git_at(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("/usr/bin/git")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args([
                "-c",
                "user.name=Owned Fixture",
                "-c",
                "user.email=fixture@invalid",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }
    fn recovery_ref_rows(f: &fixture::ManagedFixture) -> Vec<(String, String)> {
        git_text(
            f,
            &[
                "for-each-ref",
                "--format=%(refname) %(objectname)",
                "refs/work-recovery",
            ],
        )
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (name, oid) = line.split_once(' ').expect("recovery ref oid");
            (name.to_owned(), oid.to_owned())
        })
        .collect()
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

    // Constructor-only evidence. This deliberately stops before any retirement
    // observation; it is not a positive legacy prepare/abort fixture.
    #[test]
    fn legacy16_preobservation_constructor_preserves_native_prerequisites() {
        use crate::store::schema_participation_tests::{
            probe_initialization_exclusive, ExclusiveProbe,
        };
        use std::os::unix::fs::MetadataExt;

        fn rows(conn: &rusqlite::Connection) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
            let mut statement = conn.prepare(
                "SELECT name FROM sqlite_schema WHERE type='table' AND name!='quarantine_actions' ORDER BY name",
            ).unwrap();
            let names = statement
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            names
                .into_iter()
                .map(|name| {
                    let quoted = name.replace('"', "\"\"");
                    let statement = conn
                        .prepare(&format!("SELECT * FROM \"{quoted}\""))
                        .unwrap();
                    let columns = statement.column_count();
                    let ordering = (1..=columns)
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    let mut statement = conn
                        .prepare(&format!("SELECT * FROM \"{quoted}\" ORDER BY {ordering}"))
                        .unwrap();
                    let values = statement
                        .query_map([], |row| {
                            (0..columns)
                                .map(|n| row.get(n))
                                .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
                        })
                        .unwrap()
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .unwrap();
                    (name, values)
                })
                .collect()
        }
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (request, binding, os) = close_completed(&mut f);
        finish_task(&f);
        let config = remote_config(&f, &os.tmp.path().join("runtime"));
        enable_prepare(&config);
        assert!(recovery_refs::prepare_for_assessment(&config, f.allocation.checkout).prepared());
        let registry = f.temp.path().join("registry");
        let directory = f.temp.path().join("authority");
        let configuration = fs::read(&config).unwrap();
        let native = abort_files(&f);
        let marker = fs::read(registry.join("initialization.json")).unwrap();
        let mut identity_paths = vec![
            directory.clone(),
            directory.join("store.sqlite"),
            directory.join("allocation.lock"),
            directory.join("checkout-operations-v1"),
            directory.join(format!(
                "checkout-operations-v1/{}.lock",
                f.allocation.checkout
            )),
            registry.clone(),
            registry.join("initialization.lock"),
            registry.join("initialization.json"),
            registry.join("authorities.sqlite"),
            f.allocation.destination.clone(),
            f.common().to_path_buf(),
            f.private().to_path_buf(),
        ];
        let common_locks = directory.join("recovery-preparation-locks-v1");
        let mut common_lock_paths = fs::read_dir(&common_locks)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        common_lock_paths.sort();
        assert!(
            !common_lock_paths.is_empty(),
            "real native protection must retain its common lock metadata"
        );
        identity_paths.push(common_locks);
        identity_paths.extend(common_lock_paths);
        let registry_rows = || {
            let conn = rusqlite::Connection::open_with_flags(
                registry.join("authorities.sqlite"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .unwrap();
            conn.set_db_config(
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                true,
            )
            .unwrap();
            rows(&conn)
        };
        let before_claims = registry_rows();
        let identities = || {
            identity_paths
                .iter()
                .map(|path| {
                    let meta = fs::symlink_metadata(path).unwrap();
                    (
                        meta.dev(),
                        meta.ino(),
                        meta.mode(),
                        meta.uid(),
                        meta.gid(),
                        meta.nlink(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let before_ids = identities();
        let legacy_ddl = |conn: &rusqlite::Connection| {
            let mut statement = conn.prepare(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE tbl_name!='quarantine_actions' ORDER BY type,name",
            ).unwrap();
            let ddl = statement
                .query_map([], |row| {
                    (0..4)
                        .map(|column| row.get::<_, rusqlite::types::Value>(column))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            ddl
        };
        let (before_rows, before_cookie, before_ddl) = {
            let _phase = f.store.sql_phase();
            crate::store::SchemaRole::Current17
                .validate(&f.store.conn)
                .unwrap();
            let empty: bool = f.store.conn.query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM retirement_intents) AND NOT EXISTS(SELECT 1 FROM quarantine_actions)",
                [], |row| row.get(0),
            ).unwrap();
            assert!(empty);
            let (state, ready): (String, bool) = f
                .store
                .conn
                .query_row(
                    "SELECT state,ready FROM checkouts WHERE id=?1",
                    [f.allocation.checkout.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(state, "held");
            assert!(!ready);
            assert!(!crate::finish::task_open(&f.store.conn, f.allocation.checkout).unwrap());
            assert!(!terminal_candidates(&f.store.conn, f.allocation.checkout)
                .unwrap()
                .is_empty());
            assert!(
                f.store
                    .conn
                    .query_row("SELECT count(*) FROM outbox", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap()
                    > 0
            );
            (
                rows(&f.store.conn),
                f.store
                    .conn
                    .query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                legacy_ddl(&f.store.conn),
            )
        };
        // Keep only owning native resources and historical DATA. No old Driver,
        // terminal proof, Context, Store, checkout or common guard crosses EX.
        let fixture::ManagedFixture {
            temp,
            repo,
            root,
            allocation,
            store,
        } = f;
        let Manager { tmp, _bus, driver } = os;
        drop(driver);
        drop(request);
        drop(binding);
        drop(store);
        let manager_resources = (tmp, _bus);
        assert_eq!(
            probe_initialization_exclusive(&registry).unwrap(),
            ExclusiveProbe::Acquired
        );
        let store = Store::construct_legacy16_preobservation_fixture(
            &registry,
            &directory,
            std::slice::from_ref(&root),
        )
        .unwrap();
        assert_eq!(store.schema_role(), crate::store::SchemaRole::Legacy16Abort);
        assert_eq!(
            probe_initialization_exclusive(&registry).unwrap(),
            ExclusiveProbe::Blocked
        );
        assert!(
            store.authority_lease().is_err(),
            "construction grants no ordinary prepare authority"
        );
        {
            let _phase = store.sql_phase();
            store.schema_role().validate(&store.conn).unwrap();
            assert_eq!(legacy_ddl(&store.conn), before_ddl, "no16 DDL changed");
            assert_eq!(
                rows(&store.conn),
                before_rows,
                "every prerequisite, outbox and sequence row survives"
            );
            let cookie: i64 = store
                .conn
                .query_row("PRAGMA schema_version", [], |row| row.get(0))
                .unwrap();
            assert_ne!(
                cookie, before_cookie,
                "native DROP changes the cookie; it must never be restored"
            );
            let modern: i64 = store.conn.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name IN ('quarantine_actions','quarantine_actions_checkout') OR tbl_name='quarantine_actions'",
                [], |row| row.get(0),
            ).unwrap();
            assert_eq!(modern, 0);
        }
        let f = fixture::ManagedFixture {
            temp,
            repo,
            root,
            allocation,
            store,
        };
        assert_eq!(identities(), before_ids);
        assert_eq!(registry_rows(), before_claims);
        assert_eq!(fs::read(&config).unwrap(), configuration);
        assert_eq!(
            fs::read(registry.join("initialization.json")).unwrap(),
            marker
        );
        assert_eq!(
            abort_files(&f),
            native,
            "native checkout, refs and historical recovery receipts unchanged"
        );
        drop(f.store);
        assert_eq!(
            probe_initialization_exclusive(&registry).unwrap(),
            ExclusiveProbe::Acquired
        );
        drop(manager_resources);
    }

    fn fresh_for_test(
        f: &fixture::ManagedFixture,
        path: &Path,
        assertion: Option<Uuid>,
        driver: Option<&Driver>,
    ) -> FreshRetirementAssessment {
        let store = Store::open_existing_registered_mut(
            &f.temp.path().join("registry"),
            &f.temp.path().join("authority"),
            std::slice::from_ref(&f.root),
        )
        .unwrap();
        let guard =
            crate::checkout_guard::CheckoutGuard::exclusive(&store, f.allocation.checkout).unwrap();
        let result = match driver {
            Some(driver) => collect_fresh_prepare_inner(
                path,
                f.allocation.checkout,
                assertion,
                store,
                guard,
                Some(driver),
            ),
            None => collect_fresh_prepare(path, f.allocation.checkout, assertion, store, guard),
        };
        result.unwrap_or_else(|reason| panic!("fresh collector: {reason}"))
    }

    fn enable_prepare(path: &Path) {
        let mut text = fs::read_to_string(path).unwrap();
        text.push_str("\n[retirement]\nprepare_intents=true\n");
        fs::write(path, text).unwrap();
    }

    fn prepare_test(
        path: &Path,
        checkout: Uuid,
        operation: Uuid,
        assertion: Option<Uuid>,
        task_complete: bool,
        driver: Option<&Driver>,
        fault: PrepareFault,
    ) -> Held<super::retirement_intent::RetirementIntentReport> {
        super::retirement_intent::prepare_inner(
            path,
            checkout,
            operation,
            assertion,
            task_complete,
            driver,
            fault,
        )
    }

    // Test-only raw surface snapshot remains usable when negative tampering makes
    // the strict inspection context intentionally undecodable.
    fn abort_source_rows(store: &Store) -> Vec<String> {
        let mut statement = store.conn.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT IN ('retirement_intents','outbox') ORDER BY name").unwrap();
        let tables: Vec<String> = statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let mut result = Vec::new();
        for table in tables {
            let mut statement = store
                .conn
                .prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))
                .unwrap();
            let columns = statement.column_count();
            let mut rows = statement.query([]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                let values: Vec<_> = (0..columns)
                    .map(|column| format!("{:?}", row.get_ref(column).unwrap()))
                    .collect();
                result.push(format!("{table}:{values:?}"));
            }
        }
        result.sort();
        result
    }

    fn abort_files(f: &fixture::ManagedFixture) -> Vec<u8> {
        fn visit(path: &Path, out: &mut Vec<u8>) {
            use std::os::unix::fs::MetadataExt;
            let metadata = match fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
                Err(error) => panic!("{}: {error}", path.display()),
            };
            frame(out, 1, path.as_os_str().as_bytes());
            for value in [
                metadata.dev(),
                metadata.ino(),
                metadata.mode() as u64,
                metadata.uid() as u64,
                metadata.gid() as u64,
                metadata.nlink(),
                metadata.len(),
                metadata.mtime() as u64,
                metadata.mtime_nsec() as u64,
                metadata.ctime() as u64,
                metadata.ctime_nsec() as u64,
            ] {
                frame(out, 2, &value.to_be_bytes());
            }
            if metadata.is_dir() {
                let mut children: Vec<_> = fs::read_dir(path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .collect();
                children.sort();
                for child in children {
                    visit(&child, out);
                }
            } else if metadata.is_file() {
                frame(out, 3, &Sha256::digest(fs::read(path).unwrap()));
            } else if metadata.file_type().is_symlink() {
                frame(out, 4, fs::read_link(path).unwrap().as_os_str().as_bytes());
            }
        }
        let mut out = Vec::new();
        for path in [
            f.allocation.destination.as_path(),
            f.common(),
            f.temp
                .path()
                .join("authority/inspection-receipts-v1")
                .as_path(),
        ] {
            visit(path, &mut out);
        }
        out
    }

    fn abort_test(
        path: &Path,
        checkout: Uuid,
        operation: Uuid,
        revision: u64,
        fault: AbortFault,
    ) -> Held<super::retirement_intent::RetirementIntentReport> {
        super::retirement_intent::abort_inner(path, checkout, operation, revision, fault)
    }

    fn prepared_adopted_intent() -> (fixture::ManagedFixture, PathBuf, Uuid) {
        let f = fixture::ManagedFixture::recovery("sha1", "2");
        let (config, _) = f.approval();
        enable_prepare(&config);
        assert!(recovery_refs::prepare_for_assessment(&config, f.allocation.checkout).prepared());
        let assertion = approval::assertion_for_retirement_test(&config, f.allocation.checkout);
        let operation = Uuid::now_v7();
        assert!(prepare_test(
            &config,
            f.allocation.checkout,
            operation,
            Some(assertion),
            true,
            None,
            PrepareFault::None
        )
        .unwrap()
        .fresh_commit());
        (f, config, operation)
    }

    #[test]
    fn linked_source_admin_path_is_a_bounded_canonical_byte_path_not_a_reverse_endpoint() {
        for raw in [
            b"/repo/.git/worktrees/source\n".as_slice(),
            b"/repo/.git/worktrees/\xff\n".as_slice(),
        ] {
            assert_eq!(
                absolute_admin_directory(raw)
                    .unwrap()
                    .as_os_str()
                    .as_bytes(),
                &raw[..raw.len() - 1]
            );
            assert!(
                absolute_gitdir(raw).is_err(),
                "reverse endpoint stays strict"
            );
        }
        for raw in [
            b"/repo/.git/worktrees/source".as_slice(),
            b"/repo/.git/worktrees/source\n\n",
            b"/repo/.git/worktrees/source\r\n",
            b"/repo/.git/worktrees/so\nrce\n",
            b"/repo/.git/worktrees/so\0rce\n",
            b"repo/.git/worktrees/source\n",
            b"//repo/.git/worktrees/source\n",
            b"/repo//.git/worktrees/source\n",
            b"/repo/.git/worktrees/../source\n",
            b"/repo/.git/worktrees/./source\n",
            b"/repo/.git/worktrees/source/\n",
            b"/repo/.git/worktrees/source \n",
            b"/\n",
        ] {
            assert!(absolute_admin_directory(raw).is_err(), "{raw:?}");
        }
        let mut oversized = vec![b'/'];
        oversized.extend(std::iter::repeat_n(b'a', MAX_PATH_BYTES));
        oversized.push(b'\n');
        assert!(absolute_admin_directory(&oversized).is_err());
    }

    #[test]
    fn private_linked_source_alias_prepare_and_offline_abort_use_real_allocation() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let source = f.sibling();
        let config = crate::config::Config {
            store_dir: Some(f.temp.path().join("authority")),
            trusted_registry: Some(f.temp.path().join("registry")),
            repositories: vec![source.clone()],
            roots: vec![f.root.clone()],
            allocation: Some(crate::config::AllocationPolicy {
                repository_limit: 10,
                owner_limit: 10,
                floor_bytes: 0,
                warn_bytes: 0,
                capture_sink: None,
            }),
            ..Default::default()
        };
        // Allocate through the linked alias itself, not a rewritten identity DTO.
        f.allocation = crate::allocate::start(
            &config,
            crate::allocate::Start {
                operation: Uuid::now_v7(),
                repository: Some(source.clone()),
                root: Some(f.root.clone()),
                actor: Some("fixture".into()),
                owner: None,
                task: "linked-source-retirement".into(),
                branch: Some("linked-source-retirement".into()),
                base: "HEAD".into(),
                reuse_branch: false,
            },
        )
        .unwrap();
        assert_eq!(
            f.allocation.request.repository.as_deref(),
            Some(source.as_path())
        );
        assert_eq!(f.common(), f.repo.join(".git"));
        assert_eq!(
            fs::read(source.join(".git")).unwrap(),
            format!("gitdir: {}/worktrees/sibling\n", f.common().display()).as_bytes()
        );
        let (path, _) = f.approval();
        enable_prepare(&path);
        assert!(recovery_refs::prepare_for_assessment(&path, f.allocation.checkout).prepared());
        let assertion = approval::assertion_for_retirement_test(&path, f.allocation.checkout);
        let rows = abort_source_rows(&f.store);
        let operation = Uuid::now_v7();
        let events = f.store.pending_events(1000).unwrap().len();
        let prepared = prepare_test(
            &path,
            f.allocation.checkout,
            operation,
            Some(assertion),
            true,
            None,
            PrepareFault::None,
        )
        .unwrap();
        assert!(prepared.fresh_commit());
        assert!(prepared.fence_active());
        let original = crate::retirement_journal::load_operation(&f.store.conn, operation).unwrap();
        let files = abort_files(&f);
        let refs = recovery_ref_rows(&f);
        let remote_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = remote_calls.clone();
        remote_proof::set_retirement_observer(move |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
        });
        let aborted =
            abort_test(&path, f.allocation.checkout, operation, 1, AbortFault::None).unwrap();
        remote_proof::set_retirement_observer(|_, _| {});
        assert_eq!(aborted.outcome(), "aborted");
        assert!(aborted.fresh_commit());
        assert!(!aborted.fence_active());
        assert_eq!(remote_calls.load(Ordering::SeqCst), 0);
        let row = crate::retirement_journal::load_operation(&f.store.conn, operation).unwrap();
        assert_eq!(row.record, original.record);
        assert_eq!(row.aborted_from, Some(1));
        assert_eq!(row.revision, 2);
        assert_eq!(rows, abort_source_rows(&f.store));
        assert_eq!(files, abort_files(&f));
        assert_eq!(refs, recovery_ref_rows(&f));
        assert_eq!(events + 2, f.store.pending_events(1000).unwrap().len());
    }

    #[test]
    fn private_abort_prepared_and_held_restart_exact_retry_and_writer_reconciliation() {
        for attempted_writer in [false, true] {
            let (mut f, config, operation) = prepared_adopted_intent();
            let checkout = f.allocation.checkout;
            let original =
                crate::retirement_journal::load_operation(&f.store.conn, operation).unwrap();
            let source = abort_source_rows(&f.store);
            let files = abort_files(&f);
            let refs = recovery_ref_rows(&f);
            let destination = fs::metadata(&f.allocation.destination).unwrap();
            let mut revision = 1;
            if attempted_writer {
                assert!(matches!(
                    f.store.transfer(
                        checkout,
                        "other-owner",
                        crate::admission::Limits {
                            repository: 10,
                            owner: 10,
                            available_bytes: Some(1 << 30),
                            floor_bytes: 0,
                            warn_bytes: 0
                        }
                    ),
                    Err(crate::store::StoreError::RetirementFenced)
                ));
                revision = 2;
            }
            drop(f.store);
            f.store = Store::open_existing_registered_mut(
                &f.temp.path().join("registry"),
                &f.temp.path().join("authority"),
                &[f.root.clone()],
            )
            .unwrap();
            let events = f.store.pending_events(1000).unwrap().len();
            let status = super::retirement_intent::retirement_status(&config, checkout);
            assert_eq!(status.reason(), "status");
            assert!(status.fence_active());
            assert!(!status.fresh_commit());
            assert_eq!(events, f.store.pending_events(1000).unwrap().len());
            for (wrong_checkout, wrong_operation, wrong_revision) in [
                (Uuid::now_v7(), operation, revision),
                (checkout, Uuid::now_v7(), revision),
                (checkout, operation, if revision == 1 { 2 } else { 1 }),
                (checkout, operation, u64::MAX),
            ] {
                assert_eq!(
                    abort_test(
                        &config,
                        wrong_checkout,
                        wrong_operation,
                        wrong_revision,
                        AbortFault::None
                    )
                    .unwrap_err(),
                    "intent_conflict"
                );
                assert_eq!(events, f.store.pending_events(1000).unwrap().len());
            }
            let report =
                abort_test(&config, checkout, operation, revision, AbortFault::None).unwrap();
            assert_eq!(report.outcome(), "aborted");
            assert!(report.fresh_commit());
            assert!(!report.fence_active());
            let row = crate::retirement_journal::load_operation(&f.store.conn, operation).unwrap();
            assert_eq!(row.record, original.record);
            assert_eq!(row.aborted_from, Some(revision as i64));
            assert_eq!(row.revision, revision as i64 + 1);
            assert_eq!(row.held_reason.is_some(), attempted_writer);
            assert_eq!(source, abort_source_rows(&f.store));
            assert_eq!(files, abort_files(&f));
            assert_eq!(refs, recovery_ref_rows(&f));
            use std::os::unix::fs::MetadataExt;
            let after = fs::metadata(&f.allocation.destination).unwrap();
            assert_eq!(
                (destination.dev(), destination.ino()),
                (after.dev(), after.ino())
            );
            assert_eq!(events + 1, f.store.pending_events(1000).unwrap().len());
            let ex = crate::checkout_guard::CheckoutGuard::exclusive(&f.store, checkout).unwrap();
            let retry =
                abort_test(&config, checkout, operation, revision, AbortFault::None).unwrap();
            assert_eq!(retry.reason(), "historical");
            assert!(!retry.fresh_commit());
            assert!(!retry.fence_active());
            assert_eq!(events + 1, f.store.pending_events(1000).unwrap().len());
            drop(ex);
            f.store
                .transfer(
                    checkout,
                    "other-owner",
                    crate::admission::Limits {
                        repository: 10,
                        owner: 10,
                        available_bytes: Some(1 << 30),
                        floor_bytes: 0,
                        warn_bytes: 0,
                    },
                )
                .unwrap();
        }
    }

    #[test]
    fn private_abort_owns_ex_and_common_through_report_but_not_global_lease() {
        let (mut f, config, operation) = prepared_adopted_intent();
        let checkout = f.allocation.checkout;
        let shared = crate::checkout_guard::CheckoutGuard::shared(&f.store, checkout).unwrap();
        let files = abort_files(&f);
        let rows = abort_source_rows(&f.store);
        let events = f.store.pending_events(1000).unwrap().len();
        assert_eq!(
            abort_test(&config, checkout, operation, 1, AbortFault::None).unwrap_err(),
            "operations_in_flight"
        );
        assert_eq!(
            super::retirement_intent::retirement_status(&config, checkout).reason(),
            "status"
        );
        assert_eq!(events, f.store.pending_events(1000).unwrap().len());
        assert_eq!(files, abort_files(&f));
        drop(shared);
        let AbortCommit::Aborted(aborted) =
            abort_offline(&config, checkout, operation, 1, AbortFault::None).unwrap()
        else {
            panic!("fresh acknowledged abort owner required");
        };
        assert!(matches!(
            crate::checkout_guard::CheckoutGuard::shared(&f.store, checkout),
            Err(crate::store::StoreError::OperationsInFlight)
        ));
        let context = snapshot(&mut f.store, checkout, &mut Budget::new()).unwrap();
        assert!(matches!(
            recovery_refs::ExistingLock::retain(&f.store, &context, &mut Budget::new()),
            Err("preparation_busy")
        ));
        let lease = f.store.authority_lease().unwrap();
        {
            let tx = f
                .store
                .conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            tx.rollback().unwrap();
        }
        drop(lease);
        let report = aborted.into_report();
        assert_eq!(report.outcome(), "aborted");
        assert!(crate::checkout_guard::CheckoutGuard::shared(&f.store, checkout).is_ok());
        assert!(
            recovery_refs::ExistingLock::retain(&f.store, &context, &mut Budget::new()).is_ok()
        );
        assert_eq!(rows, abort_source_rows(&f.store));
        assert_eq!(files, abort_files(&f));
        assert_eq!(events + 1, f.store.pending_events(1000).unwrap().len());
    }

    #[test]
    fn private_abort_lost_ack_and_original_deadline_do_not_claim_clearance() {
        for fault in [
            AbortFault::LostAck,
            AbortFault::Deadline,
            AbortFault::BootChanged,
        ] {
            let (mut f, config, operation) = prepared_adopted_intent();
            let checkout = f.allocation.checkout;
            let source = receipts::collector_source(&mut f.store, checkout);
            let events = f.store.pending_events(1000).unwrap().len();
            let result = abort_test(&config, checkout, operation, 1, fault);
            if fault == AbortFault::LostAck {
                let report = result.unwrap();
                assert_eq!(report.outcome(), "uncertain");
                assert_eq!(
                    serde_json::to_value(&report).unwrap()["recorded"],
                    "unknown"
                );
                assert!(report.fence_active()); // conservative, not a claim of cleared authority
                assert!(!report.fresh_commit());
                let row =
                    crate::retirement_journal::load_operation(&f.store.conn, operation).unwrap();
                assert_eq!(row.stage, "aborted");
                let retry = abort_test(&config, checkout, operation, 1, AbortFault::None).unwrap();
                assert_eq!(retry.reason(), "historical");
                assert!(!retry.fence_active());
                assert!(!retry.fresh_commit());
                assert_eq!(events + 1, f.store.pending_events(1000).unwrap().len());
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    if fault == AbortFault::Deadline {
                        "deadline"
                    } else {
                        "boot_mismatch"
                    }
                );
                assert!(matches!(
                    crate::retirement_journal::require_unfenced(&f.store.conn, checkout),
                    Err(crate::store::StoreError::RetirementFenced)
                ));
                let status = super::retirement_intent::retirement_status(&config, checkout);
                assert!(status.fence_active());
                assert!(!status.fresh_commit());
            }
            assert_eq!(source, receipts::collector_source(&mut f.store, checkout));
        }
    }

    #[test]
    fn private_abort_expired_retained_assertion_does_not_clear_or_renew_the_fence() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (config, _) = f.approval();
        enable_prepare(&config);
        assert!(recovery_refs::prepare_for_assessment(&config, f.allocation.checkout).prepared());
        let assertion = approval::assertion_for_retirement_test(&config, f.allocation.checkout);
        let fresh = fresh_for_test(&f, &config, Some(assertion), None);
        let operation = Uuid::now_v7();
        let PrepareCommit::Prepared(mut prepared) = fresh
            .commit_prepared(operation, true, PrepareFault::None)
            .unwrap()
        else {
            panic!("actual fresh commit required");
        };
        let record = crate::retirement_journal::load_operation(&f.store.conn, operation)
            .unwrap()
            .record;
        // Existing private negative clock seam on the actually retained claim.
        // No sleep, host clock change, rewritten receipt, or new positive proof.
        prepared
            .owner
            .retained
            .assertion
            .as_mut()
            .unwrap()
            .expire_for_test();
        assert_eq!(
            prepared.owner.check_commit_freshness(),
            Err("approval_expired")
        );
        drop(prepared);
        drop(f.store);
        f.store = Store::open_existing_registered_mut(
            &f.temp.path().join("registry"),
            &f.temp.path().join("authority"),
            &[f.root.clone()],
        )
        .unwrap();
        let events = f.store.pending_events(1000).unwrap().len();
        let status = super::retirement_intent::retirement_status(&config, f.allocation.checkout);
        assert!(status.fence_active());
        assert!(!status.fresh_commit());
        assert_eq!(serde_json::to_value(status).unwrap()["stage"], "prepared");
        assert_eq!(events, f.store.pending_events(1000).unwrap().len());
        let row = crate::retirement_journal::load_operation(&f.store.conn, operation).unwrap();
        assert_eq!(row.record, record);
        assert_eq!(row.revision, 1);
        assert_eq!(
            abort_test(
                &config,
                f.allocation.checkout,
                operation,
                1,
                AbortFault::None
            )
            .unwrap()
            .outcome(),
            "aborted"
        );
    }

    #[test]
    fn private_abort_final_cas_rejects_new_hold_source_change_and_corrupt_record() {
        for fault in [
            AbortFault::HoldBeforeCommit,
            AbortFault::SourceBeforeCommit,
            AbortFault::CorruptBeforeCommit,
        ] {
            let (f, config, operation) = prepared_adopted_intent();
            let checkout = f.allocation.checkout;
            let events = f.store.pending_events(1000).unwrap().len();
            let files = abort_files(&f);
            assert_eq!(
                abort_test(&config, checkout, operation, 1, fault).unwrap_err(),
                match fault {
                    AbortFault::HoldBeforeCommit => "intent_conflict",
                    AbortFault::SourceBeforeCommit => "context_changed",
                    AbortFault::CorruptBeforeCommit => "history_unknown",
                    _ => unreachable!(),
                }
            );
            let stage: String = f
                .store
                .conn
                .query_row(
                    "SELECT stage FROM retirement_intents WHERE operation=?1",
                    [operation.to_string()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                stage,
                if fault == AbortFault::CorruptBeforeCommit {
                    "prepared"
                } else {
                    "held"
                }
            );
            assert_eq!(
                events + usize::from(fault != AbortFault::CorruptBeforeCommit),
                f.store.pending_events(1000).unwrap().len()
            );
            assert_eq!(files, abort_files(&f));
            if fault == AbortFault::HoldBeforeCommit {
                let row =
                    crate::retirement_journal::load_operation(&f.store.conn, operation).unwrap();
                assert_eq!(row.held_reason.as_deref(), Some("owner_transfer"));
                assert_eq!(
                    abort_test(&config, checkout, operation, 2, AbortFault::None)
                        .unwrap()
                        .outcome(),
                    "aborted"
                );
            }
        }
    }

    #[test]
    fn private_abort_local_tampering_refuses_and_holds_only_valid_own_record_once() {
        for change in [
            "payload",
            "marker-inode",
            "config-comment",
            "flag-off",
            "policy",
            "operator",
            "ref",
            "protection",
            "object",
            "stat",
            "source-root",
            "source-sql",
            "record",
            "oversize",
        ] {
            let (mut f, config, operation) = prepared_adopted_intent();
            let checkout = f.allocation.checkout;
            match change {
                "payload" => {
                    fs::write(f.allocation.destination.join("tracked"), b"different").unwrap()
                }
                "marker-inode" => {
                    let marker = f
                        .allocation
                        .identity
                        .as_ref()
                        .unwrap()
                        .private_git_dir
                        .join("work-lease.json");
                    let replacement = marker.with_extension("replacement");
                    fs::write(&replacement, fs::read(&marker).unwrap()).unwrap();
                    fs::set_permissions(&replacement, fs::metadata(&marker).unwrap().permissions())
                        .unwrap();
                    fs::rename(replacement, marker).unwrap();
                }
                "config-comment" => {
                    let text = fs::read_to_string(&config).unwrap();
                    fs::write(&config, format!("{text}\n# valid comment\n")).unwrap();
                }
                "flag-off" | "policy" | "operator" => {
                    let text = fs::read_to_string(&config).unwrap();
                    let text = match change {
                        "flag-off" => text.replace("prepare_intents=true", "prepare_intents=false"),
                        "policy" => text.replace("fixture-v1", "fixture-v2"),
                        _ => text.replace("explicit-operator", "different-operator"),
                    };
                    fs::write(&config, text).unwrap();
                }
                "ref" => {
                    git_at(
                        &f.allocation.destination,
                        &["update-ref", "refs/tags/new", "HEAD"],
                    );
                }
                "protection" => {
                    let tree = git_text(&f, &["rev-parse", "HEAD^{tree}"]);
                    let (reference, original_oid) = recovery_ref_rows(&f)
                        .into_iter()
                        .find(|(_, oid)| oid != &tree)
                        .expect("distinct protected target");
                    assert!(reference.ends_with(&format!("/{original_oid}")));
                    git_at(
                        &f.allocation.destination,
                        &["update-ref", &reference, &tree],
                    );
                    assert_eq!(git_text(&f, &["rev-parse", &reference]), tree);
                    // Recovery names bind their leaf OID to the physical target.
                    // This target mutation is rejected by the native namespace
                    // validator BEFORE the narrower existing-target comparison.
                    let mut budget = Budget::new();
                    let context = snapshot(&mut f.store, checkout, &mut budget).unwrap();
                    let (census, _, _) =
                        preservation::RecoveryCensus::recapture(&context, &mut budget).unwrap();
                    assert!(census.reserved_namespace_held());
                    assert_eq!(
                        recovery_refs::verify_existing_protection(&census, checkout).unwrap_err(),
                        "recovery_namespace_unknown"
                    );
                }
                "object" => {
                    git_at(&f.allocation.destination, &["hash-object", "-w", "--stdin"]);
                }
                "stat" | "source-root" => {
                    let path = if change == "stat" {
                        f.allocation.destination.join("tracked")
                    } else {
                        f.allocation.request.repository.clone().unwrap()
                    };
                    let mode = fs::metadata(&path).unwrap().permissions().mode();
                    fs::set_permissions(
                        path,
                        fs::Permissions::from_mode(
                            mode ^ if change == "source-root" {
                                0o010
                            } else {
                                0o100
                            },
                        ),
                    )
                    .unwrap();
                }
                "source-sql" => {
                    f.store
                        .conn
                        .execute(
                            "UPDATE checkouts SET task='tampered' WHERE id=?1",
                            [checkout.to_string()],
                        )
                        .unwrap();
                }
                "oversize" => {
                    f.store
                        .conn
                        .execute_batch("PRAGMA ignore_check_constraints=ON")
                        .unwrap();
                    f.store
                        .conn
                        .execute(
                            "UPDATE retirement_intents SET record=?1 WHERE operation=?2",
                            rusqlite::params!["x".repeat(8193), operation.to_string()],
                        )
                        .unwrap();
                }
                "record" => {
                    f.store
                        .conn
                        .execute(
                            "UPDATE retirement_intents SET record='{}' WHERE operation=?1",
                            [operation.to_string()],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let source = abort_source_rows(&f.store);
            let files = abort_files(&f);
            let refs = recovery_ref_rows(&f);
            let events = f.store.pending_events(1000).unwrap().len();
            let result = abort_test(&config, checkout, operation, 1, AbortFault::None);
            let reason = result.unwrap_err();
            assert_eq!(
                reason,
                match change {
                    "record" | "oversize" => "history_unknown",
                    "source-sql" => "context_changed",
                    "object" => "recovery_target_unknown",
                    "protection" => "recovery_namespace_unknown",
                    _ => "local_binding_changed",
                },
                "{change}"
            );
            let status = super::retirement_intent::retirement_status(&config, checkout);
            assert!(
                status.fence_active(),
                "refusal/corruption is never an absent fence"
            );
            if matches!(change, "record" | "oversize") {
                let wire = serde_json::to_value(&status).unwrap();
                assert_eq!(wire["stage"], "unknown");
                assert_eq!(wire["recorded"], "unknown");
            }
            let (stage, held_reason): (String, Option<String>) = f
                .store
                .conn
                .query_row(
                    "SELECT stage,held_reason FROM retirement_intents WHERE operation=?1",
                    [operation.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(
                stage,
                if matches!(change, "record" | "oversize") {
                    "prepared"
                } else {
                    "held"
                }
            );
            assert_eq!(
                held_reason.as_deref(),
                if matches!(change, "record" | "oversize") {
                    None
                } else {
                    Some("abort_validation_failed")
                }
            );
            assert_eq!(
                events + usize::from(!matches!(change, "record" | "oversize")),
                f.store.pending_events(1000).unwrap().len()
            );
            let repeat = abort_test(
                &config,
                checkout,
                operation,
                if matches!(change, "record" | "oversize") {
                    1
                } else {
                    2
                },
                AbortFault::None,
            );
            assert_eq!(repeat.unwrap_err(), reason);
            assert_eq!(
                events + usize::from(!matches!(change, "record" | "oversize")),
                f.store.pending_events(1000).unwrap().len()
            );
            assert_eq!(source, abort_source_rows(&f.store));
            assert_eq!(files, abort_files(&f));
            assert_eq!(refs, recovery_ref_rows(&f));
        }
    }

    #[test]
    fn private_abort_preserves_all_prior_history_not_only_active_row() {
        fn outbox(store: &Store) -> Vec<(i64, i64, String, i64)> {
            let mut statement = store
                .conn
                .prepare(
                    "SELECT sequence,version,payload,acknowledged FROM outbox ORDER BY sequence",
                )
                .unwrap();
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .unwrap();
            rows.collect::<Result<_, _>>().unwrap()
        }
        for change in [
            "unchanged",
            "delete",
            "corrupt",
            "mutable",
            "add",
            "history-bound",
            "immutable-column",
        ] {
            let mut f = fixture::ManagedFixture::recovery("sha1", "2");
            let checkout = f.allocation.checkout;
            let (config, _) = f.approval();
            enable_prepare(&config);
            assert!(recovery_refs::prepare_for_assessment(&config, checkout).prepared());
            // Retain the actual published ID before prepare A and abort A,
            // without replacing its claim, expiry or context afterward.
            let original_assertion = approval::assertion_for_retirement_test(&config, checkout);
            let original_receipt = receipts::read_receipt(&f.store, original_assertion).unwrap();
            let original_claim = original_receipt
                .approval_record()
                .unwrap()
                .encode()
                .unwrap();
            let first = Uuid::now_v7();
            assert!(prepare_test(
                &config,
                checkout,
                first,
                Some(original_assertion),
                true,
                None,
                PrepareFault::None,
            )
            .unwrap()
            .fresh_commit());
            let first_row =
                crate::retirement_journal::load_operation(&f.store.conn, first).unwrap();
            assert_eq!(
                abort_test(&config, checkout, first, 1, AbortFault::None)
                    .unwrap()
                    .outcome(),
                "aborted"
            );
            if change == "unchanged" {
                let history =
                    crate::retirement_journal::read_history(&f.store.conn, checkout).unwrap();
                let source = abort_source_rows(&f.store);
                let events = outbox(&f.store);
                let files = abort_files(&f);
                let context = snapshot(&mut f.store, checkout, &mut Budget::new()).unwrap();
                assert_eq!(context.history_count, 1);
                assert_eq!(
                    first_row.decoded.source_hex,
                    hex(&Sha256::digest(&context.source))
                );
                assert_ne!(
                    first_row.decoded.predecessor_hex,
                    hex(&Sha256::digest(&context.canonical))
                );
                let stale_operation = Uuid::now_v7();
                assert_eq!(
                    prepare_test(
                        &config,
                        checkout,
                        stale_operation,
                        Some(original_assertion),
                        true,
                        None,
                        PrepareFault::None,
                    )
                    .unwrap_err(),
                    "assertion_invalidated"
                );
                // Real wall/boottime samples AFTER rejection prove this is an
                // otherwise-unexpired published claim, not the expiry fault test.
                let claim: serde_json::Value = serde_json::from_slice(&original_claim).unwrap();
                let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
                let now_ns = u64::try_from(now.tv_sec).unwrap() * 1_000_000_000
                    + u64::try_from(now.tv_nsec).unwrap();
                assert!(wall_time().unwrap() < claim["claim_expiry"]["wall_ms"].as_u64().unwrap());
                assert!(now_ns < claim["claim_expiry"]["boottime_ns"].as_u64().unwrap());
                assert_eq!(
                    original_claim,
                    receipts::read_receipt(&f.store, original_assertion)
                        .unwrap()
                        .approval_record()
                        .unwrap()
                        .encode()
                        .unwrap()
                );
                assert_eq!(
                    history,
                    crate::retirement_journal::read_history(&f.store.conn, checkout).unwrap()
                );
                assert!(!crate::retirement_journal::operation_reserved(
                    &f.store.conn,
                    &stale_operation.to_string()
                )
                .unwrap());
                assert_eq!(source, abort_source_rows(&f.store));
                assert_eq!(events, outbox(&f.store));
                assert_eq!(files, abort_files(&f));
                assert_eq!(
                    context.canonical,
                    snapshot(&mut f.store, checkout, &mut Budget::new())
                        .unwrap()
                        .canonical
                );
            }
            // Only now publish a genuinely new begin/confirm assertion for B.
            let assertion = approval::assertion_for_retirement_test(&config, checkout);
            assert_ne!(assertion, original_assertion);
            let second = Uuid::now_v7();
            let fresh = fresh_for_test(&f, &config, Some(assertion), None);
            let PrepareCommit::Prepared(prepared) = fresh
                .commit_prepared(second, true, PrepareFault::None)
                .unwrap()
            else {
                panic!("genuine fresh B commit required");
            };
            let before_retry =
                crate::retirement_journal::read_history(&f.store.conn, checkout).unwrap();
            let retry_source = abort_source_rows(&f.store);
            let retry_events = outbox(&f.store);
            // Reuse B's actual retained owner solely to reach the final IMMEDIATE
            // historical branch. No fabricated Assessment or new capability.
            let PrepareCommit::Historical(row, count, active) = prepared
                .owner
                .commit_prepared(first, true, PrepareFault::None)
                .unwrap()
            else {
                panic!("historical A cannot mint another prepared owner");
            };
            assert_eq!(row.operation, first);
            assert_eq!(row.stage, "aborted");
            assert_eq!(count, 2);
            assert!(active);
            let historical_prepare = prepare_test(
                &config,
                checkout,
                first,
                Some(original_assertion),
                true,
                None,
                PrepareFault::None,
            )
            .unwrap();
            assert_eq!(historical_prepare.reason(), "historical");
            assert!(!historical_prepare.fresh_commit());
            assert!(historical_prepare.fence_active());
            let wire = serde_json::to_value(historical_prepare).unwrap();
            assert_eq!(wire["stage"], "aborted");
            assert_eq!(wire["history_count"], 2);
            // Exact historical retry never claims a later competing fence cleared.
            let historical = abort_test(&config, checkout, first, 1, AbortFault::None).unwrap();
            assert_eq!(historical.reason(), "historical");
            assert!(!historical.fresh_commit());
            assert!(historical.fence_active());
            assert_eq!(
                before_retry,
                crate::retirement_journal::read_history(&f.store.conn, checkout).unwrap()
            );
            assert_eq!(retry_source, abort_source_rows(&f.store));
            assert_eq!(retry_events, outbox(&f.store));
            let second_row =
                crate::retirement_journal::load_operation(&f.store.conn, second).unwrap();
            assert_eq!(second_row.stage, "prepared");
            assert_eq!(second_row.revision, 1);
            assert!(second_row.held_reason.is_none());
            match change {
                "delete" => {
                    f.store
                        .conn
                        .execute(
                            "DELETE FROM retirement_intents WHERE operation=?1",
                            [first.to_string()],
                        )
                        .unwrap();
                }
                "corrupt" => {
                    f.store
                        .conn
                        .execute(
                            "UPDATE retirement_intents SET record='{}' WHERE operation=?1",
                            [first.to_string()],
                        )
                        .unwrap();
                }
                "mutable" => {
                    f.store.conn.execute("UPDATE retirement_intents SET revision=3,aborted_from=2,held_reason='reserve' WHERE operation=?1", [first.to_string()]).unwrap();
                }
                "immutable-column" => {
                    f.store
                        .conn
                        .execute(
                            "UPDATE retirement_intents SET source=zeroblob(32) WHERE operation=?1",
                            [second.to_string()],
                        )
                        .unwrap();
                }
                "add" | "history-bound" => {
                    // Negative-only raw SQL tamper: copy a genuine tombstone with rewritten identity.
                    let row =
                        crate::retirement_journal::load_operation(&f.store.conn, first).unwrap();
                    for _ in 0..if change == "history-bound" { 63 } else { 1 } {
                        let extra = Uuid::now_v7();
                        let mut record = row.decoded.clone();
                        record.operation = extra.to_string();
                        record.declaration.as_mut().unwrap().operation = extra.to_string();
                        let encoded = crate::retirement_journal::encode_record(&record).unwrap();
                        f.store.conn.execute("INSERT INTO retirement_intents SELECT ?1,checkout,revision,stage,mode,assertion,declared_task,declared_operator,predecessor,source,?2,held_reason,aborted_from FROM retirement_intents WHERE operation=?3",
                            rusqlite::params![extra.to_string(), encoded, first.to_string()]).unwrap();
                    }
                }
                _ => (),
            }
            let source = abort_source_rows(&f.store);
            let files = abort_files(&f);
            let events = f.store.pending_events(1000).unwrap().len();
            if matches!(change, "corrupt" | "immutable-column" | "history-bound") {
                let before = outbox(&f.store);
                assert_eq!(
                    prepare_test(
                        &config,
                        checkout,
                        second,
                        Some(assertion),
                        true,
                        None,
                        PrepareFault::None,
                    )
                    .unwrap_err(),
                    "history_unknown"
                );
                assert_eq!(before, outbox(&f.store));
            }
            let result = abort_test(&config, checkout, second, 1, AbortFault::None);
            if change == "unchanged" {
                assert_eq!(result.unwrap().outcome(), "aborted");
            } else {
                let corrupt = matches!(change, "corrupt" | "immutable-column" | "history-bound");
                assert_eq!(
                    result.unwrap_err(),
                    if corrupt {
                        "history_unknown"
                    } else {
                        "history_changed"
                    }
                );
                assert_eq!(
                    super::retirement_intent::retirement_status(&config, checkout).reason(),
                    if corrupt { "history_unknown" } else { "status" }
                );
                assert_eq!(
                    f.store.pending_events(1000).unwrap().len(),
                    events + usize::from(!corrupt)
                );
            }
            assert_eq!(source, abort_source_rows(&f.store));
            assert_eq!(files, abort_files(&f));
        }
    }

    #[test]
    fn private_abort_supervised_remote_ahead_stays_offline_without_scratch() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        enable_prepare(&config);
        let remote = f.temp.path().join("backup.git");
        let parent = git_at(&remote, &["rev-parse", "refs/heads/preserved"]);
        let tree = git_at(&remote, &["rev-parse", "refs/heads/preserved^{tree}"]);
        let descendant = git_at(
            &remote,
            &["commit-tree", &tree, "-p", &parent, "-m", "remote-only"],
        );
        git_at(
            &remote,
            &["update-ref", "refs/heads/preserved", &descendant],
        );
        let scratch_path = Arc::new(std::sync::Mutex::new(None));
        let captured_path = scratch_path.clone();
        remote_proof::set_retirement_observer(move |phase, path| {
            if phase == remote_proof::Phase::BeforeCleanup {
                *captured_path.lock().unwrap() = Some(path.to_path_buf());
            }
        });
        let operation = Uuid::now_v7();
        assert!(prepare_test(
            &config,
            f.allocation.checkout,
            operation,
            None,
            false,
            Some(&os.driver),
            PrepareFault::None
        )
        .unwrap()
        .fresh_commit());
        let scratch_path = scratch_path
            .lock()
            .unwrap()
            .take()
            .expect("actual remote scratch observed");
        assert!(
            !scratch_path.exists(),
            "prepare removed its remote graph scratch"
        );
        let files = abort_files(&f);
        let source = abort_source_rows(&f.store);
        let absent = Command::new("/usr/bin/git")
            .env_clear()
            .args(["cat-file", "-e", &descendant])
            .current_dir(&f.allocation.destination)
            .output()
            .unwrap();
        assert!(!absent.status.success());
        fs::set_permissions(&remote, fs::Permissions::from_mode(0o0)).unwrap();
        let remote_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = remote_calls.clone();
        remote_proof::set_retirement_observer(move |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
        });
        let report = abort_test(
            &config,
            f.allocation.checkout,
            operation,
            1,
            AbortFault::None,
        )
        .unwrap();
        assert_eq!(report.outcome(), "aborted");
        assert_eq!(remote_calls.load(Ordering::SeqCst), 0);
        assert!(!scratch_path.exists());
        assert_eq!(source, abort_source_rows(&f.store));
        assert_eq!(files, abort_files(&f));
        remote_proof::set_retirement_observer(|_, _| {});
        fs::set_permissions(&remote, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn private_prepare_adopted_commits_real_declaration_and_retains_accounting() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (config, _) = f.approval();
        enable_prepare(&config);
        assert!(recovery_refs::prepare_for_assessment(&config, f.allocation.checkout).prepared());
        let assertion = approval::assertion_for_retirement_test(&config, f.allocation.checkout);
        let predecessor =
            snapshot(&mut f.store, f.allocation.checkout, &mut Budget::new()).unwrap();
        let before = receipts::collector_source(&mut f.store, f.allocation.checkout);
        let events = f.store.pending_events(1000).unwrap().len();
        let operation = Uuid::now_v7();
        let report = prepare_test(
            &config,
            f.allocation.checkout,
            operation,
            Some(assertion),
            true,
            None,
            PrepareFault::None,
        )
        .unwrap();
        assert!(report.fresh_commit(), "{report:?}");
        let row = crate::retirement_journal::load_operation(&f.store.conn, operation).unwrap();
        let declaration = row.decoded.declaration.as_ref().unwrap();
        assert_eq!(declaration.operator, "explicit-operator");
        assert_eq!(declaration.task, f.allocation.request.task);
        assert_eq!(declaration.assertion, assertion.to_string());
        assert_eq!(declaration.operation, operation.to_string());
        assert_eq!(declaration.checkout, f.allocation.checkout.to_string());
        assert_eq!(declaration.predecessor_hex, row.decoded.predecessor_hex);
        assert_eq!(
            row.decoded.predecessor_hex,
            hex(&Sha256::digest(&predecessor.canonical))
        );
        assert_eq!(
            row.decoded.source_hex,
            hex(&Sha256::digest(&predecessor.source))
        );
        assert_eq!(
            row.decoded.history_predecessor_hex,
            hex(&Sha256::digest(&predecessor.history))
        );
        let successor = snapshot(&mut f.store, f.allocation.checkout, &mut Budget::new()).unwrap();
        assert_ne!(
            row.decoded.predecessor_hex,
            hex(&Sha256::digest(&successor.canonical))
        );
        assert_eq!(successor.history_count, 1);
        assert_eq!(
            row.decoded.source_hex,
            row.decoded.immutable_binding.source_sql
        );
        assert_eq!(
            row.decoded.policy_digest,
            row.decoded.immutable_binding.inspection_policy
        );
        assert_eq!(row.decoded.prior_history_count, 0);
        assert_eq!(row.decoded.remote_cleanup, "complete");
        assert_eq!(
            before,
            receipts::collector_source(&mut f.store, f.allocation.checkout)
        );
        assert_eq!(events + 1, f.store.pending_events(1000).unwrap().len());
        let prepared_events = f.store.pending_events(1000).unwrap().into_iter().filter(|pending| {
            matches!(&pending.event, crate::events::Event::RetirementIntentChanged { checkout, operation: id, revision: 1, stage, reason: None }
                if *checkout == f.allocation.checkout && *id == operation && stage == "prepared")
        }).count();
        assert_eq!(prepared_events, 1);
        let writers: i64 = f
            .store
            .conn
            .query_row(
                "SELECT count(*) FROM writers WHERE checkout=?1",
                [f.allocation.checkout.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(writers, 1);
        let wire = serde_json::to_value(report).unwrap();
        assert_eq!(wire["retirement_authority"], false);
        assert_eq!(wire["execution_enabled"], false);
        assert!(wire.get("immutable_binding").is_none());
        assert!(
            crate::checkout_guard::CheckoutGuard::shared(&f.store, f.allocation.checkout).is_ok()
        );

        // Wrong revision must refuse without consuming this prepared fixture.
        let abort = super::retirement_intent::abort_retirement(
            &config,
            f.allocation.checkout,
            operation,
            2,
        );
        assert_eq!(abort.outcome(), "held");
        assert_eq!(abort.reason(), "intent_conflict");
        assert!(!abort.fresh_commit());
        assert!(abort.fence_active());
        assert_eq!(
            crate::retirement_journal::load_operation(&f.store.conn, operation)
                .unwrap()
                .stage,
            "prepared"
        );
        assert_eq!(events + 1, f.store.pending_events(1000).unwrap().len());

        // Retry is read-only, including when EX cannot be acquired. No renewed owner.
        let guard =
            crate::checkout_guard::CheckoutGuard::exclusive(&f.store, f.allocation.checkout)
                .unwrap();
        for stage in ["prepared", "held", "aborted"] {
            if stage == "held" {
                let lease = f.store.authority_lease().unwrap();
                assert!(matches!(
                    crate::retirement_journal::checkpoint(
                        &mut f.store,
                        &lease,
                        crate::retirement_journal::Scope::Checkout(f.allocation.checkout),
                        crate::retirement_journal::Attempt::Reserve
                    ),
                    Err(crate::store::StoreError::RetirementFenced)
                ));
            } else if stage == "aborted" {
                // Structural CAS only: explicitly NOT public/offline abort proof.
                let lease = f.store.authority_lease().unwrap();
                let authority = f.store.authority_identity().clone();
                let tx = f
                    .store
                    .conn
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .unwrap();
                crate::retirement_journal::abort_validated(
                    &tx,
                    f.allocation.checkout,
                    operation,
                    2,
                    &lease,
                    &authority,
                )
                .unwrap();
                tx.commit().unwrap();
            }
            let events = f.store.pending_events(1000).unwrap().len();
            let retry = prepare_test(
                &config,
                f.allocation.checkout,
                operation,
                Some(assertion),
                true,
                None,
                PrepareFault::None,
            )
            .unwrap();
            assert!(!retry.fresh_commit());
            assert_eq!(retry.outcome(), "existing");
            assert_eq!(serde_json::to_value(retry).unwrap()["stage"], stage);
            assert_eq!(events, f.store.pending_events(1000).unwrap().len());
            if stage != "aborted" {
                assert_eq!(
                    prepare_test(
                        &config,
                        f.allocation.checkout,
                        Uuid::now_v7(),
                        Some(assertion),
                        true,
                        None,
                        PrepareFault::None
                    )
                    .unwrap_err(),
                    "intent_conflict"
                );
                assert_eq!(
                    crate::retirement_journal::load_operation(&f.store.conn, operation)
                        .unwrap()
                        .stage,
                    stage
                );
            }
            assert_eq!(
                prepare_test(
                    &config,
                    Uuid::now_v7(),
                    operation,
                    Some(assertion),
                    true,
                    None,
                    PrepareFault::None
                )
                .unwrap_err(),
                "intent_conflict"
            );
        }
        drop(guard);
        let events = f.store.pending_events(1000).unwrap().len();
        f.store
            .conn
            .execute(
                "UPDATE retirement_intents SET record='{}' WHERE operation=?1",
                [operation.to_string()],
            )
            .unwrap();
        assert_eq!(
            prepare_test(
                &config,
                f.allocation.checkout,
                operation,
                Some(assertion),
                true,
                None,
                PrepareFault::None
            )
            .unwrap_err(),
            "history_unknown"
        );
        assert_eq!(events, f.store.pending_events(1000).unwrap().len());
    }

    #[test]
    fn private_prepare_supervised_uses_actual_closed_roster_and_final_age_gate() {
        for fault in [PrepareFault::None, PrepareFault::AgeTerminal] {
            let mut f = fixture::ManagedFixture::recovery("sha1", "2");
            let (_r, _b, os, config) = prepared_supervised(&mut f);
            enable_prepare(&config);
            // Actual public finish leaves the allocation record ready, but its
            // checkout held and non-ready. Never rewrite it to active to prepare.
            let (state, ready): (String, bool) = f
                .store
                .conn
                .query_row(
                    "SELECT state,ready FROM checkouts WHERE id=?1",
                    [f.allocation.checkout.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(state, "held");
            assert!(!ready);
            assert!(!crate::finish::task_open(&f.store.conn, f.allocation.checkout).unwrap());
            let source_rows = abort_source_rows(&f.store);
            let source = receipts::collector_source(&mut f.store, f.allocation.checkout);
            let events = f.store.pending_events(1000).unwrap().len();
            let operation = Uuid::now_v7();
            let result = prepare_test(
                &config,
                f.allocation.checkout,
                operation,
                None,
                false,
                Some(&os.driver),
                fault,
            );
            if fault == PrepareFault::None {
                assert!(result.unwrap().fresh_commit());
                let row =
                    crate::retirement_journal::load_operation(&f.store.conn, operation).unwrap();
                assert_eq!(row.mode, "supervised");
                assert!(row.decoded.declaration.is_none());
                assert_eq!(events + 1, f.store.pending_events(1000).unwrap().len());
            } else {
                assert_eq!(result.unwrap_err(), "observation_stale");
                assert!(!crate::retirement_journal::operation_reserved(
                    &f.store.conn,
                    &operation.to_string()
                )
                .unwrap());
                assert_eq!(events, f.store.pending_events(1000).unwrap().len());
            }
            assert_eq!(
                source,
                receipts::collector_source(&mut f.store, f.allocation.checkout)
            );
            assert_eq!(source_rows, abort_source_rows(&f.store));
        }
    }

    #[test]
    fn post_open_prepare_retry_rejects_counterfeit_legacy_drift() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_request, _binding, os, config) = prepared_supervised(&mut f);
        enable_prepare(&config);
        let checkout = f.allocation.checkout;
        let operation = Uuid::now_v7();
        assert!(prepare_test(
            &config,
            checkout,
            operation,
            None,
            false,
            Some(&os.driver),
            PrepareFault::None
        )
        .unwrap()
        .fresh_commit());
        let mut retry_store = Store::open_existing_registered_mut(
            &f.temp.path().join("registry"),
            &f.temp.path().join("authority"),
            std::slice::from_ref(&f.root),
        )
        .unwrap();
        assert_eq!(
            retry_store.schema_role(),
            crate::store::SchemaRole::Current17
        );
        let original = crate::retirement_journal::load_operation(&f.store.conn, operation).unwrap();
        let source = abort_source_rows(&f.store);
        let outbox = |conn: &rusqlite::Connection| {
            let mut stmt = conn
                .prepare(
                    "SELECT sequence,version,payload,acknowledged FROM outbox ORDER BY sequence",
                )
                .unwrap();
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            rows
        };
        // Raw negative-fixture observation remains available after pin drift;
        // the normal Store outbox reader must itself reject that drift.
        let events = outbox(&f.store.conn);
        let files = abort_files(&f);
        let native_cookie: i64 = f
            .store
            .conn
            .query_row("PRAGMA schema_version", [], |row| row.get(0))
            .unwrap();
        // This is the same helper called after the production mutable open.
        let control = super::retirement_intent::post_open_prepare_retry(
            &mut retry_store,
            checkout,
            operation,
        )
        .unwrap()
        .unwrap();
        assert_eq!(control, (original.clone(), 1, true));
        assert!(retry_store.conn.is_autocommit());
        assert_eq!(abort_source_rows(&f.store), source);
        assert_eq!(outbox(&f.store.conn), events);
        assert_eq!(
            f.store
                .conn
                .query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            native_cookie
        );

        // COUNTERFEIT negative drift only: this record was prepared on17. Drop
        // only17 DDL so metadata readers accept16, without restoring the native
        // cookie or claiming genuine16 preparation/offline-abort permission.
        f.store
            .conn
            .execute_batch("DROP TABLE quarantine_actions; PRAGMA user_version=16;")
            .unwrap();
        let drift_cookie: i64 = f
            .store
            .conn
            .query_row("PRAGMA schema_version", [], |row| row.get(0))
            .unwrap();
        assert_ne!(drift_cookie, native_cookie);
        let source = abort_source_rows(&f.store);
        // A generic version-aware history read really can take the shortcut;
        // only the actual Store pin must prevent the post-open retry here.
        assert_eq!(
            super::retirement_intent::historical_operation(&f.store.conn, checkout, operation)
                .unwrap(),
            Some((original.clone(), 1, true))
        );
        let result = super::retirement_intent::post_open_prepare_retry(
            &mut retry_store,
            checkout,
            operation,
        );
        assert_eq!(result.unwrap_err(), "history_unknown");
        assert!(retry_store.conn.is_autocommit());
        assert_eq!(
            crate::retirement_journal::load_operation(&f.store.conn, operation).unwrap(),
            original
        );
        assert_eq!(abort_source_rows(&f.store), source);
        assert_eq!(outbox(&f.store.conn), events);
        assert_eq!(abort_files(&f), files);
        assert_eq!(
            f.store
                .conn
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            16
        );
        assert_eq!(
            f.store
                .conn
                .query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            drift_cookie
        );
    }

    #[test]
    fn global_missing_action_refuses_ack_abort_and_scoped_shortcuts() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_request, _binding, os, config) = prepared_supervised(&mut f);
        enable_prepare(&config);
        let operation = Uuid::now_v7();
        let prepared = prepare_test(
            &config,
            f.allocation.checkout,
            operation,
            None,
            false,
            Some(&os.driver),
            PrepareFault::None,
        )
        .unwrap();
        assert!(prepared.fresh_commit());
        let events = f.store.pending_events(1000).unwrap();
        let sequence = events.last().unwrap().sequence;
        let original = crate::retirement_journal::load_operation(&f.store.conn, operation).unwrap();
        f.store.acknowledge(sequence).unwrap();
        assert_eq!(
            crate::retirement_journal::load_operation(&f.store.conn, operation).unwrap(),
            original,
            "notification ACK must never hold a prepared intent"
        );
        let events = f.store.pending_events(1000).unwrap();
        // Negative corruption of a genuinely prepared17 parent. There is NO
        // action owner, and quarantine_in_flight alone must never grant one.
        f.store.conn.execute("UPDATE retirement_intents SET revision=2,stage='held',held_reason='quarantine_in_flight' WHERE operation=?1", [operation.to_string()]).unwrap();
        fn raw_intents(conn: &rusqlite::Connection) -> Vec<Vec<rusqlite::types::Value>> {
            let mut stmt = conn
                .prepare("SELECT * FROM retirement_intents ORDER BY operation")
                .unwrap();
            let columns = stmt.column_count();
            let rows = stmt
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get(column))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            rows
        }
        let before = abort_source_rows(&f.store);
        let intent_before = raw_intents(&f.store.conn);
        assert!(f.store.acknowledge(sequence).is_err());
        assert_eq!(f.store.pending_events(1000).unwrap(), events);
        assert!(crate::retirement_journal::read_history(&f.store.conn, Uuid::now_v7()).is_err());
        let mut canonical = b"untouched".to_vec();
        assert!(crate::retirement_journal::frame_history_without(
            &f.store.conn,
            f.allocation.checkout,
            operation,
            &mut canonical
        )
        .is_err());
        assert_eq!(canonical, b"untouched");
        assert!(abort_offline(
            &config,
            f.allocation.checkout,
            operation,
            2,
            AbortFault::None
        )
        .is_err());
        assert_eq!(abort_source_rows(&f.store), before);
        assert_eq!(raw_intents(&f.store.conn), intent_before);
        let reason: String = f
            .store
            .conn
            .query_row(
                "SELECT held_reason FROM retirement_intents WHERE operation=?1",
                [operation.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(reason, "quarantine_in_flight");
    }

    #[test]
    fn private_prepare_rejects_invalid_finished_supervised_predecessors() {
        for change in ["missing-finish", "corrupt-finish", "reactivated"] {
            let mut f = fixture::ManagedFixture::recovery("sha1", "2");
            let (_r, _b, os, config) = prepared_supervised(&mut f);
            enable_prepare(&config);
            let checkout = f.allocation.checkout;
            // Negative-only corruption of a genuinely finished checkout. None
            // of these edits is used to manufacture a successful fresh owner.
            f.store
                .conn
                .execute(
                    match change {
                        "missing-finish" => "DELETE FROM task_finishes WHERE checkout=?1",
                        "corrupt-finish" => {
                            "UPDATE task_finishes SET record='{}' WHERE checkout=?1"
                        }
                        _ => "UPDATE checkouts SET state='active',ready=1 WHERE id=?1",
                    },
                    [checkout.to_string()],
                )
                .unwrap();
            let rows = abort_source_rows(&f.store);
            let events = f.store.pending_events(1000).unwrap().len();
            assert_eq!(
                prepare_test(
                    &config,
                    checkout,
                    Uuid::now_v7(),
                    None,
                    false,
                    Some(&os.driver),
                    PrepareFault::None,
                )
                .unwrap_err(),
                if change == "missing-finish" {
                    "task_completion_missing"
                } else {
                    "task_completion_unknown"
                }
            );
            assert_eq!(rows, abort_source_rows(&f.store));
            assert_eq!(events, f.store.pending_events(1000).unwrap().len());
            assert!(
                crate::retirement_journal::read_history(&f.store.conn, checkout)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn private_prepare_final_immediate_failures_rollback_except_lost_ack() {
        for fault in [
            PrepareFault::ExpireAssertion,
            PrepareFault::Deadline,
            PrepareFault::ContextMutation,
            PrepareFault::LostAck,
        ] {
            let mut f = fixture::ManagedFixture::recovery("sha1", "2");
            let (config, _) = f.approval();
            enable_prepare(&config);
            assert!(
                recovery_refs::prepare_for_assessment(&config, f.allocation.checkout).prepared()
            );
            let assertion = approval::assertion_for_retirement_test(&config, f.allocation.checkout);
            let source = receipts::collector_source(&mut f.store, f.allocation.checkout);
            let events = f.store.pending_events(1000).unwrap().len();
            let operation = Uuid::now_v7();
            let result = prepare_test(
                &config,
                f.allocation.checkout,
                operation,
                Some(assertion),
                true,
                None,
                fault,
            );
            if fault == PrepareFault::LostAck {
                let report = result.unwrap();
                assert_eq!(report.outcome(), "uncertain");
                assert!(!report.fresh_commit());
                assert!(report.fence_active());
                assert_eq!(serde_json::to_value(report).unwrap()["recorded"], "unknown");
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    match fault {
                        PrepareFault::ExpireAssertion => "approval_expired",
                        PrepareFault::Deadline => "deadline",
                        PrepareFault::ContextMutation => "context_changed",
                        _ => unreachable!(),
                    }
                );
            }
            assert_eq!(
                source,
                receipts::collector_source(&mut f.store, f.allocation.checkout)
            );
            assert_eq!(
                crate::retirement_journal::operation_reserved(
                    &f.store.conn,
                    &operation.to_string()
                )
                .unwrap(),
                fault == PrepareFault::LostAck
            );
            assert_eq!(
                events + usize::from(fault == PrepareFault::LostAck),
                f.store.pending_events(1000).unwrap().len()
            );
            if fault == PrepareFault::LostAck {
                assert!(matches!(
                    crate::retirement_journal::require_unfenced(
                        &f.store.conn,
                        f.allocation.checkout
                    ),
                    Err(crate::store::StoreError::RetirementFenced)
                ));
                let retry = prepare_test(
                    &config,
                    f.allocation.checkout,
                    operation,
                    Some(assertion),
                    true,
                    None,
                    PrepareFault::None,
                )
                .unwrap();
                assert!(!retry.fresh_commit());
            }
        }
    }

    #[test]
    fn private_prepare_refuses_missing_declaration_wrong_assertion_operator_and_dirty_policy() {
        for fault in [
            "declaration",
            "assertion",
            "operator",
            "policy",
            "dirty",
            "mode",
        ] {
            let f = fixture::ManagedFixture::recovery("sha1", "2");
            let (config, _) = f.approval();
            enable_prepare(&config);
            assert!(
                recovery_refs::prepare_for_assessment(&config, f.allocation.checkout).prepared()
            );
            let assertion = approval::assertion_for_retirement_test(&config, f.allocation.checkout);
            match fault {
                "operator" => {
                    let text = fs::read_to_string(&config)
                        .unwrap()
                        .replace("explicit-operator", "different-operator");
                    fs::write(&config, text).unwrap();
                }
                "policy" => {
                    let text = fs::read_to_string(&config)
                        .unwrap()
                        .replace("expiry_seconds=60", "expiry_seconds=59");
                    fs::write(&config, text).unwrap();
                }
                "dirty" => {
                    fs::write(
                        f.allocation.destination.join("unpreserved-new-file"),
                        b"not backed up",
                    )
                    .unwrap();
                }
                _ => {}
            }
            let events = f.store.pending_events(1000).unwrap().len();
            let result = prepare_test(
                &config,
                f.allocation.checkout,
                Uuid::now_v7(),
                match fault {
                    "assertion" => Some(Uuid::now_v7()),
                    "mode" => None,
                    _ => Some(assertion),
                },
                fault != "declaration" && fault != "mode",
                None,
                PrepareFault::None,
            );
            assert!(result.is_err(), "{fault}");
            assert_eq!(events, f.store.pending_events(1000).unwrap().len());
            assert!(
                crate::retirement_journal::read_history(&f.store.conn, f.allocation.checkout)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn fresh_supervised_owner_retains_ex_and_original_terminal_times_without_rows() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        let before = receipts::collector_source(&mut f.store, f.allocation.checkout);
        let events = f.store.pending_events(1000).unwrap().len();
        let mut fresh = fresh_for_test(&f, &config, None, Some(&os.driver));
        assert!(fresh.retained.assertion.is_none());
        assert!(
            !fresh.retained.observations.is_empty(),
            "full decide seam reached"
        );
        assert_eq!(fresh.declaration_context(), None);
        assert_eq!(fresh.checkout(), f.allocation.checkout);
        let (_, source, _, history_count) = fresh.context_bindings();
        assert_eq!(hex(&source), fresh.binding().source_sql);
        assert_eq!(history_count, 0);
        assert!(matches!(
            crate::checkout_guard::CheckoutGuard::shared(&f.store, f.allocation.checkout),
            Err(crate::store::StoreError::OperationsInFlight)
        ));
        fresh.recheck_before_transaction().unwrap();
        fresh.check_commit_freshness().unwrap();
        let first = fresh.retained.observations[0].observed_at();
        fresh.retained.observations[0].age_for_test();
        assert!(fresh.retained.observations[0].observed_at() < first);
        assert_eq!(fresh.check_commit_freshness(), Err("observation_stale"));
        fresh.retained.assessment.budget.test_elapsed = Some(Duration::from_secs(30));
        assert_eq!(fresh.check_commit_freshness(), Err("deadline"));
        assert_eq!(
            before,
            receipts::collector_source(&mut f.store, f.allocation.checkout)
        );
        assert_eq!(events, f.store.pending_events(1000).unwrap().len());
        let rows: i64 = f
            .store
            .conn
            .query_row("SELECT count(*) FROM retirement_intents", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0);
        drop(fresh);
        assert!(
            crate::checkout_guard::CheckoutGuard::shared(&f.store, f.allocation.checkout).is_ok()
        );
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert_eq!(
            report.outcome(),
            "prerequisites_complete",
            "{}",
            report.reason()
        );
        let wire = serde_json::to_value(report).unwrap();
        assert_eq!(wire["execution_enabled"], false);
        assert_eq!(wire["recorded"], false);
        assert!(wire.get("immutable_binding").is_none());
        assert_eq!(
            before,
            receipts::collector_source(&mut f.store, f.allocation.checkout)
        );
        assert_eq!(events, f.store.pending_events(1000).unwrap().len());
    }

    #[test]
    fn fresh_adopted_owner_uses_validated_operator_and_pure_commit_clock() {
        for fault in ["none", "boot", "expiry", "wall", "boottime", "budget"] {
            let mut f = fixture::ManagedFixture::recovery("sha1", "2");
            let (config, _) = f.approval();
            assert!(
                recovery_refs::prepare_for_assessment(&config, f.allocation.checkout).prepared()
            );
            let id = approval::assertion_for_retirement_test(&config, f.allocation.checkout);
            let source = receipts::collector_source(&mut f.store, f.allocation.checkout);
            let events = f.store.pending_events(1000).unwrap().len();
            let mut fresh = fresh_for_test(&f, &config, Some(id), None);
            assert!(matches!(
                crate::checkout_guard::CheckoutGuard::shared(&f.store, f.allocation.checkout),
                Err(crate::store::StoreError::OperationsInFlight)
            ));
            let (assertion, operator, task) = fresh
                .declaration_context()
                .expect("validated adopted owner");
            assert_eq!(assertion, id);
            assert_eq!(operator, "explicit-operator");
            assert_eq!(task, f.allocation.request.task);
            assert!(fresh.retained.observations.is_empty());
            fresh.recheck_before_transaction().unwrap();
            let assertion = fresh
                .retained
                .assertion
                .as_mut()
                .expect("consume seam reached");
            let claim_before = assertion.claim_binding_for_test();
            let latest_before = assertion.latest_for_test();
            assertion.script_commit_fault_for_test(if fault == "budget" { "none" } else { fault });
            if fault == "budget" {
                fresh.retained.assessment.budget.test_elapsed = Some(Duration::from_secs(30));
            }
            let before = fresh.retained.assessment.budget.counters.clone();
            let result = fresh.check_commit_freshness();
            assert_eq!(
                result,
                match fault {
                    "none" => Ok(()),
                    "expiry" => Err("approval_expired"),
                    "budget" => Err("deadline"),
                    _ => Err("clock_anomaly"),
                },
                "{fault}"
            );
            let assertion = fresh.retained.assertion.as_ref().unwrap();
            assert_eq!(assertion.script_consumed_for_test(), fault != "budget");
            assert_eq!(assertion.claim_binding_for_test(), claim_before);
            if fault != "none" {
                assert_eq!(assertion.latest_for_test(), latest_before);
            }
            assert_eq!(
                fresh.retained.assessment.budget.counters, before,
                "pure clock does not charge file reads"
            );
            assert_eq!(
                source,
                receipts::collector_source(&mut f.store, f.allocation.checkout)
            );
            assert_eq!(events, f.store.pending_events(1000).unwrap().len());
            let writers: i64 = f
                .store
                .conn
                .query_row(
                    "SELECT count(*) FROM writers WHERE checkout=?1",
                    [f.allocation.checkout.to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(writers, 1);
        }
    }

    fn repeat_local(fresh: &FreshRetirementAssessment, config: &Path) -> Held<LocalBinding> {
        // Independent offline invocation: one new outer budget, shared by every
        // nested collector. Never replace/reset the preparation owner's budget.
        let mut budget = Budget::new();
        let retained = &fresh.retained;
        let a = &retained.assessment;
        let (local, census, inputs) =
            preservation::RecoveryCensus::recapture(&a.context, &mut budget)?;
        let (document, first_config) = remote_proof::load_document(config, &mut budget)?;
        let (_, closing_config) = remote_proof::load_document(config, &mut budget)?;
        let manifests = [first_config, closing_config];
        let (policies, _, combined_policy) = configuration_bindings(&document)?;
        let operator = match a.mode {
            ModeKind::Adopted => Some(
                document
                    .approval()
                    .map_err(|_| "approval_policy_unknown")?
                    .operator_id,
            ),
            ModeKind::Supervised => None,
        };
        let (projection, _source) = capture_local_binding(
            &a.context,
            a.store.authority_identity(),
            LocalBindingInputs {
                first: &census,
                before: &inputs,
                closing_census: &census,
                closing_inputs: &inputs,
                recovery: &local,
                manifests: &manifests,
                policies: &policies,
                combined_policy: &combined_policy,
                operator: operator.as_deref(),
            },
            &mut budget,
        )?;
        Ok(projection)
    }

    #[test]
    fn local_projection_repeats_offline_and_detects_native_input_mutations() {
        for change in [
            "unchanged",
            "payload",
            "marker",
            "config",
            "ref",
            "stat",
            "source-root",
        ] {
            let mut f = fixture::ManagedFixture::recovery("sha1", "2");
            let (_r, _b, os, config) = prepared_supervised(&mut f);
            let fresh = fresh_for_test(&f, &config, None, Some(&os.driver));
            let original = repeat_local(&fresh, &config).expect("actual offline recollection");
            assert_eq!(original, LocalBinding::from_record(fresh.binding()));
            // Authority-dir/checkout-operation metadata churn is not source
            // identity. Creating an unrelated guard must not invalidate this.
            let unrelated =
                crate::checkout_guard::CheckoutGuard::shared(&f.store, Uuid::now_v7()).unwrap();
            drop(unrelated);
            let source = f.allocation.request.repository.as_ref().unwrap();
            match change {
                "payload" => {
                    fs::write(f.allocation.destination.join("new-payload"), b"changed").unwrap()
                }
                "marker" => {
                    let path = f
                        .allocation
                        .identity
                        .as_ref()
                        .unwrap()
                        .private_git_dir
                        .join("work-lease.json");
                    fs::write(path, b"{}").unwrap();
                }
                "config" => {
                    let text = fs::read_to_string(&config).unwrap();
                    fs::write(&config, text.replace("fixture-v1", "fixture-v2")).unwrap();
                }
                "ref" => {
                    git_at(
                        &f.allocation.destination,
                        &["update-ref", "refs/tags/extra", "HEAD"],
                    );
                }
                "stat" => {
                    let file = f.allocation.destination.join("tracked");
                    let mode = fs::metadata(&file).unwrap().permissions().mode();
                    fs::set_permissions(file, fs::Permissions::from_mode(mode ^ 0o100)).unwrap();
                }
                "source-root" => {
                    let mode = fs::metadata(source).unwrap().permissions().mode();
                    fs::set_permissions(source, fs::Permissions::from_mode(mode ^ 0o010)).unwrap();
                }
                "unchanged" => (),
                _ => unreachable!(),
            }
            let repeated = repeat_local(&fresh, &config);
            if change == "marker" {
                assert_eq!(
                    repeated,
                    Err("census_unknown"),
                    "invalid marker reaches native recapture"
                );
            } else if change == "unchanged" {
                assert_eq!(repeated.unwrap(), original);
            } else {
                let changed = repeated.unwrap_or_else(|reason| {
                    panic!("{change}: recapture failed before binding comparison: {reason}")
                });
                assert_ne!(changed, original, "{change}");
                match change {
                    "payload" | "stat" => {
                        assert_ne!(changed.managed_physical, original.managed_physical)
                    }
                    "config" => {
                        assert_ne!(changed.config_manifests, original.config_manifests);
                        assert_ne!(changed.combined_policy, original.combined_policy);
                    }
                    "ref" => assert_ne!(changed.local_git, original.local_git),
                    "source-root" => {
                        assert_ne!(changed.source_repository, original.source_repository)
                    }
                    "marker" => panic!("invalid marker must fail native collection"),
                    _ => unreachable!(),
                }
            }
        }
    }

    #[test]
    fn fresh_closing_mutation_reaches_collector_and_releases_ex_on_failure() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        let store = Store::open_existing_registered_mut(
            &f.temp.path().join("registry"),
            &f.temp.path().join("authority"),
            &[f.root.clone()],
        )
        .unwrap();
        let guard =
            crate::checkout_guard::CheckoutGuard::exclusive(&store, f.allocation.checkout).unwrap();
        let reached = Arc::new(AtomicBool::new(false));
        let hit = reached.clone();
        let destination = f.allocation.destination.clone();
        set_after_protection(move || {
            fs::write(destination.join("closing-change"), b"changed").unwrap();
            hit.store(true, Ordering::SeqCst);
        });
        let result = collect_fresh_prepare_inner(
            &config,
            f.allocation.checkout,
            None,
            store,
            guard,
            Some(&os.driver),
        );
        assert!(
            reached.load(Ordering::SeqCst),
            "actual protected collection reached"
        );
        assert!(matches!(result, Err("census_changed")));
        assert!(
            crate::checkout_guard::CheckoutGuard::shared(&f.store, f.allocation.checkout).is_ok()
        );
    }

    #[test]
    fn historical_remote_graph_is_not_an_offline_local_projection() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        let first = fresh_for_test(&f, &config, None, Some(&os.driver));
        let local = repeat_local(&first, &config).unwrap();
        let historical = first.binding().approval_semantic.clone();
        drop(first);
        let remote = f.temp.path().join("backup.git");
        let parent = git_at(&remote, &["rev-parse", "refs/heads/preserved"]);
        let tree = git_at(&remote, &["rev-parse", "refs/heads/preserved^{tree}"]);
        let descendant = git_at(
            &remote,
            &[
                "commit-tree",
                &tree,
                "-p",
                &parent,
                "-m",
                "remote-only descendant",
            ],
        );
        git_at(
            &remote,
            &["update-ref", "refs/heads/preserved", &descendant],
        );
        let second = fresh_for_test(&f, &config, None, Some(&os.driver));
        assert_ne!(second.binding().approval_semantic, historical);
        // Make the fixture remote inaccessible after genuine remote-ahead
        // collection. The local projection must not contact it or require its
        // scratch graph. Restore permissions even when recollection refuses.
        let permissions = fs::metadata(&remote).unwrap().permissions();
        fs::set_permissions(&remote, fs::Permissions::from_mode(0o0)).unwrap();
        let offline = repeat_local(&second, &config);
        fs::set_permissions(&remote, permissions).unwrap();
        assert_eq!(offline.unwrap(), local);
        let result = Command::new("/usr/bin/git")
            .args(["cat-file", "-e", &descendant])
            .current_dir(&f.allocation.destination)
            .output()
            .unwrap();
        assert!(
            !result.status.success(),
            "remote descendant was not imported locally"
        );
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
    fn passive_assessment_does_not_hold_intent_or_create_operation_locks() {
        use std::os::unix::fs::MetadataExt;

        #[derive(Debug, PartialEq, Eq)]
        struct LockIdentity {
            name: std::ffi::OsString,
            dev: u64,
            ino: u64,
            mode: u32,
            uid: u32,
            gid: u32,
            links: u64,
        }
        fn common_locks(path: &Path) -> (Vec<fs::File>, Vec<LockIdentity>) {
            let mut entries: Vec<_> = fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect();
            entries.sort_by_key(|entry| entry.file_name());
            let mut handles = Vec::new();
            let mut identities = Vec::new();
            for entry in entries {
                let named = fs::symlink_metadata(entry.path()).unwrap();
                assert!(named.is_file());
                assert_eq!(named.nlink(), 1);
                let handle = fs::File::open(entry.path()).unwrap();
                let opened = handle.metadata().unwrap();
                assert_eq!((named.dev(), named.ino()), (opened.dev(), opened.ino()));
                assert_eq!(named.mode(), opened.mode());
                assert_eq!((named.uid(), named.gid()), (opened.uid(), opened.gid()));
                assert_eq!(named.nlink(), opened.nlink());
                identities.push(LockIdentity {
                    name: entry.file_name(),
                    dev: opened.dev(),
                    ino: opened.ino(),
                    mode: opened.mode(),
                    uid: opened.uid(),
                    gid: opened.gid(),
                    links: opened.nlink(),
                });
                handles.push(handle);
            }
            (handles, identities)
        }

        let f = fixture::ManagedFixture::new("sha1", "2");
        let runtime = f.temp.path().join("runtime");
        let path = remote_config(&f, &runtime);
        let operation_dir = f.temp.path().join("authority/checkout-operations-v1");
        let before: Vec<_> = std::fs::read_dir(&operation_dir)
            .into_iter()
            .flatten()
            .map(|e| e.unwrap().file_name())
            .collect();
        let common_dir = f
            .temp
            .path()
            .join("authority/recovery-preparation-locks-v1");
        let (before_handles, common_before) = common_locks(&common_dir);
        assert!(
            !common_before.is_empty(),
            "allocation must create the common lock"
        );
        receipts::seed_collector_intent(&f.store, f.allocation.checkout);
        let events_before = f.store.pending_events(1000).unwrap().len();
        let report = assess_retirement(&path, f.allocation.checkout, None);
        assert_eq!(report.reason(), "retirement_intent_active");
        let stage: String = f
            .store
            .conn
            .query_row("SELECT stage FROM retirement_intents", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stage, "prepared");
        let after: Vec<_> = std::fs::read_dir(&operation_dir)
            .into_iter()
            .flatten()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(before, after);
        let (after_handles, common_after) = common_locks(&common_dir);
        assert_eq!(common_before, common_after);
        assert_eq!(f.store.pending_events(1000).unwrap().len(), events_before);
        // Keep the original descriptors open through comparison so replacement
        // cannot be hidden by inode reuse. Never unlink an allocation lock.
        drop((before_handles, after_handles));
    }

    #[test]
    fn schema_participation_spans_negative_assessment_report_finalization() {
        use crate::store::schema_participation_tests::{
            probe_initialization_exclusive, ExclusiveProbe,
        };

        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (request, binding, os) = close_completed(&mut f);
        // Deliberately do not finish the task: the genuine sealed assessment
        // must reach decide's task_completion_missing negative return.
        let config = remote_config(&f, &os.tmp.path().join("runtime"));
        let checkout = f.allocation.checkout;
        let registry = f.temp.path().join("registry");
        let prepared = recovery_refs::prepare_for_assessment(&config, checkout);
        assert!(prepared.prepared(), "{prepared:?}");
        drop((prepared, request, binding));
        drop(f.store);
        assert_eq!(
            probe_initialization_exclusive(&registry).unwrap(),
            ExclusiveProbe::Acquired,
            "no fixture schema owner may mask the operation's lifetime"
        );

        let probes = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let observed = probes.clone();
        let probe_registry = registry.clone();
        let mut collector = Collector::new(checkout, None);
        collector.report_observer = Some(Box::new(move |phase| {
            // Record only, including probe errors. A successful EX is released
            // by the helper before returning; assertions await report cleanup.
            observed
                .borrow_mut()
                .push((phase, probe_initialization_exclusive(&probe_registry)));
        }));
        let (report, retained) = collect_retained(&config, collector, Some(&os.driver));
        let released = probe_initialization_exclusive(&registry);

        assert!(retained.is_none());
        assert_eq!(report.outcome(), "held");
        assert_eq!(report.reason(), "task_completion_missing");
        assert_eq!(report.mode(), "supervised");
        assert!(!report.execution_enabled());
        assert!(!report.retirement_authority());
        assert!(report.writer_charges_retained());
        assert!(!report.recorded);
        let metadata = serde_json::to_value(&report).unwrap();
        assert_eq!(metadata["preservation"]["outcome"], "observed");
        assert_eq!(metadata["preservation"]["cleanup"], "complete");
        let remote = &metadata["preservation"]["remote_head"];
        assert_eq!(remote["outcome"], "observed");
        assert_eq!(remote["transport"], "LOCAL");
        assert_eq!(remote["cleanup"], "complete");
        let probes = probes.borrow();
        assert_eq!(probes.len(), 2, "both outer report boundaries reached");
        assert_eq!(
            probes[0].0,
            AssessmentReportPhase::NegativeDecision("task_completion_missing")
        );
        assert_eq!(probes[1].0, AssessmentReportPhase::MetadataComplete);
        assert_eq!(released.unwrap(), ExclusiveProbe::Acquired);
        for (_, probe) in probes.iter() {
            assert_eq!(probe.as_ref().unwrap(), &ExclusiveProbe::Blocked);
        }
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
        let common = f.common().to_path_buf();
        let tree = git_text(&f, &["rev-parse", "HEAD^{tree}"]);
        let reached = Arc::new(AtomicBool::new(false));
        let flag = reached.clone();
        let expected = tree.clone();
        set_after_protection(move || {
            fixture::git(
                &dest,
                &[
                    "update-ref".as_ref(),
                    "refs/tags/extra-tree".as_ref(),
                    expected.as_ref(),
                ],
            );
            let path = common.join("refs/tags/extra-tree");
            let bytes = fs::read(&path).unwrap();
            assert_eq!(bytes, format!("{expected}\n").into_bytes());
            flag.store(true, Ordering::SeqCst);
        });
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert!(
            reached.load(Ordering::SeqCst),
            "after-protection hook not consumed"
        );
        assert_eq!(git_text(&f, &["rev-parse", "refs/tags/extra-tree"]), tree);
        assert_eq!(
            fs::read(f.common().join("refs/tags/extra-tree")).unwrap(),
            format!("{tree}\n").into_bytes()
        );
        assert_eq!(report.outcome(), "held");
        assert_eq!(report.reason(), "census_changed");
        assert_ne!(report.reason(), "prerequisites_complete");
    }

    #[test]
    fn config_mutation_after_protection_holds_for_supervised_and_adopted() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        let path = config.clone();
        let reached = Arc::new(AtomicBool::new(false));
        let flag = reached.clone();
        set_after_protection(move || {
            let text = fs::read_to_string(&path)
                .unwrap()
                .replace("fixture-v1", "fixture-v2");
            fs::write(&path, &text).unwrap();
            assert!(text.contains("store_dir="));
            assert!(text.contains("fixture-v2"));
            toml::from_str::<toml::Value>(&text).unwrap();
            flag.store(true, Ordering::SeqCst);
        });
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert!(
            reached.load(Ordering::SeqCst),
            "supervised config hook not consumed"
        );
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
        let reached = Arc::new(AtomicBool::new(false));
        let flag = reached.clone();
        set_after_protection(move || {
            let text = fs::read_to_string(&path)
                .unwrap()
                .replace("fixture-v1", "fixture-v2");
            fs::write(&path, &text).unwrap();
            assert!(text.contains("store_dir="));
            assert!(text.contains("fixture-v2"));
            toml::from_str::<toml::Value>(&text).unwrap();
            flag.store(true, Ordering::SeqCst);
        });
        let report = assess_retirement(&config, f.allocation.checkout, Some(assertion));
        assert!(
            reached.load(Ordering::SeqCst),
            "adopted config hook not consumed"
        );
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
        let tree = git_text(&f, &["rev-parse", "HEAD^{tree}"]);
        f.git(&[
            "update-ref".as_ref(),
            "refs/tags/extra-root".as_ref(),
            tree.as_ref(),
        ]);
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        pack_recovery_refs(&f);
        let rows = recovery_ref_rows(&f);
        assert!(rows.len() >= 2, "{rows:?}");
        let (loose_name, loose_oid) = &rows[0];
        let (packed_name, packed_oid) = &rows[1];
        assert_ne!(loose_name, packed_name);
        let loose_path = f.common().join(loose_name);
        fs::create_dir_all(loose_path.parent().unwrap()).unwrap();
        let canonical = format!("{loose_oid}\n").into_bytes();
        fs::write(&loose_path, &canonical).unwrap();
        assert_eq!(fs::read(&loose_path).unwrap(), canonical);
        assert!(!f.common().join(packed_name).exists());
        let packed_refs = fs::read_to_string(f.common().join("packed-refs")).unwrap();
        assert!(
            packed_refs.contains(&format!("{packed_oid} {packed_name}\n")),
            "{packed_refs}"
        );
        assert!(
            packed_refs.contains(&format!("{loose_oid} {loose_name}\n")),
            "{packed_refs}"
        );
        let before_rows = rows.clone();
        let before_loose = fs::read(&loose_path).unwrap();
        let before_packed = fs::read(f.common().join("packed-refs")).unwrap();
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert_eq!(
            report.outcome(),
            "prerequisites_complete",
            "{}",
            report.reason()
        );
        assert_eq!(recovery_ref_rows(&f), before_rows);
        assert_eq!(fs::read(&loose_path).unwrap(), before_loose);
        assert_eq!(
            fs::read(f.common().join("packed-refs")).unwrap(),
            before_packed
        );
        assert!(!f.common().join(packed_name).exists());
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
        for case in ["present", "escaped", "reused", "reboot", "missing"] {
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
                "missing" => {
                    fs::create_dir_all(os.tmp.path().join("proc/43")).unwrap();
                }
                _ => unreachable!(),
            }
            let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
            assert_eq!(report.outcome(), "held", "{case}");
            let expected = match case {
                "present" => "missing_enrollment",
                "escaped" => "missing_enrollment",
                "reused" => "missing_enrollment",
                "reboot" => "boot_mismatch",
                // Missing stat aborts collection before unit identity is assigned;
                // verification reports that unknown identity before coverage.
                "missing" => "unknown_manager",
                _ => unreachable!(),
            };
            assert_eq!(report.reason(), expected, "{case}");
        }
    }

    #[test]
    fn remote_tip_changed_between_advertisements_holds() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        let remote = f.temp.path().join("backup.git");
        let before_head = git_text(&f, &["rev-parse", "HEAD"]);
        let before_status = git_text(&f, &["status", "--porcelain"]);
        let before_refs = git_text(&f, &["show-ref"]);
        let reached = Arc::new(AtomicBool::new(false));
        let flag = reached.clone();
        super::super::remote_proof::set_retirement_observer(move |phase, _scratch| {
            if phase != super::super::remote_proof::Phase::BeforeFinalAdvertisement
                || flag.load(Ordering::SeqCst)
            {
                return;
            }
            let parent = git_at(&remote, &["rev-parse", "refs/heads/preserved"]);
            let tree = git_at(&remote, &["rev-parse", "refs/heads/preserved^{tree}"]);
            let commit = git_at(
                &remote,
                &["commit-tree", &tree, "-p", &parent, "-m", "remote-only"],
            );
            fixture::git(
                &remote,
                &[
                    "update-ref".as_ref(),
                    "refs/heads/preserved".as_ref(),
                    commit.as_ref(),
                ],
            );
            flag.store(true, Ordering::SeqCst);
        });
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert!(
            reached.load(Ordering::SeqCst),
            "advertisement hook not consumed"
        );
        assert_eq!(git_text(&f, &["rev-parse", "HEAD"]), before_head);
        assert_eq!(git_text(&f, &["status", "--porcelain"]), before_status);
        assert_eq!(git_text(&f, &["show-ref"]), before_refs);
        assert_eq!(report.outcome(), "held");
        assert_eq!(report.reason(), "remote_changed");
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["preservation"]["cleanup"], "complete");
        assert_eq!(
            value["preservation"]["remote_head"]["reason"],
            "remote_changed"
        );
        assert_eq!(value["preservation"]["remote_head"]["cleanup"], "complete");
        assert_ne!(report.reason(), "prerequisites_complete");
    }

    #[test]
    fn unsafe_scratch_symlink_cleanup_holds() {
        let mut f = fixture::ManagedFixture::recovery("sha1", "2");
        let (_r, _b, os, config) = prepared_supervised(&mut f);
        let dest = f.allocation.destination.clone();
        let reached = Arc::new(AtomicBool::new(false));
        let flag = reached.clone();
        super::super::remote_proof::set_retirement_observer(move |phase, scratch| {
            if phase != super::super::remote_proof::Phase::BeforeCleanup {
                return;
            }
            std::os::unix::fs::symlink(&dest, scratch.join("unexpected-link")).unwrap();
            flag.store(true, Ordering::SeqCst);
        });
        let report = assess_path_with_driver(&config, f.allocation.checkout, None, &os.driver);
        assert!(reached.load(Ordering::SeqCst), "cleanup hook not consumed");
        assert_eq!(report.outcome(), "held");
        assert_eq!(report.reason(), "cleanup_unknown");
        let value = serde_json::to_value(&report).unwrap();
        assert_ne!(value["preservation"]["cleanup"], "complete");
        assert_ne!(report.reason(), "prerequisites_complete");
    }
}
