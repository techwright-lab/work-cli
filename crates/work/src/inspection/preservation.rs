//! Non-destructive preservation census. Public output is historical metadata only.
//! Native Git 2.55.0: cat-file --batch-all-objects visits loose AND packed objects,
//! not just reachable tips. rev-list --objects --no-object-names supplies graph
//! membership, never inventory. fsck --full validates connectivity and contents.
//! No lost-found, update-ref, object writes, receipt import or action capability.
use super::*;
use crate::config::ConfigDocument;

type Held<T> = Result<T, &'static str>;
type Objects = BTreeMap<Vec<u8>, Object>;
type Roots = BTreeMap<Vec<u8>, BTreeSet<Provenance>>;

#[derive(Debug, serde::Serialize)]
pub struct PreservationReport {
    checkout: Uuid,
    coverage: &'static str,
    outcome: &'static str,
    reason: &'static str,
    inspection_findings: Vec<ContentFinding>,
    additional_work_holds: Vec<WorkHold>,
    local_object_count: usize,
    remote_reachable_object_count: usize,
    recovery_manifest: Option<RecoveryManifest>,
    remote_head: Option<RemoteReport>,
    cleanup: &'static str,
    recorded: bool,
    retirement_authority: bool,
}
impl PreservationReport {
    /// Historical result, never permission for a later operation.
    pub fn observed(&self) -> bool {
        self.outcome == "observed"
    }
    pub fn reason(&self) -> &'static str {
        self.reason
    }
}
#[derive(Debug, serde::Serialize)]
struct ContentFinding {
    path_hex: String,
    kind: &'static str,
}
#[derive(Debug, serde::Serialize)]
struct WorkHold {
    reason: &'static str,
    oid: String,
    object_type: &'static str,
}
#[derive(Debug, serde::Serialize)]
struct RecoveryManifest {
    format: u32,
    checkout: Uuid,
    object_format: &'static str,
    common_identity_digest: String,
    context_digest: String,
    policy_digest: String,
    input_digest: String,
    roots: Vec<RecoveryRoot>,
}
#[derive(Debug, serde::Serialize)]
struct RecoveryRoot {
    oid: String,
    object_type: &'static str,
    provenance: BTreeSet<Provenance>,
    remote_relationship: &'static str,
    proposed_ref: String,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
struct Provenance {
    kind: &'static str,
    path_hex: String,
    record_ordinal: Option<u64>,
}
#[derive(Debug, PartialEq, Eq)]
struct Object {
    kind: &'static str,
    size: u64,
}

/// Fresh actual authority/inspection/remote observation only. No report or
/// receipt argument, URL override, persistence or configurable collector exists.
pub fn audit_preservation(checkout: Uuid) -> PreservationReport {
    let mut audit = Audit::new(checkout);
    let remote = remote_proof::audit_configured(checkout, &mut audit);
    audit.finish(remote)
}

// Only the remote coordinator drives this owned collector. It shares that
// invocation's budget and immutable document. It never receives a scratch path
// or controls a Git fetch/ref, and cannot shorten the closing/cleanup sequence.
pub(super) struct Audit {
    report: PreservationReport,
    local: Option<Local>,
    graph: Option<BTreeSet<Vec<u8>>>,
    rechecked: bool,
    inspection_policy: Option<Vec<u8>>,
    sealed: bool,
}
impl Audit {
    pub(super) fn new(checkout: Uuid) -> Self {
        Self {
            report: PreservationReport {
                checkout,
                coverage: "incomplete",
                outcome: "held",
                reason: "audit_unknown",
                inspection_findings: vec![],
                additional_work_holds: vec![],
                local_object_count: 0,
                remote_reachable_object_count: 0,
                recovery_manifest: None,
                remote_head: None,
                cleanup: "not_created",
                recorded: false,
                retirement_authority: false,
            },
            local: None,
            graph: None,
            rechecked: false,
            inspection_policy: None,
            sealed: false,
        }
    }
    pub(super) fn take_approval_local(&mut self) -> Held<ApprovalLocal> {
        if !self.sealed
            || !self.report.inspection_findings.is_empty()
            || !self.report.additional_work_holds.is_empty()
        {
            return Err("preservation_requirements_held");
        }
        let local = self.local.take().ok_or("census_unknown")?;
        let graph = self.graph.as_ref().ok_or("census_unknown")?;
        let mut semantic = Vec::new();
        frame(&mut semantic, 0, b"work.approval.preservation.semantic.v1");
        frame(&mut semantic, 1, &local.admin.approval_semantic_v1());
        for (oid, object) in &local.objects {
            frame(&mut semantic, 2, oid);
            frame(&mut semantic, 3, object.kind.as_bytes());
            frame(&mut semantic, 4, &object.size.to_be_bytes());
            frame(
                &mut semantic,
                5,
                &[
                    u8::from(local.head_graph.contains(oid)),
                    u8::from(graph.contains(oid)),
                    u8::from(local.unclassified.contains(oid)),
                ],
            );
        }
        for (oid, provenance) in &local.roots {
            frame(&mut semantic, 6, oid);
            frame(
                &mut semantic,
                7,
                &serde_json::to_vec(provenance).map_err(|_| "census_unknown")?,
            );
        }
        for oid in graph {
            frame(&mut semantic, 8, oid);
        }
        let invalidation = local.fingerprint();
        Ok(ApprovalLocal {
            local,
            semantic: Sha256::digest(semantic).to_vec(),
            invalidation,
        })
    }
    pub(super) fn take_recovery_plan(&mut self) -> Held<RecoveryCensus> {
        if !self.sealed {
            return Err("audit_sequence_unknown");
        }
        let local = self.local.take().ok_or("census_unknown")?;
        if self.graph.is_none() || !self.rechecked {
            return Err("census_unknown");
        }
        Ok(RecoveryCensus { local })
    }
    pub(super) fn begin(
        &mut self,
        document: &ConfigDocument,
        context: &Context,
        census: &filesystem::Census,
        inputs: &GitInputs,
        proof: &GitProof,
        b: &mut Budget,
    ) -> Held<()> {
        let policies = document
            .inspection_policies()
            .map_err(|_| "inspection_policy_unknown")?;
        self.inspection_policy = Some(policies.canonical_bytes().to_vec());
        let (_, findings) = classify(census, proof, &policies);
        for f in findings {
            let kind = match f.kind {
                FindingKind::TrackedContent => "tracked_content",
                FindingKind::StagedChange => "staged_change",
                FindingKind::Untracked => "untracked",
                FindingKind::IgnoredUnclassified => "ignored_unclassified",
                FindingKind::PolicyMismatch => "policy_mismatch",
            };
            checked(b.output((f.path.as_bytes().len() * 2 + 128) as u64))?;
            self.report.inspection_findings.push(ContentFinding {
                path_hex: hex(f.path.as_bytes()),
                kind,
            });
        }
        let local = Local::capture(context, inputs, b)?;
        let identity = context
            .allocation
            .identity
            .as_ref()
            .ok_or("identity_unknown")?;
        let mut binding = Vec::new();
        frame(&mut binding, 0, b"work.preservation-audit.inputs.v1");
        for bytes in [
            inputs.fingerprint(),
            census.fingerprint(),
            proof.canonical.clone(),
            local.fingerprint(),
        ] {
            frame(&mut binding, 1, &bytes);
        }
        let mut policy = policies.canonical_bytes().to_vec();
        frame(
            &mut policy,
            1,
            &serde_json::to_vec(
                &document
                    .remote_preservation()
                    .map_err(|_| "policy_unknown")?,
            )
            .map_err(|_| "policy_unknown")?,
        );
        let object_format = format_name(inputs.format);
        let mut roots = Vec::new();
        for (id, provenance) in &local.roots {
            let object = local.objects.get(id).ok_or("missing_root_object")?;
            let id = ascii_oid(id)?;
            let proposed_ref = format!(
                "refs/work-recovery/{}/{object_format}/{id}",
                self.report.checkout
            );
            checked(b.output((id.len() + proposed_ref.len() + 256) as u64))?;
            roots.push(RecoveryRoot {
                oid: id,
                object_type: object.kind,
                provenance: provenance.clone(),
                remote_relationship: "unknown",
                proposed_ref,
            });
        }
        self.report.local_object_count = local.objects.len();
        self.report.recovery_manifest = Some(RecoveryManifest {
            format: 1,
            checkout: self.report.checkout,
            object_format,
            common_identity_digest: hex(&Sha256::digest(
                [
                    identity.common_git_dir.as_os_str().as_bytes(),
                    &local.admin.fingerprint(),
                ]
                .concat(),
            )),
            context_digest: hex(&Sha256::digest(&context.canonical)),
            policy_digest: hex(&Sha256::digest(policy)),
            input_digest: hex(&Sha256::digest(binding)),
            roots,
        });
        self.local = Some(local);
        Ok(())
    }
    // Bytes originate solely from the fixed command in the remote coordinator,
    // after exact remote OID/type/fsck and before ANY local object import.
    pub(super) fn remote_graph(
        &mut self,
        bytes: &[u8],
        remote_oid: &str,
        format: ObjectFormat,
        b: &mut Budget,
    ) -> Held<()> {
        let graph = parse_graph(bytes, format)?;
        if !graph.contains(remote_oid.as_bytes()) {
            return Err("graph_protocol_unknown");
        }
        let local = self.local.as_ref().ok_or("census_unknown")?;
        self.report.remote_reachable_object_count = graph.len();
        for root in &mut self
            .report
            .recovery_manifest
            .as_mut()
            .ok_or("census_unknown")?
            .roots
        {
            root.remote_relationship = if graph.contains(root.oid.as_bytes()) {
                "reachable"
            } else {
                "not_reachable"
            };
        }
        for (id, object) in &local.objects {
            let mut reasons = Vec::new();
            if !graph.contains(id) {
                reasons.push("unpreserved_object");
            }
            // No attempt to assign repository-wide additional work to this
            // checkout. Even remotely present additional work stays held.
            if !local.head_graph.contains(id) {
                reasons.push("shared_work_ownership_unknown");
            }
            if local.unclassified.contains(id) && !graph.contains(id) {
                reasons.push("unclassified_local_work");
            }
            for reason in reasons {
                checked(b.output((id.len() + 128) as u64))?;
                self.report.additional_work_holds.push(WorkHold {
                    reason,
                    oid: ascii_oid(id)?,
                    object_type: object.kind,
                });
            }
        }
        self.graph = Some(graph);
        Ok(())
    }
    pub(super) fn recheck(
        &mut self,
        document: &ConfigDocument,
        context: &Context,
        inputs: &GitInputs,
        b: &mut Budget,
    ) -> Held<()> {
        let policies = document
            .inspection_policies()
            .map_err(|_| "inspection_policy_unknown")?;
        if self.inspection_policy.as_deref() != Some(policies.canonical_bytes()) {
            return Err("inspection_policy_changed");
        }
        let local = self.local.as_ref().ok_or("census_unknown")?;
        checked(local.admin.recheck(b))?;
        let last = Local::capture(context, inputs, b)?;
        checked(local.admin.recheck(b))?;
        checked(last.admin.recheck(b))?;
        if local.fingerprint() != last.fingerprint() {
            return Err("census_changed");
        }
        self.rechecked = true;
        Ok(())
    }
    // Called only after successful closing observations, context comparison,
    // actual owned-scratch cleanup and the original deadline/clock checks.
    pub(super) fn complete(&mut self, b: &mut Budget) -> Held<()> {
        // The bounded body plus the existing terminal reserve accommodates the
        // remote metadata. Never truncate a manifest and label it complete.
        let bytes = serde_json::to_vec(&self.report).map_err(|_| "audit_encoding_unknown")?;
        if bytes.len() as u64 > MAX_OUTPUT_BYTES - TERMINAL_RESERVE {
            return Err("audit_output_unknown");
        }
        checked(b.check())?;
        if self.local.is_none() || self.graph.is_none() || !self.rechecked {
            return Err("audit_sequence_unknown");
        }
        self.sealed = true;
        Ok(())
    }
    pub(super) fn finish(mut self, remote: RemoteReport) -> PreservationReport {
        self.report.cleanup = if remote.cleanup() == "complete" {
            "complete"
        } else if remote.cleanup() == "not_created" {
            "not_created"
        } else {
            "incomplete"
        };
        if self.sealed {
            self.report.coverage = "complete";
            self.report.reason = "preservation_requirements_held";
            if self.report.inspection_findings.is_empty()
                && self.report.additional_work_holds.is_empty()
            {
                self.report.outcome = "observed";
                self.report.reason = "consistent_observation";
            }
        } else {
            // Failed closing evidence must not leave a known-positive graph
            // relationship, even though provisional negative findings survive.
            if let Some(manifest) = &mut self.report.recovery_manifest {
                for root in &mut manifest.roots {
                    if root.remote_relationship == "reachable" {
                        root.remote_relationship = "unknown";
                    }
                }
            }
            self.report.reason = "incomplete_observation";
        }
        self.report.remote_head = Some(remote);
        self.report
    }
}
fn checked<T>(value: Result<T, IncompleteReason>) -> Held<T> {
    value.map_err(|_| "census_unknown")
}
fn ascii_oid(bytes: &[u8]) -> Held<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| "object_unknown")
}
fn format_name(format: ObjectFormat) -> &'static str {
    match format {
        ObjectFormat::Sha1 => "sha1",
        ObjectFormat::Sha256 => "sha256",
    }
}
fn rows(bytes: &[u8]) -> Held<Vec<&[u8]>> {
    if bytes.is_empty() {
        return Ok(vec![]);
    }
    let body = bytes.strip_suffix(b"\n").ok_or("protocol_unknown")?;
    let rows: Vec<_> = body
        .split(|v| *v == b'\n')
        .take(MAX_ENTRIES as usize + 1)
        .collect();
    if rows.len() > MAX_ENTRIES as usize || rows.iter().any(|r| r.is_empty()) {
        return Err("protocol_unknown");
    }
    Ok(rows)
}
fn parse_objects(bytes: &[u8], format: ObjectFormat, b: &mut Budget) -> Held<Objects> {
    let mut objects = Objects::new();
    for row in rows(bytes)? {
        checked(b.check())?;
        let fields: Vec<_> = row.splitn(4, |c| *c == b' ').collect();
        if fields.len() != 3 {
            return Err("object_protocol_unknown");
        }
        let id = checked(oid(fields[0], format))?;
        let kind = match fields[1] {
            b"commit" => "commit",
            b"tree" => "tree",
            b"blob" => "blob",
            b"tag" => "tag",
            _ => return Err("object_type_unknown"),
        };
        let size = checked(decimal(fields[2]))?;
        checked(b.file_length(size))?;
        checked(b.reserve(size))?;
        checked(b.output((id.len() + 64) as u64))?;
        if objects.insert(id, Object { kind, size }).is_some() {
            return Err("object_protocol_unknown");
        }
    }
    if objects.is_empty() {
        return Err("object_census_empty");
    }
    Ok(objects)
}
fn parse_graph(bytes: &[u8], format: ObjectFormat) -> Held<BTreeSet<Vec<u8>>> {
    let mut graph = BTreeSet::new();
    for row in rows(bytes)? {
        if !graph.insert(checked(oid(row, format))?) {
            return Err("graph_protocol_unknown");
        }
    }
    if graph.is_empty() {
        return Err("graph_protocol_unknown");
    }
    Ok(graph)
}
fn add_root(
    roots: &mut Roots,
    id: Vec<u8>,
    kind: &'static str,
    path: &[u8],
    ordinal: Option<u64>,
    b: &mut Budget,
) -> Held<()> {
    checked(b.check())?;
    if roots.len() >= MAX_ENTRIES as usize && !roots.contains_key(&id) {
        return Err("census_budget");
    }
    checked(b.output((path.len() * 2 + id.len() + 128) as u64))?;
    roots.entry(id).or_default().insert(Provenance {
        kind,
        path_hex: hex(path),
        record_ordinal: ordinal,
    });
    Ok(())
}
fn log_oid(bytes: &[u8], format: ObjectFormat) -> Held<Option<Vec<u8>>> {
    if bytes.len() == format.width() * 2 && bytes.iter().all(|c| *c == b'0') {
        return Ok(None);
    }
    checked(oid(bytes, format)).map(Some)
}
fn parse_reflog(
    path: &[u8],
    bytes: &[u8],
    format: ObjectFormat,
    roots: &mut Roots,
    b: &mut Budget,
) -> Held<()> {
    for (index, row) in rows(bytes)?.into_iter().enumerate() {
        if row.contains(&0) || row.contains(&b'\r') {
            return Err("reflog_unknown");
        }
        let width = format.width() * 2;
        if row.len() <= 2 * width + 2 || row[width] != b' ' || row[2 * width + 1] != b' ' {
            return Err("reflog_unknown");
        }
        let rest = &row[2 * width + 2..];
        // Git 2.55 files-backend log_ref_write_fd omits TAB for no message.
        // Only the message is optional; validate the entire identity either way.
        let identity_end = rest.iter().position(|c| *c == b'\t').unwrap_or(rest.len());
        let identity = &rest[..identity_end];
        let mut parts = identity.rsplitn(3, |c| *c == b' ');
        let zone = parts.next().ok_or("reflog_unknown")?;
        let time = parts.next().ok_or("reflog_unknown")?;
        let author = parts.next().ok_or("reflog_unknown")?;
        if zone.len() != 5
            || !matches!(zone[0], b'+' | b'-')
            || !zone[1..].iter().all(u8::is_ascii_digit)
            || &zone[1..3] > b"23".as_slice()
            || &zone[3..5] > b"59".as_slice()
            || time.is_empty()
            || !time.iter().all(u8::is_ascii_digit)
            || !author.ends_with(b">")
            || !author.windows(2).any(|p| p == b" <")
            || author.iter().any(|c| *c < b' ' || *c == 127)
        {
            return Err("reflog_unknown");
        }
        let email_start = author
            .iter()
            .position(|c| *c == b'<')
            .ok_or("reflog_unknown")?;
        if email_start == 0
            || author[email_start - 1] != b' '
            || author[..email_start].contains(&b'>')
            || author[email_start + 1..author.len() - 1]
                .iter()
                .any(|c| *c <= b' ' || b"<>".contains(c))
        {
            return Err("reflog_unknown");
        }
        checked(decimal(time))?;
        for (value, kind) in [
            (&row[..width], "reflog_old"),
            (&row[width + 1..2 * width + 1], "reflog_new"),
        ] {
            if let Some(id) = log_oid(value, format)? {
                add_root(roots, id, kind, path, Some(index as u64 + 1), b)?;
            }
        }
    }
    Ok(())
}

// Sealed retained admin census, not reconstructible from the public report.
pub(super) struct ApprovalLocal {
    local: Local,
    semantic: Vec<u8>,
    invalidation: Vec<u8>,
}
impl ApprovalLocal {
    pub(super) fn semantic(&self) -> Vec<u8> {
        self.semantic.clone()
    }
    pub(super) fn invalidation(&self) -> Vec<u8> {
        self.invalidation.clone()
    }
    pub(super) fn recheck(&self, b: &mut Budget) -> Held<()> {
        checked(self.local.admin.recheck(b))
    }
}

pub(super) struct RecoveryPlanRow {
    pub reference: String,
    pub oid: String,
    pub object_type: &'static str,
    pub provenance: Vec<u8>,
}

pub(super) struct RecoveryCensus {
    local: Local,
}
impl RecoveryCensus {
    pub(super) fn reserved_namespace_held(&self) -> bool {
        self.local.reserved_held
    }
    pub(super) fn common_dev_ino(&self) -> (u64, u64) {
        self.local.admin.root_dev_ino()
    }
    pub(super) fn common(&self) -> &filesystem::Manifest {
        &self.local.admin
    }
    pub(super) fn common_mut(&mut self) -> &mut filesystem::Manifest {
        &mut self.local.admin
    }
    pub(super) fn format(&self) -> ObjectFormat {
        self.local.format
    }
    pub(super) fn object_format(&self) -> &'static str {
        format_name(self.local.format)
    }
    pub(super) fn source_witness(
        &self,
        checkout: &filesystem::Census,
        inputs: &GitInputs,
        config: Option<&filesystem::Manifest>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        frame(&mut out, 0, b"work.recovery.source.v1");
        frame(&mut out, 1, checkout.fingerprint().as_slice());
        frame(&mut out, 2, &inputs.source_witness());
        frame(&mut out, 3, &self.local.admin.source_witness());
        for (id, object) in &self.local.objects {
            frame(&mut out, 4, id);
            frame(&mut out, 5, object.kind.as_bytes());
            frame(&mut out, 6, &object.size.to_be_bytes());
        }
        for (id, provenance) in &self.local.roots {
            frame(&mut out, 7, id);
            frame(
                &mut out,
                8,
                &serde_json::to_vec(provenance).unwrap_or_default(),
            );
        }
        for id in &self.local.unclassified {
            frame(&mut out, 9, id);
        }
        for id in &self.local.head_graph {
            frame(&mut out, 10, id);
        }
        frame(&mut out, 11, &Sha256::digest(&self.local.native_nonref));
        if let Some(config) = config {
            frame(&mut out, 12, &config.fingerprint());
        }
        frame(&mut out, 13, &encode_native_refs(&self.local.native_refs));
        out
    }
    pub(super) fn source_commitment(
        &self,
        checkout: &filesystem::Census,
        inputs: &GitInputs,
        config: Option<&filesystem::Manifest>,
    ) -> [u8; 32] {
        let digest = Sha256::digest(self.source_witness(checkout, inputs, config));
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
    pub(super) fn packed_recovery(&self) -> bool {
        self.local
            .recovery_refs
            .keys()
            .any(|path| !self.local.admin.contains(path))
    }
    pub(super) fn existing_target(&self, reference: &str) -> Option<&[u8]> {
        self.local
            .recovery_refs
            .get(reference.as_bytes())
            .map(|v| v.as_slice())
    }
    pub(super) fn plan(&self, checkout: Uuid) -> Held<Vec<RecoveryPlanRow>> {
        let object_format = format_name(self.local.format);
        let mut plan = Vec::new();
        for (id, provenance) in &self.local.roots {
            let object = self.local.objects.get(id).ok_or("missing_root_object")?;
            let oid = ascii_oid(id)?;
            let reference = format!("refs/work-recovery/{checkout}/{object_format}/{oid}");
            plan.push(RecoveryPlanRow {
                reference,
                oid,
                object_type: object.kind,
                provenance: encode_provenance(provenance)?,
            });
        }
        plan.sort_by(|a, b| a.reference.cmp(&b.reference));
        Ok(plan)
    }
    pub(super) fn recheck(&self, b: &mut Budget) -> Held<()> {
        checked(self.local.admin.recheck(b))
    }
    pub(super) fn recapture(
        context: &Context,
        b: &mut Budget,
    ) -> Held<(Self, filesystem::Census, GitInputs)> {
        let identity = context
            .allocation
            .identity
            .as_ref()
            .ok_or("identity_unknown")?;
        let census = checked(filesystem::walk(
            &identity.path,
            b,
            &mut filesystem::SystemBoundary,
        ))?;
        let inputs = checked(GitInputs::capture(context, &census, b))?;
        Ok((
            Self {
                local: Local::capture(context, &inputs, b)?,
            },
            census,
            inputs,
        ))
    }
    pub(super) fn expected_delta(
        &self,
        before: &Self,
        before_checkout: &filesystem::Census,
        before_inputs: &GitInputs,
        after_checkout: &filesystem::Census,
        after_inputs: &GitInputs,
        planned_new: &BTreeSet<Vec<u8>>,
    ) -> Held<()> {
        if after_checkout.fingerprint() != before_checkout.fingerprint() {
            return Err("census_changed");
        }
        if after_inputs.private.source_witness() != before_inputs.private.source_witness()
            || after_inputs.checkout.source_witness() != before_inputs.checkout.source_witness()
            || after_inputs.boot != before_inputs.boot
            || after_inputs.version != before_inputs.version
            || after_inputs.endpoints.len() != before_inputs.endpoints.len()
        {
            return Err("census_changed");
        }
        for (after, original) in after_inputs
            .endpoints
            .iter()
            .zip(before_inputs.endpoints.iter())
        {
            if after.fingerprint() != original.fingerprint() {
                return Err("census_changed");
            }
        }
        checked(
            after_inputs
                .common
                .recovery_delta(&before_inputs.common, planned_new),
        )?;
        checked(
            self.local
                .admin
                .recovery_delta(&before.local.admin, planned_new),
        )?;
        if self.local.objects != before.local.objects
            || self.local.roots != before.local.roots
            || self.local.unclassified != before.local.unclassified
            || self.local.head_graph != before.local.head_graph
        {
            return Err("census_changed");
        }
        Ok(())
    }
    pub(super) fn verify_named(&self, targets: &[(String, String)]) -> Held<()> {
        for (reference, oid) in targets {
            match self.existing_target(reference) {
                Some(existing) if existing == oid.as_bytes() => (),
                _ => return Err("recovery_target_unknown"),
            }
            if !self.local.objects.contains_key(oid.as_bytes()) {
                return Err("missing_root_object");
            }
        }
        Ok(())
    }
    pub(super) fn verify_closure(&self, original: &Self, targets: &[(String, String)]) -> Held<()> {
        self.verify_named(targets)?;
        if self.local.objects != original.local.objects {
            return Err("object_census_inconsistent");
        }
        for (id, object) in &original.local.objects {
            let Some((_, oid)) = targets
                .iter()
                .find(|(_, oid)| oid.as_bytes() == id.as_slice())
            else {
                if !original.local.roots.contains_key(id) {
                    continue;
                }
                return Err("incomplete_closure");
            };
            let Some(current) = self.local.objects.get(oid.as_bytes()) else {
                return Err("missing_root_object");
            };
            if current.kind != object.kind || current.size != object.size {
                return Err("object_type_unknown");
            }
        }
        for id in original.local.roots.keys() {
            if !targets
                .iter()
                .any(|(_, oid)| oid.as_bytes() == id.as_slice())
            {
                return Err("incomplete_closure");
            }
        }
        Ok(())
    }
    pub(super) fn closure_digest(
        &self,
        checkout: &filesystem::Census,
        inputs: &GitInputs,
        config: Option<&filesystem::Manifest>,
    ) -> [u8; 32] {
        self.source_commitment(checkout, inputs, config)
    }
    pub(super) fn planned_new(&self, plan: &BTreeSet<Vec<u8>>) -> BTreeSet<Vec<u8>> {
        plan.iter()
            .filter(|name| {
                self.existing_target(std::str::from_utf8(name).unwrap_or(""))
                    .is_none()
            })
            .cloned()
            .collect()
    }
}

fn take_frames(bytes: &[u8]) -> Held<Vec<(u8, Vec<u8>)>> {
    let mut at = 0;
    let mut out = Vec::new();
    while at < bytes.len() {
        let tag = *bytes.get(at).ok_or("census_changed")?;
        at += 1;
        let raw = bytes
            .get(at..at.saturating_add(8))
            .ok_or("census_changed")?;
        let len = u64::from_be_bytes(raw.try_into().map_err(|_| "census_changed")?);
        at += 8;
        let n = usize::try_from(len).map_err(|_| "census_changed")?;
        let end = at.checked_add(n).ok_or("census_changed")?;
        let value = bytes.get(at..end).ok_or("census_changed")?.to_vec();
        at = end;
        out.push((tag, value));
    }
    Ok(out)
}

struct WitnessPath {
    identity: Vec<u8>,
    directory: bool,
    names: Vec<Vec<u8>>,
    content: Option<Vec<u8>>,
}

struct ManifestWitness {
    paths: BTreeMap<Vec<u8>, WitnessPath>,
    absent: BTreeSet<Vec<u8>>,
}

fn encode_manifest_witness(witness: &ManifestWitness) -> Vec<u8> {
    let mut out = Vec::new();
    frame(&mut out, 0, b"work.recovery.manifest.v1");
    for (path, held) in &witness.paths {
        frame(&mut out, 1, path);
        frame(&mut out, 2, &held.identity);
        frame(&mut out, 3, &[u8::from(held.directory)]);
        for name in &held.names {
            frame(&mut out, 4, name);
        }
        if let Some(content) = &held.content {
            frame(&mut out, 5, content);
        }
    }
    for path in &witness.absent {
        frame(&mut out, 6, path);
    }
    out
}

fn parse_manifest_witness(bytes: &[u8]) -> Held<ManifestWitness> {
    let frames = take_frames(bytes)?;
    let mut paths = BTreeMap::new();
    let mut absent = BTreeSet::new();
    let mut last_path: Option<Vec<u8>> = None;
    let mut i = match frames.first() {
        Some((0, value)) if value == b"work.recovery.manifest.v1" => 1,
        _ => return Err("census_changed"),
    };
    while i < frames.len() {
        match frames[i].0 {
            1 => {
                let path = frames[i].1.clone();
                i += 1;
                if last_path.as_ref().is_some_and(|prev| prev >= &path)
                    || paths.contains_key(&path)
                    || absent.contains(&path)
                {
                    return Err("census_changed");
                }
                if i >= frames.len() || frames[i].0 != 2 {
                    return Err("census_changed");
                }
                let identity = frames[i].1.clone();
                i += 1;
                if i >= frames.len() || frames[i].0 != 3 {
                    return Err("census_changed");
                }
                let directory = match frames[i].1.as_slice() {
                    [1] => true,
                    [0] => false,
                    _ => return Err("census_changed"),
                };
                i += 1;
                let mut names = Vec::new();
                let mut seen_names = BTreeSet::new();
                while i < frames.len() && frames[i].0 == 4 {
                    if names.last().is_some_and(|prev| prev >= &frames[i].1)
                        || !seen_names.insert(frames[i].1.clone())
                    {
                        return Err("census_changed");
                    }
                    names.push(frames[i].1.clone());
                    i += 1;
                }
                let mut content = None;
                if i < frames.len() && frames[i].0 == 5 {
                    content = Some(frames[i].1.clone());
                    i += 1;
                }
                if i < frames.len() && matches!(frames[i].0, 2 | 3 | 5) {
                    return Err("census_changed");
                }
                last_path = Some(path.clone());
                paths.insert(
                    path,
                    WitnessPath {
                        identity,
                        directory,
                        names,
                        content,
                    },
                );
            }
            6 => break,
            _ => return Err("census_changed"),
        }
    }
    let mut last_absent: Option<Vec<u8>> = None;
    while i < frames.len() {
        if frames[i].0 != 6 {
            return Err("census_changed");
        }
        let path = frames[i].1.clone();
        if last_absent.as_ref().is_some_and(|prev| prev >= &path)
            || paths.contains_key(&path)
            || !absent.insert(path.clone())
        {
            return Err("census_changed");
        }
        last_absent = Some(path);
        i += 1;
    }
    let witness = ManifestWitness { paths, absent };
    if encode_manifest_witness(&witness) != bytes {
        return Err("census_changed");
    }
    Ok(witness)
}

fn binding_blob(identity: &[u8]) -> Held<([u8; 24], [u8; 16])> {
    if identity.len() != 88 {
        return Err("census_changed");
    }
    let mut head = [0u8; 24];
    head.copy_from_slice(&identity[..24]);
    let mut ids = [0u8; 16];
    ids.copy_from_slice(&identity[32..48]);
    Ok((head, ids))
}

fn manifest_witness_delta(
    before: &[u8],
    after: &[u8],
    planned_new: &BTreeSet<Vec<u8>>,
) -> Held<()> {
    let ManifestWitness {
        paths: before_paths,
        absent: before_absent,
    } = parse_manifest_witness(before)?;
    let ManifestWitness {
        paths: after_paths,
        absent: after_absent,
    } = parse_manifest_witness(after)?;
    let mut allowed_dirs = BTreeSet::new();
    for path in planned_new {
        let mut i = 0;
        while let Some(rel) = path[i..].iter().position(|c| *c == b'/') {
            i += rel;
            allowed_dirs.insert(path[..i].to_vec());
            i += 1;
        }
    }
    for (path, was) in &before_paths {
        let now = after_paths.get(path).ok_or("census_changed")?;
        if was.directory {
            if allowed_dirs.contains(path) {
                if binding_blob(&was.identity)? != binding_blob(&now.identity)? || !now.directory {
                    return Err("census_changed");
                }
            } else if was.identity != now.identity || was.names != now.names || !now.directory {
                return Err("census_changed");
            }
        } else if was.identity != now.identity || was.content != now.content || now.directory {
            return Err("census_changed");
        }
    }
    for (path, now) in &after_paths {
        if before_paths.contains_key(path) {
            continue;
        }
        if now.directory {
            if !allowed_dirs.contains(path) {
                return Err("census_changed");
            }
        } else if !planned_new.contains(path) {
            return Err("census_changed");
        }
    }
    for path in &before_absent {
        if planned_new.contains(path) {
            continue;
        }
        if !after_absent.contains(path) {
            return Err("census_changed");
        }
    }
    Ok(())
}

pub(super) fn planned_new_from_witness(
    original: &[u8],
    plan: &BTreeSet<Vec<u8>>,
) -> Held<BTreeSet<Vec<u8>>> {
    let frames = take_frames(original)?;
    let mut present = BTreeSet::new();
    let mut found = false;
    for (tag, value) in frames {
        if tag == 13 {
            if found {
                return Err("census_changed");
            }
            found = true;
            present.extend(parse_native_refs(&value)?.into_keys());
        }
    }
    if !found {
        return Err("census_changed");
    }
    Ok(plan.difference(&present).cloned().collect())
}

pub(super) fn source_witness_delta(
    original: &[u8],
    current: &[u8],
    planned_new: &BTreeSet<Vec<u8>>,
) -> Held<()> {
    let original = take_frames(original)?;
    let current = take_frames(current)?;
    if original.len() != current.len() {
        return Err("census_changed");
    }
    for (before, after) in original.iter().zip(current.iter()) {
        if before.0 != after.0 {
            return Err("census_changed");
        }
        match before.0 {
            0 => {
                if before.1 != b"work.recovery.source.v1" || after.1 != before.1 {
                    return Err("census_changed");
                }
            }
            2 => {
                let before_inputs = take_frames(&before.1)?;
                let after_inputs = take_frames(&after.1)?;
                if before_inputs.len() != after_inputs.len() {
                    return Err("census_changed");
                }
                for (left, right) in before_inputs.iter().zip(after_inputs.iter()) {
                    if left.0 != right.0 {
                        return Err("census_changed");
                    }
                    if left.0 == 1 {
                        manifest_witness_delta(&left.1, &right.1, planned_new)?;
                    } else if left.1 != right.1 {
                        return Err("census_changed");
                    }
                }
            }
            3 => manifest_witness_delta(&before.1, &after.1, planned_new)?,
            13 => native_ref_delta(&before.1, &after.1, planned_new)?,
            _ if before.1 != after.1 => return Err("census_changed"),
            _ => (),
        }
    }
    Ok(())
}

fn encode_native_refs(refs: &BTreeMap<Vec<u8>, Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, id) in refs {
        frame(&mut out, 1, name);
        frame(&mut out, 2, id);
    }
    out
}

fn parse_native_refs(bytes: &[u8]) -> Held<BTreeMap<Vec<u8>, Vec<u8>>> {
    let frames = take_frames(bytes)?;
    if frames.len() % 2 != 0 {
        return Err("census_changed");
    }
    let mut refs = BTreeMap::new();
    let mut previous: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < frames.len() {
        if frames[i].0 != 1 || frames[i + 1].0 != 2 {
            return Err("census_changed");
        }
        let name = frames[i].1.clone();
        let id = frames[i + 1].1.clone();
        if previous.as_ref().is_some_and(|p| p >= &name) || refs.insert(name.clone(), id).is_some()
        {
            return Err("census_changed");
        }
        previous = Some(name);
        i += 2;
    }
    Ok(refs)
}

fn native_ref_delta(before: &[u8], after: &[u8], planned_new: &BTreeSet<Vec<u8>>) -> Held<()> {
    let original = parse_native_refs(before)?;
    let current = parse_native_refs(after)?;
    for (name, oid) in &original {
        match current.get(name) {
            Some(now) if now == oid => (),
            _ => return Err("census_changed"),
        }
    }
    for name in current.keys() {
        if original.contains_key(name) {
            continue;
        }
        if !planned_new.contains(name) {
            return Err("census_changed");
        }
    }
    Ok(())
}

const PROVENANCE_KINDS: &[&str] = &[
    "named_ref",
    "HEAD",
    "reflog_old",
    "reflog_new",
    "unreachable_census",
    "unclassified_census",
    "administrative_HEAD",
    "pseudoref",
];

fn provenance_kind(bytes: &[u8]) -> Held<&'static str> {
    PROVENANCE_KINDS
        .iter()
        .copied()
        .find(|kind| kind.as_bytes() == bytes)
        .ok_or("record_corrupt")
}

fn hex_text(text: &str) -> bool {
    text.len().is_multiple_of(2) && text.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

fn encode_provenance(set: &BTreeSet<Provenance>) -> Held<Vec<u8>> {
    let mut out = Vec::new();
    for provenance in set {
        provenance_kind(provenance.kind.as_bytes())?;
        if !hex_text(&provenance.path_hex) {
            return Err("record_corrupt");
        }
        frame(&mut out, 1, provenance.kind.as_bytes());
        frame(&mut out, 2, provenance.path_hex.as_bytes());
        match provenance.record_ordinal {
            Some(n) => frame(&mut out, 3, &n.to_be_bytes()),
            None => frame(&mut out, 3, &[]),
        }
    }
    Ok(out)
}

fn decode_provenance(bytes: &[u8]) -> Held<BTreeSet<Provenance>> {
    let frames = take_frames(bytes).map_err(|_| "record_corrupt")?;
    if frames.len() % 3 != 0 {
        return Err("record_corrupt");
    }
    let mut set = BTreeSet::new();
    let mut i = 0;
    while i < frames.len() {
        if frames[i].0 != 1 || frames[i + 1].0 != 2 || frames[i + 2].0 != 3 {
            return Err("record_corrupt");
        }
        let kind = provenance_kind(&frames[i].1)?;
        let path_hex = std::str::from_utf8(&frames[i + 1].1).map_err(|_| "record_corrupt")?;
        if !hex_text(path_hex) {
            return Err("record_corrupt");
        }
        let record_ordinal = match frames[i + 2].1.as_slice() {
            [] => None,
            raw => Some(u64::from_be_bytes(
                raw.try_into().map_err(|_| "record_corrupt")?,
            )),
        };
        if !set.insert(Provenance {
            kind,
            path_hex: path_hex.to_owned(),
            record_ordinal,
        }) {
            return Err("record_corrupt");
        }
        i += 3;
    }
    Ok(set)
}

pub(super) fn validate_provenance(bytes: &[u8]) -> Held<()> {
    let encoded = encode_provenance(&decode_provenance(bytes)?)?;
    if encoded != bytes {
        return Err("record_corrupt");
    }
    Ok(())
}

enum RecoveryNs {
    Ordinary,
    Valid,
    Invalid,
}
fn recovery_namespace(path: &[u8], target: &[u8], format: ObjectFormat) -> RecoveryNs {
    let rest = match path.strip_prefix(b"refs/work-recovery") {
        None => return RecoveryNs::Ordinary,
        Some(b"") => return RecoveryNs::Invalid,
        Some(rest) => match rest.strip_prefix(b"/") {
            Some(rest) => rest,
            None => return RecoveryNs::Invalid,
        },
    };
    let parts: Vec<_> = rest.split(|c| *c == b'/').collect();
    if parts.len() != 3 {
        return RecoveryNs::Invalid;
    }
    let Ok(text) = std::str::from_utf8(parts[0]) else {
        return RecoveryNs::Invalid;
    };
    let Ok(id) = Uuid::parse_str(text) else {
        return RecoveryNs::Invalid;
    };
    if id.get_version_num() != 7
        || id.get_variant() != uuid::Variant::RFC4122
        || id.to_string() != text
    {
        return RecoveryNs::Invalid;
    }
    let expected = match format {
        ObjectFormat::Sha1 => b"sha1".as_slice(),
        ObjectFormat::Sha256 => b"sha256".as_slice(),
    };
    if parts[1] != expected {
        return RecoveryNs::Invalid;
    }
    if parts[2] != target || oid(parts[2], format).is_err() {
        return RecoveryNs::Invalid;
    }
    RecoveryNs::Valid
}
struct Local {
    admin: filesystem::Manifest,
    objects: Objects,
    roots: Roots,
    head_graph: BTreeSet<Vec<u8>>,
    unclassified: BTreeSet<Vec<u8>>,
    native_digest: Vec<u8>,
    native_nonref: Vec<u8>,
    native_refs: BTreeMap<Vec<u8>, Vec<u8>>,
    recovery_refs: BTreeMap<Vec<u8>, Vec<u8>>,
    reserved_held: bool,
    format: ObjectFormat,
}
impl Local {
    fn fingerprint(&self) -> Vec<u8> {
        let mut out = self.admin.fingerprint();
        frame(&mut out, 1, &self.native_digest);
        for (id, object) in &self.objects {
            frame(&mut out, 2, id);
            frame(&mut out, 3, object.kind.as_bytes());
            frame(&mut out, 4, &object.size.to_be_bytes());
        }
        Sha256::digest(out).to_vec()
    }
    fn capture(context: &Context, inputs: &GitInputs, b: &mut Budget) -> Held<Self> {
        let identity = context
            .allocation
            .identity
            .as_ref()
            .ok_or("identity_unknown")?;
        let mut admin = checked(filesystem::Manifest::new(&identity.common_git_dir, b))?;
        let mut refs = match checked(admin.optional(b"packed-refs", b))? {
            Some(bytes) => checked(packed_refs(&bytes, inputs.format))?,
            None => BTreeMap::new(),
        };
        checked(collect_refs(
            &mut admin,
            b"refs",
            0,
            inputs.format,
            b,
            &mut refs,
        ))?;
        // Per-worktree namespaces are deliberately not widened by this audit.
        if refs.keys().any(|r| {
            [
                b"refs/bisect/".as_slice(),
                b"refs/rewritten/",
                b"refs/worktree/",
            ]
            .iter()
            .any(|p| r.starts_with(p))
        }) {
            return Err("private_refs_unsupported");
        }
        let mut roots = Roots::new();
        let mut recovery_refs = BTreeMap::new();
        let mut reserved_held = false;
        for (path, id) in &refs {
            match recovery_namespace(path, id, inputs.format) {
                RecoveryNs::Ordinary => {
                    add_root(&mut roots, id.clone(), "named_ref", path, None, b)?;
                }
                RecoveryNs::Valid => {
                    recovery_refs.insert(path.clone(), id.clone());
                }
                RecoveryNs::Invalid => {
                    reserved_held = true;
                }
            }
        }
        let mut admin_heads = Vec::new();
        administrative(
            &mut admin,
            b"",
            &refs,
            inputs.format,
            &mut roots,
            &mut admin_heads,
            b,
        )?;
        for name in checked(admin.list(b"worktrees", b))? {
            let prefix = joined(b"worktrees", &name);
            administrative(
                &mut admin,
                &prefix,
                &refs,
                inputs.format,
                &mut roots,
                &mut admin_heads,
                b,
            )?;
        }
        add_root(&mut roots, inputs.head.clone(), "HEAD", b"HEAD", None, b)?;
        checked(admin.recheck(b))?;
        let charge = checked(inputs.native_read_reservation())?
            .checked_add(admin.read_size())
            .ok_or("census_budget")?;
        let mut native_digest = Vec::new();
        let mut native_nonref = Vec::new();
        let mut command =
            |args: &[&str], stdin: &[u8], b: &mut Budget, bind_nonref: bool| -> Held<Vec<u8>> {
                checked(b.reserve(charge))?;
                b.counters.native_input_reserved_bytes += charge;
                let bytes = checked(git_success(Some(&identity.path), args, stdin, b))?;
                for arg in args {
                    frame(&mut native_digest, 1, arg.as_bytes());
                    if bind_nonref {
                        frame(&mut native_nonref, 1, arg.as_bytes());
                    }
                }
                frame(&mut native_digest, 2, &Sha256::digest(stdin));
                frame(&mut native_digest, 3, &Sha256::digest(&bytes));
                if bind_nonref {
                    frame(&mut native_nonref, 2, &Sha256::digest(stdin));
                    frame(&mut native_nonref, 3, &Sha256::digest(&bytes));
                }
                Ok(bytes)
            };
        let effective = command(
            &["for-each-ref", "--format=%(objectname)%00%(refname)"],
            b"",
            b,
            false,
        )?;
        let mut native_refs = BTreeMap::new();
        for row in rows(&effective)? {
            let separator = row
                .iter()
                .position(|c| *c == 0)
                .ok_or("ref_protocol_unknown")?;
            let (id, name) = (&row[..separator], &row[separator + 1..]);
            if !valid_ref(name)
                || !name.starts_with(b"refs/")
                || native_refs
                    .insert(name.to_vec(), checked(oid(id, inputs.format))?)
                    .is_some()
            {
                return Err("ref_protocol_unknown");
            }
        }
        if refs != native_refs {
            return Err("refs_changed");
        }
        // Root/pseudoref crosschecks address only administrative directories,
        // never open or walk any sibling worktree payload.
        for (prefix, name, expected) in admin_heads {
            let dir = identity
                .common_git_dir
                .join(std::ffi::OsStr::from_bytes(&prefix));
            let dir = dir.to_str().ok_or("admin_path_unknown")?;
            let name = std::str::from_utf8(&name).map_err(|_| "admin_path_unknown")?;
            let bytes = command(
                &["--git-dir", dir, "rev-parse", "--verify", name],
                b"",
                b,
                true,
            )?;
            if checked(oid(checked(line(&bytes))?, inputs.format))? != expected {
                return Err("refs_changed");
            }
        }
        let bytes = command(
            &[
                "cat-file",
                "--batch-all-objects",
                "--batch-check=%(objectname) %(objecttype) %(objectsize)",
            ],
            b"",
            b,
            true,
        )?;
        let objects = parse_objects(&bytes, inputs.format, b)?;
        let head = ascii_oid(&inputs.head)?;
        // A supplied root prevents fsck's default sibling-index traversal. Full
        // object validation still scans every loose/packed object, reachable or
        // not. No --connectivity-only and no --lost-found writes.
        let validation = command(
            &[
                "fsck",
                "--full",
                "--strict",
                "--no-reflogs",
                "--no-dangling",
                &head,
            ],
            b"",
            b,
            true,
        )?;
        if !validation.is_empty() {
            return Err("object_validation_unknown");
        }
        for id in roots.keys() {
            if !objects.contains_key(id) {
                return Err("missing_root_object");
            }
        }
        let head_graph = parse_graph(
            &command(
                &["rev-list", "--objects", "--no-object-names", &head],
                b"",
                b,
                true,
            )?,
            inputs.format,
        )?;
        let mut root_input = Vec::new();
        for id in roots.keys() {
            root_input.extend(id);
            root_input.push(b'\n');
        }
        let rooted = parse_graph(
            &command(
                &["rev-list", "--objects", "--no-object-names", "--stdin"],
                &root_input,
                b,
                true,
            )?,
            inputs.format,
        )?;
        if !head_graph.contains(&inputs.head) || roots.keys().any(|id| !rooted.contains(id)) {
            return Err("graph_protocol_unknown");
        }
        for (id, object) in &objects {
            if object.kind == "commit" && !rooted.contains(id) {
                add_root(&mut roots, id.clone(), "unreachable_census", b"", None, b)?;
            }
        }
        let mut all_commits_and_roots = BTreeSet::new();
        all_commits_and_roots.extend(roots.keys().cloned());
        all_commits_and_roots.extend(
            objects
                .iter()
                .filter(|(_, o)| o.kind == "commit")
                .map(|(id, _)| id.clone()),
        );
        let mut input = Vec::new();
        for id in all_commits_and_roots {
            input.extend(id);
            input.push(b'\n');
        }
        let classified = parse_graph(
            &command(
                &["rev-list", "--objects", "--no-object-names", "--stdin"],
                &input,
                b,
                true,
            )?,
            inputs.format,
        )?;
        if roots.keys().any(|id| !classified.contains(id)) {
            return Err("graph_protocol_unknown");
        }
        for graph in [&head_graph, &rooted, &classified] {
            if graph.iter().any(|id| !objects.contains_key(id)) {
                return Err("object_census_inconsistent");
            }
        }
        let mut unclassified = BTreeSet::new();
        for (id, object) in &objects {
            if object.kind != "commit" && !classified.contains(id) {
                unclassified.insert(id.clone());
                add_root(&mut roots, id.clone(), "unclassified_census", b"", None, b)?;
            }
        }
        checked(admin.recheck(b))?;
        checked(inputs.recheck(b))?;
        Ok(Self {
            admin,
            objects,
            roots,
            head_graph,
            unclassified,
            native_digest,
            native_nonref,
            native_refs,
            recovery_refs,
            reserved_held,
            format: inputs.format,
        })
    }
}
// Only these plain administrative pseudorefs are supported. FETCH_HEAD and
// merge/rebase/bisect sequencer layouts are unknown rather than partially read.
const PSEUDOREFS: &[&[u8]] = &[
    b"ORIG_HEAD",
    b"CHERRY_PICK_HEAD",
    b"REVERT_HEAD",
    b"REBASE_HEAD",
    b"AUTO_MERGE",
    b"BISECT_HEAD",
];
type AdminHeads = Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>;
fn administrative(
    m: &mut filesystem::Manifest,
    prefix: &[u8],
    refs: &BTreeMap<Vec<u8>, Vec<u8>>,
    format: ObjectFormat,
    roots: &mut Roots,
    heads: &mut AdminHeads,
    b: &mut Budget,
) -> Held<()> {
    for name in checked(m.list(prefix, b))? {
        let allowed = if prefix.is_empty() {
            matches!(
                name.as_slice(),
                b"HEAD"
                    | b"config"
                    | b"description"
                    | b"hooks"
                    | b"info"
                    | b"index"
                    | b"logs"
                    | b"objects"
                    | b"packed-refs"
                    | b"refs"
                    | b"worktrees"
                    | b"COMMIT_EDITMSG"
            )
        } else {
            matches!(
                name.as_slice(),
                b"HEAD"
                    | b"commondir"
                    | b"gitdir"
                    | b"index"
                    | b"logs"
                    | b"refs"
                    | b"work-lease.json"
                    | b"locked"
                    | b"config.worktree"
                    | b"COMMIT_EDITMSG"
            )
        };
        if !allowed && !PSEUDOREFS.contains(&name.as_slice()) {
            return Err("admin_layout_unknown");
        }
    }
    if !prefix.is_empty() {
        // Preflight every supported sibling's config and unsafe metadata too,
        // without widening Task9's empty private refs envelope.
        for name in [
            b"objects".as_slice(),
            b"packed-refs",
            b"reftable",
            b"shallow",
            b"info",
            b"modules",
        ] {
            checked(m.absent(&joined(prefix, name), b))?;
        }
        if let Some(bytes) = checked(m.optional(&joined(prefix, b"config.worktree"), b))? {
            if checked(parse_config(&bytes, b))?.is_some_and(|f| f != format) {
                return Err("admin_config_unknown");
            }
        }
        let path = joined(prefix, b"refs");
        match m.absent(&path, b) {
            Ok(()) => (),
            Err(IncompleteReason::UnsupportedGit) => {
                if !checked(m.list(&path, b))?.is_empty() {
                    return Err("private_refs_unsupported");
                }
            }
            Err(_) => return Err("admin_layout_unknown"),
        }
    }
    let path = joined(prefix, b"HEAD");
    let (id, _) = checked(head_value(&checked(m.required(&path, b))?, refs, format))?;
    add_root(roots, id.clone(), "administrative_HEAD", &path, None, b)?;
    heads.push((prefix.to_vec(), b"HEAD".to_vec(), id));
    for name in PSEUDOREFS {
        let path = joined(prefix, name);
        if let Some(bytes) = checked(m.optional(&path, b))? {
            let id = checked(oid(checked(line(&bytes))?, format))?;
            add_root(roots, id.clone(), "pseudoref", &path, None, b)?;
            heads.push((prefix.to_vec(), name.to_vec(), id));
        }
    }
    let logs = joined(prefix, b"logs");
    match m.absent(&logs, b) {
        Ok(()) => Ok(()),
        Err(IncompleteReason::UnsupportedGit) => logs_walk(m, &logs, &logs, 0, format, roots, b),
        Err(_) => Err("reflog_unknown"),
    }
}
fn logs_walk(
    m: &mut filesystem::Manifest,
    base: &[u8],
    path: &[u8],
    depth: usize,
    format: ObjectFormat,
    roots: &mut Roots,
    b: &mut Budget,
) -> Held<()> {
    if depth > MAX_DEPTH {
        return Err("census_budget");
    }
    for name in checked(m.list(path, b))? {
        let next = joined(path, &name);
        let relative = next
            .strip_prefix(base)
            .and_then(|v| v.strip_prefix(b"/"))
            .ok_or("reflog_unknown")?;
        if !valid_ref(relative)
            || !(relative == b"HEAD" || relative == b"refs" || relative.starts_with(b"refs/"))
        {
            return Err("reflog_layout_unknown");
        }
        if checked(m.is_directory(&next, b))? {
            if relative == b"HEAD" {
                return Err("reflog_layout_unknown");
            }
            logs_walk(m, base, &next, depth + 1, format, roots, b)?;
        } else {
            if relative == b"refs" {
                return Err("reflog_layout_unknown");
            }
            parse_reflog(&next, &checked(m.required(&next, b))?, format, roots, b)?;
        }
    }
    Ok(())
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

    #[test]
    fn strict_object_and_graph_protocols_reject_omission_ambiguity_and_unknown_types() {
        let id = "1".repeat(40);
        let row = format!("{id} commit 12\n");
        let mut b = Budget::new();
        assert!(parse_objects(row.as_bytes(), ObjectFormat::Sha1, &mut b).is_ok());
        for bytes in [
            format!("{row}{row}"),
            row.replace("commit", "future"),
            row.replace("12", "012"),
            row.replace("12", "18446744073709551616"),
            row.trim_end().to_owned(),
            row.replace('1', "0"),
        ] {
            assert!(
                parse_objects(bytes.as_bytes(), ObjectFormat::Sha1, &mut Budget::new()).is_err()
            );
        }
        assert!(parse_graph(format!("{id}\n").as_bytes(), ObjectFormat::Sha1).is_ok());
        for bytes in [
            String::new(),
            format!("{id}\n{id}\n"),
            format!("{id} raw-path\n"),
            id.clone(),
            format!("{}\n", "0".repeat(40)),
        ] {
            assert!(parse_graph(bytes.as_bytes(), ObjectFormat::Sha1).is_err());
        }
    }
    #[test]
    fn reflog_zero_sentinel_and_both_endpoint_provenance_without_payload() {
        for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
            let width = format.width() * 2;
            let old = "1".repeat(width);
            let new = "2".repeat(width);
            let zero = "0".repeat(width);
            // Git's files backend omits the TAB entirely for an absent message.
            // A present delimiter may have an empty or arbitrary non-UTF8 body.
            for suffix in [b"".as_slice(), b"\t", b"\tDO_NOT_ECHO\t\xff"] {
                let mut bytes = Vec::new();
                for (from, to, time) in [(&zero, &old, 1), (&old, &new, 2), (&new, &zero, 3)] {
                    bytes.extend(format!("{from} {to} Name <DO_NOT_ECHO> {time} +0000").bytes());
                    bytes.extend_from_slice(suffix);
                    bytes.push(b'\n');
                }
                let mut roots = Roots::new();
                parse_reflog(b"logs/HEAD", &bytes, format, &mut roots, &mut Budget::new()).unwrap();
                assert_eq!(roots.len(), 2);
                assert!(!roots.contains_key(zero.as_bytes()));
                for (id, records) in [
                    (&old, [("reflog_new", 1), ("reflog_old", 2)]),
                    (&new, [("reflog_new", 2), ("reflog_old", 3)]),
                ] {
                    let expected: BTreeSet<_> = records
                        .into_iter()
                        .map(|(kind, ordinal)| Provenance {
                            kind,
                            path_hex: hex(b"logs/HEAD"),
                            record_ordinal: Some(ordinal),
                        })
                        .collect();
                    assert_eq!(roots.get(id.as_bytes()), Some(&expected));
                }
                assert!(!serde_json::to_string(&roots.values().collect::<Vec<_>>())
                    .unwrap()
                    .contains("DO_NOT_ECHO"));
            }
            let bytes = format!("{old} {new} Name <DO_NOT_ECHO> 1 +0000\tsecret\n");
            // All three optional-message forms still require a complete identity.
            for suffix in ["", "\t", "\tsecret"] {
                for identity in [
                    "Name <DO_NOT_ECHO> 1",
                    "Name <DO_NOT_ECHO> 1 +000",
                    "Name <DO_NOT_ECHO> +0000",
                    "Name\t<DO_NOT_ECHO> 1 +0000",
                    "Name <DO_NOT_ECHO> 1\t+0000",
                    "Name <DO_NOT_ECHO>\t\t",
                ] {
                    let invalid = format!("{old} {new} {identity}{suffix}\n");
                    assert!(parse_reflog(
                        b"logs/HEAD",
                        invalid.as_bytes(),
                        format,
                        &mut Roots::new(),
                        &mut Budget::new()
                    )
                    .is_err());
                }
            }
            for invalid in [
                bytes.trim_end().to_owned(),
                bytes.replace(" +0000", " BAD"),
                bytes.replace("Name <DO_NOT_ECHO>", "BAD"),
                bytes.replace("Name <DO_NOT_ECHO>", "Name <bad <nested>"),
                bytes.replace("Name <DO_NOT_ECHO>", "Name <bad email>"),
                bytes.replace(" +0000\tsecret", "\tsecret"),
                bytes.replace(&old, &"0".repeat(width - 1)),
                bytes.replace("secret", "bad\0body"),
                bytes.replace("secret", "bad\rbody"),
            ] {
                assert!(parse_reflog(
                    b"logs/HEAD",
                    invalid.as_bytes(),
                    format,
                    &mut Roots::new(),
                    &mut Budget::new()
                )
                .is_err());
            }
        }
    }
    fn setup(format: &str) -> (fixture::ManagedFixture, PathBuf) {
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
        let path = f.temp.path().join("config.toml");
        fs::write(&path, format!("store_dir={:?}\ntrusted_registry={:?}\nroots=[{:?}]\n[remote_preservation]\nformat=1\nversion='fixture-v1'\n[[remote_preservation.targets]]\ncommon_dir={:?}\nremote='backup'\nurl={url:?}\nbranch='refs/heads/preserved'\n", f.temp.path().join("authority"), f.temp.path().join("registry"), f.root, f.common())).unwrap();
        (f, path)
    }
    #[test]
    fn actual_sha256_flow_uses_exact_format_without_caller_positive_ids() {
        let (f, config) = setup("sha256");
        let mut audit = Audit::new(f.allocation.checkout);
        let remote = remote_proof::audit_path(&config, f.allocation.checkout, &mut audit, None);
        let report = audit.finish(remote);
        assert!(report.observed(), "{report:?}");
        assert_eq!(
            report.recovery_manifest.as_ref().unwrap().object_format,
            "sha256"
        );
    }
    #[test]
    fn changes_to_ref_reflog_objects_boot_context_or_policy_never_leave_known_positive() {
        for case in ["ref", "reflog", "object", "boot", "context", "policy"] {
            let (f, config) = setup("sha1");
            let mut fired = false;
            let mut hook = || {
                fired = true;
                match case {
                    "ref" => {
                        let id = fs::read(f.common().join("refs/heads/main")).unwrap();
                        fs::write(f.common().join("refs/heads/late"), id).unwrap();
                    }
                    "reflog" => {
                        let path = f.private().join("logs/HEAD");
                        let mut bytes = fs::read(&path).unwrap();
                        bytes.extend(b"malformed\n");
                        fs::write(path, bytes).unwrap();
                    }
                    "object" => {
                        let path = f.temp.path().join("late-blob");
                        fs::write(&path, b"late object").unwrap();
                        f.git(&["hash-object".as_ref(), "-w".as_ref(), path.as_os_str()]);
                    }
                    "policy" => {
                        let text = fs::read_to_string(&config).unwrap();
                        fs::write(
                            &config,
                            format!("{text}\n[inspection]\nformat=1\npolicies=[]\n"),
                        )
                        .unwrap();
                    }
                    _ => {
                        let conn = rusqlite::Connection::open(
                            f.temp.path().join("authority/store.sqlite"),
                        )
                        .unwrap();
                        if case == "boot" {
                            let mut allocation = f.allocation.clone();
                            allocation.identity.as_mut().unwrap().boot_id = "changed-boot".into();
                            conn.execute(
                                "UPDATE allocations SET record=?1 WHERE checkout=?2",
                                (
                                    serde_json::to_string(&allocation).unwrap(),
                                    allocation.checkout.to_string(),
                                ),
                            )
                            .unwrap();
                        } else {
                            conn.execute(
                                "UPDATE checkouts SET ready=0 WHERE id=?1",
                                [f.allocation.checkout.to_string()],
                            )
                            .unwrap();
                        }
                    }
                }
            };
            let mut audit = Audit::new(f.allocation.checkout);
            let remote = remote_proof::audit_path(
                &config,
                f.allocation.checkout,
                &mut audit,
                Some(&mut hook),
            );
            let report = audit.finish(remote);
            assert!(fired, "{case}: {report:?}");
            assert!(!report.observed(), "{case}: {report:?}");
            assert_eq!(report.coverage, "incomplete", "{case}: {report:?}");
        }
    }
    #[test]
    fn shared_deadline_exhaustion_is_not_a_skipped_success() {
        let mut b = Budget::new();
        b.test_elapsed = Some(Duration::from_secs(30));
        let id = "1".repeat(40);
        assert!(parse_objects(
            format!("{id} blob 1\n").as_bytes(),
            ObjectFormat::Sha1,
            &mut b
        )
        .is_err());
    }
    #[test]
    fn manifest_witness_rejects_duplicate_paths_and_malformed_field_order() {
        let mut ok = Vec::new();
        frame(&mut ok, 0, b"work.recovery.manifest.v1");
        frame(&mut ok, 1, b"HEAD");
        frame(&mut ok, 2, &[0u8; 88]);
        frame(&mut ok, 3, &[0]);
        frame(&mut ok, 5, &[1; 32]);
        assert!(parse_manifest_witness(&ok).is_ok());
        let mut duplicate = ok.clone();
        frame(&mut duplicate, 1, b"HEAD");
        frame(&mut duplicate, 2, &[0u8; 88]);
        frame(&mut duplicate, 3, &[0]);
        assert!(parse_manifest_witness(&duplicate).is_err());
        let mut overwritten = Vec::new();
        frame(&mut overwritten, 0, b"work.recovery.manifest.v1");
        frame(&mut overwritten, 1, b"HEAD");
        frame(&mut overwritten, 2, &[0u8; 88]);
        frame(&mut overwritten, 2, &[1u8; 88]);
        frame(&mut overwritten, 3, &[0]);
        assert!(parse_manifest_witness(&overwritten).is_err());
        let mut bad_kind = Vec::new();
        frame(&mut bad_kind, 0, b"work.recovery.manifest.v1");
        frame(&mut bad_kind, 1, b"HEAD");
        frame(&mut bad_kind, 2, &[0u8; 88]);
        frame(&mut bad_kind, 3, &[2]);
        assert!(parse_manifest_witness(&bad_kind).is_err());
        let mut absent_and_present = ok.clone();
        frame(&mut absent_and_present, 6, b"HEAD");
        assert!(parse_manifest_witness(&absent_and_present).is_err());
    }
    #[test]
    fn manifest_witness_rejects_noncanonical_path_or_absence_order() {
        fn path_block(out: &mut Vec<u8>, path: &[u8]) {
            frame(out, 1, path);
            frame(out, 2, &[0u8; 88]);
            frame(out, 3, &[0]);
            frame(out, 5, &[1; 32]);
        }
        let mut canonical = Vec::new();
        frame(&mut canonical, 0, b"work.recovery.manifest.v1");
        path_block(&mut canonical, b"HEAD");
        path_block(&mut canonical, b"config");
        frame(&mut canonical, 6, b"a");
        frame(&mut canonical, 6, b"b");
        assert!(parse_manifest_witness(&canonical).is_ok());
        let mut swapped_paths = Vec::new();
        frame(&mut swapped_paths, 0, b"work.recovery.manifest.v1");
        path_block(&mut swapped_paths, b"config");
        path_block(&mut swapped_paths, b"HEAD");
        frame(&mut swapped_paths, 6, b"a");
        frame(&mut swapped_paths, 6, b"b");
        assert!(parse_manifest_witness(&swapped_paths).is_err());
        let mut swapped_absences = Vec::new();
        frame(&mut swapped_absences, 0, b"work.recovery.manifest.v1");
        path_block(&mut swapped_absences, b"HEAD");
        path_block(&mut swapped_absences, b"config");
        frame(&mut swapped_absences, 6, b"b");
        frame(&mut swapped_absences, 6, b"a");
        assert!(parse_manifest_witness(&swapped_absences).is_err());
        let mut unsorted_names = Vec::new();
        frame(&mut unsorted_names, 0, b"work.recovery.manifest.v1");
        frame(&mut unsorted_names, 1, b"refs");
        frame(&mut unsorted_names, 2, &[0u8; 88]);
        frame(&mut unsorted_names, 3, &[1]);
        frame(&mut unsorted_names, 4, b"heads");
        frame(&mut unsorted_names, 4, b"HEAD");
        assert!(parse_manifest_witness(&unsorted_names).is_err());
    }
    #[test]
    fn provenance_round_trip_rejects_unknown_kind_and_noncanonical_order() {
        let mut set = BTreeSet::new();
        set.insert(Provenance {
            kind: "named_ref",
            path_hex: hex(b"refs/heads/main"),
            record_ordinal: None,
        });
        let bytes = encode_provenance(&set).unwrap();
        validate_provenance(&bytes).unwrap();
        let mut swapped = Vec::new();
        frame(&mut swapped, 2, hex(b"refs/heads/main").as_bytes());
        frame(&mut swapped, 1, b"named_ref");
        frame(&mut swapped, 3, &[]);
        assert!(validate_provenance(&swapped).is_err());
        let mut unknown = Vec::new();
        frame(&mut unknown, 1, b"guessed_author");
        frame(&mut unknown, 2, b"");
        frame(&mut unknown, 3, &[]);
        assert!(validate_provenance(&unknown).is_err());
    }
}
