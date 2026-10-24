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
    pub fn reason(&self) -> &str {
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
        let tab = rest
            .iter()
            .position(|c| *c == b'\t')
            .ok_or("reflog_unknown")?;
        let identity = &rest[..tab];
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

struct Local {
    admin: filesystem::Manifest,
    objects: Objects,
    roots: Roots,
    head_graph: BTreeSet<Vec<u8>>,
    unclassified: BTreeSet<Vec<u8>>,
    native_digest: Vec<u8>,
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
        for (path, id) in &refs {
            add_root(&mut roots, id.clone(), "named_ref", path, None, b)?;
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
        let mut command = |args: &[&str], stdin: &[u8], b: &mut Budget| -> Held<Vec<u8>> {
            checked(b.reserve(charge))?;
            b.counters.native_input_reserved_bytes += charge;
            let bytes = checked(git_success(Some(&identity.path), args, stdin, b))?;
            for arg in args {
                frame(&mut native_digest, 1, arg.as_bytes());
            }
            frame(&mut native_digest, 2, &Sha256::digest(stdin));
            frame(&mut native_digest, 3, &Sha256::digest(&bytes));
            Ok(bytes)
        };
        let effective = command(
            &["for-each-ref", "--format=%(objectname)%00%(refname)"],
            b"",
            b,
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
            let bytes = command(&["--git-dir", dir, "rev-parse", "--verify", name], b"", b)?;
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
        let id = "1".repeat(40);
        let bytes = format!("{} {id} Name <DO_NOT_ECHO> 1 +0000\tsecret\n{id} {} Name <DO_NOT_ECHO> 2 +0000\tsecret\n", "0".repeat(40), "0".repeat(40));
        let mut roots = Roots::new();
        parse_reflog(
            b"logs/HEAD",
            bytes.as_bytes(),
            ObjectFormat::Sha1,
            &mut roots,
            &mut Budget::new(),
        )
        .unwrap();
        assert_eq!(roots.len(), 1);
        let provenance = roots.get(id.as_bytes()).unwrap();
        assert_eq!(provenance.len(), 2);
        assert!(provenance
            .iter()
            .any(|p| p.kind == "reflog_new" && p.record_ordinal == Some(1)));
        assert!(provenance
            .iter()
            .any(|p| p.kind == "reflog_old" && p.record_ordinal == Some(2)));
        assert!(!serde_json::to_string(provenance)
            .unwrap()
            .contains("DO_NOT_ECHO"));
        for invalid in [
            bytes.trim_end().to_owned(),
            bytes.replace(" +0000", " BAD"),
            bytes.replace("Name <DO_NOT_ECHO>", "BAD"),
            bytes.replace("Name <DO_NOT_ECHO>", "Name <bad <nested>"),
            bytes.replace("Name <DO_NOT_ECHO>", "Name <bad email>"),
            bytes.replace('\t', " "),
            bytes.replace(&id, &"0".repeat(39)),
        ] {
            assert!(parse_reflog(
                b"logs/HEAD",
                invalid.as_bytes(),
                ObjectFormat::Sha1,
                &mut Roots::new(),
                &mut Budget::new()
            )
            .is_err());
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
}
