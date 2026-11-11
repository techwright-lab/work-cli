# Specification: native Apple Silicon support and single-command distribution

**Status:** accepted implementation handoff. The operator explicitly accepted this independently reviewed specification. This is an implementation-ready contract, not implementation authorization, a passing qualification report, or release permission.

**Baseline:** `41d01c3a6f1ea2bafcc7432240f725c55c810781`. **Canonical map:** [Map native Apple Silicon support and single-command distribution for work-cli](https://github.com/techwright-lab/work-cli/issues/13). **Acceptance:** [Agree the implementation-ready specification and acceptance boundary](https://github.com/techwright-lab/work-cli/issues/20).

## 1. Destination and non-goals

Make macOS Apple Silicon (`aarch64-apple-darwin`) Work's second supported release platform, alongside Linux x86_64. Deliver native core operations, native GitHub Actions qualification, versioned standalone executable assets and a one-command user-local installer. Ordinary installation requires no repository clone, Rust, Python or source build. Qualified external Git remains a runtime prerequisite for repository operations.

Core scope: setup/check/cancellation, prerequisite inspection, status, start/reuse, finish, removal preview, confirmed safe removal and conservative reconciliation. Preserve ownership, identity, history, quota, immutable retry identity, local preservation and unknown-outcome holds. Finish, stopped-writer confirmation and removal remain distinct.

Out of scope: Intel macOS, Windows, Linux ARM64 release support (retain existing CI coverage), macOS agent launching/supervision, automatic authority migration/adoption, a metadata backup format, automatic permission repair, offline-first-use packaging, installation switching/publication during planning. Core bounded owned Git helpers remain in scope; they are not supervision substitutes.

## 2. Approved safety and observable behavior

- No weakened removal checks or fallback to Git cleanliness. Required incomplete/unsupported evidence holds the affected operation, preserving payload, history and charge.
- Authorities remain host-local. Copied/restored/incompatible state is not adopted by rewriting identities. Recovery into fresh managed state needs its own authorization.
- Unsupported launching/supervision commands fail before side effects; historical state stays intact and can hold removal.
- Preview never removes the checkout or releases its charge. Payload inspection may create tracked temporary hard links: link count and ctime change, including again on cleanup; original ctime cannot be restored. Disclose this exception instead of claiming filesystem-read-only inspection. Do not intentionally edit source contents, mtime, modes, ownership, ACLs or attributes. Commands not requiring payload inspection gain no reason to create captures.
- Actual removal still needs explicit operator stopped-writer confirmation, fresh validated inspection/preservation, durable intent/outcome and fresh checkout/registration absence before releasing charge. Reboot, finish, clean status, successful child exit, age and locks are not confirmation.
- Threat boundary is cooperative host-local operation, not malicious same-UID/root containment. Ordinary concurrent changes and mistaken stopped-writer declarations remain relevant. Staging must exclude unrelated principals and concurrent Work actors; confirmation alone is not exclusion.
- Read bytes/results are speculative until all mandatory validation passes. Late changes can cause refusal after reading; neither platform promises immutable payload or universal zero-read detection of every concurrent write.

## 3. Platform and prerequisite envelope

Target macOS 15 minimum, with final support bounded by actual qualified capabilities and versions. Required native CI families are explicit ARM64 macOS 15 and 26, each with Git 2.55.0 and 2.56.0. Confirm actual runner availability at implementation; missing mandatory coverage is not a pass. The operator's macOS 27 requires separate native qualification before installation there is called supported. Rust's target deployment floor alone is not Work's floor.

APFS is the initial macOS qualification/support scope, including case-sensitive and case-insensitive variants only after qualification. Apply storage requirements to the operations and locations using them, not a universal ban on unrelated paths/read-only diagnostics. Unqualified filesystem behavior may refuse relevant managed mutations. Separate qualified locations/volumes are permitted where the operation permits; acquisition/atomic operations enforce their own same-mounted-filesystem conditions.

No blanket private-state ACL rejection or universal cloud/File Provider detector is required. Prove relevant ownership/effective-access and filesystem behavior, or refuse that operation without repair. APFS labels, equal device numbers, ordinary mode bits or path-name heuristics alone are insufficient evidence.

### Git selection and isolation

- Preserve canonical stable Git >=2.55.0 on both platforms; 2.55.0 and 2.56.0 are required fixtures. Newer canonical stable versions remain eligible, not automatically separately qualified.
- Precedence: global `--git /absolute/path`, optional top-level `git_path` config, platform defaults. Invalid explicit selection fails with no fallback; no new environment variable.
- macOS defaults consider `/opt/homebrew/bin/git`, then `/usr/bin/git`, choosing the first qualified candidate and reporting rejections. No arbitrary shell PATH, Intel Homebrew or directory search. Linux default remains `/usr/bin/git`.
- Accept normal Homebrew symlinks; resolve/validate executable, relevant installation access and helper layout before use. Reject unsafe candidates before executing them. No chmod/repair or system-Git replacement.
- Resolve once per invocation: canonical executable, version, helper directory and object identities. Revalidate before dispatch, hold on in-operation change, never switch executables mid-operation. A later invocation can select a newly qualified version.
- Get helpers from the validated executable; bind `GIT_EXEC_PATH`; restrict child PATH to system utility locations. Explicit local helpers use that installation rather than unrelated hard-coded helpers. Do not pretend this controls an unrelated remote host's helper paths.
- Preserve existing per-command sanitized environment/configuration, locale, noninteractive behavior and protections against hooks, unapproved external execution, replacement objects and lazy fetch. Do not inherit arbitrary user settings or globally erase required repository config.
- Discovery before config exists does not write config. Setup persists a choice only through the operator-confirmed proposal. Outside explicit setup, `--git` is invocation-only.
- Help/version, skill installation and prerequisite diagnostics work without qualified Git. Managed repository operations require it. Diagnostics expose selection source, attempts/reasons, canonical path/version/helper layout without credentials; installation never silently provisions Git or initializes authority.

## 4. Platform architecture and safe binding boundary

Keep common lifecycle, manifest, budget, hold, preservation, journal and capacity logic shared. Isolate native observation/acquisition beneath that logic; do not fork the entire CLI into unrelated platform implementations or substitute successful no-ops on macOS.

Selected internal responsibilities:

| Responsibility | Required contract |
| --- | --- |
| Held directory child | Validated single component + held parent -> directory-only/no-follow retained FD and route/real-mount observations. |
| Bounded directory batch | Fresh independent cursor + caller buffer/budget -> exact counted records or explicit error; no hidden growth or unbounded retries. |
| Anchored attributes | Held parent/component or safe FD -> bounded returned-mask-bearing identity, generation and relevant metadata/access observations. |
| Owned capture link | Active protected same-mount stage + intent/reservation -> one tracked entry or held unknown outcome; never recursive capture/overwrite. |
| Validated readable capture | Proven active regular capture + current source/stage/route evidence -> readable FD or refusal before opening. |
| Validate/finish capture | Full required validation -> accepted inspection and exact active cleanup; otherwise retain evidence/resources/charge. |
| Persistence/boot observation | Checked acknowledgements and provider-tagged identity evidence; unavailable or changing mandatory evidence holds. |

Reuse safe rustix 1.1.5 operations where available. Add a small internal, non-published Darwin adapter crate for missing anchored attributes, counted bulk batches and relevant ACL/topology observations. The operator explicitly authorizes a narrow unsafe-FFI exception in that adapter; application crates retain `forbid(unsafe_code)`. No scattered unsafe, silent lint bypass or raw-pointer API to Work. Confine unsafe to the necessary ABI/ownership boundary and keep parsing safe where possible.

Safe interfaces must make FD borrowing/ownership, initialization, lengths, returned masks/counts, errno and bounded retries explicit. Require focused independent review and malformed/truncated/overflow/signed-reference/stale-buffer tests. Do not adopt the screened generic bulk crate unchanged or invent numeric runtime flags merely because a newer SDK defines them.

### Containment property

Use validated one-component held-parent walking, directory-only/no-follow acquisition, actual mounted-volume identity, mountpoint/firmlink observations, complete route revalidation and kernel same-mount hard-link enforcement. Single-component names exclude slash, NUL, empty, `.` and `..`. Hold on inconsistent, truncated, stale or unavailable mandatory route/topology evidence before payload read or accepted results.

This is qualified validated containment under stable observed topology, NOT atomic prevention of every transient forbidden directory lookup/acquisition as Linux NO_XDEV can provide. A directory lookup can involve foreign/aliased filesystem activity before rejection; topology can change between observations. Document this explicit limitation. It does not authorize foreign payload reads, accepted wrong census, unpreserved deletion or a blanket storage ban. Stage/route checks must discharge the selected property on qualified native configurations.

### Bounded native enumeration

Prefer a narrow counted `getattrlistbulk` wrapper with fresh independently opened cursors and caller-owned capped buffers. Decode exactly the returned record count, not stale buffer lengths. Validate group length/alignment, bounds/progress, returned masks, per-entry errors, signed reference offsets, terminators/name bytes and arithmetic. Bound native refills, entries, names, memory, FDs, retries and time; malformed/over-budget/incomplete results are never clean EOF. Handle mountpoint/firmlink metadata versus actual opened identities explicitly. A caller buffer/timeout is not a hard bound on uninterruptible kernel I/O. A different mechanism requires an equivalent reviewed boundedness/error argument.

## 5. Hard-link inspection and metadata protocol

1. Reserve resources before capture; establish a fresh protected stage on the source's actual mounted filesystem outside the source census. Include stage/manifest/FD/entry/byte costs and retained allocation risks, not just later read bytes. Validate actual owner, relevant effective access, parent replacement/deletion rights and stage identity; accept proven harmless ACLs rather than the toy fixture's blanket any-ACL rejection. Serialize active Work actors. Unknown protection refuses before readable payload open.
2. Preserve initial source/route/data/metadata evidence and record a bounded durable capture intent, active session, exact source/stage identities and fresh destination name. Capture bookkeeping is not checkout deletion authority. Do not use a receipt, filename, age or count as self-authenticating recovery ownership.
3. `linkat` with no follow-target fallback creates at most one entry relative to held parents. Enforce same mounted filesystem and no overwrite. Classify resulting type without following symlinks; reject devices, FIFO, socket, symlink and unsupported directory links before readable payload opening. Do not infer universal directory rejection from one APFS probe or permit recursive cloning/copy fallback.
4. Bind exact active source and capture objects, original user-link status, current source name/ancestor route, stage, real mount, expected owned-link contribution, relevant fields/metadata and required valid data-generation observations. No blanket nlink=2 exemption: user-created or unknown links hold. Unsupported/default/zero mandatory observations refuse, not timestamps-only fallback.
5. Treat acquisition and cleanup ctime/link-count changes as explicit transitions. Preserve the initial observation, compare non-exempt fields and relevant metadata, establish a post-link baseline and revalidate through acceptance. Do not globally ignore ctime or conceal unrelated changes. If implementation exposes a concrete preservation regression, return that precise decision rather than waive consistency.
6. Only a proven active regular capture in a protected/exclusive stage can supply a readable handle. Check opened FD identity/type/required metadata before bounded reading. The safety argument is protected namespace plus retained regular inode, not O_NONBLOCK or a post-open type check. Ordinary source writers can still change the same inode; enforce before/after data/metadata checks, final route checks and complete fresh census. Discard/quarantine partial results on failure.
7. Normal completion removes only exact links owned by that validated active protocol, syncs required state and checks disposition. A capture reservation is not Work checkout quota. Unknown interrupted links/outcomes hold with evidence/accounting; no destructor, historical receipt, plausible count or generic orphan cleanup adopts/deletes/releases them. Recovery needs established ownership/outcome and any necessary explicit operator disposition.

ACL/xattr/resource-fork payload Work cannot classify and preserve causes a removal hold even when Git is clean, not a general-use ban. No blanket `com.apple.*` disposal exemption, permission stripping or new metadata backup format is authorized. Report concrete unsupported observations. Read-only diagnostics remain available to explain holds.

## 6. Persistence and identity design

### Checked OS acknowledgements

Mandatory database/WAL/journal, sidecar/namespace-publication and checkpoint boundaries must expose required checked OS acknowledgements before dependent effects. Define and test the boundary-to-acknowledgement mapping in code and fixtures; a successful initial capability probe or PRAGMA readback is not enforcement.

For Work's own staged files/markers/journals: fully write, check required file sync, publish, check retained-parent sync, then acknowledge. On macOS the selected strong file/directory acknowledgement uses F_FULLFSYNC where required; pinned Rust source already uses this for sync_all. Failed/unknown post-publication acknowledgement means possibly changed/held, not inferred rollback or permission to repeat destructive work.

Use the exact pinned bundled SQLite, not system SQLite. Select a narrowly maintained macOS-only source patch to enforce requested mandatory full-sync acknowledgements instead of silent ordinary-sync success, and check required directory open/sync/deletion/sidecar operations. Preserve Linux path behavior unless separately reviewed. Pin source/checksum and patch expectations; fail closed on mismatch and require upgrade re-review. This is not merely deleting a two-line fallback.

On macOS, disable swallowed default automatic-checkpoint handling in favor of checked explicit checkpoints; changing Linux checkpoint behavior requires separate review. Specify when WAL commit is sufficient versus when checkpoint acknowledgement is mandatory; expose failures before dependent workflow effects. A post-commit error is possibly committed and must reconcile without pretending rollback. Cover initialization, independent connections, WAL restart/checkpoint/internal ordering and namespace changes. A later marker/full-device flush cannot retroactively prove earlier ordering-sensitive phases safe.

Prove actual bundled-build propagation with injected full-sync-only failure, ordinary-sync failure, directory open/sync failure, deletion/sidecar errors, ENOSPC and checkpoint failures. The extracted-function harness and system SQLite observations are evidence of seams, not completed VFS tests. Accepted acknowledgements do not promise universal stable-media/hardware-failure survival; process crash, reboot and power-loss evidence are distinct.

### Provider-aware host-local identity

New Darwin records use explicit versioned boot-provider/domain and object-identity representation. Strictly frame/validate native kern.bootsessionuuid, canonicalize consistently before comparison and reject missing, malformed, nil or changing evidence without fallback IDs. Preserve relevant mounted-volume/file/root/registry/marker bindings, not UUID strings alone.

Keep existing Linux decoding/history operational through its existing provider semantics; do not relabel unversioned Linux records as Darwin, rewrite stored identities to fit a copy or initialize over unknown state. Cross-provider/incompatible schema/object evidence refuses the affected operation. Boot changes invalidate ephemeral observations and require durable-evidence reconciliation; device numbers are not assumed stable across reboot. No boot transition authorizes deletion, uncertain replay or quota release.

Copied-fixture rejection is not proof against identity-preserving VM restore or every inode-reuse case. Record representation/schema compatibility tests and native lifecycle limits; qualify actual reboot/identity behavior in an authorized disposable native environment before advertising those semantics as supported.

## 7. Installer and published artifact contract

### Release assets

Publish one shared package version with:

- `work-VERSION-linux-x86_64` and `.sha256`.
- `work-VERSION-macos-arm64` and `.sha256`.
- Release-specific `install.sh` and `install.sh.sha256`.
- Existing `work-cli-VERSION-linux-x86_64.tar.gz` and `.sha256`.
- Equivalent `work-cli-VERSION-macos-arm64.tar.gz` and `.sha256`.

Standalone is the normal path; bundles carry optional helper/instructions. Verify bundled/standalone executable byte identity. No download names imply an unpublished release exists.

### One-command bootstrap and trust

Document a fail-on-download-error download-then-run shell command for the published GitHub Release installer, with latest stable and pinned-release URLs. Each installer embeds its exact release version and expected Developer ID identity; the latest URL selects it once, then payload/checksum downloads use that fixed version. No second latest lookup or moving-source-branch bootstrap. No arbitrary cross-version/architecture fallback.

HTTPS-only downloads/redirects, private staging, strict checksum validation before activation; authenticate macOS architecture and expected Developer ID identity and require successful candidate version check. Checksums detect corruption, not independent publisher authenticity; bootstrap execution trusts GitHub/publisher control. Do not suggest that downloading the bootstrap's sidecar authenticates already-executed code.

Require Developer ID signing and Apple notarization for supported macOS assets. Checksum/test final signed bytes; no PR secrets. Raw executables cannot carry stapled tickets: internet-dependent first-use trust checks are acceptable, offline first use is not promised. Never clear quarantine, disable Gatekeeper/SIP or re-sign locally to bypass denial.

### Destination, updates, rollback and ownership

- Default `~/.local/bin/work`; explicit `--bin-dir`. No sudo, shell-profile editing, silent Git/dependency installation, Work setup or authority initialization. Explain PATH/shadowing without modifying startup files.
- Interface: `install.sh install`, `install.sh update --confirm-stopped`, `install.sh rollback --version VERSION --confirm-stopped`; each accepts `--bin-dir`. Pinned installer URL chooses install/update version; rollback selects a verified retained direct-install version.
- Maintain private cooperative direct-install records outside Work authority storage: destination/version/digest/rollback entries. Validate actual bytes/ownership/path against records; no auto-adoption of missing/altered/foreign state. Refuse helper-managed links and direct users to their updater; do not silently take over its layout. This record is not malicious-same-UID containment.
- Serialize cooperating installers, stage on destination filesystem, retain previous recognized direct executable, activate atomically and verify active path/version/digest. Pre-activation failure leaves active installation unchanged; uncertain activation retains evidence and inspects before retry. Atomic rename is not universal power-loss durability.
- Physical architecture detection must install native ARM64 on Apple Silicon even from a Rosetta shell, and reject Intel Macs/unsupported Linux architectures. Preflight supported OS envelope and required native utilities before activation; no emulated fallback or tool installation.
- First install needs no version-switch confirmation. Updating/rollback requires explicit stopped-Work-operation confirmation. Leave stores/registries/checkouts/outboxes/history/quota untouched. Skills are a separate `work skill install` action; do not silently update catalogs or claim reload.

## 8. CI, qualification and release gates

### Required checks

Retain existing Linux coverage and pinned-container qualification with Git 2.55.0 and 2.56.0 (`WORK_QUALIFICATION_GIT_VERSION=2.56.0` for the second fixture). Preserve existing Linux ARM64 CI without promoting it to supported assets.

Add native Apple Silicon macOS15/26 × both Git fixtures. Use isolated HOME/config/state, disposable owned repositories/authorities and known fixtures, never the operator's real state/credentials. Qualify APFS case variants through owned runner fixtures; no unapproved mounts/reboots on the operator machine. Do not claim Linux containers on a Mac test Darwin behavior. Update project qualification instructions explicitly when introducing the native harness, rather than silently ignoring the existing container-only instructions.

Run complete applicable locked workspace tests, formatting, strict all-target Clippy, Python helper tests, packaging and installed-artifact smoke. Linux-only supervision tests remain on Linux; macOS tests explicit unsupported-command refusal. Record source SHA, actual OS/image/architecture, toolchain/SDK/deployment metadata, Git executable/helper identity and final artifact digest/run identity. Missing required tests/runners are blockers, not successful skips. No bare build-only support claim.

### Finite acceptance matrix

| Area | Required evidence before support/release |
| --- | --- |
| Core lifecycle | setup/check/cancel, status, start/reuse/retries, finish retaining charge, passive-to-lifecycle removal preview with documented capture effects, confirmed removal preserving refs and reconciling charge once. |
| Inspection | exact capture provenance, unsafe type/substitution refusal, effective stage/parent protection including benign/dangerous ACLs, own ctime transitions, writable-FD/mmap/late changes, complete data/metadata/census validation, bounded enumeration/parser failures, unknown metadata holds. |
| Containment | one-component route/ancestor replacement, real mounted identity, aliases/firmlinks/mountpoints, topology changes and uncertain evidence under the explicitly selected guarantee. |
| Interrupted capture/removal | intent/result/cleanup faults, unreceipted/foreign/replaced links/stages, no historical adoption or unknown cleanup, retained payload/history/accounting; uncertain native removal never replays against recreated paths. |
| Git | selection precedence/order, unsafe/unsupported candidate diagnostics, helper layout/environment isolation, upgrades/replacements, no fallback from invalid explicit path. |
| Persistence/identity | exact patched bundled-build sync/checkpoint/namespace fault injection and ordering, post-commit uncertainty, provider/schema compatibility and copied-state holds; separately authorized native reboot/lifecycle evidence, without a power-loss claim. |
| Installer | fresh/install/update/rollback, checksum/signer/version/architecture failures, interrupted activation, ownership/helper conflicts, PATH shadowing, Rosetta/unsupported platforms, no implicit configuration/skill/Git changes. |
| Final artifacts | final Mach-O architecture/minimum-OS/link dependencies/signature/notarization, installed lifecycle/skill smoke, standalone/bundle identity, final checksums and exact-byte provenance. |
| Linux regressions | locked workspace, formatting, strict all-target Clippy, helper tests, packaging/artifact smoke and both supported Git fixtures. |

### Publication

Only an actual package-version change merged to main is eligible after successful CI at that exact commit. Ordinary feature/dependency/test/docs PRs do not bump versions; release PRs batch reviewed changes, package/lockfile metadata and versioned changelog. Verify/create matching tag at the eligible commit; ordinary tags do not independently publish. Manual dispatch may resume eligibility, never bypass it.

Signing/notarization and public publication require explicit operator approval through protected release environments and least-privilege credentials. Final public publication requires approval after signed-artifact verification. Audit actual remote settings/review/bypass controls; YAML alone is not enforcement. Select/verify actual Apple identity and credential custody before publication; none is configured/assumed by this specification.

Retain built artifacts, sign/notarize, then checksum/smoke after final byte-changing steps; no rebuild/substitution before publication. Stage all assets in a draft, verify complete set/digests for both platforms, then publish/update latest only with approved completed release. Failed preparation stays unpublished. Resume only after inspecting exact version/commit/artifact identity. Uncertain/partial public outcomes require reporting and explicit disposition, not automatic asset deletion/overwrite or claimed rollback.

## 9. Evidence status, rollout and handoff

Retained experiments support feasibility only on macOS27.0.1 ARM64/APFS. Independent reviews were static/source reviews, not native reruns. Existing packets distinguish system SQLite3.54, extracted pinned3.51.1 source harness and actual bundled-build tests (not yet run). Five boot observations/three process exits are not reboot/power-loss qualification.

One SDK diagnostic caused Apple tooling to emit an external error bundle; it was reported, not inspected or cleaned. Later probes used an explicit existing SDK. No real authority/repository, normal installation, native reboot, mount or publication was modified by these experiments. Setup-doc changes remain uncommitted locally; prototype/research branches are retained, unmerged, with no PRs.

After final specification acceptance, copy this accepted canonical issue into repository documentation when implementation begins, retaining its issue/revision provenance. Start implementation only with its separate authorization and configured Work lifecycle or an explicitly supplied isolated workspace; do not initialize an authority/capacity implicitly. Group independent implementation/review work in isolated lanes without repeated continue prompts; escalate new policy trade-offs and manual steps, not routine already-authorized work.

The eventual right-pane trial first qualifies macOS27, uses an isolated installation directory and disposable repository/authority, and reports exact candidate/version/evidence. A separately approved normal-install switch follows only if desired. Never infer publication, real configuration migration or stopped-writer/removal confirmation from trial success.

## 10. Decision and evidence pointers

Authoritative policy refinements are the linked final resolutions; later explicit refinements supersede earlier broad proposals, not vice versa.

- [Core safety contract](https://github.com/techwright-lab/work-cli/issues/16#issuecomment-6686126937).
- [OS/Git prerequisite direction](https://github.com/techwright-lab/work-cli/issues/17#issuecomment-6686348904) and [deterministic Git binding](https://github.com/techwright-lab/work-cli/issues/21#issuecomment-6686579792).
- [Operation-specific storage/metadata refinement](https://github.com/techwright-lab/work-cli/issues/22#issuecomment-6686716683).
- [Installer contract](https://github.com/techwright-lab/work-cli/issues/18#issuecomment-6686475701) and [qualification/release gates](https://github.com/techwright-lab/work-cli/issues/19#issuecomment-6686795535).
- [Staged/cooperative/capture refinement](https://github.com/techwright-lab/work-cli/issues/23#issuecomment-6687838428) and [hard-link metadata/recovery permission](https://github.com/techwright-lab/work-cli/issues/26#issuecomment-6688783050).
- [Validated containment selection](https://github.com/techwright-lab/work-cli/issues/27#issuecomment-6689783298), [explicit safe-adapter boundary](https://github.com/techwright-lab/work-cli/issues/28#issuecomment-6689784209), [SQLite/identity selection](https://github.com/techwright-lab/work-cli/issues/29#issuecomment-6689785096).
- [Inspection feasibility acceptance for planning](https://github.com/techwright-lab/work-cli/issues/23#issuecomment-6689785970) and [persistence feasibility acceptance for planning](https://github.com/techwright-lab/work-cli/issues/24#issuecomment-6689786832).
- [Hard-link packet](https://github.com/techwright-lab/work-cli/blob/99d497becc9e169936870b619f97a95571153d74/docs/prototypes/macos-hardlink-protocol/README.md), [platform seam packet](https://github.com/techwright-lab/work-cli/blob/b8ea771ef2614ec3ff86cd097d80a5aac4aedc49/docs/research/macos-safe-platform-boundary.md), [persistence packet](https://github.com/techwright-lab/work-cli/blob/fd471fca477400ed127a3148278a2e9fd8090bac/docs/prototypes/macos-persistence-identity/README.md).
- [Independent safety review](https://github.com/techwright-lab/work-cli/issues/23#issuecomment-6689322900) and [independent persistence review](https://github.com/techwright-lab/work-cli/issues/24#issuecomment-6689323315).
