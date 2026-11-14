# Native macOS implementation — wave 2

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Fresh implementer per bounded task; independent spec review, then independent quality review; one writer per isolated worktree. Use checkbox tracking, observed test-first evidence and frequent scoped commits.

**Goal:** move beyond first-wave scaffolding to real Git installation binding, a native development CLI binary, counted Darwin observations and execution of the real SQLite build guard.

**Architecture:** preserve shared policy and Linux behavior. Add reviewed native capabilities behind existing application boundaries; intermediate unsupported capabilities must refuse rather than fabricate safe observations. Parallel independent tasks own separate files/worktrees; parent integrates shared manifests and cross-stream hooks only after review.

**Tech stack:** Rust/Cargo1.98.1, existing rustix/libc, narrow internal Darwin FFI, exact vendored SQLite3.51.1, shell/Python disposable qualification tooling.

Accepted contract: `doc/specs/2026-11-06-native-macos-support.md`. First-wave integration baseline: `6a95254`. All six first-wave source slices passed spec then quality review. Focused Linux checks passed; complete baseline is NOT green due to required openat2 ENOSYS in Rosetta and unqualified source-bind recovery storage. Those restrictions must not be weakened. Native adapter compiled/linked/executed on27; committed checks passed using isolated pinned1.98.1; a generated disposable-test lint is separately being corrected without altering production source.

## Authority and coordination

The operator explicitly authorized temporary plain Git worktrees under `/Users/ravi/projects/techwright/work-cli-worktrees/` until Work is usable. No authority initialization, limits/configuration changes, cleanup/removal, normal installation, push, signing or publication is implied. Preserve original worktrees and evidence. Create new phase-specific sibling worktrees from this reviewed-plan integration commit to avoid altering earlier source-pinned evidence branches.

Parent owns root Cargo.toml/Cargo.lock, docs/AGENTS coordination and serial integration. G2 owns only Git seam files. A2 owns only the internal adapter. H2 owns only native-harness files. N1 owns application native-compilation boundaries, excluding Git seam/config/setup/doctor source and root manifests; freeze shared-module edits while N1 runs. S2 owns SQLite guard qualification files, not vendor/source patches or root Cargo integration. No lane writes another lane or delegates further.

## Dependency DAG

```text
reviewed wave2 plan + clean integration base
  |-- G2 real bounded Git binding -> G3 CLI/config/redaction/callsite integration (later)
  |-- H2 complete source snapshot + explicit development-with-Git mode
  |       `-- S2 actual vendored Rust guard dependency fixture (native after H2)
  |-- A2 native counted batches + boot provider (development through reviewed H1/H2)
  `-- N1 native read-only CLI build/refusal boundary (reviewed H1; vendor unused until S3)
G3 + A2 + provider-aware durable identities + strict store/checkpoints
 -> full native inspection/core lifecycle (later), NOT a wave2 completion claim
```

N1 may start compiling/adding tests with reviewed H1 before H2: root Cargo has no vendor patch yet. S2 must wait for H2 before copying exact vendor source into native fixtures. No root dependency switch occurs silently. Remaining installer activation, final packaging/workflow/release gates stay explicit later tasks, not presumed done because shell preflight exists.

## G2 — Real Git installation qualification and invocation binding

Files: `crates/work/src/git.rs`, `git_tests.rs`, optionally private `git_binding.rs`/`git_binding_tests.rs` referenced from the owned Git module. No CLI/config/setup/identity/inspection/doctor/lib/root manifest changes yet.

- [ ] Write failing tests using owned controlled executable/helper fixtures: unsafe/nonregular/nonexecutable candidate rejected BEFORE execution; canonical symlink selection and original spelling retained; explicit failure never falls back; automatic candidates can advance; canonical strict version and absolute bounded exec-path; missing/unsafe helper layout; executable/symlink/helper replacement before dispatch refuses rather than selects anew.
- [ ] Implement typed invocation-owned binding from G1 candidates. Validate relevant executable/ancestor/helper ownership/write access before execution. Linux fixture checks use existing safe APIs; Darwin access not yet provable through the observation layer must return explicit unproven evidence, not assume mode bits cover ACLs. No blanket arbitrary ACL policy.
- [ ] Use existing bounded_process::output_aggregate for sanitized bounded version/exec-path probes: fixed small byte/time budgets, noninteractive environment, system utility PATH, no inherited user Git config/environment. Unsupported/over-budget output is refusal, not trimming into validity. Do not implement a second unbounded child runner.
- [ ] Bind canonical executable/helper/route identities once. Expose fallible pre-dispatch revalidation and a command-building capability that keeps executable/GIT_EXEC_PATH binding while allowing each caller's existing stronger security profile. No lowest-common-denominator replacement of caller restrictions, mutable global test selector, new production environment option or mid-invocation fallback.
- [ ] Test prepared command environment/program/revalidation with controlled fixture services; keep all tests isolated and fake probes labelled as such, not real Git qualification evidence. Source/diagnostic paths remain non-lossy.
- [ ] Run focused tests in both pinned Linux wrappers. Record pending unused-private-API production lint until G3; no suppressions/artificial consumers/unnecessary public exposure. Self-review and commit.

G3 will consume this binding across redacted CLI/global args, all config-document paths, setup persistence and all four Git constructors/local service helpers. No partial callsite migration in G2.

## H2 — Complete reviewed source snapshots and local development with qualified Git

Files: `tools/qualification/native-macos.sh`, `tests/qualification/test_macos_harness.py` only.

- [ ] Test before editing: allowlisted `vendor`/`patches` source is copied so the exact reviewed libsqlite3-sys package/guard fixtures can build. Preserve its ordinary `.gitignore` member where required for provenance; NEVER copy `.git` directories/ref pointers, user `.gitconfig`/credentials or follow escaping symlinks. Use exact reviewed-source paths, no general secret-discovery promise. Retain existing exclusion/refusal tests.
- [ ] Add explicit `--development` mode that permits27 and selected installed1.98.1/1.99.1 with an explicitly selected exact supported Git fixture; keep `--without-git` compatibility as nongate development with repository operations prohibited. Qualification without development remains15/26ARM64+pinned1.98.1+exactGit. There is no silent OS/tool fallback.
- [ ] Development WITH Git validates the same executable/helper binding and isolates real HOME/config/state as qualification candidates; only disposable repository operations may run. It remains support_claim:false, with missing capability/SDK/artifact gates NOT_CHECKED.
- [ ] Permit optional explicitly selected existing native SDK directory, setting SDKROOT without xcrun discovery or provisioning. Validate path and record supplied selection as observed configuration, not SDK qualification. Existing no-SDK harmless commands remain supported.
- [ ] Portable transcript tests through both Linux fixtures; harmless native smoke through the new wrapper using isolated installed-tool cache. Do not install Git/toolchains, mount, reboot or change normal settings. Self-review/commit for two-stage review before S2 consumes it.

## S2 — Execute the actual vendored Rust build guard

Files: `tools/qualification/sqlite/**`, `tests/qualification/test_sqlite_patch.py` only. Do not change vendor source/digests/patches, root Cargo files or application store code unless a concrete defect is returned for its own fix/review.

- [ ] Add an owned standalone dependency fixture outside the root workspace (`[workspace]` in generated fixture) that builds the real pinned vendor build.rs and bundled library, not an extracted function or system SQLite. Freeze dependency versions/use approved offline registry cache; do not update root lockfile.
- [ ] Tests must demonstrate permitted bundled inputs, altered/missing each mandatory pinned input, rejected alternate feature/environment routes, and target-versus-host selection. Preserve exact original source bytes; fault mutations only in new fixture copies. Guard rejection must happen before unsafe alternate compile/link; no fuzzy source acceptance.
- [ ] Use reviewed H2 source snapshot to include vendor/patches. On native27 use explicit cached1.98.1 + SDK and DEVELOPMENT/non-gate; run actual real build-guard and SQL link/smoke. Linux fixture separately checks its unchanged path. Offline source resolution must not fetch moving versions or use credentials.
- [ ] Record actual build-script execution versus source-check/static evidence. A failed guard after prior file creation is not proof no side effects. Native Work-linked VFS fault propagation and explicit checkpoints remain S3, not claimed by simple SQL success.
- [ ] If build guard defect emerges, return exact reproducer; coordinate source fix and provenance digest update through reviewed S1 owner rather than silently rewriting expected hashes. Self-review/commit fixture/tests.

Parent applies root `[patch.crates-io]`/lock edge only after guard evidence and separate integration review. Later H2 snapshots must contain the selected vendor before that root switch.

## A2 — Native counted directory batches and boot-session observation

Files: `crates/work-darwin/**` only; no root manifest/lock or application types. Reuse current dependencies unless an actual new edge is proposed to parent.

- [ ] Add test-first native batch interface over an explicitly owned/borrowed fresh directory cursor and caller-sized storage. One native getattrlistbulk call per request, explicit count/errno/EOF; no hidden refill/retry/allocation/growth. Continue safe checked decoding and clear failed output. Keep native effects in the confined FFI module.
- [ ] Validate ACTUAL native returned layout against the request schema using owned files/directories/non-UTF8 names/symlinks, not just synthetic parser fixtures. Repeated censuses use fresh opens, not dup cursors. Count/mask/entry-error/over-budget/stale-buffer behavior stays explicit.
- [ ] Do not require unavailable data-generation metadata in a NAME census as evidence that a directory is empty/clean. Keep explicit observation roles: enumeration needs proven names/identity/error handling; payload-generation proof is separately mandatory before accepted reads. If schema evolves, preserve existing portable decoder semantics or version the new API; no default-zero evidence/fake completion.
- [ ] Add a safe readonly native boot-session observation with fixed bounded sysctl buffer. Portable framing tests: exact37-byte UUID+NUL, canonical case, invalid/nil/extra bytes/embedded NUL refusal; no fallback IDs. Observe repeated native values without publishing host UUIDs. Do not perform a reboot or claim lifecycle qualification.
- [ ] Run portable tests/Clippy through both containers and native tests/check/strictClippy through reviewed H1/H2 with isolated pinned toolchain/cache. No real repositories/authority/mount/device operations. No full ACL/topology, durable identity migration or full collector claim.
- [ ] Self-review, record native ABI/OS/toolchain limits and commit. Real access/mount proof remains next adapter slice before safe core use.

## N1 — Build native CLI and reject unsupported Linux-only execution

Exclusive application owner for the phase: native cfg/import/body boundaries in `crates/work/src/lib.rs`, `platform.rs` if needed, scope/capture/Linux-native modules, filesystem/guard/receipt/recovery native implementation boundaries, `cli.rs` early unsupported dispatch, and focused `crates/work/tests/macos_unsupported.rs`. Do NOT edit `git.rs`, Git selection/config/setup/doctor logic, root manifests/lock or the adapter. Parent coordinates any registration edge.

- [ ] Write/read native build and unsupported-command tests BEFORE port edits. Record existing native compilation failures as capability-red; tests must verify --help/--version and explicit unsupported public/private supervision paths leave disposable sentinel/config/authority paths unchanged and never execute a child. Preserve redaction.
- [ ] Compile native application incrementally through reviewed H1 with isolated cached1.98.1/SDK/offline dependencies. Linux-only native imports/calls require cfg separation; keep shared serialization/history/lifecycle types, not whole-module disappearance or duplicate fake histories. Preserve bounded owned Git helpers on Darwin.
- [ ] Where core native backend is not implemented yet, return explicit unsupported/incomplete errors BEFORE managed mutation. Do not replace Linux openat2 with ordinary unsafe fallback, invent success, boot IDs, filesystem capability or completed supervision. Linux behavior and native code paths stay unchanged.
- [ ] Unsupported launching/supervision must refuse before identifier/context/registry/artifact creation or child launch/signalling, including private __scope-child. Existing historical state remains readable/holdable as its current contract permits.
- [ ] Build a native development `work` for harmless isolated help/version/refusal tests, not normal installation or supported-core advertising. No native repository lifecycle under without-Git mode; actual setup/start/finish/removal requires later Git/persistence/identity/inspection integration and qualification.
- [ ] Run pinned Linux compile/focused unchanged tests and native smoke. Full all-target native tests and workspace Clippy may retain explicitly enumerated integration gaps; no new broad lint suppression or test deletion. Record exact remaining core methods before claiming phase completion.
- [ ] Commit coherent small cfg/refusal slices; escalate concrete architecture contradictions rather than refactor all shared history. Spec review then quality review precede integration.

## Review/verification and subsequent phases

Every task records actual red/green, source/tool identities and failure limits, self-reviews/commits and returns DONE/DONE_WITH_CONCERNS/BLOCKED/NEEDS_CONTEXT. Read-only reviewers may use git diff/show/status; no mutation or test reruns unless separately assigned. Parent supplies missing artifacts/context without returning routine coordination to the user.

Both first-wave fixtures remain pinned; portable success is not syscall-capable Linux qualification. Do not change filesystem allowlists or sourceguards to satisfy Rosetta/fakeowner failures. No fullsuite repeated on the same diagnosed invalid runtime until corrected. Record complete locked workspace, formatting, strict all-target Clippy, Python helpers, packaging/artifact smoke and native matrix as outstanding release gates.

Next phases remain explicit: G3 real CLI/config/callsite integration; provider-aware durable identity preserving Linux decode; A3 protected access/real-mount proof; owned-hardlink capture journal/accounting/full metadata/census; S3 checked connections/checkpoints and root dependency wiring; full native lifecycle; I2/I3 direct ownership/activation/rollback/signer verification; P2 legacy/final-byte smoke; CI/version eligibility/protected release graph. No version/changelog bump until the separately authorized release PR. No normal installation, authority initialization, push, signing/publication, mount/reboot or checkout/worktree cleanup.
