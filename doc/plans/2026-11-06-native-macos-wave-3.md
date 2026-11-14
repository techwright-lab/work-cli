# Native macOS support — wave 3 implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Use a fresh implementer per bounded task, observed test-first evidence, scoped commits, independent SPEC review, then independent quality review. One writer per isolated worktree. Parent integrates serially.

**Goal:** compile native test targets, establish bounded access/topology and generation observations, integrate invocation-wide Git selection, and prove checked SQLite connections without enabling native managed mutation.

**Architecture:** extend the reviewed adapter, Git binding and store boundaries, retaining shared policy and Linux behavior. Application changes are serialized N2 → G3 → S3a; adapter and tooling lanes are independent. Native mutable authority admission stays closed until later identity, capture, checkpoint and lifecycle work is separately reviewed.

**Tech stack:** Rust/Cargo 1.98.1, existing rustix/libc, confined Darwin FFI, vendored libsqlite3-sys 0.36.0 / SQLite 3.51.1, Python/C qualification tooling, Git 2.55.0 and 2.56.0.

Accepted contract: `doc/specs/2026-11-06-native-macos-support.md`. Earlier plans: `doc/plans/2026-11-06-native-macos-support.md` and `doc/plans/2026-11-06-native-macos-wave-2.md`.

## Baseline and authority

All five wave-two slices passed separate spec and quality reviews and were integrated through `62c11868ff1e1238dc618f63b7430a35c1a7c559`. Final-root Linux evidence: locked workspace all-target compilation, formatting, 33 `git::` tests, five Linux-scope tests and six runtime-scope integration tests passed with each pinned Git fixture. Earlier unchanged adapter/harness/SQLite source passed 33/38/16 tests per fixture. Native S2 separately passed 23 real-build guard controls and static bundled SQL sum=42.

Integrated native macOS 27 ARM64 / pinned 1.98.1 / explicit SDK27 evidence: workspace check, development binary build, ten refusal tests and 37 adapter tests passed. The aggregate verifier exited 1 because its count assertion expected all 37 in one test-result line. The failed record remains retained. A fresh reviewed-H2 follow-up ran only missing strict adapter Clippy and formatting; both and its harness exited 0. Both packets attest the same source fingerprint and unchanged ARM64 binary. This is not native all-target/full-suite or release qualification.

Root Cargo still selects registry SQLite, not the reviewed vendor. The native development binary is help/version/refusal only. Git's Darwin access proof remains explicitly unproven until A3a/G3. Forty-five native unused findings and enumerated native test-compilation gaps remain integration debt, not passing lint.

The operator's temporary plain-Git-worktree exception remains in effect while Work is unusable. Use phase-specific siblings under `/Users/ravi/projects/techwright/work-cli-worktrees/`; do not nest allocation inside an assigned feature worktree. No real authority/configuration/capacity changes, normal install, push, signing, publication, mounts, reboot or cleanup are authorized. Application crates retain `forbid(unsafe_code)`; audited Darwin FFI stays confined to the approved adapter.

## Ownership and ordering

| Task | Exclusive files | Boundary |
| --- | --- | --- |
| N2 | Test helpers/narrow test cfgs in `crates/work/src/setup.rs`, `inspection_tests.rs`, `capture_artifacts_tests.rs`, `inspection/receipts.rs`, `inspection/retirement.rs`, **`git_binding_tests.rs` (test fixtures only)** and relevant `crates/work/tests/**` | Native all-target checking/test compilation; not native backend implementation |
| A3a | New `crates/work-darwin/src/access.rs`, `topology.rs`; adapter `ffi.rs`, `lib.rs`; source-named tests | Bounded access/actual-mount observations, explicit unknowns |
| A3b | Adapter attributes/decoder/FFI and new `tests/native_generation.rs` | Actual mandatory payload-generation characterization; serialized after A3a |
| H3 | New `tools/qualification/build-native-git.py`, `tests/qualification/test_native_git_fixture.py`, fixture documentation | Exact-source native Git in private prefixes |
| G3 | Git seam/tests, `cli.rs`, `config.rs`, `setup.rs`, `doctor.rs`, `identity.rs`, `inspection.rs`, affected local-helper consumers and focused tests | All production Git consumers use one invocation-owned binding |
| S3a-P | Parent: root Cargo/lock and application dependency registration. SQLite owner: narrowly reviewed vendor Rust/build glue and provenance if needed | Exact selection plus fail-closed unpatched native compilation |
| S3a | Store connection boundary/tests; `tools/qualification/sqlite/native_ack*`; source-named Python tests | Checked configuration and actual application-linked C acknowledgement errors |

Additional files discovered by the native error inventory require explicit parent coordination. N2 hands application/Git-test ownership to G3 only after review/integration. G3 hands application ownership to S3a afterward. A3a and A3b share one adapter writer sequentially. Parent alone registers shared manifest/lock edges.

```text
accepted N1 -> N2 -> G3 -> S3a
accepted G2 ---------^      ^
A3a access ----------^      |
H3 real native Git --^      |
accepted S2 -> S3a-P -------+
A3a -> A3b generation
later: S3b checkpoint/effect propagation + identity/capture/lifecycle
```

N2, A3a and H3 may start independently. Heavy builds are serialized even across source-isolated lanes. No I2 activation work is included in this wave.

## N2 — Native fixture and test compilation

- [ ] Capture native workspace all-target/test-compilation failures before editing. Classify exact source and semantics: FIFO/device `mknodat`, O_PATH, Linux receipt helpers and retirement `Boottime`, including Git's FIFO fixture.
- [ ] Add a minimal failing compile/refusal regression for each corrected seam. Use safe portable FIFO construction where the test remains portable; keep actual Linux-specific mechanisms narrowly target-gated.
- [ ] Preserve Git unsafe/nonregular rejection cases, Linux tests, portable parser/model/history tests and native refusal coverage. Do not delete broad modules, fabricate clocks/identities, replace production O_PATH with readable opens or make native core succeed to construct fixtures.
- [ ] Run native `cargo check --workspace --all-targets --locked --offline` and `cargo test --workspace --all-targets --no-run --locked --offline` through H2. Compilation is not execution or lifecycle qualification.
- [ ] Repeat focused Linux checks with both fixtures. Record remaining unused lint debt without suppression, self-review and commit.

## A3a — Access and actual mounted-route observations

- [ ] Write failing bounded tests for ACL count/truncation/overflow, unknown rights/principals, missing membership evidence and inconsistent observations.
- [ ] Define safe held-FD/component observations distinguishing object modification from parent replacement/deletion protection. Separate raw evidence from application policy; no raw pointer escape.
- [ ] Implement only necessary native calls inside audited `ffi.rs`. Bound buffers/counts and retain actual errno/validity; unsupported evidence is not mode-only proof.
- [ ] Test new owned fixtures with harmless and dangerous ACL grants, inheritance, effective access, changed identities and ancestor replacement. Accept proven harmless ACLs rather than banning all ACLs.
- [ ] Observe actual mounted identity, mountpoint/firmlink evidence and route consistency. APFS labels or equal `st_dev` alone are insufficient. Missing/contradictory topology refuses.
- [ ] Record unavailable foreign-volume coverage honestly; no mount is authorized. Review the safe interface before G3 consumes it. Self-review and commit.

## A3b — Payload-generation characterization

- [ ] Invoke the actual anchored attribute API, not NAME census, on owned files. Retain returned masks and field validity before/after ordinary/same-length writes, truncation, retained writable-FD writes and synchronized writable-mmap changes.
- [ ] Separately characterize hard-link creation/removal, expected nlink/ctime transitions, rename, metadata-only changes and unchanged controls.
- [ ] Relate results to native API semantics. Nonzero values alone do not establish adequate data-change detection. Zero/default/unavailable mandatory evidence remains refusal.
- [ ] If the mechanism is inadequate, stop payload-read advancement and return the precise blocker. No timestamp-only fallback or specification change is implicit. macOS27 development evidence does not establish 15/26 guarantees.
- [ ] Run portable/native focused checks, self-review and commit separately after A3a.

## H3 — Native Git fixtures

- [ ] Test unsupported versions, checksum failure, unsafe archive members/links, existing destinations, private-prefix enforcement and retained failure evidence before building.
- [ ] Fetch only the Dockerfile-pinned public official archives in isolated staging; verify bytes before extraction. No credentials or real repositories. Exact SHA256 pins:
  - Git2.55.0: `457fdb04dc8728e007d4688695e6912e6f680727920f2a40bf11eacc17505357`.
  - Git2.56.0: `26c56c296b38c0695b26fa95f475f1d01704d2d38e73465ca30b0b2f5dc789d3`.
- [ ] Reuse verified immutable archives where available. Build serially with explicit existing SDK/compiler into new owned private prefixes, never `/usr`, Homebrew or normal user bin/PATH.
- [ ] Record flags/dependencies, actual ARM64 architecture, exact version, executable/helper identities/layout and real disposable repository/helper smoke through qualified H2 Git mode. No silent disabling of required capabilities; missing dependencies block without tool installation.
- [ ] Run portable transcript tests in both containers, self-review and commit. Public pinned-source acquisition is routine implementation work, not an authentication step.

## G3 — Invocation-wide Git consumers

- [ ] After N2 and accepted G2, write failing global `--git`, precedence, invalid-explicit/no-fallback and diagnostic tests. Preserve native early refusal/redaction regardless of global-option placement.
- [ ] Extend every relevant config-document projection and setup proposal/render/persistence path. Discovery without config does not write; invocation overrides persist only through confirmed setup.
- [ ] Thread one binding through setup, doctor, identity, inspection and transitive local helpers. Preserve each caller's stronger environment/configuration/timeout profile; no globals, independent rediscovery or mid-operation fallback.
- [ ] Replace local upload-pack spelling with the selected validated helper, without claiming control of remote-host helper paths.
- [ ] Consume reviewed A3a for native access proof and parent-registered dependency edges. Test harmless ACL acceptance, dangerous/unknown refusal, effective directory search and executable/helper changes before/after dispatch, including `possibly_executed`.
- [ ] Run anchored controlled tests and H3 real-native fixtures. Audit all hard-coded production Git execution. Consume G2 private APIs rather than suppressing unused lint. Native managed mutation remains closed.
- [ ] Self-review and commit; remaining unrelated native integration lint/full-suite gaps are explicitly reported.

## S3a-P / S3a — Selection, checked connections and C fault evidence

- [ ] Parent selects the exact vendor via Cargo/lock without upgrading dependencies. Record actual application dependency resolution, build-script execution and static linkage, not merely an upstream SQLite version string.
- [ ] Demonstrate native application compile refusal when a fresh fixture removes the root patch and resolves upstream libsqlite3-sys. Root patches are not transitive into published `.crate` consumers.
- [ ] Coordinate a narrow safe enforcement marker/build contract from the actually verified dependency if required. Generation follows mandatory source verification; a workspace feature or manually supplied application cfg is not proof. Re-review vendor Rust/build glue, patches and provenance changes; rerun affected real guard controls. No unchecked digest regeneration.
- [ ] Record packaging behavior/conflicts, including the private `work-darwin` dependency. Linux Cargo-package verification and native final-artifact qualification are separate gates, neither waived. No internal-crate publication or silently unsafe native registry install is authorized.
- [ ] First prove dedicated native **test-target-only** C interception with actual-call traces and owned SQLite FD classification. VFS `fcntl`/directory/unlink/write seams exist; direct `fsync` requires separately demonstrated interception. Constructors/link overrides are hypotheses until proven. No app unsafe, production selector, mandatory-source mutation or guard bypass.
- [ ] Through safe crate-local tests, check every Darwin connection's `fullfsync=ON`, `checkpoint_fullfsync=ON`, `synchronous=FULL`, and `wal_autocheckpoint=0`, with readback, independent opens and initialization errors. Preserve Linux behavior.
- [ ] Trace full-sync-only failure with ordinary-sync success controls, ordinary-sync failure, directory open/sync, sidecar create/delete, writes and ENOSPC into actual SQLite/Work errors. Stop on unproven interception rather than substituting extracted-function evidence.
- [ ] Preserve possibly-committed observations on COMMIT error. State inspection/destructor rollback does not prove nothing committed. Inventory propagation seams but do not certify lifecycle cleanup before S3b.
- [ ] Public native mutable admission remains closed throughout. Self-review/commit bounded connection work after G3.

## Qualification, resource ceiling and later gates

Portable commands use `tools/qualification/container.sh`, repeated with `WORK_QUALIFICATION_GIT_VERSION=2.56.0`:

```sh
tools/qualification/container.sh check --workspace --all-targets --locked
tools/qualification/container.sh test --locked -p work-cli --lib git::
tools/qualification/container.sh test --locked -p work-cli --test runtime_scope
tools/qualification/container.sh test --locked -p work-darwin
tools/qualification/container.sh -- python3 -m unittest discover -s tests/qualification -p test_native_git_fixture.py
```

Do not use broad `--lib git`: it selects unrelated inspection/recovery tests that hit the diagnosed ENOSYS/fake-owner environment. Do not repeat the invalid full Linux suite or weaken filesystem/source guards.

Native runs use reviewed H2, explicit installed1.98.1/SDK, isolated registry-only Cargo home and new owned evidence destinations. Use explicit qualified H3 Git for repository tests; `--without-git` runs no repository operations. Record exact source/tool/context, command exits, counts, hashes, faults and limitations. All local macOS27 results remain DEVELOPMENT/NON-GATE.

Historical free-space observations declined from 35GiB to 21.8GiB before integrated native verification, 20.9GiB afterward and 20.37GiB after the lint/format continuation; remeasure before every heavy job. Parent adopts an **8GiB aggregate maximum additional retained footprint** for this wave, not a Work authority capacity setting. Serialize heavy jobs; estimate source/cache/target/evidence growth, account actual growth and stop before exceeding the ceiling or projected 10GiB physical free space. This is not permission to prune/clean, nor a guarantee every proposed task fits. Reuse only verified immutable sources, not shared mutable targets or fault trees. Preserve evidence and request storage guidance if insufficient.

Every task requires genuine red/green, scoped commits, SPEC then QUALITY approval and integrated checks. Complete valid-runtime locked tests, strict all-target Clippy, Python helpers, packaging/artifact smoke, both Git fixtures, macOS15/26 ARM64/APFS qualification and final-byte release provenance remain outstanding gates.

Later S3b must address checked checkpoint timing/progress, swallowed close/cleanup errors and possibly-committed effects across lifecycle callers. Provider-aware durable identity, protected hard-link capture/journals, full lifecycle, installer activation/rollback/authentication and protected release workflows remain separate work. No later flush retroactively proves earlier ordering, and no native activation follows automatically from S3a.
