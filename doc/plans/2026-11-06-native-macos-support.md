# Native Apple Silicon support implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development. Each task is test-first and receives separate spec-compliance review, then code-quality review. Steps use checkbox tracking. Parallelism is allowed only in isolated worktrees with exclusive file ownership.

**Goal:** implement the accepted Apple Silicon core, safe inspection/persistence boundaries, native qualification and standalone one-command distribution without weakening Linux behavior.

**Architecture:** shared lifecycle/hold/budget logic consumes a narrow platform seam. A confined Darwin adapter supplies missing safe observations; a bounded owned-hardlink protocol supplies original-object acquisition; a pinned macOS SQLite patch enforces checked persistence. Git binding, installer, packaging and native harness are separate workstreams, integrated only after review.

**Tech stack:** Rust workspace (pinned Rust 1.98.1), existing rustix/rusqlite, audited internal Darwin FFI, exact bundled SQLite 3.51.1, POSIX shell/Python developer tooling, Docker Linux fixtures and native ARM64 fixtures.

**Accepted contract:** `doc/specs/2026-11-06-native-macos-support.md`, snapshot of https://github.com/techwright-lab/work-cli/issues/30. Baseline `8d36fad79374792f010f0b3e89877c7ebe8d8ad2`. No version/changelog bump; no push, release, credentials, reboot, normal installation or checkout removal is authorized by implementation.

## Bootstrap authority and isolation

The operator explicitly authorized plain Git worktrees under `/Users/ravi/projects/techwright/work-cli-worktrees/` until Work becomes usable on this Mac. This is a recorded temporary exception, NOT permission to initialize authority/configuration or alter capacity. Revisit managed allocation when the binary is usable; still obtain configuration choices before onboarding. No nested allocation.

Main retains the documentation commit only. Integration: `integration`, branch `feat/macos-support`. Existing sibling lanes: `darwin-adapter`, `git-binding`, `shell-installer`, `sqlite-durability`, `qualification`, `packaging`, each on a matching `feat/macos-*` branch. One writer per worktree. Preserve all worktrees/evidence; no automatic finish/remove/prune.

## Dependency graph and bounded execution

```text
existing-Dockerfile image/cache bootstrap (already authorized, no source edits)
                  + plan review -> F0 disposable-fixture validation/review
                  -> F0 common crate/module foundation committed to lane bases
                  |-- A1 Darwin parser + native attribute surface -- A2 full observation layer
                  |-- G1 Git version/selection model -> G2 binding -> G3 CLI/config/callsite integration
                  |-- I1 rendered bootstrap/preflight -> I2 ownership/activation -> I3 native verification
                  |-- S1 pinned SQLite patch/provenance -> S2 exact-build fault matrix -> S3 store integration
                  |-- H1 native harness + Linux image preparation -> native evidence for A/S and later core
                  `-- P1 exact-byte packaging -> P2 smoke/assets -> release CI
A2 + identity + S3 -> owned-hardlink protocol -> full inspection/lifecycle -> native matrix
G3 + core + installer/package -> final artifact gates -> separately approved signing/publication
```

Image/cache bootstrap precedes F0 validation; it is not blocked on the later H1 harness code task. The first wave is F0 + A1/G1/I1/S1/H1/P1. These are finite reviewable deliverables, not a claim that macOS works. Later tasks below remain explicit dependencies; partial implementations refuse unsupported actions rather than pretending success. Do not reopen settled policy as a question about every test. Escalate concrete new policy contradictions or missing authorization only.

### Shared-file reservations

Parent integration owns root `Cargo.toml`, `Cargo.lock`, application `lib.rs` registration, `AGENTS.md`, distribution/skill/README/example docs and all integration/cherry-pick decisions. A worker may edit only its own new crate manifest inside its owned directory. No simultaneous writers to `inspection.rs`, `identity.rs`, `store.rs`, shared fixture support or workflow files.

Git's later CLI/config/setup/callsite migration is serialized before core owners change those same files. Inspection has one integration owner across its filesystem/manifest/receipts/recovery-ref/removal machinery. Supervised terminal capture modules are NOT the owned-hardlink capture subsystem.

## F0 — Common foundation (parent, after plan review)

Files: root `Cargo.toml`, `Cargo.lock`, new `crates/work-darwin/Cargo.toml`, `crates/work-darwin/src/lib.rs`, `crates/work/src/git.rs`, application `lib.rs`.

- [ ] Register internal non-published `work-darwin`; use workspace version without bumping it, and the already locked libc 0.2.191 where needed. Preserve exact existing dependency versions. Application workspace/`lib.rs` forbid-unsafe remains unchanged.
- [ ] Adapter does not inherit workspace forbid: crate defaults deny unsafe, with explicit reviewed allowance only in its FFI module. Safe parsing remains unsafe-free. No raw-pointer application API.
- [ ] Register an initially empty private application Git module so G1 can be independently compiled without owning application `lib.rs`.
- [ ] First identify/build the pinned Linux2.55.0 image and prepare its dependency cache using the existing Dockerfile/wrapper; this bootstrap may run before F0, while2.56.0 preparation reuses cache independently. Diagnose any baseline fixture/environment failures without weakening application checks.
- [ ] Validate manifest/lock consistency in the available pinned disposable fixture; review/commit foundation and fast-forward all clean lane branches to it before dispatch. Do not substitute native1.99.1 for this pinned foundation gate. No worker changes root manifests/lockfile.

## A1 — Darwin bounded parsing and minimal attribute surface

Exclusive files: `crates/work-darwin/**` (not root manifests). Test paths: `src/attributes.rs`, `src/bulk.rs`, `src/ffi.rs`, `tests/bulk_decode.rs`, `tests/native_attributes.rs`.

- [ ] Write portable failing parser tests: exact positive record count, stale tail, zero/nonprogressing lengths, truncation, arithmetic overflow, 4/8-byte alignment, missing returned masks, per-entry error, signed attrreference offsets, missing NUL/embedded NUL/slash and invalid child names. Buffers stay caller-bounded; unsupported fields are not equal-zero evidence.
- [ ] Run the new tests and retain actual red output; implement the smallest safe decoder to pass them. No hidden retries/growth/UTF-8 loss.
- [ ] Add a minimal Darwin-only anchored attributes wrapper for returned masks, file/data generation and relevant identity, with precise FD lifetimes, no-follow name semantics, checked sizes/errno. Keep FFI confined. Native tests use synthetic fixtures only through H1 when available; portable tests run through Linux qualification.
- [ ] Explicitly defer full ACL/topology/bulk syscall integration to A2; do not expose a fake safe-complete collector or fallback live readable-open.
- [ ] Run formatting/strict focused Clippy/tests in available fixture; self-review and commit. Report unsupported target evidence honestly.

Commands once images/cache are ready:
`tools/qualification/container.sh test --locked -p work-darwin`
`tools/qualification/container.sh clippy --locked -p work-darwin --all-targets -- -D warnings`
Native targeted tests must use H1; an existing 1.99.1 toolchain may be DEVELOPMENT evidence only, never substituted for the pinned release gate.

## G1 — Git version and deterministic selection model

Exclusive files: `crates/work/src/git.rs`, `crates/work/src/git_tests.rs` if used. No edits to CLI/config/identity/inspection in this slice.

- [ ] Write failing tests preserving exact current version policy: `git version MAJOR.MINOR.PATCH\n`, canonical decimal u32 components, no suffix/prerelease/extra newline/leading zeros, >=2.55.0. Preserve current admission vectors, add malformed/overflow bounds.
- [ ] Add typed version/admission errors independent of inspection, deterministic candidate policy, selection-source and rejection metadata. Input precedence is CLI absolute path > configured absolute path > defaults; invalid explicit choice never falls back. macOS defaults only `/opt/homebrew/bin/git`, `/usr/bin/git`; Linux only `/usr/bin/git`; no PATH/env selector.
- [ ] Test path policy and candidate ordering as pure data. Do not execute untrusted fake executables or introduce mutable global overrides. Do not implement a lowest-common-denominator Git command security profile.
- [ ] Implement/run red-green model tests and self-review; commit. Record any production dead-code lint limitation while these private APIs lack G2/G3 consumers; strict production/all-target lint acceptance remains pending until reviewed consumer integration. Do not use allow/expect(dead_code), artificial consumers, test-only production implementations or unnecessarily public APIs to hide it. G2 later adds actual bounded executable/helper qualification and invocation-bound revalidation; G3 migrates every caller including redacted argument handling. The final strict workspace gate is unchanged.

Command: `tools/qualification/container.sh test --locked -p work-cli --lib git`.

## I1 — Release-bound installer renderer and nonmutating preflight

Exclusive files: `tools/install.sh.in`, `tools/render_installer.py`, `tests/qualification/test_shell_install.py`.

Frozen renderer: `python3 tools/render_installer.py --version VERSION --developer-id EXPECTED_IDENTITY --output FILE`. No production placeholder/empty identity. Explicit test identities are fixture-only. Published `install.sh` embeds version/identity; no runtime Python/jq requirement.

- [ ] Test renderer validation, shell quoting/injection hazards, exact embedded version/identity and output refusal/replacement policy before implementation.
- [ ] Test `install`, `update --confirm-stopped`, `rollback --version VERSION --confirm-stopped`, `--bin-dir`, unknown/missing args and confirmation rules. Default destination `~/.local/bin`; no sudo/profile/Git/skill/setup changes.
- [ ] Test fixed-version HTTPS-only download/redirect contract, required utility preflight and strict bounded checksum sidecar parsing with expected filename/digest. Mock tools only inside owned test fixtures; no real download execution or system utility replacement.
- [ ] Implement renderer/parser/preflight with fail-closed behavior. Until I2 activation exists, do NOT return success for install/update/rollback or touch an installation. This partial template must not be published as a release installer.
- [ ] Run red-green helper tests through Linux fixtures, shell syntax validation in those tests, self-review and commit.

Command: `tools/qualification/container.sh -- python3 -m unittest discover -s tests/qualification -p test_shell_install.py`.

I2 frozen ownership direction (document, not implement in I1): distinct private user-data namespace `work-cli/direct-installs/v1/`, one destination-hash-keyed directory and bounded versioned record/intent plus retained binaries. Hash canonical bin destination with SHA-256; reject newline/control-path ambiguity. Do not reuse helper `current`, receipts or lock as direct ownership evidence. Concrete encoding/activation tests belong to I2; no implicit adoption or unknown cleanup.

## S1 — Exact pinned SQLite provenance and narrow Darwin enforcement patch

Exclusive files: `vendor/libsqlite3-sys/**`, `patches/sqlite/**`, `tests/qualification/test_sqlite_patch.py`, `tools/qualification/sqlite/**`. Parent alone applies root dependency patch/lock integration after review.

- [ ] Retrieve ONLY exact libsqlite3-sys 0.36.0 crate source, verify Cargo.lock checksum before safe extraction; retain origin/version/checksum and source/patch expectations. Do not use system SQLite or a moving download at build time. Validate archive paths; no credential/repo copying.
- [ ] Write failing source/provenance/patch-context tests and bounded compile/fault harness controls before modifying source. Expected source drift/patch mismatch fails, not fuzzy application.
- [ ] Implement narrowly gated Darwin changes: requested mandatory full-sync cannot silently succeed via ordinary fallback; required creation/deletion/sidecar directory open/sync failures propagate at selected acknowledgement boundaries. Linux C behavior remains unchanged. This is not merely deleting the fallback line.
- [ ] Prove source changes and failure paths with available exact-source harness. Clearly distinguish an extracted control-flow test, a whole amalgamation test and actual Work-linked native bundled transactions. Do not count one as another.
- [ ] Document exact next S2/S3 obligations: actual bundled VFS injection, WAL/internal checkpoint ordering, explicit macOS checkpoint error handling and post-COMMIT held semantics. No root Cargo patch/lock or `store.rs` edits in S1.
- [ ] Self-review/commit source provenance, minimal patch and tests. No version bump, arbitrary dependency upgrade, production environment-controlled fault switch or package publication.

Command: `tools/qualification/container.sh -- python3 -m unittest discover -s tests/qualification -p test_sqlite_patch.py`.

## H1 — Disposable native harness and pinned Linux fixture preparation

Exclusive files: `tools/qualification/native-macos.sh`, `tests/qualification/test_macos_harness.py`, lane-owned logs under ignored target. No workflow/container-script/AGENTS changes in this slice.

- [ ] Reuse/finish the pre-F0 bootstrap: build pinned Linux qualification images for both Git versions as needed, using an EMPTY scratch build context plus the existing Dockerfile, `--platform linux/amd64` on this ARM Mac. Tags remain `work-cli-qualification:rust-1.98.1-git-VERSION`. Keep real repositories/credentials outside containers except the prescribed source-only qualification mount. Record actual image architecture/tool identities. Do not modify Docker/registry credentials.
- [ ] Publish readiness to supervisor as soon as the 2.55.0 image is available; no other lane builds the same tag. Build second fixture reusing cache. No image/tool setup claim until observed.
- [ ] Write failing portable tests for harness argument validation, nonnative/unsupported host refusal, existing destination refusal, isolated HOME/XDG/config/temp, source-only fixture copy excluding `.git`/target/credentials, working-directory correctness and retained evidence on error. No normal config/authority access.
- [ ] Implement explicit `--git-version VERSION --git /absolute/path --toolchain TOOLCHAIN -- COMMAND...` qualification mode that validates required versions/native ARM64 and uses an isolated owned fixture. Missing qualified tools fail before command. Never replace `/usr/bin/git`.
- [ ] Provide explicit `--without-git` DEVELOPMENT mode for adapter/parser/format tests that need no repository operations; label evidence as non-full-qualification. No implicit unsupported success. Do not auto-install toolchains or Git; report missing prerequisites.
- [ ] An explicitly selected already-installed 1.99.1 toolchain is allowed for development evidence, not the pinned1.98.1 release gate. Copy source and use disposable HOME/config/state while keeping intentional toolchain/cache paths explicit; no unbounded toolchain autodownload into user state.
- [ ] Run red-green portable harness tests through container; native smoke only with safe commands and owned fixtures, no mounts/reboot. Self-review/commit, report harness/image readiness. Parent reviews before other branches consume it.

## P1 — Exact-final-byte packaging primitive

Exclusive files: `tools/package-common.py`, `tests/qualification/test_package.py`. Do not edit legacy `package-linux.sh`, smoke.py, installer files or workflows until P2 integration.

- [ ] Write failing tests using inert fixture bytes for explicit platform/version/executable/source-root/output arguments, exact standalone/bundle names and checksums, allowlisted bundle contents, no authority/unrelated source inclusion, existing-output refusal and standalone/bundle byte identity.
- [ ] Implement packaging of ALREADY FINAL supplied bytes; never build, sign, notarize, execute or modify them. Developer Python packaging is permitted; installed Work remains standalone/no-Python.
- [ ] Supported asset vocabulary: linux-x86_64 and macos-arm64, names in accepted specification. Validate path/version/platform and archive layout. Do not treat inert fixtures as executable/native qualification.
- [ ] Installer asset rendering/signing verification belongs to reviewed later integration; P1 does not emit a fake fully qualified release. Preserve existing Linux packaging behavior by not changing its entry point yet.
- [ ] Run red-green helper tests, self-review/commit. P2 later wires existing Linux wrapper, Darwin final-byte checks and full artifact smoke.

Command: `tools/qualification/container.sh -- python3 -m unittest discover -s tests/qualification -p test_package.py`.

## SDD review and integration gates

For EVERY task:
- [ ] Fresh implementer receives complete bounded task, cwd, ownership, accepted-contract pointers, tests and stop conditions. No subagent nesting.
- [ ] Implementer demonstrates red-green evidence where tools available, self-reviews, commits only owned changes, and reports DONE / DONE_WITH_CONCERNS / NEEDS_CONTEXT / BLOCKED.
- [ ] Fresh read-only SPEC reviewer compares actual diff/tests against task + accepted contract; fix/re-review gaps.
- [ ] Only after spec approval, fresh CODE QUALITY reviewer checks safety/maintainability/error behavior/test validity; fix/re-review defects.
- [ ] Parent integrates reviewed commits serially, preserving one writer per cwd; no merging unreviewed shared-file changes.
- [ ] Integrated regression evidence is observed before completion claims. Baseline unavailable/failing checks remain explicit, not counted as passing tests.

Remaining implementation phases after first wave: G2/G3 full invocation binding/CLI/config/redaction/local-helper migration; A2 complete native attributes/access/topology/enumeration; provider-aware Darwin identity compatibility retaining Linux decode; selected SQLite store/connection/checkpoint integration; native compilation boundary retaining shared history and rejecting Linux-only commands before side effects; protected hardlink journaling/resource/accounting; full manifest/inspection/receipt/recovery-ref/removal integration; installer ownership/atomic activation/rollback/native signer checks; full packaging/smoke/native matrix/release eligibility/approval graph; coordinated runbook/skills/setup diagnostics.

## Complete verification before any release-readiness claim

For EACH Git fixture2.55.0/2.56.0 and its actual matching qualified Linux image:

```sh
export WORK_QUALIFICATION_GIT_VERSION=2.55.0 # repeat with 2.56.0
tools/qualification/container.sh fetch --locked
tools/qualification/container.sh -- python3 tools/release_version.py
tools/qualification/container.sh test --workspace --locked --no-fail-fast -- --test-threads=4
tools/qualification/container.sh fmt --all -- --check
tools/qualification/container.sh clippy --workspace --all-targets --locked -- -D warnings
tools/qualification/container.sh -- python3 -m unittest discover -s tests/qualification
tools/qualification/container.sh -- tools/package-linux.sh
tools/qualification/container.sh -- python3 tools/qualification/smoke.py
```

Repeat applicable checks through the reviewed native harness for macOS15/26, both Git fixtures and APFS variants. macOS27 development observations do not replace this matrix. Signing/notarization and publication each require separate explicit approval with actual remote protection/credential audit and final-byte evidence. No unapproved reboot, mounts, power-loss trial, real-state mutation, normal install switch, confirmed checkout removal or publish action.

## Work tracking

Record task identities/branch/commit and observed tests in implementation issue comments or this plan. Do not reopen the completed Wayfinder map for ordinary build tasks. The accepted spec remains the source of product policy; newly exposed policy changes return explicitly to the operator. Continue authorized tasks/reviews autonomously and in isolated parallel lanes; no routine continue prompts.
