# Native setup and default configuration discovery Implementation Plan

> **REQUIRED SUB-SKILL:** Use the subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Deliver native, consent-gated setup and shared default configuration discovery without initializing or changing Work authority.

**Architecture:** Keep discovery and TOML ownership in Config/ConfigDocument and expose existing actor/Git validators crate-privately. A new setup module validates an in-memory proposal, previews it, then only after confirmation prepares directories and atomically publishes configuration. The existing native skill installer supplies observable partial progress; lifecycle and registered-root admission remain unchanged.

**Tech Stack:** Rust, existing Clap/Serde/TOML/rustix/tempfile, Linux filesystem primitives, Python qualification helpers and disposable Docker Git fixtures.

**Spec:** `doc/specs/2026-11-01-native-setup-config-discovery.md`

**Verification:** `tools/qualification/container.sh test --workspace --locked --no-fail-fast -- --test-threads=4` && `tools/qualification/container.sh fmt --all -- --check` && `tools/qualification/container.sh clippy --workspace --all-targets --locked -- -D warnings` && `tools/qualification/container.sh -- python3 -m unittest discover -s tests/qualification` && `tools/qualification/container.sh -- tools/package-linux.sh` && `tools/qualification/container.sh -- python3 tools/qualification/smoke.py` && `WORK_QUALIFICATION_GIT_VERSION=2.56.0 tools/qualification/container.sh test --workspace --locked --no-fail-fast -- --test-threads=4` && `WORK_QUALIFICATION_GIT_VERSION=2.56.0 tools/qualification/container.sh fmt --all -- --check` && `WORK_QUALIFICATION_GIT_VERSION=2.56.0 tools/qualification/container.sh clippy --workspace --all-targets --locked -- -D warnings` && `WORK_QUALIFICATION_GIT_VERSION=2.56.0 tools/qualification/container.sh -- python3 -m unittest discover -s tests/qualification` && `WORK_QUALIFICATION_GIT_VERSION=2.56.0 tools/qualification/container.sh -- tools/package-linux.sh` && `WORK_QUALIFICATION_GIT_VERSION=2.56.0 tools/qualification/container.sh -- python3 tools/qualification/smoke.py`

Baseline techwright-lab/work-cli: 7620c7c

Baseline provenance (techwright-lab/work-cli): HEAD 7620c7c, approved spec commit 7620c7cda785bbf61e3541aa2427042855df63be. Initial `git status --porcelain --untracked-files=all` inventory was empty; admitted workflow paths are only `doc/specs/2026-11-01-native-setup-config-discovery.md` and `doc/plans/2026-11-01-native-setup-config-discovery.md`. Executed the four existing-anchor commands below in this checkout's qualification container: cli_contract 14 tests, doctor 13 tests, skill_install 7 tests, release-version 1 test, all exit 0. After each command HEAD remained 7620c7c and status remained empty. Setup anchors are declared Create paths and absent, so their command is skipped under the all-created-anchor rule. No generated untracked artifacts were observed. On ordinary repair, pre-run inventory was only the admitted untracked plan; HEAD remained 7620c7c. Endpoint-tree proof `git diff --quiet 7620c7c 7620c7c -- . ':!doc/specs/' ':!doc/plans/'` exited 0. Reran all three changed Rust-adapter commands unchanged from their repaired Tests text: 14/13/7 tests passed, exit 0; after each, only the admitted plan was untracked and HEAD stayed 7620c7c. Retained the unchanged Python command evidence at the same SHA after that proof; regenerated both all-created setup skipped bullets for the split integration/internal commands. Header verification remains for verify, not baseline. Native-adapter amendment baseline: initial inventory was only `?? doc/plans/2026-11-01-native-setup-config-discovery.md`, admitted as the dispatched plan; BASE remained 7620c7c. Before running commands, `git diff --quiet 7620c7c HEAD -- . ':!doc/specs/' ':!doc/plans/'` exited 0. Retained 6 bullets: 7620c7c -> 7620c7c, tree-equivalent outside doc/specs, doc/plans (four unchanged passing commands and two unchanged all-created setup commands). Executed the newly added exact config:: Rust-adapter Tests command: five tests passed, exit 0. Post-run HEAD remained 7620c7c and inventory remained only the admitted untracked plan, with no new artifacts. The new skill_install:: command anchors solely the absent Create+Test path and is skipped by the all-created-anchor rule.

---

## Execution boundaries

- Home leg is techwright-lab/work-cli at the explicitly supplied Work-owned checkout. Keep this checkout; do not allocate/nest another checkout, finish/remove any real checkout, change global configuration, or use live authority as a fixture. The recorded Work lifecycle contract is not permission to invoke creation/destruction during implementation.
- Rules re-walk found root `AGENTS.md` only, no descendant AGENTS files and no gauntlet overrides. Apply `AGENTS.md`, `skills/work-cli/SKILL.md`, `skills/work-cli/reference/setup.md`, `docs/distribution.md` and `tools/qualification/container.sh`. The setup-reference link is the extra one-hop local rule read during recon. Do not change AGENTS policy.
- One feature plan: no independently deployed intermediate topology or mechanical review-risk split exists. Do not publish/tag, upgrade the host, or alter actual user configuration. Exact-SHA main CI/CodeQL and tag gates remain separate publication requirements.
- Every fixture owns its temporary HOME, repositories, state, root, skill data and cleanup boundary. Clear inherited selectors/credentials in spawned CLI environments. Use `/usr/bin/git` and local disposable commits only. No fetch/network/hooks/project installers. Fixture allocation/finish/removal must target only fixture tasks; permission never transfers to a live checkout.
- Cargo has no file-path integration-test selector. Decision: scoped commands use a Python adapter inside the qualification container, mapping an exact Rust test path to its Cargo target name and propagating failure/nonzero-test summaries. This is test tooling only, not a Python runtime requirement or a reason to create another source helper.
- Owner-approved option A adapts execution to native pi-subagents in this existing checkout, without global configuration changes. Legacy pi-cohort preflight actually failed with `pi-cohort not installed`; no implementation has started and all five existing tracker entries remain pending. Preserve those entries, task titles and wave positions; do not reinitialize the tracker.
- Execute one fresh implementer per task, serially in place, with one writer at a time (including Tasks 1 and 2 in Wave 1). No worker commits, temporary/nested worktrees, allocations, patch folding or reset folding. Wait for asynchronous native completion notifications rather than polling. The parent owns dispatch, review and commits; workers leave their scoped changes in this checkout.
- Retain every TDD red/green and scoped formatting/lint instruction. After each task, require a fresh spec review against the approved spec and repair/re-review until accepted before the next task writer starts. At each code-wave boundary, the parent runs the integrated scoped test gate (the union of that wave's Tests commands on the combined checkout) and requires one fresh code-quality review of the complete wave diff; fixes repeat affected tests and reviews before acceptance. Parent commits only after acceptance, using the task commit subjects below; if splitting Wave 1 into its two task commits, preserve the accepted combined tree and never reset/fold worker patches. The documentation wave also requires fresh task spec review and parent acceptance before commit. Final verification and separate publication gates remain unchanged.
- Keep new APIs crate-private. No persistent schema, database migration, status JSON field, framework or dependency addition. Prompt wording and incidental artifact names remain implementation-owned; ownership/identification must be testable.

## Files

**Create — native setup:**
- `crates/work/src/setup.rs` — arguments, proposal, prompts, validation, writer, report and internal filesystem seam.
- `crates/work/tests/setup.rs` — isolated public setup contract.

**Modify — shared configuration and validation:**
- `crates/work/src/config.rs` — shared fallback and document-owned prospective/render/addition helpers.
- `crates/work/src/allocate.rs` — crate-private component validator reuse only.
- `crates/work/src/inspection.rs` — crate-private supported-version policy reuse only.
- `crates/work/src/doctor.rs` — crate-private layout precheck and absolute Git executable.
- `crates/work/tests/cli_contract.rs` — discovery and initialized-charge regressions.
- `crates/work/tests/doctor.rs` — selector, malformed-config and layout regressions.

**Create — private installer tests:**
- `crates/work/src/skill_install_tests.rs` — private test-only observation/failure cases, included by a cfg(test) path module in skill_install.rs; no product component or API.

**Modify — installer and CLI:**
- `crates/work/src/skill_install.rs` — typed completed/failed/unknown action observation.
- `crates/work/tests/skill_install.rs` — standalone protection/observation regressions.
- `crates/work/src/cli.rs` — Setup variant and report/exit dispatch before configuration loading.
- `crates/work/src/lib.rs` — private setup module.

**Modify — delivery qualification:**
- `Cargo.toml` — workspace 0.3.0.
- `Cargo.lock` — only work-cli/work-contract versions 0.3.0.
- `tests/qualification/test_release_version.py` — workspace/local-lock regression plus retained mismatch tests.
- `tools/qualification/smoke.py` — setup-produced default config drives packaged lifecycle.

**Modify — canonical onboarding and embedded instructions:**
- `README.md` — Configure once and version-specific install examples.
- `docs/distribution.md` — onboarding, defaults, precedence, security/failure boundaries and install examples.
- `skills/work-cli/SKILL.md` — authorized setup routing.
- `skills/work-cli/reference/setup.md` — native setup/update guidance.
- `examples/work.toml` — aligned comments, unchanged schema/defaults.

**Delete:** none.

## Wave 1 — Shared owners

Tasks 1 and 2 are independent and file-disjoint; retain this grouping, but execute Task 1 then Task 2 serially under the owner-approved native adapter. Tests use separately owned temporary directories, no shared HOME/database/port/fixture path. Cargo's cache lock is not a fixture coordination contract; never share authority fixtures.

### Task 1: Fix discovery and expose document-owned validation seams
Leg: techwright-lab/work-cli

**TDD scenario:** Modifying tested code — run existing tests first.

**Spec:** doc/specs/2026-11-01-native-setup-config-discovery.md § "Acceptance criteria" L26, § "Acceptance criteria" L28, § "Acceptance criteria" L38, § "Acceptance criteria" L42, § "Changes and ownership" L80, § "Changes and ownership" L81, § "Changes and ownership" L83, § "Changes and ownership" L87, § "Changes and ownership" L89, § "Shared discovery" L93-L94, § "Shared discovery" L95, § "Shared discovery" L96, § "Shared discovery" L97, § "Shared discovery" L99, § "First-time fields and defaults" L128, § "First-time fields and defaults" L131, § "Existing configuration: option A" L145-L146, § "Existing configuration: option A" L149, § "Existing configuration: option A" L153, § "Config publication and reports" L157, § "Config publication and reports" L159, § "Version and delivery" L179, § "Errors and edge cases" L183, § "Errors and edge cases" L191, § "Tests" L195, § "Tests" L197-L198, § "Tests" L205, § "Out of scope" L226

**Files:**
- Modify: `crates/work/src/config.rs:68-440`
- Modify: `crates/work/src/allocate.rs:73-81`
- Modify: `crates/work/src/inspection.rs:98-132`
- Modify: `crates/work/src/doctor.rs:52-159`
- Modify: `crates/work/tests/cli_contract.rs`
- Modify: `crates/work/tests/doctor.rs`
- Test: `crates/work/tests/cli_contract.rs`
- Test: `crates/work/tests/doctor.rs`
- Test: `crates/work/src/config.rs`

**Tests:**
- `tools/qualification/container.sh -- python3 -c "__import__('subprocess').run(('cargo','test','-p','work-cli','--locked','--test',__import__('pathlib').Path(__import__('sys').argv.pop()).stem),check=True)" crates/work/tests/cli_contract.rs`
- baseline: 7620c7c pass
- via: `Config::load`, `ConfigDocument::load`, `Config::discover_path`, public status
- `tools/qualification/container.sh -- python3 -c "__import__('subprocess').run(('cargo','test','-p','work-cli','--locked','--test',__import__('pathlib').Path(__import__('sys').argv.pop()).stem),check=True)" crates/work/tests/doctor.rs`
- baseline: 7620c7c pass
- via: `doctor::precheck`, public doctor
- `tools/qualification/container.sh -- python3 -c "__import__('subprocess').run(('cargo','test','-p','work-cli','--locked','--lib','config::'),check=True)" crates/work/src/config.rs`
- baseline: 7620c7c pass
- via: `ConfigDocument` internal config:: tests (existing cfg(test) modules begin at config.rs:567)

- [ ] **Step 1: Run all three Tests commands.** Expect the existing 14 cli_contract, 13 doctor and five config:: tests green.
- [ ] **Step 2: Add selector regression cases.** Extend env-cleared IsolatedRoot/run_work at cli_contract.rs:14-85 without process-global environment changes. Put distinct valid files at explicit/XDG/HOME locations. Assert explicit wins; XDG wins absent explicit; HOME wins absent/empty XDG; empty explicit disables all discovery; no usable HOME/XDG stays passive; missing implicit remains passive; explicit missing fails. Preserve an explicit relative reader path.
- [ ] **Step 3: Add initialized-inventory proof.** Create/commit a disposable local repository, root and config, start a fixture task through the public CLI, then compare parsed status for explicit WORK_CONFIG versus selectors removed and HOME default selected. Require initialized=true, charged>0 and identical checkout UUID/state/charge inventory. Two uninitialized results are not proof. Extend doctor's existing malformed/oversized/special-file cases with location-only parser diagnostics and selector cases.
- [ ] **Step 4: Run both integration Tests commands red.** Require the HOME case to expose the old fallback failure, not a broken fixture or Git-version failure.
- [ ] **Step 5: Fix the shared resolver.** Keep present-WORK_CONFIG first, including empty disable. Otherwise filter empty XDG_CONFIG_HOME then empty HOME, choosing XDG/work/config.toml or HOME/.config/work/config.toml. Retain read_text's explicit-missing distinction, final NOFOLLOW/NONBLOCK bounded regular-file reads, 1 MiB maximum and sanitized parser location. All ConfigDocument consumers inherit this owner; add no caller-local fallback.
- [ ] **Step 6: Add document-helper tests.** In config.rs internal tests round-trip actor/repositories/roots/allocation and unknown TOML tables; append canonical repository values, deduplicate without reordering existing entries and compare every protected/unknown value. Cover wrong actor/repository types and prospective missing-root validation without creating a directory.
- [ ] **Step 7: Implement owner-level document helpers.** Add crate-private field inspection/render/addition and new-install construction over toml::Value. Retain raw bytes/identity in setup's snapshot, not a lossy Config reconstruction. Validate setup-owned actor/allocation/path fields using existing types. Separate prospective missing-root checks from execution(), whose required roots/repositories checks stay unchanged. Preserve lazy inspection/recovery/retirement policy isolation; unrelated historical declarations are not execution prerequisites for a repository-only edit. Task 3 revalidates created directories with normal required-path validation.
- [ ] **Step 8: Expose existing validators without changing rules.** Make allocate::component (allocate.rs:73-81), inspection::require_supported_git_version (inspection.rs:98-132) and doctor::precheck (doctor.rs:110-147) crate-private. Retain strict stable >=2.55.0 and private/common-directory checks. Doctor probes use `/usr/bin/git`, preserving bounded_process, deadline, output cap and scrubbed environment. Add doctor regression assertions for supported unrelated linked repositories and unsafe private/common metadata; managed-task/root exclusion belongs to setup, not a blanket doctor ban.
- [ ] **Step 9: Run public and internal tests green.** Repeat all three Tests commands, including the exact scoped config:: adapter command. Expect tests executed and green; regressions must exercise production resolver/validators.
- [ ] **Step 10: Format and lint.** Run: `tools/qualification/container.sh -- rustfmt --edition 2021 crates/work/src/config.rs crates/work/src/allocate.rs crates/work/src/inspection.rs crates/work/src/doctor.rs crates/work/tests/cli_contract.rs crates/work/tests/doctor.rs`. Run: `tools/qualification/container.sh clippy -p work-cli --lib --test cli_contract --test doctor --locked -- -D warnings`. Expect idempotent formatting and zero warnings.
- [ ] **Step 11: Parent commit after acceptance; no worker commit.** After the per-task fresh spec review and Wave 1 integrated scoped test/code-quality gates accept, the parent stages the six owned files and commits with `git commit -m "Fix shared config discovery and expose setup validation seams"` under reviewed-wave commit policy. Do not allocate another checkout.

Decision: preserve ancestor-symlink reader compatibility; writer eligibility is separate. Config::read_text/config.rs:259-295 follows ancestors while opening the final file NOFOLLOW, and the spec explicitly preserves that distinction. Do not harden the reader into a writer check.

### Task 2: Observe native skill installation without losing partial actions
Leg: techwright-lab/work-cli

**TDD scenario:** Modifying tested code — run existing tests first.

**Spec:** doc/specs/2026-11-01-native-setup-config-discovery.md § "Acceptance criteria" L46, § "Acceptance criteria" L48, § "Changes and ownership" L82, § "Changes and ownership" L87, § "Changes and ownership" L89, § "Config publication and reports" L167, § "Skill registration" L171, § "Skill registration" L173, § "Version and delivery" L179, § "Tests" L195, § "Tests" L208

**Files:**
- Modify: `crates/work/src/skill_install.rs:28-354`
- Create: `crates/work/src/skill_install_tests.rs`
- Modify: `crates/work/tests/skill_install.rs`
- Test: `crates/work/tests/skill_install.rs`
- Test: `crates/work/src/skill_install_tests.rs`

**Tests:**
- `tools/qualification/container.sh -- python3 -c "__import__('subprocess').run(('cargo','test','-p','work-cli','--locked','--test',__import__('pathlib').Path(__import__('sys').argv.pop()).stem),check=True)" crates/work/tests/skill_install.rs`
- baseline: 7620c7c pass
- via: `skill_install::install`, public skill install
- `tools/qualification/container.sh -- python3 -c "__import__('subprocess').run(('cargo','test','-p','work-cli','--locked','--lib','skill_install::'),check=True)" crates/work/src/skill_install_tests.rs`
- baseline: 7620c7c skipped - crates/work/src/skill_install_tests.rs created by this task
- via: private skill_install:: observation tests

- [ ] **Step 1: Run the existing integration Tests command first.** Expect seven standalone installer tests green. Do not run the internal command until its test file/module exists.
- [ ] **Step 2: Add failing internal observation tests.** Create crates/work/src/skill_install_tests.rs and include it in skill_install.rs with `#[cfg(test)]`, `#[path = "skill_install_tests.rs"]`, `mod tests;`; keep all new tests under skill_install:: and private to the test build. Exercise directory creation, snapshot publication, skill-current publication and per-target registration as ordered typed actions. A private operations/observer seam fails after pointer publication and after an earlier target registration. Assert prior successes persist, failed/uncertain actions differ and snapshots remain. Extend public tests to retain foreign-target protection and config independence with malformed WORK_CONFIG and PATH=/no-tools.
- [ ] **Step 3: Run new internal tests red.** Run the exact scoped skill_install:: adapter command from Tests, now that the Create+Test file and cfg(test) path module exist. Require missing progress observation to explain the failure; no public fault-injection environment selector.
- [ ] **Step 4: Add compatible structured progress.** Introduce crate-private InstallProgress/InstallAction records with kind, target and completed/failed/unknown status and an observation-capable installer returning progress on failure. Preserve install(all: bool)'s existing successful Report/string-error API for cli.rs:197-211 by delegating to it. Task 3 consumes the structured result directly.
- [ ] **Step 5: Record actions at their mutation owners.** Thread observation through directory(), snapshot(), atomic_link() and discovery-target registration in install(). Record syscall publication before later sync; distinguish unknown durability from skipped/rolled-back. Retain earlier completed actions on failure. Keep all-target preflight, foreign-link protection, existing lock, NOFOLLOW/hardlink/ownership checks, cached-content verification and retained snapshots. No config loading, Git/Python/network or unknown-outcome retry.
- [ ] **Step 6: Run internal and integration tests green.** Run both Tests commands after creating the internal test file/module. Prove preflight failure differs from failure after activation and never erases prior actions.
- [ ] **Step 7: Format and lint.** Run: `tools/qualification/container.sh -- rustfmt --edition 2021 --config skip_children=true crates/work/src/skill_install.rs crates/work/src/skill_install_tests.rs crates/work/tests/skill_install.rs`. Run: `tools/qualification/container.sh clippy -p work-cli --lib --test skill_install --locked -- -D warnings`. Expect idempotent formatting and zero warnings.
- [ ] **Step 8: Parent commit after acceptance; no worker commit.** After the per-task fresh spec review and Wave 1 integrated scoped test/code-quality gates accept, the parent stages all three owned files and commits with `git commit -m "Expose truthful partial progress from native skill installation"` under reviewed-wave commit policy.

Decision: keep standalone install JSON/config independence unchanged; its current Report and dispatch are consumed by smoke.py:24-30 and public installer tests. The observation API is additive and crate-private.

## Wave 2 — Native setup orchestration

Depends on Wave 1: Task 3 consumes Task 1's document/validator seams and Task 2's installer observation API.

### Task 3: Build, confirm and safely publish native setup proposals
Leg: techwright-lab/work-cli

**TDD scenario:** New feature — full TDD cycle.

**Spec:** doc/specs/2026-11-01-native-setup-config-discovery.md § "Acceptance criteria" L30, § "Acceptance criteria" L32, § "Acceptance criteria" L34, § "Acceptance criteria" L36, § "Acceptance criteria" L38, § "Acceptance criteria" L40, § "Acceptance criteria" L42, § "Acceptance criteria" L44, § "Acceptance criteria" L46, § "Acceptance criteria" L48, § "Changes and ownership" L78, § "Changes and ownership" L79, § "Changes and ownership" L81, § "Changes and ownership" L83, § "Changes and ownership" L87, § "Changes and ownership" L89, § "Shared discovery" L97, § "Shared discovery" L99, § "Command and interaction" L103, § "Command and interaction" L105, § "Command and interaction" L107, § "Command and interaction" L108, § "Command and interaction" L109, § "Command and interaction" L110, § "Command and interaction" L111, § "Command and interaction" L113, § "Command and interaction" L117, § "Command and interaction" L118, § "Command and interaction" L119, § "Command and interaction" L120, § "Command and interaction" L121, § "Command and interaction" L122, § "Command and interaction" L124, § "First-time fields and defaults" L128, § "First-time fields and defaults" L130, § "First-time fields and defaults" L131, § "First-time fields and defaults" L132, § "First-time fields and defaults" L133, § "First-time fields and defaults" L134, § "First-time fields and defaults" L135, § "First-time fields and defaults" L137, § "First-time fields and defaults" L139, § "First-time fields and defaults" L141, § "Existing configuration: option A" L145-L146, § "Existing configuration: option A" L147, § "Existing configuration: option A" L148, § "Existing configuration: option A" L149, § "Existing configuration: option A" L150, § "Existing configuration: option A" L151, § "Existing configuration: option A" L153, § "Config publication and reports" L157, § "Config publication and reports" L159, § "Config publication and reports" L161, § "Config publication and reports" L163, § "Config publication and reports" L165, § "Config publication and reports" L167, § "Skill registration" L171, § "Skill registration" L173, § "Version and delivery" L179, § "Errors and edge cases" L183, § "Errors and edge cases" L185, § "Errors and edge cases" L187, § "Errors and edge cases" L189, § "Errors and edge cases" L191, § "Tests" L195, § "Tests" L199-L202, § "Tests" L203-L204, § "Tests" L205, § "Tests" L206, § "Tests" L207, § "Tests" L208, § "Out of scope" L226

**Files:**
- Create: `crates/work/src/setup.rs`
- Create: `crates/work/tests/setup.rs`
- Modify: `crates/work/src/cli.rs:18-212`
- Modify: `crates/work/src/lib.rs:53-59`
- Test: `crates/work/tests/setup.rs`
- Test: `crates/work/src/setup.rs`

**Tests:**
- `tools/qualification/container.sh -- python3 -c "__import__('subprocess').run(('cargo','test','-p','work-cli','--locked','--test',__import__('pathlib').Path(__import__('sys').argv.pop()).stem),check=True)" crates/work/tests/setup.rs`
- baseline: 7620c7c skipped - crates/work/tests/setup.rs created by this task
- via: public setup CLI integration
- `tools/qualification/container.sh -- python3 -c "__import__('subprocess').run(('cargo','test','-p','work-cli','--locked','--lib','setup::'),check=True)" crates/work/src/setup.rs`
- baseline: 7620c7c skipped - crates/work/src/setup.rs created by this task
- via: `work setup`, `SetupArgs`, `SetupPlan`, `SetupReport`, `interactive::open`, `Store::open_existing_registered_readonly`

- [ ] **Step 1: Create a public fixture and first red tests.** Use tempfile-owned HOME/config/state/data, missing storage parents, local repository and managed root. Spawn built work with env_clear, local Git-config suppression and piped stdin under a timeout. Snapshot entries/bytes/symlink targets/modes/identities without following symlinks. Test setup help, complete headless dry-run and missing actor/repository/confirmation. Handled failures produce one JSON object on stdout, preview/prompts only stderr, no destination changes.
- [ ] **Step 2: Run Tests red.** Missing setup command/module must explain initial failure. Only then add private setup module and CLI wiring.
- [ ] **Step 3: Add the argument boundary.** Implement crate-private SetupArgs (Clap Args) and none/standard/all value enum. Support --actor, repeatable --repository, --root, --store-dir, --trusted-registry, --repository-limit, --owner-limit, --floor-bytes, --warn-bytes, --skills, --yes, --interactive, --dry-run, --check and repeatable --add-repository. Add Command::Setup before any Config::load. Reject interactive+yes, dry-run+yes, repository+add-repository, and check with creation/addition/root/skills/yes/dry-run. Track explicit option presence, including --skills none and protected values equal to defaults. Parser errors remain Clap-owned.
- [ ] **Step 4: Add stable reports and exits.** SetupReport fields: config_path selected string/null; action inspect/create/add_repositories/skills_only; outcome success/no_op/preview/cancelled/failed/partial; config_written; authority_modified=false; created_directories; backup_path; skills; next_steps; error. Skills has selection none/standard/all, status skipped/succeeded/failed/unknown and typed observed actions. next_steps is Vec<Vec<String>>, not shell interpolation. Error is sanitized field/location-and-reason, never original TOML/private values. Selection failure uses inspect with empty progress. Every handled validation/I/O failure uses the same report. Cancellation/failure is unsuccessful, inspection/preview/no-op/full success successful; no fixed new exit-code mapping or status JSON change.
- [ ] **Step 5: Add default/prospective-validation tests.** Require explicit headless actor/nonempty repositories, exact limits 8/4 and floor/warning 1073741824/5368709120; USER suggestion only interactively if valid; HOME/worktrees; nonempty XDG_STATE_HOME or HOME/.local/state. Test all overrides, explicit zero hold, warn below floor, invalid unsigned input, missing bases, nonabsolute config, explicit missing WORK_CONFIG creation, disabled discovery and missing default file. Dry-run creates no parent.
- [ ] **Step 6: Implement prospective plan construction.** Resolve only through Config::discover_path; classify missing/existing via bounded no-follow metadata, never exists() as absence proof. Use ConfigDocument helpers, allocate::component and shared Git policy. Require absolute canonical writer paths with safe ancestry while allowing prospective missing directories without weakening required runtime validation. Validate entire proposal and path overlaps: state/registry outside repositories/roots, distinct from one another, and no config/skill destinations into authority data. Only verified NotFound endpoints with accessible safe ancestry count absent; existing empty endpoints, permission errors, partial data and unknown authority destinations hold. Do not open initializing Store APIs or infer valid bindings from marker names.
- [ ] **Step 7: Add Git/input refusal cases red.** Test missing/non-Git/bare/unsafe-layout sources, symlink/noncanonical paths, source under proposed/configured root, linked managed fixture task, and supported unrelated linked repository. Test inaccessible endpoint ancestry, pre-existing empty endpoint directories, partial/conflicting authority data and allowed prepared empty parents. Invalid actor/malformed/oversized TOML/protected options reveal only selected file/field and reason. Use actual production validators, never a public fault selector.
- [ ] **Step 8: Complete bounded Git validation green.** Use stable version admission and doctor precheck before non-bare local repository probes via bounded_process with deadline/output caps, `/usr/bin/git`, no optional locks and scrubbed environment. Exclude managed sources through configured/proposed root membership and existing managed-checkout evidence; no blanket linked-worktree ban. Future metadata remains subject to normal start admission. Repeat Tests green for Steps 5-8.
- [ ] **Step 9: Add guided interaction tests red.** Controlled --interactive input follows actor, first repository, additional repositories until empty, root, store, registry, limits, thresholds, skills, approval. Cover flag prefills, advanced edits without retyping defaults, empty responses accepting only displayed defaults, absent undisplayed defaults, empty/negative confirmation and EOF at every prompt boundary. Nonterminal input without interactive and terminal+yes never wait for missing values. Existing guided mode only offers additions/skills; declining both inspects.
- [ ] **Step 10: Implement prompts and preview.** Prompt only on explicit interactive or terminal stdin without yes. Preserve Step 9 field order, explicit first repository, displayed defaults and exact/readable bytes. Show all values/actions on stderr. Advertise one explicit affirmative and accept only it; empty/negative cancels, EOF cancels entire proposal. Dry-run omits approval and every mutation. Inspection/check/yes-alone-existing never turns into a write. Never print complete existing TOML.
- [ ] **Step 11: Add read-only mode matrix tests red.** Cover every spec mode/action row and contradictory combination. Compare config/parents, root, storage parents/endpoints, writer artifacts, skill data/discovery, runtime pointers and authority/task records after help/inspection/check/dry-run/cancel/EOF. Check reports missing/unusable prerequisites without repair. Existing readable ancestor-symlink config can inspect, but write attempts explain refusal.
- [ ] **Step 12: Implement existing planning green.** Keep original bounded bytes/file identity/document. Refuse creation fields including repository, actor, store/registry/limits and root-list edits. Root selects only an existing registered root for guidance. Require interactive::open (interactive.rs:26-37) positive Store::open_existing_registered_readonly evidence before additions; never register roots. Inspection may show uninitialized when both endpoints are verified absent, but addition before first start must fail for lack of registration. Append only approved canonical repositories through ConfigDocument, preserving unknown/protected values. Duplicate-only action is no-op without lock/backup/skill mutations; separately selected skills remain actionable. Run Tests green for readonly planning.
- [ ] **Step 13: Add writer ownership/ordering tests red.** A private filesystem-operations seam supplies real production syscalls and deterministic internal failures; an artifact-identification seam describes owned lock/stage/backup families without fixed incidental filenames. Test no artifact before approval, new private directories 0700 and files 0600, no chmod existing directories. Trace stage flush/sync, backup-file sync, backup-directory sync, replacement and config-parent sync. Fail each operation and prove backup syncs precede replacement and parent sync follows both publication modes. No public test-only argument/environment selector.
- [ ] **Step 14: Implement confirmed directory preparation and lock.** After approval only, create necessary owned config parents, approved managed root and missing empty store/registry parents, recording each successful creation immediately. Do not create endpoints/SQLite/markers/checkout records. Revalidate materialized directories and endpoint absence. Refuse symlink ancestors including HOME/.config instead of resolving/rebinding. Open adjacent private setup-writer lock NOFOLLOW with nonblocking exclusive flock; verify regular type, ownership, link count and safe mode. Refuse foreign/unsafe/contended locks and preserve unknown bytes.
- [ ] **Step 15: Implement atomic publication and backups.** Stage config create-new on its filesystem, mode 0600, write/flush/sync. New config uses Linux atomic no-replace rename or equivalent no-clobber primitive, never check-then-replacing-rename. Existing update re-reads bounded bytes/identity under lock and refuses stale snapshot; create a collision-safe private backup in owned private adjacent directory, save exact original bytes, sync backup and its directory, then atomically replace. Sync config parent after either mode. Set config_written=true immediately after publication, before parent sync. Later errors report partial/durability uncertainty without rollback. Track backup_path/directories on failure. Clean only positively owned invocation staging, never config/backups/unknown artifacts/history.
- [ ] **Step 16: Add public race/security tests and complete refusals.** Pause interactive previews to make config appear before create, change original before approval, and hold a cooperating lock during a second invocation. Assert no clobber. Cover unsafe config/lock/backup symlinks/hardlinks/special files/ownership/modes and backup collisions; preserve unknown artifacts. Test symlinked HOME/.config reader compatibility versus writer refusal. Run Tests green after implementing every refusal.
- [ ] **Step 17: Prove fresh and existing success.** Fresh HOME starts without config/state parents, ends with config/root/parents but no endpoints/tasks, authority_modified=false, and a separately test-authorized later public start succeeds. Existing disposable fixture starts a charged task; capture bindings/root identities, protected and unknown TOML, append a repository, then compare active UUID/state/charge and all authority identities. Backup equals original raw bytes; resulting document preserves unknown values. Also assert setup-then-add-before-start refusal and duplicate-only byte/identity no-op. Setup itself calls no authority writer API.
- [ ] **Step 18: Wire explicit skills after confirmed actions.** None skips; standard/all delegates to Task 2's observed installer after successful publication or a confirmed existing-config action. Skills-only and duplicate-add-plus-skills never rewrite/backup config. Standard selects .agents; all adds Claude Code/Codex. Copy typed completed/failed/unknown records into skills report. A later skill failure exits nonzero with truthful config_written and preserved progress; do not proceed to skill mutation if config publication/durability reporting failed. Never call installer on dry-run/inspection/help/cancel/unconfirmed plans.
- [ ] **Step 19: Add partial report tests.** Cover none/standard/all, existing skills-only, duplicate-add plus skills, foreign target after publication, failure after skill-current, failure after an earlier registration and uncertain observation. Assert prior config/backups/directories/actions persist and report partial/failed/unknown rather than skipped/rolled-back. For late writer errors assert no force/repair/retry and truthful progress. Every pre-mutation handled error has empty progress/sanitized JSON; parent-sync failure after publish has config_written=true and explicit uncertainty.
- [ ] **Step 20: Complete guidance and run Tests green.** Return selected path and argv-array start guidance with actor/repository/root where needed, explicit repository/root for multiple choices, catalog reload guidance only when selected; never launch or claim reload/universal invocation. Require both public integration and internal setup tests executed, not just compilation.
- [ ] **Step 21: Format and lint.** Run: `tools/qualification/container.sh -- rustfmt --edition 2021 --config skip_children=true crates/work/src/setup.rs crates/work/src/cli.rs crates/work/src/lib.rs crates/work/tests/setup.rs`. Run: `tools/qualification/container.sh clippy -p work-cli --lib --test setup --locked -- -D warnings`. Expect idempotent formatting and zero warnings; full workspace checks remain header-only.
- [ ] **Step 22: Parent commit after acceptance; no worker commit.** After fresh task spec review, the Wave 2 integrated scoped test gate and one fresh code-quality review accept, the parent stages four owned files and commits with `git commit -m "Add consent-gated native setup with atomic private config publication"` under reviewed-wave commit policy. Preserve this checkout/charge.

Decision: setup validation/I/O errors are JSON-owned but syntactically invalid Clap argv is parser-owned, matching cli.rs:139-195 parsing/dispatch and the spec. Decision: interactive::open is the readonly registered admission seam; Store::private_dir/store.rs:213-243 explains preparation of endpoint parents only. Decision: use existing rustix locking/Linux no-replace support, not a new dependency or config schema.

## Wave 3 — Version preparation and packaged lifecycle

Depends on Wave 2: packaged smoke needs usable setup. No publication or host upgrade.

### Task 4: Prepare v0.3.0 and prove setup from the standalone artifact
Leg: techwright-lab/work-cli

**TDD scenario:** Modifying tested code — run existing tests first.

**Spec:** doc/specs/2026-11-01-native-setup-config-discovery.md § "Acceptance criteria" L50, § "Acceptance criteria" L52, § "Changes and ownership" L83, § "Changes and ownership" L85, § "Version and delivery" L177, § "Version and delivery" L179, § "Tests" L195, § "Tests" L209, § "Tests" L210, § "Tests" L212

**Files:**
- Modify: `Cargo.toml:5-10`
- Modify: `Cargo.lock`
- Modify: `tests/qualification/test_release_version.py`
- Modify: `tools/qualification/smoke.py:34-104`
- Test: `tests/qualification/test_release_version.py`

**Tests:**
- `tools/qualification/container.sh -- python3 -m unittest tests/qualification/test_release_version.py`
- baseline: 7620c7c pass
- via: `release_version`, packaged `work setup`, `tools/qualification/smoke.py`

- [ ] **Step 1: Run Tests.** Expect existing release-version test green, including tag and local-lock mismatch refusal.
- [ ] **Step 2: Add actual workspace regression red.** Read checkout Cargo.toml/local Cargo.lock and assert workspace/work-cli/work-contract all 0.3.0. Retain synthetic stable-version/tag-mismatch tests, generic validator behavior and third-party versions.
- [ ] **Step 3: Update local metadata green.** Set workspace and only two local lockfile entries to 0.3.0; preserve all third-party checksums/versions. Repeat Tests. Existing tooling continues deriving binaries/archive names.
- [ ] **Step 4: Replace smoke's manual TOML fixture.** At smoke.py:43-56 invoke standalone setup with actor smoke, the actual owned repository/root argv, repository/owner limits 1, floor/warning 0 and --yes. Use isolated HOME/state and unset WORK_CONFIG/XDG_CONFIG_HOME. Run standalone outside source checkout with PATH=/no-tools: `/usr/bin/git` probes are available, Python/shell runtime helpers are not on PATH. Assert report, config_written=true, authority_modified=false, HOME default selection and endpoints absent after setup. Python smoke driver is qualification tooling only.
- [ ] **Step 5: Retain and extend artifact proof.** Keep pre-extraction standalone checksum/version and native skill registration without Python/Git on PATH, extracted binary byte identity and optional helper interoperability/retained snapshots. Both quota-one tasks use setup-produced default config without explicit selectors. Assert initialized charged status, idempotent start, charge until fixture finish/remove, preserved commit refs and checkout absence after explicit fixture removal. While a task is active compare explicit WORK_CONFIG status once with default discovery.
- [ ] **Step 6: Run scoped checks.** Repeat Tests. Run: `tools/qualification/container.sh -- python3 tools/release_version.py --tag v0.3.0` (validation, not tag creation). Run: `tools/qualification/container.sh -- python3 -c "[compile(__import__('pathlib').Path(p).read_bytes(),p,'exec') for p in __import__('sys').argv[1:]]" tools/qualification/smoke.py tests/qualification/test_release_version.py`. Expect valid syntax with no pycache write. No Rust formatting change for metadata. Packaging/actual smoke runs through header verification after final embedded-doc changes.
- [ ] **Step 7: Parent commit after acceptance; no worker commit.** After fresh task spec review, the Wave 3 integrated scoped test gate and one fresh code-quality review accept, the parent stages four files and commits with `git commit -m "Prepare v0.3.0 and qualify setup-driven standalone lifecycle"` under reviewed-wave commit policy; no release/tag/install.

Decision: no smoke-only action selector. Existing complete artifact smoke (smoke.py:15-123) owns extraction/helper/two-task proof and stays header-only. Scoped version tests supply baseline, not proof of artifact behavior; the final header execution supplies that evidence. Task 4 owns the delivery-readiness obligation: after Wave 4, require the verify phase to execute every header command on the final commit for both Git fixtures, preserve failed-run evidence, report unavailable checks honestly, and withhold release-readiness claims until all pass. Exact-commit remote main CI/CodeQL and tag qualification remain separate publication gates; this plan authorizes neither publication nor a host upgrade.

## Wave 4 — Canonical onboarding

Depends on Waves 1-3: document actual behavior/metadata. One trailing task owns hub/embedded docs, then verify qualifies final embedded bytes.

### Task 5: Replace manual-copy-first onboarding with authorized native setup
Leg: techwright-lab/work-cli

**TDD scenario:** Trivial change — use judgment.

**Spec:** doc/specs/2026-11-01-native-setup-config-discovery.md § "Acceptance criteria" L52, § "Changes and ownership" L84, § "Changes and ownership" L85, § "Changes and ownership" L87, § "First-time fields and defaults" L134, § "Version and delivery" L177, § "Version and delivery" L179, § "Documentation impact" L216, § "Documentation impact" L219

**Files:**
- Modify: `README.md`
- Modify: `docs/distribution.md`
- Modify: `skills/work-cli/SKILL.md`
- Modify: `skills/work-cli/reference/setup.md`
- Modify: `examples/work.toml`

**Tests:**
- none: documentation/example comments; header verification checks final embedded-document packaging

- [ ] **Step 1: Amend canonical onboarding.** README Configure once and distribution Configure everyday work use v0.3.0+ `work setup` as normal guided path. Give complete headless actor/repository/yes example, dry-run without yes, check, explicit skills and registered-root-only add-repository. Keep manual explicit configuration as advanced alternative and v0.2.0 explicit-WORK_CONFIG workaround accurately release-scoped.
- [ ] **Step 2: Document selection/defaults.** Explain present nonempty WORK_CONFIG, empty explicit discovery-disable, nonempty XDG then HOME fallback and empty XDG behavior. Explain HOME/worktrees, state suggestions, exact tunable 8/4 limits and 1073741824/5368709120 bytes, zero hold and no identity inference. Describe preview, negative-default confirmation, EOF/cancel, headless nonprompting and passive modes.
- [ ] **Step 3: Document safety/partial outcomes.** Setup creates config/root/storage parents, not endpoints/tasks; normal later start initializes. Additions require positive registered-root evidence and cannot change actor/roots/store/registry/limits; no addition before first start. Explain no adoption/repair, ancestor-symlink writer refusal versus reader compatibility, private artifacts/backups/stale checks and truthful config_written/partial skill/durability failures. Unknown outcomes need state inspection, not force/retry. Publication and stopped-writer removal remain separate gates.
- [ ] **Step 4: Route embedded instructions and align example.** SKILL.md/reference/setup.md require explicit operator choices/authorization before setup and retain read-only analysis until approval, supplied checkout, identity/operation, finish/preview/confirmed-removal safeguards. Skill selection stays explicit; catalog reload is not universal invocation. Add only comments to examples/work.toml aligning native defaults/advanced manual use, no new fields/default changes.
- [ ] **Step 5: Align version-specific examples.** Prepare 0.3.0 binary/bundle/helper examples in README/runbook, retaining historical 0.2.0 capability statements/workaround. Assets require publication; no prepublication availability, host install, tag execution or AGENTS edit. Check relative Markdown links/embedded layout. No project Markdown formatter/linter exists, so no artificial test command.
- [ ] **Step 6: Parent commit after acceptance; no worker commit.** After fresh task spec review and parent acceptance, the parent stages five owned files and commits with `git commit -m "Document native setup and v0.3.0 onboarding boundaries"` under reviewed-wave commit policy. Verify runs header commands against these final embedded bytes.

## Spec coverage

| anchor | requirement (short) | owner |
|---|---|---|
| § "Acceptance criteria" L26 | HOME default sees initialized nonzero fixture inventory | Task 1 |
| § "Acceptance criteria" L28 | Precedence, empty explicit disable and explicit-missing error | Task 1 |
| § "Acceptance criteria" L30 | Guided fields/defaults, preview and confirmation | Task 3 |
| § "Acceptance criteria" L32 | Headless equivalence and missing-input/confirmation refusal | Task 3 |
| § "Acceptance criteria" L34 | Passive modes/cancel preserve every destination | Task 3 |
| § "Acceptance criteria" L36 | Fresh config/parents without endpoints or checkout | Task 3 |
| § "Acceptance criteria" L38 | Additive edit preserves protected/unknown values and active authority | Task 1, Task 3 |
| § "Acceptance criteria" L40 | Duplicate no-op and protected-flag refusal | Task 3 |
| § "Acceptance criteria" L42 | Invalid/unsafe/stale/conflicting evidence holds | Task 1, Task 3 |
| § "Acceptance criteria" L44 | Private atomic writes/backups and serialized writers | Task 3 |
| § "Acceptance criteria" L46 | Explicit skills and truthful later failure | Task 2, Task 3 |
| § "Acceptance criteria" L48 | Late failures retain/report completed actions and unknown data | Task 2, Task 3 |
| § "Acceptance criteria" L50 | Standalone setup/default config drives disposable lifecycle | Task 4 |
| § "Acceptance criteria" L52 | Consistent 0.3.0 metadata/examples without publication/upgrade | Task 4, Task 5 |
| § "Changes and ownership" L78 | Private setup arguments, in-memory plan/report, one config format | Task 3 |
| § "Changes and ownership" L79 | Setup CLI dispatch and module | Task 3 |
| § "Changes and ownership" L80 | Document-owned inspect/validate/retain/render/add helpers | Task 1 |
| § "Changes and ownership" L81 | Existing actor/version/layout policy reused unchanged | Task 1, Task 3 |
| § "Changes and ownership" L82 | Installer partial-progress observation | Task 2 |
| § "Changes and ownership" L83 | Setup/discovery/package regressions | Task 1, Task 3, Task 4 |
| § "Changes and ownership" L84 | Onboarding/embedded docs/template alignment | Task 5 |
| § "Changes and ownership" L85 | Local metadata and install-example versions | Task 4, Task 5 |
| § "Changes and ownership" L87 | Remove no behavior; native onboarding and explicit alternative | Task 1, Task 2, Task 3, Task 5 |
| § "Changes and ownership" L89 | Existing libraries, no parallel schema/UI/bootstrap/status/database changes | Task 1, Task 2, Task 3 |
| § "Shared discovery" L93-L94 | One shared owner, explicit path and empty disable | Task 1 |
| § "Shared discovery" L95 | Nonempty XDG | Task 1 |
| § "Shared discovery" L96 | Nonempty HOME fallback | Task 1 |
| § "Shared discovery" L97 | No-selector passive behavior and actionable setup error | Task 1, Task 3 |
| § "Shared discovery" L99 | Empty XDG, legacy reader, bounded diagnostics and absolute writer | Task 1, Task 3 |
| § "Command and interaction" L103 | setup not init; terminal/piped line prompts; no unexpected wait | Task 3 |
| § "Command and interaction" L105 | All flags/repeats and shared selector | Task 3 |
| § "Command and interaction" L107 | Explicit headless inputs/confirmation, usable defaults only | Task 3 |
| § "Command and interaction" L108 | Reject contradictory/check/dry-run mutation flags | Task 3 |
| § "Command and interaction" L109 | stderr preview, stdout JSON, no TOML leak | Task 3 |
| § "Command and interaction" L110 | Readonly prerequisite inspection without initialization/repair | Task 3 |
| § "Command and interaction" L111 | Complete negative-default approval, EOF not confirmation | Task 3 |
| § "Command and interaction" L113 | Ordered fields/prefill/default/repository rules, existing guided restrictions | Task 3 |
| § "Command and interaction" L117 | Missing-create mode, no add/adoption | Task 3 |
| § "Command and interaction" L118 | Existing inspect/root guidance, no creation fields | Task 3 |
| § "Command and interaction" L119 | Confirmed add with registered root, no protected edits | Task 3 |
| § "Command and interaction" L120 | Skills-only confirmation, no config rewrite; none inspects | Task 3 |
| § "Command and interaction" L121 | Check presentation only, reject action inputs | Task 3 |
| § "Command and interaction" L122 | Dry-run validates without approval/mutation | Task 3 |
| § "Command and interaction" L124 | Terminal+yes headless, mixed repo modes refused, independent skills | Task 3 |
| § "First-time fields and defaults" L128 | Existing top-level/u64 schema, no historical policies | Task 1, Task 3 |
| § "First-time fields and defaults" L130 | Interactive actor suggestion only; explicit headless | Task 3 |
| § "First-time fields and defaults" L131 | Supported layout/non-bare sources, managed/root exclusions, linked compatibility | Task 1, Task 3 |
| § "First-time fields and defaults" L132 | HOME root/default, canonical alternative, multiple repos | Task 3 |
| § "First-time fields and defaults" L133 | State suggestions become literal absolute paths | Task 3 |
| § "First-time fields and defaults" L134 | Exact defaults/readable bytes/ordering/zero hold | Task 3, Task 5 |
| § "First-time fields and defaults" L135 | Advanced edits and complete preview | Task 3 |
| § "First-time fields and defaults" L137 | Confirmed root/config/storage parents only; no authority API | Task 3 |
| § "First-time fields and defaults" L139 | Bounded no-follow absence/ancestry, no adoption, recheck | Task 3 |
| § "First-time fields and defaults" L141 | Selected path/explicit argv guidance, no launch | Task 3 |
| § "Existing configuration: option A" L145-L146 | Inspect default, bounded original byte/identity snapshot | Task 1, Task 3 |
| § "Existing configuration: option A" L147 | Canonical additions, registered root guidance only | Task 3 |
| § "Existing configuration: option A" L148 | Protected-setting/root edit refusal | Task 3 |
| § "Existing configuration: option A" L149 | Unknown TOML retention and exact backup | Task 1, Task 3 |
| § "Existing configuration: option A" L150 | Readonly registration evidence, absent/inaccessible addition hold | Task 3 |
| § "Existing configuration: option A" L151 | Duplicate-only no-op changes no config/backup/skill | Task 3 |
| § "Existing configuration: option A" L153 | Document ownership, active UUID/state/charge/bindings retained | Task 1, Task 3 |
| § "Config publication and reports" L157 | Entire proposal prevalidated, created dirs normally revalidated | Task 1, Task 3 |
| § "Config publication and reports" L159 | Reader/writer distinction, ancestor/final/owner/link/type protection | Task 1, Task 3 |
| § "Config publication and reports" L161 | Confirmed adjacent lock/private synced stage/no-replace create | Task 3 |
| § "Config publication and reports" L163 | Locked stale compare, durable backup, atomic replace/parent sync, truthful partial | Task 3 |
| § "Config publication and reports" L165 | Artifact identification/collision-safe backup/private modes/no chmod unknown | Task 3 |
| § "Config publication and reports" L167 | Stable JSON/enums/argv/errors/exits/progress and cleanup limits | Task 2, Task 3 |
| § "Skill registration" L171 | Explicit skill choices/sequencing and native independence | Task 2, Task 3 |
| § "Skill registration" L173 | Installer protections/history, completed/failed/unknown actions, no retry | Task 2, Task 3 |
| § "Version and delivery" L177 | Local 0.3.0/derived artifacts/release-scoped examples | Task 4, Task 5 |
| § "Version and delivery" L179 | Reviewed feature, no publication/host/live-config/real-checkout mutation | Task 1, Task 2, Task 3, Task 4, Task 5 |
| § "Errors and edge cases" L183 | All missing/conflicting/typed/path/Git/TOML/protected/authority refusals | Task 1, Task 3 |
| § "Errors and edge cases" L185 | Unsafe/racing writer and I/O failures preserve unknowns/report actions | Task 3 |
| § "Errors and edge cases" L187 | Every write family unchanged in passive modes | Task 3 |
| § "Errors and edge cases" L189 | No adoption/migration/rebinding; inaccessible evidence holds | Task 3 |
| § "Errors and edge cases" L191 | Bounded absolute Git/stable floor/no hooks-fetch/future admission | Task 1, Task 3 |
| § "Tests" L195 | Public CLI/disposable homes/repos/controlled prompts/internal fault seams | Task 1, Task 2, Task 3, Task 4 |
| § "Tests" L197-L198 | Existing-owner discovery/precedence/bounded-parser regression | Task 1 |
| § "Tests" L199-L202 | Fields/headless/passive/fresh-parent matrix | Task 3 |
| § "Tests" L203-L204 | Active-authority additive preservation and duplicate no-op | Task 3 |
| § "Tests" L205 | Every validation/linked/root/endpoint/permission/symlink case | Task 1, Task 3 |
| § "Tests" L206 | Appearing/stale/unsafe/serialized writer and exact backup | Task 3 |
| § "Tests" L207 | Internal failure/trace seam proves sync order and truthful published partial | Task 3 |
| § "Tests" L208 | Skill selections and partial pointer/registration/unknown evidence | Task 2, Task 3 |
| § "Tests" L209 | Local version/tag mismatch tests | Task 4 |
| § "Tests" L210 | Standalone setup/default two-task preservation/removal | Task 4 |
| § "Tests" L212 | Delivery-readiness gate requires all header checks on both Git fixtures, honest unavailable/failed evidence and separate publication qualification | Task 4 |
| § "Documentation impact" L216 | Canonical README/runbook procedures/defaults/security/partial limits | Task 5 |
| § "Documentation impact" L219 | Embedded routing/consent/task safeguards, aligned example, no guide/AGENTS edit | Task 5 |
| § "Out of scope" L223 | Existing root/identity/path/capacity repair/adoption/pruning excluded | waived: excluded by approved spec |
| § "Out of scope" L224 | Automatic allocation/completion/removal/launch/inferred permission excluded | waived: excluded by approved spec |
| § "Out of scope" L225 | Fullscreen UI/Git install/cloning/network/profile mutation/implicit skills excluded | waived: excluded by approved spec |
| § "Out of scope" L226 | Historical wizard excluded; unrelated declarations retain semantics | Task 1, Task 3 |
| § "Out of scope" L227 | Parallel schema/mappings/database/status changes excluded | waived: excluded by approved spec |
| § "Out of scope" L228 | Publication and active-host upgrade excluded | waived: excluded by approved spec |
