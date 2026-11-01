# Native setup and default configuration discovery

**Goal:** Make the native CLI discover its documented default configuration and provide safe guided or headless onboarding without initializing or changing Work authority.
**Amend-grant:** none
**Engine:** waves
**Release preparation:** v0.3.0; publication and host upgrade are separate operator actions.

## Problem

Framing: kept. The request reaches the shared configuration owner rather than adding caller-specific workarounds or a second runtime settings model.

Released v0.2.0 selects WORK_CONFIG or XDG_CONFIG_HOME but does not fall back to HOME/.config (crates/work/src/config.rs:298-310). The bundled skill and distribution guidance describe that fallback. With both selectors unset, a real configured authority can therefore be hidden behind an uninitialized, zero-charge status. A read-only comparison reproduced that discrepancy against an initialized authority; it was not evidence that the live checkout or charge had disappeared.

The CLI has no setup command or configuration writer. Initial configuration currently requires manually copying a TOML example, creating prerequisite directories and knowing how environment selectors work. Cross-project use also requires operator-approved repository allowlisting; it is not restricted to the work-cli repository.

The operator requested a native interactive setup entry point, approved the architecture and safety/testing design, and chose option A for existing installations: append repositories using existing registered roots only. Existing root registration checks remain intact. In particular, store.rs:1970-1972 refuses passive opens when configured roots require registration; setup must not bypass that contract.

Existing shared Config/ConfigDocument readers, typed policy validation, native skill installation, public CLI fixtures and Git qualification policy are available. A prompt frontend and safe config writer must be added. Store::private_dir requires existing ancestors (store.rs:213-243), so a fresh configuration also needs empty storage-parent directories prepared before a later start. Creating those parents is not creating the authority endpoints, databases or markers.

No predecessor spec was identified: the spec corpus was empty and code recon found no existing setup design. No ticket or external reference supplies acceptance rows.

## Acceptance criteria

Drafted from the design, no ticket rows:

- [ ] With the environment selectors unset, a configuration at HOME/.config/work/config.toml gives bare status the same initialized authority and charge inventory as explicit WORK_CONFIG.
  in-scope
- [ ] Configuration selection honors explicit WORK_CONFIG, then nonempty XDG_CONFIG_HOME, then HOME, while preserving explicitly empty WORK_CONFIG as discovery-disabled and explicit missing-file errors.
  in-scope
- [ ] Guided first-time setup previews and, after confirmation, writes the selected actor, repositories, managed root, storage paths, quotas and disk thresholds, including configurable published-example defaults.
  in-scope
- [ ] Headless setup produces the same validated configuration without reading prompts; missing required input or confirmation fails without configuration changes.
  in-scope
- [ ] Help, inspection, dry runs, cancellation and EOF leave the enumerated setup write destinations unchanged.
  in-scope
- [ ] Successful first-time setup prepares configuration and required empty parent/root directories, but leaves authority endpoints uninitialized and allocates no checkout.
  in-scope
- [ ] An approved repository addition using an existing registered root preserves actor, roots, store, registry, limits, unrelated TOML values and an active fixture checkout's state and charge.
  in-scope
- [ ] A duplicate repository addition without another requested action is a no-op, and existing configuration cannot be replaced through first-time or protected-setting flags.
  in-scope
- [ ] Invalid inputs, unsafe filesystem destinations, conflicting authority data and stale proposals are refused with actionable diagnostics rather than forced repair or replacement.
  in-scope
- [ ] Confirmed configuration writes are private and atomically published; an existing update retains the original bytes as a private backup and cooperating writers do not clobber one another.
  in-scope
- [ ] Explicit skill selection registers the embedded instructions; a skill failure after configuration publication reports failure and the already-written configuration truthfully.
  in-scope
- [ ] Late filesystem failures report completed setup actions without deleting unknown data or claiming that nothing changed.
  in-scope
- [ ] The standalone package can perform native setup without a source checkout or Python, and the resulting default configuration drives the disposable task lifecycle.
  in-scope
- [ ] Workspace, local-package lockfile versions, executable version and package/install examples consistently prepare v0.3.0 without creating a release or upgrading the host.
  in-scope

## Legs

### Leg: techwright-lab/work-cli
branch: setup-config-discovery
contract:
- create: native work start with the operator-selected WORK_CONFIG, --repository <primary>, --root <managed-root>, --actor <actor>, --task <name>, --branch <branch> and --base origin/main; retain its generated operation and checkout identities
- destroy: native work finish only after task completion, then work remove preview; confirmed removal requires fresh operator stopped-writer permission and the recorded checkout identity; never substitute git worktree removal
- home: <managed-root>/<name>
- spec-dir: doc/specs
- plan-dir: doc/plans
- verification: tools/qualification/container.sh test --workspace --locked --no-fail-fast -- --test-threads=4; tools/qualification/container.sh fmt --all -- --check; tools/qualification/container.sh clippy --workspace --all-targets --locked -- -D warnings; tools/qualification/container.sh -- python3 -m unittest discover -s tests/qualification; tools/qualification/container.sh -- tools/package-linux.sh; tools/qualification/container.sh -- python3 tools/qualification/smoke.py; repeat with WORK_QUALIFICATION_GIT_VERSION=2.56.0
Rules: AGENTS.md
Rules: skills/work-cli/SKILL.md
Rules: docs/distribution.md
Rules: tools/qualification/container.sh
scope: none
design: Own all acceptance criteria: shared discovery, native setup orchestration and configuration persistence, CLI integration, regression tests, package smoke, onboarding guidance and version preparation. No companion repository or authority-schema changes.

## Design

### Changes and ownership

Add:
- crates/work/src/setup.rs, containing crate-private SetupArgs, an in-memory SetupPlan and SetupReport. Keep prompts/flag collection, prospective validation, preview, safe config publication and optional skill orchestration here; do not add another persistent config format.
- A Setup command variant and dispatch in crates/work/src/cli.rs, and its module declaration in crates/work/src/lib.rs.
- Owner-level ConfigDocument helpers in crates/work/src/config.rs for inspecting, validating, retaining and rendering the TOML document and adding repository entries. Preserve its existing policy isolation and bounded-read semantics.
- Crate-private reuse of the existing actor-component validation, supported-Git-version policy and supported Git-layout precheck from allocate.rs, inspection.rs and doctor.rs where setup needs them. Keep lifecycle validation rules unchanged rather than copying or relaxing them.
- A partial-progress observation seam in the existing skill_install.rs module for the setup report, preserving the standalone skill command's configuration independence and protections.
- crates/work/tests/setup.rs and discovery regressions in cli_contract.rs/doctor.rs, plus setup-driven packaged lifecycle proof in tools/qualification/smoke.py.
- Onboarding changes in the existing README/runbook and the embedded skill/setup reference; update examples/work.toml only for guidance needed to keep the template aligned.
- Workspace/local-lockfile v0.3.0 metadata and matching version-specific install examples.

Remove: no files, commands, authority checks or supported behavior. Replace manual-copy-first onboarding guidance with native setup as the normal new-install path; retain explicit configuration as an advanced alternative.

Use existing Clap, standard input/output, TOML/schema support, filesystem primitives and native skill installation. Do not add a fullscreen UI framework, shell bootstrap or parallel configuration schema. Keep status JSON's existing fields unchanged. No database tables, indexes or authority migrations are added.

### Shared discovery

Resolve once through the shared owner used by Config::load, ConfigDocument and retained inspection/recovery/retirement policy consumers:
1. A present, nonempty WORK_CONFIG selects that path. A present empty value deliberately disables discovery; do not fall through.
2. Otherwise select nonempty XDG_CONFIG_HOME/work/config.toml.
3. Otherwise select nonempty HOME/.config/work/config.toml.
4. Without a usable selector, retain read-only no-config behavior; setup returns an actionable selection/defaults error instead of guessing a machine path or passwd identity.

Treat empty XDG_CONFIG_HOME as unset. Preserve existing explicit-path loading behavior and missing explicit-file errors. A missing implicit file is not an authority initializer. Keep bounded 1 MiB regular-file reads and location-only TOML parser diagnostics. Setup writes require absolute, validated destinations even where an explicit legacy reader accepts a relative path.

### Command and interaction

Expose work setup, not an init alias. In an interactive terminal, use line-based prompts. An explicit --interactive selects the same prompt path for controlled piped input; it is not a test-only mode. Without terminal input or --interactive, never wait for an answer.

Support --actor, repeatable --repository, --root, --store-dir, --trusted-registry, --repository-limit, --owner-limit, --floor-bytes, --warn-bytes, --skills none|standard|all, --yes, --interactive, --dry-run, --check and repeatable --add-repository. Reuse WORK_CONFIG for alternate config selection rather than adding a setup-only path resolver.

- New headless creation requires an explicit actor and at least one repository, plus --yes to apply (not for --dry-run). Other fields may use the displayed defaults when the required home/state bases are available; otherwise require explicit paths. Do not infer authority from Git user.name or a passwd entry.
- --interactive and --yes are mutually exclusive. --check is inspection-only and rejects mutating options. --dry-run never applies or registers skills, even with a complete proposal; reject combining it with --yes. Reject other contradictory action flags rather than ignoring them.
- Send prompts and the readable action preview to stderr; emit a final SetupReport as JSON on stdout. Never print the complete existing TOML, which may contain unrelated private declarations.
- --check reports the selected path and whether existing configuration/prerequisites validate; it neither repairs nor initializes. A missing/unusable configuration is reported as such, not as an initialized authority with zero charge.
- Confirm the complete action list, with a default negative response. EOF/cancellation does not count as approval. In headless apply mode, --yes is explicit confirmation of the validated, reported proposal, not permission to overwrite protected state.

Guided creation collects fields in the order actor, repositories, managed root, store, registry, repository/owner limits, floor/warning thresholds, skills, then complete preview and confirmation. Supplied flags prefill their fields; prompt only for missing inputs or explicitly requested advanced edits. An empty line accepts a displayed default, never an undisplayed value. Collect the first required repository, then offer further repository entries until an empty response ends the list; an empty list is invalid. Advertise the accepted affirmative response at confirmation and accept only that explicit affirmative; empty/negative responses cancel. EOF at any prompt cancels the entire proposal. Literal wording and presentation are implementation-owned. Existing guided mode first inspects, then offers repository additions and optional skills; declining both remains inspection-only. It never offers protected-setting edits.

| Mode/action | Accepted inputs and confirmation | Refusals / behavior |
| --- | --- | --- |
| Missing config, create | Creation fields, optional skills; guided confirmation or headless --yes | --add-repository; insufficient headless inputs; no implicit authority adoption |
| Existing config, inspect | No apply action; --root may select an existing registered root for next-step guidance | --yes alone does not turn inspection into a write; creation fields, including --repository, are refused |
| Existing config, add | --add-repository or guided additions; optional registered --root and skills; confirmation required | Root-list/identity/path/limit edits; missing registration evidence |
| Existing config, skills only | Explicit standard/all selection and confirmation; config remains unchanged | No config rewrite or backup solely for skills; none alone is inspection |
| --check | Inspection/prerequisite validation only; --interactive may select presentation but cannot propose edits | Reject creation/addition/root/skill/--yes options and --dry-run |
| --dry-run | Otherwise valid creation/addition/skill proposal, using flags or guided collection | Reject --yes; omit final approval and all mutations |

A terminal plus --yes uses the headless collection path: it must not prompt for missing values. Explicit --interactive remains incompatible with --yes. Reject mixing --repository and --add-repository. A no-op duplicate addition does not suppress a separately selected skill action.

### First-time fields and defaults

Use top-level actor (string), repositories (array of absolute local paths), roots (array containing the chosen managed root), store_dir and trusted_registry (absolute paths), and allocation.repository_limit, owner_limit, floor_bytes and warn_bytes (u64). Do not create legacy supervised/capture/remote/approval policies.

- Prompt for actor; a valid USER value may be offered interactively, but headless creation supplies actor explicitly.
- Choose existing local non-bare Git repositories; offer a verified suitable current repository interactively or ask for a path. Reuse the supported Git-layout precheck owned by crates/work/src/doctor.rs, including its private/common-directory checks, rather than treating --show-toplevel as suitability proof. Reject linked managed task checkouts and repository paths inside any proposed/configured managed root. Do not extend this into a blanket rejection of unrelated linked worktrees beyond the existing supported-layout policy.
- Offer HOME/worktrees as the common managed root. Allow an explicit canonical alternative. Multiple repositories can reuse that root; task naming/path collision safeguards remain unchanged.
- Offer XDG_STATE_HOME/work/store and XDG_STATE_HOME/work/registry, falling back to HOME/.local/state/work/store and HOME/.local/state/work/registry. Materialize literal absolute paths in TOML. These are new-install suggestions, not changes to existing installation paths.
- Offer repository_limit=8, owner_limit=4, floor_bytes=1073741824 and warn_bytes=5368709120, matching examples/work.toml. Show exact byte values and readable units; require warn_bytes >= floor_bytes. Preserve the underlying unsigned policy semantics, including explicitly selected zero capacity as a hold rather than silently raising it.
- Offer advanced path/capacity editing without requiring all defaults to be retyped; show every final value in the confirmation preview.

After confirmation, create only necessary owned configuration parents, the approved managed root and missing empty parent directories for the future store/registry. Do not create the store/registry endpoint directories, initialization markers, SQLite files or checkout records. Keep state/registry outside repositories and managed roots; reject overlapping or unknown-authority destinations rather than adopting them. Store::private_dir's required-parent precondition is satisfied without invoking any authority API.

Before first-time publication, inspect each proposed store/registry endpoint with bounded, no-follow metadata checks and validate existing ancestors. Only a verified NotFound endpoint with accessible safe ancestry counts as absent. Existing endpoints, including empty endpoint directories, are not permission to adopt authority; inaccessible, partial or unsafe evidence is a hold. Prepared empty parent directories are allowed: distinguish them from endpoint directories. The authority owner remains store.rs (including store.sqlite and authorities.sqlite evidence); do not open an initializing API or independently infer valid bindings from marker names. Recheck absence before publication and report any late uncertainty rather than treating it as empty state.

Finish with the selected config path and an explicit next-step work start command. With multiple repositories/roots, include --repository and --root rather than implying an unconfigured default. Do not allocate or launch that command automatically.

### Existing configuration: option A

Without an apply action, inspect only. For --add-repository or its guided equivalent:
- Read the original bounded TOML document and keep a snapshot of its bytes/identity for conflict detection.
- Append only approved canonical repository paths. A --root selection must be one of the existing registered roots and is used for the next-step command, not a new mapping or root-list edit.
- Do not add/remove roots, change actor, store, trusted registry or any allocation value. Reject attempts to supply protected creation settings to existing mode instead of silently using or changing them.
- Preserve unrelated TOML values, including advanced/unknown top-level declarations. Formatting may normalize; retain original bytes in the private backup before replacement.
- Validate the existing configuration/registered-root boundary read-only through Store::open_existing_registered_readonly (the existing interactive::open seam), not an initializing open. Refuse unresolved roots or conflicting authority data; never register roots or repair authority as a side effect. Inspection can report uninitialized configuration when both endpoints are absent. Addition still requires positive registered-root evidence: after setup but before the first start, absent endpoints are not proof of registration. Refuse additions when that evidence is absent or inaccessible, explain the prerequisite, and leave all destinations unchanged.
- If all requested repositories are already present and no other action was selected, return a no-op without changing config, backups or skills.

Use ConfigDocument's schema ownership rather than a lossy Config reconstruction. Keep a fixture's active checkout identity, state, charge and existing store/registry/root bindings unchanged across an additive edit.

### Config publication and reports

Validate the entire prospective plan before mutation. Use existing typed/path/actor/Git policy rather than divergent rules. New-root planning can validate prospective missing paths without weakening required-path validation for runtime loads; revalidate actual created directories before config publication.

Read compatibility and write eligibility are distinct: the existing bounded config reader follows ancestor symlinks, but setup writes refuse symlink ancestors, including a symlinked HOME/.config. Preserve readable legacy configurations for inspection; explain the writer refusal without resolving and rewriting a different path. Keep final-file no-follow, ownership, hardlink and special-file protections. HOME fallback does not relax writer validation.

Create an owned private setup-writer lock adjacent to the selected config only after apply is confirmed. Reject unsafe lock ownership, links or file types. Stage mode-0600 config on the same filesystem, flush/fsync it, then publish atomically. New creation must use no-replace publication so a file that appears after planning is retained, not overwritten.

For existing edits, under the setup-writer lock re-read and compare the original file and refuse a detected stale snapshot. Save original bytes to a mode-0600 backup in an owned private backup directory beside the config; do not overwrite unrelated backups or prune history. Successfully sync the backup file and its directory entry before replacing the original. Then atomically replace. After either no-replace creation or existing replacement, sync the config parent before reporting durable success. A failure after publication, including parent-sync failure, reports config_written=true and durability uncertainty; do not roll back or claim no publication. Cooperating setup writers serialize. This is detected-edit protection for cooperative user-scoped software, not a promise against hostile same-UID writers or every external editor race.

Writer artifacts need a testable ownership/identification seam for the adjacent lock, per-invocation stage and retained backups, so tests can enumerate their write families without fixing incidental filenames or timestamp formats. Allocate backup identities collision-safely without replacement. New setup-owned private directories use mode 0700; writer lock, stage and backup files use mode 0600. Do not chmod existing directories or claim ownership of unknown artifacts.

SetupReport is a stable JSON object: config_path is the selected path string or null when selection fails (successful write plans require an absolute path); action is inspect, create, add_repositories or skills_only; outcome is success, no_op, preview, cancelled, failed or partial; config_written and authority_modified are booleans (the latter always false); created_directories is an array of path strings; backup_path is a path string or null; skills is a structured outcome with selection none/standard/all, status skipped/succeeded/failed/unknown, and observed progress; next_steps is an array of argv string arrays, never a shell command requiring interpolation; error is null or a sanitized field/location-and-reason object. Failed selection has action inspect. Distinguish selected paths from validated paths in diagnostics. Report all handled setup validation and I/O failures, including pre-mutation failures, using the same object with empty progress and config_written=false when appropriate. Clap help/usage failures remain CLI-owned, not setup reports. Full success, inspection, preview and no-op exit successfully; cancellation/EOF, validation, I/O and partial failure exit unsuccessfully. CLI usage errors retain the parser's existing unsuccessful convention; no new fixed numeric exit-code mapping is imposed. Report normal completion and detected partial completion using the same shape. Preserve successful publication on a later skill failure; no silent rollback or no-change claim. Report directories/backups already created on a late I/O error. Clean only the command's owned staging artifacts, never unknown data, committed config, authority history or skill snapshots.

### Skill registration

Default selection is none/skip. Explicit standard or all delegates to the existing native skill installer after successful config publication or a confirmed existing-config action. Standard uses .agents discovery; all also includes Claude Code/Codex. No Python, network or source checkout is needed for this step.

Do not change skill install's independent config behavior, foreign-target protection, lock or retained-snapshot model. Add a structured partial-install result or equivalent observation seam: retain completed directory creation, snapshot publication, skill-pointer publication and per-target registration actions even when a later installer operation fails. Represent an unobservable/uncertain result explicitly as unknown, not as skipped or rolled back. SetupReport.skills carries that progress as typed action records (action kind, target path, completed/failed/unknown status), including earlier successes. Preserve retained history and do not retry unknown outcomes automatically. A skill error makes setup exit nonzero with config_written reflecting reality and a clear skill error/outcome. A dry run never calls the mutating installer. Offer catalog reload guidance without claiming reload or universal invocation.

### Version and delivery

Prepare workspace and the work-cli/work-contract lockfile package versions as 0.3.0. Keep third-party package versions unchanged. Derive binaries/archive names and smoke expectations from the workspace version as existing tooling does. Update operator examples and mark native setup as v0.3.0+; v0.2.0's explicit-WORK_CONFIG workaround remains accurate for that release.

Implementation delivery is a reviewed feature branch/PR. Do not tag, publish assets, upgrade a host binary, modify existing live configuration or finish/remove any real checkout as part of tests or release preparation. Those require their normal separate gates.

## Errors and edge cases

Enumerated input/validation failures: missing headless actor/repository/default bases/confirmation; conflicting action flags; invalid actor or unsigned integer; warning below floor; missing/non-Git/unsuitable repository; noncanonical, symlinked or overlapping data/root paths; invalid/malformed/oversized existing TOML; protected-setting attempts; missing or unresolved registered roots; unknown authority data. Refuse these before mutation and identify the selected file/field without revealing unrelated values.

Enumerated filesystem failures: unsafe config/lock/backup ownership, symlinks, hardlinks or special files; an appearing config during new publication; detected changed original during an update; a concurrent setup writer; staging/sync/publication errors. Retain existing/unknown bytes, report actual partial actions where applicable, and offer no force/repair fallback. Do not follow an unsafe destination merely to make setup succeed.

Cancellation, help, --check and --dry-run preserve these write families: configuration file/parents, managed root, storage parents/endpoints, writer lock/backups/staging, skill discovery/data, runtime pointers and Work authority/task records. Validation/dry-run uses prospective checks without creating missing directories.

A new config cannot silently adopt pre-existing authority data when its binding/configuration is unknown. Existing-mode setup does not move, recreate, initialize, migrate or rebind an authority. Inaccessible evidence is an error/hold, not empty-state proof.

Git probes are bounded, read-only and use /usr/bin/git with the existing stable >=2.55.0 policy. Do not fetch, run project hooks/installers, or claim setup proves every future Git metadata state eligible; normal task admission still validates runtime conditions.

## Tests

Run public CLI tests in disposable owned homes/repositories; use actual commands and production validators, not a fault-injection environment selector. Controlled --interactive input exercises the supported prompt path. All authority fixtures are disposable; never use live charges as test data.

- Default HOME config sees the same initialized fixture and nonzero inventory as explicit WORK_CONFIG - crates/work/tests/cli_contract.rs.
- Explicit/XDG/HOME precedence, empty XDG, empty explicit disable, missing implicit file, explicit missing file and location-only malformed-TOML behavior - cli_contract.rs and doctor.rs.
- All first-time fields, example defaults and overrides, guided preview/confirmation and JSON result - crates/work/tests/setup.rs.
- Headless complete flags and missing-input/confirmation refusal without prompts - setup.rs.
- Cancellation/EOF, help, inspection and dry-run preserve the enumerated write families - setup.rs.
- Brand-new home with missing config/state parents becomes usable for later start while store/registry endpoints remain absent after setup - setup.rs.
- Existing add-repository preserves protected fields, unknown TOML values, registered-root/authority identity and an active charged fixture task; setup-then-add-before-start refuses without mutation because registration evidence is absent - setup.rs.
- Duplicate additions without other actions preserve config/backup/skill bytes and identities - setup.rs.
- Each enumerated input/validation failure refuses without mutation, including linked managed task sources, repository-under-root paths, existing versus absent authority endpoints, permitted prepared parents, permission-denied evidence and symlinked HOME/.config writer refusal with reader compatibility - setup.rs, plus existing policy/doctor tests where their seam already owns the behavior.
- Appearing config, stale preview, unsafe lock/backup/config types, two cooperating writers and original-byte backup behavior - setup.rs.
- Late filesystem failure reports completed actions and preserves unknown data; verify backup-file/directory sync precedes replacement, parent sync follows both publication modes, and published-but-sync-failed reporting remains truthful, using internal test seams rather than a public fault-injection selector - setup.rs.
- Explicit standard/all/skip skills and foreign-target failure after config publication report truthful partial results; failures after pointer publication and after an earlier target registration retain completed/unknown action evidence - setup.rs and existing skill_install.rs integration tests.
- Workspace/local lockfile v0.3.0 consistency and tag mismatch checks - existing Python release-version tests and tools/release_version.py.
- Standalone native setup without source/Python, default discovery and setup-produced config driving two-task preservation/removal workflow - tools/qualification/smoke.py.

Before release-readiness claims, run the complete locked Rust workspace suite, formatting, strict all-target Clippy, all Python helpers, packaging and artifact smoke through tools/qualification/container.sh for both Git 2.55.0 and 2.56.0. Preserve failed-run evidence and report unavailable checks honestly. Exact-commit remote main CI/CodeQL and tag qualification remain publication requirements, not substitutes for a spec approval.

## Documentation impact
- Feature / user-facing docs introduced: none
- Materially amended existing docs: README.md (Configure once) and docs/distribution.md (Configure everyday work) - major onboarding procedures, tunable defaults, selection precedence, existing-authority limits and partial-failure/security boundaries
- Derived / memory docs invalidated: none

Apply reference/documentation-impact.md for the materiality bar. Amend the canonical onboarding owners, not a new standalone setup guide. skills/work-cli/SKILL.md and reference/setup.md are implementation surface and must route absent configuration through approved setup while preserving explicit operator consent and task/removal safeguards. Keep examples/work.toml guidance aligned; no new schema fields are required. No AGENTS policy change is needed.

## Out of scope

- Existing managed-root additions/removal, root registration, authority identity/path migration or repair, actor/limit reconfiguration, automatic state adoption and cleanup/pruning.
- Automatic checkout allocation, task completion/removal, process launching or inferred stopped-writer permission.
- Fullscreen TUI, Git installation, repository cloning, network setup, shell-profile/environment mutation and implicit skill installation.
- Wizard configuration of historical supervised/capture/remote/approval/retirement protocols; preserve existing unrelated declarations rather than changing their semantics.
- New runtime config formats, repository-to-root mappings, database tables/indexes, authority schema changes and changes to status JSON.
- Release publication or upgrade of the active host installation.

## Open questions

- none
