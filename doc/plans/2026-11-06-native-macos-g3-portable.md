# G3 portable invocation routing — implementation notes

Contract: [accepted specification](../specs/2026-11-06-native-macos-support.md),
Git selection section; [wave-three plan](2026-11-06-native-macos-wave-3.md), G3.
This note describes the portable slice, not completed native G3 qualification or
release readiness. Independent SPEC then QUALITY review remains a parent gate.

## Binding and dispatch

`git_binding.rs::GitInvocation` shares one lazy `OnceLock` selection through an
`Arc`. Both successful and failed qualification are retained. Configuration is
bound once; repeated document observations must agree. Qualification does not
read an environment Git selector. CLI selection wins over configured selection,
then the existing platform defaults apply. Invalid explicit choices do not fall
back. Public library entry points without a configuration argument retain a
platform-default invocation; CLI entry points pass the explicit shared context.

`BoundGitCommand::dispatch` generalizes G2's private aggregate-only convenience
method. It revalidates immediately before and after the caller's existing runner.
A pre-run refusal has `possibly_executed=false`; a post-run binding failure has
`possibly_executed=true`. Inner runner errors remain caller-owned and do not
permit retries, fallback or inferred rollback. Existing G2 aggregate controls use
a test adapter over this same dispatch guard, retaining their original limits and
error classifications.

Qualification's fixed bounded version/helper probes remain prerequisite work.
Inspection's original operation clock includes that elapsed time; stopped budgets
are checked before qualification and the original runner still reserves/counts
each operational child, stdin, argv and output. Qualification is not represented
as an extra repository-operation child in those counters.

## Production call map

- `cli.rs`: global `--git`; root-global scanning preserves native early refusal,
  private scope-child routing and sensitive parse-error redaction. Parsing
  help/version and skill installation does not require qualification.
- `config.rs`: `Config`, authority/execution projections, dedicated getter,
  `InstallDocument`, setter and rendering carry `git_path`. Selector syntax is
  absolute executable spelling, not the symlink-free directory validator.
- `setup.rs`: one context spans discovery/repository checks, proposal, preview,
  confirmation and publication. Creation proposes the selected spelling;
  existing-document updates preserve unrelated TOML values and retain writer
  ownership/authority-overlap preflights for selector-only updates. Check, preview and
  cancellation do not persist. Qualified selections are revalidated before
  writes, after staging/before rename, and after publication; a late failure is
  possibly persisted, not rolled back or automatically retried.
- `doctor.rs`: selected source, attempts/reasons, canonical program, version and
  helper layout accompany explicitly unknown/incomplete inventory. A diagnostic
  report needs neither configured repositories nor initialized authority. New
  Git diagnostic paths use display strings with exact byte companions only when
  opaque Unix bytes require them. Withheld paths have no raw companion; display
  strings never feed execution/proof. Existing repository-path JSON conventions
  are unchanged.
- `identity.rs` → `allocate.rs` / `recovery.rs` → `capture_setup.rs`,
  `capture_readiness.rs`, `gap_continuation.rs`: identity queries and retained
  physical proofs carry the same context, including later reinspection.
- `capture_preparation.rs`, `capture_recovery.rs`, `capture_cli.rs`,
  `capture_finish.rs`, `finish.rs`, `attribution_gap.rs`, `supervisor.rs`,
  `adopted.rs`: signature/context propagation only; existing lifecycle policy,
  schema, admission, ownership, closure and accounting remain unchanged.
- `inspection.rs` and its receipts, removal, remote, preservation, approval,
  recovery-ref and retirement coordinators share the context through `Budget`.
  The inspection process-group/stdin runner and remote aggregate deadline,
  owned HOME, reservations and uncertain-reaping behavior remain in place.
- LOCAL fetch uses the selected validated upload-pack helper, shell-quoted as one
  literal word, including opaque Unix bytes. HTTPS makes no remote-host helper
  selection claim.

The original per-caller environment/configuration profiles are retained, including
hooks, credentials, fsmonitor, grafts, replacements, lazy fetch and literal
pathspec controls. No runner was replaced wholesale; no global binding exists.

## Focused checks and remaining gates

Source-named controls live in `git_binding_tests.rs`, config/CLI/setup/doctor
unit tests, `inspection.rs::invocation_git_tests`, remote local-helper tests and
`tests/invocation_git.rs`. They cover cached/concurrent selection, precedence,
no fallback, stdin/accounting, global placement/redaction, setup no-write and
confirmed-persistence paths, helper replacement and literal helper quoting.

`lib.rs::test_fifo` registers the existing FIFO fixture once. Its two fixture
self-tests were previously loaded three times in the library binary. This removes
four duplicate executions, not behavioral coverage; Git FIFO refusal cases remain.

Portable qualification uses both pinned `container.sh` fixtures, locked/offline,
with fixture-local `CARGO_INCREMENTAL=0`, development/test debug zero and strip
`none`. Old incremental caches and failed records are retained. Exact commands,
exits, counts, fingerprints and footprint measurements accompany the task handoff.
Full invalid-runtime Linux lifecycle execution is not claimed.

Native candidate access remains `AccessUnproven`. No A3 ACL absence/mode fallback,
new native getter, readable pre-access acquisition, Darwin dependency edge, H3
prefix consumption or native activation was added. Native all-target/lint
requalification, native Git/access evidence and the remaining lifecycle/release
matrix are outstanding; Linux container results do not qualify Darwin behavior.
