---
name: work-cli
description: Use before starting code changes in a repository configured for work-cli, when creating or reusing task worktrees, when finishing a task or removing a checkout, and when installing or updating work-cli. Load for Git worktree ownership, capacity holds, or interrupted removal.
---

# Work CLI task lifecycle

Use the configured Work authority for agent-owned task checkouts. Keep allocation,
task completion, stopped-writer confirmation and removal as separate decisions.

## Start a task

1. Read `work --version`, `work start --help` and `work status --json`. Use v0.1.2
   or newer on Linux x86_64 with stable Git >=2.55.0 at `/usr/bin/git`.
2. Locate the operator-selected configuration through `WORK_CONFIG` or
   `${XDG_CONFIG_HOME:-$HOME/.config}/work/config.toml`. For absent configuration
   or an unavailable binary, read [setup and updates](reference/setup.md); ask the
   operator to choose repository, actor, managed root, registry and capacity.
   Keep analysis read-only until those choices are explicit.
3. Check the current checkout and status inventory. Use an existing feature
   worktree explicitly supplied by the operator; do not create a nested worktree
   or replace the operator's checkout. For a new managed task, choose a stable
   ASCII task slug and an explicit repository/base branch. Resolve the base with
   `git rev-parse --verify BASE^{commit}` before allocation; ask for the base when
   none is specified and the repository's remote default is unknown.
4. Allocate with `work start --task TASK --base BASE`. Supply `--repository`,
   `--root` and `--actor` when configuration does not select exactly one intended
   value. Keep the returned checkout UUID, destination and JSON
   `request.operation` as the task record. Reuse the returned live checkout for
   the same task/actor; retain its original operation for exact retries.
5. Run edits, Git and verification in the returned destination. Keep evidence and
   large build caches outside the checkout when the project supports external
   locations. Keep the allocated branch checked out. Report conflicts or holds
   rather than substituting another owner, resetting state or bypassing Work.

## Finish and hand back

1. Run the project's verification commands and report their observed results.
   Preserve unfinished changes and report their disposition; do not fabricate
   completion to recover capacity. Commit/push only within the user's authority.
2. Stop task-owned background processes and leave the checkout. Record
   `work finish TASK_OR_UUID` only after the task is complete. Expect files and
   quota to remain: finish is not process-quiescence or deletion proof.
3. Preview with `work remove TASK_OR_UUID` and report the exact selected path,
   outcome, holds, retained charge and preservation limitations to the operator.
4. Require explicit operator confirmation that relevant agents, editors and jobs
   are stopped before issuing `work remove UUID --confirm-stopped`. Target only
   the confirmed checkout. Never infer confirmation from age, clean Git status,
   a successful finish, a process exit or an incomplete process scan.
5. Verify status, checkout/registration absence, expected retained branch/recovery
   refs and capacity after removal. Report local preservation as local storage,
   not off-host backup. Preserve backup/authority evidence; no automatic pruning.

## Handle holds and recovery

| Observed result | Required action |
|---|---|
| Dirty, untracked, ignored, draft or unsupported metadata | Report the hold and preserve bytes; obtain an explicit disposition. |
| Capacity exhausted | Identify charged checkout IDs and next actions from status; keep the configured limits. |
| Unknown native outcome or changed identity/boot | Keep the charge and evidence; stop automatic retries and request recovery guidance. |
| Recorded native success awaiting reconciliation | Follow the CLI's exact UUID reconciliation instruction with stopped-writer confirmation; verify absence again. |
| Restored backup has new filesystem identities | Recover selected work into fresh managed state; retain old authority as history. Do not rewrite SQL, markers or inode/boot bindings. |

Use the documented supported recovery procedure in the operator's runbook. Treat
historical receipts as observations, never new writer or removal permission.

## Completion report

Return task/checkout identity, working path or removed state, verification,
commit/PR references, remaining charge and unresolved holds. Distinguish finished
from removed and source-built candidates from published releases.
