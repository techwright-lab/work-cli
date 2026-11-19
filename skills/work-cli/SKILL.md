---
name: work-cli
description: Use before starting code changes in a repository configured for work-cli, when creating or reusing task worktrees, when finishing a task or removing a checkout, when configuration is absent or onboarding is requested, and when installing or updating work-cli. Load for Git worktree ownership, capacity holds, or interrupted removal.
---

# Work CLI task lifecycle

Use the configured Work authority for agent-owned task checkouts. Keep allocation,
task completion, stopped-writer confirmation and removal as separate decisions.

## Start a task

1. Read `work --version`, `work start --help` and `work status --json`. Use v0.4.0
   or newer. It runs on Linux x86_64 with Git at `/usr/bin/git`, and on macOS
   (Apple Silicon) with the Git from Xcode, the Command Line Tools or Homebrew.
   On macOS, `setup`, `start`, `status`, `finish` and `remove` work.
   Work has no Git version minimum. It was run with Git 2.48.1 to 2.56.0, and
   `work doctor` warns for older versions.
2. Locate the operator-selected configuration. A present nonempty `WORK_CONFIG`
   selects that path. A present empty `WORK_CONFIG` disables discovery with no
   fallback. Otherwise select nonempty `XDG_CONFIG_HOME/work/config.toml`, else
   nonempty `HOME/.config/work/config.toml`. Treat empty `XDG_CONFIG_HOME` as
   unset. For absent configuration or an unavailable binary, read
   [setup and updates](reference/setup.md). Ask the operator to authorize actor,
   repository, root, registry and capacity, or guided `work setup`, before any
   onboarding write. Keep analysis read-only until those choices are explicit.
   Do not treat missing configuration as setup authority or silently reconfigure
   an existing machine.
3. Check the current checkout and status inventory. Use an existing feature
   worktree explicitly supplied by the operator; do not create a nested worktree
   or replace the operator's checkout. For a new managed task, choose a stable
   ASCII task slug and an explicit repository/base branch. Resolve the base with
   `git rev-parse --verify BASE^{commit}` before allocation; ask for the base when
   none is specified and the repository's remote default is unknown.
4. Allocate with `work start --task TASK --base BASE` from inside the repository.
   Work uses the repository that contains the current directory and adds it to
   the configuration on first use. The checkout is created at
   `ROOT/REPOSITORY/TASK`. Supply `--repository`, `--root` and `--actor` when the
   current directory or configuration does not select the intended value. Keep
   the returned checkout UUID, destination and JSON
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
   On macOS, Git refuses a checkout with modified or untracked files. The preview
   lists ignored files in `ignored_files`; removal deletes them, so report them
   before confirmation. Files in the user's global Git excludes count as ignored.
   The branch stays in the repository, with a preserved ref for the checkout's
   last commit and for each commit that a per-worktree ref names.
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

On macOS, ignored files are not a hold: the preview lists them and removal
deletes them. An interrupted or refused removal is not an unknown outcome to
stop on: fix the cause, then repeat the same `work remove ... --confirm-stopped`
to complete it.

Use the documented supported recovery procedure in the operator's runbook. Treat
historical receipts as observations, never new writer or removal permission.

## Completion report

Return task/checkout identity, working path or removed state, verification,
commit/PR references, remaining charge and unresolved holds. Distinguish finished
from removed and source-built candidates from published releases.
