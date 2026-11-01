# Setup and version changes

1. Read the packaged [distribution runbook](../../../docs/distribution.md).
2. Require operator authorization for installation, version changes and new
   authority/configuration. Keep Work operations stopped while switching binaries.
3. Install from a reviewed source checkout with
   `python3 tools/work_install.py install --version v0.2.4`. Verify the resulting
   binary version and put the reported bin directory on PATH explicitly.
4. Register the skill in directories the target agent actually discovers. Pass
   `--skills-dir "$HOME/.agents/skills"` for standard Agent Skills discovery and
   `--skills-dir "$HOME/.claude/skills"` for Claude Code. Repeat for other documented
   discovery directories. Preserve foreign existing skill/binary targets and ask
   the operator to resolve conflicts.
5. For an approved upgrade, use `work-install update --version VERSION
   --confirm-stopped` and repeat the required skill-directory flags. Inspect the
   reported result and `work --version` before resuming operations.
6. For rollback, select a previously installed version whose state compatibility
   the operator has reviewed, then run `work-install rollback --version VERSION
   --confirm-stopped`. Preserve every Work store, registry, checkout and outbox.
   Keep rollback separate from data repair or schema downgrade.
7. Configure literal absolute paths outside repositories and managed roots for
   the store/registry. Set an explicit accountable actor and capacity policy.
   Verify `work status --json` is read-only before the first allocation.
8. Record that skill files provide portable instructions, not automatic execution
   across every agent. Reload the target agent's skill catalog and add a project
   instruction pointer for agents that require explicit routing.
