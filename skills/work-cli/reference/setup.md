# Setup and version changes

1. Read the packaged [distribution runbook](../../../docs/distribution.md).
2. Require operator authorization for installation, version changes and new
   authority/configuration. Keep Work operations stopped while switching binaries.
3. Download the native executable and its checksum from the project's published
   GitHub Release. Verify the checksum, install on the user's PATH and check
   `work --version`. Use `bin/work` from the release bundle when that release
   predates the standalone asset. Keep repository cloning, Rust builds and Python
   out of the ordinary binary-install path.
4. Register the portable skill from a permanently retained release bundle in the
   target agent's documented discovery directory. Use `.agents/skills` for standard
   Agent Skills discovery and `.claude/skills` for Claude Code. Preserve existing
   targets and ask the operator to resolve conflicts. Reload the skill catalog.
5. Offer the bundled Python `work-install` helper only for operator-selected
   managed updates, rollback or instruction snapshots. For an existing managed
   installation, use that helper; do not overwrite its binary link manually.
6. For updates, verify a newly downloaded executable before replacing a direct
   install, or use `work-install update --version VERSION --confirm-stopped` for a
   managed install. Recheck the active version before resuming Work operations.
7. For rollback, restore a retained compatible executable or select a verified
   cached version through the helper. Preserve every Work store, registry,
   checkout and outbox. Keep binary rollback separate from data repair.
8. Configure literal absolute store/registry paths outside repositories and managed
   roots, an explicit accountable actor and approved capacity. Verify read-only
   `work status --json` before the first allocation.
9. Record that portable skill files are instructions, not universal hooks. Add a
   project pointer for agents that require explicit routing; never claim automatic
   invocation in every harness.
