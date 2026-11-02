# Setup and version changes

1. Read the packaged [distribution runbook](../../../docs/distribution.md) for
   discovery, defaults, existing-config limits, writer safety and the passive
   `-shm` preservation exception.
2. Require operator authorization for installation, version changes and new
   authority/configuration. Keep Work operations stopped while switching binaries.
   Keep analysis read-only until the operator explicitly chooses or authorizes
   onboarding (actor, repository, root, registry, capacity, or guided collection).
3. Download the native executable and its checksum from the project's published
   GitHub Release. Verify the checksum, install on the user's PATH and check
   `work --version`. Use `bin/work` from the release bundle when that release
   predates the standalone asset. Keep repository cloning, Rust builds and Python
   out of the ordinary binary-install path.
4. For v0.2.0+ binaries, register embedded instructions with `work skill install`
   for standard `.agents/skills` discovery; use `--all` for the operator-selected
   inclusion of `.claude/skills` and `.codex/skills`. For binaries without this
   command, register from a permanently retained release bundle. Preserve unrelated
   targets and ask the operator to resolve conflicts. When the operator's catalog
   reads installed skills, ask them to reload it; do not claim reload or universal
   invocation.
5. Offer the bundled Python `work-install` helper only for operator-selected
   managed updates, rollback or instruction snapshots. For an existing managed
   installation, use that helper; do not overwrite its binary link manually.
6. For updates, verify a newly downloaded executable before replacing a direct
   install, or use `work-install update --version VERSION --confirm-stopped` for a
   managed install. Recheck the active version before resuming Work operations.
7. For rollback, restore a retained compatible executable or select a verified
   cached version through the helper. Preserve every Work store, registry,
   checkout and outbox. Keep binary rollback separate from data repair.
8. For a v0.3.0+ binary, run `work setup` only after that onboarding
   authorization. Headless creation requires `--actor`, at least one
   `--repository`, and `--yes`. Use `--dry-run` without `--yes` to preview. Use
   `--check` for inspection only. Default skill selection is none; pass
   `--skills standard` or `--skills all` only when the operator selects them.
   After a confirmed skill action, follow step 4 for catalog-reload guidance.
   Setup creates the config, the approved root and empty storage parents; it does
   not create store/registry endpoints, SQLite files, markers or checkouts, and it
   does not allocate or start a task. On an existing config, `--add-repository`
   appends canonical repositories only when a positively identified registered
   root exists; it cannot change actor, roots, store, registry or limits. `--root`
   selects an existing registered root for guidance only. Refuse additions before
   the first `work start`. Duplicate additions without another action are a no-op.
   Reuse an explicitly supplied Work-owned checkout; do not nest or reallocate it.
   Verify read-only `work status --json` before the first allocation. For a v0.2.0
   binary, set explicit `WORK_CONFIG` to an operator-edited configuration file;
   that release has no HOME fallback and no `work setup`. Advanced manual editing
   of the bundled example remains an alternative.
9. Record that portable skill files are instructions, not universal hooks. Add a
   project pointer for agents that require explicit routing; never claim automatic
   invocation in every harness.
