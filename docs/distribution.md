# Download, install, update and release work-cli

## Ordinary users: download the native binary

`work` is a native executable. **No repository checkout, Rust toolchain or Python
is required to run it.** Require Linux x86_64, glibc >=2.36 and stable Git >=2.55.0
at `/usr/bin/git`. Git 2.55.0 and 2.56.0 are tested.

Download these files from
[GitHub Releases](https://github.com/techwright-lab/work-cli/releases):

- `work-0.2.0-linux-x86_64` - standalone executable.
- `work-0.2.0-linux-x86_64.sha256` - checksum for that executable.

For a fresh installation:

```sh
mkdir -p "$HOME/.local/bin"
sha256sum --check work-0.2.0-linux-x86_64.sha256 &&
  install -m 755 work-0.2.0-linux-x86_64 "$HOME/.local/bin/work" &&
  work --version
```

Add ~/.local/bin to PATH when the shell does not already include it. Keep an
existing installation intact until its ownership and update method are known;
use the helper for an installer-managed `work` link instead of overwriting it.

These standalone assets become available after v0.2.0 is published, not when its
PR opens. Earlier releases already contain the same native executable at
`bin/work` inside `work-cli-VERSION-linux-x86_64.tar.gz`: verify that archive's
sidecar, extract it and install `bin/work`. No clone or Python is needed for that
path either.

The optional full bundle adds configuration examples, the agent skill, installer
and this runbook. Checksums detect corruption; GitHub/publisher access remains the
authenticity trust. The sidecar is not a cryptographic signing identity. Native
ARM64/runner builds remain CI coverage, not supported release assets.

## Direct binary updates and rollback

Stop Work operations before replacing the executable. Download and verify the new
binary, retain a copy of the existing executable, replace the direct installation,
and check `work --version` before resuming. Restore the retained compatible binary
for rollback. Keep stores, registries, checkouts and outboxes untouched.

Use a compatible binary consistently across an authority. Binary rollback is not
a schema downgrade, authority repair, identity rebinding or quota release. Do not
mix a direct installation with the optional helper's managed links without an
explicit ownership migration.

## Optional agent skill, without a repository checkout

Download and checksum-verify the full release bundle. Extract it to a permanent
user-owned location, then link its `skills/work-cli` directory into the agent's
documented discovery directory. Preserve existing targets; plain `ln -s` refuses
collisions instead of overwriting them. For example, after extracting the bundle:

```sh
mkdir -p "$HOME/.agents/skills"
ln -s /absolute/permanent/work-cli-0.2.0-linux-x86_64/skills/work-cli \
  "$HOME/.agents/skills/work-cli"
```

Keep the complete bundle so the skill's relative references remain valid.
`.agents/skills` is standard Agent Skills discovery; Claude Code uses
`.claude/skills`. Reload/restart agent catalogs. Other agents can read SKILL.md
explicitly or use project guidance that points to it. Portable instructions are
not a universal hook or automatic invocation guarantee.

## Optional managed installation and updater

Choose the bundled Python 3.11+ helper for cached versions, atomic activation,
managed skill snapshots and rollback. **It is optional, not the binary bootstrap
requirement.** Use the script in an extracted, verified release bundle:

```sh
python3 /absolute/work-cli-0.2.0-linux-x86_64/tools/work_install.py install \
  --version v0.2.0 --archive /downloads/work-cli-0.2.0-linux-x86_64.tar.gz \
  --checksum /downloads/work-cli-0.2.0-linux-x86_64.tar.gz.sha256 \
  --skills-dir "$HOME/.agents/skills" --skills-dir "$HOME/.claude/skills"
```

Omit archive/checksum for an anonymous HTTPS download of an explicitly selected
version. `download --version VERSION --output-dir DIR` verifies files without
installing. `latest` resolves GitHub's public latest-release redirect without
using the anonymous REST API quota. Existing download paths are refused.

Managed commands:

```sh
work-install update --version latest --confirm-stopped
work-install rollback --version VERSION --confirm-stopped
```

The confirmation is an operator assertion that relevant Work operations stopped,
not kernel process proof. A first install needs no version-switch confirmation.

| Item | Default location |
|---|---|
| CLI/helper | ~/.local/bin/work and ~/.local/bin/work-install |
| Cached versions | `${XDG_DATA_HOME:-~/.local/share}/work-cli/releases/vVERSION` |
| Runtime pointer | installer data directory's `current` symlink |
| Skill snapshots | installer data directory's `skill-snapshots` and `skill-current` |

Use --bin-dir/--data-dir for isolated installations and repeat --skills-dir for
actual supported discovery directories. The helper rejects unsafe archive entries,
bad checksums/versions, foreign targets, changed caches, symlinked installation
paths and known authority-looking destinations. It serializes installers, stages
and verifies files, then changes the runtime pointer atomically. Previous versions
remain; no automatic pruning or Work-state cleanup occurs.

Runtime and skill pointers are independent. Skill-bearing installations update
registered snapshots; rollback to a pre-skill archive retains the last reviewed
instructions. Review their binary-version requirement. The updater stays available
when rolling back to a pre-updater archive. Check pointers/version after any error;
an interruption after activation is not proof the previous version is active.
This is cooperative user-scoped installation, not hostile-same-UID containment or
hardware power-loss certification.

For explicitly reviewed local instructions before release, the optional helper's
`skill --source-root /reviewed/source --skills-dir DIR` snapshots the skill and its
linked runbook without installing a binary. Later skill-bearing releases can
migrate the same managed links. Treat unpublished instructions as a candidate.

## Configure everyday work

Choose actor, source repositories, capacity and a persistent managed root. Use the
packaged examples/work.toml at `${XDG_CONFIG_HOME:-~/.config}/work/config.toml`,
with literal absolute paths. Create the root; keep store/registry outside it and
repositories. Exclude the root from unrelated cleaners. WORK_CONFIG selects a
different authority explicitly.

Verify `work status --json` before allocation: missing authority stays uninitialized.
Start with an intended base, for example `work start --task TASK --base origin/main`.
Run the agent/editor in the returned destination and retain checkout/operation IDs.
Finish, preview and operator-confirmed removal remain separate steps.

## Maintainers: release process

1. Select semantic version intentionally. From 0.1.2, the next patch is 0.1.3 and
   the next minor is **0.2.0**. A subsequent patch is 0.2.1. Confirm the intended
   patch/minor progression before changing version metadata.
2. Prepare a PR changing the workspace version and the two local-package lockfile
   versions. Archive/binary naming and smoke derive that version automatically.
   Run tools/release_version.py and qualify both tested Git versions: full locked
   Rust tests, formatting, strict Clippy, Python helpers, packaging and smoke.
   Smoke proves the standalone binary is byte-identical to the tested bundle CLI,
   verifies both version/checksum and optional package/helper/skill installation.
3. Merge and require green exact-SHA main CI, including ARM64, both qualifications,
   builds and CodeQL. Fetch origin; verify the selected clean release HEAD equals
   that tested origin/main. Passing results from an older SHA do not qualify it.
4. Run `python3 tools/release_version.py --tag vVERSION`. Confirm no such tag/release
   exists. With explicit publication authorization, create an annotated tag at the
   tested commit and push only that tag. Keep published tags/assets immutable.
5. Tag CI reruns qualification and rejects tag/workspace/lockfile mismatches.
   Publication downloads only the pinned-container qualified artifact, verifies
   the exact version's binary and bundle checksums, and creates the GitHub Release
   with those four assets and generated notes. No native-runner binary is substituted.
6. Download public assets afresh, verify binary and bundle checksums and version,
   and exercise a disposable installation. Record tag/commit, workflow and digests.
   Upgrade operator installations only with stopped-operation authorization.

The workflow creates downloadable releases; it does not authorize the tag, replace
review of exact-SHA CI or automatically update users' installations. Use a new
patch version for a failed published release, not a silently replaced asset.
