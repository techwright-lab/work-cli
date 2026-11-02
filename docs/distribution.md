# Download, install, update and release work-cli

## Ordinary users: download the native binary

`work` is a native executable. **No repository checkout, Rust toolchain or Python
is required to run it.** Require Linux x86_64, glibc >=2.36 and stable Git >=2.55.0
at `/usr/bin/git`. Git 2.55.0 and 2.56.0 are tested.

Published v0.2.0 files are on
[GitHub Releases](https://github.com/techwright-lab/work-cli/releases):

- `work-0.2.0-linux-x86_64` - standalone executable.
- `work-0.2.0-linux-x86_64.sha256` - checksum for that executable.

For a fresh installation of that published release:

```sh
mkdir -p "$HOME/.local/bin"
sha256sum --check work-0.2.0-linux-x86_64.sha256 &&
  install -m 755 work-0.2.0-linux-x86_64 "$HOME/.local/bin/work" &&
  work --version
```

After a qualified v0.3.0 publication, use `work-0.3.0-linux-x86_64` and
`work-0.3.0-linux-x86_64.sha256` with the same steps. Do not use 0.3.0 download
names until that GitHub Release exists. Native `work setup` requires v0.3.0+.

Add ~/.local/bin to PATH when the shell does not already include it. Keep an
existing installation intact until its ownership and update method are known;
use the helper for an installer-managed `work` link instead of overwriting it.

Standalone assets become available after their version is published, not when a
PR opens. v0.2.0 standalone assets are published. Earlier releases already contain
the same native executable at `bin/work` inside
`work-cli-VERSION-linux-x86_64.tar.gz`: verify that archive's sidecar, extract it
and install `bin/work`. No clone or Python is needed for that path either.

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

## Install the agent skill directly from the binary

After installing the v0.2.0+ executable, choose one registration command:

```sh
work skill install          # standard ~/.agents/skills discovery
work skill install --all    # also ~/.claude/skills and ~/.codex/skills
```

The binary embeds SKILL.md, its setup reference and this runbook. Registration
needs no Python, Git, network, source checkout or extracted bundle. It creates a
content-addressed snapshot under `${XDG_DATA_HOME:-$HOME/.local/share}/work-cli`,
then registers links through `skill-current`. Old snapshots remain. Repeating the
command verifies the cached snapshot instead of overwriting changed instructions.
After a direct binary update, rerun registration to select that binary's skill.

Registration preserves unrelated targets, rejects symlinked installation
directories, and shares its lock and managed-link layout with the optional helper.
`--all` preflights all targets before changing active skill links; resolve any
conflict explicitly rather than forcing replacement. Errors after activation
require checking current links before retrying. This is cooperative user-scoped
installation, not hostile-same-UID containment or power-loss certification.

Only this explicit command installs skills. Help, version, status and task
commands do not register them implicitly. Work configuration, authorities,
checkouts and capacity are untouched. The command needs HOME for discovery and
uses XDG_DATA_HOME for snapshots; paths must be absolute, UTF-8 user-owned directories.

Reload/restart agent catalogs after registration. `.agents/skills` is standard
Agent Skills discovery; Claude Code uses `.claude/skills`. Other agents can read
the installed SKILL.md explicitly or use project routing. Portable instructions
are not a universal hook or automatic invocation guarantee. Pre-v0.2.0 binaries
can register the skill from a permanently retained full bundle instead.

## Optional managed installation and updater

Choose the bundled Python 3.11+ helper for cached versions, atomic activation,
managed skill snapshots and rollback. **It is optional, not the binary bootstrap
requirement.** Use the script in an extracted, verified release bundle:

Published v0.2.0 helper example:

```sh
python3 /absolute/work-cli-0.2.0-linux-x86_64/tools/work_install.py install \
  --version v0.2.0 --archive /downloads/work-cli-0.2.0-linux-x86_64.tar.gz \
  --checksum /downloads/work-cli-0.2.0-linux-x86_64.tar.gz.sha256 \
  --skills-dir "$HOME/.agents/skills" --skills-dir "$HOME/.claude/skills"
```

After a qualified v0.3.0 publication, substitute `0.3.0` / `v0.3.0` in those
paths and `--version`. Do not fetch 0.3.0 archives until that GitHub Release
exists.

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

On v0.3.0+, `work setup` is the normal guided new-install path. It is not `init`,
a fullscreen UI, a shell bootstrap or a Python installer. In an interactive
terminal it collects actor, repositories, root, store, registry, quotas,
thresholds and skills in that order, prints the complete preview on stderr, and
applies only after the operator types `yes` (default: no). EOF or any other
answer cancels the whole proposal and exits nonzero. The final SetupReport is
JSON on stdout.

```sh
work setup
work setup --actor alice --repository /home/alice/src/project --yes
work setup --actor alice --repository /home/alice/src/project --dry-run
work setup --check
work setup --actor alice --repository /home/alice/src/project --skills standard --yes
work setup --add-repository /home/alice/src/other --root /home/alice/worktrees --yes
```

Headless creation requires explicit `--actor`, at least one `--repository`, and
`--yes` (or `--dry-run` without `--yes`). Other new-install fields derive only
from usable HOME/state paths; otherwise pass them explicitly. Do not infer actor
from Git or passwd. Interactive mode may suggest a valid `USER` for the operator
to accept. `--interactive` selects the same prompts for controlled input.
Non-terminal stdin without `--interactive`, and a terminal with `--yes`, never
prompt. `--yes` confirms a validated proposal; it is not permission to overwrite
protected settings. `--dry-run` must not combine with `--yes`. `--check` is
inspection-only and rejects action flags.

Configuration selection: a present nonempty `WORK_CONFIG` selects that path. A
present empty `WORK_CONFIG` disables discovery with no fallback. Otherwise select
nonempty `XDG_CONFIG_HOME/work/config.toml`, else nonempty
`HOME/.config/work/config.toml`. Treat empty `XDG_CONFIG_HOME` as unset. Legacy
explicit relative paths remain readable; setup writes require absolute paths with
safe ancestry. A missing implicit config is not an authority initializer. v0.2.0
has no HOME fallback, so set explicit `WORK_CONFIG` on that release.

New-install suggestions, not migrations of existing paths or limits:

| Field | Default |
|---|---|
| root | `HOME/worktrees` |
| store | `XDG_STATE_HOME/work/store`, else `HOME/.local/state/work/store` |
| registry | `XDG_STATE_HOME/work/registry`, else `HOME/.local/state/work/registry` |
| repository_limit | 8 |
| owner_limit | 4 |
| floor_bytes | 1073741824 (1 GiB) |
| warn_bytes | 5368709120 (5 GiB) |

Nonempty `XDG_STATE_HOME` chooses `XDG_STATE_HOME/work/{store,registry}`; empty
or absent `XDG_STATE_HOME` falls back to nonempty
`HOME/.local/state/work/{store,registry}`. Missing both bases requires
operator-supplied explicit absolute values.

`warn_bytes` must be >= `floor_bytes`. Zero is an explicit capacity hold, not a
raised default.

After consent, setup creates the config file, the approved managed root and
necessary empty storage-parent directories. It does not create store or registry
endpoint directories, SQLite files, markers or checkouts. Later `work start`
initializes and allocates under operator authority. Setup does not start a task.

Existing configuration is read-only inspection by default. Guided mode inspects
prerequisites before offering additions or skills. `--add-repository` appends
only canonical repositories when a positively identified registered root admits
read-only. Before the first `start`, absent endpoints are not registration proof;
addition refuses without mutation. `--root` selects an existing registered root
for next-step guidance only; it does not change the root list. Actor, roots,
store, registry and allocation are protected. There is no adopt, migrate, repair,
rebind, force or prune path. Unknown TOML is preserved. A duplicate addition
without another action is a no-op (no lock, backup or skill install); a
separately selected skill action remains actionable. `--yes` alone, and
`--skills none` alone, stay inspection.

Readable configs whose ancestors include symlinks can still be inspected. Setup
writes refuse symlink ancestors, including a symlinked `HOME/.config`, rather
than rebinding to another path. Unknown unsafe ownership, file type, links or
permissions are holds. Adjacent private lock, stage and backup files protect
cooperative users: new files use no-replace publication; updates re-check the
original snapshot under the lock, sync an exact original private backup, then
replace; the config parent is fsynced after publication. This is not hostile
same-UID or power-loss certification.

`config_written` in the JSON report is true only when the config was actually
published. Parent-sync or lock-release uncertainty after that is a later
failure: do not roll back and do not claim no change. Directories, backups and
skill actions already completed stay and are reported. Unknown outcomes need
read-only state inspection, not automatic retry or force.

Default skill selection is none. `standard` or `all` run only after a confirmed
action or publication (`standard` is `.agents`; `all` also adds Claude and Codex).
Native skill install needs no Python, network or source checkout. A later skill
failure keeps the written config and reports typed completed, failed or unknown
actions. When skills succeeded, the report may include a catalog-reload next
step; that is guidance, not a claim that reload ran or that every harness
invokes the skill.

Help, `--check`, `--dry-run`, cancellation and EOF leave setup write destinations
unchanged, with one narrow exception during required non-initializing read-only
authority admission: that admission may change only the contents and associated
timestamps of existing authority-owned SQLite `-shm` coordination files. Those
files keep their identities, ownership, permissions and regular-file type. The
exception permits no creation, deletion or replacement; no database, WAL, record,
binding or quota changes; no initialization, registration, migration, repair or
rebinding; no checkpoint, journal-mode change or cache cleanup. Every other
destination remains unchanged. This is not a broad `-shm` exemption.

Publication of a GitHub Release and confirmed stopped-writer removal remain
separate operator gates. Setup does not publish assets, upgrade the host, finish
a task or remove a checkout.

Advanced alternative: copy [examples/work.toml](../examples/work.toml) from a
separately obtained retained release bundle or source checkout, replace
its absolute paths, create the managed root, and keep store/registry outside it
and repositories. That relative link works in source and the full bundle only;
native skill snapshots embed SKILL.md, its setup reference and this runbook, not
`examples/work.toml`. Exclude the root from unrelated cleaners. `WORK_CONFIG` still
selects a different authority explicitly.

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
   verifies native skill registration with no Python/Git on PATH before bundle
   extraction, then checks optional helper interoperability and retained snapshots.
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
