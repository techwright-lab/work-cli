# work-cli

`work` manages Git worktrees for interactive agent tasks. Create or reuse a
checkout, run your agent there, then explicitly finish and remove it.

The interactive workflow is `start → status → finish → remove`. Agents run in your
terminal or editor. No process supervisor, capture service, background cleanup,
or remote-preservation configuration is required.

## Download the binary

The current release is v0.4.1. Its assets are on
[GitHub Releases](https://github.com/techwright-lab/work-cli/releases/tag/v0.4.1).
Each platform has a standalone binary and a `.sha256` checksum file. On Linux,
download both files to the current directory, then run the commands. On macOS,
the commands download both files.

Linux x86_64:

```sh
mkdir -p "$HOME/.local/bin"
sha256sum --check work-0.4.1-linux-x86_64.sha256 &&
  install -m 755 work-0.4.1-linux-x86_64 "$HOME/.local/bin/work" &&
  work --version
```

macOS on Apple Silicon:

```sh
base=https://github.com/techwright-lab/work-cli/releases/download/v0.4.1
curl -fLO "$base/work-0.4.1-macos-arm64" &&
  curl -fLO "$base/work-0.4.1-macos-arm64.sha256"
mkdir -p "$HOME/.local/bin"
shasum -a 256 -c work-0.4.1-macos-arm64.sha256 &&
  install -m 755 work-0.4.1-macos-arm64 "$HOME/.local/bin/work" &&
  work --version
```

The macOS binary is not signed or notarized. A file that curl downloads runs.
A file that a browser downloads has a quarantine attribute, and macOS blocks it.
Remove the attribute before you install the file:
`xattr -d com.apple.quarantine work-0.4.1-macos-arm64`.

Native `work setup` requires v0.3.0+.

**No repository clone, Rust or Python is required.** Keep Git installed as described
below. Standalone assets arrive with their tagged version after publication;
existing releases already include the native executable at `bin/work` inside their
release archive. A version-bump PR is not a published release.

Install the [agent skill](skills/work-cli/SKILL.md) directly from the binary:

```sh
work skill install          # ~/.agents/skills/work-cli
work skill install --all    # also ~/.claude/skills and ~/.codex/skills
```

Choose one command. The skill and its references are embedded: no Python, bundle
or repository checkout is needed. Registration is explicit, preserves unrelated
skills and keeps old snapshots. Reload your agent's skill catalog afterward.

The optional full bundle includes a Python `work-install` helper for managed
updates/rollback. See [download, install, update and release instructions](docs/distribution.md)
for direct binary updates, native skill registration and the optional helper. Preserve an
existing installation until its ownership/update method is known; do not overwrite
an installer-managed link with the direct-install command.

## Requirements and build

Requires Linux x86_64 and **Git at `/usr/bin/git`**, or macOS on Apple Silicon
with Git. On macOS, use the Git from Xcode or the Command Line Tools, or Homebrew
Git. Source builds use Rust 1.98.1.
On macOS, `setup`, `start`, `status`, `finish` and `remove` work. Removal on macOS
uses Git's own check; see [Removal on macOS](#removal-on-macos).
Work uses the selected Git without a version minimum. Work was run with Git 2.48.1
to 2.56.0. `work doctor` warns when the selected Git is older than 2.48.1.

Version admission reads a `git version MAJOR.MINOR.PATCH` line. Vendor text after
the three numbers is accepted, for example ` (Apple Git-157)` or `.windows.1`.
Other output is refused as `UnsupportedGit`. Unsupported repository layouts are
still refused for each Git version.
Native packed stores may include validated `.rev` reverse indexes and
`objects/info/packs`. Standalone commit graphs and split commit-graph chains
are also admitted within the existing file/read limits, at most 64 layers and
4,096 total graph commits. Graphs require valid checksums, bounded known chunks,
exact chain/base bindings and native read-only verification against commit
objects. Ordinary proof commands disable commit-graph acceleration; verified
graph metadata never replaces object evidence. Bloom-filter/unknown graph
extensions, simultaneous standalone/nonempty split storage and stale extra
chain files hold. An ordinary empty graph directory is supported.

Reverse indexes must match their pack/index contents, checksums and offset
ordering; the pack list must exactly name the current packs. Unknown, stale,
malformed or replaced metadata still holds. This does not add support for
remote-HEAD symrefs, bitmaps, multi-pack indexes, Bloom-filter graph chunks,
cruft-pack mtimes or object alternates.

CI tests Git 2.55.0 and 2.56.0. Other versions are accepted, but they are not
claimed as tested. Version admission never substitutes for fresh repository,
object, preservation and removal safety checks.

Inspection keeps a 128 MiB aggregate read-accounting allowance. Exact internal
metadata queries reserve retained administration/object-store bytes, without
charging checkout payload they do not scan. Object/status/ignore queries still
reserve administration plus payload; worktree listing retains repeated
registration charges. Unknown argv keeps the full repeated envelope. Commands
and repeated observations are charged independently; these conservative input
estimates are not measurements or kernel-enforced limits on Git's actual I/O.
Large repositories can still hold at the existing file/read/output/deadline limits.
The packaged binary requires glibc 2.36 or newer. Git is a separate prerequisite.
Tagged releases publish the qualified x86_64 executable, its full bundle and their
checksums. Smoke tests prove both contain identical binary bytes. Native x86_64
and ARM64 CI builds are additional coverage, not supported release artifacts.

Build and test in the disposable qualification container:

```sh
docker build -f tools/qualification/Dockerfile \
  -t work-cli-qualification:rust-1.98.1-git-2.55.0 .
tools/qualification/container.sh fetch --locked
tools/qualification/container.sh test --workspace --locked -- --test-threads=4
tools/qualification/container.sh clippy --workspace --all-targets --locked -- -D warnings
tools/qualification/container.sh -- tools/package-linux.sh
```

To exercise the same suite with Git 2.56.0, build the qualification image with
`--build-arg GIT_VERSION=2.56.0` and tag it
`work-cli-qualification:rust-1.98.1-git-2.56.0`, then prefix the container commands
with `WORK_QUALIFICATION_GIT_VERSION=2.56.0`. This test-only selector does not alter
the installed Git or the product's fixed `/usr/bin/git` executable.

Standalone executables, full bundles and SHA-256 checksums appear in `target/dist/`.
Install the executable directly or extract a bundle's `bin/work` onto your PATH. Nothing in these scripts installs a host binary
or uses a live work registry. Tests create their own disposable repositories.

For a source build on a supported host: `cargo build --release --locked -p work-cli`.

## Configure once

On v0.3.0+, `work setup` is the normal guided new-install path. It is not `init`,
a fullscreen UI, a shell bootstrap or a Python installer. In a terminal it collects
actor, repositories, root, store, registry, quotas, thresholds and skills, prints
the complete preview on stderr, and applies only after an explicit `yes` (default:
no). EOF or any other answer cancels the whole proposal with a nonzero exit. Final
JSON goes to stdout.

```sh
work setup
work setup --yes
work setup --dry-run
work setup --check
work setup --root /home/alice/projects/.worktrees --skills standard --yes
work setup --add-repository /home/alice/src/other --yes
```

Headless apply needs only `--yes`. The actor comes from Git: the part of the
global `user.email` before `@`, else `user.name`, lowercased, with characters
other than letters, digits, `.` and `_` replaced by `-`. Setup asks for the
actor only when Git has neither value; headless setup then needs `--actor`.
Repositories are optional: `work start` adds the repository it runs in.
`--dry-run` must not combine with `--yes`. `--check` is inspection-only and
rejects action flags. `--interactive` enables the same prompts on non-terminal
input. A terminal with `--yes` never prompts. `--yes` confirms a valid proposal;
it does not overwrite protected settings.
Discovery, defaults, existing-config limits, writer safety and the passive `-shm`
exception are in [download, install, update and release instructions](docs/distribution.md).

Setup creates the config, the approved root and empty storage parents. It does not
create store or registry endpoints, SQLite files, markers or checkouts. `start`
initializes them later; `status` does not. Setup does not allocate a task.

On v0.2.0, copy [examples/work.toml](examples/work.toml), replace its absolute
paths, and set `WORK_CONFIG` to that file; that release has no `work setup` and
no HOME fallback. Copying the example remains an advanced alternative on v0.3.0+.
Create the managed root first. Keep the store and registry outside repositories
and managed roots.

`work start` uses the Git repository that contains the current directory. Outside
a repository, a single configured repository is the default. A repository that is
not in the configuration is added to it on first use. A single configured root and
the top-level `actor` supply defaults; with multiple roots, pass `--root`.
`--actor` overrides the configured actor. Task names use letters, digits, `_`,
`-`, or `.`, with no leading dot/dash or consecutive dots.

Each checkout is created at `ROOT/REPOSITORY/TASK`, where `REPOSITORY` is the
repository's folder name. Checkouts recorded by earlier releases at `ROOT/TASK`
keep their paths.

## Daily workflow

On v0.3.0+, omit `WORK_CONFIG` to use default discovery. An empty `WORK_CONFIG`
disables discovery. The explicit export below remains valid on every supported
release, including v0.2.0.

```sh
export WORK_CONFIG=/absolute/path/to/work.toml
cd /home/alice/src/project
work start --task fix-login
# JSON reports the checkout UUID and destination. Keep these for recovery.
cd /home/alice/worktrees/project/fix-login
# Run your interactive agent or editor here; commit the changes you want to keep.

# Stop all agents and editors using this checkout, then leave it.
cd /home/alice/src/project
work status
work finish fix-login
work remove fix-login                    # preview; retains checkout and capacity
work remove fix-login --confirm-stopped  # explicit removal
work status --json
```

Repeating `start` for the same live task and actor reuses its checkout. A different
owner is never silently substituted. `finish` records completion once and retains
the worktree and its capacity charge. Task selectors must be unambiguous; use the
reported checkout UUID when necessary.

Removal supports finished, ordinary interactive checkouts. It refuses dirty,
untracked, or ignored files; unfinished tasks; unknown private Git files; and
historical supervised, adopted, capture, or retirement state. Keep the allocated
branch checked out: detached checkouts and branch changes are unsupported and
retain their work and charge. `work inspect UUID`
helps investigate content holds. There is no force flag or recursive fallback.

Removal keeps the branch and preserves HEAD and private reflog commit roots in
`refs/work-preserved/<checkout-uuid>/<object-id>`. A completed private commit
message is accepted only when its exact text is present in a preserved commit;
a draft message holds. These refs protect local work from ordinary Git garbage
collection. They are **local preservation, not a remote backup**. Push or back up
work separately. To revisit a retained branch, explicitly use `--reuse-branch`.

`--confirm-stopped` is your statement that writers have stopped. The CLI does not
prove that an editor or agent is gone. Its locks coordinate cooperating work-cli
commands; they do not contain arbitrary concurrent filesystem changes.

Capacity is released only after native Git removal and verified absence. If an
interruption leaves a recorded successful native result, repeat `remove` to
reconcile capacity. If the native outcome is unknown, the checkout remains
charged and removal will not replay. `status` reports that hold for manual
investigation. A recreated destination is never removed by recovery.

### Removal on macOS

On macOS, removal uses Git's own safety check in place of the Linux inspection.
Work runs `git worktree remove` without `--force`. Git refuses a checkout with
modified or untracked files. Work names these files and keeps the charge. Commit,
stash or delete them, then run the same command again.

Git deletes ignored files without a prompt. The preview lists them in
`ignored_files`, and removal with `--confirm-stopped` deletes them. A wholly
ignored directory is listed once, as `dir/`. Files that the user's global Git
excludes name (`core.excludesFile`, or `~/.config/git/ignore` when it is not
set) count as ignored, for example `.DS_Store`.

The branch stays in the repository. Work keeps a preserved ref,
`refs/work-preserved/<checkout-uuid>/<object-id>`, for the checkout's last commit
and for each commit that a per-worktree ref (`refs/worktree/*`, `refs/bisect/*`)
names.

If Git refuses the removal, or the removal stops before Work records the result,
fix the cause and run the same command again. Work checks the checkout and its
Git registration. If Git removed the checkout, Work releases the charge. If the
checkout is still present, Work runs the removal again with the same record.
A commit made in the checkout since then must be on a branch. If it is not, for
example after a commit on a detached HEAD, Work names it and keeps the charge.
Put it on a branch, then run the same command again. Work also refuses if the
checkout's identity or its finish record changed. Any other state keeps the
charge and you correct it by hand.

A per-worktree ref that names a tag is preserved through its commit. A
per-worktree ref that names no commit, for example a tree, refuses the removal.

## Existing installations

Schema-17 state and historical commands remain available. Run a historical
command's explicit `--help` for its interface; those commands are outside the
interactive v0.1 release workflow. No state reset or conversion of old run history
is required. Use this version consistently for an authority while removing
checkouts; older binaries do not understand the new removal events.

The durable removal journal uses append-only lifecycle events in the existing
outbox. Acknowledging events does not delete them. Keep that journal with the
store; do not prune it independently.

Apache-2.0. See [LICENSE](LICENSE).
