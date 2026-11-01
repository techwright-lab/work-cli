# work-cli

`work` manages Git worktrees for interactive agent tasks. Create or reuse a
checkout, run your agent there, then explicitly finish and remove it.

The interactive workflow is `start → status → finish → remove`. Agents run in your
terminal or editor. No process supervisor, capture service, background cleanup,
or remote-preservation configuration is required.

## Download the binary

Get `work-0.2.0-linux-x86_64` and its `.sha256` file from
[GitHub Releases](https://github.com/techwright-lab/work-cli/releases). For a fresh
installation:

```sh
mkdir -p "$HOME/.local/bin"
sha256sum --check work-0.2.0-linux-x86_64.sha256 &&
  install -m 755 work-0.2.0-linux-x86_64 "$HOME/.local/bin/work" &&
  work --version
```

**No repository clone, Rust or Python is required.** Keep Git installed as described
below. Standalone assets arrive with v0.2.0 after publication; existing releases
already include the native executable at `bin/work` inside their release archive.
A version-bump PR is not a published release.

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

Requires Linux x86_64 and **stable Git ≥2.55.0 at `/usr/bin/git`**; source builds
use Rust 1.98.1. Version admission accepts canonical `git version MAJOR.MINOR.PATCH`
output, including newer minor and major releases. Older versions, prereleases,
vendor-suffixed or unparseable version strings are refused as `UnsupportedGit`.
Unsupported repository layouts are still refused regardless of Git version.
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

CI tests Git 2.55.0 (the minimum) and 2.56.0. Newer stable versions are accepted,
not automatically claimed as tested. Version admission never substitutes for
fresh repository, object, preservation and removal safety checks.

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

Copy [examples/work.toml](examples/work.toml), replace its absolute paths, and set
`WORK_CONFIG` to that file. Create the managed root directory first. Keep the
store and registry outside repositories and managed roots. `start` initializes
them; `status` does not.

A single configured repository/root and the top-level `actor` supply defaults.
With multiple repositories or roots, pass `--repository` and `--root` explicitly.
`--actor` overrides the configured actor. Task names use letters, digits, `_`,
`-`, or `.`, with no leading dot/dash or consecutive dots.

## Daily workflow

```sh
export WORK_CONFIG=/absolute/path/to/work.toml
work start --task fix-login
# JSON reports the checkout UUID and destination. Keep these for recovery.
cd /home/alice/worktrees/fix-login
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
