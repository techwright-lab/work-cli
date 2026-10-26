# work-cli

`work` manages Git worktrees for interactive agent tasks. Create or reuse a
checkout, run your agent there, then explicitly finish and remove it.

The v0.1 workflow is `start → status → finish → remove`. Agents run in your
terminal or editor. No process supervisor, capture service, background cleanup,
or remote-preservation configuration is required.

## Requirements and build

The qualified environment is Linux x86_64, Rust 1.98.1, and **Git 2.55.0 at
`/usr/bin/git`**. Removal refuses other Git versions and unsupported layouts.
The packaged binary requires glibc 2.36 or newer. Git is a separate prerequisite.

Build and test in the disposable qualification container:

```sh
docker build -f tools/qualification/Dockerfile \
  -t work-cli-qualification:rust-1.98.1-git-2.55.0 .
tools/qualification/container.sh fetch --locked
tools/qualification/container.sh test --workspace --locked -- --test-threads=4
tools/qualification/container.sh clippy --workspace --all-targets --locked -- -D warnings
tools/qualification/container.sh -- tools/package-linux.sh
```

Archives and SHA-256 checksums appear in `target/dist/`. Extract an archive and
put its `bin/work` on your PATH. Nothing in these scripts installs a host binary
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
historical supervised, adopted, capture, or retirement state. `work inspect UUID`
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
