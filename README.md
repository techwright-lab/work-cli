# work-cli

Linux-first command-line tool (`work`) for managed Git worktree lifecycle:
admission, checkout ownership, execution groups, and retirement.

This is a public Apache-2.0 project. Configuration lives on the host; the
binary has no baked-in organization paths, identities, quotas, or notification
channels.

## Status

Early construction. Read-only `work --help`, `work status [--run <uuidv7>]` and `work doctor` are
available, plus configured `work start` allocation. Start never launches a writer.
Configured root-only `work run` coordination is available for construction/testing,
not production activation. Adopted-only declarations (`work adopt begin/event/status`) are
available without process control. Finish/removal and capture integration are not implemented.
Status does not inspect lifecycle/run inventory or qualify a live runtime; use doctor
for read-only accounting. Historical run bindings cannot be restored.

## Read-only inventory

```sh
work doctor --json --repository /absolute/repo --managed-root /absolute/checkouts \
  --store-dir /absolute/private/store --trusted-registry /absolute/private/registry
```

Repeat `--repository` and `--managed-root` for multiple scopes. Repository inputs
may be the primary checkout or a linked checkout; canonical Git common directories
deduplicate aliases. No repository discovery outside these inputs occurs. Roots
must be existing canonical absolute directories, not symlinks, nested roots,
duplicate roots or `/`. No host-specific defaults are supplied. Omit the store
options to report unknown accounting rather than initialize anything.

Alternatively set `WORK_CONFIG` to a TOML file (or use
`$XDG_CONFIG_HOME/work/config.toml`):

```toml
repositories = ["/absolute/repo"]
roots = ["/absolute/checkouts"]
store_dir = "/absolute/private/store"
trusted_registry = "/absolute/private/registry"
```

Path fields require strings/string arrays of absolute canonical directory paths;
store/registry paths may be missing or inaccessible so unresolved evidence can be
reported unknown (never treated as canonical identity proof).
Explicit CLI lists replace their respective config lists. Empty scope is an error.
`--json` emits the version-1 report; without it the same report is pretty printed.
Unknown evidence is a successful report, not a healthy empty inventory.

Inventory includes Git-registered worktrees and at most 1,000 immediate children
per managed root. Unregistered child subtrees are reported as unmanaged/unknown,
not exhaustively searched for nested checkouts. Missing or malformed private Git
metadata is unknown/partial/recreated, never evidence of safe retirement. Valid
registered checkouts are **legacy/unmanaged candidates**, not proof of absence
from managed accounting: doctor does not certify allocation metadata against filesystem identity.
`managed_filesystem_count` therefore remains null; doctor never guesses a match
from a basename, actor or task. Owner/state accounting includes every non-retired
charge independently of filesystem classification.

Headroom is `statvfs` available bytes, not a quota guarantee. Logical size estimates
use metadata only, at most 10,000 entries and depth 32 per path, without following
symlinks or crossing devices; incomplete estimates are null. They are neither
allocated nor reclaimed Btrfs bytes. Reports are observations, not atomic snapshots;
concurrent same-UID replacement remains a reconciliation concern.

Doctor never calls store initialization/migration, repairs evidence, runs hooks,
creates notifications or contacts remotes. SQLite is opened read-only with existing
initialization/authority evidence. Writable lifecycle connections retain **WAL and
SHM files** on last close (no-close-checkpoint), while retaining FULL synchronization
and normal autocheckpoint. Ordinary create/write/close therefore remains readable.
External clients that remove bookkeeping leave strict reads conservatively unknown:
readers never recreate sidecars or use `immutable=1` (which ignores active WAL). Existing
SHM bookkeeping may change: read-only does not promise byte immutability.
Lifecycle regression snapshots check directory entries, DB/WAL bytes and events,
but exclude **all SHM contents**, not merely lock bytes.
No new files/directories or lifecycle/outbox writes are intended. Missing, corrupt,
inaccessible or partial authority/store evidence is unknown, not zero charges.

## Allocation (explicit host policy only)

Protect managed roots from competing cleaners before activation. No host is activated
by these examples. Configure existing canonical repository/root directories and one
trusted registry/store; every non-retired reservation consumes its owner/repository slot.
Add explicit policy to the configuration above (these small values are examples, not defaults):

```toml
[allocation]
repository_limit = 10
owner_limit = 2
floor_bytes = 1073741824
warn_bytes = 2147483648
# No capture_sink: allocation may become ready without attribution capture.
# Any configured capture_sink currently fails closed; capture is NOT prepared.
```

```sh
work start --operation UUIDV7 --repository /absolute/repo --root /absolute/checkouts \
  --actor developer --task ticket-123 --branch ticket-123 --base main
```

Generate one UUIDv7 per operation and retain it for retries. Without `--operation`,
start generates and prints one. A retry must supply the same normalized arguments;
policy reductions do not consume another slot or checkout. Destination is exactly
`root/task`. The allocating actor remains accountable (`--owner`, if supplied,
must match); reassignment requires explicit transfer, not an allocation flag. Existing
branches require explicit `--reuse-branch`; their commits are preserved, never reset.
Colliding destinations are never adopted, removed or replaced. Same-task lookup
alone never grants a writer and a different operation cannot adopt an existing path.

Full intent and reservation are committed together before Git. Every create/resume
checks source common-Git-directory identity against the durable charged repository,
not just two fresh Git observations. Allocation retries reconcile private-Git-directory
marker, registration and durable/stat identity. An explicit persisted hold cannot be
released by ordinary start, even after configuration or metadata is repaired; it
requires operator recovery outside start. Initial in-progress crash stages may reconcile.
Incomplete creation (including create-before-marker crashes), altered metadata or
unsupported layouts remain charged and held for operator reconciliation; nothing
is deleted, timed out or automatically retired. Boot/device changes require durable
identity reconciliation, not invented activity. Capture-enabled configurations are
unsupported and fail closed. Schema-v1 migration preserves old charges with writer
readiness false; doctor remains a no-migration existing-evidence reader for both versions.

Controlled creation fails closed on any effective nonempty `filter.*.smudge` or
`filter.*.process` configuration, including included configuration. LFS is not yet
supported. Conditional includes are also rejected: a new gitdir/branch can activate
configuration absent in the source context. There is no filter override option until
these execution paths are qualified. Hooks and fsmonitor are disabled. Git runs via
`/usr/bin/git` with a cleared environment, trusted `/usr/bin:/bin` PATH, disabled
global/system config and prompts; credentials and `GIT_CONFIG_*` overrides are not
inherited. Each Git subprocess has a two-second deadline and one-MiB capture bound
per output stream, with owned process-group kill and child reap. This is not hard
containment against malicious `setsid` descendants or concurrent same-UID mutation.
Private marker/backlink reads require nonblocking, no-follow regular descriptors
and a 16-KiB byte bound. Uncertainty retains the charge and never triggers deletion.

## Supervised root commands (not activation)

A previously allocated, active/ready checkout ID is required. No implicit allocation,
path reuse, repository discovery or held-lease revival occurs. Extend host configuration
with explicit finite policy and named actor Git profiles (values below are examples,
not compiled defaults):

```toml
[supervisor]
runtime_directory = "/absolute/private/user-runtime"
bus_address = "unix:path=/absolute/private/user-runtime/bus"
runtime_max_seconds = 3600
preexec_ms = 5000
closure_grace_ms = 2000
cancel_grace_ms = 2000

[supervisor.actors.developer]
author_name = "Configured Actor"
author_email = "actor@example.invalid"
committer_name = "Configured Actor"
committer_email = "actor@example.invalid"
```

The existing private runtime directory must be owned by the current UID, mode 0700,
with its owned `bus` socket. RuntimeMaxSec is 1..86400 whole seconds; each other budget
is 1..30000 milliseconds. Actor selection is explicit `--actor` or the lease actor;
an exact registered Git profile is mandatory, independently of executor/model metadata.
All four Git identity variables are projected only into the launched command, with no
global Git/process-environment changes. Original presence/bytes of XDG_RUNTIME_DIR and
DBUS_SESSION_BUS_ADDRESS are restored for the delegate, not replaced by manager context.

Supply a bounded typed execution-chain JSON **file**, not stdin. For example, declare
`[{"kind":"executor","system":"declared-executor"}]`; declare actual model/provider
entries explicitly when applicable. No model/provider is inferred. Generate and retain
one UUIDv7 before invoking:

```sh
work run CHECKOUT_UUID --run-id RUN_UUIDV7 --execution-chain /absolute/chain.json -- command arg
```

The CLI prints the retry ID and completion/hold metadata to stderr only; protocol
stdin/stdout/stderr otherwise pass through unchanged. Raw argv, environment and prompts
are not journaled. Command digests use length-prefixed raw OS bytes, preserving empty
and non-UTF8 arguments. Exact retries are metadata receipts, **never relaunch authority**;
changed immutable inputs conflict. Existing receipts retain original group/context/boot.

Intent and writer commit before launching. Bound metadata and permit-attempt commit
separately before gate publication. Root Completed/Failed/Cancelled status is separate
from writer closure: only fresh, complete whole-scope emptiness against the exact
scope identity and current root roster/revision can release that group's writer.
Uncertain evidence or surviving descendants retain a held writer under finite policy.
A closed group permits a sequential run without another checkout charge. Lease charges
and task openness are never released here. Capture_sink remains unsupported and fails
closed before any delegate; attribution capture is not configured.

SIGINT/SIGTERM request cancellation through an atomic token. Cancellation freshly
revalidates exact unit/invocation/boot/cgroup identity before requesting scope SIGTERM;
never killpg or a historical PID. No hard-kill escalation is configured. Acknowledgement
is not emptiness proof. Bounded grace exhaustion/failures retain recovery holds. Kernel
D-state can make owned-child kill/reaping unbounded despite finite userspace policy.
An owned process group isolates non-terminal protocols; interactive TTY/job-control
has not been qualified and terminal stdio is explicitly refused.

`work recover <uuidv7>` explicitly tries ROOT-ONLY writer handoff after controller loss.
Store-validated historical scope metadata is only a non-executing candidate for fresh
manager/boot/invocation/cgroup and double recursive/PID-start inspection. It never
reconstructs an execution Binding. Reaped scopes require an explicit inactive/not-found
manager result and confirmed absence of the exact old cgroup. Live/uncertain, reused or
escaped PIDs, replacement invocations, unknown queries and boot changes retain the
writer and charges without fabricating a root outcome or refreshing a heartbeat.
Unbound intents and legacy bare writers cannot be closed. Already-closed receipts
require no runtime inspection and cannot remove a subsequent run's writer.
Recovery never launches, signals, kills, finishes a task, deletes or uncharges.

`work status --run <uuidv7>` reports validated historical request/stage/outcome, group,
hold and charge metadata with runtime `not_inspected`, not an actual exit-code or
runtime qualification claim. It requires an existing initialized trusted v6 authority;
missing/corrupt/older authority is unknown or upgrade-required, never empty accounting.
Like doctor, strict read-only access refuses WAL databases lacking existing WAL/SHM
bookkeeping rather than creating files or ignoring committed WAL. Normal lifecycle
writers retain that bookkeeping. Recovery validates initialized intent, claims and
schema read-only before opening the existing store writable; it never initializes,
repairs missing sidecars or migrates authority/schema. SQL budgets are scoped to
operations/preflight; nested SQL phases share a cumulative limit, and time spent
between operations inspecting Git or runtime state does not consume that limit.
Neither command needs the original actor's current Git profile. Existing `work run`
retries remain receipts/holds, not relaunches or automatic recovery.

Supervised groups remain ROOT-ONLY: attaching external/adopted participants is refused.
Supervised child coverage, bridge, task finish, retirement and automatic recovery
are not implemented. Serialized metadata alone grants no cancellation/closure authority.
Library fixtures use actual child birth identity with synthetic manager/cgroup IO and
do **not** qualify a live systemd backend. No CLI fake-manager selector exists.

## Adopted declarations (Task 6.4a; not activation)

Already-running interactive sessions are **not retroactively supervised**. Adopted
metadata never controls cwd, OS environment, Git identity or process lifetime and
never provides ScopeRoot/physical-exit proof. This is cooperative attestation, not a
same-UID security sandbox. No supervisor bus, Git profile or LLM is required.

Use dedicated hook-process stdin (never delegate protocol stdin):

```sh
work adopt begin < adopted-request.json
work adopt event < typed-activity.json
work adopt status RUN_UUIDV7
```

`begin` takes this strict typed JSON shape (replace UUID placeholders with distinct
UUIDv7 values, and CHECKOUT with an explicitly allocated checkout UUID):

```json
{
  "operation": "OPERATION_UUIDV7",
  "identity": {
    "checkout": "CHECKOUT_UUIDV7", "group": "GROUP_UUIDV7", "run": "RUN_UUIDV7",
    "run_ref": "sdk:stable-run-reference", "actor": "declared-actor",
    "parent_run_ref": null,
    "execution_chain": [{"kind":"executor","system":"declared-sdk"}]
  },
  "source": "sdk", "session": "stable-session", "agent": "root-agent"
}
```

The CLI freshly verifies active/ready allocation, marker, source and branch under
its short allocator lock before claiming the **same** exclusive writer used by
supervised runs. The immutable adopted root, root session and outbox commit with
that writer. Exact retries return `existing` without new events, grants or activity;
changed claims conflict. Another independent writer is refused, never merged.
Quota owner/charges remain unchanged. Capture-enabled begin/event are unsupported
and refused; there is no sink bypass. Library `adopted::begin` is the integrated
entry point; `Store::begin_adopted` is its low-level active/ready SQL transaction.

`event` takes only typed references and declaration metadata, for example:

```json
{
  "run": "RUN_UUIDV7", "group": "GROUP_UUIDV7", "source": "sdk",
  "participant": {"session":"stable-session","agent":"root-agent"},
  "parent": null, "actor":"declared-actor",
  "prompt":"stable-prompt-or-segment", "tool":"stable-tool-reference",
  "event_ref":"stable-event-reference", "kind":"stop", "observed_at":123
}
```

Kinds are `stop`, `subagent_start`, `subagent_stop`, `session_end`, `reconcile`.
A child event explicitly supplies the already-registered parent's session/agent
key and the child's own key; its declared actor may be null (unknown remains
unknown). Known participant actor/parent claims cannot change. Self/cross-group,
foreign-source, reparenting and unknown-parent claims are refused. The roster is
bounded to 256 participants including root, at most 16 child levels. Sources,
session/agent/event/prompt/tool references, actor and run references are nonblank,
control-free and at most 256 Unicode scalars. Chains retain their existing typed
limits. JSON stdin is bounded to 4 MiB, covering the full UTF-8/JSON domain of these
limits; unknown fields and raw payloads are refused with value-free CLI errors.

Idempotency includes source/group/session/agent/prompt/tool/kind/event_ref, not
just time. Same key and normalized body returns `existing` with no heartbeat,
revision or event change; changed body conflicts. Unique accepted events increment
the group revision. Stop appends a segment/heartbeat only. SubagentStop retains a
terminal tombstone even if Start arrives later. SessionEnd records that session
participant's logical closure and requests reconciliation; open/unknown children
remain visible. Reconcile never refreshes a heartbeat. Session IDs may span many
checkouts, with separate group-scoped journals. Shared output is group/root-based,
not individual authorship inferred from timestamps or email.

Status is read-only existing-v6-authority metadata, with
`adopted_basis="checkout/session declaration"`, `git_identity_controlled=false`,
`automatic_quiescence=false`, `runtime="unknown"`. Declared closed is **not verified
exited**. Reads, silence, reboot, missing SessionEnd, reconciliation, and even all
logical closures never release the adopted writer, finish a task, change checkout
state or uncharge it. The writer remains explicitly held until a future qualified
handoff path (operator quiescence/retirement approval is Task 10). `work status --run`
and `work recover` remain supervised ROOT-ONLY; use `work adopt status` for adopted
metadata. Schema v6 is additive: supervised proof tables are not rebuilt or weakened,
old charges/history/outbox/aliases/unknown writers are retained, missing versioned
tables fail closed, and read APIs never initialize or migrate.

Actual runtime-hook payload-to-stable-ID mapping, installation and fork coverage
qualification belong to Task 13 and are not implemented. Supervised child coverage
is the next Task 6 slice; this journal does not complete Task 6.

## Requirements

- Rust 1.98.1
- Linux is the supported platform; live runtime qualification is not implied by Linux.
  Other operating systems are unsupported.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
