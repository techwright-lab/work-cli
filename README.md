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
available without process control. Explicit `work finish <checkout-id>` records task completion;
retirement is disabled and every finished checkout retains its tree and charge.
Production capture integration and removal are not implemented.
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
scope identity and current full contained roster/revision can release that group's writer.
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

`work recover <uuidv7>` explicitly tries full-roster supervised writer handoff after
controller loss. Store-validated historical scope and contained-host metadata are only
non-executing candidates for fresh kernel-backed manager/boot/invocation/cgroup and
double recursive/PID-start inspection. Every recorded actual host, including declared
terminal children, must be freshly absent; pending/unverified or unknown evidence holds.
Closure atomically records Interrupted only for proven-lost open contained children,
without fabricating root or declared child outcomes. It never
reconstructs an execution Binding. Reaped scopes require an explicit inactive/not-found
manager result and confirmed absence of the exact old cgroup. Live/uncertain, reused or
escaped PIDs, replacement invocations, unknown queries and boot changes retain the
writer and charges without fabricating a root outcome or refreshing a heartbeat.
Unbound intents and legacy bare writers cannot be closed. Already-closed receipts
require no runtime inspection and cannot remove a subsequent run's writer.
Recovery never launches, signals, kills, finishes a task, deletes, uncharges or retires.

`work status --run <uuidv7>` reports validated historical request/stage/outcome, group,
hold and charge metadata with runtime `not_inspected`, not an actual exit-code or
runtime qualification claim. It requires an existing initialized trusted v9 authority;
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

### Explicit task finish (retirement disabled)

`work finish <checkout-id>` requires a UUIDv7 and existing trusted, managed allocation.
It never initializes missing authority. A read-only established-authority preflight can
upgrade a valid v8 store to v9; malformed schemas, missing tables, views, incorrect
claims and non-WAL authority fail closed, without repair. Other historical commands
remain read-only and report upgrade-required for older schemas.

Finish refuses active/unknown/bare/adopted writers and incomplete or contradictory
root/child journals, even when a writer row is missing. Stop, SessionEnd, root exit
and timeouts never finish a task. Fresh marker, source, branch and checkout identity
verification precedes first completion. One IMMEDIATE transaction rechecks eligibility,
records the immutable finish operation/identity/capture-binding digest and exactly one
private `TaskFinished` outbox event, and fences the lease `held`, not ready, with
`retirement-disabled`. Run outcomes, ownership, aliases and charges are unchanged.
Task completion is separate from run completion. Historical status and finished-run
retry receipts derive task openness from the same snapshot as run/accounting metadata;
finished retries require no original actor Git profile or runtime.

No sink is a valid completion (exit 0). Configured production capture is explicitly
unsupported: completion remains durable, local freeze is Failed, evidence is incomplete,
and the sanitized held report exits nonzero. Configured capture never silently becomes
no-sink. A trusted library-only `LocalSink` seam supports future local capture; it is
not selected from CLI/environment/plugins and grants no receiver/network authority.
Local freeze runs only **after** the durable completion fence, outside SQL transactions
and the lifecycle flock. Local Frozen/Failed and delivery Pending/Delivered/Failed are
separate: no delivery queue/session is invented. Pending/Failed retries can call an
explicit local sink only with the original binding and Work-owned idempotency key;
Frozen never refreezes. Changed configuration returns stored evidence, never retargets it.
No raw sink URI, prompt or environment is persisted. A second exact-context transaction
records the capture result without another task-completion event.

Reports distinguish task completion, unchanged run outcomes, local freeze/delivery,
incomplete evidence, held lease, retained charge and retirement `disabled`/action `none`.
Retries return the same durable operation after lost acknowledgements. Allocation
recovery/start and writer APIs cannot reopen the fence; finish IDs stay reserved across
allocation, root/adopted/child and legacy-writer namespaces. Dirty/untracked no-sink
checkouts remain in place: completion is **not preservation proof or deletion permission**.
There are no force/delete options, retirement callbacks, moves, quarantines, Git writes,
branch changes or charge releases. Tasks 8 and 10 must qualify real capture and shared
retirement separately; this construction milestone authorizes neither activation nor cleanup.

Supervised closure covers the full enrolled host roster; adopted participants cannot join it.
`Store::register_child(root, ChildRequest)` records an immutable
supervised child intent before inspection, bumps group revision/child count and appends
an outbox event in the same IMMEDIATE transaction. Exact retries validate the entire
child tree without grants/events, including after closure. New registration requires
the exact open writer and permitted root,
explicit known parent run/ref, same checkout/group, at most 16 levels and 256 children.
Late metadata remains accepted after root/parent logical completion or a recovery hold
while the permitted group is open; it preserves those outcomes/holds and invalidates
older empty proofs. Closed groups reject new children and changed requests, but acknowledge
exact known-child requests as metadata only. Child run IDs also cannot become
legacy writer groups or reservation operation IDs, including on exact retries.
Child Work IDs/refs share the global root/adopted-run/group/operation/child namespace.
Those IDs stay reserved on reverse admission and legacy writer paths, including
historical IDs; genuine bare writers and immutable allocation retries remain valid.
Optional actual source/session/agent/actor references remain unknown when absent. Expected boot/PID/start
is a candidate host identity, **not** observed containment or individual authorship;
logical children can name the same physical host without inventing child PIDs.

The reviewed Task6 supervised metadata implementation is conservative: expected-host children start `pending`,
children without an expected host start `unverified`, and `record_child_hold` only tightens
pending or contained to unverified (retaining prior enrollment audit). `record_child_outcome` records immutable/idempotent declared
Completed/Failed/Cancelled, never caller-declared Interrupted or physical absence.
Exact declared-outcome retries remain metadata-only Existing after closure; different
outcomes conflict (including attempts to override kernel Interrupted). Closed groups
reject new outcomes and holds. These receipts grant no launch or writer permission,
perform no fresh kernel inspection and cannot release a newer run's writer.
Every accepted change bumps revision; no writer, charge, task or checkout state changes.
Full child requests and parent trees are validated in one SQLite snapshot on root
lookup/retry/status/recovery. Missing ledger rows, orphan/corrupt metadata and versioned
views fail closed. Status includes `record.children` and still says `not_inspected`.
Pending/Unverified children block both live and historical empty proof, even after logical
closure or expected shared-root-host declarations; a pre-registration proof fails CAS.
Contained children require fresh absence of every recorded actual host, including declared
terminal hosts. No child is silently dropped by terminal/grace/cancellation/recovery closure.

Positive enrollment uses reviewed library proofs: `Driver::identify(pid)` uses bounded no-follow
proc inspection (production fixed `/proc`, explicit library fixture IO otherwise).
`GroupSnapshot::certify_child_enrollment(driver, child_run, optional_original_binding)`
returns a private, nonserializable `EnrollmentProof` only after exact original host
boot/PID/start matching, fresh active exact scope inspection and complete recursive/
participant coverage for the target execution host and necessary actual registrar only.
Identification and census share one cumulative byte budget and earliest deadline,
capped at two seconds. Membership still covers every recursive kernel member;
the full root record and complete child ledger still bind validation and commit CAS.
An absent original root process or unrelated unknown, unverified, missing or dead
sibling does not veto positive target facts or mutate sibling metadata. This is target
enrollment, not entire-group quiescence; enrollment receipts alone cannot release a writer.
Without the original
root Binding, the actual registrar process must also be freshly present in that scope;
there is no caller-selected registrar PID or environment lease. Shared root hosts need
the same fresh evidence, not invented child PIDs. Terminal root outcomes/recovery holds
are retained and do not grant execution. Exact declared Completed/Failed/Cancelled
child outcomes are also retained and do not veto enrollment of a still-live pending
host. Unknown/unverified targets cannot upgrade. No new native IDs, individual
authorship, launch permission or cancellation permission are created.

`Store::record_child_enrollment(root, child, proof)` revalidates the exact full snapshot,
writer, immutable child, root binding and revision under IMMEDIATE locking, checks the
original observation's two-second age after locking, then atomically stores `contained`
host metadata with revision/outbox. An exact committed retry is `Existing` metadata only,
without events, heartbeat or renewed evidence. Serializable `HostSnapshot` and
`EnrollmentRecord` are historical audit, never execution or current-containment tokens.
Status labels this **enrollment recorded; runtime not inspected now**; attribution
remains group/root/unknown. Schema8 transactionally rebuilds the v7 child table, preserving
all rows and other journals/accounting; malformed/missing/view schemas and corrupt host,
scope or parent metadata fail closed. There is no row removal or repair.

`GroupSnapshot::certify_empty(driver, original_binding)` and
`certify_historical_empty(driver)` construct the same complete actual-host roster internally.
Exact shared physical hosts deduplicate without inventing child PIDs; different birth
identities are never dropped. Every host (including the original root, whether its outcome
is known or not) must be freshly absent, with complete recursive empty-scope and participant
coverage. Historical candidates never reconstruct Binding/permit/signal authority.

The private `GroupEmptyProof` binds the entire child snapshot and mandatory open-child loss
set. `Store::close_supervised_group(snapshot, proof)` uses one IMMEDIATE transaction to
revalidate exact context/revision and the original two-second evidence age after locking,
mark only proven-lost open Contained children `Interrupted`, emit `ChildrenInterrupted`,
remove only this group's writer, and emit `GroupClosed` at one new revision. Freshness is
checked again near writer removal. Failures roll back outcomes/writer/events together;
no OS calls occur under SQL lock. Declared child outcomes, unknown root outcomes, retained
child count/rows and checkout/task/owner/charge metadata are preserved. Exact closed retries
normalize the proof's interruptions, acknowledge even expired committed receipts, and cannot
affect a newer writer. Corrupt closed child history fails before recovery filtering;
Interrupted is illegal in open groups and rejected by public child outcome declarations.
No time, heartbeat or missing SessionEnd is an exit proof.

### Explicit child metadata CLI (reviewed Task6 implementation; not activation)

```sh
work participant register < child-request.json
work participant enroll < child-request.json
work participant close < child-outcome.json
work participant status ROOT_RUN_UUIDV7
```

Registration/enrollment use the strict envelope `{ "root_run": "ROOT_RUN_UUIDV7",
"child": { ... } }`. The child object requires every field: `checkout`, `group`,
`run`, `run_ref`, `parent_run`, `parent_run_ref`, `execution_chain`, `source`,
`session`, `agent`, `actor`, `expected_host`. Unknown native references are explicit
JSON `null`, never generated IDs. `execution_chain` is the existing typed Work
execution chain; `expected_host` is either `null` or the complete object
`{ "boot": "BOOT_UUID", "pid": 42, "start_ticks": 10 }`. These are declared
metadata, not prompts, commands, arbitrary payloads or environment. Close adds
`"outcome": "completed"`, `"failed"` or `"cancelled"` to the envelope;
`"interrupted"` is always rejected, including on retries.

Dedicated stdin must reach EOF and is limited to 4 MiB (including legal Unicode
chains); a producer that never closes stdin is not time-bounded. Unknown/duplicate
fields, malformed/trailing input and oversized input fail with sanitized errors.
Explicit `root_run` resolves an existing stored supervised root; environment lease
IDs, automatic group joins, adopted roots and invented context are never accepted.
Mutators require existing registered current-schema authority: no bootstrap,
migration or new allocation. Registration commits a pending/unverified barrier
without runtime/Git calls, including when optional capture cannot execute.
Close only declares immutable logical metadata: it never runs recovery, proves
absence, finishes a task, releases a writer or removes charges.

Enroll requires an exact previously registered pending child and explicit validated
`supervisor.runtime_directory`/`supervisor.bus_address`. It uses fixed production OS
paths, no original Binding, no caller-selected registrar PID and no actor Git-profile
lookup; the actual CLI process must be in scope. Missing runtime or uncertain host/
registrar facts durably tighten the target to unverified and return nonzero `held`.
Unverified targets cannot upgrade. A post-inspection CAS conflict keeps the existing
barrier and reports held without hidden retries. Previously contained exact metadata
returns `already_recorded` history only, without constructing a Driver or claiming a
fresh proof. Reports distinguish `changed`, `existing`, `already_recorded`, `held`,
carry static reason codes, `no_execution_permission: true` and
`fresh_runtime_claim: false`. Status needs neither runtime nor actor profiles and
returns full validated historical children with `runtime: "not_inspected"`; it does
not write DB/WAL, directory entries, events, acknowledgements or heartbeats.
Help/version are read-only throughout the participant command tree.

**Not implemented:** native hook routing, bridge, retirement
or scheduled automatic recovery. Task6 metadata implementation review does not qualify live activation.
Serialized metadata alone grants no launch, cancellation or closure authority.
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
  "source": "sdk", "session": "actual-runtime-session", "agent": null
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
  "participant": {"session":"actual-runtime-session","agent":null},
  "parent": null, "actor":null,
  "prompt":null, "tool":null,
  "event_ref":"stable-event-reference", "kind":"stop", "observed_at":123
}
```

Kinds are `stop`, `subagent_start`, `subagent_stop`, `session_end`, `reconcile`.
The session-only example also supports root `session_end` and `reconcile`: use the
actual session ID, without inventing agent, prompt or tool references. Those three
references may be null or omitted. An absent agent denotes the session root, not a
made-up runtime agent ID; it remains distinct from every actual agent reference.
The required `identity.actor` declares run accountability, not runtime attribution.
New root participants have unknown (`null`) runtime actor; child actors may likewise
remain unknown. Historical explicit v6 root actor declarations are preserved.
A child without an agent ID needs a distinct session from its parent; otherwise it
cannot identify a distinct child and is refused. No runtime IDs are generated.
A child event explicitly supplies the already-registered parent's session/agent
key and the child's own key; its declared actor may be null (unknown remains
unknown). Known participant actor/parent claims cannot change. Self/cross-group,
foreign-source, reparenting and unknown-parent claims are refused. The roster is
bounded to 256 participants including root, at most 16 child levels. Sources,
session/event references, present agent/prompt/tool references, actor and run references are nonblank,
control-free and at most 256 Unicode scalars. Chains retain their existing typed
limits. JSON stdin is bounded to 4 MiB, covering the full UTF-8/JSON domain of these
limits; unknown fields and raw payloads are refused with value-free CLI errors.

Idempotency includes source/group/session/optional-agent/prompt/tool/kind/event_ref,
not time. Same key and typed immutable context (including parent and actor) returns
`existing` even with a newer or older observation timestamp. The first stored body,
heartbeat, revision and outbox remain unchanged; changed parent/actor claims conflict.
Different event references are never coalesced. Unique accepted events increment
the group revision. Stop appends a segment/heartbeat only. SubagentStop retains a
terminal tombstone even if Start arrives later. SessionEnd records that session
participant's logical closure and requests reconciliation; open/unknown children
remain visible. Reconcile never refreshes a heartbeat. Session IDs may span many
checkouts, with separate group-scoped journals. Shared output is group/root-based,
not individual authorship inferred from timestamps or email.

Status reads revision, writer and validated roster in one database snapshot. All
retry paths validate durable declarations before returning success; corruption is
an error, never absence or authority to reverify/update the allocation.
Status is read-only existing-v8-authority metadata, with
`adopted_basis="checkout/session declaration"`, `git_identity_controlled=false`,
`automatic_quiescence=false`, `runtime="unknown"`. Declared closed is **not verified
exited**. Reads, silence, reboot, missing SessionEnd, reconciliation, and even all
logical closures never release the adopted writer, finish a task, change checkout
state or uncharge it. The writer remains explicitly held until a future qualified
handoff path (operator quiescence/retirement approval is Task 10). `work status --run`
and `work recover` remain supervised-only; the full contained supervised roster requires
fresh whole-group kernel proof, while pending/unverified children block handoff.
Use `work adopt status` for adopted metadata. Existing-authority reads require schema v9.
Schema v7 added the supervised child ledger and retained child count; v8 adds positive
host audit metadata without rebuilding the v6 adopted/supervised proof tables;
old charges/history/outbox/aliases/unknown writers are retained, missing versioned
tables fail closed, and read APIs never initialize or migrate. Optional references
reuse v6 columns without migration: absence is stored as an empty SQL key (not a
user-facing reference), present refs retain their original text, and historical
string-valued request/event/parent JSON remains compatible without row rewrites.

Actual runtime-hook payload-to-stable-ID mapping, installation and fork coverage
qualification belong to Task 13 and are not implemented. Positive supervised child
containment and full-roster closure proof are implemented in the library; explicit
`work participant` child metadata CLI is available. Native-hook mapping, routing,
qualification and installation remain unimplemented (Task 13). Task6 supervised,
adopted and participant metadata implementation is reviewed; this is not production
deployment, live-hook or capture-bridge activation, or retirement readiness.
Explicit task finish is a separate construction milestone above, with retirement disabled.
Earlier root-only recovery and all-child barrier increments were intentionally narrower
historical stages, not current limits. Writer release is not task completion, uncharging
or retirement.

## Requirements

- Rust 1.98.1
- Linux is the supported platform; live runtime qualification is not implied by Linux.
  Other operating systems are unsupported.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
