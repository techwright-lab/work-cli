# work-cli

Linux-first command-line tool (`work`) for managed Git worktree lifecycle:
admission, checkout ownership, execution groups, and retirement.

This is a public Apache-2.0 project. Configuration lives on the host; the
binary has no baked-in organization paths, identities, quotas, or notification
channels.

## Status

Early construction. Read-only `work --help`, `work status [--run <uuidv7>]` and `work doctor` are
available, plus configured `work start` allocation. Start never launches a writer.
Configured supervised `work run` coordination is available for construction/testing,
not production activation. Adopted-only declarations (`work adopt begin/event/status`) are
available without process control. Explicit `work finish <checkout-id>` records task completion;
retirement is disabled and every finished checkout retains its tree and charge.
Configured supervised capture integration and certified continuation are implemented in source;
production qualification/activation and removal are not implemented.
Status does not inspect lifecycle/run inventory or qualify a live runtime; use doctor
for read-only accounting. Historical run bindings cannot be restored.

### Capture construction (Tasks 8.1–8.4b; implementation, not acceptance)

The library exposes `capture_bridge` typed begin/finish/retry requests and
`sinks::ProcessSink` for a trusted host adapter, plus a durable library-only
`capture_journal`. Typed host configuration and capture-pending allocation
materialization, trusted library-only capture preparation and captured supervised
execution and explicit trusted-library terminal finalization are available.
Explicitly configured supervised `work run` uses the integrated capture path described
below. Captured adopted execution remains unsupported. Tests use
private fake executables or disposable Git repositories, not an installed
DevDiary/Python CLI, a live scope or a receiver.

Settings require absolute executable/registry/state paths, a 1..30000 ms runtime
budget and a 1..1048576-byte aggregate stdout+stderr budget. Input encoding stops
at 1 MiB before spawn. Literal argv contains only registry/state locators and the
operation; all capture data (including an optional key-file locator, never a key
value) travels as operation-specific JSON on stdin. The receiver process inherits
operator environment; captured supervised execution strips qualified receiver
credential names from launcher, manager inspection/cancellation, helper and delegate.
Nonblocking stdin/stdout/stderr share one original deadline, with ETXTBSY-only
pre-exec retry and owned-group kill/reap. Exact response-cap exhaustion is refused
without an EOF lookahead. Kernel D-state can still delay reap.

Begin projections require exact actor/run/capture binding and the seven-key
allowlist. Both `ProcessSink::begin(&request, &expected_git)` and
`capture_bridge::decode_begin(bytes, &request, &expected_git)` require the
caller's trusted `GitProfile`; all four values and their presence must match
before `Prepared` can be returned. `GitProfile::default()` explicitly expects
all four fields absent; it never means accept any response. Expected strings
are bounded/control-free, and the process sink validates them before spawn.
Do not derive the expected profile from the receiver's response. Response
objects must use JSON objects at every nesting level, never positional arrays;
request execution-chain/task-reference arrays remain supported.
Projections are redacted and not serializable. Terminal exit zero with `pending`
is only a local-frozen/delivery-pending observation, never delivery or lifecycle
authority. Delivered requires a matching receipt (`event_id` per the portable
protocol, positive integer `session_id`, exact actor/run). Errors never expose
raw child output. Lifecycle IDs/scope remain declarations, not ownership proof.

`CaptureSpec::new(operation, snapshot, begin_request, expected_git)` seals a full
typed sink/declaration snapshot: literal paths, finite transport limits, optional
key-file locator, credential environment **names**, explicit endpoint/registry
identity labels, registry actor mapping, Git profile and begin declarations.
Labels alone do not pin mutable registry bytes: `capture_preparation` verifies
bounded no-follow registry bytes against the declared SHA-256 before Begin.
No key values, arbitrary returned environment, argv, prompts or output are stored.
The begin declaration must match the durable allocation's checkout path and primary
task, and the root's run/group/chain/parent context. Additional task refs remain
sealed declarations. Root actor mapping is independent of quota ownership.

Schema 10 adds per-root capture intents/mappings and an indexed checkout barrier;
v9 no-sink run and finish JSON/outbox receipts are not rewritten or backfilled.
Schema checks are shape-only; targeted reads/retries validate related capture/root
history under the existing cumulative 500 ms/200000-instruction SQL budget.
`Store::begin_captured_run` shares the ordinary active/ready writer transaction:
root, writer, capture intent, events and not-ready state commit atomically.
Only `BeginCapturedRun::Created` yields a private, nonserializable, non-Clone
`PreparationHandle`. Existing results are metadata only and never reacquire writers.
An existing no-sink root cannot acquire capture retroactively.

`record_capture_prepared(handle, prepared)` accepts only unchanged, unbound,
unpermitted live context with the exact writer and no hold/outcome/finish fence.
The response must match the sealed actor/run/profile and the public context path
`state-dir/<capture-id>.context.json`. It records typed nonsecret observation data
and readiness, not a runtime Binding or permit. Lost-response
`reconcile_capture_prepared` may attach the same validated binding as held/not-ready
metadata; it cannot mint a handle or restore launch permission. Local intent,
preparation and whole-group observation times are not receiver start times.

Capture operations reserve Work UUIDv7 namespaces; external capture IDs do not.
Captured roots cannot bind/permit before live preparation. Physical writer closure
still requires the original fresh complete full-roster proof. Its transaction
records an immutable whole-group wall observation before exact writer removal,
retains unknown outcomes and flags backward-clock uncertainty. Closure alone retains
capture-incomplete, held/not-ready checkout accounting.
Indexed capture-row presence independently fences every **new ordinary public** writer,
even if checkout flags or mapping JSON are corrupt. Ordinary allocation retries cannot
revive Preparing/reconciled/held capture. Live Prepared own-root identity refresh and
qualified certified-history refresh remain possible; neither grants a new writer.
Only the private certified admission path below permits a subsequent captured root.
Capture metadata never finishes a task or releases charge.

Schema 11 adds a permanent per-allocation `capture_requirements` relation and
operation index. Its allocation-operation reference is the existing reservation
operation, not a second reserved ID. Requirement, charge, allocation intent and
reservation event share one transaction before Git. Migration adds no requirements
to historical allocations and rewrites no allocation/root/finish/capture/outbox bytes.
Requirement presence independently fences all ordinary public writer/root/adopted/
captured-root **new** admission, regardless of forged readiness or allocation JSON.

Explicit `allocation.capture_sink = "devdiary"` plus a valid `[capture]` definition
allows `start` to materialize `capture_pending` (authoritative `partial`, `ready=0`).
A definition alone is dormant. Missing/unknown selected sinks refuse before charging.
Same-operation and matching-task pending receipts retain their original path/charge;
removing current config cannot erase a durable requirement or turn it into no-sink Ready.
No run, execution chain or capture session is invented by `start`.

```toml
[capture]
executable = "/absolute/bin/capture"
registry = "/absolute/private/actors.json"
state_dir = "/absolute/private/capture-state"
timeout_ms = 5000
response_cap = 1048576
# Replace with the explicit canonical lowercase SHA-256 pin for your registry.
registry_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
endpoint_identity = "receiver:example"
receiver_credential_names = ["RECEIVER_TOKEN"]
# key_file = "/absolute/private/key" # locator only, never a key value
[capture.actor_refs]
developer = "actor:example"
```

Paths are literal absolute locators, not shell expressions. The registry identity
snapshot is declared `sha256:<pin>` metadata. The setup-only helper does not inspect
registry bytes; `capture_preparation::prepare` performs actual verification before Begin. Actor mappings and credential names are
bounded to 128 each; all nine projection/runtime environment names are forbidden as
receiver credentials. Without a key-file locator, names must be explicitly nonempty.
Endpoint labels cannot contain userinfo, query or fragment delimiters. TOML is bounded
to 1 MiB and configuration diagnostics never echo supplied values.

Trusted library callers construct a matching selected root snapshot using
`Config::capture_spec(root, allocation, capture_operation, task_refs, source)`.
This selects only the root actor's registry mapping and existing supervisor Git
profile (all four fields), not unrelated actor-map settings. No live runtime/bus
inspection is needed for materialization. Full selected settings are sealed per root.
For first-use capture-pending materialization, `capture_setup::begin(config, root, spec)`
verifies those current selected settings,
registered authority, charged source common directory, actual marker/registration/
branch/path/device/inode/boot identity and pending durable context. Its private,
non-Clone/non-Serde proof binds the exact root/spec/allocation/requirement revision,
expires after two seconds, and never renews its timestamp during reinspection.
Setup first captures owned allocation/charge/source-common/requirement context in a
short bounded SQL read snapshot, then drops both the transaction and SQL phase.
Real bounded Git/filesystem inspection and pre-admission reinspection occur outside
all SQL phases/transactions, under the allocator flock. The IMMEDIATE admission
transaction performs only exact stored-context CAS, eligibility/namespace checks
and original-proof age checks after locking and near handoff; it performs no Git
or filesystem inspection. Only the shared internal admission kernel consumes the
proof; no public flag/DTO can bypass ordinary Ready admission. A new pending root
refuses any prior supervised group on its checkout (including closed/rootless
rows) and disconnected runs with missing groups. These are bounded relational
checks, not a global capture-payload scan or history quota. Refusal retains the
charge and grants no root.

A fresh Created-only handle admits preparation at active/not-ready; matched
`record_capture_prepared` atomically promotes both allocation JSON (`ready`, no reason)
and authoritative readiness. Changed allocation/requirement/writer/root revision,
holds, outcomes and finish fences refuse late promotion. Lost-result reconciliation
remains held/not-ready. Exact historical Existing setup uses the sealed request/spec
without current actor profiles, registry files, filesystem refresh or a new handle.
Returned preparation metadata is not a kernel Binding or actor launch permission.

No capture process is invoked by the setup-only helper. Trusted library callers may
instead call `capture_preparation::prepare(config, root, spec) -> (Store, PreparationResult)`.
It first performs that genuine setup, committing the root/capture intent and exact
writer **before** any receiver process side effect. Setup releases its SQL phases,
transactions and allocator flock before registry/artifact reads and ProcessSink Begin.
`prepare_observed` offers trusted boundary observations, not a fake OS/process selector.
Exact `Existing` returns only its historical `CaptureRecord`: no callbacks, artifact
refresh, receiver invocation, readiness promotion or live result, even if current
profiles, registry, executable and context files are unavailable.

For Created, registry qualification uses bounded nonblocking descriptors with
`openat2` no-symlink resolution across every component, owned regular single-link
0400/0600 files, before/after metadata and a maximum 1 MiB read. Recursive JSON
uniqueness and critical ingest object shapes are checked. Actual `ingest.key_env`
(default `DEVDIARY_INGEST_KEY`) must be explicitly covered by configured receiver
names without a key file. With a key file, its metadata alone is checked using
O_PATH (never secret reads/hashes), and the actual receiver name is still included
in the ephemeral removal-name union, even when the configured list is empty.
Only explicit additional names are included; no prefix or unrelated-key inference.
The derived union is at most 129 names; all nine reserved names remain forbidden.
Key contents may rotate at their stable locator. Endpoint identity remains a label,
not a claim of equality to the registry URL.

State must be owned 0700 with no symlink components. After literal bounded Begin,
registry identity/content is rechecked. The exact returned
`state-dir/<capture-id>.context.json` must be owned, regular, single-link, read-only
0400, bounded to 1 MiB and stable across descriptor/path/directory rechecks. Unique
JSON binds hook schema **string `"1.0"`**, actor/run/parent/primary task, exact typed
execution chain, canonical working directory and timezone-aware RFC3339 start time
to the sealed spec. Object-only actor/run/principal/command positions cannot be
replaced with positional arrays. Principal/display fields are not ownership proof.
No raw context, registry, command, receiver environment or credential values are
logged or journaled. Regular filesystem I/O and kernel D-state can still exceed
hard wall-clock expectations; these checks do not claim a watchdog guarantee.

Only after final artifact revalidation does a private verified-observation method
consume the Created handle through the existing exact preparation CAS. It atomically
promotes allocation JSON/readiness and adds an optional typed context digest/stat
observation. That preparation increment required no change beyond schema 11;
older preparation JSON omits this field unchanged. Current authority requires schema 15.
The public `record_capture_prepared` remains a metadata observer without an artifact
claim. Failures retain tree, charge and exact writer, record the root recovery hold
(without inventing outcome/capture ID), and return no live result. If hold persistence
itself fails, the sanitized error explicitly reports uncertainty; no cleanup or
receiver relaunch is attempted. A root recovery hold does not imply physical closure
or a change of the checkout's `active` accounting state.

Only this new successful path constructs non-Clone, nonserializable, redacted
`LiveCapture`, carrying the seven-key typed projection, receiver removal **names**
and a retained descriptor-backed context proof. `revalidate_context()` performs
actual FD/path/digest reobservation outside SQL at the captured pre-exec boundary.
Neither this value, a decoded `Prepared`, stored observation nor a ready flag mints
a kernel Binding or permit. Lost acknowledgement/retry is metadata-only Existing.
This preparation capability alone does not activate CLI execution.

`supervisor::supervise_captured_with_io` retains the deliberately unfrozen b2 library contract.
It first observes matching open/closed captured history read-only, before current
supervisor/profile/sink/registry dependence. Historic mapping corruption or caller
checkout/explicit actor/chain/literal-command conflict refuses; a no-sink root
cannot acquire capture. Historical receipts never recreate a live capability,
readiness, writer or process. New calls select the explicit root actor or allocation
actor (never quota owner), its trusted Git profile, the allocation's primary task
and the caller's typed chain/literal argv. Pending allocation metadata is read in a
short owned SQL snapshot, without presenting it as ordinary Ready.

Only successful actual preparation supplies `LiveCapture` to private captured
spawn. It binds exact root/input/command/cwd/Git attribution and projects exactly
seven allowlisted keys, clearing absent values. Only configured and actual-registry
receiver credential names are removed; unrelated names and prefix lookalikes remain.
The receiver still inherits its intended credential. Literal OsString argv, cwd,
inherited protocol stdio and original raw-byte runtime-variable presence survive.
No process-global environment mutation or production fake-backend selector exists.

Actual descriptor context checks run outside SQL and allocator flock before blocked
spawn and just before release preflight. Only that actual live reobservation mints a
private non-Clone/non-Serde `CapturedReleaseProof`, timed **before** inspection and
bound to the same live instance/root. Its original two-second age is checked after
allocator lock acquisition and again after owned-root and actual kernel validation,
immediately before permit publication. Generic `OwnedLaunch::release` refuses a
captured launch. Neither the proof nor cached/prepared metadata substitutes for the
original Driver/Binding, owned PID, nonce, lease/journal/finish checks or deadlines.
The captured-only `Boundary::CapturedPreflight` observer runs after proof collection
and before the allocator lock; callbacks never run inside SQL or allocator flock.

Ordinary, b2 captured and integrated captured entrypoints share one
bind/journal/permit/outcome/cancellation/full-roster physical-closure loop. Root exit,
logical child outcomes and Stop acknowledgements never close a writer. Physical closure
records group end before exact writer removal. The b2 entry leaves capture **unfrozen**
and accounting held/not-ready; it never automatically finalizes or restores readiness.
`RunReport::capture_unfrozen` is separate from root outcome, group closure, durable
`checkout_ready`, task openness and charge. Integrated continuation is described below.

Schema 12 adds `capture_finalizations` without rewriting or backfilling old rows.
Its intent, confirmation, revisions and `CaptureFinalizationChanged` outbox events
are separate from the closed root/group revision and its original closure receipt.
`capture_finalization::finalize(config, &run)` requires an established current-schema
store, physically closed group, known root outcome and certain whole-group end.
It commits the exact FINISH intent before invoking the original sealed process
settings. Unconfirmed intent replays FINISH byte-for-byte; confirmed finalize returns
passive `Existing` without a process. `retry_delivery` requires confirmation and only
invokes RETRY. No current actor registry, key or context reread is needed.
`finalize_observed` exposes a callback after intent commit, outside SQL and locks.

Typed snapshots retain receiver-reported start/end/source/attempt/error/receipt facts.
Optional end echoes must match the instant or explicitly qualify as the same
microsecond (receiver truncation); the original nanosecond request is preserved.
Delivered facts and known event identity cannot be downgraded; later session receipts
may refresh. Transport or persistence failures retain the unconfirmed intent (or
previous confirmed evidence). No raw child JSON/stderr is retained.
Only actual matching FINISH plus committed confirmation yields a private-constructor,
non-Clone/non-Serde `FreezeAcknowledgement`. Snapshots, `Existing` and RETRY cannot
mint it. This observation is not readiness authority. `RunReport::capture_delivery`
distinguishes historical frozen-pending/delivered from unfrozen/not-configured.
Standalone terminal APIs leave writer/task/charge/ready flags and the ordinary
ANY-capture-history writer fence unchanged. An acknowledgement alone cannot restore Ready.

#### Operator terminal reconciliation (Task 8.4b candidate)

```text
work capture status <run-id>
work capture finalize <run-id>
work capture retry <run-id>
```

These commands require a UUIDv7 root run and an existing registered current-schema
(15) authority configured by `store_dir`, `trusted_registry` and nonempty `roots`.
They never initialize, migrate or repair an authority. Help/version are read-only;
invalid arguments exit 2 without echoing argument values. Historical operations need
no current supervisor, actor profile or capture selection. Their configuration loader
validates only `store_dir`, `trusted_registry` and `roots`; unrelated current execution,
capture, allocation and repository declarations are ignored, even when invalid.
The bounded, regular-file/no-symlink reader and global TOML syntax checks still apply;
normal execution commands retain full configuration validation.

`status` reads the **WORK journal only**, not the receiver's external status operation.
The allowlisted JSON reports recorded root closure/outcome, actual task-open and
lease-charge facts, preparation, local freeze, delivery and any typed receipt.
`runtime: "not_inspected"` is explicit: these are journal observations, not a fresh
kernel-quiescence claim. Missing capture rows, unprepared mappings, unfrozen roots,
unconfirmed FINISH intents and confirmed frozen roots remain distinguishable.
No settings, source, context, environment, intent body or raw receiver errors are printed.

`finalize` delegates the terminal library API above: only a known-outcome, closed,
certain-end root with its prepared mapping can send the exact original FINISH.
Confirmed results are passive, even if the original executable is gone. `retry`
requires a confirmed freeze and explicitly sends only RETRY, including when already
delivered. Both use sealed per-root process settings rather than current capture
configuration. External I/O holds neither SQL transactions/phases nor lifecycle flock.
Actual FINISH acknowledgements are discarded, never converted into readiness authority.

Post-operation JSON reflects current per-root journal facts. Attempt `response_recorded`
means a validated response was recorded, **not** that this attempt newly delivered.
`receiver_error_recorded` is a boolean only: a failed refresh can retain prior Delivered
and receipt facts. A confirmed local freeze with Pending delivery (including a receiver
delivery error) exits 0; delivery outages are not local-freeze failures. Status and
passive `existing_confirmation` also exit 0. Refusals and `finish_uncertain` /
`delivery_uncertain` exit 1, retaining trustworthy passive observations when available.
If the post-read fails, only constant phase/result-unknown metadata is emitted; no
claim that the external operation had no effect is made.

These commands do not launch/control actors, inspect runtime, finish tasks, release
charges, restore Ready or rewrite a previously recorded task-finish receipt (even its
old Pending delivery). Off/adopted policy, broader privacy work,
real private CLI/HTTP qualification and production
activation remain later work. Tests use synthetic allocation/fake closure fixtures
and disposable public-protocol producers, not the private product or actual kernel path.
This increment does not complete Task 8 or constitute acceptance.

#### Explicit BEGIN metadata recovery (Task 8.4c candidate)

```text
work capture reconcile-begin <UUIDv7-run>
```

This command uses the same existing registered current-schema authority and bounded
metadata-only report as the terminal commands. It **invalidates pre-bind authority**;
it is not a controller-death assertion or proof that an OS process has stopped.
Bound, permitted, adopted, task-fenced or contradictory open roots are refused.
It never creates a new root, launches/relaunches an actor, invokes a Driver, signals,
hands off a writer, grants Ready, finishes a task, releases quota or retires a tree.

For an already prepared pre-bind Intent, it checks and holds the existing metadata
without consulting checkout files, registry or receiver. Preparation bytes (including
live/artifact observations) remain unchanged. Closed known history is passive, even
with a finished task or a newer current writer. An already held open Intent is passive
only after validating its raw task fence and pre-bind eligibility.

For an existing Intent with missing preparation, it inspects the actual allocation,
charged source authority, checkout identity and Git/marker state outside SQL and locks.
Only eligible capture-pending or ready allocation history can replay the **exact sealed
BEGIN and process settings**, not a current profile or caller-provided environment.
The durable intent precedes receiver I/O. First receiver creation is possible here only
because an unprepared Intent could never have released a WORK actor. This does not
attribute any past actor. After a matching response, a fresh physical observation must
match the pre-call observation; the full original durable context must still match under
lifecycle lock and an immediate transaction. Both physical observations retain their
original two-second deadlines, including a near-commit check. No artifact qualification
or live capability is reconstructed: new preparation is recorded with
`live_preparation=false`, checkout not-ready/held and root recovery hold.

`metadata_reconciled` and passive `existing_preparation` exit 0, even though the lease
remains charged and held. Pre-call refusal exits 1 without dispatching BEGIN. Any
transport, codec, physical, lock or commit failure after dispatch reports
`begin_uncertain` (exit 1); a receiver effect may have occurred. Exact replay can be
retried. Concurrent original-creator progress is never overwritten. Untrustworthy
post-read state produces only constant unknown-result metadata.

Tests use disposable real Git worktrees and public-protocol fake producers for the
missing-preparation path, synthetic durable fixtures for known metadata, and private
clock seams for expiry. These are not kernel/private-product or production qualification.

#### Integrated supervised readiness and continuation (schema 13)

`supervisor::supervise_captured_integrated_with_io` is the trusted library entry with
explicit fixture IO. Explicitly configured supervised `work run` uses the same integrated
coordinator with fixed actual manager/helper paths, never a flag/environment fake backend.
Matching captured Existing is metadata-only before current supervisor/profile/receiver/
artifact requirements, including CLI before Driver construction. It cannot relaunch or
recreate a live capability. Ordinary no-sink changed-profile conflicts remain unchanged.
Interactive TTY/job control remains unsupported.

Only Changed full-roster closure with the original Created `LiveCapture` may produce a
private non-Clone/non-Serde closure seal. Cached checks bind the original preparation
frame/spec and authority registry, exact post-close root/capture, current durable allocation
JSON/request, charged identity/current owner, permanent requirement and eligible held state.
Existing closure, stored rows and DTOs cannot mint it. Unknown outcome, uncertain group-end
clock or unrelated holds do not prevent otherwise proved physical closure, but provide no
readiness seal or guessed FINISH claim. Added SQL work shares the original closure proof's
two-second lifetime, with a fresh check near commit.

After committed closure, actual FINISH runs outside SQL phases/transactions and allocator
flock. Only a matching actual `FreezeAcknowledgement` can proceed; passive Existing or RETRY
cannot replace it. New actual source/checkout/marker/branch/private/common/directory/HEAD/boot
inspection and reinspection occur outside SQL and allocator flock. Their original two-second
clock starts before inspection and is never renewed. After allocator and IMMEDIATE locking,
SQL-only exact-context CAS checks and a near-commit age check gate atomic Ready/certification.
Legitimate descendant HEAD is recorded atomically. Changed owner/requirement/allocation,
finish, writer or other conflicting state refuses restoration. Capture/readiness failures
preserve task/charge and known physical closure, rather than inventing root failure or
attempting a closed-root recovery-hold transition. Frozen pending delivery permits Ready.

Schema 13 adds one passive `capture_readiness` certificate per checkout without rewriting
v12 JSON or backfilling certification. It binds the last certified closed run, checkout,
trusted store/registry locators, stable allocation/source/requirement identity, actual
filesystem anchors/marker/certified HEAD, and a versioned domain-separated frontier digest
of target root/capture IDs and immutable frozen intents/context seals. Delivery receipts
and revisions, wall-clock ordering and SQLite rowid are not frontier authority. New root
admission changes that frontier atomically: an old certificate cannot authorize another
root after newer frozen-but-uncertified history, even with forged Ready flags. Work-owned
unrelated readiness revocation marks the certificate revoked in the same transaction;
history is not deleted. Store validation is shape-only; targeted certificate readers are
strict. Historical stale certification during an open root is not global corruption.

A separate private certified continuation proof requires active/Ready state, valid targeted
certification/frontier, all prior captured groups closed/certain/frozen, no writer/adopted/
orphan/finish barrier, current owner/lease/requirement and new root/spec identities. It obtains
fresh actual filesystem evidence, checks descent from the certified immutable HEAD anchor,
and rechecks cached context after locking and original age near commit. It shares the
existing admission kernel: root, writer, capture intent and not-ready state commit together;
Created-only matched preparation restores readiness for that exact root without pretending
an already-Ready allocation was capture-pending. Normal descendant HEAD, qualified boot/device
refresh and post-certification owner transfer need not invalidate certification. No history
count quota or per-history Git inspection is introduced. All ordinary public writer fences
remain intact, and removed capture configuration cannot downgrade a permanent requirement.
Each related captured-history traversal uses one structural child-ledger check and batched
target rosters in its read snapshot, retaining strict root/capture/finalization validation within unchanged
SQL budgets. Validated history is not cached across I/O, mutations or locked transactions.
The generic no-sink library finish path still refuses new completion when current selection
is absent but a permanent requirement or any capture-history row exists. Production explicit
finish instead reconciles that obligation using original per-run settings, as described below.
Authority-wide finish roster preflight batches raw child rows within its read snapshot and
retains every root/child check without parsing unrelated capture JSON.

Certification persists an already **committed** Ready result across CLI processes; it cannot
recover lost/uncommitted live handles or automatically unhold a checkout. It is passive
metadata, not a kernel proof, HMAC or claim of resistance to full same-UID SQL forgery.
Reports keep observed process exit/root outcome, group closure, local freeze, delivery,
durable readiness, task openness and retained charge separate. Reported readiness is an
observation, not fresh physical proof or permission to launch.

Captured adopted execution, complete attribution-off support, full operator recovery,
privacy qualification and real private-CLI/HTTP contract qualification
remain deferred. The bounded initial Off/local-queue increment below does not complete Task 8. Existing credential filtering and bounded public-JSON interoperability are
not a claim that those later reviews are complete. No installation, host-policy changes,
live manager/receiver test or production activation is implied by this implementation.

## Checkout inspection (Task 9 functional pilot)

```sh
work inspect CHECKOUT_UUIDV7
work inspect CHECKOUT_UUIDV7 --record
```

Inspection uses one bounded configuration snapshot: `store_dir`, `trusted_registry`,
`roots` and only the optional `[inspection]` policy subtree. It requires an existing
registered schema-15 authority with an existing qualified `allocation.lock`;
plain inspection and `--record` refuse a missing lock rather than repair it.
A no-create lock descriptor is retained across Store opening and checked against
the named lock and cached authority afterward. This cooperative check does not
prevent hostile same-UID unlink/replacement races. Inspection never initializes
or migrates an authority. Unrelated
malformed execution/capture declarations do not block inspection. An absent policy
section means zero exemptions. An explicit empty section is:

```toml
[inspection]
format = 1
policies = []
```

Nonempty `[[inspection.policies]]` use the strict `disposal::PolicyDocument` format:
explicit ID/version, lowercase-hex relative scope, finite file/byte maxima, exact
file hashes/lengths/modes and complete directory coverage. No glob or extension
exemptions exist. Unknown policy fields and invalid policies are refused.

Plain inspection is nondurable and creates no receipt directory. `--record` freshly
captures context and retained filesystem/Git evidence internally, then explicitly
records provenance in `<store>/inspection-receipts-v1/`. It does not append a caller's
old Observation. The private directory is 0700; immutable single-link files are 0600.
Receipts retain unchanged canonical observation bytes, policy versions, context and
observation digests, authority binding, observation times and an envelope checksum.
No raw SQL rows, file contents, config values, credentials or Git stderr are included.

Receipt envelopes are bounded to 2 MiB, with an independent 16 MiB aggregate and
4096-entry receipt-directory limit. The existing SQLite 16 MiB preflight remains
unchanged. Exclusive `pending-<uuidv7>-<reserved-length>` names charge the entire
declared reservation even when empty; final names are `<uuidv7>.receipt`. Unknown
names, unsafe metadata, links and over-capacity stores refuse append. There is no
pruning, automatic orphan cleanup, adoption or recovery command. Failures before
publication can retain charged pending files. After rename but before confirmed
directory sync, recording reports `durability_unknown` with the ID/digest, not
success or definitely-not-stored. Only file sync, no-replace rename and directory
sync acknowledge a `PersistedReceipt`.

The existing Store-instance exclusive lease covers reservation metadata and the
final exact-context read transaction, followed by SQL-off rename/directory sync.
Payload writes and all checkout/Git/config I/O remain outside SQL and that lease.
The original inspection budget is never renewed. Cooperative filesystem writers
are not stopped: these are observations, not atomic snapshots or quiescence proofs.
The inspector still requires source-qualified Git **2.55.0**; unsupported inputs
remain incomplete. Native Git pathname races and kernel D-state limitations remain.

JSON is a bounded allowlist of coverage, finding counts, observation counts/digest,
`recorded`, `recording`, and an optional `receipt_id`; raw paths/payloads are not
printed. Incomplete coverage, preservation findings or any requested recording
failure exit 1. Exit 0 means only a complete, clear observation, **never deletion
permission**. Valid incomplete provenance may be recorded when its retained context
and inputs still match; recording does not turn it complete. Help and sanitized
argument failures are read-only.

Library `inspection::read_receipt(&Store, id)` is passive and targeted, using an
existing mutable-open current-authority Store handle. It checks bounds, canonical
encoding, checksum, body/header agreement and authority binding, not today's
checkout context. Historical reads cannot reconstruct freshness, original delivery
acknowledgement, writer permission or retirement authority. Inspection and recording
never alter lifecycle, readiness, writers, charges or outbox rows. Task 8 remains
parked; Task 9 acceptance and production qualification are not implied by this pilot.

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
# capture_sink = "devdiary" # only with valid [capture]; start stays capture_pending.
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
identity reconciliation, not invented activity. Configured capture materializes pending;
explicit supervised execution then uses the qualified capture path above. Schema-v1
migration preserves old charges with writer readiness false; doctor remains a no-migration
existing-evidence reader.

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

A previously allocated checkout ID is required: active/ready for ordinary no-sink roots,
or capture-pending first-use / certified active/ready continuation for explicitly configured
captured roots. Explicit `--attribution off` uses the bounded ordinary/initial/qualified
required-Gap classes described below. No implicit allocation, path reuse, repository
discovery or generic held-lease revival occurs. Extend host configuration
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
A closed no-sink group permits a sequential run without another checkout charge.
Captured continuation additionally requires committed readiness certification and fresh
physical admission, not closure or frozen flags alone. Lease charges and task openness
are never released here. Explicit `allocation.capture_sink = "devdiary"` selects integrated
supervised capture; absence of a sink is valid and reports attribution not configured.
Neither route bypasses a permanent capture requirement or an irreversible task-finish fence.

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
runtime qualification claim. It requires an existing initialized trusted schema-15 authority;
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

### Explicit per-run Off and local Gap queue (bounded construction increment)

```sh
work run CHECKOUT_UUID --run-id RUN_UUIDV7 --execution-chain /absolute/chain.json --attribution off -- command arg
```

The option applies to this run only. Omitting it retains the default configured/ordinary
policy; there is no global Off default or `on` value. Public `RootCommand` and
`AttributedCommand` shapes are unchanged. A durable Off marker is intent, not launch authority.

| Supported class | Admission | Immutable queue | After fresh full-roster closure |
| --- | --- | --- | --- |
| OrdinaryUnconfigured | Current selection genuinely absent; Ready allocation; no permanent capture requirement, capture history or certificate | NoTarget / NotConfigured | Ordinary no-sink continuation and receipt-v1 finish remain possible after complete history validation |
| RequiredInitial | First exact capture_pending allocation; permanent requirement; valid selected target; partial/not-ready; no previous run/writer/history | Configured target / Pending, unchanged Gap-v1 bytes | Held, not-ready and charged; an eligible new live closure may qualify a later explicit-Off run |
| RequiredContinuation | Held/not-ready capture_pending allocation; unchanged requirement and original allocation; available qualification from the preceding required Gap; fresh same-boot/actor/exact-target checks | New distinct Pending event and Gap-v2 predecessor link | Held, not-ready and charged; each eligible new live closure may qualify the next explicit-Off run, never generic Ready or new task finish |

Other combinations refuse. Off cannot repair an uncertain captured intent, change a past
run's mode, bypass a certificate, or mix ordinary/captured/adopted history into a required
Gap chain. Root exit/cancellation alone never releases a writer. Required Gap closure is
not task completion.

Required continuation is future-live-only. An actual Changed full-roster close using that
run's private live metadata may qualify known Completed, Failed or Cancelled outcomes;
qualification does not reinterpret failure/cancellation as success. Unknown outcomes,
recovery-only closure, legacy closed rows, lost/abandoned qualification and reboot never
gain eligibility through reads, Existing, reconcile or backfill. Process restart in the
same boot may consume an already committed qualification only through fresh admission
checks. Same-ID Existing is always passive and never republishes or relaunches.

The new run derives its actor/Git profile and public destination/removal metadata from
its own immutable Config and actual pinned registry, then compares the same Work actor
and exact sealed target. No key values, producer or session artifacts are read for Off.
Fresh physical observations retain all four source/checkout/private/common directory
identities and marker bytes. HEAD may advance only as an immutable-object descendant of
BOTH the original allocation HEAD and the latest qualified HEAD; rewinds, divergence and
non-HEAD replacements refuse. Neither allocation identity nor old records are rewritten.

Qualification is durable Work-only provenance, not a decoded live capability or perpetual
physical freshness. A private once-used close seal produces two equal complete physical
observations in one original two-second window before atomic qualification publication.
Each next admission and release has its own fresh observations. Predecessor claim, new
Root/group/writer/Gap/event and cursor transition commit together. Actual owner/context
or independent safety revocation permanently blocks the checked eligibility epoch, even
when owner or visible held flags are restored; no-op/refused attempts do not revoke.
The existing authority lease excludes participating revokers through actual permit
publication, not the actor lifetime. A later committed hold blocks future qualification,
not an already issued permit. Publication failure preserves committed physical closure,
outcome, held state and charge; there is no public retry publisher. A committed qualification
whose acknowledgement was lost may be freshly consumed by a DIFFERENT run; a qualification
that never committed remains unavailable. Neither case gives same-ID retry live authority.

Schema 15 adds empty required-Gap eligibility and closure-qualification tables.
Migration does not backfill old runs or rewrite historical records. Older-version
writer processes and Store handles must be quiesced before migration and must not
write the new authority afterward; overlapping old writers are unsupported.
This is a deployment prerequisite, not permission to operate on a live authority.

Schema 14 adds an immutable typed non-session Gap decision/local queue without rewriting
old Root, capture, readiness, finalization, receipt or outbox bytes. Its exact public
AttributionGap event uses `operator_attribution_off`. A separate generic
`AttributionGapRecorded` journal notification cannot acknowledge the typed queue.
Pending means **local intent recorded, transport deferred**, not sent or delivered.
There is no queue consumer, acknowledgement or Delivered API, and no fabricated
BEGIN/FINISH, capture ID, session, freeze or receiver call.

Matching Off retries return the same recorded event before current execution profiles,
registry or runtime work. Conflicts/corruption refuse rather than falling through to a new
run. Run/status/finish observations distinguish event recording, execution, physical closure,
charge and delivery. Status includes actual checkout state/readiness and required-Gap
limitations, with `required_continuation` origin for Gap-v2. Qualification payloads and
public-target/removal metadata are not report fields; historical metadata never restores
live launch or closure authority.

Off filters verified receiver credential names plus `AGENT_ATTRIBUTION_CONTEXT`,
`DEVDIARY_ATTRIBUTION_CONTEXT` and `DEVDIARY_CAPTURE_ID` from owned helper/actor commands.
It preserves declared Work Git identity, unrelated raw bytes and original delegate runtime
address presence/bytes. It never changes the caller's global environment.

Recovery uses one immutable configuration-document snapshot. Strict historical validation
and closed/unbound/unverified-host receipts precede unused target/runtime declarations.
Open bound Gap inspection combines sealed receiver names with the current selected host's
actual pinned registry names (complete deduplicated union at most 129); no current supervisor
Git actor profile, producer, key value or session artifact is needed. Genuine selection None
uses sealed names even if the old registry is gone. Unqualifiable current selection stays
held before runtime inspection. Ordinary/captured recovery gains no new capture dependency.
`recover_with_config` shares this removal/physical core; configuration-less library `recover`
cannot inspect an open bound Gap. No historical metadata becomes live/release authority.
Normal execution configuration still requires and validates execution actors.

A later selected sink blocks a **new** NoTarget Gap finish before either library callbacks
or integrated capture aggregation. Neither required origin supports a new task-finish
receipt. Already-persisted receipts remain passive and unchanged. Generic Ready, capture
certificates, transport/ACK and mixed-frontier continuation remain unsupported.
This is construction/testing only: no live private-product/systemd qualification, transport,
retirement, deletion, uncharging, operational activation or whole-Task-8 completion.

### Explicit task finish (retirement disabled)

`work finish <checkout-id>` requires a UUIDv7 and existing trusted, managed allocation.
It never initializes missing authority. A read-only established-authority preflight can
upgrade a valid v8/v9/v10/v11/v12/v13/v14 store to schema 15; malformed schemas, missing tables, views, incorrect
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

No sink is a valid completion (exit 0) only without current selection, permanent requirement
or captured history. Genuine historical NotConfigured receipts never upgrade or rebind.
Production finish uses a private integrated policy; the trusted library-only `LocalSink`
seam retains its separate binding/callback guards. No public bypass selector is introduced.

Captured completion also accepts previously-Ready allocation JSON held after closed groups,
not incomplete creation, open/adopted/orphan writers or unrelated holds. Actual source,
marker, registration, branch, directory and HEAD-descent inspection occurs outside SQL and
lifecycle flock. The original two-second observation lifetime and exact allocation/current
owner/requirement/history snapshot are checked after locking and near commit. Descendant
HEAD refresh commits with the task fence; no temporary Ready state or writer is granted.

TaskFinished commits **first**. While still holding the lifecycle lock, a shared pure-SQL
helper prepares every known per-root FINISH intent. Intent failure does not undo task truth.
All SQL phases and lifecycle flock end before capture processes run. Confirmed roots are
passive; unconfirmed roots use the exact original capture ID, terminal outcome/end and sealed
settings, even after current selection/profile/registry removal. Lost responses leave local
Pending with per-run Unconfirmed observations; retries replay FINISH, never RETRY to establish
freeze. Unknown outcome/clock, missing maps, zero maps or family mismatch remain incomplete,
without guessing outcomes or inventing sessions. Frozen requires at least one map and every
root locally confirmed; delivery is Pending if any confirmed root remains pending.

Frozen task receipts never refreeze or implicitly retry delivery. Historical configured
Unsupported/Failed receipts may reconcile genuine original maps, but cannot retroactively
begin capture. Receipt v1 fields and exact case-sensitive capture-binding hashes are unchanged;
there is no schema migration or historical backfill. Capture-result persistence failures retain
the already committed task fence and recorded receipt. Raw JSON, stderr, credentials, prompts
and argv are not included in finish observations or errors.

Reports distinguish task completion, unchanged run outcomes, local freeze/delivery,
incomplete evidence, held lease, retained charge and retirement `disabled`/action `none`.
Top-level freeze/delivery describe the recorded task receipt; each `run_outcomes[].capture`
is a current passive per-run observation. A later explicit delivery reconciliation can
therefore show Delivered per run while the immutable Frozen task receipt still says Pending.
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
Status is read-only existing-schema-15-authority metadata, with
`adopted_basis="checkout/session declaration"`, `git_identity_controlled=false`,
`automatic_quiescence=false`, `runtime="unknown"`. Declared closed is **not verified
exited**. Reads, silence, reboot, missing SessionEnd, reconciliation, and even all
logical closures never release the adopted writer, finish a task, change checkout
state or uncharge it. The writer remains explicitly held until a future qualified
handoff path (operator quiescence/retirement approval is Task 10). `work status --run`
and `work recover` remain supervised-only; the full contained supervised roster requires
fresh whole-group kernel proof, while pending/unverified children block handoff.
Use `work adopt status` for adopted metadata. Existing-authority reads require schema 15.
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
- Git must support the fixed `--no-replace-objects` and `--no-lazy-fetch` flags.
  Unsupported flags fail closed, never fall back or probe a remote. Authority checks
  ignore replacement objects, neutralize legacy grafts with `GIT_GRAFT_FILE=/dev/null`,
  and disable lazy fetching; synthetic parents cannot prove HEAD descent. The minimal
  Git environment still disables hooks, fsmonitor and credential helpers.
- Linux is the supported platform; live runtime qualification is not implied by Linux.
  Other operating systems are unsupported.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
