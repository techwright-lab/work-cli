# Darwin hot-journal acknowledgement correction

Status: proposed bounded design. The operator approved pursuing a Darwin C
correction while preserving journal recovery. Detailed implementation and heavy
qualification require design review and separate resource admission.

Baseline: `5fdc6b560c6c4bc0e0f000c19d7419ceee533f32`.
Parent: native Apple Silicon support, issues 30/31. The integrated S3a-P
compile-selection feature is not full S3a qualification or native admission.

## Problem and boundary

`pagerSyncHotJournal` synchronizes a recovery journal before its size is recorded
and playback may proceed. In the pinned SQLite 3.51.1 amalgamation, it requests
`SQLITE_SYNC_NORMAL` even when connection-local `fullfsync` is enabled.

This is not repaired merely by moving Rust PRAGMA setters earlier. Preparing the
`synchronous` setter can load schema and initiate recovery before assigning the
requested safety level. Main-file open/header reads also precede Rust
configuration; automatic extensions run before SQLite open returns.

The bounded contract is:

> When `pagerSyncHotJournal` requires synchronization (`noSync == false`),
> Darwin requests the strong journal acknowledgement before proceeding to
> FileSize/journalHdr processing. A failed acknowledgement propagates through
> this helper without ordinary-fsync fallback or FileSize processing.

This contract concerns the journal acknowledgement, not every recovery effect,
connection profile, close result or durability outcome.

## Considered approaches

1. **Recommended: narrow pager journal correction.** Select FULL in this helper
   on Apple targets; retain NORMAL elsewhere. Existing patched Unix FULL-sync
   handling already requires `F_FULLFSYNC` without Darwin fallback. This is a
   small, reviewable correction with an exact-source test oracle.
2. **Force every Darwin VFS NORMAL request to FULL.** Broader policy and
   performance change affecting unrelated producers. Not selected here.
3. **Ban existing journals or bypass recovery.** Changes recovery/admission
   semantics and risks abandoning valid history. Rejected for this work.

## Proposed source change

In `vendor/libsqlite3-sys/sqlite3/sqlite3.c`, change only the sync-mode selection
inside `pagerSyncHotJournal` (baseline approximately lines 63031–63040):

- `defined(__APPLE__)`: request `SQLITE_SYNC_FULL`.
- All other targets: retain the existing `SQLITE_SYNC_NORMAL` expression.
- Preserve the `!pPager->noSync` branch, error return and sync-before-FileSize
  ordering. Do not temporarily mutate `pPager->syncFlags`.
- Do not change callers, transaction/replay decisions, VFS NORMAL handling or
  public SQLite/Rust interfaces.

The same helper is called during shared-lock recovery and pager close. A helper
error prevents normal playback progression in the former path. The close caller
can record a pager error yet return `SQLITE_OK`; this design does not claim to
repair caller-visible close errors.

## Preconditions and deliberately preserved behavior

- Persistent-file defaults currently yield `noSync == false`, but build flags
  and registered extensions can affect defaults and ordering. Five input hashes
  and a generated marker do not independently establish those runtime facts.
  Qualification must record its actual compiler inputs and assumptions.
- `noSync == true` remains a bypass: no sync is attempted, FileSize still runs,
  and journalHdr may advance. This is explicitly **not** strong acknowledgement.
- Ordinary read-only hot-journal handling refuses before the writable recovery
  helper; it must not be replaced with immutable access.
- The immutable-empty bootstrap exception remains narrowly scoped to existing
  initialization exclusion and absent sidecars. It is not writer recovery.
- On sync failure, FileSize is not called and journalHdr is unchanged by this
  helper. On FileSize failure, propagate its error; its output argument must not
  be assumed unchanged.
- Existing native managed-operation refusal and Git `AccessUnproven` stay closed.

## Known gaps: not hidden by this correction

1. Successful `pager_playback` also calls `sqlite3PagerSync` for the recovered
   **database**. Its initial flags can still be NORMAL. That producer requires a
   separate reviewed correction or justified policy before complete S3a.
2. Work precreates its main DB and opens without CREATE. CREATE-classified
   directory acknowledgement does not certify earlier main-DB publication.
3. WAL/SHM recovery, ignored deletion/close results, checkpoint scheduling and
   possibly committed effects need their own coverage. Disabling Darwin automatic
   checkpoints and interpreting workflow effects are not implemented here.
4. No runtime VFS-contract PRAGMA, safe file-control wrapper, named-VFS policy or
   private Store checked-connection API is selected by this design.
5. An error may follow a changed/committed outcome. Preserve payload, history,
   quota and uncertainty; do not infer rollback, replay permission or release.

## Deterministic test-first oracle

Extend the existing qualification harness and extractor. Extract the actual
`pagerSyncHotJournal` implementation from the pinned amalgamation alongside the
actual `full_fsync`, `unixSync` and required directory helper. Minimal test-only
Pager/file-dispatch/FileSize stubs may supply the inputs and record calls; they
must not replace the recovery helper with a rewritten algorithm.

The existing harness is never linked into Work. Its new results establish
extracted control flow only, **not actual Work-linked VFS fault propagation**.

Required observations:

- Genuine RED against unchanged source: `noSync == false`, Darwin expects FULL;
  the actual NORMAL request causes the intended assertion failure. Setup,
  provenance, compiler and admission failures are not valid RED.
- Strong file success: verify FULL selection, file acknowledgement before
  FileSize, and journalHdr supplied by successful FileSize.
- File-only `F_FULLFSYNC` failure/ENOTSUP while ordinary fsync would succeed:
  require `SQLITE_IOERR_FSYNC`, no fallback, no FileSize and no journalHdr change.
  Directory success must not mask a failed journal-file acknowledgement.
- Other sync failure propagates without FileSize. FileSize failure propagates,
  including a control whose failing callback modifies its output argument.
- `noSync == true`: zero sync calls and preserved FileSize behavior.
- Non-Apple build: retain NORMAL and existing fallback behavior. Compare the
  non-Apple helper tokens/control flow, not whole-amalgamation byte identity;
  inserted source lines can affect diagnostics using `__LINE__`.
- Preserve all existing 23 original controls and subsequent marker/build guards;
  new cases supplement rather than replace them.

Actual Work-linked hot-journal creation, syscall interception traces, owned-FD
classification, extended SQLite/Work errors and uncertain-outcome handling remain
future S3a acceptance gates. Standalone SQLite or sum=42 is not that oracle.

## Provenance, ownership and implementation discipline

One bounded writer owns the C correction, existing C patch, corresponding
qualification harness/extractor/tests and exact provenance consequences.

Expected affected files include:

- `vendor/libsqlite3-sys/sqlite3/sqlite3.c`;
- `patches/sqlite/darwin-required-ack.patch` and `provenance.json`;
- the C input digest in `vendor/libsqlite3-sys/build.rs` and its corresponding
  `patches/sqlite/vendor-glue.patch` reconstruction;
- `tools/qualification/sqlite/ack_harness.c`, `run_harness.py`, relevant
  `tests/qualification/test_sqlite_patch.py` cases and associated documentation.

Inspect the source delta before accepting digests. Reverse and forward
reconstruction must exactly recover the approved upstream member and final
vendor files, including all four glue sections. Upstream archive/member pins,
SQLite version and the other four mandatory guarded inputs remain unchanged.
Keep mandatory target verification before route selection, fatal marker-write
failure and marker generation after successful bundled compilation.

No application unsafe, direct dependency, Cargo/lock change, package-version or
changelog bump, general connection-policy change, journal ban or admission
activation is part of this slice. Any additional source owner or changed file
requires explicit review, not an opportunistic expansion.

## Verification and resource gates

Before each executable batch, retain a measured owned-fixture estimate, full
observation reserve, current cumulative charge and physical-free measurement.
Use the prescribed Linux container wrapper, including
`WORK_QUALIFICATION_GIT_VERSION=2.56.0` for the second fixture. Native development
checks use reviewed H2, fresh destinations and the explicitly selected installed
SDK/toolchain, without real repositories or credentials.

Plan independently retained RED/GREEN, exact reconstruction/provenance and guard
checks; both Linux matrices and applicable locked check/format/strict Clippy
checks; then a fresh native application-marker compilation for the new C input.
Do not reuse old-C native linkage evidence as an exact new-C execution claim.
Complete supported-platform and actual Work fault qualification remain separate.

References measured during scoping include Linux matrix fixtures of differing
sizes (approximately 0.45–0.73 GiB each) and a native fixture with roughly
26,960 KiB source, 203,032 KiB private Cargo home, 301,980 KiB target and 34,948 KiB
evidence. These are retained references, not a future peak guarantee.

The combined preliminary estimate is 2.5–3.8 GiB additional, **not admission**.
Latest recorded wave retention was 17,501,986,816 bytes under an 18-GiB ceiling;
approximately 1.7 GiB of aggregate headroom and 0.02 GiB unassigned envelope do
not authorize the proposed verification programme. Refine staged estimates and
obtain any necessary resource approval before code/heavy fixtures. No pruning,
cleanup, exclusion or deletion credit is assumed.

## Acceptance and handoff

Accept this bounded source correction only after genuine RED/GREEN, preserved
non-Apple/bypass/error semantics, exact provenance reconstruction, applicable
verification and independent SPEC then QUALITY review.

Do not close full S3a, native support or release qualification on that basis.
Historical fingerprint status remains UNRESOLVED/HELD. Existing normalized
source-package blockers, native strict-Clippy debt, invalid local full-lifecycle
qualification, macOS15/26 × both Git/APFS coverage and final signed/notarized
artifacts remain outstanding. No push, publication, normal installation,
authority mutation, mount/reboot or checkout removal is authorized.
