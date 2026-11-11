# Darwin hot-journal acknowledgement correction

Status: operator-approved bounded design. The approved scope snapshot is
`d3c09bc11ef6b73b93f858160b8159555ed2f758`, independently reviewed by `b691f8b1`.
The operator approved the revised scope and resource limits after that review.
Implementation still requires a reviewed plan and measured batch admission.

Baseline: `5fdc6b560c6c4bc0e0f000c19d7419ceee533f32`.
Parent: native Apple Silicon support, issues 30/31. The integrated S3a-P
compile-selection feature is not full S3a qualification or native admission.

## Terms and document location

- **FULL and NORMAL:** SQLite file-sync modes. `PRAGMA synchronous=FULL` is a
  separate SQL setting; it does not itself select `SQLITE_SYNC_FULL`.
- **F_FULLFSYNC:** Darwin's strong storage-flush request. Its acknowledgement is
  not proof of complete lifecycle durability.
- **VFS:** SQLite's virtual filesystem interface.
- **WAL:** write-ahead logging. A rollback journal is a different recovery file.
- **S3a:** the connection and acknowledgement safety stage in the
  [native specification](2026-11-06-native-macos-support.md). **S3a-P** is its
  preceding compile-selection feature, not runtime acknowledgement proof.
- **H2:** the reviewed native qualification harness,
  `tools/qualification/native-macos.sh`. macOS27/SDK27 results are development
  evidence, not supported-platform qualification.
- **FileSize and journalHdr:** the file-size operation and pager field that record
  the journal extent after synchronization.
- **sum=42:** an arithmetic SQL smoke test. It proves query execution, not
  filesystem error propagation or durability.
- **Wave retention:** all retained agent artifacts for the native-port work.
- **Envelope:** a task's allocation within the total artifact ceiling. An
  unassigned envelope is not extra capacity or a Work authority quota.

Paths are repository-relative unless they start with `_vault/`. Vault paths
start at the TechWright workspace root. The current native-port specs and plans
retain a recorded placement exception in the Work CLI vault documentation index.
See `_vault/products/work-cli/docs/reports/2026-11-09-darwin-hot-journal-design-review.md`.
This exception creates no duplicate design or repository/vault symlink.

## Problem and current Work settings

`pagerSyncHotJournal` synchronizes a recovery journal before recording its size
and permitting playback. The pinned SQLite 3.51.1 function requests
`SQLITE_SYNC_NORMAL`, independently of the connection's `fullfsync` setting.

Work's explicit sync setting is `PRAGMA synchronous=FULL` (`crates/work/src/store.rs:314`).
Production Rust does not enable `fullfsync` or `checkpoint_fullfsync`.
Under the reviewed defaults, ordinary commit and WAL file-sync requests therefore
remain NORMAL and use ordinary `fsync()` on Darwin.
This correction does not strengthen those file-sync paths. Existing directory
acknowledgements already use a separate strong-sync policy.

Moving Rust setters earlier does not solve the recovery problem alone.
Preparing the `synchronous` setter can initiate recovery before assigning its
requested safety level. Main-file open/header reads also precede Rust settings.
Automatic extensions execute before SQLite open returns.

## Why a Work open can encounter a rollback journal

The writer factory accepts regular journal sidecars at `crates/work/src/store.rs:287–292`.
It queries `user_version` at line 307, before checking WAL mode at lines 315–325.
SQLite checks for a hot journal before opening an existing WAL in this path.
The later Work WAL requirement therefore does not prevent earlier recovery.

Candidate exposure routes include:

- An initialization crash before the WAL transition completes.
- An interruption during the authorized transition to WAL.
- A stale, stray or foreign journal that passes Work's existing file checks.

These are fixture candidates, not proof that every such interruption creates a
hot journal. SQLite still applies its lock, page-count and journal-header checks.
Zero-page and malformed-journal paths can behave differently.
Future application tests must use SQLite-produced crash states and record which
checks lead to this helper. They must not treat arbitrary journal bytes as a
realistic recovery fixture or as permission to repair foreign history.

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
   Merely honoring `pPager->syncFlags` is insufficient: recovery can precede
   connection settings, and initial persistent-file flags are NORMAL.
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

The same helper serves shared-lock recovery and pager close. A helper error
prevents normal playback progression during shared-lock recovery.

## Availability and close-path consequences

If the journal's `F_FULLFSYNC` fails, `unixSync` returns `SQLITE_IOERR_FSYNC`.
The writable open cannot pass this recovery step. There is no ordinary-fsync
retry, journal deletion workaround or automatic history repair.
Preserve the database, journal, history and quota for a reviewed recovery action.

Some filesystems or virtualized mounts can reject `F_FULLFSYNC`.
Network storage, exFAT media and FUSE-backed mounts require specific qualification.
A filesystem class name alone establishes neither support nor failure.
This correction deliberately sacrifices availability when the requested strong
acknowledgement is unavailable. `noSync` and earlier refusal paths remain distinct.
Native managed-operation admission remains closed throughout this slice.

A close with an open journal can also request the stronger acknowledgement.
When synchronization is required, this can add syscall and latency cost.
If synchronization fails, the pager records an error and skips rollback and
journal finalization. The journal can remain for the next user's recovery.
The pager close function still returns `SQLITE_OK`.
This design does not repair that lost caller-visible close error.

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

1. Ordinary commit and WAL file synchronization remain weaker under Work's
   current settings, as described above. Checked connection settings remain
   separate S3a work.
2. Successful `pager_playback` also calls `sqlite3PagerSync` for the recovered
   **database**. Its initial flags can still be NORMAL. That producer needs a
   separate reviewed correction or justified policy before complete S3a.
3. Work precreates its main DB and opens without CREATE. CREATE-classified
   directory acknowledgement does not certify earlier main-DB publication.
4. WAL/SHM recovery, ignored deletion/close results and checkpoint effects need
   separate coverage. Darwin automatic checkpoints remain enabled today.
5. No runtime VFS-contract PRAGMA, safe file-control wrapper, named-VFS policy or
   private Store checked-connection API is selected here.
6. Errors can follow changed or committed outcomes. Preserve payload, history,
   quota and uncertainty. Do not infer rollback, replay permission or release.

## Deterministic test-first oracle

Extend the existing qualification harness and extractor. Extract the actual
`pagerSyncHotJournal` implementation from the pinned amalgamation alongside the
actual `full_fsync`, `unixSync` and required directory helper. Minimal test-only
Pager and FileSize stubs may supply inputs and record calls.
The `sqlite3OsSync` stub must forward to the real extracted `unixSync`.
It must not merely record flags and return a fabricated result.
The extracted `unixSync` must reach the extracted `full_fsync` implementation.
Only its operating-system calls use the bounded fault stubs.

The existing harness is never linked into Work. Its new results establish
extracted control flow only, **not actual Work-linked VFS fault propagation**.

Required observations:

- Genuine RED against unchanged source: `noSync == false`, Darwin expects FULL;
  the actual NORMAL request causes the intended assertion failure. Setup,
  provenance, compiler and admission failures are not valid RED.
- Use `ctrlFlags=0` for the primary recovery-journal fixture. Recovery reopens
  the journal with READWRITE and MAIN_JOURNAL, without CREATE (`sqlite3.c:64316`).
  This path does not set `UNIXFILE_DIRSYNC` or perform directory synchronization.
- Strong file success: verify FULL selection, file acknowledgement before
  FileSize, and journalHdr supplied by successful FileSize.
- File-only `F_FULLFSYNC` failure/ENOTSUP while ordinary fsync would succeed:
  require `SQLITE_IOERR_FSYNC`, no fallback, zero directory calls, no FileSize
  and no journalHdr change.
- An optional DIRSYNC variant is supplementary, not the realistic recovery case.
  It must also prove that file failure returns before directory handling.
- Other sync failure propagates without FileSize. FileSize failure propagates,
  including a control whose failing callback modifies its output argument.
- `noSync == true`: zero sync calls and preserved FileSize behavior.
- Non-Apple build: retain NORMAL and existing fallback behavior. Compare the
  non-Apple helper tokens/control flow, not whole-amalgamation byte identity;
  inserted source lines can affect diagnostics using `__LINE__`.
- Preserve all **29 current portable controls**: the original 23 plus six
  marker controls. Preserve existing native build guards as well.
  Report journal-specific assertions separately. They supplement existing cases.

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

Retain independent RED and GREEN records.
Check exact reconstruction, provenance and guards.
Run both Linux matrices and applicable locked check, format and strict Clippy checks.
Then compile a fresh native application-marker check with the new C input.
Do not reuse old-C native linkage evidence as an exact new-C execution claim.
Complete supported-platform and actual Work fault qualification remain separate.

Retained Linux matrix fixtures range from approximately 0.45 to 0.73 GiB each.
One retained native fixture had these approximate component sizes:

- Source: 26,960 KiB.
- Private Cargo home: 203,032 KiB.
- Target: 301,980 KiB.
- Evidence: 34,948 KiB.

These are measured references, not a future peak guarantee.

The following paragraphs retain the **pre-approval scoping record**.
They do not describe the current approved ceiling.

The combined preliminary estimate is 2.5–3.8 GiB additional, **not admission**.
Recorded wave retention was 17,501,986,816 bytes under the 18-GiB ceiling.
Approximately 1.7 GiB of aggregate headroom remained.
Only 0.02 GiB of envelope allocation was unassigned.
Neither amount authorizes the proposed verification programme.

**The next resource action belongs to the parent agent.** Prepare staged
estimates, then request an operator ceiling decision before implementation.
A proposed 22-GiB total ceiling would cover the upper planning estimate with
additional margin. It is not approved by this document.
Keep the 10-GiB physical-free floor and full batch reserves unchanged.
If the operator retains 18 GiB, pause or propose a smaller programme.
Do not drop required gates or use cleanup, exclusions or deletion credit.

**Subsequent operator decision:** the revised scope and resource request are approved.
The current limits are 22 GiB total and 4 GiB additional for this programme, including reserves.
The 10-GiB physical-free floor and preservation holds remain binding.
The [implementation plan](../plans/2026-11-09-darwin-hot-journal-ack.md) defines proposed staged allocations.
No executable batch is admitted by the ceiling decision alone.

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
