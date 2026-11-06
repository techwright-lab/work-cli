# S1: pinned SQLite source and Darwin acknowledgement enforcement

Issue #35, accepted `doc/specs/2026-11-06-native-macos-support.md` §6.
This is a source-enforcement slice, **not completed Work durability integration or
native qualification**. Root `[patch.crates-io]`, root lockfile dependency edge,
connection configuration and checked lifecycle/checkpoint boundaries belong to
subsequent integration. There is no version bump or system SQLite substitution.

## Provenance and drift gates

- Exact crate: `libsqlite3-sys` **0.36.0**, from the immutable versioned URL
  `https://static.crates.io/crates/libsqlite3-sys/libsqlite3-sys-0.36.0.crate`.
- Archive SHA256, checked against the baseline root `Cargo.lock` **before parsing
  or extraction**:
  `95b4103cffefa72eb8428cb6b47d6627161e51c2739fc5e3b734584157bc642a`.
- SQLite **3.51.1**, source ID
  `2025-11-28 17:28:25 281fc0e9afc38674b9b0991943b9e9d1e64c6cbdb133d35f6f5c87ff6af38a88`.
  This upstream source ID is retained; it does **not** identify patched bytes.
- Original `sqlite3/sqlite3.c` SHA256:
  `ff57e8d0a1572b35c17cab9a7dea34616bc12b6fb8b29acf5cb00b6ecf025149`.
- Patched `sqlite3/sqlite3.c` SHA256:
  `3eff5da4fd92cd6c6c756139534ccf2a5bb17fd611daf93b748f05438841a8fe`.
- `provenance.json` records all 26 named original members, all vendored file
  hashes, and both patch hashes. All original files are retained, including
  upstream license, bindings and unused SQLCipher sources. Only `sqlite3.c`,
  `build.rs`, `Cargo.toml` and `Cargo.toml.orig` differ from the crate.
- `darwin-required-ack.patch` is the exact C delta; `vendor-glue.patch` is the
  separate build/manifest delta. The offline verifier checks every vendored input
  and reverses both exact, line-numbered patches to the original member hashes.
  There is no fuzz, offset acceptance, download, or automatic upgrade.
- The vendored `build.rs` hashes C/header/bundled-binding inputs with the already
  workspace-locked `sha2 =0.10.9` **for the macOS target, not the build host**, before
  any linked-library escape path. Mismatch is fatal. macOS system/SQLCipher/
  loadable-extension/in-gecko substitution is rejected. Darwin C compilation
  rejects `SQLITE_NO_SYNC`, `SQLITE_DISABLE_DIRSYNC` and missing `F_FULLFSYNC`.
  This is a reviewed-build integrity gate, not hostile compiler/toolchain defense.

Offline verification (through the disposable wrapper):

```sh
tools/qualification/container.sh -- python3 tools/qualification/sqlite/verify.py
tools/qualification/container.sh -- python3 -m unittest discover -s tests/qualification -p test_sqlite_patch.py
WORK_QUALIFICATION_GIT_VERSION=2.56.0 tools/qualification/container.sh -- python3 -m unittest discover -s tests/qualification -p test_sqlite_patch.py
```

For an independently obtained **local** archive, the import tool verifies the
fixed archive SHA256 before opening the tar, validates the complete allowlisted
regular-file membership (no duplicate/extra/link/path-escape members), verifies
all member hashes, then writes into a **fresh** destination:

```sh
python3 tools/qualification/sqlite/verify.py --extract-crate /owned/path/libsqlite3-sys-0.36.0.crate --destination /owned/fresh/upstream
```

This produces the original crate, not the patched tree. Reproduction applies the
two retained deltas to those exact members; the verifier's `apply_patch` rejects
context/line-number drift. Updating any pin, patch, build hash or dependency
version requires source and boundary re-review, not merely regenerating hashes.
Builds consume committed bytes and never fetch SQLite source at build/run time.

## Exact boundary-to-acknowledgement mapping

All behavioral changes below are `__APPLE__`-guarded. Shared `walIndexClose`
return-type plumbing is mechanical; Linux still discards the same results, uses
its existing sync flags, directory handling and deletion policy. No Linux
checkpoint policy changes are made.

| Boundary / exact seam | Darwin acknowledgement and failure result | Limits / checked caller |
| --- | --- | --- |
| `full_fsync(fd, fullSync, dataOnly)` | When `fullSync!=0`, require `fcntl(F_FULLFSYNC)` itself to succeed; **no ordinary `fsync` fallback**. NORMAL requests still use ordinary `fsync` and return its failure. | Does not turn NORMAL requests into mandatory full sync. Connection/pager flags remain an integration obligation. |
| `unixSync` file phase | Return `SQLITE_IOERR_FSYNC` on failed file acknowledgement before attempting directory ACK. | Existing pager/WAL callers must check `xSync`. |
| `unixOpen` creation classification -> `UNIXFILE_DIRSYNC` -> first successful `unixSync` | Existing CREATE journal/super-journal/WAL handles plus CREATE main-DB handles require containing-directory open and `F_FULLFSYNC`. | CREATE flags can also be used for existing files; re-acknowledgement is intentional. No claim that `xOpen` alone acknowledges publication, or that `synchronous=OFF` is safe. |
| `unixSyncDirectory` (internal static helper) | Check `osOpenDirectory` result and valid nonnegative FD (reject sandbox no-op); require directory `F_FULLFSYNC`; close the held FD. Open failure is returned unchanged (`SQLITE_CANTOPEN` in Unix VFS); sync failure is `SQLITE_IOERR_DIR_FSYNC`. | `unixSync` retains `DIRSYNC` on failure and clears it only after success. Close is resource cleanup, not an additional durability certificate. |
| `unixOpenSharedMemory` | After successful shared-memory lock/init, writable SHM publication requires directory ACK before attaching connection. On failure use existing `shm_open_err` cleanup and return error. | SHM content is reconstructible coordination, **not durable database content**. Read-only opens, heap/exclusive-memory mode and another connection's existing shared node do not create a new namespace entry here. Failed publication may already have created a sidecar; no rollback/cleanup ownership claim. |
| `unixDelete` (`xDelete`) | Preserve unlink errors, including `SQLITE_IOERR_DELETE_NOENT`; after successful unlink require directory ACK **even when caller passed `dirSync=0`**. | Journal finalization (`pager_end_transaction`), empty-DB WAL removal (`pagerOpenWalIfPresent`), super-journal deletion (`vdbeCommit`) and other checked `sqlite3OsDelete` callers receive the error. An error after unlink means possibly changed, not rollback. |
| `unixShmUnmap` last-reference deletion | Check SHM unlink and directory ACK; purge/close existing resources and return first error instead of unconditional success. | No deletion/ACK when other shared-node references remain. Error does not resurrect the unlinked name. |
| `walIndexClose` -> `sqlite3WalClose` | Return `xShmUnmap` failure to checked WAL-close path. Preserve an earlier checkpoint error. Do not unlink WAL after failed SHM cleanup. Check WAL `xDelete` and its directory ACK when deletion is requested. | `sqlite3PagerCloseWal` already checks `sqlite3WalClose` (e.g. explicit WAL-to-rollback journal-mode transition). Close/checkpoint can already have changed durable state before returning an error. |

The only modified C function definitions are `full_fsync`, `unixSync`,
`unixOpenSharedMemory`, `unixShmUnmap`, `unixOpen`, `unixDelete`, `walIndexClose`
and `sqlite3WalClose`, plus the new private `unixSyncDirectory`. The other
`walIndexClose` callers (`sqlite3WalOpen` error cleanup and `walIndexReadHdr`
error cleanup) still discard its result; those calls do **not** request deletion
and already return an error. No new exported SQLite or Rust application API,
application unsafe code, environment fault switch or runtime download is added.

## UNSOLVED S3 integration obligations (not waived by this patch)

- Default automatic checkpoint handling still swallows checkpoint errors. On
  macOS disable it on **each** connection and establish checked explicit
  checkpoint policy/order before dependent effects. A checkpoint API that returns
  OK/busy or partial progress needs appropriate result/progress interpretation.
- `sqlite3PagerClose` discards `sqlite3WalClose` results. `sqlite3_close` /
  `sqlite3_close_v2` success and Rust destructors are **not** mandatory durability
  certificates. No lifecycle redesign or sticky-error API is attempted in S1.
- Some upstream `sqlite3OsDelete` calls discard results: pager rollback/cleanup
  paths, super-journal error cleanup/collision handling and related recovery
  paths. They are visibly **pending** where an operation would need a checked
  deletion certificate. S1 does not convert those callers to checked boundaries.
- Pager/WAL flags and internal ordering still need actual bundled-build tests:
  initialization, independent connections, WAL header/restart, explicit checkpoint,
  commit vs checkpoint requirements, namespace transitions, and post-commit
  uncertainty. PRAGMA readback/probes do not prove enforcement.
- A reported error can follow a successful commit, unlink, or publication. Work
  must preserve/reconcile evidence and holds; do not infer rollback or replay
  destructive work because a later ACK failed.

Accordingly **not all successful SQL, checkpoint, or close results certify all
mandatory durability boundaries**. Source-level seams are not store integration.
Accepted OS ACKs are not universal hardware stable-media, reboot or power-loss
proof.

## Evidence classes and bounded test controls

1. **Exact-source extracted control flow:** `run_harness.py` extracts unchanged
   function bodies and the exact creation-classifier expression/flag assignment
   from the hash-verified patched amalgamation. C harnesses substitute bounded
   syscall/SQLite support stubs. `--mode darwin` selects the Darwin branches on
   Linux; it is **not native Darwin compilation or APFS behavior**. Tests cover
   full-sync-only failure (ordinary sync succeeds), ordinary-sync failure,
   DB/WAL/main/super-journal creation classification, directory open/sync and
   invalid-FD refusal, SHM creation/open/delete, WAL delete errors, preservation
   of checkpoint error, successful controls and Linux legacy behavior (with and
   without synthetic `HAVE_FULLFSYNC`). Calls assert fewer than ten per operation,
   temporary fixtures are owned, and compile/run subprocesses have finite
   timeouts. Fault choices are C-local counters, never production environment
   variables. CLI mode choices are closed; no retry count or unbounded input.
2. **Whole-amalgamation Linux compile/smoke:** `whole_linux.py` compiles the complete
   pinned patched `sqlite3.c` directly, links **no system SQLite**, and exercises
   rollback journal, WAL, independent connection, checked truncate-checkpoint and
   WAL-to-DELETE transition in temporary state. This proves Linux compile/basic
   SQL viability, not Rust linkage or injected Darwin propagation.
3. **Actual Work-linked bundled/native gates:** **NOT RUN in S1**. Root Cargo patch/
   lock and store integration are separate. The build-time Rust source gate is
   present but its execution requires that integration/dependency fixture. Native
   execution waits for reviewed H1. Required actual bundled fault gates remain:
   full-sync-only and ordinary-sync failure, directory open/sync failure, creation/
   deletion/sidecar errors, ENOSPC/write errors, explicit checkpoint/restart/
   ordering failures and post-commit unknown-outcome behavior. Native macOS15/26 ×
   Git2.55/2.56 and authorized reboot evidence remain separate support gates.

Direct source compile commands (also run by the unittest module):

```sh
tools/qualification/container.sh -- python3 tools/qualification/sqlite/run_harness.py --mode darwin
tools/qualification/container.sh -- python3 tools/qualification/sqlite/run_harness.py --mode linux
tools/qualification/container.sh -- python3 tools/qualification/sqlite/whole_linux.py
```

This slice does not claim full workspace/release readiness. Full locked workspace,
Clippy, packaging, artifact smoke and native fault/reboot gates must be recorded
at the integrated candidate, separately from these source-control-flow checks.
