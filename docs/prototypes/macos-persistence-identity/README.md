# macOS persistence and boot identity — throwaway native prototype

**Question:** can the approved host-local, OS-acknowledged persistence/identity contract be realized without silently accepting weaker SQLite syncing or rebinding copied/restored identities?

**Verdict:** native file **and directory** `F_FULLFSYNC` succeeded on the observed APFS volume. The boot provider is usable for repeated read-only observations and a versioned, fail-closed representation is plausible. **Unmodified locked SQLite plus PRAGMAs is not sufficient evidence for a mandatory full-sync contract:** it silently falls back to ordinary `fsync`, and its directory-sync path ignores failures. A strict SQLite sync/error-propagation mechanism and native qualification on the agreed macOS versions remain blockers to accepting the complete approach. This is a candidate contract/options report, not a human acceptance decision or a port.

- Ticket: [Demonstrate macOS persistence and boot-identity boundaries](https://github.com/techwright-lab/work-cli/issues/24), under [the Apple Silicon map](https://github.com/techwright-lab/work-cli/issues/13).
- Source baseline: `41d01c3a6f1ea2bafcc7432240f725c55c810781`; observed 2026-11-06.
- Boundaries: [approved safety contract](https://github.com/techwright-lab/work-cli/issues/16#issuecomment-6686126937), [operation-specific storage policy](https://github.com/techwright-lab/work-cli/issues/22#issuecomment-6686716683), [prior primary-source research](https://github.com/techwright-lab/work-cli/blob/research/macos-safety-primitives/docs/research/macos-safety-primitives.md).
- Only disposable scratch fixtures were deliberately written. No real store, authority, repository lifecycle, credentials, installation/configuration, mount, reboot, VM or power-loss action was used. The supplied baseline was read-only. No Rust toolchain was installed or invoked for compilation.
- Scope exception from a diagnostic: `xcrun --show-sdk-version` failed and Apple's tool automatically wrote an error result bundle outside scratch. No further `xcrun` was used; compilation selected an already-present SDK directly. No external cleanup was attempted. No private paths or bundle contents are published.

## 1. Exact observed environment

| Item | Observed |
|---|---|
| OS / architecture | macOS **27.0.1**, build **26A434**, ARM64 |
| Kernel | Darwin **27.0.0**, XNU **13432.1.9~1**, RELEASE_ARM64_T6041 |
| Scratch filesystem | `fstatfs` reports **apfs**; no blanket admission conclusion follows |
| Compiler / SDK | Apple clang **21.0.0** (`clang-2100.3.34.2`), explicit existing macOS **27.0** SDK |
| Python | system **3.9.6** |
| Executed SQLite | **system 3.54.0**; CLI identifies Apple source `8fa8248e303219400c646a885e36dfc52eae33d83f4412e3f369b2be5373aapl` |
| Project pins, inspected only | Rust **1.98.1**, rusqlite **0.38.0**, libsqlite3-sys **0.36.0**, bundled SQLite **3.51.1** |

This host is **not** the map's macOS 15/26 qualification matrix. Neither the pinned Rust binary nor full bundled SQLite transactions were built/run. The native C probe links system SQLite. The separately compiled fallback probe executes only an exact extracted function with fake syscalls, not the bundled library. `results/matrix.json` records all matrix observations; `source_manifest.json` identifies retrieved public sources and hashes.

## 2. Native sync results

`native_probe.c` opens only a newly created fixture, retains descriptors, writes a regular file, then creates/renames/unlinks its name. Each row below represents both calls, executed in the order `fsync` then `F_FULLFSYNC` on the same FD:

| Descriptor / boundary | `fsync` | `fcntl(F_FULLFSYNC)` |
|---|---:|---:|
| regular file, RW, after write | 0 | 0 |
| directory, RO + `O_DIRECTORY`, after create | 0 | 0 |
| directory, RO + `O_DIRECTORY`, after rename | 0 | 0 |
| regular file, RO, after rename | 0 | 0 |
| directory, RO + `O_DIRECTORY`, after unlink | 0 | 0 |
| invalid FD negative control | -1 / **EBADF (9)** | -1 / **EBADF (9)** |

There was also an initial independent run with the same outcomes. In the process-exit marker case, dirty marker data and its parent after rename were full-synced directly (without an immediately preceding ordinary `fsync`) successfully. The native matrix reports calls rather than hiding unsuccessful results. This does not inject EIO/ENOSPC into real filesystem syncing or qualify failure propagation in production.

**Meaning:** the OS acknowledged the requested operations on these descriptors. Apple documents that ordinary `fsync` can leave drive-cache/order exposure and that `F_FULLFSYNC` requests a stronger device flush. Device/controller honesty, actual stable-media writes and survival of power loss were **not measured**. APFS copy-on-write, clean reopening, or a successful one-time capability probe does not prove future flushes succeed. Directory full-sync failure is **not an observed blocker here**; it would be a mandatory hold on a target where the chosen contract requires it and it fails. Do not silently substitute ordinary directory `fsync`.

### Exact pinned Rust behavior (source, not a Rust execution)

Rust **1.98.1** [`File::sync_all`](https://github.com/rust-lang/rust/blob/1.98.1/library/std/src/fs.rs) delegates to the platform file's `fsync`. The inspected [Unix implementation, lines 1413–1434](https://github.com/rust-lang/rust/blob/1.98.1/library/std/src/sys/fs/unix.rs#L1413-L1434) uses `libc::fcntl(fd, libc::F_FULLFSYNC)` on Apple for **both** `sync_all` and `sync_data`; the surrounding `cvt_r` propagates errors/retries interrupted calls, with **no ordinary-fsync fallback**. `sync_data` is not a way to avoid the Apple directory full-sync requirement. Baseline `store.rs::sync_dir` calls `File::open(path)?.sync_all()?`. The C directory result supports that native primitive on this host, not compilation/qualification of the pinned Rust stdlib.

## 3. SQLite: settings, fallback, and directory caveat

System SQLite was given WAL, `synchronous=FULL` (readback **2**) and disabled automatic checkpointing. A table transaction and explicit FULL checkpoint succeeded in each configuration (return **0**, **3/3** WAL frames checkpointed):

| System 3.54.0 configuration | `fullfsync` readback | `checkpoint_fullfsync` readback |
|---|---:|---:|
| No explicit full-sync PRAGMAs | 0 | **1** |
| Explicit checkpoint full-sync ON only | 0 | 1 |
| Explicit full-sync ON and checkpoint full-sync ON | 1 | 1 |

**Important vendor distinction:** upstream documentation describes both defaults as off, but this Apple system library actually has checkpoint full-sync ON. An in-memory CLI query reports `sqlite_compileoption_used('DEFAULT_CKPTFULLFSYNC') = 1` (`results/system-sqlite-vendor.txt`). No system default is transferred to the project's bundled build. These successful commits/checkpoints and PRAGMA readbacks are **not syscall traces** and do not prove any actual SQLite `F_FULLFSYNC` call succeeded.

The project enables `rusqlite`'s `bundled` feature. Its locked crate archive SHA-256 was verified as `95b4103cffefa72eb8428cb6b47d6627161e51c2739fc5e3b734584157bc642a`; its `sqlite3.c` identifies **3.51.1**. The exact archive source establishes:

1. SQL `synchronous=FULL` selects SQLite's synchronization policy; it is distinct from `PRAGMA fullfsync=ON`. `checkpoint_fullfsync=ON` alone does not cover all WAL commits. With `fullfsync=ON`, the checkpoint setting is redundant for selecting full-sync mode.
2. `full_fsync`, lines **42973–43039**, calls `osFcntl(fd, F_FULLFSYNC, 0)` for a full sync, **then uses ordinary `fsync(fd)` if that fails**. Success of the fallback is returned as success.
3. `unixSync`, lines **43106–43153**, separately opens/syncs the directory once with `full_fsync(dirfd, 0, 0)` and **ignores the directory sync result** (also tolerates an unavailable directory open). Full-sync PRAGMAs do not turn this into checked directory full-sync.

The extracted-function harness compiles that function unchanged, with fake calls, and asserts all four cases:

| Synthetic case | full-sync calls | ordinary-sync calls | result |
|---|---:|---:|---:|
| ordinary only | 0 | 1 | 0 |
| full-sync succeeds | 1 | 0 | 0 |
| full-sync EINVAL, ordinary sync succeeds | 1 | 1 | **0** |
| full-sync EINVAL, ordinary sync EIO | 1 | 1 | -1 |

This confirms the fallback's control flow; it is **not injected failure of the actual system or bundled SQLite VFS**. No bundled transaction behavior is claimed tested.

## 4. Bounded process-exit observations

With system SQLite full-sync settings ON, a child terminated via `_exit(77)` at three explicit points, skipping SQLite close/normal cleanup. The parent reopened the fixture and observed `integrity_check = ok`:

| Exit boundary | committed event rows | final marker present |
|---|---:|---:|
| before transaction COMMIT | 0 | no |
| after COMMIT, before marker | 1 | no |
| after marker write/full-sync/rename/parent full-sync | 1 | yes |

This demonstrates the **need for reconciliation**, especially committed SQL with an absent marker; it is not a real Work outbox/removal-journal test. `_exit` is an abrupt process exit, not a kernel crash, reboot, random SIGKILL schedule or loss of the OS page cache/device power. Only one run per boundary was performed. No simulated filesystem damage or real-state recovery was attempted.

## 5. Boot and copied-object identity observations

`identity_probe.py` calls `sysctlbyname("kern.bootsessionuuid", ..., newp=NULL, newlen=0)` read-only five times over approximately half a second. All reads returned **37 bytes**, **36 uppercase UUID characters plus NUL**, canonical values equal. Actual host UUID and fixture inode/device numbers are intentionally not published. XNU exports this as `CTLFLAG_RD | CTLFLAG_LOCKED` [in the inspected source](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_sysctl.c#L2921-L2923). That establishes an interface, not its entire reboot/VM-restore lifecycle.

The candidate provider strictly frames the native 37-byte string, rejects invalid/nil UUIDs, and canonicalizes hexadecimal case to lowercase **before** persistence/comparison. It does not use `.strip()`, permit unexpected newline/NUL framing, invent fallback boot IDs or require a particular UUID version. Provider and record schema are tagged separately; integer fields survive a JSON round trip. Illustrative **synthetic** representation:

```json
{
  "schema": "work-host-local-identity/v1",
  "boot": {
    "provider": "darwin-kern.bootsessionuuid/v1",
    "uuid": "12345678-1234-4234-9234-123456789abc"
  },
  "store_object": {"device": 123, "file_id": 456}
}
```

Eleven negative cases refused: absent bytes, missing NUL, extra newline, embedded NUL, bad hex, nil UUID, incompatible Linux provider, valid-but-changed boot during collection, copied fixture root, changed boot requiring reconciliation, and historical unversioned schema. Native boot changes/malformed kernel responses were **not induced**; those provider inputs are synthetic only. A newly created directory and a copied directory contain identical synthetic marker bytes, but their root object tuples differ, so the same-boot comparison refuses the copy. Original fixture comparison succeeds; serialization and case normalization checks succeed.

**Identity limits:** this is a refusal/representation model, not a descriptor-anchored store admission implementation. Its simple `(device,file_id)` comparison detects the ordinary fixture copy, not every snapshot/restore, inode reuse or a cloned VM preserving all observable identities. A UUID stored inside the copied database is not independent host binding. Production needs live root/registry/marker bindings and retained-object checks, provenance/domain checks, and fresh reconciliation; historical Linux/unversioned records must remain history, not be relabeled or rewritten. Device IDs are not assumed stable across reboot. There is no automatic same-object admission after boot change in this model, and no reboot grants deletion/replay/charge-release authority.

## 6. Concrete candidate contract and choices to accept later

**Candidate A — explicit full-sync ACK, fail closed (recommended for the next feasibility step, not selected human policy):**

1. Before admitting each mutating operation, qualify the affected storage's required creation, identity, locking and persistence properties. Do not make this a universal prerequisite for diagnostics or impose a blanket filesystem ban on unrelated paths.
2. For staged file publication, write fully → mandatory file `F_FULLFSYNC` ACK → checked publish/rename → mandatory retained-parent `F_FULLFSYNC` ACK → only then acknowledge that publication. Apply equivalent checked ordering to new directories, markers and journal/ref publication. A failed/unknown post-publication ACK means **possibly changed, held**, not rollback or permission to retry destructive work. Retain evidence and charge.
3. Use WAL + `synchronous=FULL` + explicit `fullfsync=ON` on every relevant connection, **plus a mechanism that actually enforces and exposes required full-sync and directory ACK failures**. Mandatory failures must stop successful workflow acknowledgement/dispatch and retain history/charge. PRAGMA readback and an initial successful probe are not enforcement.
4. Bind durable operation IDs/digests to SQL intent, associated markers and observations. Consume fresh checked ACKs in the operation's state machine before subsequent dependent side effects; committed SQL/missing marker is a reconciliation case. Recorded native success still needs fresh anchored absence and separately confirmed stopped writers before charge reconciliation. Uncertain dispatch is never automatically replayed.
5. Read boot evidence around collection and at consequential revalidation boundaries. Missing/malformed/changing provider evidence holds the operation. Persist versioned provider/domain data rather than using raw native formatting as a boot transition. New boot invalidates ephemeral observations and requires durable-evidence reconciliation; copied/restored/incompatible identity is not implicitly adopted.

**What realizes item 3 remains a specific blocker, not an approved implementation:**

- **Option A1: strict SQLite VFS/binding or a narrowly maintained bundled-source change** that propagates `F_FULLFSYNC` failure rather than silently succeeding through fallback, and provides checked directory syncing at namespace boundaries. Verify every relevant WAL/checkpoint/journal/initialization path, including independent connections and newly created sidecars. Safe Rust integration must respect the existing `forbid(unsafe_code)` policy. This prototype does not add a dependency, patch SQLite or choose its maintenance policy.
- **Option A2: a separately proved explicit barrier protocol** over retained/revalidated SQLite/WAL/database and parent handles under appropriate writer/checkpoint exclusion. Apple's `fcntl` manual documents that full-sync drains earlier fsynced I/O on the same device. That is a possible ingredient, **not proof that a post-COMMIT flush retroactively establishes every internal SQLite ordering/error condition**. A pathname reopen, a marker flush alone, or successful COMMIT is insufficient. This alternative needs an ordering proof and failure/crash tests before acceptance.
- If a target cannot full-sync directories, **hold the affected mutation under candidate A**. A documented same-device protocol using checked ordinary directory `fsync` followed by mandatory full-sync on a suitable retained FD could be investigated using the cited device-flush semantics; it is not an automatic fallback or an accepted equivalent. Directory operations must be proved included, not inferred from file success.
- Merely defining the guarantee as “whatever weaker syncing SQLite happened to do” would change the proposed stronger contract. That is **not recommended or silently accepted** here; only the human decision owner can choose a precisely restated boundary consistent with the approved safety constraints.

Thus native directory support does not currently prevent the candidate on this host; **undetected SQLite fallback/directory failure does prevent claiming that the unmodified baseline meets it**. This is not evidence that every compliant implementation is impossible.

## 7. Remaining evidence and manual gates

No manual action was requested or performed in this lane. Any later right-pane handoff needs separate explicit operator authorization and disposable fixtures; the following are evidence needs, **not commands to run now**:

- Repeat native file/directory ACK and negative-error tests on the agreed **macOS 15 and 26** APFS configurations (including separately qualified case variants and participating locations). This macOS 27 host does not satisfy that gate.
- Run the **exact pinned Rust toolchain and bundled SQLite build**, trace/instrument actual VFS syncs and inject full-sync-only, ordinary-sync, parent-sync, ENOSPC and checkpoint failures. Prove the selected strict mechanism refuses success and keeps evidence/charge; validate sidecar namespace ordering and all operation-specific persistence boundaries.
- On a separately authorized disposable system, observe boot identity/host-local object bindings through actual full reboot and relevant sleep/wake/userspace-restart behavior. Reopen/reconcile fixtures without rewriting stored identities. VM snapshot/restore and volume remount semantics remain unmeasured, not approved actions.
- Controlled VM/device power-loss tests are distinct and currently unavailable in this lane. Neither process exit nor orderly reboot proves stable-media/power-loss behavior; no universal hardware-failure guarantee is proposed even after testing.
- Review/accept a concrete versioned identity compatibility and recovery contract, including copied/restored history and the limits of clone detection. Obtain human reaction to this report and select/accept a strict persistence mechanism before closing the ticket. No issue closure, map edit, PR, merge, release or production integration is authorized by this artifact.

## 8. Reproduce and inspect

Copy only this artifact directory into a **new disposable writable directory** on the documented host/SDK and run:

```sh
/usr/bin/python3 run_probes.py
```

The runner uses strict C11 `-Wall -Wextra -Werror -pedantic`, fixed per-command timeouts, a 20-second C alarm, local compiler temporaries and exclusively new fixture directories; it refuses an existing matrix result/fixture instead of cleaning or reusing it. `fetch_sources.py` downloads bounded public sources and verifies the locked crate checksum, extracting only named files (no archive path extraction). No automatic toolchain install or SDK discovery occurs. The documented SDK must already exist. Native I/O can still be kernel-blocked; the alarm/timeout is not a proof of hard-bounded uninterruptible filesystem I/O.

Published inputs/results: `native_probe.c`, `identity_probe.py`, `sqlite_fallback_probe.c`, `fetch_sources.py`, `run_probes.py`, `source_manifest.json`, `results/matrix.json`, `results/system-sqlite-vendor.txt`. No binaries, downloaded full upstream sources, fixture databases, UUIDs, private paths or credentials are published.

### Primary-source links

- Apple [`fsync(2)`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/fsync.2) and [`fcntl(2)`, especially full-sync/device barrier semantics](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/fcntl.2#L207-L245). These inspected XNU documents are not a measured guarantee for every deployed device or supported OS floor.
- Exact [Rust 1.98.1 Unix file sync implementation](https://github.com/rust-lang/rust/blob/1.98.1/library/std/src/sys/fs/unix.rs#L1413-L1434).
- SQLite [`synchronous`](https://sqlite.org/pragma.html#pragma_synchronous), [`fullfsync`](https://sqlite.org/pragma.html#pragma_fullfsync), [`checkpoint_fullfsync`](https://sqlite.org/pragma.html#pragma_checkpoint_fullfsync). Live documentation retrieval is hashed, not an immutable release snapshot.
- [Locked libsqlite3-sys 0.36.0 archive](https://static.crates.io/crates/libsqlite3-sys/libsqlite3-sys-0.36.0.crate), verified against baseline Cargo.lock; readable matching [full_fsync and unixSync source](https://github.com/rusqlite/rusqlite/blob/v0.38.0/libsqlite3-sys/sqlite3/sqlite3.c#L42973-L43153). Archive bytes, rather than a movable release tag alone, are the authority for the extracted synthetic probe.
