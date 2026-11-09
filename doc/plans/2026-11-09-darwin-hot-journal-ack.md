# Darwin hot-journal acknowledgement implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task. Follow the established one-writer, SPEC, separate QUALITY, then serial-integration workflow. Steps use checkboxes for tracking.

**Goal:** Require Darwin FULL journal acknowledgement in `pagerSyncHotJournal` without changing non-Apple recovery behavior.

**Architecture:** Extract the real pager helper into the existing syscall-fault harness. Forward its sync call through the extracted `unixSync` and `full_fsync`. Change only the helper's Apple sync argument, then reconstruct the complete vendor patches and provenance.

**Tech stack:** SQLite 3.51.1, vendored libsqlite3-sys 0.36.0, C99, Python qualification tooling, Rust 1.98.1 and pinned Linux Git fixtures.

---

## Authority and boundaries

The operator approved the revised [design](../specs/2026-11-09-darwin-hot-journal-ack-design.md) at `d3c09bc11ef6b73b93f858160b8159555ed2f758`.
Independent design review `b691f8b1` found no blockers.
The operator approved **22 GiB total retained artifacts** and **4 GiB additional for this programme**, including reserves.
Neither approval admits an executable batch without fresh measurements.

Use the existing temporary plain-Git-worktree exception.
Do not run Work onboarding, change authority configuration or nest a worktree inside another task checkout.
Planning stays in the supplied integration checkout. Implementation uses one new sibling checkout.

Only Darwin journal sync selection changes in production C.
Keep non-Apple NORMAL, `noSync`, error propagation, FileSize output semantics and callers unchanged.
No application Rust, root Cargo/lock edge, version, changelog, public API or connection-setting changes are permitted.
Do not enable native managed operations or weaken `AccessUnproven`.

The following remain separate gates: recovered-database sync, ordinary commit/WAL settings, close errors, uncertain effects and actual Work-linked faults.
Supported macOS15/26 qualification, full lifecycle, source packaging and signed/notarized release remain incomplete.
No push, installation, signing, publication, cleanup, pruning or checkout removal is authorized.
Historical failed aggregates and the unresolved preservation hold remain held.

## File responsibilities

All paths below are relative to the implementation checkout.

| Path | Responsibility and permitted delta |
|---|---|
| `tools/qualification/sqlite/ack_harness.c` | Minimal Pager/FileSize model, real sync dispatch, fault controls and journal assertions |
| `tools/qualification/sqlite/run_harness.py` | Extract the real helper; retain generated C and distinct binaries for each variant |
| `tests/qualification/test_sqlite_patch.py` | Regression for retained harness artifacts and existing extracted-source tests |
| `vendor/libsqlite3-sys/sqlite3/sqlite3.c` | Apple FULL versus non-Apple NORMAL inside `pagerSyncHotJournal` only |
| `patches/sqlite/darwin-required-ack.patch` | Exact upstream-to-final C reconstruction, preserving all older hunks |
| `vendor/libsqlite3-sys/build.rs` | Replace only the guarded C digest |
| `patches/sqlite/vendor-glue.patch` | Reconstruct the changed build.rs; retain all four target sections |
| `patches/sqlite/provenance.json` | Update only derived hashes for the reviewed deltas |
| `tools/qualification/sqlite/README.md` | Add dated observations and remaining limits; preserve historical records |

Parent-owned plans, resource records and vault findings are separate from this writer's source scope.
An additional changed source file requires review before proceeding.

## Execution variables and resource admission

The parent binds these variables once and retains their resolved values:

```sh
I=/Users/ravi/projects/techwright/work-cli-worktrees/integration
W=/Users/ravi/projects/techwright/work-cli-worktrees/darwin-hot-journal-ack
P="$W/target/darwin-hot-journal-ack"
SEED="$I/target/container-cargo/registry"
```

`P` is a new programme namespace, not an old evidence directory.
The programme charge includes the entire new checkout, all retained fixtures, registry copies, targets, logs and transient peaks.
Do not count only `P` or deduct COW extents.

| Admission stage | Maximum including full observation reserve |
|---|---:|
| Source checkout, TDD and provenance | 0.20 GiB |
| Git2.55 portable SQLite matrix | 0.80 GiB |
| Git2.56 portable SQLite matrix | 0.80 GiB |
| Linux workspace checks | 1.25 GiB |
| Native application compilation | 0.85 GiB |
| Unallocated programme contingency | 0.10 GiB |
| **Programme total** | **4.00 GiB** |

Each executable stage retains its full 64-MiB observation reserve.
The parent may allocate contingency prospectively with a recorded justification.
No retrospective overrun repair, deletion credit or automatic cap increase is allowed.
The programme limits are estimates, not a promise that every batch fits.

Before every batch:

- [ ] Measure the programme, all existing wave roots and physical free space.
- [ ] Use allocated `st_blocks*512`, unique `(st_dev, st_ino)` within each lane; sum lanes conservatively.
- [ ] Use reviewed H3 `footprint` logic: three complete attempts, retrying only listed-descendant `lstat` ENOENT.
- [ ] Fail closed on root, walk/scandir, other errors or persistent churn. Use `du` only when quiescent.
- [ ] Retain a full per-path baseline and source/registry hashes. Historical aggregate-only mismatches remain unresolved.
- [ ] Estimate the next batch from measured seed/source/tool outputs; include temporary payload and full reserve.
- [ ] Require stage, programme and wave fit, plus at least 10 GiB projected physical free space.
- [ ] Retain the exact admission, command, deadline and ownership record before launch.

Use one heavy/native slot. Each admitted agent execution has a fresh two-hour window and a checkpoint five minutes before expiry.
Stop on unexpected failure, budget gap or unknown ownership. Report before attempting recovery.
Keep primary errors, secondary diagnostics and all failed evidence distinct.

Linux execution must go through `tools/qualification/container.sh` in a fresh owned source fixture.
The wrapper's checkout must contain only reviewed source and private registry/tool outputs, never real repositories or credentials.
Inspect the exact pinned image and owned mount before releasing commands.
Use the previously reviewed bounded start gate and TERM/KILL/reap/drain protocol.
Do not infer a missing wrapper exit from a later absent container.

For compilation, use locked/offline dependencies, `CARGO_INCREMENTAL=0`, DEV/TEST debug level 0, strip `none` and disabled Cargo auto-clean.
Construct the fixture environment; do not edit global profiles or toolchain configuration.
On Linux, put test temporary files in owned container-native `/tmp` if opaque bytes are needed.
Account their peak and retain required failure payload before terminal handoff.

## Task 1: Establish ownership and retention before journal TDD

**Files:** `run_harness.py`, `test_sqlite_patch.py`; new ignored programme evidence.

- [ ] Parent verifies integration is clean and the plan-review commit is the selected base.
- [ ] Verify `W` and `feat/macos-darwin-hot-journal-ack` do not already exist. Hold on a collision.
- [ ] After source-stage admission, create the sibling checkout:

```sh
BASE=$(git -C "$I" rev-parse --verify 'feat/macos-support^{commit}')
git -C "$I" worktree add -b feat/macos-darwin-hot-journal-ack "$W" "$BASE"
```

- [ ] Register this root in the ledger before further output. Confirm the writer's exact allowed files.
- [ ] Prepare a fresh allowlisted source fixture for the prescribed container. Do not mount `I`, `W/.git` or a user's Cargo home.
- [ ] Within this source-stage fixture, permit only recorded writer-file updates between TDD steps. Preserve prior generated source, binaries and logs first.
- [ ] Keep source-stage registry empty: these focused C/tooling tests do not require Cargo. Never reuse this mutable TDD fixture for final qualification.
- [ ] Add `test_extracted_source_linux_retains_generated_artifacts` to `SqlitePatchTests`.

Use this regression in the existing unittest class:

```python
    def test_extracted_source_linux_retains_generated_artifacts(self):
        parent = ROOT / "target/sqlite-harness-evidence"
        before = set(parent.glob("*"))
        result = subprocess.run(
            [sys.executable, "-B", str(TOOLS / "run_harness.py"),
             "--mode", "linux"], capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        created = set(parent.glob("*")) - before
        self.assertEqual(len(created), 1)
        retained, = created
        for name in ("harness.c", "harness-0", "harness-1"):
            self.assertTrue((retained / name).is_file(), name)
```

Ignore pre-existing entries; never overwrite or delete them.

- [ ] Run the new retention test through the fixture wrapper:

```sh
tools/qualification/container.sh -- python3 -I -B \
  tests/qualification/test_sqlite_patch.py \
  SqlitePatchTests.test_extracted_source_linux_retains_generated_artifacts -v
```

Expected: the old runner fails the artifact-retention assertion, not compilation.
This tooling RED is **not** the required journal-behavior RED.

- [ ] Replace only the temporary-directory lifecycle in `run_harness.py`.

Use `tempfile.mkdtemp` beneath a private owned `target/sqlite-harness-evidence` parent.
Retain the generated C and name each executable `harness-{fullsync}`.
Print the fresh destination before compilation with `flush=True`.
Preserve the existing compile flags, timeouts, verification and mode refusal.
Keep all files after success or failure; do not reuse an existing destination.
Do not add `-I` when invoking `run_harness.py`: it imports the sibling `verify` module.
Use its reviewed private fixture path and a constructed environment without user Python paths.

- [ ] Re-run the exact retention test. Require exit 0 and both retained variants.
- [ ] Preserve raw commands, source, binaries, hashes and actual return codes.
- [ ] Commit only the tooling retention regression and runner change.

## Task 2: Obtain genuine journal-behavior RED

**Files:** `ack_harness.c`, `run_harness.py`.

- [ ] Add `static int pagerSyncHotJournal(` to the exact-source extraction list.
- [ ] Before `/* EXACT_SOURCE */`, provide the minimal Pager and dispatch definitions below.

```c
typedef long long sqlite3_int64;
typedef struct Pager {
  int noSync;
  sqlite3_file *jfd;
  sqlite3_int64 journalHdr;
} Pager;
static int unixSync(sqlite3_file *, int);
static int journal_flags, journal_sync_calls, journal_size_calls;
static int journal_order, journal_ack_order, journal_size_order;
static int journal_size_rc;
static sqlite3_int64 journal_size_value;
static int sqlite3OsSync(sqlite3_file *f, int flags){
  int rc;
  journal_flags=flags;
  journal_sync_calls++;
  rc=unixSync(f,flags);
  if( rc==SQLITE_OK ) journal_ack_order=++journal_order;
  return rc;
}
static int sqlite3OsFileSize(sqlite3_file *f, sqlite3_int64 *size){
  assert(f!=0);
  journal_size_calls++;
  journal_size_order=++journal_order;
  *size=journal_size_value;
  return journal_size_rc;
}
```

These stubs must not return invented sync success or replace the extracted helper.
The FileSize stub deliberately writes its output even on an error.

- [ ] Extend `reset()` to clear journal counters/order/return code and set `journal_size_value=321`.
- [ ] Add a file-only full-sync errno control to `mock_fcntl`. Default it to EIO; permit ENOTSUP.
- [ ] Keep the existing directory-failure behavior and all older assertions intact.
- [ ] Add a journal-test function called by `main`, after the existing controls.

Start with a fresh `unixFile` whose `ctrlFlags=0`, plus `Pager{0, &file, 77}` using the required pointer cast.
On Darwin, success must observe FULL, one full call, no ordinary or directory calls and size 321.
The following assertion must fail against unchanged production C:

```c
assert(journal_flags==SQLITE_SYNC_FULL);
```

- [ ] Compile and run the actual old helper with the new harness:

```sh
tools/qualification/container.sh -- sh -c \
  'ulimit -c 0; exec python3 -B tools/qualification/sqlite/run_harness.py --mode darwin'
```

- [ ] Require successful verification and C compilation, then the expected FULL-selection assertion failure.
- [ ] Record the unchanged production C hash and generated source containing the old NORMAL call.
- [ ] Preserve the failed binary/source, stderr, child signal and outer failure. A separate expected-RED predicate may pass.
- [ ] Do not call the failed wrapper GREEN. Setup, budget or compiler failure is not this RED.
- [ ] Commit only the test/extractor changes after the predicate is independently inspectable.

## Task 3: Make the minimal C correction and reconstruct provenance

**Files:** C amalgamation, C patch, build.rs digest, glue patch, provenance.

- [ ] Change only the sync-mode selection inside `pagerSyncHotJournal`:

```c
  if( !pPager->noSync ){
#if defined(__APPLE__)
    rc = sqlite3OsSync(pPager->jfd, SQLITE_SYNC_FULL);
#else
    rc = sqlite3OsSync(pPager->jfd, SQLITE_SYNC_NORMAL);
#endif
  }
```

- [ ] Inspect the complete production C diff before accepting any new digest.
- [ ] Preserve the old `if( rc==SQLITE_OK )` FileSize branch and return expression exactly.
- [ ] Do not change `full_fsync`, `unixSync`, callers, `syncFlags` or any other C producer.
- [ ] Reverse the pre-change C patch using `verify.apply_patch` and verify the upstream C SHA256.
- [ ] Generate a complete upstream-to-final unified diff using `difflib.unified_diff`, with `a/sqlite3/sqlite3.c` and `b/sqlite3/sqlite3.c` headers.
- [ ] Verify every prior C hunk remains semantically present. New differences must be this helper only.
- [ ] Replace only the C digest in `build.rs`.
- [ ] Reconstruct the build.rs glue section from its pinned upstream bytes. Retain Cargo.toml, Cargo.toml.orig and src/lib.rs sections unchanged.
- [ ] Update only `vendored_files[sqlite3/sqlite3.c]`, `vendored_files[build.rs]`, `patch_sha256` and `glue_patch_sha256` in provenance.
- [ ] Preserve crate/archive/upstream hashes, version, other vendor members and the other four mandatory input digests.
- [ ] Run `python3 -I -B tools/qualification/sqlite/verify.py` through the fixture container.

Require exact reverse and forward reconstruction for C and all four glue targets.
Do not run a blanket hash refresh over unreviewed source.

## Task 4: Complete the deterministic journal oracle

**Files:** `ack_harness.c`, relevant existing qualification tests.

- [ ] Add the remaining assertions below. Use separate resets and retain distinct output for each mode.

| Case | Required result |
|---|---|
| Darwin, sync required, `ctrlFlags=0`, success | FULL; one full call; no ordinary/directory calls; ack order before size order; journalHdr 321 |
| Darwin, EIO full failure, ordinary sync would succeed | IOERR_FSYNC; one full call; zero ordinary/directory/size calls; journalHdr 77 |
| Darwin, ENOTSUP full failure, ordinary sync would succeed | Same refusal and unchanged journalHdr; no fallback |
| Sync failure while DIRSYNC is set, supplementary | Failure before directory open; DIRSYNC remains set; no FileSize |
| Non-Apple ordinary-sync failure | NORMAL; IOERR_FSYNC; zero FileSize calls; journalHdr 77 |
| Successful sync, FileSize error after writing output | Exact FileSize error; one size call; journalHdr 321, not assumed unchanged |
| `noSync=1` | Zero sync/full/ordinary/directory calls; FileSize still runs; journalHdr 321 |
| `noSync=1`, FileSize error after writing output | Exact size error; no sync; modified output retained |
| Non-Apple success | NORMAL; zero full calls; ordinary sync succeeds; then FileSize |

- [ ] Run both exact-source modes through the prescribed Linux wrapper:

```sh
tools/qualification/container.sh -- sh -c \
  'ulimit -c 0; python3 -B tools/qualification/sqlite/run_harness.py --mode darwin && python3 -B tools/qualification/sqlite/run_harness.py --mode linux'
```

- [ ] Require Darwin and both Linux HAVE_FULLFSYNC variants to pass, without dropping older assertions.
- [ ] Compare non-Apple helper tokens/control flow to the original helper. Whole-amalgamation bytes can differ because `__LINE__` moves.
- [ ] Retain GREEN independently of RED. Index generated C, binaries, commands, source hashes and return codes.
- [ ] Commit the minimal production/provenance change and complete oracle after source-stage observation fits its cap.

## Task 5: Fresh portable qualification on the final source

**Files:** no production edits; ignored evidence and dated README observations.

- [ ] Freeze the final tracked source revision and complete input inventory.
- [ ] Prepare two fresh, independent owned Linux SQLite fixtures from that revision.
- [ ] Seed only the approved registry bytes into each private Cargo home. Verify the seed before and after.
- [ ] Admit each matrix separately; run Git2.55 first and Git2.56 second:

```sh
tools/qualification/container.sh -- python3 -I -B -m unittest discover \
  -s tests/qualification -p test_sqlite_patch.py -v
WORK_QUALIFICATION_GIT_VERSION=2.56.0 tools/qualification/container.sh -- \
  python3 -I -B -m unittest discover -s tests/qualification -p test_sqlite_patch.py -v
```

Each command runs in its own fresh source fixture, not the implementation checkout.
The current file defines 16 test methods. Record the actual executed new count, including skips, failures and errors.
Require all **29** named build controls, whole Linux SQL smoke, provenance faults and both extracted modes.
New journal assertions do not replace those controls or establish Work-linked faults.

- [ ] After separate workspace-stage admission, prepare a fresh owned workspace fixture.
- [ ] Resolve actual installed toolchain executables without invoking a rustup shim through a renamed symlink.
- [ ] For each selected Git fixture, run the following commands through its wrapper:

```sh
tools/qualification/container.sh check --locked --offline --workspace --all-targets
tools/qualification/container.sh fmt --all -- --check
tools/qualification/container.sh clippy --locked --offline --workspace --all-targets -- -D warnings
```

Set `WORK_QUALIFICATION_GIT_VERSION=2.56.0` for every second-pin command.
Serially sharing a compatible workspace target across these two contexts is permitted only when recorded explicitly.
The two 29-control fixtures remain independent; do not reuse their result reports.

- [ ] Record raw stdout/stderr, exact image/tool identities and actual exits independently.
- [ ] Do not rerun invalid Rosetta/openat2 full-lifecycle or canonical artifact smoke as a substitute.
- [ ] Keep complete locked workspace tests, all-helper suites, packaging and release smoke listed as separate unmet readiness gates.

## Task 6: Fresh native application compilation with the new C

**Files:** no production edits; new H2 destination and ignored driver/evidence.

- [ ] Admit the native batch from fresh measurements, including source, private registry, target, driver and observations.
- [ ] Use the reviewed `tools/qualification/native-macos.sh`, fresh destination and explicit installed toolchain/SDK.

```sh
TC=/Users/ravi/projects/techwright/work-cli-worktrees/qualification/target/native-toolchain-cache/pinned-1.98.1-20261106T175521Z/rustup-home/toolchains/1.98.1-aarch64-apple-darwin
SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX27.0.sdk
```

The parent records fresh absolute `NATIVE_DEST` and `NATIVE_DRIVER` paths beneath `P` before launch.
The driver is a frozen ignored evidence input, not an application source file.
Its only jobs are registry-only seeding, setting the admitted profile/cache environment, running the commands below and recording outputs.
It must not access repositories, authority state or credentials.

```sh
tools/qualification/native-macos.sh --source "$W" --destination "$NATIVE_DEST" \
  --development --without-git --toolchain 1.98.1 --toolchain-dir "$TC" \
  --sdk-root "$SDK" -- /usr/bin/python3 -I -B "$NATIVE_DRIVER"
```

- [ ] In the H2 source snapshot, run the actual toolchain binaries, not shims:

```sh
cargo metadata --locked --offline --format-version=1
cargo check --locked --offline -p work-cli --lib
cargo build --locked --offline -p work-cli --bin work
```

Here `cargo` means the recorded absolute `$TC/bin/cargo`, with absolute RUSTC/RUSTDOC from the same toolchain.
Capture JSON stdout separately from warnings. Check the selected path sys package, existing rusqlite edge and unchanged root lock.
Require all five real Darwin verification directives before bundled compilation.
Record new-C input, compiler/archive evidence, generated marker, successful production consumer compilation and final binary hashes.

- [ ] Label all results **DEVELOPMENT/NON-GATE** for macOS27/SDK27.
- [ ] Preserve native guard source and its 37-control coverage. Do not delete, relax or relabel those controls.
- [ ] Do not claim a fresh 37-control native run: that larger matrix is outside this compilation batch.
- [ ] Report any unexecuted native controls and actual Work-linked faults as NOT_RUN for this new source.
- [ ] Old-C native linkage evidence remains historical, not fresh new-C proof.

## Task 7: Review, serial integration and truthful handoff

**Files:** dated README addition, parent ledger and vault findings; no opportunistic code fixes.

- [ ] Add a dated README section only after observing results. Keep earlier native pending/failed receipts as historical records.
- [ ] Retain a complete evidence index, source/registry preservation delta and final resource census.
- [ ] Reconcile `du` only after owned processes are quiescent. Unknown results retain charge and payload.
- [ ] Obtain independent implementation SPEC review against the approved design and this plan.
- [ ] Resolve actual findings with the same writer, new genuine TDD if behavior changes, and fresh admissions where required.
- [ ] Then obtain a separate QUALITY reviewer. Neither reviewer writes source or reports into supplied input paths.
- [ ] Parent verifies allowed file list, C-only semantic delta, four glue reconstructions, root Cargo/lock equality and raw result classifications.
- [ ] Integrate serially into `feat/macos-support` only after both approvals and a clean ownership handback.
- [ ] Verify integrated tracked bytes/modes against the reviewed source. Record any documentation-only source-epoch distinction.
- [ ] Keep issues31/50 and native admission open. Do not claim complete S3a or release readiness.
- [ ] Update the vault review record with bounded outcomes, remaining gaps and retained charge. Preserve historical source-package and fingerprint holds.

The final report must separate source correctness, extracted control-flow evidence, native compilation and unsupported/unexecuted qualification.
No expected-RED predicate or static review converts a failed aggregate into GREEN.
