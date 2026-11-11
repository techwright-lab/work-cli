# Real SQLite build-guard qualification (S2)

`build_guard.py` creates a **new, retained standalone Cargo workspace**, with
`[workspace]` in its generated manifest and explicit `--manifest-path` commands.
The fixture may live under the checkout's ignored `target/`; it is not a member
of, and does not resolve/build, the application workspace. It verifies and copies
the real pinned `vendor/libsqlite3-sys` 0.36.0 package, including `build.rs`, before
building the dependency and running an in-memory SQL smoke (`sum=42`, SQLite
3.51.1). Cargo's build-script execution event, static `sqlite3` link directive,
bundled archive, source and executable digests, and command output are retained.
No system SQLite or extracted guard function is substituted.

## Inputs and isolation

Supply absolute paths to installed **Rust 1.98.1** cargo/rustc executables, not
rustup shims, and an explicitly approved **registry-only** cache directory.
The runner seeds only that registry into a fresh isolated CARGO_HOME. It does not
copy Cargo configuration, credentials, repository `.git` state or user HOME.
It refuses source/cache symlinks and special files. All commands have constructed
environments, offline resolution and a 240-second per-command timeout. Existing
fixture destinations are refused; no automatic cleanup occurs.

The root Cargo.lock is copied into the fixture. Offline metadata may prune it and
replace the registry SQLite edge with the copied path dependency. **Before any
dependency compilation**, every resolved registry name/version/source/checksum
must already be in the original root lock. The actual build then uses `--locked`
and `--offline`. No root lock update, newly selected registry version or download
is permitted. Hashes of the original root Cargo files and every pinned vendor
member are checked again on exit.

## What the 23 controls demonstrate

* **One full Cargo dependency build and linked SQL execution**, on the actual
  platform running the wrapper. This uses the real vendored manifest and bundled
  source, not a synthetic replacement crate.
* Two bounded permitted-input checks: the Cargo-built build-script executable
  verifies every mandatory digest with the package-config override unset or `0`.
  Deliberately omitting OUT_DIR then stops the real `main` at its next `unwrap`.
  That expected post-guard error is a barrier, **not a successful Cargo build**.
* Ten bounded faults: altered and missing copies of each of `sqlite3.c`,
  `sqlite3.h`, `sqlite3ext.h`, and both bundled binding files. Alterations are
  checked against the exact original **and** altered SHA256 printed by the real
  assertion. Missing-source errors must be the guard's missing-input/NotFound
  error, not a later compiler/copy error.
* Three package-config override rejections (`1`, empty, `true`).
* Five feature configurations rejected by the guard: no bundled feature,
  bundled+sqlcipher, bundled+bundled-sqlcipher, bundled+in_gecko, and
  bundled+loadable_extension. These variants compile the **entire unmodified real
  build.rs** with rustc and the Cargo-built locked externs, setting the listed
  feature cfgs. They do **not** resolve/build the optional Cargo dependency graphs
  (e.g. bindgen/SQLCipher/OpenSSL). Compilation commands, cfgs, source SHA and
  resulting executable SHA are recorded.
* Two target/host controls: macOS target + Linux host rejects drift; Linux target
  + Darwin host bypasses the Darwin guard and reaches the bounded compiler trap.
  These are deliberately constructed build-script environments, not cross-target
  Cargo compilation claims.

All faults run against new full source copies. The pristine fixture vendor is
retained separately. Negative executions have a fresh output directory and
logging CC/AR/pkg-config traps. The expected exact guard error, absence of tool
execution, absence of generated binding/output files, and absence of the later
route-selection directive establish rejection before the alternate build path.
The Linux-target bypass control intentionally records compiler trap execution.
This does **not** claim no prior side effects: the fixture, source mutations,
tool traps, empty output directory and logs already exist. These are **bounded
real build-script executions, not full Cargo transaction fault tests**.

## Portable execution

Use the prescribed containers with the operator-approved registry seed already
in this lane's `target/container-cargo/registry`. Do not copy the rest of another
CARGO_HOME. No fetch is needed with the approved cached root-lock dependencies.

```sh
tools/qualification/container.sh -- python3 -m unittest discover \
  -s tests/qualification -p test_sqlite_patch.py -v
WORK_QUALIFICATION_GIT_VERSION=2.56.0 tools/qualification/container.sh -- \
  python3 -m unittest discover -s tests/qualification -p test_sqlite_patch.py -v
```

The tests retain complete fixtures at `target/sqlite-guard-evidence/test-*/fixture`.
`runner-context.json` identifies the container Git fixture; `evidence/report.json`
indexes the matrix, with adjacent per-command JSON/stdout/stderr. Absolute
`/workspace/...` evidence paths refer to the checkout mount in the container.
The test runner asserts independent Cargo membership, original root/vendor
hashes, exact locked registry versions and static bundled linkage.

Test-first observation on base `6f94da1`: both newly added tests failed because
`build_guard.py` did not yet exist. Initial fixture bring-up also caught selection
of a rustup shim (isolated HOME could not find a toolchain) and Cargo's null
`executable` field for build-script artifacts. The implementation now refuses
shims and takes build-script filenames from Cargo's real artifact records. The
failed fixtures/logs from those bring-up runs are retained, not reused.

## Native status and remaining boundary

**PENDING_NATIVE**: the portable framework does not authorize copying vendor via
the older H1 native wrapper. Native execution must wait for dual-reviewed H2,
whose source snapshot includes vendor, patches and the crate's `.gitignore`.
Use H2 `--without-git` development/non-gate mode on the macOS 27 host, its explicit
SDK selection for `/Library/Developer/CommandLineTools/SDKs/MacOSX27.0.sdk`, and
the approved installed cache toolchain:

```text
/Users/ravi/projects/techwright/work-cli-worktrees/qualification/target/native-toolchain-cache/pinned-1.98.1-20261106T175521Z/rustup-home/toolchains/1.98.1-aarch64-apple-darwin
```

Inside the reviewed source snapshot, invoke the runner with a **new absolute**
fixture destination, `--registry` pointing only to the approved registry seed,
and `--cargo`/`--rustc` pointing to that installed toolchain's `bin` executables.
Retain H2 wrapper evidence as well as this runner's evidence. Do not run the
whole existing Linux-oriented test file natively as a substitute. A native
successful Cargo build must also show all mandatory Darwin guard rerun directives
in the real build-script output; the runner checks that on Darwin.

Neither Linux Docker Desktop storage nor macOS 27 development execution is a
supported Work authority/recovery-storage qualification. Actual Work-linked VFS
fault propagation, acknowledgement ordering, store integration and checked
checkpoints remain **S3**, even if this matrix and SQL smoke pass. No native
support, release readiness, complete workspace test/Clippy/package/artifact gates,
macOS 15/26 qualification, or root dependency switch is claimed here.

## S3a-P marker controls and evidence limits

The portable suite now preserves all **23** controls above and adds six (29
total): bundled-windows-only/bundled-bindings-only rejection, failed C compile
with fresh output, failed C compile with historical marker output, failed input
verification with historical output, and actual library compilation without a
generated marker. On Linux the last control succeeds without requiring or
creating a Darwin marker. All bounded failures assert no new marker generation;
stale fixtures explicitly retain historical bytes. The existing OUT_DIR barriers
are still **not marker-positive evidence**.

To bound retained storage, script cases copy only the five mandatory inputs they
can reach, not the unused SQLCipher tree. Prohibited routes receive no source
inputs: they must fail at the route guard before opening any source. Each fault
mutates only its own copied file. The complete pristine vendor remains separately
hash-verified. No shared mutable fault source or target is used.

On native Darwin, `library_controls` additionally compiles the real library for
the actual rustc host target (no synthetic target cfg): seven prohibited feature
sets must fail even with historical marker output. `marker_io_failure` proves a
real successful C/archive build followed by fatal marker-write failure.
`links_override_control` uses a fresh standalone Cargo target and an explicit
negative-only links override: build-script execution is suppressed, and the
missing generated include refuses compilation. These are callable qualification
controls; native orchestration must supply an explicit installed **Python 3.11+**
(as `tomllib` requires), not assume H2's system `python3` is suitable. Do not
install tools or change global PATH to satisfy that prerequisite.

Stage3 retained evidence lives in `target/s3ap-stage3/`:

- `portable-red-{255,256}`: the new fourth-glue-target test genuinely failed
  before implementation; `portable-green-{255,256}`: 17 Python tests and 29
  real-script/library controls passed per pinned Git fixture.
- `native-positive-20261108T224741Z`: H2 exit 1, driver setup predicate error
  **before Cargo**, retained unchanged. This is not a marker compilation result.
- `native-recovery-20261108T224913Z`: actual locked/offline application metadata
  and `cargo check -p work-cli --test sqlite_selection` both **0** on fresh H2
  source/target/private registry. Five source checks precede successful Darwin C
  compile/archive; the generated marker bytes/hash and real rusqlite API check
  are recorded. H2 aggregate remains **1** because subsequent guard import used
  system Python without `tomllib`. Do not relabel that aggregate GREEN.
- `native-guard-only-20261108T225208Z`: separately authorized fresh H2 run,
  explicit existing arm64 Python 3.11.11 with `-I -B`, exit **0**. It verifies the
  positive run's full immutable input inventory, copies registry-only bytes to
  new private state, reads its compiler artifacts without modifying them, and
  executes **37 compile-only guard controls** (22 original non-SQL controls plus
  15 marker controls). No application/runtime SQLite/SQL execution occurs here.

Admission/command/resource JSON, source and complete registry before/after hashes,
actual exits, marker bytes, archive hashes, control counts and logs are retained.
The initial 1.50-GiB Stage3 retention ceiling was explicitly raised by the
supervisor to 2.00 then 2.50 GiB for the separately admitted recoveries, within
unchanged whole-lane 6-GiB/wave 18-GiB ceilings and physical 10-GiB floor. Failures
were preserved, never cleaned or automatically retried. These macOS27/SDK27
observations remain **DEVELOPMENT/NON-GATE**. Independent SPEC then quality review,
parent production enforcement/link evidence/upstream negative, full integrated
qualification and packaging/release gates remain separate obligations.

Final self-review initially caught a rustfmt-only wrapping difference in the new
library `compile_error!`. That failed formatting run is retained. The explicitly
approved correction changes only whitespace outside the unchanged literal;
`final-format-equivalence-and-reconstruction.json` proves identical macro tokens,
otherwise identical whole-library bytes, unchanged first three glue sections,
and exact fourth-section upstream reconstruction. Only library/glue hashes and
their documented values changed. Both portable fixtures subsequently rerun small
format/provenance/Python checks, without repeating the heavy control matrix.
**Native evidence is on the pre-format bytes**, not the final exact source:
library `8799808cbe6cd56fd61516fcc5cd4ebaaec020d73b6720dede74653d1309e96d`,
glue `a3bb26a4fa46c7320e1aeb8beee026799236ba54f4f9b6838a95f2785194cfd5`.
The final exact-source native/integration gate remains pending with the parent.
