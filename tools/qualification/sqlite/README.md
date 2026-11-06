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
