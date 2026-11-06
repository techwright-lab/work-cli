# Private native Git qualification fixtures (H3)

`build-native-git.py` is fixture tooling, **not a normal Git installer**. It builds
only the public official Git 2.55.0 and 2.56.0 release archives, pinned identically
to `Dockerfile`:

| Git | SHA256 |
| --- | --- |
| 2.55.0 | `457fdb04dc8728e007d4688695e6912e6f680727920f2a40bf11eacc17505357` |
| 2.56.0 | `26c56c296b38c0695b26fa95f475f1d01704d2d38e73465ca30b0b2f5dc789d3` |

There are no moving refs, clones for source acquisition, credentialed downloads,
package-manager invocations, dependency installation, authority/configuration
changes, shell-profile edits, or changes to normal Git/PATH. PATH changes are
child-process-only. These fixtures do not authorize publication, normal install,
checkout removal, mounts, reboot, or pruning.

## Boundaries and prerequisites

Use an explicitly assigned owned source checkout. Its `.gitignore` must contain
`/target`; create `target/native-git-fixtures` with owner-only access before use.
Each build destination must be a **new direct child** of that directory. Existing
destinations, symlink parents, foreign ownership and writable-by-others parents
are refused. Installed Git is private under `DESTINATION/prefix`. Success and
failure retain archives, extracted sources, intermediate objects, prefix, logs
and `manifest.json`. Do not retry into or automatically remove a failed fixture.

Select an **already installed** native compiler and SDK explicitly. The compiler's
existing adjacent `make`, `ar`, `ld`, `lipo` and `otool` are selected directly,
avoiding system developer-tool launchers/SDK discovery. `file`, Perl, curl and system shell
utilities must already exist. The C dependency probe requires working curl with
TLS, Expat, zlib, iconv and CommonCrypto headers/libraries; missing capabilities
stop the build. No fallback disables repository transports or installs tools.
Git retains upstream Darwin CommonCrypto and iconv behavior. `NO_HOMEBREW` prevents
implicit dependency discovery; `NO_GETTEXT` and `NO_TCLTK` match the container
fixture's optional UI/localization exclusions. Compilation is native thin ARM64,
serial (`-j1`), with explicit SDK and deployment target 15.0. That deployment flag
is **not proof of macOS 15 support**. Make paths containing whitespace or shell
metacharacters are refused rather than interpolated into Git's shell recipes.

Archive acquisition uses a sanitized, credentialless environment with an isolated
HOME and `/usr/bin/curl --disable`, HTTPS-only initial/redirect protocols, finite
size/time/redirect bounds and the exact official URL. Checksums are verified
**before tar decoding or extraction**. Inventory limits bound members, expanded
bytes and path lengths. Reject absolute/traversing/duplicate/conflicting paths,
hard links, special/sparse files, escaping/chained/missing symlink targets and
members beneath symlinks. The three official internal symlinks are created last,
after validating their targets against the complete inventory. File ownership,
modes and metadata are not imported from tar; files/directories are newly owned.
An optional `--archive /absolute/cache/git-VERSION.tar.xz` must be a verified,
regular, owned file with no write bits and no symlink route. It is never modified.

The fixture-root retained ceiling is 3GiB, with a conservative 1GiB additional
estimate before each build and a projected physical-free floor of 10GiB. The
manifest records before/after storage observations. Physical accounting counts
hardlinked Git aliases once, does not follow symlinks, and is not an APFS snapshot
or compressed-storage guarantee. The parent must separately account the shared
8GiB wave ceiling, evidence outside this root and concurrent growth. **Obtain the
parent's heavy slot before any real Cargo/lock generation, native compiler
probe, make or native batch.**
Remeasure before each version; stop if it will not fit. No automatic cleanup,
pruning or capacity increase is authorized.

## Two phases through the reviewed native harness

First read `native-macos.sh --help`. Always pass `--source` as the assigned
checkout, never a real unrelated repository. The harness snapshots source bytes
without `.git` or `target`, isolates HOME/configuration and records its own run
metadata. A build does **no repository operations** and may therefore use H2's
`--without-git` mode before qualified Git exists. Only version/helper-layout
observations execute the freshly built Git in this phase. The build child PATH
contains a Git blocker; optional upstream commit/date discovery is explicitly
`unknown`, not guessed from an ancestor repository or invented from the archive
checksum. The manifest retains the exact source archive checksum independently.

The builder also requires `--toolchain-dir` for the same **already installed
native Rust 1.98.1** selected by H2. It checks the actual `cargo`, `rustc` and
`rustdoc` executable identities, architecture and exact versions, then binds them
through private `build-tools` symlinks plus explicit `RUSTC`/`RUSTDOC`. An empty
fixture-private `CARGO_HOME`, offline mode and one Cargo job exclude normal Rust
settings, credentials and network fallback. No Rust support is disabled.

Both pinned archives have the same dependency-free root `gitcore` 0.1.0 manifest
and no root lock. The builder verifies those exact manifest bytes, refusing any
new dependencies, workspace inheritance or path references. Cargo can otherwise
find Work's ancestor workspace even beneath `target/`; `--manifest-path` alone
is not an isolation boundary. The builder writes a **separate fixture-local**
`Cargo.toml` containing only `[workspace]`, `members = ["source"]` and resolver 2,
without editing the extracted Git manifest or Work's manifests. It also refuses
ancestor `.cargo/config` and `.cargo/config.toml`, whose discovery would otherwise
cross the workspace boundary.

With an explicit heavy grant, pinned Cargo generates the private workspace lock
**offline**. Only the exact generated dependency-free `gitcore` 0.1.0 lock is
accepted: pinned Cargo currently emits the legacy **versionless** lock for this
Rust-1.49 manifest (SHA256
`a65229eff534ef41f49334df65fe0f0660e33d5ba16db0a5aeb09a0d7fe1449b`).
Validation reads at most the expected length plus one byte, requires those exact
raw bytes, and derives only the `gitcore` 0.1.0 package graph from that limited
literal grammar. It is not a general TOML parser or normalization policy. Extra
fields, packages, comments or future format changes refuse for review. Unexpected
lock contents stop before make; no dependency resolution or fetch fallback is
permitted. Workspace, lock and original source-manifest bytes
and SHA256 are recorded and revalidated after make. `CARGO_TARGET_DIR` is explicitly
`DESTINATION/source/target`, matching Git's hardcoded library location; make gets
`CARGO_ARGS=--release --locked --offline`. These generated fixture files are not
patches to the source archive. The manifest records the pinned Rust tools and
child environment. Logs retain stdout/stderr in observed stream order, returning
stdout alone for machine-readable observations and reporting failure exit/status
plus a bounded stderr diagnostic. This is observed pipe order, not a promise of
atomic ordering between independent child streams.

Example after the parent grants the slot (use new destination names per run):

```sh
source="$PWD"
root="$source/target/native-git-fixtures"
mkdir -m 700 -p "$root"
# Select existing paths; never use rustup shims or xcrun to provision anything.
toolchain=/absolute/installed/1.98.1-aarch64-apple-darwin
sdk=/absolute/existing/MacOSX.sdk
cc=/absolute/existing/compiler/bin/clang
revision=FULL_REVIEWED_40_HEX_WORK_SOURCE_COMMIT
version=2.55.0 # Repeat serially for 2.56.0, with fresh destinations.
fixture="$root/git-$version-RUN"

tools/qualification/native-macos.sh \
  --destination "$root/h2-build-$version-RUN" --source "$source" \
  --development --toolchain 1.98.1 --toolchain-dir "$toolchain" \
  --sdk-root "$sdk" --without-git -- \
  /usr/bin/python3 tools/qualification/build-native-git.py build \
  --version "$version" --source "$source" --source-revision "$revision" \
  --destination "$fixture" --sdk-root "$sdk" --cc "$cc" \
  --toolchain-dir "$toolchain"
```

`source_revision` is the explicitly supplied Work commit, not a discovered Git
ref. The builder's own SHA256 and the H2 source-snapshot fingerprint also bind
working-source bytes. The fixture manifest records archive URL/SHA256, host,
compiler/tools/SDK/deployment choice, flags, dependency versions/linkage, exact
Git version/exec path, and executable plus all three helpers' native architecture,
mode, SHA256 and filesystem identities. `status=passed` here means **build only**;
repository smoke is explicitly `NOT_RUN`.

Then use H2 **with that exact qualified Git**, not `--without-git`, for actual
repository operations. Each smoke destination is new/private and contains only
explicitly owned disposable repositories. The smoke requires H2's selected
`GIT_EXEC_PATH`, binds the fixture identities and independently sanitizes all Git
configuration/environment. It tests commit, clone through the exact
`git-upload-pack`, push through the exact `git-receive-pack`, and remote archive
through the exact `git-upload-archive`, verifying the resulting bytes/commit IDs.
No ancestor repository discovery or remote network repository is used.

```sh
smoke="$root/h2-smoke-$version-RUN"
tools/qualification/native-macos.sh \
  --destination "$smoke" --source "$source" \
  --development --toolchain 1.98.1 --toolchain-dir "$toolchain" \
  --sdk-root "$sdk" --git-version "$version" --git "$fixture/prefix/bin/git" -- \
  /usr/bin/python3 tools/qualification/build-native-git.py smoke \
  --fixture "$fixture" --destination "$smoke/source/owned-git-smoke"
```

Inspect both H2 `evidence/run.json`/logs and the builder/smoke manifests. A missing
prerequisite or failed command is a blocker, not a successful skip. Results on
macOS 27 are **DEVELOPMENT/NON-GATE**, not support proof for macOS 15 or 26,
APFS variants, full Work lifecycle, networking, or final release artifacts.

## Portable regression checks

Tests use mocked archives/native command transcripts and disposable temporary
files; they are not Darwin or actual Git qualification:

```sh
tools/qualification/container.sh -- python3 -m unittest discover \
  -s tests/qualification -p test_native_git_fixture.py
WORK_QUALIFICATION_GIT_VERSION=2.56.0 tools/qualification/container.sh -- \
  python3 -m unittest discover -s tests/qualification -p test_native_git_fixture.py
```

Full workspace, formatting, strict all-target Clippy, helper, packaging, installed
artifact, macOS15/26 and release gates remain separate; this fixture slice alone
makes no release-readiness claim.

## Retained H3 development observation (2026-11-06)

On native macOS 27.0.1 ARM64, both exact fixtures built serially with installed
Rust 1.98.1, existing CLT clang 21 and explicit SDK27.0. Both H2 build commands and
exact-Git H2 repository/helper smokes exited 0. Rust remained enabled; the three
helpers exercised upload-pack clone, receive-pack push and upload-archive with
verified owned payload/ref results. This is DEVELOPMENT/NON-GATE only.

Relative to the assigned `native-git-fixtures` checkout:

- Prefixes: `target/native-git-fixtures/git-VERSION-lockfix-20261106/prefix`.
- Build manifests/logs: the prefixes' parent `manifest.json` and `build.log`.
- H2 build records: `target/native-git-fixtures/h2-build-VERSION-lockfix-20261106/evidence/`.
- H2 smoke records: `target/native-git-fixtures/h2-smoke-VERSION-lockfix-20261106/evidence/`;
  helper smoke manifests are under that fixture's `source/owned-git-smoke/`.
- Git 2.55.0 executable SHA256:
  `ca64beda6887f30e5ca8a56df8e141b75f7188201c8395e73f6cfdca35b6b5ec`.
- Git 2.56.0 executable SHA256:
  `dc708714ef74c6e290a3199c85bab2316dff3062bd85030385689a9c70c5a5d3`.
- Summary and exact invocation scripts: `target/h3-evidence/native-summary.json`
  and `build-lockfix-one.sh` / `smoke-lockfix-one.sh`.
- Portable final count: 37 tests passed per pinned container. Red/green logs are
  under `target/h3-evidence/`, including `red-versionless-lock.log` and
  `green-versionless-lock-git-VERSION.log`.

Two earlier failed Git 2.55.0 packets remain untouched: the initial builder lost
H2's Cargo PATH, and its first correction refused the actual versionless lock
because it expected format 4. Both failures stopped before any fallback; new
fixtures were used after test-first corrections and fresh execution grants.
All source archives, failures, build/Rust targets, prefixes, source snapshots and
evidence totaled approximately 671MiB; observed physical free space after the
batch was approximately 13.80GiB. These are historical observations, not fresh
storage admission or cleanup permission.
