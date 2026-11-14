# A3b: owned payload-generation characterization

This records `tests/native_generation.rs`, not payload-read admission. Contract:
[accepted specification](../../doc/specs/2026-11-06-native-macos-support.md),
sections 4–5 and 8; [wave-three plan](../../doc/plans/2026-11-06-native-macos-wave-3.md),
A3b. Production attributes, decoder, FFI, source helpers and manifests are unchanged.

## Observed development packet

The fresh `target/native-a3b-fresh-20261107T012554Z/evidence/` packet records
**macOS 27.0.1 ARM64**, explicit **MacOSX27.0.sdk**, installed **Rust 1.98.1**,
reviewed H2 (`ec6816ea946baf3b31a926c6545b7b0dadf8e1a7`), `--without-git`,
locked/offline dependencies and **DEVELOPMENT/NON-GATE** mode. Its `run.json`
records exit 0 and `support_claim=false`. This is not macOS 15/26 qualification.

The native integration target completed **four tests**: one owned native
experiment and three portable reporting tests. It produced **27 anchored
`attributes_at` samples**, not a NAME census. Each syscall succeeded with no
errno, declared length 36 and returned masks `[0x82080000, 0, 0, 0, 0]`.
`stderr.log` retains each initialized raw window, strict result, file ID and
before/after metadata. Strict decoding accepted 25 samples and refused two.

| Owned scenario | Observed generation |
| --- | --- |
| Unchanged; writable open/close without writing | 2 → 2 |
| Ordinary write; same-length write; truncation; retained writable-FD write (each synchronized) | 2 → 3 each |
| Before mmap → live mapped pre-write → live mapped synchronized post-write → unmapped | **2 → 0 → 0 → 4** |
| chmod; metadata-only mtime change; rename | 2 → 2 |
| Hard-link creation, alias observation and removal | 2 throughout |

Hard-link nlink changed **1 → 2 → 1**, with ctime changing at both transitions;
the alias retained the same file ID and metadata. Rename retained file ID and
size. Metadata checks are separate from generation evidence, not substitutes.

Both live writable-mmap observations returned zero and the existing strict
decoder refused them as `Decode(UnavailableIdentity)`. The test recorded
`BLOCKED payload-read advancement: mmap-live-synchronized: Unavailable`.
This is an observed **safe refusal/hold**, not an all-case inadequacy finding.
Nor do the changed nonzero tokens prove universal write detection. Mandatory
returned-mask and nonzero identity/generation requirements remain unchanged;
missing, zero or unavailable evidence must hold. Timestamp-only fallback is
forbidden; there is no NAME-census fallback or production fix in this slice.

## Fixture and verification boundary

The test creates a new private owned directory and regular files, retains its
fixture, and removes only its own just-created hard link. Assertions check
fixture mechanics, stable per-sample metadata and returned identity, not a
required native generation progression. The actual tokens above are observations.

The mmap writer uses `/usr/bin/python3 -I`, a fixed script and one owned path;
there is no shell or test FFI. It maps the eight-byte file, exchanges fixed
READY/WRITE/SYNCED/CLOSE pipe messages and flushes/fsyncs before the post-write
sample. Python uses 15-second command waits and a 20-second alarm; Rust owns the
child/pipes, waits on normal close and kills/reaps its child on drop. These are
bounded cooperative fixture controls, not hard interruption guarantees for
kernel I/O or interpreter startup. Raw diagnostics inspect only the fixed
36-byte initialized window; header/mask/field parsing is gated by syscall success
and bounded declared lengths. Zero diagnostic values never become valid tokens.

Earlier retained portable logs record **51 passing tests per Git 2.55.0 and
2.56.0 fixture**, strict crate all-target Clippy and crate formatting. The
reporting-helper RED log has two expected assertion failures and one pass;
subsequent GREEN logs distinguish repeated/changed/replaced/unavailable tokens.
Container logs also retain the amd64-on-arm64 image warning; they are not native
Darwin execution. Fresh native strict crate all-target Clippy and crate formatting
both exited 0. Closeout added only this documentation alongside the unchanged
validated test bytes; it did not rerun builds or tests.

From the repository source root, the focused portable commands are:

```sh
tools/qualification/container.sh test --locked --offline -p work-darwin
tools/qualification/container.sh clippy --locked --offline -p work-darwin --all-targets -- -D warnings
tools/qualification/container.sh -- cargo fmt -p work-darwin -- --check
# Repeat each command with WORK_QUALIFICATION_GIT_VERSION=2.56.0.
```

Native reproduction requires a newly authorized, new owned H2 destination via
`tools/qualification/native-macos.sh --source "$SOURCE_ROOT" --destination
"$NEW_DESTINATION" --without-git --toolchain 1.98.1 --toolchain-dir
"$INSTALLED_TOOLCHAIN" --sdk-root "$EXISTING_SDK" -- COMMAND...`. Select an
existing explicit SDK/toolchain; do not install or discover replacements. Inside
that snapshot, first copy only the approved registry into its empty private
Cargo home, verify count/bytes/content completeness without config/credentials,
and check lane/wave budgets and physical free space. Then run:

```sh
cargo test --locked --offline -p work-darwin --test native_generation -- --nocapture --test-threads=1
cargo clippy --locked --offline -p work-darwin --all-targets -- -D warnings
cargo fmt -p work-darwin -- --check
```

Evidence pointers (repository-relative, retained locally):

- `target/evidence/portable-{red,tests,clippy,format-check}-*.log`.
- Fresh packet `stdout.log`: seed completeness (8,611 files; 186,327,776 bytes),
  progress/budget checkpoints and three command exits 0; `stderr.log`: all samples.
- `target/evidence/closeout-provenance.json`: hashes, counts, exits and resource ledger.
- Prior `target/native-a3b-20261106T225846Z/`: retained **partial** registry seed,
  outer 180-second timeout during seed/budget work, no `run.json`, no recorded
  Cargo/API observations and unknown child exit status. Its late grant-delivery
  uncertainty remains unresolved. It was not replayed, adopted or cleaned; fresh
  exit 0 does not retroactively resolve that packet or establish ABI semantics.

## Remaining gates

This does not prove atomic capture/containment, boot identity or boottime,
foreign-mount behavior, inode-reuse safety, concurrent-writer completeness, core
lifecycle or release readiness. No foreign mount or boot transition was tested.
Native managed mutation remains closed. Independent SPEC then QUALITY reviews,
macOS 15/26 ARM64 × both Git fixtures, APFS case variants, complete applicable
workspace tests/lints, helper tests, packaging/artifact smoke and the rest of the
accepted finite matrix (capture, persistence, identity, lifecycle, installer and
final-byte release provenance) remain separate outstanding gates.
