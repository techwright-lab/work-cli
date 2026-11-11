# Internal Darwin adapter — bounded A1/A2 slices

This unpublished crate provides safe byte decoding and small macOS-only native
observation APIs. It is **not** a complete filesystem observation, durable
identity provider or qualified macOS workflow.

## Fixed schemas

All values use native byte order. Fields are four-byte aligned, including
64-bit file IDs. Every group begins with a `u32` length and the five-group
`attribute_set_t` returned mask. Unexpected masks, absent mandatory fields and
zero mandatory identities are explicit errors. No schema uses
`FSOPT_PACK_INVAL_ATTRS`; absent fields take no space.

The A1 APIs retain their original strict semantics:

- `decode_attributes`: returned masks, `ATTR_CMN_GEN_COUNT` (`u32`), then
  `ATTR_CMN_FILEID` (`u64`). The group must be exactly 36 bytes; unused caller
  storage after that group is ignored. Generation and file ID must be nonzero.
- `decode_bulk`: returned masks, optional `ATTR_CMN_ERROR` (`u32`, before all
  other fields), `ATTR_CMN_NAME` (`attrreference_t`), generation, file ID, then
  name bytes. Eight-byte record alignment is mandatory. Generation and file ID
  must be nonzero; missing generation does **not** mean an empty/clean directory.

A2 uses a **separate** API and observation type:

- `decode_census`: returned masks, optional `ATTR_CMN_ERROR`, name reference,
  file ID, then name bytes. Eight-byte record alignment is mandatory. It permits
  only RETURNED_ATTRS, ERROR, NAME and FILEID common bits, and no other attribute
  groups. It requires returned NAME and nonzero FILEID. `CensusEntry` has **no**
  generation field: enumeration proves names/identity/error handling only.
  Payload-generation evidence remains separately mandatory before accepted reads.

Both counted decoders accept the exact native returned count and caller-owned
`Option<Entry>` slots. They never allocate, refill, grow storage or retry. They
validate exactly that many records, never a stale tail or inferred byte count.
Errors clear all slots; success clears slots beyond the returned count. Names
borrow the input buffer and preserve arbitrary non-NUL bytes without text
conversion. Signed, aligned references are checked against the current group;
name data cannot alias fixed fields or another record. Names must have exactly
one final terminator and be single components (no empty, `.`, `..`, slash or
interior NUL). Budget exhaustion, malformed data and per-entry errno are errors,
not EOF or evidence of cleanliness.

## Native boundary

Only private `src/ffi.rs` opts into unsafe code for ABI calls/FD ownership
transfer. The crate's default deny and the application's/workspace's unsafe
forbid remain intact. There is no public raw-pointer interface or readable
payload open. Kernel I/O is not made interruptible or time-bounded by a caller
buffer.

### Anchored attributes (A1)

`attributes_at(BorrowedFd, &CStr, &mut [u8])` validates the component and requires
at least `ATTRIBUTE_BUFFER_SIZE` bytes, initializes exactly that fixed window,
then makes one `getattrlistat` call with
`FSOPT_NOFOLLOW | FSOPT_ATTR_CMN_EXTENDED`. No invalid-attribute packing,
full-size reporting, symlink-follow fallback or EINTR retry is used. The FD is
borrowed for the call, not duplicated, closed or converted to owned state. Errno
is captured immediately on failure; parsing occurs only on success.

### Counted census (A2)

`DirectoryCursor::open_at(BorrowedFd, &CStr)` validates one component and makes
one fresh `openat(O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`. It transfers
that new FD once into an owned cursor, closed on drop. There is no dup, clone,
rewind, from-existing-FD constructor or public descriptor accessor: each new
census must freshly open an independent directory offset. Acquisition borrows
the parent only for that call and does not retry or open readable payload.

`DirectoryCursor::read_batch(&mut self, &mut [u8])` makes **one**
`getattrlistbulk` call with the census mask and options zero. The syscall returns
the entries themselves (including symlinks); no generation request, invalid-field
packing or follow fallback is used. The entire supplied byte slice bounds the
call. The result is its exact record count, or immediately captured native errno,
including EINTR. Only count zero is native EOF. The caller explicitly performs
any bounded refill loop and passes each count to `decode_census` with its entry
budget. No initialization of stale tails is needed for exact-count decoding.
After a decode/budget error the offset may have advanced: discard the incomplete
census, never turn it into empty/clean evidence. No hidden retry, refill,
allocation or capacity growth occurs.

A held parent/cursor does not prove its route, real mounted-volume identity,
ACLs or safe access. Lookup can encounter changed topology before rejection;
this is not atomic Linux NO_XDEV containment. File IDs alone do not establish
inode-reuse protection or complete identity/metadata. Full ACL/topology,
provider-aware durable identity, capture acquisition and lifecycle remain out of
scope.

### Boot session (A2)

`boot_session_uuid()` makes one read-only `sysctlbyname("kern.bootsessionuuid")`
call into an initialized fixed 37-byte stack buffer. There is no size query,
retry, allocation, growth, alternate provider or synthesized/fallback ID.
`parse_boot_session_uuid` portably requires exactly 36 ASCII UUID characters and
one final NUL, standard hyphen positions and non-nil hex; it canonicalizes case
to lower case and refuses missing/extra/embedded NUL/bad hex frames.
`BootSessionUuid` Debug redacts its value. The explicit byte accessor is for
caller comparison/binding, not diagnostic publication. Missing, malformed or
changing mandatory evidence must hold the caller's operation. This adapter does
not establish a durable provider domain or authorize anything on boot changes.

## Verification boundary

Portable tests cover exact counts/stale tails, entry budgets, missing records,
malformed/truncated/nonprogressing and misaligned lengths, arithmetic overflow,
returned masks, per-entry errno, signed references, terminators/components,
non-UTF-8 byte preservation, A1 preflight, and boot UUID framing/case/nil refusal.
Run via `tools/qualification/container.sh test --locked -p work-darwin` and
`clippy --locked -p work-darwin --all-targets -- -D warnings`; repeat with
`WORK_QUALIFICATION_GIT_VERSION=2.56.0`. Formatting is crate-scoped.

`tests/native_observations.rs` tests **actual** requested/returned census layout
and file IDs against no-follow metadata of new owned files/directories/symlinks;
fresh repeated censuses, independent offsets, small batches, exact EOF, errno,
entry-budget refusal and stale bytes; repeated boot observations redact the UUID.
On the observed macOS 27.0 arm64 host, successful entries returned common mask
`0x82000001` (requested ERROR omitted), validating the un-packed optional-field
layout, not just a synthetic fixture. Zero/too-small native byte buffers returned
ERANGE. Creating byte-name `b"\xff"` returned EILSEQ on this host: the test accepts
only that specific construction refusal or, if creation succeeds, validates the
entry normally. **Arbitrary-byte native enumeration was not exercised here**;
portable preservation tests are not a substitute. Per-entry errno fault records
are portable fixtures, not native fault-injection qualification.

Native development uses the separately dual-reviewed H1 harness at sibling
`qualification` commit `ed820a0`, `--without-git`, a new owned destination each
run, explicit cached Rust 1.98.1 and explicit `SDKROOT` selecting MacOSX27.0.sdk.
Only the approved lane `target/container-cargo/registry` source cache is seeded
after `tools/qualification/container.sh fetch --locked`; dependencies remain
locked/offline. Tests/check/strict all-target crate Clippy execute inside those
snapshots, not in real repositories or authority state. No xcrun discovery,
auto-install, mounts, devices, reboot or cleanup is used.

These are **macOS 27 DEVELOPMENT/NON-GATE** observations, not supported macOS
15/26 qualification or lifecycle/reboot/power-loss evidence. Focused independent
FFI/spec/quality review remains mandatory. Complete workspace, packaging,
artifact, filesystem/case-variant and native support-matrix gates remain separate;
this slice makes no release-readiness claim.
