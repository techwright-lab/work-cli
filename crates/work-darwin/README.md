# Internal Darwin adapter — bounded A1 slice

This unpublished crate provides safe byte decoding and a minimal macOS-only
anchored attribute call. It is **not** a complete filesystem observation or a
qualified macOS workflow.

## Fixed schemas

All values use native byte order. Fields are four-byte aligned, including the
64-bit file ID. Every group begins with a `u32` length and the five-group
`attribute_set_t` returned mask. Unsupported/missing mandatory attributes,
unexpected masks and zero file ID/data generation are explicit errors.

- `decode_attributes`: returned masks, `ATTR_CMN_GEN_COUNT` (`u32`), then
  `ATTR_CMN_FILEID` (`u64`). The group must be exactly 36 bytes; unused caller
  storage after that group is ignored.
- `decode_bulk`: returned masks, optional `ATTR_CMN_ERROR` (`u32`, before all
  other fields), `ATTR_CMN_NAME` (`attrreference_t`), generation, file ID, then
  name bytes. Group lengths must preserve eight-byte batch alignment. These are
  the only supported common attributes; all other attribute groups must be zero.
  The schema does **not** use `FSOPT_PACK_INVAL_ATTRS`.

The bulk decoder accepts the exact native returned count and caller-owned
`Option<BulkEntry>` slots. It never allocates, refills, grows storage or retries.
It validates that many records, never a stale tail or an inferred byte count.
Errors clear all slots; success clears slots beyond the returned count. Names
borrow the input buffer and preserve arbitrary non-NUL bytes without text
conversion. References are signed, aligned and checked against the current group;
name data cannot alias fixed fields or another record. Names must have exactly
one final terminator and be single components (no empty, `.`, `..`, slash or
interior NUL).

## Native boundary

`attributes_at(BorrowedFd, &CStr, &mut [u8])` is available only on macOS. It
validates the component and requires at least `ATTRIBUTE_BUFFER_SIZE` bytes,
initializes exactly that fixed window, then makes one `getattrlistat` call with
`FSOPT_NOFOLLOW | FSOPT_ATTR_CMN_EXTENDED`. No invalid-attribute packing,
full-size reporting, symlink-follow fallback or EINTR retry is used. The FD is
borrowed for the call, not duplicated, closed or converted to owned state. The
request struct, C string and exclusively borrowed buffer stay live through the
call. Errno is captured immediately on failure; parsing occurs only on success.

Only private `src/ffi.rs` opts into unsafe code for that ABI call. The crate's
default deny and the application's/workspace's unsafe forbid remain intact.
There is no public raw-pointer interface and no readable payload open.

A retained parent FD does not by itself prove its route or mounted-volume
identity. File ID and generation alone are not complete identity/metadata,
ACL, topology, inode-reuse, capture-provenance or removal evidence. No native
bulk syscall/cursor, capture link or readable-capture acquisition is implemented
in this slice. A caller buffer does not bound uninterruptible kernel I/O time.

## Verification boundary

Portable tests cover exact counts/stale tails, capacities, malformed/truncated/
nonprogressing and misaligned lengths, oversized arithmetic inputs, returned
masks, per-entry errno, signed references, terminators, invalid components,
non-UTF-8 byte preservation and anchored-call buffer preflight. Run them through
`tools/qualification/container.sh test --locked -p work-darwin`.

Linux-container tests do not compile or execute the Darwin-only FFI. Native
compilation, syscall/errno/nofollow qualification and matching against actual
APFS observations remain pending the separately reviewed H1 disposable native
harness. No real-state native commands or toolchain downloads are required or
authorized by these portable tests. Focused independent FFI review is required
before accepting the boundary; this slice makes no support/release claim.
