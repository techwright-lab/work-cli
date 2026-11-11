# A3c / issue48: non-payload-readable handles and independent ACL evidence

**2026-11-07 — source-only research; BLOCKED for production access proof.**
Workspace: `feat/macos-native-access-proof`, base
`b958d10e225632766221c3f5a4078c41724f43c8`. No adapter, application, API,
dependency, test or qualification change is proposed here. `ProductionAccessUnproven`
and native managed admission remain closed. This is a review input, **not an
accepted acquisition contract, implementation authorization or native experiment**.

## 1. Answer and contract boundary

The captured sources support **independent FD-based security retrieval without
FREAD**, and public macOS15/26 `O_EXEC` / `O_SEARCH` access modes. They do **not yet
close** a complete, anchored, non-payload-readable acquisition contract:

- `O_EXEC` / `O_SEARCH` produce descriptor modes without FREAD/FWRITE, but XNU
  explicitly retries some failed filesystem opens with **FREAD added at the
  VNOP/compound-open boundary**. That does not add FREAD to the returned fileglob;
  it does prevent claiming that acquisition never performs a filesystem-level
  readable open. Read/pread rejection alone cannot settle that distinction.
- The mmap path checks FREAD for initially readable mappings, but also constructs
  and later widens maximum protections. A negative initial `mmap(PROT_READ)` is
  **not** a demonstrated closure over mapping/protection conversions.
- Libc's convenient FD ACL getter hides an allocation/refetch loop without a
  caller retry budget. These kernel snapshots nevertheless enforce a 128-entry
  allocation cap, permitting a conditional finite loop bound (§5.3), not a
  claim of intrinsically unbounded retries. NULL, ENOENT, a zero-byte security
  result and NOACL cannot be promoted to complete negative ACL evidence.
- A fixed-budget extended-fstat security getter could avoid the *same attrlist
  returned-mask dependency* on successful non-sentinel ACL output. It still needs
  supported ABI, acquisition, snapshot/provenance and policy review; the raw
  NOACL representation itself loses support provenance.

These conclusions follow from [open-mode conversion][15-flags],
[15 open1][15-open1] / [26 open1][26-open1],
[15 VNOP retries][15-vnopen] / [26 VNOP retries][26-vnopen],
[15 mmap][15-mmap] / [26 mmap][26-mmap], and
[Libc ACL/statx][libc-acl] / [Libc statx loop][libc-statx].
Detailed implications and uncertainties follow; no missing source is treated as
proof of impossibility.

The accepted [SPEC §§3–5](../specs/2026-11-06-native-macos-support.md) and
[wave3 A3a/G3](../plans/2026-11-06-native-macos-wave-3.md) require safe held-parent
single-component observations, actual mounted identity, effective access and
unrelated-principal/parent replacement protection **before readable payload
opening**. Neither a post-open type check, mode-only fallback, all-ACL ban nor a
successful metadata call alone discharges that contract. Qualification remains
macOS15/26 ARM64/APFS, not the operator's SDK27 environment.

**Mask distinction:** the supplied A3a observation `common=0x82238000` is a
*returned* mask missing `EXTENDED_SECURITY=0x00400000`; the request constant in
this checkout is already `0x82638000`
(`crates/work-darwin/src/access.rs:166–188`). XNU only sets the returned ACL bit
when `va_acl` is supported **and non-NULL** [26 packing][26-pack]. Missing bit
means unavailable ACL evidence for this observer, not observed no ACL. No change
to that decoder or fallback is authorized by this note.

## 2. Primary sources, release mapping and provenance

The supplied immutable captures in `/tmp/work-acl-primary.uzZfRS` were inputs,
not an execution environment. All 43 entries of their `SHA256SUMS` were verified;
seven Libc15/26 pairs compare byte-identical. The earlier `d94ccd97…worker_output.md`
audit was navigation only, not a primary authority. No capture scripts were
executed/imported. The other supplied `apple-source` tree and SDK27 headers/man
were not needed for the conclusions below.

| Published distribution mapping | Libc commit / release | XNU commit / release |
| --- | --- | --- |
| `macos-150`, distribution commit `fafa0d30e9943c16e82740488dc0750c24355562` | `af11da5ca9d527ea2f48bb7efbd0f0f2a4ea4812`, `Libc-1669.0.4` | `8d741a5de7ff4191bf97d57b9f54c2f6d4a15585`, `xnu-11215.1.10` |
| `macos-265`, distribution commit `83390100289cedfe669c31a96c94326d31afa1ed` | `4e34d0559e3a1b081afeb8604d9e204a1f31321d`, `Libc-1752.120.2` | `ac9718fb1af618d5ce8678d0dc6e8a58f252216f`, `xnu-12377.121.6` |

Mapping evidence: immutable first-party [15 tree][dist15] and [26 tree][dist26],
entries `Libc` and `xnu` (retained JSON lines 200–204 and 1024–1028). Annotated-tag
resolution and source release names are retained in the supplied provenance.
This establishes published-source relevance for 15 and 26, **not** equality to
installed binaries, every point release, private APFS implementation or passing
qualification. References below are commit-pinned GitHub source URLs, with exact
source paths and line ranges in their definitions. `15` and `26` mean these two
source snapshots, not universal OS guarantees.

New GETs were confined to ignored `target/primary-source/a3c/` with `URLS.tsv`,
`PROVENANCE.md` and `SHA256SUMS`. Each used unauthenticated, first-party immutable
HTTPS source URLs and `curl --disable --fail --silent --show-error --proto
'=https' --max-time 30 --max-filesize 2097152`; no clones, archive extraction,
redirect following, credentials or installations. One discovery request for
15 `bsd/kern/kern_fileport.c` returned HTTP404/no retained body; fileport code was
already in `kern_descrip.c`. The successful new data are listed by digest below;
well below 10MiB total / 2MiB each / 0.05GiB lane budget. No old input was modified.

Licensing: source headers retain Apple's APSL2.0 / OSReference terms and,
where present, Regents/NeXT/USL BSD-style notices. Libc captures carry APSL2.0
notices. These are source-analysis citations, not relicensing or an authorization
to redistribute production code. Exact notices stay with each capture.

## 3. Acquisition candidates: facts versus sufficiency

### 3.1 Best-supported research candidate: O_EXEC regular, O_SEARCH directory

Both public XNU headers define `O_EXEC=0x40000000`,
`O_SEARCH=(O_EXEC|O_DIRECTORY)` outside `KERNEL`, gated by the POSIX2008 Darwin
feature level, and both public `open(2)` sources list them as access modes
[15 flags][15-flags] / [26 flags][26-flags],
[15 man][15-man] / [26 man][26-man]. This is not a numeric flag inferred only
from SDK27.

`FFLAGS` handles O_EXEC specially by removing `O_ACCMODE`, instead of adding one
as for ordinary modes; FEXEC/FSEARCH are the same internal bit. `open1` rejects
access-mode value3 and O_EXEC combined with nonzero ordinary access mode. Thus
`O_EXEC|O_RDONLY` is indistinguishable from O_EXEC (O_RDONLY is zero), **not** a
read request; O_EXEC|O_WRONLY / O_RDWR is invalid. Saved fileglob flags preserve
FEXEC but do not acquire FREAD/FWRITE through this conversion
[15 flags][15-flags] / [26 flags][26-flags],
[15 open1][15-open1] / [26 open1][26-open1].

Traditional authorization rejects FEXEC on non-regular non-directories, rejects
O_DIRECTORY on non-directories, requires O_DIRECTORY with directory FSEARCH,
and authorizes EXECUTE for regular files / SEARCH for directories, not READ_DATA
[15 authorization][15-authopen] / [26 authorization][26-authopen]. Consequences:

- It grants an ancillary execute/search capability; it is **not inert** like a
  claim of universal O_PATH equivalence. No Git/helper execution is authorized
  before the application's access policy passes. This note does not prove every
  executable-dispatch API's behavior from an FEXEC descriptor.
- It can fail on a non-executable regular file even if READ_SECURITY would be
  allowed. That is not evidence that the file has no ACL. Refusal may be correct;
  an observer for arbitrary non-executable payload is not established by this
  candidate. Directory search permission is relevant but not unrelated-user or
  parent deletion/replacement protection.
- `O_NOFOLLOW` and O_DIRECTORY are useful **kernel acquisition constraints**;
  component validation, anchored identity comparison and route revalidation are
  still necessary. No O_SYMLINK, creation, truncation, append, lock or raw-data
  flags are proposed. A final symlink is not a Homebrew policy rejection: Git
  symlink resolution needs its separately validated route, not a follow-on-open
  shortcut.

**Important blocker:** both `vn_open_auth` implementations retry failed
FEXEC-only `VNOP_COMPOUND_OPEN` and `VNOP_OPEN` using `fmode|FREAD`
[15:587–597,661–674][15-vnopen] / [26:625–635,719–732][26-vnopen]. The local
`fmode` is not changed by the retry; `open1` still saves the original no-FREAD
mode. Therefore two claims must remain separate:

1. **Supported source fact:** these paths can return a fileglob lacking FREAD
   and FWRITE, even after an FREAD filesystem-open retry.
2. **Not established:** acquisition never enters a payload-readable filesystem
   open or triggers relevant filesystem/provider effects. The exact pre-readable
   contract cannot be silently reduced to “read(fd) fails.” Private APFS compound
   operations and failed-open effects are not proven here. No retry-disable
   public flag was established by this research; that is a source gap, not a
   universal nonexistence claim.

Even the successful ordinary open path takes vnode references and emits
open notifications [15 finish][15-finish]. `open1` can break leases, call lock
operations if requested and truncate if requested [15 open1 tail][15-open1tail]
/ [26 tail][26-open1tail]. Excluding those flags avoids requesting those changes;
it is not a proof of no observable open, permission/provider activity or stable
data-generation evidence. No payload-generation guarantee follows from FEXEC or
`st_gen`; stat itself filters nonzero generation for unprivileged users
[15 stat security][15-statsec] / [26 stat security][26-statsec]. A3b's mandatory
data-generation gate remains separate.

### 3.2 O_EVTONLY and ordinary access-mode hypotheses

| Hypothesis | Captured source fact | Present-contract assessment |
| --- | --- | --- |
| `O_EVTONLY` alone (ordinary mode0) | Ordinary FFLAGS yields FREAD. Stripping FREAD/FWRITE occurs only when `proc_disallow_rw_for_o_evtonly(p)` is true [15 open1][15-open1] / [26 open1][26-open1]. | **Reject as universal nonreadable acquisition.** Process policy is not a reviewed invariant here. Merely not issuing reads is weaker than not obtaining a readable handle. |
| `O_EVTONLY|O_WRONLY` | Without stripping, conversion yields FWRITE, not FREAD. With stripping, neither bit remains. No FEXEC combination is needed. | Narrow !FREAD hypothesis is plausible, but grants write capability under one policy and requests write authorization; ordinary write/pwrite admission checks FWRITE [15 write gate][15-write] / [26 write gate][26-write]. It is not a safe, inert metadata-handle contract by itself. |
| `O_WRONLY` without EVTONLY | FWRITE; ordinary read paths reject. | Same ancillary write issue, no justification for changing inspection capability policy. Neither `O_TRUNC` absence nor O_NONBLOCK makes an arbitrary special-file open harmless. |
| `O_EVTONLY|O_RDWR` or O_RDONLY | FREAD unless policy strips it. | Same process-policy dependency; reject as universal. |
| `O_ACCMODE` value3; O_EXEC with WRONLY/RDWR | Explicit EINVAL in open1. | Not a hidden metadata-only access mode. |
| Policy-stripped EVTONLY plus a runtime read test | May demonstrate one process/outcome, not all capabilities or open side effects. | No native experiment authorized here, and one negative read would not prove the required contract. |

The writable alternative is **not declared universally impossible or forbidden
solely because its descriptor is writable**. The existing safety contract does
not authorize intentional payload writes/repair; this route still lacks a
positive, reviewed harmless-acquisition argument under type substitution. In
particular, unlike O_DIRECTORY / the traditional FEXEC type gate, ordinary
WRONLY can reach `VNOP_OPEN` for devices/FIFOs before any user-space identity/type
check. O_NONBLOCK only changes blocking semantics; it does not establish regular
inode provenance. Read-only metadata preclassification is not an atomic guard
against replacement before open [15 VNOP path][15-vnopen],
[15 authorization][15-authopen] / [26 authorization][26-authopen].

EVTONLY's documented purpose is monitoring, and its descriptor does **not
prevent unmount** [15 man:235–239][15-man] / [26 man:237–241][26-man]. Equal
`st_dev` or an event handle is not a held-mount guarantee. The final mount/route
protocol cannot be dropped even for a no-FREAD result.

### 3.3 Descriptor capability closure: what has and has not been traced

| Surface | Rechecked primary-source result | Bound on conclusion |
| --- | --- | --- |
| `read`, `pread`, vector read preparation | `preparefileread` requires FREAD, otherwise EBADF [15:225–258][15-read] / [26:227–260][26-read]. | Supports ordinary read rejection for genuine no-FREAD fileglobs, not absence of every payload path. |
| `mmap` | Initial requested WRITE/EXEC implies READ; regular file mapping requires FREAD for initial PROT_READ. However maxprot starts with EXEC, private mappings add WRITE, then later EXEC/WRITE implies READ in maxprot before VM entry [15 mmap][15-mmap] / [26 mmap][26-mmap]. | Need trace of PROT_NONE→mprotect/Mach protection, MAC/VM/filesystem checks and ARM64 behavior. **No claim of a successful bypass** or universal unreadability. Even failed mmap may attempt atime update earlier. Future tests must not stop at initial PROT_READ rejection. |
| `dup`, F_DUPFD family | `finishdup` shares the same fileglob [15 dup][15-dup] / [26 dup][26-dup]. | Does not itself add FREAD, but duplicates ancillary capabilities and lifetimes. Keep internal ownership/FD budget and no descriptor escape. |
| `fcntl(F_SETFL)` / F_GETFL | Settable mask excludes FREAD/FWRITE/FEXEC; F_GETFL can synthesize FREAD for policy-stripped EVTONLY before converting back [15 fcntl][15-fcntl] / [26 fcntl][26-fcntl], [flags][15-flags]. | Reported access mode is not a raw internal-bit oracle; F_SETFL is not permission to convert a metadata handle into a readable one. |
| `fileport_makeport` / makefd | Sendability/guard checks; port retains fileglob; new descriptor uses the same fileglob [15 fileport][15-fileport] / [26 fileport][26-fileport]. | Does not itself upgrade access bits. No general arbitrary-port/SCM transfer proof is claimed; an eventual adapter should expose no transport/raw FD escape. |
| `fclonefileat` | Explicit FREAD gate [15 clone][15-clone] / [26 clone][26-clone]. | No-FREAD blocks this FD variant. Path-based clone re-resolves and authorizes a source; it is not capability attenuation or an allowed inspection fallback. No cloning performed. |
| `/dev/fd` open fallback | `dupfdopen` checks requested READ/WRITE subset and shares existing fileglob [15 fd reopen][15-fdreopen] / [26 fd reopen][26-fdreopen]. | This branch is not a universal account of all reopen/FD-path operations. Reopening by a reconstructed pathname would need fresh route/acquisition proof. |

Work's cooperative host-local threat model is not hostile same-UID confinement.
Nevertheless, the *claimed handle contract* must state whether it means OS-wide
capability closure or a constrained internal metadata-only use discipline. This
note cannot silently choose the weaker interpretation. The mmap and filesystem
FREAD-retry gaps must be resolved or explicitly taken to SPEC review, not hidden
behind Rust wrapper non-use.

## 4. Anchoring and identity: necessary future contract, not a proven procedure

The strongest source-supported **candidate shape** is held-parent one-component
`openat` with no final follow, O_SEARCH for a directory and O_EXEC for a regular
executable. In 15, for relative names and non-AT_FDCWD parents, `open1at` obtains
a vnode from the supplied FD, verifies VDIR and passes it as USEDVP
[15 anchor][15-anchor]. In 26 the wrapper instead records `ni_atfd` and sets
`NAMEI_ATFD`, deferring resolution to namei [26 anchor][26-anchor]; this note does
not equate the two internal paths or claim a complete 26 namei audit. Public man
text in both families specifies held-directory relative resolution
[15 man][15-man] / [26 man][26-man]. A genuine retained parent is required;
absolute paths do not supply the intended held-parent anchoring.

A later proposal would have to specify all of the following, with refusal at
any missing step (this list grants no implementation/experiment authority):

1. Validate one component (no slash/NUL/empty/dot/dotdot), parent ownership,
   effective search, ACL/modes and parent deletion/replacement exposure; establish
   its actual mounted identity and root-to-parent route. Bootstrap acquisition of
   those parent FDs needs its own same safety argument; “already held” must not
   smuggle in unvalidated readable ancestors.
2. Obtain no-follow component identity/type/metadata/topology without payload
   opening. A symlink route is handled by the existing validated selection
   protocol, not O_SYMLINK or silently following openat. Distinguish regular,
   directory and unsupported special types.
3. Acquire the chosen constrained FD, then compare FD identity/type and actual
   mounted-volume/route evidence with the anchored component and held parent.
   Compare within the same observation interval; file ID without mounted-volume
   provenance is not enough. FD matching confirms the object actually queried;
   it does **not** retroactively make a transient wrong-object open safe.
4. Query ACL and effective-access evidence on that **same held object**, retain
   identity provenance and recheck parent/component/ancestors before use and
   dispatch. Refuse changing fields, route, mounts, unsupported ACL outcomes or
   relevant access. A positive ACL snapshot is not immutable permission history.
5. Discharge executable/helper layout and replacement/deletion protection before
   any payload-readable opens or Git/helper execution. Retain the selected
   identities; revalidate before/after dispatch with existing possibly-executed
   semantics. No native admission opens merely because metadata retrieval works.

Current A3a already distinguishes component topology from opened actual-mount
proof (`topology.rs:246–258`), and its existing `open_directory_at` uses O_RDONLY
(`ffi.rs:64–76`). This research neither replaces it nor certifies it for the
non-payload-readable contract. The accepted containment property permits some
foreign/aliased lookup before rejection, **not foreign payload reads**, and is
not Linux NO_XDEV. Substitution, mount/firmlink and ancestor checks remain
mandatory; no atomic lookup exclusion or real-filesystem qualification is claimed.

## 5. Independent ACL retrieval and a bounded result model

### 5.1 FD security retrieval does not require FREAD

Libc `acl_get_fd_np(fd, ACL_TYPE_EXTENDED)` creates a filesec, calls `fstatx_np`,
then extracts FILESEC_ACL [Libc getter][libc-acl]. With non-NULL filesec,
`fstatx_np` goes through `statx1` and `__fstat64_extended` (for 64-bit inode ABI),
not fgetattrlist [Libc entry points][libc-statentry]. Both kernel fstat paths
look up the FD and call `vn_stat` for requested extended security, **without an
FREAD eligibility requirement** [15 fstat][15-fstat] / [26 fstat][26-fstat].
`vn_stat` authorizes READ_ATTRIBUTES|READ_SECURITY, then requests va_acl and
owner/group UUID metadata [15 stat][15-stat] / [26 stat][26-stat]. Lack of FREAD
therefore does not itself prevent ACL queries; permissions/MAC/filesystem
support can still refuse. In 26, even *basic* fstat on a non-FREAD descriptor
uses the authorized path, unlike 15's unconditional basic-stat shortcut; do not
assume identity checks are permission-free [15 fstat][15-fstat] / [26 fstat][26-fstat].

### 5.2 Why NULL/ENOENT and successful zero entries are different

- Getter NULL can arise from invalid ACL type, filesec allocation failure,
  fstatx failure, missing FILESEC_ACL property or conversion allocation/error.
  It is not a negative security assertion [Libc getter][libc-acl],
  [filesec extraction][libc-filesec]. Preserve API stage/return/errno and mark
  unavailable; errno alone does not prove filesystem-level cause.
- `statx1` clears ACL properties both for an explicit raw NOACL sentinel and
  insufficient/no filesec output [Libc loop][libc-statx]. FILESEC_ACL retrieval
  then returns ENOENT [filesec][libc-filesec]. That collapses provenance. There
  is also a realloc-failure path that leaves `error` at syscall success, sets
  errno and exits without populating the fresh filesec. Return0 from this helper
  is not enough to infer complete ACL acquisition.
- Kernel stat builds filesec only when at least one of ACL/owner UUID/group UUID
  is supported. If ACL is unsupported **or** NULL while UUID data is supported,
  it emits NOACL; if none are supported it returns no filesec. Thus even raw
  NOACL is **reported sentinel / ACL unavailable**, not physical no-ACL proof
  [15 security packing][15-statsec] / [26 security packing][26-statsec].
- Any successfully observed zero-entry ACL is **observed zero entries**, not
  physical absence or a settled access policy. Conversion preserves the returned
  count [Libc conversion][libc-convert]; `kauth.h` distinguishes NOACL from empty
  entries [15 layout][15-kauth] / [26 layout][26-kauth]. **Additional source-layout
  caveat:** statx1 tests `fsacl_size >= sizeof(struct kauth_filesec)`, while the
  public structure includes `acl_ace[1]` and KAUTH_FILESEC_SIZE(0) omits it.
  Consequently a header-only zero-count result is shorter than that sizeof test
  and follows the clear-property branch. This is a source-layout inference, not
  a measured ABI/result: these Libc paths must not be assumed to expose a
  successful empty ACL at all. A lower-level raw observer could retain that
  distinction, subject to ABI review. Do not treat `acl_get_entry` failure alone
  as a reliable count oracle: this implementation returns -1/EINVAL at iteration
  end [entry iteration][libc-entry].

### 5.3 Boundedness and candidate lower-level security getter

Libc `statx1` starts with a 16-entry heuristic allocation, repeatedly invokes
stat, and reallocates/refetches until reported size fits, with no explicit
caller retry or allocation budget [Libc:159–195][libc-statx]. **Do not call this
intrinsically unbounded on the captured kernel paths:**
`kauth_filesec_alloc` rejects counts outside 0..128 in both snapshots
[15 allocator][15-alloc] / [26 allocator][26-alloc]. With well-formed results from
these paths, every retry strictly increases `buffer_size` to the previous
reported size; valid ACL sizes rise by integral ACEs and cannot exceed 128 entries.
Starting at 16, worst-case growth by one entry yields at most 112 refetch
transitions / **113 stat calls**, even with changing ACLs. The largest requested
Libc realloc is the 128-entry filesec plus two ACEs padding (3164 bytes for the
44+24*n layout). This is a **conditional source-derived bound**, not a public
API promise or an observed run; it assumes valid layout/counts and the captured
kernel behavior, not arbitrary future providers/binaries or corrupted output.

A future proposal could review that explicit upper cost instead of assuming
unlimited looping; this note does not insist that a direct syscall is the only
possible solution. The high-level API cannot enforce a caller-selected smaller
attempt/byte budget, loses zero/sentinel/support provenance and has the error
behavior above. No public budget guarantee was established. A timeout does not
make the individual kernel/service calls hard wall-clock bounded.

**Research candidate, not a selected API:** the kernel extended-fstat boundary
accepts a supplied security-buffer length, reports the required length, and
copies security bytes only if the buffer is large enough
[15 fstat:5537–5560][15-fstat] / [26:5775–5798][26-fstat]. It does not use the
attrlist returned common mask. One fixed-capacity, initialized buffer with **one
call and no resizing/retry** could therefore distinguish a complete, valid,
non-sentinel security result from oversize/no-data/error. A later reviewed design
could select at most 128 ACEs, checked header+count*24 byte arithmetic (44-byte
header, 3116-byte total cap), exact framing/magic/flags/principals/rights checks,
and refusal on any unknown. Layout and cap appear in both
[15 kauth.h][15-kauth] / [26 kauth.h][26-kauth]; this is a conservative observer
budget, not an assurance that future kernels never return more.

This route can supply independent **positive** ACL evidence when the attrlist
ACL bit is missing, because successful non-sentinel output is copied from a
supported non-NULL va_acl. It cannot restore support provenance to NOACL or a
zero-length result. It cannot automatically replace the mask-based observer:

- `fstatx_np` is publicly declared [15 stat.h][15-stath] / [26 stat.h][26-stath],
  but its public interface contains the unbudgeted helper. Libc names
  `__fstat64_extended` internally; no supported public caller-buffer API/ABI
  commitment for direct application use was established here. No syscall number,
  private-symbol binding or FFI is proposed.
- Kernel-internal ACL allocation/filesystem I/O is not eliminated by bounding
  caller buffers and call counts. Memory/retry/FD limits and no hard wall-clock
  guarantee must be explicit.
- A single fstat-family call returns stat+security from the held vnode, but
  source does not promise an atomic multi-field snapshot or concurrent-change
  immunity. Bind/revalidate identity and metadata; never splice a successful ACL
  from one object/time onto another object's mask/permissions.
- An accepted getter contract, positive-result provenance, safe decoder and
  native 15/26 fixtures/reviews are still needed. Missing public contract is
  an unresolved input, not proof that no usable lower-level API exists.

### 5.4 Required observations, separate from access authorization

A future bounded result model should retain these independent dimensions, not a
single boolean “has ACL” and not new application code in this task:

| Observation | Evidence retained | Allowed interpretation |
| --- | --- | --- |
| `ObservedEntries(n)` including n=0 | Getter/source kind; successful complete return; raw length/count/flags/entries; same-FD identity/mount and observation interval; bounded decoding | Positive observed ACL result only. Zero means observed zero entries, not physical absence. Apply separate ownership/modes/effective search and parent-exposure policy. |
| `ReportedNoAclSentinel` | Complete raw NOACL header, successful status, same provenance | Distinct from empty; ACL support/physical absence not established. Hold where complete ACL evidence is mandatory. |
| `Unavailable` | API/stage/status, actual errno when meaningful, zero bytes or missing validity, allocation/permission/unsupported indication if actually known | Unknown, never no ACL; preserve reason without overclaiming it. NULL/ENOENT alone stays here. |
| `IncompleteOrOverBudget` | Returned required length, initialized capacity, attempts, count/overflow/truncation checks | Hold, no partial success; no unbounded retry/growth. |
| `InconsistentOrUninterpretable` | Identity/route mismatch, changes, malformed framing, unknown rights/principals/flags/membership | Hold; no silent entry skipping or denies-cancel-all-grants shortcut. |

A later application policy may accept proven harmless ACL grants; “all ACLs
unsafe” is not the accepted policy. An observer success does not prove absence
of unrelated writers, outstanding writable FDs/mappings or future replacements.
No row is an admission token by itself.

## 6. Exact remaining proof gaps and smallest next inputs

1. **Acquisition semantics:** resolve the filesystem FREAD-retry effect for
   O_EXEC/O_SEARCH on supported APFS 15/26, including compound opens, substitutions
   and failures. Need first-party filesystem/open-contract evidence or an
   explicitly reviewed interpretation of “before readable open.” Do not simply
   weaken it to no explicit POSIX read.
2. **Capability closure:** trace relevant mmap/VM maximum-protection transitions,
   MAC checks and ARM64 behavior, plus any required executable-FD conversion.
   Shared-fileglob dup/fileport facts are not enough. A restricted-wrapper claim
   requires explicit contract review rather than assumption.
3. **Bounded security interface:** identify supported 15/26 caller-buffer getter
   ABI/documentation, or review the high-level API with its conditional 113-call
   source bound and provenance limitations (or another equivalently bounded
   public route). Require independent positive ACL provenance and explicit
   unavailable/NOACL/zero-entry handling. High-level Libc success/errno behavior
   cannot be patched over by interpretation.
4. **Anchoring and policy:** root/parent bootstrap, real mount/route identity,
   harmless/dangerous grants, effective search and parent replacement/delete
   protection need a complete application argument. No independent getter fixes
   this automatically; no mode fallback or fallback-to-readable-FD acquisition.
5. **Qualification:** source establishes candidate behavior, not binaries/APFS
   behavior across the mandatory 15/26×Git2.55/2.56 configurations. SDK27 results
   cannot close those gates. A source-only answer may legitimately stay BLOCKED.

## 7. Minimal FUTURE owned-fixture matrix (not authorized or run)

Only after separately approved acquisition/API direction: disposable owned native
ARM64/APFS fixtures on **both 15 and 26**, isolated process/configuration/evidence;
no real repos/credentials, device nodes, mounts/reboots, repair or normal install.
Record OS/build/SDK/architecture/source identity, flags, process-policy context,
API returns/errno/lengths/masks, identities/mounts before/after and retained
failures. Unsupported mandatory evidence refuses, not skipped-success. Proposed
row names are concrete future tests, **not existing test additions**.

| Proposed source-named test | Minimum fixture/control and fail-closed expected outcome |
| --- | --- |
| `open_modes_regular_and_directory` | Owned executable regular and searchable directory; non-executable regular and denied-search directory controls. Inspect the chosen mode's reported semantics without relying on F_GETFL as a raw bit oracle. No automatic fallback on failure. |
| `handle_capabilities_do_not_read_payload` | For the chosen owned fixture handle: read/pread/vector variants, initial readable/exec/write mmap, and PROT_NONE→mprotect/Mach transitions where required; dup and fileport roundtrip where applicable, FD clone refusal, close-on-exec/lifetime accounting. No payload escape is acceptable; retain unexpected possible-read evidence, stop advancement. This would require separate testing permission, not given here. |
| `nofollow_type_substitution_before_open` | Owned regular/directory/symlink/FIFO/Unix-socket substitutions synchronized between component observation and acquisition; no device access. Symlink target must not be opened; wrong-type/special/changed identities refuse. Post-open refusal alone does not pass a pre-open safety claim. |
| `anchored_identity_matches_parent_component_fd` | Held parent, single-component observation, actual FD/mount identity; rename parent, replace child, replace ancestor; invalid components and absolute-path bypass controls. All mismatches refuse; unrelated same-name object is never accepted. |
| `acl_zero_nonzero_and_unavailable_are_distinct` | Explicit zero-entry, harmless nonzero, dangerous grant, no-security/unavailable, denied READ_SECURITY and missing attrlist bit controls. Record actual supported construction/outcome; do not fabricate zero-ACL capability if native API cannot construct it. Successful independent nonzero/zero evidence distinct from NULL/ENOENT/raw NOACL. |
| `security_getter_budget_and_provenance` | Synthetic decoder/FFI-boundary cases for zero/short/oversize/overflow/bad magic/unknown flags/principals/rights, allocation/errors, changing length and stale buffer; exactly capped attempts/memory and no partial success. Real owned zero/nonzero ACL success controls; same-FD identity changes/metadata changes must hold. |
| `mount_route_and_access_policy_hold` | Actual owned route observations, parent delete/replace rights, effective search, harmless ACL accepted only with complete policy; unknown/unavailable/contradictory topology holds. Foreign mounts/firmlinks only on separately authorized supplied fixtures; missing coverage is a blocker, not permission to mount. |

A tiny experiment cannot establish all-provider/all-version guarantees. If public
contract or source proof still cannot justify the pre-readable property, report
the exact blocked row and preserve evidence rather than proceeding to Git.

## 8. Self-review and scope validation

Rechecked the prior audit's four central facts directly: extended-security FD
queries do not require FREAD; NULL/ENOENT is ambiguous; empty means observed
zero entries; EVTONLY stripping is process-policy dependent. Also checked both
published families for O_EXEC/O_SEARCH, FREAD retries and mmap concerns. Did not
turn a source gap into impossibility or a private implementation into a public
API guarantee. Compared candidate ancillary write/execute/search effects and
open/type/mount identity limitations with the exact accepted boundary.

Only this Markdown note is a tracked change. New captures/provenance/checksums
are owned ignored target artifacts. No native experiment, compilation, test,
container, payload probe, tool/helper-prefix execution, authority onboarding,
configuration write, push, installation, mount/reboot or cleanup was run. TDD is
not applicable to source-only documentation; the matrix above is explicitly
future work. Documentation/source-integrity checks, not runtime verification,
are the validation evidence. Independent SPEC/QUALITY review remains required;
source-only findings do not establish release readiness.

## 9. Durable checksum inventory

Reused input provenance SHA256:
`PROVENANCE.md=c6e6d25763a45c4a04881b938166c98587e3a48d1ee025105da025172f0a2ed7`;
`SHA256SUMS=d0b37751bca3171d42cc53b1efd63c5a72b15a041234408296e5ebcce5fb6b47`.
Prior audit SHA256:
`2b3c670157afd3e7edab28c23837a84492a2e3143a569112b95412c8566beb17`.
The tables below pin bytes used here, independent of temporary-directory lifetime.
Local `15-`/`26-` prefixes select the commits in §2; unprefixed Libc is26.

### Reused primary captures

| Capture / immutable source | SHA256 |
| --- | --- |
| [15-acl_file.c](https://github.com/apple-oss-distributions/Libc/blob/af11da5ca9d527ea2f48bb7efbd0f0f2a4ea4812/posix1e/acl_file.c) | `61a075c38c4c3d5d382248d9b0a52894012f54d8310009402c218e7907c76b78` |
| [15-acl.c](https://github.com/apple-oss-distributions/Libc/blob/af11da5ca9d527ea2f48bb7efbd0f0f2a4ea4812/posix1e/acl.c) | `598c6cbeb8aa65b852e2a0b2de567de051bdfa2bccb6cce34027084e33c3fcef` |
| [15-acl_entry.c](https://github.com/apple-oss-distributions/Libc/blob/af11da5ca9d527ea2f48bb7efbd0f0f2a4ea4812/posix1e/acl_entry.c) | `9fdc2b0c787a6305f1a26a11910f34de031e7ac242086428de8feade43680919` |
| [15-acl_translate.c](https://github.com/apple-oss-distributions/Libc/blob/af11da5ca9d527ea2f48bb7efbd0f0f2a4ea4812/posix1e/acl_translate.c) | `929b16ba8d52527c1bb4812ed7ed25f3e43f315516898d1bd777a10ca690e4c2` |
| [15-filesec.c](https://github.com/apple-oss-distributions/Libc/blob/af11da5ca9d527ea2f48bb7efbd0f0f2a4ea4812/gen/filesec.c) | `ae040dd45027269485360f736bf983d1371f25bac5c56184a7b2d7021490a454` |
| [15-statx_np.c](https://github.com/apple-oss-distributions/Libc/blob/af11da5ca9d527ea2f48bb7efbd0f0f2a4ea4812/sys/statx_np.c) | `5a05eabc7d870f2c1a98c4e3b828d020e4a51e4b60c6887d955422add747730d` |
| [acl_file.c](https://github.com/apple-oss-distributions/Libc/blob/4e34d0559e3a1b081afeb8604d9e204a1f31321d/posix1e/acl_file.c) | `61a075c38c4c3d5d382248d9b0a52894012f54d8310009402c218e7907c76b78` |
| [acl.c](https://github.com/apple-oss-distributions/Libc/blob/4e34d0559e3a1b081afeb8604d9e204a1f31321d/posix1e/acl.c) | `598c6cbeb8aa65b852e2a0b2de567de051bdfa2bccb6cce34027084e33c3fcef` |
| [acl_entry.c](https://github.com/apple-oss-distributions/Libc/blob/4e34d0559e3a1b081afeb8604d9e204a1f31321d/posix1e/acl_entry.c) | `9fdc2b0c787a6305f1a26a11910f34de031e7ac242086428de8feade43680919` |
| [acl_translate.c](https://github.com/apple-oss-distributions/Libc/blob/4e34d0559e3a1b081afeb8604d9e204a1f31321d/posix1e/acl_translate.c) | `929b16ba8d52527c1bb4812ed7ed25f3e43f315516898d1bd777a10ca690e4c2` |
| [filesec.c](https://github.com/apple-oss-distributions/Libc/blob/4e34d0559e3a1b081afeb8604d9e204a1f31321d/gen/filesec.c) | `ae040dd45027269485360f736bf983d1371f25bac5c56184a7b2d7021490a454` |
| [statx_np.c](https://github.com/apple-oss-distributions/Libc/blob/4e34d0559e3a1b081afeb8604d9e204a1f31321d/sys/statx_np.c) | `5a05eabc7d870f2c1a98c4e3b828d020e4a51e4b60c6887d955422add747730d` |
| [15-kern_descrip.c](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_descrip.c) | `7385f86a8c0b98946f00d0993b4ece5a3707faf4443bfb0232bcc5e5ae5bb494` |
| [26-kern_descrip.c](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/kern_descrip.c) | `5ec7c4392f60733bb44c8d2df61870bbabf9b4d7c474032e30eac129b3f2d258` |
| [15-vfs_vnops.c](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/vfs/vfs_vnops.c) | `6a62654f54843addf467652c6e6469ba68cf391a79ffd70402801183dde90ad2` |
| [26-vfs_vnops.c](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/vfs/vfs_vnops.c) | `d45d4bf1d4e1e8079e1fb6c7275eb73e211833619c0b3f08ed3d637dc3d3e05a` |
| [15-vfs_syscalls.c](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/vfs/vfs_syscalls.c) | `444fc3f4bc2f37abecb5520263337a3bb530565b90d5dee625b95a2806cc538d` |
| [26-vfs_syscalls.c](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/vfs/vfs_syscalls.c) | `67cfe165523ac4375504241a418d3cebbb46a4a10b77b22c5d590a31ebd0235d` |
| [26-vfs_attrlist.c](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/vfs/vfs_attrlist.c) | `ac3fe4827e77cd0f98af117e0107e8788723435490b7b4a514d12c666b225fc3` |
| [distribution-150-tree.json](https://api.github.com/repos/apple-oss-distributions/distribution-macOS/git/trees/fafa0d30e9943c16e82740488dc0750c24355562) | `33b8215483082385176798149369812e5bfb78924b7d2bcbdea0cd8336e81a37` |
| [distribution-265-tree.json](https://api.github.com/repos/apple-oss-distributions/distribution-macOS/git/trees/83390100289cedfe669c31a96c94326d31afa1ed) | `48042c675f7ec8c4f9737bb3dfc1bfc2212de0c5a15bda47b933113b8153b1e7` |
| [15-kern_authorization.c](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_authorization.c) | `a7d9e1bdbb4feacd4edfa2731958471300c7577a0516c4b8031aac22f4655126` |
| [26-kern_authorization.c](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/kern_authorization.c) | `6909f51300732fe195252b9de1ce0a2fb5d086af9072dc5746269a8ffeb2e249` |

### New primary captures

| Capture / immutable source | Bytes | SHA256 |
| --- | ---: | --- |
| [15-fcntl.h](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/sys/fcntl.h) | 35541 | `97220cde64577effbad0a48c0d8b3cb3f41e0b3d2db7a5c43df064dcff180dd4` |
| [15-file_internal.h](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/sys/file_internal.h) | 18695 | `eecc3ac648ef62b90cefeeb9f13ab82fa166018abedc2a04b64ccf9dcef3fc09` |
| [15-kauth.h](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/sys/kauth.h) | 38566 | `9009cb706a24501dff4f47024c63dc730618249d85dd050f2bf97515a3ca6098` |
| [15-kern_mman.c](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_mman.c) | 47787 | `89ad7efb9225a4e2b5ada91df0068667bb9979a980641c259c754ac82100e637` |
| [15-open.2](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/man/man2/open.2) | 14012 | `2f0b2523bc1f1cbaf5f0a1354eff9eb0873d3a4fb39f5c4bd571fbcdef538707` |
| [15-stat.h](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/sys/stat.h) | 30233 | `dd8154be80f467ba57d4edaa7c6617bd32db54bfebdda892b390f9b0364fe488` |
| [15-sys_generic.c](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/sys_generic.c) | 78455 | `46403bd8485d9ca78d5dc5dce6dbb3bf3afca1445c93de13db38852e66ee0414` |
| [15-vfs_subr.c](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/vfs/vfs_subr.c) | 338286 | `3e0d2577db3650146a51488fe2d64b19512d1a26140e726f4e8622ab9e7747a6` |
| [26-fcntl.h](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/sys/fcntl.h) | 32748 | `5d227b5ec649d710a9cc938ff2f9b9b929e1932cdcd24c868a3d74e877c3fbe0` |
| [26-file_internal.h](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/sys/file_internal.h) | 18670 | `b1898582da217112a7c966b2b124525cfeab60f2a66a57c2809fcb7af7da29d3` |
| [26-kauth.h](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/sys/kauth.h) | 38566 | `9009cb706a24501dff4f47024c63dc730618249d85dd050f2bf97515a3ca6098` |
| [26-kern_mman.c](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/kern_mman.c) | 51778 | `cf8c0d8923c718bd80ec1cc569d57ea5b45f0d895123c4e1b48a51b5de2cada3` |
| [26-open.2](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/man/man2/open.2) | 14824 | `2bb0b53e538c46cee9bb5b935fb14a7dcfc868735f7b4a6c339babd8be18ac61` |
| [26-stat.h](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/sys/stat.h) | 30233 | `dd8154be80f467ba57d4edaa7c6617bd32db54bfebdda892b390f9b0364fe488` |
| [26-sys_generic.c](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/sys_generic.c) | 72868 | `4d50d6beb87bd71b9dc669e9154c8250f1394ec6806f716fa1caac1f9e4c1fc6` |
| [26-vfs_subr.c](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/vfs/vfs_subr.c) | 346449 | `75ffa35def63c2f3a4d815dce2c147717f90e5ca6518a1970058c380aa192738` |

Total new source: **16 files, 1207711 bytes** (about 1.15MiB). Provenance/checksum text adds only a few KiB.


## Immutable primary-source references (path:line)

[15-flags]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/sys/fcntl.h#L96-L239 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/sys/fcntl.h:96–239"
[26-flags]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/sys/fcntl.h#L96-L246 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/sys/fcntl.h:96–246"
[15-open1]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/vfs/vfs_syscalls.c#L4606-L4678 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/vfs/vfs_syscalls.c:4606–4678"
[26-open1]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/vfs/vfs_syscalls.c#L4919-L4991 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/vfs/vfs_syscalls.c:4919–4991"
[15-open1tail]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/vfs/vfs_syscalls.c#L4680-L4732 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/vfs/vfs_syscalls.c:4680–4732"
[26-open1tail]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/vfs/vfs_syscalls.c#L4993-L5045 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/vfs/vfs_syscalls.c:4993–5045"
[15-vnopen]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/vfs/vfs_vnops.c#L541-L674 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/vfs/vfs_vnops.c:541–674"
[26-vnopen]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/vfs/vfs_vnops.c#L579-L732 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/vfs/vfs_vnops.c:579–732"
[15-finish]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/vfs/vfs_vnops.c#L184-L207 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/vfs/vfs_vnops.c:184–207"
[15-mmap]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_mman.c#L343-L939 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/kern/kern_mman.c:343–939"
[26-mmap]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/kern_mman.c#L346-L909 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/kern/kern_mman.c:346–909"
[15-authopen]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/vfs/vfs_subr.c#L8165-L8270 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/vfs/vfs_subr.c:8165–8270"
[26-authopen]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/vfs/vfs_subr.c#L8340-L8484 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/vfs/vfs_subr.c:8340–8484"
[15-man]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/man/man2/open.2#L103-L251 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/man/man2/open.2:103–251"
[26-man]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/man/man2/open.2#L103-L253 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/man/man2/open.2:103–253"
[15-read]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/sys_generic.c#L225-L258 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/kern/sys_generic.c:225–258"
[26-read]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/sys_generic.c#L227-L260 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/kern/sys_generic.c:227–260"
[15-write]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/sys_generic.c#L525-L555 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/kern/sys_generic.c:525–555"
[26-write]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/sys_generic.c#L527-L557 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/kern/sys_generic.c:527–557"
[15-dup]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_descrip.c#L520-L580 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/kern/kern_descrip.c:520–580"
[26-dup]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/kern_descrip.c#L555-L615 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/kern/kern_descrip.c:555–615"
[15-fcntl]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_descrip.c#L2856-L2900 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/kern/kern_descrip.c:2856–2900"
[26-fcntl]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/kern_descrip.c#L2941-L3019 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/kern/kern_descrip.c:2941–3019"
[15-fileport]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_descrip.c#L5830-L5965 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/kern/kern_descrip.c:5830–5965"
[26-fileport]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/kern_descrip.c#L6066-L6201 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/kern/kern_descrip.c:6066–6201"
[15-clone]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/vfs/vfs_syscalls.c#L8935-L8970 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/vfs/vfs_syscalls.c:8935–8970"
[26-clone]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/vfs/vfs_syscalls.c#L9445-L9480 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/vfs/vfs_syscalls.c:9445–9480"
[15-fdreopen]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_descrip.c#L1821-L1913 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/kern/kern_descrip.c:1821–1913"
[26-fdreopen]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/kern_descrip.c#L1854-L1946 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/kern/kern_descrip.c:1854–1946"
[15-anchor]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/vfs/vfs_syscalls.c#L4895-L4949 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/vfs/vfs_syscalls.c:4895–4949"
[26-anchor]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/vfs/vfs_syscalls.c#L5211-L5229 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/vfs/vfs_syscalls.c:5211–5229"
[15-fstat]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_descrip.c#L5426-L5570 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/kern/kern_descrip.c:5426–5570"
[26-fstat]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/kern_descrip.c#L5662-L5807 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/kern/kern_descrip.c:5662–5807"
[15-stat]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/vfs/vfs_vnops.c#L1450-L1497 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/vfs/vfs_vnops.c:1450–1497"
[26-stat]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/vfs/vfs_vnops.c#L1523-L1578 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/vfs/vfs_vnops.c:1523–1578"
[15-statsec]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/vfs/vfs_vnops.c#L1587-L1667 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/vfs/vfs_vnops.c:1587–1667"
[26-statsec]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/vfs/vfs_vnops.c#L1656-L1734 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/vfs/vfs_vnops.c:1656–1734"
[15-kauth]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/sys/kauth.h#L604-L707 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/sys/kauth.h:604–707"
[26-kauth]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/sys/kauth.h#L604-L707 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/sys/kauth.h:604–707"
[15-stath]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/sys/stat.h#L589-L609 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/sys/stat.h:589–609"
[26-stath]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/sys/stat.h#L589-L609 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/sys/stat.h:589–609"
[26-pack]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/vfs/vfs_attrlist.c#L2083-L2098 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/vfs/vfs_attrlist.c:2083–2098"
[libc-acl]: https://github.com/apple-oss-distributions/Libc/blob/4e34d0559e3a1b081afeb8604d9e204a1f31321d/posix1e/acl_file.c#L73-L91 "Libc 4e34d0559e3a1b081afeb8604d9e204a1f31321d, posix1e/acl_file.c:73–91"
[libc-statentry]: https://github.com/apple-oss-distributions/Libc/blob/4e34d0559e3a1b081afeb8604d9e204a1f31321d/sys/statx_np.c#L56-L129 "Libc 4e34d0559e3a1b081afeb8604d9e204a1f31321d, sys/statx_np.c:56–129"
[libc-statx]: https://github.com/apple-oss-distributions/Libc/blob/4e34d0559e3a1b081afeb8604d9e204a1f31321d/sys/statx_np.c#L144-L220 "Libc 4e34d0559e3a1b081afeb8604d9e204a1f31321d, sys/statx_np.c:144–220"
[libc-filesec]: https://github.com/apple-oss-distributions/Libc/blob/4e34d0559e3a1b081afeb8604d9e204a1f31321d/gen/filesec.c#L67-L195 "Libc 4e34d0559e3a1b081afeb8604d9e204a1f31321d, gen/filesec.c:67–195"
[libc-convert]: https://github.com/apple-oss-distributions/Libc/blob/4e34d0559e3a1b081afeb8604d9e204a1f31321d/posix1e/acl_translate.c#L172-L205 "Libc 4e34d0559e3a1b081afeb8604d9e204a1f31321d, posix1e/acl_translate.c:172–205"
[libc-entry]: https://github.com/apple-oss-distributions/Libc/blob/4e34d0559e3a1b081afeb8604d9e204a1f31321d/posix1e/acl_entry.c#L117-L149 "Libc 4e34d0559e3a1b081afeb8604d9e204a1f31321d, posix1e/acl_entry.c:117–149"
[dist15]: https://api.github.com/repos/apple-oss-distributions/distribution-macOS/git/trees/fafa0d30e9943c16e82740488dc0750c24355562
[dist26]: https://api.github.com/repos/apple-oss-distributions/distribution-macOS/git/trees/83390100289cedfe669c31a96c94326d31afa1ed

[15-alloc]: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_authorization.c#L1060-L1078 "xnu 8d741a5de7ff4191bf97d57b9f54c2f6d4a15585, bsd/kern/kern_authorization.c:1060–1078"
[26-alloc]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/kern_authorization.c#L1032-L1050 "xnu ac9718fb1af618d5ce8678d0dc6e8a58f252216f, bsd/kern/kern_authorization.c:1032–1050"
