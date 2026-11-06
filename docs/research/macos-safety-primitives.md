# macOS primitives for equivalent Work safety guarantees

Research resolution for [Establish macOS primitives for equivalent Work safety guarantees](https://github.com/techwright-lab/work-cli/issues/14), under [Map native Apple Silicon support and single-command distribution for work-cli](https://github.com/techwright-lab/work-cli/issues/13).

- **Source baseline:** `41d01c3a6f1ea2bafcc7432240f725c55c810781` (main).
- **Research date:** 2026-11-06.
- **Scope:** core setup, status, start/reuse, finish, preview removal and explicitly confirmed safe removal on `aarch64-apple-darwin`; retain the existing Linux guarantees. No implementation, OS/filesystem support-policy selection, migration approval, supervision design, release qualification, or publication approval is implied.
- **Method:** read baseline source and tests; retrieve primary Apple/XNU, POSIX, Rust/rustix and SQLite sources. API/source inspection is evidence of a primitive, **not** evidence that the complete workflow is qualified. No build, installation, authority/configuration inspection, live repository lifecycle mutation, or local file change was performed. The report is the sole branch-only artifact.

## 1. Findings at a glance

**There are plausible native primitives for much of the core, but equivalent end-to-end safety is not yet established.** In particular, do not reduce the port to conditional compilation or replacing `/proc` paths.

| Area | Classification | Finding and consequence |
|---|---|---|
| Accountable owner, limits, lifecycle journal | Equivalent logical mechanism, pending native qualification | Existing SQL transactions, leases, immutable retry identity and retained charges are not intrinsically Linux policy. Preserve them; do not replace unknown disk space or native outcomes with success. [C1][C2][C7] |
| Descriptor-relative access | Available primitives, incomplete equivalence | Apple has `openat`, `O_DIRECTORY`, `O_NOFOLLOW`, and newer whole-path `O_NOFOLLOW_ANY` / `O_RESOLVE_BENEATH`. It is **incorrect** to say macOS categorically lacks beneath resolution. These are not the existing rustix `openat2` interface, and no public open-flag equivalent for the complete `NO_XDEV` contract was established here. [A1][A2][R1][R2] |
| Inspect type before readable open; retain exact object | Major unqualified seam | Linux inspection relies on `O_PATH`, trusted `/proc/<self>/fd` reopening, and Linux-only `RawDir`. Apple `O_EVTONLY`, `O_SYMLINK`, `O_SEARCH` and ordinary readable descriptors are not established drop-in replacements. The current collector refuses stable special files **before** readable data open. [C3][A1][R1][R2] |
| Create-only/no-replace | Native equivalent with capability qualification | `renameatx_np(..., RENAME_EXCL)` rejects an existing destination on supporting filesystems; `O_CREAT|O_EXCL` provides exclusive file creation. Locked rustix maps `RenameFlags::NOREPLACE` to Apple's flag. Check the filesystem capability and actual operation; never emulate with check-then-plain-rename. [A1][A3][A4][R2][R3][P1] |
| Filesystem/boot identity | Useful primitives, compatibility unknown | `fstat` identity fields, filesystem UUID/file-ID queries, and read-only `kern.bootsessionuuid` exist. They do not authorize restoring copied authority records, dismissing inode reuse, or treating reboot as permission. Serialized identity compatibility needs an explicit design. [A5][A6][A7][C4][C8] |
| Cooperative locking | Strong candidate equivalent | Apple `flock` supplies shared/exclusive/nonblocking locks, with shared lock identity across `dup`/`fork`. It is advisory, not exclusion against arbitrary writers. Retain explicit unlock-on-owner-drop and revalidation. [A8][C5][C6] |
| Durability | Existing useful behavior plus a real gap | Rust **1.98.1** already maps Apple `File::sync_all` to `F_FULLFSYNC`; adding it everywhere as if absent would misdiagnose the code. SQLite `synchronous=FULL` is separate from `fullfsync`, which defaults off. Even requested SQLite full sync can fall back to ordinary `fsync`. Directory/device behavior still needs qualification. [R4][A9][A10][S1][S2][C6] |
| Safe removal | Preserve state machine; native collector is a blocker | Keep stopped-writer confirmation, preservation refs, fresh inspection, durable intent, native Git removal and anchored absence checks. A clean Git status, lock, process scan, rename or completed task is not deletion authority. [C7][C9] |
| Process scope | Core child cleanup is relevant; supervision is excluded | Core Git helpers already use process groups and unreaped-child `waitid(WNOWAIT)`. Apple exposes the needed wait flags; historical `/proc`/cgroup/systemd supervision cannot be replaced by process-name scans or a launch service. [C10][A11][R5][P2][C11] |

## 2. The actual baseline safety contract and implementation seams

The baseline explicitly describes a **cooperative**, trusted host-local authority, not protection against a malicious same UID. It separates task finish, operator confirmation that writers are stopped, and removal. It retains capacity through unknown outcomes and promises local preservation, not off-host backup. Those limits are part of equivalence, not gaps to silently “fix” with a different policy. [C6][C9]

| Baseline source | Relevant responsibilities/dependencies |
|---|---|
| [`admission.rs`][C1], [`ownership.rs`][C2] | `BEGIN IMMEDIATE`, repository/owner counts, immutable request digest, capacity denial for unknown available bytes; transfer/retirement preserve accountability. |
| [`store.rs`][C6] | Host-local private authority/registry, ownership/mode/link validation, allocation/schema flock identities, Linux filesystem-magic allowlist, WAL plus `synchronous=FULL`, initialization and directory sync ordering. |
| [`checkout_guard.rs`][C5] | Retained authority/directory/file identity; exact private modes; `openat2` with `BENEATH|NO_SYMLINKS|NO_MAGICLINKS|NO_XDEV`, `O_PATH`, shared/exclusive nonblocking locks, explicit unlock in `Drop`. |
| [`identity.rs`][C4], [`recovery.rs`][C8] | Checkout `(device,inode)`, canonical checkout/private/common paths, HEAD, Git backlink/registration and Linux boot UUID. Recovery keeps inode/path checks; device equality is conditional on the same boot. |
| [`allocate.rs`][C12] | Source/destination and branch checks, reservation/physical-creation stages, root `statvfs`, `f_bavail.checked_mul(f_frsize)`, markers and directory synchronization, Store-bound authority leases. |
| [`inspection.rs` filesystem module][C3] | Retained path-component anchors and object handles, bounded census/hash/read/reenumeration, regular-file validation before readable opens, trusted procfs descriptor reopening, no-mount-crossing checks, boot evidence and descriptor-bound preservation syncing. |
| [`setup.rs` staging writer][C13] | Exclusive stage creation, private lock, staged write/sync; distinct authorized replacement versus `renameat_with(NOREPLACE)` publication. No port should conflate those two modes. |
| [`inspection/removal.rs`][C7], [`removal_journal.rs`][C14] | Ordinary finished checkout only; history/identity checks, clean retained collections, preserve roots, sync objects/refs, Git fsck, intent before dispatch, native result and verified absence before releasing capacity. Unknown intent is not replay authority. |
| [`bounded_process.rs`][C10] | Bounded stdout/stderr/input and runtime, fresh process group, observe exit without reaping, kill owned group, then wait; not malicious `setsid` containment or a hard bound on uninterruptible I/O. Its detailed `/proc` birth-identity observations are in the **test module**, not the production runner. |
| [`scope_driver.rs`][C11], `linux_scope.rs`, `scope_child.rs`, historical participation/run modules | Linux process birth/cgroup membership and systemd scope evidence. These are distinct from core Git-helper lifetime ownership; macOS supervision is expressly outside this map. |

The crate has `#![forbid(unsafe_code)]`, and the lockfile fixes rustix **1.1.5** and libsqlite3-sys **0.36.0**. An Apple C API being present does not mean the currently used safe Rust interfaces expose it. Any binding/library change and the handling of unsupported historical commands need later specification, not an unreviewed unsafe workaround. [C15][C16][R1][R2]

## 3. Primitives and limits

### 3.1 Ownership and private local storage

**Candidate equivalent:** UID, mode, link count, file type and descriptor/name identity comparisons are available through `stat`/`fstat` and Unix metadata. Apple's `stat` documentation supplies device, inode, ownership, link count and timestamps; POSIX defines the corresponding information and no-follow `lstat`/`fstatat` behavior. [A5][P3]

**Additional constraint:** Apple's filesystem security model includes ACLs and per-file flags as well as mode bits, and ownership/permissions checking can be disabled on some volumes. Its mount flags include `MNT_IGNORE_OWNERSHIP`; `MNT_LOCAL` only says the filesystem is stored locally. Therefore a Linux-style numeric magic allowlist and a mode-bit-only private-directory check are not established sufficient Apple admission evidence. This is a platform-admission issue, not permission to chmod, remove inherited ACLs, or reconfigure a volume. [A12][A13][C6]

**Fail closed:** unqualified filesystem, ignored ownership, unverifiable effective access, altered descriptor/name binding, linked lock/database, symlink ancestor, unsupported mount or unavailable mandatory metadata must prevent mutation/admission, with existing state retained. Supporting inherited ACLs versus rejecting them is **not decided here**. Prototype the observation/refusal first; do not silently grant other users access or rewrite existing permissions. [C5][C6]

**Unknown:** the exact effective-access test and safe Rust API coverage necessary to preserve private authority semantics, including existing authorities on ACL-bearing directories. Stock macOS path aliases must also be exercised: canonicalizing a string is not evidence that every later access used retained, no-follow anchors. Current setup already distinguishes read-only config discovery from write refusal for symlinked paths. [C13][C17]

### 3.2 Path containment, type-before-open and bounded enumeration

**Established native building blocks:** Apple's `openat` resolves a relative path against a directory FD; `O_NOFOLLOW` rejects a final symlink; `O_NOFOLLOW_ANY` rejects symlinks anywhere in the path; `O_RESOLVE_BENEATH` rejects escape from the starting directory. POSIX's ordinary `openat`/`O_NOFOLLOW` alone must not be presented as whole-path beneath/no-symlink resolution. [A1][A2][P1]

**Not yet an equivalent implementation:**

1. Locked rustix exports `openat2` only for its Linux raw dependency and `RawDir` only for Linux; its `OFlags::PATH` is not exposed for Apple. In rustix 1.1.5, `OFlags::RESOLVE_BENEATH` is exposed for FreeBSD, not Apple, notwithstanding Apple's newer native header. [R1][R2]
2. No inspected public Apple open flag establishes Linux `RESOLVE_NO_XDEV` behavior. Comparing `st_dev` after an open detects some crossings but is not a demonstrated substitute for prohibiting traversal in the lookup itself, including same-filesystem alternate mounts and firmlink/mount topology. The source exposes internal `NOCROSSMOUNT`; that is **not** proof of a public user-space open API. [A1][A2][A14]
3. Apple's `O_EVTONLY` is documented for change monitoring and explicitly does not prevent volume unmount; `O_SYMLINK` can open a symlink itself. Neither documentation establishes Linux `O_PATH` plus trusted-procfs reopening semantics. `O_SEARCH` addresses directories, not arbitrary file objects. [A1][A2]
4. `F_GETPATH` returns a pathname (and `F_GETPATH_NOFIRMLINK` a non-firmlinked pathname). Reopening that string would not reopen a retained object by identity; pathname replacement remains possible. Do not call it a descriptor-reopen equivalent. [A10][C3]
5. A naive readable `openat(O_NONBLOCK|O_NOFOLLOW)` followed by `fstat` can already have opened a device or special file before rejecting it. `O_NONBLOCK` is not a universal “safe metadata-only open.” The baseline test deliberately requires special files never reach the readable-open boundary. [A1][P1][C3][C18]
6. Replacing the bounded `RawDir` collector with high-level enumeration needs evidence for syscall/refill accounting, name-byte limits, independent cursors, retained parents and deterministic ordering. A second enumeration is a change detector, not a filesystem snapshot. [C3][C18]

**Testable hypotheses, not approved fallbacks:** a descriptor-relative single-component walk with retained ancestors and strict component validation might provide sufficient cooperative containment on a qualified mount topology; an Apple event-only/object-handle strategy might enable type validation and a safe subsequent readable open. Neither is accepted as equivalent by this research. A precheck followed by pathname reopening must pass the original replacement/special-file tests and any stronger necessary race proof, rather than merely “usually” detecting replacement afterward. [C3][C18]

Until these seams are demonstrated, affected inspection, preservation and destructive operations must report incomplete/unsupported rather than enabling removal on Git cleanliness alone. [C7][C18]

### 3.3 Exclusive creation and no-replace rename

Apple documents `renameatx_np` and `RENAME_EXCL`: supporting filesystems return `EEXIST` if the target already exists. The header marks `renameatx_np` available from **macOS 10.12**, while `renameat`/`openat` are from **10.10**. Filesystem support is separate: inspect the `ATTR_VOL_CAPABILITIES` valid and supported bits for `VOL_CAP_INT_RENAME_EXCL`, then test actual collisions and errors. An unknown/invalid capability bit is not positive support. [A1][A3][A4][A6]

The locked rustix Apple backend maps `NOREPLACE` to `RENAME_EXCL` and calls `renameatx_np`. If that symbol is unavailable, its fallback rejects nonempty flags or retained-dirfd usage with `NOSYS`, rather than silently plain-renaming. This is useful existing behavior. [R2][R3]

**Preserve:** exclusive stage creation and exclusive final publication are distinct from an explicitly authorized replacement. An absent-path precheck followed by `rename` is not exclusive publication. `EXDEV`, unsupported operations, collision, and errors after a possible mutation must not trigger copy/delete or clobber fallback. A no-replace rename also does not revoke open FDs or an existing cwd. Baseline Git move explicitly acknowledges the latter constraint and requires same-filesystem pre/post identity validation. [P1][A3][C4][C13]

### 3.4 Filesystem identity, reboot and restoration

Apple offers `st_dev`/`st_ino`; `ATTR_CMN_FILEID` identifies an object within its mounted volume and is documented as equivalent to `st_ino`, while `ATTR_VOL_UUID` returns a filesystem UUID. Volume capabilities distinguish persistent object IDs from other file-ID behavior. Apple's `st_gen` is documented as superuser-only, so it is not a demonstrated unprivileged generation solution. None of these sources establishes a globally unique, never-reused, clone-proof identity for a copied authority. [A5][A6][A4]

**Boot candidate:** the inspected XNU source exports `kern.bootsessionuuid` as a read-only string sysctl; it separately exposes `kern.boottime` and userspace-reboot fields. This is a concrete primary-source candidate, not merely a shell command that prints a time. However, this research has not established a documented support floor or complete lifecycle contract across full reboot, userspace restart, suspend/hibernate and VM restore. Do not substitute hostname, hardware/host UUID, wall time, PID or filesystem UUID for a boot session. [A7]

**Compatibility matters:** baseline `CheckoutIdentity` serializes `device`, `inode`, `boot_id` and Git paths; the collector expects Linux boot UUID bytes including a newline, and evidence/journal formats bind filesystem and boot observations. Recovery currently allows a changed device across a different boot but still requires path and inode agreement. An Apple provider must not accidentally invent a boot transition by formatting differently, compare incompatible identity domains, or interpret an old Linux/procfs receipt as fresh macOS authority. [C3][C4][C8][C19]

**Fail closed:** absent/short/malformed boot observations, changes during collection, restored/copied databases or markers with changed identities, missing registration and replacement directories are reconciliation/hold cases, never automatic charge release. Whether the portable representation changes, how mixed-platform historical state is recognized, and how an operator recovers selected work into fresh state are unresolved specification topics, not an authorization to rewrite identities. [C6][C7][C8][C9]

### 3.5 Locks, durability and crash consistency

**Lock candidate:** Apple `flock` is advisory and supports shared/exclusive/nonblocking operations. `dup`/`fork` reference the same lock; an explicit unlock by one duplicate affects that lock. This fits the baseline's explicit unlock in the RAII owner, independent opens for independent participants, `CLOEXEC`, never-unlinked lock names and descriptor/name identity checks. Test it across processes, independent shared owners, inherited descriptors and replacement; do not exchange it for POSIX record locks without revalidating ownership semantics. [A8][C5][C6][C12]

**Durability has three separate layers:**

1. Apple `fsync` documentation warns that flushing to a drive need not flush the drive's cache or preserve write order on power loss. `F_FULLFSYNC` requests the stronger flush. This is still an OS/device acknowledgement, not a backup guarantee. [A9][A10]
2. The exact pinned Rust **1.98.1** standard-library implementation calls `fcntl(F_FULLFSYNC)` for Apple `File::sync_all` and `sync_data`. Existing Work `sync_all` calls therefore already select that path when compiled for Apple. Confirm the behavior on regular files **and directories**; do not suppress errors or silently weaken directory ordering when the stronger primitive is unsupported. [R4][C6][C12][C13][C19]
3. Work's SQLite connections use WAL and `PRAGMA synchronous=FULL`, but that does not set Apple's `PRAGMA fullfsync`. SQLite documents both `fullfsync` and `checkpoint_fullfsync` as default-off; setting fullfsync affects all syncs, making checkpoint_fullfsync redundant. More importantly, the exact locked libsqlite3-sys **0.36.0** bundles SQLite **3.51.1**, whose Unix `full_fsync` explicitly falls back to ordinary `fsync` when `F_FULLFSYNC` fails. A successful transaction or setting alone therefore does not prove the stronger flush succeeded. [C6][C16][S1][S2]

For the last point, the crate artifact was fetched **in memory** and its SHA-256 matched the baseline lockfile: `95b4103cffefa72eb8428cb6b47d6627161e51c2739fc5e3b734584157bc642a`. Its bundled source identifies SQLite 3.51.1 and has `full_fsync` at line 42973 and the fallback at lines 43016–43024. No crate was installed or extracted to the checkout. [S2][C16]

**Unresolved guarantee:** baseline preservation sync describes “OS fsync ACK only”; that is not an unconditional promise against faulty hardware. The macOS specification must define the equivalent acknowledged durability boundary for authority WAL, initialization marker, allocation marker, recovery objects/refs and removal journal, then show their ordering on the qualified storage. It must address the SQLite fallback, rather than infer that APFS copy-on-write, `synchronous=FULL`, or one successful probe proves every later flush. Process-crash tests cannot establish power-loss persistence. [C6][C19][A9][S1][S2]

### 3.6 Capacity, names and non-Git metadata

**Capacity equivalent candidate:** preserve the current byte-based observation (`f_bavail * f_frsize`, checked for overflow) and the SQL reservation counts. Apple `statfs` identifies blocks available to non-superuser callers, filesystem identity/type name and mount flags. Rustix's portable `StatVfs` has explicit `u64` byte/block-related fields. A successful space observation is not reserved disk capacity; concurrent consumption or ENOSPC after reservation must remain a held/recoverable operation, not erase the charge. Unknown is not zero, unlimited, or a reason to raise configured limits. [A13][R2][C1][C12]

**Filesystem-dependent behavior to qualify:** Apple documents case-sensitive and case-insensitive APFS variants, normalization-insensitive behavior in released High Sierra-era variants, and names returned in hash rather than lexicographic order. Those historical descriptions are useful hypotheses, not current qualification. Volume capability bits also expose case sensitivity/preservation. Test ASCII case collisions, Unicode-equivalent aliases, canonical root/common-dir aliases and Git's `core.ignorecase`/`core.precomposeunicode` interactions without normalizing away distinct evidence. The collector must retain byte-protocol bounds and sort its own observations. Choosing a supported case/normalization policy is outside this report. [A15][A4][C1][C3]

**Metadata gap:** Apple extended attributes are name/data pairs on objects, including directories and symlinks, and `flistxattr` provides descriptor-based enumeration. Apple documents filesystem security beyond Unix mode bits. The baseline census hashes regular-file contents and captures selected stat metadata; it does not enumerate ACLs or xattrs as independent payload. Thus “Git clean plus equal data fork” has not established preservation of all macOS metadata/resource-fork-bearing work. This is a demonstrable coverage gap, not a decision that every attribute is user payload or that every attribute should be discarded. Define the boundary with the operator; until required metadata is understood/proven preservable, do not claim full removal eligibility. [A12][A16][C3][C7]

APFS cloning, snapshots, shared space, volume quotas/reserves and external-storage failure behavior need owned-fixture measurements; this report does not substitute logical file sizes, reclaimable/purgeable space or a directory-size estimate for the existing capacity policy. [C1][C12]

### 3.7 Core child ownership versus out-of-scope supervision

Production core Git helpers use `CommandExt::process_group(0)`, retain their child leader while checking `waitid(EXITED|NOHANG|NOWAIT)`, clean up the owned group even after leader exit, and finally reap the leader. Apple declares `waitid`, `WEXITED`, `WNOHANG`, and `WNOWAIT`; POSIX specifies that WNOWAIT leaves the child waitable, and locked rustix exposes this API for Apple. This is a plausible preservation path for **owned synchronous children**, subject to native tests of failure/setup/pipe/exit paths and group cleanup. It is not a claim to contain maliciously daemonizing descendants or impose a hard kernel-I/O deadline. [C10][A11][P2][R5]

Apple's `proc_bsdinfo` has PID/parent and start-time fields, but merely observing those fields does not grant race-free signal authority, establish complete descendant membership, or substitute for Linux cgroup scope evidence. The baseline's Linux historical supervision modules bind much more than a PID. No launchd/process-group/proc scan replacement is established or recommended for those guarantees here. [A17][C11]

**Core removal still requires the operator's `--confirm-stopped`.** No PID absence check, age, `finish`, successful Git helper exit, lock acquisition, rename, reboot or scan is a replacement. The macOS availability/diagnostics of out-of-scope historical commands must be specified so they cannot accidentally exercise partial Linux-dependent behavior or invent successful supervision. Existing historical state remains history and may hold removal. [C7][C9][C11]

## 4. Capability and minimum-version evidence

This table distinguishes **declaration availability**, **source evidence**, and **qualified product support**. No product OS minimum or filesystem allowlist is selected.

| Primitive | Evidence | What remains unproven |
|---|---|---|
| ARM64 Rust target | Rust's Apple target documentation gives `aarch64-apple-darwin` an OS floor of macOS **11.0** and documents `MACOSX_DEPLOYMENT_TARGET`. [R6] | This is a Rust target floor, not Work's safe-operation floor or a promise about the selected Git. |
| `openat` / `renameat` | Apple open manual / stdio header: **10.10**. [A1][A3] | Effective flags, retained handles and filesystem behavior must be qualified. |
| `renameatx_np`, `RENAME_EXCL` | Apple header: API **10.12**; manual requires filesystem support; capability flag is available. [A3][A4] | Declared API availability does not promise every filesystem implements exclusive rename. |
| `O_NOFOLLOW_ANY`, `O_SEARCH` | Present in Apple XNU tags `xnu-8796.141.3`, `xnu-10063.121.3`, and inspected `xnu-11417.140.69`. [A18][A19][A20] | Earliest supported public SDK/runtime pairing not established here; source presence is not a deployment guarantee. |
| `O_RESOLVE_BENEATH` | Absent from inspected `xnu-10063.121.3` header, present in `xnu-11417.140.69`, and described in pinned XNU `f6217f8…` open manual/header. [A19][A20][A1][A2] | Exact OS release/SDK introduction and rename-race behavior require qualification. Do not infer universal macOS 11 support or rely on an older kernel ignoring an unknown bit. |
| `O_PATH` / `RawDir` / `openat2` in locked rustix | Apple is excluded from these used interfaces; native Apple flags are not all exposed by the same Rust types. [R1][R2] | A safe, bounded Apple collector has not been demonstrated. |
| `kern.bootsessionuuid` | Read-only kernel export in inspected XNU. [A7] | Public stability/minimum version, boot/session lifecycle and VM-restore behavior. |
| `flock`, `fstat`, `statfs`, volume capabilities | Documented Apple primitives; capability support/validity is per volume. [A4][A5][A6][A8][A13] | Mount topology, effective access, atomicity and persistence on each admitted filesystem. |
| `F_FULLFSYNC` / Rust `sync_all` | Apple manual plus exact Rust **1.98.1** source. [A9][A10][R4] | File/directory/device acknowledgements and failure handling, separately from SQLite's fallback. |
| `flistxattr` | Apple manual records introduction in **10.4**. [A16] | Which metadata belongs to preservation, bounded reads/rechecks and safe Rust integration. |

Inspect the target SDK, deployment target and actual native behavior together in future qualification. Unsupported mandatory capabilities must refuse **before mutation/dispatch where possible**, not proceed by dropping flags on `EINVAL` or by reducing an unreadable observation to absence. [C3][C5][C7]

## 5. Explicit fail-closed constraints inherited by a port

These are consequences of the existing core contract, not new operator policy:

1. **Keep authority and charge** if identity, boot evidence, registry/schema provenance, storage durability or a native outcome cannot be established. Never initialize over unknown existing authority or rewrite inode/boot bindings to make records fit. [C6][C8][C9]
2. **Do not follow path aliases as a fallback** after mandatory no-follow/beneath validation fails. Keep descriptor/name rechecks and mount-boundary rules; canonicalization alone does not discharge them. [C3][C5][C13]
3. **Do not read first and classify later** where the baseline requires rejecting symlinks, hardlinks, FIFOs, devices and sockets before data open. Exhaustion/unreadability/change is incomplete inspection, not an empty census. [C3][C18]
4. **Do not replace create-only publication with clobbering rename**, copy/delete, adoption of an existing directory, or force Git operations. Unknown after side effects requires reconciliation. [C4][C12][C13]
5. **Do not turn finish into removal.** Preserve explicit stopped-writer confirmation, dirty/untracked/ignored/draft/unsupported-metadata holds, branch/HEAD constraints and historical-state holds. [C7][C9]
6. **Do not release capacity on native success alone.** Retain durable journal sequencing and fresh anchored absence of checkout plus private Git registration; a recreated path or uncertain dispatch is not a retry target. [C7][C14]
7. **Do not advertise process containment or metadata preservation not demonstrated.** Core child cleanup is not scope supervision; OS sync acknowledgement/local preservation is not off-host backup. [C9][C10][C11][C19]

## 6. Testable hypotheses and proposed acceptance evidence

**None of these native tests was run for this research.** Execute future work only in disposable owned fixtures, not the operator's authority or real repositories. This is a qualification backlog for the parent specification, not an implementation plan or a request to change the approved container workflow.

| ID / hypothesis | Owned-fixture experiment and required observation | Existing source-named regression to preserve |
|---|---|---|
| H1: Apple path resolution can enforce the required containment | Probe actual SDK/runtime flags; adversarial final/intermediate symlink, `..`, absolute path, renamed ancestor, root replacement, nested mount, same-volume alternate route and firmlink. Must refuse/invalidate forbidden traversal and never read an outside replacement. Separate no-XDEV proof from device mismatch detection. | `inspection_tests.rs`: `unsupported_resolution_is_incomplete`, `outside_ancestor_binding_changes_still_refuse`, `simulated_device_is_rejected_before_data_open`. [C18] |
| H2: Type-before-readable-open survives the collector port | Insert FIFO/socket/symlink/hardlinked regular file and an owned harmless special-file surrogate at each boundary; observe metadata/data-open hooks. Replace a validated regular file immediately before read. Must not open prohibited replacement data; preserve budgets and retained-object identity. | `stable_links_specials_and_nested_git_never_reach_data_open`, `descriptor_reopen_never_opens_a_replacement`. [C18] |
| H3: Bounded native enumeration is equivalent | Exercise empty/large/deep directories, refill/EOF/errors, unusual names, repeated enumeration, name/content replacement and outside-parent sibling churn. Verify reserved byte/syscall/time/entry limits and no cursor reuse or hidden background work. | `census_rechecks_names_and_anchors`, `outside_parent_sibling_churn_preserves_private_census`, `read_errors_keep_conservative_reservations_and_stop_further_reads`, `growth_and_missing_names_invalidate_the_private_census`. [C18] |
| H4: Exclusive creation/rename never clobbers | Barrier-race two publishers on absent destination; include existing file/directory/symlink, same name with case/normalization alias, unsupported capability and cross-device error. Exactly one create-only publication wins; loser preserves destination/source/evidence and never plain-renames. | `setup.rs` staging writer and `git_move.rs` collision/identity tests. [C13][C21] |
| H5: Cooperative locks retain exact owner semantics | Two independent opens/processes; SH+SH then EX contention; dup/fork inheritance; explicit unlock at owner drop; replaced/unlinked lock or directory; parent/child exec. No inherited descriptor prolongs a dropped owner, no unrelated shared owner is unlocked, revalidation catches replacement. | `checkout_guard.rs`: `drop_unlocks_even_when_an_inherited_descriptor_remains_open`, `dropping_one_shared_owner_does_not_unlock_another`, `directory_replacement_fails_revalidation`. [C5] |
| H6: Private storage admission is equivalent | Owned volumes/directories with unexpected UID/mode/link count, ACL grant/inheritance, ignore-ownership setting, remote/FUSE/unqualified filesystem and synthetic read failures. Observe refusal before unsafe authority mutation; do not auto-repair. | `store_recovery.rs`: `authority_and_private_storage_fail_closed`, `a_claimed_authority_never_recreates_a_lost_database`. [C20] |
| H7: Boot/identity lifecycle is correctly represented | Repeated reads, full reboot, sleep/wake, userspace restart where available, remount, copied/restored marker/database and controlled malformed/changed observations. Record expected/actual UUID stability and device/file-ID scope. Never equate changed boot with safe deletion or migration permission. | `allocation_crashes.rs`: `reboot_reconciles_durable_evidence_but_marker_tampering_holds`; recovery identity checks. [C22][C8] |
| H8: Acknowledged persistence/ordering survives interruption | Trace the exact Rust and SQLite sync paths; inject file/directory sync failure, SQLite full-sync fallback, ENOSPC and crash around WAL/marker/ref/journal boundaries. Verify no successful stronger-durability claim on weaker/unknown outcome. Test process death separately from controlled VM/device power-loss recovery; CI process abort alone proves neither stable media nor hardware behavior. | `store_recovery.rs`: `committed_outbox_survives_process_death_and_ack_is_idempotent`; `allocation_crashes.rs`: `subprocess_abort_boundaries_retain_exact_path_and_charge`; descriptor-bound ref sync. [C20][C22][C19] |
| H9: Capacity remains conservative | Known byte floor, unknown/overflow result, simultaneous reservations and post-reservation space consumption; measure APFS shared-volume/clone/snapshot/quota cases without changing limits or selecting a new purgeable-space policy. Failure retains charge; retry never double-charges. | `admission.rs`, `store_recovery.rs`: `every_nonretired_state_retains_its_charge`, ownership capacity test. [C1][C20][C2] |
| H10: Case and metadata do not hide work | Case-sensitive/insensitive owned volumes; Unicode aliases, common-dir alias collisions; files clean to Git but carrying xattrs/resource-fork data or ACL changes. Observe/report the extra evidence and verify whatever later approved preservation/refusal boundary is chosen; do not silently delete it. | Collector and preservation census/dirty-hold tests; this is **new native negative coverage**, not already-proven protection. [C18][C23] |
| H11: Core helper lifetime ownership is preserved | Timeout, blocked output/input, closed pipes, leader exit with live group child, setup failure and rapid child exit. Confirm leader remains waitable until owned-group cleanup and is reaped afterward; never signal caller/unowned recycled group. | `inspection_tests.rs`: `runner_retains_leader_until_group_cleanup`; `bounded_process.rs` regression suite (its Linux test observations need native equivalents). [C18][C10] |
| H12: Removal retains journal safety | Preview is passive; confirmed clean removal preserves refs/branches and verifies both absences. Crash after intent/native/result; recreate path or registration; change parent/common identities; inject unsupported metadata and failed ref sync. Unknown dispatch never replays; only recorded success plus fresh absence and confirmation reconciles charge once. | `inspection/removal.rs`: `recorded_native_success_reconciles_capacity_once_through_cli`, `uncertain_dispatch_never_replays_or_deletes_a_recreated_path`. [C7] |

Every positive should be paired with a negative proving failure leaves payload, authority history and quota intact. Version-qualified Git behavior and native macOS CI remain separate work owned by the map; these hypotheses do not qualify any current macOS release artifact. [C7][C9][C22]

## 7. Unknowns and decision inputs returned to the map owner

The research question is answerable at the primitive/gap level; the following are **not resolved human policy**:

- Product minimum macOS version and supported SDK/runtime pairing, especially if direct beneath resolution is required.
- Admitted filesystem/mount variants and how mandatory no-mount-crossing is established; APFS name alone and `MNT_LOCAL` are insufficient qualification evidence.
- A safe Rust-accessible replacement for retained metadata-only handles, trusted descriptor reopening and bounded enumeration without relaxing pre-data-open rejection.
- Definition of acknowledged durability and how the SQLite full-sync fallback is prevented/detected/qualified; regular-file and directory sync evidence on admitted devices.
- Boot-session lifecycle guarantees and a versioned identity/evidence compatibility story for existing or restored authority records. Do not “migrate” identities by overwriting stored values.
- Which ACL/xattr/resource-fork information is required payload versus platform bookkeeping, and whether supported cases are preserved or explicitly held. This report does not choose to ignore or erase attributes.
- Case/normalization/alias compatibility of repository charging and task paths on admitted volumes.
- Explicit behavior of out-of-scope historical supervision commands/state on macOS; no process-scan downgrade is authorized.
- Native evidence for the hypotheses above, including limitations of power-loss testing. No claim of release readiness is made.

## 8. Evidence and sources

### Project source (all pinned to the specified baseline)

[C1]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/admission.rs
[C2]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/ownership.rs
[C3]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/inspection.rs#L2947-L4400
[C4]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/identity.rs
[C5]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/checkout_guard.rs
[C6]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/store.rs#L1-L320
[C7]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/inspection/removal.rs
[C8]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/recovery.rs#L202-L230
[C9]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/README.md#L175-L215
[C10]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/bounded_process.rs
[C11]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/scope_driver.rs
[C12]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/allocate.rs
[C13]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/setup.rs#L2235-L2325
[C14]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/removal_journal.rs
[C15]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/lib.rs#L1-L8
[C16]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/Cargo.lock
[C17]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/tests/setup.rs
[C18]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/inspection_tests.rs
[C19]: https://github.com/techwright-lab/work-cli/tree/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/inspection/recovery_refs
[C20]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/tests/store_recovery.rs
[C21]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/tests/git_move.rs
[C22]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/tests/allocation_crashes.rs
[C23]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/tests/preservation.rs

### Primary external sources

Apple XNU links below pin the inspected main revision `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` (tag `xnu-12377.1.9`); older headers are explicitly tagged to bound source presence. A source tag is not by itself a product deployment guarantee. Archived Apple guides are marked as historical evidence where used.

- **[A1] Apple `open(2)`**: relative-FD resolution; no-follow, beneath, event-only and symlink opens; introduction history.
- **[A2] Apple `<sys/fcntl.h>`**: actual flag definitions, including `O_SEARCH` and `O_RESOLVE_BENEATH`.
- **[A3] Apple `rename(2)` and `<sys/stdio.h>`**: exclusive-rename behavior, capability dependency, API availability. [Rename manual][A3manual].
- **[A4] Apple `<sys/attr.h>`**: documented volume capability semantics and bits.
- **[A5] Apple `stat(2)`**: identity metadata and unprivileged `st_gen` limitation.
- **[A6] Apple `getattrlist(2)`**: file ID, volume UUID, valid/supported capability interpretation.
- **[A7] XNU `kern_sysctl.c`**: `kern.bootsessionuuid`, boot time and userspace-reboot exports.
- **[A8] Apple `flock(2)`**: advisory locking and descriptor-duplication/fork behavior.
- **[A9] Apple `fsync(2)`**: drive-cache/order limitations and stronger flush.
- **[A10] Apple `fcntl(2)`**: full sync and pathname queries.
- **[A11] Apple `<sys/wait.h>`**: declared waitid and WNOWAIT flags.
- **[A12] Apple File System Programming Guide, File System Details**: ACLs, Unix permissions, BSD flags and ignored ownership.
- **[A13] Apple `<sys/mount.h>`**: `statfs` fields and mount flags.
- **[A14] XNU `vfs_lookup.c`**: native beneath checks versus internal cross-mount lookup machinery.
- **[A15] Apple APFS Guide FAQ** (retired, updated 2018-06-04): historical case, normalization and enumeration descriptions.
- **[A16] Apple `listxattr(2)`**: descriptor-based extended-attribute enumeration and availability history.
- **[A17] Apple `<sys/proc_info.h>`**: process observation fields, not a scope-containment contract.
- **[A18]–[A20] Apple tagged headers**: evidence of flag presence/absence, not inferred runtime support.
- **[P1] POSIX.1-2024 `open`/`openat`**; **[P2] `waitid`**; **[P3] `stat`/`fstatat`**: normative interface semantics, separately from Apple's implementation.
- **[R1]–[R3], [R5] rustix 1.1.5 source**: exact locked interface gates, flags, Apple rename backend and wait API.
- **[R4] Rust 1.98.1 Unix filesystem implementation**: actual Apple full-sync selection; **[R6] Rust Apple platform requirements**: target/deployment floor, not Work support policy.
- **[S1] SQLite PRAGMA documentation**; **[S2] bundled SQLite source/artifact**: distinguish SQL FULL from Apple full sync, and document fallback. The artifact link is the checksum-verified locked package; the readable source link is the corresponding rusqlite release's bundled source.

[A1]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/open.2
[A2]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/fcntl.h
[A3]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/stdio.h#L34-L54
[A3manual]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/rename.2
[A4]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/attr.h
[A5]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/stat.2
[A6]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/getattrlist.2
[A7]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_sysctl.c#L2921-L2949
[A8]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/flock.2
[A9]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/fsync.2
[A10]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/fcntl.2
[A11]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/wait.h
[A12]: https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html
[A13]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/mount.h
[A14]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_lookup.c
[A15]: https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/FAQ/FAQ.html
[A16]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/listxattr.2
[A17]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info.h
[A18]: https://github.com/apple-oss-distributions/xnu/blob/xnu-8796.141.3/bsd/sys/fcntl.h
[A19]: https://github.com/apple-oss-distributions/xnu/blob/xnu-10063.121.3/bsd/sys/fcntl.h
[A20]: https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/sys/fcntl.h
[P1]: https://pubs.opengroup.org/onlinepubs/9799919799/functions/open.html
[P2]: https://pubs.opengroup.org/onlinepubs/9799919799/functions/waitid.html
[P3]: https://pubs.opengroup.org/onlinepubs/9799919799/functions/stat.html
[R1]: https://github.com/bytecodealliance/rustix/blob/v1.1.5/src/fs/mod.rs
[R2]: https://github.com/bytecodealliance/rustix/blob/v1.1.5/src/backend/libc/fs/types.rs
[R3]: https://github.com/bytecodealliance/rustix/blob/v1.1.5/src/backend/libc/fs/syscalls.rs#L585-L621
[R4]: https://github.com/rust-lang/rust/blob/1.98.1/library/std/src/sys/fs/unix.rs#L1413-L1434
[R5]: https://github.com/bytecodealliance/rustix/blob/v1.1.5/src/process/wait.rs
[R6]: https://doc.rust-lang.org/rustc/platform-support/apple-darwin.html#os-version
[S1]: https://sqlite.org/pragma.html#pragma_fullfsync
[S2]: https://github.com/rusqlite/rusqlite/blob/v0.38.0/libsqlite3-sys/sqlite3/sqlite3.c#L42973-L43024

Additional exact SQLite references: [checkpoint_fullfsync](https://sqlite.org/pragma.html#pragma_checkpoint_fullfsync), [checksum-verified libsqlite3-sys 0.36.0 artifact](https://static.crates.io/crates/libsqlite3-sys/libsqlite3-sys-0.36.0.crate).
