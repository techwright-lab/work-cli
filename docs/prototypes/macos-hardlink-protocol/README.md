# THROWAWAY: macOS hardlink capture protocol and owned-link lifecycle

## Verdict

**A bounded acquisition and conservative active-link lifecycle candidate, not a qualified collector or immutable snapshot.** On macOS 27.0.1 ARM64/APFS, this finite native lane demonstrates capture → no-follow type/identity/consistency validation → readable opening → bounded read → postvalidation, with exact active ownership bookkeeping. Stable completion removes exactly its known link. Tested prior-to-final-gate mutations and unsafe stage states refuse with **zero collector data opens/bytes**. Every interrupted/reinspection case retains evidence and the synthetic reservation, including a consistent-looking `nlink=2` leftover.

Two precise counterexamples delimit that result: an ordinary source writer **after the final pathname check but before data open** causes **1 data open / 0 bytes**, refused by opened-FD checking; a writer **after the opened-FD check but before read** yields `MUTATED!`, **1 data open / 8 bytes**, followed by a post-read hold. A hardlink retains the original mutable inode, not initial bytes. Neither more prechecks nor a stopped-writer assertion eliminates these windows. This does not show a special-file data-open escape under the protected-stage/cooperative boundary: an ordinary source writer cannot change the linked inode's type. It does refute “all source mutations before open/read are necessarily refused before that operation” and “a hardlink is a snapshot.” Full consistency/preservation acceptance remains open.

### Authority and provenance

- Parent: [Demonstrate safe retained-object inspection on macOS](https://github.com/techwright-lab/work-cli/issues/23), map13. No issue resolution, map edit, PR, merge or product acceptance in this lane.
- Accepted [temporary hard-link side effects/recovery decision](https://github.com/techwright-lab/work-cli/issues/26#issuecomment-6688783050): narrowly scoped link-count/ctime effects permitted; no intentional content/mtime alteration, blanket cleanup, user-hardlink exception or charge release on unknown outcomes.
- [Approved staged semantics and cooperative boundary](https://github.com/techwright-lab/work-cli/issues/23#issuecomment-6687838428): ordinary concurrency/mistaken stopped-writer assertions remain relevant; malicious same-UID containment is excluded. Unrelated principals must not write staging.
- Baseline read-only source: `41d01c3a6f1ea2bafcc7432240f725c55c810781`. In particular `crates/work/src/inspection_tests.rs::stable_links_specials_and_nested_git_never_reach_data_open`, inspection filesystem retained-handle implementation, receipt-store private-directory checks, `identity.rs` cooperative-guard commentary, and `skills/work-cli/SKILL.md` informed the boundaries. No baseline files or Work authorities/configurations changed; no Work allocation/lifecycle commands run.
- Starting native evidence: [experiment 7](https://github.com/techwright-lab/work-cli/blob/fcad502700d982a84e679f1c46c452066d4a2445/docs/prototypes/macos-retained-object/experiment-7.md); returned-mask/generation parsing follows [experiment 5](https://github.com/techwright-lab/work-cli/blob/fcad502700d982a84e679f1c46c452066d4a2445/docs/prototypes/macos-retained-object/experiment-5.md). This lane is independent of the parallel Rust/containment investigation.

## Artifacts and reproduction

- [`hardlink-protocol.c`](hardlink-protocol.c): native throwaway protocol, deterministic mutation hooks, explicit data-open/byte counters, separate interruption/reinspection commands.
- [`run.py`](run.py): finite runner and assertions, including before/after evidence snapshots across reinspection.
- [`observations.txt`](observations.txt): retained final output, source SHA-256, two actual bounded manifests and case counters. No binaries or host-private paths published.

On macOS with an already installed clang and Python 3, from a writable disposable directory containing these sources:

```sh
python3 run.py ./NEW-owned-fixture > observations-local.txt
```

The argument **must not exist**. The runner creates it mode 0700, writes the binary and all synthetic fixtures only there, and never cleans it up. It installs nothing. Compilation is `clang -std=c11 -Wall -Wextra -Werror -Wconversion -Wshadow`. Compilation has a 30-second bound; each native invocation has a 15-second outer bound. These are experiment bounds, not proof of a hard syscall latency limit. The native `run` invocation completes 20 active cases; three other processes exit deliberately with status 70; five separate reinspection processes return holds without mutation. All final assertions passed; stderr was empty.

Observed environment: Darwin arm64, macOS **27.0.1**, build **26A434**, APFS, Apple clang **21.0.0** (`clang-2100.3.34.2`), target `arm64-apple-darwin27.0.0`. No macOS 15/26, other filesystem, device, actual reboot/power-loss, mount, real repository, credential, installer or production workflow qualification is implied. No Rust toolchain was invoked/installed. GitHub artifact reads/publication were the only network use, separate from native probes; no native network or process-supervision scope work occurred.

## Concrete protocol exercised

1. **Private bounded fixture/stage and reservation.** Retain directory FDs; require root/stage owner == effective UID, exact mode 0700, no extended ACL entries, and same filesystem for source/stage. Check the stage and source-directory names still bind the recorded directory identities. Names are fixed single components (`payload`); captures cannot introduce slash traversal. Source initial metadata must be regular and initially singly linked to pass validation; initial generation/stream tokens must be valid to acquire. Initial nonregular fixtures in this matrix arise by substitution after observing a regular source.
2. **Intent before link.** Bound the manifest to <2048 bytes and sync it plus its containing directory. Record capture ID, phase, reservation, retained root/source-directory/stage device+inode identities, source/link names, initial source device+inode and link count, linked device+inode/count, generation/stream tokens, size/mtime and linked ctime. An active in-memory capture is the ownership authority; a manifest is evidence, **not self-authenticating ownership or removal permission**. Actual sample records are in the output. No adoption by age, plausible name or count occurs.
3. **Acquire one entry.** `linkat(source_fd, "payload", stage_fd, "payload", 0)` creates at most one new link, does not follow a substituted symlink, does not recursively capture directories, and refuses an existing destination. Sync the stage, record the actual linked metadata/tokens, and write the `LINKED` record. The 1→2 link-count and non-restorable ctime changes are disclosed. Content/mtime are not intentionally changed by capture or unlink; only named synthetic mutation actors edit contents or restore mtime.
4. **Validate BEFORE readable opening.** Check protected stage/root and named directory bindings again; no-follow stat source and capture. Require captured type regular, initial and captured inode/device equal, source path still names that inode, initial `nlink=1`, observed `nlink=2`, matching owner/group/mode/flags/size/mtime, and matching source/stage ctime at each comparison. Compare source/captured returned-mask-validated nonzero generation, file-ID and stream tokens to the initial tokens. Initial→linked ctime is deliberately not required equal, because this protocol itself changes it; linked→later ctime **is** required equal. No timestamp-only equivalence claim is made. The exact fixed 44-byte native attribute layout is checked; unsupported/invalid tokens refuse.
5. **Protected handoff, not an atomic type-open flag.** Recheck the recorded stage and entry immediately before opening, then `openat(stage_fd, "payload", O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC)`. Check opened identity/type/stamp before reading up to eight bytes. A private stage with one cooperative writer supplies entry stability; `O_NOFOLLOW`/post-open stat **alone** are not special-file protection. Deliberate stage corruption hooks are checked before this final handoff, not advertised as containment of a malicious same-UID stage writer. Ordinary source writes remain possible through the shared inode.
6. **Post-read and exact normal completion.** Revalidate source path, protected stage, identities, stamps/tokens/counts after reading and once more before cleanup. Only a fully successful active capture can `unlinkat(stage_fd, "payload", 0)`. Sync the stage, check exact link absence and original source identity/count=1, persist `LINK_REMOVED` while still charged, then mark `COMPLETE` with synthetic reservation=0. Stable output shows unchanged mtime, ctime changed, and exactly one normal-completion unlink. No other capture link is removed by this experiment. This is a link-reservation demonstration, **not release of Work checkout capacity or removal eligibility**.
7. **Hold on any refusal or interruption.** Retain links, manifest and synthetic reservation. Separate reinspection reads a bounded regular owner-only singly linked manifest, compares root/source-directory/stage/link identity evidence, and **always holds**, even when the identity subset is consistent. Its `identity_consistent=1` is not full token/data validation or ownership certification. Missing receipts, unreceipted links, replaced links/stages and unknown outcomes never enter normal completion. No recovery deletion/disposition is implemented or implicitly authorized.

### Why count two is insufficient

An initial user hardlink causes a hold without a collector open. An extra user hardlink added after acquisition makes the count three and also holds. More importantly, the replaced-stage-entry case intentionally has a **foreign regular inode with count two**, while the real captured inode still exists under another fixture name. Identity validation refuses it. Interrupted recovery repeats this plausible-count-two replacement and refuses adoption. The manifest binds the *specific active capture and stage/link identities*, not a broad exemption for all two-link files. A historical matching manifest/count still never reactivates an interrupted capture.

## Finite case matrix (actual final run)

Counters below count **collector payload data-open attempts and bytes returned by collector read**, not directory opens, manifest IO, fixture construction or synthetic writer operations. All payloads are eight-byte synthetic strings.

| Case/schedule | Result | Data opens / bytes | Link/reservation disposition |
| --- | --- | --- | --- |
| Stable regular | Original inode, generation 2→2; reads `ORIGINAL`; postvalidation passes | **1 / 8** | Exact active link removed, source count 1, reservation 0 |
| User hardlink present before acquisition | Refuse initial count two | **0 / 0** | User links untouched; conservative hold |
| Regular→directory before link | `EPERM`; no stage payload entry | **0 / 0** | No recursive capture; hold |
| Regular→FIFO before link | One linked FIFO classified/refused | **0 / 0** | Evidence retained, reservation 1 |
| Regular→symlink before link | Symlink itself linked/classified/refused; target not opened | **0 / 0** | Evidence retained, reservation 1 |
| Stage mode 0755 before acquisition | Refuse protection | **0 / 0** | No capture; hold |
| Source regular replaced after capture | Source/capture inode mismatch | **0 / 0** | Captured original retained, hold |
| Content mutation before validation | Generation 2→3; refuse | **0 / 0** | Hold |
| Content mutation/restoration + synthetic mtime restoration | Generation 2→4; refuse despite original bytes/mtime restored | **0 / 0** | Hold |
| Stage directory replaced | Named stage identity differs from retained FD | **0 / 0** | Both fixture directories retained, hold |
| Stage link replaced by foreign regular inode, count two | Refuse actual identity, not merely count | **0 / 0** | Both original and foreign links retained, hold |
| Stage link replaced by FIFO | Refuse type/identity before open | **0 / 0** | Both entries retained, hold |
| Stage mode 0755 after acquisition | Refuse protection | **0 / 0** | Hold |
| User hardlink added after acquisition | Count three, refuse | **0 / 0** | All links retained, hold |
| Source pathname rename-away/restore after acquisition | Linked ctime differs; refuse in this schedule | **0 / 0** | Hold; no universal anti-ABA proof |
| Added extended ACL entry on stage | Refuse any ACL entry even with mode 0700 | **0 / 0** | ACL/evidence left intact, hold |
| Mutation after first validation, before final handoff validation | Second gate refuses | **0 / 0** | Hold |
| **Mutation after final path validation, before open** | **Opened-FD stamp refuses; pre-open universal refusal claim fails** | **1 / 0** | Hold, original inode/type still retained |
| **Mutation after opened-FD validation, before read** | **Reads `MUTATED!`; postvalidation refuses; immutable-bytes claim fails** | **1 / 8** | Hold; consumed bytes do not become accepted output |
| Regular→different regular before link | Link succeeds but captured identity != initial identity | **0 / 0** | Replacement link retained, hold |

Collector totals: **3 data-open calls / 16 bytes**. Seventeen active negative schedules have zero opens/bytes; the two deliberately last-gap schedules are not counted as pre-open successes.

| Separate-process interruption/reinspection | Evidence check | Mutation / release |
| --- | --- | --- |
| Exit 70 after synced `LINKED` record, then reinspection | Identity subset consistent, including count two | **HOLD; 0 opens/bytes/unlinks; reservation 1** |
| Replace leftover link with foreign inode (also count two), reinspect | Identity inconsistent | Same hold; original/foreign links retained |
| Replace leftover stage directory, reinspect | Stage identity inconsistent | Same hold; both stages retained |
| Exit 70 after successful link but before linked receipt (`INTENT` remains), reinspect | Receipt lacks actual linked identity | Same hold; no adoption from plausible intent |
| Exit 70 with a link but no manifest, reinspect | Mandatory evidence missing | Same hold; no guessed cleanup |

Runner snapshots every fixture entry's identity, mode, link count, size, mtime and ctime before/after each reinspection and asserts equality. Reading a manifest may affect atime; atime is intentionally not an equality criterion. The normal active path is the **only unlink call**. Controlled exits are process-interruption evidence, not reboot, OS crash, fsync fault, storage failure or power-loss qualification. The untracked-link test deliberately constructs missing evidence; the intended protocol journals intent first.

## Protected stage argument and explicit remaining obligations

- **Observed:** owner/mode checks, actual extended-ACL entry rejection, same-volume check and named-stage replacement checks work in this fixture. On this host `acl_get_fd_np(valid_directory_fd, ACL_TYPE_EXTENDED)` returns NULL/`ENOENT` when no ACL is present. The probe admits that observed absence result; other errors refuse. Darwin `acl_get_entry` returns 0 for an entry, unlike common POSIX-style iteration assumptions. These details require binding/native qualification, not silent cross-platform reuse.
- **Argument, not cross-principal experiment:** exact owner-only mode plus absence of granting ACLs is intended to exclude unrelated unprivileged principals from entry replacement. No second account, privilege transition, root-containment, sandbox or malicious same-UID test was performed. No mount/ancestor-substitution proof is supplied by this lane's same-device test; same-device mount aliases are not ruled out. Retained stage FD plus named-binding checks are fixture-local, not a proof that every ancestor remains beneath a production root.
- **Mutable source:** generation/stream returned masks strengthen controlled refusal and are not an atomic receipt, immutable snapshot or coherent whole-tree witness. Read/open windows remain as demonstrated. A full collector must discard/quarantine speculative data until all required data/metadata/live-tree checks succeed; whether that satisfies the complete safety contract requires parent design/HITL review. Whole-tree atomicity, generation wrap/invalid/mmap histories, non-atomic stat+token sampling, adversarially timed metadata restoration and simultaneous metadata/fork changes remain unproved. The hardlink's own ctime change complicates initial evidence bracketing; no timestamps-alone proof is asserted.
- **Lifecycle/persistence:** this is a single active cooperative writer with exclusive fresh fixture names. The manifest is an ordinary synced bounded file overwritten in place, not a qualified crash-atomic journal. No record authentication, inode-reuse/boot/session defense, journal tamper matrix, sync-error injection, durable reservation store or power-loss evidence exists. Recovery only holds and does not fully parse/validate every recorded token/stamp. Those omissions are why even the best-looking interrupted record cannot authorize deletion, repair, adoption or release. Any future explicit recovery disposition needs separate authority and full evidence.
- **Budgets:** one link attempt creates at most one entry; manifests are bounded <2048 bytes and reads at eight bytes; construction has a fixed finite case count. Per-fixture source/stage directories and manifest are additional test infrastructure, not magically free. `capture_charge` is an illustrative one-slot reservation, not real Work quota accounting. A hardlink retains shared payload blocks if the source name disappears; ordinary writers can grow the same object. Production reservation/entry/byte/time accounting, safe bounded enumeration and interruption of blocked IO are not established by this small fixture or outer timeout.
- **Metadata/preservation:** no intentional source chmod/ACL/xattr edits by acquisition; the stage ACL/mode corruption and content/mtime mutation are explicit fixture actors only. Stable acquisition/removal preserve source mtime but necessarily change ctime. Source ACL/xattr/resource-fork classification/preservation, permissions/read failures, nested layouts and complete before/after metadata census are outside this lane. Stopped-writer confirmation and actual removal remain separate mandatory decisions.

### Safe Rust interface needs (unresolved here)

A future safe surface needs owned directory/regular-read descriptors and single-component validated names; no-follow `fstatat`/`linkat`/`openat`/`unlinkat`; checked device+inode and complete stamp conversion; macOS ACL acquisition/iteration with precise absence/error handling; checked returned-mask and exact-length parsing for `getattrlistat` generation/file/stream attributes; explicit reservation and held/unknown states; and fallible file/directory sync with durable outcome reporting. The readable-open capability must only come from a validated active private-stage capture, not from an arbitrary pathname or historical receipt. Captured bytes must not be published before complete postvalidation. A destructor/drop must **not** silently unlink ambiguous links or release reservations. No safe Rust wrapper, audited unsafe dependency, target/MSRV compile, mount-containment layer or production API is implemented/accepted here.

## Stop point

This finite case matrix answers the lane's question without inventing recovery policy. It supplies an evidenced active protocol, exact-only normal completion and conservative reinspection. It also supplies two concrete final-gap counterexamples and a list of unproved obligations. **Do not resolve the parent HITL ticket or infer full macOS support/collector acceptance from this report.** Parent review can combine this evidence with the independent safe-Rust/containment lane and choose the next explicitly authorized design/acceptance step. All local fixtures are retained; nothing outside the assigned scratch workspace was written by the probes.
