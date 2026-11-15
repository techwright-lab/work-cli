# THROWAWAY experiment 4: clone consistency and ABA counterexamples

## Question

Can a post-clone source check distinguish an unchanged source from a temporary replacement that is restored before validation? This isolates a consistency requirement; it does not implement a collector.

## Method

Native `clone-consistency-prototype.c`, macOS 27.0.1 ARM64, compiled using `clang -std=c11 -Wall -Wextra -Werror`, one controlled run, exit 0, outer timeout 10 seconds. Three cases with synthetic files inside the authorized scratch fixture. No real repository, authority, installation, mount or device operation.

The negative cases deliberately wait 20 ms before mutation, making timestamp changes observable. Thus this probe tests the listed schedules, NOT clock-resolution edge cases, all races or arbitrary storage behavior.

## Observed results

| Case | Captured clone content | Same source inode before/after | Full checked source stamp equal |
| --- | --- | --- | --- |
| Unchanged | ORIGINAL | yes | yes |
| Pathname ABA: original moved away, replacement cloned, original restored | REPLACED | yes | no (ctime changed) |
| Content ABA: original overwritten, cloned, contents and mtime restored | REPLACED | yes | no (ctime changed) |

Checked stamp: device, inode, mode, owner/group, link count, size, mtime, ctime and birthtime. ACLs/xattrs, mount/ancestor state and global census consistency are NOT covered by this stamp. It is not called a universal complete metadata record.

## Implications

- An inode-only postcheck would accept replacement data in both negative schedules. This is a concrete counterexample, not just a hypothetical concern.
- The fuller stamp rejected those two schedules in this run. That supports conservative invalidation tests, not an atomic identity/provenance guarantee.
- Rejection happens AFTER the clone is captured/read. A requirement that only a retained, previously identified original object reaches the data boundary is stronger than eventually discovering a mismatch.
- Baseline [`descriptor_reopen_never_opens_a_replacement`](https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/inspection_tests.rs#L656-L695) checks that the opened object has the retained original inode even when replacement occurs immediately before data open, and the census then reports Changed with zero observed bytes. A clone-first architecture cannot claim this regression is preserved merely by noticing a post-clone ctime difference. It needs an explicit boundary/provenance argument and equivalent tests, not relabeling a clone inode as original identity.

## Decision status

Reject naive clone-plus-inode-check. Do not approve clone-plus-stat-check as a complete equivalent based on these tests. Clone-first remains a different potential architecture requiring a justified capture/metadata/live-tree binding protocol, safe resource budgets and native evidence. The public clone call tested here returns a new object, not a token atomically authenticating the source identity observed before capture.

No complete collector, exact-object provenance proof, safe Rust boundary, bounded enumeration, no-mount-crossing protocol or macOS 15/26 qualification has been demonstrated. The prototype ticket remains open. Repeating stress tests cannot by itself fill the missing design argument; the next step should be a bounded architecture/feasibility analysis, returning either a defensible protocol or a clearly stated blocker before more implementation.
