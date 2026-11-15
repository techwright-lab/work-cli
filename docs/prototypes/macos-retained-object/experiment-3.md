# THROWAWAY experiment 3: screen identity-open alternatives and APFS clones

The operator accepted rejecting the event-only shortcut and investigating other strategies without weakening safety. This checkpoint is evidence, not a completed collector design or acceptance of a new preservation policy.

## Primary-source screening

Pinned Apple XNU `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`:

- [`vfs_syscalls.c` lines 5437–5549](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_syscalls.c#L5437-L5549) implements `openbyid_np` with an expected file ID check. However, it first requires an Apple platform binary or `com.apple.private.vfs.open-by-id`. That is not a general unprivileged third-party CLI interface. It was not invoked, and no entitlement/privilege workaround was attempted.
- The expected identity comparison in [`vfs_vnops.c` lines 636–657](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_vnops.c#L636-L657) occurs before the ordinary open call, but ordinary public `openat` supplies NULL expected IDs in the inspected source. Seeing an internal primitive is not proof that Work can use it through public safe APIs.
- [`clonefileat` source](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_syscalls.c#L9037-L9333) looks up a source vnode and calls the clone operation. `clonefile_internal` rejects types other than regular files, symlinks and eligible directories before invoking clone. It requires same mounted filesystem and an absent destination. Source data-read authorization is still required; this is not a permission bypass. This path offers a distinct approach worth testing rather than opening an unknown source object through a readable descriptor.

This pinned source is not asserted to be the exact running Darwin 27 revision. Public API/runtime behavior still needs independent native evidence and supported-version qualification.

## Controlled native experiment

`clone-acquisition-prototype.c`, strict `-std=c11 -Wall -Wextra -Werror`, outer 10-second timeout, exit 0, macOS 27.0.1 ARM64. Synthetic files only, under the authorized scratch directory. Source and clone destinations are private sibling directories on the same filesystem. No mount/device operations, credentials, real repository, authority or installation touched.

Using `clonefileat` with `CLONE_NOFOLLOW_ANY | CLONE_RESOLVE_BENEATH`:

1. An ordinary file cloned successfully; the clone had a different inode and original synthetic contents.
2. After replacing the source pathname, a second clone contained replacement contents and again had a distinct inode.
3. An existing destination failed with `EEXIST` rather than being overwritten.
4. A source FIFO failed with `EINVAL`; a source symlink failed with `ELOOP`.

Actual output is in `clone-acquisition-observations.txt`. The probe opens only successful regular clones in its private directory for reading, never the source FIFO. Source `fstatat` observations in this single controlled run are NOT an atomic expected-identity binding to the later clone call.

## Meaning and limits

Cloning is not a drop-in retained-object implementation: it creates a NEW object and captures whatever source pathname resolves at clone time. This experiment does not bind a prior source metadata observation to the cloned contents, establish unchanged live-worktree state, or close ABA/replacement/mount races. Successful FIFO rejection alone does not prove an entire race-safe collector.

A clone-first collector would be a different internal architecture requiring an explicit design: capture/provenance association, consistency/revalidation of the live census, metadata handling, bounded staging/accounting, interrupted temporary-file lifetime, independent enumeration, same-volume requirements and failure handling. It must preserve operation-specific storage policy and safe-removal guarantees. No temporary-directory creation in real repositories or change to passive command semantics is authorized by these synthetic tests.

## Proposed next step for human review

Keep the prototype ticket open. Investigate whether clone-first acquisition plus a conservative live-tree consistency protocol can meet the contract, or document why it cannot. Do not accept clones as exact-object proof merely because captured bytes can be read safely. If this demands a new product/preservation policy, create an explicit decision before production work.

No complete strategy, safe Rust API layer, macOS 15/26 evidence, bounded collector or release qualification has been demonstrated. No claim that native macOS support is impossible is made.
