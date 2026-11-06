# THROWAWAY experiment 7: bounded hard-link acquisition, with source metadata side effects

## Scope

Native scratch-only `hardlink-acquisition-prototype.c`, macOS 27.0.1 ARM64, strict `clang -std=c11 -Wall -Wextra -Werror`, exit 0, outer timeout 10 seconds. Synthetic regular files, directory tree, FIFO and symlink only. No actual device nodes, mounts, real repositories, authority, installation or cleanup. All synthetic links are retained to expose the leftover-link state. Source metadata changes in this experiment are NOT authorization to mutate real payload during production inspection.

## Mechanism

Call `linkat` with flags 0 on one-component source/destination names relative to retained directory descriptors, placing one entry into a private same-filesystem stage. Inspect the stage name without following symlinks before any payload-readable open. Compare retained inode with the originally observed regular-file inode, and account for the acquisition link's expected link-count increment.

A link names the SAME object, not a snapshot. The probe deliberately replaces the source path after a successful regular acquisition, then reads the original via the private link to demonstrate retention. This is not an accepted live-source consistency protocol: production would still need before-read checks/refusal and post-read validation rather than treating this intentional read-after-replacement demonstration as an accepted census.

## Observations

- Regular acquisition succeeded with identical inode. Link count changed 1→2 and ctime changed. After the original source name was moved and replaced, the retained private link still opened/read ORIGINAL, not replacement data.
- Substitution with a nonempty directory failed with EPERM and no destination entry. It did not recursively capture the hierarchy as pathname cloning did.
- FIFO substitution created one hard link, which was classified/rejected without a readable payload open. Symlink substitution with flags 0 linked the symlink itself, not its target; it too was classified/rejected without a payload-readable open. The synthetic target sentinel was not read.

Apple's [link/linkat manual](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/link.2#L55-L175) documents atomic new-entry creation, same-filesystem constraints, incremented source-object link count, directory prohibition and linkat symlink flag behavior. This supports a bounded one-entry acquisition candidate, not a complete collector proof or a hard wall-clock bound on filesystem I/O.

## Trade-off requiring an explicit human decision

Hard linking MUTATES source-object metadata: link count increases, ctime changes, and removing the temporary link changes them again. Ordinary user code cannot restore the old ctime. Content/mtime are not intentionally edited by acquisition, but a hard link is not an immutable data snapshot and does not exclude concurrent writers. This conflicts with the previously approved no-source-modification capture direction unless explicitly refined.

A crash can leave a private link and a source link count of 2. Existing user-created hardlinks must remain distinct from exact Work-owned capture links. No production ignore-all-hardlinks exception, automatic orphan cleanup, identity rebinding, permission repair or charge release is authorized. Resource/stage identity, owned-link provenance, lifecycle, recovery and preservation need specification before acceptance.

Native directory/mount traversal, protected-stage ownership/ACL access, safe readable handoff under the cooperative threat boundary, data/metadata generation/validation ordering, bounded enumeration and macOS 15/26 qualification remain unresolved. One bounded primitive does not finish the whole inspection design.

## Verdict

This is a concrete alternative that avoids the observed recursive directory-substitution failure and retains original object identity in the tested schedule. It has material source-metadata and crash-recovery costs. It is a candidate for human trade-off review, NOT an approved production approach. The prototype stays open; further design should first decide whether temporary source metadata side effects are acceptable under an explicit bounded acquisition/recovery contract.
