# THROWAWAY experiment 2: initial type boundary and path containment

## Scope and method

Ran `type-and-containment-prototype.c` once on macOS 27.0.1 ARM64, compiled with `clang -std=c11 -Wall -Wextra -Werror`, exit 0, under an outer 10-second timeout. Owned synthetic regular files, executable file, FIFO, Unix-domain socket, symlink and directories only, all in the authorized scratch directory. No device nodes, mounts, real repositories, Work state, installation or reboot. Full actual output is in `type-and-containment-observations.txt`.

Inspected Apple primary-source XNU revision `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`. This is a pinned source snapshot, not a claim that it exactly matches the running Darwin 27 kernel.

## Native observations

- `O_EVTONLY | O_NONBLOCK | O_NOFOLLOW` opened the synthetic FIFO, as well as regular files and a directory. It rejected the socket and symlink. Therefore the initial event-only acquisition is not a type-filtered regular-file open. Experiment 1 separately showed readable event-only descriptors in this process.
- `O_EXEC | O_NONBLOCK | O_NOFOLLOW` rejected the FIFO and non-executable regular file (mode 0600), accepted the executable regular file (mode 0700), and rejected directory/socket/symlink. Requiring execute permission for ordinary payload files cannot provide general-purpose inspection without changing user permissions or excluding ordinary data files. No chmod fallback was attempted or authorized.
- `O_RESOLVE_BENEATH | O_NOFOLLOW_ANY` accepted a contained ordinary file and rejected a symlink, `..` escape and absolute path in these controlled cases. This establishes only the tested cases, not adversarial race freedom, no-mount-crossing or macOS 15/26 availability.
- After an anchored subdirectory was renamed outside the chosen root (but still within scratch), lookup from the root failed, while lookup beneath the retained subdirectory FD succeeded. Beneath resolution is relative to the supplied FD; it does not by itself establish that a previously retained child remains under the original root. Fresh ancestor/name binding checks remain necessary. Keeping access to a moved retained object is not itself a newly discovered kernel bug.

## Primary-source explanation and limits

- [`open.2` lines 237 onward](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/open.2#L237-L268): `O_EVTONLY` is intended for event monitoring and does not prevent unmount; separately documents no-follow-any and beneath semantics. It does not document an `O_PATH` equivalent or mandatory regular-file type filter.
- [`vfs_syscalls.c` lines 4895–4910](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_syscalls.c#L4895-L4910): removal of FREAD/FWRITE for event-only is conditional on process policy, then opening proceeds through `vn_open_auth`. Descriptor readability therefore must not be treated as a portable invariant of that flag.
- [`vfs_vnops.c` lines 663–715](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_vnops.c#L663-L715): the noncompound existing-object path authorizes and calls `VNOP_OPEN`; event-only is not a blanket bypass of vnode open. Source inspection does not substitute for proof of every filesystem/device path, but provides no basis to promise side-effect-free special-file acquisition.
- [`vfs_subr.c` lines 8330–8460](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_subr.c#L8330-L8460): existing-open authorization rejects nonregular objects for FEXEC and requests execute authorization, explaining the observed O_EXEC limitation. Merely using O_EXEC is not an approved substitute for reading ordinary non-executable data.

## Verdict proposed for human review

Reject `O_EVTONLY` + `/dev/fd` as a **demonstrated equivalent** of the baseline metadata-only/type-before-readable-open strategy. It retains the original regular object in tested replacements, but does not establish the crucial initial type boundary. `O_EXEC` is not a general substitute. Ordinary beneath/no-symlink flags help but do not finish ancestor/mount containment.

This is a blocker for these candidate approaches, NOT proof that every possible macOS implementation is impossible. The whole ticket remains open pending human response and either a different evidenced design or an explicit decision on how to proceed. No relaxation of the approved safety contract is proposed or implemented.

Still unproven: a safe Rust-accessible complete collector, independent bounded enumeration/cursors, forbidden mount traversal, stressed ancestor/replacement races, exact-object identity compatibility, and native macOS 15/26 behavior.
