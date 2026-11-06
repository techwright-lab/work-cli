# THROWAWAY: macOS retained-object inspection experiment 1

Question: after a controlled pathname replacement, does reopening the pathname or opening `/dev/fd/N` reach the retained original object?

This is a native C API probe, NOT production Rust, a safe Rust binding design, full safety qualification, or approval to remove anything. It was run on macOS 27.0.1 ARM64 only. Source, actual output and environment are retained beside this note. The compiled binary is retained locally, not published.

## Run

In a disposable owned directory with only synthetic files:

```sh
clang -std=c11 -Wall -Wextra -Werror inspection-prototype.c -o inspection-prototype
mkdir fixture
./inspection-prototype fixture
```

Use a new empty fixture directory for each run. Existing entries intentionally cause failure. No mounts, native device nodes, real repositories, credentials, Work authorities, installation changes or cleanup are involved. The user authorized a scratch directory; none of this writes the project checkout.

## Observations (one controlled run, not a race proof)

- After a synthetic regular file was renamed and replaced, a fresh readable pathname open reached the replacement inode. A replacement FIFO was also successfully opened before any post-open type rejection. The probe did not read the FIFO. `O_NOFOLLOW` rejected a replacement symlink, but did not prevent opening the FIFO.
- A retained `O_EVTONLY` handle plus `/dev/fd/N` returned the original inode and original synthetic data for regular, FIFO and symlink pathname replacements.
- `dup` reported the original inode, but its read returned EOF after the first read through `/dev/fd/N`, consistent with a shared file offset. Descriptor duplication must not be assumed to create an independent read/enumeration cursor.
- `O_SYMLINK` on the original regular file did not provide a distinct metadata-only readable transition: reported access flags were ordinary read-only; descriptor reopening again read original data.
- Critically, reading through a descriptor carrying `O_EVTONLY` succeeded. Therefore this result does NOT establish an `O_PATH`-like type-before-readable-open boundary or prove that opening arbitrary special files with `O_EVTONLY` has no driver/FIFO side effects. No actual device nodes were tested, and such a test is not authorized by the scratch-only experiment.

## What this answers

The controlled experiment rejects precheck-then-pathname-readable-open as a sufficient exact-object strategy. It establishes an interesting native descriptor duplication behavior on this OS and exposes shared-offset semantics. It does not yet establish a production approach preserving all baseline guarantees.

## Remaining gaps

- Does the initial handle acquisition avoid forbidden readable/device-open effects for every rejected type? Need source/API reasoning as well as bounded synthetic probes, not just a successful regular-file test.
- `/dev/fd` trust/availability, descriptor lifetime/aliasing and independent cursor behavior need explicit design; merely finding original bytes is insufficient.
- Bounded native enumeration, ancestor replacement, symlink escape and no-mount-crossing are not exercised here.
- macOS 15/26 behavior, race/adversarial stress, safe Rust interfaces and native release-artifact qualification are not demonstrated.

The decision ticket remains open for human feedback and further bounded investigation. No accepted safety guarantee is relaxed by these findings.
