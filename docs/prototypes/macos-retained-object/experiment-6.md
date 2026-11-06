# THROWAWAY experiment 6: directory substitution defeats a per-file capture budget

## Question and method

Can a prechecked regular file be replaced by a directory before `clonefileat`, causing capture work beyond the reservation before validation gets a chance to refuse?

Native C probe `directory-substitution-prototype.c`, macOS 27.0.1 ARM64, strict `clang -std=c11 -Wall -Wextra -Werror`, final run exit 0, outer 10-second timeout. Only small synthetic fixtures in the authorized scratch directory. No devices, mounts, real repositories, authorities, credentials, installation or cleanup. Captured directories are enumerated only for measuring this deliberately small synthetic result, with count/depth limits. The enumeration is not proposed production code.

Each case begins with a regular 9-byte file, reads its metadata and assumes a one-object capture reservation. The probe then renames that file away and substitutes either an empty directory or a directory with four files plus a nested directory containing four more files. It calls `clonefileat` with no-follow-any and beneath flags, validates the result type and refuses it as nonregular. No captured payload file is opened/read.

## Actual observations

| Substituted source | Clone result | Objects created by capture | One-object reservation exceeded? | Payload reads |
| --- | --- | --- | --- | --- |
| Empty directory | success | 1 directory | no | 0 |
| Directory with 9 descendants | success | 10 objects | **yes** | 0 |

The populated hierarchy was already cloned BEFORE the post-capture type check could reject it. A prechecked 9-byte regular file did not bound actual capture work. Source remains untouched except for the probe's explicit synthetic mutation actor; captures/results are retained.

This agrees with Apple's public [clonefile manual](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/clonefile.2#L80-L91): when the source names a directory, the hierarchy is cloned as if each item were cloned individually. The inspected [public clone flags](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/clonefile.h#L32-L52) do not expose a regular-file-only/expected-source-type condition. Beneath/no-symlink restrictions do not imply regular-only capture.

## Verdict

This is a concrete blocker for **the currently proposed precheck → pathname-clone → validate → read protocol under its bounded-capture requirement**. Experiment 5's pre-read validation still protects those tested data-open schedules, but does not undo already-performed capture work. Restating that validation will return Changed is not a fix for the resource boundary.

No production protocol is accepted. Do not silently increase limits, charge only eventual reads, claim post-capture size checks prevented prior allocation, or add a recursive-copy fallback. Process timeouts are not a demonstrated hard bound on an in-flight filesystem operation; killing a helper is not proof no capture/evidence remains. A resource/quota containment approach, if proposed, needs an actual enforced bound and compatibility argument, not an assumption.

This does not prove every native macOS approach impossible. It establishes that this tested public pathname-clone strategy still needs a mechanism that either excludes directory substitution atomically or enforces an adequate capture-work bound independently of the source precheck. Neither is demonstrated by these probes. Stage handoff, native enumeration, ancestor/mount safety and full metadata proof remain additional obligations even if this blocker is solved.

## Next decision boundary

Do not accept the prototype or begin the full port on the strength of ordinary-file clone success. Return this candidate's concrete blocker for human review. Further work must name a specific bounded-acquisition mechanism/changed assumption before more happy-path probes; any reduction of the approved ordinary-concurrency or capture-budget guarantees must be an explicit decision, not inferred from the desire to support macOS.
