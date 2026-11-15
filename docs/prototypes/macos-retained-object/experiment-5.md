# THROWAWAY experiment 5: capture, validate, then open/read

## Approved refinements and boundary

The operator approved [authenticated staged-equivalent semantics, the cooperative threat boundary and bounded private capture](https://github.com/techwright-lab/work-cli/issues/23#issuecomment-6687838428). This permits a different internal architecture IF equivalent preservation/consistency/unsafe-open protection is demonstrated. It does not accept timestamps or stopped-writer confirmation alone as proof, malicious same-UID containment, production staging or a completed port.

## Method

Native C prototype `validate-before-read-prototype.c`, synthetic scratch-only fixtures, macOS 27.0.1 ARM64. Compiled with `clang -std=c11 -Wall -Wextra -Werror`; final bounded run exited 0 under a 10-second outer timeout. No actual device nodes, mounts, real repositories, authorities, credentials, installations or cleanup. An earlier exploratory run was used to move invalid-initial-token refusal before capture; retained final source/output correspond to the tightened final run.

Requests `ATTR_CMN_RETURNED_ATTRS`, `ATTR_CMN_GEN_COUNT`, `ATTR_CMN_FILEID`, and `ATTR_CMNEXT_CLONEID` through `getattrlistat` with no-follow, extended attributes, and packed-invalid-fields options. Parses the 44-byte result with memcpy, checks returned masks/length, and requires nonzero generation/clone tokens. Attribute file IDs must match the separately observed inode identities. This parser covers exactly this fixed probe request, not arbitrary attribute layouts or a production safe Rust binding.

Control flow: initial tokens/stamp; refuse invalid initial tokens; clone into private same-volume staging; reobserve source and stage tokens/stamps; require matching source stamps, unchanged source generation/clone ID, regular singly-linked stage and matching source/stage stream ID; ONLY THEN readable-open and read the staged file, checking opened identity. The source pathname is never opened for data by this collector logic; controlled mutation actors use synthetic writer handles to inject negative schedules.

## Actual final observations

| Case | Observation | Candidate decision | Readable clone opens | Captured bytes read |
| --- | --- | --- | --- | --- |
| Stable ordinary file | Source generation 2 stayed 2; source/clone had equal stream ID but distinct file IDs | READ original synthetic data | 1 | 8 |
| Pathname replacement/restoration | Source original restored; captured clone's stream ID identified replacement | REFUSE | 0 | 0 |
| Content replacement/restoration | Source generation changed 2→4; source stamp/stream changed | REFUSE | 0 | 0 |
| Shared writable mmap present | Initial source generation was 0 (invalid), despite otherwise ordinary file | REFUSE before capture | 0 | 0 |

Native returned masks included all requested fields. First clone creation did not invalidate stable source tokens in this run. Source/clone data generations need not equal each other; comparison is source-before versus source-after, with stream association separately checked.

## What this establishes

The public tokens are observable and useful on this native fixture, not just theoretical header definitions. The revised ordering allows a stable data path and rejects the tested changes BEFORE readable opening or consuming captured data. This is a meaningful improvement over the deliberately naive earlier probes, and a direct counterexample to the overbroad claim that clone-first necessarily reads replacement data before validation.

## What this does NOT establish

- No claim of universal anti-ABA proof, a coherent whole-tree snapshot, metadata/fork equivalence, mmap history/wrap semantics or every concurrency schedule.
- Stage is modified only by this probe; its prevalidation-to-readable-FD handoff still needs the accepted cooperative ownership argument and adversarial tests against unrelated-principal access/ordinary staging changes. Post-open fstat alone is not a general cure for opening a substituted device.
- The probe does not solve regular-source→directory substitution during clone, capture/metadata growth budgets, unknown interruption outcomes or bounded staging cleanup.
- Mount/ancestor containment, bounded fresh directory enumeration, post-read/live-tree revalidation, Git common-directory and preservation binding are not implemented.
- No macOS 15/26, APFS case-variant, reboot/persistence, safe Rust wrapper, complete suite, final artifact or release qualification evidence exists from this run.
- Mapped files are a conservative refusal for THIS candidate; a successful mmap test does not define all product treatment of editors, nor imply that generation counters are globally valid after every possible mapping lifecycle.

## Next finite obligations

Before accepting the inspection prototype, establish bounded capture under source-type substitution, an explicit protected-stage-to-readable-handle protocol under the approved threat boundary, and required native enumeration/ancestor/mount/refusal evidence. Then obtain human acceptance of the concrete approach and list remaining release-qualification obligations. More successful ordinary-file tests do not discharge these obligations.

Evidence basis: [bounded primary-source feasibility report](https://github.com/techwright-lab/work-cli/blob/1603d738cb504bfc0135c50b729129e8077017ed/docs/research/macos-inspection-feasibility.md), especially generation/clone-ID semantics, returned masks and staged handoff limitations. This remains a throwaway experiment; no production design or support claim is approved by its exit status.
