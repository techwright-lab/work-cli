# Apple Silicon CI and standalone distribution constraints

Research for [Establish Apple Silicon CI and standalone distribution constraints](https://github.com/techwright-lab/work-cli/issues/15), informing [Map native Apple Silicon support and single-command distribution for work-cli](https://github.com/techwright-lab/work-cli/issues/13).

- **Observed:** 2026-11-06 UTC. Runner availability and Apple service requirements are time-sensitive.
- **Repository baseline:** `41d01c3a6f1ea2bafcc7432240f725c55c810781` (main when research was assigned). Repository claims below refer to that commit, not uncommitted checkout documentation.
- **Method:** read-only source/document review and public primary-source retrieval. No build, installation, native test, Work configuration/authority access, credential inspection, or GitHub environment-settings audit was performed. This report is not qualification evidence or release authorization.
- **Scope:** macOS Apple Silicon (`aarch64-apple-darwin`) and its interaction with existing Linux x86_64 distribution. No Intel macOS support decision, implementation, PR, merge, or release publication.

## Executive findings

1. **Native hosted CI is available now:** standard `macos-15` and `macos-26` runners are ARM64; `macos-latest` currently maps to 26. Do not use old advice that `macos-14` is the standard Apple Silicon option: GitHub Actions retired macOS 14 on **2026-11-02**. An OS label is not an immutable machine image. [G1][G2][G3]
2. **There are three different floors:** Rust supports ARM64 macOS 11.0+, hosted native runner coverage currently starts at macOS 15, and Work has **no qualified macOS minimum yet**. A deployment target or successful cross-build does not resolve that gap. [R1][R2][G1][W1]
3. **Do not replace Apple's Git:** System Integrity Protection protects `/usr`; Git supports a separate installation prefix. But baseline Work hard-codes `/usr/bin/git`, clears child environments, and restricts child `PATH`. Installing another Git or changing the user's shell `PATH` alone cannot port that baseline. [A1][T1][W3]
4. **A standalone signed executable is feasible, with a material offline limitation:** Developer ID signing and notarization support command-line code. A ZIP can carry a tool for notarization, but neither a ZIP nor a standalone executable can have a notarization ticket stapled directly. A raw binary cannot promise the same offline first-run ticket availability as a stapled supported container. [A3][A4][A5]
5. **Checksums are not signing identity:** preserve the existing executable-plus-SHA-256 pattern, but distinguish corruption detection, publisher/transport trust, Developer ID identity, notarization, and native behavioral qualification. None substitutes for the others. [W1][A3][A5][D2]

## 1. Factual constraints

### 1.1 GitHub-hosted Apple Silicon runners

The GitHub standard-runner tables list the following for both public and private repositories. Public standard runners are free and unlimited under the documented model; private usage draws from the account's included compute usage and then incurs charges. This establishes product availability, **not** this repository's enabled Actions settings, quotas, budget, or scheduling behavior. [G1]

| Label | Architecture / advertised resources | Current documentation observation |
| --- | --- | --- |
| `macos-15` | ARM64, 3 CPU (M1), 7 GB RAM, 14 GB SSD | macOS 15.8.2; image `20261028.0489.1` |
| `macos-26` | ARM64, same standard resource class | macOS 26.6.2; image `20261026.0455.2` |
| `macos-latest` | ARM64, same standard resource class | Currently points at macOS 26; a moving alias |
| `macos-15-xlarge`, `macos-26-xlarge` | Larger-runner class: ARM64 M2, 5 CPU, 14 GB RAM, 14 GB SSD | Separate larger-runner availability/billing/access constraints, not the standard-runner entitlement |

The image snapshots list Git 2.56.0 and Rust 1.99.1; macOS 15's default Xcode is 16.4 and macOS 26's is 26.6. These are **image documentation observations**, not commands run by this research, not a guarantee about `/usr/bin/git`, and not a reason to use image-default tools rather than Work's selected toolchain/fixtures. The baseline pins Rust 1.98.1 and qualifies Git 2.55.0 and 2.56.0. [G4][G5][W2]

GitHub updates images generally weekly, migrates `-latest` over time, and supports a limited rolling set of GA OS images. Even `macos-15` pins an OS family, not an exact image revision. GitHub says to obtain the image actually used from the job's **Set up job** logs. The retirement announcement explicitly keeps the 2026-11-02 date for Actions macOS 14, regardless of the temporary Azure DevOps Intel extension. [G2][G3]

Documented limitations include no nested virtualization on ARM64 macOS runners and no static UUID/UDID. GitHub-provided actions support ARM64, but third-party actions may need compatibility work. Docker container actions, job containers, and service containers require Linux runners; the baseline Linux container wrapper is not a native Darwin qualification mechanism. Larger-runner static IP/private-network limitations also exist. None of these facts inherently requires a provisioning profile for a plain Developer ID CLI: Apple distinguishes restricted entitlements, which need profiles, from unrestricted hardened-runtime entitlements. [G6][G7][A5]

### 1.2 Rust, deployment targets, and the minimum macOS claim

At the repository-selected Rust **1.98.1**, `aarch64-apple-darwin` is **Tier 1 with host tools**, supporting native `rustc`, Cargo, the standard library, and Rust's own automated testing. The target's minimum OS is **macOS 11.0 Big Sur** on M1-family or later Apple Silicon. The documented minimum for ARM64 host tools is also 11.0. This is a Rust guarantee, not proof that Work or all its dependencies/APIs work on every such OS. [R1][R2]

The target emits Mach-O. Rust honors `MACOSX_DEPLOYMENT_TARGET`; `rustc --print=deployment-target --target aarch64-apple-darwin` reports its deployment target. Raising the target can permit newer APIs/optimizations. Apple distinguishes an SDK (APIs available to compile against) from the deployment target (older OS compatibility); its archived deployment guide also describes checking availability of newer APIs. Rust's target docs warn that linking/C compilation may require Xcode or the macOS SDK, with `SDKROOT` or SDK discovery corresponding roughly to `xcrun --sdk macosx --show-sdk-path`. [R1][A2]

The baseline includes `rusqlite` with bundled SQLite, plus `rustix`, `signal-hook`, and other dependencies. The artifact's real floor depends on Work's native APIs, dependencies, C compilation/link flags, the selected SDK/linker, and qualified Git. It cannot be established by the Rust floor alone. A binary linked on a newer runner and executed there is not evidence of execution on macOS 11–14, nor on the earliest minor release of macOS 15. [W4][R1][A2] **Inference:** without separately supplied older native Macs/VMs, hosted-runner-only qualification cannot demonstrate an older support floor than its available native OS coverage.

### 1.3 Qualified Git without modifying `/usr/bin/git`

Apple says System Integrity Protection protects `/usr` (among other system locations), restricting even root; `/usr/local` is an explicitly writable exception. Overwriting `/usr/bin/git`, disabling SIP, or transplanting the Linux CI step that copies a staged `/usr` tree into `/usr` is therefore not a valid macOS installation/qualification plan. [A1][W2]

Git's own installation guide supports a user installation (normally `~/bin`) and custom prefixes. Build and install must use the same prefix because paths are encoded into the build. A pinned source build into a private prefix is a feasible **CI provisioning path**, not an end-user requirement to compile Git or Work. Git's build also has Darwin-specific rules; its 2.55.0 Darwin configuration has additional libiconv handling on Darwin 24+, illustrating why the actual macOS Git fixture must be built and tested rather than copying the Linux recipe blindly. [T1][T3]

Homebrew's own documentation identifies `/opt/homebrew` as the default Apple Silicon prefix and currently requires macOS 15+ for its supported configuration. Homebrew can provision a Git installation separate from Apple's files, but using it adds Homebrew's version/OS/trust constraints; its current default is not an immutable two-version qualification matrix. **No Homebrew installation or formula availability was tested here.** A pre-existing installation is only a discovery candidate, not automatically qualified. [H1][G4][G5]

Git documents `--exec-path` / `GIT_EXEC_PATH` for locating core helper programs; this does **not** select the top-level Git executable. Git also resolves external `git-*` commands through `PATH` and supports explicit global/system config controls. A separately installed `git` must retain its appropriate helper/runtime layout, not just be copied alone. [T1][T2]

**Baseline-specific blocker:** `identity.rs`, `inspection.rs`, `setup.rs`, and `doctor.rs` invoke `/usr/bin/git`; identity/inspection clear the environment and set `PATH=/usr/bin:/bin`. Integration fixtures and artifact smoke also contain hard-coded paths; remote-proof code includes an absolute upload-pack path. The inspection version gate accepts canonical stable `MAJOR.MINOR.PATCH` versions >=2.55.0. Thus neither shell `PATH` modification nor an Apple/vendor-suffixed version should be assumed sufficient. [W3]

**Feasible selection shapes (not a chosen API):** discover a separately installed Git from an explicit operator-supplied location, a documented trusted candidate location, or a bounded search; validate it and use its resolved absolute path consistently across prerequisite checks and native operations. The precedence, symlink/ownership rules, persistence, runtime revalidation, and failure semantics require the specification's decision. Introducing an environment variable or config field here would be a product/API decision, so this report does not invent one. No approved minimum is lowered and no unqualified fallback to Apple Git is recommended.

### 1.4 Native qualification and exact-artifact release boundaries

The baseline's complete locked Rust suite, helper tests, package script, and artifact smoke run through a disposable pinned **Linux** container for each Git fixture. Native Linux ARM64 jobs are CI coverage only, not supported release assets. The package script explicitly rejects non-Linux-x86_64 hosts. Smoke verifies SHA-256, binary version, byte identity between standalone/bundle executables, native skill registration without tools on `PATH`, disposable task lifecycle/preservation/quota behavior, and optional Python helper interoperability. The release job publishes only the selected qualified Linux artifact; it does not reference a GitHub environment in the reviewed YAML. That last observation is **not an audit of remote settings or approval gates**. [W1][W2][W5]

Rust supports native tests on the macOS ARM64 target. Cross-compilation demonstrates that code can be built, not Darwin filesystem/process/reboot behavior, Work's ownership/preservation guarantees, or macOS installer/Gatekeeper behavior. Docker-based Linux tests on a Mac still do not establish Darwin behavior. This distinction follows from the target/runner separation, and the current wrapper is explicitly Linux-specific. [R1][G7][W2]

Signing changes the executable's signature-bearing bytes. Apple directs external build systems to add a signing step, and recommends testing the distribution users actually receive, preferably on another Mac. Therefore a signed release asset must be validated and checksummed **after final signing**; do not publish unsigned-build checksums or substitute a later rebuild for the tested executable. A final signed bundle and standalone asset can contain identical executable bytes. Notarization submission/acceptance and final-container stapling add steps beyond `cargo build`. [A3][A4][A5][A6]

GitHub documents temporary-keychain certificate import for hosted macOS CI and destruction of the hosted VM at job end; self-hosted machines need explicit cleanup. GitHub environments can withhold job execution/secrets until configured rules pass, including required review and optional prevention of self-review, subject to plan/visibility constraints. These are available mechanisms, **not claims that this repository's Apple credentials, reviewers, protections, or environment are configured**. [G8][G9]

### 1.5 Gatekeeper, quarantine, signing, and notarization

Keep these layers separate:

| Layer | What primary sources establish | What it does not prove |
| --- | --- | --- |
| SHA-256 sidecar | Byte-integrity comparison against the supplied digest | An independently authenticated publisher, malware absence, or correct runtime behavior |
| Developer ID signature | Distribution identity and integrity checks for directly distributed code | Notarization or Work's safety qualification |
| Notarization | Apple's automated malware/code-signing checks and an online ticket; not App Review | Complete security review or native functional correctness |
| Gatekeeper / provenance / quarantine | First-run trust/approval checks and provenance-sensitive behavior under system policy | Identical behavior for every download client, OS, account, or managed Mac |
| Native artifact smoke | Observed behavior of tested bytes in specified environments | Untested OS floors, unmanaged host configurations, or all Gatekeeper paths |

Sources: [A3][A4][A5][A7][W1][D2].

Apple's current platform-security guide says software is checked for known malicious content on first opening regardless of arrival path, and that Gatekeeper tracks provenance. Its user guide describes Developer ID/notarization checks and first-open approval; administrators can restrict available overrides. The archived TN2206 provides a quarantine-sensitive distribution-test procedure. Its older wording that Gatekeeper checks only quarantined files must **not** be treated as a complete description of modern macOS policy. A locally built or already trusted executable, or a successful terminal download/run, cannot certify a fresh browser-download experience. [A7][A8][A9]

For the supported direct-distribution signing path, Apple specifies **Developer ID Application** for independent executable distribution, a secure timestamp, hardened runtime on main executable/command-line targets, a code-signing identifier for nonbundled code, and no enabled `get-task-allow`. Ad hoc/local development signatures are not acceptable substitutes for the notary service's Developer ID requirement for new software. Restricted entitlements can impose provisioning/bundle requirements, but this report finds no reason to assume Work needs such entitlements without reviewing the eventual port. [A3][A5]

Apple accepts ZIP archives, UDIF disk images, and signed flat installer packages for notarization; a raw Mach-O is not the documented upload container. A single CLI can be placed in a ZIP for submission without becoming an app bundle. Use the supported `notarytool` flow and inspect the final status and log; do not treat a successful upload/submission ID alone as acceptance. Apple's overview says Xcode 14+ is required for its current supported upload workflow after the 2023 service change; its customization page still mentions the earlier Xcode 13 introduction of `notarytool`. Follow the current service requirement, not that historical introduction. A Notary API is also documented. [A3][A4]

**Stapling constraint:** Apple explicitly says tickets exist for standalone binaries but cannot currently be stapled to them. ZIPs cannot be stapled either; repacking a ZIP cannot give a bare CLI a stapled ticket. Supported app bundles, disk images, and flat installer packages can carry stapled tickets. Without a stapled ticket, Gatekeeper may need online ticket discovery and can block offline use/installation. This limits a strict raw-binary-first offer; it does not mean notarizing a standalone tool is impossible. [A4][A6]

The installer must not silently clear `com.apple.quarantine`, disable Gatekeeper/SIP, re-sign downloaded binaries locally, or claim that `curl` is a security-policy bypass. This is a **safety recommendation**, not a claim that all clients attach the same extended attributes. Actual quarantine/provenance handling for direct download, file copying, terminal invocation, browser download, online/offline launch, and managed Macs remains a qualification question. Apple's documented user override is an explicit user/security-policy action, not installer consent to weaken protections. [A7][A8][A9]

### 1.6 Standalone assets, checksums, and one-command installation mechanics

The baseline already distributes a native `work-VERSION-linux-x86_64` executable and matching `.sha256`; ordinary execution needs neither source checkout, Rust, nor Python, but still needs qualified external Git for repository operations. The optional bundle/helper is a separate path. This is **not** an existing macOS asset claim. A single executable can still depend on OS libraries and Git; macOS qualification must inspect the actual Mach-O dependencies rather than interpreting “standalone” as “fully static” or “no Git required.” [W1][W4][W5]

GitHub documents stable release and latest-release links, including `/releases/latest/download/ASSET`. A latest URL is mutable. **Recommendation:** a one-command installer that offers “latest” should resolve one version once and fetch both executable and checksum for that same version, with exact agreed OS/architecture asset names; do not independently resolve two moving URLs or use a source-branch binary. Do not fetch a not-yet-published version or silently fall back to another architecture. [D1][W1]

The mechanics require only native tools/a reviewed shell installer, not Rust, Python, or a source checkout: identify supported OS/CPU and minimum OS, download into a private staging area, verify the expected file and SHA-256, preserve current installation ownership, then activate in a user-writable destination. `curl --fail --location --output` handles HTTP failures/redirects/output; `--proto '=https' --proto-redir '=https'` constrains protocols. `shasum -a 256 -c FILE.sha256` is the macOS-style check command when that utility is present; unlike `sha256sum`, its default algorithm is SHA-1. The utility is implemented in system Perl, not Python; availability/version must be preflighted on the selected support floor rather than silently installing a runtime. These are documented mechanics and a proposed sequence, **not an implemented or tested installer**. [D2][D3]

**Integrity/trust limitation:** a checksum downloaded beside a compromised executable can be replaced with it. HTTPS, GitHub/publisher control, installer-code trust, Developer ID verification, optional attestations/signatures, and the intended freshness policy are separate concerns. A `curl | sh`-style bootstrap executes installer code before that code can verify its payload: payload checksums do not authenticate the bootstrap script retroactively. The map authorizes a one-command direction, not a new signing trust root or a particular pipe-to-shell implementation. [W1][D2][A5]

## 2. Recommendations for the later specification (not decisions)

### 2.1 Qualification envelope

- Prefer explicit currently supported ARM64 OS labels to `macos-latest` for required qualification, with optional latest-canary coverage. Candidate current native families are **15 and 26**; no floor is selected here. If support below 15 is desired, provide separately authorized native environments and evidence, or explicitly retain that gap. A family label does not cover every minor release.
- Record exact source SHA; runner label, actual image version, `sw_vers`, `uname -m`; Rust/Cargo versions and target; SDK/Xcode/Clang identity; deployment target; selected Git absolute path/version/helper path; final artifact digest and workflow/run identity. Assert native ARM64 execution and do not let Rosetta success stand in for ARM64 coverage. Use private disposable fixtures, isolated HOME/config, and no real repositories, authorities, or credentials.
- Retain complete locked workspace tests, formatting, strict all-target Clippy, helper tests, packaging, and artifact smoke as independent evidence. Run both existing Git fixtures (2.55.0 and 2.56.0) natively where promised. Keep Linux's pinned-container qualification; design a separate native macOS qualification harness instead of weakening the Linux wrapper or marking Darwin failures as a successful skip.
- Translate the core-flow smoke into native disposable macOS fixtures: setup/check/cancellation boundaries, status, start/reuse, finish retaining charge, preview retaining checkout, and authorized confirmed removal with preserved refs and released charge. Add negative Git-selection, checksum, unsupported-platform/floor, and installation-ownership cases. Filesystem/process identity and reboot guarantees need their separate domain research/specification; a happy-path release smoke cannot prove them.
- Inspect final Mach-O architecture, minimum OS metadata, dynamic libraries, signature identity/runtime flags and entitlements. Test the **final signed bytes** in standalone and optional bundle forms, including version and byte equality. Preserve skill-registration proof without Git/Python on `PATH`, while keeping a separately validated Git available for commands that need it.

These proposals preserve baseline release expectations and address the factual gaps above; no tests were executed by this research. [W1][W2][W3][W5][R1][G2][A5][A6]

### 2.2 Feasible distribution/release paths and limitations

| Path | Feasibility | Limitation / unresolved choice |
| --- | --- | --- |
| Raw ARM64 executable + SHA-256, without Developer ID notarization | Can carry executable bytes; analogous integrity packaging to current Linux | No Apple distribution identity/notary assurance; fresh protected-download behavior cannot be promised. Not a recommended implicit default. |
| Developer ID-signed ARM64 executable, notarized via a submission ZIP; raw executable + final checksum distributed | Preserves single-file installation and Apple's online notary record | No stapled ticket on the raw binary; must document and qualify online first use and offline limitations. |
| Signed/notarized CLI in a supported stapled DMG or flat installer package | Can provide a ticket with the distribution container | Adds packaging/install semantics; does not make the bare extracted binary itself staplable. Not a choice to replace the approved standalone UX without a decision. |
| Native build/qualification, later gated signing/notarization of those retained bytes, final artifact smoke, publish both platforms | Separates unprivileged qualification from signing credentials and maintains exact-artifact linkage | Needs a designed evidence chain, signature verification, final-byte checksums, both-platform gating, and approved remote protections; a rebuild after qualification is not the same artifact. |

Grounding: [A3][A4][A5][A6][W1][W2][G8][G9]. “Feasible” means the documented services support the shape, **not** that the Work port compiles or is qualified.

For a shared no-sudo user-local installer, preserve direct-versus-helper-managed ownership, old binary rollback, and stopped-operation boundaries. Stage and verify before replacing; retain the prior executable and leave authority/store/registry/checkouts/quota untouched. An unsupported platform, unavailable qualified Git, download failure, checksum mismatch, foreign/symlink/conflicting destination, or security-policy denial must not become an implicit setup, force overwrite, platform downgrade, or security bypass. Activation/interruption and self-update behavior need explicit acceptance criteria. [W1]

The map already requires one version for both platforms and publication only after both qualify, with actual package-version change on main and configured approval gates. Those are **existing direction**, not new decisions made here. Future release design must extend the baseline tag workflow to enforce that direction; this research neither publishes a release nor certifies any environment configuration. [M1][W2][G9]

## 3. Unknowns and decision inputs left open

1. **Work support floor:** macOS 15 (including which minor versions), an older OS with separately supplied native evidence, or another envelope? Rust's 11.0 floor is only a lower technical boundary. No choice is made here.
2. **Git selection contract:** explicit path/configuration versus trusted-location discovery versus bounded `PATH`; ownership/symlink handling, helper layout, replacement/revalidation behavior, diagnostic exposure, and consistency across all call sites. No environment variable or configuration field is introduced by this report.
3. **Signing policy and credentials:** whether the release must be Developer ID-signed/notarized, the authorized developer/team identity, credential custody/rotation, signing approval and credential-free PR boundaries. No Apple account or GitHub secret was inspected.
4. **Offline and quarantined first-use promise:** is the raw binary's online ticket discovery acceptable, or is an additional stapled container required? Native/browser/terminal/managed-policy trials are still needed on each promised OS. No blanket unsigned-CLI or terminal exemption is claimed.
5. **Actual native dependencies and safety:** the port's minimum APIs, link dependencies, complete suite results, macOS Git build dependencies, and equivalence of ownership/filesystem/process/reboot/preservation behavior remain untested. General toolchain support is not Work qualification.
6. **Installer trust and compatibility:** exact asset vocabulary, bootstrap origin/versioning, authenticity/attestation verification, latest/freshness policy, minimum system utilities, unsupported Rosetta invocation handling, managed-install migration, atomic activation/recovery, and rollback need specification. Existing direct/helper installs must not be silently taken over.
7. **Remote enforcement:** required reviewers, self-review/bypass controls, branch/tag protections, workflow permissions, Actions availability/budget, environment names/secrets and exact-SHA enforcement have **not been audited**. Reading `.github/workflows/ci.yml` does not establish these settings. The operator must verify them before release readiness/publication.

These are evidence gaps and inputs for later human decisions, not blockers to completing this research ticket and not permission for implementation or publication.

## 4. Primary-source index

GitHub source snapshots below use `github/docs` commit `c9d8b26db3b48d8d3e1d91f4cef575623ff12f83` and `actions/runner-images` commit `fad015e47059f40cf0786dcb4593384f6a0720d3`, observed 2026-11-06. Apple/other live pages can change; archived documents are explicitly identified. Rust references use the baseline toolchain tag, not a future nightly. Retrieval succeeded for the cited sources; inaccessible/404 candidate URLs were not used as evidence.

[G1]: https://github.com/github/docs/blob/c9d8b26db3b48d8d3e1d91f4cef575623ff12f83/data/reusables/actions/supported-github-runners.md "GitHub: standard public/private runner tables"
[G2]: https://github.com/actions/runner-images/blob/fad015e47059f40cf0786dcb4593384f6a0720d3/README.md "GitHub runner-images: labels, update/support policy, image logs, macOS 14 retirement"
[G3]: https://github.com/actions/runner-images/issues/15226 "GitHub runner-images: Actions macOS 14 retirement date and Azure Intel-only extension"
[G4]: https://github.com/actions/runner-images/blob/fad015e47059f40cf0786dcb4593384f6a0720d3/images/macos/macos-15-arm64-Readme.md "GitHub: macOS 15 ARM64 image manifest"
[G5]: https://github.com/actions/runner-images/blob/fad015e47059f40cf0786dcb4593384f6a0720d3/images/macos/macos-26-arm64-Readme.md "GitHub: macOS 26 ARM64 image manifest"
[G6]: https://github.com/github/docs/blob/c9d8b26db3b48d8d3e1d91f4cef575623ff12f83/data/reusables/actions/macos-runner-limitations.md "GitHub: ARM64 macOS runner limitations"
[G7]: https://github.com/github/docs/blob/c9d8b26db3b48d8d3e1d91f4cef575623ff12f83/data/reusables/actions/docker-container-os-support.md "GitHub: Linux-only workflow containers"
[G8]: https://github.com/github/docs/blob/c9d8b26db3b48d8d3e1d91f4cef575623ff12f83/content/actions/how-tos/deploy/deploy-to-third-party-platforms/sign-xcode-applications.md "GitHub: signing certificates and temporary keychains on macOS runners"
[G9]: https://github.com/github/docs/blob/c9d8b26db3b48d8d3e1d91f4cef575623ff12f83/content/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments.md "GitHub: environment protection, reviewers, secrets and plan constraints"
[R1]: https://github.com/rust-lang/rust/blob/1.98.1/src/doc/rustc/src/platform-support/apple-darwin.md "Rust 1.98.1: Darwin target, OS floor, deployment target and SDK requirements"
[R2]: https://github.com/rust-lang/rust/blob/1.98.1/src/doc/rustc/src/platform-support.md "Rust 1.98.1: Tier 1 with host tools policy and target table"
[A1]: https://support.apple.com/en-us/102149 "Apple: System Integrity Protection"
[A2]: https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/cross_development/Configuring/configuring.html "Apple archived: SDK-based development/deployment configuration"
[A3]: https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution "Apple: notarization requirements and current submission service"
[A4]: https://developer.apple.com/documentation/security/customizing-the-notarization-workflow "Apple: notarization containers, status/logs, stapling and standalone binary limitation"
[A5]: https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac "Apple: external build signing, Developer ID, identifiers, hardened runtime and provisioning"
[A6]: https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution "Apple: containers, final-distribution testing and offline stapling implications"
[A7]: https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/web "Apple Platform Security: modern Gatekeeper/provenance behavior"
[A8]: https://support.apple.com/en-us/102445 "Apple: safe opening, first-run approval, notarization and managed-policy caveats"
[A9]: https://developer.apple.com/library/archive/technotes/tn2206/_index.html "Apple archived TN2206: single-file signatures and quarantined distribution testing; not a complete modern policy description"
[T1]: https://github.com/git/git/blob/v2.55.0/INSTALL "Git 2.55.0: custom-prefix installation, encoded paths and dependencies"
[T2]: https://github.com/git/git/blob/v2.55.0/Documentation/git.adoc "Git 2.55.0: exec-path, external commands and configuration environment"
[T3]: https://github.com/git/git/blob/v2.55.0/config.mak.uname "Git 2.55.0: Darwin-specific build configuration"
[H1]: https://docs.brew.sh/Installation "Homebrew: Apple Silicon prefix, supported OS and provisioning prerequisites"
[D1]: https://github.com/github/docs/blob/c9d8b26db3b48d8d3e1d91f4cef575623ff12f83/content/repositories/releasing-projects-on-github/linking-to-releases.md "GitHub: release and latest-asset links"
[D2]: https://perldoc.perl.org/shasum "Perl primary documentation: SHA-256 and check mode; checksum format"
[D3]: https://curl.se/docs/manpage.html "curl primary manual: fail, location, output and protocol restrictions"
[W1]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/docs/distribution.md "Work baseline: supported platform, published standalone assets, trust limits and publication gates"
[W2]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/.github/workflows/ci.yml "Work baseline: native matrices, Git/toolchain fixtures, qualification and release workflow"
[W3]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/src/inspection.rs "Work baseline Git gate/command builder; also inspected identity.rs, setup.rs, doctor.rs and Git-related fixtures at this SHA"
[W4]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/crates/work/Cargo.toml "Work baseline dependencies; workspace rust-version is 1.98.1"
[W5]: https://github.com/techwright-lab/work-cli/blob/41d01c3a6f1ea2bafcc7432240f725c55c810781/tools/qualification/smoke.py "Work baseline artifact smoke; also inspected tools/package-linux.sh and tools/qualification/container.sh"
[M1]: https://github.com/techwright-lab/work-cli/issues/13 "Operator-approved map scope and direction, not external technical evidence"

Additional runner sizing source: [GitHub larger-runners reference](https://github.com/github/docs/blob/c9d8b26db3b48d8d3e1d91f4cef575623ff12f83/content/actions/reference/runners/larger-runners.md). Apple Developer article text was retrieved through the corresponding first-party `developer.apple.com/tutorials/data/documentation/...json` endpoints as well as the human-facing sources above.
