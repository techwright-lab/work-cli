# Download, install, update and release work-cli

## Supported distribution

Publish Linux x86_64 archives built and smoked in the pinned Debian qualification
container. Require glibc >=2.36, stable Git >=2.55.0 at `/usr/bin/git`, and Python
3.11+ for the distribution helper. Git 2.55.0 and 2.56.0 are tested; accepted newer
versions are not automatically qualified. Keep ARM64/native-runner archives as
CI coverage, not supported release assets.

Use public GitHub Releases from `techwright-lab/work-cli`. Verify SHA-256 before
executing a downloaded binary. The archive and sidecar share GitHub's trust domain:
the checksum detects corruption, not a compromised publisher or cryptographic
signing identity. The helper uses anonymous HTTPS without host credentials or
proxy settings and permits only GitHub/GitHub asset redirect hosts.

## Bootstrap and download

Obtain the helper from a reviewed source checkout/tag. The commands below target
v0.2.4 after its release has been published; a PR or successful build is not a
published release.

```sh
git clone --branch v0.2.4 --single-branch https://github.com/techwright-lab/work-cli.git
cd work-cli
python3 tools/work_install.py download --version v0.2.4 --output-dir "$HOME/Downloads/work-cli-v0.2.4"
```

Download creates the output directory, verifies both canonical archive name and
checksum, and leaves the binary uninstalled. Existing destinations are refused.
Use `--version latest` to resolve the latest non-draft, non-prerelease GitHub
release. Offline installation requires an explicit version plus both files.

## User-scoped install

Stop Work operations before switching an existing installation. Install without
sudo, shell-profile edits, changes to host Git or writes to a Work authority:

```sh
python3 tools/work_install.py install --version v0.2.4 \
  --archive "$HOME/Downloads/work-cli-v0.2.4/work-cli-0.2.4-linux-x86_64.tar.gz" \
  --checksum "$HOME/Downloads/work-cli-v0.2.4/work-cli-0.2.4-linux-x86_64.tar.gz.sha256" \
  --skills-dir "$HOME/.agents/skills" \
  --skills-dir "$HOME/.claude/skills"
export PATH="$HOME/.local/bin:$PATH"
work --version
work-install --help
```

Omit archive/checksum to download the selected release during installation. Add
`--confirm-stopped` when changing an existing active version. This flag is an
operator assertion, not process inspection or kernel quiescence proof.

Defaults:

| Item | Location |
|---|---|
| Work command | `~/.local/bin/work` |
| Updater command | `~/.local/bin/work-install` |
| Versioned files | `${XDG_DATA_HOME:-~/.local/share}/work-cli/releases/vVERSION` |
| Active pointer | installer data directory's `current` symlink |
| Optional skills | explicitly supplied `--skills-dir` directories |

Use `--bin-dir` and `--data-dir` for isolated installs. The helper rejects symlinked
managed directories, unmanaged existing binary/skill targets, invalid checksums,
version mismatches, archive links/traversal/duplicates/special files and changed
cached releases. It bounds download/extraction size and serializes installers.
It stages and verifies files before switching the current pointer atomically.
Previous releases remain available; no automatic pruning occurs. This is a
cooperative user-scoped installer, not hostile-same-UID containment or hardware
power-loss certification. Recheck the active version after interrupted operations.

## Agent skill discovery

The archive includes `skills/work-cli/SKILL.md` and references. Register a
content-addressed snapshot through the stable installer `skill-current` link with
explicit `--skills-dir` flags. The snapshot includes its linked distribution
document, so references remain valid and later source edits cannot silently change
installed instructions. `.agents/skills` serves
agents supporting that standard discovery path; Claude Code uses `.claude/skills`.
Pass another directory only when the agent documents it as a skill location.
Reload/restart the agent's skill catalog after installation.

For an explicitly reviewed local skill before a matching binary release exists,
run `python3 tools/work_install.py skill --source-root /absolute/reviewed/checkout
--skills-dir "$HOME/.agents/skills" --skills-dir "$HOME/.claude/skills"`. This
snapshots instructions without installing a binary or touching Work authority.
The next skill-bearing package installation can update the same managed links.
Treat unpublished instructions as a candidate, not a published artifact.

The skill is portable instructions, not a universal hook: tools that do not scan
these paths can read the file explicitly. Add a project instruction such as
"Before code changes in this configured repository, read the work-cli skill" to
the project's agent guidance. This repository's `AGENTS.md` owns its routing.
Keep existing skill/binary targets intact when the installer reports a conflict;
review and resolve that target explicitly rather than using a force overwrite.

## Configure everyday work

Choose an accountable actor, repositories, capacity and persistent managed root.
Copy `examples/work.toml` to `${XDG_CONFIG_HOME:-~/.config}/work/config.toml`, set
literal absolute paths and create the managed root. Keep store and registry
outside repositories and managed roots, and exclude the root from unrelated
cleaners. Use `WORK_CONFIG=/absolute/document.toml` for a different authority.

Verify `work status --json` before allocation: absent authority reports
uninitialized without creating one. Start with an explicit intended base:
`work start --task TASK --base origin/main`. Run the agent/editor in the returned
destination, retain checkout/operation IDs and follow the skill's completion and
confirmation contract. Leave prior experimental/pilot authorities separate.

## Update and rollback

Stop all Work operations sharing the installation/authority, then request a
specific version or resolve the latest stable release explicitly:

```sh
work-install update --version latest --confirm-stopped \
  --skills-dir "$HOME/.agents/skills" --skills-dir "$HOME/.claude/skills"
work --version
```

Updates preserve Work stores, registries, checkouts and outboxes. Use the same
compatible binary across an authority; binary rollback is not schema rollback or
permission to reinterpret historical events. After reviewing state compatibility,
activate a previously verified cached release with
`work-install rollback --version VERSION --confirm-stopped`. Receipt/file hashes
and binary version are rechecked before activation. The updater remains available
even when rolling back to a pre-updater archive. Skill snapshots have an independent
pointer: a skill-bearing install updates registered instructions, while rollback
to a pre-skill release retains the last reviewed snapshot. Review its minimum
binary-version requirement before continuing; independent instructions are not
proof of binary/state compatibility.

Remove only installer-owned command/skill links to uninstall; retain versioned
files until rollback is no longer needed. Work state is separate and must remain
preserved. No installer command repairs authority identities, releases quota,
removes task checkouts or sweeps old backup prefixes.

## Maintainer release process

1. Prepare a feature/release PR. Set `[workspace.package].version` in Cargo.toml
   and the two local-package versions in Cargo.lock. Keep dependency versions
   unchanged for a metadata-only bump. Archive naming and smoke derive the
   workspace version; do not edit CI for every release.
2. Run `python3 tools/release_version.py`, then qualify both tested Git versions:
   complete locked workspace tests, formatting, strict all-target Clippy, Python
   helper tests, `tools/package-linux.sh`, and `python3 tools/qualification/smoke.py`
   through the pinned container helper. The package smoke includes offline install,
   installed binary version and agent-skill discovery in disposable directories.
3. Review and merge the PR. Require green exact-commit main CI, including ARM64,
   both container qualifications, build gates and CodeQL. Do not reuse an older
   SHA's passing result. Fetch origin and verify the clean selected release HEAD
   equals the merged, tested `origin/main`.
4. Validate the proposed tag with `python3 tools/release_version.py --tag vVERSION`.
   Confirm no such tag/release exists. With explicit publication authorization,
   create an annotated `vVERSION` tag on the exact tested commit and push only
   that tag. Do not rewrite a published tag or force-push a release.
5. Tag CI reruns validation and requires tag/workspace/lockfile identity. The
   publication job downloads only `work-cli-linux-x86_64-qualified`, verifies its
   sidecar and publishes the archive plus checksum with generated release notes.
   A failed gate prevents publication. Keep the failed tag/run as evidence and
   use a new patch version rather than silently replacing release assets.
6. Download the public assets afresh, verify checksum and `work --version`, then
   exercise install/upgrade in an isolated directory. Record exact tag/commit,
   workflow URL, archive digest and test results. Update operator installations
   only after stopping their Work operations and obtaining their authorization.

The version guard prevents mismatched tags; it does not authorize publication,
prove the selected commit is main, or replace human review of CI/release evidence.
Keep those checks explicit.
