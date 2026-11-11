#!/usr/bin/env bash
# Owned native fixtures only; no installation, authority discovery, or cleanup.
set -euo pipefail
qualification_root=$(cd "$(dirname "$0")/../.." && pwd -P)
exec python3 - "$qualification_root" "$@" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

HELP = """Usage: native-macos.sh --destination /absolute/new/path
  [--source /absolute/source] [--development] --toolchain VERSION
  --toolchain-dir /absolute/installed/toolchain [--sdk-root /absolute/existing/sdk]
  (--git-version VERSION --git /absolute/path | --without-git) -- COMMAND...

Qualification candidates require native arm64 macOS 15/26, installed Rust 1.98.1,
and exact canonical native Git 2.55.0 or 2.56.0 with its installed helpers.
--development is DEVELOPMENT/NON-GATE: native macOS 27 and explicitly selected
installed Rust 1.98.1/1.99.1 are permitted, still requiring exact selected Git and
its helper/identity checks. Only disposable owned repository operations may run.
--without-git implies DEVELOPMENT/NON-GATE and prohibits repository operations;
Git on PATH is blocked. This is not a sandbox: do not pass absolute Git invocations
in --without-git mode, credentials, or commands that access real host state.

No Git/toolchain is installed or downloaded. CARGO_HOME starts empty; commands
must use offline dependencies or explicitly reviewed cache paths, never user
credentials. Invoke installed cargo/rustc directly, not rustup shims.
--sdk-root sets SDKROOT to the resolved explicitly supplied existing directory.
No SDK discovery or provisioning occurs; this records selection, not qualification.

The new private destination and evidence are retained on success and failure;
existing destinations and symlink parents are refused. No automatic cleanup.
Source allowlist: Cargo.toml, Cargo.lock, rust-toolchain.toml, README.md, LICENSE,
AGENTS.md, crates, doc, docs, examples, skills, tests, tools, vendor, patches.
Recursively exclude .git*, target, credential/config directories, .env*,
credentials*, *.pem, *.key, *.p12 and *.pfx. The only .git* exception is the
regular source file vendor/libsqlite3-sys/.gitignore required by pinned provenance.
Refuse remaining symlinks/special files, never follow them.
This copies source bytes into owned files, not repository refs or authority state.
Allowlisting cannot identify arbitrary secrets hidden in source: select reviewed
source only. Retained stdout/stderr are command evidence, not environment dumps.
Exit 0 means only harness/command success, not platform qualification. Evidence
marks APFS capabilities/case variants, SDK/deployment and final artifacts
NOT_CHECKED. Aggregate qualification must reject these missing release gates.
"""


class Refusal(Exception):
    pass


def refuse(message):
    raise Refusal(message)


def parse(argv):
    if argv == ["--help"]:
        print(HELP)
        sys.exit(0)
    options = {}
    valued = {"--destination", "--source", "--toolchain", "--toolchain-dir",
              "--git-version", "--git", "--sdk-root"}
    index = 0
    while index < len(argv) and argv[index] != "--":
        key = argv[index]
        if key not in valued | {"--without-git", "--development"}:
            refuse("unknown option: " + key)
        if key in options:
            refuse("duplicate option: " + key)
        index += 1
        if key in {"--without-git", "--development"}:
            options[key] = True
        else:
            if index == len(argv) or argv[index].startswith("--"):
                refuse("missing value for " + key)
            options[key] = argv[index]
            index += 1
    for key in ("--destination", "--toolchain", "--toolchain-dir"):
        if key not in options:
            refuse("required " + key)
    without_git = options.get("--without-git", False)
    development = options.get("--development", False) or without_git
    if without_git and ("--git" in options or "--git-version" in options):
        refuse("--without-git and Git selection are exclusive")
    if not without_git and not all(k in options for k in ("--git", "--git-version")):
        refuse("required --git-version and --git, or explicit --without-git")
    if not without_git and options["--git-version"] not in ("2.55.0", "2.56.0"):
        refuse("unsupported Git fixture")
    versions = ("1.98.1", "1.99.1") if development else ("1.98.1",)
    if options["--toolchain"] not in versions:
        refuse("qualification requires Rust 1.98.1; development permits 1.98.1/1.99.1")
    if index == len(argv) or not argv[index + 1:]:
        refuse("required -- COMMAND...")
    for key in ("--destination", "--source", "--toolchain-dir", "--git", "--sdk-root"):
        if key in options and not Path(options[key]).is_absolute():
            refuse(key + " must be absolute")
    return options, argv[index + 1:], development


def observe(command, env=None):
    try:
        result = subprocess.run(command, env=env, text=True, capture_output=True,
                                timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        refuse("unavailable prerequisite: " + str(command[0]))
    if result.returncode:
        refuse("failed prerequisite: " + str(command[0]))
    return result.stdout.strip()


def native_host(development):
    if observe(["uname", "-s"]) != "Darwin":
        refuse("requires native macOS")
    if observe(["uname", "-m"]) != "arm64":
        refuse("requires native arm64, not Intel/Rosetta")
    if observe(["sysctl", "-n", "sysctl.proc_translated"]) != "0":
        refuse("translated execution refused")
    if observe(["sysctl", "-n", "hw.optional.arm64"]) != "1":
        refuse("native arm64 hardware unavailable")
    version = observe(["sw_vers", "-productVersion"])
    if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", version):
        refuse("unsupported macOS version")
    allowed = (15, 26, 27) if development else (15, 26)
    if int(version.split(".")[0]) not in allowed:
        refuse("unsupported macOS " + version)
    return {"os": "macOS", "version": version, "architecture": "arm64",
            "translated": False}


def no_symlink_parents(path):
    # Check the spelling before resolving: resolve() alone hides unsafe parents.
    if ".." in path.parts:
        refuse("parent traversal refused: " + str(path))
    for component in reversed([path, *path.parents]):
        if component.is_symlink():
            refuse("symlink path refused: " + str(component))


def owned_parent(path):
    no_symlink_parents(path)
    if not path.is_dir():
        refuse("destination parent must already exist")
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        refuse("destination parent must be private to its owner")
    for ancestor in path.parents:
        info = ancestor.stat()
        protected_sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if (info.st_uid not in (0, os.getuid()) or
                (info.st_mode & 0o022 and not protected_sticky)):
            refuse("unsafe destination ancestor: " + str(ancestor))


SOURCE_NAMES = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "README.md",
                "LICENSE", "AGENTS.md", "crates", "doc", "docs", "examples",
                "skills", "tests", "tools", "vendor", "patches")


def excluded(name):
    name = name.lower()
    return (name.startswith((".git", ".env", "credentials")) or
            name in {"target", ".ssh", ".aws", ".azure", ".config", ".cargo",
                     ".rustup", ".gnupg", ".netrc", ".npmrc", ".pypirc"} or
            name.endswith((".pem", ".key", ".p12", ".pfx")))


def snapshot(source, destination):
    digest = hashlib.sha256()

    def copy(path, output):
        # This reviewed crate member is pinned source, not Git state or config.
        pinned_gitignore = path.relative_to(source) == Path("vendor/libsqlite3-sys/.gitignore")
        if excluded(path.name) and not pinned_gitignore:
            return
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            refuse("source symlink refused: " + str(path.relative_to(source)))
        if pinned_gitignore and not stat.S_ISREG(info.st_mode):
            refuse("vendored .gitignore must be a regular source file")
        if stat.S_ISDIR(info.st_mode):
            output.mkdir(mode=0o700)
            for child in sorted(path.iterdir()):
                copy(child, output / child.name)
        elif stat.S_ISREG(info.st_mode):
            # New files, not hard links, preserve source executable bits only.
            with path.open("rb") as original, output.open("xb") as copied:
                file_digest = hashlib.sha256()
                while True:
                    data = original.read(1024 * 1024)
                    if not data:
                        break
                    copied.write(data)
                    file_digest.update(data)
            output.chmod(0o700 if info.st_mode & 0o111 else 0o600)
            relative = str(path.relative_to(source)).encode("utf-8")
            digest.update(len(relative).to_bytes(8, "big") + relative)
            digest.update(file_digest.digest())
        else:
            refuse("source special file refused: " + str(path.relative_to(source)))

    destination.mkdir(mode=0o700)
    for name in SOURCE_NAMES:
        path = source / name
        if path.exists() or path.is_symlink():
            copy(path, destination / name)
    return digest.hexdigest()


def executable(path, label):
    try:
        canonical = path.resolve(strict=True)
        info = canonical.stat()
    except OSError:
        refuse("missing " + label)
    if not stat.S_ISREG(info.st_mode) or not os.access(canonical, os.X_OK):
        refuse("not executable: " + label)
    if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
        refuse("unsafe executable: " + label)
    description = observe(["file", "-b", str(canonical)])
    if "Mach-O" not in description or "arm64" not in description:
        refuse(label + " must be a native arm64 Mach-O executable")
    return canonical


def identity(path):
    info = path.stat()
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def run(options, command, development, host):
    destination = Path(options["--destination"])
    if destination.exists() or destination.is_symlink():
        refuse("destination already exists; retained fixtures must not be reused")
    owned_parent(destination.parent)
    source = Path(options.get("--source", sys.argv[1]))
    no_symlink_parents(source)
    if not source.is_dir():
        refuse("source must be an existing directory")
    source = source.resolve()
    # target/ is deliberately not copied, allowing evidence beneath target/.
    if destination == source or any(source / name == destination or source / name in destination.parents
                                    for name in SOURCE_NAMES):
        refuse("destination overlaps allowlisted source")
    os.umask(0o077)
    destination.mkdir(mode=0o700)  # No exist_ok: create only a known new fixture.
    evidence = destination / "evidence"
    evidence.mkdir(mode=0o700)
    mode = "DEVELOPMENT/NON-GATE" if development else "QUALIFICATION-CANDIDATE"
    metadata = {"mode": mode, "host": host, "git": None, "sdk": None,
                "command": command, "exit_code": None,
                "support_claim": False,
                "qualification_gates": {
                    "apfs_capabilities": "NOT_CHECKED", "apfs_case_variants": "NOT_CHECKED",
                    "sdk_deployment": "NOT_CHECKED", "final_artifacts": "NOT_CHECKED"}}
    print(mode + ": owned evidence retained at " + str(evidence), file=sys.stderr)
    status = 1
    try:
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C",
               "WORK_CONFIG": "", "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
               "GIT_ATTR_NOSYSTEM": "1", "RUSTUP_AUTO_INSTALL": "0",
               "CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "4"}
        for key, relative in {"HOME": "home", "XDG_CONFIG_HOME": "config",
                              "XDG_STATE_HOME": "state", "XDG_DATA_HOME": "data",
                              "XDG_CACHE_HOME": "cache", "TMPDIR": "tmp",
                              "CARGO_HOME": "cargo-home", "CARGO_TARGET_DIR": "target"}.items():
            directory = destination / relative
            directory.mkdir(mode=0o700)
            env[key] = str(directory)
        if "--sdk-root" in options:
            sdk = Path(options["--sdk-root"])
            if not sdk.is_dir():
                refuse("--sdk-root must be an existing directory")
            sdk = sdk.resolve(strict=True)
            env["SDKROOT"] = str(sdk)
            metadata["sdk"] = {"selection": options["--sdk-root"], "directory": str(sdk)}
        metadata["snapshot_sha256"] = snapshot(source, destination / "source")
        toolchain = Path(options["--toolchain-dir"]).resolve(strict=True)
        cargo = executable(toolchain / "bin/cargo", "installed toolchain cargo")
        rustc = executable(toolchain / "bin/rustc", "installed toolchain rustc")
        if cargo.parent != toolchain / "bin" or rustc.parent != toolchain / "bin":
            refuse("installed toolchain must contain actual binaries, not rustup shims")
        bindings = {cargo: identity(cargo), rustc: identity(rustc)}
        env["RUSTC"] = str(rustc)
        env["RUSTDOC"] = str(toolchain / "bin/rustdoc")
        env["PATH"] = str(toolchain / "bin") + ":" + env["PATH"]
        release = options["--toolchain"]
        cargo_version = observe([str(cargo), "--version"], env)
        rustc_version = observe([str(rustc), "-vV"], env)
        if (not cargo_version.startswith("cargo " + release + " ") or
                not rustc_version.startswith("rustc " + release + " ") or
                "release: " + release not in rustc_version.splitlines() or
                "host: aarch64-apple-darwin" not in rustc_version.splitlines()):
            refuse("installed toolchain version/native host mismatch")
        metadata["toolchain"] = {"directory": str(toolchain), "version": release,
                                 "cargo": cargo_version, "rustc": rustc_version}
        if options.get("--without-git", False):
            blocked = destination / "no-git-bin"
            blocked.mkdir(mode=0o700)
            blocker = blocked / "git"
            blocker.write_text("#!/bin/sh\necho 'DEVELOPMENT/NON-GATE: Git repository operations forbidden' >&2\nexit 1\n")
            blocker.chmod(0o700)
            env["PATH"] = str(blocked) + ":" + env["PATH"]
        else:
            git = executable(Path(options["--git"]), "Git")
            bindings[git] = identity(git)
            version = observe([str(git), "--version"], env)
            if version != "git version " + options["--git-version"]:
                refuse("exact Git fixture version mismatch")
            helper_output = observe([str(git), "--exec-path"], env)
            helpers = Path(helper_output)
            if not helpers.is_absolute() or not helpers.is_dir():
                refuse("invalid Git helper directory")
            helpers = helpers.resolve(strict=True)
            for name in ("git-upload-pack", "git-receive-pack", "git-upload-archive"):
                helper = executable(helpers / name, "Git helper " + name)
                bindings[helper] = identity(helper)
            env["GIT_EXEC_PATH"] = str(helpers)
            # Put the selected canonical Git first without replacing system Git.
            selected = destination / "git-bin"
            selected.mkdir(mode=0o700)
            (selected / "git").symlink_to(git)
            env["PATH"] = str(selected) + ":" + env["PATH"]
            metadata["git"] = {"path": str(git), "version": options["--git-version"],
                               "exec_path": str(helpers), "identity": list(identity(git))}
        for path, initial in bindings.items():
            if identity(path) != initial:
                refuse("selected prerequisite changed before command")
        with (evidence / "stdout.log").open("xb") as stdout, (evidence / "stderr.log").open("xb") as stderr:
            result = subprocess.run(command, cwd=destination / "source", env=env,
                                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
        status = result.returncode if result.returncode >= 0 else 128 - result.returncode
    except (Refusal, OSError) as error:
        metadata["error"] = str(error)
        print("refused: " + str(error), file=sys.stderr)
    except KeyboardInterrupt:
        metadata["error"] = "interrupted; retain fixture and inspect child outcome"
        status = 130
    finally:
        metadata["exit_code"] = status
        (evidence / "run.json").write_text(json.dumps(metadata, indent=2) + "\n")
        print("Evidence retained at " + str(evidence) + "; exit " + str(status), file=sys.stderr)
    return status


try:
    options, command, development = parse(sys.argv[2:])
    sys.exit(run(options, command, development, native_host(development)))
except (Refusal, OSError) as error:
    print("refused: " + str(error), file=sys.stderr)
    sys.exit(1)
PY
