#!/usr/bin/env python3
"""Verified, user-scoped work-cli downloads, activation, updates and rollback.

Requires Python 3.11+, Linux x86_64/glibc 2.36+. Never edits Work authority data.
Checksums detect corruption; HTTPS/release access remains the authenticity trust.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import uuid

REPOSITORY = "techwright-lab/work-cli"
MAX_DOWNLOAD = 64 * 1024 * 1024
MAX_UNPACKED = 128 * 1024 * 1024
RECEIPT = ".work-cli-install.json"


def version(value):
    if not isinstance(value, str):
        raise ValueError("expected a stable version string")
    value = value.removeprefix("v")
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value):
        raise ValueError("expected stable version X.Y.Z or vX.Y.Z")
    return value


def supported_host():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("supported release platform is Linux x86_64")
    libc = os.confstr("CS_GNU_LIBC_VERSION") or ""
    match = re.fullmatch(r"glibc ([0-9]+)\.([0-9]+)", libc)
    if not match or tuple(map(int, match.groups())) < (2, 36):
        raise ValueError("glibc 2.36 or newer is required")


def directory(path):
    path = Path(os.path.abspath(Path(path).expanduser()))
    for current in [*reversed(path.parents), path]:
        try:
            info = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            info = current.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("installation directories must not contain symlinks or files")
    info = path.lstat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError("installation directory must be owned and not group/world writable")
    if any(os.path.lexists(path / name) for name in ("store.sqlite", "authorities.sqlite", "initialization.json", "allocation.lock", "checkout-operations-v1")):
        raise ValueError("keep installer destinations separate from Work authority directories")
    return path


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def atomic_file(path, data, mode=0o600):
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}")
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_link(path, target):
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}")
    try:
        temporary.symlink_to(target)
        os.replace(temporary, path)
        sync_dir(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def install_lock(data):
    fd = os.open(data / ".install.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise ValueError("invalid installer lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("another installer is active") from error
        yield
    finally:
        os.close(fd)


class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        allowed_url(url)
        return super().redirect_request(request, fp, code, message, headers, url)


def allowed_url(url):
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError("release transport requires HTTPS")
    if host not in ("github.com", "api.github.com") and not host.endswith(".githubusercontent.com"):
        raise ValueError("unexpected release download host")


def fetch(url, destination, maximum=MAX_DOWNLOAD):
    allowed_url(url)
    # Ignore host proxies/credentials; download only public approved release assets.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), HTTPSOnly())
    request = urllib.request.Request(url, headers={"User-Agent": "work-cli-installer"})
    with opener.open(request, timeout=30) as response, destination.open("xb") as stream:
        allowed_url(response.url)
        total = 0
        while block := response.read(65536):
            total += len(block)
            if total > maximum:
                raise ValueError("release download exceeds limit")
            stream.write(block)


def latest_version():
    # GitHub's public latest-release redirect avoids the anonymous REST API
    # quota. Trust only this repository's canonical stable release-tag URL.
    url = f"https://github.com/{REPOSITORY}/releases/latest"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), HTTPSOnly())
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "work-cli-installer"})
    with opener.open(request, timeout=30) as response:
        allowed_url(response.url)
        prefix = f"https://github.com/{REPOSITORY}/releases/tag/v"
        if not response.url.startswith(prefix):
            raise ValueError("unexpected latest-release redirect; select an explicit version")
        return version(response.url[len(prefix):])


def release_files(release, output):
    name = f"work-cli-{release}-linux-x86_64.tar.gz"
    archive, checksum = output / name, output / f"{name}.sha256"
    if os.path.lexists(archive) or os.path.lexists(checksum):
        raise ValueError("download destination already contains release files")
    try:
        base = f"https://github.com/{REPOSITORY}/releases/download/v{release}"
        fetch(f"{base}/{name}", archive)
        fetch(f"{base}/{name}.sha256", checksum, 4096)
        verify_archive(archive, checksum, release)
    except Exception:
        archive.unlink(missing_ok=True)
        checksum.unlink(missing_ok=True)
        raise
    return archive, checksum


def verify_archive(archive, checksum, release):
    name = f"work-cli-{release}-linux-x86_64.tar.gz"
    if archive.is_symlink() or checksum.is_symlink() or archive.stat().st_size > MAX_DOWNLOAD or checksum.stat().st_size > 4096:
        raise ValueError("invalid release files")
    match = re.fullmatch(r"([a-f0-9]{64}) [ *]" + re.escape(name) + r"\n?", checksum.read_text())
    if not match or digest(archive) != match.group(1):
        raise ValueError("release checksum mismatch")
    return match.group(1)


def extract(archive, destination, release):
    prefix = f"work-cli-{release}-linux-x86_64"
    seen, total = set(), 0
    with tarfile.open(archive, "r:gz") as bundle:
        for count, member in enumerate(bundle, 1):
            name = member.name.rstrip("/")
            path = PurePosixPath(name)
            if count > 256 or path.is_absolute() or ".." in path.parts or path.as_posix() != name or not path.parts or path.parts[0] != prefix or name in seen:
                raise ValueError("unsafe or duplicate archive member")
            seen.add(name)
            if not member.isdir() and not member.isfile():
                raise ValueError("archive links and special files are refused")
            relative = Path(*path.parts[1:])
            if str(relative) == ".":
                if not member.isdir():
                    raise ValueError("invalid archive root")
                continue
            if relative.name == RECEIPT:
                raise ValueError("archive contains reserved install metadata")
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            total += member.size
            if member.size < 0 or total > MAX_UNPACKED:
                raise ValueError("unpacked release exceeds limit")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with bundle.extractfile(member) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, 65536)
                output.flush()
                os.fsync(output.fileno())
            target.chmod(0o755 if str(relative) in ("bin/work", "tools/work_install.py") else 0o644)
    for required in ("bin/work", "README.md", "LICENSE", "examples/work.toml"):
        if not (destination / required).is_file():
            raise ValueError("release is missing a required file")


def verify_binary(root, release):
    process = subprocess.run([str(root / "bin/work"), "--version"], cwd="/", env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C"}, capture_output=True, text=True, timeout=5)
    if process.returncode or process.stdout != f"work {release}\n":
        raise ValueError("binary version does not match release")


def files(root):
    result = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("installed release contains a symlink")
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode) and not stat.S_ISDIR(mode):
            raise ValueError("installed release contains a special file")
        if stat.S_ISREG(mode) and path != root / RECEIPT:
            result[path.relative_to(root).as_posix()] = digest(path)
    return result


def cached_release(root, release):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("invalid cached release")
    receipt = root / RECEIPT
    if receipt.is_symlink() or receipt.stat().st_size > 128 * 1024:
        raise ValueError("invalid install receipt")
    record = json.loads(receipt.read_text())
    if record.get("version") != release or record.get("files") != files(root):
        raise ValueError("cached release changed; refusing activation")
    verify_binary(root, release)
    return record


def managed_link(path, expected):
    if os.path.lexists(path) and (not path.is_symlink() or os.readlink(path) != str(expected)):
        raise ValueError("refusing to replace an unmanaged binary or skill target")


def skill_links(data, targets):
    current = data / "skill-current"
    if os.path.lexists(current) and (not current.is_symlink() or not re.fullmatch(r"skill-snapshots/[a-f0-9]{64}/skills/work-cli", os.readlink(current))):
        raise ValueError("unmanaged active skill snapshot")
    links = [(directory(target) / "work-cli", current) for target in targets]
    for path, target in links:
        managed_link(path, target)
    return links


def snapshot_skill(data, source):
    source = Path(source)
    skill = source / "skills/work-cli"
    if skill.is_symlink() or (source / "skills").is_symlink() or (source / "docs").is_symlink() or not (skill / "SKILL.md").is_file():
        raise ValueError("reviewed source does not contain the work-cli skill")
    paths = list(skill.rglob("*")) + [source / "docs/distribution.md"]
    contents = {}
    for path in paths:
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1024 * 1024:
            raise ValueError("skill snapshot requires bounded regular files")
        if len(contents) >= 32:
            raise ValueError("skill snapshot exceeds file limit")
        contents[path.relative_to(source).as_posix()] = path.read_bytes()
    if sum(map(len, contents.values())) > 4 * 1024 * 1024:
        raise ValueError("skill snapshot exceeds size limit")
    hashes = {name: hashlib.sha256(body).hexdigest() for name, body in contents.items()}
    identity = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    snapshots = directory(data / "skill-snapshots")
    target = snapshots / identity
    if os.path.lexists(target):
        if target.is_symlink() or files(target) != hashes:
            raise ValueError("cached skill snapshot changed")
    else:
        with tempfile.TemporaryDirectory(prefix=".skill-", dir=snapshots) as scratch:
            stage = Path(scratch) / "snapshot"
            stage.mkdir(mode=0o700)
            for name, body in contents.items():
                path = stage / name
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                atomic_file(path, body, 0o644)
            for child in sorted((p for p in stage.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
                sync_dir(child)
            sync_dir(stage)
            os.rename(stage, target)
            sync_dir(snapshots)
    return f"skill-snapshots/{identity}/skills/work-cli"


def activate_skill(data, snapshot, links):
    atomic_link(data / "skill-current", snapshot)
    for path, target in links:
        if not os.path.lexists(path):
            atomic_link(path, target)


def activate(data, bin_dir, skills_dirs, release, confirmed):
    root = data / "releases" / f"v{release}"
    cached_release(root, release)
    current = data / "current"
    if os.path.lexists(current):
        if not current.is_symlink() or not re.fullmatch(r"releases/v[0-9]+\.[0-9]+\.[0-9]+", os.readlink(current)):
            raise ValueError("unmanaged current installation")
        if os.readlink(current) != f"releases/v{release}" and not confirmed:
            raise ValueError("stop Work operations and pass --confirm-stopped before changing versions")
    links = [(bin_dir / "work", current / "bin/work")]
    if (root / "tools/work_install.py").is_file():
        # Keep a verified updater independent of the runtime pointer so rollback
        # to a historical release without an updater does not break updates.
        links.append((bin_dir / "work-install", data / "updater.py"))
    registered = skill_links(data, skills_dirs)
    has_skill = (root / "skills/work-cli/SKILL.md").is_file()
    if skills_dirs and not has_skill:
        raise ValueError("selected release does not contain the agent skill")
    for path, target in links:
        managed_link(path, target)
    snapshot = snapshot_skill(data, root) if has_skill and (registered or os.path.lexists(data / "skill-current")) else None
    if (root / "tools/work_install.py").is_file():
        atomic_file(data / "updater.py", (root / "tools/work_install.py").read_bytes(), 0o755)
    for path, target in links:
        if not os.path.lexists(path):
            atomic_link(path, target)
    atomic_link(current, f"releases/v{release}")
    if snapshot:
        activate_skill(data, snapshot, registered)
    return {"version": release, "binary": str(bin_dir / "work"), "previous_versions_retained": True, "authority_modified": False}


def install(args):
    data, bin_dir = directory(args.data_dir), directory(args.bin_dir)
    with install_lock(data):
        release = latest_version() if args.version == "latest" and args.command != "rollback" else version(args.version)
        releases = directory(data / "releases")
        target = releases / f"v{release}"
        if args.command == "rollback":
            return activate(data, bin_dir, args.skills_dir, release, args.confirm_stopped)
        with tempfile.TemporaryDirectory(prefix=".stage-", dir=releases) as scratch:
            stage = Path(scratch)
            if args.archive:
                if args.version == "latest" or not args.checksum:
                    raise ValueError("offline installation requires an explicit version and checksum")
                archive, checksum = Path(args.archive), Path(args.checksum)
            else:
                if args.checksum:
                    raise ValueError("--checksum requires --archive")
                archive, checksum = release_files(release, stage)
            archive_hash = verify_archive(archive, checksum, release)
            unpacked = stage / "unpacked"
            unpacked.mkdir(mode=0o700)
            extract(archive, unpacked, release)
            verify_binary(unpacked, release)
            record = {"version": release, "archive_sha256": archive_hash, "files": files(unpacked)}
            atomic_file(unpacked / RECEIPT, (json.dumps(record, sort_keys=True) + "\n").encode())
            if os.path.lexists(target):
                if cached_release(target, release)["archive_sha256"] != archive_hash:
                    raise ValueError("cached version has a different archive digest")
            else:
                for child in sorted((p for p in unpacked.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
                    sync_dir(child)
                sync_dir(unpacked)
                os.rename(unpacked, target)
                sync_dir(releases)
        return activate(data, bin_dir, args.skills_dir, release, args.confirm_stopped)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    download = commands.add_parser("download", help="download and checksum-verify without installing")
    download.add_argument("--version", default="latest")
    download.add_argument("--output-dir", required=True)
    skill = commands.add_parser("skill", help="register a snapshot of explicitly reviewed local agent instructions")
    skill.add_argument("--source-root", required=True, type=Path)
    skill.add_argument("--data-dir")
    skill.add_argument("--skills-dir", action="append", required=True)
    for name in ("install", "update", "rollback"):
        p = commands.add_parser(name)
        p.add_argument("--version", default=None if name == "rollback" else "latest", required=name == "rollback")
        p.add_argument("--data-dir")
        p.add_argument("--bin-dir")
        p.add_argument("--skills-dir", action="append", default=[], help="explicit agent skill discovery directory; repeat for multiple agents")
        p.add_argument("--confirm-stopped", action="store_true", help="assert all Work operations stopped before changing the active binary")
        if name != "rollback":
            p.add_argument("--archive")
            p.add_argument("--checksum")
    args = parser.parse_args(argv)
    try:
        supported_host()
        # Resolve defaults only for the selected command and missing arguments.
        # Explicit offline paths work for container UIDs without HOME/passwd.
        if hasattr(args, "data_dir") and args.data_dir is None:
            xdg = os.environ.get("XDG_DATA_HOME")
            args.data_dir = str((Path(xdg) if xdg else Path.home() / ".local/share") / "work-cli")
        if hasattr(args, "bin_dir") and args.bin_dir is None:
            args.bin_dir = str(Path.home() / ".local/bin")
        if args.command == "download":
            release = latest_version() if args.version == "latest" else version(args.version)
            archive, checksum = release_files(release, directory(args.output_dir))
            result = {"version": release, "archive": str(archive), "checksum": str(checksum), "installed": False}
        elif args.command == "skill":
            data = directory(args.data_dir)
            with install_lock(data):
                links = skill_links(data, args.skills_dir)
                snapshot = snapshot_skill(data, args.source_root)
                activate_skill(data, snapshot, links)
            result = {"skill": "work-cli", "snapshot": snapshot, "registered": args.skills_dir, "binary_changed": False, "authority_modified": False}
        else:
            result = install(args)
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, EOFError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"work installer stopped: {error}; check the active version and skill pointers before retrying", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
