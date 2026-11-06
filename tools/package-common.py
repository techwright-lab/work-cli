#!/usr/bin/env python3
"""Package supplied final bytes (Python 3.11+ development tool only).

Never build, sign, notarize or execute the supplied bytes. Python is not an
end-user runtime requirement. This primitive does not validate native architecture
or version output, supply release install.sh assets, or qualify a release. Native
verification, signing/notarization and the complete release asset set remain
separate gates; packaging inert bytes is not Mach-O or native-platform evidence.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile


MATERIALS = (
    "LICENSE",
    "README.md",
    "AGENTS.md",
    "examples/work.toml",
    "tools/work_install.py",
    "docs/distribution.md",
    "skills/work-cli/SKILL.md",
    "skills/work-cli/reference/setup.md",
)
PLATFORMS = ("linux-x86_64", "macos-arm64")


def validate_route(path: Path) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"path must be absolute without parent traversal: {path}")
    for parent in reversed(path.parents):
        if not stat.S_ISDIR(parent.lstat().st_mode):
            raise ValueError(f"path ancestor must be a real directory, not a symlink: {parent}")


def checked_input(path: Path, *, directory: bool = False) -> os.stat_result:
    validate_route(path)
    metadata = path.lstat()
    if directory:
        valid = stat.S_ISDIR(metadata.st_mode)
    else:
        valid = stat.S_ISREG(metadata.st_mode) and metadata.st_size > 0
    if not valid:
        raise ValueError(f"expected {'directory' if directory else 'nonempty regular file'}: {path}")
    return metadata


def checksum(artifact: Path) -> None:
    with artifact.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    with artifact.with_name(artifact.name + ".sha256").open("xb") as sidecar:
        sidecar.write(f"{digest}  {artifact.name}\n".encode("ascii"))


def package(version: str, platform: str, executable: Path,
            source_root: Path, output_dir: Path) -> None:
    """Create four artifacts in a new, exclusively owned private directory.

    All paths must be absolute with real, non-symlink directory ancestors; the
    output parent must already exist. Inputs must remain stable during packaging.
    Preflight failures create nothing. Any existing output path is refused, even
    an empty directory or a complete-looking prior result. After exclusive mkdir,
    failures retain the directory and any partial artifacts for inspection, never
    clean up or overwrite entries. Retry requires a different absent output path.
    Exit success, not the mere existence of this directory, signals completion.
    This is cooperative packaging, not hostile same-UID or crash-durability proof.
    """
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("version must be canonical stable X.Y.Z (no v prefix)")
    if platform not in PLATFORMS:
        raise ValueError(f"unsupported platform: {platform}")
    name = f"work-cli-{version}-{platform}"
    if len(f"{name}.tar.gz.sha256") > 255:
        raise ValueError("artifact name exceeds portable filename length")
    checked_input(executable)
    checked_input(source_root, directory=True)
    for relative in MATERIALS:
        checked_input(source_root / relative)
    validate_route(output_dir)
    output_dir.mkdir(mode=0o700)
    binary = output_dir / f"work-{version}-{platform}"
    with executable.open("rb") as source, binary.open("xb") as target:
        shutil.copyfileobj(source, target)
    binary.chmod(0o755)
    archive = output_dir / f"{name}.tar.gz"
    with tarfile.open(archive, "x:gz") as bundle:
        entries = [(binary, "bin/work")]
        entries.extend((source_root / relative, relative) for relative in MATERIALS)
        for path, relative in entries:
            member = tarfile.TarInfo(f"{name}/{relative}")
            member.size = path.stat().st_size
            member.mode = 0o755 if relative in ("bin/work", "tools/work_install.py") else 0o644
            with path.open("rb") as source:
                bundle.addfile(member, source)
    checksum(binary)
    checksum(archive)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="canonical stable X.Y.Z, without v prefix")
    parser.add_argument("--platform", choices=PLATFORMS, required=True)
    parser.add_argument("--executable", type=Path, required=True, help="absolute path to final bytes")
    parser.add_argument("--source-root", type=Path, required=True, help="absolute path to bundle materials")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="absent absolute path with existing parent; failures retain partial output")
    args = parser.parse_args()
    try:
        package(args.version, args.platform, args.executable, args.source_root, args.output_dir)
        return 0
    except (OSError, ValueError, tarfile.TarError) as error:
        print(f"packaging refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
