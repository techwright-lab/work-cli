#!/usr/bin/env python3
"""Validate workspace/lockfile/tag identity; print the canonical stable version."""
import argparse
import os
from pathlib import Path
import re
import sys
import tomllib


def release_version(root, tag=None):
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    version = manifest["workspace"]["package"]["version"]
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("workspace version must be stable X.Y.Z")
    packages = tomllib.loads((root / "Cargo.lock").read_text())["package"]
    for name in ("work-cli", "work-contract"):
        entries = [p["version"] for p in packages if p["name"] == name]
        if entries != [version]:
            raise ValueError("local lockfile package version disagrees with workspace")
    if tag and tag != f"v{version}":
        raise ValueError("release tag disagrees with workspace version")
    return version


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--tag")
    args = parser.parse_args()
    ref = os.environ.get("GITHUB_REF", "")
    tag = args.tag if args.tag is not None else ref.removeprefix("refs/tags/") if ref.startswith("refs/tags/") else None
    try:
        print(release_version(args.root, tag))
        return 0
    except (OSError, ValueError, KeyError) as error:
        print(f"release identity refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
