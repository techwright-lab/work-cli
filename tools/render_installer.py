#!/usr/bin/env python3
"""Render the release-bound I1 installer candidate (not publishable yet)."""
import argparse
import os
from pathlib import Path
import re
import shlex
import sys


STABLE_VERSION = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"


def render(version, developer_id, output):
    if not re.fullmatch(STABLE_VERSION, version):
        raise ValueError("version must be canonical stable X.Y.Z")
    if (any(ord(char) < 32 or ord(char) == 127 for char in developer_id)
            or not re.fullmatch(r"Developer ID Application: \S[^\r\n]* \([A-Z0-9]{10}\)", developer_id)):
        raise ValueError("explicit Developer ID Application identity with team ID required")
    template = Path(__file__).with_name("install.sh.in").read_text(encoding="utf-8")
    rendered = template.replace("@RELEASE_VERSION@", shlex.quote(version)).replace(
        "@DEVELOPER_ID@", shlex.quote(developer_id))
    # Exclusive creation refuses regular files, directories and dangling symlinks.
    # Never create parents or replace an existing output, including a prior render.
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(rendered)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--developer-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        render(args.version, args.developer_id, args.output)
    except (OSError, ValueError) as error:
        print(f"installer render refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
