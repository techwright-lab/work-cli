"""Offline, fail-closed import and verification; never downloads source."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile

ROOT = Path(__file__).resolve().parents[3]
PATCHES = ROOT / "patches/sqlite"
CRATE_SHA256 = "95b4103cffefa72eb8428cb6b47d6627161e51c2739fc5e3b734584157bc642a"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def manifest():
    pin = json.loads((PATCHES / "provenance.json").read_text())
    expected = {
        "crate": "libsqlite3-sys",
        "version": "0.36.0",
        "sqlite_version": "3.51.1",
        "url": "https://static.crates.io/crates/libsqlite3-sys/libsqlite3-sys-0.36.0.crate",
        "crate_sha256": CRATE_SHA256,
    }
    if any(pin.get(key) != value for key, value in expected.items()):
        raise ValueError("provenance metadata mismatch")
    return pin


def extract_crate(archive, destination):
    """Validate digest BEFORE parsing; validate ALL named members BEFORE writes."""
    archive = Path(archive)
    data = archive.read_bytes()
    if digest(data) != CRATE_SHA256:
        raise ValueError("crate checksum mismatch")
    import io
    expected = manifest()["upstream_files"]
    prefix = "libsqlite3-sys-0.36.0/"
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        members = tar.getmembers()
        if (len(members) != len(expected)
                or {m.name for m in members} != {prefix + p for p in expected}
                or any(not m.isfile() for m in members)):
            raise ValueError("unexpected crate members")
        files = {}
        for m in members:
            name = m.name.removeprefix(prefix)
            if Path(name).is_absolute() or any(p in ("", ".", "..") for p in name.split("/")):
                raise ValueError("unsafe crate member")
            content = tar.extractfile(m).read()
            if digest(content) != expected[name]:
                raise ValueError(f"upstream digest mismatch: {name}")
            files[name] = content
    destination = Path(destination)
    # A fresh destination rules out symlinks/overwriting an existing checkout.
    destination.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def apply_patch(source, patch, reverse=False, target="sqlite3/sqlite3.c"):
    """Apply exact line-numbered unified hunks. No fuzz, offsets, or shell patch."""
    lines = source.splitlines(keepends=True)
    diff = patch.splitlines(keepends=True)
    if diff[:2] != [f"--- a/{target}\n", f"+++ b/{target}\n"]:
        raise ValueError("unexpected patch target")
    output, cursor, i = [], 0, 2
    while i < len(diff):
        match = re.fullmatch(r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@\n", diff[i])
        if not match:
            raise ValueError("invalid patch hunk")
        old_start, old_count, new_start, new_count = map(int, match.groups())
        i += 1
        before, after = [], []
        while i < len(diff) and not diff[i].startswith("@@ "):
            line = diff[i]
            if line[0] in " -":
                before.append(line[1:])
            if line[0] in " +":
                after.append(line[1:])
            if line[0] not in " +-":
                raise ValueError("invalid patch line")
            i += 1
        if len(before) != old_count or len(after) != new_count:
            raise ValueError("patch hunk length mismatch")
        start = (new_start if reverse else old_start) - 1
        if reverse:
            before, after = after, before
        if start < cursor or lines[start:start + len(before)] != before:
            raise ValueError("patch context mismatch")
        output.extend(lines[cursor:start])
        output.extend(after)
        cursor = start + len(before)
    output.extend(lines[cursor:])
    return "".join(output)


def verify_tree(tree):
    tree = Path(tree)
    pin = manifest()
    patch = (PATCHES / "darwin-required-ack.patch").read_bytes()
    if digest(patch) != pin["patch_sha256"]:
        raise ValueError("patch digest mismatch")
    expected = pin["vendored_files"]
    # Cargo may create target/ and Cargo.lock in standalone validation. They are
    # not source inputs; all pinned inputs (including crate Cargo.lock) are checked.
    for name, sha in expected.items():
        path = tree / name
        if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != sha:
            raise ValueError(f"vendored digest mismatch: {name}")
    source = (tree / "sqlite3/sqlite3.c").read_text()
    original = apply_patch(source, patch.decode(), reverse=True)
    if digest(original.encode()) != pin["upstream_files"]["sqlite3/sqlite3.c"]:
        raise ValueError("reverse patch source digest mismatch")
    glue = (PATCHES / "vendor-glue.patch").read_text()
    if digest(glue.encode()) != pin["glue_patch_sha256"]:
        raise ValueError("glue patch digest mismatch")
    sections = re.split(r"(?=^--- a/)", glue, flags=re.MULTILINE)[1:]
    targets = [section.splitlines()[0].removeprefix("--- a/") for section in sections]
    if targets != ["Cargo.toml", "Cargo.toml.orig", "build.rs"]:
        raise ValueError("unexpected glue patch targets")
    for name, section in zip(targets, sections):
        original = apply_patch((tree / name).read_text(), section, reverse=True, target=name)
        if digest(original.encode()) != pin["upstream_files"][name]:
            raise ValueError(f"reverse glue patch digest mismatch: {name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extract-crate", type=Path)
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    if args.extract_crate:
        if not args.destination:
            parser.error("--destination required for extraction")
        extract_crate(args.extract_crate, args.destination)
    else:
        verify_tree(ROOT / "vendor/libsqlite3-sys")
        print("exact crate inventory, patched source, and patch SHA256 verified")
