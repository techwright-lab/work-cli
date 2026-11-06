#!/usr/bin/env python3
"""THROWAWAY: one finite synthetic matrix; writes ONLY below supplied NEW directory.
No cleanup. Requires macOS and an existing clang; never installs toolchains.
"""
import hashlib
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: python3 run.py NEW_FIXTURE_DIRECTORY")
    fixture = Path(sys.argv[1])
    fixture.mkdir(mode=0o700)  # no adoption, replacement or deletion of existing fixtures
    fixture = fixture.resolve()
    source = Path(__file__).with_name("hardlink-protocol.c").resolve()
    binary = fixture / "hardlink-protocol"
    print("THROWAWAY synthetic hardlink protocol matrix", flush=True)
    print("OS", platform.system(), platform.mac_ver()[0], platform.machine(), flush=True)
    print("source_sha256", hashlib.sha256(source.read_bytes()).hexdigest(), flush=True)
    build = ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wconversion", "-Wshadow", str(source), "-o", str(binary)]
    subprocess.run(build, check=True, timeout=30)
    print("strict_compile=PASS", flush=True)

    def invoke(command, expected=0):
        print("COMMAND", command, flush=True)
        p = subprocess.run([str(binary), command, str(fixture)], text=True, capture_output=True, timeout=15)
        print(p.stdout, end="", flush=True)
        if p.stderr:
            print(p.stderr, end="", file=sys.stderr)
        assert p.returncode == expected, (command, p.returncode, expected)
        print("exit_status", p.returncode, flush=True)
        return p.stdout

    output = invoke("run")
    cases = re.split(r"\nCASE ", output)[1:]
    assert len(cases) == 20
    expected_holds = 0
    for case in cases:
        name = case.splitlines()[0]
        m = re.search(r"outcome=(\w+) data_open_calls=(\d+) data_bytes=(\d+) capture_charge=(\d+)", case)
        assert m, name
        actual = (m[1], int(m[2]), int(m[3]), int(m[4]))
        expected = {"clean": ("COMPLETE", 1, 8, 0), "open-gap-counterexample": ("HOLD", 1, 0, 1), "read-gap-counterexample": ("HOLD", 1, 8, 1)}.get(name, ("HOLD", 0, 0, 1))
        assert actual == expected, (name, actual, expected)
        expected_holds += actual[0] == "HOLD"
    assert expected_holds == 19
    assert not (fixture / "clean/stage/payload").exists()
    assert (fixture / "clean/source/payload").stat().st_nlink == 1
    assert "phase=COMPLETE charge=0" in (fixture / "clean/manifest").read_text()
    foreign = fixture / "link-replaced/stage/payload"
    assert foreign.stat().st_nlink == 2  # plausible count, WRONG identity, still refused
    assert stat.S_ISFIFO((fixture / "fifo-substitution/stage/payload").lstat().st_mode)
    assert stat.S_ISLNK((fixture / "symlink-substitution/stage/payload").lstat().st_mode)
    assert not (fixture / "directory-substitution/stage/payload").exists()

    def snapshot():
        result = {}
        for root, dirs, files in os.walk(fixture, followlinks=False):
            for name in dirs + files:
                path = Path(root) / name
                s = path.lstat()
                result[str(path.relative_to(fixture))] = (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        return result

    def reinspection(command, consistent):
        before = snapshot()
        out = invoke(command)
        assert snapshot() == before, "reinspection changed retained fixture evidence"
        assert "outcome=HOLD data_open_calls=0 data_bytes=0 unlinks=0 capture_charge=1" in out
        if consistent is not None:
            assert f"identity_consistent={int(consistent)}" in out
        return out

    invoke("crash-linked", 70)
    reinspection("reinspect-linked", True)
    print("MANIFEST sample=linked-leftover", flush=True)
    print((fixture / "crash-linked/manifest").read_text(), end="", flush=True)
    invoke("replace-leftover-link")
    assert (fixture / "crash-linked/stage/payload").stat().st_nlink == 2
    reinspection("reinspect-linked", False)
    invoke("replace-leftover-stage")
    reinspection("reinspect-linked", False)
    invoke("crash-intent", 70)
    reinspection("reinspect-intent", False)
    print("MANIFEST sample=unreceipted-link", flush=True)
    print((fixture / "crash-intent/manifest").read_text(), end="", flush=True)
    invoke("crash-untracked", 70)
    reinspection("reinspect-untracked", None)
    print("ASSERTIONS PASS: 20 active cases; 3 controlled process exits; 5 nonmutating reinspections; no cleanup outside one proven active link", flush=True)
    print("Collector totals: 3 data open calls, 16 data bytes; mutation-actor/manifest/directory IO excluded", flush=True)
    print("All fixtures/binary retained locally; fixture path deliberately omitted", flush=True)


if __name__ == "__main__":
    main()
