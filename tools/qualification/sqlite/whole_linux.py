"""Compile/run the complete pinned amalgamation on Linux, NOT Work's linked build."""
from pathlib import Path
import subprocess
import sys
import tempfile

from verify import ROOT, verify_tree


def run():
    if sys.platform != "linux":
        raise SystemExit("whole_linux.py requires the disposable Linux fixture")
    vendor = ROOT / "vendor/libsqlite3-sys/sqlite3"
    verify_tree(vendor.parent)
    with tempfile.TemporaryDirectory(prefix="work-sqlite-whole-") as temp:
        temp = Path(temp)
        exe = temp / "whole-linux"
        subprocess.run(["cc", "-std=c99", "-D_GNU_SOURCE", "-DSQLITE_THREADSAFE=1",
                        "-I", str(vendor), str(vendor / "sqlite3.c"),
                        str(Path(__file__).with_name("whole_linux.c")),
                        "-lpthread", "-ldl", "-lm", "-o", str(exe)],
                       check=True, timeout=90)
        subprocess.run([str(exe), str(temp / "owned.db")], check=True, timeout=15)
    print("Linux whole-amalgamation compile/SQL smoke passed; NOT Work-linked/native Darwin")


if __name__ == "__main__":
    run()
