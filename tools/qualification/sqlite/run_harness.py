"""Compile exact extracted SQLite functions against bounded syscall stubs.

This is control-flow evidence, NOT a Darwin whole-amalgamation or Work-linked test.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

from verify import verify_tree

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def function(source, signature):
    start = source.index(signature)
    # SQLite function terminators are at column zero; avoid parsing C comments.
    end = source.index("\n}", start) + 2
    return source[start:end]


def run(mode):
    verify_tree(ROOT / "vendor/libsqlite3-sys")
    source = (ROOT / "vendor/libsqlite3-sys/sqlite3/sqlite3.c").read_text()
    signatures = ["static int full_fsync(", "static int unixSync(", "static int unixDelete("]
    if "static int unixSyncDirectory(" in source:
        signatures.insert(1, "static int unixSyncDirectory(")
    code = (HERE / "ack_harness.c").read_text()
    code = code.replace("/* EXACT_SOURCE */", "\n\n".join(function(source, s) for s in signatures))
    sidecar = (HERE / "sidecar_harness.c").read_text()
    index_signature = ("static int walIndexClose(" if "static int walIndexClose(" in source
                       else "static void walIndexClose(")
    sidecar_source = function(source, "static int unixOpenSharedMemory(") + "\n"
    sidecar_source += function(source, "static int unixShmUnmap(") + "\n"
    sidecar_source += ("static int sqlite3OsShmUnmap(sqlite3_file *f, int d){"
                       "return unixShmUnmap(f,d);}\n")
    sidecar_source += function(source, index_signature) + "\n"
    sidecar_source += function(source, "SQLITE_PRIVATE int sqlite3WalClose(\n")
    sidecar = sidecar.replace("/* SIDECAR_SOURCE */", sidecar_source)
    code = code.replace("/* SIDECAR_HARNESS */", sidecar)
    start = source.index("  int isNewJrnl = (isCreate && (")
    end = source.index("  ));", start) + len("  ));")
    classifier = "static int creation_flags(int isCreate, int eType){\n" + source[start:end]
    classifier += "\n int ctrlFlags=0;\n"
    assignment = "  if( isNewJrnl )               ctrlFlags |= UNIXFILE_DIRSYNC;"
    assert assignment in source
    classifier += assignment + "\n return ctrlFlags;\n}\n"
    constants = []
    for name in ["SUPER_JOURNAL", "MAIN_JOURNAL", "WAL", "MAIN_DB"]:
        key = "#define SQLITE_OPEN_" + name
        start = source.index(key + " ")
        constants.append(source[start:source.index("\n", start)])
    code = code.replace("/* CREATION_CLASSIFIER */", "\n".join(constants) + "\n" + classifier)
    with tempfile.TemporaryDirectory(prefix="work-sqlite-source-") as temp:
        c = Path(temp) / "harness.c"
        exe = Path(temp) / "harness"
        c.write_text(code)
        command = ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
                   "-Wno-unused-function", str(c), "-o", str(exe)]
        if mode == "darwin":
            command.insert(1, "-D__APPLE__=1")
        variants = [1] if mode == "darwin" else [0, 1]
        for fullsync in variants:
            subprocess.run(command + [f"-DHAVE_FULLFSYNC={fullsync}"], check=True, timeout=60)
            subprocess.run([str(exe)], check=True, timeout=10)
    print(f"{mode}: exact-source extracted control-flow harness passed (not native VFS)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["darwin", "linux"], required=True)
    run(parser.parse_args().mode)
