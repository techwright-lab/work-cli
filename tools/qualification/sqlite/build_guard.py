"""Offline real vendored Cargo smoke and bounded build.rs guard executions.

Run only in the prescribed Linux container or reviewed H2 native source snapshot.
The caller supplies an approved registry-only seed and installed cargo/rustc. No
network, installation, root workspace resolution, or Work store operations occur.
All destinations must be new; source, mutations, binaries and logs are retained.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

import verify

ROOT = Path(__file__).resolve().parents[3]
MANDATORY = ("sqlite3.c", "sqlite3.h", "sqlite3ext.h",
             "bindgen_bundled_version.rs", "bindgen_bundled_version_ext.rs")
ALTERNATE_ERROR = ("Work requires exact patched bundled SQLite; "
                   "system/alternate SQLite is not permitted")
SMOKE = r'''
use libsqlite3_sys as sql;
use std::ffi::{CStr, CString};
fn main() {
    unsafe {
        assert_eq!(CStr::from_ptr(sql::sqlite3_libversion()).to_str().unwrap(), "3.51.1");
        let mut db = std::ptr::null_mut();
        assert_eq!(sql::sqlite3_open(c":memory:".as_ptr(), &mut db), sql::SQLITE_OK);
        let query = CString::new("CREATE TABLE s(x); INSERT INTO s VALUES(40),(2);").unwrap();
        assert_eq!(sql::sqlite3_exec(db, query.as_ptr(), None, std::ptr::null_mut(),
                                  std::ptr::null_mut()), sql::SQLITE_OK);
        let mut stmt = std::ptr::null_mut();
        assert_eq!(sql::sqlite3_prepare_v2(db, c"SELECT sum(x) FROM s".as_ptr(), -1,
                                         &mut stmt, std::ptr::null_mut()), sql::SQLITE_OK);
        assert_eq!(sql::sqlite3_step(stmt), sql::SQLITE_ROW);
        assert_eq!(sql::sqlite3_column_int(stmt, 0), 42);
        assert_eq!(sql::sqlite3_finalize(stmt), sql::SQLITE_OK);
        assert_eq!(sql::sqlite3_close(db), sql::SQLITE_OK);
    }
    println!("bundled SQLite 3.51.1 SQL sum=42");
}
'''


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def lock_packages(path):
    return tomllib.loads(Path(path).read_text())["package"]


def validate_lock(lock, original):
    """Allow pruning the root lock, never selecting a new registry version."""
    approved = {(p["name"], p["version"], p.get("source")): p.get("checksum")
                for p in lock_packages(original) if "source" in p}
    for package in lock_packages(lock):
        if "source" in package:
            key = (package["name"], package["version"], package["source"])
            require(key in approved and approved[key] == package.get("checksum"),
                    "dependency outside approved root lock: " + repr(key))


def copy_tree(source, destination):
    # Approved source/cache only. Never follow symlinks or copy repository refs.
    require(source.is_dir() and not source.is_symlink(), "not a regular source directory")
    for path in source.rglob("*"):
        require(not path.is_symlink(), "source/cache symlink refused: " + str(path))
        require(path.name != ".git", "repository metadata refused: " + str(path))
        require(path.is_file() or path.is_dir(), "source/cache special file refused")
    shutil.copytree(source, destination)


class Fixture:
    def __init__(self, destination, registry, cargo, rustc):
        require(destination.is_absolute(), "destination must be absolute")
        require(not destination.exists() and not destination.is_symlink(),
                "destination already exists")
        require(".." not in destination.parts and
                not any(p.is_symlink() for p in destination.parents),
                "destination symlink/traversal refused")
        self.destination = destination
        destination.mkdir(mode=0o700)
        self.evidence = destination / "evidence"
        self.evidence.mkdir()
        self.report = {"status": "failed", "scope": "real Cargo bundled SQL smoke; bounded real build.rs executions",
                       "cargo_dependency": "libsqlite3-sys 0.36.0 (path copy)",
                       "work_vfs_faults_tested": False, "cases": []}
        for tool in (cargo, rustc):
            require(tool.is_absolute() and tool.is_file() and os.access(tool, os.X_OK),
                    "explicit installed toolchain executable required")
            rustup = tool.with_name("rustup")
            require(not rustup.exists() or not tool.samefile(rustup), "rustup shims refused")
        self.cargo, self.rustc = str(cargo), str(rustc)
        self.original = {ROOT / "Cargo.toml": sha(ROOT / "Cargo.toml"),
                         ROOT / "Cargo.lock": sha(ROOT / "Cargo.lock")}
        for name in verify.manifest()["vendored_files"]:
            self.original[ROOT / "vendor/libsqlite3-sys" / name] = sha(ROOT / "vendor/libsqlite3-sys" / name)
        self.env = {"PATH": str(Path(rustc).parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
                    "LC_ALL": "C", "LANG": "C", "CARGO_NET_OFFLINE": "true",
                    "CARGO_BUILD_JOBS": "4", "RUSTC": self.rustc,
                    "RUST_BACKTRACE": "0", "RUSTUP_AUTO_INSTALL": "0"}
        # Only the explicit SDK chosen by the reviewed native wrapper crosses in.
        if "SDKROOT" in os.environ:
            self.env["SDKROOT"] = os.environ["SDKROOT"]
        for key, name in (("HOME", "home"), ("CARGO_HOME", "cargo-home"),
                          ("CARGO_TARGET_DIR", "target"), ("TMPDIR", "tmp")):
            directory = destination / name
            directory.mkdir()
            self.env[key] = str(directory)
        self.registry = registry

    def command(self, name, args, cwd, env=None, expected=0):
        env = self.env if env is None else env
        record = {"command": list(map(str, args)), "cwd": str(cwd), "environment": env,
                  "timeout_seconds": 240}
        # All recorded environment values are constructed here, never a host dump.
        try:
            result = subprocess.run(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=240)
            (self.evidence / (name + ".stdout")).write_bytes(result.stdout)
            (self.evidence / (name + ".stderr")).write_bytes(result.stderr)
            record["returncode"] = result.returncode
        except subprocess.TimeoutExpired as error:
            record["error"] = "timed out; fixture retained, no retry"
            (self.evidence / (name + ".stdout")).write_bytes(error.stdout or b"")
            (self.evidence / (name + ".stderr")).write_bytes(error.stderr or b"")
            raise
        except OSError as error:
            record["error"] = str(error)
            raise
        finally:
            (self.evidence / (name + ".json")).write_text(json.dumps(record, indent=2) + "\n")
        if expected == 0:
            require(result.returncode == 0, name + " failed; inspect retained stderr")
        elif expected == "failure":
            require(result.returncode != 0, name + " unexpectedly succeeded")
        return result

    def prepare(self):
        verify.verify_tree(ROOT / "vendor/libsqlite3-sys")
        copy_tree(self.registry, Path(self.env["CARGO_HOME"]) / "registry")
        copy_tree(ROOT / "vendor/libsqlite3-sys", self.destination / "vendor")
        copy_tree(ROOT / "patches/sqlite", self.evidence / "patches")
        shutil.copyfile(ROOT / "Cargo.lock", self.evidence / "root-Cargo.lock")
        self.vendor = self.destination / "vendor"
        verify.verify_tree(self.vendor)
        self.dependency = self.destination / "dependency"
        self.dependency.mkdir()
        (self.dependency / "src").mkdir()
        (self.dependency / "src/main.rs").write_text(SMOKE)
        (self.dependency / "Cargo.toml").write_text(
            '[workspace]\n\n[package]\nname = "work-sqlite-guard-smoke"\n'
            'version = "0.0.0"\nedition = "2021"\n\n[dependencies]\n'
            'libsqlite3-sys = { path = "../vendor", version = "=0.36.0", features = ["bundled"] }\n')
        shutil.copyfile(ROOT / "Cargo.lock", self.dependency / "Cargo.lock")
        self.report["standalone_workspace"] = str(self.dependency)
        self.report["source_hashes"] = {str(p.relative_to(ROOT)): h for p, h in self.original.items()}
        self.report["registry_seed"] = str(self.registry)
        self.report["sdkroot"] = self.env.get("SDKROOT")

    def cargo_smoke(self):
        versions = self.command("rustc-version", [self.rustc, "-vV"], self.dependency).stdout.decode()
        require("release: 1.98.1\n" in versions, "requires installed pinned Rust 1.98.1")
        self.host = next(line.removeprefix("host: ") for line in versions.splitlines() if line.startswith("host: "))
        self.report["host"] = self.host
        self.command("cargo-version", [self.cargo, "--version"], self.dependency)
        base = [self.cargo, "--offline", "--manifest-path", str(self.dependency / "Cargo.toml")]
        # Resolution is a separate step, checked BEFORE any dependency compilation.
        metadata = self.command("metadata", [base[0], "metadata", *base[1:], "--format-version=1"], self.dependency)
        resolved = json.loads(metadata.stdout)
        require(resolved["workspace_root"] == str(self.dependency), "root workspace discovery")
        packages = [p for p in resolved["packages"] if p["name"] == "libsqlite3-sys"]
        require(len(packages) == 1 and packages[0]["version"] == "0.36.0" and
                packages[0]["manifest_path"] == str(self.vendor / "Cargo.toml"),
                "dependency did not resolve to exact copied vendor")
        validate_lock(self.dependency / "Cargo.lock", self.evidence / "root-Cargo.lock")
        self.report["fixture_lock_sha256"] = sha(self.dependency / "Cargo.lock")
        self.report["registry_packages"] = [
            {k: p[k] for k in ("name", "version", "checksum")}
            for p in lock_packages(self.dependency / "Cargo.lock") if "source" in p]
        built = self.command("cargo-build", [base[0], "build", *base[1:], "--locked", "--message-format=json"], self.dependency)
        self.externs = {}
        script = None
        smoke = None
        script_execution = None
        for line in built.stdout.decode().splitlines():
            artifact = json.loads(line)
            if (artifact.get("reason") == "build-script-executed" and
                    "libsqlite3-sys" in artifact["package_id"]):
                script_execution = artifact
            if artifact.get("reason") == "compiler-artifact":
                name = artifact["target"]["name"]
                if name in ("sha2", "cc", "pkg_config", "vcpkg"):
                    self.externs[name] = next(f for f in artifact["filenames"] if f.endswith(".rlib"))
                if name == "build-script-build" and "libsqlite3-sys" in artifact["package_id"]:
                    script = artifact["filenames"][0]
                if name == "work-sqlite-guard-smoke":
                    smoke = artifact["executable"]
        require(len(self.externs) == 4 and script and smoke and script_execution,
                "missing real Cargo build artifacts/execution")
        require("static=sqlite3" in script_execution["linked_libs"], "not bundled static linkage")
        build_output = Path(script_execution["out_dir"]).parent / "output"
        if "apple-darwin" in self.host:
            require(all("cargo:rerun-if-changed=sqlite3/" + p in build_output.read_text()
                        for p in MANDATORY), "Cargo did not execute Darwin source checks")
        self.bundled_script = Path(script)
        self.report["cargo_build_script"] = {"path": script, "sha256": sha(script),
                                             "source_sha256": sha(self.vendor / "build.rs"),
                                             "cargo_execution": script_execution,
                                             "output_path": str(build_output), "output_sha256": sha(build_output)}
        success = self.command("cargo-sql-smoke", [smoke], self.dependency)
        require(success.stdout == b"bundled SQLite 3.51.1 SQL sum=42\n", "SQL smoke output mismatch")
        # Cargo emitted an archive from this path dependency, not system SQLite.
        archives = list((self.destination / "target/debug/build").glob("libsqlite3-sys-*/out/libsqlite3.a"))
        require(len(archives) == 1, "expected exactly one bundled SQLite archive")
        self.report["bundled_archive"] = {"path": str(archives[0]), "sha256": sha(archives[0])}
        self.report["cases"].append({"name": "cargo-bundled-sql", "status": "passed",
                                     "execution": "full Cargo dependency build and linked SQL execution"})

    def compile_variant(self, name, features):
        output = self.destination / ("guard-" + name)
        args = [self.rustc, "--edition=2021", "--crate-name", "work_sqlite_guard",
                str(self.vendor / "build.rs"), "-o", str(output),
                "-L", "dependency=" + str(self.destination / "target/debug/deps")]
        for feature in ["min_sqlite_version_3_34_1", *features]:
            args += ["--cfg", 'feature="' + feature + '"']
        for dependency, artifact in sorted(self.externs.items()):
            args += ["--extern", dependency + "=" + artifact]
        env = dict(self.env, CARGO_MANIFEST_DIR=str(self.vendor))
        self.command("compile-" + name, args, self.vendor, env)
        self.report.setdefault("bounded_variants", {})[name] = {
            "features": ["min_sqlite_version_3_34_1", *features],
            "source": str(self.vendor / "build.rs"), "source_sha256": sha(self.vendor / "build.rs"),
            "executable": str(output), "sha256": sha(output),
            "provenance": "rustc on complete unmodified build.rs with Cargo-built locked externs; not optional-feature Cargo resolution"}
        return output

    def guard_case(self, name, script, *, fault=None, package_env=None,
                   target_os="macos", target="aarch64-apple-darwin", host=None, permitted=False):
        case = self.destination / "cases" / name
        case.mkdir(parents=True)
        tree = case / "vendor"
        copy_tree(self.vendor, tree)
        mutation = None
        if fault:
            kind, filename = fault
            path = tree / "sqlite3" / filename
            original = path.read_bytes()
            if kind == "missing":
                path.unlink()  # Only this new case's copy is mutated.
            else:
                path.write_bytes(original + b"\n/* S2 owned source-drift fixture */\n")
            mutation = {"path": str(path.relative_to(tree)), "kind": kind,
                        "before_sha256": hashlib.sha256(original).hexdigest(),
                        "after_sha256": sha(path) if path.exists() else None}
        tools = case / "blocked-tools"
        tools.mkdir()
        for tool in ("cc", "ar", "pkg-config"):
            path = tools / tool
            path.write_text('#!/bin/sh\nprintf "%s\\n" "$0" >> "$S2_TOOL_LOG"\nexit 86\n')
            path.chmod(0o700)
        out = case / "out"
        out.mkdir()
        env = dict(self.env, CARGO_CFG_TARGET_OS=target_os, TARGET=target,
                   HOST=host or self.host, CARGO_MANIFEST_DIR=str(tree),
                   CC=str(tools / "cc"), AR=str(tools / "ar"), PKG_CONFIG=str(tools / "pkg-config"),
                   S2_TOOL_LOG=str(case / "tool-executions.log"), OPT_LEVEL="0", DEBUG="true",
                   CARGO_CFG_TARGET_ENV="gnu" if target_os == "linux" else "",
                   CARGO_CFG_TARGET_FEATURE="", OUT_DIR=str(out))
        if permitted:
            # A deterministic barrier in REAL main immediately after the guard.
            # No C/archiver/system-library probe is needed to test guard acceptance.
            del env["OUT_DIR"]
        if package_env is not None:
            env["LIBSQLITE3_SYS_USE_PKG_CONFIG"] = package_env
        result = self.command(name, [str(script)], tree, env, expected="failure")
        stdout, stderr = result.stdout.decode(), result.stderr.decode()
        executed = (case / "tool-executions.log").exists()
        expected_error = None
        if permitted:
            expected_error = 'called `Result::unwrap()` on an `Err` value: NotPresent'
            require(expected_error in stderr, name + " did not reach post-guard OUT_DIR barrier")
            require(stdout.splitlines() == ["cargo:rerun-if-changed=sqlite3/" + p for p in MANDATORY],
                    name + " did not verify every mandatory input")
        elif target_os == "linux":
            require(executed, name + " did not reach bounded compiler trap after bypassing macOS guard")
            require("Work SQLite source drift:" not in stderr and ALTERNATE_ERROR not in stderr,
                    name + " incorrectly enforced Darwin guard")
            require((out / "bindgen.rs").is_file(), name + " did not take ordinary bundled path")
        elif fault:
            kind, filename = fault
            if kind == "missing":
                expected_error = "Work SQLite source is missing:"
                require("kind: NotFound" in stderr, name + " wrong missing-input error")
            else:
                expected_error = f"Work SQLite source drift: sqlite3/{filename}; upgrade requires re-review"
                require('left: "' + mutation["after_sha256"] + '"' in stderr and
                        'right: "' + mutation["before_sha256"] + '"' in stderr,
                        name + " did not compare exact altered/original SHA256")
        else:
            expected_error = ALTERNATE_ERROR
        if expected_error:
            require(expected_error in stderr, name + " wrong guard/barrier error")
            require(not executed and not list(out.iterdir()), name + " unsafe downstream effects")
            require("cargo:rerun-if-env-changed=LIBSQLITE3_SYS_USE_PKG_CONFIG" not in stdout,
                    name + " reached alternate-route selection")
        self.report["cases"].append({"name": name, "status": "passed", "mutation": mutation,
                                     "execution": "compiled real build.rs, not a Cargo fault transaction",
                                     "executable": str(script), "executable_sha256": sha(script),
                                     "target_os": target_os, "target": target, "host": env["HOST"],
                                     "expected_error": expected_error, "alternate_tools_executed": executed,
                                     "tool_paths": {t: str(tools / t) for t in ("cc", "ar", "pkg-config")}})

    def matrix(self):
        bundled = self.bundled_script  # This executable was built by REAL Cargo.
        for name, value in (("permitted-unset", None), ("permitted-zero", "0")):
            self.guard_case(name, bundled, package_env=value, permitted=True)
        for filename in MANDATORY:
            for fault in ("altered", "missing"):
                self.guard_case(fault + "-" + filename, bundled, fault=(fault, filename))
        for name, value in (("one", "1"), ("empty", ""), ("other", "true")):
            self.guard_case("reject-env-" + name, bundled, package_env=value)
        for name, features in (("no-bundled", []), ("sqlcipher", ["bundled", "sqlcipher"]),
                               ("bundled-sqlcipher", ["bundled", "bundled-sqlcipher"]),
                               ("in_gecko", ["bundled", "in_gecko"]),
                               ("loadable_extension", ["bundled", "loadable_extension"])):
            script = self.compile_variant(name, features)
            self.guard_case("reject-" + name, script)
        self.guard_case("target-macos-host-linux", bundled, host="x86_64-unknown-linux-gnu",
                        fault=("altered", "sqlite3.c"))
        self.guard_case("target-linux-host-macos", bundled, target_os="linux",
                        target="x86_64-unknown-linux-gnu", host="aarch64-apple-darwin",
                        fault=("altered", "sqlite3.c"))

    def run(self):
        try:
            self.prepare()
            self.cargo_smoke()
            self.matrix()
            verify.verify_tree(self.vendor)
            self.report["status"] = "passed"
        except Exception as error:
            self.report["error"] = str(error)
            raise
        finally:
            unchanged = all(sha(path) == before for path, before in self.original.items())
            self.report["root_inputs_unchanged"] = unchanged
            if not unchanged:
                self.report["status"] = "failed"
                self.report["error"] = "original root/vendor inputs changed"
            (self.evidence / "report.json").write_text(json.dumps(self.report, indent=2) + "\n")
            require(unchanged, "original root/vendor inputs changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("destination", "registry", "cargo", "rustc"):
        parser.add_argument("--" + flag, required=True, type=Path)
    args = parser.parse_args()
    try:
        fixture = Fixture(args.destination, args.registry, args.cargo, args.rustc)
        print("Source and evidence retained at " + str(args.destination), flush=True)
        fixture.run()
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print("BLOCKED: " + str(error), file=sys.stderr)
        return 1
    print("real Cargo SQL smoke and bounded real build.rs guard matrix passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
