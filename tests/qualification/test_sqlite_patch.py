"""Offline provenance and extracted pinned-source tests, not Work-linked VFS tests."""
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools/qualification/sqlite"
VENDOR = ROOT / "vendor/libsqlite3-sys"


class SqlitePatchTests(unittest.TestCase):
    def test_pinned_provenance_and_offline_verifier_exist(self):
        self.assertTrue((ROOT / "patches/sqlite/provenance.json").is_file(),
                        "S1 must pin the exact crate, source, and patch digests")
        self.assertTrue((TOOLS / "verify.py").is_file())

    def verifier(self):
        spec = importlib.util.spec_from_file_location("sqlite_verify", TOOLS / "verify.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_exact_vendor_tree(self):
        self.assertTrue(VENDOR.is_dir(), "exact pinned crate must be vendored")
        self.verifier().verify_tree(VENDOR)

    def test_source_drift_is_fatal(self):
        self.assertTrue(VENDOR.is_dir(), "exact pinned crate must be vendored")
        with tempfile.TemporaryDirectory() as temp:
            tree = Path(temp) / "vendor"
            shutil.copytree(VENDOR, tree)
            source = tree / "sqlite3/sqlite3.c"
            source.write_bytes(source.read_bytes() + b"\n/* unexpected drift */\n")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                self.verifier().verify_tree(tree)

    def test_wrong_archive_is_rejected_before_tar_parsing(self):
        self.assertTrue((TOOLS / "verify.py").is_file(), "offline verifier required")
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "wrong.crate"
            archive.write_bytes(b"not a tar archive")
            destination = Path(temp) / "destination"
            with self.assertRaisesRegex(ValueError, "crate checksum mismatch"):
                self.verifier().extract_crate(archive, destination)
            self.assertFalse(destination.exists())

    def test_archive_members_are_validated_before_writes(self):
        module = self.verifier()
        expected_pin = module.manifest()
        module.manifest = lambda: expected_pin
        for kind in ("traversal", "symlink", "duplicate"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                temp = Path(temp)
                archive = temp / "hostile.crate"
                with tarfile.open(archive, "w:gz") as tar:
                    for name in module.manifest()["upstream_files"]:
                        if kind == "traversal" and name == "build.rs":
                            name = "../escape"
                        if kind == "duplicate" and name == "README.md":
                            name = "build.rs"
                        member = tarfile.TarInfo("libsqlite3-sys-0.36.0/" + name)
                        if kind == "symlink" and name == "build.rs":
                            member.type = tarfile.SYMTYPE
                            member.linkname = "/tmp/foreign"
                        tar.addfile(member, io.BytesIO(b""))
                # Test-only override lets malformed fixtures reach member checks;
                # shipped code has a fixed checksum and no runtime override.
                module.CRATE_SHA256 = module.digest(archive.read_bytes())
                with self.assertRaisesRegex(ValueError, "unexpected crate members"):
                    module.extract_crate(archive, temp / "extracted")
                self.assertFalse((temp / "extracted").exists())

    def test_provenance_metadata_drift_is_fatal(self):
        module = self.verifier()
        with tempfile.TemporaryDirectory() as temp:
            patches = Path(temp) / "patches"
            shutil.copytree(ROOT / "patches/sqlite", patches)
            pin = json.loads((patches / "provenance.json").read_text())
            pin["crate_sha256"] = "0" * 64
            (patches / "provenance.json").write_text(json.dumps(pin))
            module.PATCHES = patches
            with self.assertRaisesRegex(ValueError, "provenance metadata mismatch"):
                module.verify_tree(VENDOR)

    def test_patch_digest_drift_is_fatal(self):
        module = self.verifier()
        with tempfile.TemporaryDirectory() as temp:
            patches = Path(temp) / "patches"
            shutil.copytree(ROOT / "patches/sqlite", patches)
            patch = patches / "darwin-required-ack.patch"
            patch.write_bytes(patch.read_bytes() + b"unexpected")
            module.PATCHES = patches
            with self.assertRaisesRegex(ValueError, "patch digest mismatch"):
                module.verify_tree(VENDOR)

    def test_patch_context_drift_is_fatal(self):
        self.assertTrue(VENDOR.is_dir(), "exact pinned crate must be vendored")
        module = self.verifier()
        manifest = json.loads((ROOT / "patches/sqlite/provenance.json").read_text())
        source = (VENDOR / "sqlite3/sqlite3.c").read_text()
        patch = (ROOT / "patches/sqlite/darwin-required-ack.patch").read_text()
        original = module.apply_patch(source, patch, reverse=True)
        self.assertEqual(module.digest(original.encode()), manifest["upstream_files"]["sqlite3/sqlite3.c"])
        with self.assertRaisesRegex(ValueError, "patch context mismatch"):
            module.apply_patch(original.replace("  if( rc ) rc = fsync(fd);",
                                                "  if( rc ) rc = changed_fsync(fd);"), patch)
        self.assertEqual(module.apply_patch(original, patch), source)

    def test_darwin_build_has_sha256_source_gate(self):
        build = (VENDOR / "build.rs").read_text()
        self.assertIn("verify_work_darwin_source();", build)
        self.assertIn("sha2::Sha256", build)
        self.assertIn('env::var("CARGO_CFG_TARGET_OS")', build)
        self.assertIn("Work requires exact patched bundled SQLite", build)
        pin = json.loads((ROOT / "patches/sqlite/provenance.json").read_text())
        for name in ("sqlite3/sqlite3.c", "sqlite3/sqlite3.h", "sqlite3/sqlite3ext.h",
                     "sqlite3/bindgen_bundled_version.rs", "sqlite3/bindgen_bundled_version_ext.rs"):
            self.assertIn(pin["vendored_files"][name], build)

    def test_darwin_c_rejects_disabled_required_sync(self):
        source = (VENDOR / "sqlite3/sqlite3.c").read_text()
        start = source.index("#if defined(__APPLE__) && (defined(SQLITE_NO_SYNC)")
        guard = source[start:source.index("#endif", start) + len("#endif")]
        for flags in (["-DF_FULLFSYNC=51"], ["-DF_FULLFSYNC=51", "-DSQLITE_NO_SYNC"],
                      ["-DF_FULLFSYNC=51", "-DSQLITE_DISABLE_DIRSYNC"], []):
            with self.subTest(flags=flags):
                result = subprocess.run(["cc", "-E", "-x", "c", "-D__APPLE__", *flags, "-"],
                                        input=guard, capture_output=True, text=True, timeout=10)
                if flags == ["-DF_FULLFSYNC=51"]:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Work requires Darwin F_FULLFSYNC", result.stderr)

    def test_extracted_source_darwin_faults(self):
        self.assertTrue((TOOLS / "run_harness.py").is_file(), "bounded exact-source harness required")
        result = subprocess.run(["python3", str(TOOLS / "run_harness.py"), "--mode", "darwin"],
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_extracted_source_linux_unchanged(self):
        self.assertTrue((TOOLS / "run_harness.py").is_file(), "bounded exact-source harness required")
        result = subprocess.run(["python3", str(TOOLS / "run_harness.py"), "--mode", "linux"],
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_whole_linux_amalgamation_smoke(self):
        self.assertTrue((TOOLS / "whole_linux.py").is_file(),
                        "whole-amalgamation smoke must be distinct from extracted tests")
        result = subprocess.run(["python3", str(TOOLS / "whole_linux.py")],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fault_controls_are_closed_and_bounded(self):
        self.assertTrue((TOOLS / "run_harness.py").is_file(), "bounded exact-source harness required")
        result = subprocess.run(["python3", str(TOOLS / "run_harness.py"), "--mode", "unbounded"],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid choice", result.stderr)


if __name__ == "__main__":
    unittest.main()
