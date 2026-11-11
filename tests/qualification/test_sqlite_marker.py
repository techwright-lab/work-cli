"""S3a-P marker provenance; real target compilation is qualified separately."""
import importlib.util
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class SqliteMarkerTests(unittest.TestCase):
    def test_glue_patch_reconstructs_marker_library_to_pinned_upstream(self):
        spec = importlib.util.spec_from_file_location(
            "sqlite_verify", ROOT / "tools/qualification/sqlite/verify.py")
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        glue = (ROOT / "patches/sqlite/vendor-glue.patch").read_text()
        sections = re.split(r"(?=^--- a/)", glue, flags=re.MULTILINE)[1:]
        targets = [s.splitlines()[0].removeprefix("--- a/") for s in sections]
        self.assertEqual(targets, ["Cargo.toml", "Cargo.toml.orig", "build.rs", "src/lib.rs"])
        original = verifier.apply_patch(
            (ROOT / "vendor/libsqlite3-sys/src/lib.rs").read_text(),
            sections[3], reverse=True, target="src/lib.rs")
        self.assertEqual(verifier.digest(original.encode()),
                         verifier.manifest()["upstream_files"]["src/lib.rs"])


if __name__ == "__main__":
    unittest.main()
