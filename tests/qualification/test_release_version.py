import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "tools/release_version.py"


class ReleaseVersionTests(unittest.TestCase):
    def test_workspace_lockfile_and_tag_must_match(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / "Cargo.toml").write_text('[workspace.package]\nversion="0.2.4"\n')
            lock = root / "Cargo.lock"
            lock.write_text('[[package]]\nname="work-cli"\nversion="0.2.4"\n[[package]]\nname="work-contract"\nversion="0.2.4"\n')
            def run(tag):
                return subprocess.run([sys.executable, str(SCRIPT), "--root", str(root), "--tag", tag], capture_output=True, text=True,
                                      env={"PATH":"/usr/bin:/bin", "LC_ALL":"C"})
            good = run("v0.2.4")
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertEqual(good.stdout.strip(), "0.2.4")
            self.assertNotEqual(run("v0.2.5").returncode, 0)
            lock.write_text(lock.read_text().replace('version="0.2.4"', 'version="0.2.3"', 1))
            self.assertNotEqual(run("v0.2.4").returncode, 0)


if __name__ == "__main__":
    unittest.main()
