"""Owned offline archives; never invoke network or touch the user's install."""
import hashlib
import io
import importlib.util
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "tools/work_install.py"
spec = importlib.util.spec_from_file_location("work_install", INSTALLER)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.data = self.base / "data"
        self.bin = self.base / "bin"
        self.skills = self.base / "skills"

    def archive(self, version, extra=None, bad_version=False):
        archive = self.base / f"work-cli-{version}-linux-x86_64.tar.gz"
        prefix = f"work-cli-{version}-linux-x86_64"
        binary_version = "0.0.0" if bad_version else version
        files = {
            "bin/work": f"#!/bin/sh\nprintf 'work {binary_version}\\n'\n".encode(),
            "README.md": b"fixture release\n",
            "LICENSE": b"fixture license\n",
            "docs/distribution.md": b"fixture distribution process\n",
            "examples/work.toml": b"# fixture configuration\n",
            "skills/work-cli/SKILL.md": b"---\nname: work-cli\ndescription: Use for task worktrees.\n---\n",
            "tools/work_install.py": b"#!/usr/bin/env python3\nprint('fixture updater')\n",
        }
        with tarfile.open(archive, "w:gz") as tf:
            for name, contents in files.items():
                info = tarfile.TarInfo(f"{prefix}/{name}")
                info.size = len(contents)
                info.mode = 0o755 if name.startswith(("bin/", "tools/")) else 0o644
                tf.addfile(info, io.BytesIO(contents))
            if extra:
                info, contents = extra(prefix)
                tf.addfile(info, io.BytesIO(contents) if contents else None)
        checksum = archive.with_suffix(archive.suffix + ".sha256")
        checksum.write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n")
        return archive, checksum

    def run_install(self, command, version, archive=None, checksum=None, *more):
        args = [sys.executable, str(INSTALLER), command, "--version", f"v{version}",
                "--data-dir", str(self.data), "--bin-dir", str(self.bin)]
        if archive:
            args += ["--archive", str(archive), "--checksum", str(checksum)]
        return subprocess.run(args + list(more), capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin", "HOME": str(self.base), "LC_ALL": "C"})

    def test_install_update_and_rollback_keep_one_atomic_current_pointer(self):
        first = self.archive("0.2.4")
        p = self.run_install("install", "0.2.4", *first, "--skills-dir", str(self.skills))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(subprocess.check_output([self.bin / "work"], text=True), "work 0.2.4\n")
        self.assertTrue((self.skills / "work-cli/SKILL.md").is_file())
        self.assertTrue((self.bin / "work-install").is_symlink())
        second = self.archive("0.2.5")
        refused = self.run_install("update", "0.2.5", *second)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(os.readlink(self.data / "current"), "releases/v0.2.4")
        p = self.run_install("update", "0.2.5", *second, "--confirm-stopped", "--skills-dir", str(self.skills))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(subprocess.check_output([self.bin / "work"], text=True), "work 0.2.5\n")
        self.assertEqual(os.readlink(self.data / "current"), "releases/v0.2.5")
        p = self.run_install("rollback", "0.2.4", None, None, "--confirm-stopped")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(subprocess.check_output([self.bin / "work"], text=True), "work 0.2.4\n")
        self.assertTrue((self.data / "releases/v0.2.5").is_dir())

    def test_bad_checksum_version_and_archive_entries_never_activate(self):
        for case in ["checksum", "version", "traversal", "symlink", "hardlink", "duplicate"]:
            with self.subTest(case=case):
                def extra(prefix):
                    name = "../escaped" if case == "traversal" else f"{prefix}/bin/work"
                    info = tarfile.TarInfo(name)
                    if case in ("symlink", "hardlink"):
                        info.type = tarfile.SYMTYPE if case == "symlink" else tarfile.LNKTYPE
                        info.linkname = "/etc/passwd"
                    else:
                        info.size = 1
                    return info, b"x" if info.isfile() else b""
                a, c = self.archive("0.2.4", extra if case in ("traversal", "symlink", "hardlink", "duplicate") else None, case == "version")
                if case == "checksum":
                    c.write_text(f"{'0'*64}  {a.name}\n")
                p = self.run_install("install", "0.2.4", a, c)
                self.assertNotEqual(p.returncode, 0, case)
                self.assertFalse((self.data / "current").exists())
                self.assertFalse((self.bin / "work").exists())
                self.assertFalse((self.base / "escaped").exists())

    def test_foreign_install_and_skill_targets_are_not_overwritten(self):
        self.bin.mkdir()
        existing = self.bin / "work"
        existing.write_text("keep existing binary")
        a, c = self.archive("0.2.4")
        p = self.run_install("install", "0.2.4", a, c)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(existing.read_text(), "keep existing binary")
        existing.unlink()
        (self.skills / "work-cli").mkdir(parents=True)
        (self.skills / "work-cli/SKILL.md").write_text("keep existing skill")
        p = self.run_install("install", "0.2.4", a, c, "--skills-dir", str(self.skills))
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual((self.skills / "work-cli/SKILL.md").read_text(), "keep existing skill")
        self.assertFalse((self.data / "current").exists())

    def test_tampered_cached_release_cannot_be_rolled_back(self):
        a, c = self.archive("0.2.4")
        p = self.run_install("install", "0.2.4", a, c)
        self.assertEqual(p.returncode, 0, p.stderr)
        (self.data / "releases/v0.2.4/README.md").write_text("changed")
        p = self.run_install("rollback", "0.2.4", None, None, "--confirm-stopped")
        self.assertNotEqual(p.returncode, 0)

    def test_independent_skill_registration_migrates_to_packaged_skill(self):
        source = self.base / "reviewed-source"
        (source / "skills/work-cli/reference").mkdir(parents=True)
        (source / "docs").mkdir()
        skill = source / "skills/work-cli/SKILL.md"
        skill.write_text("---\nname: work-cli\ndescription: Use for task worktrees.\n---\nReviewed bootstrap skill.\n")
        (source / "docs/distribution.md").write_text("Reviewed setup instructions.\n")
        p = subprocess.run([sys.executable, str(INSTALLER), "skill", "--source-root", str(source),
            "--data-dir", str(self.data), "--skills-dir", str(self.skills)], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("Reviewed bootstrap", (self.skills / "work-cli/SKILL.md").read_text())
        skill.write_text("Modified source must not alter installed instructions")
        self.assertIn("Reviewed bootstrap", (self.skills / "work-cli/SKILL.md").read_text())
        archive = self.archive("0.2.4")
        installed = self.run_install("install", "0.2.4", *archive, "--skills-dir", str(self.skills))
        self.assertEqual(installed.returncode, 0, installed.stderr)
        self.assertEqual((self.skills / "work-cli/SKILL.md").read_bytes(), b"---\nname: work-cli\ndescription: Use for task worktrees.\n---\n")

    def test_download_verifies_and_preserves_existing_destinations(self):
        archive, checksum = self.archive("0.2.4")
        output = self.base / "download"
        output.mkdir()
        calls = []
        def fetch(url, destination, maximum=installer.MAX_DOWNLOAD):
            calls.append(url)
            destination.write_bytes(checksum.read_bytes() if url.endswith(".sha256") else archive.read_bytes())
        with patch.object(installer, "fetch", side_effect=fetch):
            downloaded, check = installer.release_files("0.2.4", output)
            self.assertEqual(installer.verify_archive(downloaded, check, "0.2.4"), hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(len(calls), 2)
            with self.assertRaises(ValueError):
                installer.release_files("0.2.4", output)
            self.assertEqual(len(calls), 2)
            downloaded.unlink()
            downloaded.symlink_to(output / "missing")
            with self.assertRaises(ValueError):
                installer.release_files("0.2.4", output)
            self.assertTrue(downloaded.is_symlink())
        for url in ["http://github.com/file", "https://evil.invalid/file", "https://github.com@evil.invalid/file", "https://github.com:444/file"]:
            with self.assertRaises(ValueError): installer.allowed_url(url)
        installer.allowed_url("https://release-assets.githubusercontent.com/file?public-signature=fixture")

    def test_latest_uses_public_release_redirect_not_the_rest_api(self):
        from unittest.mock import MagicMock
        response = MagicMock()
        response.__enter__.return_value.url = f"https://github.com/{installer.REPOSITORY}/releases/tag/v0.2.4"
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(installer, "fetch", side_effect=AssertionError("REST metadata must not be fetched")), patch.object(installer.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(installer.latest_version(), "0.2.4")
            request = opener.open.call_args.args[0]
            self.assertTrue(request.full_url.endswith("/releases/latest"))
            self.assertEqual(request.get_method(), "HEAD")
            response.__enter__.return_value.url = "https://github.com/foreign/project/releases/tag/v0.2.4"
            with self.assertRaises(ValueError): installer.latest_version()
            response.__enter__.return_value.url = f"https://github.com/{installer.REPOSITORY}/releases/tag/v0.2.4-rc1"
            with self.assertRaises(ValueError): installer.latest_version()

    def test_installer_lock_and_failed_update_leave_current_unchanged(self):
        first = self.archive("0.2.4")
        self.assertEqual(self.run_install("install", "0.2.4", *first).returncode, 0)
        with (self.data / ".install.lock").open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            p = self.run_install("install", "0.2.4", *first)
            self.assertNotEqual(p.returncode, 0)
        second = self.archive("0.2.5")
        second[1].write_text(f"{'0'*64}  {second[0].name}\n")
        self.assertNotEqual(self.run_install("update", "0.2.5", *second, "--confirm-stopped").returncode, 0)
        self.assertEqual(os.readlink(self.data / "current"), "releases/v0.2.4")
        self.assertEqual(subprocess.check_output([self.bin / "work"], text=True), "work 0.2.4\n")

    def test_explicit_paths_do_not_require_a_home_directory(self):
        archive, checksum = self.archive("0.2.4")
        with patch.object(Path, "home", side_effect=RuntimeError("no passwd or HOME")), patch("sys.stdout", new_callable=io.StringIO):
            result = installer.main(["install", "--version", "v0.2.4", "--archive", str(archive), "--checksum", str(checksum), "--bin-dir", str(self.bin), "--data-dir", str(self.data)])
        self.assertEqual(result, 0)
        self.assertTrue((self.bin / "work").is_file())

    def test_authority_looking_destination_is_refused_before_installer_writes(self):
        self.data.mkdir()
        database = self.data / "store.sqlite"
        database.write_bytes(b"retained authority bytes")
        archive = self.archive("0.2.4")
        p = self.run_install("install", "0.2.4", *archive)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(database.read_bytes(), b"retained authority bytes")
        self.assertEqual({p.name for p in self.data.iterdir()}, {"store.sqlite"})

    def test_symlinked_managed_directory_and_bad_versions_refuse(self):
        real = self.base / "real"
        real.mkdir()
        self.data.symlink_to(real, target_is_directory=True)
        a, c = self.archive("0.2.4")
        p = self.run_install("install", "0.2.4", a, c)
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse((real / "current").exists())
        for version in ["../outside", "0.2.4-rc1", "02.4.0"]:
            self.assertNotEqual(self.run_install("rollback", version, None, None, "--confirm-stopped").returncode, 0)


if __name__ == "__main__":
    unittest.main()
