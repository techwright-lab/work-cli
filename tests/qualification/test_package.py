"""Packaging-devtool tests using inert bytes, not native/release evidence."""
import hashlib
import importlib.util
from pathlib import Path
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/package-common.py"
MATERIALS = (
    "LICENSE",
    "README.md",
    "AGENTS.md",
    "examples/work.toml",
    "tools/work_install.py",
    "docs/distribution.md",
    "skills/work-cli/SKILL.md",
    "skills/work-cli/reference/setup.md",
)
INERT_EXECUTABLE = b"INERT packaging fixture, not ELF or Mach-O\x00\xff\r\n"


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        for name in MATERIALS:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"inert material: {name}\n".encode())
        self.executable = self.root / "final-executable"
        self.executable.write_bytes(INERT_EXECUTABLE)
        self.executable.chmod(0o440)  # Packaging must not execute or alter its input.
        self.output = self.root / "artifacts"

    def run_package(self, **overrides):
        arguments = {
            "version": "0.3.0",
            "platform": "linux-x86_64",
            "executable": self.executable,
            "source-root": self.source,
            "output-dir": self.output,
        }
        arguments.update(overrides)
        command = [sys.executable, str(SCRIPT)]
        for name, value in arguments.items():
            command.extend([f"--{name}", str(value)])
        try:
            return subprocess.run(command, capture_output=True, text=True, timeout=10,
                                  env={"PATH": "", "LC_ALL": "C"}, cwd=self.root)
        except subprocess.TimeoutExpired:
            self.fail("packaging blocked on an unsafe input instead of refusing it")

    def load_packager(self):
        spec = importlib.util.spec_from_file_location("package_common", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def assert_refused(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("refused", result.stderr)
        self.assertFalse(os.path.lexists(self.output))

    def assert_checksum(self, artifact):
        expected = hashlib.sha256(artifact.read_bytes()).hexdigest()
        self.assertEqual(artifact.with_name(artifact.name + ".sha256").read_bytes(),
                         f"{expected}  {artifact.name}\n".encode("ascii"))

    def test_packages_exact_final_bytes_for_each_platform(self):
        original = self.executable.stat()
        for platform in ("linux-x86_64", "macos-arm64"):
            with self.subTest(platform=platform):
                output = self.root / platform
                result = self.run_package(platform=platform, **{"output-dir": output})
                self.assertEqual(result.returncode, 0, result.stderr)
                binary = output / f"work-0.3.0-{platform}"
                archive = output / f"work-cli-0.3.0-{platform}.tar.gz"
                self.assertEqual({path.name for path in output.iterdir()},
                                 {binary.name, binary.name + ".sha256",
                                  archive.name, archive.name + ".sha256"})
                self.assertEqual(binary.read_bytes(), INERT_EXECUTABLE)
                self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o755)
                self.assert_checksum(binary)
                self.assert_checksum(archive)
                with tarfile.open(archive, "r:gz") as bundle:
                    member = bundle.getmember(f"work-cli-0.3.0-{platform}/bin/work")
                    self.assertTrue(member.isfile())
                    self.assertEqual(member.mode, 0o755)
                    self.assertEqual(bundle.extractfile(member).read(), binary.read_bytes())
        self.assertEqual(self.executable.read_bytes(), INERT_EXECUTABLE)
        after = self.executable.stat()
        self.assertEqual((after.st_mode, after.st_mtime_ns, after.st_ino, after.st_size),
                         (original.st_mode, original.st_mtime_ns, original.st_ino, original.st_size))

    def test_bundle_is_exact_material_allowlist_with_portable_modes(self):
        for name in (".git/config", "store/authority.db", "registry/marker",
                     "unrelated-source.rs", "skills/foreign/SKILL.md",
                     "skills/work-cli/secret", "tools/build.py"):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"must never ship")
        (self.source / "skills/work-cli/unrelated-link").symlink_to(self.executable)
        before = {name: ((self.source / name).read_bytes(), (self.source / name).stat())
                  for name in MATERIALS}
        result = self.run_package()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        with tarfile.open(self.output / "work-cli-0.3.0-linux-x86_64.tar.gz") as bundle:
            prefix = "work-cli-0.3.0-linux-x86_64/"
            self.assertEqual(sorted(bundle.getnames()),
                             sorted(prefix + name for name in (*MATERIALS, "bin/work")))
            for member in bundle:
                self.assertTrue(member.isfile(), member.name)
                self.assertEqual((member.uid, member.gid, member.uname, member.gname), (0, 0, "", ""))
                self.assertEqual(member.pax_headers, {})
                relative = member.name.removeprefix(prefix)
                mode = 0o755 if relative in ("bin/work", "tools/work_install.py") else 0o644
                self.assertEqual(member.mode, mode, member.name)
                if relative != "bin/work":
                    self.assertEqual(bundle.extractfile(member).read(), before[relative][0])
        for name, (content, metadata) in before.items():
            self.assertEqual((self.source / name).read_bytes(), content)
            after = (self.source / name).stat()
            self.assertEqual((after.st_mode, after.st_mtime_ns, after.st_ino),
                             (metadata.st_mode, metadata.st_mtime_ns, metadata.st_ino))

    def test_uses_supplied_version_without_workspace_metadata_or_execution(self):
        result = self.run_package(version="12.34.56")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({path.name for path in self.output.iterdir()}, {
            "work-12.34.56-linux-x86_64", "work-12.34.56-linux-x86_64.sha256",
            "work-cli-12.34.56-linux-x86_64.tar.gz",
            "work-cli-12.34.56-linux-x86_64.tar.gz.sha256",
        })
        with tarfile.open(self.output / "work-cli-12.34.56-linux-x86_64.tar.gz") as bundle:
            self.assertEqual(bundle.extractfile("work-cli-12.34.56-linux-x86_64/bin/work").read(),
                             INERT_EXECUTABLE)

    def test_empty_materials_refuse_before_output_creation(self):
        for name in MATERIALS:
            path = self.source / name
            content = path.read_bytes()
            path.write_bytes(b"")
            with self.subTest(name=name):
                self.assert_refused(self.run_package())
            path.write_bytes(content)

    def test_requires_all_explicit_arguments(self):
        arguments = ["--version", "0.3.0", "--platform", "linux-x86_64",
                     "--executable", str(self.executable), "--source-root", str(self.source),
                     "--output-dir", str(self.output)]
        for index in range(0, len(arguments), 2):
            with self.subTest(missing=arguments[index]):
                result = subprocess.run([sys.executable, str(SCRIPT),
                                         *arguments[:index], *arguments[index + 2:]],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("required", result.stderr)
                self.assertFalse(self.output.exists())

    def test_rejects_noncanonical_versions_before_writes(self):
        for version in ("", "v0.3.0", "01.3.0", "0.03.0", "0.3.00", "0.3",
                        "0.3.0-rc.1", "0.3.0+build", "../escape", "0.3.0\n",
                        "1" * 250 + ".0.0"):
            with self.subTest(version=version):
                self.assert_refused(self.run_package(version=version))

    def test_rejects_unsupported_platforms_in_cli_and_callable(self):
        module = self.load_packager()
        for platform in ("darwin-arm64", "macos-x86_64", "linux-aarch64", "../escape", ""):
            with self.subTest(platform=platform):
                result = self.run_package(platform=platform)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.output.exists())
                with self.assertRaises(ValueError):
                    module.package("0.3.0", platform, self.executable, self.source, self.output)
                self.assertFalse(self.output.exists())

    def test_missing_materials_refuse_before_output_creation(self):
        for name in MATERIALS:
            with self.subTest(name=name):
                path = self.source / name
                original = path.read_bytes()
                path.unlink()
                self.assert_refused(self.run_package())
            path.write_bytes(original)

    def test_rejects_missing_empty_or_nonregular_executable(self):
        for kind in ("missing", "empty", "directory", "fifo", "symlink", "dangling"):
            with self.subTest(kind=kind):
                path = self.root / kind
                if kind == "empty":
                    path.touch()
                elif kind == "directory":
                    path.mkdir()
                elif kind == "fifo":
                    os.mkfifo(path)
                elif kind in ("symlink", "dangling"):
                    path.symlink_to(self.executable if kind == "symlink" else self.root / "absent")
                self.assert_refused(self.run_package(executable=path))

    def test_rejects_symlink_or_nonregular_required_materials(self):
        for name in MATERIALS:
            path = self.source / name
            content = path.read_bytes()
            path.unlink()
            with self.subTest(name=name, kind="symlink"):
                path.symlink_to(self.executable)
                self.assert_refused(self.run_package())
            path.unlink()
            with self.subTest(name=name, kind="directory"):
                path.mkdir()
                self.assert_refused(self.run_package())
            path.rmdir()
            path.write_bytes(content)
        path = self.source / "README.md"
        path.unlink()
        os.mkfifo(path)
        self.assert_refused(self.run_package())

    def test_rejects_unsafe_path_ancestry_and_parent_traversal(self):
        link = self.root / "alias"
        link.symlink_to(self.root, target_is_directory=True)
        cases = (
            {"executable": link / self.executable.name},
            {"source-root": link / self.source.name},
            {"output-dir": link / self.output.name},
            {"executable": self.source / ".." / self.executable.name},
            {"source-root": self.source / ".." / self.source.name},
            {"output-dir": self.source / ".." / self.output.name},
            {"executable": Path("final-executable")},
            {"source-root": Path("source")},
            {"output-dir": Path("artifacts")},
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                self.assert_refused(self.run_package(**arguments))
        reference = self.source / "skills/work-cli/reference"
        saved = reference.with_name("saved")
        reference.rename(saved)
        reference.symlink_to(saved, target_is_directory=True)
        self.assert_refused(self.run_package())

    def test_requires_existing_source_directory_and_output_parent(self):
        for source in (self.root / "missing-source", self.executable):
            with self.subTest(source=source):
                self.assert_refused(self.run_package(**{"source-root": source}))
        missing_parent = self.root / "missing-parent"
        self.assert_refused(self.run_package(**{"output-dir": missing_parent / "artifacts"}))
        self.assertFalse(missing_parent.exists())

    def test_refuses_any_existing_output_without_overwrite_or_cleanup(self):
        for kind in ("empty-directory", "incomplete", "complete-looking", "file", "symlink", "dangling"):
            with self.subTest(kind=kind):
                output = self.root / kind
                if kind in ("empty-directory", "incomplete", "complete-looking"):
                    output.mkdir()
                    if kind != "empty-directory":
                        (output / "work-0.3.0-linux-x86_64").write_bytes(b"foreign")
                    if kind == "complete-looking":
                        for name in ("work-0.3.0-linux-x86_64.sha256",
                                     "work-cli-0.3.0-linux-x86_64.tar.gz",
                                     "work-cli-0.3.0-linux-x86_64.tar.gz.sha256"):
                            (output / name).write_bytes(b"foreign")
                elif kind == "file":
                    output.write_bytes(b"foreign")
                else:
                    output.symlink_to(self.source if kind == "symlink" else self.root / "absent")
                before = output.lstat()
                result = self.run_package(**{"output-dir": output})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("refused", result.stderr)
                self.assertEqual(output.lstat(), before)
                if kind in ("incomplete", "complete-looking"):
                    self.assertEqual((output / "work-0.3.0-linux-x86_64").read_bytes(), b"foreign")
                elif kind == "file":
                    self.assertEqual(output.read_bytes(), b"foreign")

    def test_failure_after_creation_retains_private_incomplete_output_and_refuses_retry(self):
        module = self.load_packager()
        with patch.object(module.tarfile, "open", side_effect=OSError("injected archive failure")):
            with self.assertRaisesRegex(OSError, "injected archive failure"):
                module.package("0.3.0", "linux-x86_64", self.executable, self.source, self.output)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        binary = self.output / "work-0.3.0-linux-x86_64"
        self.assertEqual(binary.read_bytes(), INERT_EXECUTABLE)
        before = binary.stat()
        result = self.run_package()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(binary.stat(), before)
        self.assertEqual({path.name for path in self.output.iterdir()}, {binary.name})

    def test_colliding_archive_is_not_overwritten_or_cleaned_up(self):
        module = self.load_packager()
        real_open = tarfile.open

        def collide(path, *args, **kwargs):
            path.write_bytes(b"foreign archive")
            return real_open(path, *args, **kwargs)

        with patch.object(module.tarfile, "open", side_effect=collide):
            with self.assertRaises(FileExistsError):
                module.package("0.3.0", "linux-x86_64", self.executable, self.source, self.output)
        self.assertEqual((self.output / "work-cli-0.3.0-linux-x86_64.tar.gz").read_bytes(),
                         b"foreign archive")
        self.assertEqual((self.output / "work-0.3.0-linux-x86_64").read_bytes(), INERT_EXECUTABLE)

    def test_colliding_binary_or_sidecars_are_never_overwritten(self):
        module = self.load_packager()
        real_open = Path.open
        names = ("work-0.3.0-linux-x86_64", "work-0.3.0-linux-x86_64.sha256",
                 "work-cli-0.3.0-linux-x86_64.tar.gz.sha256")
        for index, name in enumerate(names):
            output = self.root / f"collision-{index}"
            collision = output / name

            def collide(path, mode="r", *args, **kwargs):
                if path == collision and mode == "xb":
                    with real_open(path, "xb") as foreign:
                        foreign.write(b"foreign bytes")
                return real_open(path, mode, *args, **kwargs)

            with self.subTest(name=name):
                with patch.object(Path, "open", new=collide):
                    with self.assertRaises(FileExistsError):
                        module.package("0.3.0", "linux-x86_64", self.executable, self.source, output)
                self.assertEqual(collision.read_bytes(), b"foreign bytes")
                self.assertEqual(self.executable.read_bytes(), INERT_EXECUTABLE)
                self.assertEqual(stat.S_IMODE(self.executable.stat().st_mode), 0o440)

    def test_competing_output_directory_creation_does_not_adopt_foreign_directory(self):
        module = self.load_packager()
        real_mkdir = Path.mkdir

        def collide(path, *args, **kwargs):
            real_mkdir(path, *args, **kwargs)
            (path / "foreign-marker").write_bytes(b"foreign directory")
            return real_mkdir(path, *args, **kwargs)

        with patch.object(Path, "mkdir", new=collide):
            with self.assertRaises(FileExistsError):
                module.package("0.3.0", "linux-x86_64", self.executable, self.source, self.output)
        self.assertEqual({path.name for path in self.output.iterdir()}, {"foreign-marker"})
        self.assertEqual((self.output / "foreign-marker").read_bytes(), b"foreign directory")


if __name__ == "__main__":
    unittest.main()
