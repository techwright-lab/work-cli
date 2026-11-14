"""Portable harness contracts using owned source and MOCK native utility transcripts.

These tests do not qualify Darwin, Git, toolchains, or repository lifecycle behavior.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "tools/qualification/native-macos.sh"


class MacosHarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "input"
        self.source.mkdir()
        (self.source / "Cargo.toml").write_text("owned snapshot\n")
        (self.source / "crates").mkdir()
        (self.source / "crates/lib.rs").write_text("// owned source\n")
        self.destination = self.root / "fixture"
        self.utilities = self.root / "utilities"
        self.utilities.mkdir()
        self.toolchain = self.root / "toolchain"
        (self.toolchain / "bin").mkdir(parents=True)
        self.git_home = self.root / "git-install"
        (self.git_home / "bin").mkdir(parents=True)
        self.helpers = self.git_home / "libexec/git-core"
        self.helpers.mkdir(parents=True)
        self.git = self.git_home / "bin/git"
        self.stub(self.utilities / "uname", 'print({"-s": "Darwin", "-m": "arm64"}[sys.argv[1]])')
        self.stub(self.utilities / "sw_vers", 'print("15.7")')
        self.stub(self.utilities / "sysctl", 'print("0" if sys.argv[-1] == "sysctl.proc_translated" else "1")')
        self.stub(self.utilities / "file", 'print("Mach-O 64-bit executable arm64")')
        self.set_toolchain("1.98.1")
        self.set_git("2.55.0")
        for name in ("git-upload-pack", "git-receive-pack", "git-upload-archive"):
            self.stub(self.helpers / name, 'sys.exit("must not execute helper")')
        self.probe = self.root / "probe.py"
        self.probe.write_text('''import json, os, pathlib, sys
print("fixture-output")
print("fixture-error", file=sys.stderr)
pathlib.Path("probe.json").write_text(json.dumps({
    "cwd": os.getcwd(), "env": dict(os.environ), "args": sys.argv[1:]}))
sys.exit(int(sys.argv[1]) if len(sys.argv) > 1 else 0)
''')
        self.env = dict(os.environ, PATH=f"{self.utilities}:{os.environ['PATH']}",
                        HOME=str(self.root / "real-home"), WORK_CONFIG="real-authority",
                        XDG_STATE_HOME="real-state", CARGO_HOME="real-cargo",
                        RUSTUP_HOME="real-rustup", GIT_DIR="real-repository",
                        AWS_SECRET_ACCESS_KEY="never-inherit-this",
                        CARGO_REGISTRIES_TEST_TOKEN="never-inherit-this",
                        SDKROOT="unselected-host-sdk")

    def stub(self, path, body):
        path.write_text(f"#!{sys.executable}\nimport sys\n{body}\n")
        path.chmod(0o700)

    def set_toolchain(self, version, host="aarch64-apple-darwin"):
        self.stub(self.toolchain / "bin/cargo", f'print("cargo {version} (mock)")')
        self.stub(self.toolchain / "bin/rustc", f'print("rustc {version} (mock)\\nrelease: {version}\\nhost: {host}")')

    def set_git(self, version):
        self.stub(self.git, f'print("git version {version}" if sys.argv[1] == "--version" else {str(self.helpers)!r})')

    def options(self, without_git=False, version="1.98.1", development=False,
                git_version="2.55.0"):
        args = ["--destination", str(self.destination), "--source", str(self.source),
                "--toolchain", version, "--toolchain-dir", str(self.toolchain)]
        if development:
            args.append("--development")
        return args + (["--without-git"] if without_git else
                       ["--git-version", git_version, "--git", str(self.git)])

    def launch(self, args=None, command=None):
        if args is None:
            args = self.options()
        if command is None:
            command = [sys.executable, str(self.probe), "0", "space arg"]
        return subprocess.run(["bash", str(HARNESS), *args, "--", *command],
                              env=self.env, text=True, capture_output=True, timeout=15)

    def assert_refused(self, result, reason):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(reason, result.stderr)
        self.assertFalse((self.destination / "source/probe.json").exists())

    def test_help_describes_explicit_non_gate_mode(self):
        result = subprocess.run(["bash", str(HARNESS), "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for text in ("--destination", "--git-version", "--git", "--toolchain-dir",
                     "--without-git", "--development", "--sdk-root", "NON-GATE", "retained"):
            self.assertIn(text, result.stdout)

    def test_arguments_are_explicit_and_exclusive(self):
        for args, reason in [([], "--destination"),
                             (self.options() + ["--unknown"], "unknown option"),
                             (self.options() + ["--without-git"], "exclusive"),
                             (self.options() + ["--git", str(self.git)], "duplicate"),
                             (["--destination"], "value"),
                             (self.options() + ["--git-version", "2.56.0"], "duplicate")]:
            with self.subTest(args=args):
                self.assert_refused(self.launch(args), reason)
        self.assert_refused(self.launch(command=[]), "COMMAND")
        self.assertFalse(self.destination.exists())

    def test_nonnative_and_unsupported_hosts_refuse_before_command(self):
        cases = [("uname", 'print("Linux" if sys.argv[1] == "-s" else "arm64")', "native macOS"),
                 ("uname", 'print("Darwin" if sys.argv[1] == "-s" else "x86_64")', "arm64"),
                 ("sysctl", 'print("1")', "translated"),
                 ("sw_vers", 'print("14.7")', "unsupported macOS"),
                 ("sw_vers", 'print("27.0.1")', "unsupported macOS")]
        for utility, body, reason in cases:
            with self.subTest(utility=utility, body=body):
                original = (self.utilities / utility).read_text()
                self.stub(self.utilities / utility, body)
                self.assert_refused(self.launch(), reason)
                (self.utilities / utility).write_text(original)
        self.assertFalse(self.destination.exists())

    def test_existing_destination_is_never_reused_or_removed(self):
        self.destination.mkdir()
        sentinel = self.destination / "keep"
        sentinel.write_text("preserve")
        self.assert_refused(self.launch(), "destination")
        self.assertEqual(sentinel.read_text(), "preserve")
        self.assertEqual(list(self.destination.iterdir()), [sentinel])

    def test_symlink_destination_parent_is_refused(self):
        parent = self.root / "alias"
        parent.symlink_to(self.source, target_is_directory=True)
        self.destination = parent / "new"
        self.assert_refused(self.launch(), "symlink")
        self.assertFalse((self.source / "new").exists())

    def test_isolated_environment_owned_snapshot_and_fixture_cwd(self):
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        source = self.destination / "source"
        record = json.loads((source / "probe.json").read_text())
        self.assertEqual(record["cwd"], str(source))
        self.assertEqual(record["args"], ["0", "space arg"])
        env = record["env"]
        for key, relative in {"HOME": "home", "XDG_CONFIG_HOME": "config",
                              "XDG_STATE_HOME": "state", "XDG_DATA_HOME": "data",
                              "XDG_CACHE_HOME": "cache", "TMPDIR": "tmp",
                              "CARGO_HOME": "cargo-home", "CARGO_TARGET_DIR": "target"}.items():
            self.assertEqual(env[key], str(self.destination / relative))
            self.assertTrue(Path(env[key]).is_dir())
        self.assertEqual(env["WORK_CONFIG"], "")
        self.assertEqual(env["RUSTC"], str(self.toolchain / "bin/rustc"))
        self.assertEqual(env["RUSTUP_AUTO_INSTALL"], "0")
        self.assertNotIn("SDKROOT", env)
        for key in ("AWS_SECRET_ACCESS_KEY", "CARGO_REGISTRIES_TEST_TOKEN", "GIT_DIR", "RUSTUP_HOME"):
            self.assertNotIn(key, env)
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(env["GIT_EXEC_PATH"], str(self.helpers))
        self.assertEqual((source / "Cargo.toml").stat().st_uid, os.getuid())
        self.assertEqual((source / "Cargo.toml").read_text(), "owned snapshot\n")
        self.assertFalse((self.source / "probe.json").exists())
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)
        evidence = self.destination / "evidence"
        self.assertIn("fixture-output", (evidence / "stdout.log").read_text())
        self.assertIn("fixture-error", (evidence / "stderr.log").read_text())
        metadata = json.loads((evidence / "run.json").read_text())
        self.assertEqual(metadata["mode"], "QUALIFICATION-CANDIDATE")
        self.assertFalse(metadata["support_claim"])
        self.assertEqual(metadata.get("qualification_gates"), {
            "apfs_capabilities": "NOT_CHECKED", "apfs_case_variants": "NOT_CHECKED",
            "sdk_deployment": "NOT_CHECKED", "final_artifacts": "NOT_CHECKED"})
        self.assertEqual(metadata["exit_code"], 0)
        self.assertIsNone(metadata.get("sdk"))
        self.assertEqual(metadata["git"]["path"], str(self.git.resolve()))
        self.assertEqual(metadata["git"]["version"], "2.55.0")
        self.assertEqual(metadata["git"]["exec_path"], str(self.helpers))
        self.assertIn("snapshot_sha256", metadata)
        self.assertNotIn("never-inherit-this", json.dumps(metadata))

    def test_source_copy_excludes_repository_build_and_credentials(self):
        for name in (".git", "target", ".ssh", ".aws", "unapproved"):
            (self.source / name).mkdir()
            (self.source / name / "secret").write_text("not source")
        for name in (".env", ".env.local", "credentials.json", "private.key", ".netrc"):
            (self.source / "crates" / name).write_text("not source")
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        copied = self.destination / "source"
        for name in (".git", "target", ".ssh", ".aws", "unapproved"):
            self.assertFalse((copied / name).exists(), name)
        self.assertEqual(sorted(p.name for p in (copied / "crates").iterdir()), ["lib.rs"])

    def test_source_snapshot_preserves_exact_sqlite_vendor_and_patches(self):
        args = self.options()
        args[args.index("--source") + 1] = str(ROOT)
        result = self.launch(args, command=[sys.executable, "tools/qualification/sqlite/verify.py"])
        self.assertEqual(result.returncode, 0, result.stderr)
        copied = self.destination / "source"
        pin = json.loads((ROOT / "patches/sqlite/provenance.json").read_text())
        for name, expected in pin["vendored_files"].items():
            with self.subTest(name=name):
                path = copied / "vendor/libsqlite3-sys" / name
                self.assertTrue(path.is_file(), name)
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)
        for path in (ROOT / "patches/sqlite").rglob("*"):
            if path.is_file():
                self.assertEqual((copied / path.relative_to(ROOT)).read_bytes(), path.read_bytes())

    def test_vendor_snapshot_excludes_git_state_and_user_config(self):
        vendor = self.source / "vendor/libsqlite3-sys"
        vendor.mkdir(parents=True)
        (vendor / ".gitignore").write_text("/target\n")
        (self.source / "patches").mkdir()
        for directory in (vendor, self.source / "patches", self.source / "crates"):
            (directory / ".git").mkdir()
            (directory / ".git/refs").write_text("not source")
            for name in (".gitconfig", ".git-credentials", "credentials.toml", ".env"):
                (directory / name).write_text("not source")
            nested = directory / "nested"
            nested.mkdir()
            (nested / ".git").write_text("gitdir: /real/repository\n")
            (nested / ".gitignore").write_text("not the pinned member\n")
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        copied = self.destination / "source"
        self.assertTrue((copied / "vendor/libsqlite3-sys/.gitignore").is_file())
        self.assertEqual((copied / "vendor/libsqlite3-sys/.gitignore").read_text(), "/target\n")
        self.assertEqual([p.relative_to(copied).as_posix() for p in copied.rglob(".git*")],
                         ["vendor/libsqlite3-sys/.gitignore"])
        self.assertFalse(list(copied.rglob("credentials*")))
        self.assertFalse(list(copied.rglob(".env*")))

    def test_vendor_gitignore_symlink_is_never_followed(self):
        vendor = self.source / "vendor/libsqlite3-sys"
        vendor.mkdir(parents=True)
        secret = self.root / "secret"
        secret.write_text("never copy")
        (vendor / ".gitignore").symlink_to(secret)
        self.assert_refused(self.launch(), "symlink")
        self.assertEqual(secret.read_text(), "never copy")

    def test_vendor_gitignore_directory_is_not_a_source_file(self):
        (self.source / "vendor/libsqlite3-sys/.gitignore").mkdir(parents=True)
        self.assert_refused(self.launch(), "regular source file")

    def test_vendor_and_patch_symlink_escapes_are_refused(self):
        for name in ("vendor", "patches"):
            with self.subTest(name=name):
                (self.source / name).symlink_to(self.root / "unavailable", target_is_directory=True)
                self.destination = self.root / ("fixture-" + name)
                self.assert_refused(self.launch(), "symlink")
                (self.source / name).unlink()

    def test_source_symlink_escape_refuses_without_reading_target(self):
        secret = self.root / "secret"
        secret.write_text("never copy")
        (self.source / "crates/escape.rs").symlink_to(secret)
        self.assert_refused(self.launch(), "symlink")
        self.assertEqual(secret.read_text(), "never copy")

    def test_failure_preserves_evidence_and_propagates_status(self):
        result = self.launch(command=[sys.executable, str(self.probe), "23"])
        self.assertEqual(result.returncode, 23, result.stderr)
        evidence = self.destination / "evidence"
        self.assertEqual(json.loads((evidence / "run.json").read_text())["exit_code"], 23)
        self.assertIn("fixture-output", (evidence / "stdout.log").read_text())
        self.assertIn("retained", result.stderr)
        self.assertTrue((self.destination / "source/probe.json").exists())

    def test_git_exact_version_native_architecture_and_helper_validation(self):
        self.set_git("2.55.0.vendor")
        self.assert_refused(self.launch(), "exact Git")
        self.assertTrue((self.destination / "evidence/run.json").exists())

    def test_git_fixture_256_and_canonical_symlink(self):
        self.set_git("2.56.0")
        alias = self.root / "selected-git"
        alias.symlink_to(self.git)
        args = self.options()
        args[args.index("--git-version") + 1] = "2.56.0"
        args[args.index("--git") + 1] = str(alias)
        result = self.launch(args)
        self.assertEqual(result.returncode, 0, result.stderr)
        metadata = json.loads((self.destination / "evidence/run.json").read_text())
        self.assertEqual(metadata["git"]["path"], str(self.git))

    def test_git_wrong_architecture_refused(self):
        self.stub(self.utilities / "file", 'print("Mach-O 64-bit executable " + ("x86_64" if sys.argv[-1].endswith("/git") else "arm64"))')
        self.assert_refused(self.launch(), "arm64")

    def test_missing_git_helpers_refused(self):
        (self.helpers / "git-upload-pack").unlink()
        self.assert_refused(self.launch(), "helper")

    def test_git_selection_requires_absolute_path_and_supported_fixture(self):
        args = self.options()
        args[args.index("--git") + 1] = "relative/git"
        self.assert_refused(self.launch(args), "absolute")
        args = self.options()
        args[args.index("--git-version") + 1] = "2.57.0"
        self.assert_refused(self.launch(args), "Git fixture")
        self.assertFalse(self.destination.exists())

    def test_missing_or_wrong_installed_toolchain_refuses_without_installing(self):
        (self.toolchain / "bin/cargo").unlink()
        self.assert_refused(self.launch(), "installed toolchain")
        self.assertFalse((self.destination / "cargo-home/credentials.toml").exists())

    def test_toolchain_version_and_native_host_must_match(self):
        self.set_toolchain("1.99.1", "x86_64-apple-darwin")
        self.assert_refused(self.launch(), "toolchain")

    def test_qualification_cannot_use_development_toolchain(self):
        self.set_toolchain("1.99.1")
        self.assert_refused(self.launch(self.options(version="1.99.1")), "1.98.1")
        self.assertFalse(self.destination.exists())

    def test_unsafe_destination_ancestor_is_refused(self):
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        nested = unsafe / "owned"
        nested.mkdir(mode=0o700)
        self.destination = nested / "fixture"
        self.assert_refused(self.launch(), "unsafe destination ancestor")
        self.assertFalse(self.destination.exists())

    def test_inconsistent_rustc_version_report_is_refused(self):
        self.stub(self.toolchain / "bin/rustc", 'print("rustc 1.99.1 (mock)\\nrelease: 1.98.1\\nhost: aarch64-apple-darwin")')
        self.assert_refused(self.launch(), "toolchain")

    def test_toolchain_shims_are_refused(self):
        shim = self.root / "rustup"
        self.stub(shim, 'sys.exit("must not execute rustup")')
        (self.toolchain / "bin/cargo").unlink()
        (self.toolchain / "bin/cargo").symlink_to(shim)
        self.assert_refused(self.launch(), "rustup shims")

    def test_missing_command_is_reported_with_retained_evidence(self):
        result = self.launch(command=[str(self.root / "missing-command")])
        self.assert_refused(result, "refused")
        metadata = json.loads((self.destination / "evidence/run.json").read_text())
        self.assertEqual(metadata["exit_code"], 1)
        self.assertIn("error", metadata)

    def test_explicit_sdk_directory_is_recorded_without_discovery_or_qualification(self):
        sdk = self.root / "installed sdk"
        sdk.mkdir()
        alias = self.root / "selected-sdk"
        alias.symlink_to(sdk, target_is_directory=True)
        self.stub(self.utilities / "xcrun", 'sys.exit("SDK discovery forbidden")')
        for mode in ("qualification", "development", "without-git"):
            with self.subTest(mode=mode):
                self.destination = self.root / ("fixture-" + mode)
                args = self.options(development=mode == "development", without_git=mode == "without-git")
                result = self.launch(args + ["--sdk-root", str(alias)])
                self.assertEqual(result.returncode, 0, result.stderr)
                env = json.loads((self.destination / "source/probe.json").read_text())["env"]
                self.assertEqual(env["SDKROOT"], str(sdk))
                metadata = json.loads((self.destination / "evidence/run.json").read_text())
                self.assertEqual(metadata["sdk"], {"selection": str(alias), "directory": str(sdk)})
                self.assertEqual(metadata["qualification_gates"]["sdk_deployment"], "NOT_CHECKED")
                self.assertFalse(metadata["support_claim"])
        self.assertEqual(list(sdk.iterdir()), [])

    def test_sdk_selection_requires_absolute_existing_directory(self):
        not_directory = self.root / "sdk-file"
        not_directory.write_text("not an SDK directory")
        cases = (("relative/sdk", "absolute"),
                 (str(self.root / "missing-sdk"), "existing directory"),
                 (str(not_directory), "existing directory"))
        for index, (name, reason) in enumerate(cases):
            with self.subTest(name=name):
                self.destination = self.root / ("fixture-sdk-" + str(index))
                self.assert_refused(self.launch(self.options() + ["--sdk-root", name]), reason)
        self.assertEqual(not_directory.read_text(), "not an SDK directory")

    def test_sdk_argument_requires_one_value(self):
        for extra, reason in ((["--sdk-root"], "missing value"),
                              (["--sdk-root", str(self.root), "--sdk-root", str(self.root)], "duplicate")):
            with self.subTest(extra=extra):
                self.assert_refused(self.launch(self.options() + extra), reason)
        self.assertFalse(self.destination.exists())

    def test_development_with_git_permits_27_and_selected_installed_toolchains(self):
        self.stub(self.utilities / "sw_vers", 'print("27.0.1")')
        for release in ("1.98.1", "1.99.1"):
            for git_version in ("2.55.0", "2.56.0"):
                with self.subTest(release=release, git_version=git_version):
                    self.destination = self.root / ("fixture-" + release + "-" + git_version)
                    self.set_toolchain(release)
                    self.set_git(git_version)
                    result = self.launch(self.options(development=True, version=release,
                                                      git_version=git_version))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    record = json.loads((self.destination / "source/probe.json").read_text())
                    env = record["env"]
                    for key, relative in {"HOME": "home", "XDG_CONFIG_HOME": "config",
                                          "XDG_STATE_HOME": "state", "CARGO_HOME": "cargo-home"}.items():
                        self.assertEqual(env[key], str(self.destination / relative))
                    self.assertEqual(env["WORK_CONFIG"], "")
                    self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
                    self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
                    self.assertEqual(env["GIT_EXEC_PATH"], str(self.helpers))
                    selected = Path(env["PATH"].split(os.pathsep)[0]) / "git"
                    self.assertEqual(selected.resolve(), self.git.resolve())
                    for key in ("GIT_DIR", "AWS_SECRET_ACCESS_KEY", "CARGO_REGISTRIES_TEST_TOKEN"):
                        self.assertNotIn(key, env)
                    metadata = json.loads((self.destination / "evidence/run.json").read_text())
                    self.assertEqual(metadata["mode"], "DEVELOPMENT/NON-GATE")
                    self.assertFalse(metadata["support_claim"])
                    self.assertTrue(all(gate == "NOT_CHECKED"
                                        for gate in metadata["qualification_gates"].values()))
                    self.assertEqual(metadata["toolchain"]["version"], release)
                    self.assertEqual(metadata["git"]["version"], git_version)
                    self.assertEqual(metadata["git"]["path"], str(self.git))

    def test_development_still_requires_explicit_supported_git_fixture(self):
        no_git_selection = self.options(without_git=True)[:-1] + ["--development"]
        cases = [(no_git_selection, "required --git-version"),
                 (self.options(development=True, git_version="2.48.0"), "Git fixture"),
                 (self.options(development=True, version="1.100.0"), "1.98.1")]
        for args, reason in cases:
            with self.subTest(args=args):
                self.assert_refused(self.launch(args), reason)
        self.assertFalse(self.destination.exists())

    def test_development_git_binding_rejects_exact_version_mismatch(self):
        self.set_git("2.55.0.vendor")
        self.assert_refused(self.launch(self.options(development=True)), "exact Git")

    def test_development_git_binding_rejects_missing_helper(self):
        (self.helpers / "git-upload-pack").unlink()
        self.assert_refused(self.launch(self.options(development=True)), "helper")

    def test_development_git_binding_rejects_wrong_architecture(self):
        self.stub(self.utilities / "file", 'print("Mach-O 64-bit executable " + ("x86_64" if sys.argv[-1].endswith("/git") else "arm64"))')
        self.assert_refused(self.launch(self.options(development=True)), "arm64")

    def test_development_git_binding_rejects_unsafe_executable(self):
        self.git.chmod(0o777)
        self.assert_refused(self.launch(self.options(development=True)), "unsafe executable")

    def test_selected_git_identity_change_refuses_in_both_modes(self):
        self.stub(self.git, f'''from pathlib import Path
if sys.argv[1] == "--version":
    print("git version 2.55.0")
else:
    path = Path(__file__)
    path.write_text(path.read_text() + "# changed during probe\\n")
    print({str(self.helpers)!r})''')
        for development in (False, True):
            with self.subTest(development=development):
                self.destination = self.root / ("fixture-" + str(development))
                self.assert_refused(self.launch(self.options(development=development)),
                                    "changed before command")

    def test_qualification_macos_26_remains_a_candidate(self):
        self.stub(self.utilities / "sw_vers", 'print("26.0.1")')
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        metadata = json.loads((self.destination / "evidence/run.json").read_text())
        self.assertEqual(metadata["mode"], "QUALIFICATION-CANDIDATE")

    def test_without_git_is_explicit_development_not_a_gate(self):
        self.git.unlink()
        self.set_toolchain("1.99.1")
        self.stub(self.utilities / "sw_vers", 'print("27.0.1")')
        result = self.launch(self.options(without_git=True, version="1.99.1"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DEVELOPMENT/NON-GATE", result.stderr)
        record = json.loads((self.destination / "source/probe.json").read_text())
        self.assertNotIn("GIT_EXEC_PATH", record["env"])
        self.assertEqual(record["env"]["GIT_CONFIG_GLOBAL"], "/dev/null")
        # An actual git invocation is refused, even if a system Git is installed.
        git_result = subprocess.run([record["env"]["PATH"].split(os.pathsep)[0] + "/git", "status"],
                                    capture_output=True, text=True)
        self.assertNotEqual(git_result.returncode, 0)
        self.assertIn("NON-GATE", git_result.stderr)
        metadata = json.loads((self.destination / "evidence/run.json").read_text())
        self.assertEqual(metadata["mode"], "DEVELOPMENT/NON-GATE")
        self.assertIsNone(metadata["git"])


if __name__ == "__main__":
    unittest.main()
