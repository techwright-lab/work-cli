"""Offline rendered-shell tests; all external tools are owned fixture transcripts."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RENDERER = ROOT / "tools/render_installer.py"
IDENTITY = "Developer ID Application: Installer Fixture (TESTTEAM01)"


class ShellInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.home = self.base / "home"
        self.home.mkdir()
        # Docker's amd64 Rosetta runtime can create .cache/rosetta on shell
        # startup, even for `exit`. Establish that runtime-only baseline first.
        subprocess.run(["/bin/sh", "-c", "exit"], check=True,
                       env={"HOME": str(self.home), "PATH": "/nonexistent"})
        self.home_baseline = self.home_snapshot()
        self.output = self.base / "install.sh"

    def home_snapshot(self):
        return {str(path.relative_to(self.home)): (path.read_bytes() if path.is_file() else None)
                for path in self.home.rglob("*")}

    def render(self, version="1.2.3", identity=IDENTITY, output=None):
        return subprocess.run(
            [sys.executable, str(RENDERER), "--version", version,
             "--developer-id", identity, "--output", str(output or self.output)],
            text=True, capture_output=True)

    def rendered(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)

    def run_shell(self, *args, env=None):
        return subprocess.run(["/bin/sh", str(self.output), *args], text=True,
                              capture_output=True, env=env or {
                                  "PATH": "/nonexistent", "HOME": str(self.home)})

    def test_renderer_embeds_exact_release_and_quoted_identity(self):
        identity = "Developer ID Application: O'Name $(touch NEVER) `id` (TESTTEAM01)"
        result = self.render(identity=identity)
        self.assertEqual(result.returncode, 0, result.stderr)
        syntax = subprocess.run(["/bin/sh", "-n", str(self.output)], capture_output=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        # Read only the literal assignment prefix, not the installer body.
        prefix = self.output.read_text().split("# End release identity.\n")[0]
        probe = subprocess.run(["/bin/sh", "-c", prefix + '\nprintf "%s\\n%s\\n" "$RELEASE_VERSION" "$DEVELOPER_ID"'],
                               cwd=self.base, text=True, capture_output=True)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        self.assertEqual(probe.stdout, f"1.2.3\n{identity}\n")
        self.assertFalse((self.base / "NEVER").exists())
        self.assertNotIn("python", self.output.read_text().lower())
        self.assertNotIn("jq", self.output.read_text())
        self.assertIn("NOT FOR RELEASE PUBLICATION", self.output.read_text())

    def test_renderer_refuses_invalid_versions_and_identities_without_output(self):
        for version in ["", "v1.2.3", "01.2.3", "1.2", "1.2.3-rc1", "1.2.3\n", "1.2.3;id", "../1.2.3"]:
            with self.subTest(version=version):
                self.assertNotEqual(self.render(version=version).returncode, 0)
                self.assertFalse(self.output.exists())
        for identity in ["", " ", "placeholder", "Developer ID Application: X (BAD)",
                         IDENTITY + "\n", IDENTITY + "\r", IDENTITY + "\x01"]:
            with self.subTest(identity=identity):
                self.assertNotEqual(self.render(identity=identity).returncode, 0)
                self.assertFalse(self.output.exists())
        missing = subprocess.run([sys.executable, str(RENDERER), "--version", "1.2.3",
                                  "--output", str(self.output)], capture_output=True)
        self.assertNotEqual(missing.returncode, 0)

    def test_renderer_refuses_existing_outputs_symlinks_and_missing_parents(self):
        self.output.write_text("preserve")
        self.assertNotEqual(self.render().returncode, 0)
        self.assertEqual(self.output.read_text(), "preserve")
        link = self.base / "link"
        link.symlink_to(self.output)
        self.assertNotEqual(self.render(output=link).returncode, 0)
        dangling = self.base / "dangling"
        dangling.symlink_to(self.base / "absent")
        self.assertNotEqual(self.render(output=dangling).returncode, 0)
        self.assertFalse((self.base / "absent").exists())
        self.assertNotEqual(self.render(output=self.base / "missing/install.sh").returncode, 0)
        self.assertFalse((self.base / "missing").exists())

    def test_shell_rejects_invalid_arguments_before_external_tools(self):
        self.rendered()
        cases = [(), ("unknown",), ("--help", "install"), ("install", "extra"),
                 ("install", "--version", "2.0.0"), ("update",),
                 ("rollback", "--confirm-stopped"), ("rollback", "--version", "1.0.0"),
                 ("install", "--confirm-stopped"), ("install", "--bin-dir"),
                 ("install", "--bin-dir", "relative"), ("install", "--bin-dir", "/"),
                 ("install", "--bin-dir", "/tmp/../bin"),
                 ("install", "--bin-dir", "/tmp/./bin"),
                 ("install", "--bin-dir", "/tmp//bin"),
                 ("install", "--bin-dir", "/tmp/bin\nother"),
                 ("install", "--bin-dir", "/tmp/bin\tother"),
                 ("install", "--bin-dir", "/tmp/bin/"),
                 ("install", "--bin-dir", "/tmp/bin", "--bin-dir", "/tmp/other"),
                 ("update", "--confirm-stopped", "--confirm-stopped"),
                 ("rollback", "--version"),
                 ("rollback", "--version", "../1.0.0", "--confirm-stopped"),
                 ("rollback", "--version", "01.0.0", "--confirm-stopped"),
                 ("rollback", "--version", "1.0.0\n", "--confirm-stopped")]
        for args in cases:
            with self.subTest(args=args):
                result = self.run_shell(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("usage:", result.stderr)
                self.assertNotIn("required utility", result.stderr)
        self.assertEqual(self.home_snapshot(), self.home_baseline)

    def fixture(self, **settings):
        tools = self.base / "tools"
        tools.mkdir(exist_ok=True)
        log = self.base / "transcript"
        # Tool execution must be faked: downloading or running a release is forbidden.
        driver = tools / "driver"
        driver.write_text(f'''#!{sys.executable}
import hashlib, json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["TRANSCRIPT"], "a") as f:
    f.write(json.dumps([name, *args]) + "\\n")
settings = json.loads(os.environ["SETTINGS"])
if settings.get("fail") == name:
    sys.exit(1)
if name == "uname": print(settings.get("os", "Linux") if args == ["-s"] else settings.get("arch", "x86_64"))
elif name == "getconf": print(settings.get("libc", "glibc 2.36"))
elif name == "sysctl": print(settings.get("arm64", "1"))
elif name == "sw_vers": print(settings.get("os_version", "15.0"))
elif name == "mktemp":
    if "stage_output" in settings:
        print(settings["stage_output"])
    else:
        p = pathlib.Path(os.environ["STAGE"]); p.mkdir(mode=0o700); print(p)
elif name == "curl":
    dest = pathlib.Path(args[args.index("--output") + 1])
    asset = "work-1.2.3-" + ("macos-arm64" if settings.get("os") == "Darwin" else "linux-x86_64")
    digest = hashlib.sha256(b"inert fixture bytes\\n").hexdigest()
    content = settings.get("sidecar", digest + "  " + asset + "\\n").encode() if args[-1].endswith(".sha256") else b"inert fixture bytes\\n"
    dest.write_bytes(content)
elif name == "wc": print(len(sys.stdin.buffer.read()))
elif name == "cat": sys.stdout.buffer.write(pathlib.Path(args[-1]).read_bytes())
elif name in ("sha256sum", "shasum"):
    print(hashlib.sha256(pathlib.Path(args[-1]).read_bytes()).hexdigest() + "  " + args[-1])
elif name == "rm":
    import shutil
    if args[-1] != os.environ["STAGE"]:
        sys.exit("refusing fixture removal outside the owned stage")
    shutil.rmtree(args[-1])
else: sys.exit("unexpected fixture invocation: " + name)
''')
        driver.chmod(0o755)
        names = ["uname", "getconf", "sysctl", "sw_vers", "mktemp", "curl", "wc", "cat",
                 "sha256sum", "shasum", "rm", "codesign", "spctl", "lipo"]
        for name in names:
            path = tools / name
            if not path.exists():
                path.symlink_to(driver)
        return {"PATH": str(tools), "HOME": str(self.home), "LC_ALL": "C",
                "TRANSCRIPT": str(log), "SETTINGS": json.dumps(settings),
                "STAGE": str(self.base / "stage")}

    def transcript(self):
        log = self.base / "transcript"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def test_preflight_fixed_https_downloads_and_valid_checksum_never_install(self):
        self.rendered()
        env = self.fixture()
        result = self.run_shell("install", env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("activation is not implemented", result.stderr)
        self.assertIn(str(self.home / ".local/bin/work"), result.stderr)
        calls = [call for call in self.transcript() if call[0] == "curl"]
        self.assertEqual(len(calls), 2, self.transcript())
        for call, suffix in zip(calls, [".sha256", ""]):
            self.assertEqual(call[1], "--disable")
            self.assertIn("--fail", call)
            self.assertIn("--location", call)
            self.assertEqual(call[call.index("--proto") + 1], "=https")
            self.assertEqual(call[call.index("--proto-redir") + 1], "=https")
            self.assertEqual(call[-1], "https://github.com/techwright-lab/work-cli/releases/download/v1.2.3/work-1.2.3-linux-x86_64" + suffix)
        self.assertEqual(calls[0][calls[0].index("--max-filesize") + 1], "4096")
        self.assertEqual(calls[1][calls[1].index("--max-filesize") + 1], "268435456")
        self.assertEqual(self.home_snapshot(), self.home_baseline)
        self.assertFalse((self.base / "stage").exists())

    def test_update_and_rollback_explicit_destination_remain_unchanged(self):
        self.rendered()
        target = self.home / "bin with spaces;literal"
        target.mkdir()
        binary = target / "work"
        binary.write_bytes(b"preserve foreign binary")
        env = self.fixture()
        for args in [("update", "--confirm-stopped"),
                     ("rollback", "--version", "0.9.0", "--confirm-stopped")]:
            result = self.run_shell(*args, "--bin-dir", str(target), env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("activation is not implemented", result.stderr)
            self.assertIn(str(binary), result.stderr)
            self.assertEqual(binary.read_bytes(), b"preserve foreign binary")
            self.assertEqual(list(target.iterdir()), [binary])
        # Rollback never resolves or downloads a different release.
        self.assertEqual(len([c for c in self.transcript() if c[0] == "curl"]), 2)

    def test_checksum_sidecar_contract_refuses_malformed_or_mismatched_data(self):
        self.rendered()
        digest = hashlib.sha256(b"inert fixture bytes\n").hexdigest()
        asset = "work-1.2.3-linux-x86_64"
        for sidecar in ["", "a" * 4097, f"{digest}  ../{asset}\n", f"{digest}  other\n",
                        f"{digest} *{asset}\n", f"{digest} {asset}\n",
                        f"{digest}  {asset}\nextra\n", f"{digest}  {asset}\n\n",
                        f"{digest}  {asset}\r\n", f"{digest.upper()}  {asset}\n",
                        f"{'0' * 64}  {asset}\n", f"{'g' * 64}  {asset}\n",
                        f"{digest}  {asset}", f"{digest}\x00  {asset}\n",
                        f"{digest}  {asset}\x00\n"]:
            with self.subTest(sidecar=sidecar[:90]):
                result = self.run_shell("install", env=self.fixture(sidecar=sidecar))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("checksum", result.stderr)
                self.assertNotIn("activation is not implemented", result.stderr)
                self.assertFalse((self.base / "stage").exists())
                self.assertEqual(self.home_snapshot(), self.home_baseline)

    def test_required_utility_and_download_failures_are_closed(self):
        self.rendered()
        for name in ["curl", "mktemp", "wc", "cat", "rm", "sha256sum", "getconf", "uname"]:
            with self.subTest(missing=name):
                env = self.fixture()
                tool = Path(env["PATH"]) / name
                tool.unlink()
                result = self.run_shell("install", env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("required utility", result.stderr)
                self.assertFalse((self.base / "stage").exists())
        for name in ["curl", "mktemp", "wc", "cat", "sha256sum"]:
            with self.subTest(failing=name):
                result = self.run_shell("install", env=self.fixture(fail=name))
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("activation is not implemented", result.stderr)
                self.assertFalse((self.base / "stage").exists())

    def test_failed_staging_never_cleans_an_unvalidated_path(self):
        self.rendered()
        result = self.run_shell("install", env=self.fixture(stage_output="untrusted-stage"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("staging", result.stderr)
        self.assertFalse(any(call[0] in ("rm", "curl") for call in self.transcript()))
        self.assertEqual(self.home_snapshot(), self.home_baseline)

    def test_native_utility_absence_and_failed_inspection_refuse_before_download(self):
        self.rendered()
        for name in ["sysctl", "sw_vers", "shasum", "codesign", "spctl", "lipo"]:
            with self.subTest(missing=name):
                env = self.fixture(os="Darwin")
                (Path(env["PATH"]) / name).unlink()
                start = len(self.transcript())
                result = self.run_shell("install", env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("required utility", result.stderr)
                self.assertFalse(any(call[0] == "curl" for call in self.transcript()[start:]))
        for name in ["sysctl", "sw_vers"]:
            result = self.run_shell("install", env=self.fixture(os="Darwin", fail=name))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsupported", result.stderr)
        self.assertFalse((self.base / "stage").exists())

    def test_native_platform_preflight_including_rosetta(self):
        self.rendered()
        for settings in [{"os": "Darwin", "arch": "arm64", "os_version": "15.0"},
                         {"os": "Darwin", "arch": "x86_64", "os_version": "26.1"}]:
            with self.subTest(settings=settings):
                result = self.run_shell("install", env=self.fixture(**settings))
                self.assertIn("activation is not implemented", result.stderr)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(any("macos-arm64" in c[-1] for c in self.transcript() if c[0] == "curl"))
                self.assertEqual(self.home_snapshot(), self.home_baseline)
        for settings in [{"arch": "aarch64"}, {"os": "FreeBSD"}, {"libc": "glibc 2.35"},
                         {"libc": "musl 1.2.3"}, {"os": "Darwin", "arm64": "0"},
                         {"os": "Darwin", "os_version": "14.0"},
                         {"os": "Darwin", "os_version": "27.0"},
                         {"os": "Darwin", "os_version": "15.0\n26.0"}]:
            with self.subTest(settings=settings):
                count = len(self.transcript())
                result = self.run_shell("install", env=self.fixture(**settings))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unsupported", result.stderr)
                self.assertFalse(any(c[0] == "curl" for c in self.transcript()[count:]))
                self.assertEqual(self.home_snapshot(), self.home_baseline)


if __name__ == "__main__":
    unittest.main()
