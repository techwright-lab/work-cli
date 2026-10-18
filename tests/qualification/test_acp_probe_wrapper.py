"""Opt-in launcher contract tests; only local fake executables are launched."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "tools/qualification/acp_probe_wrapper.py"
spec = importlib.util.spec_from_file_location("acp_probe_wrapper", WRAPPER)
wrapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrapper)

GROUP = "/user.slice/user-1000.slice/work-qualification-123-456.scope"
REPORT = dict(
    fixture_executed=True, cleanup_outcome="verified-empty", disposition="accounted",
    paperclip_qualified=True,
    host=dict(uid=1000, runtime_directory_available=True, user_bus_available=True,
              cgroup_v2=True, current_cgroup=GROUP,
              systemd_version="systemd 257 (257.5-1)", git_version="git version 2.49.0"),
    unit="work-qualification-123-456.scope", unit_owner_uid=1000, scope_cgroup=GROUP,
    observed_members=[123, 124, 125, 126],
    observations=[dict(fixture=f, pid=123 + i, cgroup=GROUP) for i, f in enumerate(
        ("setsid", "double_fork_parent_exit", "cwd_fd", "exit_during_inspection"))],
    reasons=[])


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir(mode=0o700)
        self.probe_log = self.root / "probe-log"
        self.probe = self.stub("probe", '''import json, os, sys, time
with open(os.environ["PROBE_LOG"], "a") as f:
    f.write(json.dumps({"argv": sys.argv[1:], "stdin": sys.stdin.read()}) + "\\n")
report = json.loads(os.environ["PROBE_REPORT"])
report.update(secret=os.environ["PROVIDER_KEY"], env=dict(os.environ),
              rawstderr=os.environ["PROVIDER_KEY"], protocolstdout=os.environ["PROVIDER_KEY"])
report["reasons"].append(os.environ["PROVIDER_KEY"])
print(json.dumps(report), flush=True)
print(os.environ["PROVIDER_KEY"], file=sys.stderr)
time.sleep(float(os.environ.get("PROBE_SLEEP", "0")))
''')
        self.delegate = self.stub("delegate", '''import json, os, sys
print(json.dumps({"argv": sys.argv[1:], "executable": sys.argv[0], "stdin": sys.stdin.read(),
                  "key": os.environ["PROVIDER_KEY"],
                  "run_id": os.environ.get("PAPERCLIP_RUN_ID"),
                  "agent_id": os.environ.get("PAPERCLIP_AGENT_ID"),
                  "control": "WORK_QUALIFICATION_CONFIG" in os.environ}))
print("delegate-stderr", file=sys.stderr)
sys.exit(7)
''')
        self.config_path = self.root / "config.json"
        self.config = dict(probe_binary=str(self.probe),
                           pinned_sha256=hashlib.sha256(self.probe.read_bytes()).hexdigest(),
                           evidence_dir=str(self.evidence),
                           delegate_command=[str(self.delegate), "existing-acp-arg"],
                           timeout_seconds=2)
        self.save_config()
        self.env = dict(os.environ, WORK_QUALIFICATION_CONFIG=str(self.config_path),
                        PAPERCLIP_RUN_ID="actual-run-123", PAPERCLIP_AGENT_ID="actual-agent-456",
                        PROVIDER_KEY="secret-do-not-record", PROBE_LOG=str(self.probe_log),
                        PROBE_REPORT=json.dumps(REPORT))

    def stub(self, name, body):
        path = self.root / name
        path.write_text(f"#!{sys.executable}\n" + body)
        path.chmod(0o700)
        return path

    def save_config(self):
        self.config_path.write_text(json.dumps(self.config))
        self.config_path.chmod(0o600)

    def launch(self, env=None):
        return subprocess.run([sys.executable, str(WRAPPER), "--acp", "space arg"],
                              input="protocol-input\n", text=True, capture_output=True,
                              env=self.env if env is None else env, timeout=8)

    def assert_delegate(self, result, run_id="actual-run-123"):
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(json.loads(result.stdout), dict(
            argv=["existing-acp-arg", "--acp", "space arg"], executable=str(self.delegate),
            stdin="protocol-input\n",
            key="secret-do-not-record", run_id=run_id,
            agent_id="actual-agent-456", control=False))
        self.assertEqual(result.stderr, "delegate-stderr\n")

    def records(self):
        return self.probe_log.read_text().splitlines() if self.probe_log.exists() else []

    def completion(self):
        return json.loads((self.evidence / "completion.json").read_text())

    def test_first_launch_preserves_delegate_protocol_and_sanitizes_evidence(self):
        self.assert_delegate(self.launch())
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(json.loads(self.records()[0]), dict(
            argv=["actual-run-123", "codex_local", "--real-user-scope"], stdin=""))
        completion = self.completion()
        self.assertEqual(completion["run_id"], "actual-run-123")
        self.assertEqual(completion["exit_code"], 0)
        self.assertIs(completion["fixture_executed"], True)
        self.assertEqual(completion["cleanup_outcome"], "verified-empty")
        provenance = json.loads((self.evidence / "provenance.json").read_text())
        self.assertEqual(provenance.get("run_id"), "actual-run-123")
        self.assertEqual(provenance.get("agent_id"), "actual-agent-456")
        self.assertIs(provenance["digest_verified"], True)
        self.assertEqual(provenance["uid"], os.getuid())
        report = json.loads((self.evidence / "report.json").read_text())
        self.assertEqual(report, dict(REPORT, paperclip_qualified=False))
        for path in self.evidence.iterdir():
            self.assertEqual(path.stat().st_mode & 0o077, 0)
            self.assertNotIn("secret-do-not-record", path.read_text())
        self.assertIs(completion["paperclip_qualified"], False)

    def test_negative_report_retains_only_static_reasons(self):
        reasons = ["user-bus-or-cgroup-v2-unavailable", "fixture-inspection-failed",
                   "incomplete-or-terminated-during-inspection-membership",
                   "scope-membership-not-proven", "scope-cleanup-not-verified",
                   "real-user-scope-fixture-not-opted-in"]
        self.env["PROBE_REPORT"] = json.dumps(dict(
            REPORT, disposition="unknown_hold", cleanup_outcome="unknown-hold",
            reasons=reasons + ["secret-reason", {"token": "secret-token"}]))
        self.assert_delegate(self.launch())
        report = json.loads((self.evidence / "report.json").read_text())
        self.assertEqual(report["reasons"], reasons)
        self.assertEqual(report["disposition"], "unknown_hold")
        self.assertEqual(report["observations"], REPORT["observations"])
        self.assertNotIn("secret", json.dumps(report))

    def test_malformed_reports_are_bounded_typed_and_unknown(self):
        unknown = wrapper.sanitized(b"not json")
        self.assertEqual(unknown["disposition"], "unknown_hold")
        self.assertIs(unknown["paperclip_qualified"], False)
        for value in ([], None, "secret", {"host": []},
                      {"fixture_executed": True, "fixture_executed": "secret"}):
            with self.subTest(value=value):
                result = wrapper.sanitized(json.dumps(value).encode())
                self.assertEqual(result["disposition"], "unknown_hold")
                self.assertIsNone(result["fixture_executed"])
        malformed = dict(REPORT, disposition="secret", unit="secret.scope",
                         unit_owner_uid=True, scope_cgroup="/../secret",
                         observed_members=[True, 0, -1, "123", 2**32],
                         observations=[dict(fixture="secret", pid=123, cgroup=GROUP)],
                         host=dict(uid=-1, cgroup_v2=1, current_cgroup="secret",
                                   git_version="secret", systemd_version="x" * 161),
                         reasons=["secret"], unknown="secret")
        result = wrapper.sanitized(json.dumps(malformed).encode())
        self.assertEqual(result["disposition"], "unknown_hold")
        self.assertEqual(result["observed_members"], [])
        self.assertEqual(result["observations"], [])
        self.assertNotIn("secret", json.dumps(result))
        self.assertNotEqual(result.get("unit_owner_uid"), True)
        for key in ("observed_members", "observations", "reasons"):
            oversized = dict(REPORT, **{key: [REPORT[key][0] if REPORT[key] else "secret"] * 513})
            result = wrapper.sanitized(json.dumps(oversized).encode())
            self.assertLessEqual(len(result.get(key, [])), 512)
        self.assertEqual(wrapper.sanitized(b'{"fixture_executed":true,"fixture_executed":false}'), unknown)

    def test_cgroup_escape_sanitization_preserves_only_single_backslash_hex(self):
        for path, valid in (
                (r"/app-Hyprland-xdg\x2dterminal.scope", True),
                (r"/app-Hyprland-xdg\\x2dterminal.scope", False),
                (r"/app-Hyprland-xdg\x2terminal.scope", False),
                (r"/app-Hyprland-xdg\xGGterminal.scope", False),
                (r"/app-Hyprland-xdg\q2dterminal.scope", False)):
            with self.subTest(path=path):
                observation = dict(fixture="setsid", pid=123, cgroup=path)
                result = wrapper.sanitized(json.dumps(dict(
                    host=dict(current_cgroup=path), scope_cgroup=path,
                    observations=[observation])).encode())
                if valid:
                    self.assertEqual(result["host"].get("current_cgroup"), path)
                    self.assertEqual(result.get("scope_cgroup"), path)
                    self.assertEqual(result["observations"], [observation])
                else:
                    self.assertNotIn("current_cgroup", result["host"])
                    self.assertNotIn("scope_cgroup", result)
                    self.assertEqual(result["observations"], [])

    def test_repeated_and_concurrent_launches_share_one_claim(self):
        children = [subprocess.Popen([sys.executable, str(WRAPPER), "--acp", "space arg"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, env=self.env) for _ in range(5)]
        results = []
        for child in children:
            out, err = child.communicate("protocol-input\n", timeout=8)
            results.append(subprocess.CompletedProcess([], child.returncode, out, err))
        for result in results:
            self.assert_delegate(result)
        self.env["PAPERCLIP_RUN_ID"] = "resumed-different-run"
        self.assert_delegate(self.launch(), "resumed-different-run")
        self.assertEqual(len(self.records()), 1)

    def test_incomplete_claim_never_retries(self):
        (self.evidence / "probe.claim").write_text("")
        self.assert_delegate(self.launch())
        self.assertEqual(self.records(), [])
        self.assertFalse((self.evidence / "completion.json").exists())

    def test_digest_mismatch_records_failure_and_delegates_without_probe(self):
        self.config["pinned_sha256"] = "0" * 64
        self.save_config()
        self.assert_delegate(self.launch())
        self.assert_delegate(self.launch())
        self.assertEqual(self.records(), [])
        self.assertEqual(self.completion()["status"], "digest-mismatch")

    def test_timeout_records_unknown_and_never_retries(self):
        self.config["timeout_seconds"] = 0.15
        self.save_config()
        self.env["PROBE_SLEEP"] = "5"
        self.assert_delegate(self.launch())
        self.assert_delegate(self.launch())
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(self.completion()["status"], "timeout")
        self.assertIsNone(self.completion()["fixture_executed"])
        self.assertEqual(self.completion()["cleanup_outcome"], "unknown")

    def test_missing_or_invalid_real_ids_never_probe(self):
        for value in (None, "", "bad/id", "x" * 129):
            with self.subTest(value=value):
                env = dict(self.env)
                if value is None:
                    del env["PAPERCLIP_RUN_ID"]
                else:
                    env["PAPERCLIP_RUN_ID"] = value
                self.assert_delegate(self.launch(env), value)
        env = dict(self.env)
        del env["PAPERCLIP_AGENT_ID"]
        result = self.launch(env)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(self.records(), [])

    def test_malformed_config_refuses_arbitrary_exec(self):
        for field, value in (("timeout_seconds", 46), ("timeout_seconds", True),
                             ("delegate_command", ["relative"]),
                             ("pinned_sha256", "invalid"), ("probe_binary", "relative"),
                             ("extra", "unexpected")):
            with self.subTest(field=field, value=value):
                original = dict(self.config)
                self.config[field] = value
                self.save_config()
                result = self.launch()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "qualification-wrapper: invalid configuration\n")
                self.config = original
        self.assertEqual(self.records(), [])

    def test_insecure_paths_and_symlinks_refused(self):
        for path in (self.config_path, self.evidence, self.probe, self.delegate):
            with self.subTest(path=path.name):
                mode = path.stat().st_mode & 0o777
                path.chmod(mode | 0o020)
                result = self.launch()
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "qualification-wrapper: invalid configuration\n")
                path.chmod(mode)
                target = path.with_name(path.name + "-real")
                path.rename(target)
                path.symlink_to(target)
                result = self.launch()
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "qualification-wrapper: invalid configuration\n")
                path.unlink()
                target.rename(path)
        self.assertEqual(self.records(), [])

    def test_output_is_bounded_and_unparseable_report_is_source_free(self):
        self.probe.write_text(f"#!{sys.executable}\nprint('secret-do-not-record' * 20000)\n")
        self.config["pinned_sha256"] = hashlib.sha256(self.probe.read_bytes()).hexdigest()
        self.save_config()
        self.assert_delegate(self.launch())
        for path in self.evidence.iterdir():
            self.assertLess(path.stat().st_size, 4096)
            self.assertNotIn("secret-do-not-record", path.read_text())


if __name__ == "__main__":
    unittest.main()
