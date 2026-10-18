"""Opt-in launcher contract tests; only local fake executables are launched."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "tools/qualification/acp_probe_wrapper.py"


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
print(json.dumps({"fixture_executed": True, "cleanup_outcome": "verified-empty",
                  "reasons": [os.environ["PROVIDER_KEY"]], "secret": os.environ["PROVIDER_KEY"]}), flush=True)
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
                        PROVIDER_KEY="secret-do-not-record", PROBE_LOG=str(self.probe_log))

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
        for path in self.evidence.iterdir():
            self.assertEqual(path.stat().st_mode & 0o077, 0)
            self.assertNotIn("secret-do-not-record", path.read_text())
            self.assertNotIn("qualified", path.read_text())

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
