#!/usr/bin/env python3
"""Extract the built archive and complete two disposable tasks at quota one."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

archive = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="work-release-smoke-") as scratch:
    base = Path(scratch)
    subprocess.run(["tar", "-xzf", str(archive), "-C", str(base)], check=True)
    binaries = list(base.glob("work-cli-*/bin/work"))
    assert len(binaries) == 1
    repo, root = base / "repo", base / "root"
    repo.mkdir()
    root.mkdir()
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    for args in [["init", "-b", "main"], ["config", "user.name", "Smoke"], ["config", "user.email", "smoke@example.invalid"], ["commit", "--allow-empty", "-m", "initial"]]:
        subprocess.run(["/usr/bin/git", *args], cwd=repo, env=environment, check=True, capture_output=True)
    config = base / "work.toml"
    config.write_text(f'''actor="smoke"
store_dir={json.dumps(str(base / "store"))}
trusted_registry={json.dumps(str(base / "registry"))}
roots=[{json.dumps(str(root))}]
repositories=[{json.dumps(str(repo))}]
[allocation]
repository_limit=1
owner_limit=1
floor_bytes=0
warn_bytes=0
''')
    environment["WORK_CONFIG"] = str(config)

    def work(*args):
        result = subprocess.run([str(binaries[0]), *args], cwd=repo, env=environment, capture_output=True, text=True)
        assert result.returncode == 0, (args, result.stdout, result.stderr)
        return json.loads(result.stdout)

    for task in ["first", "second"]:
        allocation = work("start", "--task", task)
        assert work("start", "--task", task)["checkout"] == allocation["checkout"]
        assert work("status", "--json")["charged"] == 1
        assert work("finish", task)["task_finished"]
        assert work("remove", task)["outcome"] == "preview"
        assert Path(allocation["destination"]).is_dir()
        assert work("remove", task, "--confirm-stopped")["outcome"] == "removed"
        assert not Path(allocation["destination"]).exists()
        assert work("status", "--json")["charged"] == 0
    print("Artifact smoke passed: two interactive tasks, capacity one, explicit removal.")
