#!/usr/bin/env python3
"""Extract the built archive and complete two disposable tasks at quota one."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

workspace = Path(__file__).resolve().parents[2]
version = tomllib.loads((workspace / "Cargo.toml").read_text())["workspace"]["package"]["version"]
archive = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else workspace / "target/dist" / f"work-cli-{version}-linux-x86_64.tar.gz"
standalone = archive.parent / f"work-{version}-linux-x86_64"
assert standalone.is_file(), "Missing standalone release binary"
assert standalone.with_name(standalone.name + ".sha256").read_text() == f"{hashlib.sha256(standalone.read_bytes()).hexdigest()}  {standalone.name}\n"
assert subprocess.check_output([str(standalone), "--version"], text=True) == f"work {version}\n"
with tempfile.TemporaryDirectory(prefix="work-release-smoke-") as scratch:
    base = Path(scratch)
    # Exercise the standalone asset before extracting its optional bundle. No
    # Python/Git (or any child executable) is available on its PATH.
    native_home = base / "native-home"
    native_home.mkdir()
    native_env = {"HOME": str(native_home), "XDG_DATA_HOME": str(base / "native-data"), "PATH": "/no-tools"}
    native = subprocess.run([str(standalone), "skill", "install", "--all"], cwd=native_home,
        env=native_env, capture_output=True, text=True)
    assert native.returncode == 0, (native.stdout, native.stderr)
    assert json.loads(native.stdout)["authority_modified"] is False
    for agent in [".agents", ".claude", ".codex"]:
        skill = native_home / agent / "skills/work-cli"
        assert (skill / "SKILL.md").read_bytes() == (workspace / "skills/work-cli/SKILL.md").read_bytes()
        assert (skill / "reference/../../../docs/distribution.md").read_bytes() == (workspace / "docs/distribution.md").read_bytes()
    subprocess.run(["tar", "-xzf", str(archive), "-C", str(base)], check=True)
    binaries = list(base.glob("work-cli-*/bin/work"))
    assert len(binaries) == 1
    assert hashlib.sha256(binaries[0].read_bytes()).digest() == hashlib.sha256(standalone.read_bytes()).digest(), "Standalone binary differs from qualified bundle"
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
        checkout = Path(allocation["destination"])
        (checkout / "work.txt").write_text(f"Completed {task}\n")
        for args in [["add", "work.txt"], ["commit", "-m", f"Complete {task}"]]:
            subprocess.run(["/usr/bin/git", *args], cwd=checkout, env=environment, check=True, capture_output=True)
        commit = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=checkout, env=environment, text=True).strip()
        assert work("finish", task)["task_finished"]
        assert work("remove", task)["outcome"] == "preview"
        assert Path(allocation["destination"]).is_dir()
        removed = work("remove", task, "--confirm-stopped")
        assert removed["outcome"] == "removed"
        preserved = f"refs/work-preserved/{allocation['checkout']}/{commit}"
        assert preserved in removed["preserved_refs"]
        assert subprocess.check_output(["/usr/bin/git", "rev-parse", preserved], cwd=repo, env=environment, text=True).strip() == commit
        assert not Path(allocation["destination"]).exists()
        assert work("status", "--json")["charged"] == 0
    installer = binaries[0].parents[1] / "tools/work_install.py"
    installed = subprocess.run([sys.executable, str(installer), "install", "--version", version,
        "--archive", str(archive), "--checksum", str(archive) + ".sha256",
        "--bin-dir", str(base / "bin"), "--data-dir", str(base / "native-data/work-cli"),
        "--skills-dir", str(base / "agent-skills")], env=environment, capture_output=True, text=True)
    assert installed.returncode == 0, (installed.stdout, installed.stderr)
    assert subprocess.check_output([str(base / "bin/work"), "--version"], env=environment, text=True) == f"work {version}\n"
    assert (base / "agent-skills/work-cli/SKILL.md").is_file()
    assert (base / "bin/work-install").is_file()
    subprocess.run([str(base / "bin/work-install"), "--help"], env=environment, check=True, capture_output=True)
    assert (base / "agent-skills/work-cli/reference/../../../docs/distribution.md").is_file()
    # Native registration and the optional helper share links/locking and can
    # switch instruction snapshots without deleting either prior snapshot.
    prior = (base / "native-data/work-cli/skill-current").resolve()
    native = subprocess.run([str(standalone), "skill", "install", "--all"], cwd=native_home,
        env=native_env, capture_output=True, text=True)
    assert native.returncode == 0, (native.stdout, native.stderr)
    assert prior.is_dir()
    assert (base / "agent-skills/work-cli/SKILL.md").is_file()
    print("Artifact smoke passed: standalone native skill install without Python/Git; two-task lifecycle, preservation, explicit removal and optional helper interoperability verified.")
