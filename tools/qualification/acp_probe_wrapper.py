#!/usr/bin/env python3
"""Opt-in, Linux qualification helper, not work runtime behavior.

WORK_QUALIFICATION_CONFIG names an absolute, owner-private JSON file with exactly
probe_binary, pinned_sha256, evidence_dir, delegate_command (argv list), and
timeout_seconds (0 < n <= 45). Executable paths must be absolute regular files;
all path components must be non-symlink and not group/world writable. Config and
evidence root must be own-UID, with no group/world permissions. Parent prepares
these paths; this helper installs nothing. delegate_command must name the existing
ACP launcher (codex-acp), never raw codex. Its fixed arguments precede wrapper
arguments. Only WORK_QUALIFICATION_CONFIG is removed from the delegated environment.

The evidence root is ONE qualification attempt, shared across runs/resumes. An
exclusive durable probe.claim is never removed, including on crash or failure;
a missing completion means UNKNOWN, not permission to retry. Use a new root only
after human review. Evidence is point-in-time fixture information, never a pass.
Same-UID malicious mutation and power-loss storage guarantees are outside scope.
"""
import hashlib
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid


CONTROL = "WORK_QUALIFICATION_CONFIG"
FIELDS = {"probe_binary", "pinned_sha256", "evidence_dir", "delegate_command",
          "timeout_seconds"}
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
LIMIT = 65536


def checked_open(path, directory=False, private=False):
    """Walk with dirfds: no symlink races or writable ancestors."""
    if (not isinstance(path, str) or not path.startswith("/") or "\x00" in path
            or len(path) > 4096):
        raise ValueError()
    parts = path.split("/")[1:]
    if not parts or any(p in ("", ".", "..") for p in parts):
        raise ValueError()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if not last or directory:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_mode & 0o022:
                raise ValueError()
            if last:
                expected = stat.S_ISDIR if directory else stat.S_ISREG
                if not expected(info.st_mode):
                    raise ValueError()
                if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
                    raise ValueError()
        return fd
    except BaseException:
        os.close(fd)
        raise


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def load_config():
    opened = []
    try:
        fd = checked_open(os.environ.get(CONTROL), private=True)
        with os.fdopen(fd, "rb") as stream:
            raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError()
        cfg = json.loads(raw, object_pairs_hook=unique_object)
        if not isinstance(cfg, dict) or set(cfg) != FIELDS:
            raise ValueError()
        digest = cfg["pinned_sha256"]
        timeout = cfg["timeout_seconds"]
        command = cfg["delegate_command"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError()
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0 < timeout <= 45):
            raise ValueError()
        if (not isinstance(command, list) or not 1 <= len(command) <= 128
                or any(not isinstance(x, str) or "\x00" in x or len(x) > 4096
                       for x in command)):
            raise ValueError()
        for path in (command[0], cfg["probe_binary"]):
            fd = checked_open(path)
            opened.append(fd)
            if not os.fstat(fd).st_mode & 0o111:
                raise ValueError()
        opened.append(checked_open(cfg["evidence_dir"], directory=True, private=True))
        return cfg, opened
    except BaseException:
        for fd in opened:
            os.close(fd)
        raise


def atomic_json(root, name, value):
    temporary = "." + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=root)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, name, src_dir_fd=root, dst_dir_fd=root)
    os.fsync(root)


def capture(probe_fd, argv, timeout):
    """Drain bounded stdout; stderr is discarded, never logged or sent to ACP."""
    with subprocess.Popen(argv, executable=f"/proc/self/fd/{probe_fd}",
                          pass_fds=(probe_fd,), stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          start_new_session=True) as child:
        data = bytearray()
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map() or child.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                    return child.returncode, b"", "timeout"
                for key, _ in selector.select(min(remaining, 0.05)):
                    block = os.read(key.fileobj.fileno(), 8192)
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        data.extend(block[:max(0, LIMIT + 1 - len(data))])
        return child.wait(), bytes(data), "finished"


def sanitized(raw):
    report = {"fixture_executed": None, "cleanup_outcome": "unknown"}
    try:
        parsed = json.loads(raw) if len(raw) <= LIMIT else None
        if not isinstance(parsed, dict):
            return report
        if type(parsed.get("fixture_executed")) is bool:
            report["fixture_executed"] = parsed["fixture_executed"]
        cleanup = parsed.get("cleanup_outcome")
        if cleanup in ("not-started", "verified-empty", "unknown-hold"):
            report["cleanup_outcome"] = cleanup
    except (ValueError, UnicodeError, RecursionError):
        pass
    return report


def qualify(cfg, probe_fd, root):
    run_id = os.environ.get("PAPERCLIP_RUN_ID", "")
    agent_id = os.environ.get("PAPERCLIP_AGENT_ID", "")
    valid_ids = bool(ID.fullmatch(run_id) and ID.fullmatch(agent_id))
    try:
        claim = os.open("probe.claim", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        | os.O_NOFOLLOW, 0o600, dir_fd=root)
    except FileExistsError:
        return
    with os.fdopen(claim, "w") as stream:
        stream.write("attempt-reserved; incomplete means unknown\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(root)  # Reservation MUST be durable before any fixture is launched.
    report = sanitized(b"")
    completion = {"run_id": run_id if valid_ids else None, "exit_code": None,
                  "status": "missing-or-invalid-origin"}
    provenance = {"adapter": "codex_local", "origin_valid": valid_ids,
                  "run_id": run_id if valid_ids else None,
                  "agent_id": agent_id if valid_ids else None,
                  "pinned_sha256": cfg["pinned_sha256"], "digest_verified": False}
    if valid_ids:
        try:
            with os.fdopen(os.dup(probe_fd), "rb") as binary:
                digest = hashlib.file_digest(binary, "sha256").hexdigest()
            if digest != cfg["pinned_sha256"]:
                completion["status"] = "digest-mismatch"
            else:
                provenance["digest_verified"] = True
                code, raw, status = capture(probe_fd, [cfg["probe_binary"], run_id,
                                            "codex_local", "--real-user-scope"],
                                            cfg["timeout_seconds"])
                completion.update(exit_code=code, status=status)
                if status == "finished":
                    report = sanitized(raw)
        except (OSError, ValueError, subprocess.SubprocessError):
            completion["status"] = "probe-error"
    completion.update(report)
    atomic_json(root, "report.json", report)
    atomic_json(root, "provenance.json", provenance)
    atomic_json(root, "completion.json", completion)


def main():
    try:
        cfg, (delegate_fd, probe_fd, root) = load_config()
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        sys.stderr.write("qualification-wrapper: invalid configuration\n")
        return 78
    try:
        qualify(cfg, probe_fd, root)
    except (OSError, ValueError):
        # Safe persistence failure leaves the permanent claim unknown. No raw data.
        pass
    finally:
        os.close(probe_fd)
        os.close(root)
    env = dict(os.environ)
    env.pop(CONTROL, None)
    os.close(delegate_fd)
    try:
        # Preserve argv[0]/script $0 too; trusted same-UID mutation is out of scope.
        os.execve(cfg["delegate_command"][0], cfg["delegate_command"] + sys.argv[1:], env)
    except OSError:
        sys.stderr.write("qualification-wrapper: delegate unavailable\n")
        return 78


if __name__ == "__main__":
    sys.exit(main())
