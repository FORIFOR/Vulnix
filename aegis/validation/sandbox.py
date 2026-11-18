"""Constrained synthetic fixture execution. Fail closed on unsupported hosts."""
import json
import contextlib
import os
import platform
import resource
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

from .test_generator import HARNESS


class SandboxUnavailable(RuntimeError):
    pass


def _limits():
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, 1 << 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))


def _run_linux(code: Path, harness: Path, pool=None, prelaunch=None) -> str:
    """Use the existing cgroup, nftables, network and mount namespace gate."""
    from aegis.artex_bridge import planner_hidden_paths
    from aegis.confinement import ConfinementError, KernelConfinement
    from aegis.runtime import WorkerPool

    conf = KernelConfinement()
    if not conf.status()["ok"]:
        raise SandboxUnavailable("Linux kernel confinement unavailable")
    # A private, empty loopback listener satisfies the confinement canary. The
    # worker can reach no external address or service through this rule.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        try:
            with conf.session("127.0.0.1", listener.getsockname()[1],
                              limits={"pids.max": 16, "memory.max": 512 << 20},
                              namespaces={"hide": planner_hidden_paths(),
                                          "keep": [str(code.parent)]}) as session:
                result = (pool or WorkerPool(max_concurrent=1, cpu_seconds=2)).run(
                    [sys.executable, str(harness), str(code)], 5, session=session,
                    prelaunch=prelaunch)
                if (result.returncode or result.timed_out or result.pipes_held or
                    result.output_truncated):
                    raise SandboxUnavailable("confined synthetic runner failed")
            if session.leftover or session.files_left or session.netns_left:
                raise SandboxUnavailable("synthetic confinement teardown unconfirmed")
            return result.stdout
        except ConfinementError as exc:
            raise SandboxUnavailable("Linux kernel confinement failed") from exc


def run_synthetic_case(source: str, *, pool=None, prelaunch=None) -> dict:
    """Execute only the fixed synthetic fixture, never customer source."""
    system = platform.system()
    if system not in {"Darwin", "Linux"} or (system == "Darwin" and not shutil.which("sandbox-exec")):
        raise SandboxUnavailable("synthetic sandbox unavailable")
    with tempfile.TemporaryDirectory(prefix="vulnix-synthetic-") as temp:
        root = Path(temp).resolve()
        code = root / "api.py"
        harness = root / "test.py"
        code.write_text(source, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        if system == "Linux":
            # The worker uses a fresh UID. No source checkout is mounted back.
            root.chmod(0o755)
            stdout = _run_linux(code, harness, pool, prelaunch)
            if len(stdout) > 4096:
                raise SandboxUnavailable("synthetic output too large")
            parsed = json.loads(stdout)
            if set(parsed) != {"own", "other"}:
                raise SandboxUnavailable("invalid synthetic result")
            return parsed
        home = str(Path.home().resolve())
        # Deny all network calls and home reads. The copied synthetic file is in
        # /private/tmp; no customer checkout or inherited environment is exposed.
        profile = (f'(version 1)(allow default)(deny network*)'
                   f'(deny file-read* (subpath "{home}"))'
                   f'(deny file-write* (subpath "{home}"))')
        cmd = ["sandbox-exec", "-p", profile, sys.executable, "-I", str(harness), str(code)]
        if pool is not None:
            result = pool.run(cmd, 5, extra_env={"PYTHONDONTWRITEBYTECODE": "1"}, cwd=root,
                              prelaunch=prelaunch)
            if (result.returncode or result.timed_out or result.pipes_held or
                result.output_truncated or len(result.stdout) > 4096):
                raise SandboxUnavailable("synthetic runner failed")
            parsed = json.loads(result.stdout)
            if set(parsed) != {"own", "other"}:
                raise SandboxUnavailable("invalid synthetic result")
            return parsed
        with prelaunch() if prelaunch else contextlib.nullcontext():
            proc = subprocess.Popen(cmd, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
                                    preexec_fn=_limits, start_new_session=True)
        try:
            stdout, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired as exc:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            raise SandboxUnavailable("synthetic runner timed out") from exc
        if proc.returncode or len(stdout) > 4096:
            raise SandboxUnavailable("synthetic runner failed")
        parsed = json.loads(stdout)
        if set(parsed) != {"own", "other"}:
            raise SandboxUnavailable("invalid synthetic result")
        return parsed
