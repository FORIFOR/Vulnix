"""Layer 4 Runtime: isolated worker processes with limits and hard kill.

Each worker runs in its own process group (session) so the emergency stop can
SIGKILL it together with every child it spawned.
"""
from __future__ import annotations

import os
import resource
import signal
import subprocess
import threading
import time
from dataclasses import dataclass


class RuntimeLimitError(Exception):
    pass


@dataclass
class WorkerResult:
    returncode: int
    stdout: str
    stderr: str
    killed: bool
    elapsed_s: float


class WorkerPool:
    def __init__(self, max_concurrent: int = 4, cpu_seconds: int = 60):
        self._sem = threading.BoundedSemaphore(max_concurrent)
        self._cpu = cpu_seconds
        self._procs: dict[int, subprocess.Popen] = {}
        self._sessions: dict[int, object] = {}
        self._lock = threading.Lock()
        self._closed = False

    def run(self, argv: list[str], timeout_s: float, *, extra_env: dict[str, str] | None = None,
            session=None, permit=None) -> WorkerResult:
        """`session` is a kernel confinement session (confinement.py): the worker is
        started inside it, and killing the worker kills everything in it."""
        if not self._sem.acquire(blocking=False):
            raise RuntimeLimitError("concurrency limit reached")
        try:
            with self._lock:
                if self._closed:
                    raise RuntimeLimitError("worker pool closed")
                cpu = self._cpu
                proc_env = {"PATH": "/usr/bin:/bin"}
                if extra_env:
                    proc_env.update({str(k): str(v) for k, v in extra_env.items() if v is not None})
                if session is not None:
                    argv = session.wrap(argv, env_keys=tuple(proc_env), cpu_seconds=cpu)
                if permit is not None:
                    # Checked under the same lock that registers the process: whoever
                    # withdraws the permission afterwards finds this worker in the
                    # table and kills it; whoever did so before, stops it here.
                    permit()
                proc = subprocess.Popen(
                    argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    encoding="utf-8", errors="replace",      # a target cannot make decoding raise
                    start_new_session=True, close_fds=True, env=proc_env,
                    preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu)),
                )
                self._procs[proc.pid] = proc
                if session is not None:
                    self._sessions[proc.pid] = session
            t0 = time.monotonic()
            killed = False
            try:
                out, err = proc.communicate(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                if session is not None:
                    session.kill()
                _killpg(proc.pid)
                out, err = proc.communicate()
                killed = True
            killed = killed or proc.returncode == -signal.SIGKILL
            return WorkerResult(proc.returncode, out, err, killed, time.monotonic() - t0)
        finally:
            with self._lock:
                for pid, p in list(self._procs.items()):
                    if p.poll() is not None:
                        self._procs.pop(pid, None)
                        self._sessions.pop(pid, None)
            self._sem.release()

    def active_pids(self) -> list[int]:
        with self._lock:
            return list(self._procs)

    def kill_all(self) -> list[int]:
        with self._lock:
            self._closed = True
            pids = list(self._procs)
            sessions = list(self._sessions.values())
        for sess in sessions:          # confined workers: kill the whole cgroup
            sess.kill()
        for pid in pids:
            _killpg(pid)
        return pids

    def still_running(self, pids: list[int]) -> list[int]:
        """Those of `pids` that are not confirmed dead: the child has not been
        reaped, its process group still exists, or (for a confined worker) its
        cgroup is not known to be empty."""
        with self._lock:
            procs = {pid: self._procs.get(pid) for pid in pids}
            sessions = {pid: self._sessions.get(pid) for pid in pids}
        alive = []
        for pid in pids:
            proc, sess = procs[pid], sessions[pid]
            if ((proc is not None and proc.poll() is None) or self.group_alive(pid)
                    or (sess is not None and not getattr(sess, "empty", lambda: True)())):
                alive.append(pid)
        return alive

    def terminate_active(self, confirm_timeout_s: float = 5.0) -> list[int]:
        """Kill every worker that is running now WITHOUT closing the pool, wait
        until they are confirmed dead, and return the ones that are not."""
        with self._lock:
            pids = list(self._procs)
            sessions = [self._sessions[p] for p in pids if p in self._sessions]
        if not pids:
            return []
        for sess in sessions:
            sess.kill()
        for pid in pids:
            _killpg(pid)
        deadline = time.monotonic() + confirm_timeout_s
        while True:
            alive = self.still_running(pids)
            if not alive or time.monotonic() > deadline:
                return alive
            time.sleep(0.02)

    @staticmethod
    def group_alive(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True


def _killpg(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        # a confined worker is started through sudo, whose process we may not
        # signal; everything in its cgroup is killed by the session instead
        pass
