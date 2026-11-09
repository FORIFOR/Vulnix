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
        self._lock = threading.Lock()
        self._closed = False

    def run(self, argv: list[str], timeout_s: float) -> WorkerResult:
        if not self._sem.acquire(blocking=False):
            raise RuntimeLimitError("concurrency limit reached")
        try:
            with self._lock:
                if self._closed:
                    raise RuntimeLimitError("worker pool closed")
                cpu = self._cpu
                proc = subprocess.Popen(
                    argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    start_new_session=True, close_fds=True, env={"PATH": "/usr/bin:/bin"},
                    preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu)),
                )
                self._procs[proc.pid] = proc
            t0 = time.monotonic()
            killed = False
            try:
                out, err = proc.communicate(timeout=timeout_s)
            except subprocess.TimeoutExpired:
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
            self._sem.release()

    def active_pids(self) -> list[int]:
        with self._lock:
            return list(self._procs)

    def kill_all(self) -> list[int]:
        with self._lock:
            self._closed = True
            pids = list(self._procs)
        for pid in pids:
            _killpg(pid)
        return pids

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
