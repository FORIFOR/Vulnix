"""Layer 4 Runtime: isolated worker processes with limits and hard kill.

Each worker runs in its own process group (session) so the emergency stop can
SIGKILL it together with every child it spawned.

Deadline (external to the worker): `run()` fixes a deadline on the monotonic clock
when the process starts. If the worker has not exited by then, its process group
(and, when confined, its cgroup) is killed and confirmed dead, and the result is
`timed_out`: whatever the worker printed is not a successful result, even valid
JSON written just before the kill or an exit that the clock places after the
deadline. This does not depend on the worker's own SIGALRM at all.

Platforms: POSIX only (process groups, killpg, RLIMIT_CPU; this module imports
`resource`, which Windows lacks). Workers are not run on Windows at all, so none of
this is claimed there.
What "stopped" covers: the worker's process group, and for a confined worker (Linux,
real-service L2) its cgroup, which also holds a descendant that left the group.
Without confinement (always on macOS; on Linux for unconfined runs such as L1) a
descendant that calls setsid() itself is NOT reached by the kill and
`stop_confirmed` does not cover it. If such a descendant still holds the worker's
output when the worker is gone, the run is rejected (`pipes_held`, output
discarded); if it closed the output first, it can outlive the run unnoticed.
"""
from __future__ import annotations

import os
import re
import resource
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field


class RuntimeLimitError(Exception):
    pass


@dataclass
class WorkerResult:
    returncode: int
    stdout: str
    stderr: str
    killed: bool
    elapsed_s: float
    # set by the runtime from its own clock, never from the worker's output
    timed_out: bool = False
    deadline_s: float | None = None
    last_stage: str | None = None              # last stage the worker announced (progress markers)
    stages: tuple = field(default_factory=tuple)   # ((stage, ms since start), ...)
    # after a deadline kill: the process group (and, when confined, the cgroup) is confirmed
    # empty. Without confinement this says nothing about a descendant that left the group.
    stop_confirmed: bool | None = None
    pid: int | None = None                     # also the process group id
    # the worker's pipes were still open after it and its group were gone: something outside
    # the group (an escaped descendant) holds them, so nothing read from them is trusted
    pipes_held: bool = False
    output_truncated: bool = False


# Progress markers a worker writes on stderr when told to (http_probe: --progress stderr).
# Only whole lines ending in "\n" that are exactly a marker with a known stage count, and
# only when the caller asked for progress; they are removed from `stderr`.
PROGRESS_STAGES = frozenset({"connect", "tls", "send", "first_byte", "body", "report"})
_MARKER = re.compile(rb"@@vulnix-stage ([a-z_]{1,32})")
MAX_CAPTURE = 1_000_000                       # bytes kept per stream; the rest is read and dropped
MAX_STAGES = 32                               # stage events kept (the latest)
_READ_CHUNK = 65536
_PIPE_GRACE_S = 1.0                           # after the worker and its group are gone

class HeldSessions:
    """Thread-safe registry of confinement sessions in use (shared between pools)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._items: list = []

    def add(self, session) -> None:
        with self._lock:
            if not any(x is session for x in self._items):
                self._items.append(session)

    def remove(self, session) -> None:
        with self._lock:
            self._items = [x for x in self._items if x is not session]

    def snapshot(self) -> list:
        with self._lock:
            return list(self._items)


class WorkerPool:
    def __init__(self, max_concurrent: int = 4, cpu_seconds: int = 60, held: "HeldSessions | None" = None,
                 clock=time.monotonic):
        self._clock = clock                        # monotonic; injectable for tests
        self._sem = threading.BoundedSemaphore(max_concurrent)
        self._cpu = cpu_seconds
        self._procs: dict[int, subprocess.Popen] = {}
        self._sessions: dict[int, object] = {}
        # confinement sessions from apply until their teardown has finished. Shared
        # by every pool of one service, so replacing the pool (a workspace reset)
        # does not hide a confined process that is still being torn down.
        self._held = held if held is not None else HeldSessions()
        self._lock = threading.Lock()
        self._closed = False

    def run(self, argv: list[str], timeout_s: float, *, extra_env: dict[str, str] | None = None,
            session=None, permit=None, progress: bool = False) -> WorkerResult:
        """`session` is a kernel confinement session (confinement.py): the worker is
        started inside it, and killing the worker kills everything in it.
        `progress`: record the stage markers the worker writes on stderr."""
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
                    argv, stdin=subprocess.DEVNULL,       # never the control plane's terminal or socket
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,   # bytes: decoded once, at the end
                    start_new_session=True, close_fds=True, env=proc_env,
                    preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu)),
                )
                t0 = self._clock()
                deadline = t0 + timeout_s               # fixed at start, on the monotonic clock
                self._procs[proc.pid] = proc
                if session is not None:
                    self._sessions[proc.pid] = session
            out, err = _Capture(), _Capture()
            stages: list = []
            readers = [threading.Thread(target=_drain, args=(proc.stdout, out, None), daemon=True),
                       threading.Thread(target=_drain, args=(proc.stderr, err,
                                                             (stages, self._clock, t0) if progress else None),
                                        daemon=True)]
            for r in readers:
                r.start()
            timed_out = False
            stop_confirmed = None
            try:
                proc.wait(timeout=max(0.0, deadline - self._clock()))
            except subprocess.TimeoutExpired:
                timed_out = True
            if not timed_out and self._clock() > deadline:
                # it exited, but the runtime's own clock puts that after the deadline:
                # not a success, whatever it printed
                timed_out = True
            if timed_out:
                if session is not None:
                    session.kill()
                _killpg(proc.pid)
                stop_confirmed = not self.confirm_stopped([proc.pid])
            elif self.group_alive(proc.pid):
                # the worker exited but left something in its group (which may hold the
                # pipes open): nothing a worker starts outlives it
                _killpg(proc.pid)
            # One bounded wait for both pipes: a pipe still open now is held by something
            # outside the (dead) group, and what came through it is not trusted.
            grace_end = time.monotonic() + _PIPE_GRACE_S
            for r in readers:
                r.join(timeout=max(0.0, grace_end - time.monotonic()))
            # The readers of held pipes are left to end on their own (daemon threads): closing an
            # fd another thread is blocked reading could let that thread read a reused fd.
            pipes_held = any(r.is_alive() for r in readers)
            returncode = proc.poll()
            if returncode is None:                      # not reaped (survivor): reported, not waited for
                returncode = -signal.SIGKILL
            killed = timed_out or returncode == -signal.SIGKILL
            last = stages[-1][0] if stages else None
            return WorkerResult(returncode, "" if pipes_held else out.text(), "" if pipes_held else err.text(),
                                killed, self._clock() - t0, timed_out=timed_out, deadline_s=timeout_s,
                                last_stage=last, stages=tuple(stages), stop_confirmed=stop_confirmed,
                                pid=proc.pid, pipes_held=pipes_held,
                                output_truncated=out.truncated or err.truncated)
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
            sessions = list(self._sessions.values()) + [x for x in self._held.snapshot()
                                                         if x not in self._sessions.values()]
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

    def confirm_stopped(self, pids: list[int], confirm_timeout_s: float = 5.0) -> list[int]:
        """Kill `pids` (and the cgroups of confined ones) and keep killing until they
        are confirmed dead or the time is up. Returns the ones NOT confirmed dead.
        The kill is repeated because a worker started through sudo may not have
        joined its cgroup yet when the first kill arrives."""
        if not pids:
            return []
        deadline = time.monotonic() + confirm_timeout_s
        last_kill = 0.0
        while True:
            alive = self.still_running(pids)        # look first: nothing dead is signalled again
            if not alive:
                return []
            now = time.monotonic()
            if now - last_kill >= 0.25:
                last_kill = now
                for sess in self.sessions_for(alive):
                    sess.kill()
                for pid in alive:
                    _killpg(pid)
                alive = self.still_running(alive)
            if not alive or time.monotonic() > deadline:
                return alive
            time.sleep(0.02)

    def hold(self, session) -> None:
        self._held.add(session)

    def release(self, session) -> None:
        self._held.remove(session)

    def busy_sessions(self) -> list:
        """Held confinement sessions that still contain a process (e.g. while the
        probe runs, or between the worker being reaped and the end of the cgroup's
        teardown). A session that cannot say counts as busy."""
        busy = []
        for x in self._held.snapshot():
            try:
                if not getattr(x, "empty")():
                    busy.append(x)
            except Exception:
                busy.append(x)
        return busy

    def sessions_for(self, pids: list[int]) -> list:
        with self._lock:
            return [self._sessions[p] for p in pids if p in self._sessions]

    def terminate_active(self, confirm_timeout_s: float = 5.0) -> list[int]:
        """Kill every worker that is running now WITHOUT closing the pool, wait
        until they are confirmed dead, and return the ones that are not."""
        with self._lock:
            pids = list(self._procs)
        for sess in self.busy_sessions():
            sess.kill()
        return self.confirm_stopped(pids, confirm_timeout_s)

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


class _Capture:
    """Bytes kept up to MAX_CAPTURE; the rest is read (so the worker never blocks) and dropped."""

    def __init__(self):
        self.parts: list[bytes] = []
        self.size = 0
        self.truncated = False

    def add(self, data: bytes) -> None:
        room = MAX_CAPTURE - self.size
        if len(data) > room:
            self.truncated = True
            data = data[:max(0, room)]
        if data:
            self.parts.append(data)
            self.size += len(data)

    def text(self) -> str:
        return b"".join(self.parts).decode("utf-8", "replace")   # a target cannot make decoding raise


def _drain(stream, cap: _Capture, markers) -> None:
    """Read a worker stream in chunks (never a whole unbounded line in memory). With
    `markers` (stderr, progress requested), whole lines that are exactly a stage marker are
    recorded with the runtime's own time and left out of the capture."""
    pending = b""
    in_long_line = False                                # the rest of an over-long line is never a marker
    try:
        fd = stream.fileno()
        while True:
            chunk = os.read(fd, _READ_CHUNK)
            if not chunk:
                break
            if markers is None:
                cap.add(chunk)
                continue
            pending += chunk
            *lines, pending = pending.split(b"\n")
            for line in lines:
                if in_long_line:                        # the end of a line already passed on
                    cap.add(line + b"\n")
                    in_long_line = False
                else:
                    _line(line + b"\n", cap, markers)
            if len(pending) > 4096:                     # a long line is no marker: pass it on
                cap.add(pending)
                pending = b""
                in_long_line = True
        if pending:
            cap.add(pending)
    except (OSError, ValueError):
        pass


def _line(line: bytes, cap: _Capture, markers) -> None:
    stages, clock, t0 = markers
    m = _MARKER.fullmatch(line[:-1])
    if m and m.group(1).decode() in PROGRESS_STAGES:
        stages.append((m.group(1).decode(), round((clock() - t0) * 1000)))
        del stages[:-MAX_STAGES]
        return
    cap.add(line)

