"""External worker deadline (aegis/runtime.py WorkerPool.run, aegis/gateway.py deadline_report).

The deadline is kept by the runtime on the monotonic clock, independent of the worker's own
SIGALRM: the process group is killed and confirmed dead, the worker's output is not a success,
and the gateway reports the last stage it saw without reading the worker's stdout.
POSIX only (process groups); macOS has no cgroups, so a descendant that leaves the process
group is reached only on Linux through confinement (see runtime docstring)."""
from __future__ import annotations

import json
import os
import secrets
import socket
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path

from aegis.audit import AuditLog
from aegis.authz import ApprovalStore, Engagement, Target, TokenAuthority
from aegis.gateway import Gateway, deadline_report, http_probe_tool
from aegis.network import EgressGuard
from aegis.policy import ArgSpec, Budget, Tool
from aegis.runtime import WorkerPool, WorkerResult
from tests.test_http_probe_timeouts import _DEADLINE_LOST_WORKER, _Drip, _FiniteDrip

ROOT = Path(__file__).resolve().parents[1]


class _Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def _script_tool(name: str, code: str, timeout_s: float) -> Tool:
    return Tool(name, "read_only_probe", {"url": ArgSpec(str, pattern=r"https?://[^\s]+")},
                lambda a, d: [sys.executable, "-I", "-c", code], timeout_s=timeout_s)


class GatewayBase(unittest.TestCase):
    """A gateway with a target on a loopback port chosen per test."""

    def make(self, port: int, tools: dict) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        clock = _Clock()
        target = Target("t1", hosts=("lab.test",), cidrs=("127.0.0.1/32",), ports=(port,))
        self.eng = Engagement("eng1", True, "SOW-1", clock.t - 10, clock.t + 3600, {"t1": target},
                              frozenset({"read_only_probe"}))
        self.approvals = ApprovalStore()
        self.tokens = TokenAuthority(secrets.token_bytes(32), clock)
        self.audit = AuditLog(Path(self.tmp.name) / "audit.jsonl")
        self.workers = WorkerPool(max_concurrent=2)
        self.addCleanup(self.workers.kill_all)
        self.gw = Gateway(engagement=self.eng, tokens=self.tokens, approvals=self.approvals,
                          egress=EgressGuard(lambda h: ["127.0.0.1"] if h == "lab.test" else []),
                          workers=self.workers, audit=self.audit, tools=tools, budget=Budget(50), clock=clock)
        self.apr = self.approvals.approve("human:alice", "eng1", "t1", "read_only_probe")
        self.port = port

    def execute(self, tool: str, method: str | None = None):
        token = self.tokens.issue(self.eng, "t1", "read_only_probe", tool, self.apr, self.approvals, 300)
        args = {"url": f"http://lab.test:{self.port}/"}
        if method:
            args["method"] = method
        return self.gw.execute({"tool": tool, "target_id": "t1", "action": "read_only_probe", "args": args}, token)

    def events(self, name: str) -> list[dict]:
        return [e["fields"] for e in self.audit.entries() if e["event"] == name]


class TestGatewayDeadlineOnTheRealProbe(GatewayBase):
    """The real worker (through the egress sentinel). Its own deadline is 45 s, far beyond the
    gateway's here, so it is the gateway's clock that has to end these runs."""

    def run_against(self, srv, timeout_s=2.0):
        self.make(srv.port, {"http_probe": replace(http_probe_tool(), timeout_s=timeout_s)})
        t0 = time.monotonic()
        d = self.execute("http_probe", "GET")
        return d, time.monotonic() - t0

    def check_deadline_report(self, d, took, stage):
        self.assertTrue(d.allowed)
        r = d.result
        self.assertTrue(r.timed_out and r.killed)
        self.assertTrue(r.stop_confirmed)
        self.assertLess(took, 6)
        out = json.loads(r.stdout)
        self.assertEqual(out["error"], {"stage": stage, "kind": "deadline_exceeded", "timeout_s": 2.0,
                                        "exception": "GatewayDeadline", "source": "gateway"})
        self.assertTrue(out["gateway"]["worker_stdout_discarded"])
        ev = self.events("worker.deadline_exceeded")[-1]
        self.assertEqual((ev["last_stage"], ev["stop_confirmed"]), (stage, True))
        self.assertTrue(self.events("result")[-1]["timed_out"])
        self.assertFalse(WorkerPool.group_alive(r.pid))                  # the whole process group is gone
        return out

    def test_a_slow_drip_in_the_headers_is_stopped_at_the_gateway_deadline(self):
        srv = _Drip("headers")
        try:
            d, took = self.run_against(srv)
        finally:
            srv.close()
        out = self.check_deadline_report(d, took, "first_byte")
        self.assertEqual(out["gateway"]["stages_seen"], ["connect", "send", "first_byte"])

    def test_a_slow_drip_in_the_final_body_stage_is_stopped_too(self):
        srv = _Drip("body")
        try:
            d, took = self.run_against(srv)
        finally:
            srv.close()
        out = self.check_deadline_report(d, took, "body")
        self.assertEqual(out["gateway"]["stages_seen"][-1], "body")


class TestGatewayDeadlineWhenTheWorkerAlarmIsLost(GatewayBase):
    def test_the_gateway_ends_a_run_whose_sigalrm_deadline_was_lost(self):
        srv = _Drip("headers")
        try:
            args = ["--scheme", "http", "--host", "drip.test", "--ip", "127.0.0.1", "--port", str(srv.port),
                    "--path", "/", "--method", "GET", "--read-timeout", "1", "--overall-timeout", "1",
                    "--progress", "stderr"]
            tool = Tool("lost_alarm_probe", "read_only_probe", {"url": ArgSpec(str, pattern=r"https?://[^\s]+")},
                        lambda a, d: [sys.executable, "-I", "-c", _DEADLINE_LOST_WORKER, str(ROOT), *args],
                        timeout_s=2.0)
            self.make(srv.port, {"lost_alarm_probe": tool})
            t0 = time.monotonic()
            d = self.execute("lost_alarm_probe")
            took = time.monotonic() - t0
        finally:
            srv.close()
        self.assertTrue(d.result.timed_out)
        self.assertLess(took, 6)                     # not the 2 minutes the drip would take
        self.assertEqual(json.loads(d.result.stdout)["error"]["stage"], "first_byte")


class TestDeadlineEdges(GatewayBase):
    def test_a_run_that_finishes_just_before_the_deadline_is_a_normal_result(self):
        srv = _FiniteDrip(n=1, gap=0.01)
        try:
            code = "import json, time; time.sleep(1.7); print(json.dumps({'status': 200, 'headers': {}}))"
            self.make(srv.port, {"late_ok": _script_tool("late_ok", code, 2.0)})
            d = self.execute("late_ok")
        finally:
            srv.close()
        self.assertFalse(d.result.timed_out)
        self.assertEqual(json.loads(d.result.stdout), {"status": 200, "headers": {}})
        self.assertEqual(self.events("worker.deadline_exceeded"), [])

    def test_valid_json_printed_before_a_kill_is_not_a_success(self):
        srv = _FiniteDrip(n=1, gap=0.01)
        try:
            code = ("import json, sys, time; print(json.dumps({'status': 200, 'headers': {}})); "
                    "sys.stdout.flush(); time.sleep(30)")
            self.make(srv.port, {"json_then_hang": _script_tool("json_then_hang", code, 1.0)})
            d = self.execute("json_then_hang")
        finally:
            srv.close()
        self.assertTrue(d.result.timed_out)
        out = json.loads(d.result.stdout)
        self.assertEqual(out["error"]["kind"], "deadline_exceeded")       # the worker's JSON was dropped
        self.assertNotIn("status", out)
        printed = json.dumps({"status": 200, "headers": {}}) + "\n"
        self.assertEqual(self.events("worker.deadline_exceeded")[-1]["worker_stdout_bytes"], len(printed))

    def test_an_exit_the_runtime_clock_places_after_the_deadline_is_not_a_success(self):
        real = time.monotonic
        calls = {"n": 0}

        def clock():                                   # start and the wait budget at real time, then 10 s late
            calls["n"] += 1
            return real() + (10 if calls["n"] > 2 else 0)
        pool = WorkerPool(max_concurrent=1, clock=clock)
        self.addCleanup(pool.kill_all)
        r = pool.run([sys.executable, "-I", "-c", "print('{\"status\": 200}')"], timeout_s=5)
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.timed_out)                   # exited with valid JSON, but after the deadline


class TestStopRacesAndNoTrafficAfterTheStop(unittest.TestCase):
    def test_exit_and_kill_racing_at_the_deadline_stay_consistent(self):
        pool = WorkerPool(max_concurrent=1)
        self.addCleanup(pool.kill_all)
        # calibrated on this machine: the deadline sits 0.5 s after a typical interpreter start,
        # and the naps spread from well inside it to well past it
        start = min(pool.run([sys.executable, "-I", "-c", "pass"], timeout_s=30).elapsed_s for _ in range(3))
        deadline = start + 0.5
        outcomes = set()
        for i in range(40):
            nap = 0.2 + (i % 8) * 0.085            # 0.20 .. 0.795 s around 0.5 s
            r = pool.run([sys.executable, "-I", "-c", f"import time; time.sleep({nap}); print('{{}}')"],
                         timeout_s=deadline)
            if r.timed_out:
                outcomes.add("timed_out")
                self.assertTrue(r.killed and r.stop_confirmed, i)
                self.assertFalse(WorkerPool.group_alive(r.pid), i)
            else:
                outcomes.add("ok")
                self.assertEqual((r.returncode, r.stdout.strip()), (0, "{}"), i)
                self.assertLessEqual(r.elapsed_s, deadline + 0.05, i)   # never "ok" past the deadline
            self.assertFalse(r.pipes_held, i)
        self.assertEqual(outcomes, {"ok", "timed_out"})         # both sides of the race were exercised

    def test_an_emergency_stop_during_a_deadline_run_is_consistent(self):
        pool = WorkerPool(max_concurrent=1)
        self.addCleanup(pool.kill_all)
        for i in range(20):
            res = {}
            t = threading.Thread(target=lambda: res.setdefault("r", pool.run(
                [sys.executable, "-I", "-c", "import time; time.sleep(30)"], timeout_s=0.5)))
            t.start()
            time.sleep(0.44 + (i % 5) * 0.03)     # the stop lands just before or just after the deadline
            survivors = pool.terminate_active(confirm_timeout_s=3)
            t.join(10)
            r = res["r"]
            self.assertEqual(survivors, [], i)
            self.assertTrue(r.killed, i)
            self.assertFalse(WorkerPool.group_alive(r.pid), i)

    def test_a_stopped_worker_and_its_children_send_nothing_more(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(64)
        port = listener.getsockname()[1]
        received: list[float] = []
        stop = threading.Event()

        def serve():
            listener.settimeout(0.1)
            while not stop.is_set():
                try:
                    c, _ = listener.accept()
                except OSError:
                    continue
                c.settimeout(0.2)
                try:
                    while c.recv(16):
                        received.append(time.monotonic())
                except OSError:
                    pass
                c.close()
        threading.Thread(target=serve, daemon=True).start()
        # the worker forks a child (same process group); both keep connecting and sending
        code = f"""
import os, socket, time
os.fork()
while True:
    try:
        s = socket.create_connection(("127.0.0.1", {port}), timeout=1)
        for _ in range(5):
            s.sendall(b"x"); time.sleep(0.05)
        s.close()
    except OSError:
        time.sleep(0.05)
"""
        pool = WorkerPool(max_concurrent=1)
        self.addCleanup(pool.kill_all)
        try:
            r = pool.run([sys.executable, "-I", "-c", code], timeout_s=1.0)
            stopped_at = time.monotonic()
            time.sleep(1.5)
        finally:
            stop.set()
            listener.close()
        self.assertTrue(r.timed_out and r.stop_confirmed)
        self.assertTrue(any(t < stopped_at for t in received))           # it was talking before
        self.assertEqual([t for t in received if t > stopped_at + 0.1], [])  # and not after the stop
        self.assertFalse(WorkerPool.group_alive(r.pid))                  # the forked child is gone too


class TestUnconfirmedStopFailsClosed(GatewayBase):
    def test_a_deadline_kill_that_cannot_be_confirmed_yields_no_result(self):
        srv = _Drip("headers")
        try:
            self.make(srv.port, {"http_probe": replace(http_probe_tool(), timeout_s=1.5)})
            real = self.workers.confirm_stopped
            # the kill is sent, but the pool cannot confirm the group is gone
            self.workers.confirm_stopped = lambda pids, confirm_timeout_s=5.0: (real(pids, confirm_timeout_s), list(pids))[1]
            d = self.execute("http_probe", "GET")
        finally:
            self.workers.confirm_stopped = real
            srv.close()
        self.assertFalse(d.allowed)
        self.assertIn("could not be confirmed stopped", d.reason)
        self.assertEqual(len(self.events("worker.stop_unconfirmed")), 1)
        self.assertEqual(self.events("result"), [])          # no result, not even the timeout report


class TestPipesHeldByAnEscapedDescendant(GatewayBase):
    """A descendant that leaves the process group (setsid) is not reached by killpg; without
    confinement it can outlive the worker. If it still holds the worker's output, nothing read
    from it is trusted."""

    CODE = ("import os, sys, time, json\n"
            "if os.fork() == 0:\n"
            "    os.setsid(); time.sleep(0.3)\n"
            "    print(json.dumps({'status': 200, 'forged': 1})); sys.stdout.flush(); time.sleep(4); os._exit(0)\n"
            "print(json.dumps({'status': 200}))\n")

    def test_the_pool_flags_it_and_discards_the_output(self):
        pool = WorkerPool(max_concurrent=1)
        self.addCleanup(pool.kill_all)
        r = pool.run([sys.executable, "-I", "-c", self.CODE], timeout_s=5)
        self.assertTrue(r.pipes_held)
        self.assertEqual((r.stdout, r.stderr), ("", ""))
        self.assertLess(r.elapsed_s, 3)                       # one bounded wait, not per pipe

    def test_the_gateway_does_not_accept_the_run(self):
        srv = _FiniteDrip(n=1, gap=0.01)
        try:
            self.make(srv.port, {"escaper": _script_tool("escaper", self.CODE, 5.0)})
            d = self.execute("escaper")
        finally:
            srv.close()
        self.assertFalse(d.allowed)                            # refused (gateway.execute turns PolicyError into a denial)
        self.assertIn("kept its output open", d.reason)
        self.assertEqual(len(self.events("worker.pipes_held")), 1)
        self.assertEqual(self.events("result"), [])            # no result was recorded for it


class TestCaptureLimits(unittest.TestCase):
    def test_output_without_newlines_is_capped_and_marked(self):
        pool = WorkerPool(max_concurrent=1)
        self.addCleanup(pool.kill_all)
        code = "import sys; [sys.stdout.write('x' * 65536) for _ in range(48)]"   # 3 MiB, no newline
        r = pool.run([sys.executable, "-I", "-c", code], timeout_s=10)
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.output_truncated)
        self.assertLessEqual(len(r.stdout.encode()), 1_000_000)

    def test_stage_events_are_capped(self):
        pool = WorkerPool(max_concurrent=1)
        self.addCleanup(pool.kill_all)
        code = "import sys; [sys.stderr.write('@@vulnix-stage send\\n') for _ in range(5000)]"
        r = pool.run([sys.executable, "-I", "-c", code], timeout_s=10, progress=True)
        self.assertEqual(len(r.stages), 32)


class TestProgressMarkers(unittest.TestCase):
    def run_markers(self, text: str, progress=True):
        pool = WorkerPool(max_concurrent=1)
        self.addCleanup(pool.kill_all)
        code = f"import sys; sys.stderr.write({text!r}); print('{{}}')"
        return pool.run([sys.executable, "-I", "-c", code], timeout_s=5, progress=progress)

    def test_only_whole_lines_with_a_known_stage_count_and_are_removed_from_stderr(self):
        r = self.run_markers("@@vulnix-stage connect\n@@vulnix-stage evil_stage\n"
                             "@@vulnix-stage first_byte trailing\nnote\n")
        self.assertEqual((r.last_stage, [s for s, _ in r.stages]), ("connect", ["connect"]))
        self.assertEqual(r.stderr, "@@vulnix-stage evil_stage\n@@vulnix-stage first_byte trailing\nnote\n")

    def test_a_carriage_return_cannot_fake_a_marker(self):
        r = self.run_markers("target bytes x\r@@vulnix-stage report\r\n@@vulnix-stage send\r\n")
        self.assertEqual(r.stages, ())
        self.assertIn("@@vulnix-stage report", r.stderr)

    def test_the_rest_of_an_over_long_line_is_not_a_marker(self):
        pool = WorkerPool(max_concurrent=1)
        self.addCleanup(pool.kill_all)
        code = ("import sys, time; sys.stderr.write('T' * 5000); sys.stderr.flush(); time.sleep(0.2); "
                "sys.stderr.write('@@vulnix-stage report\\n@@vulnix-stage send\\n'); print('{}')")
        r = pool.run([sys.executable, "-I", "-c", code], timeout_s=5, progress=True)
        self.assertEqual([s for s, _ in r.stages], ["send"])   # the tail of the long line did not count
        self.assertIn("@@vulnix-stage report", r.stderr)

    def test_without_progress_markers_are_not_parsed(self):
        r = self.run_markers("@@vulnix-stage tls\n", progress=False)
        self.assertEqual((r.stages, r.stderr), ((), "@@vulnix-stage tls\n"))

    def test_the_probe_writes_markers_only_when_told_to(self):
        pool = WorkerPool(max_concurrent=1)
        self.addCleanup(pool.kill_all)
        base = [sys.executable, "-I", str(ROOT / "aegis" / "workers" / "http_probe.py"), "--scheme", "http",
                "--host", "x.test", "--ip", "127.0.0.1", "--port", "1", "--path", "/"]
        quiet = pool.run(base, timeout_s=10, progress=True)
        told = pool.run(base + ["--progress", "stderr"], timeout_s=10, progress=True)
        self.assertEqual((quiet.stages, quiet.stderr), ((), ""))
        self.assertEqual([s for s, _ in told.stages], ["connect", "report"])
        self.assertEqual(told.stderr, "")

    def test_the_report_ignores_whatever_the_worker_printed(self):
        r = WorkerResult(-9, '{"status": 200, "body_prefix": "secret"}', "x", True, 2.0, timed_out=True,
                         deadline_s=2.0, last_stage="body", stages=(("connect", 1), ("body", 900)), stop_confirmed=True)
        out = json.loads(deadline_report("http_probe", r).stdout)
        self.assertNotIn("secret", json.dumps(out))
        self.assertEqual(out["error"]["stage"], "body")


if __name__ == "__main__":
    unittest.main()
