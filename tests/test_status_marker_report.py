"""The marker report has no target response text, address, or arbitrary fields."""
import argparse
import threading
import unittest

from aegis.gateway import _validate_status_marker_report, status_marker_tool
from aegis.policy import PolicyError, validate_proposal
from aegis.network import PinnedDestination
from aegis.runtime import WorkerResult
from aegis.workers.http_probe import probe
from tests.fixtures.status_exposure_lab import StatusExposureLab
from tests.test_gateway import Base


class TestStatusMarkerReport(unittest.TestCase):
    def test_catalog_tool_accepts_only_fixed_endpoint(self):
        tool = status_marker_tool()
        proposal = {"tool": "status_marker", "target_id": "lab", "action": "read_only_probe",
                    "args": {"url": "http://lab.test/server-status?auto"}}
        self.assertEqual(validate_proposal(proposal, {tool.name: tool})[0], tool)
        for path in ("/server-status", "/server-status?auto&extra=1", "/private"):
            with self.subTest(path=path):
                changed = {**proposal, "args": {"url": "http://lab.test" + path}}
                with self.assertRaises(PolicyError):
                    validate_proposal(changed, {tool.name: tool})
        with self.assertRaises(PolicyError):
            tool.build_argv(proposal["args"], PinnedDestination(
                "http", "lab.test", "127.0.0.1", 80, "/private"))

    def test_independent_lab_modes_have_fixed_schema_and_truth(self):
        for mode, detected in (("vulnerable", True), ("patched", False),
                               ("generic_200", False)):
            with self.subTest(mode=mode):
                server = StatusExposureLab(mode)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                try:
                    args = argparse.Namespace(
                        scheme="http", host="lab.test", ip="127.0.0.1",
                        port=server.server_port, path="/server-status?auto",
                        method="GET", origin="https://untrusted-origin.example",
                        connect_timeout=2, read_timeout=2, overall_timeout=5,
                        report_mode="status_marker",
                    )
                    report = probe(args)
                    self.assertEqual(set(report), {"check_id", "elapsed_ms", "status", "markers", "detected"})
                    self.assertEqual(report["check_id"], "apache_mod_status")
                    self.assertEqual(report["detected"], detected)
                    self.assertNotIn("203.0.113.1", str(report))
                    self.assertNotIn("/private-example", str(report))
                    self.assertTrue(_validate_status_marker_report(report, 0))
                    self.assertEqual(server.seen, ["/server-status?auto"])
                finally:
                    server.shutdown()
                    server.server_close()

    def test_unexpected_fields_or_inconsistent_claims_are_rejected(self):
        valid = {"check_id": "apache_mod_status", "elapsed_ms": 1,
                 "status": 200, "markers": {"total_accesses": True,
                                           "uptime_seconds": True}, "detected": True}
        for changed in ({**valid, "body_prefix": "secret"},
                        {**valid, "detected": False},
                        {**valid, "markers": {"total_accesses": True,
                                              "uptime_seconds": True, "raw": "secret"}}):
            with self.subTest(changed=changed):
                with self.assertRaises(PolicyError):
                    _validate_status_marker_report(changed, 0)

    def test_connection_error_has_no_target_or_exception_text(self):
        args = argparse.Namespace(
            scheme="http", host="lab.test", ip="127.0.0.1", port=0,
            path="/server-status?auto", method="GET",
            origin="https://untrusted-origin.example", connect_timeout=1,
            read_timeout=1, overall_timeout=2, report_mode="status_marker",
        )
        report = probe(args)
        self.assertEqual(set(report), {"check_id", "elapsed_ms", "error"})
        self.assertEqual(set(report["error"]), {"stage", "kind"})
        self.assertTrue(_validate_status_marker_report(report, 3))


class TestMarkerGatewayBoundary(Base):
    def test_malformed_worker_output_never_enters_result_audit(self):
        self.gw.tools["status_marker"] = status_marker_tool()
        secret = "private-response-marker"
        self.workers.run = lambda *_args, **_kwargs: WorkerResult(
            0, '{"status":200,"body_prefix":"' + secret + '"}', "", False, 0.01)
        result = self.gw.execute(self.prop("http://lab.test/server-status?auto",
                                           tool="status_marker"), self.token("status_marker"))
        self.assertFalse(result.allowed)
        entries = self.audit.entries()
        self.assertNotIn(secret, str(entries))
        self.assertFalse(any(row["event"] == "result" for row in entries))

    def test_worker_stderr_is_rejected_without_logging_it(self):
        self.gw.tools["status_marker"] = status_marker_tool()
        secret = "private-stderr-marker"
        report = ('{"check_id":"apache_mod_status","elapsed_ms":1,"status":200,'
                  '"markers":{"total_accesses":true,"uptime_seconds":true},"detected":true}')
        self.workers.run = lambda *_args, **_kwargs: WorkerResult(
            0, report, secret, False, 0.01)
        result = self.gw.execute(self.prop("http://lab.test/server-status?auto",
                                           tool="status_marker"), self.token("status_marker"))
        self.assertFalse(result.allowed)
        entries = self.audit.entries()
        self.assertNotIn(secret, str(entries))
        self.assertFalse(any(row["event"] == "result" for row in entries))

    def test_duplicate_json_keys_are_rejected(self):
        self.gw.tools["status_marker"] = status_marker_tool()
        self.workers.run = lambda *_args, **_kwargs: WorkerResult(
            0, '{"check_id":"apache_mod_status","check_id":"other","elapsed_ms":1}',
            "", False, 0.01)
        result = self.gw.execute(self.prop("http://lab.test/server-status?auto",
                                           tool="status_marker"), self.token("status_marker"))
        self.assertFalse(result.allowed)
        self.assertFalse(any(row["event"] == "result" for row in self.audit.entries()))
