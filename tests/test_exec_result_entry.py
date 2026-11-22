"""A Worker's result is tied to ITS OWN audit entry (by the token's jti), never to whichever
result was recorded last: another Worker of the same organization may finish in between."""
from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.assessment import AssessmentService
from tests import TEST_CONFINEMENT
from tests.fixtures.access_control_lab import AccessControlLab


class TestExecResultEntry(unittest.TestCase):
    def test_a_result_recorded_by_another_worker_in_between_is_not_taken(self):
        lab = AccessControlLab("unauth_exposure")
        threading.Thread(target=lab.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"AEGIS_ENV": "development"}):
                svc = AssessmentService(Path(tmp), lab.server_port, l2_confinement=TEST_CONFINEMENT)
                try:
                    real = svc.gateway.execute

                    def execute_then_another_worker_finishes(request, token):
                        decision = real(request, token)
                        svc.audit.record("result", jti="another-worker", tool="http_probe", rc=0,
                                         killed=False, elapsed=0.0, timed_out=False,
                                         stdout_preview="another worker's output")
                        return decision

                    with patch.object(svc.gateway, "execute", execute_then_another_worker_finishes):
                        res, ev = svc._exec("http_probe", "read_only_probe",
                                            {"url": svc.a.target_url, "method": "GET"},
                                            approval_actor="policy:auto-L1")
                    self.assertIsNotNone(ev)
                    entry = next(e for e in svc.audit.entries() if e["hash"] == ev["audit_hash"])
                    self.assertEqual(entry["event"], "result")
                    self.assertNotEqual(entry["fields"].get("jti"), "another-worker")
                    self.assertTrue(entry["fields"].get("jti"))
                finally:
                    svc.workers.kill_all()
        finally:
            lab.shutdown()
            lab.server_close()


if __name__ == "__main__":
    unittest.main()
