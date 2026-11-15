"""Fixed truth labels for the independent mod_status fixture."""
import json
import os
import subprocess
import sys
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from tests.fixtures.status_exposure_lab import StatusExposureLab


class TestStatusExposureLab(unittest.TestCase):
    def test_expired_or_revoked_scope_never_launches_a_worker(self):
        result = subprocess.run(
            [sys.executable, "-m", "scripts.bench_status_exposure_baseline"],
            cwd=Path(__file__).resolve().parents[1],
            env={**os.environ, "VULNIX_NO_ENV_LOCAL": "1"},
            check=True, capture_output=True, text=True, timeout=30,
        )
        checks = json.loads(result.stdout)["safety"]
        self.assertEqual(set(checks), {"expired_scope", "revoked_ownership"})
        self.assertTrue(all(row["refused"] for row in checks.values()))
        self.assertTrue(all(row["worker_launches"] == 0 for row in checks.values()))
        self.assertTrue(all(row["target_requests"] == [] for row in checks.values()))

    def test_only_vulnerable_mode_exposes_status_markers(self):
        for mode, expected_status in (("vulnerable", 200), ("patched", 403), ("generic_200", 200)):
            with self.subTest(mode=mode):
                server = StatusExposureLab(mode)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                try:
                    base = f"http://127.0.0.1:{server.server_port}"
                    with urllib.request.urlopen(base + "/", timeout=2) as root:
                        self.assertEqual(root.status, 200)
                        self.assertEqual(root.headers.get("Server"), "Apache/2.4.62")
                        self.assertEqual(root.read(), b"status lab root\n")
                    try:
                        response = urllib.request.urlopen(base + "/server-status?auto", timeout=2)
                    except urllib.error.HTTPError as error:
                        response = error
                    with response:
                        self.assertEqual(response.status, expected_status)
                        body = response.read()
                    self.assertEqual(b"Total Accesses" in body, mode == "vulnerable")
                    self.assertEqual(server.seen, ["/", "/server-status?auto"])
                finally:
                    server.shutdown()
                    server.server_close()
