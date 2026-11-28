"""A normal process exit closes the data-directory lock handle."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestDataDirLockCleanup(unittest.TestCase):
    def test_no_unclosed_lock_warning_on_normal_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = (
                "from pathlib import Path\n"
                "from aegis.assessment import _claim_data_dir\n"
                f"_claim_data_dir(Path({tmp!r}))\n"
            )
            result = subprocess.run(
                [sys.executable, "-W", "always::ResourceWarning", "-c", script],
                cwd=Path(__file__).resolve().parents[1],
                env={**os.environ, "VULNIX_NO_ENV_LOCAL": "1"},
                capture_output=True, text=True, timeout=20,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("ResourceWarning", result.stderr)


if __name__ == "__main__":
    unittest.main()


def _fds() -> int:
    return len(os.listdir("/proc/self/fd" if os.path.isdir("/proc/self/fd") else "/dev/fd"))


class TestNoDescriptorGrowth(unittest.TestCase):
    """A long-running server opens organizations, closes services and answers requests
    without its open file descriptors growing (not hidden behind a higher limit)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _svc(self, path):
        from unittest.mock import patch
        from aegis.assessment import AssessmentService
        with patch.dict(os.environ, {}, clear=True):
            return AssessmentService(Path(path), 18099, verify_seconds=30)

    def test_the_last_closed_service_releases_the_claim(self):
        d = Path(self.tmp.name) / "org"
        d.mkdir()
        probe = ("import sys\nfrom pathlib import Path\nfrom aegis.assessment import _claim_data_dir\n"
                 "try:\n    _claim_data_dir(Path(sys.argv[1]))\nexcept RuntimeError:\n    sys.exit(3)\n")
        other = lambda: subprocess.run([sys.executable, "-c", probe, str(d)], cwd=Path(__file__).resolve().parents[1],
                                       env={**os.environ, "VULNIX_NO_ENV_LOCAL": "1"}, timeout=30).returncode
        a, b = self._svc(d), self._svc(d)          # a "restart" in one process shares the claim
        a.close()
        self.assertEqual(other(), 3)               # still held by b
        b.close()
        b.close()                                  # closing twice releases once
        self.assertEqual(other(), 0)               # released: another process may now take it

    def test_opening_and_closing_services_does_not_grow_descriptors(self):
        base = _fds()
        for i in range(30):
            self._svc(Path(self.tmp.name) / f"o{i % 3}").close()
        self.assertLessEqual(_fds() - base, 2)

    def test_each_loaded_organization_holds_one_descriptor_and_returns_it_on_close(self):
        from aegis.tenancy import OrgStore, TenantRegistry
        d = Path(self.tmp.name)
        svc = self._svc(d)
        store = OrgStore(d / "orgs.json", max_orgs=100)
        reg = TenantRegistry(store, svc, self._svc, d)
        base = _fds()
        ids = [store.create_org(f"o{i}", f"u{i}") for i in range(40)]
        for oid in ids:
            reg.service(oid)
        self.assertLessEqual(_fds() - base, 40 + 2)     # sizing basis for LimitNOFILE (docs)
        reg.close_all()
        svc.close()
        self.assertLessEqual(_fds() - base, 2)


class TestNoDescriptorGrowthOverHttp(unittest.TestCase):
    def test_many_requests_and_authority_checks_keep_descriptors_flat(self):
        from tests.test_tenancy import TestTenantIsolationOverHttp

        class Probe(TestTenantIsolationOverHttp):
            def runTest(self):
                a = self.signup("alice")
                oid = a["orgs"][0]["id"]
                p = self.login("padmin", "padmin-pw-1")
                for _ in range(20):                          # warm up pools and caches
                    self.req(a, "/assets/a2b-drafts", org=oid)
                base = _fds()
                for i in range(300):
                    self.req(a, "/assets/a2b-drafts", org=oid)
                    if i % 30 == 0:
                        self.req(p, "/operators/roles", {"name": "padmin", "roles": ["operator", "approver", "admin"]})
                        self.reg.service(oid).enforce_a2b_authority()
                self.assertLessEqual(_fds() - base, 5)

        r = unittest.TestResult()
        Probe().run(r)
        self.assertTrue(r.wasSuccessful(), r.failures + r.errors)
