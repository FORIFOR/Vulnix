"""A pinned synthetic candidate may be linked to a confined control result."""
import contextlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from aegis.confinement import KernelConfinement
from aegis.runtime import WorkerPool
from aegis.security_graph.service import GraphService, SourceRegistration
from aegis.validation.mcp_policy_lab import SOURCE


class McpPolicyServiceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        (self.repo / ".vulnix-synthetic-lab").write_text("synthetic-only\n")
        (self.repo / "tools.py").write_text(SOURCE)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", ".vulnix-synthetic-lab", "tools.py"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Lab",
                        "-c", "user.email=lab@lab.test", "commit", "-qm", "fixture"], check=True)
        self.sha = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        self.pool = WorkerPool(max_concurrent=1, cpu_seconds=2)
        self.service = GraphService(self.root / "org-a", worker_pool_provider=lambda: self.pool)
        self.service.register_source(SourceRegistration("lab", "repo-lab", self.repo, self.sha))
        self.snapshot = self.service.import_source("lab")
        self.candidates = self.service.mcp_scope(self.snapshot)

    def candidate(self, name):
        nodes = {item["id"]: item for item in self.service.nodes(self.snapshot)}
        return next(item for item in self.candidates if nodes[item["tool_id"]]["name"] == name)

    def test_unregistered_candidate_and_modified_checkout_are_rejected(self):
        with self.assertRaises(ValueError):
            self.service.validate_mcp_synthetic(self.snapshot, self.candidate("open_customer")["id"])
        with self.assertRaises(KeyError):
            self.service.validate_mcp_synthetic(self.snapshot, "missing", commit_guard=contextlib.nullcontext)
        (self.repo / "tools.py").write_text(SOURCE + "\n# changed after pin\n")
        with self.assertRaises(ValueError):
            self.service.validate_mcp_synthetic(
                self.snapshot, self.candidate("open_customer")["id"],
                commit_guard=contextlib.nullcontext)
        self.assertEqual(self.service.validations(self.snapshot), [])

    @unittest.skipUnless(sys.platform == "darwin" or
                         (sys.platform.startswith("linux") and KernelConfinement().status()["ok"]),
                         "synthetic sandbox requires kernel confinement or macOS")
    def test_pinned_candidate_records_synthetic_observation_only(self):
        candidate = self.candidate("guarded_customer")
        result = self.service.validate_mcp_synthetic(
            self.snapshot, candidate["id"], commit_guard=contextlib.nullcontext)
        self.assertEqual(result["status"], "synthetic_control_observed")
        self.assertEqual(result["observation"], {"viewer_denied": True,
                                                  "admin_reached_data": True})
        self.assertTrue(result["synthetic_only"])
        self.assertEqual(result["commit_sha"], self.sha)
        self.assertEqual(result["evidence_ids"], list(candidate["evidence_ids"]))
        self.assertEqual(self.service.mcp_validations(self.snapshot), [result])
        self.assertEqual(self.service.validations(self.snapshot), [])
        self.assertEqual(self.service.validate_mcp_synthetic(
            self.snapshot, candidate["id"], commit_guard=contextlib.nullcontext), result)
        self.assertEqual(self.pool.active_pids(), [])

    def test_cross_org_snapshot_is_not_found(self):
        other = GraphService(self.root / "org-b", worker_pool_provider=lambda: self.pool)
        with self.assertRaises(KeyError):
            other.validate_mcp_synthetic(self.snapshot, self.candidate("open_customer")["id"],
                                         commit_guard=contextlib.nullcontext)

    def test_revoked_lease_prevents_worker_and_record(self):
        @contextlib.contextmanager
        def revoked():
            raise PermissionError("synthetic access revoked")
            yield

        with self.assertRaises(PermissionError):
            self.service.validate_mcp_synthetic(
                self.snapshot, self.candidate("open_customer")["id"], commit_guard=revoked)
        self.assertEqual(self.pool.active_pids(), [])
        self.assertEqual(self.service.mcp_validations(self.snapshot), [])


if __name__ == "__main__":
    unittest.main()
