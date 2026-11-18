import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from aegis.security_graph.service import GraphService, SourceRegistration
from aegis.confinement import KernelConfinement
from aegis.runtime import WorkerPool
from tests.test_source_workflow import SOURCE
from tests.test_typescript_graph import VULNERABLE as NEXT_SOURCE


class GraphServiceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        (self.repo / ".vulnix-synthetic-lab").write_text("synthetic-only\n")
        (self.repo / "api.py").write_text(SOURCE)
        next_path = self.repo / "app" / "api" / "orders" / "route.ts"
        next_path.parent.mkdir(parents=True)
        next_path.write_text(NEXT_SOURCE)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "api.py", "app", ".vulnix-synthetic-lab"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Lab",
                        "-c", "user.email=lab@lab.test", "commit", "-qm", "fixture"], check=True)
        self.sha = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        self.service = GraphService(self.root / "org-a")
        self.service.register_source(SourceRegistration("lab", "repo-lab", self.repo, self.sha))

    def test_source_list_does_not_reveal_local_checkout(self):
        listed = self.service.sources()
        self.assertEqual(listed[0]["id"], "lab")
        self.assertNotIn(str(self.repo), str(listed))

    def test_registered_source_to_paths_and_hypotheses(self):
        snapshot = self.service.import_source("lab")
        self.assertEqual(snapshot, self.service.import_source("lab"))
        self.assertEqual(len(self.service.snapshots()), 1)
        self.assertTrue(any(node["kind"] == "route" for node in self.service.nodes(snapshot)))
        paths = self.service.paths(snapshot)
        self.assertGreaterEqual(len(paths), 2)
        self.assertTrue(all(path["status"] == "observed_structure" for path in paths))
        hypotheses = self.service.research(snapshot)
        self.assertTrue(hypotheses)
        self.assertTrue(all(h["verdict"] == "unverified" for h in hypotheses))
        self.assertEqual(len(self.service.research(snapshot)), len(hypotheses))
        self.assertEqual(self.service.path_detail(snapshot, paths[0]["id"])["id"], paths[0]["id"])
        handler = next(n["id"] for n in self.service.nodes(snapshot) if n["kind"] == "handler")
        self.assertGreaterEqual(self.service.remediation_impact(snapshot, handler)["predicted_paths"], 1)

    @unittest.skipUnless(sys.platform == "darwin" or
                         (sys.platform.startswith("linux") and KernelConfinement().status()["ok"]),
                         "synthetic sandbox requires kernel confinement or macOS")
    def test_import_research_sandbox_remediation_records(self):
        shared_pool = WorkerPool(max_concurrent=1, cpu_seconds=2)
        self.service.worker_pool_provider = lambda: shared_pool
        snapshot = self.service.import_source("lab")
        hypothesis = next(item for item in self.service.research(snapshot)
                          if any(node["name"] == "get_order" and node["id"] in item["affected_nodes"]
                                 for node in self.service.nodes(snapshot)))
        result = self.service.validate_synthetic(snapshot, hypothesis["hypothesis_id"])
        self.assertEqual(result["validation"]["status"], "synthetic_fixed")
        self.assertTrue(result["remediation"]["fixed"])
        self.assertEqual(len(self.service.validations(snapshot)), 1)
        self.assertEqual(len(self.service.remediations(snapshot)), 1)
        self.assertEqual(self.service.validate_synthetic(snapshot, hypothesis["hypothesis_id"]), result)
        self.assertEqual(shared_pool.active_pids(), [])

    @unittest.skipUnless(sys.platform == "darwin", "checks macOS worker launch lease")
    def test_revoked_lease_prevents_synthetic_worker_launch(self):
        shared_pool = WorkerPool(max_concurrent=1, cpu_seconds=2)
        self.service.worker_pool_provider = lambda: shared_pool
        snapshot = self.service.import_source("lab")
        hypothesis = next(item for item in self.service.research(snapshot)
                          if any(node["name"] == "get_order" and node["id"] in item["affected_nodes"]
                                 for node in self.service.nodes(snapshot)))

        @contextmanager
        def revoked():
            raise PermissionError("revoked before launch")
            yield

        with self.assertRaises(PermissionError):
            self.service.validate_synthetic(snapshot, hypothesis["hypothesis_id"], commit_guard=revoked)
        self.assertEqual(shared_pool.active_pids(), [])
        self.assertEqual(self.service.validations(snapshot), [])

    def test_unregistered_source_and_cross_tenant_snapshot_rejected(self):
        with self.assertRaises(KeyError):
            self.service.import_source("/tmp/elsewhere")
        snapshot = self.service.import_source("lab")
        other = GraphService(self.root / "org-b")
        self.assertEqual(other.snapshots(), [])
        with self.assertRaises(KeyError):
            other.nodes(snapshot)

    def test_commit_diff_keeps_snapshots_separate(self):
        before = self.service.import_source("lab")
        fixed = SOURCE.replace("    return order", "    if order.org_id != identity['org_id']:\n"
                               "        raise HTTPException(status_code=403)\n    return order")
        (self.repo / "api.py").write_text(fixed)
        subprocess.run(["git", "-C", str(self.repo), "add", "api.py"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Lab",
                        "-c", "user.email=lab@lab.test", "commit", "-qm", "fix"], check=True)
        sha = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        self.service.register_source(SourceRegistration("lab-fixed", "repo-lab", self.repo, sha))
        after = self.service.import_source("lab-fixed")
        diff = self.service.diff(before, after)
        self.assertNotEqual(before, after)
        self.assertTrue(diff["guard_observed_after"])
        self.assertEqual(diff["status"], "graph_prediction_only")


if __name__ == "__main__":
    unittest.main()
