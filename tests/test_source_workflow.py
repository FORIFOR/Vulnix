"""A deliberately small, synthetic end-to-end authorization case."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.connectors.github_source import open_pinned_local_checkout
from aegis.confinement import KernelConfinement
from aegis.security_graph.builder import build_graph
from aegis.research.planner import RuleBasedResearchModel, research
from aegis.validation.broker import ValidationBroker
from aegis.remediation.patch_planner import plan_patch
from aegis.remediation.patch_validator import validate_patch
from aegis.remediation.github_pr import draft_pr_description
from aegis.research.report import build_report
from aegis.research.local_workflow import run_local_synthetic_workflow
from aegis.validation.sandbox import SandboxUnavailable, run_synthetic_case


SOURCE = '''class App:
    def get(self, path):
        return lambda fn: fn

app = App()
def Depends(fn):
    return fn
def current_identity():
    return None
class HTTPException(Exception):
    def __init__(self, status_code):
        self.status_code = status_code
class Order:
    def __init__(self, org_id):
        self.org_id = org_id
class Store:
    def get(self, order_id):
        return {"a": Order("org-a"), "b": Order("org-b")}[order_id]
store = Store()

@app.get("/orders/{order_id}")
def get_order(order_id, identity=Depends(current_identity)):
    order = store.get(order_id)
    return order
'''


class SourceWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "api.py").write_text(SOURCE)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "api.py"], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Lab",
                        "-c", "user.email=lab@lab.test", "commit", "-qm", "fixture"], check=True)
        self.sha = subprocess.check_output(["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).strip()

    def test_pinned_checkout_rejects_dirty_and_wrong_sha(self):
        open_pinned_local_checkout(self.root, self.sha)
        with self.assertRaises(ValueError):
            open_pinned_local_checkout(self.root, "b" * 40)
        (self.root / "api.py").write_text(SOURCE + "\n# dirty\n")
        with self.assertRaises(ValueError):
            open_pinned_local_checkout(self.root, self.sha)

    def test_linux_without_verified_kernel_confinement_fails_closed(self):
        with patch("aegis.validation.sandbox.platform.system", return_value="Linux"), \
             patch("aegis.confinement.KernelConfinement.status", return_value={"ok": False}):
            with self.assertRaises(SandboxUnavailable):
                run_synthetic_case(SOURCE)

    def test_ignored_python_file_is_not_indexed(self):
        (self.root / ".git" / "info" / "exclude").write_text("private.py\n")
        (self.root / "private.py").write_text("SECRET = 'not-for-indexing'\n")
        checkout = open_pinned_local_checkout(self.root, self.sha)
        graph = build_graph(checkout, self.sha)
        self.assertTrue(all(e.source_path == "api.py" for e in graph.evidence.values()))

    def test_graph_reads_pinned_blob_if_worktree_changes_after_gate(self):
        checkout = open_pinned_local_checkout(self.root, self.sha)
        (self.root / "api.py").write_text(SOURCE.replace("return order", "return None"))
        graph = build_graph(checkout, self.sha)
        self.assertEqual(len(research(graph, RuleBasedResearchModel())), 1)
        # The post-gate edit must not enter a validation or patch run.
        with self.assertRaises(ValueError):
            ValidationBroker(graph, checkout).validate(research(graph, RuleBasedResearchModel())[0])

    @unittest.skipUnless(sys.platform == "darwin" or
                         (sys.platform.startswith("linux") and KernelConfinement().status()["ok"]),
                         "synthetic sandbox requires kernel confinement or macOS")
    def test_vulnerable_to_fixed_draft(self):
        checkout = open_pinned_local_checkout(self.root, self.sha)
        graph = build_graph(checkout, self.sha)
        hypotheses = research(graph, RuleBasedResearchModel())
        self.assertEqual(len(hypotheses), 1)
        broker = ValidationBroker(graph, checkout)
        before = broker.validate(hypotheses[0])
        self.assertEqual(before.status, "confirmed_in_synthetic_lab")
        self.assertTrue(before.cross_tenant_exposed)
        patch = plan_patch(checkout, graph, hypotheses[0], before)
        result = validate_patch(broker, patch, hypotheses[0])
        self.assertTrue(result.fixed)
        self.assertTrue(result.same_tenant_preserved)
        self.assertIn("Draft", draft_pr_description(hypotheses[0], before, result))
        report = build_report(graph, hypotheses[0], before, result)
        self.assertEqual(report["status"], "synthetic_validated")
        self.assertTrue(report["graph"]["edges"])
        self.assertTrue(report["evidence"])
        self.assertIn("Draft", report["remediation"]["description"])
        self.assertNotIn("class Store:", str(report))
        with tempfile.TemporaryDirectory() as output:
            destination = Path(output) / "research-report.json"
            packaged = run_local_synthetic_workflow(self.root, self.sha, destination)
            self.assertEqual(packaged["hypothesis"]["hypothesis_id"], hypotheses[0].hypothesis_id)
            self.assertTrue(destination.exists())
        self.assertEqual((self.root / "api.py").read_text(), SOURCE)

    def test_safe_handler_does_not_get_patch(self):
        fixed = SOURCE.replace("    return order", "    if order.org_id != identity['org_id']:\n"
                               "        raise HTTPException(status_code=403)\n    return order")
        (self.root / "api.py").write_text(fixed)
        subprocess.run(["git", "-C", str(self.root), "add", "api.py"], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Lab",
                        "-c", "user.email=lab@lab.test", "commit", "-qm", "fixed"], check=True)
        sha = subprocess.check_output(["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).strip()
        graph = build_graph(open_pinned_local_checkout(self.root, sha), sha)
        self.assertEqual(research(graph, RuleBasedResearchModel()), ())


if __name__ == "__main__":
    unittest.main()
