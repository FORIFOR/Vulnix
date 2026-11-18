"""Fixed synthetic MCP policy controls; no customer tool is executed."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.analyzers.ai_agents import review_mcp_tool_scope
from aegis.confinement import KernelConfinement
from aegis.security_graph.builder import build_graph
from aegis.validation.mcp_policy_lab import SOURCE, run_mcp_policy_lab
from aegis.validation.sandbox import SandboxUnavailable


class McpPolicyLabTest(unittest.TestCase):
    def test_graph_marks_declarations_as_unverified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "tools.py").write_text(SOURCE, encoding="utf-8")
            graph = build_graph(root, "a" * 40)
        candidates = review_mcp_tool_scope(graph)
        by_name = {next(node.name for node in graph.nodes if node.id == item.tool_id): item
                   for item in candidates}
        self.assertEqual(set(by_name), {"open_customer", "guarded_customer", "misordered_customer"})
        self.assertEqual(by_name["open_customer"].status, "scope_unknown")
        self.assertEqual(by_name["guarded_customer"].status, "role_declaration_unverified")
        self.assertEqual(by_name["misordered_customer"].status, "scope_unknown")
        self.assertTrue(all(item.validation_status == "not_run" for item in candidates))

    def test_unavailable_confinement_fails_closed(self):
        with patch("aegis.validation.sandbox.platform.system", return_value="Unsupported"):
            with self.assertRaises(SandboxUnavailable):
                run_mcp_policy_lab()

    @unittest.skipUnless(sys.platform == "darwin" or
                         (sys.platform.startswith("linux") and KernelConfinement().status()["ok"]),
                         "synthetic sandbox requires kernel confinement or macOS")
    def test_decorator_order_in_confined_synthetic_runtime(self):
        result = run_mcp_policy_lab()
        self.assertEqual(result, {
            "open_viewer_reached_data": True,
            "guarded_viewer_denied": True,
            "misordered_viewer_reached_data": True,
            "guarded_admin_reached_data": True,
        })


if __name__ == "__main__":
    unittest.main()
