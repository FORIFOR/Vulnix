"""MCP tool scope remains an unverified policy question until isolated validation."""
import tempfile
import unittest
from pathlib import Path

from aegis.analyzers.ai_agents import review_mcp_tool_scope
from aegis.security_graph.builder import build_graph


SOURCE = '''from fastmcp import FastMCP
server = FastMCP("lab")

@server.tool()
def read_customer(customer_id):
    return store.get(customer_id)
'''


class McpScopeTest(unittest.TestCase):
    def build(self, source):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / "tools.py").write_text(source)
        return build_graph(root, "a" * 40)

    def test_data_read_without_local_role_declaration_requires_review(self):
        graph = self.build(SOURCE)
        candidates = review_mcp_tool_scope(graph)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].status, "scope_unknown")
        self.assertEqual(candidates[0].declared_role_ids, ())
        self.assertEqual(candidates[0].validation_status, "not_run")
        self.assertTrue(set(candidates[0].evidence_ids) <= set(graph.evidence))

    def test_declared_role_is_recorded_but_not_treated_as_enforced(self):
        source = SOURCE.replace("@server.tool()", '@server.tool()\n@requires_role("admin")')
        graph = self.build(source)
        candidates = review_mcp_tool_scope(graph)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].status, "role_declaration_unverified")
        self.assertEqual(len(candidates[0].declared_role_ids), 1)
        self.assertNotIn('"admin"', str(graph))
        self.assertTrue(any(edge.relation == "REQUIRES_ROLE" and edge.evidence_status == "inferred"
                            for edge in graph.edges))

    def test_dynamic_role_declaration_is_unknown(self):
        source = SOURCE.replace("@server.tool()", "@server.tool()\n@requires_role(role_from_config)")
        graph = self.build(source)
        candidates = review_mcp_tool_scope(graph)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].status, "scope_unknown")

    def test_role_wrapper_outside_registration_does_not_count(self):
        source = SOURCE.replace("@server.tool()", '@requires_role("admin")\n@server.tool()')
        graph = self.build(source)
        candidates = review_mcp_tool_scope(graph)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].status, "scope_unknown")
        self.assertFalse(any(edge.relation == "REQUIRES_ROLE" for edge in graph.edges))

    def test_tool_without_resource_edge_is_not_a_scope_candidate(self):
        graph = self.build(SOURCE.replace("return store.get(customer_id)", "return 'ok'"))
        self.assertEqual(review_mcp_tool_scope(graph), ())


if __name__ == "__main__":
    unittest.main()
