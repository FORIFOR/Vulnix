"""MCP registration is a structural fact, not proof of tool authorization."""
import tempfile
import unittest
from pathlib import Path

from aegis.security_graph.builder import build_graph
from aegis.analyzers.ai_agents import review_mcp_tool_scope
from aegis.security_graph.paths import candidate_paths
from aegis.security_graph.queries import authorization_paths
from aegis.security_graph.models import SecurityGraph
from aegis.security_graph.sqlite_store import GraphStore, PARSER_VERSION
from aegis.research.planner import RuleBasedResearchModel, research


MCP_SOURCE = '''from fastmcp import FastMCP as Server
server = Server("lab")

@server.tool()
def read_customer(customer_id):
    return store.get(customer_id)
'''


class AiToolGraphTest(unittest.TestCase):
    def build(self, source):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / "tools.py").write_text(source)
        return build_graph(root, "a" * 40)

    def test_registered_mcp_tool_reaches_data_as_unverified_structure(self):
        graph = self.build(MCP_SOURCE)
        tools = [node for node in graph.nodes if node.kind == "ai_tool"]
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0].name, "read_customer")
        self.assertEqual(tools[0].status, "observed_registration")
        paths = [path for path in candidate_paths(graph).paths if path.nodes[0] == tools[0].id]
        self.assertEqual(len(paths), 1)
        self.assertEqual([edge.relation for edge in paths[0].edges], ["EXPOSES", "READS"])
        self.assertEqual(paths[0].status, "observed_structure")
        self.assertTrue(set(paths[0].evidence_ids) <= set(graph.evidence))
        self.assertTrue(all(graph.evidence[eid].commit_sha == graph.commit_sha
                            for eid in paths[0].evidence_ids))
        self.assertEqual(authorization_paths(graph), ())
        self.assertEqual(research(graph, RuleBasedResearchModel()), ())

    def test_other_tool_decorator_is_not_mcp_registration(self):
        source = MCP_SOURCE.replace('from fastmcp import FastMCP as Server',
                                    'from unrelated import Server')
        graph = self.build(source)
        self.assertFalse(any(node.kind == "ai_tool" for node in graph.nodes))

    def test_rebound_server_is_not_mcp_registration(self):
        source = MCP_SOURCE.replace('@server.tool()', 'server = unrelated_factory()\n\n@server.tool()')
        graph = self.build(source)
        self.assertFalse(any(node.kind == "ai_tool" for node in graph.nodes))

    def test_conditional_server_rebinding_is_not_observed_registration(self):
        source = MCP_SOURCE.replace('@server.tool()',
                                    'if flag:\n    server = unrelated_factory()\n\n@server.tool()')
        graph = self.build(source)
        self.assertFalse(any(node.kind == "ai_tool" for node in graph.nodes))

    def test_dynamic_tool_name_remains_unknown(self):
        source = MCP_SOURCE.replace('@server.tool()', '@server.tool(name=dynamic_name)')
        graph = self.build(source)
        tools = [node for node in graph.nodes if node.kind == "ai_tool"]
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0].status, "unknown")

    def test_literal_tool_alias_is_not_stored_as_source_value(self):
        source = MCP_SOURCE.replace('@server.tool()', '@server.tool(name="private_alias")')
        graph = self.build(source)
        tool = next(node for node in graph.nodes if node.kind == "ai_tool")
        self.assertEqual(tool.name, "read_customer")
        self.assertEqual(tool.status, "registration_observed_name_redacted")
        self.assertNotIn("private_alias", str(graph))

    def test_official_mcp_fastmcp_import_alias_is_recognized(self):
        source = MCP_SOURCE.replace('from fastmcp import FastMCP as Server',
                                    'from mcp.server.fastmcp import FastMCP as Server')
        graph = self.build(source)
        self.assertEqual(len([node for node in graph.nodes if node.kind == "ai_tool"]), 1)

    def test_uninvoked_nested_helper_is_not_a_tool_data_read(self):
        source = MCP_SOURCE.replace("    return store.get(customer_id)",
                                    "    def unused():\n"
                                    "        return store.get(customer_id)\n"
                                    "    return 'ok'")
        graph = self.build(source)
        self.assertFalse(any(edge.relation == "READS" for edge in graph.edges))
        self.assertEqual(review_mcp_tool_scope(graph), ())

    def test_uninvoked_lambda_is_not_a_tool_data_read(self):
        source = MCP_SOURCE.replace("    return store.get(customer_id)",
                                    "    unused = lambda: store.get(customer_id)\n"
                                    "    return 'ok'")
        graph = self.build(source)
        self.assertFalse(any(edge.relation == "READS" for edge in graph.edges))
        self.assertEqual(review_mcp_tool_scope(graph), ())

    def test_immediately_invoked_lambda_keeps_data_read(self):
        source = MCP_SOURCE.replace("return store.get(customer_id)",
                                    "return (lambda: store.get(customer_id))()")
        graph = self.build(source)
        self.assertTrue(any(edge.relation == "READS" for edge in graph.edges))
        self.assertEqual(len(review_mcp_tool_scope(graph)), 1)

    def test_parser_upgrade_preserves_prior_commit_snapshot(self):
        graph = self.build(MCP_SOURCE)
        with tempfile.TemporaryDirectory() as temp:
            with GraphStore(Path(temp) / "security-graph.sqlite") as store:
                old_id = store.save_snapshot("lab", SecurityGraph(graph.commit_sha, (), (), {}),
                                             "source-ast-v4")
                new_id = store.save_snapshot("lab", graph, PARSER_VERSION)
                self.assertNotEqual(old_id, new_id)
                self.assertEqual(store.load_graph(old_id).nodes, ())
                self.assertTrue(any(n.kind == "ai_tool" for n in store.load_graph(new_id).nodes))
                self.assertEqual(new_id, store.save_snapshot("lab", graph, PARSER_VERSION))


if __name__ == "__main__":
    unittest.main()
