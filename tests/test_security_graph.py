"""Offline contracts for source graph and authorization research."""
import tempfile
import unittest
from pathlib import Path

from aegis.security_graph.builder import build_graph
from aegis.security_graph.queries import authorization_paths
from aegis.research.planner import RuleBasedResearchModel, research


VULNERABLE = '''from fastapi import FastAPI, HTTPException, Depends
app = FastAPI()

def current_identity():
    return {"org_id": "org-a"}

@app.get("/orders/{order_id}")
def get_order(order_id: str, identity=Depends(current_identity)):
    order = store.get(order_id)
    return order
'''

PROTECTED = VULNERABLE.replace('    return order',
    '    if order.org_id != identity["org_id"]:\n'
    '        raise HTTPException(status_code=403)\n'
    '    return order')


class SecurityGraphTest(unittest.TestCase):
    def build(self, source):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "api.py").write_text(source)
        return build_graph(root, "a" * 40)

    def test_evidence_on_every_node_and_edge(self):
        graph = self.build(VULNERABLE)
        self.assertTrue(graph.nodes)
        self.assertTrue(graph.edges)
        for node in graph.nodes:
            self.assertEqual(node.commit_sha, "a" * 40)
            self.assertEqual(node.source_path, "api.py")
            self.assertGreater(node.source_line, 0)
            self.assertTrue(node.evidence_ids)
        for edge in graph.edges:
            self.assertTrue(edge.evidence_ids)
            self.assertTrue(set(edge.evidence_ids) <= set(graph.evidence))
            self.assertEqual(edge.commit_sha, "a" * 40)
            self.assertEqual(edge.source_path, "api.py")
            self.assertGreater(edge.source_line, 0)
        self.assertEqual(len(authorization_paths(graph)), 1)
        self.assertEqual(authorization_paths(graph)[0].status, "unknown")
        self.assertTrue(any(edge.relation == "USES_DEPENDENCY" for edge in graph.edges))

    def test_missing_check_is_hypothesis_not_finding(self):
        graph = self.build(VULNERABLE)
        hypotheses = research(graph, RuleBasedResearchModel())
        self.assertEqual(len(hypotheses), 1)
        self.assertEqual(hypotheses[0].verdict, "unverified")
        self.assertTrue(hypotheses[0].evidence_ids)

    def test_known_guard_suppresses_hypothesis(self):
        graph = self.build(PROTECTED)
        self.assertEqual(len({node.id for node in graph.nodes}), len(graph.nodes))
        self.assertEqual(authorization_paths(graph)[0].status, "guard_observed")
        self.assertEqual(research(graph, RuleBasedResearchModel()), ())
        class ForcedModel:
            def propose(self, context):
                path = context["paths"][0]
                return [{"hypothesis_id": "H-forced", "category": "broken_object_authorization",
                         "summary": "誤った仮説", "affected_nodes": [path["route_id"], path["handler_id"]],
                         "evidence_ids": path["evidence_ids"], "assumptions": [],
                         "counter_evidence": [], "validation_strategy": "isolated_unit_test",
                         "confidence": 1.0, "uncertainties": []}]
        self.assertEqual(research(graph, ForcedModel()), ())

    def test_inverted_org_guard_does_not_suppress_hypothesis(self):
        inverted = PROTECTED.replace('order.org_id != identity["org_id"]',
                                     'order.org_id == identity["org_id"]')
        graph = self.build(inverted)
        self.assertEqual(authorization_paths(graph)[0].status, "unknown")
        self.assertEqual(len(research(graph, RuleBasedResearchModel())), 1)

    def test_nested_unused_guard_does_not_suppress_hypothesis(self):
        nested = VULNERABLE.replace('    return order',
            '    def unused():\n'
            '        if order.org_id != identity["org_id"]:\n'
            '            raise HTTPException(status_code=403)\n'
            '    return order')
        self.assertEqual(authorization_paths(self.build(nested))[0].status, "unknown")

    def test_conditional_rejection_does_not_count_as_guard(self):
        conditional = VULNERABLE.replace('    return order',
            '    if order.org_id != identity["org_id"]:\n'
            '        if identity.get("is_admin"):\n'
            '            raise HTTPException(status_code=403)\n'
            '    return order')
        graph = self.build(conditional)
        self.assertEqual(authorization_paths(graph)[0].status, "unknown")
        self.assertEqual(len(research(graph, RuleBasedResearchModel())), 1)

    def test_unreachable_guard_after_return_is_unknown(self):
        unreachable = VULNERABLE.replace('    return order',
            '    return order\n'
            '    if order.org_id != identity["org_id"]:\n'
            '        raise HTTPException(status_code=403)')
        graph = self.build(unreachable)
        self.assertEqual(authorization_paths(graph)[0].status, "unknown")
        self.assertEqual(len(research(graph, RuleBasedResearchModel())), 1)

    def test_dynamic_identity_fallback_is_unknown(self):
        fallback = PROTECTED.replace('identity["org_id"]',
                                     'identity.get("org_id", order.org_id)')
        graph = self.build(fallback)
        self.assertEqual(authorization_paths(graph)[0].status, "unknown")
        self.assertEqual(len(research(graph, RuleBasedResearchModel())), 1)

    def test_bad_model_references_rejected(self):
        class BadModel:
            def propose(self, _):
                return [{"hypothesis_id": "H-1", "category": "broken_object_authorization",
                         "affected_nodes": ["invented"], "evidence_ids": ["fake"],
                         "summary": "fake", "assumptions": [], "counter_evidence": [],
                         "validation_strategy": "isolated_unit_test", "confidence": 1.0,
                         "uncertainties": []}]
        self.assertEqual(research(self.build(VULNERABLE), BadModel()), ())

    def test_model_receives_only_graph_identifiers(self):
        seen = []
        class CapturingModel:
            def propose(self, context):
                seen.append(context)
                return []
        self.assertEqual(research(self.build(VULNERABLE), CapturingModel()), ())
        self.assertNotIn("return order", str(seen))
        self.assertEqual(set(seen[0]), {"commit_sha", "paths"})

    def test_symlink_and_secret_files_are_not_read(self):
        with tempfile.TemporaryDirectory() as outside, tempfile.TemporaryDirectory() as inside:
            (Path(outside) / "private.py").write_text('SECRET = "do-not-read"')
            root = Path(inside)
            (root / "external.py").symlink_to(Path(outside) / "private.py")
            (root / ".env.local").write_text('SECRET=do-not-read')
            (root / "data-export").mkdir()
            (root / "data-export" / "private.py").write_text('SECRET = "do-not-read"')
            (root / "api.py").write_text(VULNERABLE)
            graph = build_graph(root, "b" * 40)
            self.assertTrue(all(e.source_path == "api.py" for e in graph.evidence.values()))

    def test_database_named_source_file_is_not_treated_as_secret_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "database.py").write_text(VULNERABLE)
            graph = build_graph(root, "b" * 40)
            self.assertTrue(any(node.source_path == "database.py" for node in graph.nodes))

    def test_next_route_without_data_relation_is_not_an_attack_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            route = root / "app" / "api" / "orders" / "route.ts"
            route.parent.mkdir(parents=True)
            route.write_text("export async function GET() { return Response.json({}) }\n")
            graph = build_graph(root, "c" * 40)
            self.assertTrue(any(n.kind == "route" for n in graph.nodes))
            self.assertEqual(authorization_paths(graph), ())

    def test_unparseable_python_is_recorded_as_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "api.py").write_text("def broken(:\n")
            graph = build_graph(root, "d" * 40)
            self.assertEqual(graph.nodes[0].status, "unknown")


if __name__ == "__main__":
    unittest.main()
