import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from aegis.security_graph.builder import build_graph
from aegis.security_graph.models import GraphEdge
from aegis.security_graph.paths import search_paths
from aegis.remediation.impact import predict_node_impact


SOURCE = '''from fastapi import FastAPI
app = FastAPI()
@app.get("/orders/{order_id}")
def get_order(order_id):
    order = store.get(order_id)
    return order
'''


class GraphPathTest(unittest.TestCase):
    def graph(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / "api.py").write_text(SOURCE)
        return build_graph(root, "a" * 40)

    def test_bounded_path_and_predicted_impact(self):
        graph = self.graph()
        route = next(n.id for n in graph.nodes if n.kind == "route")
        resource = next(n.id for n in graph.nodes if n.kind == "resource")
        result = search_paths(graph, (route,), (resource,))
        self.assertEqual(len(result.paths), 1)
        self.assertEqual(result.paths[0].status, "observed_structure")
        self.assertEqual(result.paths[0].nodes, (route, result.paths[0].nodes[1], resource))
        self.assertEqual(predict_node_impact(result.paths, result.paths[0].nodes[1])["predicted_paths"], 1)
        self.assertFalse(result.truncated)

    def test_cycle_stops_and_limits_are_enforced(self):
        graph = self.graph()
        route = next(n.id for n in graph.nodes if n.kind == "route")
        resource = next(n.id for n in graph.nodes if n.kind == "resource")
        edge = GraphEdge(resource, route, "CALLS", 0.5, graph.edges[0].evidence_ids,
                         "api.py", 1, graph.commit_sha, "inferred")
        graph = replace(graph, edges=graph.edges + (edge,))
        result = search_paths(graph, (route,), (resource,), max_depth=8, max_nodes=5000, max_paths=100)
        self.assertEqual(len(result.paths), 1)
        self.assertEqual(len(set(result.paths[0].nodes)), len(result.paths[0].nodes))
        limited = search_paths(graph, (route,), (resource,), max_nodes=1)
        self.assertTrue(limited.truncated)
        self.assertEqual(limited.paths, ())
        with self.assertRaises(ValueError):
            search_paths(graph, ("missing",), (resource,))

    def test_guarded_handler_is_not_a_verified_attack(self):
        graph = self.graph()
        nodes = tuple(replace(n, status="guard_observed") if n.kind == "handler" else n for n in graph.nodes)
        graph = replace(graph, nodes=nodes)
        route = next(n.id for n in nodes if n.kind == "route")
        resource = next(n.id for n in nodes if n.kind == "resource")
        path = search_paths(graph, (route,), (resource,)).paths[0]
        self.assertEqual(path.status, "guard_observed")
        self.assertEqual(predict_node_impact((path,), path.nodes[1])["predicted_paths"], 0)

    def test_evidence_state_is_not_promoted_to_verified(self):
        graph = self.graph()
        route = next(n.id for n in graph.nodes if n.kind == "route")
        resource = next(n.id for n in graph.nodes if n.kind == "resource")
        edges = tuple(replace(e, evidence_status="hypothesized") if e.relation == "READS" else e
                      for e in graph.edges)
        path = search_paths(replace(graph, edges=edges), (route,), (resource,)).paths[0]
        self.assertEqual(path.status, "hypothesized")


if __name__ == "__main__":
    unittest.main()
