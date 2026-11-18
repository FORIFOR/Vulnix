"""Immutable per-service graph snapshot contracts."""
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from aegis.security_graph.builder import build_graph
from aegis.security_graph.models import GraphEdge, SecurityGraph
from aegis.security_graph.storage import GraphStore


SOURCE = '''from fastapi import FastAPI, Depends
app = FastAPI()
def current_identity():
    return None
@app.get("/orders/{order_id}")
def get_order(order_id, identity=Depends(current_identity)):
    order = store.get(order_id)
    return order
'''


class GraphStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "api.py").write_text(SOURCE)
        self.graph = build_graph(self.root, "a" * 40)
        self.store = GraphStore(self.root / "tenant-a" / "security-graph.sqlite")
        self.addCleanup(self.store.close)

    def test_idempotent_snapshot_and_evidence(self):
        snapshot = self.store.save_snapshot("repo-lab", self.graph, "python-ast-v1")
        self.assertEqual(snapshot, self.store.save_snapshot("repo-lab", self.graph, "python-ast-v1"))
        self.assertEqual(self.store.list_snapshots()[0]["commit_sha"], "a" * 40)
        loaded = self.store.load_graph(snapshot)
        self.assertEqual(loaded, self.graph)
        self.assertEqual(len(loaded.evidence), len(self.graph.evidence))
        self.assertEqual(self.store.schema_version(), 4)

    def test_same_key_different_content_is_rejected(self):
        self.store.save_snapshot("repo-lab", self.graph, "python-ast-v1")
        changed = replace(self.graph, nodes=tuple(replace(n, name="tampered") if i == 0 else n
                                                  for i, n in enumerate(self.graph.nodes)))
        with self.assertRaises(ValueError):
            self.store.save_snapshot("repo-lab", changed, "python-ast-v1")

    def test_missing_edge_endpoint_rolls_back(self):
        edge = self.graph.edges[0]
        bad = replace(self.graph, edges=(replace(edge, target="missing"),))
        with self.assertRaises(ValueError):
            self.store.save_snapshot("repo-lab", bad, "python-ast-v1")
        self.assertEqual(self.store.list_snapshots(), [])

    def test_immutable_rows_reject_direct_update(self):
        snapshot = self.store.save_snapshot("repo-lab", self.graph, "python-ast-v1")
        self.store.append_record("graph_paths", snapshot, "P-1", {"id": "P-1"})
        with self.assertRaises(sqlite3.DatabaseError):
            self.store.connection.execute("UPDATE graph_nodes SET name='changed' WHERE snapshot_id=?", (snapshot,))
        with self.assertRaises(sqlite3.DatabaseError):
            self.store.connection.execute("DELETE FROM graph_snapshots WHERE id=?", (snapshot,))
        with self.assertRaises(sqlite3.DatabaseError):
            self.store.connection.execute("UPDATE graph_snapshots SET commit_sha=? WHERE id=?", ("b" * 40, snapshot))
        with self.assertRaises(sqlite3.DatabaseError):
            self.store.connection.execute("UPDATE graph_paths SET payload_json='{}' WHERE snapshot_id=?", (snapshot,))
        with self.assertRaises(sqlite3.DatabaseError):
            self.store.connection.execute("DELETE FROM graph_edge_evidence WHERE snapshot_id=?", (snapshot,))

    def test_tenant_database_files_do_not_share_rows(self):
        a = self.store.save_snapshot("repo-lab", self.graph, "python-ast-v1")
        other = GraphStore(self.root / "tenant-b" / "security-graph.sqlite")
        self.addCleanup(other.close)
        self.assertEqual(other.list_snapshots(), [])
        with self.assertRaises(KeyError):
            other.load_graph(a)

    def test_snapshot_commit_mismatch_and_evidence_reference_rejected(self):
        bad_edge = GraphEdge("missing", "missing", "READS", 1, ("missing",), "api.py", 1, "b" * 40)
        bad = SecurityGraph(self.graph.commit_sha, self.graph.nodes, (bad_edge,), self.graph.evidence)
        with self.assertRaises(ValueError):
            self.store.save_snapshot("repo-lab", bad, "python-ast-v1")

    def test_mcp_validation_is_immutable_and_bound_to_snapshot_node(self):
        snapshot = self.store.save_snapshot("repo-lab", self.graph, "python-ast-v1")
        node_id = self.graph.nodes[0].id
        payload = {"validation_id": "mcp-v1", "candidate_id": "candidate-v1",
                   "tool_id": node_id, "synthetic_only": True}
        self.store.append_mcp_validation(snapshot, "mcp-v1", "candidate-v1", node_id, payload)
        self.store.append_mcp_validation(snapshot, "mcp-v1", "candidate-v1", node_id, payload)
        self.assertEqual(self.store.mcp_validations(snapshot), [payload])
        with self.assertRaises(ValueError):
            self.store.append_mcp_validation(snapshot, "mcp-v1", "candidate-v1", node_id,
                                             {**payload, "synthetic_only": False})
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.append_mcp_validation(snapshot, "mcp-v2", "candidate-v1", "missing",
                                             {**payload, "validation_id": "mcp-v2", "tool_id": "missing"})
        with self.assertRaises(sqlite3.DatabaseError):
            self.store.connection.execute("UPDATE graph_mcp_validations SET candidate_id='other'"
                                          " WHERE snapshot_id=?", (snapshot,))

    def test_v3_schema_migrates_without_rewriting_snapshot(self):
        snapshot = self.store.save_snapshot("repo-lab", self.graph, "python-ast-v1")
        path = self.root / "tenant-a" / "security-graph.sqlite"
        self.store.close()
        with sqlite3.connect(path) as connection:
            connection.execute("DROP TABLE graph_mcp_validations")
            connection.execute("PRAGMA user_version = 3")
        with GraphStore(path) as upgraded:
            self.assertEqual(upgraded.schema_version(), 4)
            self.assertEqual(upgraded.load_graph(snapshot), self.graph)
            self.assertEqual(upgraded.mcp_validations(snapshot), [])


if __name__ == "__main__":
    unittest.main()
