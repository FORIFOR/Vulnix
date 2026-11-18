import tempfile
import unittest
from pathlib import Path

from aegis.artex_bridge import ArtexRun
from aegis.research.graph_context import ArtexGraphResearchModel, make_artex_graph_request
from aegis.research.planner import research
from aegis.security_graph.builder import build_graph


SOURCE = '''from fastapi import FastAPI
app=FastAPI()
@app.get('/orders/{id}')
def get_order(id):
    order=store.get(id)
    return order
'''


class GraphArtexContextTest(unittest.TestCase):
    def graph(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / "api.py").write_text(SOURCE)
        return build_graph(root, "a" * 40)

    def run_record(self, intents, allowed=None):
        return ArtexRun(intents, False, allowed or ["graph_overview", "add_intent"],
                        [], [], {"kind": "artex-binary", "pinned": True,
                                 "isolation": {"confined": True, "enforced_after_run": True}}, 1.0)

    def test_only_graph_metadata_enters_artex_request(self):
        graph = self.graph()
        request = make_artex_graph_request(graph)
        self.assertEqual(request["targets"][0]["url"], "http://lab.test/")
        self.assertNotIn("return order", str(request))
        self.assertTrue(request["observations"])

    def test_selected_path_becomes_unverified_hypothesis(self):
        graph = self.graph()
        run = self.run_record([{"id": 1, "asset_ids": [1], "summary": "check", "unmapped": False}])
        result = research(graph, ArtexGraphResearchModel(run))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].verdict, "unverified")
        self.assertTrue(result[0].evidence_ids)

    def test_out_of_allowlist_run_is_rejected(self):
        graph = self.graph()
        run = self.run_record([{"id": 1, "asset_ids": [1], "summary": "check", "unmapped": False}],
                              allowed=["Bash"])
        with self.assertRaises(ValueError):
            ArtexGraphResearchModel(run)

    def test_unpinned_run_is_rejected(self):
        run = self.run_record([])
        run.provenance["pinned"] = False
        with self.assertRaises(ValueError):
            ArtexGraphResearchModel(run)


if __name__ == "__main__":
    unittest.main()
