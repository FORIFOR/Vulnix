import tempfile
import unittest
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from aegis.artex_bridge import ArtexBridgeError, ArtexRun
from aegis.research.graph_context import (ArtexGraphResearchModel, make_artex_graph_request,
                                          run_confined_graph_research)
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
    def graph(self, source=SOURCE):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / "api.py").write_text(source)
        return build_graph(root, "a" * 40)

    def run_record(self, intents, graph, allowed=None):
        request = make_artex_graph_request(graph)
        request_sha256 = hashlib.sha256(json.dumps(request, ensure_ascii=False).encode()).hexdigest()
        return ArtexRun(intents, False, allowed or ["graph_overview", "add_intent"],
                        [], [], {"kind": "artex-binary", "pinned": True,
                                 "request_sha256": request_sha256,
                                 "isolation": {"confined": True, "enforced_after_run": True}}, 1.0)

    def test_only_graph_metadata_enters_artex_request(self):
        graph = self.graph()
        request = make_artex_graph_request(graph)
        self.assertEqual(request["targets"][0]["url"], "http://lab.test/")
        self.assertNotIn("return order", str(request))
        self.assertTrue(request["observations"])

    def test_selected_path_becomes_unverified_hypothesis(self):
        graph = self.graph()
        run = self.run_record([{"id": 1, "asset_ids": [1], "summary": "check", "unmapped": False}], graph)
        result = research(graph, ArtexGraphResearchModel(run, graph))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].verdict, "unverified")
        self.assertTrue(result[0].evidence_ids)

    def test_out_of_allowlist_run_is_rejected(self):
        graph = self.graph()
        run = self.run_record([{"id": 1, "asset_ids": [1], "summary": "check", "unmapped": False}],
                              graph, allowed=["Bash"])
        with self.assertRaises(ValueError):
            ArtexGraphResearchModel(run, graph)

    def test_unpinned_run_is_rejected(self):
        graph = self.graph()
        run = self.run_record([], graph)
        run.provenance["pinned"] = False
        with self.assertRaises(ValueError):
            ArtexGraphResearchModel(run, graph)

    def test_run_from_another_graph_is_rejected(self):
        graph = self.graph()
        other = self.graph(SOURCE.replace("/orders/{id}", "/private/orders/{id}"))
        run = self.run_record([{"id": 1, "asset_ids": [1], "summary": "check", "unmapped": False}], graph)
        self.assertEqual(len(research(graph, ArtexGraphResearchModel(run, graph))), 1)
        self.assertEqual(research(other, ArtexGraphResearchModel(run, graph)), ())
        with self.assertRaises(ValueError):
            ArtexGraphResearchModel(run, other)
        run.provenance.pop("request_sha256")
        with self.assertRaises(ValueError):
            ArtexGraphResearchModel(run, graph)

    def test_confined_local_runner_uses_pinned_graph_request(self):
        graph = self.graph()
        run = self.run_record([{"id": 1, "asset_ids": [1], "summary": "check", "unmapped": False}], graph)
        confinement = object()
        with patch("aegis.research.graph_context.run_artex_planner", return_value=run) as planner:
            result = run_confined_graph_research(
                graph, ["/tmp/pinned-artex"], llm_url="http://127.0.0.1:18401/v1",
                expected_sha256="a" * 64, confinement=confinement)
        self.assertEqual(len(result), 1)
        self.assertEqual(planner.call_args.args[1], make_artex_graph_request(graph))
        self.assertIs(planner.call_args.kwargs["confinement"], confinement)
        with patch("aegis.research.graph_context.run_artex_planner") as planner:
            with self.assertRaises(ValueError):
                run_confined_graph_research(graph, ["/tmp/pinned-artex"],
                                            llm_url="http://127.0.0.1:18401/v1",
                                            expected_sha256="", confinement=confinement)
            with self.assertRaises(ValueError):
                run_confined_graph_research(graph, ["/tmp/pinned-artex"],
                                            llm_url="http://127.0.0.1:18401/v1",
                                            expected_sha256="a" * 64, confinement=None)
            with self.assertRaises(ArtexBridgeError):
                run_confined_graph_research(graph, ["/tmp/pinned-artex"],
                                            llm_url="https://example.com/v1",
                                            expected_sha256="a" * 64, confinement=confinement)
            planner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
