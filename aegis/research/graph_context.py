"""ARTEX selects anonymized path IDs; Vulnix owns evidence and execution gates."""
import hashlib
import json
import re

from aegis.artex_bridge import (ArtexRun, PLANNER_TOOL_ALLOWLIST,
                                require_loopback_llm, run_artex_planner)
from aegis.security_graph.models import SecurityGraph
from aegis.security_graph.queries import authorization_paths
from .planner import make_research_context, research


def make_artex_graph_request(graph: SecurityGraph) -> dict:
    paths = authorization_paths(graph)[:20]
    observations = []
    targets = []
    for index, path in enumerate(paths, 1):
        fact = {"path_id": index, "edge_status": path.status,
                "node_ids": [path.route_id, path.handler_id, *path.resource_ids],
                "evidence_ids": list(path.evidence_ids)}
        detail = json.dumps(fact, ensure_ascii=False, sort_keys=True)
        observations.append({"title": f"Graph path {index}", "detail": detail})
        targets.append({"asset_id": index, "target_id": f"path-{index}", "url": "http://lab.test/"})
    return {"goal": "匿名化されたコード構造から認可境界の調査候補を選ぶ。脆弱性を確定せず、実行を計画しない。",
            "targets": targets, "observations": observations, "max_turns": 6}


class ArtexGraphResearchModel:
    """Adapter for an already validated, pinned and confined ARTEX planner run."""
    def __init__(self, run: ArtexRun, graph: SecurityGraph):
        request = make_artex_graph_request(graph)
        request_sha256 = hashlib.sha256(json.dumps(request, ensure_ascii=False).encode()).hexdigest()
        if (not isinstance(run, ArtexRun) or run.provenance.get("kind") != "artex-binary" or
            run.provenance.get("pinned") is not True or
            run.provenance.get("request_sha256") != request_sha256 or
            run.provenance.get("isolation", {}).get("confined") is not True or
            run.provenance.get("isolation", {}).get("enforced_after_run") is not True or
            not set(run.allowed_tools) <= PLANNER_TOOL_ALLOWLIST or
            any(item.get("allowed") and item.get("name") not in PLANNER_TOOL_ALLOWLIST
                for item in run.tool_calls)):
            raise ValueError("untrusted ARTEX planner run")
        self.run = run
        self.graph = graph

    def propose(self, context: dict) -> list[dict]:
        if context != make_research_context(self.graph):
            return []
        paths = context.get("paths", [])[:20]
        selected = []
        for intent in self.run.intents:
            if intent.get("unmapped") or not isinstance(intent.get("asset_ids"), list):
                continue
            for asset_id in intent["asset_ids"]:
                if type(asset_id) is int and 1 <= asset_id <= len(paths) and asset_id not in selected:
                    selected.append(asset_id)
        return [{"hypothesis_id": f"H-ARTEX-{index:03}",
                 "category": "broken_object_authorization",
                 "summary": "組織境界の検証が不足している可能性",
                 "affected_nodes": [paths[index - 1]["route_id"], paths[index - 1]["handler_id"]],
                 "evidence_ids": paths[index - 1]["evidence_ids"],
                 "assumptions": ["共通の認可処理が存在しない場合"],
                 "counter_evidence": ["共通ミドルウェアによる組織照合"],
                 "validation_strategy": "isolated_unit_test", "confidence": 0.5,
                 "uncertainties": ["静的解析で確認できない動的処理"]}
                for index in selected if paths[index - 1]["status"] == "unknown"]


def run_confined_graph_research(graph: SecurityGraph, command: list[str], *, llm_url: str,
                                expected_sha256: str, confinement, pg_dsn: str = "",
                                forbidden_paths=(), data_dirs=()):
    """Trusted, local-only entry point; ARTEX can select paths but cannot execute them."""
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or "") or confinement is None:
        raise ValueError("pinned ARTEX binary and confinement required")
    require_loopback_llm(llm_url)
    run = run_artex_planner(command, make_artex_graph_request(graph), llm_url=llm_url,
                            expected_sha256=expected_sha256, confinement=confinement,
                            pg_dsn=pg_dsn,
                            forbidden_paths=forbidden_paths, data_dirs=data_dirs)
    return research(graph, ArtexGraphResearchModel(run, graph))
