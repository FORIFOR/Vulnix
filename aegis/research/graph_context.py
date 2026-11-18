"""ARTEX selects anonymized path IDs; Vulnix owns evidence and execution gates."""
import json

from aegis.artex_bridge import ArtexRun, PLANNER_TOOL_ALLOWLIST
from aegis.security_graph.models import SecurityGraph
from aegis.security_graph.queries import authorization_paths


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
    def __init__(self, run: ArtexRun):
        if (not isinstance(run, ArtexRun) or run.provenance.get("kind") != "artex-binary" or
            run.provenance.get("pinned") is not True or
            run.provenance.get("isolation", {}).get("confined") is not True or
            run.provenance.get("isolation", {}).get("enforced_after_run") is not True or
            not set(run.allowed_tools) <= PLANNER_TOOL_ALLOWLIST or
            any(item.get("allowed") and item.get("name") not in PLANNER_TOOL_ALLOWLIST
                for item in run.tool_calls)):
            raise ValueError("untrusted ARTEX planner run")
        self.run = run

    def propose(self, context: dict) -> list[dict]:
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
