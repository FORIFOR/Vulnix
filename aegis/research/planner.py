"""Pluggable hypothesis interface. The local model is deterministic and offline.

This is separate from ARTEX's execution catalog. ARTEX integration is a later
gate; no model output here can request a command or a Gateway action.
"""
from typing import Protocol

from aegis.security_graph.models import SecurityGraph
from aegis.security_graph.queries import authorization_paths
from .critic import critique
from .evidence import valid_references
from .hypotheses import Hypothesis
from .ranking import rank


class ResearchModel(Protocol):
    def propose(self, context: dict) -> list[dict]: ...


class RuleBasedResearchModel:
    """Offline baseline. Produces candidates, never confirmed findings."""
    def propose(self, context: dict) -> list[dict]:
        return [{"hypothesis_id": f"H-{i:03}",
                 "category": "broken_object_authorization",
                 "summary": "組織境界の検証が不足している可能性",
                 "affected_nodes": [p["route_id"], p["handler_id"]],
                 "evidence_ids": p["evidence_ids"],
                 "assumptions": ["共通ミドルウェアで認可されていない場合"],
                 "counter_evidence": ["共通ミドルウェアによる組織照合"],
                 "validation_strategy": "isolated_unit_test", "confidence": 0.5,
                 "uncertainties": ["動的認可と依存関係内の検査は未解析"]}
                for i, p in enumerate(context["paths"], 1) if p["status"] == "unknown"]


def research(graph: SecurityGraph, model: ResearchModel) -> tuple[Hypothesis, ...]:
    # Send identifiers and statuses, never raw source text or secret values.
    context = {"commit_sha": graph.commit_sha,
               "paths": [dict(route_id=p.route_id, handler_id=p.handler_id,
                              resource_ids=list(p.resource_ids), evidence_ids=list(p.evidence_ids),
                              status=p.status) for p in authorization_paths(graph)]}
    raw_items = model.propose(context)
    if not isinstance(raw_items, list) or len(raw_items) > 100:
        return ()
    accepted = []
    allowed = set(Hypothesis.__dataclass_fields__) - {"verdict"}
    for raw in raw_items:
        if not isinstance(raw, dict) or set(raw) != allowed:
            continue
        try:
            if any(type(raw[key]) is not str or len(raw[key]) > 500 for key in
                   ("hypothesis_id", "category", "summary", "validation_strategy")):
                continue
            if raw["category"] != "broken_object_authorization" or raw["validation_strategy"] != "isolated_unit_test":
                continue
            if type(raw["confidence"]) not in (int, float) or not 0 <= raw["confidence"] <= 1:
                continue
            for key in ("affected_nodes", "evidence_ids", "assumptions", "counter_evidence", "uncertainties"):
                if type(raw[key]) is not list or len(raw[key]) > 20 or any(type(x) is not str or len(x) > 500 for x in raw[key]):
                    raise ValueError("invalid sequence")
            item = Hypothesis(**{k: tuple(v) if isinstance(v, list) else v for k, v in raw.items()})
        except (TypeError, ValueError):
            continue
        if valid_references(graph, item.affected_nodes, item.evidence_ids) and critique(graph, item):
            accepted.append(item)
    return rank(tuple(accepted))
