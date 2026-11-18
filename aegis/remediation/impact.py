"""Graph-only remediation predictions; no probability or verified fix claim."""
from aegis.security_graph.paths import AttackPath


def predict_node_impact(paths: tuple[AttackPath, ...], node_id: str) -> dict:
    affected = [path for path in paths if node_id in path.nodes and path.status not in {"refuted", "guard_observed"}]
    return {"node_id": node_id, "predicted_paths": len(affected),
            "path_ids": [path.id for path in affected], "status": "prediction_only",
            "assumption": "このノードの修正が全対象経路を遮断できる場合"}
