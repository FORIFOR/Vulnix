from dataclasses import dataclass
from .models import SecurityGraph


@dataclass(frozen=True)
class AuthorizationPath:
    route_id: str
    handler_id: str
    resource_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    status: str


def authorization_paths(graph: SecurityGraph) -> tuple[AuthorizationPath, ...]:
    nodes = {node.id: node for node in graph.nodes}
    result = []
    for exposure in graph.edges:
        if exposure.relation != "EXPOSES" or nodes[exposure.source].kind != "route":
            continue
        reads = [edge for edge in graph.edges if edge.source == exposure.target and edge.relation == "READS"]
        if not reads:
            continue
        handler = nodes[exposure.target]
        ids = set(exposure.evidence_ids)
        for edge in reads:
            ids.update(edge.evidence_ids)
        result.append(AuthorizationPath(exposure.source, handler.id,
                                        tuple(edge.target for edge in reads), tuple(sorted(ids)), handler.status))
    return tuple(result)
