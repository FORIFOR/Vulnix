"""Review candidates for MCP data access; no finding is confirmed here."""
import hashlib
from dataclasses import dataclass

from aegis.security_graph.models import SecurityGraph


@dataclass(frozen=True)
class McpScopeCandidate:
    id: str
    tool_id: str
    handler_id: str
    resource_ids: tuple[str, ...]
    declared_role_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    status: str
    validation_status: str = "not_run"


def review_mcp_tool_scope(graph: SecurityGraph) -> tuple[McpScopeCandidate, ...]:
    """Identify MCP tools with observed data relations for manual policy review.

    An absent role declaration is not evidence that external authorization is
    absent. A declaration is not evidence that its wrapper actually enforces it.
    """
    nodes = {node.id: node for node in graph.nodes}
    result = []
    for exposure in graph.edges:
        if (exposure.relation != "EXPOSES" or
                nodes.get(exposure.source, None) is None or
                nodes[exposure.source].kind != "ai_tool"):
            continue
        reads = [edge for edge in graph.edges
                 if edge.source == exposure.target and edge.relation == "READS" and
                 edge.target in nodes]
        if not reads:
            continue
        roles = [edge for edge in graph.edges
                 if edge.source == exposure.target and edge.relation == "REQUIRES_ROLE" and
                 edge.target in nodes]
        resource_ids = tuple(sorted({edge.target for edge in reads}))
        role_ids = tuple(sorted({edge.target for edge in roles}))
        evidence = tuple(sorted({ref for edge in (exposure, *reads, *roles)
                                 for ref in edge.evidence_ids}))
        candidate_id = hashlib.sha256("\0".join((graph.commit_sha, exposure.source,
                                                    *resource_ids, *role_ids)).encode()).hexdigest()[:24]
        result.append(McpScopeCandidate(candidate_id, exposure.source, exposure.target,
                                        resource_ids, role_ids, evidence,
                                        "role_declaration_unverified" if roles else "scope_unknown"))
    return tuple(sorted(result, key=lambda item: item.id))
