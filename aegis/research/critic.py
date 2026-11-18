from aegis.security_graph.models import SecurityGraph
from aegis.security_graph.queries import authorization_paths
from .hypotheses import Hypothesis


def critique(graph: SecurityGraph, hypothesis: Hypothesis) -> bool:
    """Independent deterministic check; it cannot establish exploitability."""
    return any(path.status == "unknown" and
               path.route_id in hypothesis.affected_nodes and
               path.handler_id in hypothesis.affected_nodes and
               set(hypothesis.evidence_ids) & set(path.evidence_ids)
               for path in authorization_paths(graph))
