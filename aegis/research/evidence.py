from aegis.security_graph.models import SecurityGraph


def valid_references(graph: SecurityGraph, nodes: tuple[str, ...], evidence: tuple[str, ...]) -> bool:
    known_nodes = {node.id for node in graph.nodes}
    return bool(nodes and evidence and set(nodes) <= known_nodes and set(evidence) <= set(graph.evidence))
