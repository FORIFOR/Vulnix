"""Bounded structural graph search. Reachability is never proof of a flaw."""
import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass

from .models import GraphEdge, SecurityGraph


@dataclass(frozen=True)
class AttackPath:
    id: str
    nodes: tuple[str, ...]
    edges: tuple[GraphEdge, ...]
    evidence_ids: tuple[str, ...]
    status: str


@dataclass(frozen=True)
class PathSearchResult:
    paths: tuple[AttackPath, ...]
    visited_nodes: int
    truncated: bool


def _status(nodes: tuple[str, ...], edges: tuple[GraphEdge, ...], node_map: dict) -> str:
    if any(edge.evidence_status == "refuted" for edge in edges):
        return "refuted"
    if any(node_map[node].status == "guard_observed" for node in nodes):
        return "guard_observed"
    if edges and all(edge.evidence_status == "verified" for edge in edges):
        return "verified"
    if any(edge.evidence_status == "hypothesized" for edge in edges):
        return "hypothesized"
    if any(edge.evidence_status == "inferred" for edge in edges):
        return "inferred"
    return "observed_structure"


def search_paths(graph: SecurityGraph, starts: tuple[str, ...], targets: tuple[str, ...], *,
                 max_depth: int = 8, max_nodes: int = 5000, max_paths: int = 100,
                 importance: dict[str, int] | None = None) -> PathSearchResult:
    if not (1 <= max_depth <= 8 and 1 <= max_nodes <= 5000 and 1 <= max_paths <= 100):
        raise ValueError("search limits exceed reviewed bounds")
    node_map = {node.id: node for node in graph.nodes}
    if not starts or not targets or not set(starts + targets) <= set(node_map):
        raise ValueError("unknown or empty search endpoints")
    adjacency = defaultdict(list)
    for edge in graph.edges:
        if edge.source not in node_map or edge.target not in node_map or edge.commit_sha != graph.commit_sha:
            raise ValueError("invalid graph edge")
        adjacency[edge.source].append(edge)
    for edges in adjacency.values():
        edges.sort(key=lambda item: (item.target, item.relation, item.source_line))
    queue = deque((start, (start,), ()) for start in dict.fromkeys(starts))
    target_set = set(targets)
    found = []
    seen = set()
    explored = 0
    truncated = False
    while queue:
        if explored >= max_nodes or len(found) >= max_paths:
            truncated = True
            break
        current, nodes, edges = queue.popleft()
        explored += 1
        seen.add(current)
        if current in target_set and edges:
            eid = hashlib.sha256("\0".join(nodes).encode()).hexdigest()[:24]
            refs = tuple(dict.fromkeys(ref for edge in edges for ref in edge.evidence_ids))
            found.append(AttackPath(eid, nodes, edges, refs, _status(nodes, edges, node_map)))
            continue
        if len(edges) >= max_depth:
            continue
        for edge in adjacency[current]:
            if edge.target not in nodes:
                queue.append((edge.target, nodes + (edge.target,), edges + (edge,)))
    priority = importance or {}
    found.sort(key=lambda path: (-priority.get(path.nodes[-1], 0), len(path.edges), path.id))
    return PathSearchResult(tuple(found), len(seen), truncated)


def candidate_paths(graph: SecurityGraph, **limits) -> PathSearchResult:
    starts = tuple(node.id for node in graph.nodes
                   if (node.kind == "route" and node.status == "observed") or node.kind == "ai_tool")
    targets = tuple(node.id for node in graph.nodes if node.kind in {"resource", "database", "ai_tool"})
    if not starts or not targets:
        return PathSearchResult((), 0, False)
    return search_paths(graph, starts, targets, **limits)
