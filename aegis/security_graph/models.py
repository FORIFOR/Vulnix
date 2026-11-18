from dataclasses import dataclass
from typing import Literal

NodeType = Literal["repository", "route", "handler", "identity", "role", "resource", "database", "dependency", "secret_reference", "ai_tool"]
Relation = Literal["CALLS", "READS", "WRITES", "REQUIRES_ROLE", "OWNS", "EXPOSES", "USES_DEPENDENCY"]


@dataclass(frozen=True)
class Evidence:
    id: str
    source_path: str
    source_line: int
    commit_sha: str
    source_digest: str  # SHA-256 of the line, never the line or a secret value.


@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: NodeType
    name: str
    source_path: str
    source_line: int
    commit_sha: str
    evidence_ids: tuple[str, ...]
    status: str = "observed"


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    relation: Relation
    confidence: float
    evidence_ids: tuple[str, ...]
    source_path: str
    source_line: int
    commit_sha: str
    evidence_status: str = "observed"


@dataclass(frozen=True)
class SecurityGraph:
    commit_sha: str
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    evidence: dict[str, Evidence]
