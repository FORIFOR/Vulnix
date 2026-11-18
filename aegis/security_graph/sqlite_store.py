"""SQLite snapshots: one database per AssessmentService data directory."""
import hashlib
import json
import math
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .models import Evidence, GraphEdge, GraphNode, SecurityGraph

SCHEMA_VERSION = 3
PARSER_VERSION = "source-ast-v2"


def _canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _edge_id(edge: GraphEdge) -> str:
    return hashlib.sha256(_canonical(asdict(edge)).encode()).hexdigest()[:32]


def _validate(graph: SecurityGraph) -> None:
    ids = {node.id for node in graph.nodes}
    evidence = set(graph.evidence)
    if len(ids) != len(graph.nodes) or not graph.commit_sha:
        raise ValueError("duplicate node or missing commit")
    for item in graph.evidence.values():
        if item.commit_sha != graph.commit_sha or item.id not in evidence:
            raise ValueError("evidence commit mismatch")
    for node in graph.nodes:
        if (node.commit_sha != graph.commit_sha or node.source_line < 1 or
                not node.evidence_ids or not set(node.evidence_ids) <= evidence):
            raise ValueError("invalid node evidence")
    edge_ids = set()
    for edge in graph.edges:
        eid = _edge_id(edge)
        if (edge.source not in ids or edge.target not in ids or edge.commit_sha != graph.commit_sha or
                edge.source_line < 1 or not math.isfinite(edge.confidence) or
                not 0 <= edge.confidence <= 1 or not edge.evidence_ids or
                edge.evidence_status not in {"observed", "inferred", "hypothesized", "verified", "refuted"} or
                not set(edge.evidence_ids) <= evidence or eid in edge_ids):
            raise ValueError("invalid edge reference")
        edge_ids.add(eid)


class GraphStore:
    def __init__(self, path: Path):
        if path.name != "security-graph.sqlite" or path.is_symlink():
            raise ValueError("tenant graph database filename required")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, timeout=5)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        current = self.schema_version()
        if current not in (0, 1, 2, SCHEMA_VERSION):
            self.connection.close()
            raise ValueError("unsupported graph schema version")
        if current in (0, 1, 2):
            self.connection.executescript((Path(__file__).parent / "schema.sql").read_text())
            self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def schema_version(self) -> int:
        return self.connection.execute("PRAGMA user_version").fetchone()[0]

    def save_snapshot(self, repository_id: str, graph: SecurityGraph, parser_version: str = PARSER_VERSION) -> str:
        if not repository_id or not parser_version or len(repository_id) > 160 or len(parser_version) > 80:
            raise ValueError("repository and parser version required")
        _validate(graph)
        digest = hashlib.sha256(_canonical(asdict(graph)).encode()).hexdigest()
        snapshot_id = hashlib.sha256(f"{repository_id}\0{graph.commit_sha}\0{parser_version}".encode()).hexdigest()[:32]
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            found = self.connection.execute(
                "SELECT content_sha256, status FROM graph_snapshots WHERE id=?", (snapshot_id,)).fetchone()
            if found:
                if found["content_sha256"] != digest or found["status"] != "complete":
                    raise ValueError("same snapshot key has different content")
                return snapshot_id
            now = datetime.now(timezone.utc).isoformat()
            self.connection.execute("INSERT INTO graph_snapshots VALUES (?,?,?,?,?,?,?)",
                                    (snapshot_id, repository_id, graph.commit_sha, parser_version, digest, "building", now))
            self.connection.executemany("INSERT INTO graph_evidence VALUES (?,?,?,?,?,?)",
                ((snapshot_id, e.id, e.source_path, e.source_line, e.commit_sha, e.source_digest)
                 for e in graph.evidence.values()))
            self.connection.executemany("INSERT INTO graph_nodes VALUES (?,?,?,?,?,?,?,?)",
                ((snapshot_id, n.id, n.kind, n.name, n.source_path, n.source_line, n.commit_sha, n.status)
                 for n in graph.nodes))
            self.connection.executemany("INSERT INTO graph_node_evidence VALUES (?,?,?)",
                ((snapshot_id, n.id, eid) for n in graph.nodes for eid in n.evidence_ids))
            self.connection.executemany("INSERT INTO graph_edges VALUES (?,?,?,?,?,?,?,?,?,?)",
                ((snapshot_id, _edge_id(e), e.source, e.target, e.relation, e.confidence,
                  e.evidence_status, e.source_path, e.source_line, e.commit_sha)
                 for e in graph.edges))
            self.connection.executemany("INSERT INTO graph_edge_evidence VALUES (?,?,?)",
                ((snapshot_id, _edge_id(e), eid) for e in graph.edges for eid in e.evidence_ids))
            self.connection.execute("UPDATE graph_snapshots SET status='complete' WHERE id=?", (snapshot_id,))
        return snapshot_id

    def list_snapshots(self) -> list[dict]:
        rows = self.connection.execute(
            "SELECT id, repository_id, commit_sha, parser_version, status, created_at FROM graph_snapshots "
            "WHERE status='complete' ORDER BY created_at DESC, id DESC").fetchall()
        return [dict(row) for row in rows]

    def load_graph(self, snapshot_id: str) -> SecurityGraph:
        snapshot = self.connection.execute(
            "SELECT commit_sha FROM graph_snapshots WHERE id=? AND status='complete'", (snapshot_id,)).fetchone()
        if snapshot is None:
            raise KeyError(snapshot_id)
        evidence = {row["evidence_id"]: Evidence(row["evidence_id"], row["source_path"],
                    row["source_line"], row["commit_sha"], row["source_digest"])
                    for row in self.connection.execute("SELECT * FROM graph_evidence WHERE snapshot_id=?", (snapshot_id,))}
        nodes = []
        for row in self.connection.execute("SELECT * FROM graph_nodes WHERE snapshot_id=? ORDER BY rowid", (snapshot_id,)):
            refs = tuple(x[0] for x in self.connection.execute(
                "SELECT evidence_id FROM graph_node_evidence WHERE snapshot_id=? AND node_id=? ORDER BY rowid",
                (snapshot_id, row["node_id"])))
            nodes.append(GraphNode(row["node_id"], row["kind"], row["name"], row["source_path"],
                                   row["source_line"], row["commit_sha"], refs, row["status"]))
        edges = []
        for row in self.connection.execute("SELECT * FROM graph_edges WHERE snapshot_id=? ORDER BY rowid", (snapshot_id,)):
            refs = tuple(x[0] for x in self.connection.execute(
                "SELECT evidence_id FROM graph_edge_evidence WHERE snapshot_id=? AND edge_id=? ORDER BY rowid",
                (snapshot_id, row["edge_id"])))
            edges.append(GraphEdge(row["source_node"], row["target_node"], row["relation"], row["confidence"],
                                   refs, row["source_path"], row["source_line"], row["commit_sha"],
                                   row["evidence_status"]))
        return SecurityGraph(snapshot["commit_sha"], tuple(nodes), tuple(edges), evidence)

    def append_record(self, table: str, snapshot_id: str, record_id: str, payload: dict) -> None:
        """Append derived evidence without rewriting a completed graph."""
        columns = {"graph_paths": "path_id", "graph_hypotheses": "hypothesis_id",
                   "graph_validations": "validation_id", "graph_remediations": "remediation_id"}
        if table not in columns or not record_id or len(record_id) > 100:
            raise ValueError("invalid graph record")
        data = _canonical(payload)
        if len(data) > 64_000:
            raise ValueError("graph record too large")
        key = columns[table]
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            found = self.connection.execute(
                f"SELECT payload_json FROM {table} WHERE snapshot_id=? AND {key}=?", (snapshot_id, record_id)).fetchone()
            if found:
                if found[0] != data:
                    raise ValueError("immutable graph record differs")
                return
            parent = ("hypothesis_id", payload.get("hypothesis_id")) if table == "graph_validations" else (
                ("validation_id", payload.get("validation_id")) if table == "graph_remediations" else None)
            if parent and (not isinstance(parent[1], str) or not parent[1]):
                raise ValueError("missing parent graph record")
            if parent:
                self.connection.execute(
                    f"INSERT INTO {table} (snapshot_id,{key},{parent[0]},payload_json,created_at) VALUES (?,?,?,?,?)",
                    (snapshot_id, record_id, parent[1], data, datetime.now(timezone.utc).isoformat()))
            else:
                self.connection.execute(
                    f"INSERT INTO {table} (snapshot_id,{key},payload_json,created_at) VALUES (?,?,?,?)",
                    (snapshot_id, record_id, data, datetime.now(timezone.utc).isoformat()))

    def records(self, table: str, snapshot_id: str) -> list[dict]:
        if table not in {"graph_paths", "graph_hypotheses", "graph_validations", "graph_remediations"}:
            raise ValueError("invalid graph record table")
        self.load_graph(snapshot_id)  # refuse nonexistent or incomplete snapshot
        return [json.loads(row[0]) for row in self.connection.execute(
            f"SELECT payload_json FROM {table} WHERE snapshot_id=? ORDER BY rowid", (snapshot_id,))]
