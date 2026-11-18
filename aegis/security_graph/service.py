"""Organization-owned graph service, with explicitly registered synthetic input."""
import contextlib
import re
import threading
from dataclasses import asdict, dataclass
from pathlib import Path

from aegis.connectors.github_source import open_pinned_local_checkout, read_pinned_file
from aegis.remediation.impact import predict_node_impact
from aegis.remediation.github_pr import draft_pr_description
from aegis.remediation.patch_planner import plan_patch
from aegis.remediation.patch_validator import validate_patch
from aegis.research.hypotheses import Hypothesis
from aegis.research.planner import RuleBasedResearchModel, research
from aegis.validation.broker import ValidationBroker
from .builder import build_graph
from .paths import candidate_paths
from .sqlite_store import GraphStore, PARSER_VERSION


@dataclass(frozen=True)
class SourceRegistration:
    id: str
    repository_id: str
    checkout: Path
    commit_sha: str


class GraphService:
    def __init__(self, tenant_data_dir: Path, worker_pool_provider=None):
        self.data_dir = tenant_data_dir
        self.database = tenant_data_dir / "security-graph.sqlite"
        self._sources: dict[str, SourceRegistration] = {}
        self._lock = threading.RLock()
        self.worker_pool_provider = worker_pool_provider

    def register_source(self, source: SourceRegistration) -> None:
        """Trusted server-side registration. No HTTP route accepts a path or URL."""
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", source.id):
            raise ValueError("invalid source identifier")
        with self._lock:
            if source.id in self._sources and self._sources[source.id] != source:
                raise ValueError("source registration changed")
            self._sources[source.id] = source

    def sources(self) -> list[dict]:
        """Only public registration metadata; never a checkout path or URL."""
        with self._lock:
            return [{"id": item.id, "repository_id": item.repository_id,
                     "commit_sha": item.commit_sha, "scope": "synthetic_only"}
                    for item in sorted(self._sources.values(), key=lambda value: value.id)]

    def import_source(self, source_id: str, *, commit_guard=None) -> str:
        with self._lock:
            source = self._sources.get(source_id)
        if source is None:
            raise KeyError(source_id)
        root = open_pinned_local_checkout(source.checkout, source.commit_sha)
        if read_pinned_file(root, source.commit_sha, ".vulnix-synthetic-lab") != "synthetic-only\n":
            raise ValueError("only registered synthetic source is allowed")
        graph = build_graph(root, source.commit_sha)
        gate = commit_guard() if commit_guard else contextlib.nullcontext()
        with gate:
            with GraphStore(self.database) as store:
                snapshot = store.save_snapshot(source.repository_id, graph, PARSER_VERSION)
                for path in candidate_paths(graph).paths:
                    store.append_record("graph_paths", snapshot, path.id, _path_payload(path))
        return snapshot

    def snapshots(self) -> list[dict]:
        with GraphStore(self.database) as store:
            return store.list_snapshots()

    def nodes(self, snapshot_id: str, *, limit: int = 200, offset: int = 0) -> list[dict]:
        if not 1 <= limit <= 500 or offset < 0:
            raise ValueError("invalid pagination")
        with GraphStore(self.database) as store:
            return [asdict(node) for node in store.load_graph(snapshot_id).nodes[offset:offset + limit]]

    def paths(self, snapshot_id: str) -> list[dict]:
        with GraphStore(self.database) as store:
            return store.records("graph_paths", snapshot_id)

    def evidence(self, snapshot_id: str, *, limit: int = 500) -> list[dict]:
        if not 1 <= limit <= 500:
            raise ValueError("invalid evidence limit")
        with GraphStore(self.database) as store:
            return [asdict(item) for item in list(store.load_graph(snapshot_id).evidence.values())[:limit]]

    def path_detail(self, snapshot_id: str, path_id: str) -> dict:
        for path in self.paths(snapshot_id):
            if path["id"] == path_id:
                return path
        raise KeyError(path_id)

    def research(self, snapshot_id: str, *, model=None, commit_guard=None) -> list[dict]:
        with GraphStore(self.database) as store:
            graph = store.load_graph(snapshot_id)
        candidates = research(graph, model if model is not None else RuleBasedResearchModel())
        gate = commit_guard() if commit_guard else contextlib.nullcontext()
        with gate:
            with GraphStore(self.database) as store:
                for item in candidates:
                    store.append_record("graph_hypotheses", snapshot_id, item.hypothesis_id, asdict(item))
                return store.records("graph_hypotheses", snapshot_id)

    def hypotheses(self, snapshot_id: str) -> list[dict]:
        with GraphStore(self.database) as store:
            return store.records("graph_hypotheses", snapshot_id)

    def validate_synthetic(self, snapshot_id: str, hypothesis_id: str, *, commit_guard=None) -> dict:
        """Run only the fixed two-organization fixture, then retain immutable evidence.

        The saved graph and registration must identify the same pinned checkout.
        No model-provided command, path, or source is accepted.
        """
        with GraphStore(self.database) as store:
            graph = store.load_graph(snapshot_id)
            row = next((item for item in store.list_snapshots() if item["id"] == snapshot_id), None)
            proposed = next((item for item in store.records("graph_hypotheses", snapshot_id)
                             if item["hypothesis_id"] == hypothesis_id), None)
        if row is None or proposed is None:
            raise KeyError(hypothesis_id)
        with self._lock:
            sources = [item for item in self._sources.values() if item.repository_id == row["repository_id"]
                       and item.commit_sha == graph.commit_sha]
        if len(sources) != 1:
            raise ValueError("registered synthetic source required")
        source = sources[0]
        root = open_pinned_local_checkout(source.checkout, source.commit_sha)
        if read_pinned_file(root, source.commit_sha, ".vulnix-synthetic-lab") != "synthetic-only\n":
            raise ValueError("only registered synthetic source is allowed")
        hypothesis = Hypothesis(**{key: tuple(value) if isinstance(value, list) else value
                                    for key, value in proposed.items()})
        broker = ValidationBroker(graph, root,
                                  pool=self.worker_pool_provider() if self.worker_pool_provider else None)
        before = broker.validate(hypothesis)
        if before.status != "confirmed_in_synthetic_lab":
            result = {"hypothesis_id": hypothesis_id, "validation_id": f"{hypothesis_id}-before",
                      "before": asdict(before), "status": before.status, "synthetic_only": True}
            gate = commit_guard() if commit_guard else contextlib.nullcontext()
            with gate, GraphStore(self.database) as store:
                store.append_record("graph_validations", snapshot_id, result["validation_id"], result)
            return result
        patch = plan_patch(root, graph, hypothesis, before)
        after = validate_patch(broker, patch, hypothesis)
        validation_id = f"{hypothesis_id}-before"
        validation = {"validation_id": validation_id, "hypothesis_id": hypothesis_id,
                      "before": asdict(before), "after_status": after.after_status,
                      "same_tenant_preserved": after.same_tenant_preserved,
                      "status": "synthetic_fixed" if after.fixed and after.same_tenant_preserved else "inconclusive",
                      "synthetic_only": True}
        remediation = {"remediation_id": f"{hypothesis_id}-local-draft", "validation_id": validation_id,
                       "status": "local_draft_only", "diff": patch.diff,
                       "description": draft_pr_description(hypothesis, before, after),
                       "fixed": after.fixed, "same_tenant_preserved": after.same_tenant_preserved}
        gate = commit_guard() if commit_guard else contextlib.nullcontext()
        with gate, GraphStore(self.database) as store:
            store.append_record("graph_validations", snapshot_id, validation_id, validation)
            store.append_record("graph_remediations", snapshot_id, remediation["remediation_id"], remediation)
        return {"validation": validation, "remediation": remediation}

    def validations(self, snapshot_id: str) -> list[dict]:
        with GraphStore(self.database) as store:
            return store.records("graph_validations", snapshot_id)

    def remediations(self, snapshot_id: str) -> list[dict]:
        with GraphStore(self.database) as store:
            return store.records("graph_remediations", snapshot_id)

    def remediation_impact(self, snapshot_id: str, node_id: str) -> dict:
        with GraphStore(self.database) as store:
            graph = store.load_graph(snapshot_id)
        if node_id not in {node.id for node in graph.nodes}:
            raise KeyError(node_id)
        return predict_node_impact(candidate_paths(graph).paths, node_id)

    def diff(self, before_id: str, after_id: str) -> dict:
        with GraphStore(self.database) as store:
            before = store.load_graph(before_id)
            after = store.load_graph(after_id)
            rows = {row["id"]: row for row in store.list_snapshots()}
        if rows[before_id]["repository_id"] != rows[after_id]["repository_id"]:
            raise ValueError("cannot compare different repositories")
        if before_id == after_id:
            raise ValueError("different snapshots required")
        def key(path, graph):
            nodes = {node.id: node for node in graph.nodes}
            return (nodes[path.nodes[0]].name, nodes[path.nodes[-1]].name)
        before_paths = candidate_paths(before).paths
        after_paths = {key(path, after): path for path in candidate_paths(after).paths}
        guarded = [path.id for path in before_paths if (match := after_paths.get(key(path, before))) and
                   match.status == "guard_observed" and path.status != "guard_observed"]
        return {"before_snapshot": before_id, "after_snapshot": after_id,
                "guard_observed_after": guarded, "status": "graph_prediction_only",
                "verified_remediation": False}


def _path_payload(path) -> dict:
    return {"id": path.id, "nodes": list(path.nodes),
            "edges": [asdict(edge) for edge in path.edges],
            "evidence_ids": list(path.evidence_ids), "status": path.status}
