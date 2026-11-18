"""Bind a fixed MCP control to one pinned synthetic graph candidate."""
from pathlib import Path

from aegis.analyzers.ai_agents import McpScopeCandidate, review_mcp_tool_scope
from aegis.connectors.github_source import read_pinned_file
from aegis.research.evidence import valid_references
from aegis.security_graph.models import SecurityGraph
from .mcp_policy_lab import SOURCE, run_mcp_policy_lab


_OBSERVATIONS = {
    "open_customer": ("viewer_reached_data", "open_viewer_reached_data"),
    "guarded_customer": ("viewer_denied", "guarded_viewer_denied"),
    "misordered_customer": ("viewer_reached_data", "misordered_viewer_reached_data"),
}


class McpValidationBroker:
    def __init__(self, graph: SecurityGraph, checkout: Path, *, pool, prelaunch):
        if pool is None or prelaunch is None:
            raise ValueError("shared worker pool and authorization lease required")
        self.graph = graph
        self.checkout = checkout
        self.pool = pool
        self.prelaunch = prelaunch

    def validate(self, candidate: McpScopeCandidate) -> dict:
        if candidate not in review_mcp_tool_scope(self.graph):
            raise ValueError("candidate is not in the pinned graph")
        nodes = {node.id: node for node in self.graph.nodes}
        tool = nodes[candidate.tool_id]
        handler = nodes[candidate.handler_id]
        if (tool.kind != "ai_tool" or tool.source_path != "tools.py" or
                handler.source_path != "tools.py" or tool.name not in _OBSERVATIONS or
                not valid_references(self.graph,
                                     (candidate.tool_id, candidate.handler_id,
                                      *candidate.resource_ids, *candidate.declared_role_ids),
                                     candidate.evidence_ids)):
            raise ValueError("only the fixed synthetic MCP fixture is supported")
        pinned = read_pinned_file(self.checkout, self.graph.commit_sha, "tools.py")
        current = self.checkout / "tools.py"
        if (pinned != SOURCE or current.is_symlink() or not current.is_file() or
                current.stat().st_size != len(SOURCE.encode("utf-8")) or
                current.read_text(encoding="utf-8") != SOURCE):
            raise ValueError("synthetic MCP source does not match pinned fixture")
        observed = run_mcp_policy_lab(pool=self.pool, prelaunch=self.prelaunch)
        label, key = _OBSERVATIONS[tool.name]
        observation = {label: observed[key]}
        if tool.name == "guarded_customer":
            observation["admin_reached_data"] = observed["guarded_admin_reached_data"]
        return {
            "validation_id": f"{candidate.id}-mcp-synthetic",
            "candidate_id": candidate.id,
            "tool_id": candidate.tool_id,
            "commit_sha": self.graph.commit_sha,
            "evidence_ids": list(candidate.evidence_ids),
            "observation": observation,
            "status": "synthetic_control_observed" if all(observed.values()) else "inconclusive",
            "synthetic_only": True,
        }
