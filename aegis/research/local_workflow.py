"""Offline synthetic vertical slice; caller must provide a tenant-scoped output."""
from pathlib import Path

from aegis.connectors.github_source import open_pinned_local_checkout
from aegis.security_graph.builder import build_graph
from aegis.security_graph.storage import write_report
from aegis.validation.broker import ValidationBroker
from aegis.remediation.patch_planner import plan_patch
from aegis.remediation.patch_validator import validate_patch
from .planner import RuleBasedResearchModel, research
from .report import build_report


def run_local_synthetic_workflow(checkout: Path, commit_sha: str, destination: Path) -> dict:
    """Run the fixed two-organization fixture and save its evidence metadata.

    Never points at a real target or writes to the source checkout. It is not a
    production source connector, customer code runner, or PR creation command.
    """
    source = open_pinned_local_checkout(checkout, commit_sha)
    if destination.resolve().is_relative_to(source):
        raise ValueError("report destination must be outside source checkout")
    graph = build_graph(source, commit_sha)
    hypotheses = research(graph, RuleBasedResearchModel())
    if len(hypotheses) != 1:
        raise ValueError("expected exactly one synthetic hypothesis")
    broker = ValidationBroker(graph, source)
    before = broker.validate(hypotheses[0])
    patch = plan_patch(source, graph, hypotheses[0], before)
    after = validate_patch(broker, patch, hypotheses[0])
    report = build_report(graph, hypotheses[0], before, after)
    write_report(report, destination)
    return report
