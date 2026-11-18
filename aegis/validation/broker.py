from pathlib import Path
import platform

from aegis.connectors.github_source import read_pinned_file
from aegis.research.critic import critique
from aegis.research.evidence import valid_references
from aegis.research.hypotheses import Hypothesis
from aegis.security_graph.models import SecurityGraph
from .sandbox import run_synthetic_case
from .verdicts import Verdict


class ValidationBroker:
    def __init__(self, graph: SecurityGraph, checkout: Path, *, pool=None):
        self.graph = graph
        self.checkout = checkout
        self.pool = pool

    def validate(self, hypothesis: Hypothesis, *, replacement_source: str | None = None) -> Verdict:
        if (hypothesis.verdict != "unverified" or
            not valid_references(self.graph, hypothesis.affected_nodes, hypothesis.evidence_ids) or
            not critique(self.graph, hypothesis) or
            hypothesis.validation_strategy != "isolated_unit_test"):
            raise ValueError("unapproved hypothesis")
        handlers = [node for node in self.graph.nodes if node.id in hypothesis.affected_nodes and node.kind == "handler"]
        if len(handlers) != 1 or handlers[0].name != "get_order" or handlers[0].source_path != "api.py":
            raise ValueError("only the synthetic fixture is supported")
        pinned_source = read_pinned_file(self.checkout, self.graph.commit_sha, "api.py")
        if (self.checkout / "api.py").read_text(encoding="utf-8") != pinned_source:
            raise ValueError("checkout changed after pinning")
        source = replacement_source if replacement_source is not None else pinned_source
        if "class App:" not in source or "class Store:" not in source:
            raise ValueError("only the synthetic fixture is supported")
        observed = run_synthetic_case(source, pool=self.pool)
        own = observed["own"]["returned_org"] == "org-a" and not observed["own"]["denied"]
        cross = observed["other"]["returned_org"] == "org-b" and not observed["other"]["denied"]
        denied = observed["other"]["denied"] and observed["other"]["returned_org"] is None
        status = "confirmed_in_synthetic_lab" if own and cross else "not_reproduced" if own and denied else "inconclusive"
        return Verdict(hypothesis.hypothesis_id, status, cross, own,
                       hypothesis.evidence_ids,
                       "linux_kernel_synthetic_sandbox" if platform.system() == "Linux"
                       else "macos_synthetic_sandbox")
