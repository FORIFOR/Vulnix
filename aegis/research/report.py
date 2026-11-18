"""Metadata-only, Japanese research report for an organization-scoped UI."""
from dataclasses import asdict

from aegis.security_graph.models import SecurityGraph
from aegis.validation.verdicts import Verdict
from aegis.remediation.patch_validator import PatchResult
from aegis.remediation.github_pr import draft_pr_description
from .hypotheses import Hypothesis


def build_report(graph: SecurityGraph, hypothesis: Hypothesis,
                 before: Verdict, after: PatchResult) -> dict:
    if before.hypothesis_id != hypothesis.hypothesis_id or not after.fixed or not after.same_tenant_preserved:
        raise ValueError("synthetic validation and regression required")
    return {
        "status": "synthetic_validated",
        "scope": "合成した2組織のローカルテスト。顧客コード・実サイトでの実証ではありません。",
        "commit_sha": graph.commit_sha,
        "graph": {"nodes": [asdict(node) for node in graph.nodes],
                  "edges": [asdict(edge) for edge in graph.edges]},
        "evidence": [asdict(item) for item in graph.evidence.values()],
        "hypothesis": asdict(hypothesis),
        "verification": {"before": asdict(before), "after": asdict(after)},
        "remediation": {"diff": after.diff, "description": draft_pr_description(hypothesis, before, after),
                        "review_status": "Draft（ローカル差分のみ）"},
    }
