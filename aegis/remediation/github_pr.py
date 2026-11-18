"""Draft text only. This module performs no GitHub API writes."""
from aegis.research.hypotheses import Hypothesis
from aegis.validation.verdicts import Verdict
from .patch_validator import PatchResult


def draft_pr_description(hypothesis: Hypothesis, before: Verdict, after: PatchResult) -> str:
    if before.status != "confirmed_in_synthetic_lab" or not after.fixed or not after.same_tenant_preserved:
        raise ValueError("validated synthetic repair required")
    return ("# Draft: 組織間アクセスの検証を追加\n\n"
            f"仮説: {hypothesis.hypothesis_id} / {hypothesis.summary}\n\n"
            f"根拠ID: {', '.join(hypothesis.evidence_ids)}\n\n"
            "合成ラボ: 修正前は別組織の注文を返し、修正後は403で拒否。"
            "同一組織の正常な参照は維持。\n\n"
            "実顧客リポジトリ、実サイト、実ARTEX、実モデルでは未検証。"
            "人間のレビューと承認が必要。\n")
