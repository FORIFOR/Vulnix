from dataclasses import dataclass

from aegis.research.hypotheses import Hypothesis
from aegis.validation.broker import ValidationBroker
from .patch_planner import PatchPlan


@dataclass(frozen=True)
class PatchResult:
    fixed: bool
    same_tenant_preserved: bool
    before_status: str
    after_status: str
    diff: str


def validate_patch(broker: ValidationBroker, patch: PatchPlan, hypothesis: Hypothesis) -> PatchResult:
    if patch.commit_sha != broker.graph.commit_sha or patch.source_path != "api.py":
        raise ValueError("patch source mismatch")
    if (broker.checkout / patch.source_path).read_text(encoding="utf-8") != patch.original:
        raise ValueError("source changed since patch planning")
    before = broker.validate(hypothesis)
    if before.status != "confirmed_in_synthetic_lab":
        raise ValueError("pre-patch failure not reproduced")
    after = broker.validate(hypothesis, replacement_source=patch.modified)
    return PatchResult(after.status == "not_reproduced" and not after.cross_tenant_exposed,
                       after.same_tenant_works, before.status, after.status, patch.diff)
