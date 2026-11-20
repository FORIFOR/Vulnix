"""One planner input for every method (docs/evaluation/EVALUATION_PROTOCOL.md).

The common payload is built only from what Vulnix itself measured: the planner view
of a DiagnosisState (ids, kinds, short words), the registered target refs, and the
check catalog allowed at this level. It never carries a case id, a lab mode, a label,
a URL, a response body, a cookie or a hash. Every model gets the same bytes; only the
provider envelope (model_adapter) differs.
"""
from __future__ import annotations

import hashlib
import json

from ..artex_bridge import CATALOG
from ..plan_contract import REASONS

SCHEMA_VERSION = 1
MAX_STEPS = 4

# Neutral descriptions: what each check does, not which hypothesis it settles.
CHECK_DESCRIPTIONS = {
    "l1_http_probe": "one GET of the target with no credentials (read only)",
    "l1_apache_mod_status": "one GET of a fixed Apache server-status marker on the root (read only)",
    "l2_idor": ("as test account A, request the target resource while account B (its owner) is used as a "
                "positive control; needs a separate human approval for every run"),
    "l2_sqli": "non-destructive SQL injection boundary reproduction; needs a separate human approval",
    "l2_cve_2021_41773": "non-destructive CVE-2021-41773 reproduction; needs a separate human approval",
}

SYSTEM_PROMPT = (
    "You choose the next verification checks for an authorized security assessment of a "
    "registered test target. You only choose checks by id; you never run anything, and you never "
    "decide whether a hypothesis is true: a fixed judge does that from the measured result.\n"
    "Input: JSON with observations (evidence_id, target_ref, generation, kind, source, attrs), "
    "hypotheses (id, claim, target_ref, state, purpose, generation, and the evidence ids that "
    "support / contradict / leave it inconclusive), the allowed checks, target refs and reasons.\n"
    "Rules: choose checks only for hypotheses whose state is open or inconclusive and whose "
    "generation is the current one; evidence_refs must be ids of observations about the same "
    "target_ref in the current generation; reason confirm_fix only for purpose confirm_fix; do not "
    "repeat a check that adds nothing new; choose no check when none is useful.\n"
    "Answer with exactly one JSON object: {\"steps\": [ {\"hypothesis_id\": str, \"catalog_id\": str, "
    "\"target_ref\": str, \"evidence_refs\": [str], \"reason\": str} ]} with at most "
    f"{MAX_STEPS} steps, most useful first. No other text."
)

STEP_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["steps"],
    "properties": {"steps": {"type": "array", "items": {
        "type": "object", "additionalProperties": False,
        "required": ["hypothesis_id", "catalog_id", "target_ref", "evidence_refs", "reason"],
        "properties": {"hypothesis_id": {"type": "string"}, "catalog_id": {"type": "string"},
                       "target_ref": {"type": "string"},
                       "evidence_refs": {"type": "array", "items": {"type": "string"}},
                       "reason": {"type": "string"}}}}},
}


def canonical(value) -> bytes:
    """The one serialization every hash in the evaluation is taken over."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def allowed_checks(allowed_levels) -> list[dict]:
    return [{"catalog_id": c.id, "level": c.level, "does": CHECK_DESCRIPTIONS[c.id]}
            for c in sorted(CATALOG, key=lambda c: c.id) if c.level in allowed_levels]


def common_payload(view: dict, target_refs, allowed_levels=("L1", "L2")) -> dict:
    """The planner input, identical for every model and for the fixed rule."""
    return {
        "schema_version": SCHEMA_VERSION,
        "generation": view["generation"],
        "observations": [{k: o[k] for k in ("evidence_id", "target_ref", "generation", "kind", "source", "attrs")}
                         for o in view["observations"]],
        "hypotheses": [{k: h[k] for k in ("id", "claim", "target_ref", "state", "purpose", "generation",
                                          "basis", "supporting", "contradicting", "inconclusive")}
                       for h in view["hypotheses"]],
        "allowed_checks": allowed_checks(set(allowed_levels)),
        "target_refs": sorted(target_refs),
        "reasons": sorted(REASONS),
        "max_steps": MAX_STEPS,
    }


def template() -> dict:
    """Everything fixed across requests (instructions, schema, catalog). Its hash binds an
    approval for re-planning requests whose observations are not known in advance."""
    return {"schema_version": SCHEMA_VERSION, "system": SYSTEM_PROMPT, "schema": STEP_SCHEMA,
            "allowed_checks": allowed_checks({"L1", "L2"}), "reasons": sorted(REASONS),
            "max_steps": MAX_STEPS}


__all__ = ["CHECK_DESCRIPTIONS", "MAX_STEPS", "STEP_SCHEMA", "SYSTEM_PROMPT", "allowed_checks", "canonical",
           "common_payload", "sha256", "template"]
