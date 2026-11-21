"""Request previews: what WOULD be sent, as hashes and worst-case costs.

Two hashes per request:
- common_sha256: the canonical UTF-8 bytes of the common payload (identical across models)
- body_sha256:   the exact HTTP body bytes for that provider (what an approval binds)
plus config_sha256 (model settings + fixed template); changing a model setting or a
token cap after the preview changes it and voids the approval.

A preview reads no API key, opens no connection, and stores no header, URL of a
target, cookie or personal data: the payload holds ids and short words only.
"""
from __future__ import annotations

from .model_adapter import MODELS, adapter_for
from .request_builder import canonical, sha256, template

# The same rough rule as the product gateway (aegis.planner_llm_gateway.estimate_tokens).
# A real run additionally counts tokens with the provider before sending and refuses a
# request whose count exceeds max_input_tokens (EVALUATION_PROTOCOL.md, pre-send checks).
CHARS_PER_TOKEN_FLOOR = 3


def estimate_input_tokens(body: bytes, overhead: int) -> int:
    return len(body) // CHARS_PER_TOKEN_FLOOR + 1 + overhead


def config_sha256(model_key: str) -> str:
    spec = MODELS[model_key].as_dict()
    return sha256(canonical({"model": spec, "template_sha256": sha256(canonical(template()))}))


def preview(*, evaluation_id: str, case_id: str, round_no: int, payload: dict, model_key: str) -> dict:
    adapter = adapter_for(model_key)
    spec = adapter.spec
    body = adapter.request_body(payload)
    est = estimate_input_tokens(body, spec.overhead_tokens)
    return {
        "evaluation_id": evaluation_id, "case_id": case_id, "round": round_no,
        "model": spec.key, "model_id": spec.model_id, "provider": spec.provider,
        "model_version": spec.model_id, "api_spec": spec.api_spec, "sendable": spec.sendable,
        "common_sha256": sha256(canonical(payload)),
        "body_sha256": sha256(body), "body_bytes": len(body),
        "config_sha256": config_sha256(model_key),
        "template_sha256": sha256(canonical(template())),
        "estimated_input_tokens": est,
        "max_input_tokens": spec.max_input_tokens, "max_output_tokens": spec.max_output_tokens,
        "within_input_cap": est <= spec.max_input_tokens,
        "price_in_per_m": spec.price_in_per_m, "price_out_per_m": spec.price_out_per_m,
        "price_source": spec.price_source, "price_checked": spec.price_checked,
        "max_cost_usd": spec.max_cost_usd(),
        "body": body.decode("utf-8"),
    }


def cost_estimate(*, cases: int, rounds: int, fix_cases: int = 0, cap_usd: float = 5.00) -> dict:
    """The worst case if every case (and every fix re-check) used every round on every model."""
    n = (cases + fix_cases) * rounds
    per_model = {k: {"per_request_usd": m.max_cost_usd(), "requests": n,
                     "max_usd": round(m.max_cost_usd() * n, 6),
                     "price_in_per_m": m.price_in_per_m, "price_out_per_m": m.price_out_per_m,
                     "official_price_in_per_m": m.official_price_in_per_m,
                     "official_price_out_per_m": m.official_price_out_per_m,
                     "price_source": m.price_source, "price_checked": m.price_checked,
                     "max_input_tokens": m.max_input_tokens, "max_output_tokens": m.max_output_tokens}
                 for k, m in MODELS.items()}
    total = round(sum(v["max_usd"] for v in per_model.values()), 6)
    return {"cases": cases, "fix_rechecks": fix_cases, "rounds_per_case_per_model": rounds, "per_model": per_model,
            "total_max_usd": total, "cap_usd": cap_usd, "unreserved_usd": round(cap_usd - total, 6),
            "fits_cap": total <= cap_usd}


__all__ = ["config_sha256", "cost_estimate", "estimate_input_tokens", "preview"]
