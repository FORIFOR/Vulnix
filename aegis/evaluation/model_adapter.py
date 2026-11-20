"""Model adapters: the common payload -> one provider request body, and a provider
reply -> contract steps (still to be checked by aegis.plan_contract).

Nothing here opens a connection. A body is bytes; sending them is the job of a
transport the caller passes in, and the evaluation runner refuses any transport
unless the budget ledger authorizes that exact body (budget_ledger.authorize_send).

Facts the specs rest on (checked 2026-11-21, docs only - nothing has been sent):
- Abliteration: https://docs.abliteration.ai/models.md, /pricing.md, /capabilities/thinking.md,
  /api/openai-compatibility.md. `abliterated-model` turns reasoning off with
  reasoning_effort "none"; `abliterated-model-large-v2` cannot turn it off ("none" maps
  to low). Official prices are $1/$3 and $3/$5 per 1M tokens; the evaluation budgets
  with the higher figures from the owner's plan ($3/$3 and $5/$5).
- Claude Sonnet 5.5: model id `claude-sonnet-5-5`, $2/$10 per 1M tokens (Anthropic
  pricing as cached 2026-11-03 in the Claude API reference), Messages API with
  structured output in output_config.format. No server-side fallback: a fallback would
  answer with another model and break the comparison.
Every spec is `sendable=False`. A prices / API re-check on the day of a real run is
part of the approval (docs/evaluation/EVALUATION_PROTOCOL.md).
"""
from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass

from .request_builder import STEP_SCHEMA, SYSTEM_PROMPT, canonical


@dataclass(frozen=True)
class ModelSpec:
    key: str
    provider: str
    model_id: str
    price_in_per_m: float          # USD per 1M input tokens used for reservations
    price_out_per_m: float         # USD per 1M output tokens (reasoning billed as output assumed)
    official_price_in_per_m: float | None
    official_price_out_per_m: float | None
    price_source: str
    price_checked: str
    max_input_tokens: int = 2000
    max_output_tokens: int = 2048
    overhead_tokens: int = 0       # provider-side tokens not in the body (system framing)
    api_spec: str = "docs_only"    # "docs_only" | "sent_before" | "unverified"
    sendable: bool = False
    notes: str = ""

    def prices_known(self) -> bool:
        return all(isinstance(p, (int, float)) and math.isfinite(p) and p > 0
                   for p in (self.price_in_per_m, self.price_out_per_m))

    def max_cost_usd(self) -> float:
        """The worst case of one request: full input cap and full output cap."""
        if not self.prices_known():
            raise ValueError(f"{self.key}: price unknown")
        return round((self.max_input_tokens * self.price_in_per_m
                      + self.max_output_tokens * self.price_out_per_m) / 1_000_000, 6)

    def as_dict(self) -> dict:
        return asdict(self)


ABLITERATED = ModelSpec(
    key="abliterated-model", provider="abliteration", model_id="abliterated-model",
    price_in_per_m=3.00, price_out_per_m=3.00, official_price_in_per_m=1.00, official_price_out_per_m=3.00,
    price_source="https://docs.abliteration.ai/pricing.md (official $1/$3); owner's plan $3/$3 kept as the higher",
    price_checked="2026-11-21", overhead_tokens=50, api_spec="sent_before",
    notes="reasoning_effort none turns reasoning off (docs/ABLITERATION_SELECTION_REAL_RESULT.md, 2026-11-19)")
ABLITERATED_LARGE_V2 = ModelSpec(
    key="abliterated-model-large-v2", provider="abliteration", model_id="abliterated-model-large-v2",
    price_in_per_m=5.00, price_out_per_m=5.00, official_price_in_per_m=3.00, official_price_out_per_m=5.00,
    price_source="https://docs.abliteration.ai/pricing.md (official $3/$5); owner's plan $5/$5 kept as the higher",
    price_checked="2026-11-21", overhead_tokens=50, api_spec="docs_only",
    notes=("reasoning cannot be turned off (docs: none maps to low); reasoning may use the output cap, "
           "an answer cut by length is rejected, never retried"))
CLAUDE_SONNET = ModelSpec(
    key="claude-sonnet-5-5", provider="anthropic", model_id="claude-sonnet-5-5",
    price_in_per_m=2.00, price_out_per_m=10.00, official_price_in_per_m=2.00, official_price_out_per_m=10.00,
    price_source="Anthropic API pricing, Claude Sonnet 5.5 $2/$10 (reference cached 2026-11-03)",
    price_checked="2026-11-21", overhead_tokens=400, api_spec="docs_only",
    notes="structured output (output_config.format json_schema), effort low, no fallback model")

MODELS = {m.key: m for m in (ABLITERATED, ABLITERATED_LARGE_V2, CLAUDE_SONNET)}


class AdapterError(ValueError):
    """A reply that cannot become contract steps (recorded, never retried)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _steps_from_text(text) -> list:
    if not isinstance(text, str) or not text.strip() or len(text) > 20_000:
        raise AdapterError("empty_or_oversized_answer")
    try:
        value = json.loads(text, parse_constant=lambda _c: (_ for _ in ()).throw(ValueError("nan")))
    except ValueError:
        raise AdapterError("invalid_json") from None
    if not isinstance(value, dict) or set(value) != {"steps"} or not isinstance(value["steps"], list):
        raise AdapterError("not_the_answer_shape")
    return value["steps"]          # every step is still checked by plan_contract.parse_steps


class _Adapter:
    spec: ModelSpec

    def __init__(self, spec: ModelSpec | None = None):
        self.spec = spec or self.default

    def request_body(self, payload: dict) -> bytes:
        raise NotImplementedError

    def parse_reply(self, raw: bytes) -> tuple[list, dict]:
        """-> (steps, usage). Raises AdapterError."""
        raise NotImplementedError


class AbliterationAdapter(_Adapter):
    """OpenAI-compatible /v1/chat/completions."""
    default = ABLITERATED
    reasoning_effort = "none"

    def request_body(self, payload: dict) -> bytes:
        body = {"model": self.spec.model_id,
                "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                             {"role": "user", "content": canonical(payload).decode("utf-8")}],
                "max_tokens": self.spec.max_output_tokens,
                "response_format": {"type": "json_object"},
                "reasoning_effort": self.reasoning_effort,
                "stream": False}
        return canonical(body)

    def parse_reply(self, raw: bytes) -> tuple[list, dict]:
        try:
            resp = json.loads(raw)
            choice = resp["choices"][0]
            usage = resp.get("usage") or {}
            finish = choice.get("finish_reason")
            text = (choice.get("message") or {}).get("content")
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            raise AdapterError("unreadable_reply") from None
        usage = {"input_tokens": usage.get("prompt_tokens"), "output_tokens": usage.get("completion_tokens"),
                 "reasoning_tokens": ((usage.get("completion_tokens_details") or {}).get("reasoning_tokens")),
                 "finish": finish}
        if finish != "stop":
            raise AdapterError(f"finish_{finish}")
        return _steps_from_text(text), usage


class AbliterationLargeV2Adapter(AbliterationAdapter):
    default = ABLITERATED_LARGE_V2
    reasoning_effort = "low"          # the lowest documented level; reasoning stays on


class ClaudeAdapter(_Adapter):
    """Anthropic Messages API (POST /v1/messages)."""
    default = CLAUDE_SONNET

    def request_body(self, payload: dict) -> bytes:
        body = {"model": self.spec.model_id,
                "max_tokens": self.spec.max_output_tokens,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": canonical(payload).decode("utf-8")}],
                "output_config": {"effort": "low", "format": {"type": "json_schema", "schema": STEP_SCHEMA}}}
        return canonical(body)

    def parse_reply(self, raw: bytes) -> tuple[list, dict]:
        try:
            resp = json.loads(raw)
            stop = resp.get("stop_reason")
            usage = resp.get("usage") or {}
            texts = [b.get("text") for b in resp.get("content") or [] if b.get("type") == "text"]
        except (ValueError, TypeError, AttributeError):
            raise AdapterError("unreadable_reply") from None
        usage = {"input_tokens": usage.get("input_tokens"), "output_tokens": usage.get("output_tokens"),
                 "reasoning_tokens": None, "finish": stop}
        if stop != "end_turn":
            raise AdapterError(f"finish_{stop}")
        if len(texts) != 1:
            raise AdapterError("not_one_text_block")
        return _steps_from_text(texts[0]), usage


class FixedRuleBaseline:
    """The comparison baseline: no model, the fixed table (aegis.diagnosis_judge)."""
    key = "fixed_rule"

    def steps(self, view: dict) -> list[dict]:
        from ..diagnosis_judge import fixed_rule_steps
        return fixed_rule_steps(view)


ADAPTERS = {"abliterated-model": AbliterationAdapter, "abliterated-model-large-v2": AbliterationLargeV2Adapter,
            "claude-sonnet-5-5": ClaudeAdapter}


def adapter_for(key: str) -> _Adapter:
    return ADAPTERS[key]()


__all__ = ["ADAPTERS", "AbliterationAdapter", "AbliterationLargeV2Adapter", "AdapterError", "ClaudeAdapter",
           "FixedRuleBaseline", "MODELS", "ModelSpec", "adapter_for"]
