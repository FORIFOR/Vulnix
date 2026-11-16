"""One-call, preview-only blind selection evaluation for the access-control lab.

The committed request contains structural observations and owner requirements only.
Truth labels stay local. This module cannot contact a paid model or a target.
"""
from __future__ import annotations

import json
from pathlib import Path

from aegis.planner_llm_gateway import Budget, PlannerLLMGateway
from tests.fixtures.access_control_lab import ACCOUNT_SURFACE

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
MODEL = "abliterated-model"
SYSTEM = (
    "You are choosing whether an isolated, authorized lab should run one read-only "
    "cross-account resource access check. Review the owner's access requirements and "
    "the measured presence of an account resource link for each anonymous case. "
    "Select cases where this check is useful. This is a plan candidate, never a "
    "vulnerability verdict or permission to execute. Return exactly one JSON object "
    'with a single key, "selected", containing an array of case IDs. No prose.'
)


def build_request() -> tuple[dict, dict[str, str]]:
    owners = json.loads((FIXTURES / "access_control_owner_specs.json").read_text(encoding="utf-8"))
    truth = json.loads((FIXTURES / "access_control_truth.json").read_text(encoding="utf-8"))
    if set(owners) != set(truth):
        raise ValueError("owner and independent truth cases differ")
    mapping = {f"C{i:02d}": mode for i, mode in enumerate(sorted(owners), 1)}
    cases = [{"id": case_id,
              "root_access_requirement": owners[mode]["root_requirement"],
              "account_resource_requirement": owners[mode]["account_resource_requirement"],
              "account_resource_link_observed": mode in ACCOUNT_SURFACE}
             for case_id, mode in mapping.items()]
    request = {"model": MODEL,
               "messages": [{"role": "system", "content": SYSTEM},
                            {"role": "user", "content": json.dumps({"cases": cases},
                                                                       ensure_ascii=False, sort_keys=True)}],
               "temperature": 0, "max_tokens": 384}
    return request, mapping


def validate_answer(content: str, mapping: dict[str, str]) -> set[str]:
    def unique_object(pairs: list[tuple[str, object]]) -> dict:
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate answer key")
            out[key] = value
        return out

    try:
        answer = json.loads(content, object_pairs_hook=unique_object)
    except (ValueError, TypeError) as exc:
        raise ValueError("answer must be plain JSON") from exc
    if not isinstance(answer, dict) or set(answer) != {"selected"} or not isinstance(answer["selected"], list):
        raise ValueError("answer shape rejected")
    selected = answer["selected"]
    if any(not isinstance(x, str) or x not in mapping for x in selected) or len(selected) != len(set(selected)):
        raise ValueError("answer contains an invalid or repeated case")
    return set(selected)


def score(selected: set[str], mapping: dict[str, str]) -> dict:
    truth = json.loads((FIXTURES / "access_control_truth.json").read_text(encoding="utf-8"))
    actual = {case_id for case_id, mode in mapping.items() if truth[mode]["idor_check_appropriate"]}
    tp, fp, fn, tn = (len(selected & actual), len(selected - actual),
                      len(actual - selected), len(set(mapping) - selected - actual))
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "unnecessary_check_rate": fp / len(mapping)}


def run_preview() -> dict:
    request, mapping = build_request()

    def local_reference(clean: dict) -> dict:
        # An explicitly labelled fixed-rule reference, never an AI-quality result.
        cases = json.loads(clean["messages"][1]["content"])["cases"]
        selected = [c["id"] for c in cases if c["account_resource_link_observed"]
                    and c["account_resource_requirement"] == "authentication_required"]
        return {"choices": [{"message": {"role": "assistant",
                                          "content": json.dumps({"selected": selected})}}]}

    gateway = PlannerLLMGateway(mode="preview", model=MODEL, responder=local_reference,
                                budget=Budget(max_calls=1, max_total_tokens=2000, max_cost_usd=0.01,
                                              usd_per_1k_input=0.001, usd_per_1k_output=0.003))
    try:
        status, response = gateway.handle(json.dumps(request).encode(), f"Bearer {gateway.token}")
        if status != 200:
            raise ValueError("planner gateway refused the preview")
        selected = validate_answer(response["choices"][0]["message"]["content"], mapping)
        return {"preview_request": gateway.preview_requests[0],
                "gateway": gateway.report(), "mock_selection": score(selected, mapping),
                "mock_note": "Fixed local rule; NOT Abliteration AI performance",
                "paid_model_cost_usd": 0}
    finally:
        gateway.close()


if __name__ == "__main__":
    print(json.dumps(run_preview(), ensure_ascii=False, indent=2))
