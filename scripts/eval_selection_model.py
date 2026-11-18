"""One-call blind selection evaluation for the access-control lab.

The committed request contains structural observations and owner requirements only.
Truth labels stay local. Preview is local; the separately approved path can
contact a paid model once, but neither path contacts a diagnostic target.
"""
from __future__ import annotations

import json
import hmac
import os
import time
from functools import partial
from pathlib import Path

from aegis.ai_advisor import _external_transport
from aegis.audit import AuditLog
from aegis.planner_llm_gateway import Budget, PlannerLLMGateway
FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
MEASUREMENTS = Path(__file__).resolve().parents[1] / "docs" / "ACCESS_CONTROL_BLIND_REAL_ARTEX.json"
MODEL = "abliterated-model"
ENDPOINT = "https://api.abliteration.ai/v1/chat/completions"
APPROVAL_DIR = Path.home() / ".local" / "share" / "vulnix" / "selection-eval-approvals"
SYSTEM = (
    "You are choosing whether an isolated, authorized lab should run one read-only "
    "cross-account resource access check. Review the owner's access requirements and "
    "the measured presence of an account resource link for each anonymous case. "
    "Select cases where this check is useful. This is a plan candidate, never a "
    "vulnerability verdict or permission to execute. Return exactly one JSON object "
    'with a single key, "selected", containing an array of case IDs. No prose.'
)


def build_request(*, max_output_tokens: int = 384,
                  structured_output: bool = False,
                  local_reasoning: dict | None = None) -> tuple[dict, dict[str, str]]:
    if type(max_output_tokens) is not int or max_output_tokens not in (384, 960, 1024):
        raise ValueError("unsupported evaluation output cap")
    if type(structured_output) is not bool:
        raise ValueError("invalid structured output setting")
    if local_reasoning is not None and (type(local_reasoning) is not dict or
                                        set(local_reasoning) not in ({"reasoning"}, {"reasoning_effort"})):
        raise ValueError("invalid local reasoning setting")
    owners = json.loads((FIXTURES / "access_control_owner_specs.json").read_text(encoding="utf-8"))
    truth = json.loads((FIXTURES / "access_control_truth.json").read_text(encoding="utf-8"))
    recorded = json.loads(MEASUREMENTS.read_text(encoding="utf-8"))["adaptive_plan"]
    observed = {row["mode"]: row["observed_account_link"] for row in recorded}
    if len(observed) != len(recorded) or set(owners) != set(truth) or set(owners) != set(observed) \
            or any(type(value) is not bool for value in observed.values()):
        raise ValueError("owner, independent truth and measured cases differ")
    mapping = {f"C{i:02d}": mode for i, mode in enumerate(sorted(owners), 1)}
    cases = [{"id": case_id,
              "root_access_requirement": owners[mode]["root_requirement"],
              "account_resource_requirement": owners[mode]["account_resource_requirement"],
              "account_resource_link_observed": observed[mode]}
             for case_id, mode in mapping.items()]
    request = {"model": MODEL,
               "messages": [{"role": "system", "content": SYSTEM},
                            {"role": "user", "content": json.dumps({"cases": cases},
                                                                       ensure_ascii=False, sort_keys=True)}],
               "temperature": 0, "max_tokens": max_output_tokens}
    if structured_output:
        request["response_format"] = {"type": "json_object"}
    if local_reasoning:
        request.update(local_reasoning)
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
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("answer must be plain JSON") from exc
    if not isinstance(answer, dict) or set(answer) != {"selected"} or not isinstance(answer["selected"], list):
        raise ValueError("answer shape rejected")
    selected = answer["selected"]
    if any(not isinstance(x, str) or x not in mapping for x in selected) or len(selected) != len(set(selected)):
        raise ValueError("answer contains an invalid or repeated case")
    return set(selected)


def score(selected: set[str], mapping: dict[str, str]) -> dict:
    actual = truth_ids(mapping)
    tp, fp, fn, tn = (len(selected & actual), len(selected - actual),
                      len(actual - selected), len(set(mapping) - selected - actual))
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "unnecessary_check_rate": fp / (tp + fp) if tp + fp else None,
            "unnecessary_case_rate": fp / len(mapping)}


def truth_ids(mapping: dict[str, str]) -> set[str]:
    truth = json.loads((FIXTURES / "access_control_truth.json").read_text(encoding="utf-8"))
    return {case_id for case_id, mode in mapping.items() if truth[mode]["idor_check_appropriate"]}


def selection_errors(selected: set[str], mapping: dict[str, str]) -> list[dict]:
    actual = truth_ids(mapping)
    return [{"case_id": case_id, "lab_condition": mapping[case_id],
             "kind": "false_positive" if case_id in selected else "missed"}
            for case_id in sorted(selected ^ actual)]


def run_preview(*, max_output_tokens: int = 384,
                structured_output: bool = False,
                local_reasoning: dict | None = None) -> dict:
    request, mapping = build_request(max_output_tokens=max_output_tokens,
                                     structured_output=structured_output,
                                     local_reasoning=local_reasoning)

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


def run_approved(*, approval_sha256: str, api_key: str, audit: AuditLog,
                 transport=None, max_output_tokens: int = 384,
                 structured_output: bool = False) -> dict:
    """One explicitly approved model call; returns only aggregate quality and usage."""
    request, mapping = build_request(max_output_tokens=max_output_tokens,
                                     structured_output=structured_output)
    preview = run_preview(max_output_tokens=max_output_tokens,
                          structured_output=structured_output)["gateway"]
    if not hmac.compare_digest(approval_sha256, preview["first_request_sha256"]):
        raise ValueError("approval does not match the fixed preview")
    if not api_key or audit is None:
        raise ValueError("a server-side key and durable audit are required")
    gateway = PlannerLLMGateway(
        mode="forward", model=MODEL, upstream_url=ENDPOINT, api_key=api_key,
        budget=Budget(max_calls=1, max_total_tokens=2000, max_cost_usd=0.01,
                      usd_per_1k_input=0.001, usd_per_1k_output=0.003),
        approval={"max_calls": 1, "first_request_sha256": approval_sha256},
        audit=audit, transport=transport or partial(_external_transport, timeout_s=30))
    try:
        # One owner approval must survive a process restart and a failed upstream call.
        # O_EXCL also prevents two processes on this host from consuming it together.
        APPROVAL_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        if APPROVAL_DIR.stat().st_mode & 0o077:
            raise ValueError("approval store permissions are too broad")
        marker = APPROVAL_DIR / approval_sha256
        try:
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise ValueError("approval already consumed") from None
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(json.dumps({"request_sha256": approval_sha256, "at": time.time()}) + "\n")
            file.flush()
            os.fsync(file.fileno())
        directory_fd = os.open(APPROVAL_DIR, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        audit.record("selection_model.approval_consumed", request_sha256=approval_sha256)
        started = time.monotonic()
        status, response = gateway.handle(json.dumps(request).encode(), f"Bearer {gateway.token}")
        elapsed = round(time.monotonic() - started, 3)
        if status != 200:
            report = gateway.report()
            failure_type = (report.get("failed_upstream") or {}).get("error_type")
            failure_reason = {"UsageExceededBudget": "usage_exceeded_budget",
                              "InvalidUsage": "invalid_usage"}.get(failure_type)
            return {"selection": None, "accepted": False, "response_adoption_rate": 0.0,
                    "reject_reason": failure_reason or ("upstream_exchange_failed" if status == 409
                                                         else "gateway_refused"),
                    "selection_errors": [], "selected_case_ids": [], "usage": {},
                    "finish_reason": None, "elapsed_s": elapsed, "gateway": report,
                    "provider_billed_cost_usd": None, "target_get": 0, "worker_launches": 0}
        content = response["choices"][0]["message"].get("content")
        try:
            if not isinstance(content, str):
                raise ValueError("missing content")
            selected = validate_answer(content, mapping)
            accepted = True
            reject_reason = None
        except ValueError as exc:
            selected, accepted = set(), False
            reject_reason = {"answer must be plain JSON": "invalid_json",
                             "missing content": "missing_content",
                             "duplicate answer key": "duplicate_json_key",
                             "answer shape rejected": "invalid_shape",
                             "answer contains an invalid or repeated case": "invalid_case_id"}.get(str(exc), "invalid_answer")
        usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
        details = usage.get("completion_tokens_details") or {}
        reported_usage = {k: usage[k] for k in ("prompt_tokens", "completion_tokens")
                          if isinstance(usage.get(k), int) and usage[k] >= 0}
        if isinstance(details, dict) and isinstance(details.get("reasoning_tokens"), int) \
                and details["reasoning_tokens"] >= 0:
            reported_usage["reasoning_tokens"] = details["reasoning_tokens"]
        finish_reason = response["choices"][0].get("finish_reason")
        if finish_reason not in ("stop", "length", "tool_calls", "content_filter"):
            finish_reason = "other" if finish_reason is not None else None
        if accepted and finish_reason != "stop":
            selected, accepted = set(), False
            reject_reason = {"length": "truncated", "content_filter": "filtered",
                             "tool_calls": "unexpected_tool_call"}.get(finish_reason,
                                                                          "unknown_finish_reason")
        if accepted and gateway.failed:
            selected, accepted = set(), False
            reject_reason = "gateway_terminal_response"
        return {"selection": score(selected, mapping) if accepted else None, "accepted": accepted,
                "response_adoption_rate": 1.0 if accepted else 0.0, "reject_reason": reject_reason,
                "selection_errors": selection_errors(selected, mapping) if accepted else [],
                "selected_case_ids": sorted(selected), "usage": reported_usage,
                "finish_reason": finish_reason,
                "elapsed_s": elapsed, "gateway": gateway.report(),
                "provider_billed_cost_usd": None,
                "target_get": 0, "worker_launches": 0}
    finally:
        gateway.close()


if __name__ == "__main__":
    print(json.dumps(run_preview(), ensure_ascii=False, indent=2))
