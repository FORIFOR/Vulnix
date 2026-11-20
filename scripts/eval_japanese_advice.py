"""Evaluate Japanese advice on aegis/advisor_eval/japanese_quality_cases.json.

Two sources are scored with the same product validator (aegis.ai_advisor.validate_advice)
and the same quality axes (aegis.advisor_eval.japanese_quality):

  builtin_rule_table   the local mock model's fixed rule-table answer
                       (aegis.abliteration_server._build_advice_content) - what a user sees
                       today without an external model. NOT a model's quality.
  labelled_candidates  hand-written replies standing in for a model: one good answer per
                       finding plus labelled defects (overclaim, unsupported impact, unsafe
                       fix, secret leak, wrong verdict state, no retest, hard to read).

The real Abliteration AI request for the same findings is built and hashed, never sent.

  python3 -m scripts.eval_japanese_advice [--out report.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

os.environ.setdefault("VULNIX_NO_ENV_LOCAL", "1")

from aegis import advisor_catalog as catalog  # noqa: E402
from aegis.abliteration_server import _build_advice_content  # noqa: E402
from aegis.advisor_eval import japanese_quality as jq  # noqa: E402
from aegis.ai_advisor import (ExternalAbliterationAdvisor, _extract_json_from_text,  # noqa: E402
                              finding_to_payload_item, validate_advice)

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "aegis" / "advisor_eval" / "japanese_quality_cases.json"
HARD_DEFECTS = ("overclaim", "unsupported_impact", "unsafe_fix", "secret_leak")
QUALITY_AXIS = {"verdict_state": "verdict_state", "no_retest": "retest", "readability": "readability_auto"}


def _validate(finding: dict, item: dict):
    advice, rejected = validate_advice({"advice": [{"ref": "F1", **item}]}, {"F1": finding})
    return (advice[0] if advice else None), rejected


def _advice_dict(a) -> dict:
    return {"risk_explanation": a.risk_explanation,
            "remediation": [{"fix": r.fix, "detail": r.detail} for r in a.remediation],
            "next_checks": [{"operation": c.operation, "purpose": c.purpose} for c in a.next_checks]}


def _dropped_unsafe(item: dict, accepted) -> bool:
    """An unsafe step counts as refused when it did not survive into the accepted advice."""
    if accepted is None:
        return True
    kept = {(r.fix, r.detail) for r in accepted.remediation}
    return not any((r["fix"], r.get("detail") or "") in kept or
                   (r["fix"] in {k[0] for k in kept} and not r.get("detail"))
                   for r in item["remediation"])


def eval_candidates(cases: list[dict]) -> dict:
    gates = {k: 0 for k in ("dangerous_accepted", "unsupported_impact_accepted", "overclaim_accepted",
                            "secret_leak_accepted", "schema_violations_accepted")}
    good_rejected, good_quality_failures, missed, flagged = 0, [], [], 0
    totals: dict[str, int] = {}
    for case in cases:
        finding = case["finding"]
        for cand in case["candidates"]:
            defect = cand["defect"]
            totals[defect or "good"] = totals.get(defect or "good", 0) + 1
            accepted, rejected = _validate(finding, cand["item"])
            ident = f"{case['case_id']}:{cand['id']}"
            if defect is None:
                if accepted is None or rejected:
                    good_rejected += 1
                    continue
                s = jq.score(_advice_dict(accepted), finding["verdict"], finding["id"])
                bad = [a for a in jq.AXES if not s[a]]
                if bad:
                    good_quality_failures.append({"id": ident, "axes": bad})
                continue
            if defect == "schema":
                v = cand["violation"]
                survived = accepted is not None and (
                    v in ("authority_key", "claim_not_in_catalog")
                    or (v == "unknown_fix" and any(r.fix not in catalog.REMEDIATION_ACTIONS for r in accepted.remediation))
                    or (v == "unknown_operation" and any(c.operation not in catalog.OPERATIONS
                                                         for c in accepted.next_checks)))
                if survived:
                    gates["schema_violations_accepted"] += 1
                    gates["dangerous_accepted"] += 1
                continue
            if defect in HARD_DEFECTS:
                refused = (_dropped_unsafe(cand["item"], accepted) if defect == "unsafe_fix"
                           else accepted is None)
                if not refused:
                    gates["dangerous_accepted"] += 1
                    key = {"unsupported_impact": "unsupported_impact_accepted", "overclaim": "overclaim_accepted",
                           "secret_leak": "secret_leak_accepted"}.get(defect)
                    if key:
                        gates[key] += 1
                continue
            # quality defects: may be shown, must be flagged by the scorer
            if accepted is None:
                flagged += 1            # refused outright is also not shown
                continue
            s = jq.score(_advice_dict(accepted), finding["verdict"], finding["id"])
            if s[QUALITY_AXIS[defect]]:
                missed.append(ident)
            else:
                flagged += 1
    return {"gates": gates, "good_rejected": good_rejected, "good_quality_failures": good_quality_failures,
            "quality_defects_flagged": flagged, "quality_defects_missed": missed, "candidates_by_kind": totals}


def eval_builtin(cases: list[dict]) -> dict:
    failures = {a: [] for a in jq.AXES}
    rejected_total, read = 0, []
    for case in cases:
        f = case["finding"]
        user = json.dumps({"findings": [finding_to_payload_item("F1", f)]}, ensure_ascii=False)
        raw = _extract_json_from_text(_build_advice_content(user))
        advice, rejected = validate_advice(raw, {"F1": f})
        if not advice:
            rejected_total += 1
            continue
        s = jq.score(_advice_dict(advice[0]), f["verdict"], f["id"])
        read.append(s["readability"])
        for a in jq.AXES:
            if not s[a]:
                failures[a].append(case["case_id"])
    n = max(1, len(read))
    return {"rejected": rejected_total, "axis_failures": failures,
            "avg_sentence_chars": round(sum(r["avg_sentence_chars"] for r in read) / n, 1),
            "max_sentence_chars": max((r["max_sentence_chars"] for r in read), default=0),
            "note": "fixed local rule table (the mock model's own answer); NOT a model's performance"}


def real_api_request(cases: list[dict]) -> dict:
    """The request a real ExternalAbliterationAdvisor would send. Built with a dummy key and
    an injected transport that is never called; nothing leaves this process."""
    def never(*_a, **_k):
        raise AssertionError("must not send")
    adv = ExternalAbliterationAdvisor("https://api.abliteration.ai/v1/chat/completions",
                                      api_key="not-a-real-key", transport=never)
    body, ref_map = adv.build_request([c["finding"] for c in cases[:20]])
    payload = json.loads(body)
    assert "not-a-real-key" not in body.decode()
    return {"status": "実モデル日本語解説：未測定", "sent": False, "findings": len(ref_map),
            "request_sha256": hashlib.sha256(body).hexdigest(), "request_bytes": len(body),
            "model": payload["model"], "max_tokens": payload["max_tokens"],
            "reasoning_effort": payload.get("reasoning_effort"),
            "note": "Needs a new owner approval bound to request_sha256 before any send."}


ENDPOINT = "https://api.abliteration.ai/v1/chat/completions"
PRICE_IN, PRICE_OUT = 0.001, 0.003            # USD per 1K tokens, abliterated-model (docs pricing)
APPROVED_CAP_USD = 0.02
APPROVAL_PURPOSE = "japanese_advice_quality"


def _fixed_findings() -> list[dict]:
    return [c["finding"] for c in json.loads(CASES.read_text(encoding="utf-8"))["cases"]]


def fixed_request(api_key: str = "not-a-real-key", transport=None):
    def never(*_a, **_k):
        raise AssertionError("must not send")
    adv = ExternalAbliterationAdvisor(ENDPOINT, api_key=api_key, transport=transport or never)
    body, ref_map = adv.build_request(_fixed_findings())
    return adv, body, ref_map


def worst_case_usd(body: bytes, max_tokens: int) -> float:
    # every byte counted as one input token: an upper bound for any tokenizer
    return round(len(body) / 1000 * PRICE_IN + max_tokens / 1000 * PRICE_OUT, 6)


def run_approved(*, approval_sha256: str, api_key: str, audit, transport=None,
                 approval_dir: Path | None = None) -> dict:
    """ONE owner-approved send of the fixed advice request. Returns scores only, never the
    model's text. Same gates as scripts/eval_adaptive_holdout.run_approved, with the
    worst-case cost reserved in the audit log (AuditLog.record_with_budget)."""
    from functools import partial

    from aegis.ai_advisor import _external_transport
    from aegis.advisor_eval import japanese_quality as jq_mod
    from scripts.eval_approval import (DEFAULT_APPROVAL_ROOT, ApprovalError, consume_approval,
                                       require_key_and_audit, require_matching_approval, usage_fits)

    _, body, _ = fixed_request()
    fixed_sha = hashlib.sha256(body).hexdigest()
    require_matching_approval(approval_sha256, fixed_sha)
    require_key_and_audit(api_key, audit)
    reserve = worst_case_usd(body, json.loads(body)["max_tokens"])
    if reserve > APPROVED_CAP_USD:
        raise ApprovalError("worst-case cost exceeds the approved cap")
    upstream = transport or partial(_external_transport, timeout_s=30)
    sent, raw_reply = [], []

    def guarded(url, headers, sent_body):
        # the bytes on the wire must be the approved bytes; one send only
        if sent or hashlib.sha256(sent_body).hexdigest() != approval_sha256 or url != ENDPOINT:
            raise ApprovalError("refused: not the approved request or a second send")
        sent.append(True)
        reply = upstream(url, headers, sent_body)
        raw_reply.append(reply)
        return reply
    adv, _, ref_map = fixed_request(api_key=api_key, transport=guarded)
    base = {"request_sha256": approval_sha256, "model": adv.model, "findings": len(ref_map),
            "reserved_usd": reserve, "target_get": 0}
    consume_approval(approval_dir or DEFAULT_APPROVAL_ROOT / APPROVAL_PURPOSE, approval_sha256, audit,
                     purpose=APPROVAL_PURPOSE)
    audit.record_with_budget("advisor.safe_send_requested", reserve_micro_usd=int(reserve * 1_000_000) + 1,
                             cap_micro_usd=int(APPROVED_CAP_USD * 1_000_000), endpoint_kind="external",
                             purpose=APPROVAL_PURPOSE, request_sha256=approval_sha256)
    started = time.monotonic()
    try:
        result = adv.advise(_fixed_findings())
    except Exception as e:  # noqa: BLE001 - one failure ends the run; the approval stays consumed
        return {**base, "accepted": False, "reject_reason": f"no_usable_reply:{type(e).__name__}",
                "sends": len(sent), "elapsed_s": round(time.monotonic() - started, 3)}
    elapsed = round(time.monotonic() - started, 3)
    data = json.loads(raw_reply[0])
    finish = (data.get("choices") or [{}])[0].get("finish_reason")
    usage, problem = usage_fits(data.get("usage"), usd_per_1k_input=PRICE_IN, usd_per_1k_output=PRICE_OUT,
                                reserved_usd=reserve)
    audit.record("advisor.safe_send_settled", purpose=APPROVAL_PURPOSE, request_sha256=approval_sha256,
                 usage=usage, finish_reason=str(finish)[:20])
    if finish != "stop" or problem:
        return {**base, "accepted": False, "reject_reason": problem or f"finish_reason_{finish}",
                "usage": usage, "sends": len(sent), "elapsed_s": elapsed}
    findings = {f"F{i + 1}": f for i, f in enumerate(_fixed_findings()[:20])}
    axes = {a: 0 for a in jq_mod.AXES}
    for a in result.advice:
        f = findings[a.ref]
        sc = jq_mod.score(_advice_dict(a), f["verdict"], f["id"])
        for k in jq_mod.AXES:
            axes[k] += int(bool(sc[k]))
    return {**base, "accepted": True, "reject_reason": None, "usage": usage, "sends": len(sent),
            "elapsed_s": elapsed, "answered": len(result.advice), "missing": len(result.missing_refs),
            "rejected_components": len(result.rejected), "axes_passed": axes,
            "human_review": "未実施（日本語の分かりやすさは人間評価が必要）"}


def evaluate() -> dict:
    data = json.loads(CASES.read_text(encoding="utf-8"))
    cases = data["cases"]
    cand = eval_candidates(cases)
    builtin = eval_builtin(cases)
    gates_passed = (all(v == 0 for v in cand["gates"].values()) and cand["good_rejected"] == 0
                    and builtin["rejected"] == 0)
    return {"dataset": data["version"], "cases_sha256": hashlib.sha256(CASES.read_bytes()).hexdigest(),
            "findings": len(cases), "candidates": sum(len(c["candidates"]) for c in cases),
            "labelled_candidates": cand, "builtin_rule_table": builtin,
            "real_api_request": real_api_request(cases), "gates_passed": gates_passed,
            "human_review": "日本語の分かりやすさは自動指標のみ。人間評価（rubric の human_scale）は未実施"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="")
    args = ap.parse_args(argv)
    report = evaluate()
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report["gates_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
