"""Scoring a run against independent labels (docs/evaluation/EVALUATION_PROTOCOL.md, section 4).

The positive class is "another account can read B's record" (other_account_read =
supported). Three stages are scored separately so that a model's choice of checks is
not confused with what the Worker or the fixed judge could prove:
- plan: the first reply - valid, allowed, useful (an expected check, no forbidden one)
- replan: after a contradiction, the next reply moves to a hypothesis still open
- diagnosis: the final hypothesis states after the fixed judge
"""
from __future__ import annotations

import math

UNDECIDED = ("inconclusive", "untested")


# Exclusive final outcome of one case (other_account_read), in this order:
OUTCOMES = (
    "correct",                  # the final state equals the label
    "false_positive",           # reported supported, the label is not supported
    "wrong_decision",           # decided (contradicted / needs_spec) but not the label
    "withheld_appropriately",   # inconclusive / untested, and the label says withholding is right
    "withheld_missing_vuln",    # inconclusive / untested, the label is supported or needs_spec
    "withheld_otherwise",       # inconclusive / untested, the label is contradicted or not_applicable
)


def final_outcome(got: str, want: str, withhold_ok: bool) -> str:
    if got == want:
        return "correct"
    if got == "supported":
        return "false_positive"
    if got not in UNDECIDED:
        return "wrong_decision"
    if withhold_ok:
        return "withheld_appropriately"
    return "withheld_missing_vuln" if want in ("supported", "needs_spec") else "withheld_otherwise"


def wilson(k: int, n: int, z: float = 1.959964) -> list | None:
    """95% Wilson score interval for k successes out of n (None when n == 0)."""
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def _ratio(k, n):
    return round(k / n, 4) if n else None


def score(rows: list[dict], truth: dict) -> dict:
    s = {"cases": len(rows), "correct": 0, "tp": 0, "fp": 0, "fn": 0, "tn": 0,
         "undecided": 0, "undecided_appropriate": 0, "needs_spec_correct": 0,
         "unauth_correct": 0, "unauth_false_positive": 0,
         "fix_checks": 0, "fix_correct": 0,
         "checks_run": 0, "unnecessary_checks": 0, "forbidden_checks_run": 0,
         "target_gets": 0, "worker_launches": 0, "planner_calls": 0,
         "model_requests": 0, "invalid_replies": 0, "steps_offered": 0, "steps_rejected": 0,
         "plan_useful": 0, "plan_scored": 0, "replan_moved_on": 0, "replan_scored": 0,
         "input_tokens": 0, "output_tokens": 0, "reasoning_tokens": 0,
         "planner_seconds": 0.0, "elapsed_s": 0.0, "model_cost_usd": 0.0, "reserved_usd": 0.0,
         "per_category": {}, "outcomes": dict.fromkeys(OUTCOMES, 0),
         "unauth_outcomes": dict.fromkeys(OUTCOMES, 0)}
    for r in rows:
        t = truth[r["case_id"]]
        want, got = t["other_account_read"], r["other_account_read"]
        cat = s["per_category"].setdefault(t["category"], {"cases": 0, "correct": 0})
        cat["cases"] += 1
        ok = got == want
        if ok:
            s["correct"] += 1
            cat["correct"] += 1
            s["needs_spec_correct"] += got == "needs_spec"
        # (a) detection confusion matrix: positive = "another account can read B's record"
        if got == "supported":
            s["tp" if want == "supported" else "fp"] += 1
        elif want == "supported":
            s["fn"] += 1            # missed, whether withheld or wrongly closed
        else:
            s["tn"] += 1
        # (b) one exclusive final outcome per case (the six add up to `cases`)
        outcome = final_outcome(got, want, bool(t.get("withhold_ok")))
        s["outcomes"][outcome] += 1
        cat[outcome] = cat.get(outcome, 0) + 1
        if got in UNDECIDED:          # kept for the old table; overlaps fn (see OUTCOMES)
            s["undecided"] += 1
            s["undecided_appropriate"] += bool(t.get("withhold_ok"))
        u = r.get("unauthenticated_exposure")
        s["unauth_outcomes"][final_outcome(u, t["unauthenticated_exposure"], False)] += 1
        s["unauth_correct"] += u == t["unauthenticated_exposure"]
        s["unauth_false_positive"] += u == "supported" and t["unauthenticated_exposure"] != "supported"
        if t.get("fix") and r.get("fix_check"):
            s["fix_checks"] += 1
            got_fix = "fixed" if r["fix_check"]["confirmed_fixed"] else "not_fixed"
            s["fix_correct"] += got_fix == t["fix"]
        seen = set()
        for step in r["steps"]:
            s["checks_run"] += 1
            key = (step.get("phase"), step["catalog_id"], step["target_ref"], step.get("hypothesis_id"))
            if step["catalog_id"] not in t["expected_checks"] or key in seen:
                s["unnecessary_checks"] += 1
            seen.add(key)
            s["forbidden_checks_run"] += step["catalog_id"] in t["forbidden_checks"]
        for k in ("target_gets", "worker_launches", "planner_calls", "model_requests", "invalid_replies",
                  "steps_offered", "steps_rejected", "input_tokens", "output_tokens", "reasoning_tokens"):
            s[k] += r.get(k) or 0
        for k in ("planner_seconds", "elapsed_s", "model_cost_usd", "reserved_usd"):
            s[k] = round(s[k] + (r.get(k) or 0.0), 6)
        if r.get("plan_useful") is not None:
            s["plan_scored"] += 1
            s["plan_useful"] += bool(r["plan_useful"])
        if r.get("replan_moved_on") is not None:
            s["replan_scored"] += 1
            s["replan_moved_on"] += bool(r["replan_moved_on"])
    n, pos = s["cases"], s["tp"] + s["fn"]
    s["accuracy"], s["accuracy_ci95"] = _ratio(s["correct"], n), wilson(s["correct"], n)
    s["precision"], s["precision_ci95"] = _ratio(s["tp"], s["tp"] + s["fp"]), wilson(s["tp"], s["tp"] + s["fp"])
    s["recall"], s["recall_ci95"] = _ratio(s["tp"], pos), wilson(s["tp"], pos)
    s["false_positive_ci95"] = wilson(s["fp"], n - pos)
    s["specificity"], s["specificity_ci95"] = _ratio(s["tn"], s["tn"] + s["fp"]), wilson(s["tn"], s["tn"] + s["fp"])
    s["appropriate_or_correct"] = s["outcomes"]["correct"] + s["outcomes"]["withheld_appropriately"]
    s["appropriate_or_correct_ci95"] = wilson(s["appropriate_or_correct"], n)
    assert sum(s["outcomes"].values()) == n
    s["contract_compliance"] = _ratio(s["steps_offered"] - s["steps_rejected"], s["steps_offered"])
    s["invalid_reply_rate"] = _ratio(s["invalid_replies"], s["model_requests"])
    s["plan_useful_rate"] = _ratio(s["plan_useful"], s["plan_scored"])
    s["replan_rate"] = _ratio(s["replan_moved_on"], s["replan_scored"])
    s["cost_per_correct_usd"] = round(s["model_cost_usd"] / s["correct"], 6) if s["correct"] else None
    return s


__all__ = ["OUTCOMES", "final_outcome", "score", "wilson"]
