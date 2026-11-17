"""Compare redundant fact lookup with selection from ARTEX's initial graph summary.

Both arms use the same withheld access targets and local scripted model. This
isolates model round trips; it does not establish real-model decision quality.
"""
from __future__ import annotations

import argparse
import json
import os

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"

from scripts.bench_access_holdout import TRUTH, _score, measure_holdout  # noqa: E402


def compare(rows: list[dict], truth: dict | None = None) -> dict:
    truth = TRUTH if truth is None else truth
    expected = {(mode, strategy) for mode in truth
                for strategy in ("adaptive", "adaptive_one_pass")}
    if len(rows) != len(expected) or {(r["mode"], r["strategy"]) for r in rows} != expected:
        raise ValueError("incomplete or duplicate comparison grid")
    by_mode = {(r["mode"], r["strategy"]): r for r in rows}
    out = {}
    for strategy in ("adaptive", "adaptive_one_pass"):
        group = [by_mode[mode, strategy] for mode in truth]
        selection = _score(group, "idor_check_appropriate", "plan_adopted")
        out[strategy] = {
            "selection": selection,
            "root_detection": _score(group, "unauth_exposure", "root_exposure_detected"),
            "idor_detection": _score(group, "cross_account_access", "idor_proven"),
            "target_get": sum(len(r["target_requests"]) for r in group),
            "worker_launches": sum(r["worker_launches"] for r in group),
            "planner_calls": sum(r["planner_calls"] for r in group),
            "local_model_calls": sum(r["local_model_calls"] for r in group),
            "budget_est_tokens": sum(r.get("ai_est_tokens") or 0 for r in group),
            "hypothetical_model_cost_usd": round(sum(
                r.get("hypothetical_model_cost_usd") or 0 for r in group), 6),
            "paid_model_cost_usd": 0,
            "elapsed_s_sum": round(sum(r["elapsed_s"] for r in group), 3),
        }
    for mode in truth:
        old = by_mode[mode, "adaptive"]
        new = by_mode[mode, "adaptive_one_pass"]
        if (old["truth"] != truth[mode] or new["truth"] != truth[mode]
                or any(old[key] != new[key] for key in (
                    "plan_adopted", "root_exposure_detected", "idor_proven",
                    "target_requests", "worker_launches", "planner_calls"))):
            raise AssertionError(f"selection or diagnosis changed for {mode}")
        if old["plan_adopted"] and not old["idor_proven"] and truth[mode]["cross_account_access"]:
            raise AssertionError(f"positive IDOR lost proof for {mode}")
        if old["engine_kind"] == "artex-binary":
            if (new["engine_kind"] != "artex-binary"
                    or new["local_model_calls"] != old["local_model_calls"] - 1
                    or (new.get("ai_est_tokens") or 0) >= (old.get("ai_est_tokens") or 0)):
                raise AssertionError(f"first-prompt fact did not remove one model round for {mode}")
    return {"scope": "withheld access holdout; same seven local targets",
            "model": "real ARTEX when configured plus local scripted model, not Abliteration AI",
            "strategies": out, "rows": rows}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    modes = (["cross_account_allowed", "private_root_200", "account_directory_public"]
             if args.smoke else list(TRUTH))
    rows = [measure_holdout(mode, strategy) for mode in modes
            for strategy in ("adaptive", "adaptive_one_pass")]
    report = compare(rows, {mode: TRUTH[mode] for mode in modes})
    missing = measure_holdout("private_root_200", "adaptive_one_pass",
                              omit_account_fact=True)
    if (not missing["root_exposure_detected"] or missing["plan_adopted"]
            or missing["idor_proven"] or missing["observed_account_link"] is not None):
        raise AssertionError("missing observation must not create an IDOR verdict")
    if os.environ.get("VULNIX_ARTEX_REAL_BIN"):
        signals = missing["model_signals"]
        if (len(signals) != 2 or signals[0]["has_surface_title"]
                or "list_facts" not in signals[1]["prior_tool_names"]):
            raise AssertionError("missing initial fact did not fall back to ARTEX list_facts")
    report["missing_initial_fact_fallback"] = missing
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
