"""Withheld access responses scored through existing ARTEX/Gateway/Worker paths.

The approved 14-condition Abliteration request is unchanged. These separate
targets and labels never enter the planner's anonymous feature request.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from unittest.mock import patch

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"

from scripts import bench_access_control as baseline  # noqa: E402
from tests.fixtures.access_holdout_lab import AccessHoldoutLab  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
TRUTH = json.loads((ROOT / "tests/fixtures/access_holdout_truth.json").read_text())
OWNER_SPECS = json.loads((ROOT / "tests/fixtures/access_holdout_owner_specs.json").read_text())


def measure_holdout(mode: str, strategy: str, *, omit_account_fact: bool = False) -> dict:
    if mode not in TRUTH or strategy not in ("fixed_l1", "always", "adaptive", "adaptive_one_pass"):
        raise ValueError("unknown holdout condition")
    with patch.object(baseline, "AccessControlLab", AccessHoldoutLab), \
            patch.object(baseline, "TRUTH", TRUTH), \
            patch.object(baseline, "OWNER_SPECS", OWNER_SPECS):
        return baseline._measure(mode, strategy, omit_account_fact=omit_account_fact)


def _score(rows: list[dict], truth_key: str, observed_key: str) -> dict:
    tp = sum(r["truth"][truth_key] and r[observed_key] for r in rows)
    fp = sum(not r["truth"][truth_key] and r[observed_key] for r in rows)
    fn = sum(r["truth"][truth_key] and not r[observed_key] for r in rows)
    tn = sum(not r["truth"][truth_key] and not r[observed_key] for r in rows)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None}


def summarize(rows: list[dict]) -> dict:
    strategies = {}
    for name in ("fixed_l1", "always", "adaptive"):
        selected = [r for r in rows if r["strategy"] == name]
        selection = _score(selected, "idor_check_appropriate", "plan_adopted")
        strategies[name] = {
            "classes": {
                "unauthenticated_protected_json": _score(selected, "unauth_exposure", "root_exposure_detected"),
                "cross_account_idor": _score(selected, "cross_account_access", "idor_proven"),
            },
            "selection": selection,
            "unnecessary_proposals": selection["fp"],
            "appropriate_check_omissions": selection["fn"],
            "target_get": sum(len(r["target_requests"]) for r in selected),
            "worker_launches": sum(r["worker_launches"] for r in selected),
            "gateway_calls": sum(r["gateway_calls"] for r in selected),
            "planner_calls": sum(r["planner_calls"] for r in selected),
            "model_calls": sum(r["local_model_calls"] for r in selected),
            "elapsed_s_sum": round(sum(r["elapsed_s"] for r in selected), 3),
            "budget_est_tokens_sum": sum(r.get("ai_est_tokens") or 0 for r in selected),
            "hypothetical_model_cost_usd_sum": round(sum(
                r.get("hypothetical_model_cost_usd") or 0 for r in selected), 6),
            "paid_model_cost_usd_sum": 0,
        }
    return {"scope": f"{len(rows) // 3} withheld access-control conditions",
            "model": "real ARTEX when configured, local scripted model; not Abliteration AI",
            "strategies": strategies, "rows": rows,
            "shared_case_note": "The auth and IDOR classes share the same target requests; do not sum their GETs."}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    cases = [mode for mode in TRUTH if not args.smoke or mode in
             ("private_root_200", "cross_account_allowed", "account_directory_public")]
    rows = [measure_holdout(mode, strategy) for mode in cases
            for strategy in ("fixed_l1", "always", "adaptive")]
    for row in rows:
        truth = TRUTH[row["mode"]]
        assert row["truth"] == truth
        assert row["root_exposure_detected"] == truth["unauth_exposure"]
        assert row["idor_proven"] == (truth["cross_account_access"]
                                      if row["strategy"] != "fixed_l1" else False)
    adaptive = [row for row in rows if row["strategy"] == "adaptive"]
    selection = _score(adaptive, "idor_check_appropriate", "plan_adopted")
    assert selection["fn"] == 0 and selection["fp"] <= 1
    assert all(row["planner_calls"] == (0 if row["strategy"] == "fixed_l1" else 1)
               for row in rows)
    if os.environ.get("VULNIX_ARTEX_REAL_BIN"):
        assert all(r["engine_kind"] == "artex-binary" and r["local_model_calls"] > 0
                   for r in rows if r["strategy"] != "fixed_l1")
    print(json.dumps(summarize(rows), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
