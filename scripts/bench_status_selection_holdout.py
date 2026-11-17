"""Independent status exposure and selection labels on local HTTPS targets.

Consent withdrawal is scored for selection safety, not as a detection miss:
Vulnix is forbidden to fetch the endpoint in that condition.
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"

from scripts.bench_initial_extra_selection import _certificate, measure  # noqa: E402


TRUTH = json.loads((Path(__file__).resolve().parents[1] /
                    "tests/fixtures/status_selection_holdout_truth.json").read_text())


def _score(pairs: list[tuple[bool, bool]]) -> dict:
    tp = sum(truth and observed for truth, observed in pairs)
    fp = sum(not truth and observed for truth, observed in pairs)
    fn = sum(truth and not observed for truth, observed in pairs)
    tn = sum(not truth and not observed for truth, observed in pairs)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None}


def summarize(rows: list[dict]) -> dict:
    strategies = {}
    for strategy in ("fixed", "always", "observed"):
        selected = [r for r in rows if r["strategy"] == strategy]
        selection = _score([(r["truth_check_appropriate"], r["status_plan_proposed"])
                            for r in selected])
        detection = _score([(r["truth_status_exposed"], r["status_finding_verdict"] == "detected")
                            for r in selected if r["truth_detection_evaluable"]])
        strategies[strategy] = {
            "detection": detection, "selection": selection,
            "unnecessary_extra_proposals": selection["fp"],
            "eligible_check_omissions": selection["fn"],
            "unscored_no_consent": sum(not r["truth_detection_evaluable"] for r in selected),
            "target_get": sum(r["target_get"] for r in selected),
            "worker_launches": sum(r["worker_launches"] for r in selected),
            "planner_calls": sum(r["planner_calls"] for r in selected),
            "local_model_calls": sum(r["local_model_calls"] for r in selected),
            "elapsed_s_sum": round(sum(r["elapsed_s"] for r in selected), 3),
            "budget_est_tokens_sum": sum(r["budget_est_tokens"] for r in selected),
            "hypothetical_model_cost_usd_sum": round(sum(
                r["hypothetical_model_cost_usd"] for r in selected), 6),
            "paid_model_cost_usd_sum": 0,
        }
    return {"scope": f"{len(rows) // 3} local HTTPS Apache status conditions",
            "model": "local scripted model; not Abliteration AI",
            "strategies": strategies, "rows": rows}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    cases = {key: value for key, value in TRUTH.items()
             if not args.smoke or key in ("status_exposed_apache", "status_non_apache")}
    rows = []
    with tempfile.TemporaryDirectory(prefix="vulnix-status-holdout-") as tmp:
        certificate = _certificate(Path(tmp))
        for case_id, truth in cases.items():
            for strategy in ("fixed", "always", "observed"):
                row = measure("status", truth["mode"], strategy, certificate,
                              allow_status_probe=truth["status_consent"])
                row.update(case_id=case_id,
                           truth_status_exposed=truth["status_exposed"],
                           truth_check_appropriate=truth["check_appropriate"],
                           truth_detection_evaluable=truth["detection_evaluable"])
                if strategy == "observed":
                    assert row["status_plan_proposed"] == truth["check_appropriate"]
                if truth["detection_evaluable"] and strategy != "fixed":
                    assert (row["status_finding_verdict"] == "detected") == truth["status_exposed"]
                if not truth["status_consent"]:
                    assert row["target_get"] == 1
                rows.append(row)
    if os.environ.get("VULNIX_ARTEX_REAL_BIN"):
        assert all(r["engine_kind"] == "artex-binary" and r["local_model_calls"] > 0
                   for r in rows if r["planner_calls"] > 0)
    print(json.dumps(summarize(rows), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
