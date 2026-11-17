"""Blind combination holdouts for baseline findings and Apache extra-check selection.

Truth is stored separately from the local model and never sent to ARTEX. These
are new cross-product conditions, not new vulnerability classes or a real LLM.
"""
from __future__ import annotations

import json
import os
import tempfile
import argparse
from pathlib import Path

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"

from scripts.bench_initial_extra_selection import _certificate, measure  # noqa: E402


TRUTH = json.loads((Path(__file__).resolve().parents[1] /
                    "tests/fixtures/initial_mixed_holdout_truth.json").read_text())


def _score(pairs: list[tuple[bool, bool]]) -> dict:
    tp = sum(truth and observed for truth, observed in pairs)
    fp = sum(not truth and observed for truth, observed in pairs)
    fn = sum(truth and not observed for truth, observed in pairs)
    tn = sum(not truth and not observed for truth, observed in pairs)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None}


def summarize(rows: list[dict]) -> dict:
    by_strategy = {}
    for strategy in ("fixed", "always", "observed"):
        selected = [r for r in rows if r["strategy"] == strategy]
        by_class = {}
        for kind in ("cors", "cookie"):
            class_rows = [r for r in selected if r["kind"] == kind]
            by_class[kind] = {
                "detection": _score([(r["truth_baseline_detected"], r["verdict"] == "detected")
                                     for r in class_rows]),
                "selection": _score([(r["truth_status_check_appropriate"], r["status_plan_proposed"])
                                     for r in class_rows]),
                "cases": len(class_rows),
            }
        detection = _score([(r["truth_baseline_detected"], r["verdict"] == "detected")
                            for r in selected])
        selection = _score([(r["truth_status_check_appropriate"], r["status_plan_proposed"])
                            for r in selected])
        by_strategy[strategy] = {
            "classes": by_class,
            "detection": detection,
            "selection": selection,
            "unnecessary_extra_proposals": selection["fp"],
            "needed_check_omissions": selection["fn"],
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
    return {"scope": "five local HTTPS cross-product conditions across CORS and Cookie",
            "model": "local scripted model; not Abliteration AI",
            "strategies": by_strategy, "rows": rows}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    cases = {key: value for key, value in TRUTH.items()
             if not args.smoke or key in ("cors_credentialed_apache", "cookie_safe_apache")}
    rows = []
    with tempfile.TemporaryDirectory(prefix="vulnix-mixed-holdout-") as tmp:
        certificate = _certificate(Path(tmp))
        for case_id, truth in cases.items():
            for strategy in ("fixed", "always", "observed"):
                row = measure(truth["kind"], truth["mode"], strategy, certificate,
                              server_banner=truth["banner"],
                              allow_status_probe=truth["status_consent"])
                row["case_id"] = case_id
                row["truth_baseline_detected"] = truth["baseline_detected"]
                row["truth_status_check_appropriate"] = truth["status_check_appropriate"]
                row["truth_status_exposed"] = truth["status_exposed"]
                assert (row["verdict"] == "detected") == truth["baseline_detected"]
                assert not truth["status_exposed"] or row["status_finding_verdict"] == "detected"
                assert row["status_finding_verdict"] != "detected" or truth["status_exposed"]
                rows.append(row)
    if os.environ.get("VULNIX_ARTEX_REAL_BIN"):
        assert all(r["engine_kind"] == "artex-binary" and r["local_model_calls"] > 0
                   for r in rows if r["planner_calls"] > 0)
    print(json.dumps(summarize(rows), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
