"""Compare lookup-first and first-prompt facts on the same status holdout."""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"

from scripts.bench_initial_extra_selection import _certificate, measure  # noqa: E402
from scripts.bench_status_selection_holdout import TRUTH, _score  # noqa: E402


def summarize(rows: list[dict], cases: dict) -> dict:
    expected = {(case_id, strategy) for case_id in cases
                for strategy in ("lookup_facts", "initial_facts")}
    if len(rows) != len(expected) or {(r["case_id"], r["strategy"]) for r in rows} != expected:
        raise ValueError("incomplete or duplicate status comparison")
    by_case = {(r["case_id"], r["strategy"]): r for r in rows}
    strategies = {}
    for strategy in ("lookup_facts", "initial_facts"):
        selected = [by_case[case_id, strategy] for case_id in cases]
        selection = _score([(r["truth_check_appropriate"], r["status_plan_proposed"])
                            for r in selected])
        detection = _score([(r["truth_status_exposed"], r["status_finding_verdict"] == "detected")
                            for r in selected if r["truth_detection_evaluable"]])
        if selection["fp"] or selection["fn"] or detection["fp"] or detection["fn"]:
            raise AssertionError(f"independent status quality gate failed for {strategy}")
        strategies[strategy] = {
            "selection": selection, "detection": detection,
            "unscored_no_consent": sum(not r["truth_detection_evaluable"] for r in selected),
            "target_get": sum(r["target_get"] for r in selected),
            "worker_launches": sum(r["worker_launches"] for r in selected),
            "planner_calls": sum(r["planner_calls"] for r in selected),
            "local_model_calls": sum(r["local_model_calls"] for r in selected),
            "budget_est_tokens": sum(r["budget_est_tokens"] for r in selected),
            "paid_model_cost_usd": 0,
            "elapsed_s_sum": round(sum(r["elapsed_s"] for r in selected), 3),
        }
    for case_id in cases:
        old = by_case[case_id, "lookup_facts"]
        new = by_case[case_id, "initial_facts"]
        if any(old[key] != new[key] for key in (
                "status_plan_proposed", "status_finding_verdict", "target_get",
                "worker_launches", "planner_calls")):
            raise AssertionError(f"result or execution changed for {case_id}")
        if old["engine_kind"] == "artex-binary" and old["planner_calls"]:
            if (new["engine_kind"] != "artex-binary"
                    or new["local_model_calls"] != old["local_model_calls"] - 1
                    or new["budget_est_tokens"] >= old["budget_est_tokens"]):
                raise AssertionError(f"fact lookup was not removed for {case_id}")
    return {"scope": "same local HTTPS status targets and independent labels",
            "model": "real ARTEX when configured plus local scripted model; not Abliteration AI",
            "strategies": strategies, "rows": rows}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    cases = {k: v for k, v in TRUTH.items()
             if not args.smoke or k in ("status_exposed_apache", "status_non_apache")}
    rows = []
    with tempfile.TemporaryDirectory(prefix="vulnix-status-facts-") as tmp:
        certificate = _certificate(Path(tmp))
        for case_id, truth in cases.items():
            for strategy in ("lookup_facts", "initial_facts"):
                row = measure("status", truth["mode"], strategy, certificate,
                              allow_status_probe=truth["status_consent"])
                row.update(case_id=case_id,
                           truth_status_exposed=truth["status_exposed"],
                           truth_check_appropriate=truth["check_appropriate"],
                           truth_detection_evaluable=truth["detection_evaluable"])
                if not truth["status_consent"] and row["target_get"] != 1:
                    raise AssertionError("unconsented status endpoint was fetched")
                rows.append(row)
    print(json.dumps(summarize(rows, cases), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
