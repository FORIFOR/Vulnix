"""Re-score existing independent labs with common per-class and macro metrics.

Uses loopback targets only. ARTEX columns are absent where no ARTEX selection
experiment exists; a local scripted model is never reported as Abliteration AI.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _score(rows: list[tuple[bool, bool]]) -> dict:
    tp = sum(truth and chosen for truth, chosen in rows)
    fp = sum(not truth and chosen for truth, chosen in rows)
    fn = sum(truth and not chosen for truth, chosen in rows)
    tn = sum(not truth and not chosen for truth, chosen in rows)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "cases": len(rows),
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None}


def _macro(scores: list[dict]) -> dict:
    result = {"class_count": len(scores)}
    for metric in ("precision", "recall", "false_positive_rate"):
        values = [score[metric] for score in scores if score[metric] is not None]
        result[metric] = sum(values) / len(values) if values else None
        result[f"{metric}_classes"] = len(values)
    return result


def summarize(classes: dict[str, dict]) -> dict:
    for name, data in classes.items():
        if data["artex"] is not None and [truth for truth, _ in data["fixed"]] != [
                truth for truth, _ in data["artex"]]:
            raise ValueError(f"{name}: fixed and ARTEX rows use different truth conditions")
    scored = {name: {"fixed": _score(data["fixed"]),
                     "artex": _score(data["artex"]) if data["artex"] is not None else None}
              for name, data in classes.items()}
    paired = [name for name, item in scored.items() if item["artex"] is not None]
    return {"classes": scored, "paired_classes": paired,
            "macro_fixed": _macro([item["fixed"] for item in scored.values()]),
            "macro_fixed_paired": _macro([scored[name]["fixed"] for name in paired]),
            "macro_artex_paired": _macro([scored[name]["artex"] for name in paired])}


def _run(module: str) -> dict:
    env = {**os.environ, "VULNIX_NO_ENV_LOCAL": "1"}
    completed = subprocess.run([sys.executable, "-m", module], cwd=ROOT, env=env,
                               capture_output=True, text=True, check=True, timeout=900)
    return json.loads(completed.stdout)


def build_report(cors: dict, cookie: dict, access: dict, exposure: dict) -> dict:
    classes = {
        "cors_policy": {"fixed": [(r["truth_unsafe_policy"], r["cors_detected"])
                                  for r in cors["rows"]], "artex": None},
        "cookie_session_attributes": {
            "fixed": [(r["expected"] == "detected", r["current"] == "detected")
                      for r in cookie["cases"]], "artex": None},
        "unauthenticated_protected_json": {
            "fixed": [(r["truth"]["unauth_exposure"], r["root_exposure_detected"])
                      for r in access["fixed_l1"]],
            "artex": [(r["truth"]["unauth_exposure"], r["root_exposure_detected"])
                      for r in access["adaptive_plan"]]},
        "cross_account_idor": {
            "fixed": [(r["truth"]["cross_account_access"], r["idor_proven"])
                      for r in access["fixed_l1"]],
            "artex": [(r["truth"]["cross_account_access"], r["idor_proven"])
                      for r in access["adaptive_plan"]]},
        "apache_status_exposure": {
            "fixed": [(r["truth_status_exposed"], r["status_exposure_detected"])
                      for r in exposure["before"]],
            "artex": [(r["truth_status_exposed"], r["status_exposure_detected"])
                      for r in exposure["after"]]},
    }
    report = summarize(classes)
    report["source_scope"] = {
        "cors": {"cases": len(cors["rows"]), "target_get": sum(r["target_gets"] for r in cors["rows"]),
                 "worker_launches": 0, "model_calls": 0},
        "cookie": {"cases": len(cookie["cases"]), "target_get": cookie["target_get"],
                   "worker_launches": cookie["worker_launches"], "model_calls": cookie["model_calls"]},
        "access_fixed": {"cases": len(access["fixed_l1"]),
                         "target_get": sum(len(r["target_requests"]) for r in access["fixed_l1"]),
                         "worker_launches": sum(r["worker_launches"] for r in access["fixed_l1"]),
                         "elapsed_s_sum": round(sum(r["elapsed_s"] for r in access["fixed_l1"]), 3),
                         "model_calls": 0},
        "access_adaptive": {"cases": len(access["adaptive_plan"]),
                            "target_get": sum(len(r["target_requests"]) for r in access["adaptive_plan"]),
                            "worker_launches": sum(r["worker_launches"] for r in access["adaptive_plan"]),
                            "model_calls": sum(r["local_model_calls"] for r in access["adaptive_plan"]),
                            "elapsed_s_sum": round(sum(r["elapsed_s"] for r in access["adaptive_plan"]), 3),
                            "budget_est_tokens_sum": sum(r.get("ai_est_tokens") or 0 for r in access["adaptive_plan"]),
                            "hypothetical_model_cost_usd_sum": round(sum(
                                r.get("hypothetical_model_cost_usd") or 0 for r in access["adaptive_plan"]), 6),
                            "engine_kinds": sorted({r["engine_kind"] for r in access["adaptive_plan"]})},
        "status_fixed": {"cases": len(exposure["before"]),
                         "target_get": sum(len(r["target_requests"]) for r in exposure["before"]),
                         "worker_launches": sum(r["worker_launches"] for r in exposure["before"]),
                         "elapsed_s_sum": round(sum(r["elapsed_s"] for r in exposure["before"]), 3),
                         "model_calls": 0},
        "status_artex": {"cases": len(exposure["after"]),
                         "target_get": sum(len(r["target_requests"]) for r in exposure["after"]),
                         "worker_launches": sum(r["worker_launches"] for r in exposure["after"]),
                         "model_calls": sum(r["local_model_calls"] for r in exposure["after"]),
                         "elapsed_s_sum": round(sum(r["elapsed_s"] for r in exposure["after"]), 3),
                         "budget_est_tokens_sum": sum(r.get("ai_est_tokens") or 0 for r in exposure["after"]),
                         "hypothetical_model_cost_usd_sum": round(sum(
                             r.get("hypothetical_model_cost_usd") or 0 for r in exposure["after"]), 6),
                         "engine_kinds": sorted({r["engine_kind"] for r in exposure["after"]})},
    }
    report["idor_selection"] = access["adaptive_selection_quality"]
    report["model_note"] = ("unverified engine uses a stand-in with zero model calls; "
                            "artex-binary uses a local scripted model. Actual Abliteration AI is not measured")
    report["non_additive_count_note"] = "Authentication and IDOR share the same 14 access cases; do not sum category GET or Worker counts"
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("cors", "cookie", "access", "status"):
        parser.add_argument(f"--{name}-file", type=Path)
    args = parser.parse_args()
    inputs = {name: (json.loads(getattr(args, f"{name}_file").read_text())
                     if getattr(args, f"{name}_file") else _run(module))
              for name, module in (("cors", "scripts.bench_cors_policy_precision"),
                                   ("cookie", "scripts.bench_cookie_purpose"),
                                   ("access", "scripts.bench_access_control"),
                                   ("status", "scripts.bench_status_exposure_after"))}
    print(json.dumps(build_report(inputs["cors"], inputs["cookie"],
                                  inputs["access"], inputs["status"]),
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
