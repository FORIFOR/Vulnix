"""Combine independent holdout reports without hiding class imbalance.

Runs only local `.test` targets. Raw truth tables never enter ARTEX or the
scripted model. Auth and IDOR share one seven-condition target set, so their
GET and Worker counts are included once in the totals.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STRATEGIES = {"fixed": ("fixed", "fixed", "fixed_l1"),
              "always": ("always", "always", "always"),
              "observed": ("observed", "observed", "adaptive")}


def _require_complete_rows(rows: list[dict], case_ids: set[str],
                           strategies: tuple[str, ...], id_key: str) -> None:
    expected = {(case_id, strategy) for case_id in case_ids for strategy in strategies}
    observed = [(row.get(id_key), row.get("strategy")) for row in rows]
    if len(observed) != len(expected) or set(observed) != expected:
        raise ValueError(f"incomplete or duplicate holdout rows: {id_key}")


def _read_or_run(path: Path | None, module: str) -> dict:
    if path is not None:
        return json.loads(path.read_text())
    completed = subprocess.run([sys.executable, "-m", module], cwd=ROOT,
                               env={**os.environ, "VULNIX_NO_ENV_LOCAL": "1"},
                               capture_output=True, text=True, check=True, timeout=900)
    return json.loads(completed.stdout)


def _merge_counts(*scores: dict) -> dict:
    tp = sum(s["tp"] for s in scores)
    fp = sum(s["fp"] for s in scores)
    fn = sum(s["fn"] for s in scores)
    tn = sum(s["tn"] for s in scores)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None}


def summarize(mixed: dict, status: dict, access: dict) -> dict:
    _require_complete_rows(
        mixed["rows"], set(json.loads((ROOT / "tests/fixtures/initial_mixed_holdout_truth.json").read_text())),
        ("fixed", "always", "observed"), "case_id")
    _require_complete_rows(
        status["rows"], set(json.loads((ROOT / "tests/fixtures/status_selection_holdout_truth.json").read_text())),
        ("fixed", "always", "observed"), "case_id")
    _require_complete_rows(
        access["rows"], set(json.loads((ROOT / "tests/fixtures/access_holdout_truth.json").read_text())),
        ("fixed_l1", "always", "adaptive"), "mode")
    strategies = {}
    for name, (mkey, skey, akey) in STRATEGIES.items():
        m, s, a = (mixed["strategies"][mkey], status["strategies"][skey],
                   access["strategies"][akey])
        classes = {
            "cors_policy": m["classes"]["cors"]["detection"],
            "cookie_session_attributes": m["classes"]["cookie"]["detection"],
            "apache_status_exposure": s["detection"],
            "unauthenticated_protected_json": a["classes"]["unauthenticated_protected_json"],
            "cross_account_idor": a["classes"]["cross_account_idor"],
        }
        classes = {key: {**score,
                         "false_positive_rate": (score["fp"] / (score["fp"] + score["tn"])
                                                 if score["fp"] + score["tn"] else None)}
                   for key, score in classes.items()}
        macro = {key: {
            "value": (sum(c[key] for c in classes.values() if c[key] is not None) /
                      sum(c[key] is not None for c in classes.values())
                      if any(c[key] is not None for c in classes.values()) else None),
            "classes": sum(c[key] is not None for c in classes.values()),
        } for key in ("precision", "recall", "false_positive_rate")}
        status_selection = _merge_counts(m["selection"], s["selection"])
        idor_selection = a["selection"]
        strategies[name] = {
            "classes": classes, "macro": macro,
            "selection_by_check": {"apache_status": status_selection, "idor": idor_selection},
            "selection_micro": _merge_counts(status_selection, idor_selection),
            "unnecessary_proposals": (m["unnecessary_extra_proposals"] +
                                       s["unnecessary_extra_proposals"] + a["unnecessary_proposals"]),
            "eligible_check_omissions": (m["needed_check_omissions"] +
                                         s["eligible_check_omissions"] + a["appropriate_check_omissions"]),
            "target_get": m["target_get"] + s["target_get"] + a["target_get"],
            "worker_launches": m["worker_launches"] + s["worker_launches"] + a["worker_launches"],
            "planner_calls": m["planner_calls"] + s["planner_calls"] + a["planner_calls"],
            "local_model_calls": m["local_model_calls"] + s["local_model_calls"] + a["model_calls"],
            "elapsed_s_sum": round(m["elapsed_s_sum"] + s["elapsed_s_sum"] + a["elapsed_s_sum"], 3),
            "budget_est_tokens_sum": (m["budget_est_tokens_sum"] + s["budget_est_tokens_sum"] +
                                      a["budget_est_tokens_sum"]),
            "hypothetical_model_cost_usd_sum": round(
                m["hypothetical_model_cost_usd_sum"] + s["hypothetical_model_cost_usd_sum"] +
                a["hypothetical_model_cost_usd_sum"], 6),
            "paid_model_cost_usd_sum": 0,
        }
    return {"scope": "five classes; 17 independent local HTTPS/loopback conditions in three target sets",
            "model": "ARTEX-compatible stand-in with fixed intents; not Abliteration AI",
            "method_note": ("CORS and Cookie are new combinations of known responses; Apache status has a "
                            "positive and negatives; auth/IDOR use separately withheld response variants. "
                            "Macro excludes undefined precision and reports its denominator. "
                            "Auth and IDOR share target requests, counted once. Consent-forbidden status "
                            "exposure is excluded from detection quality but scored for selection safety."),
            "strategies": strategies}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mixed-file", type=Path)
    parser.add_argument("--status-file", type=Path)
    parser.add_argument("--access-file", type=Path)
    args = parser.parse_args()
    reports = (_read_or_run(args.mixed_file, "scripts.bench_initial_mixed_holdout"),
               _read_or_run(args.status_file, "scripts.bench_status_selection_holdout"),
               _read_or_run(args.access_file, "scripts.bench_access_holdout"))
    report = summarize(*reports)
    observed = report["strategies"]["observed"]
    always = report["strategies"]["always"]
    assert observed["selection_micro"]["fn"] == 0
    assert observed["selection_micro"]["fp"] <= 1
    assert all(score["fn"] == 0 and score["fp"] == 0
               for score in observed["classes"].values())
    assert observed["target_get"] <= always["target_get"]
    assert observed["worker_launches"] <= always["worker_launches"]
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
