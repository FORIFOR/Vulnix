"""Diagnosis-model evaluation: dry-run previews and the no-model comparison.

    preview   round-1 request previews for every held-out case x every model (bytes,
              SHA-256, token caps, worst-case cost), the cost estimate and the manifest.
              Reads no API key and sends nothing (every non-loopback connection is
              refused and counted).
    compare   fixed_l1, fixed_rule and local_model (ARTEX + local scripted model) on the
              30 held-out cases, scored against the independent labels.
    freeze    check (or with --write, record) the SHA-256 of the 16 regression conditions.

Usage: VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.run_model_evaluation {preview,compare,freeze} [--out DIR]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"

from aegis.evaluation.evaluation_runner import LIMITS, Harness, run_case  # noqa: E402
from aegis.evaluation.metrics import score  # noqa: E402
from aegis.evaluation.model_adapter import MODELS  # noqa: E402
from aegis.evaluation.network_guard import no_external_connections  # noqa: E402
from aegis.evaluation.request_builder import canonical, sha256, template  # noqa: E402
from aegis.evaluation.request_preview import config_sha256, cost_estimate  # noqa: E402
from tests import TEST_CONFINEMENT  # noqa: E402
from tests.artex_mock_llm import MockLLM  # noqa: E402
from tests.diagnosis_planner import intents_from_facts  # noqa: E402
from tests.evaluation.fixtures.holdout_lab import CASES, HoldoutLab  # noqa: E402
from tests.test_artex_bridge import FAKE  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests/evaluation/fixtures"
TRUTH = json.loads((FIX / "holdout_truth.json").read_text())["cases"]
EVALUATION_ID = "vulnix-eval-001"
REGRESSION_FILES = ("tests/fixtures/access_control_lab.py", "tests/fixtures/access_control_truth.json",
                    "tests/fixtures/access_control_owner_specs.json",
                    "tests/fixtures/access_control_loop_truth.json",
                    "tests/fixtures/access_control_loop_owner_specs.json")
HOLDOUT_FILES = ("tests/evaluation/fixtures/holdout_cases.json", "tests/evaluation/fixtures/holdout_lab.py",
                 "tests/evaluation/fixtures/holdout_truth.json",
                 "tests/evaluation/fixtures/holdout_truth_independent.json")
NO_MODEL_METHODS = ("fixed_l1", "fixed_rule", "local_model")


def harness() -> Harness:
    return Harness(lab_factory=HoldoutLab, confinement=TEST_CONFINEMENT, artex_stand_in=FAKE,
                   mock_llm=lambda sel: MockLLM(intent_selector=sel), scripted_intents=intents_from_facts)


def file_hashes(paths) -> dict:
    return {p: sha256((ROOT / p).read_bytes()) for p in paths}


def do_preview(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    h = harness()
    rows = []
    with no_external_connections() as attempts:
        for case_id in sorted(CASES):
            for key in MODELS:
                r = run_case(case_id, CASES[case_id], f"model:{key}", h, evaluation_id=EVALUATION_ID)
                if r["status"] != "not_run_dry_run" and r["previews"]:
                    raise SystemExit(f"{case_id}/{key}: a dry run executed something")
                rows.append(r)
    lines, totals = [], {k: 0.0 for k in MODELS}
    for r in rows:
        for pv in r["previews"]:
            totals[pv["model"]] = round(totals[pv["model"]] + pv["max_cost_usd"], 6)
            lines.append(json.dumps({**pv, "cumulative_model_reserve_usd": totals[pv["model"]],
                                     "cumulative_total_reserve_usd": round(sum(totals.values()), 6)},
                                    ensure_ascii=False, sort_keys=True))
    no_hypothesis = sorted({r["case_id"] for r in rows if not r["previews"]})
    (out / "requests.jsonl").write_text("\n".join(lines) + "\n")
    fix_cases = sum(1 for t in TRUTH.values() if t.get("fix"))
    estimate = cost_estimate(cases=len(CASES), rounds=LIMITS.max_planner_rounds, fix_cases=fix_cases)
    estimate["owner_plan_without_fix_rechecks"] = cost_estimate(cases=len(CASES),
                                                               rounds=LIMITS.max_planner_rounds)["total_max_usd"]
    estimate["round1_previews_reserve_usd"] = {**totals, "total": round(sum(totals.values()), 6)}
    (out / "cost_estimate.json").write_text(json.dumps(estimate, indent=2, ensure_ascii=False) + "\n")
    manifest = {
        "evaluation_id": EVALUATION_ID, "created": "2026-11-21", "dry_run": True, "external_calls_enabled": False,
        "models": {k: {**m.as_dict(), "config_sha256": config_sha256(k)} for k, m in MODELS.items()},
        "baselines": list(NO_MODEL_METHODS),
        "limits": {**LIMITS.__dict__, "max_total_cost_usd": 5.00, "max_cases": 30,
                   "max_requests_per_case_per_model_per_phase": LIMITS.max_planner_rounds},
        "template_sha256": sha256(canonical(template())),
        "holdout": {"cases": len(CASES), "files": file_hashes(HOLDOUT_FILES)},
        "regression": {"conditions": 16, "files": file_hashes(REGRESSION_FILES),
                       "use": "development and regression only; never in the model selection score"},
        "previews": {"requests": len(lines), "per_model": {k: sum(1 for r in rows if r["method"] == f"model:{k}"
                                                                   and r["previews"]) for k in MODELS},
                     "cases_without_a_request": no_hypothesis,
                     "requests_jsonl_sha256": sha256((out / "requests.jsonl").read_bytes())},
        "external_connection_attempts": len(attempts), "api_keys_read": 0,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"requests": len(lines), "external_connection_attempts": len(attempts),
                      "reserve": estimate["round1_previews_reserve_usd"],
                      "worst_case_total": estimate["total_max_usd"]}, indent=2))
    return 1 if attempts else 0


def do_compare(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    h = harness()
    rows = {m: [] for m in NO_MODEL_METHODS}
    with no_external_connections() as attempts:
        for m in NO_MODEL_METHODS:
            for case_id in sorted(CASES):
                rows[m].append(run_case(case_id, CASES[case_id], m, h, truth=TRUTH[case_id]))
    summary = {m: score(rows[m], TRUTH) for m in NO_MODEL_METHODS}
    bad = [f"{m}/{r['case_id']}: {why}" for m, rs in rows.items() for r in rs for why in (
        (["audit"] if not (r["audit_chain_valid"] and r["every_judgement_cites_an_audited_result"]) else [])
        + ([f"leak {r['planner_input_leaked']}"] if r["planner_input_leaked"] else []))]
    real = bool(os.environ.get("VULNIX_ARTEX_REAL_BIN"))
    if real:
        bad += [f"local_model/{r['case_id']}: not the real ARTEX binary" for r in rows["local_model"]
                if r["planner_calls"] and r["engine_kind"] != "artex-binary"]
    result = {"about": "held-out comparison without a real model (docs/evaluation/EVALUATION_PROTOCOL.md)",
              "artex": "real overlay binary" if real else "Python stand-in",
              "model": "local scripted stand-in (tests/diagnosis_planner.py); not a real model",
              "limits": LIMITS.__dict__, "external_connection_attempts": len(attempts),
              "summary": summary, "cases": rows, "checks_failed": bad}
    name = "comparison_ci.json" if real else "comparison.json"
    (out / name).write_text(json.dumps(result, indent=2, ensure_ascii=False, default=str) + "\n")
    cols = ("outcomes", "tp", "fp", "fn", "tn", "precision", "recall",
            "unnecessary_checks", "forbidden_checks_run", "target_gets", "worker_launches", "planner_calls",
            "fix_correct", "elapsed_s")
    for m in NO_MODEL_METHODS:
        print(m, {c: summary[m][c] for c in cols})
    for b in bad:
        print("CHECK FAILED:", b, file=sys.stderr)
    for m in ("fixed_rule", "local_model"):
        if summary[m]["fp"] or summary[m]["forbidden_checks_run"]:
            print(f"CHECK FAILED: {m}: false positive or forbidden check", file=sys.stderr)
            bad.append(m)
    return 1 if bad or attempts else 0


def do_freeze(write: bool) -> int:
    path = ROOT / "docs/evaluation/regression_manifest.json"
    now = {"conditions": 16, "files": file_hashes(REGRESSION_FILES),
           "rule": "frozen 2026-11-21: these 16 conditions are for development and regression only. "
                   "A change to them needs a new manifest in its own PR."}
    if write:
        path.write_text(json.dumps(now, indent=2, ensure_ascii=False) + "\n")
        return 0
    old = json.loads(path.read_text())
    print("frozen" if old["files"] == now["files"] else "CHANGED")
    return 0 if old["files"] == now["files"] else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=("preview", "compare", "freeze"))
    ap.add_argument("--out", default=str(ROOT / "docs/evaluation"))
    ap.add_argument("--write", action="store_true")
    a = ap.parse_args(argv)
    if a.command == "preview":
        return do_preview(Path(a.out))
    if a.command == "compare":
        return do_compare(Path(a.out))
    return do_freeze(a.write)


if __name__ == "__main__":
    sys.exit(main())
