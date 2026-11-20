"""Blind Link-layout holdout against the historical and current lab observation."""
from __future__ import annotations

import argparse
import json
import os
import re
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"

from aegis import assessment as assessment_module  # noqa: E402
from scripts import bench_access_control as baseline  # noqa: E402
from scripts.bench_access_holdout import _score  # noqa: E402
from tests.fixtures.access_link_holdout_lab import AccessLinkHoldoutLab, MODES  # noqa: E402


FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures"
TRUTH = json.loads((FIXTURES / "access_link_holdout_truth.json").read_text())
OWNER_SPECS = json.loads((FIXTURES / "access_link_holdout_owner_specs.json").read_text())


def measure(mode: str, parser: str) -> dict:
    if mode not in TRUTH or parser not in ("legacy_exact", "link_fields"):
        raise ValueError("unknown condition or parser")
    def old(value):
        return bool(re.fullmatch(r'</api/accounts/B/secret>; rel="account-resource"',
                                 str(value or "")))
    parser_patch = (patch.object(assessment_module, "_has_lab_account_resource_link", side_effect=old)
                    if parser == "legacy_exact" else nullcontext())
    with patch.object(baseline, "AccessControlLab", AccessLinkHoldoutLab), \
            patch.object(baseline, "TRUTH", TRUTH), \
            patch.object(baseline, "OWNER_SPECS", OWNER_SPECS), parser_patch:
        row = baseline._measure(mode, "adaptive_one_pass")
    row["parser"] = parser
    return row


def summarize(rows: list[dict], modes: list[str]) -> dict:
    expected = {(mode, parser) for mode in modes for parser in ("legacy_exact", "link_fields")}
    if (len(rows) != len(expected) or
            {(r["mode"], r["parser"]) for r in rows} != expected):
        raise ValueError("incomplete or duplicate Link holdout rows")
    out = {}
    for parser in ("legacy_exact", "link_fields"):
        group = [r for r in rows if r["parser"] == parser]
        if any(r["truth"] != TRUTH[r["mode"]] or r["root_exposure_detected"] for r in group):
            raise AssertionError("truth or protected-root label changed")
        selection = _score(group, "idor_check_appropriate", "plan_adopted")
        detection = _score(group, "cross_account_access", "idor_proven")
        out[parser] = {"selection": selection, "idor_detection": detection,
                       "target_get": sum(len(r["target_requests"]) for r in group),
                       "worker_launches": sum(r["worker_launches"] for r in group),
                       "planner_calls": sum(r["planner_calls"] for r in group),
                       "local_model_calls": sum(r["local_model_calls"] for r in group),
                       "budget_est_tokens": sum(r.get("ai_est_tokens") or 0 for r in group),
                       "paid_model_cost_usd": 0,
                       "elapsed_s_sum": round(sum(r["elapsed_s"] for r in group), 3)}
    now = out["link_fields"]
    if (now["selection"]["fn"] or now["selection"]["fp"]
            or now["idor_detection"]["fn"] or now["idor_detection"]["fp"]):
        raise AssertionError("new Link syntax missed an approved check or created a false finding")
    return {"scope": "independent local Link header variants; not unknown-site AI proof",
            "model": "real ARTEX when configured, local scripted model, no paid API",
            "strategies": out, "rows": rows}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    assert set(TRUTH) == set(OWNER_SPECS) == MODES
    modes = (["spaced_parameters_allowed", "repeated_headers_allowed", "quoted_comma_decoy"]
             if args.smoke else list(TRUTH))
    rows = [measure(mode, version) for mode in modes
            for version in ("legacy_exact", "link_fields")]
    print(json.dumps(summarize(rows, modes), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
