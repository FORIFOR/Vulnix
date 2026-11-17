"""Score new, independently labelled access conditions through existing paths.

No external target or paid model is contacted. The model gets only observed
structure; labels and owner contracts remain in local test fixtures.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from unittest.mock import patch

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"

from scripts import bench_access_control as baseline  # noqa: E402
from scripts.bench_access_holdout import summarize  # noqa: E402
from tests.fixtures.access_fresh_holdout_lab import AccessFreshHoldoutLab  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
TRUTH = json.loads((ROOT / "tests/fixtures/access_fresh_truth.json").read_text())
OWNER_SPECS = json.loads((ROOT / "tests/fixtures/access_fresh_owner_specs.json").read_text())


def run(*, smoke: bool = False) -> dict:
    if set(TRUTH) != set(OWNER_SPECS):
        raise ValueError("independent truth and owner contracts differ")
    cases = [mode for mode in TRUTH if not smoke or mode in
             ("protected_root_denial_200", "account_link_allowed_200")]
    with patch.object(baseline, "AccessControlLab", AccessFreshHoldoutLab), \
            patch.object(baseline, "TRUTH", TRUTH), \
            patch.object(baseline, "OWNER_SPECS", OWNER_SPECS):
        rows = [baseline._measure(mode, strategy) for mode in cases
                for strategy in ("fixed_l1", "always", "adaptive")]
    report = summarize(rows)
    for row in rows:
        truth = TRUTH[row["mode"]]
        if row["truth"] != truth or row["root_exposure_detected"] != truth["unauth_exposure"]:
            raise AssertionError("root verdict disagrees with independent truth")
        expected_idor = truth["cross_account_access"] and row["strategy"] != "fixed_l1"
        if row["idor_proven"] != expected_idor:
            raise AssertionError("cross-account verdict disagrees with independent truth")
    observed = report["strategies"]["adaptive"]
    if observed["selection"]["fn"] or observed["selection"]["fp"]:
        raise AssertionError("observed selection disagrees with independent truth")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(smoke=args.smoke), ensure_ascii=False, indent=2))
