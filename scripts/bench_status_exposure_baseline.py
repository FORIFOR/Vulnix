"""Measure current owned-site L1 against a separately labelled loopback fixture.

Run: VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_status_exposure_baseline
No real site, external model, or paid API is contacted.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"
os.environ["VULNIX_EXTERNAL_PROPOSALS"] = "0"
os.environ["VULNIX_REAL_SITE_SAFE_AI"] = "0"
os.environ["VULNIX_REAL_SITE_LOCAL_ARTEX"] = "0"

from aegis.assessment import AssessmentService  # noqa: E402
from aegis import assessment as assessment_module  # noqa: E402
from tests import TEST_CONFINEMENT  # noqa: E402
from tests.fixtures.status_exposure_lab import StatusExposureLab  # noqa: E402

HOST = "owned-status.example.test"


def measure(mode: str) -> dict:
    site = StatusExposureLab(mode)
    thread = threading.Thread(target=site.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            svc = AssessmentService(Path(tmp), 18081, l2_confinement=TEST_CONFINEMENT)
            svc._custom_resolver = lambda host: ["127.0.0.1"] if host == HOST else []
            url = f"http://{HOST}:{site.server_port}"
            try:
                challenge = svc.issue_ownership_challenge(url=url)["challenge"]
                assert site.seen == [], "registration contacted the target"
                verified = svc.verify_asset_ownership(
                    url_or_host=url, method="dns_txt",
                    dns_lookup=lambda name: [f'{name} text = "{challenge["dns_txt_value"]}"'],
                )
                assert verified["verified"] and site.seen == [], "proof contacted the target"
                svc.confirm_asset_scope(url_or_host=url, confirmed_prohibited=True,
                                        activate_workspace=True, allow_loopback_test=True)
                assert site.seen == [], "scope confirmation contacted the target"
                counts = {"gateway_calls": 0, "worker_launches": 0, "state_saves": 0}
                for obj, attr, key in ((svc.gateway, "execute", "gateway_calls"),
                                       (svc.workers, "run", "worker_launches"),
                                       (svc, "_save_state_locked", "state_saves")):
                    original = getattr(obj, attr)
                    def count(*args, _original=original, _key=key, **kwargs):
                        counts[_key] += 1
                        return _original(*args, **kwargs)
                    setattr(obj, attr, count)
                start = time.monotonic()
                with patch.object(assessment_module, "run_artex_planner",
                                  side_effect=AssertionError("unexpected ARTEX baseline call")) as artex:
                    svc.start()
                    deadline = start + 20
                    while time.monotonic() < deadline:
                        snap = svc.snapshot()
                        if snap["state"] in ("completed", "failed"):
                            break
                        time.sleep(0.02)
                    else:
                        raise TimeoutError("L1 did not finish")
                    assert artex.call_count == 0
                if snap["state"] != "completed":
                    raise RuntimeError(snap.get("failure"))
                assert site.seen == ["/"], site.seen
                found = [f for f in snap["findings"] if "mod_status" in
                         (f.get("title", "") + f.get("summary", "")).lower()]
                return {"mode": mode, "truth_status_exposed": mode == "vulnerable",
                        "elapsed_s": round(time.monotonic() - start, 3),
                        **counts, "artex_calls": artex.call_count,
                        "external_model_calls": 0, "ai_tokens": 0,
                        "target_requests": list(site.seen),
                        "status_exposure_detected": any(f["evidence_status"] == "detected" for f in found),
                        "all_findings": [{"id": f["id"], "status": f["evidence_status"]}
                                         for f in snap["findings"]]}
            finally:
                svc.close()
    finally:
        site.shutdown()
        site.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    print(json.dumps([measure("vulnerable"), measure("patched"), measure("generic_200")],
                     ensure_ascii=False, indent=2))
