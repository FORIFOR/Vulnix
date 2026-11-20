"""Measure one CORS policy class against independent loopback targets.

Run with VULNIX_NO_ENV_LOCAL=1. No external site or model is contacted.
The fixture is loaded from this file's checkout so the same five target
responses can be used against another checkout's analyzer via PYTHONPATH.
"""
from __future__ import annotations

import json
import runpy
import threading
from pathlib import Path
from urllib.request import Request, urlopen

from aegis.service_diag import analyze_l1_service_response


CorsPolicyLab = runpy.run_path(str(Path(__file__).resolve().parents[1] /
                                "tests/fixtures/cors_policy_lab.py"))["CorsPolicyLab"]
TRUTH = {"reflected_credentials": True, "reflected_public": False,
         "public_wildcard": False, "patched": False, "generic_200": False}


def measure() -> dict:
    rows = []
    for mode, unsafe_policy in TRUTH.items():
        site = CorsPolicyLab(mode)
        thread = threading.Thread(target=site.serve_forever, daemon=True)
        thread.start()
        try:
            req = Request(f"http://127.0.0.1:{site.server_port}/",
                          headers={"Origin": "https://untrusted-origin.example"})
            with urlopen(req, timeout=3) as response:
                observed = {"status": response.status, "headers": dict(response.headers),
                            "cors_probe_origin": "https://untrusted-origin.example",
                            "set_cookies": response.headers.get_all("Set-Cookie") or []}
            findings = analyze_l1_service_response(
                observed, {"audit_hash": "lab-proof"}, "http://owned-cors.example.test/")
            detected = any(f["id"] == "f_l1_cors" and f["verdict"] == "detected"
                           for f in findings)
            assert site.seen == ["/"], site.seen
            rows.append({"mode": mode, "truth_unsafe_policy": unsafe_policy,
                         "cors_detected": detected, "target_gets": len(site.seen)})
        finally:
            site.shutdown()
            site.server_close()
            thread.join(timeout=2)
    tp = sum(r["truth_unsafe_policy"] and r["cors_detected"] for r in rows)
    fp = sum(not r["truth_unsafe_policy"] and r["cors_detected"] for r in rows)
    fn = sum(r["truth_unsafe_policy"] and not r["cors_detected"] for r in rows)
    tn = sum(not r["truth_unsafe_policy"] and not r["cors_detected"] for r in rows)
    return {"class": "credentialed_untrusted_cors_policy", "rows": rows,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None}


if __name__ == "__main__":
    print(json.dumps(measure(), ensure_ascii=False, indent=2))
