"""Repeatable, local-only L1 baseline for the process-flow audit.

No external API or real-site traffic. Runs a vulnerable and patched lab separately.
The backend stores JSON files rather than using a SQL DB for assessment state;
`state_saves` is reported in place of a misleading database-access count.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"
os.environ["VULNIX_EXTERNAL_PROPOSALS"] = "0"
os.environ["VULNIX_REAL_SITE_SAFE_AI"] = "0"
os.environ["VULNIX_REAL_SITE_LOCAL_ARTEX"] = "0"

from aegis.assessment import AssessmentService
from aegis.lab import start_lab

CHECKS = ("f_banner", "f_idor", "f_sqli", "f_headers", "f_powered")


def measure(mode: str) -> dict:
    lab = start_lab(0, mode=mode)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            svc = AssessmentService(Path(tmp), lab.server_port, verify_seconds=0.01)
            svc._may_switch_lab = False
            counts = {"gateway_calls": 0, "worker_launches": 0, "state_saves": 0}
            for obj, attr, key in ((svc.gateway, "execute", "gateway_calls"),
                                   (svc.workers, "run", "worker_launches"),
                                   (svc, "_save_state_locked", "state_saves")):
                original = getattr(obj, attr)
                def count(*args, _original=original, _key=key, **kwargs):
                    counts[_key] += 1
                    return _original(*args, **kwargs)
                setattr(obj, attr, count)
            try:
                start = time.monotonic()
                svc.start()
                deadline = start + 15
                while time.monotonic() < deadline:
                    snap = svc.snapshot()
                    pending = next((a for a in snap["approvals"] if a["status"] == "pending"), None)
                    if pending:
                        svc.decide_approval(pending["id"], "reject", "audit")
                        break
                    if snap["state"] == "failed":
                        raise RuntimeError(snap["failure"])
                    time.sleep(0.01)
                else:
                    raise TimeoutError("no approval request")
                while time.monotonic() < deadline:
                    snap = svc.snapshot()
                    if snap["state"] in ("completed", "failed"):
                        if snap["state"] != "completed":
                            raise RuntimeError(snap["failure"])
                        break
                    time.sleep(0.01)
                else:
                    raise TimeoutError("diagnosis did not complete")
                statuses = {f["id"]: f["evidence_status"] for f in snap["findings"]}
                return {"mode": mode, "seconds": round(time.monotonic() - start, 3),
                        **counts, "external_model_calls": 0, "ai_tokens": 0,
                        "findings": {fid: statuses.get(fid, "absent") for fid in CHECKS}}
            finally:
                svc.close()
    finally:
        lab.shutdown()
        lab.server_close()


if __name__ == "__main__":
    print(json.dumps([measure("vulnerable"), measure("patched")], ensure_ascii=False, indent=2))
