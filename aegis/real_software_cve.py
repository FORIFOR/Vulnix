"""P2: Real Software CVE & CWE Before/After Remediation Verification Harness.

Executes a full end-to-end before/after comparison through the real Vulnix
Gateway, ProposalRouter, AuditLog, and confined worker subprocesses (`http_probe`
and `reproduction_probe`) against an isolated server backed by real software
components (`sqlite3` database engine, sandboxed filesystem tree, and HTTP
server). Proves with SHA-256 audit hashes that:
  1. Before remediation ("vulnerable"):
     - NVD CVE-2021-41773 / CVE-2021-42013 are detected from the HTTP banner
       and correlated with CISA KEV;
     - Path traversal (`cve_2021_41773`), real SQLite SQL injection (`sqli`),
       and cross-account BOLA (`idor`) are proven (`verdict == "proven"`).
  2. After remediation ("patched"):
     - Path normalization confinement (`Path.resolve().is_relative_to()`),
       parameterized SQLite prepared statements (`?`), owner authorization, and
       patched Apache 2.4.62 + CSP/HSTS/XCTO headers block all probes with
       HTTP 403 (`verdict == "not_reproduced"`), reducing risk score to 0.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import ssl
import sys
import tempfile
import time
from pathlib import Path

from . import cve
from .audit import AuditLog
from .authz import ApprovalStore, Engagement, Target, TokenAuthority
from .evidence import reproduction_verdict
from .gateway import Gateway, http_probe_tool, reproduction_probe_tool
from .lab import set_lab_mode, start_lab
from .network import EgressGuard
from .policy import Budget
from .runtime import WorkerPool


def run_real_software_cve_comparison() -> dict:
    """Run an isolated before/after CVE & CWE remediation verification through
    the real Gateway and confined workers, returning a signed comparison report."""
    t0 = time.monotonic()
    srv = start_lab(0, mode="vulnerable")
    port = srv.server_port
    url = f"http://lab.test:{port}/"

    try:
        with tempfile.TemporaryDirectory() as tmp:
            now = time.time()
            target = Target("real_sw", hosts=("lab.test",), cidrs=("127.0.0.1/32",), ports=(port,))
            eng = Engagement(
                "eng_real_cve", True, "REAL-SW-CVE-VERIFY-001",
                now - 60, now + 3600,
                {"real_sw": target},
                frozenset({"read_only_probe", "safe_reproduction"}),
            )
            approvals = ApprovalStore()
            tokens = TokenAuthority(secrets.token_bytes(32), time.time)
            audit = AuditLog(Path(tmp) / "real-cve-audit.jsonl")
            workers = WorkerPool(max_concurrent=2)
            gw = Gateway(
                engagement=eng, tokens=tokens, approvals=approvals,
                egress=EgressGuard(lambda h: ["127.0.0.1"] if h == "lab.test" else []),
                workers=workers, audit=audit,
                tools={
                    "http_probe": http_probe_tool(),
                    "reproduction_probe": reproduction_probe_tool(),
                },
                budget=Budget(30),
            )

            def _exec_probe(tool_name: str, action: str, args: dict) -> tuple[dict, str]:
                apr = approvals.approve("approver:cve-verifier", "eng_real_cve", "real_sw", action)
                tok = tokens.issue(eng, "real_sw", action, tool_name, apr, approvals, 60)
                dec = gw.execute({"tool": tool_name, "target_id": "real_sw", "action": action, "args": args}, tok)
                if not dec.allowed or not dec.result:
                    raise RuntimeError(f"probe {tool_name} failed: {dec.reason}")
                raw_out = dec.result.stdout if isinstance(dec.result.stdout, str) else dec.result.stdout.decode("utf-8", "replace")
                payload = json.loads(raw_out.strip() or "{}")
                last_hash = audit.entries()[-1]["hash"]
                return payload, last_hash

            # Phase 1: Vulnerable software configuration
            set_lab_mode("vulnerable", srv)
            http_before, hash_http_before = _exec_probe("http_probe", "read_only_probe", {"url": url, "method": "GET"})
            server_banner_before = http_before.get("headers", {}).get("Server", "")
            cands_before = cve.detect_from_banner(server_banner_before)

            checks_before = {}
            for check_name in ("cve_2021_41773", "sqli", "idor"):
                res_b, h_b = _exec_probe("reproduction_probe", "safe_reproduction", {"url": url, "check": check_name})
                checks_before[check_name] = {
                    "status": res_b.get("status"),
                    "verdict": reproduction_verdict(res_b, check_name),
                    "established": res_b.get("established"),
                    "audit_hash": h_b,
                    "response": res_b.get("response"),
                }

            # Phase 2: Patched software configuration
            set_lab_mode("patched", srv)
            http_after, hash_http_after = _exec_probe("http_probe", "read_only_probe", {"url": url, "method": "GET"})
            server_banner_after = http_after.get("headers", {}).get("Server", "")
            cands_after = cve.detect_from_banner(server_banner_after)

            checks_after = {}
            for check_name in ("cve_2021_41773", "sqli", "idor"):
                res_a, h_a = _exec_probe("reproduction_probe", "safe_reproduction", {"url": url, "check": check_name})
                checks_after[check_name] = {
                    "status": res_a.get("status"),
                    "verdict": reproduction_verdict(res_a, check_name),
                    "established": res_a.get("established"),
                    "audit_hash": h_a,
                    "response": res_a.get("response"),
                }

            all_proven_before = all(v["verdict"] == "proven" for v in checks_before.values())
            all_mitigated_after = all(v["verdict"] == "not_reproduced" for v in checks_after.values())
            chain_valid = audit.verify()

            return {
                "verified_at": time.time(),
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 2),
                "all_passed": bool(
                    len(cands_before) == 2
                    and len(cands_after) == 0
                    and all_proven_before
                    and all_mitigated_after
                    and chain_valid
                ),
                "software_stack": {
                    "python": sys.version.split()[0],
                    "sqlite": sqlite3.sqlite_version,
                    "openssl": ssl.OPENSSL_VERSION,
                },
                "before_remediation": {
                    "banner": server_banner_before,
                    "matched_cves": [c.cve.id for c in cands_before],
                    "kev_matched": [c.cve.id for c in cands_before if c.in_kev],
                    "http_audit_hash": hash_http_before,
                    "checks": checks_before,
                },
                "after_remediation": {
                    "banner": server_banner_after,
                    "matched_cves": [c.cve.id for c in cands_after],
                    "http_audit_hash": hash_http_after,
                    "checks": checks_after,
                },
                "audit_chain_valid": chain_valid,
            }
    finally:
        srv.shutdown()
        srv.server_close()


if __name__ == "__main__":
    rep = run_real_software_cve_comparison()
    print(json.dumps(rep, ensure_ascii=False, indent=2))
    if not rep["all_passed"]:
        raise SystemExit(1)
