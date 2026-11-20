"""Same loopback Cookie responses, old and current L1 analyzer, independent labels."""
from __future__ import annotations

import argparse
import json
import subprocess
import threading
import time
import types
from pathlib import Path
from urllib.request import urlopen

from aegis.service_diag import analyze_l1_service_response
from tests.fixtures.cookie_purpose_lab import CookiePurposeLab, COOKIES


BASELINE = "83da58023c22bf8a89030ecc7fd988e89a567251"
FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures"
TRUTH = json.loads((FIXTURES / "cookie_purpose_truth.json").read_text())
OWNER = json.loads((FIXTURES / "cookie_owner_specs.json").read_text())


def _baseline_analyzer():
    source = subprocess.check_output(
        ["git", "show", f"{BASELINE}:aegis/service_diag.py"], text=True)
    module = types.ModuleType("aegis._cookie_baseline_service_diag")
    module.__package__ = "aegis"
    exec(compile(source, f"{BASELINE}:aegis/service_diag.py", "exec"), module.__dict__)
    return module.analyze_l1_service_response


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--current-only", action="store_true",
                        help="Use current analyzer without historical git checkout")
    args = parser.parse_args()
    assert set(COOKIES) == set(TRUTH) == set(OWNER)
    analyzers = {"current": analyze_l1_service_response}
    if not args.current_only:
        analyzers = {"baseline": _baseline_analyzer(), **analyzers}
    counts = {name: {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "candidate": 0,
                     "analyzer_ms": 0.0} for name in analyzers}
    cases = []
    for mode in TRUTH:
        lab = CookiePurposeLab(mode)
        thread = threading.Thread(target=lab.serve_forever, daemon=True)
        thread.start()
        try:
            with urlopen(f"http://127.0.0.1:{lab.server_port}/", timeout=3) as response:
                observed = {"status": response.status, "headers": dict(response.headers),
                            "set_cookies": response.headers.get_all("Set-Cookie"),
                            "body_prefix": response.read().decode()}
            row = {"mode": mode, "expected": TRUTH[mode]}
            for name, analyzer in analyzers.items():
                start = time.perf_counter()
                if name == "current":
                    findings = analyzer(observed, {"audit_hash": "cookie-lab-proof"},
                                        "https://owned-cookie.example.test/", cookie_policy=OWNER[mode])
                else:
                    findings = analyzer(observed, {"audit_hash": "cookie-lab-proof"},
                                        "https://owned-cookie.example.test/")
                counts[name]["analyzer_ms"] += (time.perf_counter() - start) * 1000
                finding = next((f for f in findings if f["id"] == "f_l1_cookies"), None)
                verdict = finding["verdict"] if finding else "none"
                row[name] = verdict
                detected, expected = verdict == "detected", TRUTH[mode] == "detected"
                counts[name]["candidate"] += verdict == "candidate"
                counts[name]["tp" if detected and expected else "fp" if detected else
                             "fn" if expected else "tn"] += 1
            assert lab.seen == ["/"]
            cases.append(row)
        finally:
            lab.shutdown()
            lab.server_close()
            thread.join(timeout=2)
    for result in counts.values():
        result["analyzer_ms"] = round(result["analyzer_ms"], 3)
        result["precision"] = result["tp"] / (result["tp"] + result["fp"]) if result["tp"] + result["fp"] else None
        result["recall"] = result["tp"] / (result["tp"] + result["fn"]) if result["tp"] + result["fn"] else None
    print(json.dumps({"cases": cases, "counts": counts, "target_get": len(cases),
                      "worker_launches": 0, "model_calls": 0, "paid_cost_usd": 0},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
