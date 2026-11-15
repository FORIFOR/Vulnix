"""Compare old and current audit-log read paths on the same local fixture.

Run: VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_audit_logs
This only creates a temporary local log and uses no external services.
"""
from __future__ import annotations

import statistics
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from aegis.audit import AuditLog


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        audit = AuditLog(Path(tmp) / "audit.jsonl")
        for n in range(300):
            audit.record("fixture", n=n)

        def before() -> dict:
            return {"entries": audit.entries(), "chain_valid": audit.verify()}

        def after() -> dict:
            entries, valid = audit.verified_entries()
            return {"entries": entries, "chain_valid": valid}

        for label, operation in (("before", before), ("after", after)):
            samples = []
            with patch.object(audit, "entries", wraps=audit.entries) as reads:
                for _ in range(100):
                    start = time.perf_counter_ns()
                    result = operation()
                    samples.append(time.perf_counter_ns() - start)
                assert result["chain_valid"] and len(result["entries"]) == 300
                print(f"{label}: median_ms={statistics.median(samples) / 1_000_000:.3f} "
                      f"reads_per_call={reads.call_count / 100:.1f}")


if __name__ == "__main__":
    main()
