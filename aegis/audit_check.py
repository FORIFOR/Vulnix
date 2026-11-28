"""Verify every audit log of a data directory: its hash chain and, when the local audit
anchor is configured (VULNIX_AUDIT_ANCHOR_*), that it still holds the anchored head.

    python3 -m aegis.audit_check --data-dir /var/lib/vulnix

Prints one JSON report. Exit 0: every chain verifies and (with an anchor) matches it;
1: a chain does not verify; 3: a log was rolled back / forked against the anchor, or the
anchor could not confirm it. Used by deploy/debian13/restore.sh after a restore: a
restore of an older backup is exactly such a rollback, and the operator has to accept it
explicitly (the service refuses diagnoses, approvals and paid sends until then).
Read only: it never anchors or changes anything.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import AuditLog
from .audit_anchor import client_from_env


def audit_logs(data_dir: Path) -> list[Path]:
    """The installation's audit logs: the default and platform logs and each organization's."""
    found = [data_dir / n for n in ("audit.jsonl", "platform-audit.jsonl") if (data_dir / n).is_file()]
    orgs = data_dir / "orgs"
    if orgs.is_dir():
        found += sorted(p for p in orgs.glob("*/audit.jsonl") if p.is_file())
    return found


def check(data_dir: Path, anchor=None) -> dict:
    anchor = client_from_env() if anchor is None else anchor
    logs = []
    for path in audit_logs(data_dir):
        log = AuditLog(path, anchor=anchor, anchor_root=data_dir)
        entry = {"log": str(path.relative_to(data_dir)), "chain_ok": log.verify()}
        if anchor is not None:
            st = log.anchor_check()
            entry.update(source=log.anchor_source, anchor_ok=st["error"] in (None, "same_user"),
                         anchor_error=st["error"], anchored_seq=st["last_seq"])
        logs.append(entry)
    chains = all(e["chain_ok"] for e in logs)
    anchored = anchor is None or all(e.get("anchor_ok") for e in logs)
    return {"data_dir": str(data_dir), "anchor_enabled": anchor is not None, "logs": logs,
            "chains_ok": chains, "anchor_ok": anchored,
            "mismatched_sources": [e["source"] for e in logs if anchor is not None and not e.get("anchor_ok")]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m aegis.audit_check")
    ap.add_argument("--data-dir", required=True)
    a = ap.parse_args(argv)
    report = check(Path(a.data_dir))
    print(json.dumps(report, indent=1))
    if not report["chains_ok"]:
        return 1
    return 0 if report["anchor_ok"] else 3


if __name__ == "__main__":
    sys.exit(main())
