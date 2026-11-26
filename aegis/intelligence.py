"""Read-only assessment history derived from successfully saved diagnosis runs."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from .authority_ledger import sync_dir

LIMIT = 120
MAX_BYTES = 1_000_000
SEVERITIES = ("critical", "high", "medium", "low", "info")
STATES = ("candidate", "detected", "proven", "not_reproduced", "incomplete")
AUDIT_EVENT = "intelligence.summary_recorded"
COMMIT_EVENT = "intelligence.summary_persisted"


def fingerprint(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def load(path: Path) -> list[dict]:
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return []
    if len(raw) > MAX_BYTES:
        raise ValueError("archive exceeds size limit")
    rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) > LIMIT:
        raise ValueError("invalid run archive")
    return rows


def append(path: Path, summary: dict, audit) -> None:
    rows = load(path)
    event = audit.record(AUDIT_EVENT, run_id=summary["run_id"], asset_id=summary["asset_id"],
                         org_id=summary["org_id"], summary_sha256=fingerprint(summary))
    payload = json.dumps([{"summary": summary, "audit_hash": event["hash"]}, *rows[:LIMIT - 1]], ensure_ascii=False).encode()
    if len(payload) > MAX_BYTES:
        raise ValueError("archive exceeds size limit")
    temp = None
    try:
        with NamedTemporaryFile(dir=path.parent, prefix=".intelligence-", delete=False) as stream:
            temp = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        sync_dir(path.parent)
        audit.record(COMMIT_EVENT, run_id=summary["run_id"], record_hash=event["hash"])
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def verify_rows(rows, entries, organization, asset_ids) -> tuple[list[dict], bool]:
    hashes = {entry["hash"]: entry for entry in entries}
    commits = {(entry["fields"].get("record_hash"), entry["fields"].get("run_id"))
               for entry in entries if entry["event"] == COMMIT_EVENT}
    verified = []
    damaged = False
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("summary"), dict):
            damaged = True
            continue
        summary = row["summary"]
        reference = row.get("audit_hash")
        entry = hashes.get(reference) if isinstance(reference, str) else None
        if (entry is None or entry["event"] != AUDIT_EVENT
                or entry["fields"].get("summary_sha256") != fingerprint(summary)
                or entry["fields"].get("run_id") != summary.get("run_id")
                or entry["fields"].get("asset_id") != summary.get("asset_id")
                or entry["fields"].get("org_id") != summary.get("org_id")
                or (reference, summary.get("run_id")) not in commits):
            damaged = True
            continue
        if summary["org_id"] != organization or summary["asset_id"] not in asset_ids:
            continue
        outcome = dict(summary)
        evidence = outcome.pop("evidence_hashes")
        if not all(ref in hashes for ref in evidence):
            # Even an authenticated summary must not establish a result for missing evidence.
            damaged = True
            continue
        verified.append({**outcome, "audit_hash": reference})
    return verified, damaged
