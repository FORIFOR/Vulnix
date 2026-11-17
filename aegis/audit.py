"""Append-only, hash-chained audit log (JSONL). Tampering breaks verify()."""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._prev = GENESIS
        self.listeners: list = []   # called after each durable write (e.g. SSE bus)
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    self._prev = json.loads(line)["hash"]

    def record(self, event: str, **fields) -> dict:
        with self._lock:
            entry = self._append_locked(event, fields)
        for listener in list(self.listeners):
            listener(entry)
        return entry

    def _append_locked(self, event: str, fields: dict) -> dict:
        if event in ("allow", "planner_llm.forwarding"):
            # These records authorize a Worker or paid model send. A durable
            # append alone is insufficient if an older entry was altered.
            entries, valid = self.verified_entries()
            tail = entries[-1]["hash"] if entries else GENESIS
            if not valid:
                raise ValueError("audit chain invalid")
            # A second service object in the same process can have appended a
            # valid record since this object last wrote. Continue that verified
            # chain, never the older in-memory tail.
            self._prev = tail
        body = {"ts": time.time(), "event": event, "fields": fields, "prev": self._prev}
        digest = hashlib.sha256(_canon(body).encode()).hexdigest()
        entry = {**body, "hash": digest}
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._prev = digest
        return entry

    def record_with_budget(self, event: str, *, reserve_micro_usd: int,
                           cap_micro_usd: int, **fields) -> dict:
        """Durably reserve a real advisor call before forwarding it.

        The control plane holds one process claim per data directory. This lock
        serializes every audit write and every reservation inside that process.
        Missing usage on an earlier external send fails closed; it cannot be priced
        after the fact. Failed model responses keep their reservation.
        """
        if event != "advisor.safe_send_requested" or fields.get("endpoint_kind") != "external":
            raise ValueError("advisor budget applies only to external sends")
        if (not isinstance(reserve_micro_usd, int) or isinstance(reserve_micro_usd, bool)
                or not isinstance(cap_micro_usd, int) or isinstance(cap_micro_usd, bool)
                or reserve_micro_usd <= 0 or cap_micro_usd <= 0):
            raise ValueError("invalid advisor budget")
        with self._lock:
            entries, valid = self.verified_entries()
            if not valid:
                raise ValueError("audit chain invalid")
            spent = 0
            for previous in entries:
                if (previous.get("event") != "advisor.safe_send_requested"
                        or previous.get("fields", {}).get("endpoint_kind") != "external"):
                    continue
                amount = previous["fields"].get("reserved_micro_usd")
                if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
                    raise ValueError("unpriced external advisor send")
                spent += amount
            if spent + reserve_micro_usd > cap_micro_usd:
                raise ValueError("advisor budget exceeded")
            entry = self._append_locked(event, {**fields, "reserved_micro_usd": reserve_micro_usd,
                                                "budget_cap_micro_usd": cap_micro_usd})
        for listener in list(self.listeners):
            listener(entry)
        return entry

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text().splitlines() if l.strip()]

    def verified_entries(self) -> tuple[list[dict], bool]:
        """Read once so returned entries and their chain verdict match."""
        entries = self.entries()
        prev = GENESIS
        for e in entries:
            body = {k: e[k] for k in ("ts", "event", "fields", "prev")}
            if e["prev"] != prev or hashlib.sha256(_canon(body).encode()).hexdigest() != e["hash"]:
                return entries, False
            prev = e["hash"]
        return entries, True

    def verify(self) -> bool:
        return self.verified_entries()[1]


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
