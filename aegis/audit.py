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
            body = {"ts": time.time(), "event": event, "fields": fields, "prev": self._prev}
            digest = hashlib.sha256(_canon(body).encode()).hexdigest()
            entry = {**body, "hash": digest}
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._prev = digest
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
