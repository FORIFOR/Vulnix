"""Append-only, hash-chained audit log (JSONL). Tampering breaks verify()."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows has no flock; refusing writes is safer than racing budgets.
    fcntl = None

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str | Path):
        if fcntl is None:
            raise RuntimeError("audit file locking requires POSIX flock")
        self.path = Path(path)
        self._lock = threading.Lock()
        self._prev = GENESIS
        self._known_size = self.path.stat().st_size if self.path.exists() else 0
        self.listeners: list = []   # called after each durable write (e.g. SSE bus)
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    self._prev = json.loads(line)["hash"]

    def record(self, event: str, **fields) -> dict:
        with self._lock, self._exclusive_file():
            entry = self._append_locked(event, fields)
        for listener in list(self.listeners):
            listener(entry)
        return entry

    @contextmanager
    def _exclusive_file(self):
        # A data directory can have more than one service object in one process.
        # Serialize the complete verify/reserve/append transaction across them.
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _append_locked(self, event: str, fields: dict) -> dict:
        current_size = self.path.stat().st_size if self.path.exists() else 0
        if (event in ("allow", "planner_llm.forwarding")
                or current_size != self._known_size):
            # These records authorize a Worker or paid model send. A durable
            # append alone is insufficient if an older entry was altered.
            entries, valid = self.verified_entries()
            tail = entries[-1]["hash"] if entries else GENESIS
            if not valid or not self._is_continuation(entries):
                raise ValueError("audit chain invalid")
            # Another service object may have appended since our last write.
            # Reanchor even ordinary records so they cannot corrupt that chain.
            self._prev = tail
        body = {"ts": time.time(), "event": event, "fields": fields, "prev": self._prev}
        digest = hashlib.sha256(_canon(body).encode()).hexdigest()
        entry = {**body, "hash": digest}
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
            self._known_size = f.tell()
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
        with self._lock, self._exclusive_file():
            entries, valid = self.verified_entries()
            if not valid or not self._is_continuation(entries):
                raise ValueError("audit chain invalid")
            self._prev = entries[-1]["hash"] if entries else GENESIS
            spent = 0
            for previous in entries:
                if (previous.get("event") != "advisor.safe_send_requested"
                        or previous.get("fields", {}).get("endpoint_kind") != "external"):
                    continue
                amount = previous["fields"].get("reserved_micro_usd")
                if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
                    raise ValueError("unpriced external advisor send")
                spent += amount
            floor_path = self.path.with_name(self.path.name + ".advisor-budget")
            try:
                if floor_path.is_symlink():
                    raise ValueError("audit budget history invalid")
                floor = floor_path.read_text(encoding="ascii").strip() if floor_path.exists() else None
            except (OSError, UnicodeError) as exc:
                raise ValueError("audit budget history invalid") from exc
            if (floor is None and spent != 0) or (floor is not None and floor != str(spent)):
                # A valid older JSONL prefix can pass the hash-chain check after
                # restart. Keep its paid-send total in a separate durable floor.
                raise ValueError("audit budget history invalid")
            if spent + reserve_micro_usd > cap_micro_usd:
                raise ValueError("advisor budget exceeded")
            # Persist the new floor before the audit append. A crash between
            # these writes leaves paid calls disabled, never undercounted.
            fd, temp_name = tempfile.mkstemp(prefix=".advisor-budget-", dir=self.path.parent)
            try:
                with os.fdopen(fd, "w", encoding="ascii") as stream:
                    stream.write(f"{spent + reserve_micro_usd}\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp_name, floor_path)
                dir_fd = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)
            entry = self._append_locked(event, {**fields, "reserved_micro_usd": reserve_micro_usd,
                                                "budget_cap_micro_usd": cap_micro_usd})
        for listener in list(self.listeners):
            listener(entry)
        return entry

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text().splitlines() if l.strip()]

    def _is_continuation(self, entries: list[dict]) -> bool:
        """A valid prefix cannot silently erase this instance's durable tail."""
        return self._prev == GENESIS or any(e["hash"] == self._prev for e in entries)

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
