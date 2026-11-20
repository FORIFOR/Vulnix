"""A durable spend cap shared by every organization on one control plane.

Each organization already reserves its external advisor calls in its own audit log
(`AuditLog.record_with_budget`). With public sign-up every new organization starts
with a full per-organization cap, so that alone does not bound what the platform
spends. This file records the platform total; a reservation that would pass the
platform cap is refused before anything is sent.

Fails closed: an unreadable or tampered record refuses every reservation rather
than starting over from zero. The total only ever goes up (a failed model call
keeps its reservation, as in the per-organization budget).
"""
from __future__ import annotations

import fcntl
import json
import os
import threading
from pathlib import Path


class SpendRefused(ValueError):
    pass


_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def _thread_lock(path: Path) -> threading.Lock:
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(str(path.resolve()), threading.Lock())


class DurableSpendCap:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = _thread_lock(self.path)

    def _read_locked(self) -> int:
        if not self.path.exists():
            return 0
        try:
            data = json.loads(self.path.read_text())
            spent = data["spent_micro_usd"]
        except (OSError, ValueError, KeyError, TypeError):
            raise SpendRefused("platform spend record unreadable") from None
        if not isinstance(spent, int) or isinstance(spent, bool) or spent < 0:
            raise SpendRefused("platform spend record invalid")
        return spent

    def spent(self) -> int:
        with self._lock, open(self._lockfile(), "a+") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            return self._read_locked()

    def _lockfile(self) -> Path:
        return self.path.with_name(self.path.name + ".lock")

    def reserve(self, micro_usd: int, *, cap_micro_usd: int) -> int:
        for v in (micro_usd, cap_micro_usd):
            if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
                raise SpendRefused("invalid spend amount")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, open(self._lockfile(), "a+") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)          # also serializes other processes
            spent = self._read_locked()
            if spent + micro_usd > cap_micro_usd:
                raise SpendRefused("platform advisor spend cap reached")
            total = spent + micro_usd
            tmp = self.path.with_name(self.path.name + ".tmp")
            with open(tmp, "w") as f:
                json.dump({"spent_micro_usd": total}, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            return total


__all__ = ["DurableSpendCap", "SpendRefused"]
