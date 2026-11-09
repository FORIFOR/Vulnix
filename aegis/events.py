"""Assessment event bus for SSE.

Every event carries a monotonically increasing `seq` assigned by the server, so
clients can de-duplicate and re-order (event_id = f"evt_{seq}") and resume with
Last-Event-ID after a reconnect.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone


class EventBus:
    def __init__(self, history: int = 5000):
        self._cond = threading.Condition()
        self._events: list[dict] = []
        self._seq = 0
        self._history = history

    def publish(self, assessment_id: str, type: str, **fields) -> dict:
        with self._cond:
            self._seq += 1
            ev = {"event_id": f"evt_{self._seq}", "seq": self._seq,
                  "assessment_id": assessment_id, "type": type,
                  "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                  **fields}
            self._events.append(ev)
            del self._events[:-self._history]
            self._cond.notify_all()
            return ev

    def since(self, seq: int) -> list[dict]:
        with self._cond:
            return [e for e in self._events if e["seq"] > seq]

    def wait(self, seq: int, timeout: float) -> list[dict]:
        with self._cond:
            self._cond.wait_for(lambda: self._seq > seq, timeout=timeout)
            return [e for e in self._events if e["seq"] > seq]

    @property
    def last_seq(self) -> int:
        return self._seq
