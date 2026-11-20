"""Delivery leases shared, revocations exclusive.

A protected response or event is written to the client while the account and
membership grants that allowed it are held, so a logout, role change or member
removal never completes while something it revokes is still being delivered.

Holding one platform-wide mutex for that meant one slow reader delayed every
login, revocation and emergency stop in every organization. With this lease,
deliveries share it (they never wait for each other), and only a revocation is
exclusive: it waits for the deliveries already in flight (each write is capped
by its socket timeout) and, while it waits, no new delivery starts, so it is
never starved.
"""
from __future__ import annotations

import contextlib
import threading


class GrantLease:
    def __init__(self):
        self._cond = threading.Condition()
        self._readers = 0
        self._writer = False
        self._waiting_writers = 0
        self._held = threading.local()

    def _depth(self) -> int:
        return getattr(self._held, "n", 0)

    @contextlib.contextmanager
    def shared(self):
        if self._depth():                       # nested in the same thread: already inside
            self._held.n += 1
            try:
                yield
            finally:
                self._held.n -= 1
            return
        with self._cond:
            while self._writer or self._waiting_writers:
                self._cond.wait()
            self._readers += 1
        self._held.n = 1
        try:
            yield
        finally:
            self._held.n = 0
            with self._cond:
                self._readers -= 1
                if not self._readers:
                    self._cond.notify_all()

    @contextlib.contextmanager
    def exclusive(self):
        if self._depth():
            # it would wait for itself forever
            raise RuntimeError("a revocation cannot run inside a delivery lease")
        with self._cond:
            self._waiting_writers += 1
            try:
                while self._writer or self._readers:
                    self._cond.wait()
            finally:
                self._waiting_writers -= 1
            self._writer = True
        try:
            yield
        finally:
            with self._cond:
                self._writer = False
                self._cond.notify_all()


__all__ = ["GrantLease"]
