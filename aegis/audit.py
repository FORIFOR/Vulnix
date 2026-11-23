"""Append-only, hash-chained audit log (JSONL). Tampering breaks verify()."""
from __future__ import annotations

import errno
import hashlib
import json
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from .audit_anchor import AnchorError, source_id_for, symlink_on_path

try:
    import fcntl
except ImportError:  # Windows has no flock; refusing writes is safer than racing budgets.
    fcntl = None

GENESIS = "0" * 64

# Records that authorize a Worker, a paid send, or a change of diagnosis / finding
# state. With an anchor (aegis/audit_anchor.py) each is written only after the log
# matched the anchored head, and is not reported as written until its own head is
# anchored. Finding verdicts and evidence are taken from "result" records (their
# audit_hash); L2 runs start from "approval.approved" / "artex.item_approved".
ANCHORED_EVENTS = frozenset({
    "allow", "planner_llm.forwarding", "advisor.safe_send_requested", "result",
    "approval.approved", "artex.item_approved",
    # credential changes (docs/PASSWORD_CHANGE_DURABILITY.md): the intent and its abort, so
    # a log truncated to before a password change is detected at startup
    "auth.password_changed", "operator.password_reset", "auth.account_recovered_offline",
    "auth.credential_change_aborted",
})
ANCHORED_PREFIXES = ("diagnosis.",)


def is_anchored_event(event: str) -> bool:
    return event in ANCHORED_EVENTS or event.startswith(ANCHORED_PREFIXES)


class AuditWriteFailed(ValueError):
    """An audit record could not be written (disk, chain or anchor check).

    Raised by a change that grants authority or starts work, BEFORE anything changed
    (audit first: no record, no change). Raised by a change that removes authority or
    stops work AFTER it was applied (`applied` is True): such a change is never held
    back by a failing audit log, but the missing record is reported to the caller.
    A ValueError, like AnchorError: callers treat it as a refusal."""

    def __init__(self, message: str, *, applied: bool = False):
        super().__init__(message)
        self.applied = applied


class AuditLog:
    def __init__(self, path: str | Path, anchor=None, anchor_root: str | Path | None = None):
        if fcntl is None:
            raise RuntimeError("audit file locking requires POSIX flock")
        self.path = Path(path)
        # Optional separately privileged anchor (AnchorClient). None: behaviour as before.
        # The source id is "<installation name>:<log path relative to the data root>", not
        # a resolved path: a symlinked or renamed log cannot pose as a new source.
        self._anchor = anchor
        self._anchor_root = Path(anchor_root) if anchor_root is not None else self.path.parent
        self.anchor_source = (source_id_for(getattr(anchor, "source_name", ""), self._anchor_root, self.path)
                              if anchor is not None else None)
        self._anchor_seen = 0             # highest head this object saw or anchored
        self._anchor_error: str | None = "not_checked" if anchor is not None else None
        self._anchor_last_seq: int | None = None
        self._anchor_checked_at: float | None = None
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
        anchored = self._anchor is not None and is_anchored_event(event)
        entries = None
        if (anchored or event in ("allow", "planner_llm.forwarding")
                or current_size != self._known_size):
            # These records authorize a Worker or paid model send. A durable
            # append alone is insufficient if an older entry was altered.
            entries, valid = self.verified_entries()
            if anchored:
                # ... nor if newer entries were removed (log and reservation file
                # rolled back together): compare with the separately held head.
                self._anchor_verify_locked(entries, valid)
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
        if anchored:
            # The record is on disk, but it does not count until its head is anchored:
            # the caller gets an error and does not apply the change. The log says so.
            try:
                self._anchor_publish_locked(len(entries) + 1, digest)
            except BaseException:
                try:
                    self._append_locked("audit.record_not_anchored", {"event": event, "hash": digest})
                except Exception:  # noqa: BLE001 - best effort: the caller is refused anyway
                    pass
                raise
        return entry

    # ---- anchor (aegis/audit_anchor.py, docs/AUDIT_ANCHOR.md) -------------------------
    def _anchor_failed(self, reason: str) -> None:
        self._anchor_error = reason
        self._anchor_checked_at = time.time()

    def _anchor_verify_locked(self, entries: list[dict], valid: bool) -> int:
        """The log must still contain the anchored head, unchanged. Raises AnchorError."""
        try:
            if self.anchor_source is None:
                raise AnchorError("anchor_misconfigured")
            if symlink_on_path(self._anchor_root, self.path):
                raise AnchorError("symlink")
            if not valid:
                raise AnchorError("chain_invalid")
            head = self._anchor.head(self.anchor_source)
            seq = head["seq"] if head else 0
            if seq < self._anchor_seen:
                # the helper forgot (or lost) a head this service anchored
                raise AnchorError("anchor_regressed")
            if len(entries) < seq:
                raise AnchorError("rollback")
            if seq and entries[seq - 1].get("hash") != head["hash"]:
                raise AnchorError("fork")
        except AnchorError as e:
            self._anchor_failed(e.reason)
            raise
        except Exception:  # noqa: BLE001 - anything unexpected: not verified
            self._anchor_failed("anchor_unavailable")
            raise AnchorError("anchor_unavailable") from None
        self._anchor_seen = seq
        self._anchor_error, self._anchor_last_seq = None, seq
        self._anchor_checked_at = time.time()
        return seq

    def _anchor_publish_locked(self, seq: int, digest: str) -> None:
        try:
            self._anchor.anchor(self.anchor_source, seq, digest)
        except AnchorError as e:
            self._anchor_failed(e.reason)
            raise
        except Exception:  # noqa: BLE001
            self._anchor_failed("anchor_unavailable")
            raise AnchorError("anchor_unavailable") from None
        self._anchor_seen = max(self._anchor_seen, seq)
        self._anchor_error, self._anchor_last_seq = None, seq
        self._anchor_checked_at = time.time()

    def anchor_check(self) -> dict:
        """Verify the log against the anchor now (startup, status). Verify only: entries
        after the anchored head (non-critical records, or a critical one whose anchoring
        failed and was therefore reported as failed) are NOT anchored here; the next
        critical record anchors the head after it. Never raises: the result is in the
        returned status, and every anchored record re-checks anyway."""
        if self._anchor is not None:
            with self._lock, self._exclusive_file():
                try:
                    entries, valid = self.verified_entries()
                except Exception:  # noqa: BLE001 - an unreadable log (or a symlink) is not valid
                    entries, valid = [], False
                try:
                    self._anchor_verify_locked(entries, valid)
                except AnchorError:
                    pass
        return self._anchor_status_now()

    def anchor_status(self, max_age: float | None = 2.0) -> dict:
        """{"enabled", "protected", "last_seq", "error"}. "protected" only when enabled and
        the most recent check (at most `max_age` seconds old) succeeded."""
        if (self._anchor is not None and max_age is not None
                and (self._anchor_checked_at is None or time.time() - self._anchor_checked_at > max_age)):
            return self.anchor_check()
        return self._anchor_status_now()

    def _anchor_status_now(self) -> dict:
        enabled = self._anchor is not None
        error = self._anchor_error if enabled else None
        if enabled and error is None and getattr(self._anchor, "verified_peer_uid", None) == os.getuid():
            # The helper answered as the service's own user (development / tests): it works,
            # but it cannot protect against that user, so it is never shown as protection.
            error = "same_user"
        return {"enabled": enabled, "protected": enabled and error is None,
                "last_seq": self._anchor_last_seq if enabled else None,
                "error": error}

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
            if self._anchor is not None:
                # before the floor below is raised: a send refused by this check consumes no
                # budget. (One whose record is appended but then cannot be anchored keeps its
                # reservation, like any failed send.)
                self._anchor_verify_locked(entries, valid)
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
        if self._anchor is not None:
            # anchored: never read through a symlink (it could point at an older copy)
            try:
                fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
            except FileNotFoundError:
                return []
            except OSError as e:
                if e.errno == errno.ELOOP:
                    raise AnchorError("symlink") from None
                raise
            with os.fdopen(fd, "r") as f:
                text = f.read()
            return [json.loads(l) for l in text.splitlines() if l.strip()]
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
