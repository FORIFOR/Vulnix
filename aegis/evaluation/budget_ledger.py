"""The evaluation's own budget ledger, shared by every model (US$5.00 in total).

Independent of Vulnix's product budgets. Append-only JSON lines, each entry chained to
the previous one by SHA-256, written under an exclusive file lock and fsync'd before a
reservation counts. Rules (docs/evaluation/EVALUATION_PROTOCOL.md, section 5):

- A request's worst-case cost is reserved BEFORE it may be sent; a reservation that
  would take the total over the cap is refused, also under concurrency.
- A reservation is never refunded: a failure, timeout or unusable reply keeps it. Only a
  confirmed bill can lower the counted cost of that request (never below zero, never
  above the reservation); without a confirmed bill the reservation stands.
- No automatic retry: one (case, phase, model, round) gets one reservation; at most
  `max_requests_per_case_per_model` rounds per phase (diagnose, and fix_check after a fix).
- Unknown prices, unknown token caps or a damaged ledger refuse everything (fail closed).
- Reserving is not permission to send. `authorize_send` additionally needs
  external_calls_enabled, dry_run off, and an approval naming this exact model, request
  SHA-256, token caps, cost cap and configuration hash. The default ledger is dry-run
  with external calls disabled, so it never authorizes a send.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

GENESIS = "0" * 64


class LedgerError(Exception):
    """Refused (fail closed). `code` says why."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class LedgerLimits:
    max_total_cost_usd: float = 5.00
    max_cases: int = 30
    max_requests_per_case_per_model: int = 2


def _hash(entry: dict) -> str:
    body = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


class BudgetLedger:
    def __init__(self, path: str | os.PathLike, limits: LedgerLimits = LedgerLimits(), *,
                 dry_run: bool = True, external_calls_enabled: bool = False):
        self.path = Path(path)
        self.limits = limits
        self.dry_run = dry_run
        self.external_calls_enabled = external_calls_enabled
        if not (math.isfinite(limits.max_total_cost_usd) and limits.max_total_cost_usd > 0):
            raise LedgerError("bad_limits")

    # ---- storage -------------------------------------------------------------------
    @contextmanager
    def _locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield fd
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _read(self, fd) -> list[dict]:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks = []
        while True:
            b = os.read(fd, 1 << 16)
            if not b:
                break
            chunks.append(b)
        raw = b"".join(chunks)
        entries, prev = [], GENESIS
        if raw and not raw.endswith(b"\n"):
            raise LedgerError("ledger_damaged", "truncated last line")
        for n, line in enumerate(raw.splitlines()):
            try:
                e = json.loads(line)
            except ValueError:
                raise LedgerError("ledger_damaged", f"line {n + 1} is not JSON") from None
            if not isinstance(e, dict) or e.get("prev") != prev:
                raise LedgerError("ledger_damaged", f"line {n + 1} breaks the chain")
            h = e.pop("hash", None)
            if h != _hash(e):
                raise LedgerError("ledger_damaged", f"line {n + 1} hash mismatch")
            e["hash"] = h
            prev = h
            entries.append(e)
        return entries

    def _append(self, fd, entries: list[dict], entry: dict) -> dict:
        entry = {**entry, "prev": entries[-1]["hash"] if entries else GENESIS, "n": len(entries) + 1}
        entry["hash"] = _hash(entry)
        os.write(fd, (json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))
        os.fsync(fd)
        return entry

    # ---- accounting ------------------------------------------------------------------
    @staticmethod
    def _state(entries: list[dict]) -> dict:
        reserved, settled = {}, {}
        for e in entries:
            if e["kind"] == "reserve":
                reserved[e["reservation_id"]] = e
            elif e["kind"] == "settle":
                settled[e["reservation_id"]] = e
        counted = 0.0
        for rid, r in reserved.items():
            s = settled.get(rid)
            counted += s["counted_usd"] if s else r["max_cost_usd"]
        return {"reserved": reserved, "settled": settled, "counted_usd": round(counted, 6)}

    def summary(self) -> dict:
        with self._locked() as fd:
            entries = self._read(fd)
        st = self._state(entries)
        by_model: dict[str, float] = {}
        for rid, r in st["reserved"].items():
            s = st["settled"].get(rid)
            by_model[r["model"]] = round(by_model.get(r["model"], 0.0) + (s["counted_usd"] if s else r["max_cost_usd"]), 6)
        return {"counted_usd": st["counted_usd"], "cap_usd": self.limits.max_total_cost_usd,
                "left_usd": round(self.limits.max_total_cost_usd - st["counted_usd"], 6),
                "reservations": len(st["reserved"]), "by_model": by_model}

    def reserve(self, *, model, case_id: str, round_no: int, request_sha256: str,
                phase: str = "diagnose") -> dict:
        """Reserve the worst case of one request (model: a ModelSpec). Raises LedgerError."""
        if not model.prices_known():
            raise LedgerError("price_unknown", model.key)
        if not all(isinstance(t, int) and t > 0 for t in (model.max_input_tokens, model.max_output_tokens)):
            raise LedgerError("token_cap_unknown", model.key)
        if not (isinstance(request_sha256, str) and len(request_sha256) == 64):
            raise LedgerError("bad_request_hash")
        if not (isinstance(round_no, int) and 1 <= round_no <= self.limits.max_requests_per_case_per_model):
            raise LedgerError("too_many_requests_for_case")
        cost = model.max_cost_usd()
        with self._locked() as fd:
            entries = self._read(fd)
            st = self._state(entries)
            rs = list(st["reserved"].values())
            if phase not in ("diagnose", "fix_check"):
                raise LedgerError("bad_phase")
            if any(r["case_id"] == case_id and r["model"] == model.key and r["round"] == round_no
                   and r.get("phase", "diagnose") == phase for r in rs):
                raise LedgerError("no_retry", f"{case_id}/{phase}/{model.key}/round {round_no} already reserved")
            if len({r["case_id"] for r in rs} | {case_id}) > self.limits.max_cases:
                raise LedgerError("too_many_cases")
            if st["counted_usd"] + cost > self.limits.max_total_cost_usd + 1e-9:
                raise LedgerError("over_budget", f"{st['counted_usd']} + {cost} > {self.limits.max_total_cost_usd}")
            return self._append(fd, entries, {
                "kind": "reserve", "reservation_id": f"r{len(st['reserved']) + 1}", "model": model.key,
                "case_id": case_id, "phase": phase, "round": round_no, "request_sha256": request_sha256,
                "max_input_tokens": model.max_input_tokens, "max_output_tokens": model.max_output_tokens,
                "price_in_per_m": model.price_in_per_m, "price_out_per_m": model.price_out_per_m,
                "max_cost_usd": cost})

    def settle(self, reservation_id: str, *, outcome: str, billed_usd: float | None = None) -> dict:
        """Record how the request ended. Without a confirmed bill the reservation stands."""
        with self._locked() as fd:
            entries = self._read(fd)
            st = self._state(entries)
            r = st["reserved"].get(reservation_id)
            if r is None:
                raise LedgerError("unknown_reservation")
            if reservation_id in st["settled"]:
                raise LedgerError("already_settled")
            confirmed = (isinstance(billed_usd, (int, float)) and math.isfinite(billed_usd)
                         and 0 <= billed_usd <= r["max_cost_usd"])
            counted = round(billed_usd, 6) if confirmed else r["max_cost_usd"]
            return self._append(fd, entries, {"kind": "settle", "reservation_id": reservation_id,
                                              "outcome": outcome, "billed_usd": billed_usd if confirmed else None,
                                              "counted_usd": counted})

    def authorize_send(self, reservation: dict, *, approval: dict | None, config_sha256: str,
                       request_sha256: str) -> None:
        """Permission to send one reserved request, once. Raises LedgerError unless every
        condition holds; on success a `send` entry is written first, so a second call (in
        this process or after a restart) is refused. A dry-run ledger refuses unconditionally."""
        if self.dry_run or not self.external_calls_enabled:
            raise LedgerError("dry_run", "external calls are disabled")
        if not isinstance(approval, dict):
            raise LedgerError("no_approval")
        want = {"model": reservation["model"], "request_sha256": reservation["request_sha256"],
                "max_input_tokens": reservation["max_input_tokens"],
                "max_output_tokens": reservation["max_output_tokens"]}
        for k, v in want.items():
            if approval.get(k) != v:
                raise LedgerError("approval_mismatch", k)
        if request_sha256 != reservation["request_sha256"]:
            raise LedgerError("approval_mismatch", "body changed after the reservation")
        if approval.get("config_sha256") != config_sha256:
            raise LedgerError("approval_mismatch", "model settings changed after the preview")
        cap = approval.get("max_cost_usd")
        if not (isinstance(cap, (int, float)) and reservation["max_cost_usd"] <= cap):
            raise LedgerError("approval_mismatch", "cost cap")
        with self._locked() as fd:                      # one send per reservation, across restarts
            entries = self._read(fd)
            st = self._state(entries)
            rid = reservation.get("reservation_id")
            stored = st["reserved"].get(rid)
            if stored is None or stored["hash"] != reservation.get("hash"):
                raise LedgerError("unknown_reservation", "not the reservation this ledger recorded")
            if rid in st["settled"]:
                raise LedgerError("already_settled")
            if any(e["kind"] == "send" and e["reservation_id"] == rid for e in entries):
                raise LedgerError("already_sent")
            self._append(fd, entries, {"kind": "send", "reservation_id": rid,
                                       "request_sha256": request_sha256, "approval_id": approval.get("id")})


__all__ = ["BudgetLedger", "LedgerError", "LedgerLimits"]
