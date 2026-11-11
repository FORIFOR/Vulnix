"""The authority ledger: everything that lets this installation touch a real service.

One object, one file, one commit point. The ledger holds

  * `assets`                  real-service assets that exist (host -> record id)
  * `ownership_proofs`        recorded proofs of ownership (host -> proof)
  * `verified_external_hosts` confirmed scopes: scheme, port, window, addresses
  * `real_service_hosts`      names that are real services (a restriction: never a lab alias)
  * `accepted_profiles`       site L2 profiles an admin accepted (id -> sha256)

and a generation token `"<counter>:<random>"` that changes with every commit.
Nothing else in the data directory grants authority; `state.json` is display
state (findings, phases, chat, asset cards) and can fail to save without
touching what is authorised.

Commit protocol (a transaction is "all tables as they are now"):

  1. write `authority.ledger.tmp`, fsync, rename over `authority.ledger`,
     fsync the directory                                    <- the commit point
  2. write the new generation to `authority.epoch` (same way)

The ledger file carries its own generation and the generation the epoch record
held when it was written (`previous`). On load it is accepted when it verifies
(HMAC keyed from the 0600 master key) and the epoch record names its generation
- or its `previous`, which is exactly the state after a crash between 1 and 2.
Any other combination (older copy, missing or emptied epoch record, edited
file) restores NO authority. A crash at any point therefore leaves either the
state before the transaction or the state after it, never a mixture.

When a commit fails, the caller chooses:

  * `transaction()` - for anything that GRANTS: the tables are rolled back to
    what is on disk and `LedgerError` is raised. Nothing was granted.
  * `commit()`      - for anything that REDUCES (revocation, deletion): memory
    keeps the reduction, and the stale copy on disk is made unacceptable by
    whichever means still works: remove the epoch record, empty it in place,
    or leave a signed marker outside the data directory naming the stale
    generation. `error` stays set until a commit succeeds; the service refuses
    all real-service work while it is.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

LEDGER_FILE = "authority.ledger"
EPOCH_FILE = "authority.epoch"
_GENERATION = re.compile(r"\d{1,12}:[0-9a-f]{32}")
TABLES = ("assets", "ownership_proofs", "verified_external_hosts", "real_service_hosts", "accepted_profiles")


class LedgerError(Exception):
    """A granting transaction could not be committed; it was rolled back."""


def default_revocation_marker_dirs() -> list[Path]:
    """Places OUTSIDE the data directory where "a revocation could not be saved"
    is written down when the data directory itself cannot be changed. An operator
    may point VULNIX_REVOCATION_MARKER_DIR at one directory of their choice."""
    override = os.environ.get("VULNIX_REVOCATION_MARKER_DIR", "").strip()
    if override:
        return [Path(override)]
    uid = os.getuid() if hasattr(os, "getuid") else 0
    return [Path.home() / ".vulnix" / "revocations",
            Path(tempfile.gettempdir()) / f"vulnix-revocations-{uid}"]


def canonical(obj) -> str:
    return json.dumps(json.loads(json.dumps(obj)), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sync_dir(path: Path) -> None:
    """Make a rename in `path` durable (best effort where directories cannot be synced)."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _write_durable(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    sync_dir(path.parent)


class AuthorityLedger:
    def __init__(self, data_dir: Path, mac_key: bytes, marker_dirs: list[Path] | None = None, record=None):
        self.data_dir = Path(data_dir)
        self._key = mac_key
        self._marker_dirs = list(marker_dirs) if marker_dirs is not None else default_revocation_marker_dirs()
        self._record = record or (lambda event, **fields: None)     # audit sink
        self.assets: dict[str, dict] = {}
        self.ownership_proofs: dict[str, dict] = {}
        self.verified_external_hosts: dict[str, dict] = {}
        self.real_service_hosts: set[str] = set()
        self.accepted_profiles: dict[str, str] = {}
        self.generation = ""             # of the tables in memory, once committed
        self.error: str | None = None    # set while what is in memory is not what is on disk
        self.notice: str | None = None   # why saved authority was not restored at startup
        self.rejected_reason = ""
        self.assets_known = False        # False until a ledger that lists assets was loaded or written
        # True once the list of real-service names may be incomplete (the ledger was
        # unreadable, missing, or not acceptable). From then on EVERY name that is not
        # a bundled lab name is treated as a real service. Part of the signed tables.
        self.names_unknown = False
        self._superseded: set[str] = set()   # generations replaced while the epoch record lagged
        self.marker_pending = False
        self._counter = 0
        self._epoch_on_disk = ""         # what authority.epoch holds, as far as we know
        self._committed: str | None = None   # digest of the tables in an ACCEPTABLE ledger on disk; None = none

    # ---- tables --------------------------------------------------------------
    def tables(self) -> dict:
        return {"assets": self.assets,
                "ownership_proofs": self.ownership_proofs,
                "verified_external_hosts": self.verified_external_hosts,
                "real_service_hosts": sorted(self.real_service_hosts),
                "accepted_profiles": self.accepted_profiles,
                **({"names_unknown": True} if self.names_unknown else {})}

    def _set_tables(self, t: dict) -> None:
        self.assets = {str(k).lower(): dict(v) for k, v in (t.get("assets") or {}).items() if isinstance(v, dict)}
        self.ownership_proofs = {str(k).lower(): dict(v) for k, v in (t.get("ownership_proofs") or {}).items()
                                 if isinstance(v, dict)}
        self.verified_external_hosts = {str(k).lower(): dict(v)
                                        for k, v in (t.get("verified_external_hosts") or {}).items()
                                        if isinstance(v, dict)}
        self.real_service_hosts = {str(h).lower() for h in (t.get("real_service_hosts") or []) if isinstance(h, str)}
        self.accepted_profiles = {str(k): str(v) for k, v in (t.get("accepted_profiles") or {}).items()}
        self.names_unknown = self.names_unknown or t.get("names_unknown") is True      # never switched back

    def digest(self) -> str:
        return hashlib.sha256(canonical(self.tables()).encode("utf-8")).hexdigest()

    def dirty(self) -> bool:
        return self._committed != self.digest() or self._epoch_on_disk != self.generation

    # ---- paths, MACs ---------------------------------------------------------
    @property
    def path(self) -> Path:
        return self.data_dir / LEDGER_FILE

    @property
    def epoch_path(self) -> Path:
        return self.data_dir / EPOCH_FILE

    def _mac(self, generation: str, previous: str, tables: dict) -> str:
        msg = f"ledger|{generation}|{previous}|{canonical(tables)}".encode("utf-8")
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def _epoch_mac(self, generation: str) -> str:
        return hmac.new(self._key, f"epoch|{generation}".encode(), hashlib.sha256).hexdigest()

    def legacy_mac(self, tables: dict, epoch: str) -> str:
        """MAC of the authority block older versions kept inside state.json (import only)."""
        return hmac.new(self._key, f"{epoch}|{canonical(tables)}".encode("utf-8"), hashlib.sha256).hexdigest()

    def read_epoch(self) -> str | None:
        try:
            body = json.loads(self.epoch_path.read_text(encoding="utf-8"))
            epoch = body["epoch"]
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if not isinstance(epoch, str) or not _GENERATION.fullmatch(epoch):
            return None
        return epoch if hmac.compare_digest(str(body.get("mac") or ""), self._epoch_mac(epoch)) else None

    def _write_epoch(self, generation: str) -> None:
        _write_durable(self.epoch_path, json.dumps({"epoch": generation, "mac": self._epoch_mac(generation)}))
        self._epoch_on_disk = generation

    def _next_generation(self) -> str:
        self._counter += 1
        return f"{self._counter}:{secrets.token_hex(16)}"

    @staticmethod
    def _count(generation: str | None) -> int:
        try:
            return int(str(generation).split(":", 1)[0])
        except ValueError:
            return 0

    # ---- load ----------------------------------------------------------------
    def writable(self) -> str | None:
        """None when a file can be created, written, synced and removed in the data
        directory right now; otherwise the error. Authority is only honoured by a
        process that could also record its revocation."""
        probe = self.data_dir / f".write-probe-{secrets.token_hex(6)}"
        try:
            fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, b"x")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.unlink(probe)
            return None
        except OSError as e:
            try:
                os.unlink(probe)
            except OSError:
                pass
            return type(e).__name__

    def load(self, legacy: dict | None = None, expect_ledger: bool = False) -> str:
        """Restore the tables from disk. Returns "" or the reason nothing that
        grants authority was restored. `legacy`: a parsed state.json of a version
        that kept the signed authority block there - imported once, only when no
        ledger file exists. `expect_ledger`: the display state says a ledger was
        in use, so its absence is a loss, not a first start."""
        epoch = self.read_epoch()
        self._epoch_on_disk = epoch or ""
        self._counter = self._count(epoch)
        unwritable = self.writable()
        if unwritable:
            self.error = f"data directory not writable ({unwritable})"
        candidate: dict | None = None
        cand_generation, reason, untrusted = "", "", {}

        if self.path.exists():
            try:
                body = json.loads(self.path.read_text(encoding="utf-8"))
                tables = body["tables"]
                generation, previous = str(body["generation"]), str(body.get("previous") or "")
                if not isinstance(tables, dict):
                    raise ValueError("tables")
            except (OSError, ValueError, KeyError, TypeError, RecursionError) as e:
                reason = f"the authority ledger cannot be read ({type(e).__name__})"
                try:        # keep it for whoever has to find out why
                    os.replace(self.path, self.data_dir / f"authority.unreadable-{int(time.time())}.ledger")
                except OSError:
                    pass
            else:
                untrusted = tables
                if not hmac.compare_digest(str(body.get("mac") or ""), self._mac(generation, previous, tables)):
                    reason = "integrity check failed (unsigned or modified)"
                elif not _GENERATION.fullmatch(generation):
                    reason = "integrity check failed (generation)"
                elif epoch is None and previous == "" and not self.epoch_path.exists():
                    # The very first commit, interrupted before its epoch record was
                    # written. (Invalidation never leaves this picture: it EMPTIES the
                    # record, it does not remove it.)
                    self._counter = max(self._counter, self._count(generation))
                    candidate, cand_generation = tables, generation
                    self.assets_known = True
                elif epoch is None:
                    self._counter = max(self._counter, self._count(generation))     # verified: safe to count from
                    self._superseded.add(generation)                                # never acceptable again
                    reason = "not the latest authority state (missing or emptied epoch record)"
                elif not (hmac.compare_digest(epoch, generation)
                          or (previous and hmac.compare_digest(epoch, previous))):
                    self._superseded.add(generation)
                    reason = "not the latest authority state (older copy)"
                else:
                    self._counter = max(self._counter, self._count(generation))
                    candidate, cand_generation = tables, generation
                    self.assets_known = True
        elif isinstance(legacy, dict) and ("authority_mac" in legacy or "authority_epoch" in legacy):
            tables = {k: legacy.get(k) for k in TABLES if k != "assets"}
            tables = {"ownership_proofs": tables["ownership_proofs"] if isinstance(tables["ownership_proofs"], dict) else {},
                      "verified_external_hosts": (tables["verified_external_hosts"]
                                                  if isinstance(tables["verified_external_hosts"], dict) else {}),
                      "real_service_hosts": (tables["real_service_hosts"]
                                             if isinstance(tables["real_service_hosts"], list) else []),
                      "accepted_profiles": tables["accepted_profiles"] if isinstance(tables["accepted_profiles"], dict) else {}}
            untrusted = tables
            generation = str(legacy.get("authority_epoch") or "")
            if not hmac.compare_digest(str(legacy.get("authority_mac") or ""), self.legacy_mac(tables, generation)):
                reason = "integrity check failed (unsigned or modified)"
            elif epoch is None or not hmac.compare_digest(epoch, generation):
                reason = "not the latest authority state (older copy or missing epoch record)"
            else:
                candidate, cand_generation = tables, generation
        elif self.epoch_path.exists() or expect_ledger:
            # an epoch record (or a display state written alongside a ledger) without
            # a ledger: the ledger was removed
            reason = "the authority ledger is missing"

        names_authentic = candidate is not None      # verified AND current: its name list is complete
        marker = self._marker_hit({cand_generation} if candidate is not None else {epoch or ""})
        if marker and (candidate is not None or untrusted):
            candidate, reason = None, reason or marker
        if unwritable and candidate is not None:
            candidate, reason = None, "data directory is not writable; a revocation could not have been recorded"

        if candidate is not None:
            self._set_tables(candidate)
            self.generation = cand_generation
            before = self.digest()
            for entry in self.verified_external_hosts.values():
                if entry.get("allow_loopback_test"):
                    entry["allow_loopback_test"] = False        # a test switch is never restored
            self._committed = before if self.path.exists() else None
        else:
            self._set_tables({})
            self._committed = None                               # whatever is on disk is not acceptable
            # "This name is a real service" only ever RESTRICTS (never a lab alias,
            # never an external model), so it is kept even from a state that is not trusted.
            for key in ("real_service_hosts", "verified_external_hosts", "ownership_proofs", "assets"):
                names = untrusted.get(key) if isinstance(untrusted, dict) else None
                for name in (names if isinstance(names, (list, dict)) else []):
                    if isinstance(name, str) and name:
                        self.real_service_hosts.add(name.rstrip(".").lower())
            if reason and not names_authentic:
                # Which names are real services can no longer be known for certain
                # (the list may be gone, edited, or older than the truth).
                self.names_unknown = True
        if reason and epoch:
            # whatever the epoch record still names is refused from now on, also if
            # the record cannot be advanced when the refusal is committed
            self._superseded.add(epoch)
        self.rejected_reason = reason
        if reason:
            self.notice = ("保存されていた所有確認・範囲確認は引き継いでいません"
                           "（保存状態を信頼できないため）。所有確認からやり直してください")
        return reason

    # ---- commit --------------------------------------------------------------
    def _write(self) -> str:
        """One commit attempt: "ok", "ledger_failed" (disk still holds the previous
        state) or "epoch_failed" (the new state is on disk and acceptable; only the
        epoch record lags and is retried with every later commit)."""
        digest = self.digest()
        if self._committed != digest:
            tables = json.loads(canonical(self.tables()))
            generation, previous = self._next_generation(), self._epoch_on_disk
            body = {"version": 1, "generation": generation, "previous": previous,
                    "committed_at": time.time(), "tables": tables,
                    "mac": self._mac(generation, previous, tables)}
            try:
                _write_durable(self.path, json.dumps(body, ensure_ascii=False, indent=1))
            except Exception as e:
                self.error = type(e).__name__
                return "ledger_failed"
            replaced = self.generation
            self.generation, self._committed, self.assets_known = generation, digest, True     # committed
            if replaced and self._epoch_on_disk != replaced:
                pass                                         # that copy never matched the epoch record
            if replaced:
                self._superseded.add(replaced)
        try:
            self._write_epoch(self.generation)
        except Exception as e:
            # The new ledger is on disk and acceptable (its `previous` is what the
            # epoch record holds). But so would be an OLDER ledger written while the
            # record lagged, or the one the record still names: those are named in a
            # marker until the record catches up.
            self.error = type(e).__name__
            stale = {g for g in self._superseded if g and g != self.generation}
            if stale:
                written = self._write_markers(stale)
                self.marker_pending = self.marker_pending or written > 0
                if not written:
                    self._record("state.revocation_not_durable",
                                 reason="epoch record and marker locations are unwritable")
            return "epoch_failed"
        self.error = None
        self._superseded.clear()
        if self.marker_pending:
            self._clear_markers()
        return "ok"

    def commit(self) -> bool:
        """Make the tables as they are now the durable truth. On failure memory is
        kept and the stale copy on disk is invalidated (see module docstring)."""
        if not self.dirty():
            if self.error and self.writable() is None:
                self.error = None
            return self.error is None
        first = self.error is None
        outcome = self._write()
        if outcome == "ledger_failed":
            self._invalidate()
            if first:
                self._record("ledger.commit_failed", error=self.error)
        return outcome == "ok"

    def snapshot(self) -> dict:
        return copy.deepcopy(self.tables())

    def commit_or_rollback(self, before: dict) -> None:
        """Commit a change that GRANTS authority. If the ledger file cannot be
        replaced, the tables go back to `before` (taken with snapshot()) and
        LedgerError is raised: nothing of the change exists anywhere."""
        if self._write() == "ledger_failed":
            self._set_tables(before)
            self._record("ledger.commit_failed", error=self.error, rolled_back=True)
            if self._committed != self.digest():
                self._invalidate()      # an earlier reduction is still unsaved as well
            raise LedgerError(self.error or "commit failed")

    @contextmanager
    def transaction(self):
        """For changes that grant authority: committed, or rolled back and LedgerError."""
        before = self.snapshot()
        try:
            yield self
        except BaseException:
            self._set_tables(before)
            raise
        self.commit_or_rollback(before)

    # ---- a reduction that cannot be written where the ledger lives -----------
    def invalidate(self) -> None:
        """Public form: the caller knows memory and disk disagree."""
        self._invalidate()

    def _invalidate(self) -> None:
        self._committed = None
        # The record is EMPTIED, not removed: "no record at all" is what an
        # interrupted first commit looks like, and that is accepted at load.
        gone = False
        for attempt in ("in place", "recreate"):
            try:
                if attempt == "recreate":
                    os.unlink(self.epoch_path)          # e.g. a read-only file in a writable directory
                fd = os.open(self.epoch_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
                gone = True
                break
            except OSError:
                continue
        if gone:
            self._epoch_on_disk = ""
            sync_dir(self.data_dir)
            return                      # the copy on disk can no longer verify
        written = self._write_markers(self._disk_generations() | self._superseded)
        self.marker_pending = self.marker_pending or written > 0
        if not written:
            self._record("state.revocation_not_durable",
                         reason="data directory and marker locations are all unwritable")

    def marker_key(self) -> str:
        return hashlib.sha256(str(self.data_dir.resolve()).encode("utf-8")).hexdigest()[:32]

    def marker_paths(self) -> list[Path]:
        return [Path(d) / f"{self.marker_key()}.revoked" for d in self._marker_dirs]

    def marker_mac(self, epochs: list[str]) -> str:
        msg = f"revoked|{self.marker_key()}|{'|'.join(sorted(epochs))}"
        return hmac.new(self._key, msg.encode("utf-8"), hashlib.sha256).hexdigest()

    def _read_marker(self, path: Path) -> list[str] | None:
        """The generations a marker of ours names; None if it cannot be read or verified."""
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
            epochs = body["epochs"]
            if not isinstance(epochs, list) or not all(isinstance(e, str) for e in epochs):
                return None
            ok = hmac.compare_digest(str(body.get("mac") or ""), self.marker_mac(epochs))
        except (OSError, ValueError, KeyError, TypeError):
            return None
        return epochs if ok else None

    def _disk_generations(self) -> set[str]:
        """Every generation the files on disk could be accepted under."""
        found = {self.read_epoch() or "", self._epoch_on_disk}
        try:
            found.add(str(json.loads(self.path.read_text(encoding="utf-8"))["generation"]))
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return found

    def _write_markers(self, generations: set[str]) -> int:
        written = 0
        uid = os.getuid() if hasattr(os, "getuid") else 0
        for path in self.marker_paths():
            # Name what is on disk NOW, and keep whatever an earlier marker already
            # named: a marker is only ever widened, never narrowed.
            stale = set(generations)
            stale.discard("")
            try:
                if os.lstat(path).st_uid == uid:
                    stale |= set(self._read_marker(path) or [])
            except OSError:
                pass
            epochs = sorted(stale, key=lambda g: (self._count(g), g))[-64:]
            body = json.dumps({"epochs": epochs, "at": time.time(), "mac": self.marker_mac(epochs)})
            try:
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if hasattr(os, "getuid") and os.lstat(path.parent).st_uid != uid:
                    continue            # somebody else's directory (shared temp): not ours to trust
                _write_durable(path, body)
                written += 1
            except OSError:
                continue
        return written

    def _clear_markers(self) -> None:
        left = False
        for path in self.marker_paths():
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            except OSError:
                left = True             # tried again after the next successful commit
        self.marker_pending = left

    def _marker_hit(self, generations: set[str]) -> str | None:
        """A reason to refuse the authority on disk, or None. A marker that is ours
        but cannot be read or verified counts as a hit: unknown means refuse."""
        for path in self.marker_paths():
            try:
                st = os.lstat(path)
            except FileNotFoundError:
                continue
            except OSError:
                self.marker_pending = True
                return "a revocation marker exists but cannot be read"
            if hasattr(os, "getuid") and st.st_uid != os.getuid():
                continue                # not written by this account: ignored
            self.marker_pending = True
            named = self._read_marker(path)
            if named is None:
                return "a revocation marker exists but cannot be read or does not verify"
            if generations & set(named):
                return "a revocation could not be saved before the last shutdown"
            # it names an older state than the one on disk: a later commit succeeded
        return None
