"""Operator-managed, narrowly scoped ownership communication permissions."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
from dataclasses import dataclass
from pathlib import Path

from .google_ownership import METHOD as GOOGLE_METHOD
from .ownership import parse_service_target
from .tenancy import valid_org_id

METHODS = ("dns_txt", "well_known", GOOGLE_METHOD)
_MAX_FILE = 64 * 1024
_MAX_WINDOW = 7 * 86400
# Standing self-service policy (operator switch VULNIX_OWNERSHIP_SELF_SERVICE=1):
# the user's own proof (Search Console owner, DNS TXT, a file on the origin) is
# still required; only the per-target operator file and the second person are
# replaced by a fixed per-target, per-method, per-UTC-day attempt budget.
SELF_SERVICE_CHECKS = 5
_DAY = 86400


@dataclass(frozen=True)
class Policy:
    id: str
    org: str
    url: str
    method: str
    not_before: int
    expires_at: int
    max_checks: int


def load() -> dict[tuple[str, str, str], Policy]:
    """Read a file owned by the operator. Removal or invalid contents deny new checks."""
    filename = os.environ.get("VULNIX_OWNERSHIP_POLICY_FILE")
    if not filename or not Path(filename).is_absolute():
        return {}
    try:
        with os.fdopen(os.open(filename, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
                    or info.st_mode & 0o022):
                return {}
            raw = stream.read(_MAX_FILE + 1)
        rows = json.loads(raw) if len(raw) <= _MAX_FILE else None
        if not isinstance(rows, list) or len(rows) > 200:
            return {}
        policies = {}
        ids = set()
        for row in rows:
            policy = Policy(**row)
            target = parse_service_target(policy.url)
            if (not isinstance(policy.id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", policy.id)
                    or policy.id in ids or not isinstance(policy.org, str) or not valid_org_id(policy.org)
                    or policy.url != target["target_url"] or target["is_local_lab"]
                    or policy.method not in METHODS
                    or (policy.method == "well_known" and (target["scheme"], target["port"]) != ("https", 443))
                    or type(policy.not_before) is not int or type(policy.expires_at) is not int
                    or not 0 < policy.expires_at - policy.not_before <= _MAX_WINDOW
                    or type(policy.max_checks) is not int or not 1 <= policy.max_checks <= 20):
                return {}
            key = (policy.org, policy.url, policy.method)
            if key in policies:
                return {}
            policies[key] = policy
            ids.add(policy.id)
        return policies
    except (OSError, UnicodeError, ValueError, TypeError, AttributeError, OverflowError):
        return {}


def _self_service(org: str, url: str, method: str, now: float) -> Policy | None:
    if os.environ.get("VULNIX_OWNERSHIP_SELF_SERVICE") != "1" or method not in METHODS or not valid_org_id(org):
        return None
    try:
        target = parse_service_target(url)
    except ValueError:
        return None
    if (url != target["target_url"] or target["is_local_lab"]
            or (method == "well_known" and (target["scheme"], target["port"]) != ("https", 443))):
        return None
    day = int(now) // _DAY
    digest = hashlib.sha256(f"{org}\n{url}\n{method}\n{day}".encode()).hexdigest()[:40]
    return Policy(id=f"self-{digest}", org=org, url=url, method=method,
                  not_before=day * _DAY, expires_at=(day + 1) * _DAY, max_checks=SELF_SERVICE_CHECKS)


def for_target(org: str, url: str, now: float) -> dict[str, Policy]:
    """Policies for one registered origin, by method. A reviewed file entry wins
    over the standing self-service policy for the same method."""
    found = {method: policy for (p_org, p_url, method), policy in load().items()
             if (p_org, p_url) == (org, url)}
    for method in METHODS:
        if method not in found and (policy := _self_service(org, url, method, now)):
            found[method] = policy
    return found


def has_budget(directory: Path, policy: Policy, *, consume: bool = False) -> bool:
    """Count attempts atomically across threads, restarts and processes on this volume."""
    path = directory / "ownership-traffic.sqlite3"
    try:
        if consume:
            try:
                os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            except FileExistsError:
                pass
        elif not path.exists():
            return True
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            return False
        with contextlib.closing(sqlite3.connect(path, timeout=3)) as db:
            if consume:
                db.execute("BEGIN IMMEDIATE")
                db.execute("CREATE TABLE IF NOT EXISTS checks (policy_id TEXT PRIMARY KEY, used INTEGER NOT NULL)")
            row = db.execute("SELECT used FROM checks WHERE policy_id = ?", (policy.id,)).fetchone()
            if row and row[0] >= policy.max_checks:
                return False
            if consume:
                db.execute("INSERT INTO checks VALUES (?, 1) ON CONFLICT(policy_id) DO UPDATE SET used = used + 1",
                           (policy.id,))
                db.commit()
        return True
    except (sqlite3.Error, OSError):
        return False


# ---- platform-wide limits for the standing self-service policy -------------------
# Per-target budgets alone let one person fan out across many targets or many
# organizations. These limits are kept in one ledger for the whole platform
# (rolling windows, so there is no burst at a day boundary), survive restarts and
# are enforced atomically across threads and processes on the same volume.
SELF_SERVICE_LIMITS = {
    "account_hour": 10,          # attempts by one account, all of its organizations
    "account_day": 30,
    "org_origins_day": 5,        # distinct origins one organization may contact
    "account_origins_day": 10,   # distinct origins one account may contact
    "platform_day": 2000,        # every self-service attempt on this platform
}


class LimitReached(PermissionError):
    """A self-service limit refused the attempt (HTTP 429). Nothing was sent."""


_LEDGER = "ownership-self-service.sqlite3"


def consume_self_service(directory: Path, *, account: str, org: str, origin: str, method: str,
                         now: float) -> None:
    """Record one attempt, or raise LimitReached without recording it."""
    path = Path(directory) / _LEDGER
    refuse = LimitReached("所有確認の利用状況を確認できないため、今回は実行しませんでした。時間をおいてお試しください")
    try:
        try:
            os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600))
        except FileExistsError:
            pass
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise refuse
        with contextlib.closing(sqlite3.connect(path, timeout=5, isolation_level=None)) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("CREATE TABLE IF NOT EXISTS attempts (ts REAL NOT NULL, account TEXT NOT NULL, "
                           "org TEXT NOT NULL, origin TEXT NOT NULL, method TEXT NOT NULL)")
                db.execute("CREATE INDEX IF NOT EXISTS attempts_ts ON attempts (ts)")
                db.execute("DELETE FROM attempts WHERE ts < ?", (now - 86400,))

                def one(sql, *args):
                    return db.execute(sql, args).fetchone()[0]

                limits = SELF_SERVICE_LIMITS
                problem = None
                if one("SELECT COUNT(*) FROM attempts") >= limits["platform_day"]:
                    problem = "現在、所有確認が混み合っています。時間をおいてお試しください"
                elif one("SELECT COUNT(*) FROM attempts WHERE account = ? AND ts >= ?",
                         account, now - 3600) >= limits["account_hour"]:
                    problem = f"所有確認は1アカウントにつき1時間あたり{limits['account_hour']}回までです"
                elif one("SELECT COUNT(*) FROM attempts WHERE account = ?", account) >= limits["account_day"]:
                    problem = f"所有確認は1アカウントにつき24時間あたり{limits['account_day']}回までです"
                elif not one("SELECT COUNT(*) FROM attempts WHERE org = ? AND origin = ?", org, origin) and (
                        one("SELECT COUNT(DISTINCT origin) FROM attempts WHERE org = ?", org)
                        >= limits["org_origins_day"]):
                    problem = f"24時間以内に所有確認できる対象は1組織につき{limits['org_origins_day']}件までです"
                elif not one("SELECT COUNT(*) FROM attempts WHERE account = ? AND origin = ?", account, origin) and (
                        one("SELECT COUNT(DISTINCT origin) FROM attempts WHERE account = ?", account)
                        >= limits["account_origins_day"]):
                    problem = f"24時間以内に所有確認できる対象は1アカウントにつき{limits['account_origins_day']}件までです"
                if problem:
                    db.execute("ROLLBACK")
                    raise LimitReached(problem)
                db.execute("INSERT INTO attempts VALUES (?, ?, ?, ?, ?)", (now, account, org, origin, method))
                db.execute("COMMIT")
            except sqlite3.Error:
                db.execute("ROLLBACK")
                raise
    except LimitReached:
        raise
    except (sqlite3.Error, OSError):
        raise refuse from None


class SelfServiceSlots:
    """Simultaneous self-service checks in this process (one backend process serves
    the OAuth state as well; see docs/CLOUD_INVENTORY.md)."""

    def __init__(self, per_account: int = 1, total: int = 8):
        self._lock = threading.Lock()
        self._per_account = per_account
        self._total = total
        self._busy: dict[str, int] = {}

    @contextlib.contextmanager
    def hold(self, account: str):
        with self._lock:
            if (self._busy.get(account, 0) >= self._per_account
                    or sum(self._busy.values()) >= self._total):
                raise LimitReached("別の所有確認を実行中です。完了してからお試しください")
            self._busy[account] = self._busy.get(account, 0) + 1
        try:
            yield
        finally:
            with self._lock:
                self._busy[account] -= 1
                if not self._busy[account]:
                    del self._busy[account]
