"""Tenant-scoped Cloud Run enrollment metadata and atomic challenge consumption.

This store grants no diagnostic authority. Successful proofs are committed through
AssessmentService's signed ownership ledger and its existing scope gate.
"""
from __future__ import annotations

import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol


class ChallengeStore(Protocol):
    def binding(self, tenant: str, host: str) -> tuple[str, str] | None: ...
    def issue(self, challenge: str, tenant: str, host: str, requester: str,
              audience: str, version: str, now: float, expires_at: float) -> None: ...
    def consume(self, challenge: str, tenant: str, host: str, requester: str,
                version: str, now: float) -> dict | None: ...


class SQLiteCloudRunStore:
    def __init__(self, path: Path, *, max_pending: int = 20, max_issue_per_hour: int = 30,
                 max_issue_per_tenant_hour: int = 100):
        self.path = Path(path)
        self.max_pending = max_pending
        self.max_issue_per_hour = max_issue_per_hour
        self.max_issue_per_tenant_hour = max_issue_per_tenant_hour
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self._connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS bindings (
                    tenant TEXT NOT NULL, host TEXT NOT NULL, subject TEXT NOT NULL,
                    version TEXT NOT NULL, PRIMARY KEY (tenant, host));
                CREATE TABLE IF NOT EXISTS challenges (
                    challenge TEXT PRIMARY KEY, tenant TEXT NOT NULL, host TEXT NOT NULL,
                    requester TEXT NOT NULL, audience TEXT NOT NULL, version TEXT NOT NULL,
                    issued_at REAL NOT NULL, expires_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS issue_events (
                    tenant TEXT NOT NULL, requester TEXT NOT NULL, issued_at REAL NOT NULL);
            """)
        os.chmod(self.path, 0o600)

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        try:
            yield db
        finally:
            db.close()

    def binding(self, tenant: str, host: str) -> tuple[str, str] | None:
        with self._connection() as db:
            row = db.execute("SELECT subject, version FROM bindings WHERE tenant=? AND host=?",
                             (tenant, host)).fetchone()
            return (row["subject"], row["version"]) if row else None

    def register(self, tenant: str, host: str, subject: str, now: float) -> str:
        if not isinstance(subject, str) or not re.fullmatch(r"[A-Za-z0-9._:@-]{1,256}", subject):
            raise ValueError("invalid OIDC subject")
        version = secrets.token_hex(16)
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM challenges WHERE tenant=? AND host=?", (tenant, host))
            db.execute("INSERT INTO bindings VALUES (?,?,?,?) ON CONFLICT (tenant,host) "
                       "DO UPDATE SET subject=excluded.subject,version=excluded.version",
                       (tenant, host, subject, version))
            db.commit()
        return version

    def revoke(self, tenant: str, host: str) -> None:
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM challenges WHERE tenant=? AND host=?", (tenant, host))
            db.execute("DELETE FROM bindings WHERE tenant=? AND host=?", (tenant, host))
            db.commit()

    def rotate_host(self, host: str) -> None:
        """Invalidate in-flight proofs when the asset registration is refreshed."""
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM challenges WHERE host=?", (host,))
            rows = db.execute("SELECT tenant FROM bindings WHERE host=?", (host,)).fetchall()
            for row in rows:
                db.execute("UPDATE bindings SET version=? WHERE tenant=? AND host=?",
                           (secrets.token_hex(16), row["tenant"], host))
            db.commit()

    def revoke_host(self, host: str) -> None:
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM challenges WHERE host=?", (host,))
            db.execute("DELETE FROM bindings WHERE host=?", (host,))
            db.commit()

    def issue(self, challenge: str, tenant: str, host: str, requester: str,
              audience: str, version: str, now: float, expires_at: float) -> None:
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM challenges WHERE expires_at<=?", (now,))
            db.execute("DELETE FROM issue_events WHERE issued_at<=?", (now - 3600,))
            binding = db.execute("SELECT version FROM bindings WHERE tenant=? AND host=?",
                                 (tenant, host)).fetchone()
            if not binding or binding["version"] != version:
                raise ValueError("registration changed")
            pending = db.execute("SELECT count(*) FROM challenges WHERE tenant=?", (tenant,)).fetchone()[0]
            recent = db.execute("SELECT count(*) FROM issue_events WHERE tenant=? AND requester=?",
                                (tenant, requester)).fetchone()[0]
            tenant_recent = db.execute("SELECT count(*) FROM issue_events WHERE tenant=?", (tenant,)).fetchone()[0]
            if (pending >= self.max_pending or recent >= self.max_issue_per_hour
                    or tenant_recent >= self.max_issue_per_tenant_hour):
                raise ValueError("challenge issuance limit reached")
            db.execute("INSERT INTO challenges VALUES (?,?,?,?,?,?,?,?)",
                       (challenge, tenant, host, requester, audience, version, now, expires_at))
            db.execute("INSERT INTO issue_events VALUES (?,?,?)", (tenant, requester, now))
            db.commit()

    def consume(self, challenge: str, tenant: str, host: str, requester: str,
                version: str, now: float) -> dict | None:
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM challenges WHERE expires_at<=?", (now,))
            row = db.execute("SELECT c.* FROM challenges c JOIN bindings b "
                             "ON b.tenant=c.tenant AND b.host=c.host AND b.version=c.version "
                             "WHERE c.challenge=? AND c.tenant=? AND c.host=? AND c.requester=? "
                             "AND c.version=? AND c.expires_at>?",
                             (challenge, tenant, host, requester, version, now)).fetchone()
            if row:
                db.execute("DELETE FROM challenges WHERE challenge=?", (challenge,))
            db.commit()
            return dict(row) if row else None
