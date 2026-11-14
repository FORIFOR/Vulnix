"""Organizations (tenants): membership, per-organization roles, invitations, and one
AssessmentService per organization.

Isolation is structural: every organization has its own AssessmentService with its own
data directory (`<data>/orgs/<org_id>/`), so its sites, ownership proofs and their
secret, scope, findings, evidence, chat, audit log, event stream and emergency stop are
separate objects - nothing is filtered after the fact. Accounts stay global
(OperatorStore); an account acts in an organization only through a membership here.

Organization roles map onto the roles the existing service checks:
  owner    -> admin, operator, approver   (only an owner grants or removes owner)
  admin    -> admin, operator             (manages members and invitations)
  runner   -> operator                    (registers sites, runs L1, requests L2)
  approver -> approver                    (decides L2 requests; never their own)
  viewer   -> (none)                      (read only)
Platform-wide functions (account list, site profiles, control self-tests, CVE sync)
keep using the account's own global roles, never an organization role.

The default organization ("default") is the pre-existing single workspace: it keeps
using the data directory's root, and the accounts that existed before tenancy become
its members with roles derived from their global roles.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Callable, Iterable

ORG_ROLES = ("owner", "admin", "runner", "approver", "viewer")
SERVICE_ROLES = {
    "owner": ("admin", "operator", "approver"),
    "admin": ("admin", "operator"),
    "runner": ("operator",),
    "approver": ("approver",),
    "viewer": (),
}
DEFAULT_ORG = "default"
MAX_ORGS_PER_ACCOUNT = 5
INVITE_TTL_S = 7 * 24 * 3600
MAX_INVITE_TTL_S = 30 * 24 * 3600
_ORG_ID_RE = re.compile(r"org_[0-9a-f]{12}|default")


class TenancyError(Exception):
    """A refused membership/invitation operation (message is safe to show)."""


def service_roles(org_roles: Iterable[str]) -> tuple[str, ...]:
    out: list[str] = []
    for r in org_roles:
        for s in SERVICE_ROLES.get(r, ()):
            if s not in out:
                out.append(s)
    return tuple(out)


def _clean_roles(roles) -> list[str]:
    if not isinstance(roles, (list, tuple)):
        raise TenancyError("roles は配列で指定してください")
    out = [str(r) for r in roles]
    bad = [r for r in out if r not in ORG_ROLES]
    if bad or not out:
        raise TenancyError(f"役割は {', '.join(ORG_ROLES)} から1つ以上選んでください")
    return sorted(set(out), key=ORG_ROLES.index)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class OrgStore:
    """`<data>/orgs.json`: organizations, memberships and invitations (only invitation
    token hashes are stored). Writes are atomic; a failed write raises and leaves the
    previous file in place."""

    def __init__(self, path: Path, *, bootstrap_members: Callable[[], dict] | None = None,
                 clock: Callable[[], float] = time.time):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._clock = clock
        if self.path.exists():
            self._data = json.loads(self.path.read_text(encoding="utf-8"))
        else:
            members = dict(bootstrap_members() if bootstrap_members else {})
            self._data = {"orgs": {DEFAULT_ORG: {"name": "既定の組織", "created_at": clock(), "members": members}},
                          "invites": {}}
            self._save()

    # ---- persistence ---------------------------------------------------------
    def _save(self) -> None:
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._data, ensure_ascii=False, indent=1), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    # ---- reads -----------------------------------------------------------------
    def exists(self, org_id: str) -> bool:
        return org_id in self._data["orgs"]

    def roles_in(self, org_id: str, account: str) -> tuple[str, ...]:
        with self._lock:
            org = self._data["orgs"].get(org_id)
            return tuple((org or {}).get("members", {}).get(account, ()))

    def orgs_of(self, account: str) -> list[dict]:
        with self._lock:
            return [{"id": oid, "name": o["name"], "roles": list(o["members"][account])}
                    for oid, o in self._data["orgs"].items() if account in o.get("members", {})]

    def members(self, org_id: str) -> list[dict]:
        with self._lock:
            org = self._require(org_id)
            return [{"name": n, "roles": list(r)} for n, r in sorted(org["members"].items())]

    def invites(self, org_id: str) -> list[dict]:
        now = self._clock()
        with self._lock:
            return [{"id": iid, "roles": list(i["roles"]), "created_by": i["created_by"],
                     "expires_at": i["expires_at"], "expired": i["expires_at"] <= now}
                    for iid, i in self._data["invites"].items() if i["org"] == org_id]

    def org_name(self, org_id: str) -> str:
        return self._require(org_id)["name"]

    def _require(self, org_id: str) -> dict:
        org = self._data["orgs"].get(org_id)
        if org is None:
            raise TenancyError("組織が見つかりません")
        return org

    # ---- writes ----------------------------------------------------------------
    def create_org(self, name: str, owner: str) -> str:
        name = str(name or "").strip()[:60]
        if not name:
            raise TenancyError("組織名を入力してください")
        with self._lock:
            owned = sum(1 for o in self._data["orgs"].values() if "owner" in o["members"].get(owner, ()))
            if owned >= MAX_ORGS_PER_ACCOUNT:
                raise TenancyError(f"所有できる組織は {MAX_ORGS_PER_ACCOUNT} 件までです")
            oid = "org_" + secrets.token_hex(6)
            self._data["orgs"][oid] = {"name": name, "created_at": self._clock(), "created_by": owner,
                                       "members": {owner: ["owner"]}}
            self._save()
            return oid

    def _check_manager(self, org: dict, actor: str, roles: Iterable[str] = ()) -> None:
        mine = set(org["members"].get(actor, ()))
        if not mine & {"owner", "admin"}:
            raise TenancyError("メンバーの管理には組織のオーナーまたは管理者の権限が必要です")
        if "owner" in set(roles) and "owner" not in mine:
            raise TenancyError("オーナーの付与・削除はオーナーだけが行えます")

    def set_roles(self, org_id: str, actor: str, account: str, roles) -> list[str]:
        roles = _clean_roles(roles)
        with self._lock:
            org = self._require(org_id)
            if account not in org["members"]:
                raise TenancyError("この組織のメンバーではありません")
            before = list(org["members"][account])
            # granting or taking away owner is an owner's decision
            self._check_manager(org, actor, ["owner"] if ("owner" in before or "owner" in roles) else [])
            if "owner" in before and "owner" not in roles and self._owners(org) == [account]:
                raise TenancyError("最後のオーナーは外せません。先に別のメンバーをオーナーにしてください")
            org["members"][account] = roles
            self._save()
            return before

    def remove_member(self, org_id: str, actor: str, account: str) -> None:
        with self._lock:
            org = self._require(org_id)
            if account not in org["members"]:
                raise TenancyError("この組織のメンバーではありません")
            roles = org["members"][account]
            if actor != account:
                self._check_manager(org, actor, roles)
            if "owner" in roles and self._owners(org) == [account]:
                raise TenancyError("最後のオーナーは外せません")
            del org["members"][account]
            self._save()

    def create_invite(self, org_id: str, actor: str, roles, ttl_s: float = INVITE_TTL_S) -> tuple[str, str]:
        roles = _clean_roles(roles)
        ttl_s = max(300.0, min(float(ttl_s), MAX_INVITE_TTL_S))
        with self._lock:
            org = self._require(org_id)
            self._check_manager(org, actor, roles)
            token = "inv_" + secrets.token_urlsafe(24)
            iid = "invid_" + secrets.token_hex(6)
            self._data["invites"][iid] = {"org": org_id, "roles": roles, "hash": _hash(token),
                                          "created_by": actor, "created_at": self._clock(),
                                          "expires_at": self._clock() + ttl_s}
            self._save()
            return iid, token

    def revoke_invite(self, org_id: str, actor: str, invite_id: str) -> None:
        with self._lock:
            org = self._require(org_id)
            inv = self._data["invites"].get(invite_id)
            if inv is None or inv["org"] != org_id:
                raise TenancyError("招待が見つかりません")
            self._check_manager(org, actor, inv["roles"])
            del self._data["invites"][invite_id]
            self._save()

    def accept_invite(self, token: str, account: str) -> tuple[str, list[str]]:
        """Single use: the invitation is removed whether it is accepted or found expired."""
        h = _hash(str(token or ""))
        with self._lock:
            iid, inv = next(((k, v) for k, v in self._data["invites"].items()
                             if secrets.compare_digest(v["hash"], h)), (None, None))
            if inv is None:
                raise TenancyError("招待が無効です（使用済み・取り消し済み・誤り）")
            del self._data["invites"][iid]
            if inv["expires_at"] <= self._clock():
                self._save()
                raise TenancyError("招待の有効期限が切れています。新しい招待を依頼してください")
            org = self._require(inv["org"])
            current = set(org["members"].get(account, ()))
            org["members"][account] = sorted(current | set(inv["roles"]), key=ORG_ROLES.index)
            self._save()
            return inv["org"], list(inv["roles"])

    @staticmethod
    def _owners(org: dict) -> list[str]:
        return [n for n, r in org["members"].items() if "owner" in r]


def default_members_from(ops) -> dict:
    """Pre-tenancy accounts keep their access to the existing workspace."""
    out = {}
    for o in ops.operators():
        roles = set()
        if "admin" in o.roles:
            roles |= {"owner"}
        if "approver" in o.roles:
            roles |= {"approver"}
        if "operator" in o.roles:
            roles |= {"runner"}
        out[o.name] = sorted(roles or {"viewer"}, key=ORG_ROLES.index)
    return out


def valid_org_id(value: str) -> bool:
    return bool(_ORG_ID_RE.fullmatch(str(value or "")))


class TenantRegistry:
    """One AssessmentService per organization, created on first use. The default
    organization is the service the process already runs (data directory root)."""

    def __init__(self, store: OrgStore, default_svc, factory: Callable[[Path], object], data_dir: Path):
        self.store = store
        self.default_svc = default_svc
        self._factory = factory
        self._dir = Path(data_dir) / "orgs"
        self._services: dict[str, object] = {}
        self._lock = threading.Lock()

    def service(self, org_id: str):
        if org_id == DEFAULT_ORG:
            return self.default_svc
        if not valid_org_id(org_id) or not self.store.exists(org_id):
            raise TenancyError("組織が見つかりません")
        with self._lock:
            svc = self._services.get(org_id)
            if svc is None:
                d = self._dir / org_id
                d.mkdir(parents=True, exist_ok=True)
                os.chmod(d, 0o700)
                svc = self._factory(d)
                self._services[org_id] = svc
            return svc

    def loaded(self) -> list:
        with self._lock:
            return [self.default_svc, *self._services.values()]

    def close_all(self) -> None:
        with self._lock:
            for svc in self._services.values():
                try:
                    svc.close()
                except Exception:   # noqa: BLE001 - closing the rest matters more
                    pass
