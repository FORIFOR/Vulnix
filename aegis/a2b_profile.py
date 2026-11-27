"""Build an L2 authorization profile for an app's backend API (A2B) from what the user picked
in the browser - no hand-written JSON.

The browser reads an OpenAPI / Swagger file or the project's route definitions (nothing is
sent anywhere while it does), proposes candidate checks, and asks the user only for what an
API definition cannot say: which test account owns which test record, a unique marker string
inside each test record, and how the API answers a refused request. This module turns that
draft into the same profile format the bundled profiles use and validates it with the same
`validate_profile`.

What it never does:
- guess a marker, an owner or a denial status: a check whose facts the user did not confirm
  is written as a `placeholder` (listed, never runnable);
- make anything runnable on its own: the file lands in the site-profile directory, where an
  admin must accept its exact content (SHA-256) before the Gateway offers it, and every run
  still needs a verified asset, stored test accounts and a per-item approval.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from .l2_rules import RuleError, validate_profile

ROLES = {
    "subject": "一般利用者A（試す側）",
    "same_org": "同じ組織の利用者B",
    "other_org": "別組織の利用者C",
    "admin": "同じ組織の管理者",
}
KINDS = {
    "cross_account": {
        "owner": "same_org", "label": "同じ組織の他人のデータ",
        "title": "同じ組織の他人のデータへのアクセス（BOLA）",
        "step": "データを返すAPIで、トークンの利用者と資源の所有者をサーバー側で照合する"},
    "cross_tenant": {
        "owner": "other_org", "label": "別組織のデータ",
        "title": "別組織のデータへのアクセス（組織分離）",
        "step": "資源の組織と、トークンの利用者が属する組織をサーバー側で照合する"},
    "admin_function": {
        "owner": "admin", "label": "管理者専用の機能",
        "title": "一般利用者による管理者専用機能の実行（権限昇格）",
        "step": "管理者専用のAPIで、利用者の役割をサーバー側で確認する"},
}
_PATH_RE = re.compile(r"/[A-Za-z0-9/_.~:@!$&'()*+,;=%-]{0,255}")
_MARKER_RE = re.compile(r"[A-Za-z0-9_.:-]{8,128}")
_SLUG_RE = re.compile(r"[^a-z0-9]+")
_EVIDENCE_MAX = 300


class DraftError(ValueError):
    pass


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise DraftError(msg)


def _path(value, what: str) -> str:
    _need(isinstance(value, str) and _PATH_RE.fullmatch(value) is not None and "//" not in value
          and "/../" not in value + "/" and "{" not in value,
          f"{what} は「/」で始まる実際のパス（{{id}} などを実在の試験データの値に置き換えたもの）を入力してください")
    return value


def _marker(value, what: str) -> str:
    _need(isinstance(value, str) and _MARKER_RE.fullmatch(value) is not None,
          f"{what} は試験データにだけ含まれる 8〜128 文字の英数字の目印を入力してください")
    return value


def slug(text: str) -> str:
    return (_SLUG_RE.sub("_", (text or "").lower()).strip("_") or "api")[:40]


def build_profile(draft: dict) -> dict:
    """The profile JSON for `draft` (as the browser sends it). Raises DraftError on anything
    the user has to correct; the result also passes `validate_profile`."""
    _need(isinstance(draft, dict), "入力が不正です")
    name = str(draft.get("name") or "").strip()[:80]
    _need(bool(name), "API の名前を入力してください")
    host = str(draft.get("host") or "").strip().lower()
    _need(re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?", host) is not None,
          "対象のホスト名（例: api.example.com）を入力してください")
    pid = f"a2b_{slug(name)}"
    requested = draft.get("denied_status") or [403]
    _need(isinstance(requested, list) and 401 not in requested,
          "401 は試験用トークンの失効と区別できないため、拒否としては使えません")
    denied_status = sorted({s for s in requested if isinstance(s, int) and not isinstance(s, bool) and s in (403, 404)})
    _need(bool(denied_status), "拒否のときの応答（403 または 404）を選んでください")
    own_path = _path(draft.get("own_path"), "試す側が自分で取得できるデータのパス")
    own_marker = _marker(draft.get("own_marker"), "試す側のデータの目印")
    admin_same = bool(draft.get("admin_is_same_org"))

    checks_in = draft.get("checks")
    _need(isinstance(checks_in, list) and 0 < len(checks_in) <= 20, "確認する項目を1つ以上選んでください")
    paths = {"own_path": {"label": "試す側が自分で取得できるデータ", "default": own_path}}
    roles_used = {"subject"}
    checks = []
    seen = set()
    for i, raw in enumerate(checks_in):
        _need(isinstance(raw, dict) and raw.get("kind") in KINDS, "確認する項目の種類が不正です")
        kind = raw["kind"]
        _need(kind not in seen, "同じ種類の項目は1つまでです")
        seen.add(kind)
        meta = KINDS[kind]
        owner_role = "same_org" if kind == "admin_function" and admin_same else meta["owner"]
        roles_used.add(owner_role)
        target = _path(raw.get("path"), f"「{meta['label']}」の対象パス")
        _need(target != own_path, f"「{meta['label']}」の対象は、試す側自身のデータとは別のパスにしてください")
        marker = _marker(raw.get("marker"), f"「{meta['label']}」のデータの目印")
        _need(marker != own_marker, f"「{meta['label']}」の目印は、試す側のデータの目印と別にしてください")
        evidence = [str(e)[:_EVIDENCE_MAX] for e in (raw.get("evidence") or []) if isinstance(e, str) and e.strip()][:5]
        confirmed = bool(raw.get("confirmed")) and bool(evidence)
        path_key = f"{kind}_path"
        paths[path_key] = {"label": f"{meta['label']}（{ROLES[owner_role]}が所有）", "default": target}
        checks.append({
            "id": f"{pid}_{kind}"[:64], "category": "idor", "label": meta["label"],
            "spec_status": "confirmed" if confirmed else "placeholder",
            "spec_evidence": evidence + (["利用者が試験データの所有者・目印・拒否時の応答を画面で確認"] if confirmed else []),
            "spec_note": ("API 定義と利用者の確認による。管理者が内容を承認するまで実行されない。" if confirmed
                          else "未確認の候補。所有者・目印・拒否時の応答を確認するまで実行できない。"),
            "finding": {"id": f"f_{pid}_{kind}"[:64], "title": meta["title"], "severity": "high",
                        "category": "A2B（API認可・組織分離）", "help_term": "idor",
                        "summary": f"{meta['title']}を、試験用トークンと試験データで確認します。",
                        "impact": "アプリが呼ぶAPIで、他人や他組織のデータ・管理機能に到達される恐れがあります。",
                        "steps": [meta["step"]],
                        "how_to_verify": "正当な利用者は取得でき、権限のないトークンは拒否され、応答に対象の試験データの目印が含まれないことを同じ実行内で確認します。"},
            "subject": {"token": "subject_token", "path": path_key, "headers": {}},
            "preconditions": [
                {"name": "owner_access", "label": f"{ROLES[owner_role]}が取得できる", "token": f"{owner_role}_token",
                 "path": path_key, "expect": {"status": [200], "body_contains": [marker]}},
                {"name": "subject_authenticated", "label": "試す側が自分のデータを取得できる",
                 "token": "subject_token", "path": "own_path",
                 "expect": {"status": [200], "body_contains": [own_marker]}},
            ],
            "denied": {"status": denied_status, "body_not_contains": [marker]},
            "exposed": {"status": [200], "body_contains": [marker]},
        })
    tokens = {f"{r}_token": {"label": ROLES[r]} for r in ROLES if r in roles_used}
    keys = sorted(tokens)
    profile = {
        "id": pid, "label": f"{name}（A2B: API認可・組織分離）",
        "spec_note": f"画面で作成した下書き（{str(draft.get('source') or 'API定義')[:120]}）。管理者の承認まで実行されない。",
        "applies_to": {"hosts": [host]},
        "tokens": tokens,
        "distinct_tokens": [[a, b] for i, a in enumerate(keys) for b in keys[i + 1:]],
        "paths": paths, "checks": checks,
    }
    try:
        validate_profile(json.loads(json.dumps(profile)), f"{pid}.json")
    except RuleError as exc:
        raise DraftError(f"プロファイルを作れません: {exc}") from None
    return profile


def save_site_profile(data_dir: Path, profile: dict) -> Path:
    """Write the profile into `<data_dir>/l2_profiles/` with owner-only permissions (what the
    site-profile loader requires). Replacing a file changes its SHA-256, so an earlier
    acceptance no longer covers it."""
    d = Path(data_dir) / "l2_profiles"
    d.mkdir(mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    target = d / f"{profile['id']}.json"
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".draft-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(profile, fh, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return target


__all__ = ["DraftError", "KINDS", "ROLES", "build_profile", "save_site_profile", "slug"]
