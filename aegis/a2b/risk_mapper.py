"""Candidate risk classes for statically found endpoints - never a verdict.

Every candidate says what may happen next, and that is always gated:
- nothing happens before the host passed ownership verification and scope approval;
- on a real site only the existing read-only L1 GET may follow (no L2, by policy);
- the IDOR (BOLA) reproduction exists only in the isolated lab with test accounts;
- SSRF, SQL injection and similar classes are listed for a person to review: the
  initial A2B release has no executable check for them.
"""
from __future__ import annotations

import re

from .endpoint_inventory import Endpoint

CLASSES = {
    "bola_candidate": "利用者ごとの資源を ID で指定する API です。他人の資源を取得できないかの確認候補です。",
    "auth_candidate": "管理・内部向けに見える API です。認証が必須かどうかの確認候補です。",
    "ssrf_candidate": "URL を受け取る引数があります。サーバーが任意の宛先へ通信しないかを人が確認する候補です。",
    "injection_candidate": "検索や絞り込みの引数があります。入力の扱いを人が確認する候補です。",
    "unauth_access_candidate": "アプリ側に認証の手掛かりが見つからない API です。未認証で何が返るかの確認候補です。",
}
_ID_PATH = re.compile(r"/(?:users?|accounts?|orders?|profiles?|invoices?|payments?|customers?|me)\b.*\{param\}", re.I)
_ADMIN = re.compile(r"/(?:admin|internal|debug|manage|staff)\b", re.I)
_URL_PARAMS = frozenset({"url", "uri", "callback", "redirect", "redirect_uri", "return_url", "next", "target",
                         "webhook", "image_url", "feed"})
_QUERY_PARAMS = frozenset({"q", "query", "search", "filter", "sort", "order", "where", "keyword"})


def map_risks(endpoints: list[Endpoint], *, auth_hints: set[str], verified_hosts=()) -> list[dict]:
    verified = {h.lower() for h in verified_hosts}
    out = []
    for e in endpoints:
        classes = []
        if _ID_PATH.search(e.path):
            classes.append("bola_candidate")
        if _ADMIN.search(e.path):
            classes.append("auth_candidate")
        params = {p.lower() for p in e.query_params}
        if params & _URL_PARAMS:
            classes.append("ssrf_candidate")
        if params & _QUERY_PARAMS:
            classes.append("injection_candidate")
        if not auth_hints and e.method in ("GET", "UNKNOWN"):
            classes.append("unauth_access_candidate")
        if not classes:
            continue
        owned = bool(e.host) and e.host in verified
        for c in classes:
            if not e.host:
                gate, follow = "host_unknown", "none"
            elif not owned:
                gate, follow = "ownership_verification_required", "none"
            elif c in ("unauth_access_candidate", "auth_candidate") and e.method in ("GET", "UNKNOWN"):
                gate, follow = "scope_approval_required", "existing_l1_read_only_get"
            elif c == "bola_candidate":
                gate, follow = "scope_approval_required", "isolated_lab_l2_idor_only"
            else:
                gate, follow = "manual_review_only", "none"
            out.append({"class": c, "status": "candidate", "explanation_ja": CLASSES[c],
                        "endpoint": e.to_dict(), "gate": gate, "allowed_followup": follow,
                        "auto_contact": False})
    return sorted(out, key=lambda r: (r["endpoint"]["host"] or "~", r["endpoint"]["path"],
                                      r["endpoint"]["method"], r["class"]))
