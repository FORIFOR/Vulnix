"""Presentation-only evidence classification. Never grants execution authority."""

EVIDENCE_LABELS = {
    "candidate": "未計測の候補",
    "detected": "検出・未実証",
    "proven": "実証済み",
    "not_reproduced": "再現せず",
    "incomplete": "未完了・要確認",
    "fixture": "架空データ",
}


def l2_reproduction_recorded(finding: dict) -> bool:
    """True only when a recorded L2 run (`reproduction_probe`) is part of the evidence."""
    return any(isinstance(e, dict) and e.get("tool") == "reproduction_probe"
               and e.get("audit_hash") and e.get("saved_at") is not None
               for e in finding.get("evidence") or [])


def enforce_verdict(finding: dict) -> dict:
    """`proven` is reserved for a recorded L2 reproduction.

    A read-only L1 observation (a header, TLS, cookie or CORS check) shows that
    something is configured in a way that may be a weakness; it does not
    reproduce one. Whatever produced it, such a finding is stored and shown as
    `detected`. Demo fixtures are labelled as fixtures and left as they are."""
    if (finding.get("verdict") == "proven" and not finding.get("demo_fixture")
            and not l2_reproduction_recorded(finding)):
        out = {**finding, "verdict": "detected", "verdict_basis": "l1_observation"}
        if "risk_score" in finding or "risk_rationale" in finding:
            # the stored score was computed with the "proven" factor: recompute it
            from .service_diag import compute_finding_risk_score
            target = next((str(e.get("target_url") or "") for e in reversed(finding.get("evidence") or [])
                           if isinstance(e, dict) and e.get("target_url")), "")
            out["risk_score"], out["risk_rationale"] = compute_finding_risk_score(
                str(finding.get("severity") or "medium"), "detected", kev=bool(finding.get("kev")),
                internet_facing=target.lower().startswith("https://"))
        finding = out
    evs = finding.get("evidence")
    if isinstance(evs, list) and evs:
        import json
        from .service_diag import sanitize_http_probe_payload
        cleaned_evs = []
        changed = False
        for ev in evs:
            if (isinstance(ev, dict) and ev.get("tool") == "http_probe"
                    and isinstance(ev.get("content"), str) and ev["content"].strip()):
                try:
                    parsed = json.loads(ev["content"])
                except (TypeError, ValueError):
                    parsed = None
                if isinstance(parsed, dict) and (
                    "set_cookies" in parsed
                    or (isinstance(parsed.get("headers"), dict)
                        and any(str(k).lower() in ("set-cookie", "set-cookie2") for k in parsed["headers"]))
                ):
                    sanitized = sanitize_http_probe_payload(parsed)
                    new_content = json.dumps(sanitized, ensure_ascii=False)
                    if new_content != ev["content"]:
                        ev = {**ev, "content": new_content}
                        changed = True
            cleaned_evs.append(ev)
        if changed:
            finding = {**finding, "evidence": cleaned_evs}
    return finding


def evidence_status(finding: dict) -> str:
    if finding.get("demo_fixture"):
        return "fixture"
    if finding.get("verdict") == "candidate":
        return "candidate"
    if finding.get("verdict") in {"aborted", "unverified"}:
        return "incomplete"
    # A pre-populated candidate or unattached example is not a measured finding.
    recorded = any(e.get("audit_hash") and e.get("saved_at") is not None
                   for e in finding.get("evidence", []))
    if not recorded:
        return "candidate"
    verdict = enforce_verdict(finding).get("verdict")
    return verdict if verdict in {"detected", "proven", "not_reproduced"} else "incomplete"


def evidence_summary(findings: list[dict]) -> dict:
    counts = dict.fromkeys(EVIDENCE_LABELS, 0)
    for finding in findings:
        counts[evidence_status(finding)] += 1
    return counts


# Built-in checks of the bundled local lab only. Authorization checks against a
# real service are defined by service profiles and judged by `aegis.l2_rules`.
REPRODUCTION_MARKERS = {
    "idor": "VULNIX_LAB_IDOR_PROVEN",
    "sqli": "VULNIX_LAB_SQLI_PROVEN",
    "cve_2021_41773": "VULNIX_LAB_PATH_TRAVERSAL_PROVEN",
}

# HTTP statuses that count as an observed denial in the lab.
REPRODUCTION_DENY_STATUSES = {
    "idor": (403,),
    "sqli": (403,),
    "cve_2021_41773": (403,),
}


# The lab's fixed IDOR request: the Worker (aegis/workers/reproduction_probe.py CHECKS) sends
# it as acct_A with this header, and sends the owner control as acct_B. Both values are fixed
# in Vulnix's own code; the target never chooses who the request was sent as.
LAB_IDOR_PATH = "/api/accounts/B/secret"
LAB_IDOR_REQUESTER = {"X-Test-Account": "acct_A"}
LAB_IDOR_OWNER = {"account": "acct_B", "resource_id": "res_b_001"}


def normalised_texts(body) -> list[str]:
    """The answer as lower-case text, also with HTML entities, %-escapes, JSON escapes and
    JavaScript \\uXXXX escapes undone. Shared by the judge's absence rule ("an identifier
    hidden by an encoding still counts as present") and the owner-record match below."""
    import html
    import json
    import re
    from urllib.parse import unquote
    if isinstance(body, str):
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        raw = [body] + ([json.dumps(parsed, ensure_ascii=False)] if isinstance(parsed, (dict, list)) else [])
    else:
        raw = [json.dumps(body, ensure_ascii=False)]
    out = []
    for t in raw:
        js = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), t)   # JavaScript \uXXXX
        js = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), js)  # \xHH
        out += [t, html.unescape(t), unquote(t), unquote(html.unescape(t)), js, html.unescape(js)]
    return [t.lower() for t in out]


def _has_token(texts: list[str], needle: str) -> bool:
    """`needle` appears as a whole identifier (not inside a longer one: res_b_0012,
    VULNIX_LAB_IDOR_PROVEN_EXAMPLE) in one of the normalised texts."""
    import re
    pat = re.compile(r"(?<![0-9a-z_-])" + re.escape(needle.lower()) + r"(?![0-9a-z_-])")
    return any(pat.search(t) for t in texts)


def _lab_idor_control(result: dict) -> dict | None:
    """B's own control answer in the same Worker run, when the Worker established it."""
    owner = result.get("control_response")
    if (result.get("control_status") != 200
            or result.get("control_verified") is not True
            or not isinstance(owner, dict)
            or owner.get("Check") != "idor_cross_account_access"
            or owner.get("caller_account") != LAB_IDOR_OWNER["account"]
            or owner.get("resource_owner") != LAB_IDOR_OWNER["account"]
            or owner.get("resource_id") != LAB_IDOR_OWNER["resource_id"]
            or owner.get("confidential_marker") != REPRODUCTION_MARKERS["idor"]):
        return None
    return owner


def _key(k) -> str:
    return "".join(ch for ch in str(k).lower() if ch.isalnum())


_ID_KEYS = frozenset({"id", "resourceid", "recordid"})


def _scalar_is(value, wanted: str) -> bool:
    return isinstance(value, str) and any(t.strip() == wanted.lower() for t in normalised_texts(value))


def _names_only(value, wanted: str) -> bool:
    """An owner field names `wanted` and nothing else - also when it holds an object or a
    list (every string inside it must be `wanted`; numbers or other names fail)."""
    if isinstance(value, dict):
        value = list(value.values())
    if isinstance(value, list):
        leaves = []
        stack = list(value)
        while stack:
            v = stack.pop()
            if isinstance(v, dict):
                stack.extend(v.values())
            elif isinstance(v, list):
                stack.extend(v)
            else:
                leaves.append(v)
        return bool(leaves) and all(_scalar_is(v, wanted) for v in leaves)
    return _scalar_is(value, wanted)


def _record_paths(node, ancestors=()):
    """(dict, its ancestor dicts) for every dict in a parsed JSON answer."""
    if isinstance(node, dict):
        yield node, ancestors
        for v in node.values():
            yield from _record_paths(v, ancestors + (node,))
    elif isinstance(node, list):
        for v in node:
            yield from _record_paths(v, ancestors)


def owner_record_read_by_other_account(result: dict | None) -> bool:
    return _owner_record_match(result, whole=isinstance(result, dict) and result.get("response_truncated") is False)


def _owner_record_match(result: dict | None, *, whole: bool) -> bool:
    """Another account read the owner's record, decided only from what Vulnix measured
    (docs/evaluation/JUDGE_IDENTITY_MATCH.md, FAILURE_ANALYSIS.md 案2). Never from the
    answer's own words about who asked (caller_account, Check, established).

    All of these, for the lab's fixed IDOR check:
      * the Worker sent the request as acct_A (its fixed request path and header);
      * B's own control was established in the same Worker run;
      * A got HTTP 200 and the Worker kept the whole body (response_truncated is False);
      * the answer carries BOTH the control's resource id AND its confidential marker, each
        as a whole identifier, after the same normalisations the absence rule uses (case,
        HTML entities, %-escapes, JSON escapes, JavaScript \\uXXXX);
      * the answer does not present itself as another resource or as A's own:
          - JSON: one object holds both identifiers; in that object an id field (id,
            resource_id, record_id, any case) names only B's resource, and every owner field
            ("owner" in the key) in it, below it or in the objects around it names B;
          - HTML / text (no structure to read): the answer does not name acct_A at all.
    A base64 or otherwise re-encoded record does not match (stays undecided)."""
    import json
    if not isinstance(result, dict) or result.get("check") != "idor":
        return False
    if result.get("request_path") != LAB_IDOR_PATH or result.get("request_headers") != LAB_IDOR_REQUESTER:
        return False
    owner = _lab_idor_control(result)
    if owner is None or result.get("status") != 200 or not whole:
        return False
    rid, marker, b = owner["resource_id"], owner["confidential_marker"], owner["resource_owner"]
    requester = LAB_IDOR_REQUESTER["X-Test-Account"]
    response = result.get("response")
    parsed = response
    if isinstance(response, str):
        try:
            parsed = json.loads(response)
        except ValueError:
            parsed = response
    if isinstance(parsed, (dict, list)):
        holders = [(d, anc) for d, anc in _record_paths(parsed)
                   if _has_token(t := normalised_texts(d), rid) and _has_token(t, marker)]
        # the smallest objects that hold both: no object inside them holds both
        records = [(d, anc) for d, anc in holders
                   if not any(o is not d and any(a is d for a in oanc) for o, oanc in holders)]
        if not records:
            return False
        for d, anc in records:
            # the record itself carries both identifiers as whole field values (not inside a
            # string blob - JSON in a string, prose - nor spread over separate list items)
            values = [v for v in d.values() if not isinstance(v, (dict, list))]
            if not (any(_scalar_is(v, rid) for v in values) and any(_scalar_is(v, marker) for v in values)):
                return False
            if any(_key(k) in _ID_KEYS and not _scalar_is(v, rid) for k, v in d.items()):
                return False
            around = list(anc) + [o for o, _ in _record_paths(d)]
            if any("owner" in _key(k) and not _names_only(v, b) for o in around for k, v in o.items()):
                return False
        return True
    if not isinstance(parsed, str):
        return False
    texts = normalised_texts(parsed)
    return (_has_token(texts, rid) and _has_token(texts, marker)
            and not any(requester.lower() in t for t in texts))


def reproduction_verdict(result: dict | None, check: str, rule: dict | None = None,
                         worker_rule: dict | None = None) -> str:
    """Require the observed result and the worker verdict to agree.

    `rule`/`worker_rule` are given for profile-defined L2 checks; those are judged
    by the rule engine (positive controls + status + response content).

    The lab IDOR check is "proven" only when the Worker's own verdict, the answer's fixed
    shape AND the measured owner-record match (owner_record_read_by_other_account) all
    agree, so a finding never becomes 実証成功 on a weaker test than the diagnosis judge
    uses for "supported" (docs/evaluation/JUDGE_IDENTITY_MATCH.md)."""
    import json
    if worker_rule is not None:
        from .l2_rules import evaluate
        return evaluate(worker_rule, result)["verdict"]
    if not result or result.get("check") != check or check not in REPRODUCTION_MARKERS:
        return "unverified"
    if check == "idor":
        if (result.get("request_path") != LAB_IDOR_PATH
                or result.get("request_headers") != LAB_IDOR_REQUESTER):
            return "unverified"
        response = result.get("response")
        if _lab_idor_control(result) is None:
            return "unverified"
        if (not isinstance(response, dict)
                or response.get("Check") != "idor_cross_account_access"
                or response.get("established") is not True
                or response.get("caller_account") != "acct_A"
                or response.get("resource_owner") != "acct_B"
                or response.get("resource_id") != "res_b_001"
                or response.get("confidential_marker") != REPRODUCTION_MARKERS["idor"]
                # a Worker result always says whether it kept the whole body; an older result
                # without the flag is accepted only as before: a dict parsed from the excerpt is
                # a complete JSON document
                or not _owner_record_match(result, whole=result.get("response_truncated") is not True)):
            if (result.get("status") in REPRODUCTION_DENY_STATUSES["idor"]
                    and result.get("established") is False
                    and result.get("verdict") == "not_reproduced"):
                return "not_reproduced"
            return "unverified"
    if (result.get("status") == 200 and result.get("established") is True
            and result.get("verdict") == "proven"
            and REPRODUCTION_MARKERS[check] in json.dumps(result.get("response"))):
        return "proven"
    if (result.get("status") in REPRODUCTION_DENY_STATUSES[check]
            and result.get("established") is False
            and result.get("verdict") == "not_reproduced"):
        return "not_reproduced"
    return "unverified"


def reproduction_note(result: dict | None, check: str, rule: dict | None = None,
                      worker_rule: dict | None = None) -> str:
    if worker_rule is not None and rule is not None:
        from .l2_rules import evaluate, explain
        return explain(rule, result, evaluate(worker_rule, result))
    verdict = reproduction_verdict(result, check)
    status = (result or {}).get("status", "応答なし")
    if verdict == "proven":
        return f"HTTP {status} 応答に検証用マーカーを確認しました。防御を確認できていません。"
    if verdict == "not_reproduced":
        return f"同じ検証に対して HTTP {status} が返り、今回の条件でアクセスが拒否されたことを確認しました。"
    return f"修正確認できず（HTTP {status}）。応答と判定が不明または一致しないため、再現せずとは判定しません。"
