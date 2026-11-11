"""Authorized, non-destructive reproduction probe worker.

Runs inside the `egress_sentinel` sandbox and connects ONLY to the Gateway-pinned
(ip, port). Two modes:

1. Local lab checks (`CHECKS` below): fixed paths and markers of the bundled
   simulated lab. They never read credentials or overrides from the environment.

2. Rule-driven L2 authorization checks (`--rule-json`): the rule comes from a
   service profile (`aegis/l2_profiles/*.json`) chosen by the control plane.
   This file knows nothing about any particular target API.

   Per-call environment, set by the Gateway for one approved run only:
     * `VULNIX_L2_TOKENS`  JSON {token_key: value} - only the keys this rule needs.
     * `VULNIX_L2_PATHS`   JSON {path_key: path}   - operator overrides of rule paths.

   A rule lists positive-control `preconditions` (e.g. the owner can read the mock
   resource, the subject account is authenticated). They run first. If any of them
   fails, the cross-account request is NOT sent and the verdict is "unverified":
   a denial observed without a passing control would not distinguish an enforced
   boundary from a wrong path, missing mock data or a rejected token.
   "not_reproduced" additionally requires the subject response to match every
   `denied` condition (status AND content) and to differ from the owner response.

Only GET requests are sent, redirects are never followed, and tokens are ALWAYS
redacted (`[REDACTED_SECRET]`) in stdout/evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import socket
import ssl


CHECKS = {
    "idor": {
        "path": "/api/accounts/B/secret",
        "headers": {"X-Test-Account": "acct_A"},
        "marker": "VULNIX_LAB_IDOR_PROVEN",
    },
    "cve_2021_41773": {
        "path": "/cgi-bin/.%2e/.%2e/etc/lab-release",
        "headers": {},
        "marker": "VULNIX_LAB_PATH_TRAVERSAL_PROVEN",
    },
    "sqli": {
        "path": "/api/search?q=test%27",
        "headers": {},
        "marker": "VULNIX_LAB_SQLI_PROVEN",
    },
}

LAB_DENY = (403,)
REDACTED = "[REDACTED_SECRET]"
MAX_BODY = 262144      # bytes read per response when evaluating content conditions
EXCERPT = 4096         # characters of the subject response kept as evidence


def _scrub(obj, secrets_to_redact: list[str]):
    """Replace every occurrence of a test token anywhere in the result."""
    if isinstance(obj, str):
        for secret in secrets_to_redact:
            if secret:
                obj = obj.replace(secret, REDACTED)
        return obj
    if isinstance(obj, dict):
        return {k: _scrub(v, secrets_to_redact) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v, secrets_to_redact) for v in obj]
    return obj


def _fetch(a, path: str, headers: dict) -> dict:
    """One GET to the pinned (ip, port); never follows redirects."""
    sock = socket.create_connection((a.ip, a.port), timeout=10)
    if a.scheme == "https":
        cafile = os.environ.get("VULNIX_TEST_CA_FILE") or None
        sock = ssl.create_default_context(cafile=cafile).wrap_socket(sock, server_hostname=a.host)
    conn = http.client.HTTPConnection(a.host, a.port, timeout=10)
    conn.sock = sock
    try:
        conn.request("GET", path, headers={
            "Host": a.host, "User-Agent": "vulnix-reproduction-probe/1.0", **headers})
        r = conn.getresponse()
        raw = r.read(MAX_BODY + 1)
        ctype = r.getheader("Content-Type") or ""
    finally:
        conn.close()
    return {
        "status": r.status,
        "content_type": ctype,
        "body": raw[:MAX_BODY].decode("utf-8", "replace"),
        "sha256": hashlib.sha256(raw[:MAX_BODY]).hexdigest(),
        "bytes": min(len(raw), MAX_BODY),
        "truncated": len(raw) > MAX_BODY,
    }


def _json_field(doc, dotted: str):
    cur = doc
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


_MISSING = object()


def _match(expect: dict, obs: dict) -> dict:
    """Evaluate every condition the rule declares; one boolean per condition."""
    checks = {"status": obs["status"] in expect["status"]}
    if "content_type" in expect:
        checks["content_type"] = obs["content_type"].lower().startswith(expect["content_type"].lower())
    if "body_contains" in expect:
        checks["body_contains"] = all(m in obs["body"] for m in expect["body_contains"])
    if "body_not_contains" in expect:
        # absence can only be asserted over a response that was read completely
        checks["body_not_contains"] = (not obs["truncated"]
                                       and not any(m in obs["body"] for m in expect["body_not_contains"]))
    if "json_fields" in expect:
        try:
            doc = json.loads(obs["body"])
        except ValueError:
            doc = None
        checks["json_fields"] = all(_json_field(doc, k) == v for k, v in expect["json_fields"].items())
    return checks


def _env_json(name: str) -> dict:
    try:
        val = json.loads(os.environ.get(name) or "{}")
    except ValueError:
        return {}
    return {k: v for k, v in val.items() if isinstance(v, str) and v} if isinstance(val, dict) else {}


def run_lab_check(a) -> dict:
    spec = CHECKS[a.check]
    obs = _fetch(a, spec["path"], spec["headers"])
    raw_body = obs["body"][:EXCERPT]
    try:
        parsed_body = json.loads(raw_body)
    except ValueError:
        parsed_body = None
    established = obs["status"] == 200 and spec["marker"] in raw_body
    reason = None
    if established:
        verdict = "proven"
    elif obs["status"] not in LAB_DENY:
        verdict = "unverified"
        reason = f"HTTP {obs['status']} is not an accepted denial for this check {list(LAB_DENY)}"
    else:
        verdict = "not_reproduced"
    return {
        "check": a.check,
        "request_path": spec["path"],
        "request_headers": dict(spec["headers"]),
        "status": obs["status"],
        "established": established,
        "verdict": verdict,
        "unverified_reason": reason,
        "deny_statuses": list(LAB_DENY),
        "response": parsed_body if parsed_body is not None else raw_body,
        "connected_ip": a.ip,
        "connected_port": a.port,
    }


def run_rule_check(a, rule_json: str) -> dict:
    rule = json.loads(rule_json)
    if rule.get("id") != a.check:
        raise SystemExit("rule id does not match --check")
    tokens = _env_json("VULNIX_L2_TOKENS")
    overrides = _env_json("VULNIX_L2_PATHS")
    secrets_to_redact = list(tokens.values())

    def path_of(node: dict) -> str:
        return overrides.get(node["path_key"]) or node["path"]

    def send(node: dict) -> tuple[dict | None, str | None]:
        token = tokens.get(node["token"])
        if not token:
            return None, "token not provided"
        try:
            return _fetch(a, path_of(node), {**node["headers"], "Authorization": f"Bearer {token}"}), None
        except (OSError, http.client.HTTPException) as e:
            return None, f"request failed: {type(e).__name__}"

    pre_out: list[dict] = []
    owner_hashes: set[str] = set()
    for pre in rule["preconditions"]:
        entry = {"name": pre["name"], "token": pre["token"], "request_path": path_of(pre),
                 "performed": False, "ok": False}
        obs, err = send(pre)
        if obs is None:
            entry["reason"] = err
        else:
            checks = _match(pre["expect"], obs)
            entry.update(performed=True, status=obs["status"], content_type=obs["content_type"],
                         body_sha256=obs["sha256"], body_bytes=obs["bytes"],
                         truncated=obs["truncated"], checks=checks, ok=all(checks.values()))
            if entry["ok"] and pre["token"] != rule["subject"]["token"]:
                owner_hashes.add(obs["sha256"])
        pre_out.append(entry)

    subj = rule["subject"]
    logged_headers = {**subj["headers"], "Authorization": f"Bearer {REDACTED}"}
    out = {
        "check": a.check,
        "rule_id": rule["id"],
        "rule_digest": hashlib.sha256(rule_json.encode("utf-8")).hexdigest(),
        "request_path": path_of(subj),
        "request_headers": logged_headers,
        "preconditions": pre_out,
        "deny_statuses": list(rule["denied"]["status"]),
        "connected_ip": a.ip,
        "connected_port": a.port,
    }
    reasons: list[str] = [f"precondition_failed:{p['name']}" for p in pre_out if not p["ok"]]
    obs = err = None
    if not reasons:
        obs, err = send(subj)
        if obs is None:
            reasons.append(f"subject_request_not_performed:{err}")
    else:
        reasons.append("subject_request_not_performed:preconditions")

    if obs is None:
        out.update(status=None, established=False, verdict="unverified", unverified_reasons=reasons,
                   subject={"performed": False, "token": subj["token"]},
                   response=None, response_text="")
        return _scrub(out, secrets_to_redact)

    exposed_checks = _match(rule["exposed"], obs)
    denied_checks = _match(rule["denied"], obs)
    identical = obs["sha256"] in owner_hashes
    established = all(exposed_checks.values())
    if established:
        verdict = "proven"
    elif all(denied_checks.values()) and not identical and not obs["truncated"]:
        verdict = "not_reproduced"
    else:
        verdict = "unverified"
        if not denied_checks["status"]:
            reasons.append(f"status_not_a_denial:{obs['status']}")
        elif not all(denied_checks.values()):
            reasons.append("denial_content_mismatch")
        if identical:
            reasons.append("response_identical_to_owner")
        if obs["truncated"]:
            reasons.append("response_truncated")

    excerpt = obs["body"][:EXCERPT]
    try:
        parsed = json.loads(excerpt)
    except ValueError:
        parsed = None
    out.update(
        status=obs["status"], established=established, verdict=verdict,
        unverified_reasons=reasons,
        subject={"performed": True, "token": subj["token"], "content_type": obs["content_type"],
                 "body_sha256": obs["sha256"], "body_bytes": obs["bytes"], "truncated": obs["truncated"],
                 "identical_to_control": identical,
                 "denied_checks": denied_checks, "exposed_checks": exposed_checks},
        response=parsed if parsed is not None else excerpt,
        response_text=excerpt,
    )
    return _scrub(out, secrets_to_redact)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--scheme", required=True, choices=["http", "https"])
    p.add_argument("--host", required=True)
    p.add_argument("--ip", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--check", required=True)
    p.add_argument("--rule-json", default="")
    a = p.parse_args()

    if a.rule_json:
        result = run_rule_check(a, a.rule_json)
    elif a.check in CHECKS:
        result = run_lab_check(a)
    else:
        raise SystemExit(f"unknown check {a.check!r} (no built-in lab check and no rule supplied)")
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
