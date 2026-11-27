"""AI advisor (phase 1, mock only): allow-listed input, validated output, no path to a worker."""
from __future__ import annotations

import ast
import contextlib
import dataclasses
import hashlib
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis import ai_advisor as adv
from aegis.audit import AuditLog
from aegis.abliteration_server import start_abliteration_server
from aegis.router import AbliterationBackend, sanitize_proposal
from tests.test_real_service import HOST, RealServiceBase

ROOT = Path(__file__).resolve().parents[1]

SECRET_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLWEifQ.c2lnbmF0dXJlLXZhbHVl"
COOKIE = "sid=7f3a9c0d2b8e4f1a6c5d3e2f1a0b9c8d"


def _leaky_finding(fid="f_l1_cors", **over) -> dict:
    """A finding shaped like the analyzer's, carrying every kind of data that must stay local."""
    f = {
        "id": fid, "title": "CORS設定の過剰な許可（Access-Control-Allow-Origin: https://evil.example）",
        "severity": "medium", "verdict": "detected", "verdict_basis": "l1_observation",
        "category": "CORS・オリジン境界", "cve": ["CVE-2021-41773", "not-a-cve <script>"], "risk_score": 41.6,
        "summary": f"https://{HOST}/api/me が Origin を反映しました", "why_detected": "user@example.com の応答",
        "evidence": [{"origin": "real_service", "target_url": f"https://{HOST}/api/me", "tool": "http_probe",
                      "headers": {"Set-Cookie": COOKIE, "Authorization": f"Bearer {SECRET_TOKEN}"},
                      "body_prefix": '{"email":"user@example.com","ip":"203.0.113.7"}'}],
        "remediation": {"steps": ["内部URL http://10.0.0.5:8080/admin を閉じる"]},
        "asset": {"challenge": {"token": "vulnix-verify=abc"}},
    }
    f.update(over)
    return f


def _advice_reply(items) -> callable:
    return lambda user: "```json\n" + json.dumps({"advice": items}, ensure_ascii=False) + "\n```"


def _rem(detail, fix="restrict_cors_allowlist") -> dict:
    return {"fix": fix, "detail": detail}


def _chk(purpose="confirm_fix", operation="l1_recheck_cors_policy") -> dict:
    return {"operation": operation, "purpose": purpose}


def _txt(text, operation="l1_recheck_cors_policy") -> dict:
    """A next check that tries to carry the model's own words (v1 style)."""
    return {"operation": operation, "purpose": "confirm_fix", "reason": text}


def _ok_item(ref="F1", **over) -> dict:
    item = {"ref": ref, "claim_level": "observed", "cites": ["rule", "verdict"],
            "risk_explanation": "オリジンの許可が広く、ほかのサイトから応答を読まれる可能性があります。",
            "remediation": [_rem("許可するオリジンを明示的な一覧に限定する")],
            "next_checks": [_chk()]}
    item.update(over)
    return item


class _MockServer:
    def __init__(self, reply=None):
        self.srv = start_abliteration_server(advisor_reply=reply)
        self.url = f"http://127.0.0.1:{self.srv.server_port}/v1/chat/completions"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.srv.shutdown()
        self.srv.server_close()


class TestPayloadIsAnAllowList(unittest.TestCase):
    def test_only_enumerations_and_an_opaque_ref_are_sent(self):
        with _MockServer() as m:
            adv.AbliterationAdvisor(m.url).advise([_leaky_finding()])
            self.assertEqual(len(m.srv.received), 1)
            raw = json.dumps(m.srv.received[0], ensure_ascii=False)
        for secret in (HOST, "evil.example", SECRET_TOKEN, COOKIE, "user@example.com", "203.0.113.7",
                       "10.0.0.5", "/api/me", "/admin", "vulnix-verify", "Bearer", "<script>", "CORS設定の過剰な許可"):
            self.assertNotIn(secret, raw, secret)
        user = json.loads(m.srv.received[0]["messages"][1]["content"])
        self.assertEqual(user, {"findings": [{
            "ref": "F1", "rule": "f_l1_cors", "category": "CORS・オリジン境界", "severity": "medium",
            "verdict": "detected", "verdict_basis": "l1_observation", "cve": ["CVE-2021-41773"],
            "risk_score": 42, "kev": False}]})

    def test_unknown_values_fall_back_to_fixed_words(self):
        item = adv.finding_to_payload_item("F1", {"id": "f_site_specific_rule", "category": "社内システムXの分類",
                                                  "severity": "urgent", "verdict": "pwned", "risk_score": float("nan")})
        self.assertEqual((item["rule"], item["category"], item["severity"], item["verdict"], item["risk_score"]),
                         ("other", "その他", "medium", "unverified", None))

    def test_audited_status_finding_has_specific_safe_japanese_advice(self):
        from aegis.service_diag import analyze_status_marker_report
        finding = analyze_status_marker_report(
            {"check_id": "apache_mod_status", "detected": True},
            {"tool": "status_marker", "audit_hash": "a" * 64,
             "target_url": "https://private.example/server-status?auto", "body_prefix": "SECRET"})
        reply = _ok_item(
            risk_explanation="Apacheの状態情報が公開されています。",
            remediation=[_rem("公開範囲から外し、管理者だけにアクセスを制限します。", "restrict_apache_status")],
            next_checks=[_chk("confirm_fix", "l1_recheck_apache_status")])
        with _MockServer(_advice_reply([reply])) as mock:
            result = adv.AbliterationAdvisor(mock.url).advise([finding])
            sent = json.dumps(mock.srv.received[0], ensure_ascii=False)
            item = json.loads(mock.srv.received[0]["messages"][1]["content"])["findings"][0]
        self.assertEqual((item["rule"], item["category"], item["verdict"]),
                         ("f_l1_apache_mod_status", "情報公開設定", "detected"))
        self.assertNotIn("private.example", sent)
        self.assertNotIn("SECRET", sent)
        self.assertEqual(len(result.advice), 1, result.rejected)
        self.assertEqual(result.advice[0].remediation[0].fix, "restrict_apache_status")

    def test_single_finding_prompt_contains_only_relevant_catalog_ids(self):
        finding = _leaky_finding("f_l1_apache_mod_status", category="情報公開設定", cve=[])
        advisor = adv.AbliterationAdvisor("http://127.0.0.1:9/v1/chat/completions")
        body, _ = advisor.build_request([finding])
        prompt = json.loads(body)["messages"][0]["content"]
        self.assertIn("restrict_apache_status", prompt)
        self.assertIn("l1_recheck_apache_status", prompt)
        self.assertNotIn("parameterize_queries", prompt)
        self.assertNotIn("l2_input_boundary_check", prompt)
        self.assertLess(len(prompt.encode("utf-8")), len(adv.SYSTEM_ADVISOR_PROMPT.encode("utf-8")))
        bad = _ok_item(remediation=[_rem("入力値をパラメータ化する", "parameterize_queries")], next_checks=[])
        accepted, rejected = adv.validate_advice({"advice": [bad]}, {"F1": finding})
        self.assertEqual(accepted, [])
        self.assertTrue(any(r["where"] == "remediation" for r in rejected))

    def test_candidate_is_never_sent_or_explained_as_detected(self):
        finding = _leaky_finding("f_sqli", verdict="candidate")
        item = adv.finding_to_payload_item("F1", finding)
        self.assertEqual(item["verdict"], "candidate")
        self.assertEqual(adv.finding_to_payload_item("F1", {"id": "f_sqli", "category": "インジェクション"})["category"],
                         "インジェクション")
        observed = _ok_item("F1", claim_level="observed",
                            remediation=[_rem("入力値をパラメータ化する", "parameterize_queries")], next_checks=[])
        accepted, rejected = adv.validate_advice({"advice": [observed]}, {"F1": finding})
        self.assertEqual(accepted, [])
        self.assertTrue(any(r["where"] == "claim_level" for r in rejected))
        suspected = _ok_item("F1", claim_level="suspected",
                             remediation=[_rem("入力値をパラメータ化する", "parameterize_queries")], next_checks=[])
        accepted, rejected = adv.validate_advice({"advice": [suspected]}, {"F1": finding})
        self.assertEqual(len(accepted), 1)
        self.assertEqual(rejected, [])
        with _MockServer() as mock:
            result = adv.AbliterationAdvisor(mock.url).advise([finding])
            sent = json.loads(mock.srv.received[0]["messages"][1]["content"])
        self.assertEqual(sent["findings"][0]["verdict"], "candidate")
        self.assertTrue(result.advice, result.rejected)
        self.assertTrue(all(a.claim_level in {"suspected", "inconclusive"} for a in result.advice))

    def test_japanese_explanation_and_remediation_use_only_cited_cves(self):
        finding = _leaky_finding()
        valid = _ok_item(cites=["rule", "verdict", "cve"],
                         risk_explanation="入力情報にはCVE-2021-41773が含まれます。")
        self.assertEqual(len(adv.validate_advice({"advice": [valid]}, {"F1": finding})[0]), 1)
        cases = [
            ({**valid, "cites": ["rule", "verdict"]}, "risk_explanation"),
            ({**valid, "risk_explanation": "ＣＶＥ－２０２４－１２３４にも注意してください。"}, "risk_explanation"),
            ({**valid, "remediation": [_rem("CVE-2024-1234に対応するため設定を見直す。")]}, "remediation"),
            ({**valid, "risk_explanation": "CVE 2024 1234 にも注意してください。"}, "risk_explanation"),
            ({**valid, "risk_explanation": "CVE\u20102024\u22121234 にも注意してください。"}, "risk_explanation"),
        ]
        for item, field in cases:
            with self.subTest(field=field):
                accepted, rejected = adv.validate_advice({"advice": [item]}, {"F1": finding})
                self.assertFalse(accepted)
                self.assertEqual(rejected[0]["where"], field)

    def test_a_payload_that_still_leaks_is_refused_before_sending(self):
        calls = []
        a = adv.AbliterationAdvisor("http://127.0.0.1:9/v1/chat/completions",
                                    transport=lambda *x: calls.append(x) or b"{}")
        orig = adv.finding_to_payload_item
        try:
            adv.finding_to_payload_item = lambda ref, f: {**orig(ref, f), "rule": "https://evil.example/x"}
            with self.assertRaises(adv.AdvisorError):
                a.advise([_leaky_finding()])
        finally:
            adv.finding_to_payload_item = orig
        self.assertEqual(calls, [])

    def test_the_leak_detector_accepts_security_vocabulary(self):
        for clean in ("Cookie に Secure 属性を付ける", "Content-Security-Policy-Report-Only を設定", "TLS 1.2 以上",
                      "Node.js のバージョン表示を止める", "セッション・Cookie設定", "CVE-2021-41773"):
            self.assertEqual(adv.leak_reasons(clean), [], clean)
        for dirty in ("https://x.example", "api.example.com", "Bearer abcdefghijklmnop", "192.168.0.1",
                      "a@b.co", "Set-Cookie: sid=abc", SECRET_TOKEN, "fe80::1:2:3"):
            self.assertNotEqual(adv.leak_reasons(dirty), [], dirty)


class TestPhaseOneIsMockOnly(unittest.TestCase):
    def test_only_a_loopback_endpoint_is_accepted(self):
        for url in ("https://api.abliteration.ai/v1/chat/completions", "http://10.0.0.1/v1/chat/completions",
                    "https://127.0.0.1.example/v1", "file:///etc/passwd",
                    "http://localhost:1/v1/chat/completions",          # resolved by name: refused
                    "http://user:pw@127.0.0.1:1/v1/chat/completions"):
            with self.assertRaises(adv.AdvisorError, msg=url):
                adv.AbliterationAdvisor(url)
        adv.AbliterationAdvisor("http://127.0.0.1:1/v1/chat/completions")
        adv.AbliterationAdvisor("http://[::1]:1/v1/chat/completions")

    def test_external_adapter_requires_https_key_and_explicit_type(self):
        for url in ("http://api.abliteration.ai/v1/chat/completions",
                    "https://user:pw@api.abliteration.ai/v1/chat/completions",
                    "https://provider.example/v1/chat/completions",
                    "https://api.abliteration.ai.attacker.example/v1/chat/completions",
                    "https://api.abliteration.ai:8443/v1/chat/completions",
                    "https://api.abliteration.ai/v1/other"):
            with self.assertRaises(adv.AdvisorError):
                adv.ExternalAbliterationAdvisor(url, api_key="test-only-key")
        with self.assertRaises(adv.AdvisorError):
            adv.ExternalAbliterationAdvisor("https://api.abliteration.ai/v1/chat/completions")
        seen = []
        advisor = adv.ExternalAbliterationAdvisor(
            "https://api.abliteration.ai/v1/chat/completions", api_key="test-only-key",
            transport=lambda url, headers, body: seen.append((url, headers, body)) or json.dumps(
                {"choices": [{"finish_reason": "stop", "message": {"content": '{"advice": []}'}}]}).encode(),
        )
        advisor.advise([_leaky_finding()])
        self.assertEqual(seen[0][1]["Authorization"], "Bearer test-only-key")
        self.assertNotIn(HOST, seen[0][2].decode())
        request = json.loads(seen[0][2])
        self.assertLessEqual(request["max_tokens"], 2048)
        self.assertEqual(request["response_format"], {"type": "json_object"})
        self.assertEqual(request["reasoning_effort"], "none")
        for bad_finish in ("length", "content_filter", "tool_calls", "function_call"):
            bad_advisor = adv.ExternalAbliterationAdvisor(
                "https://api.abliteration.ai/v1/chat/completions", api_key="test-only-key",
                transport=lambda _u, _h, _b, fr=bad_finish: json.dumps(
                    {"choices": [{"message": {"content": '{"advice": []}'},
                                  "finish_reason": fr}]}).encode(),
            )
            with self.assertRaises(adv.AdvisorError):
                bad_advisor.advise([_leaky_finding()])

    def test_external_advisor_requires_a_single_unambiguous_json_object(self):
        def advisor_for(content):
            def transport(_url, _headers, _body):
                return json.dumps({"choices": [{"finish_reason": "stop",
                                                "message": {"content": content}}]}).encode()

            return adv.ExternalAbliterationAdvisor(
                "https://api.abliteration.ai/v1/chat/completions",
                api_key="test-only-key", transport=transport)

        for response in ('{"advice": [], "advice": []}', 'prefix {"advice": []}',
                         '{"advice": [], "number": NaN}'):
            with self.subTest(response=response), self.assertRaises(adv.AdvisorError):
                advisor_for(response).advise([_leaky_finding()])
        result = advisor_for('{"advice": []}').advise([_leaky_finding()])
        self.assertEqual(result.rejected, ())
        self.assertEqual(result.missing_refs, result.sent_refs)

    def test_external_transport_holds_send_scope_only_while_request_is_written(self):
        events = []

        class Response:
            status = 200

            def read(self, limit):
                events.append("read")
                return b"{}"

        class Connection:
            def __init__(self, *args, **kwargs):
                events.append("init")
                self.sock = type("Socket", (), {"settimeout": lambda _self, n: events.append("timeout")})()

            def connect(self):
                events.append("connect")

            def request(self, method, path, body, headers):
                events.append("request")
                self.method, self.path, self.body, self.headers = method, path, body, headers

            def getresponse(self):
                events.append("response")
                return Response()

            def close(self):
                events.append("close")

        @contextlib.contextmanager
        def scope():
            events.append("enter")
            try:
                yield
            finally:
                events.append("exit")

        with patch.object(adv.http.client, "HTTPSConnection", Connection):
            out = adv._external_transport(
                "https://api.abliteration.ai/v1/chat/completions",
                {"Authorization": "Bearer test-only-key", "Content-Type": "application/json"},
                b"{}", timeout_s=3.0, send_scope=scope)
        self.assertEqual(out, b"{}")
        self.assertLess(events.index("connect"), events.index("enter"))
        self.assertLess(events.index("enter"), events.index("request"))
        self.assertLess(events.index("request"), events.index("exit"))
        self.assertLess(events.index("exit"), events.index("response"))
        self.assertEqual(events[-1], "close")

    def test_the_adapter_takes_no_api_key_and_sends_no_authorization(self):
        fields = {f.name for f in dataclasses.fields(adv.AbliterationAdvisor)}
        self.assertFalse({"api_key", "key", "token"} & fields)
        seen = []
        a = adv.AbliterationAdvisor("http://127.0.0.1:9/v1/chat/completions",
                                    transport=lambda url, h, b: seen.append(h) or json.dumps(
                                        {"choices": [{"message": {"content": '{"advice": []}'}}]}).encode())
        a.advise([_leaky_finding()])
        self.assertEqual(seen, [{"Content-Type": "application/json"}])

    def test_a_dead_or_garbled_endpoint_is_one_error(self):
        a = adv.AbliterationAdvisor("http://127.0.0.1:1/v1/chat/completions", timeout_s=1)
        with self.assertRaises(adv.AdvisorError):
            a.advise([_leaky_finding()])
        b = adv.AbliterationAdvisor("http://127.0.0.1:9/x", transport=lambda *x: b"<html>")
        with self.assertRaises(adv.AdvisorError):
            b.advise([_leaky_finding()])


class TestMockOutputQuality(unittest.TestCase):
    LAB = [
        {"id": "f_headers", "severity": "medium", "verdict": "detected", "category": "設定不備"},
        {"id": "f_powered", "severity": "low", "verdict": "detected", "category": "情報露出"},
        {"id": "f_idor", "severity": "high", "verdict": "detected", "category": "アクセス制御"},
        {"id": "f_banner", "severity": "high", "verdict": "detected", "category": "既知の脆弱性（CVE）",
         "cve": ["CVE-2021-41773"]},
    ]

    def test_every_finding_gets_valid_grounded_advice(self):
        with _MockServer() as m:
            r = adv.AbliterationAdvisor(m.url).advise([dict(f) for f in self.LAB])
        self.assertEqual(r.rejected, ())
        self.assertEqual(r.missing_refs, ())
        self.assertEqual([a.finding_id for a in r.advice], [f["id"] for f in self.LAB])
        by = {a.finding_id: a for a in r.advice}
        self.assertIn("Content-Security-Policy", " ".join(r.detail for r in by["f_headers"].remediation))
        for a in r.advice:
            self.assertTrue(a.remediation and a.risk_explanation)
            self.assertNotRegex(a.risk_explanation, adv._OVERCLAIM_RE)   # all are "detected"
            for c in a.next_checks:
                self.assertEqual(c.status, "proposal_only")
                self.assertIn("scope_approved", c.required_gates)
        idor = by["f_idor"].next_checks[0]
        self.assertEqual(idor.level, "L2")
        self.assertIn("l2_human_approval", idor.required_gates)
        self.assertEqual(r.status, "proposal_only")
        self.assertEqual(r.endpoint_kind, "loopback_mock")


class TestMisproposalsAreRejected(unittest.TestCase):
    def run_with(self, items, findings=None):
        with _MockServer(_advice_reply(items)) as m:
            return adv.AbliterationAdvisor(m.url).advise(findings or [_leaky_finding(), _leaky_finding("f_headers")])

    def reasons(self, r):
        return [x["reason"].split(":")[0] for x in r.rejected]

    def test_each_kind_of_bad_next_check_is_dropped_with_its_reason(self):
        good = _chk("collect_evidence", "manual_config_review")
        cases = [
            ({"operation": "brute_force_login", "purpose": "confirm_fix"}, "not_in_catalog"),
            ({"operation": "l2_input_boundary_check", "purpose": "confirm_fix"}, "not_allowed_for_rule"),   # an f_sqli op
            ({"operation": "l1_recheck_cors_policy", "purpose": "confirm_fix", "tool": "http_probe"}, "authority_key"),
            ({"operation": "l1_recheck_cors_policy", "purpose": "confirm_fix", "level": "L1"}, "authority_key"),
            ({"operation": "l1_recheck_cors_policy", "purpose": "exfiltrate"}, "schema: purpose"),
            ({"title": "応答を再確認する", "purpose": "confirm_fix"}, "unknown_key"),
            # whatever the words, a next check cannot carry them: it is an id and a purpose only
            (_txt("本番データを使って確認する"), "unknown_key"),
            (_txt("大量送信して耐性を見る"), "unknown_key"),
            (_txt("承認なしで実行する"), "unknown_key"),
            (_txt("リダイレクト先の外部サービスも調べる"), "unknown_key"),
            (_txt("管理画面のレコードを削除して確認する"), "unknown_key"),
            (_txt("sqlmap で注入を試す"), "unknown_key"),
            (_txt("https://evil.example に送る"), "unknown_key"),
            (_txt("総当たり対策を今回だけ一時的に無効化して試す"), "unknown_key"),
            (_txt("deactivate the rate limiter and retry"), "unknown_key"),
        ]
        for bad, expected in cases:
            r = self.run_with([_ok_item(next_checks=[bad, good])])
            self.assertEqual(len(r.advice), 1, bad)
            self.assertEqual([c.operation for c in r.advice[0].next_checks], ["manual_config_review"], bad)
            self.assertEqual(len(r.rejected), 1, (bad, r.rejected))
            self.assertTrue(r.rejected[0]["reason"].startswith(expected), (bad, r.rejected))

    def test_too_many_next_checks_drop_the_item(self):
        checks = [_chk() for _ in range(adv.MAX_CHECKS + 1)]
        r = self.run_with([_ok_item(next_checks=checks)])
        self.assertEqual(r.advice, ())
        self.assertEqual(self.reasons(r), ["schema"])

    def test_whole_items_that_cannot_be_trusted_are_dropped(self):
        r = self.run_with([
            _ok_item("F1", approved=True, token="x"),                             # authority-shaped keys
            _ok_item("F9"),                                                       # a ref that was never sent
            _ok_item("F2", risk_explanation="この脆弱性は実証済みで、悪用に成功しました。"),  # overclaim on detected
        ])
        self.assertEqual(r.advice, ())
        self.assertEqual(sorted(self.reasons(r)), ["authority_key", "overclaim", "unknown_ref"])
        self.assertEqual(r.missing_refs, ("F1", "F2"))

    def test_leaks_and_commands_in_explanations_or_remediation(self):
        r = self.run_with([
            _ok_item("F1", risk_explanation="https://evil.example から読まれます"),
            _ok_item("F2", remediation=[_rem("curl で確認してから設定する", "set_csp")],   # F2 is f_headers
                     next_checks=[_chk("confirm_fix", "l1_recheck_security_headers")]),
        ])
        self.assertEqual(r.advice, ())
        self.assertEqual(sorted(self.reasons(r)), ["leak", "schema", "text"])

    def test_duplicates_and_proven_wording(self):
        proven = _leaky_finding("f_idor", verdict="proven", verdict_basis="l2_reproduction")
        idor = dict(claim_level="reproduced", remediation=[_rem("所有者を照合する", "enforce_object_ownership")],
                    next_checks=[_chk("confirm_fix", "l2_authz_boundary_check")])
        r = self.run_with([_ok_item("F1", risk_explanation="L2 で実証済みの所見です。", **idor),
                           _ok_item("F1", **idor)], findings=[proven])
        self.assertEqual(len(r.advice), 1)                    # "proven" wording is fine for a proven finding
        self.assertEqual(self.reasons(r), ["duplicate_ref"])

    def test_replies_that_are_not_the_schema(self):
        for reply in ("not json at all", '{"proposals": [{"tool": "http_probe"}]}', '{"advice": "x"}',
                      '{"advice": [], "approved": true}', "[1, 2]"):
            with _MockServer(lambda u, reply=reply: reply) as m:
                r = adv.AbliterationAdvisor(m.url).advise([_leaky_finding()])
            self.assertEqual(r.advice, (), reply)
            self.assertEqual(r.missing_refs, ("F1",), reply)
            self.assertEqual(r.rejected[0]["where"], "root", reply)


class TestNoPathFromAdviceToAWorker(unittest.TestCase):
    FORBIDDEN_IMPORTS = ("gateway", "authz", "runtime", "workers", "assessment", "confinement", "netfilter",
                         "authority_ledger", "secrets_store", "ownership")

    def test_the_module_imports_nothing_that_can_authorize_or_run(self):
        tree = ast.parse((ROOT / "aegis" / "ai_advisor.py").read_text())
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names.append(node.module or "")
        for n in names:
            for bad in self.FORBIDDEN_IMPORTS:
                self.assertNotIn(bad, n.split("."), n)
        self.assertNotIn("subprocess", names)

    def test_a_next_check_is_not_a_gateway_proposal(self):
        for cls in (adv.NextCheck, adv.RemediationStep, adv.Advice):
            self.assertFalse({"tool", "action", "args", "target_id"} & {f.name for f in dataclasses.fields(cls)}, cls)
        with _MockServer() as m:
            r = adv.AbliterationAdvisor(m.url).advise([{"id": "f_idor", "severity": "high"}])
        check = r.advice[0].next_checks[0]
        with self.assertRaises(ValueError):
            sanitize_proposal(dataclasses.asdict(check))

        def keys(o):
            if isinstance(o, dict):
                yield from o
                for v in o.values():
                    yield from keys(v)
            elif isinstance(o, list):
                for v in o:
                    yield from keys(v)
        self.assertFalse({"tool", "action", "args", "target_id", "token", "approved"} & set(keys(r.to_dict())))

    def test_the_status_is_set_by_code_not_by_the_model(self):
        r = None
        with _MockServer(_advice_reply([_ok_item(next_checks=[{"operation": "l1_recheck_cors_policy", "purpose": "confirm_fix",
                                                               "status": "approved"}])])) as m:
            r = adv.AbliterationAdvisor(m.url).advise([_leaky_finding()])
        self.assertEqual(r.advice[0].next_checks, ())         # "status" from the model is an unknown key
        self.assertEqual(r.status, "proposal_only")


class TestAdvisorAuditBudget(unittest.TestCase):
    def test_restarted_audit_rejects_valid_prefix_rollback_before_another_paid_send(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            audit = AuditLog(path)
            audit.record_with_budget("advisor.safe_send_requested", reserve_micro_usd=300_000,
                                     cap_micro_usd=900_000, endpoint_kind="external")
            older_valid_prefix = path.read_text()
            audit.record_with_budget("advisor.safe_send_requested", reserve_micro_usd=300_000,
                                     cap_micro_usd=900_000, endpoint_kind="external")
            path.write_text(older_valid_prefix)

            reopened = AuditLog(path)
            with self.assertRaisesRegex(ValueError, "audit budget history invalid"):
                reopened.record_with_budget("advisor.safe_send_requested", reserve_micro_usd=300_000,
                                            cap_micro_usd=900_000, endpoint_kind="external")

    def test_missing_budget_floor_and_interrupted_append_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            audit = AuditLog(path)
            audit.record_with_budget("advisor.safe_send_requested", reserve_micro_usd=300_000,
                                     cap_micro_usd=900_000, endpoint_kind="external")
            floor = path.with_name(path.name + ".advisor-budget")
            self.assertEqual(floor.read_text().strip(), "300000")
            self.assertEqual(floor.stat().st_mode & 0o777, 0o600)
            floor.unlink()
            with self.assertRaisesRegex(ValueError, "audit budget history invalid"):
                AuditLog(path).record_with_budget("advisor.safe_send_requested", reserve_micro_usd=1,
                                                  cap_micro_usd=900_000, endpoint_kind="external")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            # A pre-upgrade valid record has no separate floor. Its history
            # cannot be attested after restart, so another paid send is refused.
            AuditLog(path).record("advisor.safe_send_requested", endpoint_kind="external",
                                  reserved_micro_usd=300_000, budget_cap_micro_usd=900_000)
            with self.assertRaisesRegex(ValueError, "audit budget history invalid"):
                AuditLog(path).record_with_budget("advisor.safe_send_requested", reserve_micro_usd=1,
                                                  cap_micro_usd=900_000, endpoint_kind="external")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            audit = AuditLog(path)
            with patch.object(audit, "_append_locked", side_effect=OSError("audit append failed")):
                with self.assertRaises(OSError):
                    audit.record_with_budget("advisor.safe_send_requested", reserve_micro_usd=300_000,
                                             cap_micro_usd=900_000, endpoint_kind="external")
            with self.assertRaisesRegex(ValueError, "audit budget history invalid"):
                AuditLog(path).record_with_budget("advisor.safe_send_requested", reserve_micro_usd=1,
                                                  cap_micro_usd=900_000, endpoint_kind="external")

    def test_budget_survives_reopen_and_counts_concurrent_reservations(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            audit = AuditLog(path)
            outcomes = []

            def reserve():
                try:
                    audit.record_with_budget("advisor.safe_send_requested", reserve_micro_usd=300_000,
                                             cap_micro_usd=500_000, endpoint_kind="external")
                    outcomes.append("sent")
                except ValueError:
                    outcomes.append("refused")

            threads = [threading.Thread(target=reserve) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertCountEqual(outcomes, ["sent", "refused"])
            reopened = AuditLog(path)
            with self.assertRaises(ValueError):
                reopened.record_with_budget("advisor.safe_send_requested", reserve_micro_usd=300_000,
                                            cap_micro_usd=500_000, endpoint_kind="external")
            self.assertEqual(len(reopened.entries()), 1)

    def test_tampered_or_unpriced_prior_send_refuses_reservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            audit = AuditLog(path)
            audit.record("advisor.safe_send_requested", endpoint_kind="external")
            with self.assertRaises(ValueError):
                audit.record_with_budget("advisor.safe_send_requested", reserve_micro_usd=1,
                                         cap_micro_usd=500_000, endpoint_kind="external")
            path.write_text(path.read_text().replace('"external"', '"tampered"'))
            with self.assertRaises(ValueError):
                audit.record_with_budget("advisor.safe_send_requested", reserve_micro_usd=1,
                                         cap_micro_usd=500_000, endpoint_kind="external")


class TestShownRemediationComesFromTheCatalog(unittest.TestCase):
    """What the user is told to do is the approved fix, never the model's free text: a
    validator that misses one dangerous phrase must not put it on screen."""

    def _advice(self, detail):
        return adv.Advice(ref="F1", finding_id="f_headers", claim_level="suspected", cites=("rule",),
                          risk_explanation="ほかのサイトに埋め込まれるおそれがあります。",
                          remediation=(adv.RemediationStep(fix="set_csp", label="Content-Security-Policy を設定する",
                                                           detail=detail),),
                          next_checks=())

    def test_model_detail_never_reaches_the_shown_steps(self):
        from aegis.assessment import AssessmentService
        for detail in ("WAF を無効にして運用する", "認証を外して公開する"):
            text = AssessmentService._safe_advice_text(self._advice(detail))
            self.assertNotIn(detail, text)
            self.assertIn("Content-Security-Policy を設定する", text)
            self.assertIn("ほかのサイトに埋め込まれるおそれがあります。", text)

    def test_a_fix_id_outside_the_catalog_is_not_shown(self):
        from aegis.assessment import AssessmentService
        a = self._advice("x")
        a = adv.Advice(**{**a.__dict__, "remediation": (adv.RemediationStep(fix="disable_waf_rules", label="WAF を止める", detail="x"),)})
        text = AssessmentService._safe_advice_text(a)
        self.assertNotIn("WAF", text)


class TestServiceIntegration(RealServiceBase):
    def test_external_advisor_does_not_send_after_stop_at_budget_reservation(self):
        self.onboard()
        self.run_l1()
        self.svc._chat_backend = AbliterationBackend(
            "https://api.abliteration.ai/v1/chat/completions", model="mock", api_key="test-key")
        self.svc._real_site_safe_ai = True
        sent = []
        reserves = []
        original = self.svc.audit.record_with_budget

        def reserve_then_stop(*args, **kwargs):
            reserves.append(args[0])
            result = original(*args, **kwargs)
            self.svc.emergency_stop("appr")
            return result

        env = {"VULNIX_ADVISOR_PRICE_MODEL": "mock",
               "VULNIX_ADVISOR_MAX_COST_USD": "0.50",
               "VULNIX_ADVISOR_USD_PER_1K_INPUT": "0.10",
               "VULNIX_ADVISOR_USD_PER_1K_OUTPUT": "0.10"}
        with patch.dict(os.environ, env), \
                patch.object(self.svc.audit, "record_with_budget", side_effect=reserve_then_stop), \
                patch.object(adv, "_external_transport", side_effect=lambda *args, **kwargs: sent.append(args) or b"{}"):
            with self.assertRaises(ValueError) as raised:
                self.svc.ask_chat("解説", "appr", finding_id="f_headers", safe_advice=True)
        self.assertFalse(sent, "external transport must not run after stop")
        self.assertEqual(reserves, ["advisor.safe_send_requested"])
        self.assertIn("診断対象または許可状態", str(raised.exception))

    def test_external_advisor_does_not_send_after_request_authority_expires(self):
        self.onboard()
        self.run_l1()
        self.svc._chat_backend = AbliterationBackend(
            "https://api.abliteration.ai/v1/chat/completions", model="mock", api_key="test-key")
        self.svc._real_site_safe_ai = True
        active, sent = [True], []
        original = self.svc.audit.record_with_budget

        def reserve_then_revoke(*args, **kwargs):
            result = original(*args, **kwargs)
            active[0] = False
            return result

        env = {"VULNIX_ADVISOR_PRICE_MODEL": "mock",
               "VULNIX_ADVISOR_MAX_COST_USD": "0.50",
               "VULNIX_ADVISOR_USD_PER_1K_INPUT": "0.10",
               "VULNIX_ADVISOR_USD_PER_1K_OUTPUT": "0.10"}
        with patch.dict(os.environ, env), \
                patch.object(self.svc.audit, "record_with_budget", side_effect=reserve_then_revoke), \
                patch.object(adv, "_external_transport", side_effect=lambda *args, **kwargs: sent.append(1) or b"{}"):
            with self.assertRaises(ValueError):
                self.svc.ask_chat("解説", "appr", finding_id="f_headers", safe_advice=True,
                                  request_authorized=lambda: active[0])
        self.assertFalse(sent, "external transport must not run after request revocation")
        self.assertEqual(self.svc.snapshot()["chat_messages"], [])

    def test_external_advisor_does_not_send_after_scope_expires_at_reservation(self):
        self.onboard()
        self.run_l1()
        self.svc._chat_backend = AbliterationBackend(
            "https://api.abliteration.ai/v1/chat/completions", model="mock", api_key="test-key")
        self.svc._real_site_safe_ai = True
        sent = []
        original = self.svc.audit.record_with_budget

        def reserve_then_expire(*args, **kwargs):
            result = original(*args, **kwargs)
            with self.svc._lock:
                self.svc._verified_external_hosts[HOST]["not_after"] = 0
            return result

        env = {"VULNIX_ADVISOR_PRICE_MODEL": "mock",
               "VULNIX_ADVISOR_MAX_COST_USD": "0.50",
               "VULNIX_ADVISOR_USD_PER_1K_INPUT": "0.10",
               "VULNIX_ADVISOR_USD_PER_1K_OUTPUT": "0.10"}
        with patch.dict(os.environ, env), \
                patch.object(self.svc.audit, "record_with_budget", side_effect=reserve_then_expire), \
                patch.object(adv, "_external_transport", side_effect=lambda *args, **kwargs: sent.append(1) or b"{}"):
            with self.assertRaises(ValueError):
                self.svc.ask_chat("解説", "appr", finding_id="f_headers", safe_advice=True)
        self.assertFalse(sent, "external transport must not run after scope expiry")
        self.assertEqual(self.svc.snapshot()["chat_messages"], [])

    def test_external_advisor_rechecks_stop_at_transport_boundary(self):
        self.onboard()
        self.run_l1()
        self.svc._chat_backend = AbliterationBackend(
            "https://api.abliteration.ai/v1/chat/completions", model="mock", api_key="test-key")
        self.svc._real_site_safe_ai = True
        sent = []
        original_advise = adv.ExternalAbliterationAdvisor.advise
        service = self.svc

        def stop_on_advise(advisor, findings, **kwargs):
            service.emergency_stop("appr")
            return original_advise(advisor, findings, **kwargs)

        env = {"VULNIX_ADVISOR_PRICE_MODEL": "mock",
               "VULNIX_ADVISOR_MAX_COST_USD": "0.50",
               "VULNIX_ADVISOR_USD_PER_1K_INPUT": "0.10",
               "VULNIX_ADVISOR_USD_PER_1K_OUTPUT": "0.10"}
        with patch.dict(os.environ, env), \
                patch.object(adv.ExternalAbliterationAdvisor, "advise", stop_on_advise), \
                patch.object(adv, "_external_transport", side_effect=lambda *args, **kwargs: sent.append(1) or b"{}"):
            with self.assertRaises(ValueError):
                self.svc.ask_chat("解説", "appr", finding_id="f_headers", safe_advice=True)
        self.assertFalse(sent, "external transport must not run after stop before send")
        self.assertEqual(self.svc.snapshot()["chat_messages"], [])

    def test_external_advisor_does_not_write_after_stop_during_tls_connect(self):
        self.onboard()
        self.run_l1()
        self.svc._chat_backend = AbliterationBackend(
            "https://api.abliteration.ai/v1/chat/completions", model="mock", api_key="test-key")
        self.svc._real_site_safe_ai = True
        sent = []
        service = self.svc

        class Connection:
            def __init__(self, *args, **kwargs):
                self.sock = type("Socket", (), {"settimeout": lambda _self, n: None})()

            def connect(self):
                service.emergency_stop("appr")

            def request(self, *args, **kwargs):
                sent.append(1)

            def close(self):
                pass

        env = {"VULNIX_ADVISOR_PRICE_MODEL": "mock",
               "VULNIX_ADVISOR_MAX_COST_USD": "0.50",
               "VULNIX_ADVISOR_USD_PER_1K_INPUT": "0.10",
               "VULNIX_ADVISOR_USD_PER_1K_OUTPUT": "0.10"}
        with patch.dict(os.environ, env), patch.object(adv.http.client, "HTTPSConnection", Connection):
            with self.assertRaises(ValueError):
                service.ask_chat("解説", "appr", finding_id="f_headers", safe_advice=True)
        self.assertFalse(sent, "request bytes must not be written after stop during TLS connect")
        self.assertEqual(service.snapshot()["chat_messages"], [])

    def test_external_advisor_holds_non_reentrant_authority_only_for_request_write(self):
        self.onboard()
        self.run_l1()
        self.svc._chat_backend = AbliterationBackend(
            "https://api.abliteration.ai/v1/chat/completions", model="mock", api_key="test-key")
        self.svc._real_site_safe_ai = True
        held, wrote = [False], []

        def authorized():
            if held[0]:
                raise AssertionError("authority store lock was reacquired inside its lease")
            return True

        @contextlib.contextmanager
        def lease():
            held[0] = True
            try:
                yield
            finally:
                held[0] = False

        authorized.lease = lease

        class Response:
            status = 200

            def read(self, limit):
                return b'{"choices":[{"message":{"content":"{\\"advice\\":[]}"}}]}'

        class Connection:
            def __init__(self, *args, **kwargs):
                self.sock = type("Socket", (), {"settimeout": lambda _self, n: None})()

            def connect(self):
                pass

            def request(self, *args, **kwargs):
                wrote.append(held[0])

            def getresponse(self):
                if held[0]:
                    raise AssertionError("authorization lease held while waiting for model reply")
                return Response()

            def close(self):
                pass

        env = {"VULNIX_ADVISOR_PRICE_MODEL": "mock",
               "VULNIX_ADVISOR_MAX_COST_USD": "0.50",
               "VULNIX_ADVISOR_USD_PER_1K_INPUT": "0.10",
               "VULNIX_ADVISOR_USD_PER_1K_OUTPUT": "0.10"}
        with patch.dict(os.environ, env), patch.object(adv.http.client, "HTTPSConnection", Connection):
            result = self.svc.ask_chat("解説", "appr", finding_id="f_headers", safe_advice=True,
                                       request_authorized=authorized)
        self.assertEqual(wrote, [True])
        self.assertFalse(held[0])
        self.assertEqual(result["message"]["source"], "builtin")

    def test_chat_does_not_try_fallback_model_after_request_revocation(self):
        active, fallback_calls = [True], []

        def revoke_during_safe_advice(*args, **kwargs):
            active[0] = False
            return None

        with patch.object(self.svc, "_safe_real_ai_explanation", side_effect=revoke_during_safe_advice), \
                patch.object(self.svc, "_answer_question", side_effect=lambda *a, **k: fallback_calls.append(1)):
            with self.assertRaises(ValueError):
                self.svc.ask_chat("解説", "appr", safe_advice=True,
                                  request_authorized=lambda: active[0])
        self.assertFalse(fallback_calls, "revoked request must not enter a fallback model")

    def test_external_advisor_requires_a_durable_budget_before_sending(self):
        self.onboard()
        self.run_l1()
        calls = []
        self.svc._chat_backend = AbliterationBackend(
            "https://api.abliteration.ai/v1/chat/completions", model="mock", api_key="test-key")
        self.svc._real_site_safe_ai = True
        with patch.object(adv, "_external_transport", side_effect=lambda *a, **k: calls.append(a) or b"{}"):
            for config in (
                {"VULNIX_ADVISOR_PRICE_MODEL": "mock", "VULNIX_ADVISOR_MAX_COST_USD": "",
                 "VULNIX_ADVISOR_USD_PER_1K_INPUT": "", "VULNIX_ADVISOR_USD_PER_1K_OUTPUT": ""},
                {"VULNIX_ADVISOR_PRICE_MODEL": "wrong-model", "VULNIX_ADVISOR_MAX_COST_USD": "0.50",
                 "VULNIX_ADVISOR_USD_PER_1K_INPUT": "0.10", "VULNIX_ADVISOR_USD_PER_1K_OUTPUT": "0.10"},
            ):
                with self.subTest(config=config), patch.dict(os.environ, config):
                    result = self.svc.ask_chat("解説", "appr", finding_id="f_headers", safe_advice=True)
                    self.assertEqual(result["message"]["source"], "builtin")
        self.assertEqual(calls, [])

    def test_external_advisor_refuses_zero_negative_or_nonfinite_prices(self):
        self.onboard()
        self.run_l1()
        calls = []
        self.svc._chat_backend = AbliterationBackend(
            "https://api.abliteration.ai/v1/chat/completions", model="mock", api_key="test-key")
        self.svc._real_site_safe_ai = True
        with patch.object(adv, "_external_transport", side_effect=lambda *a, **k: calls.append(a) or b"{}"):
            for value in ("0", "-1", "NaN", "Infinity"):
                with self.subTest(value=value), patch.dict(os.environ, {
                    "VULNIX_ADVISOR_PRICE_MODEL": "mock",
                    "VULNIX_ADVISOR_MAX_COST_USD": "0.50",
                    "VULNIX_ADVISOR_USD_PER_1K_INPUT": value,
                    "VULNIX_ADVISOR_USD_PER_1K_OUTPUT": "0.10",
                }):
                    result = self.svc.ask_chat("解説", "appr", finding_id="f_headers", safe_advice=True)
                    self.assertEqual(result["message"]["source"], "builtin")
        self.assertEqual(calls, [])

    def test_external_advisor_reserves_before_send_and_refuses_second_call(self):
        self.onboard()
        self.run_l1()
        calls = []
        self.svc._chat_backend = AbliterationBackend(
            "https://api.abliteration.ai/v1/chat/completions", model="mock", api_key="test-key")
        self.svc._real_site_safe_ai = True
        item = _ok_item(remediation=[_rem("CSPを適切に設定する", "set_csp")],
                        next_checks=[_chk("confirm_fix", "l1_recheck_security_headers")])
        content = json.dumps({"advice": [item]}, ensure_ascii=False)
        reply = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": content}}]}).encode()
        env = {"VULNIX_ADVISOR_PRICE_MODEL": "mock",
               "VULNIX_ADVISOR_MAX_COST_USD": "0.50",
               "VULNIX_ADVISOR_USD_PER_1K_INPUT": "0.10",
               "VULNIX_ADVISOR_USD_PER_1K_OUTPUT": "0.10"}
        with patch.object(adv, "_external_transport", side_effect=lambda *a, **k: calls.append(a) or reply):
            with patch.dict(os.environ, env):
                first = self.svc.ask_chat("解説", "appr", finding_id="f_headers", safe_advice=True)
                second = self.svc.ask_chat("解説", "appr", finding_id="f_headers", safe_advice=True)
        self.assertEqual(first["message"]["source"], "external_model")
        self.assertEqual(second["message"]["source"], "builtin")
        self.assertEqual(len(calls), 1)
        reserved = [e for e in self.svc.audit.entries() if e["event"] == "advisor.safe_send_requested"]
        self.assertEqual(len(reserved), 1)
        self.assertGreater(reserved[0]["fields"]["reserved_micro_usd"], 0)
        self.assertEqual(reserved[0]["fields"]["payload_sha256"], hashlib.sha256(calls[0][2]).hexdigest())


    def _platform_case(self, platform_env, prespent=0):
        import tempfile
        from pathlib import Path
        from aegis.spend_cap import DurableSpendCap
        self.onboard()
        self.run_l1()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        cap = DurableSpendCap(Path(tmp.name) / "platform-advisor-spend.json")
        if prespent:
            cap.reserve(prespent, cap_micro_usd=prespent)
        self.svc._platform_advisor_cap = cap
        calls = []
        self.svc._chat_backend = AbliterationBackend(
            "https://api.abliteration.ai/v1/chat/completions", model="mock", api_key="test-key")
        self.svc._real_site_safe_ai = True
        item = _ok_item(remediation=[_rem("CSPを適切に設定する", "set_csp")],
                        next_checks=[_chk("confirm_fix", "l1_recheck_security_headers")])
        content = json.dumps({"advice": [item]}, ensure_ascii=False)
        reply = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": content}}]}).encode()
        env = {"VULNIX_ADVISOR_PRICE_MODEL": "mock", "VULNIX_ADVISOR_MAX_COST_USD": "0.50",
               "VULNIX_ADVISOR_USD_PER_1K_INPUT": "0.10", "VULNIX_ADVISOR_USD_PER_1K_OUTPUT": "0.10",
               **platform_env}
        with patch.object(adv, "_external_transport", side_effect=lambda *a, **k: calls.append(a) or reply), \
                patch.dict(os.environ, env):
            if "VULNIX_ADVISOR_PLATFORM_MAX_COST_USD" not in platform_env:
                os.environ.pop("VULNIX_ADVISOR_PLATFORM_MAX_COST_USD", None)
            out = self.svc.ask_chat("解説", "appr", finding_id="f_headers", safe_advice=True)
        return out, calls, cap

    def test_the_platform_cap_stops_a_send_even_with_room_in_this_organization(self):
        out, calls, cap = self._platform_case({"VULNIX_ADVISOR_PLATFORM_MAX_COST_USD": "1.00"},
                                              prespent=1_000_000)     # other orgs used it all
        self.assertEqual(calls, [])
        self.assertEqual(out["message"]["source"], "builtin")
        self.assertEqual(cap.spent(), 1_000_000)

    def test_a_send_is_counted_against_the_platform_cap(self):
        out, calls, cap = self._platform_case({"VULNIX_ADVISOR_PLATFORM_MAX_COST_USD": "1.00"})
        self.assertEqual(len(calls), 1)
        self.assertEqual(out["message"]["source"], "external_model")
        reserved = [e for e in self.svc.audit.entries() if e["event"] == "advisor.safe_send_requested"]
        self.assertEqual(cap.spent(), reserved[0]["fields"]["reserved_micro_usd"])

    def test_without_a_platform_cap_setting_a_shared_platform_sends_nothing(self):
        out, calls, cap = self._platform_case({})
        self.assertEqual(calls, [])
        self.assertEqual(out["message"]["source"], "builtin")

    def test_real_site_uses_only_allowlisted_finding_for_requested_ai_explanation(self):
        self.onboard()
        self.run_l1()
        with _MockServer() as mock:
            self.svc._chat_backend = AbliterationBackend(mock.url, model="mock")
            self.svc._real_site_safe_ai = True
            executed = []
            original = self.svc.gateway.execute
            self.svc.gateway.execute = lambda *a, **k: executed.append(a) or original(*a, **k)
            try:
                out = self.svc.ask_chat("AIで解説", "appr", finding_id="f_headers", safe_advice=True)
            finally:
                self.svc.gateway.execute = original
            self.assertEqual(out["message"]["source"], "external_model")
            self.assertIn("mock", out["message"]["actor"])
            self.assertTrue(out["message"]["text"])
            self.assertEqual(executed, [])
            self.assertEqual(len(mock.srv.received), 1)
            sent = json.dumps(mock.srv.received[0], ensure_ascii=False)
            for private in (HOST, self.url, "evidence_id", "audit_hash", "target_url", "body_prefix", "Set-Cookie"):
                self.assertNotIn(private, sent)
            finding = json.loads(mock.srv.received[0]["messages"][1]["content"])["findings"][0]
            self.assertEqual((finding["ref"], finding["rule"], finding["verdict"]),
                             ("F1", "f_headers", "detected"))

    def test_real_site_never_sends_arbitrary_chat_text_to_ai(self):
        self.onboard()
        self.run_l1()
        with _MockServer() as mock:
            self.svc._chat_backend = AbliterationBackend(mock.url, model="mock")
            self.svc._real_site_safe_ai = True
            out = self.svc.ask_chat("秘密の値は private-12345 です", "appr", finding_id="f_headers")
            self.assertEqual(out["message"]["source"], "builtin")
            self.assertEqual(mock.srv.received, [])
            safe = self.svc.ask_chat("秘密の値は private-12345 です", "appr",
                                     finding_id="f_headers", safe_advice=True)
            self.assertEqual(safe["message"]["source"], "external_model")
            self.assertNotIn("private-12345", json.dumps(mock.srv.received, ensure_ascii=False))

    def test_real_site_ai_requires_operator_opt_in_and_rejects_overclaim(self):
        self.onboard()
        self.run_l1()
        with _MockServer(_advice_reply([_ok_item(
                risk_explanation="この脆弱性は実証済みで、悪用に成功しました。")])) as mock:
            self.svc._chat_backend = AbliterationBackend(mock.url, model="mock")
            self.svc._real_site_safe_ai = False
            off = self.svc.ask_chat("AIで解説", "appr", finding_id="f_headers", safe_advice=True)
            self.assertEqual(off["message"]["source"], "builtin")
            self.assertEqual(mock.srv.received, [])
            self.svc._real_site_safe_ai = True
            rejected = self.svc.ask_chat("AIで解説", "appr", finding_id="f_headers", safe_advice=True)
            self.assertEqual(rejected["message"]["source"], "builtin")
            self.assertEqual(len(mock.srv.received), 1)

    def test_real_site_ai_never_sends_when_pre_send_audit_fails(self):
        self.onboard()
        self.run_l1()
        with _MockServer() as mock:
            self.svc._chat_backend = AbliterationBackend(mock.url, model="mock")
            self.svc._real_site_safe_ai = True
            original = self.svc.audit.record

            def fail_send(event, **fields):
                if event == "advisor.safe_send_requested":
                    raise OSError("audit unavailable")
                return original(event, **fields)

            with patch.object(self.svc.audit, "record", side_effect=fail_send):
                with self.assertRaises(OSError):
                    self.svc.ask_chat("AIで解説", "appr", finding_id="f_headers", safe_advice=True)
            self.assertEqual(mock.srv.received, [])

    def test_real_site_ai_reply_cannot_be_saved_after_workspace_switch(self):
        self.onboard()
        self.run_l1()
        with _MockServer() as mock:
            self.svc._chat_backend = AbliterationBackend(mock.url, model="mock")
            self.svc._real_site_safe_ai = True
            original = adv.AbliterationAdvisor.advise

            def switch_during_reply(advisor, findings, **kwargs):
                result = original(advisor, findings, **kwargs)
                self.svc.select_asset("lab")
                return result

            with patch.object(adv.AbliterationAdvisor, "advise", switch_during_reply):
                with self.assertRaisesRegex(ValueError, "変更"):
                    self.svc.ask_chat("AIで解説", "appr", finding_id="f_headers", safe_advice=True)
            self.assertEqual(self.svc.snapshot()["chat_messages"], [])

    def test_real_site_ai_reply_names_the_model_that_answered(self):
        self.onboard()
        self.run_l1()
        with _MockServer() as mock:
            self.svc._chat_backend = AbliterationBackend(mock.url, model="original-model")
            self.svc._real_site_safe_ai = True
            original = adv.AbliterationAdvisor.advise

            def replace_backend(advisor, findings, **kwargs):
                result = original(advisor, findings, **kwargs)
                self.svc._chat_backend = AbliterationBackend(mock.url, model="later-model")
                return result

            with patch.object(adv.AbliterationAdvisor, "advise", replace_backend):
                out = self.svc.ask_chat("AIで解説", "appr", finding_id="f_headers", safe_advice=True)
            self.assertIn("original-model", out["message"]["actor"])
            self.assertNotIn("later-model", out["message"]["actor"])

    def test_real_service_findings_never_reach_the_advisor_and_nothing_runs(self):
        with _MockServer() as m:
            advisor = adv.AbliterationAdvisor(m.url)
            self.onboard()
            self.run_l1()
            executed = []
            orig = self.svc.gateway.execute
            self.svc.gateway.execute = lambda *a, **k: executed.append(a) or orig(*a, **k)
            try:
                out = self.svc.advise_findings(advisor, actor="appr")
                self.assertEqual(out["sent_refs"], [])
                self.assertGreater(out["excluded_real_service_findings"], 0)
                self.assertEqual(m.srv.received, [])                     # no request at all
                self.svc.select_asset("lab")
                lab = self.svc.advise_findings(advisor, actor="appr")
            finally:
                self.svc.gateway.execute = orig
            self.assertEqual(sorted(a["finding_id"] for a in lab["advice"]), ["f_banner", "f_idor", "f_sqli"])
            self.assertEqual(lab["excluded_real_service_findings"], 0)
            self.assertEqual(executed, [])                               # advice launched nothing
            raw = json.dumps(m.srv.received, ensure_ascii=False)
            for s in (HOST, "lab.test", "http://", "/api/search"):
                self.assertNotIn(s, raw, s)
        events = [e["fields"] for e in self.svc.audit.entries() if e["event"] == "advisor.asked"]
        self.assertEqual([e["sent"] for e in events], [0, 3])
        self.assertTrue(all(e["sent_to_external_model"] is False for e in events))


if __name__ == "__main__":
    unittest.main()


class TestReviewFindingsStayFixed(unittest.TestCase):
    """Independent review of the first advisor commit."""

    def test_an_http_proxy_in_the_environment_is_not_used(self):
        import os
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from unittest.mock import patch
        import threading
        hits = []

        class Proxy(BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append(self.path)
                self.send_response(502)
                self.end_headers()

            def log_message(self, *a):
                pass
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        env = {k: v for k, v in os.environ.items() if k.lower() not in ("no_proxy",)}
        purl = f"http://127.0.0.1:{proxy.server_port}"
        env.update({k: purl for k in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY")})
        env.update({"no_proxy": "", "NO_PROXY": ""})
        try:
            with _MockServer() as m, patch.dict(os.environ, env, clear=True):
                r = adv.AbliterationAdvisor(m.url).advise([{"id": "f_headers", "severity": "medium"}])
                self.assertEqual(len(m.srv.received), 1)
        finally:
            proxy.shutdown()
            proxy.server_close()
        self.assertEqual(hits, [])
        self.assertEqual(len(r.advice), 1)

    def run_with(self, items, findings=None):
        with _MockServer(_advice_reply(items)) as m:
            return adv.AbliterationAdvisor(m.url).advise(findings or [_leaky_finding()])

    def test_overclaims_and_misproposals_in_remediation_and_next_checks(self):
        cases = [
            (_ok_item(remediation=[_rem("この脆弱性は実証済みなので直ちに直す")]), "overclaim"),
            (_ok_item(remediation=[_rem("承認なしで直ちに本番データを作り直す")]), "text_misproposal"),
            (_ok_item(next_checks=[_txt("実証済みの脆弱性を再確認する。確定したため")]), "unknown_key"),
            (_ok_item(risk_explanation="確実に悪用可能です。"), "overclaim"),
            (_ok_item(risk_explanation="既に侵入されています。"), "overclaim"),
        ]
        for item, expected in cases:
            r = self.run_with([item])
            self.assertTrue(r.rejected and r.rejected[0]["reason"].startswith(expected), (item, r.rejected))

    def test_rephrased_and_full_width_misproposals(self):
        for title in ("テーブルを消去して初期化する", "古いデータを破棄して確かめる", "承認を待たずに高頻度でリクエストを繰り返す",
                      "ｂｕｒｐ で確認する", "ＤｏＳ 耐性を見る", "他の利用者のアカウントで試す", "サブドメインも対象に含める"):
            r = self.run_with([_ok_item(next_checks=[_txt(title)])])
            self.assertEqual(r.advice[0].next_checks, (), title)
            self.assertTrue(r.rejected[0]["reason"].startswith("unknown_key"), (title, r.rejected))

    def test_remediation_may_still_say_remove(self):
        r = self.run_with([_ok_item(remediation=[_rem("不要な Server ヘッダーを削除する")])])
        self.assertEqual(r.rejected, ())

    def test_more_address_forms_are_leaks(self):
        for dirty in ("::1", "fe80::1", "0x7f000001", "example[.]com", "ｅｘａｍｐｌｅ．ｃｏｍ", "１０．０．０．１"):
            self.assertNotEqual(adv.leak_reasons(dirty), [], dirty)

    def test_an_injected_transport_is_not_reported_as_the_loopback_mock(self):
        a = adv.AbliterationAdvisor("http://127.0.0.1:9/x", transport=lambda *x: json.dumps(
            {"choices": [{"message": {"content": '{"advice": []}'}}]}).encode())
        self.assertEqual(a.advise([{"id": "f_headers"}]).endpoint_kind, "injected_transport")

    def test_the_mock_server_keeps_only_recent_requests(self):
        from aegis import abliteration_server as srv_mod
        with _MockServer() as m:
            a = adv.AbliterationAdvisor(m.url)
            for _ in range(srv_mod.MAX_RECORDED + 5):
                a.advise([{"id": "f_headers"}])
            self.assertEqual(len(m.srv.received), srv_mod.MAX_RECORDED)


class TestServiceAuditOnFailure(RealServiceBase):
    def test_a_failed_request_is_audited_and_other_advisors_are_refused(self):
        self.svc.select_asset("lab")
        dead = adv.AbliterationAdvisor("http://127.0.0.1:1/v1/chat/completions", timeout_s=1)
        with self.assertRaises(adv.AdvisorError):
            self.svc.advise_findings(dead, actor="appr")
        failed = [e["fields"] for e in self.svc.audit.entries() if e["event"] == "advisor.failed"]
        self.assertEqual(len(failed), 1)
        self.assertEqual((failed[0]["offered"], failed[0]["sent_to_external_model"]), (3, False))

        class Duck:
            name, endpoint_kind = "duck", "loopback_mock"

            def advise(self, findings):
                raise AssertionError("must not be called")
        with self.assertRaises(TypeError):
            self.svc.advise_findings(Duck(), actor="appr")


class TestValidAdviceIsNotThrownAway(unittest.TestCase):
    """Re-review of 78639eb: the broadened rules rejected 13 of 15 realistic remediation texts."""

    REMEDIATION = [
        "本番環境の Web サーバー設定で HSTS を有効にする",
        "他の利用者の資源に到達できないよう、サーバー側で所有者を照合する（IDOR の基本対策）",
        "顧客の個人情報を返さないよう返却項目を最小限にする",
        "ログインの総当たり対策として試行回数の制限とアカウントロックを導入する",
        "大量のリクエストに備えてレート制限を設ける",
        "リダイレクト先を許可リストで検証する",
        "サブドメインにも HSTS を適用する",
        "外部サービスから読み込むスクリプトに SRI を付ける",
        "設定変更は承認前にステージングで確認する",
        "すべての応答に確実に Secure 属性を付ける",
        "期限 2026-12-01 12:00:00 までに更新する",
        "std::string を使う箇所で長さを検証する",
        "不要な Server ヘッダーを削除する",
        "パラメータ化クエリを徹底し、入力の型と長さをサーバー側で検証する",
        "セッション Cookie に Secure、HttpOnly、SameSite を付ける",
    ]
    NEXT_CHECKS = [
        "修正後に X-Powered-By ヘッダーが削除されたかを L1 で再確認する",
        "本番の応答ヘッダーを L1 で再確認する",
        "テスト用アカウントAで、テスト用アカウントBの模擬データに到達できないことを確認する",
        "TLS の設定変更後にネゴシエーション結果を確認する",
    ]

    def run_with(self, items, findings=None):
        with _MockServer(_advice_reply(items)) as m:
            return adv.AbliterationAdvisor(m.url).advise(findings or [_leaky_finding()])

    FIXES = ("restrict_cors_allowlist", "disallow_credentials_for_untrusted", "confirm_intended_exposure")

    def test_realistic_remediation_passes(self):
        for i in range(0, len(self.REMEDIATION), len(self.FIXES)):
            batch = self.REMEDIATION[i:i + len(self.FIXES)]
            r = self.run_with([_ok_item(remediation=[_rem(t, f) for t, f in zip(batch, self.FIXES)])])
            self.assertEqual(r.rejected, (), (batch, r.rejected))
            self.assertEqual([x.detail for x in r.advice[0].remediation], batch)

    def test_every_purpose_is_accepted_and_labelled_by_code(self):
        from aegis import advisor_catalog
        for purpose, label in advisor_catalog.PURPOSES.items():
            r = self.run_with([_ok_item(next_checks=[_chk(purpose)])])
            self.assertEqual(r.rejected, (), purpose)
            self.assertEqual((r.advice[0].next_checks[0].purpose, r.advice[0].next_checks[0].purpose_label), (purpose, label))

    def test_one_bad_remediation_entry_does_not_drop_the_advice(self):
        r = self.run_with([_ok_item(remediation=[_rem("許可するオリジンを一覧に限定する"),
                                                 _rem("curl で確かめてから直す", "disallow_credentials_for_untrusted")])])
        self.assertEqual([x.detail for x in r.advice[0].remediation], ["許可するオリジンを一覧に限定する"])
        self.assertEqual([x["where"] for x in r.rejected], ["remediation"])


class TestAssetLevelRule(RealServiceBase):
    def test_an_evidence_less_finding_of_a_real_service_asset_is_not_sent(self):
        self.onboard()
        self.run_l1()
        # a finding with no evidence and no L2 profile passes the per-finding rule on its own
        bare = {"id": "f_headers", "severity": "medium", "verdict": "detected", "category": "設定不備",
                "evidence": [], "demo_fixture": False}
        self.assertFalse(self.svc._finding_touches_real_service(bare))
        with self.svc._lock:
            self.svc.a.findings["f_bare"] = bare
        with _MockServer() as m:
            out = self.svc.advise_findings(adv.AbliterationAdvisor(m.url), actor="appr")
            self.assertEqual(out["sent_refs"], [])
            self.assertEqual(m.srv.received, [])


class TestJapaneseAdjacentText(unittest.TestCase):
    """Final re-review of 5f11dde: \\b treats kana and kanji as word characters."""

    def test_addresses_written_right_after_japanese_are_leaks(self):
        for dirty in ("接続先は10.0.0.1です", "接続先はevil.comです", "接続先は::1です", "宛先fe80::1へ"):
            self.assertNotEqual(adv.leak_reasons(dirty), [], dirty)
        for clean in ("TLS 1.2以上にする", "Node.jsのバージョンを隠す", "12:00:00までに", "std::stringで受ける"):
            self.assertEqual(adv.leak_reasons(clean), [], clean)

    def test_misproposals_written_right_after_japanese(self):
        for text, rx in (("burpで確認する", adv._TOOLING_RE), ("承認を得ずに実行する", adv._APPROVAL_BYPASS_RE),
                         ("承認より先に実行する", adv._APPROVAL_BYPASS_RE)):
            self.assertRegex(adv._norm(text), rx, text)


class TestHostnameFormsAndFileNames(unittest.TestCase):
    """Independent review of 50fa827: the hostname lookbehind missed *. / _ / . / - prefixed names,
    and file names of common software were refused as hostnames."""

    def test_wildcard_and_underscore_names_are_leaks(self):
        for dirty in ("*.evil.com", "*.example.co.jpの証明書", ".evil.com", "-evil.com", "_dmarc.evil.com",
                      "_acme-challenge.evil.com", "evil.com-", "evil。com", "１０。０。０。１"):
            self.assertIn("hostname" if "0" not in dirty and "１" not in dirty else "ip_address",
                          adv.leak_reasons(dirty), dirty)

    def test_common_software_file_names_are_not_hostnames(self):
        for clean in ("Express.jsを更新する", "php.iniでexpose_phpをOffにする", "web.configで設定する",
                      "nginx.confに追記する", "httpd.confの設定", "React.jsの", "Ｅｘｐｒｅｓｓ．ｊｓを更新する",
                      "設定を見直す。次に確認する", "完了。Next.jsを更新する"):
            self.assertEqual(adv.leak_reasons(clean), [], clean)

    def test_approval_before_execution_is_bypass(self):
        rx = adv._APPROVAL_BYPASS_RE
        for t in ("承認前に実行する", "承認取得前に実行する", "承認を得ず実行する"):
            self.assertRegex(t, rx)
        self.assertNotRegex("設定変更は承認前にステージングで確認する", rx)   # remediation wording stays valid

    def test_detectors_stay_fast_on_the_longest_accepted_text(self):
        import time
        worst = max(adv.MAX_EXPLANATION, adv.MAX_REMEDIATION_LEN)
        for pattern in ("a." * (worst // 2), "a@" * (worst // 2), "a" * worst, "1." * (worst // 2)):
            t = time.perf_counter()
            adv.leak_reasons(pattern)
            self.assertLess(time.perf_counter() - t, 0.5, pattern[:10])


class TestEvaluationReviewFindings(unittest.TestCase):
    """Independent review of f4b4028."""

    def run_with(self, items, findings=None):
        with _MockServer(_advice_reply(items)) as m:
            return adv.AbliterationAdvisor(m.url).advise(findings or [_leaky_finding()])

    def test_a_defence_named_with_switching_it_off_is_refused(self):
        # HIGH on f4b4028, then MEDIUM on 35fd7d4 (rephrasings still passed, valid reasons were refused):
        # a next check no longer has free text, so no wording can be carried at all
        for text in ("総当たり対策を無効にして試す", "DoS対策を回避して確認する", "ブルートフォース防止を切ってから試す",
                     "disable brute-force protection and retry", "総当たり対策を解除して試す", "CAPTCHA を突破して試す",
                     "WAF をすり抜けて確かめる", "パスワードを片っ端から試す", "認証なしでアクセスして確かめる",
                     "lift the rate limit and retry"):
            r = self.run_with([_ok_item(next_checks=[_txt(text)])])
            self.assertEqual(r.advice[0].next_checks, (), text)
            self.assertTrue(r.rejected[0]["reason"].startswith("unknown_key"), (text, r.rejected))
        # what such a check is for is now a purpose id, which cannot be refused for its wording
        r = self.run_with([_ok_item(next_checks=[_chk("confirm_current_state")])])
        self.assertEqual(r.rejected, ())

    def test_an_l2_only_issue_is_not_observed_by_l1(self):
        idor = dict(remediation=[_rem("所有者を照合する", "enforce_object_ownership")],
                    next_checks=[_chk("collect_evidence", "l2_authz_boundary_check")])
        r = self.run_with([_ok_item(claim_level="observed", **idor)], findings=[{"id": "f_idor", "verdict": "detected"}])
        self.assertEqual(r.advice, ())
        self.assertIn("cannot be observed by L1 alone", r.rejected[0]["reason"])
        r = self.run_with([_ok_item(claim_level="suspected", **idor)], findings=[{"id": "f_idor", "verdict": "detected"}])
        self.assertEqual(len(r.advice), 1)


class TestReproducedNeedsAnL2Basis(unittest.TestCase):
    def test_reproduced_is_refused_without_an_l2_reproduction(self):
        from aegis import advisor_catalog
        self.assertIsNone(advisor_catalog.claim_problem("reproduced", "f_idor", "proven", "l2_reproduction"))
        for basis in ("l1_observation", "demo_fixture"):
            self.assertIn("needs an L2 reproduction", advisor_catalog.claim_problem("reproduced", "f_idor", "proven", basis))


class TestFinalReviewFindings(unittest.TestCase):
    """Final review of ce074d5."""

    def run_with(self, items, findings=None):
        with _MockServer(_advice_reply(items)) as m:
            return adv.AbliterationAdvisor(m.url).advise(findings or [_leaky_finding()])

    def test_bypassing_or_preceding_approval_in_a_remediation_detail_is_refused(self):
        for text in ("bypass the approval and deploy", "deploy before approval", "skip the approval step"):
            r = self.run_with([_ok_item(remediation=[_rem("許可するオリジンを一覧に限定する"),
                                                     _rem(text, "disallow_credentials_for_untrusted")])])
            self.assertEqual([x.fix for x in r.advice[0].remediation], ["restrict_cors_allowlist"], text)
            self.assertTrue(r.rejected[0]["reason"].startswith("text_misproposal: approval_bypass"), (text, r.rejected))
        r = self.run_with([_ok_item(remediation=[_rem("Make sure authentication cannot be bypassed on every endpoint")])])
        self.assertEqual(r.rejected, ())

    def test_unhashable_ids_are_schema_errors_not_crashes(self):
        for bad in (dict(claim_level=["observed"]), dict(remediation=[{"fix": ["set_csp"], "detail": "x"}]),
                    dict(next_checks=[{"operation": {"a": 1}, "purpose": "confirm_fix"}]),
                    dict(next_checks=[{"operation": "l1_recheck_cors_policy", "purpose": ["confirm_fix"]}])):
            r = self.run_with([_ok_item(**bad)])
            self.assertTrue(r.rejected, bad)
            self.assertTrue(any(x["reason"].startswith(("schema", "not_in_catalog")) for x in r.rejected), (bad, r.rejected))


class TestApprovalRuleNegationAndAudit(unittest.TestCase):
    """Review of a4952ff."""

    def test_negated_or_review_wording_is_not_approval_bypass(self):
        for valid in ("Run the regression tests before approval of the release",
                      "Have the security team review the CORS change before approval",
                      "cannot skip the approval step", "cannot circumvent approval", "Ensure no user can bypass approval",
                      "承認を回避できないように権限を分ける", "設定変更は承認前にステージングで確認する"):
            self.assertIsNone(adv._APPROVAL_BYPASS_RE.search(adv._norm(valid)), valid)
        for bad in ("deploy before approval", "bypass the approval and deploy", "skip the approval step",
                    "with no review, skip the approval", "承認なしで本番に反映する"):
            self.assertIsNotNone(adv._APPROVAL_BYPASS_RE.search(adv._norm(bad)), bad)


class TestValidatorCrashIsAudited(RealServiceBase):
    def test_a_validator_exception_becomes_advisor_failed(self):
        from unittest.mock import patch
        self.svc.select_asset("lab")
        with _MockServer() as m, patch.object(adv, "validate_advice", side_effect=RuntimeError("boom")):
            with self.assertRaises(adv.AdvisorError):
                self.svc.advise_findings(adv.AbliterationAdvisor(m.url), actor="appr")
        failed = [e["fields"] for e in self.svc.audit.entries() if e["event"] == "advisor.failed"]
        self.assertEqual(len(failed), 1)
        self.assertIn("could not be validated", failed[0]["reason"])
