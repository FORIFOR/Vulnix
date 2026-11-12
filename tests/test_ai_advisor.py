"""AI advisor (phase 1, mock only): allow-listed input, validated output, no path to a worker."""
from __future__ import annotations

import ast
import dataclasses
import json
import unittest
from pathlib import Path

from aegis import ai_advisor as adv
from aegis.abliteration_server import start_abliteration_server
from aegis.router import sanitize_proposal
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
                         ("other", "その他", "medium", "detected", None))

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


class TestServiceIntegration(RealServiceBase):
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
