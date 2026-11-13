"""Planner LLM Gateway: ARTEX's only model, run by Vulnix (loopback, key on Vulnix's side,
fixed upstream, inspection, budgets, preview without any external call)."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from aegis.planner_llm_gateway import Budget, GatewayRefused, PlannerLLMGateway
from tests.artex_mock_llm import MockLLM

KEY = "sk-test-gateway-key-NEVER-SENT-AS-CONTENT"
SHA = "a" * 64


def chat(text="lab.test を計画して", tools=("add_intent",), **extra):
    return {"model": "whatever-artex-asked", "messages": [{"role": "user", "content": text}],
            "tools": [{"type": "function", "function": {"name": t, "parameters": {}}} for t in tools], **extra}


def canned(_body):
    return {"choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5}}


def preview(**kw):
    return PlannerLLMGateway(mode="preview", model="abliterated-model", responder=canned,
                             allowed_hosts={"lab.test"}, denied_hosts={"real.example.com"}, api_key=KEY, **kw)


def post(gw, body, token=None):
    req = urllib.request.Request(gw.url + "/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {token or gw.token}"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


class TestInspection(unittest.TestCase):
    def test_the_model_is_forced_and_only_chat_fields_leave(self):
        out = preview().inspect({**chat(), "user": "x", "metadata": {"a": 1}, "max_tokens": 100})
        self.assertEqual(out["model"], "abliterated-model")
        self.assertEqual(set(out), {"model", "messages", "tools", "max_tokens"})

    def test_secrets_are_refused(self):
        for text in (f"key {KEY}", "AKIAABCDEFGHIJKLMNOP", "-----BEGIN RSA PRIVATE KEY-----",
                     "password: hunter2hunter2", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz"):
            with self.assertRaises(GatewayRefused, msg=text):
                preview().inspect(chat(text))

    def test_real_services_and_internal_hosts_outside_the_lab_are_refused(self):
        for text in ("https://real.example.com/api", "real.example.com のログイン",
                     "http://10.1.2.3/admin", "http://192.168.0.10/", "http://169.254.169.254/latest/meta-data",
                     "http://db.corp/", "https://wiki.internal/x", "http://intranet/", "http://[fd00::1]/"):
            with self.assertRaises(GatewayRefused, msg=text):
                preview().inspect(chat(text))
        # the lab itself, and public references a model may mention, are not Vulnix data
        preview().inspect(chat("http://lab.test:18081/ と http://127.0.0.1:18081/ を計画"))
        preview().inspect(chat("参考: https://owasp.org/www-community/attacks/SQL_Injection"))

    def test_tools_outside_the_planner_allowlist_and_streaming_are_refused(self):
        for body in (chat(tools=("add_intent", "Bash")), chat(tools=("WebFetch",)), chat(stream=True), {"x": 1}):
            with self.assertRaises(GatewayRefused):
                preview().inspect(body)

    def test_every_completion_has_an_explicit_cap(self):
        self.assertEqual(preview().inspect(chat())["max_tokens"], 2048)
        self.assertEqual(preview().inspect(chat(max_tokens=99999))["max_tokens"], 2048)


class TestPreviewSendsNothing(unittest.TestCase):
    def test_preview_records_what_would_be_sent_and_never_forwards(self):
        def boom(*_):
            raise AssertionError("preview must never call a transport")
        with preview(transport=boom) as gw:
            code, resp = post(gw, chat())
        self.assertEqual(code, 200)
        self.assertEqual(resp["choices"][0]["message"]["content"], "ok")
        rep = gw.report()
        self.assertEqual((rep["mode"], rep["calls"], rep["refused"]), ("preview", 1, 0))
        self.assertEqual(len(gw.preview_requests), 1)
        self.assertEqual(gw.preview_requests[0]["model"], "abliterated-model")
        self.assertEqual(len(rep["first_request_sha256"]), 64)

    def test_another_local_process_without_the_run_token_is_refused(self):
        with preview() as gw:
            code, _ = post(gw, chat(), token="guess")
        self.assertEqual(code, 401)
        self.assertEqual(gw.report()["calls"], 0)


class TestBudgets(unittest.TestCase):
    def test_call_token_and_cost_budgets(self):
        with preview(budget=Budget(max_calls=2)) as gw:
            codes = [post(gw, chat())[0] for _ in range(3)]
        self.assertEqual(codes, [200, 200, 403])
        with preview(budget=Budget(max_total_tokens=500)) as gw:     # a 2048 cap alone exceeds it
            self.assertEqual(post(gw, chat())[0], 403)
        b = Budget(max_cost_usd=0.001, usd_per_1k_input=1.0, usd_per_1k_output=1.0)
        with preview(budget=b) as gw:
            self.assertEqual(post(gw, chat())[0], 403)
        self.assertIn("cost budget", gw.report()["records"][0]["reason"])


class TestForwarding(unittest.TestCase):
    def test_forwards_only_to_the_fixed_upstream_with_vulnix_key_and_cleaned_body(self):
        seen = {}

        def transport(url, headers, body):
            seen.update(url=url, headers=headers, body=json.loads(body))
            return json.dumps(canned(None)).encode()
        gw = PlannerLLMGateway(mode="forward", model="abliterated-model",
                               upstream_url="https://api.example.test/v1/chat/completions", api_key=KEY,
                               allowed_hosts={"lab.test"}, transport=transport,
                               approval={"max_calls": 3, "first_request_sha256": SHA})
        clean = gw.inspect(chat())
        gw.approval["first_request_sha256"] = __import__("hashlib").sha256(
            json.dumps(clean, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
        with gw:
            code, _ = post(gw, {**chat(), "extra": "dropped"})
        self.assertEqual(code, 200)
        self.assertEqual(seen["url"], "https://api.example.test/v1/chat/completions")
        self.assertEqual(seen["headers"]["Authorization"], f"Bearer {KEY}")     # Vulnix's key, not ARTEX's token
        self.assertNotIn(gw.token, json.dumps(seen))
        self.assertNotIn("extra", seen["body"])

    def test_a_real_upstream_needs_an_approval_bound_to_a_preview(self):
        for approval in (None, {"max_calls": 2}, {"first_request_sha256": SHA}, {"max_calls": 2, "first_request_sha256": "x"}):
            with self.assertRaises(ValueError):
                PlannerLLMGateway(mode="forward", model="m", upstream_url="https://api.example.test/v1", approval=approval)
        with self.assertRaises(ValueError):
            PlannerLLMGateway(mode="forward", model="m", upstream_url="http://api.example.test/v1",
                              approval={"max_calls": 1, "first_request_sha256": SHA})

    def test_a_first_request_that_differs_from_the_approved_preview_is_refused(self):
        gw = PlannerLLMGateway(mode="forward", model="m", upstream_url="https://api.example.test/v1",
                               transport=lambda *a: (_ for _ in ()).throw(AssertionError("must not send")),
                               allowed_hosts={"lab.test"}, approval={"max_calls": 3, "first_request_sha256": SHA})
        with gw:
            code, resp = post(gw, chat())
        self.assertEqual(code, 403)
        self.assertIn("approved preview", resp["error"]["message"])

    def test_the_approval_caps_the_calls(self):
        gw = PlannerLLMGateway(mode="forward", model="m", upstream_url="https://api.example.test/v1",
                               budget=Budget(max_calls=10), approval={"max_calls": 2, "first_request_sha256": SHA})
        self.assertEqual(gw.budget.max_calls, 2)

    def test_a_loopback_mock_upstream_needs_no_approval(self):
        with MockLLM() as mock, PlannerLLMGateway(mode="forward", model="m", upstream_url=mock.url + "/chat/completions",
                                                  allowed_hosts={"lab.test"}) as gw:
            code, resp = post(gw, chat())
        self.assertEqual(code, 200)
        self.assertTrue(mock.requests and mock.requests[0]["body"]["model"] == "m")


class TestTheAuditHasNoContent(unittest.TestCase):
    def test_decisions_are_audited_without_content(self):
        from aegis.audit import AuditLog
        with tempfile.TemporaryDirectory() as tmp:
            audit = AuditLog(Path(tmp) / "audit.jsonl")
            with preview(audit=audit) as gw:
                post(gw, chat("UNIQUE-CONTENT-MARKER lab.test"))
                post(gw, chat(f"leak {KEY}"))
            blob = json.dumps(audit.entries(), ensure_ascii=False)
        self.assertIn("planner_llm.call", blob)
        self.assertIn("planner_llm.refused", blob)
        self.assertNotIn("UNIQUE-CONTENT-MARKER", blob)
        self.assertNotIn(KEY, blob)


class TestServiceUsesTheGateway(unittest.TestCase):
    """plan_with_artex with the gateway (the stand-in planner: no real ARTEX here)."""

    def svc(self, env):
        from aegis.assessment import AssessmentService
        from tests import TEST_CONFINEMENT
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        fake = [sys.executable, str(Path(__file__).with_name("fake_artex_planner.py"))]
        base = {"VULNIX_ARTEX_REAL_CMD": " ".join(fake), "VULNIX_ARTEX_LLM_URL": "http://127.0.0.1:9/v1",
                "AEGIS_ENV": "development"}
        with patch.dict(os.environ, {**base, **env}):
            s = AssessmentService(Path(tmp.name), 18094, l2_confinement=TEST_CONFINEMENT)
        self.addCleanup(s.workers.kill_all)
        p = patch.dict(os.environ, {**base, **env})
        p.start()
        self.addCleanup(p.stop)
        return s

    def test_preview_mode_runs_and_reports_with_no_external_call(self):
        svc = self.svc({"VULNIX_ARTEX_LLM_MODE": "gateway-preview"})
        snap = svc.plan_with_artex("op")
        gw = snap["artex_plan"]["plan"]["llm_gateway"]
        self.assertEqual(gw["mode"], "preview")
        self.assertIsNone(gw["upstream"])

    def test_forward_to_a_real_endpoint_needs_an_approver_and_an_approval(self):
        from aegis.assessment import ApproverRequired
        svc = self.svc({"VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                        "VULNIX_ARTEX_LLM_UPSTREAM_URL": "https://api.example.test/v1/chat/completions"})
        with self.assertRaises(ApproverRequired):
            svc.plan_with_artex("op", roles=("operator",))
        with self.assertRaises(ValueError):
            svc.plan_with_artex("appr", roles=("operator", "approver"))


if __name__ == "__main__":
    unittest.main()
