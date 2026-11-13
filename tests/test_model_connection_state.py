"""External model connection state: configured is not connected. Only an answer
actually received marks it verified; a failed call marks it failed, recording
only the kind of failure - never the key, URL, message or response body."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from aegis.assessment import AssessmentService
from aegis.router import AbliterationBackend

KEY = "sk-test-connection-state-SECRET"
BODY_SECRET = "upstream-body-SECRET"


def ok_transport(*_):
    return json.dumps({"choices": [{"message": {"content": "所有者確認で防ぎます。"}}]}).encode()


def failing_transport(*_):
    raise urllib.error.HTTPError("http://127.0.0.1/v1/chat/completions", 401,
                                 f"Unauthorized {KEY} {BODY_SECRET}", {}, None)


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        with patch.dict(os.environ, {}, clear=True):
            self.svc = AssessmentService(Path(self._tmp.name), 19997)
        self.transport = ok_transport
        self.svc._chat_backend = AbliterationBackend(
            "http://127.0.0.1/v1/chat/completions", api_key=KEY,
            transport=lambda *a: self.transport(*a))
        self.svc._model_conn["state"] = "configured"
        self.svc._external_model_configured = True

    def ask(self):
        return self.svc.ask_chat("IDORをどう防ぐ？", "test", finding_id="f_idor")


class TestConfiguredIsNotConnected(Base):
    def test_a_fresh_service_without_a_model_is_unconfigured(self):
        with patch.dict(os.environ, {}, clear=True):
            svc = AssessmentService(Path(self._tmp.name) / "b", 19996)
        st = svc.planner_status()
        self.assertEqual(st["connection_state"], "unconfigured")
        self.assertFalse(st["connection_verified"])

    def test_configuration_alone_never_claims_a_connection(self):
        with patch.dict(os.environ, {"VULNIX_ABLITERATION_URL": "http://127.0.0.1:9/v1/chat/completions"},
                        clear=True):
            svc = AssessmentService(Path(self._tmp.name) / "c", 19995)
        st = svc.planner_status()
        self.assertEqual(st["connection_state"], "configured")
        self.assertFalse(st["connection_verified"])
        self.assertIsNone(st["connection_checked_at"])
        self.assertIn("疎通未確認", st["note"])


class TestOnlyARealAnswerVerifies(Base):
    def test_an_answer_marks_verified(self):
        st = self.ask()["planner"]
        self.assertEqual(st["connection_state"], "verified")
        self.assertTrue(st["connection_verified"])
        self.assertIsNotNone(st["connection_checked_at"])

    def test_a_failure_marks_failed_even_after_an_earlier_success(self):
        first = self.ask()["planner"]
        self.transport = failing_transport
        res = self.ask()
        st = res["planner"]
        self.assertEqual(res["message"]["source"], "builtin")          # fell back
        self.assertEqual(st["connection_state"], "failed")
        self.assertFalse(st["connection_verified"])
        self.assertEqual(st["connection_error"], "HTTPError 401")
        self.assertGreater(st["status_seq"], first["status_seq"])

    def test_an_empty_answer_is_not_a_connection(self):
        self.transport = lambda *_: b'{"choices": [{"message": {"content": "  "}}]}'
        st = self.ask()["planner"]
        self.assertEqual(st["connection_state"], "failed")
        self.assertEqual(st["connection_error"], "empty_response")

    def test_the_failure_record_carries_no_secret(self):
        self.transport = failing_transport
        res = self.ask()
        blob = json.dumps(res, ensure_ascii=False) + json.dumps(self.svc.audit.entries(), ensure_ascii=False)
        self.assertNotIn(KEY, blob)
        self.assertNotIn(BODY_SECRET, blob)
        asked = [e for e in self.svc.audit.entries() if e["event"] == "chat.asked"][-1]["fields"]
        self.assertTrue(asked["sent_to_external_model"])                 # it was sent, and failed
        self.assertEqual(asked["answered_by"], "builtin")
        self.assertEqual(asked["model_error"], "HTTPError 401")

    def test_the_chat_event_carries_the_new_state_for_every_open_view(self):
        before = self.svc.bus.last_seq
        self.ask()
        ev = [e for e in self.svc.bus.since(before) if e["type"] == "chat.message"][-1]
        self.assertEqual(ev["planner"]["connection_state"], "verified")

    def _verify_with(self, mode, ok):
        rep = {"all_verified": ok, "proof_sha256": "x",
               "artex_cli": {"verified": True, "version": "t"},
               "abliteration_api": {"verified": ok, "endpoint_mode": mode}}
        with patch("aegis.assessment.verify_planner_connections", return_value=rep):
            self.svc.verify_planner_connections("appr")
        return self.svc.planner_status()

    def test_only_a_check_of_the_configured_endpoint_changes_its_state(self):
        self.assertEqual(self._verify_with("local_openai_server", True)["connection_state"], "configured")
        self.assertEqual(self._verify_with("external", True)["connection_state"], "verified")
        st = self._verify_with("external", False)
        self.assertEqual((st["connection_state"], st["connection_error"]), ("failed", "verification_failed"))

    def test_the_chat_event_carries_only_connection_fields(self):
        self.svc._last_planner_verification = {"abliteration_api": {"url": "https://u:tok@h/x?key=k"}}
        before = self.svc.bus.last_seq
        self.ask()
        ev = [e for e in self.svc.bus.since(before) if e["type"] == "chat.message"][-1]
        self.assertNotIn("last_verification", ev["planner"])
        self.assertNotIn("tok", json.dumps(ev, ensure_ascii=False))
        self.assertTrue(ev["planner"]["boot_id"])

    def test_concurrent_questions_keep_their_own_error_kind(self):
        backend = self.svc._chat_backend
        self.transport = failing_transport
        ans, err = backend.chat_with_status("q", {})
        self.assertEqual((ans, err), (None, "HTTPError 401"))
        self.assertFalse(hasattr(backend, "last_error"))      # nothing shared to race on

    def test_verification_state_is_not_persisted_across_restarts(self):
        self.ask()
        with patch.dict(os.environ, {"VULNIX_ABLITERATION_URL": "http://127.0.0.1:9/v1/chat/completions"},
                        clear=True):
            again = AssessmentService(Path(self._tmp.name), 19997)
        self.assertEqual(again.planner_status()["connection_state"], "configured")


if __name__ == "__main__":
    unittest.main()


class TestVerificationReportsCarryNoSecrets(unittest.TestCase):
    def test_endpoint_credentials_and_model_text_are_removed(self):
        from aegis.router import redact_verification_report
        rep = redact_verification_report({"all_verified": True, "abliteration_api": {
            "url": "https://user:tok-SECRET@api.example.test:8443/v1/chat/completions?key=q-SECRET#frag",
            "chat_preview": "model text", "chat_verified": True}})
        api = rep["abliteration_api"]
        self.assertEqual(api["url"], "https://api.example.test:8443")
        self.assertNotIn("chat_preview", api)
        self.assertTrue(api["chat_verified"])
        self.assertNotIn("SECRET", json.dumps(rep))

    def test_a_token_in_the_path_is_dropped_and_ipv6_stays_bracketed(self):
        from aegis.router import _safe_endpoint
        self.assertEqual(_safe_endpoint("https://h.example/v1/tok-SECRET/chat"), "https://h.example")
        self.assertEqual(_safe_endpoint("http://[::1]:8080/v1"), "http://[::1]:8080")
        self.assertEqual(_safe_endpoint("not a url"), "")

    def test_a_report_saved_by_an_older_version_is_redacted_on_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {}, clear=True):
                svc = AssessmentService(Path(tmp), 19994)
                svc._last_planner_verification = {"abliteration_api": {
                    "url": "https://u:tok-SECRET@h/v1?key=SECRET", "chat_preview": "SECRET"}}
                with svc._lock:
                    svc._save_state_locked()
                again = AssessmentService(Path(tmp), 19994)
            self.assertNotIn("SECRET", json.dumps(again.planner_status()))
            self.assertNotIn("SECRET", json.dumps(again.snapshot(), ensure_ascii=False))
