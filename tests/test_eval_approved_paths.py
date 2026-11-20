"""Approved one-shot paid evaluation paths, exercised ONLY with local fake transports.

No test here can reach the network: every run injects a transport, and the module-level
`_external_transport` is replaced by one that fails the test if it is ever called.
"""
import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis import ai_advisor
from aegis.audit import AuditLog
from scripts import eval_adaptive_holdout as ah
from scripts import eval_japanese_advice as ja
from scripts.eval_approval import ApprovalError

SEL_SHA = "e8eb6ecbcc82df53c8fdc997622d7152b4dfffb14df5bc618a017f96733eab87"
ADV_SHA = "4a2b188a7bebeaa16b20e6c5107fa8d935fee1410b423d1dece11f21896d30d8"
KEY = "test-only-key-not-real"


def _no_network(*_a, **_k):
    raise AssertionError("network used in a local test")


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.audit = AuditLog(self.tmp / "audit.jsonl")
        self.approvals = self.tmp / "approvals"
        for p in (patch.object(ai_advisor, "_external_transport", _no_network),
                  patch.object(socket.socket, "connect", _no_network),
                  patch.object(socket, "create_connection", _no_network)):
            p.start()
            self.addCleanup(p.stop)

    def events(self, name):
        return [e for e in self.audit.entries() if e["event"] == name]


def _selection_reply(mapping_ids, *, finish="stop", usage=(16000, 900), content=None):
    def transport(url, headers, body):
        req = json.loads(body)
        qs = [c["id"] for c in json.loads(req["messages"][1]["content"])["cases"]]
        text = content if content is not None else json.dumps({"selected": {q: [] for q in qs}})
        out = {"choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": finish}]}
        if usage is not None:
            out["usage"] = {"prompt_tokens": usage[0], "completion_tokens": usage[1]}
        mapping_ids.append((url, headers.get("Authorization", "")[:7], len(body)))
        return json.dumps(out).encode()
    return transport


class TestSelectionApprovedPath(Base):
    def run_once(self, transport, sha=SEL_SHA):
        return ah.run_approved(approval_sha256=sha, api_key=KEY, audit=self.audit, transport=transport,
                               approval_dir=self.approvals)

    def test_fixed_sha_is_the_documented_one(self):
        _, cases, owners, _ = ah.load_dataset()
        self.assertEqual(ah.fixed_request_sha256(cases, owners), SEL_SHA)

    def test_wrong_sha_sends_nothing_and_consumes_nothing(self):
        sent = []
        for bad in ("0" * 64, SEL_SHA.upper(), "", ADV_SHA):
            with self.assertRaises(ApprovalError):
                self.run_once(_selection_reply(sent), sha=bad)
        self.assertEqual(sent, [])
        self.assertFalse(self.approvals.exists() and any(self.approvals.iterdir()))

    def test_key_and_valid_audit_are_required(self):
        sent = []
        with self.assertRaises(ApprovalError):
            ah.run_approved(approval_sha256=SEL_SHA, api_key="", audit=self.audit,
                            transport=_selection_reply(sent), approval_dir=self.approvals)
        self.audit.record("x", a=1)
        lines = self.audit.path.read_text().splitlines()
        self.audit.path.write_text(lines[0].replace('"a": 1', '"a": 2').replace('"a":1', '"a":2') + "\n")
        with self.assertRaises(ApprovalError):
            self.run_once(_selection_reply(sent))
        self.assertEqual(sent, [])

    def test_one_send_then_never_again(self):
        sent = []
        r = self.run_once(_selection_reply(sent))
        self.assertTrue(r["accepted"], r)
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0][0], ah.ENDPOINT)
        self.assertEqual(sent[0][1], "Bearer ")
        self.assertEqual(r["score"]["tp"] + r["score"]["fp"], 0)       # the fake model picked nothing
        self.assertIn("paired_vs_E", r)
        self.assertNotIn(KEY, json.dumps(r))
        self.assertTrue(self.events("eval.approval_consumed"))
        self.assertTrue(self.events("planner_llm.forwarding"))
        self.assertTrue(self.audit.verify())
        with self.assertRaisesRegex(ApprovalError, "already consumed"):
            self.run_once(_selection_reply(sent))
        self.assertEqual(len(sent), 1)
        marker = self.approvals / SEL_SHA
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.approvals.stat().st_mode & 0o777, 0o700)

    def test_upstream_failure_still_consumes_the_approval(self):
        sent = []

        def broken(*a):
            sent.append(1)
            raise OSError("connection reset")
        r = self.run_once(broken)
        self.assertFalse(r["accepted"])
        with self.assertRaisesRegex(ApprovalError, "already consumed"):
            self.run_once(broken)
        self.assertEqual(len(sent), 1)

    def test_unusable_answers_are_not_adopted(self):
        cases = {"length": dict(finish="length"), "no_usage": dict(usage=None),
                 "over_budget": dict(usage=(60_000, 2_000)), "bad_json": dict(content="not json"),
                 "partial": dict(content=json.dumps({"selected": {"Q01": []}}))}
        for name, kw in cases.items():
            with self.subTest(name):
                self.approvals = self.tmp / f"approvals-{name}"
                sent = []
                r = self.run_once(_selection_reply(sent, **kw))
                self.assertFalse(r["accepted"], name)
                self.assertNotIn("score", r)
                self.assertLessEqual(len(sent), 1)

    def test_audit_failure_before_send_sends_nothing(self):
        sent = []
        real = self.audit.record

        def failing(event, **f):
            if event == "eval.approval_consumed":
                raise OSError("disk full")
            return real(event, **f)
        with patch.object(self.audit, "record", side_effect=failing):
            with self.assertRaises(OSError):
                self.run_once(_selection_reply(sent))
        self.assertEqual(sent, [])
        with self.assertRaisesRegex(ApprovalError, "already consumed"):      # fail closed: no retry
            self.run_once(_selection_reply(sent))

    def test_broad_approval_directory_is_refused(self):
        self.approvals.mkdir(mode=0o755)
        os.chmod(self.approvals, 0o755)
        sent = []
        with self.assertRaisesRegex(ApprovalError, "permissions"):
            self.run_once(_selection_reply(sent))
        self.assertEqual(sent, [])


def _advice_reply(sent, *, finish="stop", usage=(3000, 800), text=None):
    def transport(url, headers, body):
        sent.append(len(body))
        findings = json.loads(json.loads(body)["messages"][1]["content"])["findings"]
        content = text if text is not None else json.dumps({"advice": [{
            "ref": f["ref"], "claim_level": "inconclusive", "cites": ["rule"],
            "risk_explanation": "証拠が足りず判断できません。修正後に再確認してください。",
            "remediation": [{"fix": "keep_regression_check", "detail": ""}],
            "next_checks": []} for f in findings]}, ensure_ascii=False)
        out = {"choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": finish}]}
        if usage is not None:
            out["usage"] = {"prompt_tokens": usage[0], "completion_tokens": usage[1]}
        return json.dumps(out).encode()
    return transport


class TestAdviceApprovedPath(Base):
    def run_once(self, transport, sha=ADV_SHA):
        return ja.run_approved(approval_sha256=sha, api_key=KEY, audit=self.audit, transport=transport,
                               approval_dir=self.approvals)

    def test_fixed_sha_and_worst_case(self):
        import hashlib
        _, body, refs = ja.fixed_request()
        self.assertEqual(hashlib.sha256(body).hexdigest(), ADV_SHA)
        self.assertEqual(len(refs), 20)
        self.assertLessEqual(ja.worst_case_usd(body, 2048), ja.APPROVED_CAP_USD)

    def test_wrong_sha_sends_nothing(self):
        sent = []
        with self.assertRaises(ApprovalError):
            self.run_once(_advice_reply(sent), sha=SEL_SHA)
        self.assertEqual(sent, [])

    def test_one_send_budget_reserved_then_never_again(self):
        sent = []
        r = self.run_once(_advice_reply(sent))
        self.assertTrue(r["accepted"], r)
        self.assertEqual((len(sent), r["sends"]), (1, 1))
        reserved = self.events("advisor.safe_send_requested")
        self.assertEqual(len(reserved), 1)
        self.assertGreater(reserved[0]["fields"]["reserved_micro_usd"], 0)
        self.assertEqual(reserved[0]["fields"]["budget_cap_micro_usd"], 20_000)
        self.assertTrue(self.events("advisor.safe_send_settled"))
        self.assertNotIn(KEY, json.dumps(r) + self.audit.path.read_text())
        self.assertNotIn("証拠が足りず", json.dumps(r, ensure_ascii=False))   # no model text kept
        with self.assertRaisesRegex(ApprovalError, "already consumed"):
            self.run_once(_advice_reply(sent))
        self.assertEqual(len(sent), 1)

    def test_unusable_replies_are_not_adopted(self):
        for name, kw in {"length": dict(finish="length"), "no_usage": dict(usage=None),
                         "over_reserved": dict(usage=(9000, 2048)), "not_json": dict(text="hello")}.items():
            with self.subTest(name):
                self.approvals = self.tmp / f"a-{name}"
                self.audit = AuditLog(self.tmp / f"audit-{name}.jsonl")
                sent = []
                r = self.run_once(_advice_reply(sent, **kw))
                if name == "not_json":
                    self.assertEqual(r.get("answered", 0), 0)
                else:
                    self.assertFalse(r["accepted"], name)

    def test_cumulative_budget_cap_holds_across_runs(self):
        # a second, different approval on the same audit log cannot exceed the cap
        sent = []
        self.run_once(_advice_reply(sent))
        with patch.object(ja, "worst_case_usd", return_value=0.0199):
            with patch("scripts.eval_approval.require_matching_approval"):
                self.approvals = self.tmp / "approvals-2"
                with self.assertRaisesRegex(ValueError, "budget exceeded"):
                    self.run_once(_advice_reply(sent))
        self.assertEqual(len(sent), 1)

    def test_bytes_on_the_wire_must_be_the_approved_bytes(self):
        sent = []
        real_build = ja.ExternalAbliterationAdvisor.build_request
        calls = {"n": 0}

        def tampered(self_, findings):
            body, refs = real_build(self_, findings)
            calls["n"] += 1
            if calls["n"] >= 3:                    # the request built inside advise()
                body = body.replace(b'"temperature": 0.2', b'"temperature": 1.5')
            return body, refs
        with patch.object(ja.ExternalAbliterationAdvisor, "build_request", tampered):
            r = self.run_once(_advice_reply(sent))
        self.assertFalse(r["accepted"])
        self.assertEqual(sent, [])


if __name__ == "__main__":
    unittest.main()
