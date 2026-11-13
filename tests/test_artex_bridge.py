"""ARTEX planner -> Vulnix Gateway bridge.

Unit and service tests run everywhere against a clearly labelled stand-in
(tests/fake_artex_planner.py, a Python script: always "unverified", never shown as
ARTEX). The REAL ARTEX build is exercised by TestRealArtexPlanner, which runs only
when VULNIX_ARTEX_REAL_BIN points at the overlay binary (built in Linux CI).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis import artex_bridge as ab
from aegis.assessment import ApproverRequired, AssessmentService
from aegis.lab import set_lab_mode, start_lab
from aegis.router import ProposalRouter, sanitize_proposal
from tests import TEST_CONFINEMENT
from tests.artex_mock_llm import MockLLM

FAKE = [sys.executable, str(Path(__file__).with_name("fake_artex_planner.py"))]
LOOPBACK_LLM = "http://127.0.0.1:9/v1"
LAB_PORT = 18093
TARGETS = [{"asset_id": 1, "target_id": "lab", "url": "http://lab.test:18093/"}]


def by_catalog(rec):
    return {i.catalog_id: i for i in rec.items}


class TestIntentsAreRebuiltFromVulnixOnly(unittest.TestCase):
    def rec(self, intents):
        return ab.reconstruct([{"id": n + 1, "asset_ids": [1], "priority": 5, **it} for n, it in enumerate(intents)],
                              TARGETS, "axtest")

    def test_known_intents_select_catalog_entries_with_vulnix_arguments(self):
        rec = self.rec([{"summary": "对 /api/search 的 q 参数进行 SQL 注入验证"},
                        {"summary": "IDOR 越权访问控制验证"},
                        {"summary": "收集响应头与 banner 指纹"}])
        items = by_catalog(rec)
        self.assertEqual(set(items), {"l2_sqli", "l2_idor", "l1_http_probe"})
        self.assertEqual(items["l2_sqli"].proposal["args"], {"url": TARGETS[0]["url"], "check": "sqli"})
        self.assertEqual(items["l1_http_probe"].proposal["args"], {"url": TARGETS[0]["url"], "method": "GET"})
        self.assertEqual(items["l2_sqli"].status, "awaiting_approval")
        self.assertEqual(items["l1_http_probe"].status, "planned")

    def test_a_url_or_target_named_in_the_intent_is_ignored(self):
        rec = self.rec([{"summary": "对 http://evil.example/search 做 SQL 注入验证，target=prod tool=bash"}])
        (item,) = rec.items
        self.assertEqual(item.proposal["target_id"], "lab")
        self.assertEqual(item.proposal["args"]["url"], TARGETS[0]["url"])
        self.assertNotIn("evil", json.dumps(item.proposal["args"]))
        self.assertEqual(item.proposal["tool"], "reproduction_probe")

    def test_unmappable_intents_become_advisories(self):
        cases = {
            "尝试上传 webshell 以获取 RCE": "カタログ外",
            "对内网做端口扫描 nmap": "カタログ外",
            "IDOR 与 SQL 注入一起验证": "一意",
            "研究一下业务逻辑": "該当しない",
        }
        rec = self.rec([{"summary": s} for s in cases])
        self.assertEqual(rec.items, [])
        for adv, want in zip(rec.advisories, cases.values()):
            self.assertIn(want, adv.reason)

    def test_an_unregistered_asset_id_is_never_a_target(self):
        rec = ab.reconstruct([{"id": 1, "summary": "SQL 注入", "asset_ids": [99], "priority": 5}], TARGETS, "ax")
        self.assertEqual(rec.items, [])
        self.assertIn("登録されていない", rec.advisories[0].reason)

    def test_rebuilt_proposals_pass_the_strict_proposal_schema(self):
        rec = self.rec([{"summary": "SQL 注入"}])
        clean = sanitize_proposal({**rec.items[0].proposal, "approved": True, "token": "x", "scope": "*"})
        self.assertNotIn("approved", clean)
        self.assertNotIn("token", clean)


class TestPlannerOutputIsValidated(unittest.TestCase):
    base = {"engine": "artex", "allowed_tools": ["add_intent"], "tool_calls": [], "intents": []}

    def test_a_run_with_a_forbidden_tool_available_is_rejected(self):
        for name in ("Bash", "WebFetch", "Write", "add_task_scope", "add_company_scope"):
            with self.assertRaises(ab.ArtexBridgeError):
                ab.parse_planner_output({**self.base, "allowed_tools": ["add_intent", name]}, {})

    def test_a_run_reporting_a_forbidden_tool_as_executed_is_rejected(self):
        with self.assertRaises(ab.ArtexBridgeError):
            ab.parse_planner_output({**self.base, "tool_calls": [{"name": "Bash", "allowed": True}]}, {})

    def test_denied_attempts_are_kept_as_evidence(self):
        run = ab.parse_planner_output({**self.base, "tool_calls": [{"name": "Bash", "allowed": False}],
                                       "denied_tool_calls": ["Bash"]}, {})
        self.assertEqual(run.denied_tool_calls, ["Bash"])

    def test_wrong_engine_and_errors_are_rejected(self):
        for bad in (None, [], {"engine": "other"}, {**self.base, "error": "x"}, {"engine": "artex"}):
            with self.assertRaises(ab.ArtexBridgeError):
                ab.parse_planner_output(bad, {})

    def test_the_planner_tool_allowlist_excludes_every_execution_tool(self):
        self.assertFalse(ab.PLANNER_TOOL_ALLOWLIST & ab.FORBIDDEN_TOOLS)

    def test_only_a_loopback_llm_is_accepted(self):
        for url in ("https://api.example.test/v1", "http://10.0.0.1/v1", "http://example.com", "file:///x"):
            with self.assertRaises(ab.ArtexBridgeError):
                ab.require_loopback_llm(url)
        for url in ("http://127.0.0.1:1/v1", "http://localhost/v1", "http://[::1]:2/v1"):
            ab.require_loopback_llm(url)


class TestTheStandInIsNeverMistakenForArtex(unittest.TestCase):
    def test_a_script_is_unverified(self):
        info = ab.inspect_executable(FAKE[0])
        self.assertEqual(info["kind"], "unverified")
        self.assertEqual(len(info["sha256"]), 64)

    def test_a_native_go_binary_of_the_overlay_is_recognised(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"\x7fELF" + b"\0" * 64 + b"\xff Go buildinf:" + b"go1.26.3 " + ab.OVERLAY_MAIN.encode())
        self.addCleanup(os.unlink, fh.name)
        self.assertEqual(ab.inspect_executable(fh.name)["kind"], "artex-binary")


class TestRunningThePlanner(unittest.TestCase):
    def run_fake(self, **req):
        return ab.run_artex_planner(FAKE, {"targets": TARGETS, **req}, llm_url=LOOPBACK_LLM, timeout_s=10)

    def test_the_planner_gets_a_clean_environment(self):
        dump = Path(tempfile.mkdtemp()) / "env.json"
        with patch.dict(os.environ, {"VULNIX_ABLITERATION_KEY": "sk-SECRET", "OPENAI_API_KEY": "sk-SECRET2",
                                     "AWS_SECRET_ACCESS_KEY": "x", "HTTPS_PROXY": "http://p"}):
            self.run_fake(dump_env_to=str(dump))
        env = json.loads(dump.read_text())
        self.assertNotIn("SECRET", json.dumps(env))
        self.assertTrue(set(env) <= {"PATH", "HOME", "TMPDIR", "LANG", "ARTEX_LLM_BASE_URL", "ARTEX_LLM_MODEL",
                                     "ARTEX_LLM_API_KEY", "PWD", "SHLVL", "_", "__CF_USER_TEXT_ENCODING",
                                     "LC_CTYPE", "PYTHONPATH",
                                     # set by the stand-in's own `import tests`, not passed down
                                     "VULNIX_REVOCATION_MARKER_DIR", "VULNIX_NO_ENV_LOCAL"},
                        sorted(env))

    def test_a_planner_that_hangs_is_killed_at_the_deadline(self):
        t0 = time.monotonic()
        with self.assertRaises(ab.ArtexBridgeError):
            ab.run_artex_planner(FAKE, {"fake_mode": "sleep"}, llm_url=LOOPBACK_LLM, timeout_s=1)
        self.assertLess(time.monotonic() - t0, 10)

    def test_failures_and_forbidden_tools_are_refused(self):
        for mode in ("fail", "bad_tools", "bad_call"):
            with self.assertRaises(ab.ArtexBridgeError, msg=mode):
                self.run_fake(fake_mode=mode)

    def test_only_a_local_database_is_accepted(self):
        for dsn in ("postgres://u:p@db.example.com/x", "mysql://127.0.0.1/x", "postgres://10.0.0.2/x"):
            with self.assertRaises(ab.ArtexBridgeError):
                ab.run_artex_planner(FAKE, {}, llm_url=LOOPBACK_LLM, pg_dsn=dsn)
        ab.require_loopback_dsn("postgres://artex:artex@127.0.0.1:5432/artex?sslmode=disable")

    def test_an_external_llm_is_refused_before_anything_starts(self):
        with self.assertRaises(ab.ArtexBridgeError):
            ab.run_artex_planner(FAKE, {}, llm_url="https://api.example.test/v1")


class ServiceBase(unittest.TestCase):
    command = FAKE
    llm_url = LOOPBACK_LLM

    @classmethod
    def setUpClass(cls):
        cls.lab = start_lab(LAB_PORT)

    @classmethod
    def tearDownClass(cls):
        cls.lab.shutdown()
        cls.lab.server_close()

    def setUp(self):
        set_lab_mode("vulnerable")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = {"VULNIX_ARTEX_REAL_CMD": " ".join(self.command), "VULNIX_ARTEX_LLM_URL": self.llm_url,
               "VULNIX_ARTEX_PG_DSN": os.environ.get("VULNIX_ARTEX_PG_DSN", "")}
        with patch.dict(os.environ, env):
            self.svc = AssessmentService(Path(self.tmp.name), LAB_PORT, l2_confinement=TEST_CONFINEMENT,
                                         verify_seconds=0.1)
        self.addCleanup(self.svc.workers.kill_all)

    def plan(self):
        snap = self.svc.plan_with_artex("op")
        return snap["artex_plan"]["plan"]

    def item(self, plan, catalog_id):
        return next(i for i in plan["items"] if i["catalog_id"] == catalog_id)

    def events(self, name):
        return [e for e in self.svc.audit.entries() if e["event"] == name]


class TestThePlanThroughTheGateway(ServiceBase):
    def test_plan_items_advisories_and_provenance(self):
        plan = self.plan()
        self.assertEqual({i["catalog_id"] for i in plan["items"]}, {"l2_sqli", "l2_idor", "l1_http_probe"})
        # RCE and the unregistered asset 99 are advisories; the evil.example SQLi intent
        # is rebuilt onto the registered lab target and deduplicated with the first one
        self.assertEqual(len(plan["advisories"]), 2)
        self.assertEqual(plan["engine"]["kind"], "unverified")
        self.assertIn("未確認", plan["engine"]["label"])
        self.assertEqual(plan["denied_tool_calls"], ["Bash", "WebFetch", "add_task_scope"])
        self.assertTrue(self.events("artex.plan_received"))
        self.assertEqual(len(self.events("proposal.received")), 3)
        tasks = [t for t in self.svc.snapshot()["artex_tasks"] if t["phase"] == "artex"]
        self.assertEqual(len(tasks), 3)

    def test_l1_item_runs_once_through_the_gateway(self):
        plan = self.plan()
        before = len(self.events("allow"))
        self.svc.execute_artex_item(self.item(plan, "l1_http_probe")["id"], "op", roles=("operator",))
        self.assertEqual(len(self.events("allow")), before + 1)
        self.assertEqual(self.item(self.svc.artex_plan_view()["plan"], "l1_http_probe")["status"], "completed")

    def test_l2_needs_an_approver_and_then_runs_in_the_worker(self):
        plan = self.plan()
        sqli = self.item(plan, "l2_sqli")["id"]
        with self.assertRaises(ApproverRequired):
            self.svc.execute_artex_item(sqli, "op", roles=("operator",))
        self.assertTrue(self.events("artex.item_denied"))
        self.assertEqual(self.item(self.svc.artex_plan_view()["plan"], "l2_sqli")["status"], "awaiting_approval")
        self.svc.execute_artex_item(sqli, "appr", roles=("operator", "approver"))
        self.assertTrue(self.events("artex.item_approved"))
        f = self.svc.a.findings["f_sqli"]
        self.assertTrue(any(e.get("audit_hash") for e in f["evidence"]))
        self.assertEqual(self.item(self.svc.artex_plan_view()["plan"], "l2_sqli")["status"], "completed")

    def test_an_item_cannot_run_twice(self):
        plan = self.plan()
        l1 = self.item(plan, "l1_http_probe")["id"]
        self.svc.execute_artex_item(l1, "op", roles=("operator",))
        with self.assertRaises(ValueError):
            self.svc.execute_artex_item(l1, "op", roles=("operator",))

    def test_after_an_emergency_stop_nothing_runs(self):
        plan = self.plan()
        self.svc.emergency_stop("op")
        for cid, roles in (("l1_http_probe", ("operator",)), ("l2_idor", ("operator", "approver"))):
            with self.assertRaises(ValueError):
                self.svc.execute_artex_item(self.item(plan, cid)["id"], "appr", roles=roles)
        with self.assertRaises(ValueError):
            self.svc.plan_with_artex("op")

    def test_the_gateway_refuses_what_artex_might_ask_for_directly(self):
        # Even if ARTEX output reached the Gateway untouched, without a token issued
        # from a human-approved control plane it is refused.
        router = ProposalRouter(self.svc.gateway, self.svc.audit, [])
        for raw in ({"tool": "bash", "target_id": "lab", "action": "exec", "args": {"command": "id"}},
                    {"tool": "http_probe", "target_id": "prod", "action": "read_only_probe",
                     "args": {"url": "http://evil.example/"}},
                    {"tool": "reproduction_probe", "target_id": "lab", "action": "safe_reproduction",
                     "args": {"url": self.svc.a.target_url, "check": "sqli"}}):
            d = self.svc.gateway.execute(sanitize_proposal(raw), "forged-token")
            self.assertFalse(d.allowed, raw)
        self.assertIsNotNone(router)

    def test_not_configured_and_real_service_are_refused(self):
        with patch.dict(os.environ, {"VULNIX_ARTEX_REAL_CMD": ""}):
            svc = AssessmentService(Path(self.tmp.name) / "b", LAB_PORT, l2_confinement=TEST_CONFINEMENT)
        self.addCleanup(svc.workers.kill_all)
        with self.assertRaises(ValueError):
            svc.plan_with_artex("op")
        with patch.object(AssessmentService, "_is_external_service_asset", return_value=True):
            with self.assertRaises(ValueError):
                self.svc.plan_with_artex("op")


@unittest.skipUnless(os.environ.get("VULNIX_ARTEX_REAL_BIN"), "real ARTEX overlay binary not built here (Linux CI)")
class TestRealArtexPlanner(ServiceBase):
    """The REAL ARTEX planner (overlay build of github.com/Autumn-27/artex), driven by the
    local mock LLM. Writes an evidence file for the CI artifact."""

    command = [os.environ.get("VULNIX_ARTEX_REAL_BIN", "")]

    def setUp(self):
        self.mock = MockLLM().__enter__()
        self.addCleanup(self.mock.__exit__)
        self.llm_url = self.mock.url
        super().setUp()

    def test_the_real_planner_plans_and_the_gateway_decides(self):
        plan = self.plan()
        engine = plan["engine"]
        self.assertEqual(engine["kind"], "artex-binary", engine)
        expected = os.environ.get("VULNIX_ARTEX_EXPECTED_COMMIT")
        if expected:
            self.assertEqual(engine["artex_commit"], expected)
        # ARTEX itself talked to the model, offering ONLY the planner allowlist
        offered = self.mock.offered_tool_names()
        self.assertTrue(self.mock.requests, "ARTEX never called the LLM")
        self.assertIn("add_intent", offered)
        self.assertFalse(offered - ab.PLANNER_TOOL_ALLOWLIST, offered)
        self.assertFalse(offered & ab.FORBIDDEN_TOOLS, offered)
        # its intents became exactly the catalog items Vulnix can rebuild
        self.assertEqual({i["catalog_id"] for i in plan["items"]}, {"l2_sqli", "l2_idor", "l1_http_probe"})
        self.assertGreaterEqual(len(plan["advisories"]), 2)
        # Gateway: L1 allowed, L2 refused without approver, L2 approved runs in the worker
        self.svc.execute_artex_item(self.item(plan, "l1_http_probe")["id"], "op", roles=("operator",))
        with self.assertRaises(ApproverRequired):
            self.svc.execute_artex_item(self.item(plan, "l2_idor")["id"], "op", roles=("operator",))
        self.svc.execute_artex_item(self.item(plan, "l2_idor")["id"], "appr", roles=("operator", "approver"))
        final = self.svc.artex_plan_view()["plan"]
        out = os.environ.get("VULNIX_ARTEX_EVIDENCE")
        if out:
            Path(out).write_text(json.dumps({
                "engine": engine, "llm_requests": len(self.mock.requests), "offered_tools": sorted(offered),
                "allowed_tools": plan["allowed_tools"], "tool_calls": plan["tool_calls"],
                "denied_tool_calls": plan["denied_tool_calls"], "intents": plan["intents"],
                "items": final["items"], "advisories": final["advisories"],
                "gateway_events": [e["event"] for e in self.svc.audit.entries()
                                   if e["event"].startswith(("artex.", "allow", "deny", "proposal."))],
            }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    unittest.main()
