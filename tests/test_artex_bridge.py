"""ARTEX planner -> Vulnix Gateway bridge.

Unit and service tests run everywhere against a clearly labelled stand-in
(tests/fake_artex_planner.py, a Python script: always "unverified", never shown as
ARTEX). The REAL ARTEX build is exercised by TestRealArtexPlanner, which runs only
when VULNIX_ARTEX_REAL_BIN points at the overlay binary (built in Linux CI).
"""
from __future__ import annotations

import json
import os
import shlex
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis import artex_bridge as ab
from aegis.assessment import ApproverRequired, AssessmentService
from aegis.lab import set_lab_mode, start_lab
from aegis.router import sanitize_proposal
from tests import TEST_CONFINEMENT
from tests.artex_mock_llm import UNSEEDED_MARKER, MockLLM

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

    def test_an_intent_naming_an_unseeded_artex_asset_is_advisory(self):
        rec = ab.reconstruct([{"id": 1, "summary": "SQL 注入", "asset_ids": [], "priority": 5, "unmapped": True}],
                             TARGETS, "ax")
        self.assertEqual(rec.items, [])
        self.assertIn("登録されていない", rec.advisories[0].reason)
        run = ab.parse_planner_output({"engine": "artex", "allowed_tools": ["add_intent"], "intents": [
            {"id": 1, "summary": "SQL 注入", "asset_ids": [], "unmapped_asset_ids": [3]}]}, {})
        self.assertTrue(run.intents[0]["unmapped"])

    def test_an_artex_build_that_omits_the_unmapped_field_fails_closed(self):
        out = {"engine": "artex", "allowed_tools": ["add_intent"],
               "intents": [{"id": 1, "summary": "SQL 注入", "asset_ids": []}]}
        self.assertTrue(ab.parse_planner_output(out, {"kind": "artex-binary"}).intents[0]["unmapped"])
        self.assertFalse(ab.parse_planner_output(out, {"kind": "unverified"}).intents[0]["unmapped"])

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

    MODINFO = (b"\x7fELF" + b"\0" * 64 + b"\xff Go buildinf:" + b"\0" * 16 +
               b"path\t" + ab.OVERLAY_MAIN.encode() + b"\nmod\t" + ab.ARTEX_MODULE.encode() +
               b"\t(devel)\t\ndep\tgithub.com/Autumn-27/norma\tv0.4.3\th1:x\n")

    def test_the_overlay_build_info_is_recognised_and_pinning_is_checked(self):
        info = ab.inspect_bytes(self.MODINFO)
        self.assertEqual(info["kind"], "artex-binary")
        self.assertEqual(info["norma_version"], "v0.4.3")
        self.assertFalse(info["pinned"])
        self.assertTrue(ab.inspect_bytes(self.MODINFO, expected_sha256=info["sha256"])["pinned"])
        self.assertFalse(ab.inspect_bytes(self.MODINFO, expected_sha256="0" * 64)["pinned"])

    def test_the_package_path_as_a_mere_string_is_not_enough(self):
        forged = b"\x7fELF" + b"\0" * 64 + b"\xff Go buildinf:" + b" " + ab.OVERLAY_MAIN.encode()
        self.assertEqual(ab.inspect_bytes(forged)["kind"], "unverified")

    def test_a_pin_mismatch_refuses_to_run(self):
        with self.assertRaises(ab.ArtexBridgeError):
            ab.run_artex_planner(FAKE, {}, llm_url=LOOPBACK_LLM, expected_sha256="0" * 64)


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
        for dsn in ("postgres://u:p@db.example.com/x", "mysql://127.0.0.1/x", "postgres://10.0.0.2/x",
                    "postgres://u:p@localhost:5432,evil.example:5432/db", "postgres://127.0.0.1:99999/x",
                    "postgres://u:p@127.0.0.1/x?host=db.example.com", "postgres://127.0.0.1/x?hostaddr=10.0.0.1"):
            with self.assertRaises(ab.ArtexBridgeError):
                ab.run_artex_planner(FAKE, {}, llm_url=LOOPBACK_LLM, pg_dsn=dsn)
        ab.require_loopback_dsn("postgres://artex:artex@127.0.0.1:5432/artex?sslmode=disable")

    def test_an_external_llm_is_refused_before_anything_starts(self):
        with self.assertRaises(ab.ArtexBridgeError):
            ab.run_artex_planner(FAKE, {}, llm_url="https://api.example.test/v1")


class ServiceBase(unittest.TestCase):
    command = FAKE
    llm_url = LOOPBACK_LLM
    expected_sha256 = ""
    # the stand-in cannot be pinned, so the service tests run as development; the
    # real ARTEX test runs as production (pin required)
    aegis_env = "development"

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
        env = {"VULNIX_ARTEX_REAL_CMD": shlex.join(self.command), "VULNIX_ARTEX_LLM_URL": self.llm_url,
               "VULNIX_ARTEX_PG_DSN": os.environ.get("VULNIX_ARTEX_PG_DSN", ""),
               "VULNIX_ARTEX_EXPECTED_SHA256": self.expected_sha256}
        self._env = patch.dict(os.environ, {"AEGIS_ENV": self.aegis_env})
        self._env.start()
        self.addCleanup(self._env.stop)
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

    def test_a_valid_token_still_cannot_reach_outside_the_scope(self):
        apr = self.svc.approval_store.approve("appr", "eng_demo", "lab", "read_only_probe")
        tok = self.svc.tokens.issue(self.svc.a.engagement, "lab", "read_only_probe", "http_probe", apr,
                                    self.svc.approval_store, ttl=60)
        d = self.svc.gateway.execute({"tool": "http_probe", "target_id": "lab", "action": "read_only_probe",
                                      "args": {"url": "http://evil.example/", "method": "GET"}}, tok)
        self.assertFalse(d.allowed)

    def test_a_tampered_stored_proposal_is_ignored(self):
        plan = self.plan()
        l1 = self.item(plan, "l1_http_probe")["id"]
        self.svc._artex_items[l1]["item"].proposal["args"]["url"] = "http://evil.example/"
        self.svc._artex_items[l1]["item"].proposal["tool"] = "bash"
        self.svc.execute_artex_item(l1, "op", roles=("operator",))
        urls = [e["fields"].get("url") or "" for e in self.svc.audit.entries() if e["event"] == "allow"]
        self.assertFalse(any("evil" in u for u in urls))

    def test_items_of_an_old_plan_or_workspace_never_run(self):
        plan = self.plan()
        old_l1 = self.item(plan, "l1_http_probe")["id"]
        newer = self.plan()                       # a new plan replaces the old one
        with self.assertRaises(ValueError):
            self.svc.execute_artex_item(old_l1, "op", roles=("operator",))
        l1 = self.item(newer, "l1_http_probe")["id"]
        self.svc.emergency_stop("op")
        self.svc.restart("op")                    # starts a new run in a new workspace
        try:
            with self.assertRaises(ValueError):
                self.svc.execute_artex_item(l1, "op", roles=("operator",))
            self.assertIsNone(self.svc.artex_plan_view()["plan"])
        finally:
            self.svc.emergency_stop("op")
            if self.svc._thread is not None:
                self.svc._thread.join(timeout=30)

    def test_re_planning_replaces_the_old_tasks_and_waits_for_a_running_item(self):
        first = self.plan()
        self.plan()
        self.assertEqual(len([t for t in self.svc.snapshot()["artex_tasks"] if t["phase"] == "artex"]), 3)
        current = self.svc.artex_plan_view()["plan"]
        self.assertNotEqual(current["run_id"], first["run_id"])
        rec = next(iter(self.svc._artex_items.values()))
        rec["item"].status = "running"
        with self.assertRaises(ValueError):
            self.svc.plan_with_artex("op")

    def test_the_planner_cannot_approve_its_own_l2_even_across_plans(self):
        self.svc.separate_l2_approver = True
        plan = self.plan()                        # requested by "op"
        with self.assertRaises(ApproverRequired):
            self.svc.execute_artex_item(self.item(plan, "l2_idor")["id"], "op", roles=("operator", "approver"))

    def test_one_item_cannot_be_claimed_twice_concurrently(self):
        plan = self.plan()
        l1 = self.item(plan, "l1_http_probe")["id"]
        results, gate = [], threading.Barrier(2)

        def go():
            gate.wait()
            try:
                self.svc.execute_artex_item(l1, "op", roles=("operator",))
                results.append("ran")
            except ValueError:
                results.append("refused")
        threads = [threading.Thread(target=go) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        self.assertEqual(sorted(results), ["ran", "refused"])

    def test_the_gateway_refuses_what_artex_might_ask_for_directly(self):
        # Even if ARTEX output reached the Gateway untouched, without a token issued
        # from a human-approved control plane it is refused.
        for raw in ({"tool": "bash", "target_id": "lab", "action": "exec", "args": {"command": "id"}},
                    {"tool": "http_probe", "target_id": "prod", "action": "read_only_probe",
                     "args": {"url": "http://evil.example/"}},
                    {"tool": "reproduction_probe", "target_id": "lab", "action": "safe_reproduction",
                     "args": {"url": self.svc.a.target_url, "check": "sqli"}}):
            d = self.svc.gateway.execute(sanitize_proposal(raw), "forged-token")
            self.assertFalse(d.allowed, raw)

    def test_not_configured_and_real_service_are_refused(self):
        with patch.dict(os.environ, {"VULNIX_ARTEX_REAL_CMD": ""}):
            svc = AssessmentService(Path(self.tmp.name) / "b", LAB_PORT, l2_confinement=TEST_CONFINEMENT)
        self.addCleanup(svc.workers.kill_all)
        with self.assertRaises(ValueError):
            svc.plan_with_artex("op")
        with patch.object(AssessmentService, "_is_external_service_asset", return_value=True):
            with self.assertRaises(ValueError):
                self.svc.plan_with_artex("op")


class TestArtexRunsOnlyUnderOsConfinement(ServiceBase):
    def test_ruleset_pins_each_extra_endpoint_and_nothing_else(self):
        from aegis.confinement import ConfinementError, ruleset
        rules = ruleset("aegis_l2_0123456789ab", "127.0.0.1", 18080, (("127.0.0.1", 5432),))
        self.assertIn("tcp dport 18080 ct state new", rules)
        self.assertIn("tcp dport 5432 ct state new", rules)
        self.assertEqual(rules.count("ct state established"), 1)
        self.assertTrue(rules.rstrip().splitlines()[-1].strip() == "}" and "counter drop" in rules)
        self.assertEqual(ruleset("aegis_l2_0123456789ab", "127.0.0.1", 1),
                         ruleset("aegis_l2_0123456789ab", "127.0.0.1", 1, ()))
        for bad in ((("169.254.169.254", 80),), (("127.0.0.1", 0),), (("localhost", 5432),)):
            with self.assertRaises(ConfinementError):
                ruleset("aegis_l2_0123456789ab", "127.0.0.1", 1, bad)

    def test_no_confinement_means_artex_does_not_run(self):
        from aegis.confinement import KernelConfinement
        unavailable = KernelConfinement(platform="darwin")
        self.svc._l2_confinement = unavailable
        with self.assertRaises(ValueError) as cm:
            self.svc.plan_with_artex("op")
        self.assertIn("隔離", str(cm.exception))
        self.assertTrue(self.events("artex.plan_refused"))
        self.assertFalse(self.events("artex.plan_received"))

    def test_an_explicit_dev_opt_out_runs_unconfined_and_says_so(self):
        from aegis.confinement import KernelConfinement
        self.svc._l2_confinement = KernelConfinement(platform="darwin")
        with patch.dict(os.environ, {"VULNIX_ARTEX_ALLOW_UNCONFINED": "1", "AEGIS_ENV": "production"}):
            with self.assertRaises(ValueError):           # never outside development
                self.svc.plan_with_artex("op")
        with patch.dict(os.environ, {"VULNIX_ARTEX_ALLOW_UNCONFINED": "1", "AEGIS_ENV": "development"}):
            plan = self.plan()
        self.assertFalse(plan["isolation"]["confined"])
        self.assertIn("本番利用不可", plan["isolation"]["label"])
        self.assertTrue(self.events("artex.unconfined_dev_run"))

    def test_the_session_pins_llm_and_database_and_protects_the_data_dir(self):
        with patch.object(self.svc, "_artex_pg_dsn", "postgres://a:b@127.0.0.1:5432/artex"):
            plan = self.plan()
        self.assertEqual(TEST_CONFINEMENT.sessions[-1], ("127.0.0.1", 9))
        checks = TEST_CONFINEMENT.last_checks
        self.assertEqual(checks["extra_endpoints"], (("127.0.0.1", 5432),))
        data_files = {str(p) for p in Path(self.tmp.name).iterdir() if p.is_file()}
        self.assertTrue(data_files and data_files <= set(checks["forbidden_paths"]))
        self.assertTrue(plan["isolation"]["confined"])
        self.assertIn("limits", plan["isolation"])          # evidence keys reach the view

    def test_production_requires_the_binary_sha256(self):
        with patch.dict(os.environ, {"AEGIS_ENV": "production"}):
            for pin in ("", "not-a-hash"):
                with patch.object(self.svc, "_artex_expected_sha256", pin):
                    with self.assertRaises(ValueError) as cm:
                        self.svc.plan_with_artex("op")
                    self.assertIn("SHA-256", str(cm.exception))
            # a well-formed pin that the binary does not match: refused before it runs
            with patch.object(self.svc, "_artex_expected_sha256", "0" * 64):
                with self.assertRaises(ValueError):
                    self.svc.plan_with_artex("op")
        with patch.dict(os.environ, {"AEGIS_ENV": ""}):     # unmarked = production
            with self.assertRaises(ValueError):
                self.svc.plan_with_artex("op")
        self.assertTrue([e for e in self.events("artex.plan_refused")
                         if e["fields"].get("reason") == "binary sha256 not pinned"])

    def test_the_lab_port_is_never_a_planner_endpoint(self):
        with patch.object(self.svc, "_artex_llm_url", f"http://127.0.0.1:{LAB_PORT}/v1"):
            with self.assertRaises(ValueError):
                self.svc.plan_with_artex("op")

    def test_limits_and_the_leftover_hook_reach_the_session(self):
        captured = {}

        class Sess:
            evidence = {"mechanism": "fake"}
            on_leftover = None

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                captured["on_leftover"] = self.on_leftover
                return None

            def wrap(self, argv, **kw):
                captured["interpreter"] = kw.get("interpreter")
                return list(argv)

            def still_enforced(self):
                return True

            def kill(self):
                return True

        class Prov:
            def status(self):
                return {"ok": True}

            def session(self, ip, port, **kw):
                captured.update(kw)
                return Sess()
        self.svc._l2_confinement = Prov()
        self.plan()
        self.assertEqual(captured["limits"], ab.ARTEX_LIMITS)
        self.assertEqual(captured["on_leftover"], self.svc._note_leftover_session)
        self.assertEqual(captured["interpreter"], sys.executable)

    def test_a_lost_confinement_after_the_run_discards_the_result(self):
        class Sess:
            evidence = {}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return None

            def wrap(self, argv, **kw):
                return list(argv)

            def __init__(self):
                self.calls = 0

            def still_enforced(self):
                self.calls += 1
                return self.calls == 1            # true before, false after the run

            def kill(self):
                return True

        class Prov:
            def status(self):
                return {"ok": True}

            def session(self, ip, port, **kw):
                return Sess()
        self.svc._l2_confinement = Prov()
        with self.assertRaises(ValueError):
            self.svc.plan_with_artex("op")
        self.assertTrue(self.events("artex.plan_failed"))

    def test_a_planner_not_confirmed_dead_makes_the_stop_unconfirmed_and_blocks_new_runs(self):
        class Stuck:
            name = "aegis_l2_stuck0000000"

            def kill(self):
                return False

            def empty(self):
                return False

            def still_enforced(self):
                return True
        stuck = Stuck()
        self.svc._artex_live.add(stuck)
        report = self.svc.emergency_stop("op")
        self.assertFalse(report["stop_report"]["confirmed"] if "stop_report" in report else report["confirmed"])
        self.assertTrue(self.svc._session_on_record(stuck))
        self.assertTrue(self.events("artex.stop_unconfirmed"))
        self.svc._artex_live.discard(stuck)
        self.svc._unstopped = [u for u in self.svc._unstopped if stuck not in (u.get("sessions") or [])]

    def test_the_stop_kills_again_while_it_waits(self):
        class Late:
            name = "aegis_l2_late00000000"

            def __init__(self):
                self.kills = 0

            def kill(self):
                self.kills += 1
                return True

            def empty(self):
                return self.kills >= 3           # a late joiner dies with a later write
        late = Late()
        self.svc._artex_live.add(late)
        try:
            self.svc.emergency_stop("op")
            self.assertGreaterEqual(late.kills, 3)
            self.assertFalse(self.svc._session_on_record(late))
        finally:
            self.svc._artex_live.discard(late)

    def test_a_survivor_on_record_blocks_a_new_planner(self):
        class Stuck:
            def empty(self):
                return False

            def still_enforced(self):
                return True

            def kill(self):
                return False
        self.svc._unstopped.append({"host": "lab.test", "pids": [], "at": 0, "pool": None, "sessions": [Stuck()]})
        try:
            with self.assertRaises(ValueError):
                self.svc.plan_with_artex("op")
        finally:
            self.svc._unstopped.clear()

    def test_a_stop_during_set_up_means_artex_never_starts(self):
        svc = self.svc
        started = []

        class Sess:
            evidence = {}
            _cancelled = False

            def __enter__(self):
                svc.emergency_stop("op")           # pressed while the probe runs
                return self

            def __exit__(self, *exc):
                return None

            def wrap(self, argv, **kw):
                return list(argv)

            def still_enforced(self):
                return True

            def kill(self):
                self._cancelled = True
                return True

            def empty(self):
                return True

        class Prov:
            def status(self):
                return {"ok": True}

            def session(self, ip, port, **kw):
                return Sess()
        svc._l2_confinement = Prov()
        real_popen = ab.subprocess.Popen
        with patch.object(ab.subprocess, "Popen", side_effect=lambda *a, **k: started.append(a) or real_popen(*a, **k)):
            with self.assertRaises(ValueError):
                svc.plan_with_artex("op")
        self.assertEqual(started, [])
        self.assertFalse(svc._artex_live)

    def test_a_named_host_is_refused_for_a_confined_run(self):
        with patch.object(self.svc, "_artex_llm_url", "http://localhost:9/v1"):
            with self.assertRaises(ValueError):
                self.svc.plan_with_artex("op")


@unittest.skipUnless(os.environ.get("VULNIX_ARTEX_REAL_BIN"), "real ARTEX overlay binary not built here (Linux CI)")
class TestRealArtexPlanner(ServiceBase):
    """The REAL ARTEX planner (overlay build of github.com/Autumn-27/artex), driven by the
    local mock LLM. Writes an evidence file for the CI artifact."""

    command = [os.environ.get("VULNIX_ARTEX_REAL_BIN", "")]
    expected_sha256 = os.environ.get("VULNIX_ARTEX_CI_BINARY_SHA256", "")
    aegis_env = "production"

    def setUp(self):
        self.mock = MockLLM().__enter__()
        self.addCleanup(self.mock.__exit__)
        self.llm_url = self.mock.url
        super().setUp()
        self.confined = os.environ.get("VULNIX_ARTEX_CONFINE") == "1"
        if self.confined:
            from aegis.confinement import KernelConfinement
            self.svc._l2_confinement = KernelConfinement()     # the real kernel confinement
            # a loopback listener ARTEX is NOT allowed to reach
            import socket
            self.canary = socket.socket()
            self.canary.bind(("127.0.0.1", 0))
            self.canary.listen(8)
            self.canary.settimeout(0.2)
            self.addCleanup(self.canary.close)
            env = patch.dict(os.environ, {"VULNIX_ARTEX_EGRESS_CANARY": f"127.0.0.1:{self.canary.getsockname()[1]}"})
            env.start()
            self.addCleanup(env.stop)

    def test_the_real_planner_plans_and_the_gateway_decides(self):
        plan = self.plan()
        engine = plan["engine"]
        self.assertEqual(engine["kind"], "artex-binary", engine)
        if self.expected_sha256:
            self.assertTrue(engine["pinned"], engine)
            self.assertEqual(engine["sha256"], self.expected_sha256)
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
        # webshell/RCE and the target-less recon intent are advisories; the asset-99
        # intent is refused by ARTEX itself (no such asset), so it never reaches Vulnix
        self.assertFalse(any("asset 99" in a["summary"] for a in plan["advisories"]))
        reasons = [a["reason"] for a in plan["advisories"]]
        self.assertTrue(any("カタログ外" in r for r in reasons), reasons)
        self.assertTrue(any("該当しない" in r for r in reasons), reasons)
        # an intent aimed at an existing but unseeded ARTEX asset is never executable
        self.assertFalse(any(UNSEEDED_MARKER in i["intent_summary"] for i in plan["items"]), plan["items"])
        # the direct-execution tools the model asked for were denied, and never ran
        self.assertTrue({"Bash", "WebFetch", "add_task_scope"} <= set(plan["denied_tool_calls"]),
                        plan["denied_tool_calls"])
        self.assertFalse([c for c in plan["tool_calls"] if c["allowed"] and c["name"] not in ab.PLANNER_TOOL_ALLOWLIST])
        iso = plan["isolation"]
        if self.confined:
            # ARTEX itself ran inside Vulnix's kernel confinement
            self.assertTrue(iso["confined"], iso)
            self.assertIn("cgroup v2", iso["mechanism"])
            self.assertTrue(iso["probe_in_cgroup"] and iso["separate_uid"] and iso["no_capabilities"], iso)
            self.assertTrue(str(iso["probe_connect"]).startswith("BLOCKED"), iso)
            # (in its own network namespace there is no route out at all: the probe's
            # packet never reaches the host's rules, so no host drop count is expected)
            self.assertTrue(iso["protected_files_denied"], iso)
            self.assertTrue(str(iso["unix_sockets"]).startswith("DENIED"), iso)
            self.assertEqual(iso["pinned"], f"127.0.0.1:{self.mock.server.server_port}")
            self.assertIn("127.0.0.1:5432", iso["pinned_extra"])
            self.assertTrue(iso.get("enforced_after_run"), iso)
            # the ARTEX process's own direct connection to a non-pinned loopback port
            self.assertTrue(str(iso["egress_canary"]).startswith("self-reported: blocked"), iso)
            # its own network namespace (only lo; host loopback unreachable, the canary
            # listener got nothing), a private mount view, the planner seccomp profile
            self.assertTrue(iso["netns_separate"], iso)
            self.assertEqual(iso["netns_interfaces"], ["lo"], iso)
            self.assertTrue(str(iso["host_loopback_canary"]).startswith("BLOCKED"), iso)
            self.assertFalse(iso["host_loopback_canary_arrived"], iso)
            self.assertEqual(set(iso["relay_endpoints"].values()), {"OK"}, iso)
            self.assertTrue(iso["hidden_paths_ok"], iso)
            for k in ("netlink_socket", "vsock_socket", "bpf_syscall"):
                self.assertTrue(str(iso[k]).startswith("DENIED"), (k, iso))
            self.assertLessEqual(iso["procs_visible"], 2, iso)       # own PID namespace
            self.assertEqual(iso["seccomp_mode"], ["2"], iso)
            self.assertFalse(iso.get("netns_left"), iso)
            self.assertEqual(iso.get("limits"), {"pids.max": 512, "memory.max": 2 << 30}, iso)
            self.assertFalse(iso.get("files_left"), iso)
            with self.assertRaises(OSError):
                self.canary.accept()                 # nothing ever arrived
        # Gateway: L1 allowed, L2 refused without approver, L2 approved runs in the worker
        self.svc.execute_artex_item(self.item(plan, "l1_http_probe")["id"], "op", roles=("operator",))
        with self.assertRaises(ApproverRequired):
            self.svc.execute_artex_item(self.item(plan, "l2_idor")["id"], "op", roles=("operator",))
        self.svc.execute_artex_item(self.item(plan, "l2_idor")["id"], "appr", roles=("operator", "approver"))
        final = self.svc.artex_plan_view()["plan"]
        out = os.environ.get("VULNIX_ARTEX_EVIDENCE")
        if out:
            Path(out).write_text(json.dumps({
                "engine": engine, "isolation": plan["isolation"],
                "llm_requests": len(self.mock.requests), "offered_tools": sorted(offered),
                "allowed_tools": plan["allowed_tools"], "tool_calls": plan["tool_calls"],
                "denied_tool_calls": plan["denied_tool_calls"], "intents": plan["intents"],
                "items": final["items"], "advisories": final["advisories"],
                "gateway_events": [e["event"] for e in self.svc.audit.entries()
                                   if e["event"].startswith(("artex.", "allow", "deny", "proposal."))],
            }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(os.environ.get("VULNIX_ARTEX_REAL_BIN") and os.environ.get("VULNIX_ARTEX_SUPERUSER_DSN"),
                     "real ARTEX overlay binary / superuser DSN only in Linux CI")
class TestRealArtexRefusesAPrivilegedDatabaseRole(unittest.TestCase):
    def test_a_superuser_dsn_is_refused_before_planning(self):
        with MockLLM() as mock:
            with self.assertRaises(ab.ArtexBridgeError) as cm:
                ab.run_artex_planner([os.environ["VULNIX_ARTEX_REAL_BIN"]], {"targets": TARGETS, "goal": "x"},
                                     llm_url=mock.url, pg_dsn=os.environ["VULNIX_ARTEX_SUPERUSER_DSN"],
                                     timeout_s=60)
            self.assertIn("refusing to plan", str(cm.exception))
            self.assertEqual(mock.requests, [])          # it never reached the model


class TestConfinementExtensionsKeepTheL2Path(unittest.TestCase):
    """The ARTEX extensions to aegis/confinement.py, exercised with a fake command runner."""

    def owner(self):
        import subprocess as sp

        from aegis.confinement import KernelConfinement
        self.calls = []

        def runner(argv, **kw):
            self.calls.append(list(argv))
            return sp.CompletedProcess(argv, 0, "", "")
        return KernelConfinement(runner=runner, platform="linux", euid=0, which=lambda t: f"/usr/bin/{t}")

    def test_a_reattached_session_tears_down_again(self):
        sess = self.owner().reattach("aegis_l2_0123456789ab")
        sess._teardown()                                   # raised AttributeError before
        self.assertFalse(sess.leftover)
        self.assertTrue(any(c[-4:] == ["delete", "table", "inet", "aegis_l2_0123456789ab"] for c in self.calls))

    def test_a_kill_freezes_the_cgroup_before_killing_and_entry_refuses_a_frozen_one(self):
        from aegis import confinement as cf
        from aegis.confinement import ConfinementSession
        o = self.owner()
        o.fresh_identity = lambda: 4242
        sess = ConfinementSession(o, "127.0.0.1", 1)
        sess._dir = True
        sess.kill()
        script, *args = self.calls[-1][2:]
        self.assertEqual(script, 'echo 1 > "$1"; f=$?; echo 1 > "$2" && [ "$f" = 0 ]')
        self.assertTrue(args[1].endswith("cgroup.freeze") and args[2].endswith("cgroup.kill"), args)
        self.assertIn("cgroup.freeze", cf._ENTER)
        self.assertLess(cf._ENTER.index('echo $$ > "$1"'), cf._ENTER.index("cgroup.freeze"))  # join, then check

    def test_wrap_names_the_interpreter_only_when_asked(self):
        from aegis.confinement import ConfinementSession
        o = self.owner()
        o.fresh_identity = lambda: 4242
        with patch.object(type(o), "staged_workers", lambda self: Path("/staged")):
            sess = ConfinementSession(o, "127.0.0.1", 1)
            plain = sess.wrap(["/usr/bin/python3", "worker.py"])
            go = sess.wrap(["/work/artex-vulnix-planner"], interpreter="/usr/bin/python3")
        self.assertEqual(plain[plain.index("-I") - 1], "/usr/bin/python3")
        self.assertEqual(go[go.index("-I") - 1:], ["/usr/bin/python3", "-I", "/staged/_sandbox_launch.py",
                                                   "/work/artex-vulnix-planner"])

    def test_the_owned_directory_is_cleared_as_the_run_uid_then_removed(self):
        from aegis.confinement import ConfinementSession
        o = self.owner()
        o.fresh_identity = lambda: 4242
        sess = ConfinementSession(o, "127.0.0.1", 1)
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: d.exists() and d.rmdir())
        sess.own_directory(d)
        self.assertIn("chown -h", " ".join(self.calls[-1]))
        self.assertTrue(sess._remove_owned())
        deletes = [c for c in self.calls if "-delete" in c]
        self.assertTrue(deletes and all("--reuid=4242" in c for c in deletes), deletes)

    def test_a_symlink_or_non_empty_directory_is_never_given_away(self):
        from aegis.confinement import ConfinementError, ConfinementSession
        o = self.owner()
        o.fresh_identity = lambda: 4242
        sess = ConfinementSession(o, "127.0.0.1", 1)
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil_rmtree, base)
        full = base / "full"
        full.mkdir()
        (full / "x").write_text("x")
        link = base / "link"
        link.symlink_to(full)
        for bad in (full, link):
            with self.assertRaises(ConfinementError):
                sess.own_directory(bad)


def shutil_rmtree(p):
    import shutil
    shutil.rmtree(p, ignore_errors=True)



class TestPlannerSeccompProfileAndNamespaceChain(unittest.TestCase):
    def launcher(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "_launch", Path(ab.__file__).with_name("workers") / "_sandbox_launch.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    def test_the_l2_filter_is_unchanged_and_the_planner_profile_is_opt_in(self):
        m = self.launcher()
        for arch, cfg in m.ARCHES.items():
            l2 = m.filter_program(cfg)
            self.assertEqual(l2, m.filter_program(cfg, False, ()))
            planner = m.filter_program(cfg, True, m.PLANNER_DENY[arch])
            self.assertNotEqual(l2, planner)
            self.assertLess(len(planner) // 8, 256)          # BPF jumps are 8-bit

    def test_planner_profile_denies_the_listed_syscalls_and_non_ip_sockets(self):
        import struct
        m = self.launcher()
        cfg = m.ARCHES["x86_64"]
        prog = m.filter_program(cfg, True, m.PLANNER_DENY["x86_64"])
        ins = [struct.unpack("HBBI", prog[i:i + 8]) for i in range(0, len(prog), 8)]
        consts = {k for code, _, _, k in ins if code == m.JEQ}
        for nr in (321, 323, 298, 101, 165, 175, 313):      # bpf userfaultfd perf ptrace mount modules
            self.assertIn(nr, consts)
        self.assertIn(m.AF_INET, consts)
        self.assertIn(m.AF_INET6, consts)
        self.assertNotIn(m.AF_UNIX, consts)                  # allow-list now, not a deny of AF_UNIX

    def test_the_profile_flag_must_be_followed_by_a_program(self):
        import subprocess as sp
        launcher = Path(ab.__file__).with_name("workers") / "_sandbox_launch.py"
        r = sp.run([sys.executable, "-I", str(launcher), "--profile=planner"], capture_output=True)
        self.assertEqual(r.returncode, 97)

    def test_the_namespace_chain_hides_and_binds_back_and_is_root_until_the_drop(self):
        import subprocess as sp

        from aegis.confinement import ConfinementSession, KernelConfinement
        o = KernelConfinement(runner=lambda a, **k: sp.CompletedProcess(a, 0, "", ""), platform="linux",
                              euid=0, which=lambda t: f"/usr/bin/{t}")
        o.fresh_identity = lambda: 4242
        work = "/tmp/vulnix-artex-abc"
        with patch.object(type(o), "staged_workers", lambda self: Path("/tmp/vulnix-worker-xyz")):
            sess = ConfinementSession(o, "127.0.0.1", 18080, extra_endpoints=(("127.0.0.1", 5432),),
                                      namespaces={"hide": ab.planner_hidden_paths(["/srv/vulnix/data/state.json"]),
                                                  "keep": [work]})
            argv = sess.wrap(["/tmp/vulnix-artex-abc/artex-vulnix-planner"], interpreter="/usr/bin/python3")
        i = argv.index("netns")
        self.assertEqual(argv[i:i + 3], ["netns", "exec", sess.name])
        script = argv[argv.index("-c", i) + 1]
        self.assertIn("mount -n --make-rprivate /", script)
        self.assertNotIn("mount -t", script.replace("mount -n -t", ""))   # every mount without utab
        for h in ("/home", "/root", "/tmp", "/var", "/dev/shm", "/run", "/opt", "/srv", "/Users", "/Volumes",
                  "/srv/vulnix/data"):
            self.assertIn(f"vxhide {h}", script)
        # the stash (/mnt) is covered only after the bind-backs and its unmount
        self.assertLess(script.index("umount -n -l /mnt"), script.index("vxhide /mnt"))
        self.assertLess(script.rindex("mount -n --bind /mnt/k0"), script.index("umount -n -l /mnt"))
        self.assertIn("--ipc", argv)
        self.assertIn("--pid", argv)
        self.assertIn("cd /", script)
        self.assertIn(f"mount -n --bind /mnt/k0 {work}", script.replace("'", ""))
        self.assertIn("hidepid=invisible", script)
        self.assertLess(argv.index("netns"), argv.index("/usr/bin/setpriv"))   # mounts before the drop
        self.assertIn("--profile=planner", argv)
        self.assertEqual(sess.ns["ports"], [5432, 18080])

    def test_namespace_mode_accepts_only_127_0_0_1_endpoints(self):
        import subprocess as sp

        from aegis.confinement import ConfinementError, ConfinementSession, KernelConfinement
        o = KernelConfinement(runner=lambda a, **k: sp.CompletedProcess(a, 0, "", ""), platform="linux", euid=0)
        o.fresh_identity = lambda: 4242
        with self.assertRaises(ConfinementError):
            ConfinementSession(o, "10.0.0.5", 80, namespaces={"hide": [], "keep": []})


@unittest.skipUnless(os.environ.get("VULNIX_ARTEX_CONFINE") == "1" and sys.platform.startswith("linux"),
                     "real kernel namespace confinement only in Linux CI")
class TestNamespaceConfinementStopsOnLinux(unittest.TestCase):
    """Emergency stop and the deadline kill, on the real kernel, in namespace mode."""

    SLEEPER = [sys.executable, "-I", "-c", "import time; time.sleep(120)"]

    def wait_until(self, cond, seconds=15):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if cond():
                return True
            time.sleep(0.2)
        return cond()

    def test_a_kill_ends_the_planner_and_its_relay_and_the_namespace_goes(self):
        import subprocess as sp
        import urllib.parse

        from aegis.confinement import KernelConfinement
        with MockLLM() as mock:
            port = urllib.parse.urlsplit(mock.url).port
            work = tempfile.mkdtemp(prefix="vulnix-artex-")
            os.chmod(work, 0o755)
            self.addCleanup(lambda: __import__("shutil").rmtree(work, True))
            sess = KernelConfinement().session("127.0.0.1", port, limits=ab.ARTEX_LIMITS,
                                               namespaces={"hide": ab.planner_hidden_paths(), "keep": [work]})
            with sess:
                self.assertTrue(sess.evidence["netns_separate"], sess.evidence)
                proc = sp.Popen(sess.wrap(self.SLEEPER, interpreter=sys.executable), stdin=sp.DEVNULL,
                                stdout=sp.DEVNULL, stderr=sp.DEVNULL, cwd=work, start_new_session=True)
                procs = sess.cgroup / "cgroup.procs"
                # the relay is always in the cgroup: wait for the planner chain to join too
                self.assertTrue(self.wait_until(lambda: len(procs.read_text().split()) >= 2, 15))
                self.assertTrue(sess.kill())                       # what emergency stop does
                proc.wait(timeout=20)
                self.assertTrue(self.wait_until(sess.empty), "cgroup not empty after kill")
                self.assertIsNotNone(sess._relay.wait(timeout=10))  # the relay died with it
            self.assertFalse(sess.leftover)
            self.assertFalse(sess.netns_left)
            self.assertFalse(os.path.exists(f"/run/netns/{sess.name}"))

    def _late_writer(self, stop_first: bool) -> tuple[bool, object]:
        """Start a process that writes a marker into a directory THE RUN'S UID owns
        (so it can write there) - after a stop (`stop_first`) or without one."""
        import subprocess as sp
        import urllib.parse

        from aegis.confinement import KernelConfinement
        with MockLLM() as mock:
            port = urllib.parse.urlsplit(mock.url).port
            work = tempfile.mkdtemp(prefix="vulnix-artex-")
            os.chmod(work, 0o755)
            self.addCleanup(lambda: __import__("shutil").rmtree(work, True))
            home = Path(work) / "home"
            home.mkdir()
            sess = KernelConfinement().session("127.0.0.1", port, limits=ab.ARTEX_LIMITS,
                                               namespaces={"hide": ab.planner_hidden_paths(), "keep": [work]})
            marker = home / "ran"
            with sess:
                sess.own_directory(home)                 # the run's uid can write here
                if stop_first:
                    self.assertTrue(sess.kill())         # the stop lands first
                    self.assertEqual((sess.cgroup / "cgroup.freeze").read_text().strip(), "1")

                def marker_exists() -> bool:
                    # the directory is the run's (0700): look as root, like the teardown does
                    return sp.run(["sudo", "-n", "test", "-e", str(marker)]).returncode == 0
                late = [sys.executable, "-I", "-c", f"open({str(marker)!r}, 'w').write('x')"]
                proc = sp.Popen(sess.wrap(late, interpreter=sys.executable), stdin=sp.DEVNULL,
                                stdout=sp.DEVNULL, stderr=sp.DEVNULL, cwd=work, start_new_session=True)
                end = time.monotonic() + 6
                while time.monotonic() < end and not marker_exists():
                    time.sleep(0.2)
                ran = marker_exists()
                if stop_first:
                    # the kernel reports the cgroup frozen once every task in it is
                    events = sess.cgroup / "cgroup.events"
                    self.assertTrue(self.wait_until(lambda: "frozen 1" in events.read_text(), 10),
                                    events.read_text())
            proc.wait(timeout=30)                        # finished, or killed by teardown
            return ran, sess

    def test_without_a_stop_the_marker_is_written(self):
        # positive control: the late-writer test below can fail
        ran, sess = self._late_writer(stop_first=False)
        self.assertTrue(ran, "the control process could not write its marker")
        self.assertFalse(sess.leftover)

    def test_a_process_that_joins_after_the_stop_never_runs(self):
        ran, sess = self._late_writer(stop_first=True)
        self.assertFalse(ran, "a process that joined after the stop ran")
        self.assertFalse(sess.leftover)
        self.assertFalse(os.path.exists(f"/run/netns/{sess.name}"))

    def test_the_deadline_kills_a_planner_that_never_ends(self):
        from aegis.confinement import KernelConfinement
        with MockLLM() as mock:
            kc = KernelConfinement()
            made = []
            original = kc.session

            def spy(*a, **k):
                s = original(*a, **k)
                made.append(s)
                return s
            kc.session = spy
            t0 = time.monotonic()
            with self.assertRaises(ab.ArtexBridgeError) as cm:
                ab.run_artex_planner(self.SLEEPER, {}, llm_url=mock.url, timeout_s=3, confinement=kc)
            self.assertIn("制限時間", str(cm.exception))
            self.assertLess(time.monotonic() - t0, 60)
            (s,) = made
            self.assertTrue(s.empty())
            self.assertFalse(s.leftover)
            self.assertFalse(os.path.exists(f"/run/netns/{s.name}"))


@unittest.skipUnless(os.environ.get("VULNIX_ARTEX_REAL_BIN"), "real ARTEX overlay binary only in Linux CI")
class TestRealArtexThroughThePlannerGateway(TestRealArtexPlanner):
    """The real ARTEX, confined, with the Vulnix Planner LLM Gateway as its only model."""

    def test_the_real_planner_plans_and_the_gateway_decides(self):      # replaced below
        pass

    def test_forward_mode_through_the_gateway_to_the_local_mock(self):
        env = {"VULNIX_ARTEX_LLM_MODE": "gateway-forward",
               "VULNIX_ARTEX_LLM_UPSTREAM_URL": self.mock.url + "/chat/completions",
               "VULNIX_ARTEX_LLM_MODEL": "gateway-forced-model"}
        with patch.dict(os.environ, env):
            plan = self.plan()
        gw = plan["llm_gateway"]
        self.assertEqual((gw["mode"], gw["refused"]), ("forward", 0), gw)
        self.assertGreaterEqual(gw["calls"], 2)
        self.assertTrue(self.mock.requests)
        self.assertTrue(all(r["body"].get("model") == "gateway-forced-model" for r in self.mock.requests))
        self.assertEqual({i["catalog_id"] for i in plan["items"]}, {"l2_sqli", "l2_idor", "l1_http_probe"})
        # the plan still goes through the Vulnix Gateway: L1 once, L2 approver only
        self.svc.execute_artex_item(self.item(plan, "l1_http_probe")["id"], "op", roles=("operator",))
        with self.assertRaises(ApproverRequired):
            self.svc.execute_artex_item(self.item(plan, "l2_idor")["id"], "op", roles=("operator",))
        out = os.environ.get("VULNIX_ARTEX_GATEWAY_EVIDENCE")
        if out:
            Path(out + ".forward.json").write_text(json.dumps(
                {"llm_gateway": gw, "isolation_confined": plan["isolation"].get("confined"),
                 "items": [(i["catalog_id"], i["status"]) for i in plan["items"]]}, ensure_ascii=False, indent=2))

    def test_preview_mode_sends_nothing_and_shows_what_would_be_sent(self):
        with patch.dict(os.environ, {"VULNIX_ARTEX_LLM_MODE": "gateway-preview",
                                     "VULNIX_ARTEX_LLM_MODEL": "abliterated-model"}):
            plan = self.plan()
        gw = plan["llm_gateway"]
        self.assertEqual((gw["mode"], gw["upstream"]), ("preview", None))
        self.assertGreaterEqual(gw["calls"], 1)                        # the real ARTEX did ask
        self.assertEqual(self.mock.requests, [])                       # not even the local mock
        pv = self.svc.artex_llm_preview()
        self.assertEqual(len(pv["requests"]), gw["calls"])
        out = os.environ.get("VULNIX_ARTEX_GATEWAY_EVIDENCE")
        if out:
            first = pv["requests"][0] if pv["requests"] else {}
            Path(out + ".preview.json").write_text(json.dumps(
                {"llm_gateway": gw, "records": pv["report"]["records"], "first_request": first},
                ensure_ascii=False, indent=2))


def _structure(req: dict) -> list:
    """The shape of a chat request (roles, tool-call wiring, content types) - no text."""
    out = []
    for m in req.get("messages") or []:
        out.append({"role": m.get("role"), "content_type": type(m.get("content")).__name__,
                    "tool_calls": [tc.get("id") for tc in m.get("tool_calls") or []],
                    "tool_call_id": m.get("tool_call_id")})
    return out


@unittest.skipUnless(os.environ.get("VULNIX_ARTEX_REAL_BIN"), "real ARTEX overlay binary only in Linux CI / test VM")
class TestRealArtexUpstreamCompatibilityAndFailure(ServiceBase):
    """The real ARTEX's follow-up request against the official tool-calling rules, and a
    failing upstream: ARTEX's internal retries must never reach it."""

    command = [os.environ.get("VULNIX_ARTEX_REAL_BIN", "")]
    expected_sha256 = os.environ.get("VULNIX_ARTEX_CI_BINARY_SHA256", "")
    aegis_env = "production"

    def run_against(self, mock):
        self.llm_url = mock.url
        with patch.dict(os.environ, {"VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                                     "VULNIX_ARTEX_LLM_UPSTREAM_URL": mock.url + "/chat/completions",
                                     "VULNIX_ARTEX_LLM_MODEL": "abliterated-model"}):
            return self.svc.plan_with_artex("op")

    def test_the_follow_up_request_meets_the_official_tool_calling_rules(self):
        from tests.artex_mock_llm import spec_violation
        with MockLLM(strict=True) as mock:
            snap = self.run_against(mock)
        plan = snap["artex_plan"]["plan"]
        self.assertGreaterEqual(len(mock.requests), 2)
        for r in mock.requests:
            self.assertIsNone(spec_violation(r["body"]))
        self.assertEqual(plan["llm_gateway"]["refused"], 0)
        out = os.environ.get("VULNIX_ARTEX_GATEWAY_EVIDENCE")
        if out:
            Path(out + ".second-request-structure.json").write_text(json.dumps(
                {"second_request": _structure(mock.requests[1]["body"]),
                 "keys": sorted(mock.requests[1]["body"])}, indent=2))

    def test_a_failing_upstream_ends_the_run_with_no_retry_reaching_it(self):
        with MockLLM(fail_at=2, fail_status=402) as mock:
            with self.assertRaises(ValueError):
                self.run_against(mock)
        self.assertEqual(len(mock.requests), 2)                     # 0 sends after the error
        pv = self.svc.artex_llm_preview()
        rep = pv["report"]
        self.assertEqual(rep["failed_upstream"]["http_status"], 402)
        self.assertNotIn("sk-mockSECRET", json.dumps(rep, ensure_ascii=False))
        audit = json.dumps(self.svc.audit.entries(), ensure_ascii=False)
        self.assertNotIn("sk-mockSECRET", audit)
        self.assertNotIn("insufficient credits", audit)
        self.assertTrue(self.events("artex.plan_failed"))
