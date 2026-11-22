"""ARTEX planner -> Vulnix Gateway bridge.

Unit and service tests run everywhere against a clearly labelled stand-in
(tests/fake_artex_planner.py, a Python script: always "unverified", never shown as
ARTEX). The REAL ARTEX build is exercised by TestRealArtexPlanner, which runs only
when VULNIX_ARTEX_REAL_BIN points at the overlay binary (built in Linux CI).
"""
from __future__ import annotations

import contextlib
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

    def test_mod_status_intent_uses_only_the_fixed_catalog_path(self):
        rec = self.rec([{"summary": "Check Apache mod_status at http://evil.example/private"}])
        items = by_catalog(rec)
        self.assertEqual(set(items), {"l1_apache_mod_status"})
        self.assertEqual(items["l1_apache_mod_status"].proposal["args"],
                         {"url": "http://lab.test:18093/server-status?auto"})
        self.assertEqual(items["l1_apache_mod_status"].proposal["tool"], "status_marker")

    def test_ambiguous_l1_intent_is_advice_only(self):
        rec = self.rec([{"summary": "Check Apache mod_status and security headers"}])
        self.assertEqual(rec.items, [])
        self.assertIn("一意", rec.advisories[0].reason)

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


class TestPlannerCannotReadHostConfiguration(unittest.TestCase):
    """/etc (user list, host name, service configuration) is hidden from the planner like
    the homes and state directories; the confined run reports hidden_paths_ok only when
    every listed path is hidden inside its mount view."""

    def test_etc_is_hidden(self):
        hidden = ab.planner_hidden_paths()
        for path in ("/etc", "/home", "/root", "/var", "/run", "/opt"):
            self.assertIn(path, hidden)


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
        # close the service too: see tests/test_adaptive_plan_runner.py
        self.addCleanup(self.svc.close)

    def plan(self):
        snap = self.svc.plan_with_artex("op")
        return snap["artex_plan"]["plan"]

    def signed_mock_root(self, *, banner="Apache/2.4.62", status_consent=True):
        from tests.test_real_service import FakeService, HOST

        site = FakeService()
        site.banner = banner
        threading.Thread(target=site.serve_forever, daemon=True).start()
        self.addCleanup(site.server_close)
        self.addCleanup(site.shutdown)
        url = f"http://{HOST}:{site.server_port}"
        self.svc._custom_resolver = lambda host: ["127.0.0.1"] if host == HOST else []
        self.svc._real_site_local_artex = True
        challenge = self.svc.issue_ownership_challenge(url=url)["challenge"]
        self.svc.verify_asset_ownership(
            url_or_host=url, method="dns_txt",
            dns_lookup=lambda name: [f'{name} text = "{challenge["dns_txt_value"]}"'])
        self.svc.confirm_asset_scope(url_or_host=url, confirmed_prohibited=True,
                                     activate_workspace=True, allow_loopback_test=True,
                                     allow_status_probe=status_consent)
        self.svc.start()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and self.svc.snapshot()["state"] == "running":
            time.sleep(0.02)
        self.assertEqual(self.svc.snapshot()["state"], "completed", self.svc.snapshot().get("failure"))
        self.assertEqual(site.seen, [("/", None)])
        return site, url

    def item(self, plan, catalog_id):
        return next(i for i in plan["items"] if i["catalog_id"] == catalog_id)

    def events(self, name):
        return [e for e in self.svc.audit.entries() if e["event"] == name]


class TestThePlanThroughTheGateway(ServiceBase):
    def test_planner_send_scope_turns_revoked_http_lease_into_unsent_refusal(self):
        from aegis.planner_llm_gateway import GatewayRefused
        from aegis.policy import PolicyError

        def allowed():
            return True

        @contextlib.contextmanager
        def revoked_lease():
            raise PolicyError("revoked")
            yield

        allowed.lease = revoked_lease
        with patch.dict(os.environ, {"VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                                  "VULNIX_ARTEX_LLM_UPSTREAM_URL": "http://127.0.0.1:9/v1/chat/completions"}):
            gateway = self.svc._planner_gateway("op", None, (), self.svc._run_generation,
                                                "gateway-forward", real_site=True,
                                                request_authorized=allowed)
        with self.assertRaises(GatewayRefused) as caught:
            with gateway._send_scope():
                self.fail("a revoked request entered the send scope")
        self.assertEqual(caught.exception.code, "stopped")

    def test_failed_plan_audit_cannot_leave_an_executable_or_attributed_plan(self):
        original = self.svc.audit.record

        def fail_receipt(event, **fields):
            if event == "artex.plan_received":
                raise OSError("audit unavailable")
            return original(event, **fields)

        with patch.object(self.svc.audit, "record", side_effect=fail_receipt):
            with self.assertRaises(OSError):
                self.plan()
        snap = self.svc.snapshot()
        self.assertIsNone(snap["plan_source"])
        self.assertIsNone(snap["artex_plan"]["plan"])
        self.assertFalse(self.svc._artex_items)

    def test_plan_origin_survives_reopen_without_restoring_executable_items(self):
        plan = self.plan()
        source = self.svc.snapshot()["plan_source"]
        self.assertEqual(source["engine"], plan["engine"]["kind"])
        self.assertFalse(source["pinned"])
        self.assertIsNone(source["model"])
        reopened = AssessmentService(Path(self.tmp.name), LAB_PORT, l2_confinement=TEST_CONFINEMENT,
                                     verify_seconds=0.1)
        try:
            self.assertEqual(reopened.snapshot()["plan_source"], source)
            self.assertIsNone(reopened.artex_plan_view()["plan"])
            with reopened._lock:
                reopened._reset_workspace_locked()
            self.assertIsNone(reopened.snapshot()["plan_source"])
        finally:
            reopened.close()

    def test_initial_owned_scan_plans_after_signed_root_without_extra_get(self):
        from aegis import assessment as assessment_module
        from tests.test_real_service import FakeService, HOST

        site = FakeService()
        site.banner = "Apache/2.4.62"
        threading.Thread(target=site.serve_forever, daemon=True).start()
        self.addCleanup(site.server_close)
        self.addCleanup(site.shutdown)
        url = f"http://{HOST}:{site.server_port}"
        self.svc._custom_resolver = lambda host: ["127.0.0.1"] if host == HOST else []
        self.svc._real_site_local_artex = True
        challenge = self.svc.issue_ownership_challenge(url=url)["challenge"]
        self.svc.verify_asset_ownership(
            url_or_host=url, method="dns_txt",
            dns_lookup=lambda name: [f'{name} text = "{challenge["dns_txt_value"]}"'],
        )
        self.svc.confirm_asset_scope(url_or_host=url, confirmed_prohibited=True,
                                     activate_workspace=True, allow_loopback_test=True,
                                     allow_status_probe=True)
        with MockLLM() as model, patch.dict(os.environ, {
                "VULNIX_REAL_SITE_INITIAL_ARTEX": "1",
                "VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                "VULNIX_ARTEX_LLM_UPSTREAM_URL": model.url + "/chat/completions"}), \
                patch.object(assessment_module, "run_artex_planner",
                             wraps=assessment_module.run_artex_planner) as runner:
            self.svc.start()
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and self.svc.snapshot()["state"] == "running":
                time.sleep(0.02)
        snap = self.svc.snapshot()
        self.assertEqual(snap["state"], "completed", snap.get("failure"))
        self.assertEqual(site.seen, [("/", None)])
        self.assertEqual(runner.call_count, 1)
        request = runner.call_args.args[1]
        self.assertIn("Measured root fingerprint", request["observations"][0]["title"])
        self.assertNotIn(HOST, json.dumps(request, ensure_ascii=False))
        plan = snap["artex_plan"]["plan"]
        self.assertEqual([item["catalog_id"] for item in plan["items"]], ["l1_http_probe"])
        self.assertEqual(plan["items"][0]["status"], "observed")

    def test_real_site_plan_waits_for_a_completed_baseline(self):
        from aegis import assessment as assessment_module

        self.svc._real_site_local_artex = True
        self.svc.issue_ownership_challenge(url="https://site.test/")
        self.svc.verify_asset_ownership(
            url_or_host="site.test", method="google_search_console",
            google_property="sc-domain:site.test", google_endpoint=("https", 443))
        self.svc.confirm_asset_scope(url_or_host="site.test", confirmed_prohibited=True,
                                     activate_workspace=True)
        with patch.object(assessment_module, "run_artex_planner") as runner:
            with self.assertRaisesRegex(ValueError, "初回診断"):
                self.svc.plan_with_artex("op")
            runner.assert_not_called()

    def test_owned_mock_site_runs_l1_then_anonymous_plan_then_gateway_worker(self):
        from aegis import assessment as assessment_module
        from tests.test_real_service import FakeService, HOST

        site = FakeService()
        site.banner = "Apache/2.4.62"
        threading.Thread(target=site.serve_forever, daemon=True).start()
        self.addCleanup(site.server_close)
        self.addCleanup(site.shutdown)
        url = f"http://{HOST}:{site.server_port}"
        self.svc._custom_resolver = lambda host: ["127.0.0.1"] if host == HOST else []
        self.svc._real_site_local_artex = True

        challenge = self.svc.issue_ownership_challenge(url=url)["challenge"]
        self.assertEqual(site.seen, [])
        self.assertTrue(self.svc.verify_asset_ownership(
            url_or_host=url, method="dns_txt",
            dns_lookup=lambda name: [f'{name} text = "{challenge["dns_txt_value"]}"'],
        )["verified"])
        self.svc.confirm_asset_scope(url_or_host=url, confirmed_prohibited=True,
                                     activate_workspace=True, allow_loopback_test=True,
                                     allow_status_probe=True)
        self.assertEqual(site.seen, [])

        self.svc.start()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and self.svc.snapshot()["state"] == "running":
            time.sleep(0.02)
        snap = self.svc.snapshot()
        self.assertEqual(snap["state"], "completed", snap.get("failure"))
        self.assertEqual(site.seen, [("/", None)])
        self.assertTrue(any(f["evidence_status"] == "detected" and f["evidence"][0]["audit_hash"]
                            for f in snap["findings"]))

        with patch.object(assessment_module, "run_artex_planner",
                          wraps=assessment_module.run_artex_planner) as runner:
            plan = self.svc.plan_with_artex("op")["artex_plan"]["plan"]
        request = runner.call_args.args[1]
        self.assertTrue(request["observations"])
        self.assertNotIn(HOST, json.dumps(request, ensure_ascii=False))
        self.assertNotIn(url, json.dumps(request, ensure_ascii=False))
        self.assertEqual(site.seen, [("/", None)])
        self.assertEqual([item["catalog_id"] for item in plan["items"]], ["l1_http_probe"])

        self.assertEqual(plan["items"][0]["status"], "observed")
        before = len(self.events("allow"))
        with self.assertRaises(ValueError):
            self.svc.execute_artex_item(plan["items"][0]["id"], "op", roles=("operator",))
        self.assertEqual(site.seen, [("/", None)])
        self.assertEqual(len(self.events("allow")), before)

    def test_clean_baseline_without_findings_satisfies_root_plan_item(self):
        from aegis import assessment as assessment_module
        from tests.test_real_service import FakeService, HOST

        site = FakeService()
        site.banner = "Apache/2.4.62"
        threading.Thread(target=site.serve_forever, daemon=True).start()
        self.addCleanup(site.server_close)
        self.addCleanup(site.shutdown)
        url = f"http://{HOST}:{site.server_port}"
        self.svc._custom_resolver = lambda host: ["127.0.0.1"] if host == HOST else []
        self.svc._real_site_local_artex = True
        challenge = self.svc.issue_ownership_challenge(url=url)["challenge"]
        self.svc.verify_asset_ownership(
            url_or_host=url, method="dns_txt",
            dns_lookup=lambda name: [f'{name} text = "{challenge["dns_txt_value"]}"'])
        self.svc.confirm_asset_scope(url_or_host=url, confirmed_prohibited=True,
                                     activate_workspace=True, allow_loopback_test=True,
                                     allow_status_probe=True)
        self.svc.a.findings = {}
        with patch.object(assessment_module, "analyze_l1_service_response", return_value=[]), \
                patch.object(self.svc, "_l2_candidates", return_value=[]):
            self.svc.start()
            end = time.monotonic() + 20
            while time.monotonic() < end and self.svc.snapshot()["state"] == "running":
                time.sleep(0.02)
        self.assertEqual(self.svc.snapshot()["state"], "completed")
        self.assertEqual(self.svc.snapshot()["findings"], [])
        plan = self.plan()
        self.assertEqual(plan["items"][0]["status"], "observed")
        self.assertEqual(site.seen, [("/", None)])

    def test_real_site_plan_is_shown_only_when_scoped_and_opted_in(self):
        self.svc.issue_ownership_challenge(url="https://site.test/")
        self.svc.verify_asset_ownership(
            url_or_host="site.test", method="google_search_console",
            google_property="sc-domain:site.test", google_endpoint=("https", 443))
        self.svc.confirm_asset_scope(url_or_host="site.test", confirmed_prohibited=True,
                                     activate_workspace=True)
        self.assertFalse(self.svc.artex_plan_view()["configured"])
        self.svc._real_site_local_artex = True
        self.assertTrue(self.svc.artex_plan_view()["configured"])
        self.svc._verified_external_hosts["site.test"]["not_after"] = 0
        self.assertFalse(self.svc.artex_plan_view()["configured"])

    def test_completed_state_without_audited_baseline_cannot_plan(self):
        self.svc._real_site_local_artex = True
        self.svc.issue_ownership_challenge(url="https://site.test/")
        self.svc.verify_asset_ownership(
            url_or_host="site.test", method="google_search_console",
            google_property="sc-domain:site.test", google_endpoint=("https", 443))
        self.svc.confirm_asset_scope(url_or_host="site.test", confirmed_prohibited=True,
                                     activate_workspace=True)
        self.svc.a.state = "completed"  # inconsistent old state: no audited baseline in this fixture
        with patch.object(self.svc, "_plan_with_artex") as planner:
            with self.assertRaisesRegex(ValueError, "監査済み"):
                self.plan()
        planner.assert_not_called()

    def test_real_site_can_use_budgeted_gateway_only_with_literal_loopback_upstream(self):
        from aegis import assessment as assessment_module

        site, url = self.signed_mock_root()
        from aegis.policy import Budget
        remaining = Budget(2)
        remaining.spend()
        self.svc.gateway.budget = remaining

        with patch.dict(os.environ, {"VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                                  "VULNIX_ARTEX_LLM_UPSTREAM_URL": "http://127.0.0.1:9/v1/chat/completions"}):
            from aegis.planner_llm_gateway import GatewayRefused
            gateway = self.svc._planner_gateway("op", None, (), self.svc._run_generation,
                                                "gateway-forward", real_site=True)
            gateway.inspect({"model": "mock", "messages": [
                {"role": "user", "content": "Synthetic target http://lab.test/"}]})
            with self.assertRaises(GatewayRefused):
                gateway.inspect({"model": "mock", "messages": [
                    {"role": "user", "content": f"Real target {url}"}]})
            self.assertTrue(self.svc._artex_may_start(self.svc._run_generation))
            self.assertIs(self.svc.gateway.budget, remaining)
            self.assertEqual(remaining._left, 1)
            self.svc._real_service_hosts.add("lab.test")
            try:
                with self.assertRaises(GatewayRefused):
                    gateway.inspect({"model": "mock", "messages": [
                        {"role": "user", "content": "Now-real target http://lab.test/"}]})
            finally:
                self.svc._real_service_hosts.discard("lab.test")
            plan = self.plan()
        self.assertIs(self.svc.gateway.budget, remaining)
        self.assertEqual(remaining._left, 1)
        self.assertEqual(plan["llm_gateway"]["mode"], "forward")
        self.assertEqual(plan["llm_gateway"]["upstream"], "127.0.0.1")
        self.assertEqual(site.seen, [("/", None)])

        for upstream in ("https://api.example.test/v1/chat/completions",
                         "http://localhost:9/v1/chat/completions",
                         "http://127.0.0.1.evil.test/v1/chat/completions"):
            with self.subTest(upstream=upstream), \
                    patch.dict(os.environ, {"VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                                         "VULNIX_ARTEX_LLM_UPSTREAM_URL": upstream}), \
                    patch.object(assessment_module, "run_artex_planner") as runner:
                with self.assertRaisesRegex(ValueError, "ローカルモデル"):
                    self.svc.plan_with_artex("op")
                runner.assert_not_called()

        with patch.dict(os.environ, {"VULNIX_ARTEX_LLM_MODE": "direct",
                                  "VULNIX_ARTEX_LLM_UPSTREAM_URL": "http://127.0.0.1:9/v1/chat/completions"}), \
                patch.object(assessment_module, "run_artex_planner") as runner:
            with self.assertRaisesRegex(ValueError, "サーバー設定"):
                self.svc.plan_with_artex("op", llm_mode="gateway-forward")
            runner.assert_not_called()

        with patch.dict(os.environ, {"VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                                  "VULNIX_ARTEX_LLM_UPSTREAM_URL": "",
                                  "VULNIX_ABLITERATION_URL": "http://127.0.0.1:9/v1/chat/completions"}), \
                patch.object(assessment_module, "run_artex_planner") as runner:
            with self.assertRaisesRegex(ValueError, "専用"):
                self.svc.plan_with_artex("op")
            runner.assert_not_called()

    def test_real_site_artex_item_does_not_replenish_worker_budget(self):
        from aegis.policy import Budget

        self.svc._real_site_local_artex = True
        self.svc.real_site_read_only = False  # exercise the optional legacy item without a completed baseline
        self.svc.issue_ownership_challenge(url="https://site.test/")
        self.svc.verify_asset_ownership(
            url_or_host="site.test", method="google_search_console",
            google_property="sc-domain:site.test", google_endpoint=("https", 443))
        self.svc.confirm_asset_scope(url_or_host="site.test", confirmed_prohibited=True,
                                     activate_workspace=True)
        self.svc.a.state = "completed"
        plan = self.plan()
        remaining = Budget(2)
        remaining.spend()
        self.svc.gateway.budget = remaining
        with patch.object(self.svc, "_exec", return_value=(None, None)) as worker:
            self.svc.execute_artex_item(plan["items"][0]["id"], "op", roles=("operator",))
        worker.assert_called_once()
        self.assertIs(self.svc.gateway.budget, remaining)
        self.assertEqual(remaining._left, 1)

    def test_exhausted_budget_blocks_real_site_artex_worker(self):
        from aegis.policy import Budget
        from tests.test_real_service import FakeService, HOST

        site = FakeService()
        threading.Thread(target=site.serve_forever, daemon=True).start()
        self.addCleanup(site.server_close)
        self.addCleanup(site.shutdown)
        url = f"http://{HOST}:{site.server_port}"
        self.svc._custom_resolver = lambda host: ["127.0.0.1"] if host == HOST else []
        self.svc._real_site_local_artex = True
        self.svc.real_site_read_only = False  # no baseline in this budget-specific fixture
        challenge = self.svc.issue_ownership_challenge(url=url)["challenge"]
        self.svc.verify_asset_ownership(
            url_or_host=url, method="dns_txt",
            dns_lookup=lambda name: [f'{name} text = "{challenge["dns_txt_value"]}"'])
        self.svc.confirm_asset_scope(url_or_host=url, confirmed_prohibited=True,
                                     activate_workspace=True, allow_loopback_test=True)
        self.svc.a.state = "completed"
        plan = self.plan()
        exhausted = Budget(1)
        exhausted.spend()
        self.svc.gateway.budget = exhausted
        self.svc.execute_artex_item(plan["items"][0]["id"], "op", roles=("operator",))
        self.assertIs(self.svc.gateway.budget, exhausted)
        self.assertEqual(site.seen, [])
        self.assertEqual(self.svc.artex_plan_view()["plan"]["items"][0]["status"], "failed")

    def test_real_site_plan_discarded_if_scope_expires_during_model_run(self):
        from aegis import assessment as assessment_module
        from tests.test_real_service import HOST

        self.signed_mock_root()
        original_expiry = self.svc._verified_external_hosts[HOST]["not_after"]

        with patch.dict(os.environ, {"VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                                  "VULNIX_ARTEX_LLM_UPSTREAM_URL": "http://127.0.0.1:9/v1/chat/completions"}):
            gateway = self.svc._planner_gateway("op", None, (), self.svc._run_generation,
                                                "gateway-forward", real_site=True)
            self.assertTrue(gateway._may())
            self.svc._verified_external_hosts[HOST]["not_after"] = time.time() - 1
            self.assertFalse(gateway._may())

        self.svc._verified_external_hosts[HOST]["not_after"] = original_expiry
        original = assessment_module.run_artex_planner
        def expire_after(*args, **kwargs):
            result = original(*args, **kwargs)
            self.svc._verified_external_hosts[HOST]["not_after"] = time.time() - 1
            return result
        with patch.object(assessment_module, "run_artex_planner", side_effect=expire_after):
            with self.assertRaises(ValueError):
                self.svc.plan_with_artex("op")
        self.assertIsNone(self.svc._artex_plan)

    def test_real_site_plan_discarded_if_ownership_is_revoked_during_model_run(self):
        from aegis import assessment as assessment_module
        from tests.test_real_service import HOST

        self.signed_mock_root()
        record = self.svc._verified_external_hosts[HOST]

        with patch.dict(os.environ, {"VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                                  "VULNIX_ARTEX_LLM_UPSTREAM_URL": "http://127.0.0.1:9/v1/chat/completions"}):
            gateway = self.svc._planner_gateway("op", None, (), self.svc._run_generation,
                                                "gateway-forward", real_site=True)
            self.svc._verified_external_hosts.pop(HOST)
            self.assertFalse(gateway._may())
            self.svc._verified_external_hosts[HOST] = record

        original = assessment_module.run_artex_planner
        def revoke_after(*args, **kwargs):
            result = original(*args, **kwargs)
            self.svc._verified_external_hosts.pop(HOST)
            return result
        with patch.object(assessment_module, "run_artex_planner", side_effect=revoke_after):
            with self.assertRaises(ValueError):
                self.svc.plan_with_artex("op")
        self.assertIsNone(self.svc._artex_plan)

    def test_real_site_planner_refuses_an_expired_scope(self):
        self.svc._real_site_local_artex = True
        self.svc.issue_ownership_challenge(url="https://site.test/")
        self.svc.verify_asset_ownership(
            url_or_host="site.test", method="google_search_console",
            google_property="sc-domain:site.test", google_endpoint=("https", 443))
        self.svc.confirm_asset_scope(url_or_host="site.test", confirmed_prohibited=True,
                                     activate_workspace=True)
        self.svc._verified_external_hosts["site.test"]["not_after"] = 0
        with self.assertRaises(ValueError):
            self.svc.plan_with_artex("op")

    def test_real_site_planner_cannot_use_the_unconfined_dev_exception(self):
        from aegis.confinement import KernelConfinement

        self.signed_mock_root()
        self.svc._l2_confinement = KernelConfinement(platform="darwin")
        with patch.dict(os.environ, {"VULNIX_ARTEX_ALLOW_UNCONFINED": "1", "AEGIS_ENV": "development"}):
            with self.assertRaisesRegex(ValueError, "隔離"):
                self.svc.plan_with_artex("op")

    def test_real_site_direct_planner_refuses_an_external_model_endpoint(self):
        self.svc._real_site_local_artex = True
        self.svc._artex_llm_url = "https://external-model.example/v1"
        self.svc.a.state = "completed"
        with patch.object(self.svc, "_is_external_service_asset", return_value=True):
            with self.assertRaisesRegex(ValueError, "ループバック"):
                self.svc.plan_with_artex("op")

    def test_opted_in_real_site_plan_gets_only_anonymous_input_and_l1_items(self):
        from aegis import assessment as assessment_module

        self.svc._real_site_local_artex = True
        self.svc.a.target_url = "https://next-standards.com/"
        self.svc.a.state = "completed"
        self.svc.a.findings["f_headers"] = {
            "id": "f_headers", "category": "設定不備", "severity": "medium",
            "verdict": "detected", "verdict_basis": "l1_observation", "demo_fixture": False,
            "evidence": [{"audit_hash": "local-evidence", "saved_at": 1,
                          "body": "private response"}],
        }
        captured = []
        original = assessment_module.run_artex_planner

        def record(command, request, **kwargs):
            captured.append(request)
            return original(command, request, **kwargs)

        with patch.object(self.svc, "_is_external_service_asset", return_value=True), \
                patch.object(assessment_module, "run_artex_planner", side_effect=record):
            plan = self.plan()
        self.assertEqual(len(captured), 1)
        request = json.dumps(captured[0], ensure_ascii=False)
        self.assertIn("f_headers", request)
        self.assertNotIn("next-standards.com", request)
        self.assertNotIn("private response", request)
        self.assertTrue(all(item["level"] == "L1" for item in plan["items"]))
        self.assertTrue(any("許可" in advisory["reason"] for advisory in plan["advisories"]))

    def test_opted_in_real_site_l1_item_uses_gateway_worker_and_l2_has_no_item(self):
        self.svc._real_site_local_artex = True
        self.svc.a.state = "completed"
        with patch.object(self.svc, "_is_external_service_asset", return_value=True):
            plan = self.plan()
            self.assertEqual([item["catalog_id"] for item in plan["items"]], ["l1_http_probe"])
            item_id = plan["items"][0]["id"]
            before = len(self.events("allow"))
            self.svc.execute_artex_item(item_id, "op", roles=("operator",))
            self.assertEqual(len(self.events("allow")), before + 1)
            self.assertEqual(self.svc.artex_plan_view()["plan"]["items"][0]["status"], "completed")

    def test_a_tampered_real_site_plan_cannot_turn_an_l1_item_into_l2(self):
        self.svc._real_site_local_artex = True
        self.svc.a.state = "completed"
        self.svc.real_site_read_only = False  # even the extended mode must not admit ARTEX L2
        with patch.object(self.svc, "_is_external_service_asset", return_value=True):
            plan = self.plan()
            item_id = plan["items"][0]["id"]
            self.svc._artex_items[item_id]["item"].catalog_id = "l2_sqli"
            before = len(self.events("allow"))
            with patch.object(self.svc, "verify_finding") as verify:
                with self.assertRaisesRegex(ValueError, "実サイト.*L2"):
                    self.svc.execute_artex_item(item_id, "appr", roles=("operator", "approver"))
                verify.assert_not_called()
            self.assertEqual(len(self.events("allow")), before)

    def test_plan_items_advisories_and_provenance(self):
        plan = self.plan()
        self.assertEqual(plan["llm_model"], self.svc._artex_llm_model)
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
        self.addCleanup(svc.close)
        with self.assertRaises(ValueError):
            svc.plan_with_artex("op")
        with patch.object(AssessmentService, "_is_external_service_asset", return_value=True):
            with self.assertRaises(ValueError):
                self.svc.plan_with_artex("op")


class TestAnonymousRealSitePlannerInput(unittest.TestCase):
    def test_initial_fingerprint_contains_only_fixed_observed_enums(self):
        from aegis.artex_bridge import anonymous_real_site_request, safe_public_fingerprint

        secret = "private.example.com user@example.com Bearer secret-value"
        response = {"status": 200, "headers": {
            "Server": "Apache/2.4 " + secret, "Strict-Transport-Security": "max-age=1",
            "X-Secret": secret}, "body_prefix": secret,
            "connected_ip": "203.0.113.11", "tls": {"verified": True}}
        fingerprint = safe_public_fingerprint(response, scheme="https")
        self.assertEqual(fingerprint, {"scheme": "https", "status_class": "2xx",
                                       "server_family": "apache", "tls_present": True,
                                       "hsts_present": True, "csp_present": False})
        request = anonymous_real_site_request([], fingerprint=fingerprint)
        sent = json.dumps(request, ensure_ascii=False)
        self.assertIn('"server_family": "apache"', request["observations"][0]["detail"])
        for forbidden in ("private.example.com", "user@example.com", "Bearer secret-value",
                          "203.0.113.11", "2.4", "X-Secret"):
            self.assertNotIn(forbidden, sent)

    def test_initial_fingerprint_rejects_unexpected_fields(self):
        from aegis.artex_bridge import anonymous_real_site_request

        with self.assertRaises(ValueError):
            anonymous_real_site_request([], fingerprint={"server_family": "apache",
                                                        "host": "private.example.com"})

    def test_only_fixed_measured_fields_reach_artex(self):
        from aegis.artex_bridge import anonymous_real_site_request

        finding = {
            "id": "f_headers", "category": "設定不備", "severity": "medium",
            "verdict": "detected", "verdict_basis": "l1_observation",
            "title": "https://private.example.com/", "summary": "user@example.com",
            "evidence": [{"audit_hash": "local-evidence", "saved_at": 1,
                          "body": "secret response", "authorization": "Bearer secret-value"}],
            "risk_score": 42.2,
        }
        request = anonymous_real_site_request([finding])
        self.assertEqual(request["targets"], [{"asset_id": 1, "target_id": "site", "url": "http://lab.test/"}])
        self.assertEqual(len(request["observations"]), 1)
        self.assertIn("f_headers", request["observations"][0]["title"])
        detail = request["observations"][0]["detail"]
        self.assertIn("f_headers", detail)
        self.assertIn("detected", detail)
        self.assertIn("42", detail)
        serialized = json.dumps(request, ensure_ascii=False)
        for forbidden in ("private.example.com", "user@example.com", "secret response", "Bearer secret-value"):
            self.assertNotIn(forbidden, serialized)

    def test_unverified_candidates_are_not_seeded_as_observed_facts(self):
        from aegis.artex_bridge import anonymous_real_site_request

        candidate = {"id": "f_sqli", "verdict": "candidate", "summary": "unverified SQLi"}
        detected = {"id": "f_l1_tls", "verdict": "detected", "verdict_basis": "l1_observation",
                    "evidence": [{"audit_hash": "local-evidence", "saved_at": 1}]}
        only_candidate = anonymous_real_site_request([candidate])
        with_detected = anonymous_real_site_request([candidate, detected])
        self.assertEqual(only_candidate["observations"], [])
        self.assertEqual(len(with_detected["observations"]), 1)
        self.assertIn("f_l1_tls", with_detected["observations"][0]["detail"])
        self.assertNotIn("f_sqli", json.dumps(with_detected))
        self.assertNotEqual(only_candidate, with_detected)

    def test_unsupported_or_demo_findings_are_not_seeded(self):
        from aegis.artex_bridge import anonymous_real_site_request

        request = anonymous_real_site_request([
            {"id": "f_l1_tls", "verdict": "proven", "verdict_basis": "demo_fixture"},
            {"id": "invented", "verdict": "detected", "verdict_basis": "l1_observation"},
        ])
        self.assertEqual(request["observations"], [])

    def test_a_detected_label_without_recorded_evidence_is_only_a_candidate(self):
        from aegis.artex_bridge import anonymous_real_site_request

        finding = {"id": "f_headers", "verdict": "detected", "verdict_basis": "l1_observation"}
        self.assertEqual(anonymous_real_site_request([finding])["observations"], [])

    def test_a_proven_label_without_l2_evidence_is_downgraded(self):
        from aegis.artex_bridge import anonymous_real_site_request

        finding = {"id": "f_headers", "verdict": "proven", "verdict_basis": "l2_reproduction",
                   "evidence": [{"audit_hash": "local-evidence", "saved_at": 1, "tool": "http_probe"}]}
        request = anonymous_real_site_request([finding])
        self.assertIn('"verdict": "detected"', request["observations"][0]["detail"])
        self.assertNotIn('"verdict": "proven"', request["observations"][0]["detail"])

    def test_real_site_reconstruction_keeps_l2_as_an_inert_advisory(self):
        from aegis.artex_bridge import reconstruct

        intents = [
            {"id": 1, "summary": "Inspect security headers", "asset_ids": [1]},
            {"id": 2, "summary": "Test SQL injection", "asset_ids": [1]},
        ]
        targets = [{"asset_id": 1, "target_id": "lab", "url": "https://private.example.com/"}]
        result = reconstruct(intents, targets, "run1", allowed_levels=frozenset({"L1"}))
        self.assertEqual([item.catalog_id for item in result.items], ["l1_http_probe"])
        self.assertEqual(len(result.advisories), 1)
        self.assertIn("許可", result.advisories[0].reason)


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

    def test_real_planner_selects_status_check_and_gateway_records_evidence(self):
        from tests.fixtures.status_exposure_lab import StatusExposureLab

        site = StatusExposureLab("vulnerable")
        threading.Thread(target=site.serve_forever, daemon=True).start()
        self.addCleanup(site.server_close)
        self.addCleanup(site.shutdown)
        host = "owned-status.example.test"
        url = f"http://{host}:{site.server_port}"
        self.svc._custom_resolver = lambda name: ["127.0.0.1"] if name == host else []
        self.svc.real_site_read_only = True
        self.svc._real_site_local_artex = True
        self.mock.intents = [{"summary": "Check Apache mod_status exposure",
                              "asset_ids": [1], "priority": 5}]
        challenge = self.svc.issue_ownership_challenge(url=url)["challenge"]
        self.svc.verify_asset_ownership(
            url_or_host=url, method="dns_txt",
            dns_lookup=lambda name: [f'{name} text = "{challenge["dns_txt_value"]}"'])
        self.svc.confirm_asset_scope(url_or_host=url, activate_workspace=True,
                                     allow_loopback_test=True, allow_status_probe=True)
        with patch.dict(os.environ, {"VULNIX_REAL_SITE_INITIAL_ARTEX": "1",
                                   "VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                                   "VULNIX_ARTEX_LLM_UPSTREAM_URL": self.mock.url + "/chat/completions"}):
            self.svc.start()
            deadline = time.monotonic() + 90
            while self.svc.snapshot()["state"] == "running" and time.monotonic() < deadline:
                time.sleep(0.05)
        snap = self.svc.snapshot()
        self.assertEqual(snap["state"], "completed", snap.get("failure"))
        self.assertEqual(site.seen, ["/", "/server-status?auto"])
        self.assertEqual(snap["artex_plan"]["plan"]["engine"]["kind"], "artex-binary")
        item = next(i for i in snap["artex_plan"]["plan"]["items"]
                    if i["catalog_id"] == "l1_apache_mod_status")
        self.assertEqual(item["status"], "completed")
        finding = next(f for f in snap["findings"] if f["id"] == "f_l1_apache_mod_status")
        self.assertEqual(finding["evidence_status"], "detected")
        self.assertTrue(finding["evidence"][0]["audit_hash"])
        self.assertTrue(self.mock.requests)
        self.assertNotIn(host, json.dumps(self.mock.requests, ensure_ascii=False))

    def test_the_real_planner_accepts_a_scoped_site_without_receiving_its_hostname(self):
        from tests.test_real_service import HOST

        site, url = self.signed_mock_root()
        self.svc.a.findings["f_headers"] = {
            "id": "f_headers", "category": "設定不備", "severity": "medium",
            "verdict": "detected", "verdict_basis": "l1_observation", "demo_fixture": False,
            "evidence": [{"audit_hash": "local-evidence", "saved_at": 1,
                          "body": "private response text"}],
        }
        plan = self.plan()
        self.assertEqual(plan["engine"]["kind"], "artex-binary")
        self.assertTrue(self.mock.requests)
        requests = json.dumps(self.mock.requests, ensure_ascii=False)
        self.assertIn("f_headers", requests)  # real ARTEX receives a measured, site-specific feature
        self.assertNotIn(HOST, requests)
        self.assertNotIn(url, requests)
        self.assertNotIn("private response text", requests)
        self.assertEqual(site.seen, [("/", None)])
        self.assertTrue(all(item["level"] == "L1" for item in plan["items"]))
        self.assertTrue(any(item["catalog_id"] == "l1_http_probe" for item in plan["items"]))

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
            # the minimal root (pivot_root, old root detached) and the relay's own uid and filter
            self.assertTrue(iso["minimal_root"], iso)
            self.assertTrue(iso["absent_paths_ok"], iso)
            self.assertTrue(iso["relay_separate_uid"], iso)
            self.assertEqual(iso["relay_seccomp"], "2", iso)
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



# ---- the planner's minimal root and the relay's filter (pure Python, any OS) ----------

LD_X86 = "/lib64/ld-linux-x86-64.so.2"
# an Ubuntu 24.04-like (merged /usr) host as the plan sees it
UBUNTU = {
    "/lib": ("link", "usr/lib"), "/lib64": ("link", "usr/lib64"), "/bin": ("link", "usr/bin"),
    "/usr/lib/x86_64-linux-gnu/libc.so.6": "file",
    "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2": "file",
    "/usr/lib64/ld-linux-x86-64.so.2": ("link", "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
    "/usr/lib/python3.12/os.py": "file", "/usr/lib/locale/C.utf8/LC_CTYPE": "file",
    "/usr/share/keyrings/ubuntu-archive-keyring.gpg": "file", "/usr/local/bin/x": "file",
    "/usr/bin/setpriv": ("elf", LD_X86), "/usr/bin/umount": ("elf", LD_X86), "/usr/bin/sudo": ("elf", LD_X86),
    "/usr/sbin/pivot_root": ("elf", LD_X86),
    "/usr/bin/python3": ("link", "python3.12"), "/usr/bin/python3.12": ("elf", LD_X86),
    "/etc/passwd": "file", "/sys/kernel/x": "file", "/home/runner/x": "file", "/srv/vulnix/data/state.json": "file",
    "/tmp/vulnix-artex-abc/artex-vulnix-planner": ("elf", LD_X86), "/tmp/vulnix-worker-xyz/_sandbox_launch.py": "file",
}
UBUNTU_PYTHON = {"dirs": ["/usr/lib/python3.12"], "files": ["/usr/bin/python3"], "multiarch": ["x86_64-linux-gnu"]}


class FakeFS:
    def __init__(self, entries):
        self.e = dict(entries)
        self.dirs = {"/"}
        for p in self.e:
            parts = p.split("/")
            self.dirs |= {"/".join(parts[:i]) or "/" for i in range(2, len(parts))}

    def islink(self, p):
        return isinstance(self.e.get(p), tuple) and self.e[p][0] == "link"

    def readlink(self, p):
        return self.e[p][1]

    def isdir(self, p):
        return p in self.dirs and p not in self.e

    def exists(self, p):
        return p in self.e or p in self.dirs

    def elf_interp(self, p):
        v = self.e.get(p)
        return v[1] if isinstance(v, tuple) and v[0] == "elf" else None


def fake_owner(fs=UBUNTU, python=UBUNTU_PYTHON):
    import subprocess as sp

    from aegis.confinement import KernelConfinement
    o = KernelConfinement(runner=lambda a, **k: sp.CompletedProcess(a, 0, "", ""), platform="linux", euid=0,
                          which=lambda t: f"/usr/bin/{t}")
    o.fresh_identity = lambda: 4242
    o._fs = FakeFS(fs)
    o._python = dict(python)
    return o


def ns_session_and_argv(owner=None):
    from aegis.confinement import ConfinementSession
    o = owner or fake_owner()
    with patch.object(type(o), "staged_workers", lambda self: Path("/tmp/vulnix-worker-xyz")):
        sess = ConfinementSession(o, "127.0.0.1", 18080, extra_endpoints=(("127.0.0.1", 5432),),
                                  namespaces={"hide": ab.planner_hidden_paths(["/srv/vulnix/data/state.json"]),
                                              "keep": ["/tmp/vulnix-artex-abc"]})
        argv = sess.wrap(["/tmp/vulnix-artex-abc/artex-vulnix-planner"], interpreter="/usr/bin/python3")
    return sess, argv


def plan_for(**kw):
    from aegis.confinement import minimal_root_plan
    args = {"rw": ["/tmp/vulnix-artex-abc"], "ro": ["/tmp/vulnix-worker-xyz"],
            "programs": ["/usr/bin/setpriv", "/usr/bin/python3", "/tmp/vulnix-artex-abc/artex-vulnix-planner"],
            "loaders_of": ["/usr/bin/umount"], "python": UBUNTU_PYTHON,
            "hidden": ab.planner_hidden_paths(["/srv/vulnix/data/state.json"]), "fs": FakeFS(UBUNTU)}
    args.update(kw)
    return minimal_root_plan(**args)


class TestThePlannersMinimalRootPlan(unittest.TestCase):
    """The mount plan is built in Python and checked here on any OS; the kernel side
    (TestMinimalRootOnLinux) proves the view from inside on Linux CI."""

    def test_the_plan_holds_exactly_what_the_planner_needs(self):
        self.assertEqual(set(plan_for()), {
            ("rw", "/tmp/vulnix-artex-abc"),
            ("ro", "/tmp/vulnix-worker-xyz"),
            ("symlink", "/lib", "usr/lib"), ("symlink", "/lib64", "usr/lib64"),
            ("ro", "/usr/lib/x86_64-linux-gnu"), ("ro", "/usr/lib64"), ("ro", "/usr/lib/python3.12"),
            ("symlink", "/usr/bin/python3", "python3.12"),
            ("file", "/usr/bin/python3.12", "/usr/bin/python3.12"),
            ("file", "/usr/bin/setpriv", "/usr/bin/setpriv"),
        })

    def test_no_system_area_configuration_or_old_root_is_in_the_plan(self):
        from aegis.confinement import plan_mountpoints, plan_paths
        plan = plan_for()
        paths = plan_paths(plan)
        under = lambda p, d: p == d or p.startswith(d.rstrip("/") + "/")      # noqa: E731
        # nothing at all from these
        for bad in ("/sys", "/proc", "/etc", "/home", "/root", "/run", "/var", "/usr/share", "/usr/local",
                    "/usr/sbin", "/boot", "/srv", "/opt", "/dev", "/usr/bin/sudo", "/usr/bin/umount"):
            self.assertFalse([p for p in paths if under(p, bad)], bad)
        # never a directory bound whole that holds these (single files only)
        for bad in ("/", "/usr", "/usr/bin", "/usr/lib", "/tmp"):
            self.assertFalse([e for e in plan if e[0] in ("ro", "rw") and under(bad, e[1])], bad)
        self.assertEqual(plan_mountpoints(plan) & {"/sys", "/etc", "/home", "/usr", "/usr/bin"}, set())
        # /tmp is a mount point only as the run's private tmpfs: the host's /tmp is never bound
        self.assertIn("/tmp", plan_mountpoints(plan))
        self.assertFalse([e for e in plan if e[0] != "symlink" and e[1] == "/tmp"])
        # read-write: the work directory and nothing else
        self.assertEqual([e for e in plan if e[0] == "rw"], [("rw", "/tmp/vulnix-artex-abc")])

    def test_a_dangerous_or_missing_source_refuses_the_plan(self):
        from aegis.confinement import ConfinementError
        for kw in ({"rw": ["/"]}, {"ro": ["/etc"]}, {"ro": ["/sys/fs"]}, {"ro": ["/usr"]}, {"ro": ["/usr/bin"]},
                   {"ro": ["/proc/self"]}, {"ro": ["/run/secrets"]}, {"ro": ["/home"]},
                   {"ro": ["/srv/vulnix"]},                                  # holds the data directory
                   {"ro": ["/tmp/does-not-exist"]}, {"programs": ["/usr/bin/missing"]},
                   {"python": {**UBUNTU_PYTHON, "dirs": ["/usr"]}}):
            with self.subTest(kw=kw), self.assertRaises(ConfinementError):
                plan_for(**kw)

    def test_the_script_switches_root_and_detaches_the_old_one(self):
        from aegis.confinement import DEV_NODES, OLDROOT, VXROOT, minimal_root_script
        plan = plan_for()
        lines = minimal_root_script(plan, umount="/usr/bin/umount", pivot_root="/usr/sbin/pivot_root")
        script = "\n".join(lines)
        self.assertEqual(lines[0], "set -eu")
        self.assertEqual(lines[-1], 'exec "$@"')
        self.assertEqual(lines[-4:-1], [f"/usr/sbin/pivot_root . {OLDROOT[1:]}", "cd /",
                                        f"{OLDROOT}/usr/bin/umount -n -l {OLDROOT}"])
        self.assertLess(lines.index(f"mount -n -o remount,ro,nosuid,nodev {VXROOT}"), len(lines) - 4)
        self.assertIn(f"mount -n -t tmpfs -o mode=0755,nosuid,nodev,size=4m vxroot {VXROOT}", lines)
        # ARTEX's private /tmp (its work dir /tmp/vulnix-artex-planner): an empty, size-limited
        # tmpfs, mounted before anything of the plan is bound beneath it
        tmp = lines.index(f"mount -n -t tmpfs -o mode=1777,nosuid,nodev,noexec,size=64m vxtmp {VXROOT}/tmp")
        self.assertLess(tmp, min(i for i, ln in enumerate(lines) if ln.startswith("mount -n --bind ")))
        self.assertNotIn("sysfs", script)
        self.assertNotIn("--rbind", script)
        self.assertIn(f"mount -n -t proc -o hidepid=invisible,subset=pid,nosuid,nodev,noexec vxproc {VXROOT}/proc",
                      lines)
        # every bind source is in the plan (or one of the device nodes), every bind is
        # remounted with its flags: read-only except the work directory
        binds = [ln.split()[3:5] for ln in lines if ln.startswith("mount -n --bind ")]
        sources = {b[0] for b in binds}
        self.assertEqual(sources, {e[1] for e in plan if e[0] != "symlink"} | {f"/dev/{n}" for n in DEV_NODES})
        for src, dst in binds:
            if src.startswith("/dev/"):
                continue
            want = "nosuid,nodev" if src == "/tmp/vulnix-artex-abc" else "ro,nosuid,nodev"
            self.assertIn(f"mount -n -o remount,bind,{want} {dst}", lines, src)
        self.assertEqual(len([b for b in binds if b[0].startswith("/dev/")]), len(DEV_NODES))
        self.assertEqual(set(DEV_NODES), {"null", "zero", "full", "random", "urandom"})

    def test_the_probe_must_find_these_absent_and_the_verdict_checks_every_part(self):
        sess, _ = ns_session_and_argv()
        absent = sess._must_be_absent()
        for p in ("/sys", "/etc/passwd", "/etc", "/home", "/root", "/var", "/run", "/usr/share", "/usr/local",
                  "/usr/bin/sudo", "/srv/vulnix/data", "/opt", "/boot",
                  str(Path(ab.__file__).with_name("confinement.py")), str(Path(ab.__file__).with_name("server.py"))):
            self.assertIn(p, absent)
        self.assertNotIn("/tmp", absent)                       # holds the work directory
        good = self.seen(sess)
        sess.relay_evidence = {"ok": True, "relay_uid": 5000, "relay_separate_uid": True, "relay_seccomp": "2"}
        ok, ev = sess._ns_verdict(good, None)
        self.assertTrue(ok, ev)
        self.assertTrue(ev["minimal_root"] and ev["absent_paths_ok"], ev)
        bad = {
            "/sys mounted": {"mounts": good["mounts"] + [["/sys", "sysfs", "sysfs"]]},
            "host root": {"mounts": [["/", "ext4", "/dev/sda1"]] + good["mounts"][1:]},
            "old root left": {"oldroot": ["etc", "home"]},
            "host /tmp": {"mounts": [m if m[0] != "/tmp" else ["/tmp", "ext4", "/dev/sda1"] for m in good["mounts"]]},
            "no /tmp": {"mounts": [m for m in good["mounts"] if m[0] != "/tmp"]},
            "old root gone?": {"oldroot": "GONE:FileNotFoundError"},
            "passwd visible": {"absent": {**good["absent"], "/etc/passwd": False}},
            "list incomplete": {"absent": {k: v for k, v in good["absent"].items() if k != "/sys"}},
            "no mounts": {"mounts": []},
        }
        for why, change in bad.items():
            with self.subTest(why):
                self.assertFalse(sess._ns_verdict({**good, **change}, None)[0])
        sess.relay_evidence = {"ok": False}
        self.assertFalse(sess._ns_verdict(good, None)[0])

    @staticmethod
    def seen(sess):
        from aegis.confinement import plan_mountpoints
        mounts = [["/", "tmpfs", "vxroot"], ["/tmp", "tmpfs", "vxtmp"]] + [
            [m, "x", "y"] for m in sorted(plan_mountpoints(sess._plan)) if m not in ("/", "/tmp")]
        return {"netns": "net:[4026532999]", "ifaces": ["lo"], "canary": "BLOCKED:TimeoutError",
                "relay": {"5432": "OK", "18080": "OK"},
                "hidden": {h: "GONE:FileNotFoundError" for h in sess.ns["hide"] if h != "/tmp"}
                | {"/tmp": ["vulnix-artex-abc", "vulnix-worker-xyz"]},
                "netlink": "DENIED:PermissionError", "vsock": "DENIED:PermissionError", "bpf": "DENIED:1",
                "procs_visible": 1, "seccomp": ["2"], "mounts": mounts, "oldroot": [],
                "absent": {p: True for p in sess._must_be_absent()}}

    def test_a_failed_root_switch_is_reported_and_nothing_starts(self):
        import subprocess as sp

        from aegis.confinement import ROOT_FAIL_MARK, ConfinementError
        o = fake_owner()
        calls = []

        def runner(argv, **kw):
            calls.append(argv)
            if any("pivot_root" in str(a) for a in argv):           # the probe's chain
                return sp.CompletedProcess(argv, 1, "", "pivot_root: failed\n" + ROOT_FAIL_MARK + "\n")
            if argv[-3:] == ["list", "table", "inet"] or "list" in argv:
                return sp.CompletedProcess(argv, 0, 'socket cgroupv2 level 1 "x" jump confined', "")
            return sp.CompletedProcess(argv, 0, "", "")
        o._run = runner
        sess, _ = ns_session_and_argv(o)
        sess._setup_netns = lambda: None
        sess.relay_evidence = {"ok": True}
        with patch("aegis.confinement._table_is_live", lambda *a: True), \
                patch.object(sys, "executable", "/usr/bin/python3"), \
                patch.object(type(o), "staged_workers", lambda self: Path("/tmp/vulnix-worker-xyz")):
            with self.assertRaises(ConfinementError) as cm:
                sess._apply_and_verify()
        self.assertIn("最小ルート", str(cm.exception))
        self.assertIn("pivot_root: failed", str(cm.exception))


class TestTheRelaysOwnSeccompAllowlist(unittest.TestCase):
    # numbers of calls the relay must never make (x86_64, aarch64)
    FORBIDDEN = {
        "open": (2, None), "openat": (257, 56), "openat2": (437, 437), "execve": (59, 221),
        "execveat": (322, 281), "fork": (57, None), "vfork": (58, None), "bind": (49, 200), "listen": (50, 201),
        "socketpair": (53, 199), "ptrace": (101, 117), "kill": (62, 129), "tkill": (200, 130),
        "tgkill": (234, 131), "mount": (165, 40), "umount2": (166, 39), "pivot_root": (155, 41),
        "chroot": (161, 51), "unshare": (272, 97), "setns": (308, 268), "bpf": (321, 280),
        "io_uring_setup": (425, 425), "process_vm_readv": (310, 270), "setuid": (105, 146),
        "prctl": (157, 167), "seccomp": (317, 277), "memfd_create": (319, 279), "pidfd_getfd": (438, 438),
        "unlinkat": (263, 35), "mkdirat": (258, 34),
    }

    def relay(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "_relay", Path(ab.__file__).with_name("workers") / "_ns_relay.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    def run_filter(self, m, machine, nr, args=(0, 0), arch=None):
        import struct
        prog = m.relay_filter_program(machine)
        ins = [struct.unpack("HBBI", prog[i:i + 8]) for i in range(0, len(prog), 8)]
        data = {0: nr, 4: m.RELAY_ARCHES[machine]["arch"] if arch is None else arch, 16: args[0], 24: args[1]}
        pc, acc = 0, 0
        for _ in range(400):
            code, jt, jf, k = ins[pc]
            if code == 0x20:
                acc = data[k]
                pc += 1
            elif code == 0x15:
                pc += 1 + (jt if acc == k else jf)
            elif code == 0x35:
                pc += 1 + (jt if acc >= k else jf)
            elif code == 0x45:
                pc += 1 + (jt if acc & k else jf)
            elif code == 0x06:
                return k
        self.fail("no return")

    def test_forbidden_calls_fail_and_the_allowlist_has_none_of_them(self):
        m = self.relay()
        for i, machine in enumerate(("x86_64", "aarch64")):
            names = set(m.RELAY_ALLOW[machine])
            self.assertFalse(names & set(self.FORBIDDEN), names & set(self.FORBIDDEN))
            for name, nrs in self.FORBIDDEN.items():
                if nrs[i] is None:
                    continue
                with self.subTest(machine=machine, call=name):
                    self.assertEqual(self.run_filter(m, machine, nrs[i]), m.RET_ERRNO | m.EPERM)
            for name, nr in m.RELAY_ALLOW[machine].items():
                self.assertEqual(self.run_filter(m, machine, nr), m.RET_ALLOW, (machine, name))
            self.assertLess(len(m.relay_filter_program(machine)) // 8, 256)

    def test_arguments_are_checked_for_socket_clone_and_ioctl(self):
        m = self.relay()
        for machine, cfg in m.RELAY_ARCHES.items():
            f = lambda nr, *a: self.run_filter(m, machine, nr, (*a, 0, 0)[:2])      # noqa: E731
            eperm = m.RET_ERRNO | m.EPERM
            self.assertEqual(f(cfg["socket"], 2), m.RET_ALLOW)                        # AF_INET
            for domain in (1, 10, 16, 17, 40):          # unix, inet6, netlink, packet, vsock
                self.assertEqual(f(cfg["socket"], domain), eperm, domain)
            thread = 0x3D0F00                            # glibc pthread_create's flags
            self.assertEqual(f(cfg["clone"], thread), m.RET_ALLOW)
            self.assertEqual(f(cfg["clone"], 0x01200011), eperm)                       # fork()
            self.assertEqual(f(cfg["clone"], thread | 0x40000000), eperm)              # + CLONE_NEWNET
            self.assertEqual(f(cfg["clone"], thread | 0x10000000), eperm)              # + CLONE_NEWUSER
            self.assertEqual(f(cfg["clone3"]), m.RET_ERRNO | m.ENOSYS)
            self.assertEqual(f(cfg["ioctl"], 3, 0x5421), m.RET_ALLOW)                  # FIONBIO
            self.assertEqual(f(cfg["ioctl"], 0, 0x5412), eperm)                        # TIOCSTI
            self.assertEqual(self.run_filter(m, machine, 0, arch=0x40000003), m.RET_KILL_PROCESS)  # i386
            self.assertEqual(self.run_filter(m, machine, 0x40000000), m.RET_KILL_PROCESS)          # x32

    def test_the_filter_is_in_place_before_ready_and_after_the_uid_drop(self):
        src = (Path(ab.__file__).with_name("workers") / "_ns_relay.py").read_text()
        main = src[src.index("def main()"):]
        self.assertLess(main.index("os.setuid(uid)"), main.index("install_relay_filter()"))
        self.assertLess(main.index("install_relay_filter()"), main.index('print("READY"'))
        self.assertIn("sys.exit(97)", main[main.index("install_relay_filter()"):main.index('print("READY"')])
        self.assertNotIn("create_connection", src)            # no name lookup in the relay

    def test_the_relay_gets_a_uid_of_its_own_checked_from_outside(self):
        import subprocess as sp

        from aegis.confinement import ConfinementError
        zero = "0000000000000000"
        good = {"Uid": "5000\t5000\t5000\t5000", "Gid": "5000\t5000\t5000\t5000", "NoNewPrivs": "1",
                "Seccomp": "2", "CapInh": zero, "CapPrm": zero, "CapEff": zero, "CapBnd": zero, "CapAmb": zero}
        cases = [(good, None), ({**good, "Seccomp": "0"}, "seccomp"),
                 # setuid() alone leaves the bounding set full: CI run 45067537375
                 ({**good, "CapBnd": "000001ffffffffff"}, "CapBnd_zero"),
                 ({**good, "NoNewPrivs": "0"}, "no_new_privs"), ({**good, "Gid": "0\t0\t0\t0"}, "gid"),
                 ({k: v for k, v in good.items() if k != "CapAmb"}, "CapAmb_zero")]
        for fields, failing in cases:
            should_pass = failing is None
            o = fake_owner()
            ids = iter([4242, 4242, 5000])                          # planner, collision, relay
            o.fresh_identity = lambda: next(ids)
            status = "".join(f"{k}:\t{v}\n" for k, v in fields.items())

            def runner(argv, **kw):
                if argv[-1].endswith("cgroup.procs"):
                    return sp.CompletedProcess(argv, 0, "777\n", "")
                if argv[-1] == "/proc/777/status":
                    return sp.CompletedProcess(argv, 0, status, "")
                return sp.CompletedProcess(argv, 0, "", "")
            o._run = runner
            launched = []

            def popen(argv, **kw):
                launched.append(argv)
                r, w = os.pipe()
                os.write(w, b"READY\n")
                os.close(w)
                p = sp.Popen.__new__(sp.Popen)
                p.stdout = os.fdopen(r, "r")
                self.addCleanup(p.stdout.close)
                return p
            o._popen = popen
            sess, _ = ns_session_and_argv(o)
            with patch.object(type(o), "staged_workers", lambda self: Path("/tmp/vulnix-worker-xyz")):
                if should_pass:
                    sess._setup_netns()
                    self.assertEqual(sess.relay_uid, 5000)
                    self.assertNotEqual(sess.relay_uid, sess.uid)
                    self.assertEqual(launched[0][-3], "5000")           # <name> <uid> <port> <port>
                    self.assertEqual(sess.relay_evidence["relay_seccomp"], "2")
                else:
                    with self.assertRaises(ConfinementError) as cm:
                        sess._setup_netns()
                    self.assertEqual(sess.relay_evidence["failed"], [failing], str(cm.exception))
                    self.assertIn(failing, str(cm.exception))          # the message names the failed check

    def test_the_relay_empties_its_bounding_set_before_dropping_root(self):
        src = (Path(ab.__file__).with_name("workers") / "_ns_relay.py").read_text()
        main = src[src.index("def main()"):]
        self.assertLess(main.index("drop_bounding_set(libc)"), main.index("os.setuid(uid)"))
        self.assertLess(main.index("own_caps()"), main.index("install_relay_filter()"))
        for cap in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
            self.assertIn(f'"{cap}"', main[main.index("own_caps()") - 200:main.index("install_relay_filter()")])


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

    def test_the_namespace_chain_builds_a_minimal_root_and_is_root_until_the_drop(self):
        from aegis.confinement import OLDROOT, ROOT_FAIL_MARK, VXROOT
        sess, argv = ns_session_and_argv()
        work = "/tmp/vulnix-artex-abc"
        i = argv.index("netns")
        self.assertEqual(argv[i:i + 3], ["netns", "exec", sess.name])
        script = argv[argv.index("-c", i) + 1]
        lines = script.splitlines()
        self.assertEqual(lines[0], "set -eu")
        self.assertIn(ROOT_FAIL_MARK, lines[1])                            # a failed step says so
        self.assertIn("mount -n --make-rprivate /", script)
        self.assertNotIn("mount -t", script.replace("mount -n -t", ""))   # every mount without utab
        self.assertNotIn("--rbind", script)                               # no sub-mounts come along
        # the hidden directories are never created or bound in the new root
        for h in ("/home", "/root", "/var", "/dev/shm", "/run", "/opt", "/srv", "/Users", "/Volumes",
                  "/srv/vulnix/data", "/etc", "/sys", "/boot", "/usr/share", "/usr/local"):
            self.assertFalse([ln for ln in lines if f"{VXROOT}{h} " in ln + " " or f"{VXROOT}{h}/" in ln], h)
        self.assertIn(f"mount -n --bind {work} {VXROOT}{work}", script)
        self.assertIn(f"mount -n -o remount,bind,nosuid,nodev {VXROOT}{work}", script)   # read-write
        self.assertIn("hidepid=invisible,subset=pid", script)
        # the switch: root read-only, pivot_root, the old root detached, then the program
        pivot = lines.index(f"/usr/bin/pivot_root . {OLDROOT[1:]}")
        self.assertLess(lines.index(f"mount -n -o remount,ro,nosuid,nodev {VXROOT}"), pivot)
        self.assertEqual(lines[pivot + 1:], ["cd /", f"{OLDROOT}/usr/bin/umount -n -l {OLDROOT}", 'exec "$@"'])
        self.assertIn("--ipc", argv)
        self.assertIn("--pid", argv)
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


@unittest.skipUnless(os.environ.get("VULNIX_ARTEX_CONFINE") == "1" and sys.platform.startswith("linux"),
                     "real kernel namespace confinement only in Linux CI")
class TestMinimalRootOnLinux(unittest.TestCase):
    """The planner's view on the real kernel: pivot_root into the minimal root, the old
    root detached; checked from inside by a program started exactly like ARTEX."""

    # what is tried from inside; each must exist on the host (checked) and not inside
    HOST_ONLY = ["/etc/passwd", "/usr/bin/sudo", "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
                 "/sys/kernel/uevent_seqnum", "/usr/local/bin", "/home"]

    def session(self, port, work, secret, **kw):
        from aegis.confinement import KernelConfinement
        return KernelConfinement(**kw).session(
            "127.0.0.1", port, forbidden_paths=[secret], limits=ab.ARTEX_LIMITS,
            namespaces={"hide": ab.planner_hidden_paths([secret]), "keep": [work]})

    def dirs(self):
        import shutil
        work = tempfile.mkdtemp(prefix="vulnix-artex-")
        os.chmod(work, 0o755)
        data = tempfile.mkdtemp(prefix="vulnix-data-")
        self.addCleanup(lambda: shutil.rmtree(work, True))
        self.addCleanup(lambda: shutil.rmtree(data, True))
        secret = Path(data) / "state.json"
        secret.write_text("{}")
        return work, str(secret)

    def test_inside_the_view_only_the_plan_exists(self):
        import subprocess as sp
        import urllib.parse

        from aegis import confinement as cf
        here = os.path.realpath(__file__)
        vulnix = [here, os.path.realpath(cf.__file__)]
        other_pid = f"/proc/{os.getpid()}/status"            # the test process: another PID
        tried = [p for p in self.HOST_ONLY if os.path.lexists(p)] + vulnix + [other_pid]
        for must in ("/etc/passwd", "/usr/bin/sudo", "/sys/kernel/uevent_seqnum", other_pid, *vulnix):
            self.assertTrue(os.path.lexists(must), must)    # the test means something on this host
        stdlib = os.__file__
        code = (
            "import json,os\n"
            "out={'seen':{}}\n"
            f"for p in {tried!r}:\n"
            "    try:\n"
            "        (os.listdir(p) if os.path.isdir(p) else open(p,'rb').read(1)); out['seen'][p]='READ'\n"
            "    except OSError as e:\n"
            "        out['seen'][p]='DENIED:'+type(e).__name__\n"
            "for d in ('/sys','/.oldroot','/etc','/'):\n"
            "    try:\n"
            "        out[d]=sorted(os.listdir(d))\n"
            "    except OSError as e:\n"
            "        out[d]='GONE:'+type(e).__name__\n"
            "out['mounts']=sorted(l.split()[4] for l in open('/proc/self/mountinfo'))\n"
            "out['pids']=sorted(d for d in os.listdir('/proc') if d.isdigit())\n"
            # positive controls: the probe itself works
            f"out['stdlib']=len(open({stdlib!r},'rb').read(10))\n"
            "open('/dev/null','wb').write(b'x'); out['devnull']='OK'\n"
            "os.mkdir('/tmp/vulnix-artex-planner',0o700); out['tmp_workdir']='OK'\n"
            "print(json.dumps(out))\n")
        with MockLLM() as mock:
            work, secret = self.dirs()
            sess = self.session(urllib.parse.urlsplit(mock.url).port, work, secret)
            with sess:
                ev = sess.evidence
                self.assertTrue(ev["minimal_root"], ev)
                self.assertTrue(ev["absent_paths_ok"], ev)
                self.assertTrue(ev["relay_separate_uid"], ev)
                self.assertEqual(ev["relay_seccomp"], "2", ev)
                self.assertNotEqual(sess.relay_uid, sess.uid)
                r = sp.run(sess.wrap([sys.executable, "-I", "-c", code], interpreter=sys.executable),
                           stdin=sp.DEVNULL, capture_output=True, text=True, timeout=60, cwd=work,
                           env={"PATH": "/usr/bin:/bin"})
                self.assertEqual(r.returncode, 0, r.stderr[-2000:])
                out = json.loads(r.stdout.strip().splitlines()[-1])
        for p in tried:
            self.assertTrue(out["seen"][p].startswith("DENIED:"), (p, out["seen"][p]))
        self.assertTrue(str(out["/sys"]).startswith("GONE:"), out["/sys"])
        self.assertTrue(str(out["/etc"]).startswith("GONE:"), out["/etc"])
        self.assertEqual(out["/.oldroot"], [])
        self.assertNotIn("sys", out["/"])
        self.assertNotIn("home", out["/"])
        self.assertNotIn("/sys", out["mounts"])
        self.assertFalse([m for m in out["mounts"] if m.startswith("/.oldroot")], out["mounts"])
        self.assertLessEqual(len(out["pids"]), 2, out["pids"])            # its own PID namespace
        self.assertEqual(out["stdlib"], 10)
        self.assertEqual(out["devnull"], "OK")
        self.assertEqual(out["tmp_workdir"], "OK")                         # ARTEX's work dir
        self.assertFalse(os.path.exists("/tmp/vulnix-artex-planner"))     # private: not the host's /tmp

    def test_a_root_switch_that_fails_means_nothing_starts(self):
        import urllib.parse

        from aegis.confinement import ConfinementError, _system_which
        broken = lambda t: "/usr/bin/false" if t == "pivot_root" else _system_which(t)      # noqa: E731
        with MockLLM() as mock:
            work, secret = self.dirs()
            sess = self.session(urllib.parse.urlsplit(mock.url).port, work, secret, which=broken)
            with self.assertRaises(ConfinementError) as cm:
                with sess:
                    self.fail("the session must not be entered")
            self.assertIn("最小ルート", str(cm.exception))
            self.assertFalse(sess.leftover)
            self.assertFalse(os.path.exists(f"/run/netns/{sess.name}"))


@unittest.skipUnless(sys.platform.startswith("linux") and __import__("platform").machine() in ("x86_64", "aarch64"),
                     "seccomp is Linux only")
class TestRelaySeccompOnLinux(unittest.TestCase):
    """The relay's own filter on the real kernel (no root needed): what the relay does
    still works; anything outside the allowlist fails with EPERM."""

    def test_outside_the_allowlist_every_call_fails(self):
        import subprocess as sp
        relay = str(Path(ab.__file__).with_name("workers") / "_ns_relay.py")
        code = (
            "import importlib.util,json,os,socket,threading\n"
            f"spec=importlib.util.spec_from_file_location('r',{relay!r}); m=importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(m)\n"
            "lst=socket.socket(); lst.bind(('127.0.0.1',0)); lst.listen(4); port=lst.getsockname()[1]\n"
            "ppid=os.getppid(); out={}\n"
            "m.install_relay_filter()\n"
            "def t(name,fn):\n"
            "    try:\n"
            "        fn(); out[name]='OK'\n"
            "    except OSError as e:\n"
            "        out[name]='EPERM' if e.errno==1 else 'ERR:%s' % e.errno\n"
            "def relay_path():\n"
            "    c=socket.socket(socket.AF_INET,socket.SOCK_STREAM); c.settimeout(5); c.connect(('127.0.0.1',port))\n"
            "    c.settimeout(None); a,_=lst.accept(); got=[]\n"
            "    th=threading.Thread(target=lambda: got.append(a.recv(16))); th.start()\n"
            "    c.sendall(b'ping'); th.join(5)\n"
            "    if got!=[b'ping']: raise OSError(99,'no data')\n"
            "    c.shutdown(socket.SHUT_RDWR); c.close(); a.close()\n"
            "def fork():\n"
            "    if os.fork()==0: os._exit(0)\n"
            "t('relay_path',relay_path)\n"
            "t('open_file',lambda: open('/etc/hostname','rb').read())\n"
            "t('execve',lambda: os.execv('/usr/bin/true',['true']))\n"
            "t('fork',fork)\n"
            "t('unix_socket',lambda: socket.socket(socket.AF_UNIX))\n"
            "t('inet6_socket',lambda: socket.socket(socket.AF_INET6))\n"
            "t('bind',lambda: socket.socket().bind(('127.0.0.1',0)))\n"
            "t('listen',lambda: lst.listen(8))\n"
            "t('kill',lambda: os.kill(ppid,0))\n"
            "t('mkdir',lambda: os.mkdir('/tmp/vulnix-relay-must-not-exist'))\n"
            "print(json.dumps(out),flush=True)\n")
        r = sp.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        out = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertEqual(out.pop("relay_path"), "OK", out)          # positive control
        self.assertEqual(out, {k: "EPERM" for k in ("open_file", "execve", "fork", "unix_socket", "inet6_socket",
                                                    "bind", "listen", "kill", "mkdir")})
        self.assertFalse(os.path.exists("/tmp/vulnix-relay-must-not-exist"))


@unittest.skipUnless(os.environ.get("VULNIX_ARTEX_REAL_BIN"), "real ARTEX overlay binary only in Linux CI")
class TestRealArtexThroughThePlannerGateway(TestRealArtexPlanner):
    """The real ARTEX, confined, with the Vulnix Planner LLM Gateway as its only model."""

    def test_the_real_planner_plans_and_the_gateway_decides(self):      # replaced below
        pass

    def test_real_artex_plans_during_first_owned_scan_without_second_get(self):
        from tests.test_real_service import FakeService, HOST

        site = FakeService()
        site.banner = "Apache/2.4.62"
        threading.Thread(target=site.serve_forever, daemon=True).start()
        self.addCleanup(site.server_close)
        self.addCleanup(site.shutdown)
        url = f"http://{HOST}:{site.server_port}"
        self.svc._custom_resolver = lambda host: ["127.0.0.1"] if host == HOST else []
        self.svc._real_site_local_artex = True
        challenge = self.svc.issue_ownership_challenge(url=url)["challenge"]
        self.svc.verify_asset_ownership(
            url_or_host=url, method="dns_txt",
            dns_lookup=lambda name: [f'{name} text = "{challenge["dns_txt_value"]}"'],
        )
        self.svc.confirm_asset_scope(url_or_host=url, confirmed_prohibited=True,
                                     activate_workspace=True, allow_loopback_test=True,
                                     allow_status_probe=True)
        with patch.dict(os.environ, {"VULNIX_REAL_SITE_INITIAL_ARTEX": "1",
                                     "VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                                     "VULNIX_ARTEX_LLM_UPSTREAM_URL": self.mock.url + "/chat/completions"}):
            self.svc.start()
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline and self.svc.snapshot()["state"] == "running":
                time.sleep(0.05)
        snap = self.svc.snapshot()
        self.assertEqual(snap["state"], "completed", snap.get("failure"))
        self.assertEqual(site.seen, [("/", None)])
        plan = snap["artex_plan"]["plan"]
        self.assertEqual(plan["engine"]["kind"], "artex-binary")
        self.assertTrue(self.mock.requests)
        sent = json.dumps(self.mock.requests, ensure_ascii=False)
        self.assertIn("Measured root fingerprint", sent)
        self.assertNotIn(HOST, sent)
        self.assertNotIn(url, sent)
        self.assertTrue(all(item["level"] == "L1" for item in plan["items"]))
        self.assertTrue(any(item["status"] == "observed" for item in plan["items"]))

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
        self.assertEqual(self.svc.snapshot()["plan_source"],
                         {"engine": "artex-binary", "pinned": True, "model": "gateway-forced-model"})
        reopened = AssessmentService(Path(self.tmp.name), LAB_PORT, l2_confinement=TEST_CONFINEMENT,
                                     verify_seconds=0.1)
        try:
            self.assertEqual(reopened.snapshot()["plan_source"], self.svc.snapshot()["plan_source"])
            self.assertIsNone(reopened.artex_plan_view()["plan"])
        finally:
            reopened.close()
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

    def test_owned_site_real_artex_uses_budgeted_local_gateway_without_host_leak(self):
        from tests.test_real_service import HOST

        site, url = self.signed_mock_root()
        self.svc.a.findings["f_headers"] = {
            "id": "f_headers", "category": "設定不備", "severity": "medium",
            "verdict": "detected", "verdict_basis": "l1_observation", "demo_fixture": False,
            "evidence": [{"audit_hash": "local-evidence", "saved_at": 1,
                          "body": "private response text"}],
        }
        with patch.dict(os.environ, {"VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                                  "VULNIX_ARTEX_LLM_UPSTREAM_URL": self.mock.url + "/chat/completions"}):
            plan = self.plan()
        report = plan["llm_gateway"]
        self.assertEqual((report["mode"], report["upstream"], report["refused"]),
                         ("forward", "127.0.0.1", 0))
        self.assertGreater(report["calls"], 0)
        self.assertLessEqual(report["calls"], report["budget"]["max_calls"])
        self.assertTrue(self.mock.requests)
        sent = json.dumps(self.mock.requests, ensure_ascii=False)
        self.assertIn("f_headers", sent)
        self.assertNotIn(HOST, sent)
        self.assertNotIn(url, sent)
        self.assertNotIn("private response text", sent)
        self.assertEqual(site.seen, [("/", None)])
        self.assertTrue(all(item["level"] == "L1" for item in plan["items"]))

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
