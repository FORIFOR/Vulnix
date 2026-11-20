"""Multi-step ARTEX plans: state machine and the abnormal cases of docs/ARTEX_MULTISTEP_E2E.md.

Every step uses the real control plane (plan_with_artex -> ProposalRouter ->
Gateway -> Worker) against the loopback lab; the planner is the ARTEX stand-in
with scripted intents (or the real overlay when VULNIX_ARTEX_REAL_BIN is set
for TestRealArtexMultiStep).
"""
import os
import shlex
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis import assessment as assessment_module
from aegis.adaptive_plan_runner import AdaptivePlanRunner
from aegis.adaptive_plan_state import AdaptivePlan, IllegalTransition, PlanLimits, PlanState
from aegis.artex_bridge import ArtexBridgeError
from aegis.assessment import AssessmentService
from aegis.lab import set_lab_mode, start_lab
from aegis.runtime import WorkerResult
from tests import TEST_CONFINEMENT

FAKE = [sys.executable, str(Path(__file__).with_name("fake_artex_planner.py"))]
LAB_PORT = 18231
L1 = {"summary": "Read-only security header recheck with one GET", "asset_ids": [], "priority": 6}
IDOR = {"summary": "IDOR cross-account authorization verification", "asset_ids": [], "priority": 8}
SQLI = {"summary": "SQL injection boundary check", "asset_ids": [], "priority": 7}
RCE = {"summary": "upload a webshell for command execution", "asset_ids": [], "priority": 9}
APPROVER = ("appr", ("operator", "approver"))


class TestStateMachine(unittest.TestCase):
    def plan(self):
        return AdaptivePlan(1, "g1", PlanLimits())

    def move(self, p, to, **kw):
        return p.transition(to, authority_generation="g1", budget_remaining={}, audit_hash="h", **kw)

    def test_happy_path_and_loop(self):
        p = self.plan()
        for s in (PlanState.OBSERVED, PlanState.PROPOSED, PlanState.AUTHORIZED, PlanState.EXECUTING,
                  PlanState.EVIDENCE_RECORDED, PlanState.OBSERVED, PlanState.PROPOSED, PlanState.COMPLETED):
            self.move(p, s)
        self.assertTrue(p.terminal)
        self.assertEqual([t.seq for t in p.history], list(range(1, 9)))

    def test_no_shortcut_to_execution_and_nothing_after_a_terminal_state(self):
        p = self.plan()
        self.move(p, PlanState.OBSERVED)
        with self.assertRaises(IllegalTransition):
            self.move(p, PlanState.EXECUTING)
        self.move(p, PlanState.PROPOSED)
        with self.assertRaises(IllegalTransition):
            self.move(p, PlanState.EVIDENCE_RECORDED)
        self.move(p, PlanState.CANCELLED, reason="stop")
        with self.assertRaises(IllegalTransition):
            self.move(p, PlanState.OBSERVED)

    def test_limits_are_bounded(self):
        for bad in ({"max_steps": 0}, {"max_steps": 11}, {"max_seconds": 0}, {"max_planner_rounds": 0},
                    {"max_planner_cost_usd": -1}):
            with self.assertRaises(ValueError):
                PlanLimits(**bad)


class RunnerBase(unittest.TestCase):
    command = FAKE
    aegis_env = "development"
    scripted = True

    @classmethod
    def setUpClass(cls):
        cls.lab = start_lab(LAB_PORT)

    @classmethod
    def tearDownClass(cls):
        cls.lab.shutdown()
        cls.lab.server_close()

    def setUp(self):
        set_lab_mode("vulnerable")
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = patch.dict(os.environ, {"AEGIS_ENV": self.aegis_env, "VULNIX_ARTEX_REAL_CMD": shlex.join(self.command),
                                      "VULNIX_ARTEX_LLM_URL": getattr(self, "llm_url", "http://127.0.0.1:9/v1"),
                                      "VULNIX_ARTEX_EXPECTED_SHA256": getattr(self, "expected_sha256", ""),
                                      "VULNIX_ARTEX_PG_DSN": os.environ.get("VULNIX_ARTEX_PG_DSN", "")})
        env.start()
        self.addCleanup(env.stop)
        self.svc = AssessmentService(Path(tmp.name), LAB_PORT, l2_confinement=TEST_CONFINEMENT,
                                     verify_seconds=0.1)
        self.addCleanup(self.svc.workers.kill_all)
        self.rounds: list[list[dict]] = []
        self.planner_calls = 0
        original = assessment_module.run_artex_planner

        def scripted(cmd, request, **kw):
            self.planner_calls += 1
            intents = self.rounds.pop(0) if self.rounds else []
            return original(cmd, {**request, "fake_intents": intents}, **kw)
        if self.scripted:
            p = patch.object(assessment_module, "run_artex_planner", side_effect=scripted)
            p.start()
            self.addCleanup(p.stop)
        self.workers = 0
        run = self.svc.workers.run

        def counted(*a, **kw):
            self.workers += 1
            return run(*a, **kw)
        w = patch.object(self.svc.workers, "run", side_effect=counted)
        w.start()
        self.addCleanup(w.stop)

    def runner(self, **kw):
        kw.setdefault("approve", lambda item: APPROVER)
        return AdaptivePlanRunner(self.svc, actor="op", roles=("operator",), **kw)

    def states(self, plan):
        return [t.to_state for t in plan.history]

    def assert_audited(self, plan):
        hashes = {e["hash"] for e in self.svc.audit.entries() if e["event"] == "adaptive_plan.transition"}
        for t in plan.history:
            if t.audit_hash is not None:
                self.assertIn(t.audit_hash, hashes)
        self.assertTrue(self.svc.audit.verify())

    def assert_evidence_consistent(self, plan):
        results = {e["hash"][:12] for e in self.svc.audit.entries() if e["event"] == "result"}
        for step in plan.executed:
            self.assertTrue(step["evidence_ids"])
            for ev in step["evidence_ids"]:
                self.assertIn(ev[3:], results)


class TestMultiStepRuns(RunnerBase):
    def test_two_steps_then_nothing_new(self):
        self.rounds = [[L1], [L1, IDOR], [L1, IDOR]]
        approvals = []
        plan = self.runner(approve=lambda item: approvals.append(item["catalog_id"]) or APPROVER).run()
        self.assertEqual(plan.state, PlanState.COMPLETED, plan.reason)
        self.assertEqual(plan.reason, "no_new_check")
        self.assertEqual([s["catalog_id"] for s in plan.executed], ["l1_http_probe", "l2_idor"])
        self.assertEqual(approvals, ["l2_idor"])          # asked for the L2 item only, at its own step
        self.assertEqual(plan.duplicates, 3)              # repeated proposals never ran again
        self.assertEqual(self.workers, 2)
        nonces = [s["approval_nonce"] for s in plan.executed]
        self.assertEqual(len(set(nonces)), 2)             # no approval is inherited
        self.assertEqual(self.states(plan), [
            "OBSERVED", "PROPOSED", "AUTHORIZED", "EXECUTING", "EVIDENCE_RECORDED",
            "OBSERVED", "PROPOSED", "AUTHORIZED", "EXECUTING", "EVIDENCE_RECORDED",
            "OBSERVED", "PROPOSED", "COMPLETED"])
        self.assertEqual(self.svc.a.findings["f_idor"]["verdict"], "proven")
        self.assert_audited(plan)
        self.assert_evidence_consistent(plan)

    def test_l2_without_a_fresh_approval_is_rejected(self):
        self.rounds = [[IDOR]]
        plan = self.runner(approve=lambda item: None).run()
        self.assertEqual((plan.state, plan.reason), (PlanState.REJECTED, "l2_approval_missing"))
        self.assertEqual(self.workers, 0)

    def test_the_requester_cannot_approve_its_own_l2(self):
        self.svc.separate_l2_approver = True
        self.rounds = [[IDOR]]
        plan = self.runner(approve=lambda item: ("op", ("operator", "approver"))).run()
        self.assertEqual(plan.state, PlanState.REJECTED)
        self.assertEqual(self.workers, 0)

    def test_out_of_catalog_intents_never_execute(self):
        self.rounds = [[RCE]]
        plan = self.runner().run()
        self.assertEqual(plan.state, PlanState.COMPLETED)
        self.assertEqual((plan.advisories, plan.executed, self.workers), (1, [], 0))

    def test_max_steps_stops_a_planner_that_never_runs_out_of_ideas(self):
        self.rounds = [[L1], [IDOR], [SQLI]]
        plan = self.runner(limits=PlanLimits(max_steps=2)).run()
        self.assertEqual((plan.state, plan.reason), (PlanState.EXPIRED, "max_steps"))
        self.assertEqual(self.workers, 2)

    def test_repeated_identical_proposals_are_bounded_by_planner_rounds(self):
        self.rounds = [[L1]] * 10
        plan = self.runner(limits=PlanLimits(max_planner_rounds=1)).run()
        self.assertEqual((plan.state, plan.reason), (PlanState.EXPIRED, "max_planner_rounds"))
        self.assertEqual(self.planner_calls, 1)
        self.assertEqual(self.workers, 1)

    def test_deadline(self):
        ticks = iter([0.0, 0.0, 0.0, 1000.0, 1000.0, 1000.0, 1000.0, 1000.0, 1000.0])
        self.rounds = [[L1]]
        plan = self.runner(limits=PlanLimits(max_seconds=10), clock=lambda: next(ticks, 1000.0)).run()
        self.assertEqual((plan.state, plan.reason), (PlanState.EXPIRED, "deadline"))
        self.assertEqual(self.workers, 0)


class TestRevocationAndStops(RunnerBase):
    def test_logout_between_steps_starts_no_new_worker(self):
        alive = {"ok": True}
        self.rounds = [[L1], [IDOR]]
        run = self.svc.workers.run

        def logout_after_first(*a, **kw):   # wrapped again: counts as well
            r = run(*a, **kw)
            alive["ok"] = False
            return r
        evidence_before = {fid: len(f.get("evidence") or []) for fid, f in self.svc.a.findings.items()}
        with patch.object(self.svc.workers, "run", side_effect=logout_after_first):
            plan = self.runner(request_authorized=lambda: alive["ok"]).run()
        self.assertEqual(plan.state, PlanState.REJECTED)
        self.assertEqual(plan.reason, "requester_authority_revoked")
        self.assertEqual(plan.executed, [])               # not in the plan record ...
        self.assertEqual(self.planner_calls, 1)
        evidence_after = {fid: len(f.get("evidence") or []) for fid, f in self.svc.a.findings.items()}
        self.assertEqual(evidence_after, evidence_before)  # ... and not in the assessment either
        self.assertTrue([e for e in self.svc.audit.entries() if e["event"] == "result.discarded"])
        item = self.svc.artex_plan_view()["plan"]["items"][0]
        self.assertEqual(item["status"], "failed")

    def test_membership_removed_after_planning_blocks_execution(self):
        member = {"ok": True}
        runner = self.runner(request_authorized=lambda: member["ok"])
        move = runner._move

        def remove_on_authorize(plan, to, **kw):
            ok = move(plan, to, **kw)
            if to is PlanState.AUTHORIZED:
                member["ok"] = False                      # removed between authorization and execution
            return ok
        self.rounds = [[L1]]
        with patch.object(runner, "_move", side_effect=remove_on_authorize):
            plan = runner.run()
        self.assertEqual((plan.state, plan.reason), (PlanState.REJECTED, "requester_authority_revoked"))
        self.assertNotIn("EXECUTING", self.states(plan))   # the runner's own pre-execution check
        self.assertEqual(self.workers, 0)

    def test_emergency_stop_between_steps_cancels_and_resume_is_refused(self):
        self.rounds = [[L1], [IDOR]]
        original = self.svc.execute_artex_item

        def stop_after(*a, **kw):
            r = original(*a, **kw)
            self.svc.emergency_stop("op")
            return r
        with patch.object(self.svc, "execute_artex_item", side_effect=stop_after):
            plan = self.runner().run()
        self.assertEqual((plan.state, plan.reason), (PlanState.CANCELLED, "stopped_or_reset"))
        self.assertEqual(plan.executed, [])               # completed before the stop, but not adopted
        before = self.workers
        again = self.runner().run()                       # a resume request after the stop
        self.assertNotEqual(again.state, PlanState.COMPLETED)
        self.assertEqual(self.workers, before)

    def test_stop_while_the_worker_runs_drops_its_result(self):
        self.rounds = [[L1]]
        run = self.svc.workers.run

        def stop_inside(*a, **kw):
            r = run(*a, **kw)
            threading.Thread(target=self.svc.emergency_stop, args=("op",)).start()
            import time
            time.sleep(0.3)
            return r
        with patch.object(self.svc.workers, "run", side_effect=stop_inside):
            plan = self.runner().run()
        self.assertIn(plan.state, (PlanState.CANCELLED, PlanState.FAILED))
        self.assertEqual(plan.executed, [])


class TestFailuresFailClosed(RunnerBase):
    def test_planner_failure_or_truncated_model_answer(self):
        with patch.object(assessment_module, "run_artex_planner",
                          side_effect=ArtexBridgeError("finish_reason=length")):
            plan = self.runner().run()
        self.assertEqual(plan.state, PlanState.FAILED)
        self.assertIn("planner_failed", plan.reason)
        self.assertEqual(self.workers, 0)

    def test_worker_timeout_records_no_evidence(self):
        self.rounds = [[L1]]
        with patch.object(self.svc.workers, "run",
                          return_value=WorkerResult(-9, "", "", True, 30.0, timed_out=True, deadline_s=30.0)):
            plan = self.runner().run()
        self.assertEqual(plan.state, PlanState.FAILED)
        self.assertEqual(plan.executed, [])

    def test_gateway_budget_exhausted(self):
        from aegis.policy import Budget
        self.svc.gateway.budget = Budget(0)
        with patch.object(self.svc, "_ensure_active_window_locked"):   # keeps the exhausted budget
            self.rounds = [[L1]]
            plan = self.runner().run()
        self.assertEqual(plan.state, PlanState.FAILED)
        self.assertEqual(self.workers, 0)

    def test_audit_write_failure_before_execution_starts_nothing(self):
        self.rounds = [[L1]]
        original = self.svc.audit.record

        def fail_executing(event, **fields):
            if event == "adaptive_plan.transition" and fields.get("to") == "EXECUTING":
                raise OSError("disk full")
            return original(event, **fields)
        with patch.object(self.svc.audit, "record", side_effect=fail_executing):
            plan = self.runner().run()
        self.assertEqual(plan.state, PlanState.FAILED)
        self.assertIn("audit_failed", plan.reason)
        self.assertEqual(self.workers, 0)

    def test_evidence_that_does_not_belong_to_the_step_fails_the_plan(self):
        self.rounds = [[L1]]
        original = self.svc.execute_artex_item

        def forge(*a, **kw):
            r = original(*a, **kw)
            with self.svc._lock:
                f = next(iter(self.svc.a.findings.values()))
                f.setdefault("evidence", []).append({"evidence_id": "ev_forged", "audit_hash": "0" * 64})
            return r
        with patch.object(self.svc, "execute_artex_item", side_effect=forge):
            plan = self.runner().run()
        self.assertEqual((plan.state, plan.reason), (PlanState.FAILED, "evidence_mismatch"))

    def test_address_change_after_planning_is_refused_by_the_gateway(self):
        # the lab name now resolves outside the engagement's 127.0.0.1/32
        self.rounds = [[L1]]
        with patch.object(self.svc.gateway.egress, "_resolver", lambda host: ["10.9.9.9"]):
            plan = self.runner().run()
        self.assertEqual(plan.state, PlanState.FAILED)
        self.assertEqual(self.workers, 0)


@unittest.skipUnless(os.environ.get("VULNIX_ARTEX_REAL_BIN"), "real ARTEX overlay binary not available")
class TestRealArtexMultiStep(RunnerBase):
    """The real ARTEX overlay (pinned, kernel-confined when VULNIX_ARTEX_CONFINE=1) with a
    local mock model that proposes the same two checks every round."""
    command = [os.environ.get("VULNIX_ARTEX_REAL_BIN", "")]
    expected_sha256 = os.environ.get("VULNIX_ARTEX_CI_BINARY_SHA256", "")
    aegis_env = "production"
    scripted = False

    def setUp(self):
        from tests.artex_mock_llm import MockLLM, _seeded_asset_id

        def selector(messages):
            a = _seeded_asset_id(messages)
            return [{**L1, "asset_ids": [a]}, {**IDOR, "asset_ids": [a]}]
        self.mock = MockLLM(intent_selector=selector).__enter__()
        self.addCleanup(self.mock.__exit__)
        self.llm_url = self.mock.url
        super().setUp()
        if os.environ.get("VULNIX_ARTEX_CONFINE") == "1":
            from aegis.confinement import KernelConfinement
            self.svc._l2_confinement = KernelConfinement()

    def test_two_steps_through_the_real_planner(self):
        plan = self.runner().run()
        self.assertEqual(plan.state, PlanState.COMPLETED, plan.reason)
        self.assertEqual([s["catalog_id"] for s in plan.executed], ["l1_http_probe", "l2_idor"])
        self.assertEqual(self.workers, 2)
        self.assertGreaterEqual(plan.duplicates, 2)
        view = self.svc.artex_plan_view()["plan"]
        self.assertEqual(view["engine"]["kind"], "artex-binary")
        self.assertTrue(view["engine"]["pinned"])
        if os.environ.get("VULNIX_ARTEX_CONFINE") == "1":
            self.assertTrue(view["isolation"]["confined"])
        self.assertEqual(self.svc.a.findings["f_idor"]["verdict"], "proven")
        self.assert_audited(plan)
        self.assert_evidence_consistent(plan)
        out = os.environ.get("VULNIX_ARTEX_MULTISTEP_EVIDENCE")
        if out:                       # CI checks this file exists: a skipped test is a failure there
            import json
            Path(out).write_text(json.dumps({"engine": view["engine"], "plan": plan.to_dict(),
                                             "workers": self.workers}, ensure_ascii=False, default=str))


if __name__ == "__main__":
    unittest.main()
