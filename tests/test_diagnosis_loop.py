"""The diagnosis loop end to end on the independent access-control lab.

observation -> hypotheses -> check -> contradiction -> re-plan -> support -> finding
-> owner's fix -> the same check again (confirm_fix), every step through the real
control plane (plan_with_artex -> ProposalRouter -> Gateway -> Worker), with the ARTEX
stand-in (or the real overlay in TestRealArtexDiagnosisLoop) and a scripted planner
that reads only the facts Vulnix sent.
"""
import json
import os
import shlex
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis import assessment as assessment_module
from aegis.adaptive_plan_runner import AdaptivePlanRunner
from aegis.adaptive_plan_state import PlanLimits, PlanState
from aegis.assessment import AssessmentService
from aegis.diagnosis_judge import _verdict, check_attrs, fixed_rule_steps, judge
from aegis.diagnosis_loop import begin_fix_check, observe_lab_root, record_owner_spec
from aegis.diagnosis_state import DiagnosisState
from tests import TEST_CONFINEMENT
from tests.diagnosis_planner import intents_from_facts, view_from_text
from tests.fixtures.access_control_lab import AccessControlLab
from tests.test_artex_bridge import FAKE

APPROVER = ("approver-human", ("operator", "approver"))
H = "c" * 64


def _titles(request: dict) -> str:
    return "\n".join(o.get("title", "") for o in request.get("observations") or [])


class TestJudge(unittest.TestCase):
    """The fixed rules, one by one (aegis.diagnosis_judge docstring)."""

    def state(self, claim, spec="authentication_required"):
        s = DiagnosisState()
        s.observe(kind="account_resource_link", target_ref="T2", attrs={"present": True}, source="l1")
        if spec is not None:
            s.observe(kind="owner_spec", target_ref="T2", attrs={"requirement": spec}, source="owner_spec")
        return s, s.propose(claim=claim, target_ref="T2", basis=["E1"])

    def run_check(self, claim, catalog, result, spec="authentication_required"):
        s, h = self.state(claim, spec)
        e = s.observe(kind="check_result", target_ref="T2", attrs=check_attrs(catalog, result),
                      source="check", audit_hash=H, step_id="S1", catalog_id=catalog)
        v = judge(s, h, catalog, e)
        return v.to, v.rule

    def idor(self, *, status=200, control=True, owner="acct_B", marker=True, established=True):
        body = {"Check": "idor_cross_account_access", "established": established, "caller_account": "acct_A",
                "resource_owner": owner, "resource_id": "res_b_001"}
        if marker:
            body["confidential_marker"] = "VULNIX_LAB_IDOR_PROVEN"
        control_body = {"Check": "idor_cross_account_access", "caller_account": "acct_B", "resource_owner": "acct_B",
                        "resource_id": "res_b_001", "confidential_marker": "VULNIX_LAB_IDOR_PROVEN"}
        return {"check": "idor", "request_path": "/api/accounts/B/secret",
                "request_headers": {"X-Test-Account": "acct_A"}, "status": status,
                "established": established and status == 200, "verdict": "proven" if established else "x",
                "response": body, "control_status": 200 if control else 404, "control_verified": control,
                "control_response": control_body if control else None}

    def test_other_account_read(self):
        self.assertEqual(self.run_check("other_account_read", "l2_idor", self.idor()),
                         ("supported", "cross_account_read"))
        self.assertEqual(self.run_check("other_account_read", "l2_idor", self.idor(), spec=None),
                         ("needs_spec", "spec_missing"))
        self.assertEqual(self.run_check("other_account_read", "l2_idor", self.idor(), spec="unspecified"),
                         ("needs_spec", "spec_missing"))
        self.assertEqual(self.run_check("other_account_read", "l2_idor", self.idor(), spec="public"),
                         ("contradicted", "intended_public"))
        self.assertEqual(self.run_check("other_account_read", "l2_idor", self.idor(control=False)),
                         ("inconclusive", "control_failed"))
        for status in (401, 403, 404):
            self.assertEqual(self.run_check("other_account_read", "l2_idor",
                                            self.idor(status=status, established=False)),
                             ("contradicted", "denied"))
        self.assertEqual(self.run_check("other_account_read", "l2_idor",
                                        self.idor(owner="acct_A", marker=False, established=False)),
                         ("contradicted", "own_resource_only"))
        self.assertEqual(self.run_check("other_account_read", "l2_idor",
                                        self.idor(status=500, established=False)),
                         ("inconclusive", "unrecognised_answer"))
        self.assertEqual(self.run_check("other_account_read", "l2_idor", "not a dict"),
                         ("inconclusive", "control_failed"))

    def test_unauthenticated_exposure(self):
        for status in (401, 403, 404):
            self.assertEqual(self.run_check("unauthenticated_exposure", "l1_http_probe", {"status": status}),
                             ("contradicted", "denied_without_auth"))
        # a status alone never proves that the protected resource was served
        self.assertEqual(self.run_check("unauthenticated_exposure", "l1_http_probe", {"status": 200}),
                         ("inconclusive", "answered_without_auth_unverified"))
        self.assertEqual(self.run_check("unauthenticated_exposure", "l1_http_probe", {"status": 200},
                                        spec="public"), ("contradicted", "intended_public"))

    def test_a_check_that_does_not_test_the_claim_decides_nothing(self):
        self.assertEqual(self.run_check("unauthenticated_exposure", "l2_idor", self.idor()),
                         ("inconclusive", "check_not_relevant"))

    def test_the_judge_reads_only_a_check_result_on_the_hypothesis_target(self):
        s, h = self.state("other_account_read")
        with self.assertRaises(ValueError):
            judge(s, h, "l2_idor", "E1")                 # an L1 observation, not a check result
        e = s.observe(kind="check_result", target_ref="T1", attrs={"status": 200}, source="check",
                      audit_hash=H, step_id="S1", catalog_id="l2_idor")
        with self.assertRaises(ValueError):
            judge(s, h, "l2_idor", e)


    def test_the_judge_refuses_a_result_from_another_check(self):
        # the observation records which check produced it; judging it as another
        # check's result would read an L1 status as an IDOR reproduction (or back)
        for claim, asked, measured, result in (
                ("other_account_read", "l2_idor", "l1_http_probe", {"status": 200}),
                ("unauthenticated_exposure", "l1_http_probe", "l2_idor", self.idor(status=403, established=False))):
            s, h = self.state(claim)
            e = s.observe(kind="check_result", target_ref="T2", attrs=check_attrs(measured, result),
                          source="check", audit_hash=H, step_id="S1", catalog_id=measured)
            with self.assertRaises(ValueError, msg=(claim, asked)):
                judge(s, h, asked, e)


class LoopBase(unittest.TestCase):
    mode = "idor_vulnerable"
    spec = "authentication_required"
    order = "table"            # the planner's order: "table" (fixed) or "facts" (tests/diagnosis_planner)

    def setUp(self):
        self.lab = AccessControlLab(self.mode)
        t = threading.Thread(target=self.lab.serve_forever, daemon=True)
        t.start()

        def stop_lab():
            self.lab.shutdown()
            self.lab.server_close()
            t.join(timeout=2)
        self.addCleanup(stop_lab)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = patch.dict(os.environ, {"AEGIS_ENV": "development", "VULNIX_ARTEX_REAL_CMD": shlex.join(FAKE),
                                      "VULNIX_ARTEX_LLM_URL": "http://127.0.0.1:9/v1",
                                      "VULNIX_ARTEX_EXPECTED_SHA256": "", "VULNIX_ARTEX_PG_DSN": ""})
        env.start()
        self.addCleanup(env.stop)
        self.svc = AssessmentService(Path(tmp.name), self.lab.server_port, l2_confinement=TEST_CONFINEMENT,
                                     verify_seconds=0.1)
        self.addCleanup(self.svc.close)              # stops Workers and the scope-expiry thread
        self.requests: list[dict] = []
        self.reply = None                         # override: request -> intents
        original = assessment_module.run_artex_planner

        def planner(cmd, request, **kw):
            self.requests.append(json.loads(json.dumps(request)))
            if self.reply is not None:
                intents = self.reply(request)
            elif self.order == "table":
                intents = [{"summary": json.dumps(s), "asset_ids": [1], "priority": 5}
                           for s in fixed_rule_steps(view_from_text(_titles(request)))]
            else:
                intents = intents_from_facts(_titles(request))
            return original(cmd, {**request, "fake_intents": intents}, **kw)
        p = patch.object(assessment_module, "run_artex_planner", side_effect=planner)
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
        self.state = DiagnosisState()
        observe_lab_root(self.svc, self.state)
        record_owner_spec(self.state, "T2", self.spec)
        self.workers = 0                          # count the loop's Workers, not the initial L1
        self.approvals: list[dict] = []

    def approve(self, item):
        self.approvals.append(item)
        return APPROVER

    def runner(self, **kw):
        kw.setdefault("approve", self.approve)
        return AdaptivePlanRunner(self.svc, actor="requester", roles=("operator",), diagnosis=self.state, **kw)

    def hyp(self, claim, purpose="diagnose"):
        return next(h for h in self.state.hypotheses() if h["claim"] == claim and h["purpose"] == purpose)

    def audit(self, event):
        return [e for e in self.svc.audit.entries() if e["event"] == event]


class TestDiagnosisLoopEndToEnd(LoopBase):
    def test_observe_hypothesise_contradict_replan_find_fix_and_confirm(self):
        # 1. the fixed L1 observed the root and the account resource it links to
        self.assertEqual([t["target_id"] for t in self.svc.diagnosis_targets()], ["T1", "T2"])
        plan = self.runner().run()
        self.assertEqual((plan.state, plan.reason), (PlanState.COMPLETED, "all_settled"))
        steps = [(s["step_id"], s["catalog_id"], s["target_ref"], s["judgement"]["from"], s["judgement"]["to"],
                  s["judgement"]["rule"]) for s in plan.executed]
        # 2. the first hypothesis was contradicted, the plan was made again, the second supported
        self.assertEqual(steps, [
            ("S1", "l1_http_probe", "T2", "open", "contradicted", "denied_without_auth"),
            ("S2", "l2_idor", "T2", "open", "supported", "cross_account_read")])
        unauth, other = self.hyp("unauthenticated_exposure"), self.hyp("other_account_read")
        self.assertEqual((unauth["state"], other["state"]), ("contradicted", "supported"))
        # 3. every round's planner input carried the latest states and evidence
        self.assertEqual(len(self.requests), 2)
        first, second = (_titles(r) for r in self.requests)
        self.assertNotIn('"contradicted"', first)
        self.assertIn('"state":"contradicted"', second)
        self.assertIn('"contradicting":["E4"]', second)
        self.assertIn('"kind":"check_result"', second)
        # 4. each step's Worker result is tied to its audit hash and step id, and the
        #    judgement was audited before it took effect
        results = {e["hash"] for e in self.audit("result")}
        judged = self.audit("diagnosis.judged")
        self.assertEqual([j["fields"]["step_id"] for j in judged], ["S1", "S2"])
        for s, j in zip(plan.executed, judged):
            obs = self.state.observation(s["judgement"]["observation"])
            self.assertEqual((obs["step_id"], obs["audit_hash"], obs["catalog_id"]),
                             (s["step_id"], j["fields"]["result_audit_hash"], s["catalog_id"]))
            self.assertIn(obs["audit_hash"], results)
            self.assertEqual(s["judgement"]["judged_audit_hash"], j["hash"])
            self.assertEqual(j["fields"]["approval_nonce"], s["approval_nonce"])
        self.assertTrue(self.svc.audit.verify())
        # 5. the finding: the supported hypothesis, and Vulnix's own L2 evidence for it
        f = self.svc.a.findings["f_idor"]
        self.assertEqual(f["verdict"], "proven")
        self.assertIn(plan.executed[1]["judgement"]["result_audit_hash"],
                      {e["audit_hash"] for e in f["evidence"]})
        self.assertEqual([c["id"] for c in self.state.finding_candidates()], [other["id"]])
        # L2 needed its own human approval; the L1 step did not ask for one
        self.assertEqual([a["catalog_id"] for a in self.approvals], ["l2_idor"])
        self.assertEqual(self.approvals[0]["step"]["hypothesis_id"], other["id"])
        # 6. the owner fixes it; the same check runs again on new-generation evidence
        self.lab.mode = "denied_403"
        made = begin_fix_check(self.svc, self.state, {"T2": "authentication_required"})
        self.assertEqual(len(made), 1)
        fix = self.runner().run()
        self.assertEqual((fix.state, fix.reason), (PlanState.COMPLETED, "all_settled"))
        self.assertEqual([(s["catalog_id"], s["reason"], s["judgement"]["to"], s["judgement"]["rule"])
                          for s in fix.executed], [("l2_idor", "confirm_fix", "contradicted", "denied")])
        self.assertEqual(self.state.hypothesis(made[0])["supersedes"], other["id"])
        self.assertEqual(self.svc.a.findings["f_idor"]["verdict"], "not_reproduced")
        self.assertEqual(len(self.approvals), 2)              # a fresh approval after the fix
        # the original finding stays a supported record of what was true before the fix
        self.assertEqual(self.hyp("other_account_read")["state"], "supported")
        fix_request = _titles(self.requests[-1])
        self.assertIn('"purpose":"confirm_fix"', fix_request)
        self.assertIn('"generation":2', fix_request)

    def test_the_planner_payload_carries_no_lab_label_secret_or_url(self):
        self.runner().run()
        payload = json.dumps(self.requests)                 # the whole request ARTEX receives
        port = str(self.lab.server_port)
        for raw in (self.mode, "VULNIX_LAB_IDOR_PROVEN", "acct_", "/api/accounts", "lab.test", H[:12],
                    "127.0.0.1", ":" + port):
            self.assertNotIn(raw, payload)
        for e in self.audit("result"):
            self.assertNotIn(e["hash"], payload)


class TestLoopEndings(LoopBase):
    def test_missing_owner_spec_stops_as_needs_spec(self):
        self.lab.mode = "idor_spec_missing"
        self.state = DiagnosisState()
        observe_lab_root(self.svc, self.state)
        record_owner_spec(self.state, "T2", "unspecified")
        plan = self.runner().run()
        self.assertEqual((plan.state, plan.reason), (PlanState.COMPLETED, "needs_spec"))
        self.assertEqual(self.hyp("other_account_read")["state"], "needs_spec")
        self.assertEqual(self.state.finding_candidates(), [])
        self.assertEqual(self.svc.a.findings["f_idor"]["verdict"], "proven")   # the measurement itself

    def test_a_planner_that_offers_nothing_acceptable_ends_without_running_anything(self):
        self.reply = lambda request: [
            {"summary": "IDOR cross-account authorization verification", "asset_ids": [1], "priority": 9},
            {"summary": json.dumps({"hypothesis_id": "H2", "catalog_id": "l2_idor", "target_ref": "T1",
                                    "evidence_refs": ["E1"], "reason": "test_hypothesis"}),
             "asset_ids": [1], "priority": 9},
            {"summary": json.dumps({"hypothesis_id": "H2", "catalog_id": "l2_sqli", "target_ref": "T2",
                                    "evidence_refs": ["E2"], "reason": "test_hypothesis",
                                    "state": "supported"}), "asset_ids": [1], "priority": 9}]
        plan = self.runner().run()
        self.assertEqual((plan.state, plan.reason), (PlanState.COMPLETED, "no_progress"))
        self.assertEqual((self.workers, plan.executed, plan.rejected_steps), (0, [], 2))
        self.assertEqual({h["state"] for h in self.state.hypotheses()}, {"open"})

    def test_steps_that_change_nothing_are_cut_off(self):
        self.lab.mode = "denied_404"           # the owner control fails every time: inconclusive
        calls = {"n": 0}

        def ask_again(request):
            calls["n"] += 1
            view = view_from_text(_titles(request))
            refs = [o["evidence_id"] for o in view["observations"] if o["target_ref"] == "T2"]
            return [{"summary": json.dumps({"hypothesis_id": "H2", "catalog_id": "l2_idor", "target_ref": "T2",
                                            "evidence_refs": refs, "reason": "test_hypothesis"}),
                     "asset_ids": [1], "priority": 5}]
        self.reply = ask_again
        plan = self.runner().run()
        # the second identical request cites only the check's own result: a repeat
        self.assertEqual((plan.state, plan.reason), (PlanState.COMPLETED, "no_progress"))
        self.assertEqual(len(plan.executed), 1)
        self.assertEqual(self.hyp("other_account_read")["state"], "inconclusive")

    def test_stalled_steps_are_bounded(self):
        self.lab.mode = "denied_404"
        plan = self.runner(limits=PlanLimits(max_steps=10, max_stalled_steps=1)).run()
        self.assertIn(plan.reason, ("stalled", "no_progress"))
        self.assertLessEqual(len(plan.executed), 3)

    def test_max_steps_cuts_the_loop(self):
        plan = self.runner(limits=PlanLimits(max_steps=1)).run()
        self.assertEqual((plan.state, plan.reason), (PlanState.EXPIRED, "max_steps"))
        self.assertEqual(len(plan.executed), 1)

    def test_l2_without_a_fresh_human_approval_is_rejected(self):
        self.order = "facts"                   # asks for the L2 check first
        plan = self.runner(approve=lambda item: None).run()
        self.assertEqual((plan.state, plan.reason), (PlanState.REJECTED, "l2_approval_missing"))
        self.assertEqual(self.hyp("other_account_read")["state"], "open")

    def test_the_requester_cannot_approve_its_own_l2(self):
        self.order = "facts"
        self.svc.separate_l2_approver = True
        plan = self.runner(approve=lambda item: ("requester", ("operator", "approver"))).run()
        self.assertEqual(plan.state, PlanState.REJECTED)
        self.assertEqual(self.hyp("other_account_read")["state"], "open")


class TestLoopStopsAndRevocation(LoopBase):
    def test_emergency_stop_after_a_step_adopts_nothing(self):
        original = self.svc.execute_artex_item

        def stop_after(*a, **kw):
            r = original(*a, **kw)
            self.svc.emergency_stop("op")
            return r
        with patch.object(self.svc, "execute_artex_item", side_effect=stop_after):
            plan = self.runner().run()
        self.assertEqual((plan.state, plan.reason), (PlanState.CANCELLED, "stopped_or_reset"))
        self.assertEqual(plan.executed, [])
        self.assertEqual({h["state"] for h in self.state.hypotheses()}, {"open"})
        self.assertEqual(self.audit("diagnosis.judged"), [])

    def test_revocation_while_the_worker_runs_discards_the_result(self):
        alive = {"ok": True}
        run = self.svc.workers.run

        def revoke_inside(*a, **kw):
            r = run(*a, **kw)
            alive["ok"] = False
            return r
        with patch.object(self.svc.workers, "run", side_effect=revoke_inside):
            plan = self.runner(request_authorized=lambda: alive["ok"]).run()
        self.assertEqual((plan.state, plan.reason), (PlanState.REJECTED, "requester_authority_revoked"))
        self.assertEqual(plan.executed, [])
        self.assertTrue(self.audit("result.discarded"))
        self.assertEqual({h["state"] for h in self.state.hypotheses()}, {"open"})

    def test_a_judgement_that_cannot_be_audited_changes_nothing(self):
        original = self.svc.audit.record

        def fail_judged(event, **fields):
            if event == "diagnosis.judged":
                raise OSError("disk full")
            return original(event, **fields)
        with patch.object(self.svc.audit, "record", side_effect=fail_judged):
            plan = self.runner().run()
        self.assertEqual(plan.state, PlanState.FAILED)
        self.assertIn("audit_failed", plan.reason)
        self.assertEqual({h["state"] for h in self.state.hypotheses()}, {"open"})
        # the unaudited check result cannot be cited later either
        self.assertEqual([o for o in self.state.observations() if o["source"] == "check"], [])

    def test_a_step_whose_evidence_cannot_be_recorded_changes_no_hypothesis(self):
        # S1 (L1, contradicted) is recorded; recording S2's evidence (the L2 IDOR) fails
        original = self.svc.audit.record
        seen = {"n": 0}

        def fail_second_evidence(event, **fields):
            if event == "adaptive_plan.transition" and fields.get("to") == PlanState.EVIDENCE_RECORDED.value:
                seen["n"] += 1
                if seen["n"] == 2:
                    raise OSError("disk full")
            return original(event, **fields)
        with patch.object(self.svc.audit, "record", side_effect=fail_second_evidence):
            plan = self.runner().run()
        self.assertEqual(plan.state, PlanState.FAILED)
        self.assertIn("audit_failed", plan.reason)
        # the plan lists only the step whose evidence was recorded
        self.assertEqual([s["step_id"] for s in plan.executed], ["S1"])
        self.assertEqual(self.hyp("unauthenticated_exposure")["state"], "contradicted")
        # the unrecorded step moved no hypothesis and left nothing to cite
        self.assertEqual(self.hyp("other_account_read")["state"], "open")
        self.assertEqual([o["step_id"] for o in self.state.observations() if o["source"] == "check"], ["S1"])
        self.assertEqual([j["fields"]["step_id"] for j in self.audit("diagnosis.judged")], ["S1"])
        # the finding rests only on the Worker's own audited result (Gateway "result"),
        # never on the plan or the hypothesis
        results = {e["hash"] for e in self.audit("result")}
        with self.svc._lock:
            finding = dict(self.svc.a.findings.get("f_idor") or {})
        cited = {e.get("audit_hash") for e in finding.get("evidence") or [] if isinstance(e, dict)}
        self.assertTrue(cited and cited <= results, finding)
        self.assertTrue(self.svc.audit.verify())

    def test_a_result_from_another_tool_is_not_judged(self):
        original = self.svc.audit.verified_entries

        def other_tool():
            entries, ok = original()
            return [{**e, "fields": {**e["fields"], "tool": "status_marker"}} if e.get("event") == "result"
                    else e for e in entries], ok
        with patch.object(self.svc.audit, "verified_entries", side_effect=other_tool):
            plan = self.runner().run()
        self.assertEqual((plan.state, plan.reason), (PlanState.FAILED, "check_mismatch"))
        self.assertEqual(self.audit("diagnosis.judged"), [])
        self.assertEqual({h["state"] for h in self.state.hypotheses()}, {"open"})

    def test_a_fix_reported_while_a_step_runs_fails_the_plan_without_a_judgement(self):
        original = self.svc.execute_artex_item

        def fix_during(*a, **kw):
            r = original(*a, **kw)
            self.state.begin_generation()
            return r
        with patch.object(self.svc, "execute_artex_item", side_effect=fix_during):
            plan = self.runner().run()
        self.assertEqual((plan.state, plan.reason), (PlanState.FAILED, "generation_changed"))
        self.assertEqual(self.audit("diagnosis.judged"), [])
        self.assertEqual({h["state"] for h in self.state.hypotheses()}, {"open"})

    def test_a_reset_while_the_root_is_observed_records_nothing(self):
        run = self.svc.workers.run

        def reset_inside(*a, **kw):
            r = run(*a, **kw)
            with self.svc._lock:
                self.svc._reset_workspace_locked()
            return r
        fresh = DiagnosisState()
        with patch.object(self.svc.workers, "run", side_effect=reset_inside):
            with self.assertRaises(ValueError):
                observe_lab_root(self.svc, fresh)
        self.assertEqual(fresh.observations(), [])
        self.assertEqual(self.svc.diagnosis_targets(), [t for t in self.svc.diagnosis_targets()
                                                         if t["target_id"] == "T1"])

    def test_a_non_root_target_runs_only_the_plain_get(self):
        status = json.dumps({"hypothesis_id": "H1", "catalog_id": "l1_apache_mod_status", "target_ref": "T2",
                             "evidence_refs": ["E2"], "reason": "test_hypothesis"})
        self.reply = lambda request: [{"summary": status, "asset_ids": [1], "priority": 5}]
        plan = self.runner().run()
        # refused by the contract (check_not_for_target) before anything is claimed or run
        self.assertEqual((plan.state, plan.reason, plan.rejected_steps), (PlanState.COMPLETED, "no_progress", 1))
        self.assertEqual(self.workers, 0)

    def test_evidence_that_is_not_the_steps_own_result_fails_the_plan(self):
        original = self.svc.artex_item_evidence

        def forged(item_id):
            return [{**e, "audit_hash": "0" * 64} for e in original(item_id)]
        with patch.object(self.svc, "artex_item_evidence", side_effect=forged):
            plan = self.runner().run()
        self.assertEqual((plan.state, plan.reason), (PlanState.FAILED, "evidence_mismatch"))
        self.assertEqual({h["state"] for h in self.state.hypotheses()}, {"open"})

    def test_a_reset_between_rounds_cancels_the_loop(self):
        original = self.svc.execute_artex_item

        def reset_after(*a, **kw):
            r = original(*a, **kw)
            self.svc._run_generation += 1
            return r
        with patch.object(self.svc, "execute_artex_item", side_effect=reset_after):
            plan = self.runner().run()
        self.assertEqual((plan.state, plan.reason), (PlanState.CANCELLED, "stopped_or_reset"))


class TestReviewFindings(LoopBase):
    """Independent review of PR #97 (2026-11-21): each test fails on 23a95da."""

    def test_a_state_from_another_run_or_target_decides_nothing(self):
        with self.svc._lock:
            self.svc._reset_workspace_locked()          # a new run generation
        observe_lab_root(self.svc, DiagnosisState())      # the workspace measures its root again
        plan = self.runner().run()                        # ... but the old state is reused
        self.assertEqual((plan.state, plan.reason), (PlanState.FAILED, "state_from_another_run"))
        self.assertEqual(self.workers, 0)
        with self.assertRaises(ValueError):
            observe_lab_root(self.svc, self.state)        # nor can it take new observations

    def test_a_check_that_does_not_act_on_the_target_is_rejected_by_the_contract(self):
        hid = None

        def reply(request):
            nonlocal hid
            view = view_from_text(_titles(request))
            hid = next(h["id"] for h in view["hypotheses"] if h["claim"] == "other_account_read")
            bad = [{"hypothesis_id": hid, "catalog_id": c, "target_ref": "T2", "evidence_refs": ["E2"],
                    "reason": "test_hypothesis"} for c in ("l1_apache_mod_status", "l2_sqli")]
            return [{"summary": json.dumps(s), "asset_ids": [1], "priority": 5} for s in bad]
        self.reply = reply
        plan = self.runner().run()
        self.assertEqual((plan.state, plan.reason), (PlanState.COMPLETED, "no_progress"))
        self.assertEqual(plan.rejected_steps, 2)
        self.assertEqual(self.workers, 0)
        self.assertEqual(self.approvals, [])

    def test_a_stop_after_the_worker_returns_adopts_no_judgement(self):
        from aegis import diagnosis_judge
        original = diagnosis_judge.judge

        def stop_while_judging(*a, **kw):
            v = original(*a, **kw)
            self.svc.emergency_stop("op")
            return v
        with patch.object(diagnosis_judge, "judge", side_effect=stop_while_judging):
            plan = self.runner().run()
        self.assertEqual((plan.state, plan.reason), (PlanState.CANCELLED, "stopped_or_reset"))
        self.assertEqual(plan.executed, [])
        self.assertEqual({h["state"] for h in self.state.hypotheses()}, {"open"})
        self.assertEqual([o for o in self.state.observations() if o["source"] == "check"], [])

    def test_evidence_ids_are_never_reused_after_a_discard(self):
        s = DiagnosisState()
        e1 = s.observe(kind="x", target_ref="T1", attrs={}, source="l1")
        e2 = s.observe(kind="check_result", target_ref="T1", attrs={}, source="check", audit_hash=H,
                       step_id="S1", catalog_id="l2_idor")
        s.discard_unjudged(e2)
        e3 = s.observe(kind="x", target_ref="T1", attrs={}, source="l1")
        self.assertEqual((e1, e2, e3), ("E1", "E2", "E3"))
        self.assertEqual((s.seq(e3), s.count()), (2, 3))

    def test_a_failed_fix_reobservation_keeps_the_earlier_generation(self):
        self.runner().run()
        self.assertEqual(self.hyp("other_account_read")["state"], "supported")
        with self.assertRaises(ValueError):
            begin_fix_check(self.svc, self.state, {"T2": self.spec}, request_authorized=lambda: False)
        self.assertEqual(self.state.generation, 1)
        self.assertEqual(self.audit("diagnosis.judged")[-1]["fields"]["step_id"], "S2")


class TestRealSitesAreRefused(LoopBase):
    def test_no_diagnosis_targets_and_no_plan_for_a_real_service(self):
        with patch.object(self.svc, "_in_ownership_flow", return_value=True):
            self.assertEqual(self.svc.diagnosis_targets(), [])
            with self.assertRaises(ValueError):
                self.svc.plan_with_artex("requester", diagnosis=(self.state, frozenset()))
            with self.assertRaises(ValueError):
                observe_lab_root(self.svc, DiagnosisState())
        self.assertEqual(self.requests, [])
        with patch.object(self.svc, "_is_external_service_asset", return_value=True):
            self.assertEqual(self.svc.diagnosis_targets(), [])

    def test_a_forged_verdict_or_planner_words_never_move_a_hypothesis(self):
        from aegis.diagnosis_state import StateError
        from aegis.diagnosis_judge import Verdict
        self.runner(limits=PlanLimits(max_steps=1)).run()
        h = self.hyp("other_account_read")["id"]
        with self.assertRaises(StateError):
            self.state.apply(Verdict(h, "supported", ("E2",), "planner_said_so"))
        with self.assertRaises(StateError):     # even a judge verdict citing another target
            self.state.apply(_verdict(h, "supported", ["E1"], "x"))
        import dataclasses
        real = _verdict(h, "inconclusive", ["E2"], "x")
        with self.assertRaises(StateError):     # a copy of a real verdict with another outcome
            self.state.apply(dataclasses.replace(real, to="supported"))
        with self.assertRaises(StateError):     # support needs a check result, not only L1
            self.state.apply(_verdict(h, "supported", ["E2"], "x"))


@unittest.skipUnless(os.environ.get("VULNIX_ARTEX_REAL_BIN"), "real ARTEX overlay binary not available")
class TestRealArtexDiagnosisLoop(unittest.TestCase):
    """The real ARTEX overlay (pinned; kernel-confined when VULNIX_ARTEX_CONFINE=1) with a
    local mock model that reads the seeded facts and answers with contract steps."""

    def test_the_loop_through_the_real_planner(self):
        from scripts.bench_diagnosis_loop import run_case
        row = run_case("idor_vulnerable", "artex_planner")
        spec = run_case("idor_spec_missing", "artex_planner")
        out = os.environ.get("VULNIX_ARTEX_DIAGNOSIS_EVIDENCE")
        if out:                       # CI checks this file exists: a skipped test is a failure there
            Path(out).write_text(json.dumps({"idor_vulnerable": row, "idor_spec_missing": spec},
                                            ensure_ascii=False, default=str))
        why = json.dumps({k: row[k] for k in ("plans", "plan_failures", "steps", "model_saw_facts")},
                         ensure_ascii=False, default=str)[:3000]
        self.assertEqual(row["engine_kind"], "artex-binary", why)
        self.assertEqual(row["other_account_read"], "supported", why)
        self.assertEqual(row["unauthenticated_exposure"], "contradicted")
        self.assertTrue(row["fix_check"]["confirmed_fixed"])
        self.assertTrue(row["audit_chain_valid"] and row["every_judgement_cites_an_audited_result"])
        self.assertFalse(row["planner_saw_lab_label_or_secret"])
        self.assertEqual(spec["other_account_read"], "needs_spec")


if __name__ == "__main__":
    unittest.main()
