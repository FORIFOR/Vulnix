"""PR-C: start / owner spec / fix-check / L2 approval on the lab-only diagnosis loop
(aegis/diagnosis_ops.py, docs/DIAGNOSIS_ACTIONS.md). HTTP and tenancy cases live in
tests/test_tenancy.py (TestDiagnosisActionsOverHttp)."""
import contextlib
import os
import threading
import time
import unittest
from unittest.mock import patch

from aegis.assessment import AssessmentService, ExecutionConflict
from aegis.diagnosis_ops import PERMISSIONS, permissions_of
from aegis.policy import PolicyError
from tests import TEST_CONFINEMENT
from tests.test_diagnosis_loop import LoopBase

REQUESTER = ("qa", ("operator",))
OWNER = ("owner-alice", ("admin", "operator", "approver"))
APPROVER = ("approver-human", ("operator", "approver"))


def key(n) -> str:
    return f"test-key-{n:08d}-abcdef"


class ActionsBase(LoopBase):
    """LoopBase's lab, planner and Worker counter, with the service's own state driven
    only through the operations (the free-standing state of LoopBase is not used)."""

    def setUp(self):
        super().setUp()
        self.ops = self.svc.diagnosis_ops
        self.n = 0

    def op(self, op, who, body=None, *, k=None, authorized=None, approver_authorized=None):
        self.n += 1
        actor, roles = who
        return self.svc.diagnosis_ops.run(op, key=k or key(self.n), actor=actor, roles=roles, body=body or {},
                                          request_authorized=authorized, approver_authorized=approver_authorized)

    def job(self):
        with self.svc._lock:
            return self.svc.diagnosis_ops.job_view_locked()

    def wait_job(self, *states, timeout=30.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            j = self.job()
            if j and j["state"] in states:
                return j
            time.sleep(0.02)
        self.fail(f"job did not reach {states}: {self.job()}")

    def root_observations(self) -> int:
        return len([e for e in self.audit("diagnosis.observed")
                    if (e["fields"].get("record") or {}).get("kind") == "root_response"])

    def l2_workers(self):
        return [e for e in self.audit("result") if e["fields"].get("tool") == "reproduction_probe"]

    def run_to_finding(self):
        """start -> spec -> L1 -> L2 approval -> finding. Returns the approved item id."""
        code, body = self.op("start", REQUESTER)
        self.assertEqual(code, 202, body)
        self.assertEqual(body["job"]["state"], "awaiting_spec")
        self.assertEqual(body["job"]["needs_spec"], ["T2"])
        code, body = self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "authentication_required"})
        self.assertEqual(code, 200, body)
        j = self.wait_job("waiting_approval")
        item = j["waiting_item_id"]
        code, body = self.op("approve", APPROVER, {"item_id": item})
        self.assertEqual(code, 200, body)
        j = self.wait_job("finished")
        self.assertEqual(j["result"], {"plan_state": "COMPLETED", "reason": "all_settled"})
        return item


class TestPermissions(unittest.TestCase):
    def test_the_four_permissions_map_to_existing_service_roles(self):
        self.assertEqual(set(PERMISSIONS), {"diagnosis:read", "diagnosis:request", "asset:specify",
                                            "diagnosis:approve_l2"})
        self.assertEqual(permissions_of(("operator",)), ["diagnosis:read", "diagnosis:request"])
        self.assertEqual(permissions_of(("approver",)), ["diagnosis:approve_l2", "diagnosis:read"])
        self.assertEqual(permissions_of(("admin",)), ["asset:specify", "diagnosis:read"])
        self.assertEqual(permissions_of(("viewer",)), ["diagnosis:read"])
        self.assertEqual(permissions_of(()), [])


class TestStartSpecApproveFind(ActionsBase):
    def test_start_spec_l1_l2_approval_and_finding(self):
        item = self.run_to_finding()
        v = self.svc.diagnosis_view()
        self.assertEqual(v["status"], "ok")
        self.assertEqual([(s["step_id"], s["level"], s["judgement"]["to"]) for s in v["steps"]],
                         [("S1", "L1", "contradicted"), ("S2", "L2", "supported")])
        self.assertEqual(v["steps"][1]["approved_by"], "approver-human")
        self.assertEqual(v["steps"][1]["item_id"] if "item_id" in v["steps"][1] else item, item)
        self.assertEqual(v["operation"]["state"], "finished")
        self.assertEqual(v["operation"]["requested_by"], "qa")
        self.assertEqual(len(self.l2_workers()), 1)
        # the owner's statement is audited with who wrote it, before it took effect
        spec = [e["fields"]["record"] for e in self.audit("diagnosis.observed")
                if e["fields"]["record"].get("source") == "owner_spec"]
        self.assertEqual(len(spec), 1)
        self.assertEqual(spec[0]["recorded_by"], "owner-alice")
        accepted = self.audit("diagnosis.request_accepted")
        self.assertEqual([e["fields"]["op"] for e in accepted], ["start", "owner-spec", "approve"])
        self.assertEqual(len(self.audit("diagnosis.l2_approved")), 1)

    def test_a_loop_with_the_spec_already_given_runs_straight_away(self):
        self.run_to_finding()
        # nothing left to test in this generation: a second start ends at once, no Worker
        before = len(self.audit("result"))
        code, body = self.op("start", REQUESTER)
        self.assertEqual(code, 202, body)
        j = self.wait_job("finished")
        self.assertEqual(j["result"]["reason"], "all_settled")
        self.assertEqual(len(self.audit("result")), before)


class TestPermissionChecks(ActionsBase):
    def test_each_operation_needs_its_permission(self):
        code, body = self.op("start", ("viewer-v", ("viewer",)))
        self.assertEqual((code, body["reason"]), (403, "permission_denied"))
        code, body = self.op("start", ("appr", ("approver",)))
        self.assertEqual((code, body["reason"]), (403, "permission_denied"))
        self.assertEqual(self.op("start", REQUESTER)[0], 202)
        code, body = self.op("owner-spec", REQUESTER, {"target_ref": "T2", "requirement": "public"})
        self.assertEqual((code, body["reason"]), (403, "permission_denied"))
        code, body = self.op("approve", REQUESTER, {"item_id": "x1"})
        self.assertEqual((code, body["reason"]), (403, "permission_denied"))
        code, body = self.op("fix-check", ("appr", ("approver",)))
        self.assertEqual((code, body["reason"]), (403, "permission_denied"))
        # only the two statements the screen offers
        code, body = self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "unspecified"})
        self.assertEqual((code, body["reason"]), (400, "invalid_spec"))
        self.assertEqual(self.audit("diagnosis.request_accepted")[0]["fields"]["op"], "start")
        self.assertEqual(len(self.audit("diagnosis.request_accepted")), 1)   # refusals before acceptance

    def test_revoked_authority_starts_nothing(self):
        before = len(self.audit("result"))
        code, body = self.op("start", REQUESTER, authorized=lambda: False)
        self.assertEqual((code, body["reason"]), (403, "authority_revoked"))
        self.assertIsNone(self.job())
        self.assertEqual(len(self.audit("result")), before)

    def test_the_requester_cannot_approve_their_own_l2_step(self):
        both = ("qa", ("operator", "approver"))
        self.assertEqual(self.op("start", both)[0], 202)
        self.assertEqual(self.op("owner-spec", OWNER, {"target_ref": "T2",
                                                       "requirement": "authentication_required"})[0], 200)
        item = self.wait_job("waiting_approval")["waiting_item_id"]
        code, body = self.op("approve", both, {"item_id": item})
        self.assertEqual((code, body["reason"]), (403, "self_approval"))
        self.assertEqual(len(self.audit("diagnosis.approval_denied")), 1)
        self.assertEqual(self.job()["state"], "waiting_approval")
        self.assertEqual(self.l2_workers(), [])
        # another person can, and only for the item that waits
        code, body = self.op("approve", APPROVER, {"item_id": "not_this_item"})
        self.assertEqual((code, body["reason"]), (409, "not_waiting"))
        self.assertEqual(self.op("approve", APPROVER, {"item_id": item})[0], 200)
        self.wait_job("finished")
        self.assertEqual(len(self.l2_workers()), 1)

    def test_an_approver_whose_authority_lapsed_approves_nothing(self):
        self.assertEqual(self.op("start", REQUESTER)[0], 202)
        self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "authentication_required"})
        item = self.wait_job("waiting_approval")["waiting_item_id"]
        calls = []

        def lapses_after_the_request():
            calls.append(1)
            return len(calls) == 1          # live when approving, gone when the loop takes it
        self.assertEqual(self.op("approve", APPROVER, {"item_id": item},
                                 approver_authorized=lapses_after_the_request)[0], 200)
        j = self.wait_job("finished", "failed")
        # the grant was checked again when the loop took it: lapsed (second call) -> no L2
        self.assertEqual(j["result"]["reason"], "l2_approval_missing")
        self.assertEqual(self.l2_workers(), [])


class TestIdempotency(ActionsBase):
    def test_the_key_is_required(self):
        code, body = self.svc.diagnosis_ops.run("start", key="", actor="qa", roles=("operator",), body={})
        self.assertEqual((code, body["reason"]), (400, "idempotency_key_required"))
        code, body = self.svc.diagnosis_ops.run("start", key="short", actor="qa", roles=("operator",), body={})
        self.assertEqual((code, body["reason"]), (400, "idempotency_key_required"))
        self.assertIsNone(self.job())

    def test_same_key_same_request_returns_the_stored_outcome(self):
        k = key(999)
        code1, b1 = self.op("start", REQUESTER, k=k)
        code2, b2 = self.op("start", REQUESTER, k=k)
        self.assertEqual((code1, code2), (202, 202))
        self.assertTrue(b2["replayed"])
        self.assertEqual(b2["job"]["id"], b1["job"]["id"])
        self.assertEqual(len(self.audit("diagnosis.request_accepted")), 1)
        self.assertEqual(self.root_observations(), 1)

    def test_same_key_different_request_is_409(self):
        k = key(998)
        self.assertEqual(self.op("start", REQUESTER, k=k)[0], 202)
        code, body = self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "public"}, k=k)
        self.assertEqual((code, body["reason"]), (409, "idempotency_key_reused"))
        code, body = self.op("start", ("someone-else", ("operator",)), k=k)
        self.assertEqual((code, body["reason"]), (409, "idempotency_key_reused"))

    def test_concurrent_starts_run_one_loop(self):
        results = []
        barrier = threading.Barrier(6)

        def go(i, k):
            barrier.wait()
            results.append(self.svc.diagnosis_ops.run("start", key=k, actor="qa", roles=("operator",), body={}))
        same = key(500)
        ts = [threading.Thread(target=go, args=(i, same if i < 3 else key(600 + i))) for i in range(6)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(30)
        codes = sorted(c for c, _ in results)
        jobs = {b["job"]["id"] for c, b in results if c == 202}
        self.assertEqual(len(jobs), 1, results)                       # one loop
        self.assertTrue(all(c in (202, 409) for c in codes), codes)
        self.assertGreaterEqual(codes.count(409), 3)                  # the other keys
        self.assertEqual(self.root_observations(), 1)

    def test_a_duplicate_approval_runs_one_worker(self):
        self.assertEqual(self.op("start", REQUESTER)[0], 202)
        self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "authentication_required"})
        item = self.wait_job("waiting_approval")["waiting_item_id"]
        k = key(777)
        codes = [self.op("approve", APPROVER, {"item_id": item}, k=k)[0] for _ in range(3)]
        self.assertEqual(codes, [200, 200, 200])
        other = self.op("approve", ("approver-2", ("approver",)), {"item_id": item})
        self.assertIn(other[0], (409,))
        self.wait_job("finished")
        self.assertEqual(len(self.l2_workers()), 1)
        self.assertEqual(len(self.audit("diagnosis.l2_approved")), 1)


class TestAuditFailure(ActionsBase):
    def test_a_request_that_cannot_be_audited_is_not_accepted(self):
        record = self.svc.audit.record

        def failing(event, **fields):
            if event == "diagnosis.request_accepted":
                raise OSError("disk full")
            return record(event, **fields)
        with patch.object(self.svc.audit, "record", side_effect=failing):
            code, body = self.op("start", REQUESTER)
        self.assertEqual((code, body["reason"]), (503, "audit_failed"))
        self.assertIsNone(self.job())
        self.assertIsNone(self.svc._diagnosis)
        # the key was not taken: the same request may be sent again
        self.assertEqual(self.op("start", REQUESTER, k=key(1))[0], 202)

    def test_a_spec_that_cannot_be_audited_changes_nothing(self):
        self.assertEqual(self.op("start", REQUESTER)[0], 202)
        record = self.svc.audit.record

        def failing(event, **fields):
            if event == "diagnosis.observed":
                raise OSError("disk full")
            return record(event, **fields)
        with patch.object(self.svc.audit, "record", side_effect=failing):
            code, body = self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "authentication_required"})
        self.assertEqual((code, body["reason"]), (503, "audit_failed"))
        self.assertEqual([o for o in self.svc._diagnosis.observations() if o["source"] == "owner_spec"], [])
        self.assertEqual(self.job()["state"], "awaiting_spec")


class TestStopTimeoutRestart(ActionsBase):
    def test_emergency_stop_refuses_and_ends_a_waiting_loop(self):
        self.assertEqual(self.op("start", REQUESTER)[0], 202)
        self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "authentication_required"})
        item = self.wait_job("waiting_approval")["waiting_item_id"]
        self.svc.emergency_stop("qa")
        j = self.wait_job("finished", "failed")
        self.assertNotEqual(j["result"].get("plan_state"), "COMPLETED")
        code, body = self.op("approve", APPROVER, {"item_id": item})
        self.assertEqual(code, 409)
        code, body = self.op("start", REQUESTER)
        self.assertEqual((code, body["reason"]), (409, "emergency_stopped"))
        self.assertEqual(self.l2_workers(), [])

    def test_an_approval_that_never_comes_runs_no_l2(self):
        with patch.dict(os.environ, {"VULNIX_DIAGNOSIS_APPROVAL_TIMEOUT": "1"}):
            self.assertEqual(self.op("start", REQUESTER)[0], 202)
            self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "authentication_required"})
            item = self.wait_job("waiting_approval")["waiting_item_id"]
            j = self.wait_job("finished", timeout=20)
        self.assertEqual(j["result"], {"plan_state": "REJECTED", "reason": "l2_approval_missing"})
        code, body = self.op("approve", APPROVER, {"item_id": item})
        self.assertEqual((code, body["reason"]), (409, "not_waiting"))
        self.assertEqual(self.l2_workers(), [])

    def test_a_restart_interrupts_the_loop_and_a_retry_runs_nothing(self):
        k = key(4242)
        self.assertEqual(self.op("start", REQUESTER, k=k)[0], 202)
        self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "authentication_required"})
        self.wait_job("waiting_approval")
        data_dir = self.svc.data_dir
        self.svc.close()
        self.svc = AssessmentService(data_dir, self.lab.server_port, l2_confinement=TEST_CONFINEMENT,
                                     verify_seconds=0.1)
        self.addCleanup(self.svc.close)
        j = self.job()
        self.assertEqual((j["state"], j["result"]), ("interrupted", {"reason": "server_restarted"}))
        results = len(self.audit("result"))
        code, body = self.op("start", REQUESTER, k=k)          # the client retries after the restart
        self.assertEqual(code, 200)
        self.assertTrue(body["replayed"])
        self.assertEqual(len(self.audit("result")), results)    # nothing ran again
        self.assertEqual(self.job()["state"], "interrupted")
        # a new request starts a new diagnosis (the restored one is read only)
        self.assertEqual(self.op("start", REQUESTER, k=key(4243))[0], 202)
        self.assertEqual(self.job()["state"], "awaiting_spec")
        self.assertEqual(self.l2_workers(), [])


    def test_a_crash_while_waiting_never_runs_the_step_after_the_restart(self):
        k = key(5151)
        self.assertEqual(self.op("start", REQUESTER, k=k)[0], 202)
        self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "authentication_required"})
        item = self.wait_job("waiting_approval")["waiting_item_id"]
        path = self.svc.data_dir / "diagnosis_requests.json"
        on_disk = path.read_text()                       # what a killed process leaves behind
        self.assertIn('"waiting_approval"', on_disk)
        data_dir = self.svc.data_dir
        self.svc.close()
        path.write_text(on_disk)
        self.svc = AssessmentService(data_dir, self.lab.server_port, l2_confinement=TEST_CONFINEMENT,
                                     verify_seconds=0.1)
        self.addCleanup(self.svc.close)
        self.assertEqual(self.job()["state"], "interrupted")
        code, body = self.op("approve", APPROVER, {"item_id": item})
        self.assertEqual((code, body["reason"]), (409, "not_waiting"))
        code, body = self.op("start", REQUESTER, k=k)
        self.assertTrue(body["replayed"])
        self.assertEqual(self.l2_workers(), [])


class TestSpecChange(ActionsBase):
    def test_a_change_after_a_verdict_needs_a_new_generation(self):
        self.run_to_finding()
        code, body = self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "public"})
        self.assertEqual((code, body["reason"]), (409, "needs_new_generation"))
        code, body = self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "authentication_required"})
        self.assertEqual((code, body["reason"]), (409, "already_accepted"))
        specs = [o for o in self.svc._diagnosis.observations() if o["source"] == "owner_spec"]
        self.assertEqual(len(specs), 1)

    def test_a_change_before_any_verdict_is_recorded(self):
        self.assertEqual(self.op("start", REQUESTER)[0], 202)
        # the loop waits for the statement; with "public" there is nothing to prove by L2
        code, body = self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "public"})
        self.assertEqual(code, 200, body)
        item = self.wait_job("waiting_approval")["waiting_item_id"]
        self.assertEqual(self.op("approve", APPROVER, {"item_id": item})[0], 200)
        j = self.wait_job("finished")
        self.assertEqual(j["result"]["reason"], "all_settled")
        idor = next(h for h in self.svc._diagnosis.hypotheses() if h["claim"] == "other_account_read")
        self.assertEqual(idor["state"], "contradicted")      # meant to be public: not a finding


class TestFixCheck(ActionsBase):
    def test_refused_without_a_proven_finding(self):
        code, body = self.op("fix-check", REQUESTER)
        self.assertEqual((code, body["reason"]), (409, "not_started"))
        self.assertEqual(self.op("start", REQUESTER)[0], 202)
        self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "public"})
        item = self.wait_job("waiting_approval")["waiting_item_id"]
        self.op("approve", APPROVER, {"item_id": item})
        self.wait_job("finished")
        code, body = self.op("fix-check", REQUESTER)
        self.assertEqual((code, body["reason"]), (409, "no_proven_finding"))

    def test_fix_check_new_generation_fresh_evidence_new_approval(self):
        first_item = self.run_to_finding()
        before = self.svc.diagnosis_view()
        old_hashes = {e["audit_hash"] for e in before["evidence"]}
        self.lab.mode = "denied_403"                       # the owner applied the fix
        k = key(31337)
        code, body = self.op("fix-check", REQUESTER, k=k)
        self.assertEqual(code, 202, body)
        # nothing carried over: the new generation needs the owner's statement again
        self.assertEqual((body["job"]["state"], body["job"]["generation"]), ("awaiting_spec", 2))
        code, body = self.op("fix-check", REQUESTER)        # once per generation
        self.assertEqual((code, body["reason"]), (409, "loop_active"))
        self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "authentication_required"})
        item = self.wait_job("waiting_approval")["waiting_item_id"]
        self.assertNotEqual(item, first_item)
        # the earlier approval is not reused: its key replays the old outcome, approves nothing
        self.assertEqual(self.job()["state"], "waiting_approval")
        self.assertEqual(self.op("approve", APPROVER, {"item_id": item})[0], 200)
        j = self.wait_job("finished")
        self.assertEqual(j["result"]["reason"], "all_settled")
        v = self.svc.diagnosis_view()
        self.assertEqual(v["generation"], 2)
        [row] = v["fix_comparison"]
        self.assertEqual(row["result"], "fixed")
        self.assertEqual((row["before"]["to"], row["after"]["to"]), ("supported", "contradicted"))
        self.assertNotEqual(row["before"]["result_audit_hash"], row["after"]["result_audit_hash"])
        # the finding, and what each step's own result said about it
        self.assertEqual(row["finding"], {"finding_id": "f_idor", "status": "not_reproduced"})
        self.assertEqual(row["before"]["reproduction"], "proven")
        self.assertNotEqual(row["after"]["reproduction"], "proven")
        # the re-check stands only on new observations
        new = [o for o in self.svc._diagnosis.observations(generation=2)]
        self.assertTrue(new)
        self.assertFalse({o["audit_hash"] for o in new if o.get("audit_hash")} & old_hashes)
        self.assertEqual(len(self.audit("diagnosis.l2_approved")), 2)
        self.assertEqual(len(self.l2_workers()), 2)
        code, body = self.op("fix-check", REQUESTER, k=k)       # replay: nothing new
        self.assertTrue(body.get("replayed"))
        self.assertEqual(len(self.l2_workers()), 2)


class TestReviewFindings(ActionsBase):
    """Regressions from the independent review of PR-C."""

    def test_concurrent_statements_start_one_runner(self):
        self.assertEqual(self.op("start", REQUESTER)[0], 202)
        barrier = threading.Barrier(2)
        out = []

        def state(req, n):
            barrier.wait()
            out.append(self.svc.diagnosis_ops.run("owner-spec", key=key(9000 + n), actor="owner-alice",
                                                  roles=OWNER[1], body={"target_ref": "T2", "requirement": req}))
        ts = [threading.Thread(target=state, args=(r, i)) for i, r in
              enumerate(("authentication_required", "public"))]
        for t in ts:
            t.start()
        for t in ts:
            t.join(30)
        j = self.wait_job("waiting_approval", "finished")
        if j["state"] == "waiting_approval":
            self.assertEqual(self.op("approve", APPROVER, {"item_id": j["waiting_item_id"]})[0], 200)
            self.wait_job("finished")
        plans = {e["fields"]["plan_id"] for e in self.audit("adaptive_plan.transition")}
        self.assertEqual(len(plans), 1, "one job ran one loop")
        self.assertLessEqual(len(self.l2_workers()), 1)

    def test_a_job_waiting_for_the_owner_ends_on_timeout_and_on_stop(self):
        with patch.dict(os.environ, {"VULNIX_DIAGNOSIS_SPEC_TIMEOUT": "1"}):
            self.assertEqual(self.op("start", REQUESTER)[0], 202)
            time.sleep(1.2)
            j = self.job()
            self.assertEqual((j["state"], j["result"]), ("failed", {"reason": "spec_timeout"}))
            self.assertFalse(self.svc.diagnosis_ops.active())
        self.assertEqual(self.op("start", REQUESTER)[0], 202)          # the assessment is free again
        self.assertEqual(self.job()["state"], "awaiting_spec")
        self.svc.emergency_stop("qa")
        j = self.job()
        self.assertEqual((j["state"], j["result"]), ("failed", {"reason": "stopped_or_reset"}))

    def test_a_fix_check_that_measured_nothing_can_be_asked_again(self):
        self.run_to_finding()
        self.lab.mode = "denied_403"
        from aegis import diagnosis_loop
        real = diagnosis_loop.observe_lab_root
        calls = []

        def once_failing(*a, **kw):
            calls.append(1)
            if len(calls) == 1:
                raise ValueError("初期観測（L1）を記録できませんでした")
            return real(*a, **kw)
        with patch.object(diagnosis_loop, "observe_lab_root", side_effect=once_failing):
            code, body = self.op("fix-check", REQUESTER)
            self.assertEqual((code, body["reason"]), (409, "initial_observation_failed"))
            self.assertEqual(self.svc._diagnosis.generation, 1)          # abandoned: nothing measured
            code, body = self.op("fix-check", REQUESTER)
        self.assertEqual(code, 202, body)
        self.assertEqual(body["job"]["generation"], 2)

    def test_an_approval_in_the_last_moment_is_used_and_never_twice(self):
        self.assertEqual(self.op("start", REQUESTER)[0], 202)
        self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "authentication_required"})
        item = self.wait_job("waiting_approval")["waiting_item_id"]
        with self.svc._lock:
            live = self.svc.diagnosis_ops._live[self.job()["id"]]
            nonce = live["nonce"]
        # a grant for another nonce (a stale approval) is never taken
        with self.svc._lock:
            live["grant"] = ("an_stale", "approver-human", ("approver",), None)
        time.sleep(1.2)
        self.assertEqual(self.job()["state"], "waiting_approval")
        self.assertEqual(self.l2_workers(), [])
        with self.svc._lock:
            live["grant"] = None
            self.assertEqual(live["nonce"], nonce)
        self.assertEqual(self.op("approve", APPROVER, {"item_id": item})[0], 200)
        self.wait_job("finished")
        self.assertEqual(len(self.l2_workers()), 1)


def revocable():
    """A live authority (like server.live_request_authority) that can be revoked."""
    state = {"live": True}

    def allowed():
        return state["live"]

    @contextlib.contextmanager
    def lease():
        if not state["live"]:
            raise PolicyError("no live grant")
        yield
    allowed.lease = lease
    return allowed, state


class TestRemainingRisks(ActionsBase):
    """The three risks the review left open, each reproduced as a race (they fail on the
    code before the fix: requester-only launch authority, route-only ARTEX guard)."""

    def manual_l1_item(self) -> str:
        """A manual ARTEX plan (the planner's own default intents), outside any loop."""
        from aegis import artex_bridge
        from aegis import assessment as assessment_module
        with patch.object(assessment_module, "run_artex_planner", artex_bridge.run_artex_planner):
            self.svc.plan_with_artex("qa", roles=("operator",))
        return next(i["id"] for i in self.svc.artex_plan_view()["plan"]["items"]
                    if i["level"] == "L1" and i["status"] == "planned")

    def waiting(self):
        self.assertEqual(self.op("start", REQUESTER)[0], 202)
        self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "authentication_required"})
        return self.wait_job("waiting_approval")["waiting_item_id"]

    def test_the_approver_revoked_right_before_the_worker_starts_launches_nothing(self):
        item = self.waiting()
        approver, approver_state = revocable()
        guard = self.svc._late_launch_guard

        def revoke_then_guard():
            approver_state["live"] = False          # the approver is removed at the last moment
            return guard()
        with patch.object(self.svc, "_late_launch_guard", side_effect=revoke_then_guard):
            self.assertEqual(self.op("approve", APPROVER, {"item_id": item},
                                     approver_authorized=approver)[0], 200)
            j = self.wait_job("finished", "failed")
        self.assertNotEqual(j["result"].get("reason"), "all_settled")
        self.assertEqual(self.l2_workers(), [])           # no Worker for the revoked approval

    def test_an_expired_approval_launches_nothing(self):
        with patch.dict(os.environ, {"VULNIX_DIAGNOSIS_APPROVAL_VALID": "1"}):
            item = self.waiting()
            guard = self.svc._late_launch_guard

            def late():
                time.sleep(1.3)                         # the Worker would start after the approval expired
                return guard()
            with patch.object(self.svc, "_late_launch_guard", side_effect=late):
                self.assertEqual(self.op("approve", APPROVER, {"item_id": item})[0], 200)
                self.wait_job("finished", "failed")
        self.assertEqual(self.l2_workers(), [])

    def test_a_manual_artex_run_cannot_take_a_step_the_loop_holds(self):
        item = self.waiting()
        with self.assertRaises(ExecutionConflict):
            self.svc.execute_artex_item(item, "approver-human", roles=("approver",))
        with self.assertRaises(ExecutionConflict):
            self.svc.plan_with_artex("qa", roles=("operator",))
        self.assertEqual(self.l2_workers(), [])
        self.assertEqual(self.op("approve", APPROVER, {"item_id": item})[0], 200)
        self.wait_job("finished")
        self.assertEqual(len(self.l2_workers()), 1)

    def test_a_manual_run_checked_before_the_loop_started_is_refused_at_its_claim(self):
        """The manual call has passed every check before the loop takes the right, and
        claims its item after: the claim itself refuses (same lock as the job's)."""
        l1 = self.manual_l1_item()
        entered, go = threading.Event(), threading.Event()
        begin = self.svc._begin_operation

        def held_before_the_claim():
            if threading.current_thread().name == "manual":
                entered.set()
                go.wait(10)
            return begin()
        out = {}

        def manual():
            try:
                out["result"] = self.svc.execute_artex_item(l1, "qa", roles=("operator",))
            except Exception as e:  # noqa: BLE001
                out["error"] = e
        before = len(self.audit("result"))
        with patch.object(self.svc, "_begin_operation", side_effect=held_before_the_claim):
            t = threading.Thread(target=manual, name="manual")
            t.start()
            self.assertTrue(entered.wait(10))
            self.assertEqual(self.op("start", REQUESTER)[0], 202)     # the loop takes the right
            go.set()
            t.join(20)
        self.assertIsInstance(out.get("error"), ExecutionConflict)
        # only the loop's own initial observation ran
        self.assertEqual(len(self.audit("result")) - before, 1)

    def test_a_running_manual_item_keeps_the_loop_from_starting(self):
        l1 = self.manual_l1_item()
        started, release = threading.Event(), threading.Event()
        run = self.svc.workers.run

        def slow(*a, **kw):
            started.set()
            release.wait(10)
            return run(*a, **kw)
        with patch.object(self.svc.workers, "run", side_effect=slow):
            t = threading.Thread(target=lambda: self.svc.execute_artex_item(l1, "qa", roles=("operator",)))
            t.start()
            self.assertTrue(started.wait(10))
            code, body = self.op("start", REQUESTER)
            self.assertEqual((code, body["reason"]), (409, "item_running"))
            release.set()
            t.join(20)
        self.assertIsNone(self.job())
        self.assertEqual(self.op("start", REQUESTER)[0], 202)

    def test_waiting_for_the_owner_holds_no_thread_and_no_worker(self):
        self.assertEqual(self.op("start", REQUESTER)[0], 202)
        self.assertEqual(self.job()["state"], "awaiting_spec")
        time.sleep(0.2)
        self.assertEqual([t.name for t in threading.enumerate() if t.name.startswith("diagnosis-")], [])
        workers = self.workers
        time.sleep(0.5)
        self.assertEqual(self.workers, workers)
        on_disk = (self.svc.data_dir / "diagnosis_requests.json").read_text()
        self.assertIn('"awaiting_spec"', on_disk)
        self.assertIn('"spec_since"', on_disk)
        # a restart: the wait is recorded as interrupted and the execution right is free
        data_dir = self.svc.data_dir
        self.svc.close()
        self.svc = AssessmentService(data_dir, self.lab.server_port, l2_confinement=TEST_CONFINEMENT,
                                     verify_seconds=0.1)
        self.addCleanup(self.svc.close)
        self.assertEqual(self.job()["state"], "interrupted")
        self.assertIsNone(self.svc._exec_owner)


class TestNotTheLab(ActionsBase):
    def test_operations_are_404_outside_the_registered_lab(self):
        with patch.object(type(self.svc), "_diagnosis_targets_locked", return_value=[]):
            for op, who, body in (("start", REQUESTER, {}), ("owner-spec", OWNER,
                                                             {"target_ref": "T2", "requirement": "public"}),
                                  ("fix-check", REQUESTER, {}), ("approve", APPROVER, {"item_id": "x"})):
                code, b = self.op(op, who, body)
                self.assertEqual((code, b["reason"]), (404, "not_a_lab"), op)
        self.assertIsNone(self.job())
        self.assertEqual(self.audit("diagnosis.request_accepted"), [])


if __name__ == "__main__":
    unittest.main()
