"""PR-A: the service-owned diagnosis state, its audit journal, restore after a restart,
and the read-only view (docs/DIAGNOSIS_READ_API.md). HTTP / tenancy cases live in
tests/test_tenancy.py (TestDiagnosisReadApiOverHttp)."""
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.adaptive_plan_state import PlanLimits, PlanState
from aegis.assessment import AssessmentService
from aegis.audit import GENESIS, _canon
from aegis.diagnosis_loop import begin_fix_check, observe_lab_root, record_owner_spec
from aegis.diagnosis_state import StateError
from tests import TEST_CONFINEMENT
from tests.test_diagnosis_loop import LoopBase


def rewrite_chain(path: Path, edit) -> None:
    """Edit entries and re-hash the whole chain (an attacker who can write the file)."""
    entries = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    prev = GENESIS
    out = []
    for e in entries:
        edit(e)
        body = {"ts": e["ts"], "event": e["event"], "fields": e["fields"], "prev": prev}
        e = {**body, "hash": hashlib.sha256(_canon(body).encode()).hexdigest()}
        prev = e["hash"]
        out.append(json.dumps(e, ensure_ascii=False, sort_keys=True))
    path.write_text("\n".join(out) + "\n")


class ServiceStateBase(LoopBase):
    """LoopBase with the service's own (journaled) state instead of a free-standing one."""

    def setUp(self):
        super().setUp()
        self.state = self.svc.diagnosis_state()
        observe_lab_root(self.svc, self.state)
        record_owner_spec(self.state, "T2", self.spec, actor="owner-alice")
        self.workers = 0

    def view(self):
        return self.svc.diagnosis_view()

    def restart(self):
        data_dir = self.svc.data_dir
        self.svc.close()
        self.svc = AssessmentService(data_dir, self.lab.server_port, l2_confinement=TEST_CONFINEMENT,
                                     verify_seconds=0.1)
        self.addCleanup(self.svc.close)
        return self.svc


class TestViewOfTheLoop(ServiceStateBase):
    def test_the_view_shows_audited_steps_hypotheses_and_the_fix(self):
        before = self.view()
        self.assertEqual((before["status"], before["plan"], before["steps"]), ("ok", None, []))
        plan = self.runner().run()
        self.assertEqual((plan.state, plan.reason), (PlanState.COMPLETED, "all_settled"))
        v = self.view()
        self.assertEqual(v["status"], "ok")
        self.assertTrue(v["lab_only"])
        self.assertEqual(v["plan"]["state"], "COMPLETED")
        self.assertEqual(v["plan"]["reason"], "all_settled")
        self.assertEqual((v["plan"]["steps_used"], v["plan"]["steps_max"]), (2, 3))
        self.assertEqual([(s["step_id"], s["catalog_id"], s["level"], s["judgement"]["from"],
                           s["judgement"]["to"], s["judgement"]["rule"], s["reason"]) for s in v["steps"]],
                         [("S1", "l1_http_probe", "L1", "open", "contradicted", "denied_without_auth", "test_hypothesis"),
                          ("S2", "l2_idor", "L2", "open", "supported", "cross_account_read", "test_hypothesis")])
        results = {e["hash"] for e in self.audit("result")}
        judged = {e["hash"]: e for e in self.audit("diagnosis.judged")}
        for s in v["steps"]:
            self.assertIn(s["result_audit_hash"], results)
            self.assertEqual(judged[s["judged_audit_hash"]]["fields"]["result_audit_hash"], s["result_audit_hash"])
            self.assertTrue(s["at"].endswith("Z"))
        self.assertEqual(v["steps"][1]["approved_by"], "approver-human")
        self.assertIsNone(v["steps"][0]["approved_by"])      # L1: nobody approved it
        self.assertEqual(v["steps"][1]["observation"]["attrs"],
                         {"status": 200, "auth": "other_account", "control": "established",
                          "reproduction": "proven", "own_resource": False})
        spec = next(e for e in v["evidence"] if e["kind"] == "owner_spec")
        self.assertEqual((spec["recorded_by"], spec["attrs"]), ("owner-alice", {"requirement": "authentication_required"}))
        self.assertTrue(spec["journal_hash"])
        self.assertEqual(v["next"], {"kind": "confirm_fix_available"})
        # the owner fixes it; the after-fix check is compared with the step before
        self.lab.mode = "denied_403"
        made = begin_fix_check(self.svc, self.state, {"T2": "authentication_required"}, actor="owner-alice")
        self.runner().run()
        v = self.view()
        self.assertEqual(v["generation"], 2)
        self.assertEqual(len(v["fix_comparison"]), 1)
        fix = v["fix_comparison"][0]
        self.assertEqual((fix["hypothesis_id"], fix["catalog_id"], fix["result"]), (made[0], "l2_idor", "fixed"))
        self.assertEqual((fix["before"]["generation"], fix["before"]["to"]), (1, "supported"))
        self.assertEqual((fix["after"]["generation"], fix["after"]["to"]), (2, "contradicted"))
        self.assertEqual(v["next"]["kind"], "plan_ended")

    def test_the_view_carries_no_planner_text_body_url_or_token(self):
        self.runner().run()
        plan = self.svc.artex_plan_view()["plan"]
        text = json.dumps(self.view(), ensure_ascii=False)
        for raw in ([i["intent_summary"] for i in plan["items"] if i.get("intent_summary")]
                    + ["VULNIX_LAB_IDOR_PROVEN", "acct_", "res_b_", "/api/accounts", "lab.test", "http://",
                       "127.0.0.1", "input_tokens", "output_tokens", "est_cost", "advis", "intent"]):
            self.assertNotIn(raw, text)

    def test_every_change_is_published_as_the_same_view(self):
        self.runner().run()
        updates = [e for e in self.svc.bus.since(0) if e["type"] == "diagnosis.updated"]
        self.assertGreater(len(updates), 5)
        self.assertEqual(updates[-1]["diagnosis"], self.view())
        self.assertEqual([u["seq"] for u in updates], sorted(u["seq"] for u in updates))


class TestWriteAhead(ServiceStateBase):
    def test_an_owner_spec_that_cannot_be_audited_changes_nothing(self):
        before = self.state.export()
        original = self.svc.audit.record

        def failing(event, **kw):
            if event == "diagnosis.observed":
                raise OSError("disk full")
            return original(event, **kw)
        with patch.object(self.svc.audit, "record", side_effect=failing):
            with self.assertRaises(OSError):
                record_owner_spec(self.state, "T2", "public", actor="owner-alice")
        self.assertEqual(self.state.export(), before)
        self.assertEqual(self.view()["status"], "ok")
        saved = json.loads((self.svc.data_dir / "diagnosis.json").read_text())
        self.assertEqual(saved["state"], before)

    def test_a_judgement_that_cannot_be_journaled_is_not_applied(self):
        original = self.svc.audit.record

        def failing(event, **kw):
            if event == "diagnosis.applied":
                raise OSError("disk full")
            return original(event, **kw)
        with patch.object(self.svc.audit, "record", side_effect=failing):
            plan = self.runner(limits=PlanLimits(max_steps=1)).run()
        self.assertEqual(plan.state, PlanState.FAILED)
        self.assertEqual({h["state"] for h in self.state.hypotheses()}, {"open"})
        v = self.view()
        self.assertEqual((v["status"], v["steps"]), ("ok", []))


class TestRestart(ServiceStateBase):
    def test_the_audited_history_is_restored_read_only_after_a_restart(self):
        self.runner().run()
        before = self.view()
        svc = self.restart()
        after = svc.diagnosis_view()
        self.assertEqual(after["status"], "ok")
        self.assertTrue(after["restored"])
        for k in ("hypotheses", "steps", "evidence", "plan", "generation", "diag_id"):
            self.assertEqual(after[k], before[k], k)
        restored = svc._diagnosis
        with self.assertRaises(StateError):
            record_owner_spec(restored, "T2", "public")
        # a new loop does not continue the old history: it starts a new, journaled state
        fresh = svc.diagnosis_state()
        self.assertIsNot(fresh, restored)
        self.assertNotEqual(fresh.diag_id, before["diag_id"])
        self.assertIn(before["diag_id"], [e["fields"]["diag_id"] for e in svc.audit.entries()
                                          if e["event"] == "diagnosis.closed"])

    def test_a_restored_history_cannot_drive_the_runner(self):
        self.runner(limits=PlanLimits(max_steps=1)).run()
        svc = self.restart()
        from aegis.adaptive_plan_runner import AdaptivePlanRunner
        plan = AdaptivePlanRunner(svc, actor="requester", diagnosis=svc._diagnosis).run()
        self.assertEqual((plan.state, plan.reason), (PlanState.FAILED, "state_from_another_run"))

    def test_an_edited_snapshot_is_refused_after_a_restart(self):
        self.runner().run()
        path = self.svc.data_dir / "diagnosis.json"
        self.svc.close()
        snap = json.loads(path.read_text())
        for h in snap["state"]["hypotheses"]:
            if h["state"] == "supported":
                h["state"] = "contradicted"          # hide the finding
        path.write_text(json.dumps(snap))
        svc = self.restart()
        v = svc.diagnosis_view()
        self.assertEqual((v["status"], v["reason"]), ("unverified", "state_audit_mismatch"))
        self.assertEqual((v["hypotheses"], v["steps"], v["evidence"]), ([], [], []))
        self.assertTrue([e for e in svc.audit.entries() if e["event"] == "diagnosis.restore_refused"])
        with self.assertRaises(ValueError):
            svc.diagnosis_state()                    # no new loop over a disputed history
        with svc._lock:
            svc._reset_workspace_locked()            # the audited way out
        self.assertEqual(svc.diagnosis_view()["status"], "not_started")

    def test_a_deleted_snapshot_is_refused_after_a_restart(self):
        self.runner(limits=PlanLimits(max_steps=1)).run()
        self.svc.close()
        (self.svc.data_dir / "diagnosis.json").unlink()
        v = self.restart().diagnosis_view()
        self.assertEqual((v["status"], v["reason"]), ("unverified", "snapshot_missing"))

    def test_a_consistently_rewritten_log_is_refused_after_a_restart(self):
        self.runner().run()
        self.svc.close()

        def edit(e):
            if e["event"] == "diagnosis.applied" and e["fields"]["record"]["to"] == "supported":
                e["fields"]["record"]["to"] = "contradicted"
        rewrite_chain(self.svc.data_dir / "audit.jsonl", edit)
        v = self.restart().diagnosis_view()
        self.assertEqual((v["status"], v["reason"]), ("unverified", "state_audit_mismatch"))


class TestTamperingAtRuntime(ServiceStateBase):
    def test_a_broken_audit_chain_shows_nothing(self):
        self.runner().run()
        path = self.svc.data_dir / "audit.jsonl"
        lines = path.read_text().splitlines()
        i = next(n for n, line in enumerate(lines) if '"diagnosis.judged"' in line)
        e = json.loads(lines[i])
        e["fields"]["rule"] = "denied"
        lines[i] = json.dumps(e, ensure_ascii=False, sort_keys=True)
        path.write_text("\n".join(lines) + "\n")
        v = self.view()
        self.assertEqual((v["status"], v["reason"]), ("unverified", "audit_chain_invalid"))
        self.assertEqual((v["hypotheses"], v["steps"]), ([], []))
        self.assertEqual(v["next"], {"kind": "check_audit"})

    def test_a_state_changed_behind_the_journal_shows_nothing(self):
        self.runner().run()
        hid = next(h["id"] for h in self.state.hypotheses() if h["state"] == "supported")
        self.state._hyp[hid]["state"] = "contradicted"      # not through the journal
        v = self.view()
        self.assertEqual((v["status"], v["reason"]), ("unverified", "state_audit_mismatch"))

    def test_a_judgement_pointing_at_a_missing_result_shows_nothing(self):
        self.runner().run()

        def edit(e):
            if e["event"] == "result":
                e["event"] = "result.renamed"
        rewrite_chain(self.svc.data_dir / "audit.jsonl", edit)
        # an attacker who also rewrites the snapshot's tail: the result check still refuses
        from aegis.diagnosis_state import DiagnosisState
        entries, valid = self.svc.audit.verified_entries()
        self.assertTrue(valid)
        self.state.tail = DiagnosisState.replay(self.state.diag_id, entries).tail
        v = self.view()
        self.assertEqual(v["status"], "unverified")
        self.assertIn(v["reason"], ("evidence_not_in_audit", "result_not_in_audit"))


class TestResetRevocationAndRealSites(ServiceStateBase):
    def test_a_reset_closes_the_history_and_a_restart_does_not_bring_it_back(self):
        self.runner().run()
        diag_id = self.view()["diag_id"]
        with self.svc._lock:
            self.svc._reset_workspace_locked()
        self.assertEqual(self.view()["status"], "not_started")
        self.assertFalse((self.svc.data_dir / "diagnosis.json").exists())
        self.assertIn(("diagnosis.closed", diag_id, "reset"),
                      [(e["event"], e["fields"].get("diag_id"), e["fields"].get("reason"))
                       for e in self.svc.audit.entries()])
        self.assertEqual(self.restart().diagnosis_view()["status"], "not_started")

    def test_a_revoked_requester_leaves_no_step_and_the_view_says_why(self):
        alive = {"ok": True}
        run = self.svc.workers.run

        def revoke_inside(*a, **kw):
            r = run(*a, **kw)
            alive["ok"] = False
            return r
        with patch.object(self.svc.workers, "run", side_effect=revoke_inside):
            plan = self.runner(request_authorized=lambda: alive["ok"]).run()
        self.assertEqual(plan.reason, "requester_authority_revoked")
        v = self.view()
        self.assertEqual((v["status"], v["steps"]), ("ok", []))
        self.assertEqual({h["state"] for h in v["hypotheses"]}, {"open"})
        self.assertEqual(v["plan"]["state"], "REJECTED")
        self.assertEqual(v["next"], {"kind": "plan_ended", "state": "REJECTED",
                                     "reason": "requester_authority_revoked"})

    def test_a_real_service_has_no_view_no_state_and_no_update(self):
        self.runner(limits=PlanLimits(max_steps=1)).run()
        seq = self.svc.bus.last_seq
        for flag in ("_in_ownership_flow", "_is_external_service_asset"):
            with patch.object(self.svc, flag, return_value=True):
                self.assertIsNone(self.svc.diagnosis_view())
                with self.assertRaises(ValueError):
                    self.svc.diagnosis_state()
        self.assertFalse([e for e in self.svc.bus.since(seq) if e["type"] == "diagnosis.updated"])

    def test_a_planner_failure_text_is_reduced_to_its_id(self):
        def boom(*a, **kw):
            raise RuntimeError("secret detail http://lab.test/api/accounts/B")
        with patch.object(self.svc, "plan_with_artex", side_effect=boom):
            self.runner().run()
        v = self.view()
        self.assertEqual(v["plan"]["reason"], "planner_failed")
        self.assertNotIn("secret detail", json.dumps(v))


class TestReviewOfPrA(ServiceStateBase):
    """Independent review of PR-A (each failed before its fix)."""

    def test_a_cleanup_that_cannot_be_journaled_still_ends_the_plan(self):
        original = self.svc.audit.record

        def failing(event, **kw):
            if event in ("diagnosis.judged", "diagnosis.discarded"):
                raise OSError("disk full")
            return original(event, **kw)
        with patch.object(self.svc.audit, "record", side_effect=failing):
            plan = self.runner(limits=PlanLimits(max_steps=1)).run()
        self.assertEqual(plan.state, PlanState.FAILED)
        self.assertTrue(plan.reason.startswith("audit_failed"))
        self.assertEqual({h["state"] for h in self.state.hypotheses()}, {"open"})
        self.assertEqual(self.view()["status"], "ok")        # the leftover observation is audited

    def test_a_reader_does_not_hold_the_service_lock_while_reading_the_log(self):
        held, original = [], self.svc.audit.verified_entries

        def spy():
            held.append(self.svc._lock._is_owned())
            return original()
        with patch.object(self.svc.audit, "verified_entries", side_effect=spy):
            self.assertEqual(self.view()["status"], "ok")
        self.assertEqual(held, [False])

    def test_a_change_journaled_while_the_view_is_built_is_not_a_mismatch(self):
        original = self.svc.audit.verified_entries
        done = []

        def change_then_read():
            if not done:
                done.append(record_owner_spec(self.state, "T1", "public", actor="owner-alice"))
            return original()
        with patch.object(self.svc.audit, "verified_entries", side_effect=change_then_read):
            v = self.view()
        self.assertEqual(v["status"], "ok")
        self.assertNotIn(done[0], [e["evidence_id"] for e in v["evidence"]])
        self.assertIn(done[0], [e["evidence_id"] for e in self.view()["evidence"]])

    def test_a_failed_notification_does_not_report_an_applied_change_as_failed(self):
        with patch.object(self.svc, "_publish_diagnosis_locked", side_effect=ValueError("bad line")):
            eid = record_owner_spec(self.state, "T1", "public")
        self.assertEqual(self.state.observation(eid)["attrs"], {"requirement": "public"})
        self.assertEqual(self.view()["status"], "ok")

    def test_an_unreadable_log_line_is_a_broken_log(self):
        with open(self.svc.data_dir / "audit.jsonl", "a") as fh:
            fh.write("{not json\n")
        v = self.view()
        self.assertEqual((v["status"], v["reason"]), ("unverified", "audit_chain_invalid"))

    def test_only_an_audited_close_clears_a_disputed_history(self):
        self.svc._diagnosis_refused = {"diag_id": self.state.diag_id, "reason": "state_audit_mismatch"}
        original = self.svc.audit.record

        def failing(event, **kw):
            if event == "diagnosis.closed":
                raise OSError("disk full")
            return original(event, **kw)
        with patch.object(self.svc.audit, "record", side_effect=failing), self.svc._lock:
            self.svc._reset_workspace_locked()
        with self.assertRaises(ValueError):
            self.svc.diagnosis_state()
        self.assertEqual(self.view()["reason"], "state_audit_mismatch")


if __name__ == "__main__":
    unittest.main()
