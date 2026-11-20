"""The evaluation's shared US$5 ledger (aegis/evaluation/budget_ledger.py)."""
import tests  # noqa: F401
import dataclasses
import json
import tempfile
import threading
import unittest
from pathlib import Path

from aegis.evaluation.budget_ledger import BudgetLedger, LedgerError, LedgerLimits
from aegis.evaluation.model_adapter import ABLITERATED, ABLITERATED_LARGE_V2, CLAUDE_SONNET, MODELS

SHA = "a" * 64


class TestBudgetLedger(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "ledger.jsonl"
        self.ledger = BudgetLedger(self.path)

    def reserve(self, model=CLAUDE_SONNET, case="holdout-001", rnd=1, **kw):
        return self.ledger.reserve(model=model, case_id=case, round_no=rnd, request_sha256=SHA, **kw)

    def test_the_owner_plan_fits_the_cap_and_the_worst_case_matches_the_prices(self):
        self.assertEqual(ABLITERATED.max_cost_usd(), 0.012144)
        self.assertEqual(ABLITERATED_LARGE_V2.max_cost_usd(), 0.02024)
        self.assertEqual(CLAUDE_SONNET.max_cost_usd(), 0.02448)
        for n in range(1, 31):
            for rnd in (1, 2):
                for m in MODELS.values():
                    self.reserve(model=m, case=f"holdout-{n:03d}", rnd=rnd)
        self.assertAlmostEqual(self.ledger.summary()["counted_usd"], 3.41184, places=5)

    def test_a_reservation_over_the_cap_is_refused_before_sending(self):
        small = BudgetLedger(self.path, LedgerLimits(max_total_cost_usd=0.05))
        small.reserve(model=CLAUDE_SONNET, case_id="c1", round_no=1, request_sha256=SHA)
        small.reserve(model=CLAUDE_SONNET, case_id="c2", round_no=1, request_sha256=SHA)
        with self.assertRaises(LedgerError) as e:
            small.reserve(model=CLAUDE_SONNET, case_id="c3", round_no=1, request_sha256=SHA)
        self.assertEqual(e.exception.code, "over_budget")
        self.assertEqual(small.summary()["reservations"], 2)

    def test_concurrent_reservations_never_exceed_the_cap(self):
        cap = LedgerLimits(max_total_cost_usd=0.25, max_cases=100)
        results = []

        def go(i):
            try:
                BudgetLedger(self.path, cap).reserve(model=CLAUDE_SONNET, case_id=f"c{i}", round_no=1,
                                                     request_sha256=SHA)
                results.append("ok")
            except LedgerError as e:
                results.append(e.code)
        threads = [threading.Thread(target=go, args=(i,)) for i in range(40)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count("ok"), 10)            # 10 x 0.02448 = 0.2448 <= 0.25
        self.assertLessEqual(BudgetLedger(self.path, cap).summary()["counted_usd"], 0.25)

    def test_no_retry_and_at_most_two_rounds_per_phase(self):
        self.reserve()
        with self.assertRaises(LedgerError) as e:
            self.reserve()
        self.assertEqual(e.exception.code, "no_retry")
        self.reserve(rnd=2)
        with self.assertRaises(LedgerError) as e:
            self.reserve(rnd=3)
        self.assertEqual(e.exception.code, "too_many_requests_for_case")
        self.reserve(rnd=1, phase="fix_check")               # the after-fix re-check is its own phase

    def test_at_most_thirty_cases(self):
        for n in range(30):
            self.reserve(model=ABLITERATED, case=f"c{n}")
        with self.assertRaises(LedgerError) as e:
            self.reserve(model=ABLITERATED, case="c30")
        self.assertEqual(e.exception.code, "too_many_cases")

    def test_a_failure_keeps_the_reservation_and_only_a_confirmed_bill_lowers_it(self):
        a, b, c = self.reserve(case="c1"), self.reserve(case="c2"), self.reserve(case="c3")
        self.ledger.settle(a["reservation_id"], outcome="timeout")                     # no refund
        self.ledger.settle(b["reservation_id"], outcome="ok", billed_usd=0.001)
        self.ledger.settle(c["reservation_id"], outcome="ok", billed_usd=99.0)        # not plausible: ignored
        self.assertAlmostEqual(self.ledger.summary()["counted_usd"], 0.02448 * 2 + 0.001, places=6)
        with self.assertRaises(LedgerError):
            self.ledger.settle(a["reservation_id"], outcome="ok", billed_usd=0.0)

    def test_unknown_prices_or_caps_fail_closed(self):
        for bad in (dataclasses.replace(CLAUDE_SONNET, price_in_per_m=0.0),
                    dataclasses.replace(CLAUDE_SONNET, price_out_per_m=float("nan")),
                    dataclasses.replace(CLAUDE_SONNET, max_output_tokens=0)):
            with self.assertRaises(LedgerError):
                self.reserve(model=bad)

    def test_a_damaged_ledger_refuses_everything(self):
        self.reserve()
        lines = self.path.read_text().splitlines()
        entry = json.loads(lines[0])
        entry["max_cost_usd"] = 0.0                          # someone lowers a reservation by hand
        self.path.write_text(json.dumps(entry) + "\n")
        for call in (self.reserve, self.ledger.summary):
            with self.assertRaises(LedgerError) as e:
                call()
            self.assertEqual(e.exception.code, "ledger_damaged")
        self.path.write_text(lines[0][:-5])                   # truncated
        with self.assertRaises(LedgerError):
            self.ledger.summary()

    def test_reserving_is_not_permission_to_send(self):
        r = self.reserve()
        approval = {"model": r["model"], "request_sha256": SHA, "max_input_tokens": 2000,
                    "max_output_tokens": 2048, "config_sha256": "c" * 64, "max_cost_usd": 0.03}
        with self.assertRaises(LedgerError) as e:             # the default ledger is a dry run
            self.ledger.authorize_send(r, approval=approval, config_sha256="c" * 64, request_sha256=SHA)
        self.assertEqual(e.exception.code, "dry_run")
        live = BudgetLedger(self.path, dry_run=False, external_calls_enabled=True)
        live.authorize_send(r, approval=approval, config_sha256="c" * 64, request_sha256=SHA)
        for change in ({"request_sha256": "b" * 64}, {"max_output_tokens": 4096}, {"config_sha256": "d" * 64},
                       {"max_cost_usd": 0.01}, {"model": "abliterated-model"}):
            with self.assertRaises(LedgerError, msg=change):
                live.authorize_send(r, approval={**approval, **change}, config_sha256="c" * 64,
                                    request_sha256=SHA)
        with self.assertRaises(LedgerError):                  # the body changed after the preview
            live.authorize_send(r, approval=approval, config_sha256="c" * 64, request_sha256="e" * 64)
        with self.assertRaises(LedgerError):
            live.authorize_send(r, approval=None, config_sha256="c" * 64, request_sha256=SHA)

    def test_a_restart_keeps_every_reservation_and_send(self):
        r = self.reserve()
        again = BudgetLedger(self.path)                     # a new process reading the same file
        self.assertEqual(again.summary()["counted_usd"], CLAUDE_SONNET.max_cost_usd())
        with self.assertRaises(LedgerError) as e:
            again.reserve(model=CLAUDE_SONNET, case_id="holdout-001", round_no=1, request_sha256=SHA)
        self.assertEqual(e.exception.code, "no_retry")
        approval = {"model": r["model"], "request_sha256": SHA, "max_input_tokens": 2000,
                    "max_output_tokens": 2048, "config_sha256": "c" * 64, "max_cost_usd": 0.03}
        live = BudgetLedger(self.path, dry_run=False, external_calls_enabled=True)
        live.authorize_send(r, approval=approval, config_sha256="c" * 64, request_sha256=SHA)
        restarted = BudgetLedger(self.path, dry_run=False, external_calls_enabled=True)
        with self.assertRaises(LedgerError) as e:           # the same request is never sent twice
            restarted.authorize_send(r, approval=approval, config_sha256="c" * 64, request_sha256=SHA)
        self.assertEqual(e.exception.code, "already_sent")

    def test_a_forged_or_settled_reservation_cannot_be_sent(self):
        r = self.reserve()
        approval = {"model": r["model"], "request_sha256": SHA, "max_input_tokens": 2000,
                    "max_output_tokens": 2048, "config_sha256": "c" * 64, "max_cost_usd": 0.03}
        live = BudgetLedger(self.path, dry_run=False, external_calls_enabled=True)
        forged = {**r, "max_cost_usd": 0.0}
        forged_hash = {**r, "hash": "f" * 64}
        for bad in (forged_hash, {**r, "reservation_id": "r99"}):
            with self.assertRaises(LedgerError):
                live.authorize_send(bad, approval=approval, config_sha256="c" * 64, request_sha256=SHA)
        self.assertEqual(forged["hash"], r["hash"])          # the hash binds the stored entry, not the copy
        self.ledger.settle(r["reservation_id"], outcome="timeout")
        with self.assertRaises(LedgerError) as e:
            live.authorize_send(r, approval=approval, config_sha256="c" * 64, request_sha256=SHA)
        self.assertEqual(e.exception.code, "already_settled")

    def test_concurrent_sends_of_one_reservation_send_once(self):
        r = self.reserve()
        approval = {"model": r["model"], "request_sha256": SHA, "max_input_tokens": 2000,
                    "max_output_tokens": 2048, "config_sha256": "c" * 64, "max_cost_usd": 0.03}
        results = []

        def go():
            try:
                BudgetLedger(self.path, dry_run=False, external_calls_enabled=True).authorize_send(
                    r, approval=approval, config_sha256="c" * 64, request_sha256=SHA)
                results.append("sent")
            except LedgerError as e:
                results.append(e.code)
        threads = [threading.Thread(target=go) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count("sent"), 1)
        self.assertEqual(results.count("already_sent"), 11)


if __name__ == "__main__":
    unittest.main()
