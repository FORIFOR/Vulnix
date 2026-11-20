"""A platform-wide spend cap shared by every organization (review of #85, finding 2)."""
import tests  # noqa: F401
import tempfile
import threading
import unittest
from pathlib import Path

from aegis.spend_cap import DurableSpendCap, SpendRefused


class TestDurableSpendCap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "platform-advisor-spend.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_reservations_stop_at_the_cap_and_survive_a_restart(self):
        cap = DurableSpendCap(self.path)
        cap.reserve(400, cap_micro_usd=1000)
        cap.reserve(600, cap_micro_usd=1000)
        with self.assertRaises(SpendRefused):
            cap.reserve(1, cap_micro_usd=1000)
        again = DurableSpendCap(self.path)
        self.assertEqual(again.spent(), 1000)
        with self.assertRaises(SpendRefused):
            again.reserve(1, cap_micro_usd=1000)

    def test_an_unreadable_record_refuses_instead_of_starting_over(self):
        DurableSpendCap(self.path).reserve(10, cap_micro_usd=1000)
        self.path.write_text("not json")
        with self.assertRaises(SpendRefused):
            DurableSpendCap(self.path).reserve(1, cap_micro_usd=1000)

    def test_bad_amounts_are_refused(self):
        cap = DurableSpendCap(self.path)
        for amount, limit in ((0, 10), (-1, 10), (1, 0), (True, 10), (1.5, 10)):
            with self.assertRaises(SpendRefused):
                cap.reserve(amount, cap_micro_usd=limit)

    def test_concurrent_reservations_never_overspend(self):
        caps = [DurableSpendCap(self.path) for _ in range(8)]   # one per organization
        ok = []

        def go(c):
            for _ in range(20):
                try:
                    c.reserve(10, cap_micro_usd=500)
                    ok.append(1)
                except SpendRefused:
                    pass
        threads = [threading.Thread(target=go, args=(c,)) for c in caps]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(ok), 50)
        self.assertEqual(DurableSpendCap(self.path).spent(), 500)


if __name__ == "__main__":
    unittest.main()
