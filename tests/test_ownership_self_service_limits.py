"""Platform-wide limits on standing self-service ownership traffic."""
import os
import tempfile
import threading
import unittest
from pathlib import Path

from aegis import ownership_policy as op


class TestSelfServiceLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        os.chmod(self.dir, 0o700)
        self.now = 1_800_000_000.0

    def tearDown(self):
        self.tmp.cleanup()

    def use(self, account="alice", org="org_aaaaaaaaaaaa", origin="https://a.example/", method="dns_txt", at=None):
        op.consume_self_service(self.dir, account=account, org=org, origin=origin, method=method,
                                now=self.now if at is None else at)

    def test_account_hourly_and_daily_limits_span_organizations(self):
        limits = op.SELF_SERVICE_LIMITS
        orgs = [f"org_{i:012x}" for i in range(3)]
        for i in range(limits["account_hour"]):
            self.use(org=orgs[i % 3], origin="https://a.example/")
        with self.assertRaises(op.LimitReached):
            self.use(org=orgs[0])
        # an hour later the hourly window has room, but the day keeps counting
        used = limits["account_hour"]
        hour = 0
        while used < limits["account_day"]:
            hour += 1
            for _ in range(min(limits["account_hour"], limits["account_day"] - used)):
                self.use(origin=f"https://b{used % 3}.example/", at=self.now + hour * 3601)  # per-origin cap
                used += 1
        with self.assertRaises(op.LimitReached):
            self.use(at=self.now + (hour + 1) * 3601)
        self.use(account="bob", origin="https://bob.example/", at=self.now + (hour + 1) * 3601)  # others unaffected
        self.use(at=self.now + 86400 + 1)                              # rolling day, not UTC midnight

    def test_one_origin_is_capped_across_organizations_and_accounts(self):
        limits = op.SELF_SERVICE_LIMITS
        victim = "https://victim.example/"
        for i in range(limits["origin_orgs_day"]):
            self.use(account=f"u{i}", org=f"org_{i:012x}", origin=victim)
        with self.assertRaises(op.LimitReached):     # a new org cannot join this origin today
            self.use(account="sybil", org="org_ffffffffffff", origin=victim)
        n = limits["origin_orgs_day"]
        while n < limits["origin_day"]:              # orgs already on it share one attempt budget
            self.use(account=f"m{n}", org="org_000000000000", origin=victim)
            n += 1
        with self.assertRaises(op.LimitReached):
            self.use(account="late", org="org_000000000001", origin=victim)
        self.use(account="late", org="org_000000000001", origin="https://other.example/")
        self.use(account="sybil", org="org_ffffffffffff", origin=victim, at=self.now + 86401)

    def test_distinct_targets_per_org_and_account(self):
        limits = op.SELF_SERVICE_LIMITS
        for i in range(limits["org_origins_day"]):
            self.use(origin=f"https://t{i}.example/")
        with self.assertRaises(op.LimitReached):
            self.use(origin="https://new.example/")
        self.use(origin="https://t0.example/", method="well_known")   # a known target is not new
        for i in range(limits["account_origins_day"] - limits["org_origins_day"]):
            self.use(org="org_bbbbbbbbbbbb", origin=f"https://u{i}.example/", at=self.now + 3601)
        with self.assertRaises(op.LimitReached):
            self.use(org="org_cccccccccccc", origin="https://v.example/", at=self.now + 3601)

    def test_platform_daily_limit_and_restart(self):
        limits = op.SELF_SERVICE_LIMITS
        original = limits["platform_day"]
        limits["platform_day"] = 3
        try:
            for i in range(3):
                self.use(account=f"user{i}", org=f"org_{i:012x}")
            with self.assertRaises(op.LimitReached):
                self.use(account="user9", org="org_999999999999")
        finally:
            limits["platform_day"] = original

    def test_unsafe_or_unreadable_ledger_fails_closed(self):
        self.use()
        path = self.dir / "ownership-self-service.sqlite3"
        path.chmod(0o644)
        with self.assertRaises(op.LimitReached):
            self.use(account="bob")
        path.chmod(0o600)
        path.write_bytes(b"not a database")
        with self.assertRaises(op.LimitReached):
            self.use(account="bob")

    def test_parallel_attempts_do_not_exceed_the_limit(self):
        accepted, errors = [], []

        def worker():
            try:
                self.use()
                accepted.append(1)
            except op.LimitReached:
                errors.append(1)

        threads = [threading.Thread(target=worker) for _ in range(40)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(accepted), op.SELF_SERVICE_LIMITS["account_hour"])

    def test_concurrent_slots_per_account_and_platform(self):
        slots = op.SelfServiceSlots(per_account=1, total=2)
        with slots.hold("alice"):
            with self.assertRaises(op.LimitReached):
                with slots.hold("alice"):
                    pass
            with slots.hold("bob"):
                with self.assertRaises(op.LimitReached):
                    with slots.hold("carol"):
                        pass
        with slots.hold("alice"), slots.hold("carol"):
            pass


if __name__ == "__main__":
    unittest.main()
