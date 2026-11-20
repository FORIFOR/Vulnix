"""Shared delivery leases and exclusive revocations (review of #85, finding 1)."""
import tests  # noqa: F401
import threading
import time
import unittest

from aegis.grant_lease import GrantLease


class TestGrantLease(unittest.TestCase):
    def test_deliveries_share_the_lease(self):
        lease, inside, release = GrantLease(), [], threading.Event()

        def deliver():
            with lease.shared():
                inside.append(1)
                release.wait(2)
        ts = [threading.Thread(target=deliver) for _ in range(5)]
        for t in ts:
            t.start()
        deadline = time.monotonic() + 2
        while len(inside) < 5 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(len(inside), 5, "slow deliveries must not wait for each other")
        release.set()
        for t in ts:
            t.join()

    def test_a_revocation_waits_for_inflight_deliveries_and_then_blocks_new_ones(self):
        lease = GrantLease()
        in_delivery, release, revoked, late = threading.Event(), threading.Event(), threading.Event(), []

        def deliver():
            with lease.shared():
                in_delivery.set()
                release.wait(2)

        def revoke():
            with lease.exclusive():
                revoked.set()
                time.sleep(0.1)

        def late_delivery():
            with lease.shared():
                late.append(revoked.is_set())
        d = threading.Thread(target=deliver)
        d.start()
        self.assertTrue(in_delivery.wait(2))
        r = threading.Thread(target=revoke)
        r.start()
        time.sleep(0.05)
        self.assertFalse(revoked.is_set(), "revocation finished during an in-flight delivery")
        l = threading.Thread(target=late_delivery)   # arrives while the revocation waits
        l.start()
        time.sleep(0.05)
        self.assertEqual(late, [], "a new delivery started ahead of a waiting revocation")
        release.set()
        for t in (d, r, l):
            t.join(2)
        self.assertEqual(late, [True])

    def test_a_thread_may_nest_shared_leases(self):
        lease = GrantLease()
        with lease.shared():
            with lease.shared():
                pass

    def test_revoking_while_holding_a_delivery_lease_fails_loudly(self):
        lease = GrantLease()
        with lease.shared():
            with self.assertRaises(RuntimeError):
                with lease.exclusive():
                    pass


if __name__ == "__main__":
    unittest.main()
