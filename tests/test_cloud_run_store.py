"""Durable, atomic Cloud Run challenge behavior; no network access."""
import concurrent.futures
import tempfile
import unittest
from pathlib import Path

from aegis.cloud_run_store import SQLiteCloudRunStore


def _consume_in_process(args):
    path, challenge, version = args
    return SQLiteCloudRunStore(Path(path)).consume(
        challenge, "tenant-a", "app.example.com", "alice", version, 101) is not None


class TestCloudRunStore(unittest.TestCase):
    def test_restart_and_parallel_consumption(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "challenges.sqlite3"
            first = SQLiteCloudRunStore(path)
            version = first.register("tenant-a", "app.example.com", "sub-a", 100)
            first.issue("c" * 40, "tenant-a", "app.example.com", "alice", "audience", version, 100, 400)
            second = SQLiteCloudRunStore(path)

            def consume(store):
                return store.consume("c" * 40, "tenant-a", "app.example.com", "alice", version, 101)

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(consume, (first, second)))
            self.assertEqual(sum(x is not None for x in results), 1)
            self.assertIsNone(second.consume("c" * 40, "tenant-a", "app.example.com", "alice", version, 102))

    def test_separate_processes_consume_at_most_once(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "challenges.sqlite3"
            store = SQLiteCloudRunStore(path)
            version = store.register("tenant-a", "app.example.com", "sub-a", 100)
            store.issue("p" * 40, "tenant-a", "app.example.com", "alice", "audience", version, 100, 400)
            args = [(str(path), "p" * 40, version)] * 2
            with concurrent.futures.ProcessPoolExecutor(max_workers=2) as pool:
                self.assertEqual(sum(pool.map(_consume_in_process, args)), 1)

    def test_wrong_requester_does_not_consume_and_version_change_rejects(self):
        with tempfile.TemporaryDirectory() as root:
            store = SQLiteCloudRunStore(Path(root) / "challenges.sqlite3")
            version = store.register("tenant-a", "app.example.com", "sub-a", 100)
            store.issue("c" * 40, "tenant-a", "app.example.com", "alice", "audience", version, 100, 400)
            self.assertIsNone(store.consume("c" * 40, "tenant-a", "app.example.com", "bob", version, 101))
            self.assertIsNone(store.consume("c" * 40, "tenant-b", "app.example.com", "alice", version, 101))
            self.assertIsNotNone(store.consume("c" * 40, "tenant-a", "app.example.com", "alice", version, 101))
            store.issue("d" * 40, "tenant-a", "app.example.com", "alice", "audience", version, 102, 402)
            store.register("tenant-a", "app.example.com", "sub-a", 103)
            self.assertIsNone(store.consume("d" * 40, "tenant-a", "app.example.com", "alice", version, 104))

    def test_expiry_limit_and_revoke(self):
        with tempfile.TemporaryDirectory() as root:
            store = SQLiteCloudRunStore(Path(root) / "challenges.sqlite3", max_pending=1, max_issue_per_hour=2)
            version = store.register("tenant-a", "app.example.com", "sub-a", 100)
            store.issue("c" * 40, "tenant-a", "app.example.com", "alice", "audience", version, 100, 101)
            with self.assertRaises(ValueError):
                store.issue("d" * 40, "tenant-a", "app.example.com", "alice", "audience", version, 100, 400)
            store.issue("d" * 40, "tenant-a", "app.example.com", "alice", "audience", version, 102, 402)
            self.assertIsNone(store.consume("c" * 40, "tenant-a", "app.example.com", "alice", version, 103))
            store.revoke("tenant-a", "app.example.com")
            self.assertIsNone(store.consume("d" * 40, "tenant-a", "app.example.com", "alice", version, 103))

    def test_rate_limit_is_atomic_across_requesters(self):
        with tempfile.TemporaryDirectory() as root:
            store = SQLiteCloudRunStore(Path(root) / "challenges.sqlite3", max_pending=10,
                                        max_issue_per_hour=1, max_issue_per_tenant_hour=2)
            version = store.register("tenant-a", "app.example.com", "sub-a", 100)
            store.issue("a" * 40, "tenant-a", "app.example.com", "alice", "aud", version, 100, 400)
            with self.assertRaises(ValueError):
                store.issue("b" * 40, "tenant-a", "app.example.com", "alice", "aud", version, 101, 401)
            store.issue("b" * 40, "tenant-a", "app.example.com", "bob", "aud", version, 101, 401)
            with self.assertRaises(ValueError):
                store.issue("c" * 40, "tenant-a", "app.example.com", "carol", "aud", version, 102, 402)

    def test_invalid_subject_is_rejected_before_registration(self):
        with tempfile.TemporaryDirectory() as root:
            store = SQLiteCloudRunStore(Path(root) / "challenges.sqlite3")
            for subject in ("", "a b", "a\nb", "x" * 257):
                with self.subTest(subject=subject[:20]), self.assertRaises(ValueError):
                    store.register("tenant-a", "app.example.com", subject, 100)
            self.assertIsNone(store.binding("tenant-a", "app.example.com"))


if __name__ == "__main__":
    unittest.main()
