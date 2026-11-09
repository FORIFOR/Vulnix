"""Operator store: password hashing, login, sessions, seed generation."""
import json
import tempfile
import unittest
from pathlib import Path

from aegis.operators import (AuthError, MFAChallenge, OperatorStore, generate_totp_secret,
                             hash_password, totp_code, verify_password, verify_totp)


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class TestPassword(unittest.TestCase):
    def test_hash_roundtrip_and_salt_unique(self):
        h1 = hash_password("secret")
        h2 = hash_password("secret")
        self.assertNotEqual(h1, h2)                    # random salt
        self.assertTrue(verify_password("secret", h1))
        self.assertFalse(verify_password("secret ", h1))
        self.assertFalse(verify_password("", h1))

    def test_verify_rejects_garbage(self):
        self.assertFalse(verify_password("x", "not-a-hash"))
        self.assertFalse(verify_password("x", "scrypt$bad"))


class TestTotp(unittest.TestCase):
    def test_code_matches_and_window(self):
        secret = generate_totp_secret()
        t = 1_700_000_000.0
        code = totp_code(secret, t)
        self.assertTrue(code.isdigit() and len(code) == 6)
        self.assertTrue(verify_totp(secret, code, t))
        self.assertTrue(verify_totp(secret, code, t + 25))        # same 30s step
        self.assertTrue(verify_totp(secret, totp_code(secret, t), t + 30))  # ±1 step window
        self.assertFalse(verify_totp(secret, code, t + 120))      # far outside window
        self.assertFalse(verify_totp(secret, "000000", t) and code != "000000")

    def test_rejects_non_numeric(self):
        secret = generate_totp_secret()
        self.assertFalse(verify_totp(secret, "abcdef"))
        self.assertFalse(verify_totp(secret, ""))


class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_first_run_generates_seed_and_credentials(self):
        store = OperatorStore(self.dir / "operators.json")
        self.assertTrue((self.dir / "operators.json").exists())
        self.assertTrue(store.credentials_path.exists())
        # No plaintext in the seed, only hashes.
        seed = json.loads((self.dir / "operators.json").read_text())
        for o in seed["operators"]:
            self.assertTrue(o["password_hash"].startswith("scrypt$"))
            self.assertNotIn("password", o)
        self.assertEqual(oct((self.dir / "operators.json").stat().st_mode)[-3:], "600")

    def test_generated_credentials_actually_log_in(self):
        path = self.dir / "operators.json"
        OperatorStore(path)
        creds = (self.dir / "operators.initial-credentials.txt").read_text()
        # Parse "ユーザー名: X" / "パスワード: Y" pairs and log in with each.
        store2 = OperatorStore(path)   # reload from seed (no regeneration)
        lines = [l.split(": ", 1)[1] for l in creds.splitlines() if ": " in l and
                 (l.startswith("ユーザー名") or l.startswith("パスワード"))]
        pairs = list(zip(lines[0::2], lines[1::2]))
        self.assertEqual(len(pairs), 2)
        for name, pw in pairs:
            self.assertEqual(store2.login(name, pw).operator, name)

    def test_login_and_session_expiry(self):
        path = self.dir / "operators.json"
        path.write_text(json.dumps({"operators": [
            {"name": "op", "display": "x", "roles": ["operator", "approver"],
             "password_hash": hash_password("pw")}]}))
        clock = Clock()
        store = OperatorStore(path, clock=clock)
        with self.assertRaises(AuthError):
            store.login("op", "bad")
        sess = store.login("op", "pw")
        self.assertEqual(store.resolve(sess.token).roles, ("operator", "approver"))
        clock.t += 13 * 3600                            # past TTL
        self.assertIsNone(store.resolve(sess.token))

    def test_logout(self):
        path = self.dir / "operators.json"
        path.write_text(json.dumps({"operators": [
            {"name": "op", "display": "x", "roles": ["operator"],
             "password_hash": hash_password("pw")}]}))
        store = OperatorStore(path)
        sess = store.login("op", "pw")
        store.logout(sess.token)
        self.assertIsNone(store.resolve(sess.token))

    def _seed(self, path):
        path.write_text(json.dumps({"operators": [
            {"name": "op", "display": "x", "roles": ["operator", "approver"],
             "password_hash": hash_password("pw")}]}))

    def test_session_survives_restart(self):
        path = self.dir / "operators.json"
        self._seed(path)
        clock = Clock()
        store = OperatorStore(path, clock=clock)
        sess = store.login("op", "pw")
        self.assertTrue((self.dir / "sessions.json").exists())
        self.assertEqual(oct((self.dir / "sessions.json").stat().st_mode)[-3:], "600")
        # A fresh store (simulating a restart) still resolves the session.
        store2 = OperatorStore(path, clock=clock)
        resolved = store2.resolve(sess.token)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved.operator, "op")
        self.assertEqual(resolved.roles, ("operator", "approver"))

    def test_logout_persists_across_restart(self):
        path = self.dir / "operators.json"
        self._seed(path)
        store = OperatorStore(path)
        sess = store.login("op", "pw")
        store.logout(sess.token)
        store2 = OperatorStore(path)
        self.assertIsNone(store2.resolve(sess.token))

    def test_expired_sessions_not_restored(self):
        path = self.dir / "operators.json"
        self._seed(path)
        clock = Clock()
        store = OperatorStore(path, clock=clock)
        sess = store.login("op", "pw")
        clock.t += 13 * 3600                       # past TTL before "restart"
        store2 = OperatorStore(path, clock=clock)
        self.assertIsNone(store2.resolve(sess.token))
        # The reload should have pruned it from the file, too.
        kept = json.loads((self.dir / "sessions.json").read_text())["sessions"]
        self.assertEqual(kept, [])

    def test_corrupt_session_file_is_tolerated(self):
        path = self.dir / "operators.json"
        self._seed(path)
        (self.dir / "sessions.json").write_text("{ not json")
        store = OperatorStore(path)            # must not raise
        self.assertEqual(store.login("op", "pw").operator, "op")

    def test_change_password_requires_current_and_persists(self):
        path = self.dir / "operators.json"
        self._seed(path)
        store = OperatorStore(path)
        with self.assertRaises(AuthError):
            store.change_password("op", "wrong", "a-good-new-pw")     # wrong current
        with self.assertRaises(AuthError):
            store.change_password("op", "pw", "short")                # too short
        with self.assertRaises(AuthError):
            store.change_password("op", "pw", "pw")                   # unchanged
        store.change_password("op", "pw", "a-good-new-pw")
        # Old password no longer works; new one does.
        with self.assertRaises(AuthError):
            store.login("op", "pw")
        self.assertEqual(store.login("op", "a-good-new-pw").operator, "op")
        # Change survives a restart (seed rewritten with the new hash, 0600).
        self.assertEqual(oct(path.stat().st_mode)[-3:], "600")
        store2 = OperatorStore(path)
        self.assertEqual(store2.login("op", "a-good-new-pw").operator, "op")

    def test_change_password_revokes_other_sessions(self):
        path = self.dir / "operators.json"
        self._seed(path)
        store = OperatorStore(path)
        keep = store.login("op", "pw")        # the session making the change
        other = store.login("op", "pw")       # a second device
        store.change_password("op", "pw", "a-good-new-pw", keep_token=keep.token)
        self.assertIsNotNone(store.resolve(keep.token))    # kept
        self.assertIsNone(store.resolve(other.token))      # revoked

    def test_totp_enroll_then_login_requires_code(self):
        path = self.dir / "operators.json"
        self._seed(path)
        clock = Clock(1_700_000_000.0)
        store = OperatorStore(path, clock=clock)
        self.assertFalse(store.totp_enabled("op"))
        # Login works with password alone before enrollment.
        self.assertEqual(store.login("op", "pw").operator, "op")
        secret, uri = store.begin_totp_enroll("op")
        self.assertTrue(uri.startswith("otpauth://totp/"))
        # Not active until confirmed; a wrong confirm code is rejected.
        self.assertFalse(store.totp_enabled("op"))
        with self.assertRaises(AuthError):
            store.confirm_totp("op", "000000")
        store.confirm_totp("op", totp_code(secret, clock.t))
        self.assertTrue(store.totp_enabled("op"))
        # Now password alone is refused; password + valid code succeeds.
        with self.assertRaises(MFAChallenge):
            store.login("op", "pw")
        with self.assertRaises(MFAChallenge):
            store.login("op", "pw", "000000")
        self.assertEqual(store.login("op", "pw", totp_code(secret, clock.t)).operator, "op")
        # Enrollment survives a restart (secret persisted in the 0600 seed).
        self.assertEqual(oct(path.stat().st_mode)[-3:], "600")
        store2 = OperatorStore(path, clock=clock)
        self.assertTrue(store2.totp_enabled("op"))

    def test_totp_disable_requires_password(self):
        path = self.dir / "operators.json"
        self._seed(path)
        clock = Clock(1_700_000_000.0)
        store = OperatorStore(path, clock=clock)
        secret, _ = store.begin_totp_enroll("op")
        store.confirm_totp("op", totp_code(secret, clock.t))
        with self.assertRaises(AuthError):
            store.disable_totp("op", "wrong-password")
        store.disable_totp("op", "pw")
        self.assertFalse(store.totp_enabled("op"))
        self.assertEqual(store.login("op", "pw").operator, "op")   # password alone again


if __name__ == "__main__":
    unittest.main()
