"""Attacker's-eye regression tests.

Each test plays one concrete attempt against a control and asserts that nothing
was gained AND that nothing reached the stand-in service. Loopback only: no
test here resolves or contacts a real host.
"""
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from aegis import operators as ops_mod
from tests import TEST_CONFINEMENT
from aegis.assessment import AssessmentService
from aegis.l2_rules import BUILTIN_PROFILE_DIR
from aegis.network import NetworkError
from aegis.operators import AuthError, LockedOut, OperatorStore, hash_password, session_key, totp_code
from tests.test_access_control import ApiBase, PUBLIC_1, PUBLIC_2, seed
from tests.test_real_service import (HOST, LAB_PORT, NOTE_B, PROFILE_DIRS, TOKEN_A, TOKEN_B, FakeService,
                                     RealServiceBase)


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


# --------------------------------------------------------------------------- sessions
class TestStolenSessionFile(ApiBase):
    def test_session_file_holds_no_usable_secret(self):
        cookie = self.session("appr")
        token = cookie.split("=", 1)[1]
        raw = (self.dir / "sessions.json").read_text()
        stored = json.loads(raw)
        self.assertNotIn(token, raw)
        self.assertEqual(stored["version"], 2)
        entry = stored["sessions"][0]
        self.assertEqual(set(entry), {"token_sha256", "operator", "created", "expires"})   # no token, no roles
        self.assertEqual(entry["token_sha256"], hashlib.sha256(token.encode()).hexdigest())
        self.assertEqual(oct((self.dir / "sessions.json").stat().st_mode & 0o777), "0o600")
        # someone who read the file tries what they found, as cookie and as bearer token
        for stolen in (entry["token_sha256"], session_key(entry["token_sha256"])):
            for headers in ({"Cookie": f"aegis_session={stolen}"}, {"Authorization": f"Bearer {stolen}"}):
                req = urllib.request.Request(self.api + "/assets", headers=headers)
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    urllib.request.urlopen(req)
                self.assertEqual(cm.exception.code, 401)
        self.assertEqual(self.call("/assets", who="appr")[0], 200)                # the real cookie still works
        self.assertNotIn(token, json.dumps([vars(s) for s in self.ops._sessions.values()]))

    def test_sessions_written_by_an_older_version_are_revoked_not_migrated(self):
        legacy_token = "legacy-plaintext-token-0123456789"
        (self.dir / "sessions.json").write_text(json.dumps({"sessions": [
            {"token": legacy_token, "operator": "root", "roles": ["operator", "admin"],
             "created": time.time(), "expires": time.time() + 3600}]}))
        store = OperatorStore(self.dir / "operators.json")
        self.assertEqual(store.legacy_sessions_revoked, 1)
        self.assertIsNone(store.resolve(legacy_token))
        self.assertNotIn(legacy_token, (self.dir / "sessions.json").read_text())   # scrubbed at load
        # a forged v2 entry cannot grant roles either: roles always come from the account
        forged = "attacker-chosen-token-0123456789"
        (self.dir / "sessions.json").write_text(json.dumps({"version": 2, "sessions": [
            {"token_sha256": session_key(forged), "operator": "op", "roles": ["operator", "admin", "approver"],
             "created": time.time(), "expires": time.time() + 3600}]}))
        store = OperatorStore(self.dir / "operators.json")
        self.assertEqual(store.resolve(forged).roles, ("operator",))

    def test_logout_and_password_change_kill_the_stored_sessions(self):
        first = self.ops.login("op", "op-password")
        second = self.ops.login("op", "op-password")
        self.ops.change_password("op", "op-password", "a-brand-new-password", keep_token=second.token)
        self.assertIsNone(self.ops.resolve(first.token))
        self.assertIsNotNone(self.ops.resolve(second.token))
        self.ops.logout(second.token)
        self.assertIsNone(OperatorStore(self.dir / "operators.json").resolve(second.token))


# --------------------------------------------------------------------------- sign-in throttling
class TestPasswordGuessing(ApiBase):
    def login(self, name, password, code=None):
        body = {"name": name, "password": password, **({"code": code} if code else {})}
        req = urllib.request.Request(self.api + "/auth/login", json.dumps(body).encode(),
                                     {"Content-Type": "application/json", "X-Aegis-Request": "1"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r), r.headers
        except urllib.error.HTTPError as e:
            return e.code, json.load(e), e.headers

    def test_guessing_locks_the_name_and_the_right_password_does_not_get_through(self):
        with patch("aegis.server.time.sleep"):
            for i in range(ops_mod.MAX_AUTH_FAILURES - 1):
                self.assertEqual(self.login("appr", f"guess-{i}")[0], 401)
            code, body, headers = self.login("appr", "guess-final")
            self.assertEqual((code, body["locked"]), (429, True))
            self.assertGreater(int(headers["Retry-After"]), 0)
            self.assertEqual(self.login("appr", "appr-password")[0], 429)          # even the right one
            # a name that does not exist behaves the same, so the lock reveals nothing
            for i in range(ops_mod.MAX_AUTH_FAILURES):
                last = self.login("no-such-user", f"guess-{i}")
            self.assertEqual(last[0], 429)
            self.assertEqual(self.login("op", "op-password")[0], 200)              # other accounts are unaffected
        self.assertEqual([e["name"] for e in self.events("auth.locked")], ["appr", "no-such-user"])
        self.assertGreaterEqual(len(self.events("auth.login_failed")), 4)
        self.assertNotIn("guess", json.dumps(self.svc.audit.entries()))             # attempted passwords are not logged

    def test_lock_expires_and_an_admin_can_lift_it_but_nobody_else(self):
        clock = Clock()
        store = OperatorStore(self.dir / "operators.json", clock=clock)
        for _ in range(ops_mod.MAX_AUTH_FAILURES - 1):
            with self.assertRaises(AuthError):
                store.login("appr", "wrong")
        with self.assertRaises(LockedOut) as cm:
            store.login("appr", "wrong")
        self.assertTrue(cm.exception.just_locked)
        with self.assertRaises(LockedOut):
            store.login("appr", "appr-password")
        for actor in ("op", "appr"):
            with self.assertRaises(AuthError):
                store.unlock("appr", actor=actor)
        self.assertIn("appr", store.locked_accounts())
        self.assertTrue(store.unlock("appr", actor="root"))                         # recovery by an admin
        self.assertEqual(store.login("appr", "appr-password").operator, "appr")
        # ...or simply by waiting
        for _ in range(ops_mod.MAX_AUTH_FAILURES):
            try:
                store.login("op", "wrong")
            except AuthError:
                pass
        clock.t += ops_mod.AUTH_LOCK_SECONDS + 1
        self.assertEqual(store.login("op", "op-password").operator, "op")
        # old failures fall out of the window instead of accumulating forever
        for _ in range(ops_mod.MAX_AUTH_FAILURES - 1):
            with self.assertRaises(AuthError):
                store.login("op2", "wrong")
        clock.t += ops_mod.AUTH_FAILURE_WINDOW + 1
        with self.assertRaises(AuthError) as cm:
            store.login("op2", "wrong")
        self.assertNotIsInstance(cm.exception, LockedOut)

    def test_second_factor_guessing_is_throttled_and_cannot_be_switched_off_with_the_password_alone(self):
        clock = Clock()
        store = OperatorStore(self.dir / "operators.json", clock=clock)
        secret, _ = store.begin_totp_enroll("appr")
        store.confirm_totp("appr", totp_code(secret, clock.t))
        with self.assertRaises(AuthError):                       # step 1 of a normal login is not a failure
            store.login("appr", "appr-password")
        used = totp_code(secret, clock.t)
        self.assertEqual(store.login("appr", "appr-password", used).operator, "appr")
        with self.assertRaises(AuthError):                       # a code seen once (shoulder-surfed, logged) is spent
            store.login("appr", "appr-password", used)
        store.unlock("appr", actor="root")
        clock.t += 60
        with self.assertRaises(AuthError):                       # stolen password, no device
            store.disable_totp("appr", "appr-password")
        store.unlock("appr", actor="root")
        locked = False
        for guess in range(ops_mod.MAX_AUTH_FAILURES + 1):
            try:
                store.login("appr", "appr-password", f"{guess:06d}")
            except LockedOut:
                locked = True
                break
            except AuthError:
                pass
        self.assertTrue(locked)
        clock.t += 60
        with self.assertRaises(LockedOut):
            store.login("appr", "appr-password", totp_code(secret, clock.t))
        # lost device: only another admin can reset it, and that signs the account out
        store.unlock("appr", actor="root")
        sess = store.login("appr", "appr-password", totp_code(secret, clock.t))
        for actor, target in (("appr", "appr"), ("op", "appr"), ("root", "root")):
            with self.assertRaises(AuthError):
                store.reset_totp(target, actor=actor)
        self.assertTrue(store.reset_totp("appr", actor="root"))
        self.assertIsNone(store.resolve(sess.token))
        self.assertEqual(store.login("appr", "appr-password").operator, "appr")

    def test_parallel_guesses_get_no_more_tries_than_sequential_ones(self):
        import threading
        store = OperatorStore(self.dir / "operators.json")
        evaluated, results = [], []
        real_verify = ops_mod.verify_password

        def counting_verify(password, encoded):
            evaluated.append(password)
            return real_verify(password, encoded)

        def attempt(pw):
            try:
                store.login("appr", pw)
                results.append("ok")
            except LockedOut:
                results.append("locked")
            except AuthError:
                results.append("wrong")
        with patch("aegis.operators.verify_password", side_effect=counting_verify):
            threads = [threading.Thread(target=attempt, args=(f"guess-{i}",)) for i in range(24)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertLessEqual(len(evaluated), ops_mod.MAX_AUTH_FAILURES)       # not 24
        self.assertNotIn("ok", results)
        with self.assertRaises(LockedOut):
            store.login("appr", "appr-password")

    def test_name_variants_neither_lock_the_real_account_nor_reset_its_counter(self):
        store = OperatorStore(self.dir / "operators.json")
        for variant in ("ROOT", " root", "root ", "Root", "root\t"):
            for _ in range(ops_mod.MAX_AUTH_FAILURES + 1):
                try:
                    store.login(variant, "whatever")
                except AuthError:
                    pass
        self.assertEqual(store.login("root", "root-password").operator, "root")   # the admin is not locked out
        # an attacker's own account with a look-alike name cannot wipe the target's failures
        store.create_account("Appr", "attacker-own-password", actor="root")
        for i in range(ops_mod.MAX_AUTH_FAILURES - 1):
            with self.assertRaises(AuthError):
                store.login("appr", f"guess-{i}")
            store.login("Appr", "attacker-own-password")
        with self.assertRaises(LockedOut):
            store.login("appr", "guess-final")

    def test_flooding_made_up_names_does_not_evict_a_real_accounts_counter(self):
        store = OperatorStore(self.dir / "operators.json")
        with patch("aegis.operators.verify_password", return_value=False), \
                patch("aegis.operators._MAX_TRACKED_NAMES", 50):
            for i in range(ops_mod.MAX_AUTH_FAILURES - 1):
                with self.assertRaises(AuthError):
                    store.login("appr", f"guess-{i}")
            for i in range(400):
                try:
                    store.login(f"made-up-{i}", "x")
                except AuthError:
                    pass
            self.assertLessEqual(len(store._auth_failures), 50)
            with self.assertRaises(LockedOut):
                store.login("appr", "guess-final")

    def test_unknown_and_known_names_cost_the_same_single_hash(self):
        store = OperatorStore(self.dir / "operators.json")
        calls = []
        real = ops_mod.hashlib.scrypt
        with patch("aegis.operators.hashlib.scrypt", side_effect=lambda *a, **k: calls.append(1) or real(*a, **k)):
            for name in ("appr", "no-such-user"):
                calls.clear()
                with self.assertRaises(AuthError):
                    store.login(name, "wrong")
                self.assertEqual(len(calls), 1, name)

    def test_the_machine_owner_can_unlock_with_a_file_but_a_writable_by_others_file_is_ignored(self):
        store = OperatorStore(self.dir / "operators.json")

        def lock(name):
            for _ in range(ops_mod.MAX_AUTH_FAILURES + 1):
                try:
                    store.login(name, "wrong")
                except AuthError:
                    pass
        lock("root")
        request = self.dir / "unlock.request"
        request.write_text("root\n")
        request.chmod(0o666)                                     # anyone could have written it
        with self.assertRaises(LockedOut):
            store.login("root", "root-password")
        self.assertFalse(request.exists())
        self.assertEqual(store.recovery_events[-1]["event"], "auth.unlock_file_rejected")
        request.write_text("root\n")
        request.chmod(0o600)
        self.assertEqual(store.login("root", "root-password").operator, "root")
        self.assertFalse(request.exists())                        # honoured once
        self.assertEqual(store.recovery_events[-1], {"event": "auth.unlocked_by_file", "name": "root", "was_locked": True})

    def test_recovery_endpoints_are_admin_only_and_audited(self):
        for path in ("/operators/unlock", "/operators/reset-mfa"):
            self.assertEqual(self.call(path, {"name": "op"})[0], 401)
            self.assertEqual(self.call(path, {"name": "op"}, "appr")[0], 403)
            self.assertEqual(self.call(path, {"name": "op"}, "root")[0], 200)
        self.assertEqual(len(self.events("operator.recovery_denied")), 2)
        self.assertEqual(self.events("operator.unlocked")[-1]["actor"], "root")
        self.assertEqual(self.events("operator.mfa_reset")[-1]["target"], "op")


# --------------------------------------------------------------------------- job routes
class TestVerificationJobsCannotBeTriggeredByALink(ApiBase):
    JOBS = ("/system/verify-controls", "/cve/real-software-verify")

    def post(self, path, headers):
        req = urllib.request.Request(self.api + path, b"{}", {"Content-Type": "application/json", **headers})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def test_get_never_starts_a_job_and_post_needs_csrf_header_origin_and_role(self):
        with patch("aegis.server.run_live_control_verification", return_value={"all_passed": True}) as job1, \
                patch("aegis.server.run_real_software_cve_comparison", return_value={"all_passed": True}) as job2:
            for path in self.JOBS:
                self.assertEqual(self.call(path)[0], 401)                               # anonymous GET
                for who in ("op", "appr", "root"):
                    self.assertEqual(self.call(path, who=who)[0], 405)                  # GET never starts it
                cookie = {"Cookie": self.session("appr")}
                self.assertEqual(self.post(path, cookie), 403)                          # no CSRF header (plain form / link)
                self.assertEqual(self.post(path, {**cookie, "X-Aegis-Request": "1",
                                                  "Origin": "https://evil.example"}), 403)
                self.assertEqual(self.post(path, {"X-Aegis-Request": "1"}), 401)        # no session
                self.assertEqual(self.call(path, {}, "op")[0], 403)                     # operator role is not enough
            job1.assert_not_called()
            job2.assert_not_called()
            for path, who in zip(self.JOBS, ("appr", "root")):
                self.assertEqual(self.call(path, {}, who)[0], 200)
            self.assertEqual((job1.call_count, job2.call_count), (1, 1))
        self.assertEqual(len(self.events("system.job_denied")), 2)
        self.assertEqual([(e["actor"], e["job"]) for e in self.events("system.job_started")],
                         [("appr", "/api/system/verify-controls"), ("root", "/api/cve/real-software-verify")])


# --------------------------------------------------------------------------- site profiles
class TestPlantedOrEditedProfile(RealServiceBase):
    """Someone who can drop or edit a file in the site profile directory tries to
    make a rule runnable against a verified host."""

    def site_profile(self, host=HOST):
        site = json.loads((BUILTIN_PROFILE_DIR / "sample_api.json").read_text(encoding="utf-8"))
        site["applies_to"]["hosts"] = [host]
        site["paths"]["resource_b_path"]["default"] = NOTE_B
        site["paths"]["resource_a_path"]["default"] = "/api/notes/a1"
        site["checks"][0].update(spec_status="confirmed", spec_evidence=["planted.py:1"])
        return site

    def write(self, site, mode=0o600, dir_mode=0o700):
        d = self.dir / "l2_profiles"
        d.mkdir(exist_ok=True)
        f = d / "sample_api.json"
        f.write_text(json.dumps(site), encoding="utf-8")
        f.chmod(mode)
        d.chmod(dir_mode)
        return f

    def start(self):
        self.svc.workers.kill_all()
        self.svc = AssessmentService(self.dir, LAB_PORT, l2_confinement=TEST_CONFINEMENT, verify_seconds=0.1)        # default (site) profile dirs
        self.svc._custom_resolver = lambda h: ["127.0.0.1"] if h == HOST else []
        return self.svc

    def events(self, name):
        return [e["fields"] for e in self.svc.audit.entries() if e["event"] == name]

    def test_a_planted_profile_runs_nothing_until_an_admin_accepts_that_exact_content(self):
        self.write(self.site_profile())
        svc = self.start()
        self.onboard()
        self.run_l1()
        self.assertEqual(svc.l2.runnable_check_ids(), ())
        loaded = self.events("l2.profiles_loaded")[-1]["profiles"][0]
        self.assertEqual((loaded["id"], loaded["site"], loaded["accepted"]), ("sample_api", True, False))
        with self.assertRaises(ValueError):                      # its tokens cannot even be stored
            svc.configure_asset_secrets(host=HOST, tokens={"user_a_token": TOKEN_A, "user_b_token": TOKEN_B},
                                        actor="appr")
        f = self.finding("f_sample_idor")
        self.assertEqual((f["l2_ready"], f["l2_spec_status"]), (False, "unaccepted"))
        with self.assertRaises(ValueError):
            svc.verify_finding("f_sample_idor", actor="appr")
        apr = svc.approval_store.approve("appr", "eng_demo", "lab", "safe_reproduction")
        self.assertEqual(svc._exec("reproduction_probe", "safe_reproduction",
                                   {"url": svc.a.target_url, "check": "sample_idor"}, approval_id=apr),
                         (None, None))                           # not in the Gateway schema either
        self.assertEqual({p for p, _ in self.fake.seen}, {"/"})

    def test_editing_an_accepted_profile_puts_it_back_on_hold(self):
        f = self.write(self.site_profile())
        svc = self.start()
        sha = svc.l2_profiles_status()["profiles"][0]["sha256"]
        svc.accept_l2_profile("sample_api", sha, "root")
        self.assertEqual(svc.l2.runnable_check_ids(), ("sample_idor",))
        self.assertEqual(self.events("l2.profile_accepted")[-1]["sha256"], sha)
        # acceptance survives a restart only for the same bytes
        self.assertEqual(self.start().l2.runnable_check_ids(), ("sample_idor",))
        edited = self.site_profile()
        edited["paths"]["resource_b_path"]["default"] = "/api/admin/export-everything"
        f.write_text(json.dumps(edited), encoding="utf-8")
        svc = self.start()
        self.assertEqual(svc.l2.runnable_check_ids(), ())
        changed = self.events("l2.profile_changed")[-1]
        self.assertEqual((changed["profile"], changed["accepted_sha256"]), ("sample_api", sha))
        status = svc.l2_profiles_status()["profiles"][0]
        self.assertTrue(status["changed_since_acceptance"])
        with self.assertRaises(ValueError):                      # the old approval does not cover the new bytes
            svc.accept_l2_profile("sample_api", sha, "root")
        # swapping the file between "show" and "accept" does not get the swapped content accepted
        shown = status["sha256"]
        f.write_text(json.dumps(self.site_profile()).replace("planted.py:1", "other.py:2"), encoding="utf-8")
        with self.assertRaises(ValueError):
            svc.accept_l2_profile("sample_api", shown, "root")
        self.assertEqual(svc.l2.runnable_check_ids(), ())

    def test_unsafe_file_permissions_symlinks_and_bad_content_are_not_loaded(self):
        good = self.site_profile()
        cases = {
            "world-writable file": lambda: self.write(good, mode=0o666),
            "group-writable file": lambda: self.write(good, mode=0o660),
            "world-writable directory": lambda: self.write(good, dir_mode=0o777),
        }
        for name, make in cases.items():
            with self.subTest(case=name):
                make()
                svc = self.start()
                self.assertEqual(svc.l2_profiles_status()["rejected"][0]["file"], "sample_api.json")
                self.assertEqual(svc.l2.profiles["sample_api"]["hosts"], [])          # bundled template, not the site file
                self.assertTrue(self.events("l2.profile_rejected"))
        # symlink pointing at an attacker-controlled file elsewhere
        f = self.write(good)
        elsewhere = self.dir / "elsewhere.json"
        elsewhere.write_text(json.dumps(good), encoding="utf-8")
        f.unlink()
        os.symlink(elsewhere, f)
        self.assertIn("regular file", self.start().l2_profiles_status()["rejected"][0]["reason"])
        f.unlink()
        # invalid content: startup still succeeds, the file is simply not used
        bad = self.site_profile()
        bad["checks"][0]["denied"]["status"] = [401]
        self.write(bad)
        svc = self.start()
        self.assertEqual(len(svc.l2_profiles_status()["rejected"]), 1)
        self.assertEqual(svc.l2.runnable_check_ids(), ())

    def test_an_acceptance_that_cannot_be_committed_is_not_an_acceptance(self):
        self.write(self.site_profile())
        svc = self.start()
        sha = svc.l2_profiles_status()["profiles"][0]["sha256"]
        svc._save_state_locked()
        real = os.replace

        def ledger_fails(src, dst):
            if str(dst).endswith("authority.ledger"):
                raise OSError("disk full")
            return real(src, dst)
        with patch("aegis.authority_ledger.os.replace", side_effect=ledger_fails):
            with self.assertRaises(ValueError):
                svc.accept_l2_profile("sample_api", sha, actor="root")
        self.assertEqual(svc._accepted_profiles, {})
        self.assertEqual(svc.l2.runnable_check_ids(), ())
        self.assertGreater((self.dir / "authority.epoch").stat().st_size, 0)     # nothing else was invalidated
        self.assertEqual(self.start()._accepted_profiles, {})

    def test_acceptance_cannot_be_written_into_the_state_file(self):
        self.write(self.site_profile())
        svc = self.start()
        sha = svc.l2_profiles_status()["profiles"][0]["sha256"]
        svc._save_state_locked()
        state = json.loads((self.dir / "state.json").read_text())
        state["accepted_profiles"] = {"sample_api": sha}
        (self.dir / "state.json").write_text(json.dumps(state))
        svc = self.start()
        self.assertEqual(svc._accepted_profiles, {})                # state.json is not where authority is read from
        self.assertEqual(svc.l2.runnable_check_ids(), ())
        self.assertTrue(self.events("state.authority_fields_ignored"))
        # and written into the ledger itself, it does not verify
        ledger = json.loads((self.dir / "authority.ledger").read_text())
        ledger["tables"]["accepted_profiles"] = {"sample_api": sha}
        (self.dir / "authority.ledger").write_text(json.dumps(ledger))
        svc = self.start()
        self.assertEqual(svc._accepted_profiles, {})
        self.assertEqual(svc.l2.runnable_check_ids(), ())
        self.assertTrue(self.events("state.authority_rejected"))


class TestProfileAcceptanceApi(ApiBase):
    def test_only_an_admin_accepts_and_listing_needs_a_role(self):
        self.assertEqual(self.call("/l2-profiles")[0], 401)
        self.assertEqual(self.call("/l2-profiles", who="op")[0], 403)
        self.assertEqual(self.call("/l2-profiles", who="appr")[0], 200)
        for who in ("op", "appr"):
            self.assertEqual(self.call("/l2-profiles/accept", {"id": "example", "sha256": "0" * 64}, who)[0], 403)
        self.assertEqual(len(self.events("l2.profile_accept_denied")), 2)
        # profiles passed in by code (like the bundled ones) are not "site" profiles: nothing to accept
        self.assertEqual(self.call("/l2-profiles/accept", {"id": "example", "sha256": "0" * 64}, "root")[0], 409)


# --------------------------------------------------------------------------- existing controls
class TestOwnershipFromTheOutside(RealServiceBase):
    def test_a_proof_for_one_name_does_not_cover_a_sibling_parent_or_lookalike(self):
        ch = self.svc.issue_ownership_challenge(url=self.url, approver="appr")["challenge"]
        others = (f"https://admin.{HOST}", "https://example.test", f"https://{HOST}.attacker.example.org",
                  "https://svc-example.test")
        for other in others:
            with self.subTest(other=other):
                other_ch = self.svc.issue_ownership_challenge(url=other, approver="appr")["challenge"]
                self.assertNotEqual(other_ch["token"], ch["token"])
                # the attacker publishes the token they legitimately hold for THEIR name
                res = self.svc.verify_asset_ownership(url_or_host=other, dns_lookup=lambda n: [ch["dns_txt_value"]])
                self.assertFalse(res["verified"])
        # the same name written differently is the same asset, not a second authority
        for alias in (self.url.upper().replace("HTTP://", "http://"), f"http://{HOST}.:{self.fake.server_port}"):
            self.assertEqual(self.svc.issue_ownership_challenge(url=alias, approver="appr")["challenge"]["token"],
                             ch["token"])
        self.assertEqual([a["name"] for a in self.svc.assets()].count(HOST), 1)
        self.assertEqual(self.fake.seen, [])

    def test_verification_result_cannot_be_replayed_for_scope_after_the_record_is_removed(self):
        ch = self.svc.issue_ownership_challenge(url=self.url, approver="appr")["challenge"]
        self.svc.verify_asset_ownership(url_or_host=self.url, dns_lookup=self._token_lookup(ch))
        self.svc.verify_asset_ownership(url_or_host=self.url, dns_lookup=lambda n: [])      # record removed
        with self.assertRaises(ValueError):
            self.svc.confirm_asset_scope(url_or_host=self.url, approver="appr", activate_workspace=True)
        self.assertEqual(self.fake.seen, [])


class TestScopeFromTheInside(RealServiceBase):
    """An approved operator (or a compromised planner) asks the Gateway for more
    than the confirmed host and port."""

    def setUp(self):
        super().setUp()
        self.onboard()
        self.other = FakeService()                                # a different service on the same machine
        import threading
        threading.Thread(target=self.other.serve_forever, daemon=True).start()

    def tearDown(self):
        self.other.shutdown()
        self.other.server_close()
        super().tearDown()

    def test_gateway_refuses_everything_but_the_confirmed_host_and_port(self):
        port, other = self.fake.server_port, self.other.server_port
        attempts = (
            f"http://{HOST}:{other}/",                             # same host, another port
            f"http://127.0.0.1:{port}/",                           # the address instead of the name
            f"http://127.0.0.1:{other}/",
            f"http://localhost:{other}/",
            f"http://{HOST}@127.0.0.1:{other}/",                   # userinfo trick
            f"http://{HOST}:{port}@127.0.0.1:{other}/",
            f"http://lab.test:{LAB_PORT}/",                        # the lab is not in a real service's scope
            f"http://other.example.test:{port}/",
            f"https://{HOST}:{port}/",                             # another scheme
            "http://169.254.169.254/latest/meta-data/",
            f"http://[::1]:{other}/",
        )
        for url in attempts:
            with self.subTest(url=url):
                res, ev = self.svc._exec("http_probe", "read_only_probe", {"url": url, "method": "GET"},
                                         approval_actor="verify:appr")
                self.assertEqual((res, ev), (None, None))
        self.assertEqual(self.other.seen, [])
        self.assertEqual(self.fake.seen, [])
        # the confirmed URL itself does work, so the refusals above are about scope
        res, _ = self.svc._exec("http_probe", "read_only_probe",
                                {"url": f"http://{HOST}:{port}/", "method": "GET"}, approval_actor="verify:appr")
        self.assertEqual(res["status"], 200)
        self.assertEqual(self.other.seen, [])

    def test_only_get_and_head_and_no_arbitrary_tools(self):
        url = f"http://{HOST}:{self.fake.server_port}/"
        for args, tool, action in (({"url": url, "method": "POST"}, "http_probe", "read_only_probe"),
                                   ({"url": url, "method": "DELETE"}, "http_probe", "read_only_probe"),
                                   ({"url": url}, "shell", "read_only_probe"),
                                   ({"url": url, "check": "ex_idor_notes", "extra": "--rule-json={}"},
                                    "reproduction_probe", "safe_reproduction")):
            with self.subTest(args=args, tool=tool):
                self.assertEqual(self.svc._exec(tool, action, args, approval_actor="verify:appr"), (None, None))
        self.assertEqual(self.fake.seen, [])


class TestL2ApprovalFromTheInside(ApiBase):
    def setUp(self):
        super().setUp()
        self.onboard()
        self.run_l1()
        self.set_secrets()
        self.fake.seen.clear()
        self.base = f"/assessments/{self.svc.a.id}"

    def test_an_approver_whose_role_is_revoked_mid_session_cannot_run_or_configure(self):
        self.session("appr")
        self.call("/operators/roles", {"name": "appr", "roles": ["operator"]}, "root")
        self.assertEqual(self.call(self.base + "/verify-finding", {"finding_id": "f_ex_idor"}, "appr")[0], 403)
        self.assertEqual(self.call(self.base + "/verify-fix", {}, "appr")[0], 403)
        self.assertEqual(self.call("/assets/secrets", {"host": HOST, "tokens": {"user_a_token": TOKEN_B + "x"}},
                                   "appr")[0], 403)
        self.assertEqual(self.call("/assets/delete", {"id": self.svc.a.asset["id"]}, "appr")[0], 403)
        self.assertEqual(self.fake.seen, [])

    def test_an_approval_is_good_for_one_run_and_not_for_another_action(self):
        self.assertEqual(self.call(self.base + "/verify-finding", {"finding_id": "f_ex_idor"}, "appr2")[0], 200)
        from aegis.authz import AuthzError
        self.assertEqual(self.svc.approval_store._approvals, {})         # nothing left to reuse
        apr = self.svc.approval_store.approve("appr2", "eng_demo", "lab", "read_only_probe")
        self.fake.seen.clear()
        # an approval for the read-only action cannot be spent on a token-bearing L2 run
        self.assertEqual(self.svc._exec("reproduction_probe", "safe_reproduction",
                                        {"url": self.svc.a.target_url, "check": "ex_idor_notes"},
                                        approval_id=apr), (None, None))
        with self.assertRaises(AuthzError):
            self.svc.approval_store.check("apr_does_not_exist", "eng_demo", "lab", "safe_reproduction")
        self.assertEqual(self.fake.seen, [])

    def test_tokens_never_leave_through_any_read_api_even_for_an_admin(self):
        self.call(self.base + "/verify-finding", {"finding_id": "f_ex_idor"}, "appr2")
        blobs = [json.dumps(self.call(path, who="root")[1], ensure_ascii=False) for path in (
            self.base, self.base + "/logs", self.base + "/report", self.base + "/remotion?anonymize=0",
            "/assets", f"/assets/secrets-status?host={HOST}", "/operators", "/l2-profiles")]
        for name in ("state.json", "audit.jsonl", "sessions.json", "operators.json", "secrets.enc.json"):
            blobs.append((self.dir / name).read_text())
        for blob in blobs:
            for tok in (TOKEN_A, TOKEN_B):
                self.assertNotIn(tok, blob)

    def test_failed_reverification_takes_the_stored_accounts_with_it(self):
        self.assertTrue(self.svc.secrets.has_any_token(HOST))
        self.svc.verify_asset_ownership(url_or_host=self.url, dns_lookup=lambda n: [])
        self.assertFalse(self.svc.secrets.has_any_token(HOST))
        self.assertEqual(self.call(self.base + "/verify-finding", {"finding_id": "f_ex_idor"}, "appr2")[0], 409)
        self.assertEqual(self.fake.seen, [])


class TestDnsGamesAfterVerification(RealServiceBase):
    def onboard_public(self):
        ch = self.svc.issue_ownership_challenge(url=f"https://{HOST}", approver="appr")["challenge"]
        self.txt = [ch["dns_txt_value"]]
        self.svc._proof_dns_lookup = lambda name: list(self.txt)
        self.svc.verify_asset_ownership(url_or_host=HOST, method="dns_txt", dns_lookup=lambda n: list(self.txt))
        self.svc.confirm_asset_scope(url_or_host=HOST, approver="appr", activate_workspace=True)

    def test_an_answer_that_flips_to_an_internal_address_never_reaches_a_worker(self):
        self.onboard_public()
        answers = iter([[PUBLIC_1], ["127.0.0.1"], [PUBLIC_1, "10.0.0.7"], ["169.254.169.254"], ["::1"],
                        ["0.0.0.0"], ["not-an-ip"], []])
        self.svc._custom_resolver = lambda h: next(answers)
        self.assertEqual(self.svc._resolve_host(HOST), [PUBLIC_1])          # the first, honest answer
        with patch.object(self.svc.workers, "run") as run:
            for _ in range(7):                                              # every later answer is refused
                res, ev = self.svc._exec("http_probe", "read_only_probe",
                                         {"url": f"https://{HOST}/", "method": "GET"}, approval_actor="verify:appr")
                self.assertEqual((res, ev), (None, None))
            run.assert_not_called()                                          # no worker was even started
        self.assertEqual(self.fake.seen, [])

    def test_the_worker_is_pinned_to_the_checked_address_not_given_the_name_to_resolve(self):
        self.onboard_public()
        self.svc._custom_resolver = lambda h: [PUBLIC_2]
        captured = {}

        def fake_run(argv, timeout, **kw):
            captured["argv"] = argv
            raise RuntimeError("stop before any connection")
        with patch.object(self.svc.workers, "run", side_effect=fake_run):
            try:
                self.svc._exec("http_probe", "read_only_probe", {"url": f"https://{HOST}/", "method": "GET"},
                               approval_actor="verify:appr")
            except RuntimeError:
                pass
        argv = captured["argv"]
        self.assertIn(f"{PUBLIC_2}/443", argv)                               # egress sentinel allow-list: that address only
        self.assertIn(PUBLIC_2, argv)                                        # and the worker is told the address
        self.assertEqual(self.fake.seen, [])

    def test_a_scope_that_ended_cannot_be_used_by_any_entry_point(self):
        self.onboard_public()
        self.svc._custom_resolver = lambda h: [PUBLIC_1]
        self.svc._verified_external_hosts[HOST]["not_after"] = time.time() - 1
        with patch.object(self.svc.workers, "run") as run:
            for call in (self.svc.start, lambda: self.svc.verify_finding("all", actor="appr"),
                         lambda: self.svc.verify_fix("appr"),
                         lambda: self.svc.select_asset("lab") or self.svc.select_asset(self.svc._extra_assets[0]["id"])):
                try:
                    call()
                except (ValueError, NetworkError):
                    pass
            self.assertEqual(self.svc._resolve_host(HOST), [])
            run.assert_not_called()


# --------------------------------------------------------------------------- third review
class TestThirdReviewFindingsStayFixed(ApiBase):
    def setUp(self):
        super().setUp()
        self.onboard()
        self.run_l1()
        self.set_secrets()
        self.fake.seen.clear()
        self.base = f"/assessments/{self.svc.a.id}"

    def raw(self, method, path, headers=None, body=b""):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.server_port, timeout=5)
        conn.request(method, "/api" + path, body=body or None, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        return conn, resp, data

    def test_an_operator_cannot_revoke_scope_and_tokens_by_re_running_verification(self):
        with patch("aegis.ownership.default_well_known_fetcher", side_effect=OSError("no file")), \
                patch("aegis.ownership.default_dns_txt_lookup", return_value=[]):
            for method in ("well_known", "dns_txt"):
                self.assertEqual(self.call("/assets/verify-ownership", {"url": self.url, "method": method}, "op")[0], 403)
        self.assertTrue(self.svc._is_external_service_asset(HOST))
        self.assertTrue(self.svc.secrets.has_any_token(HOST))

    def test_requests_addressed_by_another_host_name_are_refused(self):
        port = self.srv.server_port
        for host in ("attacker.example.org", f"attacker.example.org:{port}", f"192.168.1.20:{port}",
                     f"127.0.0.1:{port + 1}", ""):
            with self.subTest(host=host):
                conn, resp, _ = self.raw("GET", "/auth/me", {"Host": host})
                self.assertEqual(resp.status, 421)
                conn.close()
                conn, resp, _ = self.raw("POST", "/auth/login", {"Host": host, "X-Aegis-Request": "1",
                                                                 "Content-Type": "application/json"},
                                         b'{"name": "appr", "password": "x"}')
                self.assertEqual(resp.status, 421)
                conn.close()
        self.assertEqual(self.events("auth.login_failed"), [])
        for host in (f"127.0.0.1:{port}", f"localhost:{port}"):
            conn, resp, _ = self.raw("GET", "/health", {"Host": host})
            self.assertEqual(resp.status, 200)
            conn.close()

    def test_a_rejected_post_does_not_leave_its_body_to_be_read_as_the_next_request(self):
        import socket
        smuggled = (b"POST /api/auth/login HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Aegis-Request: 1\r\n"
                    b"Content-Type: application/json\r\nContent-Length: 34\r\n\r\n"
                    b'{"name": "appr", "password": "x"}\n' % self.srv.server_port)
        outer = (b"POST /api/auth/login HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nOrigin: https://evil.example\r\n"
                 b"Content-Type: text/plain\r\nContent-Length: %d\r\n\r\n" % (self.srv.server_port, len(smuggled)))
        with socket.create_connection(("127.0.0.1", self.srv.server_port), timeout=5) as sock:
            sock.sendall(outer + smuggled)
            sock.settimeout(2)
            data = b""
            try:
                while chunk := sock.recv(4096):
                    data += chunk
            except socket.timeout:
                pass
        self.assertEqual(data.count(b"HTTP/1.1 "), 1)              # one response, then the socket is closed
        self.assertIn(b" 403 ", data.split(b"\r\n", 1)[0])
        self.assertEqual(self.events("auth.login_failed"), [])     # the smuggled login never ran

    def test_lab_attack_probes_never_reach_a_real_service_even_if_the_target_switches_mid_run(self):
        apr = self.svc.approval_store.approve("appr", "eng_demo", "lab", "safe_reproduction")
        for check in ("idor", "sqli", "cve_2021_41773"):
            self.assertEqual(self.svc._exec("reproduction_probe", "safe_reproduction",
                                            {"url": self.svc.a.target_url, "check": check}, approval_id=apr),
                             (None, None))
        self.assertEqual(self.fake.seen, [])
        # and the active asset cannot be switched or deleted while a verification is in flight
        self.svc._begin_operation()
        try:
            for call in (lambda: self.svc.select_asset("lab"), lambda: self.svc.delete_asset(self.svc.a.asset["id"]),
                         lambda: self.svc.issue_ownership_challenge(url=f"http://{HOST}:1", approver="appr")):
                with self.assertRaises(ValueError):
                    call()
        finally:
            self.svc._end_operation()
        self.svc.select_asset("lab")                               # fine once nothing is running

    def test_scope_uses_the_endpoint_in_the_signed_proof_not_the_editable_record(self):
        other = f"http://other-{HOST}:{self.fake.server_port}"
        self.svc._custom_resolver = lambda h: ["127.0.0.1"]
        ch = self.svc.issue_ownership_challenge(url=other, approver="appr")["challenge"]
        self.svc.verify_asset_ownership(url_or_host=other, dns_lookup=lambda n: [ch["dns_txt_value"]])
        rec = next(x for x in self.svc._extra_assets if x["name"] == f"other-{HOST}")
        rec["port"], rec["scheme"] = 22, "https"                    # e.g. edited in state.json before a restart
        self.svc.confirm_asset_scope(url_or_host=other, approver="appr")
        entry = self.svc._verified_external_hosts[f"other-{HOST}"]
        self.assertEqual((entry["scheme"], entry["port"]), ("http", self.fake.server_port))

    def test_a_failed_save_stops_real_service_work_and_is_reported(self):
        with patch("aegis.assessment.os.replace", side_effect=OSError("disk full")):
            self.svc._save_state_locked()
        self.assertEqual(self.svc._persist_error, "OSError")
        self.assertTrue(self.events("state.persist_failed"))
        self.assertEqual(self.svc.snapshot()["persistence_error"], "OSError")
        with patch("aegis.assessment.os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(ValueError):
                self.svc.verify_finding("f_ex_idor", actor="appr")
        self.assertEqual(self.fake.seen, [])
        self.svc.verify_finding("f_ex_idor", actor="appr")          # saving works again -> allowed again
        self.assertTrue(self.fake.seen)

    def test_role_revocation_that_could_not_be_saved_is_not_reported_as_done(self):
        self.session("root")                     # signed in while saving still works
        with patch.object(self.ops, "_atomic_write", return_value=False):
            code, body = self.call("/operators/roles", {"name": "appr", "roles": ["operator"]}, "root")
        self.assertEqual(code, 409)
        self.assertIn("保存に失敗", body["error"])

    def test_private_test_ca_is_not_handed_to_workers_for_a_real_service(self):
        with patch.dict("os.environ", {"VULNIX_TEST_CA_FILE": "/tmp/test-ca.pem", "AEGIS_ENV": ""}):
            self.assertIn("VULNIX_TEST_CA_FILE", self.svc._ephemeral_worker_env("http_probe", {}))   # loopback test target
            self.svc._verified_external_hosts[HOST]["allow_loopback_test"] = False
            self.assertNotIn("VULNIX_TEST_CA_FILE", self.svc._ephemeral_worker_env("http_probe", {}))

    def test_remaining_operator_routes_that_start_work_need_more_than_operator(self):
        for path in ("/router/verify", "/cve/sync"):
            self.assertEqual(self.call(path, {}, "op")[0], 403)
        self.assertEqual(len(self.events("system.job_denied")), 2)


class TestOneProcessPerDataDir(RealServiceBase):
    def test_a_second_process_cannot_open_the_same_data_directory(self):
        import subprocess
        import sys
        code = ("import sys; sys.path.insert(0, %r)\n"
                "from pathlib import Path\n"
                "from aegis.assessment import AssessmentService\n"
                "try:\n    AssessmentService(Path(%r), 18097)\n    print('OPENED')\n"
                "except RuntimeError as e:\n    print('REFUSED')\n") % (str(Path(__file__).parent.parent), str(self.dir))
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
        self.assertIn("REFUSED", out.stdout, out.stderr[-400:])


class TestAddressMoveNeedsANewProof(TestDnsGamesAfterVerification):
    def test_reconfirming_after_a_move_requires_verification_made_after_the_move(self):
        self.onboard_public()
        self.svc._custom_resolver = lambda h: [PUBLIC_1]
        self.svc._resolve_host(HOST)
        self.svc._custom_resolver = lambda h: [PUBLIC_2]
        self.svc._resolve_host(HOST)                               # TXT still there -> L1 may follow, L2 on hold
        self.assertIsNotNone(self.svc._l2_block_reason())
        with self.assertRaises(ValueError):                        # the proof from before the move is gone
            self.svc.confirm_asset_scope(url_or_host=HOST, approver="appr", activate_workspace=True)
        self.svc.verify_asset_ownership(url_or_host=HOST, method="dns_txt", dns_lookup=lambda n: list(self.txt))
        self.svc.confirm_asset_scope(url_or_host=HOST, approver="appr", activate_workspace=True)
        self.svc._resolve_host(HOST)
        self.assertIsNone(self.svc._l2_block_reason())


class TestCollidingSiteProfiles(TestPlantedOrEditedProfile):
    def test_one_bad_site_profile_does_not_disable_an_accepted_one(self):
        self.write(self.site_profile())
        svc = self.start()
        svc.accept_l2_profile("sample_api", svc.l2_profiles_status()["profiles"][0]["sha256"], "root")
        clash = self.site_profile()
        clash["id"] = "zz_clash"                                  # same host, same check ids -> collides
        f = self.dir / "l2_profiles" / "zz_clash.json"
        f.write_text(json.dumps(clash), encoding="utf-8")
        f.chmod(0o600)
        svc = self.start()
        self.assertEqual(svc.l2.runnable_check_ids(), ("sample_idor",))     # the accepted one still runs
        self.assertEqual([r["file"] for r in svc.l2_profiles_status()["rejected"]], ["zz_clash.json"])
        shown = svc.l2_profiles_status()["profiles"][0]
        self.assertEqual(shown["rules"][0]["request"]["path"], NOTE_B)             # the admin is shown what would be sent
        self.assertTrue(shown["directory"].endswith("l2_profiles"))
