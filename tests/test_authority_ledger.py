"""The authority ledger and what is synchronised with it.

* one commit point: after a crash at ANY durable step, a restart finds the state
  before the transaction or the state after it - never a mixture, never authority
  for an asset that no longer exists;
* a grant that cannot be committed is rolled back; a reduction that cannot be
  committed makes the stale copy unacceptable;
* withdrawing authority (revocation, deletion, stop) stops the workers that were
  using it and is not reported as completed unless they are confirmed dead;
* nothing launches once the permission it was checked against has been withdrawn.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import TEST_CONFINEMENT
from aegis.assessment import AssessmentService, StopNotConfirmed
from aegis.authority_ledger import AuthorityLedger, LedgerError
from aegis.policy import PolicyError
from aegis.network import NetworkError
from aegis.authz import AuthzError
from aegis.runtime import WorkerPool
from tests.test_fail_closed import PersistenceBase
from tests.test_real_service import HOST, LAB_PORT, PROFILE_DIRS

REPO = Path(__file__).resolve().parent.parent
KEY = b"k" * 32
SLEEPER = [sys.executable, "-I", "-c", "import time; time.sleep(60)"]


class LedgerBase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="vulnix-ledger-"))
        self.markers = Path(tempfile.mkdtemp(prefix="vulnix-ledger-markers-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.addCleanup(shutil.rmtree, self.markers, True)
        self.events = []

    def open(self):
        led = AuthorityLedger(self.dir, KEY, [self.markers], lambda ev, **f: self.events.append((ev, f)))
        led.reason = led.load()
        return led

    def granted(self):
        led = self.open()
        with led.transaction():
            led.assets["svc.example.test"] = {"id": "asset_1"}
            led.real_service_hosts.add("svc.example.test")
            led.ownership_proofs["svc.example.test"] = {"method": "dns_txt", "verified_at": 1.0}
            led.verified_external_hosts["svc.example.test"] = {"host": "svc.example.test", "port": 443}
        with led.transaction():                     # a second commit: no longer a first-generation ledger
            led.verified_external_hosts["svc.example.test"]["confirmed_at"] = 2.0
        return led


class TestLedgerCommit(LedgerBase):
    def test_round_trip_and_generation(self):
        led = self.granted()
        first = led.generation
        self.assertRegex(first, r"^\d+:[0-9a-f]{32}$")
        self.assertEqual(oct((self.dir / "authority.ledger").stat().st_mode & 0o777), "0o600")
        again = self.open()
        self.assertEqual(again.reason, "")
        self.assertEqual(again.generation, first)
        self.assertIn("svc.example.test", again.verified_external_hosts)
        self.assertEqual(again.assets, {"svc.example.test": {"id": "asset_1"}})
        self.assertFalse(again.dirty())
        again.verified_external_hosts.pop("svc.example.test")
        self.assertTrue(again.commit())
        self.assertNotEqual(again.generation, first)
        self.assertGreater(int(again.generation.split(":")[0]), int(first.split(":")[0]))

    def test_nothing_is_written_when_nothing_changed(self):
        led = self.granted()
        with patch("aegis.authority_ledger.os.replace", side_effect=AssertionError("wrote")):
            self.assertTrue(led.commit())

    def test_a_grant_that_cannot_be_committed_is_rolled_back(self):
        led = self.granted()
        gen = led.generation
        with patch("aegis.authority_ledger.os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(LedgerError):
                with led.transaction():
                    led.verified_external_hosts["other.example.test"] = {"host": "other.example.test"}
        self.assertNotIn("other.example.test", led.verified_external_hosts)      # not in memory
        self.assertEqual(led.generation, gen)
        again = self.open()                                                      # and not on disk
        self.assertEqual(again.reason, "")                                       # what was there is intact
        self.assertEqual(sorted(again.verified_external_hosts), ["svc.example.test"])

    def test_an_exception_inside_a_transaction_changes_nothing(self):
        led = self.granted()
        with self.assertRaises(RuntimeError):
            with led.transaction():
                led.verified_external_hosts.clear()
                raise RuntimeError("caller failed")
        self.assertIn("svc.example.test", led.verified_external_hosts)

    def test_a_reduction_that_cannot_be_committed_makes_the_disk_copy_unacceptable(self):
        led = self.granted()
        led.verified_external_hosts.pop("svc.example.test")
        with patch("aegis.authority_ledger.os.replace", side_effect=OSError("disk full")):
            self.assertFalse(led.commit())
        self.assertEqual(led.error, "OSError")
        self.assertNotIn("svc.example.test", led.verified_external_hosts)        # memory keeps the reduction
        self.assertEqual((self.dir / "authority.epoch").stat().st_size, 0)     # emptied, not removed
        again = self.open()
        self.assertIn("epoch", again.reason)
        self.assertEqual(again.verified_external_hosts, {})
        self.assertIn("svc.example.test", again.real_service_hosts)              # the restriction survives

    def test_the_ledger_is_committed_even_when_the_epoch_record_cannot_be_written(self):
        led = self.granted()
        real = os.replace

        def only_ledger(src, dst):
            if str(dst).endswith("authority.epoch"):
                raise OSError("no")
            return real(src, dst)
        led.verified_external_hosts.pop("svc.example.test")
        with patch("aegis.authority_ledger.os.replace", side_effect=only_ledger):
            self.assertFalse(led.commit())                 # reported as not fully saved
        again = self.open()                                # ...but the revocation IS what a restart finds
        self.assertEqual(again.reason, "")
        self.assertEqual(again.verified_external_hosts, {})
        self.assertTrue(again.dirty())                     # the epoch record is brought up to date
        self.assertTrue(again.commit())
        self.assertFalse(self.open().dirty())

    def test_older_copy_edited_copy_and_missing_epoch_are_refused(self):
        led = self.granted()
        old = (self.dir / "authority.ledger").read_bytes()
        led.verified_external_hosts.pop("svc.example.test")
        led.commit()
        current = (self.dir / "authority.ledger").read_bytes()
        (self.dir / "authority.ledger").write_bytes(old)
        self.assertIn("older copy", self.open().reason)
        body = json.loads(current)
        body["tables"]["verified_external_hosts"] = {"victim.example.org": {"host": "victim.example.org"}}
        (self.dir / "authority.ledger").write_text(json.dumps(body))
        refused = self.open()
        self.assertIn("integrity", refused.reason)
        self.assertEqual(refused.verified_external_hosts, {})
        (self.dir / "authority.ledger").write_bytes(current)
        os.unlink(self.dir / "authority.epoch")
        self.assertIn("epoch", self.open().reason)

    def test_an_unreadable_ledger_grants_nothing_and_is_kept_aside(self):
        self.granted()
        (self.dir / "authority.ledger").write_text("{ truncated")
        led = self.open()
        self.assertIn("cannot be read", led.reason)
        self.assertEqual(led.verified_external_hosts, {})
        self.assertTrue(list(self.dir.glob("authority.unreadable-*.ledger")))

    def test_another_installations_key_does_not_verify(self):
        self.granted()
        other = AuthorityLedger(self.dir, b"x" * 32, [self.markers])
        self.assertTrue(other.load())
        self.assertEqual(other.verified_external_hosts, {})

    def test_the_counter_never_goes_backwards(self):
        led = self.granted()
        n = int(led.generation.split(":")[0])
        os.unlink(self.dir / "authority.epoch")
        again = self.open()
        again.commit()
        self.assertGreater(int(again.generation.split(":")[0]), n)

    def test_legacy_block_in_state_json_is_imported_once_and_only_without_a_ledger(self):
        led = self.open()
        tables = {"ownership_proofs": {}, "verified_external_hosts": {"svc.example.test": {"host": "svc.example.test"}},
                  "real_service_hosts": ["svc.example.test"], "accepted_profiles": {}}
        led._write_epoch("7:" + "a" * 32)
        legacy = {**tables, "authority_epoch": "7:" + "a" * 32,
                  "authority_mac": led.legacy_mac(tables, "7:" + "a" * 32)}
        imported = AuthorityLedger(self.dir, KEY, [self.markers])
        self.assertEqual(imported.load(legacy), "")
        self.assertIn("svc.example.test", imported.verified_external_hosts)
        self.assertTrue(imported.commit())                         # now it lives in the ledger
        self.assertGreater(int(imported.generation.split(":")[0]), 7)
        imported.verified_external_hosts.clear()
        imported.commit()
        replay = AuthorityLedger(self.dir, KEY, [self.markers])    # the old block is not read again
        self.assertEqual(replay.load(legacy), "")
        self.assertEqual(replay.verified_external_hosts, {})
        forged = dict(legacy, authority_mac="0" * 64)
        os.unlink(self.dir / "authority.ledger")
        fresh = AuthorityLedger(self.dir, KEY, [self.markers])
        self.assertTrue(fresh.load(forged))
        self.assertEqual(fresh.verified_external_hosts, {})


class TestLedgerReviewFindings(LedgerBase):
    def replace_failing_for(self, suffix):
        real = os.replace

        def fn(src, dst):
            if str(dst).endswith(suffix):
                raise OSError("no")
            return real(src, dst)
        return patch("aegis.authority_ledger.os.replace", side_effect=fn)

    def test_an_older_ledger_is_refused_even_while_the_epoch_record_lags(self):
        led = self.granted()                                           # G1, epoch record healthy
        g1 = (self.dir / "authority.ledger").read_bytes()
        with self.replace_failing_for("authority.epoch"):
            led.verified_external_hosts["two.example.test"] = {"host": "two.example.test"}
            led.commit()                                               # G2, record still names G1
            g2 = (self.dir / "authority.ledger").read_bytes()
            led.verified_external_hosts.clear()
            led.commit()                                               # G3: everything revoked
        self.assertEqual(self.open().verified_external_hosts, {})       # G3 itself is what a restart finds
        for stale in (g2, g1):
            (self.dir / "authority.ledger").write_bytes(stale)          # only the ledger file is put back
            refused = self.open()
            self.assertTrue(refused.reason, "a superseded ledger was accepted")
            self.assertEqual(refused.verified_external_hosts, {})

    def test_the_counter_is_not_taken_from_an_unverified_ledger(self):
        led = self.granted()
        body = json.loads((self.dir / "authority.ledger").read_text())
        body["generation"] = "999999999999:" + "f" * 32
        (self.dir / "authority.ledger").write_text(json.dumps(body))
        refused = self.open()
        self.assertTrue(refused.reason)
        self.assertTrue(refused.commit())
        self.assertLess(int(refused.generation.split(":")[0]), 10 ** 6)
        self.assertEqual(self.open().reason, "")                        # and it keeps working afterwards

    def test_malformed_unverified_tables_do_not_stop_the_start(self):
        self.granted()
        for bad in ({"assets": 5, "real_service_hosts": 7}, {"verified_external_hosts": "x"}, []):
            (self.dir / "authority.ledger").write_text(json.dumps(
                {"generation": "2:" + "a" * 32, "previous": "", "tables": bad, "mac": "x"}))
            led = self.open()
            self.assertTrue(led.reason)
            self.assertEqual(led.verified_external_hosts, {})

    def test_a_lost_or_unreadable_ledger_means_the_name_list_is_unknown(self):
        for damage in ("truncate", "delete", "edit"):
            with self.subTest(damage):
                shutil.rmtree(self.dir)
                self.dir.mkdir()
                self.granted()
                if damage == "truncate":
                    (self.dir / "authority.ledger").write_text("{ truncated")
                elif damage == "delete":
                    os.unlink(self.dir / "authority.ledger")
                else:
                    body = json.loads((self.dir / "authority.ledger").read_text())
                    body["tables"]["real_service_hosts"] = []
                    (self.dir / "authority.ledger").write_text(json.dumps(body))
                led = self.open()
                self.assertTrue(led.reason)
                self.assertTrue(led.names_unknown)
                self.assertIsNotNone(led.notice)
                self.assertTrue(led.commit())
                self.assertTrue(self.open().names_unknown)              # and it stays that way

    def test_a_first_start_is_not_an_unknown_state(self):
        led = self.open()
        self.assertEqual(led.reason, "")
        self.assertFalse(led.names_unknown)

    def test_a_ledger_refused_only_because_of_a_marker_keeps_its_exact_name_list(self):
        led = self.granted()
        (self.markers / f"{led.marker_key()}.revoked").write_text(
            json.dumps({"epochs": [led.generation], "mac": led.marker_mac([led.generation])}))
        refused = self.open()
        self.assertTrue(refused.reason)
        self.assertEqual(refused.verified_external_hosts, {})
        self.assertEqual(refused.real_service_hosts, {"svc.example.test"})
        self.assertFalse(refused.names_unknown)


class TestFirstCommitAndInvalidation(LedgerBase):
    def first(self):
        led = self.open()
        with led.transaction():
            led.real_service_hosts.add("svc.example.test")
            led.verified_external_hosts["svc.example.test"] = {"host": "svc.example.test"}
        return led

    def test_a_first_commit_interrupted_before_its_epoch_record_is_not_a_lost_ledger(self):
        self.first()
        os.unlink(self.dir / "authority.epoch")         # as if killed right after the ledger rename
        led = self.open()
        self.assertEqual(led.reason, "")
        self.assertFalse(led.names_unknown)
        self.assertIn("svc.example.test", led.verified_external_hosts)
        self.assertTrue(led.commit())
        self.assertFalse(self.open().dirty())

    def test_an_invalidated_first_generation_ledger_is_still_refused(self):
        led = self.first()
        led.verified_external_hosts.clear()
        with patch("aegis.authority_ledger.os.replace", side_effect=OSError("disk full")):
            self.assertFalse(led.commit())
        self.assertTrue((self.dir / "authority.epoch").exists())               # present...
        self.assertEqual((self.dir / "authority.epoch").stat().st_size, 0)     # ...and empty
        again = self.open()
        self.assertTrue(again.reason)
        self.assertEqual(again.verified_external_hosts, {})

    def test_a_ledger_refused_at_load_is_named_when_the_epoch_record_cannot_follow(self):
        led = self.granted()
        stale = (self.dir / "authority.ledger").read_bytes()
        epoch = (self.dir / "authority.epoch").read_bytes()
        led.verified_external_hosts["x.example.test"] = {"host": "x.example.test"}
        led.commit()
        (self.dir / "authority.ledger").write_bytes(stale)    # an older copy is on disk at start
        refused = self.open()
        self.assertTrue(refused.reason)
        real = os.replace

        def only_ledger(src, dst):
            if str(dst).endswith("authority.epoch"):
                raise OSError("no")
            return real(src, dst)
        with patch("aegis.authority_ledger.os.replace", side_effect=only_ledger):
            refused.commit()                                   # records the refusal; the epoch record lags
        (self.dir / "authority.ledger").write_bytes(stale)
        (self.dir / "authority.epoch").write_bytes(epoch)
        self.assertEqual(self.open().verified_external_hosts, {} if self.open().reason else None)
        self.assertTrue(self.open().reason, "the refused older ledger was accepted later")

    def test_an_unreadable_ledger_does_not_let_the_copy_named_by_the_epoch_record_back_in(self):
        self.granted()
        good = (self.dir / "authority.ledger").read_bytes()       # what the epoch record names
        (self.dir / "authority.ledger").write_text("{ truncated")
        refused = self.open()
        self.assertTrue(refused.reason)
        real = os.replace

        def only_ledger(src, dst):
            if str(dst).endswith("authority.epoch"):
                raise OSError("no")
            return real(src, dst)
        with patch("aegis.authority_ledger.os.replace", side_effect=only_ledger):
            self.assertFalse(refused.commit())                     # the refusal is committed; the record lags
        self.assertTrue(list(self.markers.glob("*.revoked")))
        (self.dir / "authority.ledger").write_bytes(good)
        back = self.open()
        self.assertTrue(back.reason)
        self.assertEqual(back.verified_external_hosts, {})

    def test_deeply_nested_json_does_not_stop_the_start(self):
        self.granted()
        (self.dir / "authority.ledger").write_text("[" * 100000 + "]" * 100000)
        led = self.open()
        self.assertTrue(led.reason)
        self.assertEqual(led.verified_external_hosts, {})


# ---- crash at every durable step --------------------------------------------
CHILD = r"""
import os, sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from tests import TEST_CONFINEMENT
from aegis.assessment import AssessmentService
from tests.test_real_service import HOST, PROFILE_DIRS
data, markers, op, crash_at, when = Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], int(sys.argv[5]), sys.argv[6]
svc = AssessmentService(data, 19411, verify_seconds=0.1, l2_profile_dirs=PROFILE_DIRS,
                        l2_confinement=TEST_CONFINEMENT, revocation_marker_dirs=[markers])
url = "http://%s:19412" % HOST
steps = {"n": 0}
real_replace, real_fsync = os.replace, os.fsync
def step(real):
    def wrapped(*a, **kw):
        steps["n"] += 1
        if steps["n"] == crash_at and when == "before":
            os._exit(9)                      # the process dies here, like SIGKILL or a power cut
        out = real(*a, **kw)
        if steps["n"] == crash_at and when == "after":
            os._exit(9)
        return out
    return wrapped
os.replace, os.fsync = step(real_replace), step(real_fsync)
if op == "revoke":
    svc.verify_asset_ownership(url_or_host=url, dns_lookup=lambda n: [])
elif op == "delete":
    rec = next(x for x in (svc.a.asset, *svc._extra_assets) if x["name"] == HOST)
    svc.delete_asset(rec["id"], actor="appr")
elif op == "grant":
    svc.confirm_asset_scope(url_or_host=url, approver="appr", activate_workspace=True, allow_loopback_test=True)
os._exit(0)
"""


class TestCrashAtEveryDurableStep(unittest.TestCase):
    """The child process is killed (os._exit, nothing flushed, nothing cleaned up)
    immediately before or after each rename/fsync of the operation."""

    URL = f"http://{HOST}:19412"

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulnix-crash-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.script = self.root / "child.py"
        self.script.write_text(CHILD)

    def service(self, data, markers):
        svc = AssessmentService(data, 19411, verify_seconds=0.1, l2_profile_dirs=PROFILE_DIRS,
                                l2_confinement=TEST_CONFINEMENT, revocation_marker_dirs=[markers])
        self.addCleanup(svc.workers.kill_all)
        return svc

    def template(self, *, scope):
        data, markers = self.root / "template", self.root / "template-markers"
        data.mkdir()
        markers.mkdir()
        svc = self.service(data, markers)
        ch = svc.issue_ownership_challenge(url=self.URL, approver="appr")["challenge"]
        svc.verify_asset_ownership(url_or_host=self.URL, method="dns_txt", actor="appr",
                                   dns_lookup=lambda n: [f'{n} text = "{ch["dns_txt_value"]}"'])
        if scope:
            svc.confirm_asset_scope(url_or_host=self.URL, approver="appr", activate_workspace=True,
                                    allow_loopback_test=True)
        svc.workers.kill_all()
        return data

    def sweep(self, op, *, scope):
        template = self.template(scope=scope)
        outcomes = {"before": 0, "after": 0}
        for when in ("before", "after"):
            for n in range(1, 60):
                data, markers = self.root / f"{op}-{when}-{n}", self.root / f"{op}-{when}-{n}-m"
                shutil.copytree(template, data)
                (data / ".lock").unlink(missing_ok=True)
                markers.mkdir()
                p = subprocess.run([sys.executable, str(self.script), str(REPO), str(data), str(markers),
                                    op, str(n), when], capture_output=True, text=True, timeout=120,
                                   env={**os.environ, "VULNIX_REVOCATION_MARKER_DIR": str(markers)})
                self.assertIn(p.returncode, (0, 9), p.stderr[-2000:])
                svc = self.service(data, markers)
                has = svc._external_entry(HOST) is not None or HOST in svc._verified_external_hosts
                card = next((x for x in (svc.a.asset, *svc._extra_assets) if x["name"] == HOST), None)
                label = f"{op} crash {when} step {n} (child rc={p.returncode})"
                # atomic: the ledger a restart finds is always a complete, acceptable one
                self.assertEqual(svc.ledger.rejected_reason, "", label)
                # never authority without its asset, never a card that claims a scope it does not have
                if has:
                    self.assertIsNotNone(card, label)
                    self.assertIn(HOST, svc.ledger.assets, label)
                if card is not None and not has:
                    self.assertFalse(card.get("scope_confirmed"), label)
                if card is None:
                    self.assertNotIn(HOST, svc.ledger.assets, label)
                    self.assertNotIn(HOST, svc._ownership_proofs, label)
                # the name is a real service whatever happened: never a lab alias
                self.assertIn(HOST, svc._real_service_hosts, label)
                self.assertEqual(svc._resolve_host(HOST) if not has else [], [], label)
                svc.workers.kill_all()
                if p.returncode == 0:                      # the operation ran to its end
                    if op in ("revoke", "delete"):
                        self.assertFalse(has, label)
                    else:
                        self.assertTrue(has, label)
                    break
                outcomes[when] += 1
                yield when, n, has
            else:
                self.fail(f"{op}: no crash-free run within 60 steps")
        self.assertGreater(outcomes["before"], 2)          # the sweep really covered several crash points

    def test_revocation(self):
        seen = {has for _, _, has in self.sweep("revoke", scope=True)}
        self.assertEqual(seen, {True, False})              # both "not yet" and "already" were observed

    def test_deletion(self):
        seen = {has for _, _, has in self.sweep("delete", scope=True)}
        self.assertEqual(seen, {True, False})

    def test_scope_confirmation(self):
        seen = {has for _, _, has in self.sweep("grant", scope=False)}
        self.assertEqual(seen, {True, False})


# ---- display state and ledger are independent ---------------------------------
class TestDisplayStateCannotBlockTheLedger(PersistenceBase):
    def test_a_revocation_is_committed_even_when_the_display_state_cannot_be_written(self):
        self.onboard()
        self.svc._extra_assets.append({"id": "x", "name": "x.lab.test", "kind": "\ud800", "environment": "e"})
        self.revoke()                                       # state.json cannot be serialised
        self.assertIsNotNone(self.svc._persist_error)       # reported, and real-service work stops
        self.assertIsNone(self.svc.ledger.error)            # but the ledger commit went through
        self.assertGreater((self.dir / "authority.epoch").stat().st_size, 0)
        again = self.restart()
        self.assertEqual(again.ledger.rejected_reason, "")
        self.assertFalse(again._is_external_service_asset(HOST))

    def test_a_scope_that_cannot_be_committed_is_not_granted(self):
        ch = self.svc.issue_ownership_challenge(url=self.url, approver="appr")["challenge"]
        self.svc.verify_asset_ownership(url_or_host=self.url, method="dns_txt", actor="appr",
                                        dns_lookup=self._token_lookup(ch))
        real = os.replace

        def ledger_fails(src, dst):
            if str(dst).endswith("authority.ledger"):
                raise OSError("disk full")
            return real(src, dst)
        with patch("aegis.authority_ledger.os.replace", side_effect=ledger_fails):
            with self.assertRaises(ValueError) as cm:
                self.svc.confirm_asset_scope(url_or_host=self.url, approver="appr", activate_workspace=True,
                                             allow_loopback_test=True)
        self.assertIn("権限台帳", str(cm.exception))
        self.assertFalse(self.svc._is_external_service_asset(HOST))
        card = next(x for x in self.svc.assets() if x["name"] == HOST)
        self.assertFalse(card.get("scope_confirmed"))
        self.assertIn(HOST, self.svc._ownership_proofs)      # the earlier, committed proof is untouched
        again = self.restart()
        self.assertEqual(again.ledger.rejected_reason, "")
        self.assertIn(HOST, again._ownership_proofs)
        self.assertFalse(again._is_external_service_asset(HOST))

    def test_a_proof_that_cannot_be_committed_is_not_recorded(self):
        ch = self.svc.issue_ownership_challenge(url=self.url, approver="appr")["challenge"]
        real = os.replace

        def ledger_fails(src, dst):
            if str(dst).endswith("authority.ledger"):
                raise OSError("disk full")
            return real(src, dst)
        with patch("aegis.authority_ledger.os.replace", side_effect=ledger_fails):
            with self.assertRaises(ValueError):
                self.svc.verify_asset_ownership(url_or_host=self.url, method="dns_txt", actor="appr",
                                                dns_lookup=self._token_lookup(ch))
        self.assertNotIn(HOST, self.svc._ownership_proofs)
        self.assertFalse(next(x for x in self.svc.assets() if x["name"] == HOST).get("ownership_verified"))

    def test_asset_and_authority_leave_the_ledger_in_one_commit(self):
        self.onboard()
        gens = []
        real = os.replace

        def watch(src, dst):
            out = real(src, dst)
            if str(dst).endswith("authority.ledger"):
                gens.append(json.loads(Path(dst).read_text())["tables"])
            return out
        with patch("aegis.authority_ledger.os.replace", side_effect=watch):
            self.svc.delete_asset(self.svc.a.asset["id"], actor="appr")
        self.assertEqual(len(gens), 1)                                   # one transaction
        self.assertNotIn(HOST, gens[0]["assets"])
        self.assertNotIn(HOST, gens[0]["verified_external_hosts"])
        self.assertNotIn(HOST, gens[0]["ownership_proofs"])
        self.assertIn(HOST, gens[0]["real_service_hosts"])

    def test_a_card_the_ledger_does_not_list_is_dropped_at_restart(self):
        self.onboard()
        state_before = (self.dir / "state.json").read_bytes()
        self.svc.delete_asset(self.svc.a.asset["id"], actor="appr")
        self.svc.workers.kill_all()
        (self.dir / "state.json").write_bytes(state_before)   # as if the process died before the display state was written
        again = self.open()
        self.assertEqual(again.ledger.rejected_reason, "")
        self.assertNotIn(HOST, [x["name"] for x in again.assets()])
        self.assertEqual(again.a.asset["name"], "lab.test")
        self.assertTrue(self.events("asset.dropped_not_in_ledger", again))
        again.workers.kill_all()

    def test_authority_generation_is_exposed_and_moves_with_every_change(self):
        self.onboard()
        g1 = self.svc.snapshot()["authority_generation"]
        self.revoke()
        g2 = self.svc.snapshot()["authority_generation"]
        self.assertNotEqual(g1, g2)


# ---- withdrawal is synchronised with the workers --------------------------------
class TestWithdrawalStopsWorkers(PersistenceBase):
    def running_worker(self):
        box = {}
        t = threading.Thread(target=lambda: box.update(res=self.svc.workers.run(SLEEPER, 120)))
        t.start()
        end = time.time() + 5
        while time.time() < end and not self.svc.workers.active_pids():
            time.sleep(0.01)
        self.assertTrue(self.svc.workers.active_pids())
        return t, box

    def test_revocation_kills_the_worker_and_confirms_it(self):
        self.onboard()
        t, box = self.running_worker()
        pid = self.svc.workers.active_pids()[0]
        self.revoke()                                       # returns only after the stop is confirmed
        t.join(10)
        self.assertFalse(t.is_alive())
        self.assertFalse(WorkerPool.group_alive(pid))
        self.assertIsNone(self.svc.snapshot()["unstopped_workers"])
        self.svc.workers.run([sys.executable, "-I", "-c", "print(1)"], 20)   # the pool itself stays usable

    def test_a_worker_for_another_asset_is_left_alone(self):
        self.onboard()
        self.svc.select_asset("lab")
        t, box = self.running_worker()
        pid = self.svc.workers.active_pids()[0]
        self.revoke()                                       # HOST is not the active asset
        self.assertTrue(WorkerPool.group_alive(pid))
        self.svc.workers.terminate_active()
        t.join(10)

    def test_revocation_is_not_reported_as_completed_when_the_worker_survives(self):
        self.onboard()
        t, box = self.running_worker()
        pid = self.svc.workers.active_pids()[0]
        with patch("aegis.runtime._killpg"):                # the kill has no effect
            with self.assertRaises(StopNotConfirmed):
                self.revoke_raw()
        self.assertFalse(self.svc._is_external_service_asset(HOST))        # the withdrawal itself stands
        self.assertEqual(self.svc.snapshot()["unstopped_workers"]["pids"], [pid])
        self.assertTrue(self.events("workers.stop_unconfirmed"))
        self.assertFalse(self.scope_on_disk())
        self.svc.workers.terminate_active()                 # now it really dies
        t.join(10)
        self.assertIsNone(self.svc.snapshot()["unstopped_workers"])
        self.assertTrue(self.events("workers.stop_confirmed_late"))

    def revoke_raw(self):
        self.svc.verify_asset_ownership(url_or_host=self.url, dns_lookup=lambda n: [])

    def scope_on_disk(self):
        return HOST in json.loads((self.dir / "authority.ledger").read_text())["tables"]["verified_external_hosts"]

    def test_deletion_is_not_reported_as_completed_when_the_worker_survives(self):
        self.onboard()
        t, box = self.running_worker()
        pid = self.svc.workers.active_pids()[0]
        with patch("aegis.runtime._killpg"):
            with self.assertRaises(StopNotConfirmed):
                self.svc.delete_asset(self.svc.a.asset["id"], actor="appr")
        self.assertNotIn(HOST, [x["name"] for x in self.svc.assets()])     # deleted and withdrawn all the same
        self.assertFalse(self.scope_on_disk())
        self.svc.workers.terminate_active()
        box.get("res")
        t.join(10)

    def test_emergency_stop_reports_survivors_as_not_confirmed(self):
        self.svc.select_asset("lab")
        t, box = self.running_worker()
        with patch("aegis.runtime._killpg"):
            rep = self.svc.gateway.emergency_stop("appr", confirm_timeout_s=0.5)
        self.assertFalse(rep.confirmed)
        self.assertTrue(rep.survivors)
        for pid in rep.survivors:
            os.killpg(pid, 9)
        t.join(10)

    def test_terminate_active_confirms_and_keeps_the_pool_open(self):
        pool = WorkerPool(max_concurrent=2)
        t = threading.Thread(target=lambda: pool.run(SLEEPER, 120))
        t.start()
        while not pool.active_pids():
            time.sleep(0.01)
        self.assertEqual(pool.terminate_active(), [])
        t.join(10)
        self.assertEqual(pool.run([sys.executable, "-I", "-c", "print(2)"], 20).stdout.strip(), "2")
        self.assertEqual(pool.terminate_active(), [])       # nothing running: nothing to confirm


class TestNothingLaunchesAfterTheWithdrawal(PersistenceBase):
    def test_the_permit_is_checked_under_the_lock_that_registers_the_process(self):
        pool = WorkerPool()

        def refused():
            raise AuthzError("withdrawn")
        with self.assertRaises(AuthzError):
            pool.run([sys.executable, "-I", "-c", "print(1)"], 20, permit=refused)
        self.assertEqual(pool.active_pids(), [])

    def test_a_withdrawal_after_the_last_guard_still_prevents_the_launch(self):
        self.onboard()
        seen = len(self.fake.seen)
        real_guard = self.svc.gateway.launch_guard

        def guard_then_withdraw(tool, args, dest):
            real_guard(tool, args, dest)                    # everything still looks fine...
            self.svc.gateway.invalidate_pending()           # ...and then authority is withdrawn
        self.svc.gateway.launch_guard = guard_then_withdraw
        snap = self.run_l1()
        self.assertEqual(len(self.fake.seen), seen)
        self.assertEqual(snap["state"], "failed")
        self.assertTrue(any("stopped or reset" in e["fields"].get("reason", "") for e in self.events("deny")))

    def test_every_withdrawal_invalidates_what_is_waiting_in_the_gateway(self):
        self.onboard()
        e0 = self.svc.gateway._launch_epoch
        self.revoke()
        e1 = self.svc.gateway._launch_epoch
        self.assertGreater(e1, e0)
        self.onboard()
        self.svc.delete_asset(self.svc.a.asset["id"], actor="appr")
        self.assertGreater(self.svc.gateway._launch_epoch, e1)
        e2 = self.svc.gateway._launch_epoch
        self.svc.emergency_stop("appr")
        self.assertGreater(self.svc.gateway._launch_epoch, e2)


if __name__ == "__main__":
    unittest.main()


class TestReviewFindingsStayFixed(PersistenceBase):
    # ---- the name of a real service is never forgotten ----
    def lab_alias(self, svc):
        return svc.register_asset(name=HOST, kind="API", environment="x", ownership_verified=True,
                                  authorization_ref="DEMO-X", activate_workspace=True)

    def test_a_damaged_or_deleted_ledger_does_not_turn_a_real_service_into_a_lab_alias(self):
        for damage in ("truncate", "delete", "delete-both"):
            with self.subTest(damage):
                self.restart()
                self.onboard()
                self.svc.delete_asset(self.svc.a.asset["id"], actor="appr")   # no card is left
                self.svc.workers.kill_all()
                if damage == "truncate":
                    (self.dir / "authority.ledger").write_text("{ truncated")
                elif damage == "delete":
                    os.unlink(self.dir / "authority.ledger")
                else:                                   # the ledger AND its epoch record are gone
                    os.unlink(self.dir / "authority.ledger")
                    os.unlink(self.dir / "authority.epoch")
                again = self.open()
                self.assertTrue(again.ledger.names_unknown)
                self.assertIsNotNone(again.snapshot()["authority_notice"])
                self.assertTrue(self.events("state.authority_rejected", again))
                with self.assertRaises(ValueError):
                    self.lab_alias(again)
                self.assertEqual(again._resolve_host(HOST), [])
                self.assertEqual(again._resolve_host("anything-else.example.test"), [])
                self.assertEqual(again._resolve_host("lab.test"), ["127.0.0.1"])   # the bundled lab still works
                again.workers.kill_all()
                third = self.open()                                           # and a further restart changes nothing
                self.assertTrue(third.ledger.names_unknown)
                with self.assertRaises(ValueError):
                    self.lab_alias(third)
                third.workers.kill_all()
                for f in self.dir.glob("authority*"):
                    f.unlink()
                (self.dir / "state.json").unlink(missing_ok=True)

    def test_no_challenge_is_issued_while_the_name_cannot_be_recorded(self):
        with patch("aegis.assessment.os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(ValueError):
                self.svc.issue_ownership_challenge(url=self.url, approver="appr")
        self.assertNotIn(HOST, [x["name"] for x in self.svc.assets()])
        again = self.restart()
        self.assertNotIn(HOST, [x["name"] for x in again.assets()])

    # ---- grants ----
    def test_scope_is_not_granted_when_the_activation_would_be_refused(self):
        ch = self.svc.issue_ownership_challenge(url=self.url, approver="appr")["challenge"]
        self.svc.verify_asset_ownership(url_or_host=self.url, method="dns_txt", actor="appr",
                                        dns_lookup=self._token_lookup(ch))
        self.svc._begin_operation()                     # a verification is in flight
        try:
            with self.assertRaises(ValueError):
                self.svc.confirm_asset_scope(url_or_host=self.url, approver="appr", activate_workspace=True,
                                             allow_loopback_test=True)
        finally:
            self.svc._end_operation()
        self.assertNotIn(HOST, self.svc._verified_external_hosts)
        self.assertNotIn(HOST, json.loads((self.dir / "authority.ledger").read_text())["tables"]["verified_external_hosts"])
        self.assertEqual(self.events("asset.scope_confirmed"), [])

    def test_a_dropped_ledger_entry_is_announced(self):
        self.onboard()
        self.svc.workers.kill_all()
        os.unlink(self.dir / "state.json")              # every asset card is gone
        again = self.open()
        self.assertFalse(again._is_external_service_asset(HOST))
        self.assertTrue(self.events("ledger.entry_without_asset_dropped", again))
        self.assertIn(HOST, again.snapshot()["authority_notice"])
        self.assertIn(HOST, again._real_service_hosts)
        again.workers.kill_all()

    # ---- an emergency stop is terminal ----
    def test_a_verification_request_does_not_undo_an_emergency_stop(self):
        self.onboard()
        self.run_l1()
        rep = self.svc.emergency_stop("appr")
        self.assertTrue(rep["confirmed"])
        seen = len(self.fake.seen)
        for call in (lambda: self.svc.verify_finding("all", actor="op"),
                     lambda: self.svc.verify_finding("f_ex_idor", actor="appr", roles={"approver"}),
                     lambda: self.svc.verify_fix("appr")):
            with self.assertRaises(ValueError):
                call()
        self.assertEqual(len(self.fake.seen), seen)
        self.assertEqual(self.svc.gateway.state.value, "stopped")
        snap = self.svc.snapshot()
        self.assertEqual(snap["state"], "stopped")
        self.assertIsNotNone(snap["stop_report"])
        self.svc.restart("appr")                         # only an explicit new run ends the stop
        end = time.time() + 20
        while time.time() < end and self.svc.snapshot()["state"] == "running":
            time.sleep(0.05)
        self.assertEqual(self.svc.snapshot()["state"], "completed")

    # ---- survivors are not forgotten ----
    def hold_worker(self):
        t = threading.Thread(target=lambda: self.svc.workers.run(SLEEPER, 120))
        t.start()
        end = time.time() + 5
        while time.time() < end and not self.svc.workers.active_pids():
            time.sleep(0.01)
        return t, self.svc.workers.active_pids()[0]

    def test_an_unconfirmed_stop_is_remembered_across_restart_select_and_delete(self):
        self.onboard()
        t, pid = self.hold_worker()
        with patch("aegis.runtime._killpg"):             # the kill has no effect
            rep = {}
            stopper = threading.Thread(target=lambda: rep.update(self.svc.emergency_stop("appr")))
            stopper.start()
            stopper.join(30)
            self.assertFalse(rep["confirmed"])
            self.assertEqual(rep["survivors"], [pid])
            self.assertEqual(self.svc.snapshot()["unstopped_workers"]["pids"], [pid])
            with self.assertRaises(ValueError):          # no new run beside a worker that may still be alive
                self.svc.restart("appr")
            self.assertEqual(self.svc.snapshot()["unstopped_workers"]["pids"], [pid])
            self.assertEqual(self.fake.seen, [])
            self.svc.select_asset("lab")
            with self.assertRaises(StopNotConfirmed):
                self.svc.delete_asset(next(x["id"] for x in self.svc.assets() if x["name"] == HOST), actor="appr")
            self.assertEqual(self.svc.snapshot()["unstopped_workers"]["pids"], [pid])
        end = time.time() + 5                            # now the kill works: confirmed late
        while time.time() < end and self.svc.snapshot()["unstopped_workers"]:
            time.sleep(0.05)
        self.assertIsNone(self.svc.snapshot()["unstopped_workers"])
        self.assertTrue(self.events("workers.stop_confirmed_late"))
        t.join(10)
        self.assertFalse(WorkerPool.group_alive(pid))

    def test_the_kill_is_repeated_until_it_takes(self):
        from aegis import runtime
        pool = WorkerPool()
        t = threading.Thread(target=lambda: pool.run(SLEEPER, 120))
        t.start()
        while not pool.active_pids():
            time.sleep(0.01)
        real, calls = runtime._killpg, {"n": 0}

        def flaky(pgid):
            calls["n"] += 1
            if calls["n"] >= 3:
                real(pgid)
        with patch("aegis.runtime._killpg", side_effect=flaky):
            self.assertEqual(pool.terminate_active(confirm_timeout_s=5.0), [])
        self.assertGreaterEqual(calls["n"], 3)
        t.join(10)

    # ---- nothing more is looked up or fetched after a withdrawal ----
    def test_no_proof_recheck_for_a_scope_withdrawn_during_name_resolution(self):
        self.onboard()
        looked = []
        self.svc._proof_dns_lookup = lambda name: looked.append(name) or []
        ext = self.svc._verified_external_hosts[HOST]
        for withdraw in (self.svc.gateway.invalidate_pending,
                         lambda: self.svc._verified_external_hosts.pop(HOST)):
            epoch0 = self.svc.gateway._launch_epoch
            withdraw()                                   # lands while the name lookup is still running
            with self.assertRaises(NetworkError):
                self.svc._require_addresses_covered_by_proof(HOST, ext, ["203.0.113.9"], epoch0)
        self.assertEqual(looked, [])

    def test_results_measured_after_the_scope_ended_are_not_recorded(self):
        self.onboard()
        real = self.svc.gateway.execute

        def expire_during_run(proposal, token):
            d = real(proposal, token)
            self.svc._verified_external_hosts[HOST]["not_after"] = time.time() - 1   # the window closed meanwhile
            return d
        self.svc.gateway.execute = expire_during_run
        snap = self.run_l1()
        self.assertEqual(snap["state"], "failed")
        self.assertIn("診断許可が終了", snap["failure"]["reason"])
        self.assertFalse([f for f in snap["findings"] if f.get("evidence")])


class TestSecondVerificationReview(PersistenceBase):
    def wait_idle(self):
        end = time.time() + 20
        while time.time() < end and self.svc.snapshot()["state"] == "running":
            time.sleep(0.05)

    def test_nothing_but_restart_ends_an_emergency_stop(self):
        self.onboard()
        self.run_l1()
        self.svc.emergency_stop("appr")
        self.assertTrue((self.dir / "emergency-stop.flag").exists())
        seen = len(self.fake.seen)
        # re-confirming the scope (what the registration wizard does)
        self.svc.confirm_asset_scope(url_or_host=self.url, approver="appr", activate_workspace=True,
                                     allow_loopback_test=True)
        # switching to another asset and back
        self.svc.select_asset("lab")
        self.svc.select_asset(next(x["id"] for x in self.svc.assets() if x["name"] == HOST))
        # registering a lab alias with activation
        self.svc.register_asset(name="alias.lab.example", kind="API", environment="x", ownership_verified=True,
                                authorization_ref="DEMO-X", activate_workspace=True)
        self.svc.select_asset(next(x["id"] for x in self.svc.assets() if x["name"] == HOST))
        self.assertEqual(self.svc.gateway.state.value, "stopped")
        self.assertEqual(self.svc.snapshot()["state"], "stopped")
        self.assertIsNotNone(self.svc.snapshot()["stop_report"])
        for call in (lambda: self.svc.verify_finding("all", actor="op"), self.svc.start,
                     lambda: self.svc.verify_fix("appr")):
            with self.assertRaises(ValueError):
                call()
        self.assertEqual(len(self.fake.seen), seen)
        self.svc.restart("appr")
        self.wait_idle()
        self.assertEqual(self.svc.snapshot()["state"], "completed")
        self.assertFalse((self.dir / "emergency-stop.flag").exists())

    def test_no_ownership_lookup_during_an_emergency_stop(self):
        self.onboard()
        self.svc.emergency_stop("appr")
        looked = []
        with self.assertRaises(ValueError):
            self.svc.verify_asset_ownership(url_or_host=self.url, method="dns_txt", actor="appr",
                                            dns_lookup=lambda n: looked.append(n) or [])
        self.assertEqual(looked, [])
        self.assertTrue(self.svc._is_external_service_asset(HOST))     # refused, not treated as a failed proof

    def test_a_stop_whose_state_could_not_be_saved_is_still_a_stop_after_a_restart(self):
        self.onboard()
        self.svc.start()
        real = os.replace

        def state_fails(src, dst):
            if str(dst).endswith("state.json"):
                raise OSError("disk full")
            return real(src, dst)
        with patch("aegis.assessment.os.replace", side_effect=state_fails):
            self.svc.emergency_stop("appr")
        again = self.restart()
        self.assertEqual(again.snapshot()["state"], "stopped")
        self.assertEqual(again.gateway.state.value, "stopped")
        with self.assertRaises(ValueError):
            again.resume("appr")

    def test_survivors_are_still_on_record_after_the_control_plane_restarts(self):
        self.onboard()
        t = threading.Thread(target=lambda: self.svc.workers.run(SLEEPER, 120))
        t.start()
        end = time.time() + 5
        while time.time() < end and not self.svc.workers.active_pids():
            time.sleep(0.01)
        pid = self.svc.workers.active_pids()[0]
        with patch("aegis.runtime._killpg"):
            with self.assertRaises(StopNotConfirmed):
                self.svc.verify_asset_ownership(url_or_host=self.url, dns_lookup=lambda n: [])
            self.assertTrue(self.events("asset.ownership_failed"))          # recorded although the call raised
            again = self.open()                                             # the control plane is restarted
            try:
                self.assertEqual(again.system_status()["unstopped_workers"]["pids"], [pid])
                again.select_asset("lab")
                with self.assertRaises(ValueError):
                    again.restart("appr")                                   # nothing new starts beside it
            finally:
                again.workers.kill_all()
        os.killpg(pid, 9)
        t.join(10)

    def test_a_worker_that_is_gone_is_never_signalled_again(self):
        self.onboard()
        t = threading.Thread(target=lambda: self.svc.workers.run(SLEEPER, 120))
        t.start()
        end = time.time() + 5
        while time.time() < end and not self.svc.workers.active_pids():
            time.sleep(0.01)
        pid = self.svc.workers.active_pids()[0]
        with patch("aegis.runtime._killpg"):
            self.svc.emergency_stop("appr")
            self.assertEqual(self.svc.system_status()["unstopped_workers"]["pids"], [pid])
        try:
            os.killpg(pid, 9)                            # it dies by other means
        except OSError:
            pass
        t.join(10)
        self.assertFalse(WorkerPool.group_alive(pid))
        with patch("aegis.runtime._killpg") as kill, patch("aegis.runtime.os.killpg", wraps=os.killpg) as raw:
            for _ in range(3):
                self.svc.system_status()
                self.svc.snapshot()
            kill.assert_not_called()
            self.assertFalse([c for c in raw.call_args_list if c.args[1] != 0], "a dead worker's pid was signalled")
        self.assertIsNone(self.svc.system_status()["unstopped_workers"])

    def test_a_new_registration_is_not_an_error_because_of_someone_elses_survivor(self):
        self.svc._unstopped.append({"host": "other.example.test", "pids": [os.getpid()], "at": time.time(),
                                    "pool": None, "sessions": []})       # some survivor is on record
        out = self.svc.issue_ownership_challenge(url=self.url, approver="appr")
        self.assertIn("challenge", out)
        self.assertTrue(self.events("asset.challenge_issued"))
        self.svc._unstopped.clear()

    def test_a_registration_that_cannot_be_committed_disturbs_nothing_else(self):
        self.onboard()
        other = f"http://other-{HOST}:{self.fake.server_port}"
        real = os.replace

        def ledger_fails(src, dst):
            if str(dst).endswith("authority.ledger"):
                raise OSError("disk full")
            return real(src, dst)
        with patch("aegis.authority_ledger.os.replace", side_effect=ledger_fails):
            with self.assertRaises(ValueError):
                self.svc.issue_ownership_challenge(url=other, approver="appr")
        self.assertGreater((self.dir / "authority.epoch").stat().st_size, 0)    # the epoch record was not touched
        self.assertNotIn(f"other-{HOST}", (self.dir / "state.json").read_text())    # and no card was written
        again = self.restart()
        self.assertEqual(again.ledger.rejected_reason, "")
        self.assertFalse(again.ledger.names_unknown)
        self.assertIn(HOST, again._verified_external_hosts)                     # the existing scope is intact
        self.assertNotIn(f"other-{HOST}", [x["name"] for x in again.assets()])

    def test_scope_that_expires_during_name_resolution_gets_no_proof_lookup(self):
        self.onboard()
        looked = []
        self.svc._proof_dns_lookup = lambda name: looked.append(name) or []
        ext = self.svc._verified_external_hosts[HOST]
        epoch0 = self.svc.gateway._launch_epoch
        ext["not_after"] = time.time() - 1
        with self.assertRaises(NetworkError):
            self.svc._require_addresses_covered_by_proof(HOST, ext, ["203.0.113.9"], epoch0)
        self.assertEqual(looked, [])
