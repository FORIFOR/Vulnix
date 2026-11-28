"""A2B profile drafted from the UI (no hand-written JSON): the same rule engine, worker probe
and judge decide it against the synthetic lab exactly as they decide the bundled profile."""
import argparse
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.a2b_profile import DraftError, build_profile, save_site_profile
from aegis.l2_rules import L2RuleSet, evaluate, site_file_problem
from aegis.workers.reproduction_probe import run_rule_check
from tests.fixtures.a2b_lab import A2BLab

EVIDENCE = ["a2b_openapi.json: paths./api/orgs/{org}/notes/{note}.get (security: bearer)"]
DRAFT = {
    "name": "A2B Lab", "host": "a2b.lab.test", "source": "a2b_openapi.json", "admin_is_same_org": True,
    "own_path": "/api/orgs/org-a/notes/note-a1", "own_marker": "VULNIX_A2B_OWNER_A_DATA", "denied_status": [403],
    "checks": [
        {"kind": "cross_account", "path": "/api/orgs/org-a/notes/note-b1", "marker": "VULNIX_A2B_OWNER_B_DATA",
         "evidence": EVIDENCE, "confirmed": True},
        {"kind": "cross_tenant", "path": "/api/orgs/org-b/notes/note-c1", "marker": "VULNIX_A2B_ORG_B_DATA",
         "evidence": EVIDENCE, "confirmed": True},
        {"kind": "admin_function", "path": "/api/orgs/org-a/admin/export", "marker": "VULNIX_A2B_EXPORT_org-a",
         "evidence": ["a2b_openapi.json: paths./api/orgs/{org}/admin/export.get (x-required-role: admin)"],
         "confirmed": True},
    ],
}
TOKENS = {"subject_token": "tok-a", "same_org_token": "tok-b", "other_org_token": "tok-c"}


def run(profile: dict, mode: str, tokens=TOKENS) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / f"{profile['id']}.json").write_text(json.dumps(profile))
        rules = L2RuleSet.load(dirs=[Path(tmp)])
    lab = A2BLab(mode)
    threading.Thread(target=lab.serve_forever, daemon=True).start()
    try:
        out = {}
        with patch.dict(os.environ, {"VULNIX_L2_TOKENS": json.dumps(tokens), "VULNIX_L2_PATHS": "{}"}):
            for cid in rules.runnable_check_ids():
                rule = rules.worker_rule_json(cid)
                args = argparse.Namespace(check=cid, ip="127.0.0.1", port=lab.server_port,
                                          host="a2b.lab.test", scheme="http")
                out[cid.rsplit("_", 2)[-2] + "_" + cid.rsplit("_", 1)[-1]] = evaluate(json.loads(rule),
                                                                                     run_rule_check(args, rule))["verdict"]
        return out
    finally:
        lab.shutdown()
        lab.server_close()


class TestDraftedProfileOnTheLab(unittest.TestCase):
    def test_vulnerable_backend_is_proven_on_every_axis(self):
        self.assertEqual(run(build_profile(DRAFT), "vulnerable"),
                         {"cross_account": "proven", "cross_tenant": "proven", "admin_function": "proven"})

    def test_patched_backend_is_not_reproduced(self):
        self.assertEqual(set(run(build_profile(DRAFT), "patched").values()), {"not_reproduced"})

    def test_a_broken_token_is_unverified(self):
        self.assertEqual(set(run(build_profile(DRAFT), "patched", {**TOKENS, "subject_token": "x"}).values()),
                         {"unverified"})


class TestDraftRules(unittest.TestCase):
    def test_unconfirmed_checks_are_placeholders_and_never_run(self):
        draft = {**DRAFT, "checks": [{**c, "confirmed": False} for c in DRAFT["checks"]]}
        profile = build_profile(draft)
        self.assertEqual({c["spec_status"] for c in profile["checks"]}, {"placeholder"})
        self.assertEqual(run(profile, "vulnerable"), {})

    def test_confirmation_without_evidence_from_the_definition_stays_a_placeholder(self):
        draft = {**DRAFT, "checks": [{**DRAFT["checks"][0], "evidence": []}]}
        self.assertEqual(build_profile(draft)["checks"][0]["spec_status"], "placeholder")

    def test_guessed_or_unsafe_inputs_are_refused(self):
        bad = [
            {"own_path": "/api/orgs/{org}/notes/{note}"},                      # template, not a real record
            {"own_path": "https://other.example/api"},
            {"own_marker": "abc"},                                             # too short to be unique
            {"denied_status": [401]},                                          # token expiry looks the same
            {"host": "bad host"},
            {"checks": [{**DRAFT["checks"][0], "path": DRAFT["own_path"]}]},
            {"checks": [{**DRAFT["checks"][0], "marker": DRAFT["own_marker"]}]},
            {"checks": [{**DRAFT["checks"][0], "path": "/a/../admin"}]},
        ]
        for change in bad:
            with self.subTest(change=change), self.assertRaises(DraftError):
                build_profile({**DRAFT, **change})

    def test_saved_file_is_a_site_profile_that_needs_acceptance(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = save_site_profile(Path(tmp), build_profile(DRAFT))
            self.assertIsNone(site_file_problem(path))
            self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
            rules = L2RuleSet.load([], [path.parent])
            held = rules.hold_unaccepted({})
            self.assertIn("a2b_a2b_lab", held)
            self.assertEqual(list(rules.runnable_check_ids()), [])


if __name__ == "__main__":
    unittest.main()
