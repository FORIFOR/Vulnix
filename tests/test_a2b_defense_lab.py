"""A2B defense in a synthetic lab: the same profile rules, worker probe and judge the Gateway
uses decide cross-account, cross-organization and role checks on a vulnerable and a patched
backend. Every check needs its positive controls (owner can read, subject is authenticated)."""
import argparse
import json
import os
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.l2_rules import L2RuleSet, evaluate
from aegis.workers.reproduction_probe import run_rule_check
from tests.fixtures.a2b_lab import A2BLab

PROFILES = Path(__file__).parent / "fixtures" / "a2b_profiles"
TOKENS = {"member_a_token": "tok-a", "admin_b_token": "tok-b", "member_c_token": "tok-c"}


def verdicts(mode: str, tokens=TOKENS) -> dict:
    rules = L2RuleSet.load(dirs=[PROFILES])
    lab = A2BLab(mode)
    threading.Thread(target=lab.serve_forever, daemon=True).start()
    try:
        out = {}
        with patch.dict(os.environ, {"VULNIX_L2_TOKENS": json.dumps(tokens), "VULNIX_L2_PATHS": "{}"}):
            for cid in rules.runnable_check_ids():
                rule = rules.worker_rule_json(cid)
                args = argparse.Namespace(check=cid, ip="127.0.0.1", port=lab.server_port,
                                          host="a2b.lab.test", scheme="http")
                result = run_rule_check(args, rule)
                out[cid] = evaluate(json.loads(rule), result)["verdict"]
                assert "tok-" not in json.dumps(result), "a token appeared in the result"
        return out
    finally:
        lab.shutdown()
        lab.server_close()


class TestA2BDefenseLab(unittest.TestCase):
    def test_a_backend_that_checks_only_the_token_is_open_on_every_axis(self):
        self.assertEqual(verdicts("vulnerable"), {"a2b_cross_account": "proven", "a2b_cross_tenant": "proven",
                                                  "a2b_role_bypass": "proven"})

    def test_owner_organization_and_role_checks_are_each_confirmed_as_denials(self):
        self.assertEqual(verdicts("patched"), {"a2b_cross_account": "not_reproduced",
                                               "a2b_cross_tenant": "not_reproduced",
                                               "a2b_role_bypass": "not_reproduced"})

    def test_a_broken_test_token_gives_unverified_never_a_false_all_clear(self):
        broken = {**TOKENS, "member_a_token": "tok-expired"}
        self.assertEqual(set(verdicts("patched", broken).values()), {"unverified"})


if __name__ == "__main__":
    unittest.main()
