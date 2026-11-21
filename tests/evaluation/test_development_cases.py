"""The first held-out cases the owner-record rules were derived from, now development /
regression cases (docs/evaluation/regression_manifest.json "development_cases",
docs/evaluation/JUDGE_OWNER_RECORD.md). The whole control plane runs them with the fixed
rule: they pin the intended effect and the cases that must stay withheld."""
import tests  # noqa: F401
import json
import unittest
from pathlib import Path

from aegis.evaluation.evaluation_runner import Harness, run_case
from aegis.evaluation.network_guard import no_external_connections
from tests import TEST_CONFINEMENT
from tests.artex_mock_llm import MockLLM
from tests.diagnosis_planner import intents_from_facts
from tests.evaluation.fixtures.holdout_lab import CASES, HoldoutLab
from tests.test_artex_bridge import FAKE

ROOT = Path(__file__).resolve().parents[2]
H = Harness(lab_factory=HoldoutLab, confinement=TEST_CONFINEMENT, artex_stand_in=FAKE,
            mock_llm=lambda sel: MockLLM(intent_selector=sel), scripted_intents=intents_from_facts)

# case -> (other_account_read, unauthenticated_exposure) after the change, fixed rule
EXPECTED = {
    "holdout-001": ("inconclusive", "inconclusive"),  # a bare "Sign in" form without a password field: not decided
    "holdout-007": ("inconclusive", "contradicted"),   # A always 429: stays withheld
    "holdout-010": ("supported", "contradicted"),      # anon 200 JSON refusal
    "holdout-013": ("contradicted", "contradicted"),   # 200 {error: forbidden} for anon and A
    "holdout-014": ("supported", "inconclusive"),      # anon gets B's data naming B, no identifiers
    "holdout-017": ("contradicted", "inconclusive"),   # anon 200 public listing: JSON data, never closed
    "holdout-029": ("inconclusive", "contradicted"),   # no owner control: stays withheld
    # B's record served to A, announced as "caller=B": B's resource id and marker, measured against
    # B's own control, decide (案2, docs/evaluation/JUDGE_IDENTITY_MATCH.md); before 案2: inconclusive
    "holdout-030": ("supported", "contradicted"),
}


class TestDevelopmentCases(unittest.TestCase):
    def test_the_manifest_names_these_cases(self):
        dev = json.loads((ROOT / "docs/evaluation/regression_manifest.json").read_text())["development_cases"]
        self.assertEqual(sorted(dev["case_ids"]), sorted(EXPECTED))

    def test_the_fixed_rule_on_the_development_cases(self):
        rules = {}
        with no_external_connections() as attempts:
            for cid, want in EXPECTED.items():
                r = run_case(cid, CASES[cid], "fixed_rule", H)
                with self.subTest(cid):
                    self.assertEqual((r["other_account_read"], r["unauthenticated_exposure"]), want)
                    self.assertTrue(r["audit_chain_valid"] and r["every_judgement_cites_an_audited_result"])
                    self.assertEqual(r["planner_input_leaked"], [])
                rules[cid] = {s["judgement"]["rule"] for s in r["steps"] if s.get("judgement")}
        self.assertEqual(attempts, [])
        self.assertNotIn("owner_record_absent", rules["holdout-001"])   # not clearly a sign-in page
        self.assertIn("owner_record_absent", rules["holdout-013"])
        # a public JSON listing is data, not a refusal: the absence rule does not decide it
        self.assertNotIn("owner_record_absent_without_auth", rules["holdout-017"])
        self.assertIn("control_failed", rules["holdout-029"])
        self.assertIn("cross_account_read", rules["holdout-030"])          # 案2; was unrecognised_answer
        self.assertNotIn("owner_record_absent", rules["holdout-030"])


if __name__ == "__main__":
    unittest.main()
