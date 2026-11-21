"""PR-B: every fixed id the diagnosis read API can send has words on the screen.

The panel (web/src/components/assessment/DiagnosisLoopPanel.tsx) shows only the words in
web/src/lib/labels.ts; an id without an entry is shown as "未定義の値". This test reads the
ids from the backend itself, so a new claim, rule, end reason or refusal cannot reach
the screen without a label.
"""
import inspect
import re
import unittest
from pathlib import Path

from aegis import adaptive_plan_runner, diagnosis_judge, diagnosis_loop, diagnosis_ops, diagnosis_view, evidence
from aegis.adaptive_plan_state import PlanState
from aegis.assessment import AssessmentService
from aegis.diagnosis_state import CLAIMS, SOURCES, STATES
from aegis.plan_contract import REASONS

LABELS = (Path(__file__).resolve().parents[1] / "web/src/lib/labels.ts").read_text(encoding="utf-8")


def keys(table: str) -> set[str]:
    m = re.search(rf"export const {table}\b[^=]*= \{{(.*?)\n\}};", LABELS, re.S)
    if m is None:
        raise AssertionError(f"{table} is missing from labels.ts")
    return set(re.findall(r"^\s{2}([A-Za-z0-9_]+):", m.group(1), re.M))


def strings(pattern: str, source) -> set[str]:
    """Every match of `pattern` in `source`. Each pattern must find something, so a pattern
    that stops matching after a refactor fails here instead of shrinking the check."""
    found = set(re.findall(pattern, inspect.getsource(source)))
    if not found:
        raise AssertionError(f"pattern {pattern!r} found nothing in {getattr(source, '__name__', source)}")
    return found


def nested_keys(table: str) -> dict[str, set[str]]:
    m = re.search(rf"export const {table}\b[^=]*= \{{(.*?)\n\}};", LABELS, re.S)
    if m is None:
        raise AssertionError(f"{table} is missing from labels.ts")
    return {k: set(re.findall(r"([A-Za-z0-9_]+):", body))
            for k, body in re.findall(r"^\s{2}([A-Za-z0-9_]+): \{([^}]*)\}", m.group(1), re.M)}


class TestEveryIdHasWords(unittest.TestCase):
    def assertCovered(self, table: str, ids: set[str]):
        self.assertTrue(ids, f"no ids found for {table}: the extraction is broken")
        self.assertEqual(ids - keys(table), set(), f"ids without words in {table}")

    def test_claims_states_reasons_sources(self):
        self.assertCovered("DIAG_CLAIM", set(CLAIMS))
        self.assertCovered("DIAG_STATE", set(STATES))
        self.assertCovered("DIAG_REASON", set(REASONS))
        self.assertCovered("DIAG_SOURCE", set(SOURCES))
        self.assertCovered("DIAG_REQUIREMENT", set(diagnosis_judge.REQUIREMENTS))
        self.assertCovered("DIAG_PLAN_STATE", {s.value for s in PlanState})

    def test_judge_rules(self):
        rules = strings(r'_verdict\(hypothesis_id, "\w+", [^)]*?"([a-z_]+)"\)', diagnosis_judge.judge)
        rules |= strings(r'by_spec\("([a-z_]+)"\)', diagnosis_judge.judge)
        self.assertGreaterEqual(len(rules), 10)
        self.assertCovered("DIAG_RULE", rules)

    def test_checks_and_observation_kinds(self):
        self.assertCovered("DIAG_CHECK", set(diagnosis_judge.FIXED_CHECK_FOR_CLAIM.values()))
        self.assertCovered("DIAG_EVIDENCE_KIND", strings(r'observe\(kind="([a-z_]+)"', diagnosis_loop))
        self.assertCovered("DIAG_EVIDENCE_KIND", strings(r'observe\(kind="([a-z_]+)"', adaptive_plan_runner))

    def test_observation_attributes(self):
        """Every word an observation can carry (check_attrs, the L1 observations, the spec)."""
        words = nested_keys("DIAG_ATTR_VALUE")
        shown_as_numbers = {"status", "requirement"}       # "応答 200", "仕様：..." (DIAG_REQUIREMENT)
        keys_ = strings(r'"([a-z_]+)": ', diagnosis_judge.check_attrs)
        keys_ |= strings(r'attrs=\{"([a-z_]+)"', diagnosis_loop)
        keys_ |= strings(r', "([a-z_]+)": "T2" in targets', diagnosis_loop)
        self.assertEqual(keys_ - shown_as_numbers - set(words), set(), "attribute keys without words")
        values = strings(r'"(\w+)" if result\.get\("control_verified"\) is True else "(\w+)"',
                         diagnosis_judge.check_attrs)
        self.assertEqual({v for pair in values for v in pair} - words["control"], set())
        self.assertEqual({"none", "other_account"} - words["auth"], set())
        self.assertIn("unreadable", words["answer"])
        # reproduction_verdict's answers for the IDOR check
        from aegis import evidence
        verdicts = strings(r'return "([a-z_]+)"', evidence.reproduction_verdict)
        self.assertEqual(verdicts - words["reproduction"], set(), "reproduction verdicts without words")

    def test_plan_end_reasons(self):
        src = adaptive_plan_runner.AdaptivePlanRunner
        reasons = strings(r'_finish\(plan, [\w.]+, f?"([a-z0-9_]+)[":]', src)
        reasons |= strings(r'PlanState\.\w+, f?"([a-z0-9_]+)[":]', src)
        reasons |= strings(r'return f?"([a-z0-9_]+)[":]', src)
        reasons |= strings(r'"(no_progress)" if diag', src)
        # "item_<status>" is matched by its prefix (lib/diagnosisView.ts endText)
        self.assertCovered("DIAG_END", reasons - {"no_new_check"})

    def test_refusals_fix_results_and_next_kinds(self):
        self.assertCovered("DIAG_REFUSAL", strings(r'_Refuse\("([a-z_]+)"\)', diagnosis_view))
        self.assertCovered("DIAG_REFUSAL", strings(r'refused\(base, "([a-z_]+)"\)', diagnosis_view))
        self.assertCovered("DIAG_REFUSAL", strings(r'refuse\("([a-z_]+)"\)',
                                                   AssessmentService._restore_diagnosis_locked))
        self.assertCovered("DIAG_NEXT", strings(r'"kind": "([a-z_0-9]+)"', diagnosis_view))
        fix = strings(r'\{"contradicted": "(\w+)", "supported": "(\w+)"\}\.get\(h\["state"\], "(\w+)"\)',
                      diagnosis_view)
        self.assertCovered("DIAG_FIX_RESULT", {v for triple in fix for v in triple})
        self.assertCovered("DIAG_FIX_STATE", {"contradicted", "supported"})

    def test_operations_pr_c(self):
        """PR-C: every refusal reason, job state, job kind and job end reason the
        operations can send, and every finding status the fix comparison names."""
        self.assertCovered("DIAG_OP_REASON", strings(r'OpError\(\d+,[^)]*?"([a-z_]+)"\)', diagnosis_ops))
        self.assertCovered("DIAG_OP_REASON", strings(r'"reason": "([a-z_]+)"', diagnosis_ops))
        self.assertCovered("DIAG_OP_STATE", set(diagnosis_ops.ACTIVE)
                           | strings(r'state="([a-z_]+)"', diagnosis_ops)
                           | strings(r'_end_job\(job, "([a-z_]+)"', diagnosis_ops))
        self.assertCovered("DIAG_OP_KIND", strings(r'_new_job_locked\("([a-z_]+)"', diagnosis_ops))
        statuses = strings(r'return "([a-z_]+)"', evidence.evidence_status)
        statuses |= {w for group in strings(r'verdict in \{([^}]*)\}', evidence.evidence_status)
                     for w in re.findall(r'"([a-z_]+)"', group)}
        self.assertCovered("DIAG_FINDING_STATUS", statuses)


if __name__ == "__main__":
    unittest.main()
