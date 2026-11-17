"""Real ARTEX path must keep eligible status checks and reject ineligible ones."""

import tempfile
import unittest
from pathlib import Path

from scripts.bench_initial_extra_selection import _certificate, measure


class StatusSelectionHoldoutTests(unittest.TestCase):
    def test_exposed_status_needs_an_approved_extra_get(self):
        with tempfile.TemporaryDirectory() as tmp:
            certificate = _certificate(Path(tmp))
            fixed = measure("status", "vulnerable", "fixed", certificate,
                            allow_status_probe=True)
            observed = measure("status", "vulnerable", "observed", certificate,
                               allow_status_probe=True)
        self.assertEqual(fixed["target_get"], 1)
        self.assertEqual(fixed["status_finding_verdict"], "none")
        self.assertEqual(observed["target_get"], 2)
        self.assertTrue(observed["status_plan_executable"])
        self.assertEqual(observed["status_finding_verdict"], "detected")

    def test_non_apache_does_not_trigger_extra_get(self):
        with tempfile.TemporaryDirectory() as tmp:
            certificate = _certificate(Path(tmp))
            observed = measure("status", "non_apache", "observed", certificate,
                               allow_status_probe=True)
        self.assertFalse(observed["status_plan_proposed"])
        self.assertEqual(observed["target_get"], 1)


if __name__ == "__main__":
    unittest.main()
