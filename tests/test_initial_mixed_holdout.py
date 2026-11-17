"""Unseen combinations of a baseline finding and an Apache-only extra check."""

import tempfile
import unittest
from pathlib import Path

from scripts.bench_initial_extra_selection import _certificate, measure


class InitialMixedHoldoutTests(unittest.TestCase):
    def test_consent_with_apache_does_not_skip_status_check_for_other_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            certificate = _certificate(Path(tmp))
            for kind, mode in (("cors", "reflected_credentials"),
                               ("cookie", "session_full")):
                with self.subTest(kind=kind):
                    fixed = measure(kind, mode, "fixed", certificate,
                                    server_banner="Apache/2.4.62", allow_status_probe=True)
                    always = measure(kind, mode, "always", certificate,
                                     server_banner="Apache/2.4.62", allow_status_probe=True)
                    observed = measure(kind, mode, "observed", certificate,
                                       server_banner="Apache/2.4.62", allow_status_probe=True)
                    self.assertEqual(fixed["target_get"], 1)
                    self.assertEqual(always["target_get"], 2)
                    self.assertEqual(observed["target_get"], 2)
                    self.assertEqual(observed["status_check_appropriate"], True)
                    self.assertEqual(observed["status_plan_executable"], True)
                    self.assertEqual(observed["planner_calls"], 1)
                    self.assertEqual(always["planner_calls"], 1)
                    self.assertEqual(observed["status_finding_verdict"], "not_reproduced")
                    self.assertEqual(always["status_finding_verdict"], "not_reproduced")
                    self.assertEqual({fixed["verdict"], always["verdict"], observed["verdict"]},
                                     {fixed["verdict"]})


if __name__ == "__main__":
    unittest.main()
