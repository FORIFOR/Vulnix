"""Real ARTEX path must keep eligible status checks and reject ineligible ones."""

import tempfile
import json
import unittest
from pathlib import Path
from urllib.request import Request, urlopen

from scripts.bench_initial_extra_selection import _certificate, measure, _status_intents
from tests.artex_mock_llm import MockLLM


class StatusSelectionHoldoutTests(unittest.TestCase):
    def test_mock_uses_measured_fingerprint_or_falls_back_to_facts(self):
        with MockLLM(intent_selector=_status_intents, prefer_initial_facts=True) as model:
            def ask(content):
                req = Request(model.url + "/chat/completions",
                              data=json.dumps({"model": "mock", "messages": [
                                  {"role": "user", "content": content}]}).encode(),
                              headers={"Content-Type": "application/json"})
                with urlopen(req, timeout=3) as response:
                    return json.load(response)["choices"][0]["message"]
            apache = ask('Measured root fingerprint: {"server_family": "apache"}')
            self.assertEqual(apache["tool_calls"][0]["function"]["name"], "add_intent")
            nginx = ask('Measured root fingerprint: {"server_family": "nginx"}')
            self.assertNotIn("tool_calls", nginx)
            unknown = ask("No measured fingerprint is present")
            self.assertEqual(unknown["tool_calls"][0]["function"]["name"], "list_facts")

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

    def test_first_prompt_status_fact_keeps_selection_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            certificate = _certificate(Path(tmp))
            for mode, consent in (("vulnerable", True), ("patched", True),
                                  ("non_apache", True), ("vulnerable", False)):
                with self.subTest(mode=mode, consent=consent):
                    old = measure("status", mode, "lookup_facts", certificate,
                                  allow_status_probe=consent)
                    new = measure("status", mode, "initial_facts", certificate,
                                  allow_status_probe=consent)
                    for key in ("status_plan_proposed", "status_finding_verdict",
                                "target_get", "worker_launches", "planner_calls"):
                        self.assertEqual(old[key], new[key], key)
                    self.assertEqual(new["target_get"],
                                     2 if mode != "non_apache" and consent else 1)


if __name__ == "__main__":
    unittest.main()
