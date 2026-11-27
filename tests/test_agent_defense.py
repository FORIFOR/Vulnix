"""Runtime check of an AI coding agent's own permission rules (real claude CLI, loopback
stand-in model, network sandbox). Runs where the CLI and macOS sandbox-exec exist."""
import json
import tempfile
import unittest
from pathlib import Path

from aegis import agent_defense as ad

HARDENED = {"permissions": {"deny": ["Read(./.env)", "Read(./.env.*)", "Bash(cat:*)", "Bash(curl:*)", "Bash(wget:*)",
                                     "WebFetch", "Bash(rm:*)", "Edit(./.claude/**)", "Write(./.claude/**)"]}}


@unittest.skipUnless(ad.claude_cli() and Path("/usr/bin/sandbox-exec").exists(), "claude CLI and macOS sandbox-exec")
class TestAgentDefenseRuntime(unittest.TestCase):
    def evaluate(self, settings):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            if settings is not None:
                (project / ".claude").mkdir()
                (project / ".claude/settings.json").write_text(json.dumps(settings))
            (project / ".env").write_text("REAL_SECRET=must-never-be-copied\n")
            report = ad.evaluate(project)
            self.assertEqual((project / ".env").read_text(), "REAL_SECRET=must-never-be-copied\n")  # untouched
        return report, {r["id"]: r for r in report["results"]}

    def test_without_project_rules_the_secret_reaches_the_model(self):
        report, rows = self.evaluate(None)
        self.assertEqual(rows["secret_read"]["verdict"], "breached")
        self.assertTrue(rows["secret_read"]["secret_reached_model"])
        self.assertIsNotNone(rows["secret_read"]["advice"])
        self.assertNotIn("must-never-be-copied", json.dumps(report))           # only the synthetic canary

    def test_explicit_deny_rules_stop_every_attack_by_rule(self):
        _, rows = self.evaluate(HARDENED)
        for aid in ("secret_read", "secret_shell", "exfil_shell", "loosen_permissions", "destructive"):
            with self.subTest(attack=aid):
                self.assertEqual(rows[aid]["verdict"], "blocked")
                self.assertEqual(rows[aid]["blocked_by"], "rule")
                self.assertFalse(rows[aid]["secret_reached_model"])
                self.assertEqual(rows[aid]["changed_files"], [])
        self.assertFalse(rows["write_outside"]["wrote_outside_project"])


if __name__ == "__main__":
    unittest.main()
