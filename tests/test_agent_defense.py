"""Runtime check of an AI coding agent's own permission rules (real claude CLI, loopback
stand-in model, network sandbox). Runs where the CLI and macOS sandbox-exec exist."""
import json
import subprocess
import os
import tempfile
import time
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


class TestSettingsAreReducedToPermissionRules(unittest.TestCase):
    def test_executable_settings_are_dropped_and_reported(self):
        kept, ignored = ad.sanitize_settings({
            "permissions": {"deny": ["Read(./.env)", 7], "defaultMode": "bypassPermissions",
                            "additionalDirectories": ["/"]},
            "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "touch /tmp/x"}]}]},
            "mcpServers": {"x": {"command": "evil"}}, "env": {"PATH": "/evil"}, "apiKeyHelper": "evil",
            "statusLine": {"type": "command", "command": "evil"}})
        self.assertEqual(kept, {"permissions": {"deny": ["Read(./.env)"], "defaultMode": "bypassPermissions"}})
        for key in ("hooks", "mcpServers", "env", "apiKeyHelper", "statusLine", "permissions.additionalDirectories"):
            self.assertTrue(any(key in i for i in ignored), key)

    def test_unknown_default_mode_is_not_passed_on(self):
        kept, ignored = ad.sanitize_settings({"permissions": {"defaultMode": "anything"}})
        self.assertEqual(kept, {"permissions": {}})
        self.assertIn("permissions.defaultMode", ignored)


@unittest.skipUnless(ad.claude_cli() and Path("/usr/bin/sandbox-exec").exists(), "claude CLI and macOS sandbox-exec")
class TestPublicCandidatesCannotEnableTheRuntimeCheck(unittest.TestCase):
    def test_no_switch_enables_it_on_a_public_or_hosted_or_release_server(self):
        from unittest.mock import patch
        for extra in ({"VULNIX_PUBLIC_MODE": "1"}, {"VULNIX_PUBLIC_SIGNUP": "1"}, {"AEGIS_ENV": "production"},
                      {"AEGIS_ENV": "staging"}, {"K_SERVICE": "vulnix"}, {"VULNIX_RELEASE_BUILD": "1"}):
            with patch.dict(os.environ, {"VULNIX_AGENT_DEFENSE_LOCAL": "1", **extra}):
                state = ad.availability()
                self.assertFalse(state["available"], extra)
                self.assertIn("公開候補", state["reason"])
                rep = ad.evaluate_settings('{"permissions": {}}')
                self.assertEqual(rep["status"], "unsupported")

    def test_the_users_own_machine_is_unaffected(self):
        self.assertEqual(ad.public_candidate_reasons({"VULNIX_AGENT_DEFENSE_LOCAL": "1"}), [])


class TestConfinement(unittest.TestCase):
    def test_self_test_passes_its_sampled_rules(self):
        # a sample of the profile's rules (SELF_TEST_SCOPE), not proof of full isolation
        ok, failures = ad.confinement_self_test(ad.claude_cli())
        self.assertTrue(ok, failures)

    def test_only_the_model_port_and_no_unix_socket_is_reachable(self):
        profile = ad.sandbox_profile(Path("/tmp/x"), ad.claude_cli(), model_port=4321)
        self.assertIn('(allow network-outbound (remote ip "localhost:4321"))', profile)
        self.assertNotIn("unix-socket", profile)
        self.assertIn('(subpath "/Library")', profile)          # managed policies are not read either
        self.assertIn('(deny process-exec (subpath "/private/tmp/x")', profile)   # nothing the run wrote can be executed

    def test_a_cli_in_a_shared_folder_gets_only_its_own_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cli = Path(os.path.realpath(tmp)) / "bin" / "claude"
            cli.parent.mkdir()
            cli.write_text("")
            profile = ad.sandbox_profile(Path(tmp), str(cli))
            self.assertIn(f'(literal "{cli}")', profile)
            self.assertNotIn(f'(subpath "{cli.parent}")', profile)
            home_like = Path(os.path.realpath(tmp)) / "claude" / "claude"      # a home folder named claude
            home_like.parent.mkdir()
            home_like.write_text("")
            self.assertNotIn(f'(subpath "{home_like.parent}")', ad.sandbox_profile(Path(tmp), str(home_like)))

    def test_a_process_that_left_the_group_is_killed_too(self):
        marker = f"vulnix-leftover-{os.getpid()}"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(os.path.realpath(tmp)) / "project"
            root.mkdir()
            # forks, the child calls setsid() (out of the CLI's process group) and stays in the scratch run
            ad._run_confined(["/usr/bin/perl", "-e", f"use POSIX; if (fork) {{ select(undef,undef,undef,0.5); exit }} POSIX::setsid(); $0='{marker}'; sleep 60"],
                             cwd=root, env={"PATH": "/usr/bin:/bin"}, timeout_s=5, should_stop=None)
            time.sleep(0.5)
            left = subprocess.run(["/usr/bin/pgrep", "-f", marker], capture_output=True, text=True).stdout.strip()
            self.assertEqual(left, "")

    def test_a_hook_in_the_selected_settings_never_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "hook-ran"
            settings = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
                {"type": "command", "command": f"touch {marker}"}]}]}}
            kept, ignored = ad.sanitize_settings(settings)
            ad.run_attack({"settings.json": kept}, ad.ATTACKS[0], cli=ad.claude_cli(), timeout_s=60)
            self.assertFalse(marker.exists())
            self.assertIn("hooks", ignored)

    def test_stop_request_kills_the_run_and_reports_stopped(self):
        calls = []

        def should_stop():
            calls.append(1)
            return "権限が失効しました" if len(calls) > 1 else None
        report = ad.evaluate(Path("/nonexistent"), settings={}, ignored=[], should_stop=should_stop)
        self.assertEqual(report["status"], "stopped")
        self.assertEqual(report["reason"], "権限が失効しました")
        self.assertNotIn("results", report)

    def test_emergency_stop_generation_stops_a_settings_run(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"VULNIX_AGENT_DEFENSE_LOCAL": "1"}):
            report = ad.evaluate_settings('{"permissions": {}}', still_allowed=lambda: (ad.stop_all(), None)[1])
        self.assertEqual(report["status"], "stopped")
        self.assertEqual(report["settings_sha256"],
                         __import__("hashlib").sha256(b'{"permissions": {}}').hexdigest())
