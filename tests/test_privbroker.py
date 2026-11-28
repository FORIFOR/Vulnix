"""The privilege broker (aegis/privbroker.py) is the only program the service may run
as root. These tests check that it refuses everything outside its fixed operations and
arguments. They run as an ordinary user: every refusal happens before anything that
would need root. The operations themselves run on the real kernel in
tests/test_release_safety.py and tests/test_fail_closed.py (Linux, through the broker).
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis import privbroker as pb
from aegis.confinement import KernelConfinement

ROOT = Path(__file__).resolve().parent.parent
NAME = "aegis_l2_0123456789ab"
UID = str(KernelConfinement.UID_RANGE[0] + 12345)


def run_broker(*args, env=None):
    """The broker as the installed wrapper runs it: a separate `python3 -I -B` process."""
    return subprocess.run([sys.executable, "-I", "-B", str(ROOT / "aegis" / "privbroker.py"), *args],
                          capture_output=True, text=True, timeout=30, env=env or {"PATH": "/usr/bin:/bin"})


class TestOnlyFixedOperations(unittest.TestCase):
    def test_unknown_operations_and_free_commands_are_refused(self):
        for argv in ([], ["sh", "-c", "id"], ["/bin/sh"], ["exec", "id"], ["true"], ["nft", "flush", "ruleset"],
                     ["ip", "link"], ["setpriv", "--reuid=0", "id"], ["CHECK"]):
            with self.subTest(argv=argv):
                r = run_broker(*argv)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn("refused", r.stderr)

    def test_wrong_argument_counts_are_refused(self):
        for argv in (["cgroup-create"], ["cgroup-create", NAME, "x"], ["nft-list"], ["own-dir", UID],
                     ["cgroup-limit", NAME, "pids.max"]):
            with self.subTest(argv=argv):
                self.assertEqual(pb.main(argv), 2)

    def test_run_names_must_be_the_confinement_pattern(self):
        for bad in ("x", "aegis_l2_0123", "aegis_l2_0123456789ab;id", "../../etc", "aegis_l2_0123456789AB",
                    'aegis_l2_0123456789ab" accept', "aegis_l2_0123456789ab\n"):
            for op in ("cgroup-create", "cgroup-kill", "cgroup-remove", "nft-list", "nft-delete",
                       "netns-add", "netns-delete"):
                with self.subTest(op=op, name=bad):
                    self.assertEqual(pb.main([op, bad]), 2)

    def test_cgroup_limits_only_the_two_keys_and_plain_numbers(self):
        for key, value in (("cpu.max", "1"), ("cgroup.procs", "1"), ("../cgroup.procs", "1"),
                           ("pids.max", "1;id"), ("pids.max", "-1"), ("pids.max", "0"), ("memory.max", "max"),
                           ("memory.max", "01")):
            with self.subTest(key=key, value=value):
                self.assertEqual(pb.main(["cgroup-limit", NAME, key, value]), 2)

    def test_nft_rules_are_built_by_the_broker_and_refuse_metadata_and_odd_endpoints(self):
        for eps in (["169.254.169.254,80"], ["0.0.0.1,80"], ["fe80::1,443"], ["203.0.113.7,0"],
                    ["203.0.113.7:443"], ["not-an-ip,443"], ["203.0.113.7,443;id"], []):
            with self.subTest(eps=eps):
                self.assertEqual(pb.main(["nft-apply", NAME, *eps]), 2)


class TestWorkerUids(unittest.TestCase):
    def test_only_unassigned_uids_in_the_worker_range(self):
        lo, hi = KernelConfinement.UID_RANGE
        for bad in ("0", str(os.getuid()), str(lo - 1), str(hi), "-1", "1e9", " 3000000001", "3000000001x", ""):
            with self.subTest(uid=bad), self.assertRaises(pb.Refused):
                pb._run_uid(bad)
        self.assertEqual(pb._run_uid(UID), int(UID))

    def test_a_uid_that_belongs_to_an_account_is_refused(self):
        with patch.object(pb.pwd, "getpwuid", lambda u: object()), self.assertRaises(pb.Refused):
            pb._run_uid(UID)
        with patch.object(pb.grp, "getgrgid", lambda u: object()), self.assertRaises(pb.Refused):
            pb._run_uid(UID)

    def test_every_uid_taking_operation_refuses_root(self):
        d = tempfile.mkdtemp()
        self.addCleanup(os.rmdir, d)
        for argv in (["own-dir", "0", d], ["remove-dir", "0", d], ["purge-dir", "0", d], ["purge-tmp", "0"],
                     ["relay", NAME, "0", "8080"],
                     ["launch", NAME, "0", "5", "-", "-", "--", "/usr/bin/id"]):
            with self.subTest(argv=argv[0]):
                self.assertEqual(pb.main(argv), 2)


class TestLaunch(unittest.TestCase):
    def plan(self, *args, environ=None):
        with patch.object(pb, "_tool", lambda t: f"/usr/bin/{t}"), \
                patch.dict(os.environ, environ or {}, clear=False):
            return pb.plan_launch(list(args))

    def test_the_program_always_runs_as_the_run_uid_without_privileges(self):
        name, cpu, argv, env = self.plan(NAME, UID, "7", "-", "-", "--", "/usr/bin/python3", "-c", "x")
        self.assertEqual((name, cpu), (NAME, 7))
        self.assertEqual(argv[0], "/usr/bin/setpriv")
        for flag in (f"--reuid={UID}", f"--regid={UID}", "--clear-groups", "--inh-caps=-all",
                     "--bounding-set=-all", "--no-new-privs"):
            self.assertIn(flag, argv[:7])
        self.assertEqual(argv[7:], ["/usr/bin/python3", "-c", "x"])
        self.assertEqual(env, {"PATH": "/usr/bin:/bin"})

    def test_only_the_named_worker_variables_are_handed_on_under_their_own_names(self):
        _, _, _, env = self.plan(NAME, UID, "7", "TOKEN_A,X", "-", "--", "/usr/bin/w",
                                 environ={"VXENV_TOKEN_A": "s1", "VXENV_X": "s2", "VXENV_OTHER": "no",
                                          "LD_PRELOAD": "/tmp/evil.so", "TOKEN_A": "unprefixed"})
        self.assertEqual(env, {"PATH": "/usr/bin:/bin", "TOKEN_A": "s1", "X": "s2"})

    def test_malformed_launch_requests_are_refused(self):
        bad = [
            [NAME, UID, "7", "-", "-", "/usr/bin/w"],                       # no "--"
            [NAME, UID, "7", "-", "-", "--", "w"],                          # relative program
            [NAME, UID, "0", "-", "-", "--", "/usr/bin/w"],                 # cpu
            [NAME, UID, "7", "PATH", "-", "--", "/usr/bin/w"],              # PATH is the broker's
            [NAME, UID, "7", "A=B", "-", "--", "/usr/bin/w"],
            [NAME, UID, "7", "LD_PRELOAD;X", "-", "--", "/usr/bin/w"],
            [NAME, UID, "7", "-", "{not json", "--", "/usr/bin/w"],
            [NAME, UID, "7", "-", json.dumps({"hide": ["tmp"], "keep": []}), "--", "/usr/bin/w"],
            [NAME, UID, "7", "-", json.dumps({"hide": ["/tmp/../etc"], "keep": []}), "--", "/usr/bin/w"],
            [NAME, UID, "7", "-", json.dumps({"hide": ["/"], "keep": []}), "--", "/usr/bin/w"],
            [NAME, UID, "7", "-", json.dumps({"hide": [], "keep": []}), "--", "/usr/bin/w"],
            [NAME, UID, "7", "-", json.dumps({"hide": ["/tmp"], "keep": [], "run": "id"}), "--", "/usr/bin/w"],
            [NAME, UID, "7", "-", json.dumps({"hide": ["/tmp\nid"], "keep": []}), "--", "/usr/bin/w"],
        ]
        for args in bad:
            with self.subTest(args=args), self.assertRaises((pb.Refused, ValueError)):
                self.plan(*args)

    def test_namespace_mode_needs_the_runs_own_namespace_and_quotes_every_path(self):
        ns = json.dumps({"hide": ["/tmp", "/home"], "keep": ["/tmp/a b'; id #"]})
        with tempfile.TemporaryDirectory() as nd, patch.object(pb, "NETNS_DIR", Path(nd)):
            with self.assertRaises(pb.Refused):
                self.plan(NAME, UID, "7", "-", ns, "--", "/usr/bin/w")
            (Path(nd) / NAME).write_text("")
            _, _, argv, _ = self.plan(NAME, UID, "7", "-", ns, "--", "/usr/bin/w")
        self.assertEqual(argv[:4], ["/usr/bin/ip", "netns", "exec", NAME])
        script = argv[argv.index("-c") + 1]
        self.assertIn("'/tmp/a b'\"'\"'; id #'", script)              # quoted, never a command
        self.assertLess(argv.index("netns"), argv.index("/usr/bin/setpriv"))   # mounts before the drop
        self.assertEqual(argv[-1], "/usr/bin/w")

    def test_relay_runs_the_installed_relay_not_a_staged_copy(self):
        self.assertEqual(pb.RELAY, (ROOT / "aegis" / "workers" / "_ns_relay.py").resolve())
        with tempfile.TemporaryDirectory() as nd, patch.object(pb, "NETNS_DIR", Path(nd)):
            self.assertEqual(pb.main(["relay", NAME, UID, "8080"]), 2)            # no such namespace
            (Path(nd) / NAME).write_text("")
            for ports in (["0"], ["70000"], ["80;id"], []):
                self.assertEqual(pb.main(["relay", NAME, UID, *ports]), 2)


class TestDirectories(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.base)]))

    def test_paths_must_be_absolute_and_normal(self):
        for bad in ("relative", "/", "/tmp/../etc", "/tmp//x", "/tmp/x/", "/tmp/x\n", "/tmp/./x"):
            with self.subTest(path=bad), self.assertRaises(pb.Refused):
                pb._abs_path(bad)

    def test_a_symlink_anywhere_on_the_path_is_refused(self):
        real = self.base / "real"
        (real / "run").mkdir(parents=True)
        (self.base / "link").symlink_to(real)
        for argv in (["own-dir", UID, str(self.base / "link" / "run")], ["own-dir", UID, str(self.base / "link")],
                     ["remove-dir", UID, str(self.base / "link" / "run")]):
            with self.subTest(argv=argv):
                self.assertEqual(pb.main(argv), 2)

    def test_only_the_callers_own_empty_directory_is_given_away(self):
        full = self.base / "full"
        full.mkdir()
        (full / "x").write_text("x")
        self.assertEqual(pb.main(["own-dir", UID, str(full)]), 2)            # not empty
        empty = self.base / "empty"
        empty.mkdir()
        with patch.object(pb, "_caller_uid", lambda: os.getuid() + 1):
            self.assertEqual(pb.main(["own-dir", UID, str(empty)]), 2)       # not the caller's (and unsafe parent)
        f = self.base / "file"
        f.write_text("")
        self.assertEqual(pb.main(["own-dir", UID, str(f)]), 2)               # not a directory

    def test_an_ancestor_writable_by_others_is_refused(self):
        open_dir = self.base / "open"
        (open_dir / "run").mkdir(parents=True)
        open_dir.chmod(0o777)                                                # no sticky bit
        self.assertEqual(pb.main(["own-dir", UID, str(open_dir / "run")]), 2)


class TestCleanupRunsAsTheRunUid(unittest.TestCase):
    """purge-dir / purge-tmp build a real command (a TypeError here once left every run's
    files behind: files_left in the ARTEX CI job)."""

    def test_the_purges_run_find_as_the_run_uid_with_their_own_timeout(self):
        seen = []

        def fake_run(argv, **kw):
            seen.append((argv, kw))
            return subprocess.CompletedProcess(argv, 0, "", "")
        with patch.object(pb.subprocess, "run", fake_run), patch.object(pb, "_tool", lambda t: f"/usr/bin/{t}"):
            self.assertEqual(pb.main(["purge-dir", UID, "/tmp/x"]), 0)
            self.assertEqual(pb.main(["purge-tmp", UID]), 0)
        self.assertEqual(len(seen), 1 + len(pb.SHARED_TMP))
        for argv, kw in seen:
            self.assertEqual(argv[0], "/usr/bin/setpriv")
            self.assertIn(f"--reuid={UID}", argv)
            self.assertIn("/usr/bin/find", argv)
            self.assertEqual(kw["timeout"], 60)
        self.assertEqual(seen[0][0][-5:], ["/tmp/x", "-xdev", "-mindepth", "1", "-delete"])


class TestInstallation(unittest.TestCase):
    DEPLOY = ROOT / "deploy" / "debian13"

    def test_sudoers_allows_only_the_broker_without_setenv(self):
        rules = [ln for ln in (self.DEPLOY / "vulnix-sudoers").read_text().splitlines()
                 if ln.strip() and not ln.lstrip().startswith("#")]
        grants = [ln for ln in rules if not ln.startswith("Defaults")]
        self.assertEqual(grants, ["vulnix ALL=(root) NOPASSWD: /usr/local/libexec/vulnix-priv"])
        text = "\n".join(rules)
        for forbidden in ("SETENV", "/sh", "/bash", "ALL:", "nft", "/ip", "setpriv", "env_keep += \"*\"", "!env_reset"):
            self.assertNotIn(forbidden, text)
        self.assertIn('env_keep = "VXENV_*"', text)

    def test_the_wrapper_runs_the_installed_broker_isolated(self):
        lines = [ln for ln in (self.DEPLOY / "vulnix-priv").read_text().splitlines()
                 if ln.strip() and not ln.startswith("#")]
        self.assertEqual(lines, ['exec /usr/bin/python3 -I -B /opt/vulnix/backend/aegis/privbroker.py "$@"'])

    def test_the_service_names_the_installed_broker(self):
        unit = (self.DEPLOY / "vulnix-backend.service").read_text()
        self.assertIn("Environment=VULNIX_PRIV_BROKER=/usr/local/libexec/vulnix-priv", unit)

    def test_the_service_runs_no_root_command_but_the_broker(self):
        """Every privileged command line the confinement builds goes to the broker."""
        calls = []
        conf = KernelConfinement(runner=lambda a, **k: calls.append(list(a)) or subprocess.CompletedProcess(a, 1, "", ""),
                                 platform="linux", euid=1000, which=lambda t: f"/usr/bin/{t}",
                                 broker="/usr/local/libexec/vulnix-priv")
        conf.interpreter_reachable_by_others = lambda: ""
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "cgroup.controllers").write_text("cpu")
            conf._root = Path(root)
            with patch("os.path.isfile", lambda p: True):
                conf.status()
                try:
                    with conf.session("203.0.113.7", 443):
                        pass
                except Exception:
                    pass
        self.assertTrue(calls)
        for c in calls:
            self.assertEqual(c[:3], ["/usr/bin/sudo", "-n", "/usr/local/libexec/vulnix-priv"], c)
            self.assertIn(c[3], pb.OPS)


if __name__ == "__main__":
    unittest.main()
