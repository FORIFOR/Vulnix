"""nftables egress ruleset generation + guarded apply.

The ruleset builder is fully tested here. Applying it to a live kernel needs
Linux + root + nft and is NOT exercised; we test only that the apply path is
correctly gated (raises off Linux, calls nft on Linux)."""
import unittest

from aegis import netfilter


class TestRuleset(unittest.TestCase):
    def test_default_drop_and_pinned_allow_v4(self):
        rs = netfilter.ruleset_for("127.0.0.1", 18081)
        self.assertIn("policy drop;", rs)
        self.assertIn('oif "lo" accept', rs)
        self.assertIn("ct state established,related accept", rs)
        self.assertIn("ip daddr 127.0.0.1 tcp dport 18081 ct state new accept", rs)
        # Cloud metadata / link-local are explicitly dropped.
        self.assertIn("ip daddr 169.254.0.0/16 drop", rs)

    def test_pinned_allow_v6(self):
        rs = netfilter.nft_ruleset([("::1", 443)])
        self.assertIn("ip6 daddr ::1 tcp dport 443 ct state new accept", rs)

    def test_allow_lines_come_after_hard_deny(self):
        rs = netfilter.ruleset_for("10.0.0.5", 80)
        self.assertLess(rs.index("169.254.0.0/16 drop"),
                        rs.index("10.0.0.5 tcp dport 80"))

    def test_rejects_bad_ip(self):
        with self.assertRaises(ValueError):
            netfilter.nft_ruleset([("not-an-ip", 80)])


class TestApplyGating(unittest.TestCase):
    def test_raises_off_linux(self):
        with self.assertRaises(NotImplementedError):
            netfilter.apply_ruleset("table inet x {}", assume_linux=False)

    def test_calls_nft_on_linux(self):
        calls = {}

        class FakeProc:
            returncode = 0
            stderr = ""

        def runner(argv, **kw):
            calls["argv"] = argv
            calls["input"] = kw.get("input")
            return FakeProc()

        netfilter.apply_ruleset("RULES", runner=runner, assume_linux=True)
        self.assertEqual(calls["argv"], ["nft", "-f", "-"])
        self.assertEqual(calls["input"], "RULES")

    def test_raises_on_nft_failure(self):
        class FakeProc:
            returncode = 1
            stderr = "syntax error"

        with self.assertRaises(OSError):
            netfilter.apply_ruleset("RULES", runner=lambda *a, **k: FakeProc(), assume_linux=True)

    def test_supported_reflects_platform(self):
        self.assertTrue(netfilter.supported("linux"))
        self.assertFalse(netfilter.supported("darwin"))


class TestCheckRuleset(unittest.TestCase):
    def test_raises_when_nft_missing(self):
        with self.assertRaises(FileNotFoundError):
            netfilter.check_ruleset("table inet x {}", nft="")

    def test_runs_check_mode_not_apply(self):
        calls = {}

        class Ok:
            returncode = 0
            stderr = ""

        def runner(argv, **kw):
            calls["argv"] = argv
            calls["input"] = kw.get("input")
            return Ok()

        rs = netfilter.ruleset_for("127.0.0.1", 80)
        self.assertTrue(netfilter.check_ruleset(rs, runner=runner, nft="/sbin/nft"))
        self.assertEqual(calls["argv"], ["/sbin/nft", "-c", "-f", "-"])   # -c = check only
        self.assertEqual(calls["input"], rs)

    def test_syntax_error_raises(self):
        class Bad:
            returncode = 1
            stderr = "Error: syntax error"

        with self.assertRaises(OSError):
            netfilter.check_ruleset("garbage", runner=lambda *a, **k: Bad(), nft="/sbin/nft")


if __name__ == "__main__":
    unittest.main()
