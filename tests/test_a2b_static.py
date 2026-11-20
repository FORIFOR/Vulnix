"""A2B static analysis: bounded input reading, no network, no secret values in output."""
import ast
import io
import json
import socket
import struct
import subprocess
import unittest
import urllib.request
import zipfile
from pathlib import Path
from unittest.mock import patch

from aegis.a2b.manifest import A2BInputError, record_upload
from aegis.a2b.report import analyze_app
from aegis.a2b.static_analyzer import dex_strings, scan_apk

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "tests" / "fixtures" / "a2b" / "sample_app"
EXPECTED = json.loads((ROOT / "tests" / "fixtures" / "a2b" / "expected_endpoints.json").read_text())
# Fake values in provider formats are assembled at run time, so the repository never holds
# a string that a secret scanner (or a reader) could take for a real credential.
FAKE_AWS = "AKIA" + "FAKEFAKEFAKE0000"
FAKE_GOOGLE = "AIza" + "FAKEfake" * 4 + "123"
RAW_SECRETS = (FAKE_GOOGLE, "fixture-not-a-real-secret-0001", FAKE_AWS)


def make_dex(strings: list[str]) -> bytes:
    header = bytearray(0x70)
    header[:8] = b"dex\n035\x00"
    ids_off = 0x70
    data_off = ids_off + 4 * len(strings)
    ids, data = bytearray(), bytearray()
    for s in strings:
        raw = s.encode()
        ids += struct.pack("<I", data_off + len(data))
        n = len(s)
        uleb = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            uleb.append(b | (0x80 if n else 0))
            if not n:
                break
        data += uleb + raw + b"\x00"
    struct.pack_into("<II", header, 0x38, len(strings), ids_off)
    return bytes(header + ids + data)


def make_apk(extra: dict[str, bytes] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00binary-axml\x00\x00")
        z.writestr("classes.dex", make_dex([
            "Lcom/example/shop/ShopApi;", "v1/users/{userId}/orders", "v1/orders/{orderId}", "v1/orders",
            "v1/products", "internal/admin/stats", "https://api.shop-a2b.test/", "Authorization", "Bearer ",
            FAKE_AWS]))
        z.writestr("assets/config.json", (APP / "assets" / "config.json").read_bytes()
                   .replace(b"set-at-build-time", FAKE_GOOGLE.encode()))
        z.writestr("assets/index.android.bundle", (APP / "assets" / "index.android.bundle").read_bytes())
        z.writestr("res/raw/logo.png", b"\x89PNG....")
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return buf.getvalue()


def record(data: bytes, kind="apk"):
    return record_upload(data, filename="shop.apk", org_id="org_a", uploaded_by="alice", owner_attested=True,
                         kind=kind, clock=lambda: 1.0)


class NoNetwork:
    """Any network or process use during analysis fails the test."""
    def __enter__(self):
        self.calls = []

        def boom(name):
            def f(*a, **k):
                self.calls.append(name)
                raise AssertionError(f"{name} called during static analysis")
            return f
        self.patches = [patch.object(socket.socket, "connect", boom("socket.connect")),
                        patch.object(socket, "create_connection", boom("create_connection")),
                        patch.object(socket, "getaddrinfo", boom("getaddrinfo")),
                        patch.object(urllib.request, "urlopen", boom("urlopen")),
                        patch.object(subprocess, "Popen", boom("Popen"))]
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self.patches:
            p.stop()


class TestStaticAnalysis(unittest.TestCase):
    def test_source_tree_inventory_matches_the_expected_endpoints(self):
        with NoNetwork() as net:
            r = analyze_app(record=record(b"src", "source_tree"), source_dir=APP)
        self.assertEqual(net.calls, [])
        self.assertEqual([[e["method"], e["host"], e["path"]] for e in r["endpoints"]], EXPECTED["owner_endpoints"])
        self.assertEqual(r["third_party_hosts"], EXPECTED["third_party_hosts"])
        self.assertEqual(sorted({s["kind"] for s in r["secret_findings"]}), EXPECTED["secret_kinds"])
        self.assertEqual(sorted([k["class"], k["endpoint"]["path"]] for k in r["risk_candidates"]),
                         EXPECTED["risk_classes"])
        self.assertEqual(r["network_requests"], 0)

    def test_apk_dex_strings_and_assets_are_read_without_network(self):
        apk = make_apk()
        with NoNetwork() as net:
            r = analyze_app(record=record(apk), apk_bytes=apk)
        self.assertEqual(net.calls, [])
        paths = {(e["host"], e["path"]) for e in r["endpoints"]}
        self.assertIn(("api.shop-a2b.test", "/v1/users/{param}/orders"), paths)
        self.assertIn(("legacy.shop-a2b.test", "/api/coupons/redeem"), paths)
        self.assertTrue({"aws_access_key_id", "google_api_key"} <= {s["kind"] for s in r["secret_findings"]})
        self.assertIn("authorization_header", r["auth_hints"])

    def test_no_secret_value_reaches_the_report(self):
        apk = make_apk()
        for r in (analyze_app(record=record(apk), apk_bytes=apk),
                  analyze_app(record=record(b"s", "source_tree"), source_dir=APP)):
            text = json.dumps(r, ensure_ascii=False)
            for raw in RAW_SECRETS:
                self.assertNotIn(raw, text)
            self.assertTrue(all(s["fingerprint_hmac_sha256_12"] is None for s in r["secret_findings"]))
        keyed = analyze_app(record=record(apk), apk_bytes=apk, fingerprint_key=b"k" * 32)
        self.assertTrue(all(len(s["fingerprint_hmac_sha256_12"]) == 12 for s in keyed["secret_findings"]))

    def test_secrets_inside_url_paths_are_redacted(self):
        slack = "T0AAAAAAA/B0BBBBBBB/SuperSecretWebhookToken123"
        tg = "123456789:" + "AAH" + "secretTelegramTokenValue0123456789ab"
        stripe = "sk_" + "live_" + "51HabcdefghijklmnopQRSTUV"
        body = (f'{{"a": "https://hooks.slack.com/services/{slack}", "b": "https://api.telegram.org/bot{tg}/send",'
                f' "c": "https://api.shop-a2b.test/v1/data/{stripe}"}}').encode()
        apk = make_apk({"assets/hooks.json": body})
        r = analyze_app(record=record(apk), apk_bytes=apk)
        text = json.dumps(r)
        for raw in ("SuperSecretWebhookToken123", "AAHsecretTelegramTokenValue", stripe):
            self.assertNotIn(raw, text)
        self.assertIn("/v1/data/{secret}", {e["path"] for e in r["endpoints"]})
        self.assertTrue({"slack_webhook", "telegram_bot_token", "stripe_secret_key"}
                        <= {s["kind"] for s in r["secret_findings"]})

    def test_same_app_same_report(self):
        apk = make_apk()
        a = analyze_app(record=record(apk), apk_bytes=apk)
        b = analyze_app(record=record(apk), apk_bytes=apk)
        self.assertEqual(a["report_sha256"], b["report_sha256"])
        self.assertEqual(a, b)

    def test_credentials_in_urls_are_removed(self):
        apk = make_apk({"assets/x.json": b'{"u": "https://bob:hunter2pass@api.shop-a2b.test/v1/x"}'})
        r = analyze_app(record=record(apk), apk_bytes=apk)
        text = json.dumps(r)
        self.assertNotIn("hunter2pass", text)
        self.assertIn("url_credentials", {s["kind"] for s in r["secret_findings"]})


class TestHostileInput(unittest.TestCase):
    def test_owner_attestation_and_hash_binding(self):
        with self.assertRaises(A2BInputError):
            record_upload(b"x", filename="a.apk", org_id="o", uploaded_by="u", owner_attested=False)
        apk = make_apk()
        with self.assertRaisesRegex(A2BInputError, "ハッシュ"):
            analyze_app(record=record(b"other"), apk_bytes=apk)

    def test_not_a_zip(self):
        with self.assertRaises(A2BInputError):
            scan_apk(b"MZ\x90\x00 not an apk")

    def test_zip_bomb_member_is_skipped(self):
        apk = make_apk({"assets/bomb.json": b"0" * (5 << 20)})
        hints = scan_apk(apk)
        self.assertTrue(any(s.startswith("assets/bomb.json") for s in hints.skipped))

    def test_path_traversal_member_is_skipped(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("../../etc/x.json", b'{"a": "https://evil.shop-a2b.test/api/x"}')
        hints = scan_apk(buf.getvalue())
        self.assertEqual(hints.urls, [])
        self.assertTrue(hints.skipped)

    def test_broken_dex_is_reported_not_crashing(self):
        with self.assertRaises(A2BInputError):
            dex_strings(b"dex\n035\x00" + b"\xff" * 0x80)
        apk = make_apk({"classes2.dex": b"dex\n035\x00" + b"\xff" * 0x80})
        self.assertTrue(any("classes2.dex" in s for s in scan_apk(apk).skipped))

    def test_dex_entries_sharing_one_long_string_cannot_exhaust_memory(self):
        long = "A" * 200_000
        dex = bytearray(make_dex([long]))
        n = 2_000
        struct.pack_into("<II", dex, 0x38, n, len(dex))
        dex += struct.pack("<I", 0x70 + 4) * n          # every entry points at the same string
        strings = dex_strings(bytes(dex))
        self.assertEqual(len(strings), 1)
        self.assertLessEqual(len(strings[0]), 4096)

    def test_pathological_text_is_bounded(self):
        import time
        from aegis.a2b.static_analyzer import Hints, scan_text
        t0 = time.monotonic()
        scan_text("eyJ-" * 50_000 + " api" * 200_000, "x", Hints())
        self.assertLess(time.monotonic() - t0, 5.0)

    def test_malformed_urls_and_corrupt_members_do_not_crash(self):
        apk = make_apk({"assets/bad.js": b'fetch("http://[bad/api/x"); fetch("https://ok.shop-a2b.test/api/y")'})
        r = analyze_app(record=record(apk), apk_bytes=apk)
        self.assertIn("/api/y", {e["path"] for e in r["endpoints"]})
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
            z.writestr("assets/c.json", b'{"x": "https://crc.shop-a2b.test/api/z", "pad": "' + b"y" * 500 + b'"}')
        buf = bytearray(out.getvalue())
        buf[bytes(buf).find(b"y" * 50)] ^= 0xFF              # corrupt stored data -> CRC error on read
        hints = scan_apk(bytes(buf))
        self.assertTrue(any("unreadable" in s for s in hints.skipped), hints.skipped)

    def test_special_files_in_a_source_tree_are_not_opened(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            os.mkfifo(Path(tmp) / "pipe.js")
            r = analyze_app(record=record(b"s", "source_tree"), source_dir=tmp)
        self.assertTrue(any("not a regular file" in s for s in r["skipped"]))

    def test_symlinks_in_a_source_tree_are_not_followed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "outside.json"
            outside.write_text('{"x": "https://secret-host.shop-a2b.test/api/private"}')
            tree = Path(tmp) / "tree"
            tree.mkdir()
            (tree / "link.json").symlink_to(outside)
            r = analyze_app(record=record(b"s", "source_tree"), source_dir=tree)
        self.assertEqual(r["endpoints"], [])


class TestModuleHasNoNetworkCapability(unittest.TestCase):
    def test_a2b_modules_import_no_network_or_process_module(self):
        banned = {"socket", "ssl", "http", "urllib.request", "requests", "subprocess", "asyncio", "httpx"}
        for py in sorted(p for p in (ROOT / "aegis" / "a2b").glob("*.py") if not p.name.startswith(".")):
            tree = ast.parse(py.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for n in names:
                    self.assertFalse(n in banned or n.split(".")[0] in banned - {"urllib"}
                                     or n == "urllib.request", f"{py.name} imports {n}")


if __name__ == "__main__":
    unittest.main()
