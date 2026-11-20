"""CVE matcher: version ranges, banner detection, detection-is-not-proof."""
import json
import unittest

from aegis import cve


class TestVersion(unittest.TestCase):
    def test_in_range(self):
        self.assertTrue(cve.version_in_range("2.4.49", {"eq": "2.4.49"}))
        self.assertFalse(cve.version_in_range("2.4.50", {"eq": "2.4.49"}))
        self.assertTrue(cve.version_in_range("2.4.50", {"ge": "2.4.49", "lt": "2.4.51"}))
        self.assertFalse(cve.version_in_range("2.4.51", {"ge": "2.4.49", "lt": "2.4.51"}))
        self.assertFalse(cve.version_in_range("2.4.48", {"ge": "2.4.49", "lt": "2.4.51"}))

    def test_parse_handles_suffixes(self):
        self.assertEqual(cve.parse_version("2.4.49"), (2, 4, 49))
        self.assertEqual(cve.parse_version("2.4"), (2, 4))


class TestMatch(unittest.TestCase):
    def test_http_server_2449_matches_both(self):
        ids = {c.id for c in cve.match("http_server", "2.4.49")}
        self.assertEqual(ids, {"CVE-2021-41773", "CVE-2021-42013"})

    def test_http_server_2450_matches_only_incomplete_fix(self):
        ids = {c.id for c in cve.match("http_server", "2.4.50")}
        self.assertEqual(ids, {"CVE-2021-42013"})

    def test_http_server_patched_matches_none(self):
        self.assertEqual(cve.match("http_server", "2.4.52"), [])

    def test_unknown_product(self):
        self.assertEqual(cve.match("nginx", "1.0.0"), [])


class TestFeedIngestion(unittest.TestCase):
    def test_catalog_is_ingested_from_feed_file(self):
        # The live CATALOG comes from the bundled NVD-format feed, not hardcode.
        self.assertTrue(cve.FEED_PATH.exists())
        feed = cve.load_feed()
        self.assertEqual({c.id for c in feed}, {"CVE-2021-41773", "CVE-2021-42013"})
        self.assertEqual({c.id for c in cve.CATALOG}, {"CVE-2021-41773", "CVE-2021-42013"})
        # Product key is the real NVD CPE product.
        self.assertTrue(all(c.product == "http_server" for c in feed))

    def test_banner_alias_resolves_to_cpe_product(self):
        # Server header says "Apache"; catalog keys on "http_server".
        cands = cve.detect_from_banner("Apache/2.4.49 (Unix)")
        self.assertEqual({c.cve.id for c in cands}, {"CVE-2021-41773", "CVE-2021-42013"})

    def test_missing_feed_falls_back_to_builtin(self):
        from pathlib import Path
        self.assertEqual({c.id for c in cve.load_feed(Path("/no/such/feed.json"))}, set())


class TestBanner(unittest.TestCase):
    def test_detect_from_banner(self):
        cands = cve.detect_from_banner("Apache/2.4.49 (Unix)")
        self.assertEqual({c.cve.id for c in cands}, {"CVE-2021-41773", "CVE-2021-42013"})

    def test_detection_is_not_proof(self):
        for c in cve.detect_from_banner("Apache/2.4.49"):
            self.assertEqual(c.verdict, "detected")   # never "proven"
            self.assertFalse(c.verified)

    def test_patched_banner_no_candidates(self):
        self.assertEqual(cve.detect_from_banner("Apache/2.4.52"), [])

    def test_catalog_has_no_payloads(self):
        # Metadata-only guard: catalog carries descriptions/remediation, never
        # exploit code fields.
        for c in cve.CATALOG:
            self.assertTrue(c.remediation)
            self.assertFalse(hasattr(c, "exploit"))
            self.assertFalse(hasattr(c, "payload"))


class TestNvdLoader(unittest.TestCase):
    FIXTURE = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2021-41773",
                "descriptions": [{"lang": "en", "value": "Path traversal in Apache 2.4.49"},
                                 {"lang": "es", "value": "ignored"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]},
                "weaknesses": [{"description": [{"value": "CWE-22"}]}],
                "references": [{"url": "https://httpd.apache.org/"}],
                "configurations": [{"nodes": [{"cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "2.4.49",
                    "versionEndExcluding": "2.4.51",
                }]}]}],
            }
        }, {
            "cve": {"id": "CVE-9999-0001", "descriptions": [],
                    "configurations": []}       # no usable range -> skipped
        }]
    }

    def test_parses_nvd_json(self):
        cves = cve.load_nvd(self.FIXTURE)
        self.assertEqual(len(cves), 1)           # the range-less one is skipped
        c = cves[0]
        self.assertEqual(c.id, "CVE-2021-41773")
        self.assertEqual(c.product, "http_server")
        self.assertEqual(c.severity, "critical")
        self.assertEqual(c.cwe, "CWE-22")
        self.assertTrue(c.applies_to("2.4.50"))
        self.assertFalse(c.applies_to("2.4.51"))
        self.assertFalse(c.applies_to("2.4.48"))

    def test_loaded_catalog_matches(self):
        catalog = tuple(cve.load_nvd(self.FIXTURE))
        self.assertEqual([c.id for c in cve.match("http_server", "2.4.50", catalog)],
                         ["CVE-2021-41773"])
        self.assertEqual(cve.match("http_server", "2.4.51", catalog), [])

    def test_empty_feed(self):
        self.assertEqual(cve.load_nvd({}), [])


class TestCisaKevAndFeedMonitor(unittest.TestCase):
    def test_kev_catalog_loaded(self):
        self.assertTrue(cve.KEV_PATH.exists())
        self.assertIn("CVE-2021-41773", cve.KEV_CATALOG)
        self.assertIn("CVE-2021-42013", cve.KEV_CATALOG)
        entry = cve.KEV_CATALOG["CVE-2021-41773"]
        self.assertEqual(entry.vendor, "Apache")
        self.assertEqual(entry.date_added, "2021-11-03")

    def test_feed_monitor_correlates_assets_and_marks_kev(self):
        mon = cve.FeedMonitor()
        res = mon.correlate_assets([
            {"id": "scan_001", "domain": "example.com", "banner": "Apache/2.4.49 (Unix)"},
            {"id": "scan_002", "domain": "api.example.com", "banner": "Apache/2.4.52 (Unix)"},
        ])
        self.assertEqual(len(res["scan_001"]), 2)
        self.assertEqual(res["scan_002"], [])
        first = res["scan_001"][0]
        self.assertTrue(first["kev_exploited"])
        self.assertEqual(first["verdict"], "detected")
        self.assertFalse(first["verified"])

    def test_feed_monitor_ingest_and_sync_urls(self):
        mon = cve.FeedMonitor()
        kev_payload = {
            "vulnerabilities": [{
                "cveID": "CVE-2026-0001",
                "vendorProject": "Example",
                "product": "Server",
                "vulnerabilityName": "Example KEV",
                "dateAdded": "2026-01-01",
                "dueDate": "2026-01-15",
                "knownRansomwareCampaignUse": "Unknown",
            }]
        }
        status = mon.sync_from_urls(
            kev_url="https://feed.example/kev.json",
            fetcher=lambda url: json.dumps(kev_payload).encode(),
        )
        self.assertIn("CVE-2026-0001", mon.kev)
        self.assertGreaterEqual(status["kev_count"], 3)
        self.assertEqual(status["sync_count"], 1)
        self.assertEqual(status["freshness"], "fresh")
        self.assertFalse(status["stale"])
        self.assertIsNotNone(status["kev_sha256"])
        self.assertIsNone(status["last_sync_error"])

    def test_sync_failure_preserves_previous_catalog_and_tracks_freshness(self):
        mon = cve.FeedMonitor()
        mon.ingest_payloads(nvd_obj={"vulnerabilities": []})   # a real sync first (starting up is not one)
        prev_synced_at = mon.last_synced_at
        prev_count = len(mon.catalog)
        prev_nvd_sha = mon.nvd_sha256

        def failing_fetcher(_url: str) -> bytes:
            raise OSError("network unreachable")

        status = mon.sync_from_urls(nvd_url="https://feed.example/nvd.json", fetcher=failing_fetcher)
        self.assertEqual(status["cve_count"], prev_count)
        self.assertEqual(status["last_synced_at"], prev_synced_at)
        self.assertEqual(status["nvd_sha256"], prev_nvd_sha)
        self.assertIn("OSError", status["last_sync_error"])
        self.assertIsNotNone(status["last_error_at"])

        # After STALE_SECONDS, status reports stale=True and freshness="stale"
        stale_status = mon.status(now=prev_synced_at + cve.STALE_SECONDS + 10)
        self.assertTrue(stale_status["stale"])
        self.assertEqual(stale_status["freshness"], "stale")

        # Empty/unfetched monitor reports freshness="unfetched"
        empty_mon = cve.FeedMonitor(catalog=(), kev={})
        empty_mon.last_synced_at = 0.0
        unfetched_status = empty_mon.status()
        self.assertEqual(unfetched_status["freshness"], "unfetched")

    def test_starting_the_process_is_not_a_sync(self):
        # the bundled feed is whatever shipped with the code: it must not read as just fetched
        mon = cve.FeedMonitor()
        status = mon.status()
        self.assertIsNone(status["last_synced_at"])
        self.assertEqual(status["freshness"], "unfetched")
        self.assertEqual(status["sync_count"], 0)

    def test_an_empty_or_unrecognised_payload_never_makes_a_stale_feed_fresh(self):
        mon = cve.FeedMonitor()
        good = {"vulnerabilities": []}            # a real "nothing new" answer has the list
        mon.ingest_payloads(nvd_obj=good)
        synced = mon.last_synced_at
        later = synced + cve.STALE_SECONDS + 10
        self.assertEqual(mon.status(now=later)["freshness"], "stale")
        before = (mon.nvd_sha256, len(mon.catalog), mon.sync_count)
        for bad in ({}, {"totalResults": 0}, {"vulnerabilities": "x"}):
            st = mon.ingest_payloads(nvd_obj=bad)
            self.assertEqual(mon.last_synced_at, synced, bad)
            self.assertEqual((mon.nvd_sha256, len(mon.catalog), mon.sync_count), before, bad)
            self.assertEqual(st["last_sync_error"], "unrecognised_nvd_payload", bad)
            self.assertEqual(mon.status(now=later)["freshness"], "stale", bad)
        st = mon.ingest_payloads(kev_obj={})
        self.assertEqual(st["last_sync_error"], "unrecognised_kev_payload")
        self.assertEqual(mon.last_synced_at, synced)

    def test_a_valid_nothing_new_answer_is_a_sync(self):
        mon = cve.FeedMonitor()
        st = mon.ingest_payloads(nvd_obj={"vulnerabilities": []}, kev_obj={"vulnerabilities": []})
        self.assertEqual(st["freshness"], "fresh")
        self.assertEqual(st["sync_count"], 1)
        self.assertIsNone(st["last_sync_error"])

    def test_service_diag_three_conditions_applicable_non_applicable_and_unknown_version(self):
        from aegis.service_diag import analyze_l1_service_response

        mon = cve.FeedMonitor()
        ev = {"evidence_id": "ev_cve", "audit_hash": "h", "saved_at": 1.0}
        base_headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
        }

        # 1. Applicable version (Apache/2.4.49) -> detected (never proven), CVE IDs attached
        res_applicable = {"status": 200, "headers": {**base_headers, "Server": "Apache/2.4.49"}, "tls": {"version": "TLSv1.3"}}
        f_app = next(f for f in analyze_l1_service_response(res_applicable, ev, "https://svc.example/", mon) if f["id"] == "f_powered")
        self.assertEqual(f_app["verdict"], "detected")
        self.assertEqual(f_app["severity"], "high")
        self.assertEqual(set(f_app["cve"]), {"CVE-2021-41773", "CVE-2021-42013"})
        self.assertIn("検出・未実証", f_app["summary"])

        # 2. Non-applicable version (Apache/2.4.58) -> low severity info disclosure, no CVE match, not claimed globally safe
        res_patched = {"status": 200, "headers": {**base_headers, "Server": "Apache/2.4.58"}, "tls": {"version": "TLSv1.3"}}
        f_pat = next(f for f in analyze_l1_service_response(res_patched, ev, "https://svc.example/", mon) if f["id"] == "f_powered")
        self.assertEqual(f_pat["verdict"], "detected")
        self.assertEqual(f_pat["severity"], "low")
        self.assertEqual(f_pat["cve"], [])
        self.assertIn("既知バナー一致なし", f_pat["summary"])

        # 3. Unknown version (Apache without version or custom PHP without version) -> explicitly states CVE correlation is undetermined
        res_unknown = {"status": 200, "headers": {**base_headers, "Server": "Apache", "X-Powered-By": "Express"}, "tls": {"version": "TLSv1.3"}}
        f_unk = next(f for f in analyze_l1_service_response(res_unknown, ev, "https://svc.example/", mon) if f["id"] == "f_powered")
        self.assertEqual(f_unk["verdict"], "detected")
        self.assertEqual(f_unk["severity"], "low")
        self.assertEqual(f_unk["cve"], [])
        self.assertIn("バージョン番号が含まれないためCVE照合は未判定", f_unk["summary"])

        # 4. Unfetched CVE feed -> explicitly states feed is unfetched, not "no CVE match"
        empty_mon = cve.FeedMonitor(catalog=(), kev={})
        f_unfetched = next(f for f in analyze_l1_service_response(res_applicable, ev, "https://svc.example/", empty_mon) if f["id"] == "f_powered")
        self.assertEqual(f_unfetched["cve"], [])
        self.assertIn("CVEフィード未取得のためCVE照合は未実施", f_unfetched["summary"])


if __name__ == "__main__":
    unittest.main()
