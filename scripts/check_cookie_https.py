"""Local HTTPS/Chromium check of Cookie attributes and L1 verdicts.

Creates a one-day throwaway TLS certificate, contacts only loopback, and never
reads repository credentials or invokes an external model.
"""
from __future__ import annotations

import json
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

from aegis.service_diag import analyze_l1_service_response
from tests.fixtures.cookie_purpose_lab import CookiePurposeLab


ROOT = Path(__file__).resolve().parents[1]
OWNER = json.loads((ROOT / "tests/fixtures/cookie_owner_specs.json").read_text())
TRUTH = json.loads((ROOT / "tests/fixtures/cookie_purpose_truth.json").read_text())
MODES = ("session_full", "session_no_httponly", "session_no_secure",
         "session_no_samesite", "session_samesite_none_mismatch",
         "session_samesite_none_policy")


def main() -> None:
    rows = []
    with tempfile.TemporaryDirectory(prefix="vulnix-cookie-https-") as tmp:
        cert = Path(tmp) / "certificate.pem"
        private = Path(tmp) / "private.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(private), "-out", str(cert), "-subj", "/CN=localhost",
                        "-days", "1"], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(private))
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="chrome", headless=True)
            try:
                for mode in MODES:
                    site = CookiePurposeLab(mode)
                    site.socket = context.wrap_socket(site.socket, server_side=True)
                    thread = threading.Thread(target=site.serve_forever, daemon=True)
                    thread.start()
                    page_context = browser.new_context(ignore_https_errors=True,
                                                       viewport={"width": 390, "height": 844})
                    try:
                        url = f"https://127.0.0.1:{site.server_port}/"
                        page = page_context.new_page()
                        response = page.goto(url, wait_until="load")
                        assert response is not None and response.status == 200
                        raw = response.header_value("set-cookie")
                        assert raw and raw.startswith("auth=")
                        observed = {"status": 200, "headers": {"set-cookie": raw},
                                    "set_cookies": [raw]}
                        findings = analyze_l1_service_response(
                            observed, {"audit_hash": "local-https-proof", "saved_at": 1},
                            url, cookie_policy=OWNER[mode])
                        finding = next((f for f in findings if f["id"] == "f_l1_cookies"), None)
                        verdict = finding["verdict"] if finding else "none"
                        assert verdict == TRUTH[mode], (mode, verdict, TRUTH[mode])
                        cookies = [c for c in page_context.cookies([url]) if c["name"] == "auth"]
                        assert len(cookies) == 1, (mode, cookies)
                        cookie = cookies[0]
                        visible = "auth=" in page.evaluate("document.cookie")
                        assert cookie["secure"] == ("; Secure" in raw), mode
                        assert cookie["httpOnly"] == ("; HttpOnly" in raw), mode
                        assert visible == ("; HttpOnly" not in raw), mode
                        if "; SameSite=None" in raw:
                            assert cookie["sameSite"] == "None", mode
                        if "; SameSite=Lax" in raw:
                            assert cookie["sameSite"] == "Lax", mode
                        assert site.seen.count("/") == 1, (mode, site.seen)
                        rows.append({"mode": mode, "verdict": verdict,
                                     "browser_secure": cookie["secure"],
                                     "browser_http_only": cookie["httpOnly"],
                                     "browser_same_site": cookie["sameSite"],
                                     "document_cookie_visible": visible,
                                     "root_get": site.seen.count("/")})
                    finally:
                        page_context.close()
                        site.shutdown()
                        site.server_close()
                        thread.join(timeout=2)
            finally:
                browser.close()
    print(json.dumps({"viewport": 390, "https_loopback_only": True, "rows": rows},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
