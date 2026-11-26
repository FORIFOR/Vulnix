"""Browser acceptance for Intelligence, with a real local API and synthetic findings."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from urllib.error import URLError
from urllib.request import urlopen

from playwright.sync_api import expect, sync_playwright

from aegis.assessment import AssessmentService, _fixture_findings
from aegis.operators import OperatorStore, hash_password
from aegis.server import make_handler

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--screenshots", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp, ExitStack() as close:
        root = Path(tmp)
        password = secrets.token_urlsafe(24)
        seed = root / "operators.json"
        seed.write_text(json.dumps({"operators": [{"name": "reviewer", "roles": ["admin", "operator", "approver"],
                                                    "password_hash": hash_password(password)}]}))
        service = AssessmentService(root, 18081)
        close.callback(service.close)
        rows = _fixture_findings()
        with service._lock:
            service.a.findings.clear()
        finding = {**rows[0], "id": "f_intelligence", "severity": "critical", "verdict": "candidate",
                   "title": "合成データ — TLSの確認候補", "demo_fixture": False, "evidence": [], "category": "暗号・TLS設定"}
        service._upsert_finding(finding)
        backend = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(service, OperatorStore(seed)))
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        close.callback(backend.server_close)
        close.callback(backend.shutdown)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        web = subprocess.Popen(
            [str(ROOT / "web/node_modules/.bin/next"), "start", "-H", "127.0.0.1", "-p", str(port)],
            cwd=ROOT / "web", env={**os.environ, "AEGIS_API": f"http://127.0.0.1:{backend.server_port}", "NEXT_TELEMETRY_DISABLED": "1"},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        close.callback(web.wait, 5)
        close.callback(web.terminate)
        for _ in range(50):
            try:
                with urlopen(base + "/api/health", timeout=1) as response:  # noqa: S310 - loopback only
                    if response.status == 200:
                        break
            except URLError:
                time.sleep(0.2)

        browser_core = close.enter_context(sync_playwright())
        browser = browser_core.chromium.launch(**({} if os.environ.get("CI") else {"channel": "chrome"}))
        close.callback(browser.close)
        ctx = browser.new_context(reduced_motion="reduce")
        ctx.route("**/*", lambda route: route.continue_() if route.request.url.startswith(base + "/") else route.abort())
        page = ctx.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(base + "/login")
        page.get_by_label("ユーザー名", exact=True).fill("reviewer")
        page.get_by_label("パスワード", exact=True).fill(password)
        page.get_by_role("button", name="ログイン", exact=True).click()
        page.wait_for_url("**/dashboard")
        page.goto(base + "/assessments/scan_001?tab=intelligence")
        expect(page.get_by_role("heading", name="Security Intelligence")).to_be_visible()
        expect(page.get_by_text("ライブ接続中", exact=False)).to_be_visible()
        for width, height in ((390, 844), (768, 1024), (1440, 900)):
            page.set_viewport_size({"width": width, "height": height})
            donut = page.get_by_role("img", name="重大度別ドーナツグラフ")
            expect(donut.locator("svg path").first).to_be_visible()
            expect(page.get_by_role("img", name="重大度と証拠状態のマトリクス").locator("svg").first).to_be_visible()
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
            if args.screenshots:
                args.screenshots.mkdir(mode=0o700, parents=True, exist_ok=True)
                page.screenshot(path=args.screenshots / f"intelligence-{width}.png", full_page=True, animations="disabled")
        donut.scroll_into_view_if_needed()
        donut.click(position={"x": donut.bounding_box()["width"] / 2 + 72, "y": 120})
        page.wait_for_url("**?tab=findings&severity=critical")
        expect(page.get_by_text("絞り込み結果：1 件", exact=True)).to_be_visible()
        page.go_back()
        expect(page.get_by_role("heading", name="Security Intelligence")).to_be_visible()
        service._upsert_finding({**finding, "id": "f_intelligence_second", "title": "合成データ — 追加候補"})
        expect(page.get_by_role("link", name="CRITICAL 2", exact=True)).to_be_visible()
        tree = page.get_by_role("img", name="カテゴリ別ツリーマップ")
        tree.scroll_into_view_if_needed()
        tree.click(position={"x": tree.bounding_box()["width"] / 2, "y": 110})
        page.wait_for_url("**?tab=findings&category=*")
        expect(page.get_by_text("絞り込み結果：2 件", exact=True)).to_be_visible()
        assert not errors, errors
        print("PASS: 390/768/1440, chart-to-results navigation, category chart, SSE updates")


if __name__ == "__main__":
    main()
