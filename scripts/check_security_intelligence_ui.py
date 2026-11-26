"""Browser acceptance for Intelligence, with a real local API and synthetic findings."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import os
import re
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

from aegis import intelligence
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
            for asset in (service.a.asset, *service._extra_assets):
                if asset["name"] in ("lab.test", "api.lab.test"):
                    asset["project_label"] = "Synthetic intelligence project"
            for i in range(1, 6):
                service._extra_assets.append({
                    "id": f"synthetic-{i}", "name": f"synthetic-{i}.lab.test",
                    "kind": "API", "environment": "検証環境", "status": "未診断",
                })
        finding = {**rows[0], "id": "f_intelligence", "severity": "critical", "verdict": "candidate",
                   "title": "合成データ — TLSの確認候補", "demo_fixture": False, "evidence": [], "category": "暗号・TLS設定"}
        service._upsert_finding(finding)
        # Same-condition synthetic summaries are written through the real audited archive.
        for i, score in enumerate((43, 18)):
            intelligence.append(root / "intelligence-runs.json", {
                "run_id": f"ui-fixture-{i}", "asset_id": service.a.asset["id"], "asset": service.a.asset["name"],
                "org_id": "default", "at": time.time() - (2 - i) * 3600, "condition_id": "ui-fixture",
                "external": False, "evidence_hashes": [], "score": score, "findings": 1,
                "severity": {**dict.fromkeys(intelligence.SEVERITIES, 0), "critical": 1}, "counts": {"detected": 1},
            }, service.audit)
        ops = OperatorStore(seed)
        connections = []
        handler = make_handler(service, ops)

        class DisconnectableHandler(handler):
            def _sse_loop(self, *args):
                connections.append(self.connection)
                return super()._sse_loop(*args)

        backend = ThreadingHTTPServer(("127.0.0.1", 0), DisconnectableHandler)
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
        page.on("pageerror", lambda error: errors.append(error.stack or str(error)))
        page.goto(base + "/login")
        page.get_by_label("ユーザー名", exact=True).fill("reviewer")
        page.get_by_label("パスワード", exact=True).fill(password)
        page.get_by_role("button", name="ログイン", exact=True).click()
        page.wait_for_url("**/dashboard")
        page.goto(base + "/assessments/scan_001?tab=intelligence")
        expect(page.get_by_role("heading", name="Security Intelligence")).to_be_visible()
        expect(page.get_by_text("ライブ接続中", exact=False)).to_be_visible()
        comparison = page.get_by_role("region", name="修正前後の比較")
        expect(comparison.get_by_text("43/100", exact=True)).to_be_visible()
        expect(comparison.get_by_text("18/100", exact=True)).to_be_visible()
        topology = page.get_by_role("region", name="資産の関係")
        expect(topology.get_by_text("登録プロジェクト 1", exact=True)).to_be_visible()
        topology.get_by_role("button", name="次へ").click()
        expect(topology.get_by_text("synthetic-5.lab.test", exact=True)).to_be_visible()
        topology.get_by_role("button", name="前へ").click()
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
        page.go_back()
        expect(page.get_by_role("heading", name="Security Intelligence")).to_be_visible()
        service.audit.record("assessment.start_requested", actor="synthetic")
        with service._lock:
            service._set_state("running")
            phase = service.a.phases[0]
            service._phase(phase["key"], "running", "Synthetic activity")
        expect(page.get_by_role("region", name="診断アクティビティ").get_by_text(phase["label"])).to_be_visible()
        audited = service.audit.record("fixture.observation", case="intelligence")
        service._upsert_finding({**finding, "id": "f_audited", "severity": "medium", "verdict": "detected",
                                 "evidence": [{"evidence_id": "synthetic", "kind": "synthetic", "tool": "http_probe",
                                               "saved_at": audited["ts"], "audit_hash": audited["hash"], "content": "{}"}]})
        expect(page.get_by_role("img", name="所見・観測・監査の関係")).to_be_visible(timeout=12000)
        expect(page.get_by_role("img", name="悪用の根拠と所見の重大度の散布図")).to_be_visible(timeout=12000)
        if args.screenshots:
            page.screenshot(path=args.screenshots / "intelligence-observed.png", full_page=True, animations="disabled")
        page.evaluate("document.documentElement.classList.add('dark')")
        if args.screenshots:
            page.screenshot(path=args.screenshots / "intelligence-dark.png", full_page=True, animations="disabled")
        count = len(connections)
        connections[-1].shutdown(socket.SHUT_RDWR)
        expect(page.get_by_text(re.compile("再接続中|通信切断")).first).to_be_visible(timeout=10000)
        expect(page.get_by_text("ライブ接続中", exact=False)).to_be_visible(timeout=15000)
        assert len(connections) > count
        ops.logout(next(cookie["value"] for cookie in ctx.cookies(base) if cookie["name"] == "aegis_session"))
        connections[-1].shutdown(socket.SHUT_RDWR)
        expect(page.get_by_role("heading", name="Security Intelligence")).to_have_count(0, timeout=10000)
        assert not errors, errors
        print("PASS: 390/768/1440, chart filtering, SSE activity/reconnect/revocation, evidence graph, persisted comparison")


if __name__ == "__main__":
    main()
