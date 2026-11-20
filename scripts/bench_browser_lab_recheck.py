"""Exercise the lab-only post-fix browser flow at a 390px viewport.

Only loopback services are contacted. The pre-fix L2 run is authorized through
the existing control plane; the browser performs the post-fix action itself.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"
os.environ["VULNIX_EXTERNAL_PROPOSALS"] = "0"

from playwright.sync_api import sync_playwright  # noqa: E402

from aegis.assessment import AssessmentService  # noqa: E402
from aegis.lab import start_lab  # noqa: E402
from aegis.operators import OperatorStore, hash_password  # noqa: E402
from aegis.server import make_handler  # noqa: E402
from tests import TEST_CONFINEMENT  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_web(base: str, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("local Web server exited")
        try:
            with urllib.request.urlopen(base + "/login", timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("local Web server did not start")


def prepare_vulnerable_run(backend: ThreadingHTTPServer, password: str) -> dict:
    base = f"http://127.0.0.1:{backend.server_port}/api"
    cookie = None

    def request(path: str, body: dict | None = None) -> dict:
        nonlocal cookie
        headers = {"Content-Type": "application/json", "X-Aegis-Request": "1"}
        if cookie:
            headers["Cookie"] = cookie
        data = json.dumps(body).encode() if body is not None else None
        with urllib.request.urlopen(urllib.request.Request(base + path, data, headers), timeout=15) as response:
            if response.headers.get("Set-Cookie"):
                cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            return json.load(response)

    request("/auth/login", {"name": "qa", "password": password})
    path = "/assessments/scan_001"
    request(path + "/start", {})
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        snap = request(path)
        pending = next((a for a in snap["approvals"] if a["status"] == "pending"), None)
        if pending:
            request(path + "/approvals/" + pending["id"], {"decision": "approve"})
            break
        time.sleep(0.1)
    else:
        raise AssertionError("lab L2 approval was not requested")
    while time.monotonic() < deadline:
        snap = request(path)
        if snap["state"] == "completed":
            finding = next(f for f in snap["findings"] if f["id"] == "f_idor")
            assert finding["verdict"] == "proven"
            before = json.loads(finding["evidence"][-1]["content"])
            assert before["status"] == 200 and before["established"] is True
            return {"evidence_id": finding["evidence"][-1]["evidence_id"], "status": before["status"]}
        time.sleep(0.1)
    raise AssertionError("lab run did not complete")


def main() -> None:
    lab = start_lab(free_port(), "vulnerable")
    with tempfile.TemporaryDirectory() as tmp:
        data = Path(tmp)
        password = secrets.token_urlsafe(18)
        seed = data / "operators.json"
        seed.write_text(json.dumps({"operators": [{"name": "qa", "display": "QA",
            "roles": ["operator", "approver"], "password_hash": hash_password(password)}]}))
        svc = AssessmentService(data, lab.server_port, verify_seconds=0.05,
                                l2_confinement=TEST_CONFINEMENT)
        ops = OperatorStore(seed)
        backend = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(svc, ops))
        backend.daemon_threads = True
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        web_port = free_port()
        base = f"http://127.0.0.1:{web_port}"
        env = {**os.environ, "AEGIS_API": f"http://127.0.0.1:{backend.server_port}",
               "VULNIX_NO_ENV_LOCAL": "1"}
        web = subprocess.Popen([str(ROOT / "web/node_modules/.bin/next"), "start", "-H", "127.0.0.1",
                                "-p", str(web_port)], cwd=ROOT / "web", env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            before = prepare_vulnerable_run(backend, password)
            wait_for_web(base, web)
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                try:
                    page = browser.new_page(viewport={"width": 390, "height": 844})
                    errors: list[str] = []
                    page.on("pageerror", lambda e: errors.append(str(e)))
                    page.goto(base + "/login")
                    page.get_by_label("ユーザー名", exact=True).fill("qa")
                    page.get_by_label("パスワード", exact=True).fill(password)
                    page.get_by_role("button", name="ログイン", exact=True).click()
                    page.wait_for_url("**/dashboard")
                    page.goto(base + "/assessments/scan_001")
                    page.get_by_role("button", name="✓ 防御パッチ適用・再検証（修正前後の比較）").wait_for()
                    with page.expect_response(lambda response: response.url.endswith("/verify-fix")) as response:
                        page.get_by_role("button", name="✓ 防御パッチ適用・再検証（修正前後の比較）").click()
                    assert response.value.status == 200
                    after = response.value.json()
                    finding = next(f for f in after["findings"] if f["id"] == "f_idor")
                    latest = json.loads(finding["evidence"][-1]["content"])
                    assert finding["verdict"] == "not_reproduced"
                    assert latest["status"] == 403 and latest["established"] is False
                    assert before["evidence_id"] != finding["evidence"][-1]["evidence_id"]
                    page.get_by_text("✓ 修正前後の防御比較（実測）").wait_for()
                    page.get_by_text("proven →", exact=False).first.wait_for()
                    page.get_by_text("not_reproduced", exact=False).first.wait_for()
                    page.get_by_role("tab", name="結果").click()
                    page.locator("h3").filter(has_text="IDOR").locator("xpath=../..").get_by_role(
                        "link", name="詳しく見る →").click()
                    page.get_by_text("今回のアクセスは拒否されました").wait_for()
                    page.get_by_text("HTTP結果").wait_for()
                    page.get_by_text("403", exact=True).first.wait_for()
                    assert page.get_by_text("別アカウントのデータ取得を確認").count() == 0
                    page.get_by_text(before["evidence_id"], exact=True).first.wait_for()
                    page.get_by_text(finding["evidence"][-1]["evidence_id"], exact=True).first.wait_for()
                    prior_record = page.locator("details").filter(
                        has=page.locator("summary", has_text=before["evidence_id"]))
                    latest_record = page.locator("details").filter(
                        has=page.locator("summary", has_text=finding["evidence"][-1]["evidence_id"]))
                    prior_record.locator("summary").click()
                    latest_record.locator("summary").click()
                    assert '"status": 200' in prior_record.locator("pre").inner_text()
                    assert '"status": 403' in latest_record.locator("pre").inner_text()
                    assert "VULNIX_LAB_IDOR_PROVEN" in prior_record.locator("pre").inner_text()
                    assert "confidential_marker" not in latest["response"]
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                    assert not errors, errors
                    print(json.dumps({"viewport_width": 390, "before_verdict": "proven",
                                      "before_status": before["status"], "after_verdict": finding["verdict"],
                                      "after_status": latest["status"], "before_evidence_visible": True,
                                      "after_evidence_visible": True, "horizontal_overflow": False,
                                      "page_errors": len(errors)}, ensure_ascii=False, indent=2))
                finally:
                    browser.close()
        finally:
            web.terminate()
            try:
                web.wait(timeout=5)
            except subprocess.TimeoutExpired:
                web.kill()
                web.wait()
            svc.workers.kill_all()
            backend.shutdown()
            backend.server_close()
            svc.close()
            lab.shutdown()
            lab.server_close()


if __name__ == "__main__":
    main()
