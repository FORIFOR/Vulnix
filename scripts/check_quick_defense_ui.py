"""Browser acceptance with synthetic files and a newly registered local user."""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import tempfile
import threading
import time
from pathlib import Path

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"
os.environ["VULNIX_EXTERNAL_PROPOSALS"] = "0"

from playwright.sync_api import expect, sync_playwright  # noqa: E402

from aegis.assessment import AssessmentService  # noqa: E402
from aegis.operators import OperatorStore, hash_password  # noqa: E402
from aegis.server import make_handler  # noqa: E402
from aegis.tenancy import OrgStore, TenantRegistry  # noqa: E402
from scripts.check_diagnosis_ui import Backend, free_port, wait_for_web  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp)
        seed = path / "operators.json"
        seed.write_text(json.dumps({"operators": [{"name": "platform-admin", "roles": ["admin"],
                                                  "password_hash": hash_password(secrets.token_urlsafe(20))}]}))
        ops = OperatorStore(seed)

        def new_service(org_path):
            return AssessmentService(org_path, 18081)

        svc = new_service(path)
        registry = TenantRegistry(OrgStore(path / "orgs.json", bootstrap_members=lambda: {}),
                                  svc, new_service, path)
        backend = Backend(free_port(), make_handler(svc, ops, tenancy=registry, public_signup=True))
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        port = free_port()
        base = f"http://127.0.0.1:{port}"
        web = subprocess.Popen(
            [str(ROOT / "web/node_modules/.bin/next"), "start", "-H", "127.0.0.1", "-p", str(port)],
            cwd=ROOT / "web",
            env={**os.environ, "AEGIS_API": f"http://127.0.0.1:{backend.server_port}", "NEXT_TELEMETRY_DISABLED": "1"},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            wait_for_web(base, web)
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch() if os.environ.get("CI") else playwright.chromium.launch(channel="chrome")
                page = browser.new_page(viewport={"width": 390, "height": 844})
                external = []
                page.route("**/*", lambda route: route.continue_() if route.request.url.startswith(base + "/")
                           else (external.append(route.request.url), route.abort()))
                page.goto(base + "/login")
                page.get_by_role("tab", name="新規アカウント登録").click()
                pw = secrets.token_urlsafe(20)
                page.locator("#reg-name").fill("quick-check-user")
                page.locator("#reg-pw").fill(pw)
                page.locator("#reg-confirm").fill(pw)
                page.get_by_role("button", name="アカウントを登録して開始").click()
                page.wait_for_url(re.compile(r".*/(dashboard|welcome).*"))
                page.goto(base + "/dashboard")
                started = time.monotonic()
                page.get_by_role("link", name="ローカルプロジェクトの診断").click()
                expect(page.get_by_role("checkbox")).to_have_count(3)
                assert all(item.is_checked() for item in page.get_by_role("checkbox").all())
                local_requests = []
                def track(req):
                    if req.resource_type in {"fetch", "xhr"}:
                        local_requests.append(req.url)
                evidence = {
                    "controls": {"saml": {"enabled": True, "evidence": "synthetic SSO test"},
                                 "accounts": {"enabled": False, "evidence": "synthetic policy"}},
                    "components": [{"vendor": "apache", "product": "http_server", "version": "2.4.49",
                                    "reviews": {"CVE-2021-41773": {"applies": True, "patched": False}}}],
                }
                page.get_by_label("設定・依存関係の証拠JSON").set_input_files(
                    {"name": "project-review.json", "mimeType": "application/json",
                     "buffer": json.dumps(evidence).encode()})
                page.get_by_label("JavaScript / JSXソース（任意）").set_input_files(
                    {"name": "sample.js", "mimeType": "text/javascript",
                     "buffer": b"element.innerHTML = suppliedText;"})
                expect(page.get_by_role("button", name="選択したソースを外す")).to_be_visible()
                lockfile = {"lockfileVersion": 3, "packages": {
                    "node_modules/demo": {"version": "1.2.3", "resolved": "http://registry.invalid/demo.tgz"},
                }}
                page.get_by_label("package-lock.json（任意）").set_input_files(
                    {"name": "package-lock.json", "mimeType": "application/json",
                     "buffer": json.dumps(lockfile).encode()})
                expect(page.get_by_role("button", name="選択したロックファイルを外す")).to_be_visible()
                page.on("request", track)
                page.get_by_role("button", name="ローカル検証を開始").click()
                expect(page.get_by_role("status").filter(has_text="対策が必要 3件")).to_be_visible()
                before = page.locator("section[aria-label='検証結果'] details").count()
                assert before == 12
                for category, count in (("ARTEX", 5), ("CVE", 2), ("Claude Code", 5)):
                    expect(page.locator("section[aria-label='検証結果'] summary")
                           .filter(has_text=re.compile(rf"^{category} ／"))).to_have_count(count)
                for summary in (
                    "ARTEX ／ SAML署名の強制 ／ 防御確認済み",
                    "ARTEX ／ npm依存関係の取得元 ／ 対策が必要",
                    "CVE ／ http_server 2.4.49 · CVE-2021-41773 ／ 対策が必要",
                    "CVE ／ http_server 2.4.49 · CVE-2021-42013 ／ 未確認",
                    "Claude Code ／ JavaScript / JSX のHTML書き込み候補 ／ 未確認",
                ):
                    expect(page.get_by_text(summary, exact=True)).to_be_visible()
                for label in ("防御確認済み 1件", "未確認 8件"):
                    expect(page.get_by_role("status").filter(has_text=label)).to_be_visible()
                elapsed = round(time.monotonic() - started, 2)
                page.get_by_text("Claude Code ／ 認証強化と試行制限 ／ 対策が必要", exact=True).click()
                expect(page.get_by_text("synthetic policy", exact=True)).to_be_visible()
                expect(page.get_by_text("管理者にMFAを必須にし、認証試行を制限する")).to_be_visible()
                evidence["controls"]["accounts"] = {"enabled": True, "evidence": "synthetic corrected policy"}
                page.get_by_label("証拠JSONを編集").fill(json.dumps(evidence))
                page.get_by_role("button", name="ローカル検証を開始").click()
                expect(page.get_by_role("status").filter(has_text="対策が必要 2件")).to_be_visible()
                expect(page.get_by_text("Claude Code ／ 認証強化と試行制限 ／ 防御確認済み", exact=True)).to_be_visible()
                feed = json.loads((ROOT / "aegis/feeds/nvd-recent.json").read_text())
                feed["vulnerabilities"] = feed["vulnerabilities"][:1]
                page.get_by_text("入力形式とCVEカタログの更新", exact=True).click()
                page.get_by_label("NVD JSONを手動で読み込む").set_input_files(
                    {"name": "nvd-recent.json", "mimeType": "application/json", "buffer": json.dumps(feed).encode()})
                expect(page.get_by_text("ローカルで使用するCVEカタログ　nvd-recent.json", exact=True)).to_be_visible()
                page.get_by_role("button", name="ローカル検証を開始").click()
                expect(page.locator("section[aria-label='検証結果'] details")).to_have_count(11)
                page.get_by_role("button", name="模擬データで試す").click()
                expect(page.get_by_role("heading", name="模擬データの結果")).to_be_visible()
                assert not external and not local_requests, (external, local_requests)
                page.goto(base + "/dashboard")
                page.get_by_role("button", name="隔離ラボを開く").click()
                page.wait_for_url("**/assessments/scan_001**")
                assert not external, external
                print(json.dumps({"actions_to_first_result": 5, "seconds_to_first_result": elapsed,
                                  "results": before, "recheck_passed": True, "mock_mode_passed": True,
                                  "scan_requests": 0, "feed_import_passed": True, "lab_workspace_opened": True}))
                browser.close()
        finally:
            web.terminate()
            web.wait(timeout=10)
            backend.shutdown()
            backend.drop_all()
            backend.server_close()
            registry.close_all()
            svc.close()


if __name__ == "__main__":
    main()
