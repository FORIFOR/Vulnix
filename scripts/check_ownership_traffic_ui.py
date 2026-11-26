"""Offline browser acceptance for separately approved ownership traffic."""
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
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from playwright.sync_api import expect, sync_playwright

from aegis.assessment import AssessmentService
from aegis.operators import OperatorStore, hash_password
from aegis.server import make_handler

ROOT = Path(__file__).resolve().parents[1]
TARGET = "https://ownership.example.test/"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    if args.evidence:
        args.evidence.mkdir(mode=0o700, parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp, ExitStack() as cleanup:
        data = Path(tmp)
        password = secrets.token_urlsafe(18)
        seed = data / "operators.json"
        seed.write_text(json.dumps({"operators": [
            {"name": "runner", "roles": ["operator"], "password_hash": hash_password(password)},
            {"name": "reviewer", "roles": ["admin", "operator", "approver"], "password_hash": hash_password(password)},
        ]}))
        service = AssessmentService(data, 18081, real_site_read_only=True)
        cleanup.callback(service.close)
        cleanup.enter_context(patch.dict(os.environ, {"VULNIX_OWNERSHIP_TRAFFIC": "approved"}))
        cleanup.enter_context(patch.multiple("aegis.server", REAL_SITE_L1_ONLY=False, REAL_SERVICE_DIAGNOSIS=False))
        calls = cleanup.enter_context(patch("aegis.ownership.default_dns_txt_lookup"))
        backend = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(service, OperatorStore(seed)))
        backend.daemon_threads = True
        cleanup.callback(backend.server_close)
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        cleanup.callback(backend.shutdown)
        with socket.socket() as port_probe:
            port_probe.bind(("127.0.0.1", 0))
            port = port_probe.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        web = subprocess.Popen(
            [str(ROOT / "web/node_modules/.bin/next"), "start", "-H", "127.0.0.1", "-p", str(port)],
            cwd=ROOT / "web", env={**os.environ, "AEGIS_API": f"http://127.0.0.1:{backend.server_port}",
                                  "NEXT_TELEMETRY_DISABLED": "1"},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        cleanup.callback(web.wait, 5)
        cleanup.callback(web.terminate)
        playwright = cleanup.enter_context(sync_playwright())
        override = os.environ.get("VULNIX_TEST_CHROMIUM")
        browser = playwright.chromium.launch(**({"executable_path": override} if override else
                                                  {} if os.environ.get("CI") else {"channel": "chrome"}))
        cleanup.callback(browser.close)
        import urllib.request
        import time
        for _ in range(50):
            try:
                with urllib.request.urlopen(base + "/api/health", timeout=1) as response:
                    if response.status == 200:
                        break
            except OSError:
                if web.poll() is not None:
                    raise RuntimeError("Web app exited during startup") from None
                time.sleep(.2)
        for width in (390, 1440):
            # A different registered target per flow preserves the previous proof and audit.
            target = TARGET.replace("ownership.", f"ownership-{width}.")
            calls.reset_mock()
            height = 844 if width == 390 else 900
            width_options = {"viewport": {"width": width, "height": height},
                             "permissions": ["clipboard-read", "clipboard-write"]}
            if args.evidence:
                width_options["record_video_dir"] = str(args.evidence)
            runner = browser.new_context(**width_options)
            reviewer = browser.new_context(viewport={"width": width, "height": height})

            def sign_in(context, name):
                page = context.new_page()
                # The external service is never visited, even if the UI is miswired.
                context.route("**/*", lambda route: route.continue_() if route.request.url.startswith(base + "/") else route.abort())
                page.goto(base + "/login")
                page.get_by_label("ユーザー名", exact=True).fill(name)
                page.get_by_label("パスワード", exact=True).fill(password)
                page.get_by_role("button", name="ログイン", exact=True).click()
                page.wait_for_url("**/dashboard")
                return page

            def capture(page, label):
                if args.evidence:
                    dialog = page.get_by_role("dialog")
                    page.screenshot(path=args.evidence / f"{width}-{label}.png", mask=[dialog.locator("dd")])

            user_page = sign_in(runner, "runner")
            user_page.get_by_role("button", name="＋ サイトを診断する").click()
            user_page.get_by_label("診断するサイトのURL").fill(target)
            user_page.get_by_role("button", name="所有確認へ").click()
            chooser = user_page.get_by_role("dialog")
            expect(chooser.get_by_role("radio", name="Google", exact=True)).to_be_disabled()
            expect(chooser.get_by_role("radio", name="確認用ファイル", exact=True)).to_be_checked()
            with user_page.expect_download() as downloaded:
                chooser.get_by_role("link", name="確認用ファイルをダウンロード").click()
            assert downloaded.value.suggested_filename == "vulnix-verify.txt"
            asset = next(x for x in service.assets() if x.get("target_url") == target)
            content = Path(downloaded.value.path()).read_text()
            assert content == asset["challenge"]["well_known_content"]
            chooser.get_by_role("radio", name="DNS", exact=True).check()
            chooser.get_by_role("button", name="名前と値をまとめてコピー").click()
            expect(chooser.get_by_role("button", name="名前と値をコピーしました")).to_be_visible()
            assert user_page.evaluate("navigator.clipboard.readText()") == (
                asset["challenge"]["dns_txt_name"] + "\t" + asset["challenge"]["dns_txt_value"])
            expect(chooser.get_by_role("button", name="確認する", exact=True)).to_be_disabled()
            assert user_page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            # The target remains visible while using the setup controls further down.
            expect(chooser.get_by_text(target, exact=True)).to_be_in_viewport()
            chooser.locator(".overflow-y-auto").evaluate("el => { el.scrollTop = 0; }")
            expect(chooser.get_by_role("button", name="管理者に所有確認の許可を依頼する")).to_be_in_viewport()
            capture(user_page, "before-request")
            chooser.get_by_role("button", name="管理者に所有確認の許可を依頼する").click()
            expect(chooser.get_by_text("所有確認用の通信 申請中", exact=True)).to_be_visible()
            capture(user_page, "pending")
            calls.assert_not_called()

            admin_page = sign_in(reviewer, "reviewer")
            admin_page.get_by_role("button", name="所有確認を続ける", exact=False).click()
            admin_page.get_by_role("radio", name="DNS", exact=True).check()
            admin_page.get_by_role("button", name="この方法を15分間承認する").click()
            expect(chooser.get_by_text("所有確認用の通信 承認済み", exact=True)).to_be_visible(timeout=10000)
            capture(user_page, "approved")
            calls.assert_not_called()
            calls.return_value = [asset["challenge"]["dns_txt_value"]]
            chooser.get_by_role("button", name="確認する", exact=True).click()
            expect(chooser.get_by_text("所有確認が完了しました", exact=False)).to_be_visible()
            expect(chooser.get_by_role("button", name="診断範囲を保存", exact=True)).to_be_disabled()
            calls.assert_called_once_with(asset["challenge"]["dns_txt_name"])
            assert service._external_entry(asset["name"]) is None
            capture(user_page, "ownership-only")
            runner.close()
            reviewer.close()
        print(json.dumps({"viewport_widths": [390, 1440], "ownership_verified": True,
                          "diagnosis_granted": False, "external_traffic": False}))


if __name__ == "__main__":
    main()
