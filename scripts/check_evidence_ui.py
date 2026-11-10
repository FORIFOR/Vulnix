"""Read-only UI regression check for an isolated local demo (requires Playwright).

Creates a fresh browser profile. It logs in only with the generated demo account,
reads findings, tests navigation/export, and never starts a diagnostic worker.
"""
import argparse
import re
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

parser = argparse.ArgumentParser()
parser.add_argument("--url", default="http://127.0.0.1:3107")
parser.add_argument("--credentials", type=Path, required=True)
parser.add_argument("--screenshots", type=Path)
args = parser.parse_args()
if urlsplit(args.url).hostname not in {"127.0.0.1", "localhost"}:
    parser.error("Only an isolated loopback demo is supported")
password = re.search(r"ユーザー名: operator\nパスワード: (\S+)", args.credentials.read_text())[1]
base = args.url.rstrip("/") + "/assessments/scan_001"

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True)
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(args.url + "/login")
    page.get_by_label("ユーザー名", exact=True).fill("operator")
    page.get_by_label("パスワード", exact=True).fill(password)
    page.get_by_role("button", name="ログイン", exact=True).click()
    page.wait_for_url("**/dashboard")
    page.goto(base)
    overview = page.get_by_role("region", name="証拠の概要")
    expect(overview).to_be_visible()
    overview.get_by_role("link", name=re.compile("未計測の候補")).click()
    expect(page).to_have_url(re.compile("tab=findings&evidence=candidate"))
    expect(page.get_by_role("status")).to_contain_text("未計測の候補")
    page.get_by_role("link", name="絞り込みを解除").click()
    expect(page).to_have_url(re.compile(r"\?tab=findings$"))
    page.go_back()
    expect(page.get_by_role("status")).to_contain_text("未計測の候補")
    page.go_forward()
    expect(page).to_have_url(re.compile(r"\?tab=findings$"))
    page.goto(base + "?tab=invalid&evidence=invalid")
    expect(page.get_by_role("tab", name="診断", exact=True)).to_have_attribute("aria-selected", "true")
    export = page.get_by_role("button", name="⇩ 診断レポート出力 (Markdown)")
    report_url = "**/api/assessments/scan_001/report"
    page.route(report_url, lambda route: route.fulfill(status=503, json={"error": "QA: temporary unavailable"}), times=1)
    export.click()
    expect(page.locator("p[role=alert]")).to_contain_text("レポートを出力できませんでした")
    expect(export).to_be_enabled()
    with page.expect_download() as download:
        export.click()
    contents = Path(download.value.path()).read_text()
    assert "証拠の概要と検証範囲" in contents
    assert "安全性の保証ではありません" in contents
    expect(page.locator("p[role=alert]")).to_have_count(0)
    page.get_by_text("レポートプレビューを表示", exact=True).click()
    expect(page.locator("details[open]")).to_have_count(1)
    page.get_by_text("レポートプレビューを表示", exact=True).click()
    expect(page.locator("details[open]")).to_have_count(0)
    comparison = page.get_by_role("heading", name=re.compile("修正前後の防御比較"))
    if comparison.count():
        comparison.scroll_into_view_if_needed()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth && window.scrollX === 0"), "Horizontal desktop overflow"
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(args.screenshots / "evidence-desktop.png"))
    page.set_viewport_size({"width": 390, "height": 844})
    expect(overview).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "Horizontal mobile overflow"
    if args.screenshots:
        page.screenshot(path=str(args.screenshots / "evidence-mobile.png"))
    assert not errors, errors
    browser.close()
print("PASS: filter/reset/back/forward, invalid query, export failure/retry/download, preview close, mobile layout, no page errors")
