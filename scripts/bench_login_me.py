"""Measure login-page session requests against a local Next.js dev server.

Requires Python Playwright and Chrome. Start `npm run dev -- --port 3211` in web/.
The only API response is intercepted; the script never calls a real site.
"""
import json
import time

from playwright.sync_api import sync_playwright

URL = "http://127.0.0.1:3211/login"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
SESSION = {
    "session": None,
    "self_registration": True,
    "google_ownership": False,
    "multi_tenant": False,
    "development": False,
}

with sync_playwright() as playwright:
    browser = playwright.chromium.launch(executable_path=CHROME, headless=True)
    page = browser.new_page(viewport={"width": 390, "height": 844})
    calls = []

    def handle(route):
        calls.append(route.request.url)
        route.fulfill(status=200, content_type="application/json", body=json.dumps(SESSION))

    page.route("**/api/auth/me", handle)
    start = time.monotonic()
    page.goto(URL, wait_until="networkidle")
    page.get_by_role("tab", name="新規アカウント登録").wait_for(timeout=10000)
    if len(calls) > 2:
        raise AssertionError(f"login requested session {len(calls)} times")
    print(json.dumps({
        "me_calls": len(calls), "tab_visible": True,
        "elapsed_s": round(time.monotonic() - start, 3), "viewport": 390,
    }))
    browser.close()
