"""Render the actual Cookie result component in Chromium at 390px, locally."""
from __future__ import annotations

import subprocess
from pathlib import Path

from playwright.sync_api import sync_playwright


WEB = Path(__file__).resolve().parents[1] / "web"
RENDER = r"""
const fs = require('node:fs');
const ts = require('typescript');
const React = require('react');
const {renderToStaticMarkup} = require('react-dom/server');
const source = fs.readFileSync('src/components/findings/CookieCheckList.tsx', 'utf8');
const js = ts.transpileModule(source, {compilerOptions: {
  target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX
}}).outputText;
const mod = {exports: {}};
new Function('require', 'module', 'exports', js)(require, mod, mod.exports);
process.stdout.write(renderToStaticMarkup(React.createElement(mod.exports.CookieCheckList, {checks: [
  {name: 'auth', purpose: 'session', verdict: 'detected', gaps: ['HttpOnly']},
  {name: 'lang', purpose: 'non_session', verdict: 'none', gaps: []},
  {name: 'unknown', purpose: 'unknown', verdict: 'candidate', gaps: ['Secure', 'HttpOnly']}
]})));
"""


def main() -> None:
    css_files = list((WEB / ".next/static/chunks").glob("*.css"))
    if not css_files:
        raise RuntimeError("Run npm run build in web/ first")
    markup = subprocess.run(["node", "-e", RENDER], cwd=WEB, check=True,
                            capture_output=True, text=True).stdout
    css = "\n".join(path.read_text() for path in css_files)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True)
        try:
            page = browser.new_page(viewport={"width": 390, "height": 844})
            page.set_content(f"<html lang='ja'><meta name='viewport' content='width=device-width, initial-scale=1'>"
                             f"<style>{css}</style><main style='max-width:390px;padding:16px'>{markup}</main></html>")
            group = page.get_by_label("Cookieごとの確認結果")
            assert group.is_visible()
            items = group.locator("li")
            assert items.count() == 3
            assert "属性不足・不一致を確認" in items.nth(0).inner_text()
            assert "一般用途" in items.nth(1).inner_text()
            assert "用途未確認" in items.nth(2).inner_text()
            assert "確認候補" in items.nth(2).inner_text()
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            print("PASS: actual Cookie component, 3 individual verdicts, 390px, no horizontal overflow")
        finally:
            browser.close()


if __name__ == "__main__":
    main()
