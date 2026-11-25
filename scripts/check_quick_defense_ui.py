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
from scripts.quick_defense_holdout import write_fixture  # noqa: E402

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
                refresh_requests = []
                def catalog_refresh(route):
                    request = route.request
                    refresh_requests.append((request.method, request.post_data))
                    route.fulfill(json=[
                        {"source": "NVD", "fetchedAt": "2026-01-02T00:00:00.000Z", "scope": "テスト", "records": []},
                        {"source": "npm", "fetchedAt": "2026-01-02T00:00:00.000Z", "scope": "テスト", "failed": True},
                    ])
                page.route("**/api/catalog/refresh", catalog_refresh)
                update_details = page.get_by_text("CVEカタログの更新", exact=True)
                update_details.click()
                page.get_by_role("button", name="NVD・OSVの公式データを取得").click()
                expect(page.get_by_text("更新失敗：npm", exact=False)).to_be_visible()
                expect(page.get_by_text("NVD ／ 0件 ／ テスト", exact=False)).to_be_visible()
                assert refresh_requests == [("POST", None)]
                page.reload()
                update_details.click()
                expect(page.get_by_text("NVD ／ 0件 ／ テスト", exact=False)).to_be_visible()
                assert refresh_requests == [("POST", None)]
                update_details.click()
                folder = path / "sample-project"
                folder.mkdir()
                preparation_start = time.monotonic()
                (folder / "package.json").write_text('{"dependencies":{"express":"5.1.0"}}')
                (folder / "Dockerfile").write_text("FROM httpd:2.4.49\n")
                lock = folder / "package-lock.json"
                def lock_version(version):
                    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
                        "node_modules/fixture-dependency": {"version": version, "integrity": "sha512-synthetic",
                            "resolved": "https://registry.example.invalid/fixture.tgz"},
                    }}))
                lock_version("1.2.3")
                # Valid lock data above the prior 256 KiB per-file limit.
                lock.write_text(lock.read_text() + " " * (300 * 1024))
                hidden = folder / ".env"
                hidden.write_text("SYNTHETIC_PRIVATE_VALUE=never-display-this")
                generated = folder / "node_modules" / "generated"
                generated.mkdir(parents=True)
                (generated / "auth.ts").write_text("function render(req, el) { el.innerHTML = req.query.name; }")
                (folder / "database").mkdir()
                (folder / "database" / "dataAccess.ts").write_text(
                    "function display(request, target) { const value = request.body.title; target.innerHTML = value; }")
                (folder / "too-large.ts").write_text(" " * (256 * 1024 + 1))
                template = folder / "cloudformation.json"
                def cloud(endpoint, token):
                    template.write_text(json.dumps({"Resources": {"Launch": {"Type": "AWS::EC2::LaunchTemplate",
                        "Properties": {"LaunchTemplateData": {"MetadataOptions": {
                            "HttpEndpoint": endpoint, "HttpTokens": token}}}}}}))
                cloud("enabled", "optional")
                preparation = time.monotonic() - preparation_start
                posted = []
                page.on("request", lambda req: posted.append(req.method) if req.method != "GET" else None)
                picker = page.get_by_label("プロジェクトフォルダを選択")
                start = page.get_by_role("button", name="ローカル検証を開始")
                section = page.get_by_role("region", name="検証結果")
                measured = []
                def scan(expected, unknown):
                    scan_start = time.monotonic()
                    picker.set_input_files(folder)
                    start.click()
                    expect(section).to_be_visible()
                    elapsed = time.monotonic() - scan_start
                    for category, title in (("ARTEX", "EC2起動テンプレートのメタデータ保護"),
                                            ("Claude Code", "外部入力とHTML出力")):
                        status = unknown if category == "Claude Code" and unknown else expected
                        expect(section.get_by_text(f"{category} ／ {title} ／ {status}", exact=True)).to_be_visible()
                    expect(section.get_by_text("CVE ／ CVE-2021-41773 ／ 未確認", exact=True)).to_be_visible()
                    assert "never-display-this" not in page.locator("body").inner_text()
                    expect(section.get_by_text("対象外 2件 ／ ファイル上限 1件", exact=False)).to_be_visible()
                    expect(section.get_by_text("Claude Code ／ 外部入力とHTML出力", exact=False)).to_have_count(1)
                    measured.append(round(elapsed, 3))
                scan("対策が必要", "")
                finding = section.get_by_text("Claude Code ／ 外部入力とHTML出力 ／ 対策が必要", exact=True)
                finding.click()
                expect(finding.locator("..").get_by_text("修正方法", exact=True)).to_be_visible()
                expect(finding.locator("..").get_by_text("database/dataAccess.ts:1", exact=True)).to_be_visible()
                cloud("enabled", "required")
                (folder / "database" / "dataAccess.ts").write_text(
                    "function display(request, target) { const value = request.body.title; target.textContent = value; }")
                storage = folder / "storage-template.json"
                storage.write_text(json.dumps({"Resources": {"Storage": {"Type": "AWS::S3::Bucket",
                    "Properties": {"PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True, "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
                    }}}}}))
                scan("防御確認済み", "")
                expect(section.get_by_text("Claude Code ／ ストレージの公開防止 ／ 防御確認済み", exact=True)).to_be_visible()
                cloud({"Ref": "Endpoint"}, {"Ref": "TokenMode"})
                (folder / "database" / "dataAccess.ts").write_text(
                    "function display(value, target) { target.innerHTML = normalize(value); }")
                storage.write_text(json.dumps({"Resources": {"Storage": {"Type": "AWS::S3::Bucket"}}}))
                scan("未確認", "未確認")
                expect(section.get_by_text("Claude Code ／ ストレージの公開防止 ／ 未確認", exact=True)).to_be_visible()
                page.get_by_text("CVEカタログの更新", exact=True).click()
                feed = page.get_by_label("NVD・OSVのJSONを手動で読み込む")
                def import_catalog(data):
                    feed.set_input_files({"name": "catalog.json", "mimeType": "application/json",
                                          "buffer": json.dumps(data).encode()})
                compound = {"format": "NVD_CVE", "version": "2.0", "vulnerabilities": [{"cve": {
                    "id": "CVE-2099-31415", "configurations": [{"operator": "AND", "nodes": [
                        {"operator": "OR", "cpeMatch": [{"vulnerable": True,
                            "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]},
                        {"operator": "OR", "cpeMatch": [{"vulnerable": False,
                            "criteria": "cpe:2.3:o:fixture:runtime:1.2:*:*:*:*:*:*:*"}]},
                    ]}]}}]}
                import_catalog(compound)
                expect(page.get_by_text("選択したNVDデータ", exact=False)).to_be_visible()
                start.click()
                missing = section.get_by_text("CVE ／ CVE-2099-31415 ／ 未確認", exact=True)
                missing.click()
                expect(section.get_by_text("必要な構成条件の一部", exact=False)).to_be_visible()
                sbom = folder / "fixture-sbom.json"
                sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [
                    {"cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
                    {"cpe": "cpe:2.3:o:fixture:runtime:1.2:*:*:*:*:*:*:*"},
                ]}))
                picker.set_input_files(folder)
                start.click()
                section.get_by_text("CVE ／ CVE-2099-31415 ／ 未確認", exact=True).click()
                expect(section.get_by_text("製品・版・構成条件の組み合わせ", exact=False)).to_be_visible()
                advisory = {"id": "CVE-2099-27182", "affected": [
                    {"package": {"ecosystem": "npm", "name": "fixture-dependency"}, "versions": ["1.2.3"]},
                ]}
                import_catalog(advisory)
                expect(page.get_by_text("選択したOSVデータ", exact=False)).to_be_visible()
                start.click()
                expect(section.get_by_text("CVE ／ CVE-2099-27182 ／ 対策が必要", exact=True)).to_be_visible()
                lock_version("1.2.4")
                picker.set_input_files(folder)
                start.click()
                expect(section.get_by_text("CVE ／ 依存関係と公開CVEの照合 ／ 未確認", exact=True)).to_be_visible()
                holdout = path / "defense-holdout"
                catalog = write_fixture(holdout)
                (holdout / "gitleaks-redacted.json").write_text(json.dumps([
                    {"RuleID": "github-pat", "File": "literal.ts", "StartLine": 3, "Secret": "REDACTED"},
                    {"RuleID": "github-pat", "File": "/outside/project.ts", "StartLine": 1},
                ]))
                import_catalog(catalog)
                expect(page.get_by_text("選択したOSVデータ", exact=False)).to_be_visible()
                holdout_start = time.monotonic()
                picker.set_input_files(holdout)
                start.click()
                expect(section).to_be_visible()
                holdout_seconds = round(time.monotonic() - holdout_start, 3)
                expected_holdout = [
                    ("Claude Code", "エージェントのツール権限", "対策が必要", ".claude/settings.json:3"),
                    ("ARTEX", "管理ポートの公開範囲", "対策が必要", "cloudformation.json:3"),
                    ("ARTEX", "APIの試行回数制限", "防御確認済み", "cloudformation.json:16"),
                    ("ARTEX", "SAML署名要件の明示設定", "防御確認済み", "auth-options.ts:2"),
                    ("ARTEX", "SAML署名要件の明示設定", "未確認", "auth-options.ts:3"),
                    ("ARTEX", "XML外部実体・DTD設定", "対策が必要", "auth-options.ts:5"),
                    ("ARTEX", "Kubernetesの外向き通信", "対策が必要", "network-policy.json:12"),
                    ("ARTEX", "Kubernetesの権限範囲", "未確認", "role-manifest.json:7"),
                    ("ARTEX", "コンテナの既定ユーザー", "対策が必要", "Dockerfile:2"),
                    ("Claude Code", "外部入力とHTML出力", "対策が必要", "database/render.ts:3"),
                    ("Claude Code", "外部入力とHTML出力", "防御確認済み", "database/render.ts:7"),
                    ("Claude Code", "Gitleaksの資格情報候補", "未確認", "literal.ts:3"),
                    ("Claude Code", "ソース内の秘密鍵形式", "未確認", "literal.ts:2"),
                    ("CVE", "CVE-2099-40101", "対策が必要", "package-lock.json:12"),
                    ("CVE", "CVE-2099-40102", "対策が必要", "requirements.txt:1"),
                    ("CVE", "CVE-2099-40103", "対策が必要", "go.mod:5"),
                ]
                for category, label, verdict, location in expected_holdout:
                    summary = section.get_by_text(f"{category} ／ {label} ／ {verdict}", exact=True)
                    summary.click()
                    expect(summary.locator("..").get_by_text(location, exact=True)).to_be_visible()
                expect(section.get_by_text("CVE-2099-40104", exact=False)).to_have_count(0)
                expect(section.get_by_text("Claude Code ／ Gitleaksの資格情報候補", exact=False)).to_have_count(1)
                assert "SYNTHETIC_ONLY" not in section.inner_text()
                assert "REDACTED" not in section.inner_text()
                assert "/outside" not in section.inner_text()
                assert not external and not posted, (external, posted)
                print(json.dumps({"actions_to_start_from_dashboard": 3, "actions_per_recheck": 2,
                                  "scan_seconds": measured, "fixture_preparation_seconds": round(preparation, 3),
                                  "external_requests": len(external), "upload_requests": len(posted),
                                  "expected_artifact_classifications": 15, "holdout_classifications": 17,
                                  "holdout_seconds": holdout_seconds}, ensure_ascii=False))
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
