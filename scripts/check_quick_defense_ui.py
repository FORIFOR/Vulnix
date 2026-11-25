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
                update_route = base + "/api/catalog/refresh"
                update_headers = {"Origin": base, "X-Aegis-Request": "1", "X-Vulnix-Catalog": "npm"}
                assert page.request.post(update_route, headers=update_headers).status == 401
                assert page.request.post(update_route, headers=update_headers, data="unexpected input").status == 400
                assert page.request.post(update_route, headers={**update_headers, "Origin": "https://example.invalid"}).status == 403
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
                archive = {"id": "CVE-2018-27182", "affected": [
                    {"package": {"ecosystem": "npm", "name": name}, "ranges": [
                        {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.4"}]},
                    ]} for name in ("fixture-dependency", "fixture-transitive")
                ]}

                update_mode = ["initial"]

                def catalog_refresh(route):
                    request = route.request
                    source = request.headers.get("x-vulnix-catalog")
                    refresh_requests.append((request.method, request.post_data, source))
                    if source == "npm":
                        advisory = {"id": archive["id"], "withdrawn": "2026-01-03T00:00:00Z"} if update_mode[0] == "withdrawn" else archive
                        lines = [advisory, {"complete": 1, "publishedAt": "2026-01-02T00:00:00Z"}]
                        if update_mode[0] == "truncated":
                            lines = [archive]
                        route.fulfill(content_type="application/x-ndjson", body="".join(json.dumps(line) + "\n" for line in lines))
                    else:
                        route.fulfill(status=503)

                page.route("**/api/catalog/refresh", catalog_refresh)
                update_details = page.get_by_text("CVEカタログの更新", exact=True)
                update_details.click()
                page.get_by_role("button", name="NVD・OSVの公式データを取得").click()
                expect(page.get_by_text("更新失敗 PyPI・Go", exact=False)).to_be_visible(timeout=15000)
                assert all(method == "POST" and body is None for method, body, _ in refresh_requests)
                assert {source for _, _, source in refresh_requests} >= {"npm", "PyPI", "Go", "NVD-2002"}
                attempts = len(refresh_requests)
                page.reload()
                update_details.click()
                page.get_by_text("提供元・年別の収録件数と取得日時", exact=True).click()
                expect(page.get_by_text("npm ／ 1件 ／ 索引 1件", exact=False)).to_be_visible()
                assert len(refresh_requests) == attempts
                update_details.click()
                folder = path / "sample-project"
                folder.mkdir()
                preparation_start = time.monotonic()
                (folder / "package.json").write_text('{"dependencies":{"express":"5.1.0"}}')
                (folder / "Dockerfile").write_text("FROM httpd:2.4.49\n")
                lock = folder / "package-lock.json"
                def lock_version(version):
                    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
                        f"node_modules/{name}": {"version": version, "integrity": "sha512-synthetic",
                            "resolved": "https://registry.example.invalid/fixture.tgz"}
                        for name in ("fixture-dependency", "fixture-transitive")
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
                page.on("request", lambda req: posted.append(req.method) if req.method != "GET" and not req.url.endswith("/api/catalog/refresh") else None)
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
                defense = page.get_by_role("region", name="実行時の防御確認")
                evidence = defense.get_by_label("既存テストの結果（JUnit XML）")
                evidence.set_input_files({"name": "unsafe.xml", "mimeType": "application/xml",
                    "buffer": b'<!DOCTYPE testsuite><testsuite><testcase name="unsafe"/></testsuite>'})
                expect(defense.get_by_role("alert")).to_contain_text("読み込めません")
                evidence.set_input_files({"name": "test-results.xml", "mimeType": "application/xml",
                    "buffer": b'<testsuite tests="2"><testcase name="reject missing session"><system-out>synthetic-private-output</system-out></testcase><testcase name="missing setup"><skipped/></testcase></testsuite>'})
                auth_check = defense.get_by_text("認証 ／ 未確認", exact=True)
                auth_check.click()
                auth_row = auth_check.locator("..")
                auth_row.get_by_label("確認の種類").select_option("runtime")
                auth_row.get_by_label("該当するテスト").select_option("1")
                auth_row.get_by_label("確認した環境").select_option("隔離した模擬環境")
                expect(auth_row.get_by_role("button", name="記録する")).to_be_disabled()
                auth_row.get_by_label("選択した対象・版と合格条件に対応する結果です").check()
                auth_row.get_by_role("button", name="記録する").click()
                expect(defense.get_by_text("認証 ／ 動作確認済み", exact=True)).to_be_visible()
                expect(defense.get_by_text("データ分離 ／ 未確認", exact=True)).to_be_visible()
                assert "synthetic-private-output" not in defense.inner_text()
                mfa = defense.get_by_text("MFA ／ 未確認", exact=True)
                mfa.click()
                mfa_row = mfa.locator("..")
                mfa_row.get_by_label("確認の種類").select_option("settings")
                mfa_row.get_by_label("確認した環境").select_option("隔離した模擬環境")
                mfa_row.get_by_label("選択した対象・版で自分が確認した根拠です").check()
                mfa_row.get_by_role("button", name="記録する").click()
                expect(defense.get_by_text("MFA ／ 設定確認済み", exact=True)).to_be_visible()
                saml = defense.get_by_text("SAML ／ 未確認", exact=True)
                saml.click()
                saml_row = saml.locator("..")
                saml_row.get_by_label("確認の種類").select_option("na")
                saml_row.get_by_label("確認した環境").select_option("隔離した模擬環境")
                saml_row.get_by_label("選択した対象・版で自分が確認した根拠です").check()
                expect(saml_row.get_by_role("button", name="記録する")).to_be_disabled()
                saml_row.get_by_label("根拠（秘密値や個人情報を含めない）").fill("模擬環境の管理設定にSAMLを使わない方針がある")
                saml_row.get_by_label("選択した対象・版で自分が確認した根拠です").check()
                saml_row.get_by_role("button", name="記録する").click()
                expect(defense.get_by_text("SAML ／ 根拠付き対象外", exact=True)).to_be_visible()
                defense.get_by_text("SAML ／ 根拠付き対象外", exact=True).locator("..").get_by_role("button", name="未確認に戻す").click()
                evidence.set_input_files({"name": "fresh.xml", "mimeType": "application/xml",
                    "buffer": b'<testsuite tests="1"><testcase name="current revision"/></testsuite>'})
                expect(defense.get_by_text("成功 1 ／ 全 1 テスト", exact=True)).to_be_visible()
                expect(defense.get_by_text("認証 ／ 未確認", exact=True)).to_be_visible()
                expect(defense.get_by_text("SAML ／ 未確認", exact=True)).to_be_visible()
                expect(defense.get_by_text("MFA ／ 設定確認済み", exact=True)).to_be_visible()
                page.get_by_role("button", name="ローカル検証を開始").click()
                expect(defense.get_by_text("認証 ／ 未確認", exact=True)).to_be_visible()
                cached_match = section.get_by_text("CVE ／ CVE-2018-27182 ／ 対策が必要", exact=True)
                cached_match.click()
                expect(cached_match.locator("..").get_by_text("勧告の修正版 1.2.4", exact=False)).to_have_count(2)
                update_details.click()
                update_mode[0] = "truncated"
                page.get_by_role("button", name="保存済みの分も再取得").click()
                expect(page.get_by_text("更新失敗 npm・PyPI", exact=False)).to_be_visible(timeout=15000)
                start.click()
                expect(cached_match).to_be_visible()
                update_mode[0] = "withdrawn"
                page.get_by_role("button", name="保存済みの分も再取得").click()
                expect(page.get_by_text("更新失敗 PyPI・Go", exact=False)).to_be_visible(timeout=15000)
                start.click()
                expect(section).to_be_visible()
                expect(cached_match).to_have_count(0)
                update_details.click()
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
                scan("設定・コードを確認", "")
                expect(section.get_by_text("Claude Code ／ ストレージの公開防止 ／ 設定・コードを確認", exact=True)).to_be_visible()
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
                expect(section.get_by_text("CVE ／ CVE-2018-27182", exact=False)).to_have_count(0)
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
                    ("ARTEX", "APIの試行回数制限", "設定・コードを確認", "cloudformation.json:16"),
                    ("ARTEX", "SAML署名要件の明示設定", "設定・コードを確認", "auth-options.ts:2"),
                    ("ARTEX", "SAML署名要件の明示設定", "未確認", "auth-options.ts:3"),
                    ("ARTEX", "XML外部実体・DTD設定", "対策が必要", "auth-options.ts:5"),
                    ("ARTEX", "Kubernetesの外向き通信", "対策が必要", "network-policy.json:12"),
                    ("ARTEX", "Kubernetesの権限範囲", "未確認", "role-manifest.json:7"),
                    ("ARTEX", "コンテナの既定ユーザー", "対策が必要", "Dockerfile:2"),
                    ("Claude Code", "外部入力とHTML出力", "対策が必要", "database/render.ts:3"),
                    ("Claude Code", "外部入力とHTML出力", "設定・コードを確認", "database/render.ts:7"),
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
