"""390px browser path through an isolated owned .test site and local model.

This is an optional local measurement, not a production diagnostic. DNS and
loopback scope are substituted only inside this process; no public host or paid
model is contacted. Requires Chrome, Playwright and web/node_modules.
"""
from __future__ import annotations

import argparse
from contextlib import nullcontext
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
from unittest.mock import patch

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"
os.environ["VULNIX_EXTERNAL_PROPOSALS"] = "0"
os.environ["VULNIX_REAL_SITE_SAFE_AI"] = "0"
os.environ["VULNIX_REAL_SERVICE_DIAGNOSIS"] = "l1"

from playwright.sync_api import sync_playwright  # noqa: E402

from aegis import assessment as assessment_module  # noqa: E402
from aegis.assessment import AssessmentService  # noqa: E402
from aegis.confinement import KernelConfinement  # noqa: E402
from aegis.operators import OperatorStore, hash_password  # noqa: E402
from aegis.server import make_handler  # noqa: E402
from aegis.tenancy import OrgStore, TenantRegistry, default_members_from  # noqa: E402
from scripts.bench_status_exposure_after import HOST, STATUS_INTENT  # noqa: E402
from tests import TEST_CONFINEMENT  # noqa: E402
from tests.artex_mock_llm import MockLLM  # noqa: E402
from tests.fixtures.status_exposure_lab import StatusExposureLab  # noqa: E402
from tests.test_artex_bridge import FAKE  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PARSER = argparse.ArgumentParser()
PARSER.add_argument("--production", action="store_true", help="Use an already built Next.js production bundle")
PARSER.add_argument("--idle-seconds", type=float, default=0,
                    help="Count backup API requests after the completed result remains visible")
PARSER.add_argument("--block-events", action="store_true", help="Drop the SSE stream to verify backup polling")
PARSER.add_argument("--reconnect-events", action="store_true",
                    help="Abort the first SSE connection and require a reconnect")
PARSER.add_argument("--silent-change", action="store_true",
                    help="Change a lab finding without publishing an event while SSE heartbeats continue")
PARSER.add_argument("--revoke-session", action="store_true",
                    help="Revoke the lab session and require the browser to hide the old result")
PARSER.add_argument("--report-export", action="store_true",
                    help="Download the evidence-backed Markdown report in the browser")
PARSER.add_argument("--org-switch", action="store_true",
                    help="Switch to a second lab organization and confirm isolation")
PARSER.add_argument("--real-artex", action="store_true", help="Use the pinned ARTEX overlay binary supplied by CI")
PARSER.add_argument("--chromium", action="store_true", help="Use Playwright Chromium instead of local Chrome")
PARSER.add_argument("--cors-note", action="store_true", help="Check the observed CORS headers and unproven-data note")
PARSER.add_argument("--viewport-width", type=int, default=390,
                    help="Browser width for the local owned-site flow (default: 390px)")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_web(url: str, proc: subprocess.Popen) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("local Web server stopped before it was ready")
        try:
            with urllib.request.urlopen(url + "/login", timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("local Web server did not become ready")


def main() -> None:
    args = PARSER.parse_args()
    if not 320 <= args.viewport_width <= 1920:
        PARSER.error("--viewport-width must be between 320 and 1920")
    if args.block_events and args.reconnect_events:
        PARSER.error("--block-events and --reconnect-events cannot be combined")
    real_bin = os.environ.get("VULNIX_ARTEX_REAL_BIN") if args.real_artex else None
    if args.real_artex and (not real_bin or not Path(real_bin).is_file()):
        PARSER.error("--real-artex requires VULNIX_ARTEX_REAL_BIN pointing to the built overlay")
    command = [real_bin] if real_bin else FAKE
    site = StatusExposureLab("vulnerable", cors_credentials=args.cors_note)
    site_thread = threading.Thread(target=site.serve_forever, daemon=True)
    site_thread.start()
    try:
        with tempfile.TemporaryDirectory() as tmp, MockLLM(intents=[STATUS_INTENT]) as model:
            data = Path(tmp)
            env = {"AEGIS_ENV": "production" if real_bin else "development", "VULNIX_REAL_SITE_LOCAL_ARTEX": "1",
                   "VULNIX_REAL_SITE_INITIAL_ARTEX": "1", "VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                   "VULNIX_ARTEX_REAL_CMD": " ".join(command),
                   "VULNIX_ARTEX_EXPECTED_SHA256": os.environ.get("VULNIX_ARTEX_CI_BINARY_SHA256", ""),
                   "VULNIX_ARTEX_LLM_UPSTREAM_URL": model.url + "/chat/completions"}
            with patch.dict(os.environ, env):
                svc = AssessmentService(data, 18081, l2_confinement=TEST_CONFINEMENT,
                                        real_site_read_only=True)
                if real_bin and os.environ.get("VULNIX_ARTEX_CONFINE") == "1":
                    svc._l2_confinement = KernelConfinement()
                svc._custom_resolver = lambda name: ["127.0.0.1"] if name == HOST else []
                svc._real_site_local_artex = True
                svc._artex_real_cmd = command
                challenge_value = [None]
                original_verify = assessment_module.verify_ownership_challenge
                original_confirm = svc.confirm_asset_scope
                original_runner = assessment_module.run_artex_planner

                def mock_dns(name: str) -> list[str]:
                    value = challenge_value[0]
                    return [f'{name} text = "{value}"'] if value else []

                def verify_with_lab_dns(*args, **kwargs):
                    if kwargs.get("txt_lookup") is None:
                        kwargs["txt_lookup"] = mock_dns
                    return original_verify(*args, **kwargs)

                def confirm_test_scope(**kwargs):
                    kwargs["allow_loopback_test"] = True
                    return original_confirm(**kwargs)

                def propose_status(command, request, **kwargs):
                    return original_runner(command, {**request, "fake_intents": [STATUS_INTENT]}, **kwargs)

                svc._proof_dns_lookup = mock_dns
                svc.confirm_asset_scope = confirm_test_scope
                password = secrets.token_urlsafe(18)
                seed = data / "operators.json"
                seed.write_text(json.dumps({"operators": [{"name": "qa", "display": "QA",
                    "roles": ["operator", "approver"], "password_hash": hash_password(password)}]}))
                ops = OperatorStore(seed)
                registry = None
                second_org = None
                if args.org_switch:
                    store = OrgStore(data / "orgs.json", bootstrap_members=lambda: default_members_from(ops))
                    second_org = store.create_org("別の組織", "qa")
                    registry = TenantRegistry(
                        store, svc,
                        lambda path: AssessmentService(path, 18081, l2_confinement=TEST_CONFINEMENT,
                                                       real_site_read_only=True), data)
                backend = ThreadingHTTPServer(("127.0.0.1", 0),
                                              make_handler(svc, ops, tenancy=registry))
                backend.daemon_threads = True
                backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
                backend_thread.start()
                web_port = free_port()
                base = f"http://127.0.0.1:{web_port}"
                next_env = {**os.environ, "AEGIS_API": f"http://127.0.0.1:{backend.server_port}",
                            "VULNIX_NO_ENV_LOCAL": "1"}
                web = subprocess.Popen([str(ROOT / "web/node_modules/.bin/next"),
                                        "start" if args.production else "dev",
                                        "-H", "127.0.0.1", "-p", str(web_port)],
                                       cwd=ROOT / "web", env=next_env,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    wait_for_web(base, web)
                    with patch.object(assessment_module, "verify_ownership_challenge",
                                      side_effect=verify_with_lab_dns), \
                        (nullcontext() if real_bin else patch.object(assessment_module, "run_artex_planner",
                                                                      side_effect=propose_status)), \
                         sync_playwright() as playwright:
                        browser = playwright.chromium.launch(headless=True) if args.chromium else \
                            playwright.chromium.launch(channel="chrome", headless=True)
                        try:
                            page = browser.new_page(viewport={"width": args.viewport_width, "height": 844})
                            api_calls: list[str] = []
                            page_errors: list[str] = []
                            page.on("request", lambda req: api_calls.append(req.url.split("/api/", 1)[1].split("?", 1)[0])
                                    if "/api/" in req.url else None)
                            page.on("pageerror", lambda error: page_errors.append(str(error)))
                            event_connections = [0]
                            if args.block_events:
                                page.route("**/api/assessments/*/events*", lambda route: route.abort())
                            if args.reconnect_events:
                                def first_event_disconnect(route):
                                    event_connections[0] += 1
                                    if event_connections[0] == 1:
                                        route.abort()
                                    else:
                                        route.continue_()
                                page.route("**/api/assessments/*/events*", first_event_disconnect)
                            page.goto(base + "/login")
                            page.get_by_label("ユーザー名", exact=True).fill("qa")
                            page.get_by_label("パスワード", exact=True).fill(password)
                            page.get_by_role("button", name="ログイン", exact=True).click()
                            page.wait_for_url("**/dashboard")
                            actions = ["open_wizard"]
                            page.get_by_role("button", name="＋ サイトを診断する").click()
                            target = f"http://{HOST}:{site.server_port}"
                            page.get_by_label("診断するサイトのURL").fill(target)
                            actions.append("enter_url")
                            with page.expect_response(lambda res: res.url.endswith("/api/assets/challenge")) as issued:
                                page.get_by_role("button", name="所有確認へ").click()
                            actions.append("issue_challenge")
                            challenge = issued.value.json()["challenge"]
                            page.get_by_text(challenge["dns_txt_name"], exact=True).wait_for()
                            page.get_by_text(challenge["dns_txt_value"], exact=True).first.wait_for()
                            challenge_value[0] = challenge["dns_txt_value"]
                            assert site.seen == [], "target received traffic before ownership verification"
                            page.get_by_role("button", name="確認する", exact=True).click()
                            actions.append("verify_ownership")
                            page.get_by_text("所有確認が完了しました").wait_for(timeout=10000)
                            assert site.seen == [], "target received traffic during DNS verification"
                            page.get_by_label("このサイトの管理者として").check()
                            actions.append("confirm_scope")
                            page.get_by_label("AIが提案した場合").check()
                            actions.append("consent_to_extra_get")
                            started = time.monotonic()
                            page.get_by_role("button", name="診断を開始", exact=True).click()
                            actions.append("start")
                            page.wait_for_url("**/assessments/scan_001", timeout=120000 if real_bin else 15000)
                            page.get_by_role("tab", name="問題").click()
                            actions.append("open_findings")
                            try:
                                page.locator("h3").filter(has_text="Apache mod_status の公開露出").wait_for(
                                    timeout=120000 if real_bin else 30000)
                            except Exception:
                                state = svc.snapshot()
                                print(json.dumps({"state": state["state"],
                                                  "finding_ids": [f["id"] for f in state["findings"]],
                                                  "target_paths": list(site.seen),
                                                  "local_model_calls": len(model.requests),
                                                  "api_paths": api_calls,
                                                  "page_errors": page_errors}, ensure_ascii=False))
                                raise
                            elapsed = round(time.monotonic() - started, 3)
                            snap = svc.snapshot()
                            assert snap["state"] == "completed", snap.get("failure")
                            assert site.seen == ["/", "/server-status?auto"], site.seen
                            page.get_by_role("button", name="検証の記録").first.click()
                            page.get_by_text("2. 診断方法：", exact=False).first.wait_for()
                            assert page.get_by_text("EgressGuard", exact=False).count() == 0
                            if args.cors_note:
                                page.get_by_text("Access-Control-Allow-Credentials: true", exact=False).first.wait_for()
                                page.get_by_text("機密情報をブラウザから読み取れたことは実証していません", exact=False).first.wait_for()
                                assert any(f["id"] == "f_l1_cors" and f["evidence_status"] == "detected"
                                           for f in snap["findings"])
                            plan = snap["artex_plan"]["plan"]
                            assert plan["engine"]["kind"] == ("artex-binary" if real_bin else "unverified")
                            fallback_label = page.get_by_text("AIによる追加検査は未実施", exact=False)
                            source_label = page.get_by_text(
                                "ARTEXで作成した計画" if real_bin else "検証用プランナーの計画", exact=False)
                            source_label.first.wait_for()
                            fallback_label.first.wait_for(state="hidden")
                            source_label_visible = source_label.count() > 0
                            fixed_l1_only_label_visible = fallback_label.count() > 0
                            if real_bin:
                                assert plan["engine"]["pinned"] is True
                                assert model.requests, "the real ARTEX did not call the local model"
                                model_input = json.dumps(model.requests, ensure_ascii=False)
                                assert HOST not in model_input and target not in model_input
                                page.get_by_role("tab", name="診断").click()
                                page.get_by_text("診断エンジン:", exact=False).first.wait_for(timeout=10000)
                                page.get_by_text("AIモデル:", exact=False).first.wait_for(timeout=10000)
                            else:
                                assert len(model.requests) == 0, len(model.requests)
                            report_exported = False
                            if args.report_export:
                                page.get_by_role("tab", name="診断").click()
                                with page.expect_download() as download_info:
                                    page.get_by_role("button", name="診断レポート出力", exact=False).click()
                                download = download_info.value
                                report_text = Path(download.path()).read_text(encoding="utf-8")
                                assert download.suggested_filename == "vulnix-report-scan_001.md"
                                assert "Apache mod_status" in report_text
                                finding = next(f for f in snap["findings"] if f["id"] == "f_l1_apache_mod_status")
                                evidence_ids = [ev["evidence_id"] for ev in finding["evidence"]]
                                assert evidence_ids and any(evidence_id in report_text for evidence_id in evidence_ids)
                                page.get_by_text("レポートプレビューを表示").wait_for()
                                report_exported = True
                                page.get_by_role("tab", name="問題").click()
                            if args.reconnect_events:
                                page.wait_for_timeout(5000)
                                assert event_connections[0] >= 2, "SSE did not reconnect after first disconnect"
                            org_switch_isolated = False
                            if args.org_switch:
                                assert second_org is not None
                                page.locator("#org-switch").select_option(second_org)
                                page.wait_for_url("**/dashboard")
                                with page.expect_response(lambda response: response.url.endswith(
                                        "/api/assessments/scan_001")) as other_response:
                                    page.goto(base + "/assessments/scan_001")
                                other_snapshot = other_response.value.json()
                                assert other_snapshot["target_url"] != snap["target_url"]
                                assert other_snapshot["asset"] != snap["asset"]
                                page.get_by_role("tab", name="問題").click()
                                assert page.get_by_text("Apache mod_status の公開露出").count() == 0
                                page.locator("#org-switch").select_option("default")
                                page.wait_for_url("**/dashboard")
                                page.goto(base + "/assessments/scan_001")
                                page.get_by_role("tab", name="問題").click()
                                page.locator("h3").filter(has_text="Apache mod_status の公開露出").wait_for()
                                org_switch_isolated = True
                            assert not page_errors, page_errors
                            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                            idle_at = len(api_calls)
                            silent_change_recovered_s = None
                            revocation_hidden_s = None
                            if args.silent_change:
                                seq_before = svc.bus.last_seq
                                with svc._lock:
                                    svc.a.findings["f_l1_apache_mod_status"]["title"] = "心拍のみの更新確認"
                                    svc._save_state_locked()
                                assert svc.bus.last_seq == seq_before, "silent lab change emitted an event"
                                changed_at = time.monotonic()
                                page.locator("h3").filter(has_text="心拍のみの更新確認").wait_for(timeout=40000)
                                silent_change_recovered_s = round(time.monotonic() - changed_at, 3)
                            if args.revoke_session:
                                ops.revoke_all_sessions("browser-session-test")
                                revoked_at = time.monotonic()
                                page.locator("h3").filter(has_text="Apache mod_status の公開露出").wait_for(
                                    state="detached", timeout=40000)
                                revocation_hidden_s = round(time.monotonic() - revoked_at, 3)
                            if args.idle_seconds > 0:
                                page.wait_for_timeout(args.idle_seconds * 1000)
                            if args.cors_note:
                                page.goto(base + "/findings/f_l1_cors?a=scan_001")
                                page.get_by_text("観測したこと：", exact=False).first.wait_for()
                                page.get_by_text("Access-Control-Allow-Credentials: true", exact=False).first.wait_for()
                                page.get_by_text("機密情報をブラウザから読み取れたことは実証していません", exact=False).first.wait_for()
                                page.get_by_text("別のサイトから、ログイン状態を使って", exact=False).first.wait_for()
                                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                                page.screenshot(path=str(ROOT / "docs/CORS_390_RESULT.png"), full_page=True)
                                assert not page_errors, page_errors
                            print(json.dumps({"viewport_width": args.viewport_width,
                                              "web_mode": "production" if args.production else "development",
                                              "actions_from_site_open_to_result": len(actions),
                                              "action_names": actions, "browser_api_requests": len(api_calls),
                                              "api_paths": api_calls, "elapsed_start_to_visible_finding_s": elapsed,
                                              "idle_seconds": args.idle_seconds,
                                              "idle_api_requests": len(api_calls) - idle_at,
                                              "sse_blocked": args.block_events,
                                              "sse_connections": event_connections[0] if args.reconnect_events else None,
                                              "report_exported": report_exported,
                                              "org_switch_isolated": org_switch_isolated,
                                              "silent_change_recovered_s": silent_change_recovered_s,
                                              "revocation_hidden_s": revocation_hidden_s,
                                              "target_paths": list(site.seen), "local_model_calls": len(model.requests),
                                              "engine_kind": plan["engine"]["kind"],
                                              "source_label_visible": source_label_visible,
                                              "fixed_l1_only_label_visible": fixed_l1_only_label_visible,
                                              "model_input_excludes_host": True if real_bin else None,
                                              "engine_and_model_visible": True if real_bin else None,
                                              "cors_observation_and_limit_visible": args.cors_note,
                                              "cors_detail_visible": args.cors_note,
                                              "status_finding": "detected", "page_errors": len(page_errors)},
                                             ensure_ascii=False, indent=2))
                        finally:
                            browser.close()
                finally:
                    web.terminate()
                    try:
                        web.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        web.kill()
                        web.wait(timeout=5)
                    backend.shutdown()
                    backend.server_close()
                    backend_thread.join(timeout=2)
                    if registry is not None:
                        registry.close_all()
                    svc.close()
    finally:
        site.shutdown()
        site.server_close()
        site_thread.join(timeout=2)


if __name__ == "__main__":
    main()
