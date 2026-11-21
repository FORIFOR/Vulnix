"""The diagnosis loop's operations (PR-C) in a real browser, on the authorized local lab.

Everything runs on loopback in this process: the access-control lab (the registered
lab target), the control plane (make_handler + AssessmentService + TenantRegistry), the
Next.js UI, and the ARTEX stand-in with the fixed-rule planner. No model, paid API,
public host or DNS is used.

Every step is a click on the screen, by the person who holds that permission:

 1. `qa` (runner: diagnosis:request) starts the loop -> it waits for the owner's spec;
 2. `owner-alice` (organization owner: asset:specify) states "認証必須" -> the loop
    runs the L1 check and waits for the L2 approval;
 3. `qa` cannot approve their own step (no button, and the API answers 403);
 4. `approver-human` (diagnosis:approve_l2) approves on a 390px phone -> the L2 step
    runs once and the finding is proven;
 5. the lab is fixed; `qa` starts the after-fix check -> a new generation that waits for
    the owner again, a new L2 approval, and the before/after comparison with the finding;
 6. the same Idempotency-Key replays (no second Worker), another organization's member
    and a viewer get no operation, a real site has no such route (404).
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"
os.environ["VULNIX_EXTERNAL_PROPOSALS"] = "0"

from playwright.sync_api import expect, sync_playwright  # noqa: E402

from aegis import assessment as assessment_module  # noqa: E402
from aegis.assessment import AssessmentService  # noqa: E402
from aegis.diagnosis_judge import fixed_rule_steps  # noqa: E402
from aegis.operators import OperatorStore, hash_password  # noqa: E402
from aegis.server import make_handler  # noqa: E402
from aegis.tenancy import DEFAULT_ORG, OrgStore, TenantRegistry  # noqa: E402
from scripts.axe_check import gate, run_axe  # noqa: E402
from scripts.check_diagnosis_ui import Backend, free_port, titles, wait_for_web  # noqa: E402
from tests import TEST_CONFINEMENT  # noqa: E402
from tests.diagnosis_planner import view_from_text  # noqa: E402
from tests.fixtures.access_control_lab import AccessControlLab  # noqa: E402
from tests.test_artex_bridge import FAKE  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PARSER = argparse.ArgumentParser()
PARSER.add_argument("--production", action="store_true", help="Use an already built Next.js production bundle")
PARSER.add_argument("--chromium", action="store_true", help="Use Playwright Chromium instead of local Chrome")
PARSER.add_argument("--screenshots", type=Path, help="Directory for the screenshots")
USERS = {  # name -> (organization role in the default organization, account roles)
    "qa": ("runner", ["operator"]),
    "owner-alice": ("owner", ["operator"]),
    "approver-human": ("approver", ["approver"]),
    "viewer-v": ("viewer", ["operator"]),
    "outsider": (None, ["operator"]),
}


def main() -> None:
    args = PARSER.parse_args()
    shots = args.screenshots
    if shots:
        shots.mkdir(parents=True, exist_ok=True)
    report: dict = {"screenshots": [], "checks": {}}
    lab = AccessControlLab("idor_vulnerable")
    threading.Thread(target=lab.serve_forever, daemon=True).start()
    env = {"AEGIS_ENV": "development", "VULNIX_ARTEX_REAL_CMD": shlex.join(FAKE),
           "VULNIX_ARTEX_LLM_URL": "http://127.0.0.1:9/v1", "VULNIX_ARTEX_EXPECTED_SHA256": "",
           "VULNIX_ARTEX_PG_DSN": ""}
    original_planner = assessment_module.run_artex_planner

    def planner(cmd, request, **kw):
        intents = [{"summary": json.dumps(s), "asset_ids": [1], "priority": 5}
                   for s in fixed_rule_steps(view_from_text(titles(request)))]
        return original_planner(cmd, {**request, "fake_intents": intents}, **kw)

    with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, env))
        stack.enter_context(patch.object(assessment_module, "run_artex_planner", side_effect=planner))
        data = Path(tmp)
        passwords = {n: secrets.token_urlsafe(18) for n in USERS}
        seed = data / "operators.json"
        seed.write_text(json.dumps({"operators": [
            {"name": n, "display": n, "roles": roles, "password_hash": hash_password(passwords[n])}
            for n, (_, roles) in USERS.items()]}))
        ops = OperatorStore(seed)

        def new_service(path: Path) -> AssessmentService:
            return AssessmentService(path, lab.server_port, l2_confinement=TEST_CONFINEMENT, verify_seconds=0.1)

        svc = new_service(data)
        store = OrgStore(data / "orgs.json", bootstrap_members=lambda: {
            n: [role] for n, (role, _) in USERS.items() if role})
        registry = TenantRegistry(store, svc, new_service, data)
        other_org = store.create_org("別の組織", "outsider")
        port = free_port()
        backend = Backend(port, make_handler(svc, ops, tenancy=registry))
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        web_port = free_port()
        base = f"http://127.0.0.1:{web_port}"
        web = subprocess.Popen([str(ROOT / "web/node_modules/.bin/next"), "start" if args.production else "dev",
                                "-H", "127.0.0.1", "-p", str(web_port)], cwd=ROOT / "web",
                               env={**os.environ, "AEGIS_API": f"http://127.0.0.1:{port}", "NEXT_TELEMETRY_DISABLED": "1"},
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(web.terminate)
        wait_for_web(base, web)
        p = stack.enter_context(sync_playwright())
        browser = p.chromium.launch(headless=True) if args.chromium else p.chromium.launch(channel="chrome", headless=True)
        stack.callback(browser.close)
        page_errors: list[str] = []

        def open_page(user: str, width: int):
            ctx = browser.new_context(viewport={"width": width, "height": 900})
            page = ctx.new_page()
            page.on("pageerror", lambda e: page_errors.append(f"{user}: {e}"))
            page.goto(base + "/login")
            page.get_by_label("ユーザー名", exact=True).fill(user)
            page.get_by_label("パスワード", exact=True).fill(passwords[user])
            page.get_by_role("button", name="ログイン", exact=True).click()
            page.wait_for_url("**/dashboard")
            page.goto(base + "/assessments/scan_001")
            page.evaluate("window.__noReload = 1")
            return page

        def panel(page):
            return page.locator("[data-testid=diagnosis-loop]")

        def shot(page, name: str):
            if not shots:
                return
            path = shots / f"{name}.png"
            page.add_style_tag(content="header, .sticky { position: static !important; }")
            panel(page).locator("..").screenshot(path=path)
            report["screenshots"].append(str(path))

        def api(page, op: str, body: dict, key: str, org: str | None = None):
            headers = {"Origin": base, "X-Aegis-Request": "1", "Idempotency-Key": key,
                       "Content-Type": "application/json"}
            if org:
                headers["X-Vulnix-Org"] = org
            r = page.request.post(f"{base}/api/assessments/scan_001/diagnosis/{op}", data=json.dumps(body),
                                  headers=headers)
            try:
                return r.status, r.json()
            except Exception:  # noqa: BLE001
                return r.status, {}

        report["accessibility"] = {}

        def axe(page, name: str) -> None:
            report["accessibility"][name] = run_axe(page)

        def no_overflow(page) -> bool:
            return page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

        def l2_results() -> int:
            return sum(1 for e in svc.audit.entries()
                       if e["event"] == "result" and e["fields"].get("tool") == "reproduction_probe")

        # ---- 0. the sign-in screen, as a first-time user sees it ---------------------------------
        for scheme in ("light", "dark"):
            ctx = browser.new_context(viewport={"width": 390, "height": 900}, color_scheme=scheme)
            first = ctx.new_page()
            first.on("pageerror", lambda e: page_errors.append(f"login: {e}"))
            first.goto(base + "/login")
            expect(first.get_by_role("button", name="ログイン", exact=True)).to_be_visible(timeout=20000)
            axe(first, f"00m-login-390-{scheme}")
            ctx.close()

        # ---- 1. qa starts -------------------------------------------------------------------
        qa = open_page("qa", 1280)
        expect(panel(qa)).to_contain_text("まだ診断ループを実行していません", timeout=20000)
        start = panel(qa).get_by_role("button", name="診断を開始")
        expect(start).to_be_visible()
        shot(qa, "01-not-started-start-button")
        axe(qa, "01-not-started")
        start.click()
        expect(panel(qa)).to_contain_text("所有者の仕様の入力を待っています", timeout=20000)
        expect(panel(qa)).to_contain_text("対象資産の管理者が仕様を入力するのを待っています")
        report["checks"]["requester_has_no_spec_form"] = panel(qa).get_by_role("radio").count() == 0
        shot(qa, "02-waiting-for-owner-spec")
        axe(qa, "02-waiting-for-owner-spec")

        viewer = open_page("viewer-v", 1024)
        expect(panel(viewer)).to_contain_text("所有者の仕様の入力を待っています", timeout=20000)
        report["checks"]["viewer_has_no_controls"] = panel(viewer).get_by_role("button").count() == 0 \
            and panel(viewer).get_by_role("radio").count() == 0

        # ---- 2. the owner states the specification -----------------------------------------
        owner = open_page("owner-alice", 1280)
        expect(panel(owner).get_by_role("radio", name="認証必須")).to_be_visible(timeout=20000)
        shot(owner, "03-owner-spec-form")
        axe(owner, "03-owner-spec-form")
        panel(owner).get_by_role("radio", name="認証必須").check()
        panel(owner).get_by_role("button", name="仕様を記録する").click()
        expect(panel(qa)).to_contain_text("L2 検査の承認を待っています", timeout=30000)
        expect(panel(qa)).to_contain_text("認証なしの要求は拒否された")       # the L1 step, judged
        report["checks"]["live_without_reload"] = qa.evaluate("window.__noReload === 1")

        # ---- 3. the requester cannot approve -------------------------------------------------
        expect(panel(qa)).to_contain_text("依頼者本人は承認できません")
        report["checks"]["requester_has_no_approve_button"] = \
            panel(qa).get_by_role("button", name="この L2 検査を承認する").count() == 0
        item = svc.diagnosis_ops.job_view_locked()["waiting_item_id"]
        code, body = api(qa, "approve", {"item_id": item}, "e2e-qa-self-approval-0001")
        report["checks"]["requester_api_approval_status"] = code
        report["checks"]["requester_api_approval_refused"] = code == 403
        shot(qa, "04-requester-cannot-approve")
        axe(qa, "04-requester-cannot-approve")

        # ---- 4. the approver approves on a phone ---------------------------------------------
        phone = open_page("approver-human", 390)
        approve = panel(phone).get_by_role("button", name="この L2 検査を承認する")
        expect(approve).to_be_visible(timeout=20000)
        report["checks"]["phone_approval_no_horizontal_scroll"] = no_overflow(phone)
        shot(phone, "05m-approver-390")
        axe(phone, "05m-approver-390")
        approve.click()
        expect(panel(phone)).to_contain_text("所有者が「認証必須」とした資源を、別のアカウントが読めた", timeout=30000)
        expect(panel(qa)).to_contain_text("診断：終了しました", timeout=30000)
        report["checks"]["l2_runs_after_first_approval"] = l2_results()
        shot(qa, "06-finding-proven")
        axe(qa, "06-finding-proven")
        f = svc.a.findings.get("f_idor") or {}
        from aegis.evidence import evidence_status
        report["checks"]["finding_proven"] = evidence_status(f) == "proven"

        # ---- 5. the fix, and the after-fix check ---------------------------------------------
        lab.mode = "denied_403"
        fix = panel(qa).get_by_role("button", name="修正後の確認を開始")
        expect(fix).to_be_visible(timeout=20000)
        fix.click()
        expect(panel(qa)).to_contain_text("修正後の確認：所有者の仕様の入力を待っています", timeout=30000)
        expect(panel(owner).get_by_role("radio", name="認証必須")).to_be_visible(timeout=20000)
        panel(owner).get_by_role("radio", name="認証必須").check()
        panel(owner).get_by_role("button", name="仕様を記録する").click()
        approve = panel(phone).get_by_role("button", name="この L2 検査を承認する")
        expect(approve).to_be_visible(timeout=30000)
        second_item = svc.diagnosis_ops.job_view_locked()["waiting_item_id"]
        report["checks"]["new_approval_for_new_step"] = second_item != item
        # the approval is sent twice with one key (a retry): one decision, one Worker
        k = "e2e-approver-retry-key-0001"
        c1, b1 = api(phone, "approve", {"item_id": second_item}, k)
        c2, b2 = api(phone, "approve", {"item_id": second_item}, k)
        report["checks"]["same_key_replayed"] = (c1, c2, bool(b2.get("replayed"))) == (200, 200, True)
        c3, b3 = api(phone, "approve", {"item_id": second_item}, k + "x")
        report["checks"]["second_key_refused_status"] = c3
        expect(panel(qa)).to_contain_text("改善を確認", timeout=30000)
        expect(panel(qa)).to_contain_text("f_idor")
        expect(panel(qa)).to_contain_text("現在の判定 再現せず")
        expect(panel(qa)).to_contain_text("検査結果：再現 成立")
        report["checks"]["l2_runs_total"] = l2_results()
        report["checks"]["one_worker_per_approval"] = l2_results() == 2
        report["checks"]["l2_approved_records"] = sum(1 for e in svc.audit.entries()
                                                      if e["event"] == "diagnosis.l2_approved")
        shot(qa, "07-fix-comparison")
        axe(qa, "07-fix-comparison")
        phone.reload()
        expect(panel(phone)).to_contain_text("改善を確認", timeout=20000)
        report["checks"]["phone_fix_no_horizontal_scroll"] = no_overflow(phone)
        shot(phone, "07m-fix-comparison-390")
        axe(phone, "07m-fix-comparison-390")
        phone.emulate_media(color_scheme="dark")
        axe(phone, "07m-fix-comparison-390-dark")
        phone.emulate_media(color_scheme="light")

        # ---- 6. other organization, real site ---------------------------------------------------
        outsider = open_page("outsider", 1024)
        expect(panel(outsider)).to_contain_text("まだ診断ループを実行していません", timeout=20000)
        report["checks"]["other_org_screen_empty"] = panel(outsider).get_by_text("改善を確認").count() == 0
        # the UI picks the organization by the vulnix_org cookie: point it at the default one
        with svc._lock:
            before = svc.diagnosis_ops.job_view_locked()
        outsider.context.add_cookies([{"name": "vulnix_org", "value": DEFAULT_ORG, "url": base}])
        code, _ = api(outsider, "start", {}, "e2e-outsider-start-0001")
        with svc._lock:
            after = svc.diagnosis_ops.job_view_locked()
        report["checks"]["other_org_api_status"] = code
        report["checks"]["other_org_api_refused"] = code == 403 and before == after
        with registry.service(other_org)._lock:
            report["checks"]["other_org_nothing_started"] = \
                registry.service(other_org).diagnosis_ops.job_view_locked() is None
        with patch.object(type(svc), "_is_external_service_asset", return_value=True):
            code, _ = api(qa, "start", {}, "e2e-real-site-start-0001")
        report["checks"]["real_site_status"] = code
        report["checks"]["real_site_404"] = code == 404

        report["lab_paths"] = sorted({path for path, _ in lab.seen})
        report["checks"]["other_org"] = other_org
        report["page_errors"] = page_errors
        backend.shutdown()
        backend.drop_all()
        backend.server_close()
        registry.close_all()
        svc.close()
    lab.shutdown()
    # accessibility (WCAG 2.1 A/AA, axe-core): no serious or critical violation on any screen checked
    checked, clean = gate(report.get("accessibility", {}))
    report["checks"]["accessibility_screens_checked"] = checked
    report["checks"]["accessibility_no_serious_violation"] = clean
    failed = [k for k, v in report["checks"].items() if v is False]
    expected = {"requester_api_approval_status": 403, "second_key_refused_status": 409, "l2_runs_total": 2,
                "l2_approved_records": 2, "other_org_api_status": 403, "real_site_status": 404,
                "l2_runs_after_first_approval": 1, "accessibility_screens_checked": 11}
    failed += [k for k, v in expected.items() if report["checks"].get(k) != v]
    report["ok"] = not failed and not page_errors
    print(json.dumps(report, ensure_ascii=False, indent=1))
    if failed or page_errors:
        sys.exit(f"failed: {failed} {page_errors}")


if __name__ == "__main__":
    main()
