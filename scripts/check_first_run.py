"""A first-time user, end to end, in a real browser on the authorized local lab.

Nobody is set up in advance. Everything runs on loopback in this process: the access-
control lab (each organization's registered lab), the control plane with public sign-up
(make_handler + TenantRegistry), the Next.js production UI and the ARTEX stand-in with
the fixed-rule planner. No model, paid API, public host or DNS is used.

1. alice signs up (she becomes the owner of her new organization) and opens her workspace;
2. she starts the diagnosis, states the owner's specification, and the L1 check runs;
3. the L2 step waits for an approver: alice cannot approve her own request, and the
   screen tells her how to get one (settings -> invite);
4. she creates an approver invitation; bob opens the link, signs up, joins, and approves
   the one step on his phone (390px);
5. alice reads the finding and downloads the report;
6. the lab is fixed: alice starts the after-fix check, states the specification again,
   bob approves the new step, and alice sees "改善を確認".

Every step is a click on the screen; the report records the time each step took and an
accessibility check (axe-core, WCAG 2.1 A/AA) of the screens a first-time user meets.
"""
from __future__ import annotations

import argparse
import json
import os
import re
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
from aegis.tenancy import OrgStore, TenantRegistry  # noqa: E402
from scripts.axe_check import gate as axe_gate, run_axe  # noqa: E402
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


def main() -> None:
    args = PARSER.parse_args()
    shots = args.screenshots
    if shots:
        shots.mkdir(parents=True, exist_ok=True)
    report: dict = {"screenshots": [], "checks": {}, "steps_s": {}, "accessibility": {}}
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
        # one platform account exists only so that no initial account is generated
        seed = data / "operators.json"
        seed.write_text(json.dumps({"operators": [
            {"name": "platform-admin", "display": "platform", "roles": ["admin"],
             "password_hash": hash_password(secrets.token_urlsafe(18))}]}))
        ops = OperatorStore(seed)

        def new_service(path: Path) -> AssessmentService:
            return AssessmentService(path, lab.server_port, l2_confinement=TEST_CONFINEMENT, verify_seconds=0.1)

        svc = new_service(data)
        store = OrgStore(data / "orgs.json", bootstrap_members=lambda: {})
        registry = TenantRegistry(store, svc, new_service, data)
        port = free_port()
        backend = Backend(port, make_handler(svc, ops, tenancy=registry, public_signup=True))
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
        passwords = {n: secrets.token_urlsafe(16) for n in ("alice", "bob-approver")}
        t0 = time.monotonic()
        last = [t0]

        def step(name: str) -> None:
            now = time.monotonic()
            report["steps_s"][name] = round(now - last[0], 1)
            last[0] = now

        def new_page(user: str, width: int):
            ctx = browser.new_context(viewport={"width": width, "height": 900})
            page = ctx.new_page()
            page.on("pageerror", lambda e: page_errors.append(f"{user}: {e}"))
            return page

        def panel(page):
            return page.locator("[data-testid=diagnosis-loop]")

        def shot(page, name: str, *, whole_panel: bool = True):
            report["accessibility"][name] = run_axe(page)
            if not shots:
                return
            path = shots / f"{name}.png"
            page.add_style_tag(content="header, .sticky { position: static !important; }")
            if whole_panel and panel(page).count():
                panel(page).locator("..").screenshot(path=path)
            else:
                page.screenshot(path=path)
            report["screenshots"].append(str(path))

        def sign_up(page, name: str) -> None:
            page.get_by_role("tab", name="新規アカウント登録").click()
            page.locator("#reg-name").fill(name)
            page.locator("#reg-pw").fill(passwords[name])
            page.locator("#reg-confirm").fill(passwords[name])
            page.get_by_role("button", name="アカウントを登録して開始").click()

        # ---- 1. alice signs up and opens her workspace ----------------------------------------
        alice = new_page("alice", 1280)
        alice.goto(base + "/login")
        sign_up(alice, "alice")
        alice.wait_for_url(re.compile(r".*/(dashboard|welcome).*"), timeout=30000)
        alice.get_by_role("link", name="診断ワークスペース").first.click()
        alice.wait_for_url("**/assessments/scan_001**")
        start = panel(alice).get_by_role("button", name="診断を開始")
        expect(start).to_be_visible(timeout=30000)
        step("sign_up_and_open_workspace")
        shot(alice, "01-first-workspace")

        # ---- 2. start, the owner's specification, the L1 check ---------------------------------
        start.click()
        expect(panel(alice).get_by_role("radio", name="認証必須")).to_be_visible(timeout=30000)
        shot(alice, "02-owner-spec")
        panel(alice).get_by_role("radio", name="認証必須").check()
        panel(alice).get_by_role("button", name="仕様を記録する").click()
        expect(panel(alice)).to_contain_text("L2 検査の承認を待っています", timeout=30000)
        expect(panel(alice)).to_contain_text("認証なしの要求は拒否された")
        step("start_spec_and_l1")

        # ---- 3. alice cannot approve her own step; the screen says how to get an approver -----
        expect(panel(alice)).to_contain_text("依頼者本人は承認できません")
        expect(panel(alice).get_by_role("button", name="この L2 検査を承認する")).to_have_count(0)
        report["checks"]["requester_has_no_approve_button"] = True
        invite_link = panel(alice).get_by_role("link", name="設定の「メンバーを招待」")
        expect(invite_link).to_be_visible()
        shot(alice, "03-waiting-for-an-approver")
        invite_link.click()
        alice.wait_for_url("**/settings**")
        alice.get_by_label("招待する役割").select_option("approver")
        alice.get_by_role("button", name="招待リンクを作成").click()
        link_el = alice.get_by_label("招待リンク")
        expect(link_el).to_be_visible(timeout=20000)
        invite_url = link_el.input_value()
        # the link points at this (loopback) site only
        report["checks"]["invite_link_shown"] = invite_url.startswith(base + "/invite#")
        shot(alice, "04-invite-link", whole_panel=False)
        step("invite_an_approver")

        # ---- 4. bob joins from the link and approves on his phone ------------------------------
        bob = new_page("bob-approver", 390)
        bob.goto(invite_url)
        bob.get_by_role("link", name=re.compile("ログイン")).click()
        sign_up(bob, "bob-approver")
        # signing up from an invitation joins its organization (an existing account would
        # confirm with 「参加する」 instead)
        join = bob.get_by_role("button", name="参加する")
        joined = bob.get_by_text("alice の組織")
        expect(join.or_(joined).first).to_be_visible(timeout=30000)
        if join.count():
            join.click()
            expect(bob.get_by_text("として参加しました")).to_be_visible(timeout=20000)
        report["checks"]["approver_joined_alices_organization"] = bob.get_by_text("alice の組織").count() > 0
        shot(bob, "05m-joined-390", whole_panel=False)
        bob.goto(base + "/assessments/scan_001")
        approve = panel(bob).get_by_role("button", name="この L2 検査を承認する")
        expect(approve).to_be_visible(timeout=30000)
        report["checks"]["phone_no_horizontal_scroll"] = bob.evaluate(
            "document.documentElement.scrollWidth <= window.innerWidth")
        shot(bob, "06m-approve-390")
        # bob signed up himself: until his second factor is on he may not approve an L2
        # (owner decision 2026-11-23); the panel says so and nothing is approved
        approve.click()
        expect(panel(bob)).to_contain_text("2要素認証を有効にするまで", timeout=20000)
        report["checks"]["self_registered_without_mfa_refused"] = True
        bob.goto(base + "/settings")
        bob.get_by_role("button", name="有効化する").click()
        secret_el = bob.locator("dt", has_text="シークレット").locator("xpath=following-sibling::dd[1]")
        expect(secret_el).to_be_visible(timeout=20000)
        from aegis.operators import totp_code
        bob.get_by_label("認証コード").fill(totp_code(secret_el.inner_text().strip(), time.time()))
        bob.get_by_role("button", name="確定").click()
        expect(bob.get_by_text("有効", exact=True).first).to_be_visible(timeout=20000)
        report["checks"]["approver_turned_on_mfa"] = True
        bob.goto(base + "/assessments/scan_001")
        approve = panel(bob).get_by_role("button", name="この L2 検査を承認する")
        expect(approve).to_be_visible(timeout=30000)
        approve.click()
        step("approver_joins_and_approves")

        # ---- 5. alice reads the finding and the report -----------------------------------------
        alice.goto(base + "/assessments/scan_001")
        expect(panel(alice)).to_contain_text("所有者が「認証必須」とした資源を、別のアカウントが読めた", timeout=30000)
        expect(panel(alice)).to_contain_text("診断：終了しました", timeout=30000)
        shot(alice, "07-finding")
        r = alice.request.get(f"{base}/api/assessments/scan_001/report")
        md = r.json().get("markdown", "") if r.ok else ""
        report["checks"]["report_downloaded"] = r.ok and "IDOR" in md and "実証済み" in md
        step("read_finding_and_report")

        # ---- 6. the fix, and the after-fix check ------------------------------------------------
        lab.mode = "denied_403"
        fix = panel(alice).get_by_role("button", name="修正後の確認を開始")
        expect(fix).to_be_visible(timeout=20000)
        fix.click()
        expect(panel(alice).get_by_role("radio", name="認証必須")).to_be_visible(timeout=30000)
        panel(alice).get_by_role("radio", name="認証必須").check()
        panel(alice).get_by_role("button", name="仕様を記録する").click()
        bob.reload()
        approve = panel(bob).get_by_role("button", name="この L2 検査を承認する")
        expect(approve).to_be_visible(timeout=30000)
        approve.click()
        expect(panel(alice)).to_contain_text("改善を確認", timeout=30000)
        expect(panel(alice)).to_contain_text("現在の判定 再現せず")
        shot(alice, "08-fixed")
        step("fix_check")

        report["total_s"] = round(time.monotonic() - t0, 1)
        report["lab_paths"] = sorted({path for path, _ in lab.seen})
        report["page_errors"] = page_errors
        checked, clean = axe_gate(report["accessibility"])
        report["checks"]["accessibility_screens_checked"] = checked
        report["checks"]["accessibility_no_serious_violation"] = clean and checked == 8
        backend.shutdown()
        backend.drop_all()
        backend.server_close()
        registry.close_all()
        svc.close()
    lab.shutdown()
    failed = [k for k, v in report["checks"].items() if v is False]
    report["ok"] = not failed and not page_errors
    print(json.dumps(report, ensure_ascii=False, indent=1))
    if failed or page_errors:
        sys.exit(f"failed: {failed} {page_errors}")


if __name__ == "__main__":
    main()
