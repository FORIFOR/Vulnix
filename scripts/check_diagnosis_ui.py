"""The diagnosis loop panel (PR-B) in a real browser, on the authorized local lab.

Everything runs on loopback in this process: the access-control lab (the registered
lab target), the control plane (make_handler + AssessmentService + TenantRegistry), the
Next.js UI, and the ARTEX stand-in with the fixed-rule planner. No model, paid API,
public host or DNS is used.

PR-B is read only, so the loop is started here, in-process, the way the tests start it
(PR-C will add the screen's own controls). The L2 step still waits for a separate human
approver (`approver-human`, not the requester `qa`).

Checks, with screenshots:
 1. not started -> S1 contradicted -> waiting for the L2 approval -> S2 supported,
    shown live over SSE without a reload (desktop and 390px);
 2. the after-fix check: before/after comparison "改善を確認";
 3. SSE: a stream that never connects (polling backup), a stream that ends and
    reconnects, a duplicate and a replayed event carrying a forged view (dropped), and
    a control showing the same forged view is displayed when its sequence is new;
 4. another organization's member: 403 from the API, nothing on the screen;
 5. a backend restart: the open page picks up the restored, read-only record;
 6. a tampered audit log: the panel shows the refusal and no results.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from contextlib import ExitStack
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"
os.environ["VULNIX_EXTERNAL_PROPOSALS"] = "0"

from playwright.sync_api import expect, sync_playwright  # noqa: E402

from aegis import assessment as assessment_module  # noqa: E402
from aegis.adaptive_plan_runner import AdaptivePlanRunner  # noqa: E402
from aegis.adaptive_plan_state import PlanState  # noqa: E402
from aegis.assessment import AssessmentService  # noqa: E402
from aegis.diagnosis_judge import fixed_rule_steps  # noqa: E402
from aegis.diagnosis_loop import begin_fix_check, observe_lab_root, record_owner_spec  # noqa: E402
from aegis.operators import OperatorStore, hash_password  # noqa: E402
from aegis.server import make_handler  # noqa: E402
from aegis.tenancy import OrgStore, TenantRegistry  # noqa: E402
from scripts.axe_check import gate as axe_gate, run_axe  # noqa: E402
from tests import TEST_CONFINEMENT  # noqa: E402
from tests.diagnosis_planner import view_from_text  # noqa: E402
from tests.fixtures.access_control_lab import AccessControlLab  # noqa: E402
from tests.test_artex_bridge import FAKE  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
APPROVER = ("approver-human", ("operator", "approver"))
PARSER = argparse.ArgumentParser()
PARSER.add_argument("--production", action="store_true", help="Use an already built Next.js production bundle")
PARSER.add_argument("--chromium", action="store_true", help="Use Playwright Chromium instead of local Chrome")
PARSER.add_argument("--screenshots", type=Path, help="Directory for the screenshots")


class Backend(ThreadingHTTPServer):
    """Remembers its connections so a restart can drop them, as a real one would."""
    daemon_threads = True

    def __init__(self, port: int, handler):
        self.socks: set[socket.socket] = set()
        super().__init__(("127.0.0.1", port), handler)

    def process_request(self, request, client_address):
        self.socks.add(request)
        super().process_request(request, client_address)

    def drop_all(self):
        for s in list(self.socks):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_web(url: str, proc: subprocess.Popen) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("local Web server stopped before it was ready")
        try:
            with urllib.request.urlopen(url + "/login", timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError("local Web server did not become ready")


def titles(request: dict) -> str:
    return "\n".join(o.get("title", "") for o in request.get("observations") or [])


def forged_view() -> dict:
    """A view the server never sent. It must never appear unless its sequence is new."""
    h = "f" * 64
    return {"schema_version": 1, "lab_only": True, "assessment_id": "scan_001", "status": "ok",
            "restored": False, "persisted": True, "diag_id": "dg_forged", "generation": 9,
            "plan": None, "evidence": [], "fix_comparison": [], "next": {"kind": "none"},
            "hypotheses": [{"id": "H99", "claim": "intended_public", "target_ref": "T9", "state": "supported",
                            "purpose": "diagnose", "generation": 9, "supersedes": None, "basis": [],
                            "supporting": [], "contradicting": [], "inconclusive": []}],
            "steps": [{"plan_id": "x", "step_id": "S99", "catalog_id": "l1_http_probe", "level": "L1",
                       "hypothesis_id": "H99", "target_ref": "T9", "reason": "test_hypothesis",
                       "evidence_refs": [], "approved_by": None, "generation": 9,
                       "observation": {"evidence_id": "E99", "attrs": {"status": 200}},
                       "judgement": {"from": "open", "to": "supported", "rule": "denied"},
                       "result_audit_hash": h, "judged_audit_hash": h, "at": None}]}


def sse_body(events: list[dict]) -> str:
    out = "retry: 300\n\n"
    for ev in events:
        out += f"id: evt_{ev['seq']}\ndata: {json.dumps(ev, ensure_ascii=False)}\n\n"
    return out


def main() -> None:
    args = PARSER.parse_args()
    shots = args.screenshots
    if shots:
        shots.mkdir(parents=True, exist_ok=True)
    report: dict = {"screenshots": [], "checks": {}}
    lab = AccessControlLab("idor_vulnerable")
    threading.Thread(target=lab.serve_forever, daemon=True).start()
    env = {"AEGIS_ENV": "development", "VULNIX_PLANNER_ENGINE": "artex", "VULNIX_ARTEX_REAL_CMD": shlex.join(FAKE),
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
        passwords = {n: secrets.token_urlsafe(18) for n in ("qa", "approver-human", "outsider")}
        seed = data / "operators.json"
        seed.write_text(json.dumps({"operators": [
            {"name": "qa", "display": "QA (requester)", "roles": ["operator"],
             "password_hash": hash_password(passwords["qa"])},
            {"name": "approver-human", "display": "Approver", "roles": ["approver"],
             "password_hash": hash_password(passwords["approver-human"])},
            {"name": "outsider", "display": "Other org", "roles": ["operator"],
             "password_hash": hash_password(passwords["outsider"])}]}))
        ops = OperatorStore(seed)

        def new_service(path: Path) -> AssessmentService:
            return AssessmentService(path, lab.server_port, l2_confinement=TEST_CONFINEMENT, verify_seconds=0.1)

        def new_registry(svc):
            # the default organization holds the requester and the approver only
            store = OrgStore(data / "orgs.json",
                             bootstrap_members=lambda: {"qa": ["runner"], "approver-human": ["approver"]})
            return store, TenantRegistry(store, svc, new_service, data)

        svc = new_service(data)
        store, registry = new_registry(svc)
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

        def open_page(user: str, width: int, *, route=None):
            ctx = browser.new_context(viewport={"width": width, "height": 900})
            page = ctx.new_page()
            page.on("pageerror", lambda e: page_errors.append(f"{user}: {e}"))
            if route:
                page.route("**/api/assessments/*/events*", route)
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

        def shot(page, name: str, *, full: bool = False):
            if not shots:
                return
            path = shots / f"{name}.png"
            if full:
                page.screenshot(path=path, full_page=True)
            else:
                # the workspace header is sticky: let it scroll away so it does not cover the panel
                page.add_style_tag(content="header, .sticky { position: static !important; }")
                panel(page).locator("..").screenshot(path=path)
            report["screenshots"].append(str(path))

        report["accessibility"] = {}

        def no_overflow(page) -> bool:
            return page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

        # ---- 1. not started --------------------------------------------------------------
        desk = open_page("qa", 1280)
        expect(panel(desk)).to_contain_text("まだ診断ループを実行していません", timeout=20000)
        expect(panel(desk)).to_contain_text("ラボ専用")
        shot(desk, "01-not-started")
        report["accessibility"]["01-not-started"] = run_axe(desk)

        # pages that watch the same run through a broken stream
        streams = {"forged": 0, "blocked": 0}

        def forged_first(route):
            streams["forged"] += 1
            if streams["forged"] == 1:
                after = int(re.search(r"after=(\d+)", route.request.url).group(1))
                forged = forged_view()
                # a duplicate of the last applied sequence and an older replay: both dropped
                events = [{"seq": after, "type": "diagnosis.updated", "assessment_id": "scan_001",
                           "event_id": f"evt_{after}", "diagnosis": forged}]
                if after > 1:
                    events.append({"seq": after - 1, "type": "diagnosis.updated", "assessment_id": "scan_001",
                                   "event_id": f"evt_{after - 1}", "diagnosis": forged})
                route.fulfill(status=200, headers={"Content-Type": "text/event-stream"}, body=sse_body(events))
            else:
                route.continue_()            # the reconnect reaches the real stream

        def blocked(route):
            streams["blocked"] += 1
            route.abort()

        phone = open_page("qa", 390, route=forged_first)
        expect(panel(phone)).to_contain_text("まだ診断ループを実行していません", timeout=20000)
        no_events = open_page("qa", 1024, route=blocked)
        expect(panel(no_events)).to_contain_text("まだ診断ループを実行していません", timeout=20000)
        outsider = open_page("outsider", 1024)
        expect(panel(outsider)).to_contain_text("まだ診断ループを実行していません", timeout=20000)

        # ---- the loop, started in-process (PR-C adds the screen's controls) -----------------
        state = svc.diagnosis_state()
        observe_lab_root(svc, state)
        record_owner_spec(state, "T2", "authentication_required", actor="owner-alice")
        gate = threading.Event()
        asked: list[dict] = []

        def approve(item):
            asked.append(item)
            return APPROVER if gate.wait(120) else None

        result: dict = {}

        def run(label):
            runner = AdaptivePlanRunner(svc, actor="qa", roles=("operator",), diagnosis=state, approve=approve)
            plan = runner.run()
            result[label] = (plan.state, plan.reason)

        t = threading.Thread(target=run, args=("first",), daemon=True)
        t.start()
        expect(panel(desk)).to_contain_text("認証なしの要求は拒否された", timeout=30000)
        expect(panel(desk)).to_contain_text("L2 検査の承認が必要です", timeout=30000)
        deadline = time.monotonic() + 15
        while not asked and time.monotonic() < deadline:   # the item is listed before the runner asks
            time.sleep(0.05)
        assert len(asked) == 1 and asked[0]["catalog_id"] == "l2_idor", asked
        link = panel(desk).get_by_role("link", name="承認待ちの項目へ")
        target = link.get_attribute("href")
        report["checks"]["approval_link_target_exists"] = desk.locator(target).count() == 1
        shot(desk, "02-waiting-for-l2-approval")
        gate.set()
        t.join(60)
        assert result.get("first") == (PlanState.COMPLETED, "all_settled"), result
        expect(panel(desk)).to_contain_text("所有者が「認証必須」とした資源を、別のアカウントが読めた", timeout=20000)
        expect(panel(desk)).to_contain_text("修正したら、修正後の確認を行ってください")
        expect(panel(desk)).to_contain_text("L2・承認者 approver-human")
        expect(desk.locator("[data-testid=diagnosis-loop] [role=status][aria-live=polite]")).to_have_text(
            "S2 の判定：支持（成立）")
        report["checks"]["live_without_reload"] = desk.evaluate("window.__noReload === 1")
        shot(desk, "03-supported")

        # the 390px page: its first stream carried a forged duplicate and replay, then reconnected
        expect(panel(phone)).to_contain_text("別アカウントでの読み取り検査（L2）", timeout=20000)
        report["checks"]["forged_duplicate_never_shown"] = panel(phone).get_by_text("S99").count() == 0 \
            and panel(phone).get_by_text("H99").count() == 0
        report["checks"]["stream_reconnected"] = streams["forged"] >= 2
        report["checks"]["phone_no_horizontal_scroll"] = no_overflow(phone)
        shot(phone, "03m-supported-390")
        # the page whose stream never connected: the polling backup
        expect(panel(no_events)).to_contain_text("別アカウントでの読み取り検査（L2）", timeout=30000)
        report["checks"]["missed_events_recovered_by_refetch"] = streams["blocked"] >= 1
        # another organization: its own empty lab, nothing of this one
        report["checks"]["other_org_screen_empty"] = (
            panel(outsider).get_by_text("別アカウントでの読み取り検査").count() == 0
            and "まだ診断ループを実行していません" in panel(outsider).inner_text())
        denied = outsider.request.get(base + "/api/assessments/scan_001/diagnosis?org=default")
        report["checks"]["other_org_api_status"] = denied.status
        assert denied.status == 403, denied.status
        assert "dg_" not in denied.text()

        # ---- 2. the owner's fix, then the same check again -----------------------------------
        lab.mode = "denied_403"
        assert begin_fix_check(svc, state, {"T2": "authentication_required"}, actor="qa")
        run("fix")
        assert result.get("fix") == (PlanState.COMPLETED, "all_settled"), result
        expect(panel(desk)).to_contain_text("③ 修正の前後", timeout=20000)
        expect(panel(desk).get_by_text("改善を確認").first).to_be_visible()
        expect(panel(desk)).to_contain_text("世代 2・S1")
        shot(desk, "04-fix-confirmed")
        expect(panel(phone)).to_contain_text("③ 修正の前後", timeout=20000)
        report["checks"]["phone_fix_no_horizontal_scroll"] = no_overflow(phone)
        shot(phone, "04m-fix-confirmed-390")
        report["checks"]["other_org_still_empty"] = panel(outsider).get_by_text("修正の前後").count() == 0

        # control: the same forged view, sent with a new sequence, is shown - so the
        # duplicate check above was not passing for another reason
        shown = {"n": 0}

        def forged_new(route):
            shown["n"] += 1
            if shown["n"] == 1:
                after = int(re.search(r"after=(\d+)", route.request.url).group(1))
                route.fulfill(status=200, headers={"Content-Type": "text/event-stream"},
                              body=sse_body([{"seq": after + 1, "type": "diagnosis.updated",
                                              "assessment_id": "scan_001", "event_id": f"evt_{after + 1}",
                                              "diagnosis": forged_view()}]))
            else:
                route.abort()
        control = open_page("qa", 1024, route=forged_new)
        expect(panel(control)).to_contain_text("H99", timeout=20000)
        report["checks"]["control_new_sequence_is_applied"] = True
        control.context.close()

        # ---- 5. restart: the open page shows the restored, read-only record ---------------------
        backend.shutdown()
        backend.drop_all()
        backend.server_close()
        registry.close_all()
        svc.close()
        svc = new_service(data)
        store, registry = new_registry(svc)
        backend = Backend(port, make_handler(svc, ops, tenancy=registry))
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        restarted_at = time.monotonic()
        expect(panel(desk)).to_contain_text("再起動前の記録（読み取り専用）", timeout=45000)
        report["checks"]["restart_picked_up_without_reload_s"] = round(time.monotonic() - restarted_at, 1)
        report["checks"]["restart_without_reload"] = desk.evaluate("window.__noReload === 1")
        expect(panel(desk)).to_contain_text("改善を確認")
        shot(desk, "05-restored-after-restart")

        # ---- 6. a tampered audit log: the refusal, and nothing else --------------------------------
        log = data / "audit.jsonl"
        lines = log.read_text().splitlines()
        i = next(i for i, line in enumerate(lines) if '"diagnosis.judged"' in line)
        entry = json.loads(lines[i])
        entry["fields"]["rule"] = "denied"          # rewritten without re-hashing the chain
        lines[i] = json.dumps(entry, ensure_ascii=False, sort_keys=True)
        log.write_text("\n".join(lines) + "\n")
        desk.reload()
        expect(panel(desk).get_by_role("alert")).to_contain_text("記録を確かめられないため", timeout=20000)
        expect(panel(desk)).to_contain_text("監査ログのハッシュの鎖が壊れています")
        report["checks"]["refused_shows_no_steps"] = panel(desk).get_by_text("② 手順の記録").count() == 0 \
            and panel(desk).get_by_text("別アカウントでの読み取り検査").count() == 0
        shot(desk, "06-refused-tampered-log")
        report["accessibility"]["06-refused-tampered-log"] = run_axe(desk)
        phone.reload()
        expect(panel(phone).get_by_role("alert")).to_contain_text("記録を確かめられないため", timeout=20000)
        shot(phone, "06m-refused-390")
        report["accessibility"]["06m-refused-390"] = run_axe(phone)

        report["lab_paths"] = sorted({path for path, _ in lab.seen})
        report["checks"]["other_org"] = other_org
        report["page_errors"] = page_errors
        backend.shutdown()
        backend.drop_all()
        backend.server_close()
        registry.close_all()
        svc.close()
    lab.shutdown()
    checked, clean = axe_gate(report.get("accessibility", {}))
    report["checks"]["accessibility_no_serious_violation"] = clean and checked == 3
    failed = [k for k, v in report["checks"].items() if v is False]
    report["ok"] = not failed and not page_errors
    print(json.dumps(report, ensure_ascii=False, indent=1))
    if failed or page_errors:
        sys.exit(f"failed: {failed} {page_errors}")


if __name__ == "__main__":
    main()
