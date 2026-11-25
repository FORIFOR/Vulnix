"""Exercise the folder and two-person approvals on a local Linux Worker."""

import json
import hashlib
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from aegis.assessment import AssessmentService
from aegis.local_defense import PROFILE
from aegis.operators import OperatorStore, hash_password
from aegis.server import make_handler
from aegis.tenancy import DEFAULT_ORG, OrgStore, TenantRegistry, default_members_from
from scripts.check_diagnosis_ui import Backend, free_port, wait_for_web
from tests.test_local_defense import synthetic_bundle

ROOT = Path(__file__).resolve().parents[1]


def populate_folder(folder):
    for name in PROFILE["files"]:
        target = folder / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)


def check_browser(base, folder, passwords, *, node_folder=None, org=None, profile_id=None, closed=False):
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome" if sys.platform == "darwin" else None)
        pages = [browser.new_page() for _ in passwords]
        for page, (name, password) in zip(pages, passwords.items()):
            page.route("**/*", lambda route: route.continue_() if route.request.url.startswith(base + "/")
                       else route.abort())
            page.goto(base + "/login")
            login = page.request.post(base + "/api/auth/login", data={"name": name, "password": password},
                                      headers={"Origin": base, "X-Aegis-Request": "1"})
            assert login.ok, login.status
            if org:
                page.context.add_cookies([{"name": "vulnix_org", "value": org, "url": base}])
            page.goto(base + "/quick-defense")
            page.get_by_role("button", name="実行計画を見る").click()
            expect(page.get_by_text("計画 SHA-256", exact=True)).to_be_visible()
        requester, approver = pages
        select = requester.locator("input[webkitdirectory]")
        results = []
        for project in (folder, folder, node_folder):
            if not project:
                continue
            select.set_input_files(str(project))
            if project == node_folder:
                requester.get_by_label("検証プロファイル").select_option("reviewed-node-d34b9f3")
            elif profile_id:
                requester.get_by_label("検証プロファイル").select_option(profile_id)
            requester.get_by_role("button", name=("再検証を依頼する" if results else "実行を依頼する")).click()
            expect(requester.get_by_text("承認待ち ／ 依頼者", exact=False)).to_be_visible()
            expect(requester.get_by_role("button", name="この計画を承認する")).to_have_count(0)
            view = requester.request.get(base + "/api/assets/local-defense").json()
            same_actor = requester.request.post(
                f"{base}/api/assessments/{view['assessment']}/approvals/{view['job']['id']}",
                data={"decision": "approve"}, headers={"Origin": base, "X-Aegis-Request": "1"})
            assert same_actor.status == 403
            approval = approver.get_by_role("button", name="この計画を承認する")
            expect(approval).to_be_visible(timeout=10000)
            approval.click()
            requester.get_by_role("button", name="承認済みの隔離検証を開始する").click()
            label = "対策が必要" if closed else "動作確認済み"
            expect(requester.get_by_text(f"ローカル隔離での結果 ／ {label}", exact=True)).to_be_visible(timeout=30000)
            status = requester.request.get(base + "/api/assets/local-defense").json()["job"]["receipt"]
            assert status["result"]["confinement_verified"] is True
            if profile_id:
                assert status["result"]["observation"]["checks"]["authorization"]["observed"] == {
                    "allow": not closed, "deny": False}
                item = requester.get_by_text(f"認可 ／ {label}", exact=True)
                expect(item).to_be_visible()
                if closed:
                    item.click()
                    expect(requester.get_by_text("対象操作の必要権限をサーバー側で確認", exact=False)).to_be_visible()
            results.append(status["run_id"])
        assert len(results) == len(set(results))
        requester.get_by_role("button", name="再検証を依頼する").click()
        expect(requester.get_by_text("承認待ち ／ 依頼者", exact=False)).to_be_visible()
        if node_folder:
            # Staging the reviewed Node bundle keeps this run active long
            # enough to exercise the actual cancellation control.
            approver.get_by_role("button", name="この計画を承認する").click()
            requester.get_by_role("button", name="承認済みの隔離検証を開始する").click()
            expect(requester.get_by_text("隔離実行中 ／ 依頼者", exact=False)).to_be_visible()
        requester.get_by_role("button", name="隔離検証を中断する").click()
        expect(requester.get_by_text("中断 ／ 依頼者", exact=False)).to_be_visible(timeout=30000)
        assert requester.request.get(base + "/api/assets/local-defense").json()["job"]["receipt"] is None
        browser.close()
    return len(results)


def make_backend(data, port, passwords, *, node_bundle=None, registry_root=None):
    seed = data / "operators.json"
    seed.write_text(json.dumps({"operators": [
        {"name": name, "display": name, "roles": ["operator", "approver", "admin"],
         "password_hash": hash_password(password)}
        for name, password in passwords.items()
    ]}))
    seed.chmod(0o600)
    ops = OperatorStore(seed)
    svc = AssessmentService(data, 18081)
    registry = TenantRegistry(OrgStore(data / "orgs.json", bootstrap_members=lambda: default_members_from(ops)),
                              svc, lambda path: AssessmentService(path, 18081), data)
    profile_registry = None
    if registry_root:
        requester, approver = passwords
        org = registry.store.create_org("Portable defence acceptance", requester)
        _, invite = registry.store.create_invite(org, requester, ["approver"])
        registry.store.accept_invite(invite, approver)
        node = Path(shutil.which("node")).resolve(strict=True)
        with node.open("rb") as binary:
            node_hash = hashlib.file_digest(binary, "sha256").hexdigest()
        profile_registry = registry_root / "registry.json"
        ports = []
        for bundle, health in (("synthetic-node", "healthy"), ("synthetic-node-closed", "closed")):
            digest = synthetic_bundle(registry_root / bundle, "node", health=health)
            ports.append({"org": org, "bundle": bundle, "sha256": digest, "node": {"path": str(node), "sha256": node_hash}})
        profile_registry.write_text(json.dumps(ports))
        profile_registry.chmod(0o600)
    handler = make_handler(svc, ops, tenancy=registry, local_defense_python_root=ROOT,
                           local_defense_node_bundle=node_bundle, local_defense_registry=profile_registry)
    return Backend(port, handler), svc, registry


def main():
    assert os.environ.get("VULNIX_NO_ENV_LOCAL") == "1"
    passwords = {name: secrets.token_urlsafe(24) for name in ("requester", "approver")}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        data = tmp / "control"
        data.mkdir(mode=0o700)
        folder = tmp / "reviewed"
        populate_folder(folder)
        backend, svc, registry = make_backend(data, free_port(), passwords, registry_root=tmp)
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
            def resources():
                return {p for parent, name in (("/sys/fs/cgroup", "aegis_l2_*"),
                            ("/run/netns", "aegis_l2_*"), ("/tmp", "vulnix-defense-*"),
                            ("/tmp", "vulnix-worker-*")) for p in Path(parent).glob(name)}
            before = resources()
            assert check_browser(base, folder, passwords) == 2
            org = next(item["id"] for item in registry.store.orgs_of("requester") if item["id"] != DEFAULT_ORG)
            synthetic = tmp / "synthetic-node" / "source"
            assert check_browser(base, synthetic, passwords, org=org, profile_id="profile-synthetic-node") == 2
            closed = tmp / "synthetic-node-closed" / "source"
            assert check_browser(base, closed, passwords, org=org, profile_id="profile-synthetic-node-closed", closed=True) == 2
            assert resources() == before
            print("Reviewed defence: Python and portable Node in separate organizations; each rerun completed")
        finally:
            web.terminate()
            web.wait(timeout=10)
            backend.shutdown()
            backend.server_close()
            registry.close_all()
            svc.close()


if __name__ == "__main__":
    main()
