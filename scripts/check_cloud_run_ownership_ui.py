"""Offline browser flow through Cloud Run ownership and scope confirmation.

Only a mock .test host, generated RSA key, and in-process HTML fetch are used.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"
os.environ["VULNIX_EXTERNAL_PROPOSALS"] = "0"
os.environ["VULNIX_REAL_SERVICE_DIAGNOSIS"] = "l1"

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from google.auth import crypt, jwt  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

from aegis import assessment as assessment_module  # noqa: E402
from aegis import cloud_run_ownership as cloud_module  # noqa: E402
from aegis.assessment import AssessmentService  # noqa: E402
from aegis.google_oidc import GOOGLE_CERTS_URL, verify_google_id_token  # noqa: E402
from aegis.operators import OperatorStore, hash_password  # noqa: E402
from aegis.server import make_handler  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
HOST = "owned.example.test"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer = crypt.RSASigner.from_string(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def cert_request(url, **_kwargs):
        assert url == GOOGLE_CERTS_URL
        class Response:
            status = 200
            data = json.dumps({"test-key": public}).encode()
        return Response()

    def verifier(token, audience):
        return verify_google_id_token(token, audience, request=cert_request)

    mock_html = [""]
    def fetch(host, address, **_kwargs):
        assert host == HOST and address == "8.8.8.8"
        return mock_html[0]

    with tempfile.TemporaryDirectory() as tmp:
        data = Path(tmp)
        password = secrets.token_urlsafe(18)
        seed = data / "operators.json"
        seed.write_text(json.dumps({"operators": [{
            "name": "qa", "roles": ["admin", "operator", "approver"],
            "password_hash": hash_password(password)}]}))
        svc = AssessmentService(data, 18081, real_site_read_only=True)
        ops = OperatorStore(seed)
        backend = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(svc, ops))
        backend.daemon_threads = True
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        port = free_port()
        base = f"http://127.0.0.1:{port}"
        env = {**os.environ, "AEGIS_API": f"http://127.0.0.1:{backend.server_port}"}
        web = subprocess.Popen([str(ROOT / "web/node_modules/.bin/next"), "start", "-H", "127.0.0.1",
                                "-p", str(port)], cwd=ROOT / "web", env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            original_binding = svc.cloud_run_binding
            def delayed_binding(*args, **kwargs):
                time.sleep(0.4)
                return original_binding(*args, **kwargs)
            with patch.object(assessment_module, "verify_google_id_token", side_effect=verifier), \
                 patch.object(cloud_module, "resolve_public_addresses", return_value=["8.8.8.8"]), \
                 patch.object(cloud_module, "fetch_proof_file_pinned", side_effect=fetch), \
                 patch.object(svc, "cloud_run_binding", side_effect=delayed_binding), \
                 patch.object(svc, "start", return_value=svc.snapshot()), sync_playwright() as playwright:
                browser = (playwright.chromium.launch(headless=True) if os.environ.get("CI") else
                           playwright.chromium.launch(channel="chrome", headless=True))
                try:
                    page = browser.new_page(viewport={"width": 800, "height": 900})
                    page.goto(base + "/login", wait_until="domcontentloaded", timeout=30000)
                    page.get_by_label("ユーザー名", exact=True).fill("qa")
                    page.get_by_label("パスワード", exact=True).fill(password)
                    page.get_by_role("button", name="ログイン", exact=True).click()
                    page.wait_for_url("**/dashboard")
                    page.get_by_role("button", name="＋ サイトを診断する").click()
                    page.get_by_label("診断するサイトのURL").fill(f"https://{HOST}/")
                    page.get_by_role("button", name="所有確認へ").click()
                    page.get_by_text("Cloud Run OIDC 所有確認").wait_for()
                    page.get_by_label("登録するサービスアカウントの sub").fill("service-account-123")
                    page.get_by_role("button", name="主体を登録").click()
                    page.get_by_text("状態: 検証待ち", exact=True).wait_for()
                    page.get_by_role("button", name="登録を解除").click()
                    page.get_by_text("状態: 失効", exact=True).wait_for()
                    assert svc.cloud_run_store.binding("default", HOST) is None
                    page.get_by_role("button", name="主体を登録").click()
                    page.get_by_role("button", name="チャレンジ発行").click()
                    page.get_by_text("有効期限:").wait_for()
                    issued = svc.cloud_run_store.binding("default", HOST)
                    assert issued and issued[0] == "service-account-123"
                    # Read the active challenge from the same local mock store.
                    with svc.cloud_run_store._connection() as db:
                        row = db.execute("SELECT challenge,audience FROM challenges WHERE host=?", (HOST,)).fetchone()
                    assert row
                    challenge, audience = row["challenge"], row["audience"]
                    mock_html[0] = (f'<html><head><meta name="vulnix-verify" '
                                    f'content="vulnix-cloud-run={challenge}"></head></html>')
                    now = int(time.time())
                    token = jwt.encode(signer, {"iss": "https://accounts.google.com", "aud": audience,
                                                "sub": "service-account-123", "iat": now - 1,
                                                "exp": now + 120}, key_id="test-key").decode()
                    page.get_by_label("Google署名付き ID トークン").fill(token)
                    page.get_by_role("button", name="Cloud Run で確認").click()
                    page.get_by_text("所有確認が完了しました", exact=False).wait_for()
                    assert svc._external_entry(HOST) is None
                    page.get_by_label("このサイトの管理者として").check()
                    page.get_by_role("button", name="診断を開始", exact=True).click()
                    page.wait_for_url("**/assessments/*")
                    assert svc._external_entry(HOST) is not None
                    print(json.dumps({"ui": "passed", "signed_token": True,
                                      "scope_confirmed": True, "real_host_traffic": False}))
                finally:
                    browser.close()
        finally:
            web.terminate()
            try:
                web.wait(timeout=5)
            except subprocess.TimeoutExpired:
                web.kill()
            backend.shutdown()
            backend.server_close()
            svc.close()


if __name__ == "__main__":
    main()
