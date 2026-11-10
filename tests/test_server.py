"""Control-plane API: auth, CSRF guard, approval gating, emergency stop, SSE resume."""
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from aegis.assessment import AssessmentService
from aegis.lab import set_lab_mode, start_lab
from aegis.operators import OperatorStore, hash_password, totp_code
from aegis.runtime import WorkerPool
from aegis.server import make_handler

LAB_PORT = 18093


def seed_file(dir_: Path) -> Path:
    """Deterministic operators so tests know the passwords."""
    p = dir_ / "operators.json"
    p.write_text(json.dumps({"operators": [
        {"name": "op", "display": "操作者", "roles": ["operator"],
         "password_hash": hash_password("op-pw")},
        {"name": "appr", "display": "承認者", "roles": ["operator", "approver"],
         "password_hash": hash_password("appr-pw")},
    ]}))
    return p


class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = start_lab(LAB_PORT)

    @classmethod
    def tearDownClass(cls):
        cls.lab.shutdown()
        cls.lab.server_close()

    def setUp(self):
        set_lab_mode("vulnerable")
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.svc = AssessmentService(d, LAB_PORT, verify_seconds=30)
        self.ops = OperatorStore(seed_file(d))
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.svc, self.ops))
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.root = f"http://127.0.0.1:{self.srv.server_port}/api"
        self.base = f"{self.root}/assessments/scan_001"
        self.cookie = None

    def tearDown(self):
        self.svc.workers.kill_all()
        self.srv.shutdown()
        self.srv.server_close()
        self.tmp.cleanup()

    def _req(self, url, body=None, headers=None, method=None):
        h = {"Content-Type": "application/json"}
        if body is not None:
            h["X-Aegis-Request"] = "1"
        h.update(headers or {})          # explicit headers override defaults
        if self.cookie and "Cookie" not in h:
            h["Cookie"] = self.cookie
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data, h, method=method)
        try:
            with urllib.request.urlopen(req) as r:
                sc = r.headers.get("Set-Cookie")
                if sc:
                    self.cookie = sc.split(";")[0]
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def post(self, path, body=None, headers=None):
        return self._req(self.base + path, body if body is not None else {}, headers)

    def get(self, path=""):
        return self._req(self.base + path)[1]

    def login(self, name, password):
        return self._req(f"{self.root}/auth/login", {"name": name, "password": password})

    def wait_for(self, pred, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            s = self.get()
            if pred(s):
                return s
            time.sleep(0.1)
        self.fail(f"condition not met; last state={s['state']}")

    # ---- auth ---------------------------------------------------------------
    def test_requires_login(self):
        self.assertEqual(self.post("/start")[0], 401)
        self.assertEqual(self.get()["state"], "idle")

    def test_bad_password_rejected(self):
        self.assertEqual(self.login("op", "wrong")[0], 401)
        self.assertEqual(self.login("nobody", "op-pw")[0], 401)
        self.assertEqual(self.post("/start")[0], 401)

    def test_login_then_start(self):
        code, body = self.login("op", "op-pw")
        self.assertEqual(code, 200)
        self.assertEqual(body["session"]["operator"], "op")
        self.assertIsNotNone(self.cookie)
        self.assertEqual(self.post("/start")[0], 200)
        self.assertIn("auth.login", [e["event"] for e in self.get("/logs")["entries"]])

    def test_logout_invalidates_session(self):
        self.login("op", "op-pw")
        self.assertEqual(self._req(f"{self.root}/auth/logout", {})[0], 200)
        self.assertEqual(self.post("/pause")[0], 401)

    def test_operator_cannot_approve(self):
        self.login("op", "op-pw")
        self.post("/start")
        s = self.wait_for(lambda s: any(a["status"] == "pending" for a in s["approvals"]))
        rid = s["approvals"][0]["id"]
        self.assertEqual(self.post(f"/approvals/{rid}", {"decision": "approve"})[0], 403)

    def test_change_password_endpoint(self):
        pw = f"{self.root}/auth/password"
        self.assertEqual(self._req(pw, {"current": "op-pw", "new": "brand-new-pw"})[0], 401)  # needs login
        self.login("op", "op-pw")
        self.assertEqual(self._req(pw, {"current": "wrong", "new": "brand-new-pw"})[0], 400)
        self.assertEqual(self._req(pw, {"current": "op-pw", "new": "brand-new-pw"})[0], 200)
        self.assertIn("auth.password_changed", [e["event"] for e in self.get("/logs")["entries"]])
        # Old password is dead, new one works.
        self.assertEqual(self.login("op", "op-pw")[0], 401)
        self.assertEqual(self.login("op", "brand-new-pw")[0], 200)

    def test_mfa_enroll_and_login_flow(self):
        root = self.root
        self.login("op", "op-pw")
        # Enroll: get a secret, confirm with a current code.
        code, body = self._req(f"{root}/auth/totp/enroll", {})
        self.assertEqual(code, 200)
        secret = body["secret"]
        self.assertEqual(self._req(f"{root}/auth/totp/confirm", {"code": "000000"})[0], 400)  # wrong
        self.assertEqual(self._req(f"{root}/auth/totp/confirm", {"code": totp_code(secret)})[0], 200)
        # me now reports mfa_enabled.
        self.assertTrue(self._req(f"{root}/auth/me")[1]["session"]["mfa_enabled"])
        # A fresh client: password alone is challenged, password+code succeeds.
        self.cookie = None
        c, b = self.login("op", "op-pw")
        self.assertEqual(c, 401)
        self.assertTrue(b.get("mfa_required"))
        self.cookie = None
        self.assertEqual(self._req(f"{root}/auth/login",
                                   {"name": "op", "password": "op-pw", "code": totp_code(secret)})[0], 200)
        events = [e["event"] for e in self.get("/logs")["entries"]]
        self.assertIn("auth.mfa_enabled", events)

    def test_router_status_reports_no_autonomous_execution(self):
        status = self._req(f"{self.root}/router/status")[1]
        self.assertFalse(status["autonomous_execution"])    # off by design
        self.assertIn("connected", status)
        self.assertIsInstance(status["backends"], list)     # none configured in tests

    def test_evidence_summary_through_approval_and_lab_defense(self):
        self.login("appr", "appr-pw")
        self.svc.set_verify_seconds(0.05)
        initial = self.get()
        self.assertEqual(initial["evidence_summary"]["candidate"], 3)
        self.post("/start")
        pending = self.wait_for(lambda s: any(a["status"] == "pending" for a in s["approvals"]))
        self.assertGreater(pending["evidence_summary"]["detected"], 0)
        self.assertEqual(next(f for f in pending["findings"] if f["id"] == "f_banner")["evidence_status"], "detected")
        for approval in pending["approvals"]:
            self.assertEqual(self.post(f"/approvals/{approval['id']}", {"decision": "approve"})[0], 200)
        completed = self.wait_for(lambda s: s["state"] == "completed", timeout=15)
        self.assertEqual(next(f for f in completed["findings"] if f["id"] == "f_banner")["evidence_status"], "proven")
        code, after = self.post("/verify-fix")
        self.assertEqual(code, 200)
        self.assertEqual(after["evidence_summary"]["proven"], 0)
        self.assertGreater(after["evidence_summary"]["not_reproduced"], 0)
        self.assertTrue(after["defense_comparison"]["items"])
        self.assertTrue(self.get("/logs")["chain_valid"])
        for finding in after["findings"]:
            if finding["evidence_status"] == "not_reproduced":
                self.assertTrue(finding["evidence"][-1]["audit_hash"])
                self.assertIsNotNone(finding["evidence"][-1]["saved_at"])

    # ---- CSRF (independent of auth) ----------------------------------------
    def test_csrf_guard(self):
        self.login("appr", "appr-pw")
        self.assertEqual(self.post("/start", headers={"X-Aegis-Request": "0"})[0], 403)
        self.assertEqual(self.post("/start", headers={"Origin": "http://evil.example"})[0], 403)
        self.assertEqual(self.get()["state"], "idle")

    # ---- full flow with an approver ----------------------------------------
    def test_l2_waits_for_human_and_stop_kills_worker(self):
        self.login("appr", "appr-pw")
        self.assertEqual(self.post("/start")[0], 200)
        s = self.wait_for(lambda s: any(a["status"] == "pending" for a in s["approvals"]))
        self.assertNotIn("demo_verify", json.dumps(self.get("/logs")))
        rid = s["approvals"][0]["id"]
        self.assertEqual(self.post(f"/approvals/{rid}", {"decision": "approve"})[0], 200)
        self.wait_for(lambda s: any(f.get("_in_verification") for f in s["findings"]))
        time.sleep(0.5)
        code, body = self.post("/emergency-stop")
        rep = body["stop_report"]
        self.assertEqual(code, 200)
        self.assertTrue(rep["confirmed"])
        self.assertEqual(len(rep["killed_pids"]), 1)
        self.assertFalse(WorkerPool.group_alive(rep["killed_pids"][0]))
        s = self.get()
        self.assertEqual(s["state"], "stopped")
        self.assertEqual(next(f for f in s["findings"] if f["id"] == "f_banner")["verdict"], "aborted")
        self.assertEqual(self.post("/resume")[0], 409)
        self.assertTrue(self.get("/logs")["chain_valid"])

    def test_reject_skips_verification(self):
        self.login("appr", "appr-pw")
        self.post("/start")
        s = self.wait_for(lambda s: any(a["status"] == "pending" for a in s["approvals"]))
        self.post(f"/approvals/{s['approvals'][0]['id']}", {"decision": "reject"})
        s = self.wait_for(lambda s: s["state"] == "completed")
        v = next(p for p in s["phases"] if p["key"] == "verification")
        self.assertEqual(v["status"], "skipped")
        self.assertEqual(next(f for f in s["findings"] if f["id"] == "f_banner")["verdict"], "detected")

    def test_sse_resumes_after_last_event_id(self):
        self.login("appr", "appr-pw")
        self.post("/start")
        self.wait_for(lambda s: s["last_seq"] >= 5)
        req = urllib.request.Request(self.base + "/events", headers={"Last-Event-ID": "evt_3"})
        with urllib.request.urlopen(req, timeout=5) as r:
            ids = []
            for line in r:
                if line.startswith(b"id: "):
                    ids.append(int(line[len(b"id: evt_"):]))
                if len(ids) >= 2:
                    break
        self.assertEqual(ids, [4, 5])

    def test_chat_and_report_and_history(self):
        self.login("op", "op-pw")
        code, body = self.post("/chat", {"question": "なぜ検出されたのですか？", "term": "idor"})
        self.assertEqual(code, 200)
        self.assertIn("なぜ検出されたか", body["message"]["text"])
        self.assertEqual(len(body["chat_messages"]), 2)
        self.assertIn("chat.asked", [e["event"] for e in self.get("/logs")["entries"]])

        rep = self.get("/report")
        self.assertIn("# Vulnix セキュリティ診断レポート", rep["markdown"])
        self.assertTrue(rep["filename"].endswith(".md"))

        s = self.get()
        self.assertIn("history", s)
        self.assertEqual(s["history"]["previous_assessment_id"], "scan_000")

    def test_p0_live_control_verification_and_cve_sync(self):
        self.login("op", "op-pw")
        code, rep = self._req(f"{self.root}/system/verify-controls", {})
        self.assertEqual(code, 200)
        self.assertTrue(rep["all_passed"])
        check_ids = {c["id"]: c["passed"] for c in rep["checks"]}
        self.assertEqual(check_ids, {
            "egress_isolation": True,
            "privilege_escalation_prevention": True,
            "l2_approval_gate": True,
            "emergency_stop_sigkill": True,
            "netfilter_ruleset": True,
        })

        cve_st = self._req(f"{self.root}/cve/status")[1]
        self.assertGreaterEqual(cve_st["cve_count"], 2)
        self.assertGreaterEqual(cve_st["kev_count"], 2)
        sync_code, sync_res = self._req(f"{self.root}/cve/sync", {})
        self.assertEqual(sync_code, 200)
        self.assertGreaterEqual(sync_res["sync_count"], 1)

    def test_l2_reproduction_proof_and_post_patch_verify_fix(self):
        # Use short verify_seconds so L2 completes quickly with real reproduction_probe
        self.svc.set_verify_seconds(0.05)
        self.login("appr", "appr-pw")
        self.assertEqual(self.post("/start")[0], 200)
        s = self.wait_for(lambda s: any(a["status"] == "pending" for a in s["approvals"]))
        rid = s["approvals"][0]["id"]
        self.assertEqual(self.post(f"/approvals/{rid}", {"decision": "approve"})[0], 200)
        s = self.wait_for(lambda s: s["state"] == "completed", timeout=15)

        f_banner = next(f for f in s["findings"] if f["id"] == "f_banner")
        f_idor = next(f for f in s["findings"] if f["id"] == "f_idor")
        self.assertEqual(f_banner["verdict"], "proven")
        self.assertIsNotNone(f_banner["what_was_established"])
        self.assertEqual(f_idor["verdict"], "proven")
        self.assertIsNotNone(f_idor["what_was_established"])

        # Now run post-patch defense verification (/verify-fix)
        code, s_after = self.post("/verify-fix", {"mode": "patched"})
        self.assertEqual(code, 200)
        dc = s_after["defense_comparison"]
        self.assertEqual(dc["lab_mode"], "patched")
        self.assertGreater(dc["before_score"], 0)
        self.assertEqual(dc["after_score"], 0)
        self.assertTrue(all(item["after_verdict"] == "not_reproduced" for item in dc["items"]))

        f_banner_after = next(f for f in s_after["findings"] if f["id"] == "f_banner")
        f_idor_after = next(f for f in s_after["findings"] if f["id"] == "f_idor")
        self.assertEqual(f_banner_after["verdict"], "not_reproduced")
        self.assertEqual(f_idor_after["verdict"], "not_reproduced")

    def test_operator_registration_and_asset_registration(self):
        # 1. Register a new account via /api/auth/register
        code, body = self._req(f"{self.root}/auth/register", {
            "name": "sec-lead",
            "display": "セキュリティ責任者",
            "password": "strong-password-123",
            "roles": ["operator", "approver"],
        })
        self.assertEqual(code, 200)
        self.assertEqual(body["session"]["operator"], "sec-lead")
        self.assertIn("approver", body["session"]["roles"])

        # Duplicate username is rejected
        dup_code, _ = self._req(f"{self.root}/auth/register", {
            "name": "sec-lead",
            "password": "strong-password-123",
        })
        self.assertEqual(dup_code, 400)

        # 2. Register an authorized target asset via POST /api/assets
        acode, abody = self._req(f"{self.root}/assets", {
            "name": "portal.example.com",
            "kind": "Webアプリケーション",
            "environment": "検証環境",
            "authorization_ref": "SOW-2026-999",
            "ownership_verified": True,
            "activate_workspace": True,
        })
        self.assertEqual(acode, 200)
        self.assertEqual(abody["asset"]["name"], "portal.example.com")
        self.assertEqual(abody["asset"]["status"], "未診断")
        self.assertEqual(abody["asset"]["assessment_id"], "scan_001")
        ids = [a["id"] for a in abody["assets"]]
        self.assertEqual(len(ids), len(set(ids)))

        # 3. Register an asset without SOW -> locked as 承認待ち
        ucode, ubody = self._req(f"{self.root}/assets", {
            "name": "unapproved.example.com",
            "kind": "API",
            "environment": "本番環境",
            "authorization_ref": "",
            "ownership_verified": False,
        })
        self.assertEqual(ucode, 200)
        self.assertEqual(ubody["asset"]["status"], "承認待ち")
        self.assertIsNone(ubody["asset"]["assessment_id"])

        # 4. Delete unapproved asset and active asset via POST /api/assets/delete
        dcode, dbody = self._req(f"{self.root}/assets/delete", {"id": ubody["asset"]["id"]})
        self.assertEqual(dcode, 200)
        self.assertNotIn(ubody["asset"]["id"], [a["id"] for a in dbody["assets"]])

        dcode2, dbody2 = self._req(f"{self.root}/assets/delete", {"id": abody["asset"]["id"]})
        self.assertEqual(dcode2, 200)
        self.assertNotIn(abody["asset"]["id"], [a["id"] for a in dbody2["assets"]])

        # 5. Live on-demand verification of individual findings and 'all' via real Gateway + Worker
        vcode, vsnap = self.post("/verify-finding", {"finding_id": "f_sqli"})
        self.assertEqual(vcode, 200)
        f_sqli = next(f for f in vsnap["findings"] if f["id"] == "f_sqli")
        self.assertEqual(f_sqli["verdict"], "proven")
        self.assertTrue(any(e.get("audit_hash") for e in f_sqli["evidence"]))

        acode2, asnap = self.post("/verify-finding", {"finding_id": "all"})
        self.assertEqual(acode2, 200)
        self.assertFalse(any(f.get("demo_fixture") for f in asnap["findings"]))


if __name__ == "__main__":
    unittest.main()
