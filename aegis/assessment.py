"""Assessment model + demo runner that drives the real Gateway.

The runner plays the role of the control plane (not the AI): it requests human
approvals, mints tokens only after approval, and submits proposals to the
Gateway. Every worker it launches is a real process the emergency stop kills.
"""
from __future__ import annotations

import json
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import cve
from .audit import AuditLog
from .authz import ApprovalStore, Engagement, Target, TokenAuthority
from .events import EventBus
from .gateway import Gateway, State, http_probe_tool
from .network import EgressGuard
from .policy import ArgSpec, Budget, Tool
from .runtime import WorkerPool

SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}
VERDICT_FACTOR = {"proven": 1.0, "detected": 0.6, "unverified": 0.6, "aborted": 0.6,
                  "not_reproduced": 0.0}

EXECUTOR = {"agent": "Aegis デモランナー", "model": "未接続（ARTEX / Abliteration は未統合）"}


def demo_verify_tool(seconds: float) -> Tool:
    worker = str(Path(__file__).parent / "workers" / "demo_verify.py")
    return Tool("demo_verify", "safe_reproduction",
                {"url": ArgSpec(str, pattern=r"https?://[^\s]+")},
                lambda a, d: [sys.executable, "-I", worker, str(seconds)],
                timeout_s=seconds + 30)


@dataclass
class Assessment:
    id: str
    asset: dict
    engagement: Engagement
    target_url: str
    phases: list[dict]
    state: str = "idle"
    findings: dict[str, dict] = field(default_factory=dict)
    approvals: dict[str, dict] = field(default_factory=dict)
    activity: dict | None = None
    stop_report: dict | None = None


class AssessmentService:
    def __init__(self, data_dir: Path, lab_port: int, verify_seconds: float = 20):
        self.bus = EventBus()
        self.audit = AuditLog(data_dir / "audit.jsonl")
        self.audit.listeners.append(self._on_audit)
        self._lock = threading.RLock()
        now = time.time()
        target = Target("lab", hosts=("lab.test",), cidrs=("127.0.0.1/32",), ports=(lab_port,))
        eng = Engagement("eng_demo", True, "DEMO-AUTH-001（ローカル検証ラボ）", now - 60,
                         now + 8 * 3600, {"lab": target},
                         frozenset({"read_only_probe", "safe_reproduction"}))
        self.approval_store = ApprovalStore()
        self.tokens = TokenAuthority(secrets.token_bytes(32), time.time)
        self.workers = WorkerPool(max_concurrent=2)
        self.gateway = Gateway(
            engagement=eng, tokens=self.tokens, approvals=self.approval_store,
            egress=EgressGuard(lambda h: ["127.0.0.1"] if h == "lab.test" else []),
            workers=self.workers, audit=self.audit,
            tools={"http_probe": http_probe_tool(), "demo_verify": demo_verify_tool(verify_seconds)},
            budget=Budget(20))
        self.a = Assessment(
            id="scan_001",
            asset={"id": "lab", "name": "lab.test", "kind": "Webアプリケーション",
                   "environment": "ローカル検証ラボ（127.0.0.1）"},
            engagement=eng, target_url=f"http://lab.test:{lab_port}/",
            phases=[
                {"key": "scope", "label": "診断範囲を確認", "status": "pending", "detail": ""},
                {"key": "config", "label": "公開設定を検査", "status": "pending", "detail": ""},
                {"key": "analysis", "label": "検出結果を分析", "status": "pending", "detail": ""},
                {"key": "verification", "label": "脆弱性の検証", "status": "pending", "detail": ""},
                {"key": "report", "label": "結果をまとめる", "status": "pending", "detail": ""},
            ])
        for f in _fixture_findings():
            self.a.findings[f["id"]] = f
        self._approval_events: dict[str, threading.Event] = {}
        self._thread: threading.Thread | None = None

    # ---- snapshot -----------------------------------------------------------
    def assets(self) -> list[dict]:
        risk = self._risk()
        return [
            {**self.a.asset, "status": _asset_status(self.a.state), "assessment_id": self.a.id,
             "risk": risk if self.a.state != "idle" else None},
            {"id": "api", "name": "api.lab.test", "kind": "API", "environment": "検証環境",
             "status": "未診断", "assessment_id": None, "risk": None},
            {"id": "staging", "name": "internal-staging", "kind": "検証環境",
             "environment": "社内", "status": "承認待ち", "assessment_id": None, "risk": None,
             "note": "書面許可が未登録のため診断できません"},
        ]

    def snapshot(self) -> dict:
        with self._lock:
            e = self.a.engagement
            t = e.targets["lab"]
            return {
                "id": self.a.id, "asset": self.a.asset, "demo": True,
                "authorization": {
                    "status": "authorized" if e.ownership_verified and e.authorization_ref else "missing",
                    "ref": e.authorization_ref, "ownership_verified": e.ownership_verified,
                    "not_before": e.not_before, "not_after": e.not_after,
                    "scope": {"hosts": list(t.hosts), "cidrs": list(t.cidrs), "ports": list(t.ports)},
                    "allowed_actions": sorted(e.allowed_actions)},
                "state": self.a.state,
                "phases": [dict(p) for p in self.a.phases],
                "activity": self.a.activity,
                "approvals": list(self.a.approvals.values()),
                "findings": list(self.a.findings.values()),
                "risk": self._risk(),
                "stop_report": self.a.stop_report,
                "last_seq": self.bus.last_seq,
            }

    def logs(self) -> dict:
        return {"entries": self.audit.entries(), "chain_valid": self.audit.verify()}

    # ---- commands -----------------------------------------------------------
    def start(self) -> None:
        with self._lock:
            if self.a.state != "idle":
                raise ValueError(f"cannot start from {self.a.state}")
            self._set_state("running")
            self._thread = threading.Thread(target=self._run, daemon=True, name="runner")
            self._thread.start()

    def pause(self, actor: str) -> None:
        with self._lock:
            if self.a.state != "running":
                raise ValueError(f"cannot pause from {self.a.state}")
            self.gateway.pause(actor)
            self._set_state("paused")

    def resume(self, actor: str) -> None:
        with self._lock:
            if self.a.state != "paused":
                raise ValueError(f"cannot resume from {self.a.state}")
            self.gateway.resume(actor)   # re-validates engagement window
            self._set_state("running")

    def emergency_stop(self, actor: str) -> dict:
        rep = self.gateway.emergency_stop(actor)
        report = {"actor": actor, "confirmed": rep.confirmed, "killed_pids": rep.killed_pids,
                  "survivors": rep.survivors,
                  "steps": [{"name": n, "elapsed_ms": round(t * 1000, 2)} for n, t in rep.steps],
                  "at": time.time()}
        with self._lock:
            self.a.stop_report = report
            for p in self.a.phases:
                if p["status"] in ("pending", "running"):
                    self._phase(p["key"], "aborted", "緊急停止により中止")
            for f in self.a.findings.values():
                if f.get("_in_verification"):
                    self._upsert_finding({**f, "verdict": "aborted", "_in_verification": False})
            for ap in self.a.approvals.values():
                if ap["status"] == "pending":
                    self._decide(ap["id"], "rejected", actor, notify=False)
            self.a.activity = None
            self._set_state("stopped")
        self.bus.publish(self.a.id, "stop.report", stop_report=report)
        for ev in self._approval_events.values():
            ev.set()
        return report

    def decide_approval(self, approval_id: str, decision: str, actor: str) -> None:
        with self._lock:
            ap = self.a.approvals.get(approval_id)
            if ap is None or ap["status"] != "pending":
                raise ValueError("approval not pending")
            if self.a.state == "stopped":
                raise ValueError("assessment stopped")
            self._decide(approval_id, decision, actor)

    # ---- runner -------------------------------------------------------------
    def _run(self) -> None:
        try:
            self._run_inner()
        except _Stopped:
            pass

    def _run_inner(self) -> None:
        url = self.a.target_url
        self._phase("scope", "running", "許可範囲・期間・書面許可を照合しています")
        self._activity("診断範囲を確認", "Gateway（範囲検査）", "L1")
        self.gateway.engagement.check_active(time.time())
        self.gateway.egress.check(url, self.a.engagement.targets["lab"])
        self._phase("scope", "done", f"{url} は許可範囲内（127.0.0.1/32）")

        self._checkpoint()
        self._phase("config", "running", "HTTPレスポンスの公開設定を取得しています")
        self._activity("公開設定を検査（GET 1回・非破壊）", "http_probe", "L1")
        res, ev = self._exec("http_probe", "read_only_probe", {"url": url, "method": "GET"},
                             approval_actor="policy:auto-L1")
        if res is None:
            return
        self._phase("config", "done", f"HTTP {res['status']} を取得")

        self._checkpoint()
        self._phase("analysis", "running", "取得した応答から問題を判定しています")
        self._activity("検出結果を分析", "ルールベース判定", "L1")
        banner_id = self._analyze(res, ev)
        if "AI agent:" in res.get("body_prefix", ""):
            self.bus.publish(self.a.id, "agent.note",
                             message="ページ内にAI向けの指示文を検出しました。提案として扱われないため実行権限には影響しません。")
        self._phase("analysis", "done", f"{len(self._real_findings())} 件を検出")

        self._checkpoint()
        self._phase("verification", "running", "隔離環境での再現試験の承認を待っています")
        self._activity("脆弱性の検証（再現試験）", "demo_verify", "L2")
        ap_id = self._request_approval(
            "safe_reproduction", "L2", "古いApacheバージョンの再現試験",
            "検出したバージョン表示が実際に悪用可能かを、隔離Workerで確認します。"
            "このデモのWorkerは攻撃を行わず、一定時間待機するだけです。")
        if self.a.approvals[ap_id]["status"] != "approved":
            self._phase("verification", "skipped", "承認されなかったため実施していません")
        else:
            self._phase("verification", "running", "隔離Workerで検証中（デモWorker）")
            self._mark_verifying(banner_id, True)
            vres, vev = self._exec("demo_verify", "safe_reproduction", {"url": url},
                                   approval_id=self.a.approvals[ap_id]["approval_ref"])
            if vres is None:
                return
            f = self.a.findings[banner_id]
            self._upsert_finding({**f, "verdict": "unverified", "_in_verification": False,
                                  "verdict_note": "デモWorkerは再現試験を実装していないため、成立・不成立とも判定していません。",
                                  "evidence": f["evidence"] + [vev]})
            self._phase("verification", "done", "結果: 未検証（デモWorker）")

        self._checkpoint()
        self._phase("report", "running", "結果をまとめています")
        self._phase("report", "done", "診断が完了しました")
        with self._lock:
            self.a.activity = None
            self._set_state("completed")

    def _exec(self, tool, action, args, approval_actor=None, approval_id=None):
        self._checkpoint()
        if approval_id is None:
            approval_id = self.approval_store.approve(approval_actor, "eng_demo", "lab", action)
            self.audit.record("approval.auto", actor=approval_actor, action=action,
                              tool=tool, risk_level="L1")
        try:
            tok = self.tokens.issue(self.a.engagement, "lab", action, tool, approval_id,
                                    self.approval_store, ttl=120)
        except Exception as e:
            self._fail(f"トークン発行が拒否されました: {e}")
            return None, None
        d = self.gateway.execute({"tool": tool, "target_id": "lab", "action": action,
                                  "args": args}, tok)
        if self.gateway.state is State.STOPPED:
            raise _Stopped()
        if not d.allowed:
            self._fail(f"Gateway が拒否しました: {d.reason}")
            return None, None
        if d.result.killed or d.result.returncode != 0:
            self._fail(f"Worker が異常終了しました (rc={d.result.returncode})")
            return None, None
        entry = next(e for e in reversed(self.audit.entries()) if e["event"] == "result")
        evidence = {"evidence_id": "ev_" + entry["hash"][:12], "kind": f"{tool} 出力",
                    "saved_at": entry["ts"], "audit_hash": entry["hash"],
                    "content": d.result.stdout.strip()}
        return json.loads(d.result.stdout), evidence

    def _analyze(self, res: dict, ev: dict) -> str:
        h = {k.lower(): v for k, v in res["headers"].items()}
        banner = h.get("server", "")
        bid = "f_banner"
        # CVE candidates come from the catalog engine (detection only, not proof).
        candidates = cve.detect_from_banner(banner, source="server-header")
        if candidates:
            cve_ids = sorted({c.cve.id for c in candidates})
            self._upsert_finding({
                "id": bid, "title": "既知の脆弱性に該当するWebサーバーのバージョン表示",
                "severity": "high", "verdict": "detected", "category": "既知の脆弱性（CVE）",
                "cve": cve_ids, "risk_level": "L2",
                "help_term": "cve",
                "summary": f"Server ヘッダーが「{banner}」を示しています。このバージョンはパス・トラバーサル等の既知脆弱性の影響範囲です。",
                "why_detected": "応答ヘッダーのバージョン文字列が、公開されている影響バージョンと一致したためです。",
                "caveat": "バージョン表示が一致しただけで、実際に悪用できるかは確認していません。表示を偽装・改変している場合もあります。",
                "evidence": [ev],
                "remediation": {"steps": ["Apache HTTP Server を最新の安定版に更新する",
                                          "Server ヘッダーのバージョン表示を抑制する（ServerTokens Prod）"],
                                "how_to_verify": "更新後に同じ検査を実行し、表示と再現試験の結果が変わることを確認します。"},
                "executor": {**EXECUTOR, "tool": "http_probe"}, "demo_fixture": False})
        missing = [x for x in ("content-security-policy", "x-content-type-options",
                               "strict-transport-security") if x not in h]
        if missing:
            self._upsert_finding({
                "id": "f_headers", "title": "セキュリティヘッダーが設定されていない",
                "severity": "low", "verdict": "proven", "category": "設定不備", "cve": [],
                "risk_level": "L1", "help_term": "security_headers",
                "summary": "ブラウザ側の防御を有効にするヘッダーが応答に含まれていません。",
                "what_was_established": "実際のHTTP応答に " + ", ".join(missing) + " が含まれないことを確認しました。",
                "why_detected": "取得した応答ヘッダーを直接確認した結果です。",
                "evidence": [ev],
                "remediation": {"steps": [f"{m} を設定する" for m in missing],
                                "how_to_verify": "修正後に同じGET検査を行い、ヘッダーが返ることを確認します。"},
                "executor": {**EXECUTOR, "tool": "http_probe"}, "demo_fixture": False})
        if "x-powered-by" in h:
            self._upsert_finding({
                "id": "f_powered", "title": "使用技術のバージョンが露出している",
                "severity": "low", "verdict": "proven", "category": "情報露出", "cve": [],
                "risk_level": "L1", "help_term": "info_disclosure",
                "summary": f"X-Powered-By ヘッダーが「{h['x-powered-by']}」を示しています。",
                "what_was_established": "実際のHTTP応答で X-Powered-By ヘッダーが返されることを確認しました。",
                "why_detected": "取得した応答ヘッダーを直接確認した結果です。",
                "evidence": [ev],
                "remediation": {"steps": ["php.ini で expose_php = Off を設定する"],
                                "how_to_verify": "修正後に同じGET検査を行い、ヘッダーが返らないことを確認します。"},
                "executor": {**EXECUTOR, "tool": "http_probe"}, "demo_fixture": False})
        return bid

    # ---- helpers ------------------------------------------------------------
    def _request_approval(self, action, level, title, description) -> str:
        aid = "req_" + secrets.token_hex(4)
        ev = threading.Event()
        with self._lock:
            self._approval_events[aid] = ev
            self.a.approvals[aid] = {"id": aid, "action": action, "risk_level": level,
                                     "title": title, "description": description,
                                     "status": "pending", "decided_by": None,
                                     "decided_at": None, "approval_ref": None}
            self._publish_approval(aid)
        while not ev.wait(0.2):
            self._checkpoint(allow_pause=True)
        self._checkpoint()
        return aid

    def _decide(self, aid, decision, actor, notify=True):
        ap = self.a.approvals[aid]
        ap["status"] = "approved" if decision == "approve" else "rejected"
        ap["decided_by"], ap["decided_at"] = actor, time.time()
        if ap["status"] == "approved":
            ap["approval_ref"] = self.approval_store.approve(actor, "eng_demo", "lab", ap["action"])
        self.audit.record("approval." + ap["status"], request=aid, actor=actor,
                          action=ap["action"], risk_level=ap["risk_level"])
        self._publish_approval(aid)
        if notify and aid in self._approval_events:
            self._approval_events[aid].set()

    def _publish_approval(self, aid):
        self.bus.publish(self.a.id, "approval.updated", approval=dict(self.a.approvals[aid]))

    def _checkpoint(self, allow_pause=False) -> None:
        while True:
            if self.gateway.state is State.STOPPED or self.a.state == "stopped":
                raise _Stopped()
            if self.a.state != "paused" or allow_pause:
                return
            time.sleep(0.2)

    def _phase(self, key, status, detail):
        with self._lock:
            p = next(p for p in self.a.phases if p["key"] == key)
            p["status"], p["detail"] = status, detail
            self.bus.publish(self.a.id, "phase.updated", phase=key, status=status,
                             message=detail, phases=[dict(x) for x in self.a.phases])

    def _activity(self, title, tool, level):
        with self._lock:
            self.a.activity = {"title": title, "tool": tool, "risk_level": level, **EXECUTOR}
            self.bus.publish(self.a.id, "activity.updated", activity=self.a.activity)

    def _set_state(self, state):
        self.a.state = state
        self.bus.publish(self.a.id, "assessment.state", state=state, risk=self._risk())

    def _upsert_finding(self, f):
        with self._lock:
            self.a.findings[f["id"]] = f
            self.bus.publish(self.a.id, "finding.upserted", finding=f, risk=self._risk())

    def _mark_verifying(self, fid, flag):
        f = self.a.findings.get(fid)
        if f:
            self._upsert_finding({**f, "_in_verification": flag})

    def _fail(self, msg):
        with self._lock:
            for p in self.a.phases:
                if p["status"] == "running":
                    self._phase(p["key"], "aborted", msg)
            self.a.activity = None
            self._set_state("failed")

    def _real_findings(self):
        return [f for f in self.a.findings.values() if not f["demo_fixture"]]

    def _risk(self) -> dict:
        fs = self._real_findings()
        score = min(100, round(sum(SEVERITY_WEIGHT[f["severity"]] * VERDICT_FACTOR[f["verdict"]]
                                   for f in fs)))
        label = "高リスク" if score >= 70 else "中リスク" if score >= 40 else "低リスク"
        return {"score": score, "label": label,
                "provisional": self.a.state != "completed",
                "basis": "架空データを除く検出結果の深刻度 × 判定（実証=1.0, 検出・未検証=0.6, 再現せず=0）の合計（上限100）"}

    def _on_audit(self, entry: dict) -> None:
        self.bus.publish(self.a.id if hasattr(self, "a") else "scan_001", "audit.recorded",
                         entry={k: entry[k] for k in ("ts", "event", "fields", "prev", "hash")})


class _Stopped(Exception):
    pass


def _asset_status(state: str) -> str:
    return {"idle": "未診断", "running": "診断中", "paused": "一時停止中",
            "stopped": "中止", "failed": "失敗", "completed": "診断済み"}[state]


def _fixture_findings() -> list[dict]:
    """Fictional examples so every verdict style is visible. Flagged and labelled."""
    common = {"demo_fixture": True, "executor": {**EXECUTOR, "tool": "（架空）"}}
    return [
        {**common, "id": "fx_idor", "title": "他の利用者のリソースへアクセスできる（架空の例）",
         "severity": "high", "verdict": "proven", "category": "アクセス制御", "cve": [],
         "risk_level": "L2", "help_term": "idor",
         "summary": "検証用アカウントAで、検証用アカウントBのリソースIDを指定すると内容が返る想定例です。",
         "what_was_established": "権限のないテストアカウントから、別の検証用リソースへのアクセスが成立しました（架空の表示例）。",
         "why_detected": "（架空）レスポンスに他アカウントのリソースIDと所有者情報が含まれていたためです。",
         "evidence": [{"evidence_id": "ev_fixture_1", "kind": "架空の証拠", "saved_at": None,
                       "audit_hash": None, "content": "これは表示例です。実際の検証は行っていません。"}],
         "remediation": {"steps": ["サーバー側でリソースの所有者を必ず照合する"],
                         "how_to_verify": "修正後に同じ手順で再試験し、403 が返ることを確認します。"}},
        {**common, "id": "fx_sqli", "title": "検索欄のSQLインジェクション（架空の例・修正後）",
         "severity": "critical", "verdict": "not_reproduced", "category": "インジェクション",
         "cve": [], "risk_level": "L2", "help_term": "sqli",
         "summary": "修正前の環境では成立し、修正後の環境では同じ試験で成立しなかった想定例です。",
         "why_detected": "（架空）修正前の環境でエラー応答の差分が観測されたためです。",
         "caveat": "「再現せず」は実施した検証条件で成立しなかったという意味です。すべての攻撃を防げる保証ではありません。",
         "evidence": [{"evidence_id": "ev_fixture_2", "kind": "架空の証拠", "saved_at": None,
                       "audit_hash": None, "content": "これは表示例です。実際の検証は行っていません。"}],
         "remediation": {"steps": ["プレースホルダー付きクエリを使う"],
                         "how_to_verify": "修正前後で同じ試験を行い、結果を比較します。"}},
    ]
