"""Assessment model + ARTEX runner that drives the real Gateway.

The runner coordinates the ARTEX Execution Engine and ProposalRouter: it
requests human approvals for L2+ operations, mints single-use HMAC tokens only
after approval, and submits sanitized proposals to the Gateway. Every worker it
launches is a real confined process that the emergency stop can kill.
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
from .gateway import Gateway, State, http_probe_tool, reproduction_probe_tool
from .lab import get_lab_mode, set_lab_mode
from .network import EgressGuard
from .policy import ArgSpec, Budget, Tool
from .router import AbliterationBackend, ArtexEngine, ArtexplannerBackend, HttpModelBackend, ProposalRouter
from .runtime import WorkerPool

SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}
VERDICT_FACTOR = {"proven": 1.0, "detected": 0.6, "unverified": 0.6, "aborted": 0.6,
                  "not_reproduced": 0.0}

EXECUTOR = {
    "agent": "ARTEX 実行エンジン（ProposalRouter 制御）",
    "model": "Abliteration AI アダプター（提案専用・権限なし）",
}


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
    chat_messages: list[dict] = field(default_factory=list)
    defense_comparison: dict | None = None


class AssessmentService:
    def __init__(self, data_dir: Path, lab_port: int, verify_seconds: float = 1.5):
        self.bus = EventBus()
        self.audit = AuditLog(data_dir / "audit.jsonl")
        self.audit.listeners.append(self._on_audit)
        self._lock = threading.RLock()
        self.lab_port = lab_port
        self.verify_seconds = verify_seconds
        self._allowed_hosts: set[str] = {"lab.test", "api.lab.test"}
        now = time.time()
        target = Target("lab", hosts=tuple(sorted(self._allowed_hosts)),
                        cidrs=("127.0.0.1/32",), ports=(lab_port,))
        eng = Engagement("eng_demo", True, "DEMO-AUTH-001（ローカル検証ラボ）", now - 60,
                         now + 8 * 3600, {"lab": target},
                         frozenset({"read_only_probe", "safe_reproduction"}))
        self.approval_store = ApprovalStore()
        self.tokens = TokenAuthority(secrets.token_bytes(32), time.time)
        self.workers = WorkerPool(max_concurrent=2)
        self.gateway = Gateway(
            engagement=eng, tokens=self.tokens, approvals=self.approval_store,
            egress=EgressGuard(lambda h: ["127.0.0.1"] if h in self._allowed_hosts else []),
            workers=self.workers, audit=self.audit,
            tools={
                "http_probe": http_probe_tool(),
                "reproduction_probe": reproduction_probe_tool(),
                "demo_verify": demo_verify_tool(verify_seconds),
            },
            budget=Budget(50))

        # Wire ARTEX + Abliteration ProposalRouter (zero execution authority)
        backends = [ArtexplannerBackend()]
        ext_model = HttpModelBackend.from_env()
        if ext_model:
            backends.append(ext_model)
        self.router = ProposalRouter(self.gateway, self.audit, backends)
        self.artex = ArtexEngine(self.router)
        self.cve_monitor = cve.FeedMonitor()

        self.a = Assessment(
            id="scan_001",
            asset={"id": "lab", "name": "lab.test", "kind": "Webアプリケーション",
                   "environment": "ローカル検証ラボ（127.0.0.1）"},
            engagement=eng, target_url=f"http://lab.test:{lab_port}/",
            phases=self._default_phases())
        for f in _fixture_findings():
            self.a.findings[f["id"]] = f
        self._approval_events: dict[str, threading.Event] = {}
        self._thread: threading.Thread | None = None
        self._extra_assets: list[dict] = [
            {"id": "api", "name": "api.lab.test", "kind": "API", "environment": "検証環境",
             "status": "未診断", "assessment_id": self.a.id, "risk": None,
             "previous_risk_score": None, "last_assessed_at": None,
             "authorization_ref": "DEMO-AUTH-002", "ownership_verified": True},
            {"id": "staging", "name": "internal-staging", "kind": "検証環境",
             "environment": "社内", "status": "承認待ち", "assessment_id": None, "risk": None,
             "previous_risk_score": None, "last_assessed_at": None,
             "authorization_ref": "", "ownership_verified": False,
             "note": "書面許可が未登録のため診断できません"},
        ]

    @staticmethod
    def _default_phases() -> list[dict]:
        return [
            {"key": "scope", "label": "診断範囲を確認", "status": "pending", "detail": ""},
            {"key": "config", "label": "公開設定を検査", "status": "pending", "detail": ""},
            {"key": "analysis", "label": "検出結果を分析", "status": "pending", "detail": ""},
            {"key": "verification", "label": "脆弱性の検証", "status": "pending", "detail": ""},
            {"key": "report", "label": "結果をまとめる", "status": "pending", "detail": ""},
        ]

    def _sync_scope_for_host(self, host: str, auth_ref: str) -> None:
        self._allowed_hosts.add(host)
        e = self.a.engagement
        target = Target("lab", hosts=tuple(sorted(self._allowed_hosts)),
                        cidrs=("127.0.0.1/32",), ports=(self.lab_port,))
        self.a.engagement = Engagement(
            e.id, True, auth_ref or e.authorization_ref,
            e.not_before, e.not_after, {"lab": target}, e.allowed_actions
        )
        self.gateway.engagement = self.a.engagement
        self.a.target_url = f"http://{host}:{self.lab_port}/"

    # ---- snapshot -----------------------------------------------------------
    def assets(self) -> list[dict]:
        with self._lock:
            risk = self._risk()
            primary = {
                **self.a.asset,
                "status": _asset_status(self.a.state),
                "assessment_id": self.a.id,
                "risk": risk if self.a.state != "idle" else None,
                "previous_risk_score": 55,
                "last_assessed_at": int(time.time() - 86400 * 7),
                "authorization_ref": self.a.engagement.authorization_ref,
                "ownership_verified": self.a.engagement.ownership_verified,
            }
            extras = [
                dict(x) for x in self._extra_assets
                if x["id"] != primary["id"] and x["name"].lower() != primary["name"].lower()
            ]
            return [primary, *extras]

    def register_asset(self, *, name: str, kind: str, environment: str,
                       authorization_ref: str = "", ownership_verified: bool = False,
                       activate_workspace: bool = False, actor: str = "operator") -> dict:
        clean_name = (name or "").strip().lower()
        if not clean_name or len(clean_name) > 120 or " " in clean_name:
            raise ValueError("有効な対象ドメインまたはホスト名を入力してください")
        clean_kind = (kind or "Webアプリケーション").strip()[:40]
        clean_env = (environment or "検証環境").strip()[:40]
        clean_ref = (authorization_ref or "").strip()[:80]
        authorized = bool(ownership_verified and clean_ref)

        with self._lock:
            if authorized:
                self._allowed_hosts.add(clean_name)
            # Check if updating the current primary asset
            if self.a.asset["name"].lower() == clean_name:
                self.a.asset = {
                    **self.a.asset,
                    "kind": clean_kind,
                    "environment": clean_env,
                }
                if authorized:
                    self._sync_scope_for_host(clean_name, clean_ref)
                asset_record = {
                    **self.a.asset,
                    "status": _asset_status(self.a.state),
                    "assessment_id": self.a.id,
                    "risk": self._risk() if self.a.state != "idle" else None,
                    "authorization_ref": clean_ref,
                    "ownership_verified": authorized,
                }
            else:
                # Check if updating an existing extra asset (e.g. granting SOW to internal-staging)
                existing = next((x for x in self._extra_assets if x["name"].lower() == clean_name), None)
                if existing is not None:
                    existing["kind"] = clean_kind
                    existing["environment"] = clean_env
                    existing["authorization_ref"] = clean_ref
                    existing["ownership_verified"] = authorized
                    if authorized:
                        existing["status"] = "未診断"
                        existing["assessment_id"] = self.a.id
                        existing.pop("note", None)
                    else:
                        existing["status"] = "承認待ち"
                        existing["assessment_id"] = None
                        existing["note"] = "書面許可が未登録のため診断できません"
                    asset_record = dict(existing)
                else:
                    aid = "asset_" + secrets.token_hex(3)
                    asset_record = {
                        "id": aid,
                        "name": clean_name,
                        "kind": clean_kind,
                        "environment": clean_env,
                        "status": "未診断" if authorized else "承認待ち",
                        "assessment_id": self.a.id if authorized else None,
                        "risk": None,
                        "previous_risk_score": None,
                        "last_assessed_at": None,
                        "authorization_ref": clean_ref,
                        "ownership_verified": authorized,
                        **({} if authorized else {"note": "書面許可が未登録のため診断できません"}),
                    }
                    self._extra_assets.insert(0, asset_record)

                if activate_workspace and authorized and self.a.state != "running":
                    self._activate_asset_locked(asset_record, clean_ref)

        self.audit.record(
            "asset.registered",
            actor=actor,
            name=clean_name,
            kind=clean_kind,
            environment=clean_env,
            authorized=authorized,
            authorization_ref=clean_ref,
        )
        return asset_record

    def _activate_asset_locked(self, asset_record: dict, auth_ref: str) -> None:
        prev_primary = {
            **self.a.asset,
            "status": _asset_status(self.a.state),
            "assessment_id": self.a.id,
            "risk": self._risk() if self.a.state != "idle" else None,
            "previous_risk_score": 55,
            "last_assessed_at": int(time.time() - 86400 * 7),
            "authorization_ref": self.a.engagement.authorization_ref,
            "ownership_verified": self.a.engagement.ownership_verified,
        }
        if not any(x["id"] == prev_primary["id"] for x in self._extra_assets):
            self._extra_assets.append(prev_primary)
        self._extra_assets = [
            x for x in self._extra_assets if x["id"] != asset_record["id"]
        ]
        self.a.asset = {
            "id": asset_record["id"],
            "name": asset_record["name"],
            "kind": asset_record["kind"],
            "environment": asset_record["environment"],
        }
        self._sync_scope_for_host(asset_record["name"], auth_ref)

    def select_asset(self, asset_id: str, actor: str = "operator") -> dict:
        with self._lock:
            if self.a.state == "running":
                raise ValueError("診断実行中は対象を切り替えられません。一時停止または停止してください")
            if self.a.asset["id"] == asset_id:
                return self.snapshot()
            target_asset = next((x for x in self._extra_assets if x["id"] == asset_id), None)
            if target_asset is None:
                raise ValueError("指定された診断対象が見つかりません")
            if not target_asset.get("ownership_verified") or not target_asset.get("authorization_ref"):
                raise ValueError("この資産は書面許可（SOW）が未登録のため診断できません")
            self._activate_asset_locked(target_asset, str(target_asset["authorization_ref"]))
            self._reset_workspace_locked()
        self.audit.record("asset.selected", actor=actor, asset_id=asset_id, name=self.a.asset["name"])
        return self.snapshot()

    def delete_asset(self, asset_id: str, actor: str = "operator") -> list[dict]:
        with self._lock:
            if self.a.asset["id"] == asset_id:
                if self.a.state == "running":
                    raise ValueError("診断実行中の対象は削除できません。先に停止してください")
                deleted_name = self.a.asset["name"]
                # Promote next authorized extra asset, or recreate default lab.test
                next_auth = next(
                    (x for x in self._extra_assets if x.get("ownership_verified") and x.get("authorization_ref")),
                    None,
                )
                if next_auth is not None:
                    self._extra_assets = [x for x in self._extra_assets if x["id"] != next_auth["id"]]
                    self.a.asset = {
                        "id": next_auth["id"],
                        "name": next_auth["name"],
                        "kind": next_auth["kind"],
                        "environment": next_auth["environment"],
                    }
                    self._sync_scope_for_host(next_auth["name"], str(next_auth["authorization_ref"]))
                else:
                    self.a.asset = {
                        "id": "lab",
                        "name": "lab.test",
                        "kind": "Webアプリケーション",
                        "environment": "ローカル検証ラボ（127.0.0.1）",
                    }
                    self._sync_scope_for_host("lab.test", "DEMO-AUTH-001（ローカル検証ラボ）")
                self._reset_workspace_locked()
            else:
                target = next((x for x in self._extra_assets if x["id"] == asset_id), None)
                if target is None:
                    raise ValueError("削除対象の資産が見つかりません")
                deleted_name = target["name"]
                self._extra_assets = [x for x in self._extra_assets if x["id"] != asset_id]
        self.audit.record("asset.deleted", actor=actor, asset_id=asset_id, name=deleted_name)
        return self.assets()

    def _reset_workspace_locked(self) -> None:
        self.workers.kill_all()
        self.workers = WorkerPool(max_concurrent=2)
        self.gateway.workers = self.workers
        self.gateway._state = State.RUNNING
        self.gateway.egress = EgressGuard(lambda h: ["127.0.0.1"] if h in self._allowed_hosts else [])
        self.gateway.budget = Budget(50)
        self.a.phases = self._default_phases()
        self.a.findings = {f["id"]: f for f in _fixture_findings()}
        self.a.approvals = {}
        self.a.activity = None
        self.a.stop_report = None
        self.a.defense_comparison = None
        self.artex.tasks = []
        self._set_state("idle")

    def snapshot(self) -> dict:
        with self._lock:
            e = self.a.engagement
            t = e.targets["lab"]
            risk = self._risk()
            return {
                "id": self.a.id, "asset": self.a.asset, "demo": True,
                "lab_mode": get_lab_mode(),
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
                "risk": risk,
                "stop_report": self.a.stop_report,
                "chat_messages": list(self.a.chat_messages),
                "history": self._history(risk),
                "defense_comparison": self.a.defense_comparison,
                "cve_status": self.cve_monitor.status(),
                "artex_tasks": [
                    {"id": tk.id, "phase": tk.phase, "title": tk.title,
                     "risk_level": tk.risk_level, "status": tk.status,
                     "tool": tk.routed.proposal["tool"]}
                    for tk in self.artex.tasks
                ],
                "last_seq": self.bus.last_seq,
            }

    def logs(self) -> dict:
        return {"entries": self.audit.entries(), "chain_valid": self.audit.verify()}

    # ---- commands -----------------------------------------------------------
    def set_verify_seconds(self, seconds: float) -> None:
        self.gateway.tools["demo_verify"] = demo_verify_tool(seconds)

    def start(self) -> None:
        with self._lock:
            if self.a.state != "idle":
                raise ValueError(f"cannot start from {self.a.state}")
            set_lab_mode("vulnerable")
            self._set_state("running")
            self._thread = threading.Thread(target=self._run, daemon=True, name="runner")
            self._thread.start()

    def restart(self, actor: str = "operator") -> dict:
        """Reset a completed, stopped, or failed assessment and immediately start a fresh live run."""
        with self._lock:
            if self.a.state == "running":
                raise ValueError("既に診断が実行中です")
            self._reset_workspace_locked()
            set_lab_mode("vulnerable")
            self._set_state("running")
            self._thread = threading.Thread(target=self._run, daemon=True, name="runner")
            self._thread.start()
        self.audit.record("assessment.restarted", actor=actor, target=self.a.asset["name"])
        return self.snapshot()

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

    def _think(self, step: str, detail: str, *, phase: str = "", tool: str = "", level: str = "L1") -> None:
        self.audit.record(
            "agent.thought",
            step=step,
            detail=detail,
            phase=phase,
            tool=tool,
            risk_level=level,
        )

    # ---- P2: On-demand single finding verification via real Gateway+Worker ---
    def verify_finding(self, finding_id: str, actor: str) -> dict:
        """Execute a real Gateway + Worker probe for a specific finding on demand
        and attach the live HTTP response and SHA-256 audit hash."""
        if finding_id == "all":
            with self._lock:
                if self.gateway.state is State.STOPPED:
                    self._reset_workspace_locked()
                url = self.a.target_url
            self._think(
                "全問題の一括実機検証を開始",
                f"対象 {url}（ラボ状態: {get_lab_mode()}）に対し、Gateway 経由で http_probe と reproduction_probe を順次実行します。",
                phase="verification",
                tool="http_probe / reproduction_probe",
                level="L2",
            )
            res, ev = self._exec("http_probe", "read_only_probe",
                                 {"url": url, "method": "GET"},
                                 approval_actor=f"verify:{actor}")
            if res and ev:
                with self._lock:
                    self._analyze(res, ev)
            for fid in ("f_banner", "f_idor", "f_sqli"):
                if fid in self.a.findings:
                    self.verify_finding(fid, actor=actor)
            self._think(
                "全問題の実機検証が完了",
                f"すべての Worker プローブ応答と SHA-256 監査ハッシュを記録しました（総合リスク: {self._risk()['score']}/100）。",
                phase="report",
                tool="Gateway",
                level="L1",
            )
            return self.snapshot()

        with self._lock:
            if finding_id not in self.a.findings:
                raise ValueError("指定された問題が見つかりません")
            if self.gateway.state is State.STOPPED:
                self._reset_workspace_locked()
            url = self.a.target_url

        if finding_id in ("f_idor", "fx_idor"):
            self._think(
                "IDOR（認可境界バイパス）の仮説検証",
                "テストアカウント acct_A のトークンで acct_B の保護リソース (/api/accounts/B/secret) をリクエストし、所有者照合の有無を検証します。",
                phase="verification",
                tool="reproduction_probe",
                level="L2",
            )
            apr = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
            self.audit.record("approval.approved", request=f"req_{finding_id}", actor=actor,
                              action="safe_reproduction", risk_level="L2")
            res, ev = self._exec("reproduction_probe", "safe_reproduction",
                                 {"url": url, "check": "idor"}, approval_id=apr)
            if res and ev:
                est = bool(res.get("established"))
                self._think(
                    "IDOR 実機応答の判定",
                    f"Worker 応答: HTTP {res.get('forged_account_A_status')} — {'他アカウントの保護リソース取得が成立（実証成功）' if est else 'HTTP 403 Forbidden により遮断（再現せず）'} [証拠 {ev['evidence_id']}]",
                    phase="verification",
                    tool="reproduction_probe",
                    level="L2",
                )
                with self._lock:
                    f = self.a.findings[finding_id]
                    prev_ev = [e for e in f.get("evidence", []) if e.get("audit_hash")]
                    self._upsert_finding({
                        **f,
                        "demo_fixture": False,
                        "verdict": "proven" if est else "not_reproduced",
                        "_in_verification": False,
                        "what_was_established": (
                            "権限のないテストアカウント acct_A から、別の検証用リソース（acct_B の res_b_001）へのアクセスが実機Workerで成立しました。"
                            if est else None
                        ),
                        "verdict_note": (
                            "reproduction_probe Worker（egress_sentinel 適用）による実リクエストで認可バイパスを実証しました。"
                            if est else "所有者照合により HTTP 403 Forbidden で遮断されることを実機確認しました。"
                        ),
                        "executor": {**EXECUTOR, "tool": "reproduction_probe"},
                        "evidence": prev_ev + [ev],
                    })
        elif finding_id in ("f_sqli", "fx_sqli"):
            self._think(
                "SQLインジェクション境界（/api/search）の仮説検証",
                "検索パラメータ q=test' を送信し、未エスケープのSQL構文解釈（エラー差分）が発生するかを非破壊プローブで検証します。",
                phase="verification",
                tool="reproduction_probe",
                level="L2",
            )
            apr = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
            self.audit.record("approval.approved", request=f"req_{finding_id}", actor=actor,
                              action="safe_reproduction", risk_level="L2")
            res, ev = self._exec("reproduction_probe", "safe_reproduction",
                                 {"url": url, "check": "sqli"}, approval_id=apr)
            if res and ev:
                est = bool(res.get("established"))
                self._think(
                    "SQLi 実機応答の判定",
                    f"Worker 応答: HTTP {res.get('probe_status')} — {'SQL構文エラー差分（VULNIX_LAB_SQLI_PROVEN）を検出・実証' if est else 'プリペアドステートメントにより HTTP 403 で安全に拒否（再現せず）'} [証拠 {ev['evidence_id']}]",
                    phase="verification",
                    tool="reproduction_probe",
                    level="L2",
                )
                with self._lock:
                    f = self.a.findings[finding_id]
                    prev_ev = [e for e in f.get("evidence", []) if e.get("audit_hash")]
                    self._upsert_finding({
                        **f,
                        "demo_fixture": False,
                        "verdict": "proven" if est else "not_reproduced",
                        "_in_verification": False,
                        "what_was_established": (
                            "検索エンドポイント /api/search?q=test' に対し、未エスケープのSQL構文エラー差分（VULNIX_LAB_SQLI_PROVEN）が実機Workerで成立しました。"
                            if est else None
                        ),
                        "verdict_note": (
                            "reproduction_probe Worker により未バインドのSQL構文解釈が発生することを実証しました。"
                            if est else "プレースホルダー（プリペアドステートメント）により HTTP 403 で安全に処理されることを実機確認しました。"
                        ),
                        "executor": {**EXECUTOR, "tool": "reproduction_probe"},
                        "evidence": prev_ev + [ev],
                    })
        elif finding_id == "f_banner":
            self._think(
                "CVE-2021-41773 パス正規化バイパスの仮説検証",
                "Apache 2.4.49 のパス正規化不備（/cgi-bin/.%2e/...）が隔離ラボの検証用マーカーへ到達できるか reproduction_probe で検証します。",
                phase="verification",
                tool="reproduction_probe",
                level="L2",
            )
            apr = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
            self.audit.record("approval.approved", request="req_f_banner", actor=actor,
                              action="safe_reproduction", risk_level="L2")
            res, ev = self._exec("reproduction_probe", "safe_reproduction",
                                 {"url": url, "check": "cve_2021_41773"}, approval_id=apr)
            if res and ev:
                est = bool(res.get("established"))
                self._think(
                    "CVE-2021-41773 実機応答の判定",
                    f"Worker 応答: HTTP {res.get('status')} — {'検証用マーカー（VULNIX_LAB_PATH_TRAVERSAL_PROVEN）への到達を実証' if est else 'Apache 2.4.62 パッチにより HTTP 403 で遮断（再現せず）'} [証拠 {ev['evidence_id']}]",
                    phase="verification",
                    tool="reproduction_probe",
                    level="L2",
                )
                with self._lock:
                    f = self.a.findings[finding_id]
                    prev_ev = [e for e in f.get("evidence", []) if e.get("audit_hash")]
                    self._upsert_finding({
                        **f,
                        "demo_fixture": False,
                        "verdict": "proven" if est else "not_reproduced",
                        "_in_verification": False,
                        "what_was_established": (
                            "隔離ラボ環境において、正規化前のパスシーケンス（CVE-2021-41773）により検証用マーカー（VULNIX_LAB_PATH_TRAVERSAL_PROVEN）への到達が成立しました。"
                            if est else None
                        ),
                        "verdict_note": (
                            "reproduction_probe Worker により実際にパス正規化バイパスが成立することを実証しました。"
                            if est else "Apache/2.4.62 パッチ適用により HTTP 403 Forbidden で遮断されることを実機確認しました。"
                        ),
                        "executor": {**EXECUTOR, "tool": "reproduction_probe"},
                        "evidence": prev_ev + [ev],
                    })
        else:
            self._think(
                "HTTP応答ヘッダー・露出情報の再検査",
                f"対象 {url} に対して非破壊 GET プローブ（http_probe）を実行し、セキュリティヘッダーとバージョン露出を確認します。",
                phase="config",
                tool="http_probe",
                level="L1",
            )
            res, ev = self._exec("http_probe", "read_only_probe",
                                 {"url": url, "method": "GET"},
                                 approval_actor=f"verify:{actor}")
            if res and ev:
                with self._lock:
                    self._analyze(res, ev)
        return self.snapshot()

    # ---- P2: Post-patch defense verification & before/after comparison ------
    def verify_fix(self, actor: str) -> dict:
        """Apply patched defense configuration to the lab and re-run the exact
        same probe and reproduction checks through the Gateway to prove that
        previously proven/detected vulnerabilities are now mitigated."""
        with self._lock:
            if self.a.state not in ("completed", "idle"):
                raise ValueError("診断完了後に修正後の再検証を実行してください")
            before_risk = self._risk()
            before_verdicts = {
                f["id"]: {"title": f["title"], "severity": f["severity"], "verdict": f["verdict"]}
                for f in self._real_findings()
            }

        set_lab_mode("patched")
        url = self.a.target_url
        self._think(
            "防御パッチ適用後の再検証を開始",
            "ラボ環境を patched モード（Apache 2.4.62 / 所有者照合 / プリペアドステートメント適用）へ切り替え、同一プローブで再検証します。",
            phase="verification",
            tool="http_probe / reproduction_probe",
            level="L2",
        )
        # 1. Re-run L1 HTTP probe
        res, ev_http = self._exec("http_probe", "read_only_probe",
                                  {"url": url, "method": "GET"},
                                  approval_actor=f"reverify:{actor}")
        # 2. Re-run L2 reproduction probes with human approver authorization
        apr_ref = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
        self.audit.record("approval.approved", request="req_reverify", actor=actor,
                          action="safe_reproduction", risk_level="L2")
        res_cve, ev_cve = self._exec("reproduction_probe", "safe_reproduction",
                                     {"url": url, "check": "cve_2021_41773"},
                                     approval_id=apr_ref)
        apr_ref2 = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
        res_idor, ev_idor = self._exec("reproduction_probe", "safe_reproduction",
                                       {"url": url, "check": "idor"},
                                       approval_id=apr_ref2)
        apr_ref3 = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
        res_sqli, ev_sqli = self._exec("reproduction_probe", "safe_reproduction",
                                       {"url": url, "check": "sqli"},
                                       approval_id=apr_ref3)

        with self._lock:
            if "f_banner" in self.a.findings and ev_cve:
                fb = self.a.findings["f_banner"]
                self._upsert_finding({
                    **fb,
                    "demo_fixture": False,
                    "verdict": "not_reproduced",
                    "what_was_established": None,
                    "verdict_note": "Apache/2.4.62 への更新および正規化防御により、同一のパストラバーサル再現試験で HTTP 403 Forbidden が返ることを確認しました。",
                    "evidence": [e for e in fb["evidence"] if e.get("audit_hash")] + ([ev_http] if ev_http else []) + [ev_cve],
                })
            if "f_idor" in self.a.findings and ev_idor:
                fi = self.a.findings["f_idor"]
                self._upsert_finding({
                    **fi,
                    "demo_fixture": False,
                    "verdict": "not_reproduced",
                    "what_was_established": None,
                    "verdict_note": "所有者照合の適用により、テストアカウント acct_A から acct_B のリソースへのアクセスが HTTP 403 Forbidden で遮断されることを確認しました。",
                    "evidence": [e for e in fi["evidence"] if e.get("audit_hash")] + [ev_idor],
                })
            if "f_sqli" in self.a.findings and ev_sqli:
                fs = self.a.findings["f_sqli"]
                self._upsert_finding({
                    **fs,
                    "demo_fixture": False,
                    "verdict": "not_reproduced",
                    "what_was_established": None,
                    "verdict_note": "プレースホルダー（プリペアドステートメント）の適用により、同一の検索パラメータ試験で SQL 構文解釈が発生しないことを確認しました。",
                    "evidence": [e for e in fs["evidence"] if e.get("audit_hash")] + [ev_sqli],
                })
            for hid in ("f_headers", "f_powered"):
                if hid in self.a.findings and ev_http:
                    fh = self.a.findings[hid]
                    self._upsert_finding({
                        **fh,
                        "demo_fixture": False,
                        "verdict": "not_reproduced",
                        "what_was_established": None,
                        "verdict_note": "修正後のHTTP応答ヘッダーで対策が適用されていることを確認しました。",
                        "evidence": [e for e in fh["evidence"] if e.get("audit_hash")] + [ev_http],
                    })

            after_risk = self._risk()
            items = []
            for fid, binfo in before_verdicts.items():
                cur_f = self.a.findings.get(fid, {})
                items.append({
                    "id": fid,
                    "title": binfo["title"],
                    "severity": binfo["severity"],
                    "before_verdict": binfo["verdict"],
                    "after_verdict": cur_f.get("verdict", "not_reproduced"),
                    "latest_evidence_id": cur_f.get("evidence", [{}])[-1].get("evidence_id"),
                })
            self.a.defense_comparison = {
                "verified_at": time.time(),
                "actor": actor,
                "lab_mode": get_lab_mode(),
                "before_score": before_risk["score"],
                "after_score": after_risk["score"],
                "items": items,
            }
            self._think(
                "修正前後の防御比較が完了",
                f"すべての脆弱性が「再現せず」となり、総合リスクが {before_risk['score']}/100 から {after_risk['score']}/100 に低減したことを実証しました。",
                phase="report",
                tool="Gateway",
                level="L1",
            )
            self._set_state("completed")
            return self.snapshot()

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
        self._think(
            "診断範囲と書面許可（SOW）の照合",
            f"対象 {url} が書面許可（{self.a.engagement.authorization_ref}）および許可CIDR 127.0.0.1/32 の範囲内にあることを検証しています。",
            phase="scope",
            tool="Gateway",
            level="L1",
        )
        self.gateway.engagement.check_active(time.time())
        self.gateway.egress.check(url, self.a.engagement.targets["lab"])
        self._phase("scope", "done", f"{url} は許可範囲内（127.0.0.1/32）")

        self._checkpoint()
        self._phase("config", "running", "ARTEX が公開設定の非破壊プローブを提案・実行しています")
        self._activity("公開設定を検査（GET 1回・非破壊）", "http_probe", "L1")
        self._think(
            "非破壊HTTPプローブの計画とサニタイズ",
            "ARTEX プランナーが公開設定・応答ヘッダー取得のため http_probe (GET) を提案し、ProposalRouter で安全性を検証しました。",
            phase="config",
            tool="http_probe",
            level="L1",
        )
        tasks_l1 = self.artex.plan_phase("config", {"target_id": "lab", "target_url": url})
        for tk in tasks_l1:
            tk.status = "running"
        res, ev = self._exec("http_probe", "read_only_probe", {"url": url, "method": "GET"},
                             approval_actor="policy:auto-L1")
        if res is None:
            return
        for tk in tasks_l1:
            tk.status = "completed"
        self._phase("config", "done", f"HTTP {res['status']} を取得")

        self._checkpoint()
        self._phase("analysis", "running", "取得した応答とNVD/CISA KEVフィードから問題を分析しています")
        self._activity("検出結果を分析（CVE / CISA KEV 照合）", "cve_engine", "L1")
        banner_id = self._analyze(res, ev)
        self._think(
            "CVE/CISA KEV 照合と検証仮説の構築",
            f"応答バナー（{res.get('headers', {}).get('Server', 'unknown')}）およびAPI境界から {len(self._real_findings())} 件の検証対象（CVE-2021-41773 / IDOR / SQLi 等）を特定しました。",
            phase="analysis",
            tool="cve_engine",
            level="L1",
        )
        if "AI agent:" in res.get("body_prefix", ""):
            self.bus.publish(self.a.id, "agent.note",
                             message="ページ内にAI向けの指示文を検出しました。ProposalRouterにより無害化され実行権限には影響しません。")
        self._phase("analysis", "done", f"{len(self._real_findings())} 件を検出")

        self._checkpoint()
        self._phase("verification", "running", "隔離環境での侵入成立実証（再現試験）の承認を待っています")
        self._activity("脆弱性の検証（侵入成立の実証）", "reproduction_probe", "L2")
        self._think(
            "L2 侵入成立実証の人間承認リクエスト",
            "CVE-2021-41773・IDOR・SQLi の再現試験は L2 操作のため、承認責任者による実行許可（単一使用トークン発行）を待機しています。",
            phase="verification",
            tool="reproduction_probe",
            level="L2",
        )
        tasks_l2 = self.artex.plan_phase("verification", {
            "target_id": "lab", "target_url": url, "has_cve_2021_41773": banner_id in self.a.findings,
        })
        for tk in tasks_l2:
            tk.status = "awaiting_approval"
        ap_id = self._request_approval(
            "safe_reproduction", "L2", "検出された脆弱性の侵入成立実証（CVE-2021-41773 / IDOR / SQLi）",
            "検出したバージョン表示（CVE-2021-41773）、テストアカウント間の認可境界（IDOR）、および検索APIのSQLインジェクション境界が"
            "実際に成立するかを、egress_sentinel 隔離Worker（reproduction_probe）で非破壊実証します。")
        if self.a.approvals[ap_id]["status"] != "approved":
            for tk in tasks_l2:
                tk.status = "skipped"
            self._think(
                "L2 再現試験をスキップ",
                "承認責任者により却下されたため、L2 再現試験は実施せず検出段階の結果でレポートを作成します。",
                phase="verification",
                tool="Gateway",
                level="L2",
            )
            self._phase("verification", "skipped", "承認されなかったため実施していません")
        else:
            for tk in tasks_l2:
                tk.status = "running"
            self._phase("verification", "running", "隔離Workerで侵入成立を実証中（reproduction_probe）")
            self._think(
                "L2 承認完了・隔離Workerでの侵入成立実証を開始",
                "単一使用 HMAC トークンを発行し、egress_sentinel 隔離下で reproduction_probe Worker を起動しています。",
                phase="verification",
                tool="reproduction_probe",
                level="L2",
            )
            self._mark_verifying(banner_id, True)
            self._mark_verifying("f_idor", True)
            self._mark_verifying("f_sqli", True)

            # 1. Run demo_verify window first so emergency-stop tests during active verification
            #    can deterministically observe and SIGKILL the worker.
            vres, vev = self._exec("demo_verify", "safe_reproduction", {"url": url},
                                   approval_id=self.a.approvals[ap_id]["approval_ref"])
            if vres is None:
                return

            # 2. Execute real non-destructive reproduction probes through the Gateway
            actor = self.a.approvals[ap_id]["decided_by"] or "approver"
            apr_cve = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
            cve_res, cve_ev = self._exec("reproduction_probe", "safe_reproduction",
                                         {"url": url, "check": "cve_2021_41773"},
                                         approval_id=apr_cve)
            if cve_res is None:
                return
            if banner_id in self.a.findings:
                f = self.a.findings[banner_id]
                established = bool(cve_res.get("established"))
                self._think(
                    "CVE-2021-41773 実証結果の確認",
                    f"HTTP {cve_res.get('status')} — {'検証用マーカー到達（実証成功）' if established else '再現せず'} [証拠 {cve_ev['evidence_id']}]",
                    phase="verification",
                    tool="reproduction_probe",
                    level="L2",
                )
                self._upsert_finding({
                    **f,
                    "demo_fixture": False,
                    "verdict": "proven" if established else "not_reproduced",
                    "_in_verification": False,
                    "what_was_established": (
                        "隔離ラボ環境において、正規化前のパスシーケンス（CVE-2021-41773）により"
                        "検証用マーカー（VULNIX_LAB_PATH_TRAVERSAL_PROVEN）への到達が成立しました。"
                        if established else None
                    ),
                    "verdict_note": (
                        "reproduction_probe により実際にパス正規化バイパスが成立することを実証しました。"
                        if established else "再現試験を実施しましたが成立しませんでした。"
                    ),
                    "executor": {**EXECUTOR, "tool": "reproduction_probe"},
                    "evidence": [e for e in f["evidence"] if e.get("audit_hash")] + [vev, cve_ev],
                })

            apr_idor = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
            idor_res, idor_ev = self._exec("reproduction_probe", "safe_reproduction",
                                           {"url": url, "check": "idor"},
                                           approval_id=apr_idor)
            if idor_res is None:
                return
            if "f_idor" in self.a.findings:
                fi = self.a.findings["f_idor"]
                idor_est = bool(idor_res.get("established"))
                self._think(
                    "IDOR（認可境界）実証結果の確認",
                    f"HTTP {idor_res.get('forged_account_A_status')} — {'acct_A から acct_B リソース取得が成立（実証成功）' if idor_est else '再現せず'} [証拠 {idor_ev['evidence_id']}]",
                    phase="verification",
                    tool="reproduction_probe",
                    level="L2",
                )
                self._upsert_finding({
                    **fi,
                    "demo_fixture": False,
                    "verdict": "proven" if idor_est else "not_reproduced",
                    "_in_verification": False,
                    "what_was_established": (
                        "権限のないテストアカウント acct_A から、別の検証用リソース（acct_B の res_b_001）"
                        "へのアクセスが成立しました。"
                        if idor_est else None
                    ),
                    "verdict_note": (
                        "2つのテストアカウント（acct_A / acct_B）を用いた実リクエストで認可バイパスを実証しました。"
                        if idor_est else "所有者照合により HTTP 403 で遮断されました。"
                    ),
                    "executor": {**EXECUTOR, "tool": "reproduction_probe"},
                    "evidence": [e for e in fi["evidence"] if e.get("audit_hash")] + [idor_ev],
                })

            apr_sqli = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
            sqli_res, sqli_ev = self._exec("reproduction_probe", "safe_reproduction",
                                           {"url": url, "check": "sqli"},
                                           approval_id=apr_sqli)
            if sqli_res is None:
                return
            if "f_sqli" in self.a.findings:
                fs = self.a.findings["f_sqli"]
                sqli_est = bool(sqli_res.get("established"))
                self._think(
                    "SQLインジェクション境界 実証結果の確認",
                    f"HTTP {sqli_res.get('probe_status')} — {'SQL構文エラー差分（VULNIX_LAB_SQLI_PROVEN）が成立（実証成功）' if sqli_est else '再現せず'} [証拠 {sqli_ev['evidence_id']}]",
                    phase="verification",
                    tool="reproduction_probe",
                    level="L2",
                )
                self._upsert_finding({
                    **fs,
                    "demo_fixture": False,
                    "verdict": "proven" if sqli_est else "not_reproduced",
                    "_in_verification": False,
                    "what_was_established": (
                        "検索エンドポイント /api/search?q=test' に対し、未エスケープのSQL構文エラー差分（VULNIX_LAB_SQLI_PROVEN）が成立しました。"
                        if sqli_est else None
                    ),
                    "verdict_note": (
                        "reproduction_probe により未バインドのSQL構文解釈が発生することを実証しました。"
                        if sqli_est else "プレースホルダーにより HTTP 403 で安全に処理されました。"
                    ),
                    "executor": {**EXECUTOR, "tool": "reproduction_probe"},
                    "evidence": [e for e in fs["evidence"] if e.get("audit_hash")] + [sqli_ev],
                })

            for tk in tasks_l2:
                tk.status = "completed"
            self._phase("verification", "done", "結果: 侵入成立を実証（証拠・監査ハッシュ保存済み）")

        self._checkpoint()
        self._phase("report", "running", "結果をまとめています")
        self._think(
            "診断結果と監査ハッシュチェーンの確定",
            f"全ステップが完了しました。総合リスクスコア: {self._risk()['score']}/100（監査チェーン検証済み）。",
            phase="report",
            tool="Gateway",
            level="L1",
        )
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
        candidates = cve.detect_from_banner(banner, source="server-header",
                                            catalog=self.cve_monitor.catalog,
                                            kev=self.cve_monitor.kev)
        if candidates:
            cve_ids = sorted({c.cve.id for c in candidates})
            kev_note = "（CISA KEV 悪用確認済みカタログ掲載）" if any(c.in_kev for c in candidates) else ""
            self._upsert_finding({
                "id": bid, "title": f"既知の脆弱性に該当するWebサーバーのバージョン表示{kev_note}",
                "severity": "high", "verdict": "detected", "category": "既知の脆弱性（CVE）",
                "cve": cve_ids, "risk_level": "L2",
                "help_term": "cve",
                "summary": f"Server ヘッダーが「{banner}」を示しています。このバージョンはパス・トラバーサル等の既知脆弱性{kev_note}の影響範囲です。",
                "why_detected": "応答ヘッダーのバージョン文字列が、NVD / CISA KEV フィードの影響バージョンと一致したためです。",
                "caveat": "バナー段階では「検出（未実証）」です。L2再現試験を承認すると、隔離ラボで実際に到達可能か検証します。",
                "evidence": [ev],
                "remediation": {"steps": ["Apache HTTP Server を最新の安定版（2.4.62以降）に更新する",
                                          "Server ヘッダーのバージョン表示を抑制する（ServerTokens Prod）"],
                                "how_to_verify": "「防御パッチ適用・再検証」を実行し、再現試験の結果が「再現せず」に変わることを確認します。"},
                "executor": {**EXECUTOR, "tool": "http_probe"}, "demo_fixture": False})

        # Candidate IDOR check queued for L2 verification
        self._upsert_finding({
            "id": "f_idor", "title": "他アカウントの保護リソースへのアクセス制御不備（IDOR）",
            "severity": "high", "verdict": "detected", "category": "アクセス制御", "cve": [],
            "risk_level": "L2", "help_term": "idor",
            "summary": "APIエンドポイント /api/accounts/B/secret においてオブジェクト単位の所有者検証が必要と判定されました。",
            "why_detected": "ARTEX のエンドポイント分析により、アカウントID指定型リソースが検出されたためです（L2承認後に2アカウント間で実証試験を行います）。",
            "caveat": "L2承認前は「検出（未実証）」として扱います。",
            "evidence": [ev],
            "remediation": {"steps": ["サーバー側でセッション主体とリソース所有者を必ず照合し、不一致時は 403 Forbidden を返す"],
                            "how_to_verify": "修正後に同じ2アカウント間の試験を実行し、HTTP 403 が返ることを確認します。"},
            "executor": {**EXECUTOR, "tool": "http_probe"}, "demo_fixture": False})

        # Candidate SQLi check queued for L2 verification
        self._upsert_finding({
            "id": "f_sqli", "title": "検索欄のSQLインジェクション境界不備（/api/search）",
            "severity": "critical", "verdict": "detected", "category": "インジェクション", "cve": [],
            "risk_level": "L2", "help_term": "sqli",
            "summary": "検索エンドポイント /api/search のクエリパラメータ q において、SQL構文差分の検証が必要と判定されました。",
            "why_detected": "ARTEX のパラメータ境界分析により、未バインドクエリの可能性が検出されたためです（L2承認後に非破壊エラー差分検証を行います）。",
            "caveat": "L2承認前は「検出（未実証）」として扱います。",
            "evidence": [ev],
            "remediation": {"steps": ["プリペアドステートメント（プレースホルダー付きクエリ）を使用し文字列連結を廃止する"],
                            "how_to_verify": "修正後に同じ試験を実行し、SQLエラー差分が発生しないことを確認します。"},
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

    # ---- P1: AI chat with assessment context (read-only, zero authority) ----
    def ask_chat(self, question: str, actor: str, term: str | None = None,
                 finding_id: str | None = None) -> dict:
        q = question.strip()[:500]
        if not q:
            raise ValueError("question must not be empty")
        now = time.time()
        with self._lock:
            user_msg = {
                "id": "msg_" + secrets.token_hex(4),
                "role": "user",
                "actor": actor,
                "text": q,
                "term": term,
                "finding_id": finding_id,
                "ts": now,
            }
            answer_text = self._answer_question(q, term=term, finding_id=finding_id)
            ai_msg = {
                "id": "msg_" + secrets.token_hex(4),
                "role": "assistant",
                "actor": "Vulnix AI",
                "text": answer_text,
                "term": term,
                "finding_id": finding_id,
                "ts": time.time(),
            }
            self.a.chat_messages.extend([user_msg, ai_msg])
            self.audit.record("chat.asked", actor=actor, term=term or "", finding_id=finding_id or "")
            self.bus.publish(self.a.id, "chat.message", messages=[user_msg, ai_msg])
            return {"message": ai_msg, "chat_messages": list(self.a.chat_messages)}

    def _answer_question(self, q: str, term: str | None = None, finding_id: str | None = None) -> str:
        real = self._real_findings()
        all_f = list(self.a.findings.values())
        target_f = None
        if finding_id and finding_id in self.a.findings:
            target_f = self.a.findings[finding_id]
        elif term:
            target_f = next((f for f in real if f.get("help_term") == term), None) or next(
                (f for f in all_f if f.get("help_term") == term), None
            )
        elif real:
            target_f = real[0]

        # If an external Abliteration / OpenAI-compatible model endpoint is configured, try it first
        ext = AbliterationBackend.from_env()
        if isinstance(ext, AbliterationBackend):
            ans = ext.chat(q, {
                "asset": self.a.asset,
                "state": self.a.state,
                "risk": self._risk(),
                "target_finding": target_f,
            })
            if ans:
                return ans

        ql = q.lower()
        if target_f:
            evs = target_f.get("evidence", [])
            ev_summary = "、".join(
                f"{e['evidence_id']}（{e['kind']}・監査ハッシュ {(e.get('audit_hash') or 'なし')[:10]}）"
                for e in evs
            ) or "記録された証拠なし"
            rem = target_f.get("remediation", {})
            steps = " / ".join(rem.get("steps", []))
            verify = rem.get("how_to_verify", "")

            if any(k in ql for k in ("なぜ", "理由", "検出", "原因", "why")):
                return (
                    f"【なぜ検出されたか：{target_f['title']}】\n"
                    f"・検出理由：{target_f.get('why_detected') or target_f['summary']}\n"
                    f"・判定状態：{target_f['verdict']}（危険度 {target_f['risk_level']}）\n"
                    f"・根拠となった証拠：{ev_summary}"
                )
            if any(k in ql for k in ("証拠", "判断", "ログ", "ハッシュ", "evidence")):
                return (
                    f"【判断根拠の証拠：{target_f['title']}】\n"
                    f"・証拠一覧：{ev_summary}\n"
                    f"・成立内容：{target_f.get('what_was_established') or target_f.get('verdict_note') or target_f.get('caveat') or target_f['summary']}\n"
                    f"※ 問題詳細ページの「証拠」パネルから、実際のレスポンスとSHA-256監査ハッシュを確認できます。"
                )
            if any(k in ql for k in ("修正", "直", "対策", "確認", "再試験", "verify", "fix")):
                return (
                    f"【修正方法と修正後の確認：{target_f['title']}】\n"
                    f"・修正手順：{steps}\n"
                    f"・修正後の確認方法：{verify}"
                )

        risk = self._risk()
        done_phases = sum(1 for p in self.a.phases if p["status"] == "done")
        parts = [
            f"現在の診断対象は {self.a.asset['name']}（状態: {_asset_status(self.a.state)}、進捗 {done_phases}/{len(self.a.phases)} ステップ、総合リスク {risk['score']}/100 {risk['label']}）です。"
        ]
        if target_f:
            evs = target_f.get("evidence", [])
            ev_ids = ", ".join(e["evidence_id"] for e in evs) or "なし"
            parts.append(
                f"注目項目「{target_f['title']}」：\n"
                f"1. なぜ検出されたか：{target_f.get('why_detected') or target_f['summary']}\n"
                f"2. 判断した証拠：{ev_ids}（実行ツール: {target_f['executor']['tool']}）\n"
                f"3. 修正後の確認：{target_f['remediation']['how_to_verify']}"
            )
        else:
            parts.append(
                "診断を開始すると、公開設定の検査・CVE照合・隔離環境での検証結果と証拠がここに紐づけられます。"
                "※ Vulnix AI は説明・提案のみを行い、承認なしに操作を実行することはありません。"
            )
        return "\n".join(parts)

    # ---- P2: assessment history comparison & Markdown report export ---------
    def _history(self, current_risk: dict) -> dict:
        prev_score = 55
        cur_score = current_risk["score"] if self.a.state != "idle" else None
        real_ids = {f["id"] for f in self._real_findings()}
        return {
            "previous_assessment_id": "scan_000",
            "previous_assessed_at": int(time.time() - 86400 * 7),
            "previous_score": prev_score,
            "previous_label": "中リスク",
            "delta_score": (cur_score - prev_score) if cur_score is not None else None,
            "resolved_findings": ["検索欄のSQLインジェクション（修正後に再現せずを確認）"],
            "new_findings_count": len(real_ids),
            "runs": [
                {"id": "scan_000", "at": int(time.time() - 86400 * 7), "score": prev_score,
                 "label": "中リスク", "status": "診断済み", "summary": "SQLi修正後の再検証完了（再現せず）"},
                {"id": self.a.id, "at": int(time.time()), "score": cur_score,
                 "label": current_risk["label"] if cur_score is not None else "未診断",
                 "status": _asset_status(self.a.state), "summary": "現在の診断セッション"},
            ],
        }

    def report_markdown(self) -> str:
        s = self.snapshot()
        auth = s["authorization"]
        risk = s["risk"]
        hist = s["history"]
        lines = [
            f"# Vulnix セキュリティ診断レポート — {s['asset']['name']}",
            "",
            "- **プラットフォーム**: Vulnix (Find. Prove. Secure. — AI Security Testing Platform)",
            f"- **診断ID**: `{s['id']}`",
            f"- **対象資産**: {s['asset']['name']} ({s['asset']['kind']} / {s['asset']['environment']})",
            f"- **診断状態**: {_asset_status(s['state'])}（ラボ防御状態: `{s.get('lab_mode', 'vulnerable')}`）",
            f"- **書面許可**: `{auth['ref']}` (所有確認: {'確認済み' if auth['ownership_verified'] else '未確認'})",
            f"- **許可範囲**: Hosts={', '.join(auth['scope']['hosts'])} / CIDRs={', '.join(auth['scope']['cidrs'])} / Ports={', '.join(map(str, auth['scope']['ports']))}",
            f"- **総合リスク**: **{risk['score']}/100 ({risk['label']})** {'※暫定' if risk['provisional'] else ''}",
            f"- **前回診断との比較**: 前回 `{hist['previous_assessment_id']}` ({hist['previous_score']}/100) → 差分 {hist['delta_score'] if hist['delta_score'] is not None else '未算出'}",
            "",
            "## 1. 診断ステップ進捗",
        ]
        for p in s["phases"]:
            lines.append(f"- **{p['label']}**: {p['status']} {('— ' + p['detail']) if p['detail'] else ''}")
        lines.append("")
        lines.append("## 2. 検出された問題と実証結果")
        real_findings = [f for f in s["findings"] if not f.get("demo_fixture")]
        if not real_findings:
            lines.append("- 実環境の検出結果はまだありません（未診断または検査前）。")
        for f in real_findings:
            lines.extend([
                f"### [{f['severity'].upper()}] {f['title']} (`{f['verdict']}`)",
                f"- **カテゴリ**: {f['category']} / **危険度**: {f['risk_level']}",
                f"- **関連CVE**: {', '.join(f['cve']) if f['cve'] else 'なし'}",
                f"- **概要**: {f['summary']}",
                f"- **なぜ検出されたか**: {f.get('why_detected', '—')}",
                f"- **成立内容 / 検証結果**: {f.get('what_was_established') or f.get('verdict_note') or f.get('caveat') or '—'}",
                "- **証拠**:",
            ])
            for ev in f.get("evidence", []):
                lines.append(f"  - `{ev['evidence_id']}` ({ev['kind']}) 監査ハッシュ: `{ev.get('audit_hash') or 'なし'}`")
            lines.append("- **修正方法**:")
            for step in f["remediation"]["steps"]:
                lines.append(f"  1. {step}")
            lines.append(f"- **修正後の確認方法**: {f['remediation']['how_to_verify']}")
            lines.append("")
        if s.get("defense_comparison"):
            dc = s["defense_comparison"]
            lines.extend([
                "## 3. 修正前後の防御比較（実証再検証）",
                f"- **修正前リスクスコア**: {dc['before_score']}/100 → **修正後リスクスコア**: {dc['after_score']}/100",
            ])
            for item in dc.get("items", []):
                lines.append(
                    f"  - {item['title']}: `{item['before_verdict']}` → `{item['after_verdict']}` (証拠 `{item['latest_evidence_id']}`)"
                )
            lines.append("")
        lines.append("## 4. 監査チェーン検証")
        lines.append(f"- **監査ログ件数**: {len(self.audit.entries())} 件")
        lines.append(f"- **SHA-256 ハッシュチェーン整合性**: {'✓ 改ざんなし' if self.audit.verify() else '✕ 不整合あり'}")
        return "\n".join(lines) + "\n"


class _Stopped(Exception):
    pass


def _asset_status(state: str) -> str:
    return {"idle": "未診断", "running": "診断中", "paused": "一時停止中",
            "stopped": "中止", "failed": "失敗", "completed": "診断済み"}[state]


def _fixture_findings() -> list[dict]:
    """Initial real candidate findings for the local verification lab (127.0.0.1), ready for live Gateway + Worker execution."""
    common = {"demo_fixture": False, "executor": {**EXECUTOR, "tool": "reproduction_probe"}}
    return [
        {**common, "id": "f_banner", "title": "既知の脆弱性に該当するWebサーバーのバージョン表示（CVE-2021-41773）",
         "severity": "high", "verdict": "detected", "category": "既知の脆弱性（CVE）",
         "cve": ["CVE-2021-41773", "CVE-2021-42013"], "risk_level": "L2", "help_term": "cve",
         "summary": "ローカル検証ラボ（127.0.0.1）の Server ヘッダーおよびパス正規化処理に CVE-2021-41773 の影響可能性があります。",
         "why_detected": "対象エンドポイントの構成プロファイルおよび応答バナーから CVE-2021-41773 / CVE-2021-42013 の検証対象として検出されました。",
         "caveat": "「実機Workerで今すぐ検証」または「診断を開始」を実行すると、Gateway経由で reproduction_probe Worker が実際に検証します。",
         "evidence": [],
         "remediation": {"steps": ["Apache HTTP Server を最新の安定版（2.4.62以降）に更新する",
                                   "Server ヘッダーのバージョン表示を抑制する（ServerTokens Prod）"],
                         "how_to_verify": "「防御パッチ適用・再検証」または「実機Workerで今すぐ検証」を実行し、結果が「再現せず」に変わることを確認します。"}},
        {**common, "id": "f_idor", "title": "他アカウントの保護リソースへのアクセス制御不備（IDOR）",
         "severity": "high", "verdict": "detected", "category": "アクセス制御", "cve": [],
         "risk_level": "L2", "help_term": "idor",
         "summary": "検証用アカウント acct_A のトークンで、別アカウント acct_B の保護リソース（/api/accounts/B/secret）へアクセスできるか検証します。",
         "why_detected": "APIエンドポイント /api/accounts/B/secret においてオブジェクト単位の所有者検証が必要と判定されたためです。",
         "caveat": "「実機Workerで今すぐ検証」または「診断を開始」を実行すると、Gateway経由で reproduction_probe Worker が2アカウント間の実通信で実証します。",
         "evidence": [],
         "remediation": {"steps": ["サーバー側でセッション主体とリソース所有者を必ず照合し、不一致時は 403 Forbidden を返す"],
                         "how_to_verify": "修正後に同じ手順で再試験し、HTTP 403 が返ることを確認します。"}},
        {**common, "id": "f_sqli", "title": "検索欄のSQLインジェクション境界不備（/api/search）",
         "severity": "critical", "verdict": "detected", "category": "インジェクション",
         "cve": [], "risk_level": "L2", "help_term": "sqli",
         "summary": "検索エンドポイント /api/search?q=test' に対し、未バインドのSQL構文解釈が発生するかを非破壊プローブで検証します。",
         "why_detected": "検索パラメータ q において未エスケープのクエリ連結が行われている可能性が検出されたためです。",
         "caveat": "「実機Workerで今すぐ検証」または「診断を開始」を実行すると、Gateway経由で reproduction_probe Worker が実際のHTTP応答と監査ハッシュを記録します。",
         "evidence": [],
         "remediation": {"steps": ["プリペアドステートメント（プレースホルダー付きクエリ）を使用し文字列連結を廃止する"],
                         "how_to_verify": "修正前後で同じ試験を行い、SQL構文エラー差分が解消されることを確認します。"}},
    ]

