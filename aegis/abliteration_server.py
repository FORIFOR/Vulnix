"""OpenAI-compatible Abliteration AI local HTTP endpoint (`aegis/abliteration_server.py`).

Provides a real HTTP server implementing `/v1/models` and `/v1/chat/completions`
(OpenAI Chat Completions format with `messages` -> `choices[0].message.content`)
so that Vulnix can execute and verify live HTTP inference round-trips for both:
  1. Structured diagnostic proposal generation (fenced JSON inside `message.content`)
  2. Context-grounded Japanese vulnerability Q&A (`AbliterationBackend.chat`)
even in offline or CI environments when an external GPU server is not attached.
"""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL_ID = "abliteration-sec-1-local"


def _build_proposal_content(user_content: str) -> str:
    try:
        ctx = json.loads(user_content) if user_content.strip().startswith("{") else {}
    except Exception:
        ctx = {}
    target_id = str(ctx.get("target_id", "lab"))
    target_url = str(ctx.get("target_url", "http://lab.test:18081/"))
    phase = str(ctx.get("phase", "config"))
    if phase == "verification":
        proposals = [
            {
                "tool": "reproduction_probe",
                "target_id": target_id,
                "action": "safe_reproduction",
                "args": {"url": target_url, "check": "idor"},
                "rationale": "Abliteration AI: 認可境界（IDOR）の非破壊再現プローブを提案",
            }
        ]
    else:
        proposals = [
            {
                "tool": "http_probe",
                "target_id": target_id,
                "action": "read_only_probe",
                "args": {"url": target_url, "method": "GET"},
                "rationale": "Abliteration AI: 公開HTTPヘッダーとバナー露出の非破壊GETプローブを提案",
            }
        ]
    return "```json\n" + json.dumps({"proposals": proposals}, ensure_ascii=False) + "\n```"


def _build_chat_content(user_content: str) -> str:
    try:
        payload = json.loads(user_content)
    except Exception:
        payload = {"question": user_content, "context": {}}
    q = str(payload.get("question", ""))
    ctx = payload.get("context") if isinstance(payload.get("context"), dict) else {}
    tf = ctx.get("target_finding") if isinstance(ctx.get("target_finding"), dict) else None
    title = tf.get("title") if tf else "検出されたセキュリティ課題"
    verdict = tf.get("verdict") if tf else "detected"
    return (
        f"【Abliteration AI 診断解説】対象「{title}」（現在の判定: {verdict}）について回答します。"
        f"質問「{q}」に対し、サーバー側での所有者検証（セッション主体とリソース所有者の照合）、"
        "パラメータ化クエリの徹底、およびバージョン情報の非公開化・最新パッチ適用を実施した上で、"
        "Gateway 経由の再検証プローブで HTTP 403/404 等の防御応答を確認してください。"
    )


# Advisor mode (aegis/ai_advisor.py): deterministic advice from the allow-listed payload only.
ADVISOR_MARKER = "vulnix-advisor/v1"
MAX_RECORDED = 50
_ADVICE_BY_RULE = {
    "f_headers": ("ブラウザ側の防御を指示するヘッダーが無いため、スクリプトの埋め込みやクリックジャッキングの被害が大きくなりやすい状態です。",
                  ["Content-Security-Policy を段階的に導入する（まず Report-Only で影響を確認する）",
                   "X-Content-Type-Options: nosniff と X-Frame-Options（または frame-ancestors）を設定する",
                   "HTTPS で提供している場合は Strict-Transport-Security を設定する"],
                  [("修正後に同じ L1 プローブでヘッダーの有無を再確認する", "L1", "設定の反映を非破壊の1リクエストで確かめるため")]),
    "f_powered": ("使用している製品とバージョンが応答から読み取れるため、既知の脆弱性を持つ版かどうかを外部から推測されやすくなります。",
                  ["Server / X-Powered-By ヘッダーからバージョン情報を外す", "利用中のミドルウェアを保守対象の最新版に更新する"],
                  [("バージョン表示が消えたかを L1 プローブで再確認する", "L1", "情報露出の解消を確かめるため")]),
    "f_banner": ("公開されているバージョンが既知の脆弱性の対象範囲に含まれます。ただし現時点では表示からの推定で、悪用できるかは確かめていません。",
                 ["該当製品を修正済みの版に更新する", "更新までの間はバージョン表示を止め、影響する機能を無効化できるか確認する"],
                 [("更新後にバージョン表示が修正済みの版になったかを確認する", "L1", "推定の根拠そのものが解消したかを見るため")]),
    "f_l1_tls": ("古い TLS が有効なため、通信経路の暗号強度が下がる組み合わせを選ばれる余地があります。",
                 ["TLS 1.2 未満を無効化する", "弱い暗号スイートを無効化し、前方秘匿性のあるものに限定する"],
                 [("TLS の設定変更後にネゴシエーション結果を L1 で再確認する", "L1", "有効なプロトコルが変わったかを見るため")]),
    "f_l1_no_tls": ("平文 HTTP で提供されているため、経路上で内容の盗聴や改ざんを受けるおそれがあります。",
                    ["HTTPS を提供し、HTTP からは HTTPS へ誘導する", "HSTS を設定する"],
                    [("HTTPS での提供とリダイレクトの有無を L1 で確認する", "L1", "平文での提供が終わったかを見るため")]),
    "f_l1_cookies": ("Cookie の属性が不足しているため、スクリプトからの読み取りや別サイト経由の送信を許す可能性があります。",
                     ["セッション Cookie に Secure、HttpOnly、SameSite を付ける"],
                     [("修正後の応答で Cookie の属性を L1 で再確認する", "L1", "属性が付いたかを見るため")]),
    "f_l1_cors": ("オリジンの許可が広く、ほかのサイトのスクリプトから応答を読まれる可能性があります。",
                  ["許可するオリジンを明示的な一覧に限定する", "資格情報つきの要求を許可するオリジンをさらに絞る"],
                  [("信頼しないオリジンからの要求に対する応答ヘッダーを L1 で再確認する", "L1", "許可の範囲が狭まったかを見るため")]),
    "f_l1_unauth_api": ("認証なしの要求に JSON が返っています。公開を意図した API かどうかで重大さが変わり、現時点では判断できません。",
                        ["公開を意図しない API には認証を必須にする", "公開する API は返す項目を最小限にする"],
                        [("テスト用アカウントの有無で応答が変わるかを確認する", "L2", "認証境界の確認には承認つきの L2 検証が必要なため")]),
    "f_idor": ("別のアカウントの資源に到達できる可能性が示されています。判定は検出段階で、実際に到達できるかはまだ確かめていません。",
               ["資源ごとに、要求した主体が所有者かをサーバー側で照合する", "推測しやすい連番の識別子を避ける"],
               [("テスト用アカウントAで、テスト用アカウントBの模擬データに到達できないことを確認する", "L2", "所有者の照合を承認つきの L2 検証で確かめるため")]),
    "f_sqli": ("入力の扱いに不備がある可能性があります。判定は検出段階で、実際に悪用できるかはまだ確かめていません。",
               ["パラメータ化クエリを徹底する", "入力の型と長さをサーバー側で検証する"],
               [("模擬データの環境で、入力の境界が守られていることを確認する", "L2", "データベースに関わるため承認つきの L2 検証で扱うため")]),
}
_GENERIC_ADVICE = ("この所見の影響は、提供の形態と運用によって変わります。",
                   ["設定と提供範囲を見直し、不要な公開をなくす"],
                   [("修正後に同じ L1 プローブで状態を再確認する", "L1", "修正の反映を確かめるため")])


def _build_advice_content(user_content: str) -> str:
    try:
        findings = json.loads(user_content).get("findings") or []
    except Exception:
        findings = []
    advice = []
    for f in findings:
        if not isinstance(f, dict) or not isinstance(f.get("ref"), str):
            continue
        expl, rem, checks = _ADVICE_BY_RULE.get(f.get("rule"), _GENERIC_ADVICE)
        if f.get("verdict") == "proven":
            expl = "L2 の再現記録がある所見です。" + expl
        advice.append({"ref": f["ref"], "risk_explanation": expl, "remediation": list(rem),
                       "next_checks": [{"title": t, "level": lv, "reason": r} for t, lv, r in checks]})
    return "```json\n" + json.dumps({"advice": advice}, ensure_ascii=False) + "\n```"


def make_abliteration_handler(advisor_reply=None, received=None):
    """advisor_reply(user_content) -> content overrides the advisor answer (tests use it
    to play a misbehaving model); received, if a list, gets every request body."""
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _send_json(self, status: int, obj: dict) -> None:
            raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            if self.path.rstrip("/") in ("/v1/models", "/models"):
                return self._send_json(200, {
                    "object": "list",
                    "data": [{"id": MODEL_ID, "object": "model", "owned_by": "vulnix-abliteration"}],
                })
            return self._send_json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if not self.path.rstrip("/").endswith("/chat/completions"):
                return self._send_json(404, {"error": "not found"})
            n = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                return self._send_json(400, {"error": "invalid json"})

            model = str(body.get("model") or MODEL_ID)
            messages = body.get("messages") if isinstance(body.get("messages"), list) else []
            sys_prompt = " ".join(
                str(m.get("content", "")) for m in messages if isinstance(m, dict) and m.get("role") == "system"
            )
            user_prompt = " ".join(
                str(m.get("content", "")) for m in messages if isinstance(m, dict) and m.get("role") == "user"
            )

            if received is not None:
                received.append(body)
                del received[:-MAX_RECORDED]          # keep only the latest requests
            if ADVISOR_MARKER in sys_prompt:
                content = advisor_reply(user_prompt) if advisor_reply else _build_advice_content(user_prompt)
            elif "proposals" in sys_prompt or "diagnostic planner" in sys_prompt:
                content = _build_proposal_content(user_prompt)
            else:
                content = _build_chat_content(user_prompt)

            return self._send_json(200, {
                "id": f"chatcmpl-{int(time.time() * 1000)}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 64, "completion_tokens": 96, "total_tokens": 160},
            })

    return Handler


def start_abliteration_server(port: int = 0, *, advisor_reply=None) -> ThreadingHTTPServer:
    received: list = []
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_abliteration_handler(advisor_reply, received))
    srv.received = received
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True, name="abliteration-http").start()
    return srv
