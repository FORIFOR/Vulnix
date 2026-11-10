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


def make_abliteration_handler():
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

            if "proposals" in sys_prompt or "diagnostic planner" in sys_prompt:
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


def start_abliteration_server(port: int = 0) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_abliteration_handler())
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True, name="abliteration-http").start()
    return srv
