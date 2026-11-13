"""Loopback-only mock of an OpenAI-compatible LLM that drives the REAL ARTEX planner
through one planning round, for verification without any external model.

Turn 1 (no tool results yet): the assistant calls ARTEX's `add_intent` with a fixed
batch of intents, and - in the same message - tries tools the planner must not
have (Bash, WebFetch, add_task_scope). Turn 2 (after tool results): a final text
answer, no tool calls.

Every request is recorded (`MockLLM.requests`), so a test can check, independently
of the overlay's own report, which tools ARTEX actually offered to the model.
Supports non-streaming and streaming (SSE) chat completions.
"""
from __future__ import annotations

import http.server
import json
import re
import threading

INTENTS = [
    {"summary": "对 /api/search 的 q 参数进行 SQL 注入边界的非破坏性验证", "asset_ids": [1], "priority": 8},
    {"summary": "使用两个测试账号验证 /api/accounts 的 IDOR 越权访问控制", "asset_ids": [1], "priority": 7},
    {"summary": "收集首页的响应头与服务器 banner 指纹", "asset_ids": [1], "priority": 5},
    {"summary": "尝试上传 webshell 以获取 RCE", "asset_ids": [1], "priority": 9},
    # asset 99 does not exist: real ARTEX refuses to store it (foreign key)
    {"summary": "对 asset 99 的登录接口进行 SQL 注入", "asset_ids": [99], "priority": 6},
    {"summary": "研究业务逻辑，寻找可能的攻击面", "asset_ids": [], "priority": 3},
    {"summary": "对 http://evil.example/ 的 search 接口做 SQL 注入验证", "asset_ids": [1], "priority": 6},
]

FORBIDDEN_CALLS = [
    ("Bash", {"command": "curl -s http://example.com/ && id"}),
    ("WebFetch", {"url": "http://example.com/", "prompt": "x"}),
    ("add_task_scope", {"scope": "example.com"}),
]


SEEDED = re.compile(r"In-scope target: asset_id=(\d+)")


def _seeded_asset_id(messages: list) -> int:
    """The ARTEX asset id the overlay seeded for the target (read from the prompt,
    as a model would); 1 if none is found."""
    for m in messages:
        content = m.get("content") if isinstance(m, dict) else None
        text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
        found = SEEDED.search(text or "")
        if found:
            return int(found.group(1))
    return 1


# An asset that EXISTS in ARTEX's store but is not the seeded target (ARTEX creates
# host/domain assets next to a seeded HTTP service): such an intent is stored by
# ARTEX but must never become executable in Vulnix.
UNSEEDED_MARKER = "UNSEEDED-ASSET"


def intents_for(asset_id: int) -> list[dict]:
    out = [{**it, "asset_ids": [asset_id if a == 1 else a for a in it["asset_ids"]]} for it in INTENTS]
    out.append({"summary": f"对相邻主机资产进行 SQL 注入验证 {UNSEEDED_MARKER}", "asset_ids": [asset_id + 1],
                "priority": 4})
    return out


def _tool_calls(asset_id: int = 1) -> list[dict]:
    calls = [{"id": "call_add_intent", "type": "function",
              "function": {"name": "add_intent",
                           "arguments": json.dumps({"intents": intents_for(asset_id)}, ensure_ascii=False)}}]
    for i, (name, args) in enumerate(FORBIDDEN_CALLS):
        calls.append({"id": f"call_forbidden_{i}", "type": "function",
                      "function": {"name": name, "arguments": json.dumps(args)}})
    return calls


def spec_violation(req: dict) -> str | None:
    """The official Chat Completions tool-calling rules a strict upstream enforces."""
    tools = req.get("tools")
    if tools is not None and not tools:
        return "empty tools array"
    if req.get("tool_choice") is not None and not tools:
        return "tool_choice without tools"
    pending = []
    for m in req.get("messages") or []:
        role = m.get("role")
        if role == "assistant" and m.get("tool_calls"):
            if pending:
                return "tool call not answered"
            pending = [tc.get("id") for tc in m["tool_calls"]]
        elif role == "tool":
            if m.get("tool_call_id") not in pending:
                return "tool result for no open tool call"
            if not isinstance(m.get("content"), str):
                return "tool content must be a string"
            pending.remove(m["tool_call_id"])
        elif pending:
            return "tool call not answered"
    return "tool call not answered" if pending else None


class MockLLM:
    """`strict`: reject (400) what breaks the official tool-calling rules.
    `fail_at` / `fail_status`: answer the Nth request with that HTTP error (its body
    carries a secret-looking string, to prove the gateway never logs or shows it)."""

    def __init__(self, port: int = 0, *, strict: bool = False, fail_at: int | None = None, fail_status: int = 402):
        self.requests: list[dict] = []
        self.strict, self.fail_at, self.fail_status = strict, fail_at, fail_status
        mock = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                body = json.dumps({"object": "list", "data": [{"id": "mock", "object": "model"}]}).encode()
                self._send(200, body, "application/json")

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                try:
                    req = json.loads(raw or b"{}")
                except ValueError:
                    req = {}
                mock.requests.append({"path": self.path, "body": req})
                if mock.fail_at is not None and len(mock.requests) == mock.fail_at:
                    err = json.dumps({"error": {"message": "insufficient credits; account token sk-mockSECRETvalue1234567890",
                                                "type": "billing"}}).encode()
                    return self._send(mock.fail_status, err, "application/json")
                if mock.strict:
                    why = spec_violation(req)
                    if why:
                        return self._send(400, json.dumps({"error": {"message": why}}).encode(), "application/json")
                msgs = req.get("messages") or []
                has_results = any(m.get("role") == "tool" for m in msgs if isinstance(m, dict))
                if has_results:
                    message = {"role": "assistant", "content": "规划完成：已提交探索方向。"}
                    finish = "stop"
                else:
                    message = {"role": "assistant", "content": "",
                               "tool_calls": _tool_calls(_seeded_asset_id(msgs))}
                    finish = "tool_calls"
                if req.get("stream"):
                    self._stream(message, finish)
                else:
                    body = json.dumps({"id": "cmpl-mock", "object": "chat.completion", "model": req.get("model", "mock"),
                                       "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                                       "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}},
                                      ensure_ascii=False).encode()
                    self._send(200, body, "application/json")

            def _stream(self, message: dict, finish: str):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()

                def chunk(delta: dict, fin=None):
                    ev = {"id": "cmpl-mock", "object": "chat.completion.chunk", "model": "mock",
                          "choices": [{"index": 0, "delta": delta, "finish_reason": fin}]}
                    self.wfile.write(b"data: " + json.dumps(ev, ensure_ascii=False).encode() + b"\n\n")
                chunk({"role": "assistant", "content": message.get("content") or ""})
                for i, tc in enumerate(message.get("tool_calls") or []):
                    chunk({"tool_calls": [{"index": i, "id": tc["id"], "type": "function",
                                           "function": {"name": tc["function"]["name"],
                                                        "arguments": tc["function"]["arguments"]}}]})
                chunk({}, finish)
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

            def _send(self, code: int, body: bytes, ctype: str):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/v1"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def offered_tool_names(self) -> set[str]:
        names: set[str] = set()
        for r in self.requests:
            for t in r["body"].get("tools") or []:
                fn = t.get("function") if isinstance(t, dict) else None
                if isinstance(fn, dict) and fn.get("name"):
                    names.add(fn["name"])
                elif isinstance(t, dict) and t.get("name"):
                    names.add(t["name"])
        return names
