"""Planner LLM Gateway: the ARTEX planner's only model, run by Vulnix.

ARTEX stays inside its confinement and can reach only loopback endpoints. When its
model is to be a real one (Abliteration AI), ARTEX does not get the endpoint or the
key: it gets this gateway, on 127.0.0.1, and a per-run token for it. The gateway

  * authenticates ARTEX by that per-run token (any other local process is refused);
  * forwards ONLY to the configured upstream (fixed URL, https, no redirects), with the
    API key that only Vulnix holds - ARTEX's own headers are never forwarded;
  * forces the configured model, refuses streaming and oversized requests, and
    refuses tool schemas outside the planner allowlist;
  * inspects every request BEFORE it leaves: secrets (key patterns and the configured
    key itself), hosts other than the local lab / loopback, and any registered real
    service are refused - nothing of a real service is ever sent;
  * enforces budgets per run: number of calls, tokens, estimated cost;
  * in PREVIEW mode sends nothing anywhere: a local simulated model answers, and every
    request that WOULD have been sent is recorded (content and count) for the operator;
  * records each decision in the audit log (sizes, hashes, token/cost figures - never
    the content).

A real run must be approved against a preview: the approval names the digest of the
preview's first request and the maximum number of calls.
"""
from __future__ import annotations

import hashlib
import http.server
import json
import re
import secrets
import threading
import time
import urllib.parse
from dataclasses import dataclass, field

from .artex_bridge import PLANNER_TOOL_ALLOWLIST

MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 1 << 20

# Secret shapes that must never leave (in addition to the configured key itself).
SECRET_PATTERNS = [re.compile(p) for p in (
    r"sk-[A-Za-z0-9_\-]{16,}", r"ghp_[A-Za-z0-9]{20,}", r"github_pat_[A-Za-z0-9_]{20,}",
    r"AKIA[0-9A-Z]{16}", r"xox[abprs]-[A-Za-z0-9-]{10,}", r"AIza[0-9A-Za-z_\-]{30,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}",
    r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}",
)]
_URL_HOST = re.compile(r"(?i)\b(?:https?|ftp|wss?)://([^/\s:'\"\\]+)")


@dataclass
class Budget:
    max_calls: int = 6
    max_total_tokens: int = 60_000
    max_cost_usd: float = 0.50
    usd_per_1k_input: float = 0.0
    usd_per_1k_output: float = 0.0

    def estimate(self, prompt_tokens: int, completion_tokens: int) -> float:
        return round(prompt_tokens / 1000 * self.usd_per_1k_input
                     + completion_tokens / 1000 * self.usd_per_1k_output, 6)


@dataclass
class CallRecord:
    index: int
    decision: str                    # previewed | forwarded | refused
    reason: str
    request_sha256: str
    request_bytes: int
    est_prompt_tokens: int
    completion_tokens: int = 0
    est_cost_usd: float = 0.0
    at: float = field(default_factory=time.time)


def estimate_tokens(text: str) -> int:
    """A conservative estimate (no tokenizer here): ~1 token per 3 characters."""
    return max(1, len(text) // 3)


class GatewayRefused(Exception):
    pass


class PlannerLLMGateway:
    """One gateway per planner run. `mode`: "preview" (never forwards) or "forward"
    (forwards to `upstream_url`). `responder(body) -> dict` answers in preview mode
    (the local simulated model)."""

    def __init__(self, *, mode: str, model: str, upstream_url: str = "", api_key: str = "",
                 budget: Budget | None = None, allowed_hosts=(), denied_hosts=(),
                 responder=None, transport=None, audit=None, approval: dict | None = None):
        if mode not in ("preview", "forward"):
            raise ValueError("mode must be preview or forward")
        if mode == "forward":
            u = urllib.parse.urlsplit(upstream_url or "")
            loopback = (u.hostname or "") in ("127.0.0.1", "::1", "localhost")
            if not (u.scheme == "https" or (u.scheme == "http" and loopback)):
                raise ValueError("upstream must be https (http only for a local mock)")
            if not loopback:
                # a real endpoint: only with an approval bound to a preview
                if not approval or not isinstance(approval.get("max_calls"), int) \
                        or not re.fullmatch(r"[0-9a-f]{64}", str(approval.get("first_request_sha256", ""))):
                    raise ValueError("a real upstream needs an approval (max_calls, first_request_sha256)")
        elif responder is None:
            raise ValueError("preview mode needs a local responder")
        self.mode, self.model = mode, model
        self.upstream_url, self._key = upstream_url, api_key
        self.budget = budget or Budget()
        if approval and mode == "forward":
            self.budget.max_calls = min(self.budget.max_calls, int(approval["max_calls"]))
        self.approval = dict(approval or {})
        self.allowed_hosts = {h.lower() for h in allowed_hosts} | {"127.0.0.1", "localhost", "::1"}
        self.denied_hosts = {h.lower() for h in denied_hosts}
        self._responder = responder
        self._transport = transport
        self._audit = audit
        self.token = secrets.token_urlsafe(24)          # ARTEX's credential for THIS gateway only
        self.calls: list[CallRecord] = []
        self.preview_requests: list[dict] = []          # content: operator only, never audited
        self._lock = threading.Lock()
        self._tokens_used = 0
        self._cost_used = 0.0
        self._server = None

    # ---- inspection -----------------------------------------------------------
    def inspect(self, body: dict) -> dict:
        """The request as it may leave: model forced, nothing but the chat fields,
        tools within the allowlist, no secret, no foreign or real-service host."""
        if not isinstance(body, dict) or not isinstance(body.get("messages"), list):
            raise GatewayRefused("not a chat completions request")
        if body.get("stream"):
            raise GatewayRefused("streaming is not allowed")
        out = {"model": self.model, "messages": body["messages"]}
        for k in ("temperature", "top_p", "max_tokens", "tool_choice"):
            if k in body:
                out[k] = body[k]
        tools = body.get("tools") or []
        names = set()
        for t in tools:
            fn = t.get("function") if isinstance(t, dict) else None
            names.add(fn.get("name") if isinstance(fn, dict) else None)
        if names - PLANNER_TOOL_ALLOWLIST:
            raise GatewayRefused(f"tools outside the planner allowlist: {sorted(map(str, names - PLANNER_TOOL_ALLOWLIST))[:5]}")
        if tools:
            out["tools"] = tools
        text = json.dumps(out, ensure_ascii=False)
        if self._key and self._key in text:
            raise GatewayRefused("the request contains the API key")
        for pat in SECRET_PATTERNS:
            if pat.search(text):
                raise GatewayRefused("the request contains something that looks like a secret")
        for host in {h.lower().rstrip(".") for h in _URL_HOST.findall(text)}:
            if host in self.denied_hosts:
                raise GatewayRefused("the request names a registered real service")
            if host not in self.allowed_hosts:
                raise GatewayRefused(f"the request names a host outside the local lab: {host[:60]}")
        for host in self.denied_hosts:
            if host and host in text.lower():
                raise GatewayRefused("the request names a registered real service")
        mt = out.get("max_tokens")
        if not isinstance(mt, int) or not 0 < mt <= 4096:
            out["max_tokens"] = 2048                   # an explicit cap on every completion
        return out

    # ---- one call --------------------------------------------------------------
    def handle(self, raw: bytes, auth: str) -> tuple[int, dict]:
        if auth != f"Bearer {self.token}":
            return 401, {"error": {"message": "unauthorized"}}
        idx = len(self.calls) + 1
        sha = hashlib.sha256(raw).hexdigest()
        try:
            if len(raw) > MAX_REQUEST_BYTES:
                raise GatewayRefused("request too large")
            try:
                body = json.loads(raw)
            except ValueError:
                raise GatewayRefused("not JSON") from None
            clean = self.inspect(body)
            payload = json.dumps(clean, ensure_ascii=False, sort_keys=True).encode()
            sha = hashlib.sha256(payload).hexdigest()
            prompt_tokens = estimate_tokens(payload.decode())
            with self._lock:
                if len(self.calls) >= self.budget.max_calls:
                    raise GatewayRefused(f"call budget exhausted ({self.budget.max_calls})")
                worst = prompt_tokens + clean["max_tokens"]
                if self._tokens_used + worst > self.budget.max_total_tokens:
                    raise GatewayRefused(f"token budget exhausted ({self.budget.max_total_tokens})")
                worst_cost = self.budget.estimate(prompt_tokens, clean["max_tokens"])
                if self._cost_used + worst_cost > self.budget.max_cost_usd:
                    raise GatewayRefused(f"cost budget exhausted (${self.budget.max_cost_usd})")
                if (self.mode == "forward" and idx == 1 and self.approval
                        and sha != self.approval.get("first_request_sha256")):
                    raise GatewayRefused("the first request differs from the approved preview")
                rec = CallRecord(idx, "previewed" if self.mode == "preview" else "forwarded", "",
                                 sha, len(payload), prompt_tokens)
                self.calls.append(rec)
            if self.mode == "preview":
                self.preview_requests.append(clean)
                resp = self._responder(clean)
            else:
                headers = {"Content-Type": "application/json"}
                if self._key:
                    headers["Authorization"] = f"Bearer {self._key}"
                transport = self._transport
                if transport is None:
                    from .router import _http_transport
                    transport = _http_transport
                data = transport(self.upstream_url, headers, payload)
                if len(data) > MAX_RESPONSE_BYTES:
                    raise GatewayRefused("upstream response too large")
                resp = json.loads(data)
            usage = resp.get("usage") if isinstance(resp, dict) else None
            completion = int(usage.get("completion_tokens", 0)) if isinstance(usage, dict) else 0
            prompt_real = int(usage.get("prompt_tokens", 0)) if isinstance(usage, dict) else 0
            with self._lock:
                rec.completion_tokens = completion
                used = max(prompt_real, prompt_tokens) + completion
                rec.est_cost_usd = self.budget.estimate(max(prompt_real, prompt_tokens), completion)
                self._tokens_used += used
                self._cost_used += rec.est_cost_usd
            self._record("planner_llm.call", rec)
            return 200, resp
        except GatewayRefused as e:
            rec = CallRecord(idx, "refused", str(e)[:200], sha, len(raw), 0)
            with self._lock:
                self.calls.append(rec)
            self._record("planner_llm.refused", rec)
            return 403, {"error": {"message": f"refused by the Vulnix planner gateway: {e}"}}
        except Exception as e:  # noqa: BLE001 - upstream failure: recorded, no content
            rec = CallRecord(idx, "refused", f"upstream error: {type(e).__name__}", sha, len(raw), 0)
            with self._lock:
                self.calls.append(rec)
            self._record("planner_llm.upstream_error", rec)
            return 502, {"error": {"message": "upstream error"}}

    def _record(self, event: str, rec: CallRecord) -> None:
        if self._audit is None:
            return
        try:
            self._audit.record(event, mode=self.mode, index=rec.index, decision=rec.decision,
                               reason=rec.reason, request_sha256=rec.request_sha256,
                               request_bytes=rec.request_bytes, est_prompt_tokens=rec.est_prompt_tokens,
                               completion_tokens=rec.completion_tokens, est_cost_usd=rec.est_cost_usd)
        except Exception:  # noqa: BLE001 - the audit must not break the planner run
            pass

    # ---- report ------------------------------------------------------------------
    def report(self) -> dict:
        with self._lock:
            forwarded = [c for c in self.calls if c.decision in ("forwarded", "previewed")]
            return {
                "mode": self.mode, "model": self.model,
                "upstream": urllib.parse.urlsplit(self.upstream_url).netloc if self.mode == "forward" else None,
                "calls": len(forwarded), "refused": len(self.calls) - len(forwarded),
                "est_tokens": self._tokens_used, "est_cost_usd": round(self._cost_used, 6),
                "budget": {"max_calls": self.budget.max_calls, "max_total_tokens": self.budget.max_total_tokens,
                           "max_cost_usd": self.budget.max_cost_usd},
                "first_request_sha256": self.calls[0].request_sha256 if self.calls else None,
                "records": [c.__dict__ for c in self.calls],
            }

    # ---- server ------------------------------------------------------------------
    def __enter__(self) -> "PlannerLLMGateway":
        gw = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self._send(200, {"object": "list", "data": [{"id": gw.model, "object": "model"}]})

            def do_POST(self):
                if not self.path.rstrip("/").endswith("/chat/completions"):
                    return self._send(404, {"error": {"message": "not found"}})
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(min(n, MAX_REQUEST_BYTES + 1))
                code, body = gw.handle(raw, self.headers.get("Authorization", ""))
                self._send(code, body)

            def _send(self, code, body):
                data = json.dumps(body, ensure_ascii=False).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}/v1"
