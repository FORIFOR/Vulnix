"""Planner LLM Gateway: the ARTEX planner's only model, run by Vulnix.

ARTEX stays inside its confinement and can reach only loopback endpoints. When its
model is to be a real one (Abliteration AI), ARTEX does not get the endpoint or the
key: it gets this gateway, on 127.0.0.1, and a per-run token for it. The gateway

  * authenticates ARTEX by that per-run token (constant-time compare);
  * forwards ONLY to the configured upstream (fixed URL, https, no redirects, not a
    private address), with the API key only Vulnix holds - ARTEX's headers never leave;
  * forces the model, refuses streaming / oversized requests, keeps tool schemas to the
    planner allowlist (name, description, parameters only), caps every completion;
  * inspects every string BEFORE it leaves - message contents, content parts and the
    parsed tool-call arguments, each NFKC-normalised with format characters removed,
    singly and concatenated: secret shapes (also as JSON key/value pairs), the
    configured key (plain, base64, hex), registered real services (looked up per
    request), and internal hosts outside the lab (any scheme, userinfo, bare IPs, short
    or octal IPv4 forms, IPv6, internal-only names);
  * enforces per-run budgets - calls, tokens, cost - by RESERVING the worst case of a
    call before it is sent (so concurrent calls cannot overrun) and settling after;
    upstream usage figures are clamped, a call without usage or that fails after being
    sent is charged its reserved worst case; a real upstream needs non-zero prices;
  * stops forwarding when the run is stopped (`may_forward`), and on close;
  * audits BEFORE forwarding (no audit record, no forward) and after - sizes, hashes,
    token / cost figures, fixed reason codes; never content;
  * PREVIEW: sends nothing anywhere; a local responder answers and every request that
    would have been sent is kept for the approver.

A real run is approved against a stored preview (see AssessmentService): the approval
names that preview, is single-use, expires, and cannot be given by whoever ran the
preview. The gateway enforces its part: until one request has been forwarded, every
request must match the approved fingerprint (a refused request does not unlock it).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import ipaddress
import json
import re
import secrets
import socket
import threading
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

from .artex_bridge import PLANNER_TOOL_ALLOWLIST

MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 1 << 20
MAX_COMPLETION_TOKENS = 2048

SECRET_PATTERNS = [re.compile(p) for p in (
    r"sk-[A-Za-z0-9_\-]{16,}", r"ghp_[A-Za-z0-9]{20,}", r"github_pat_[A-Za-z0-9_]{20,}",
    r"AKIA[0-9A-Z]{16}", r"xox[abprs]-[A-Za-z0-9-]{10,}", r"AIza[0-9A-Za-z_\-]{30,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}",
    r"(?i)(password|passwd|secret|api[_-]?key|access[_-]?key|token)[\"']?\s*[:=]\s*[\"']?[^\s\"',}]{8,}",
)]
SECRET_KEY_NAMES = re.compile(r"(?i)^(password|passwd|secret|api[_-]?key|access[_-]?key|token|auth|authorization)$")

# Host-like tokens: URLs of any scheme (userinfo allowed), bracketed IPv6, bare IPv4
# (also short / octal / hex forms), and names under internal-only suffixes.
_URLISH = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://(?:[^\s/@'\"<>]*@)?(\[[0-9a-f:.%]+\]|[^\s/:'\"<>?#]+)")
# bare IPv4 in text: the full dotted-quad only (short / octal / hex forms are checked
# where they act as hosts - inside URLs - so "2.0" or "10.5" in prose is not an address)
_BARE_IP = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
_BRACKET_V6 = re.compile(r"\[([0-9a-f:.]+)\]", re.I)
_INTERNAL_SUFFIXES = (".internal", ".local", ".lan", ".corp", ".intranet", ".home.arpa", ".localdomain")
_INTERNAL_NAME = re.compile(r"(?i)\b[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)*(?:"
                            + "|".join(re.escape(s) for s in _INTERNAL_SUFFIXES) + r")\b")


@dataclass
class Budget:
    max_calls: int = 6
    max_total_tokens: int = 60_000
    max_cost_usd: float = 0.50
    usd_per_1k_input: float = 0.0
    usd_per_1k_output: float = 0.0

    def estimate(self, prompt_tokens: int, completion_tokens: int) -> float:
        return round(max(0, prompt_tokens) / 1000 * self.usd_per_1k_input
                     + max(0, completion_tokens) / 1000 * self.usd_per_1k_output, 6)


@dataclass
class CallRecord:
    index: int
    decision: str                    # previewed | forwarded | refused | failed
    reason: str                      # a fixed code, never request content
    request_sha256: str
    request_bytes: int
    est_prompt_tokens: int
    completion_tokens: int = 0
    charged_tokens: int = 0
    est_cost_usd: float = 0.0
    at: float = field(default_factory=time.time)


def estimate_tokens(text: str) -> int:
    """A conservative estimate (no tokenizer here): ~1 token per 3 characters."""
    return max(1, len(text) // 3)


class GatewayRefused(Exception):
    """`code` is a fixed reason code (safe to audit); the message may be more specific."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code


def _norm(s: str) -> str:
    """NFKC, then without format (Cf) characters such as zero-width spaces."""
    s = unicodedata.normalize("NFKC", s)
    return "".join(ch for ch in s if unicodedata.category(ch) != "Cf")


def _strings(obj, out: list, keyed: list) -> None:
    """Every string in a request (tool-call arguments parsed as JSON too), and every
    (key, string value) pair of a JSON object."""
    if isinstance(obj, str):
        out.append(obj)
        t = obj.strip()
        if t[:1] in "{[":
            try:
                _strings(json.loads(t), out, keyed)
            except ValueError:
                pass
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                out.append(k)
                if isinstance(v, str):
                    keyed.append((k, v))
            _strings(v, out, keyed)
    elif isinstance(obj, list):
        for v in obj:
            _strings(v, out, keyed)


def _ip(host: str):
    host = host.strip("[]").split("%", 1)[0]
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    if re.fullmatch(r"(?i)(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}", host):
        try:                                   # inet_aton forms: 10.1, 0300.0250.1.5, 0xa000001
            return ipaddress.ip_address(socket.inet_aton(host))
        except OSError:
            return None
    return None


def _internal(host: str) -> bool:
    """A private / loopback / link-local / reserved / multicast address, or an
    internal-only name. Public names a model mentions are not Vulnix data."""
    ip = _ip(host)
    if ip is not None:
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast \
            or ip.is_unspecified
    h = host.lower().rstrip(".")
    return h.endswith(_INTERNAL_SUFFIXES) or "." not in h


def host_candidates(text: str) -> set[str]:
    found = {m.group(1) for m in _URLISH.finditer(text)}
    found |= {m.group(1) for m in _BRACKET_V6.finditer(text)}
    found |= {m.group(1) for m in _BARE_IP.finditer(text)}
    found |= {m.group(0) for m in _INTERNAL_NAME.finditer(text)}
    return {h.lower().rstrip(".").strip("[]") for h in found if h}


class PlannerLLMGateway:
    """One gateway per planner run. `mode`: "preview" (never forwards) or "forward"."""

    def __init__(self, *, mode: str, model: str, upstream_url: str = "", api_key: str = "",
                 budget: Budget | None = None, allowed_hosts=(), denied_hosts=(),
                 responder=None, transport=None, audit=None, approval: dict | None = None,
                 may_forward=None):
        if mode not in ("preview", "forward"):
            raise ValueError("mode must be preview or forward")
        self.budget = budget or Budget()
        self.real = False
        if mode == "forward":
            u = urllib.parse.urlsplit(upstream_url or "")
            host = u.hostname or ""
            loopback = host in ("127.0.0.1", "::1", "localhost")
            if not (u.scheme == "https" or (u.scheme == "http" and loopback)):
                raise ValueError("upstream must be https (http only for a local mock)")
            if not loopback:
                ip = _ip(host)
                if ip is not None and (ip.is_private or ip.is_link_local or ip.is_reserved):
                    raise ValueError("upstream must not be a private address")
                if not approval or not isinstance(approval.get("max_calls"), int) or approval["max_calls"] < 1 \
                        or not re.fullmatch(r"[0-9a-f]{64}", str(approval.get("first_request_sha256", ""))):
                    raise ValueError("a real upstream needs an approval (max_calls, first_request_sha256)")
                if self.budget.usd_per_1k_input <= 0 or self.budget.usd_per_1k_output <= 0:
                    raise ValueError("a real upstream needs its prices (USD per 1K input / output tokens)")
                self.real = True
        elif responder is None:
            raise ValueError("preview mode needs a local responder")
        self.mode, self.model = mode, model
        self.upstream_url, self._key = upstream_url, api_key
        if approval and self.real:
            self.budget.max_calls = min(self.budget.max_calls, int(approval["max_calls"]))
        self.approval = dict(approval or {}) if self.real else {}
        self.allowed_hosts = {h.lower() for h in allowed_hosts} | {"127.0.0.1", "localhost", "::1"}
        self._denied = denied_hosts if callable(denied_hosts) else (lambda d=frozenset(denied_hosts): d)
        self._responder = responder
        self._transport = transport
        self._audit = audit
        self._may_forward = may_forward
        self.token = secrets.token_urlsafe(24)
        self.calls: list[CallRecord] = []
        self.preview_requests: list[dict] = []
        self._lock = threading.Lock()
        self._tokens_used = 0
        self._cost_used = 0.0
        self._first_passed = False            # until one request passed, the fingerprint binds
        self._closed = False
        self._server = None
        self._key_forms = self._forms(api_key)

    @staticmethod
    def _forms(key: str) -> list[str]:
        if not key or len(key) < 8:
            return []
        raw = key.encode()
        return [key, base64.b64encode(raw).decode().rstrip("="), base64.urlsafe_b64encode(raw).decode().rstrip("="),
                raw.hex()]

    # ---- inspection -----------------------------------------------------------
    def _tools(self, tools) -> list:
        out = []
        for t in tools or []:
            fn = t.get("function") if isinstance(t, dict) else None
            name = fn.get("name") if isinstance(fn, dict) else None
            if t.get("type", "function") != "function" or name not in PLANNER_TOOL_ALLOWLIST:
                raise GatewayRefused("tool_not_allowed", "a tool outside the planner allowlist")
            clean = {"name": name}
            for k in ("description", "parameters"):
                if k in fn:
                    clean[k] = fn[k]
            out.append({"type": "function", "function": clean})
        return out

    def inspect(self, body: dict) -> dict:
        if not isinstance(body, dict) or not isinstance(body.get("messages"), list):
            raise GatewayRefused("not_chat", "not a chat completions request")
        if body.get("stream"):
            raise GatewayRefused("stream", "streaming is not allowed")
        out = {"model": self.model, "messages": body["messages"]}
        for k in ("temperature", "top_p"):
            if isinstance(body.get(k), (int, float)):
                out[k] = body[k]
        tools = self._tools(body.get("tools"))
        if tools:
            out["tools"] = tools
        tc = body.get("tool_choice")
        if tc in ("auto", "none", "required"):
            out["tool_choice"] = tc
        elif isinstance(tc, dict) and (tc.get("function") or {}).get("name") in PLANNER_TOOL_ALLOWLIST:
            out["tool_choice"] = {"type": "function", "function": {"name": tc["function"]["name"]}}
        mt = body.get("max_tokens")
        out["max_tokens"] = mt if isinstance(mt, int) and 0 < mt <= MAX_COMPLETION_TOKENS else MAX_COMPLETION_TOKENS

        strings, keyed = [], []
        _strings(out["messages"], strings, keyed)
        normed = [_norm(s) for s in strings]
        whole = "\n".join(normed)
        whole_joined = "".join(normed)                    # a secret split across strings
        for text in (*normed, whole, whole_joined):
            for form in self._key_forms:
                if form in text:
                    raise GatewayRefused("contains_key", "the request contains the API key")
            for pat in SECRET_PATTERNS:
                if pat.search(text):
                    raise GatewayRefused("contains_secret", "the request contains something that looks like a secret")
        for k, v in keyed:
            if SECRET_KEY_NAMES.match(_norm(k).strip()) and len(_norm(v).strip()) >= 8:
                raise GatewayRefused("contains_secret", "the request contains something that looks like a secret")
        denied = {d.lower() for d in self._denied() if d}
        low, low_joined = whole.lower(), whole_joined.lower()
        for d in denied:
            forms = {d}
            try:
                forms.add(d.encode("idna").decode())
            except UnicodeError:
                pass
            if any(f in low or f in low_joined for f in forms):
                raise GatewayRefused("real_service", "the request names a registered real service")
        for host in host_candidates(whole):
            if host in denied:
                raise GatewayRefused("real_service", "the request names a registered real service")
            if host not in self.allowed_hosts and _internal(host):
                raise GatewayRefused("internal_host", "the request names an internal host outside the local lab")
        return out

    # ---- one call --------------------------------------------------------------
    def handle(self, raw: bytes, auth: str) -> tuple[int, dict]:
        if not hmac.compare_digest(auth.encode(), f"Bearer {self.token}".encode()):
            return 401, {"error": {"message": "unauthorized"}}
        rec = None
        try:
            if len(raw) > MAX_REQUEST_BYTES:
                raise GatewayRefused("too_large", "request too large")
            try:
                body = json.loads(raw)
            except ValueError:
                raise GatewayRefused("not_json", "not JSON") from None
            clean = self.inspect(body)
            payload = json.dumps(clean, ensure_ascii=False, sort_keys=True).encode()
            sha = hashlib.sha256(payload).hexdigest()
            prompt_tokens = estimate_tokens(payload.decode())
            worst_tokens = prompt_tokens + clean["max_tokens"]
            worst_cost = self.budget.estimate(prompt_tokens, clean["max_tokens"])
            with self._lock:
                if self._closed:
                    raise GatewayRefused("closed", "the planner run is over")
                if self.mode == "forward" and self._may_forward is not None and not self._may_forward():
                    raise GatewayRefused("stopped", "the planner run was stopped")
                passed = [c for c in self.calls if c.decision in ("forwarded", "previewed", "failed")]
                if len(passed) >= self.budget.max_calls:
                    raise GatewayRefused("call_budget", f"call budget exhausted ({self.budget.max_calls})")
                if self._tokens_used + worst_tokens > self.budget.max_total_tokens:
                    raise GatewayRefused("token_budget", f"token budget exhausted ({self.budget.max_total_tokens})")
                if self._cost_used + worst_cost > self.budget.max_cost_usd:
                    raise GatewayRefused("cost_budget", f"cost budget exhausted (${self.budget.max_cost_usd})")
                if self.real and not self._first_passed and sha != self.approval.get("first_request_sha256"):
                    raise GatewayRefused("not_approved", "the request differs from the approved preview")
                # reserve the worst case before anything is sent
                self._tokens_used += worst_tokens
                self._cost_used += worst_cost
                rec = CallRecord(len(self.calls) + 1, "previewed" if self.mode == "preview" else "forwarded",
                                 "", sha, len(payload), prompt_tokens, charged_tokens=worst_tokens,
                                 est_cost_usd=worst_cost)
                self.calls.append(rec)
                self._first_passed = True
            if self.mode == "preview":
                self.preview_requests.append(clean)
                resp = self._responder(clean)
            else:
                # no audit record, no forward
                self._record("planner_llm.forwarding", rec, required=True)
                headers = {"Content-Type": "application/json"}
                if self._key:
                    headers["Authorization"] = f"Bearer {self._key}"
                transport = self._transport
                if transport is None:
                    from .router import _http_transport
                    transport = _http_transport
                try:
                    data = transport(self.upstream_url, headers, payload)
                    if len(data) > MAX_RESPONSE_BYTES:
                        raise ValueError("upstream response too large")
                    resp = json.loads(data)
                except Exception as e:  # noqa: BLE001 - sent (maybe): the reserve stays charged
                    with self._lock:
                        rec.decision, rec.reason = "failed", f"upstream_error:{type(e).__name__}"[:60]
                    self._record("planner_llm.upstream_error", rec)
                    return 502, {"error": {"message": "upstream error"}}
            usage = resp.get("usage") if isinstance(resp, dict) else None
            with self._lock:
                if isinstance(usage, dict) and isinstance(usage.get("completion_tokens"), int):
                    completion = max(0, min(int(usage["completion_tokens"]), clean["max_tokens"]))
                    prompt_real = max(0, int(usage.get("prompt_tokens") or 0))
                    actual_tokens = max(prompt_real, prompt_tokens) + completion
                    actual_cost = self.budget.estimate(max(prompt_real, prompt_tokens), completion)
                    # settle: never below zero, never more than the reserve released
                    self._tokens_used += actual_tokens - rec.charged_tokens
                    self._cost_used += actual_cost - rec.est_cost_usd
                    rec.completion_tokens, rec.charged_tokens, rec.est_cost_usd = completion, actual_tokens, actual_cost
                # no usage figures: the reserved worst case stays charged
            self._record("planner_llm.call", rec)
            return 200, resp
        except GatewayRefused as e:
            r = CallRecord(len(self.calls) + 1, "refused", e.code, hashlib.sha256(raw).hexdigest(), len(raw), 0)
            with self._lock:
                self.calls.append(r)
            self._record("planner_llm.refused", r)
            return 403, {"error": {"message": f"refused by the Vulnix planner gateway: {e}"}}

    def _record(self, event: str, rec: CallRecord, required: bool = False) -> None:
        if self._audit is None:
            if required:
                raise GatewayRefused("no_audit", "no audit log: nothing is forwarded")
            return
        try:
            self._audit.record(event, mode=self.mode, index=rec.index, decision=rec.decision,
                               reason=rec.reason, request_sha256=rec.request_sha256,
                               request_bytes=rec.request_bytes, est_prompt_tokens=rec.est_prompt_tokens,
                               completion_tokens=rec.completion_tokens, charged_tokens=rec.charged_tokens,
                               est_cost_usd=rec.est_cost_usd)
        except Exception:  # noqa: BLE001
            if required:
                raise GatewayRefused("no_audit", "the audit record could not be written") from None

    # ---- report ------------------------------------------------------------------
    def report(self) -> dict:
        with self._lock:
            passed = [c for c in self.calls if c.decision in ("forwarded", "previewed", "failed")]
            return {
                "mode": self.mode, "model": self.model,
                "upstream": (urllib.parse.urlsplit(self.upstream_url).hostname if self.mode == "forward" else None),
                "calls": len(passed), "refused": len(self.calls) - len(passed),
                "failed": sum(1 for c in self.calls if c.decision == "failed"),
                "est_tokens": self._tokens_used, "est_cost_usd": round(self._cost_used, 6),
                "budget": {"max_calls": self.budget.max_calls, "max_total_tokens": self.budget.max_total_tokens,
                           "max_cost_usd": self.budget.max_cost_usd,
                           "usd_per_1k_input": self.budget.usd_per_1k_input,
                           "usd_per_1k_output": self.budget.usd_per_1k_output},
                "first_request_sha256": passed[0].request_sha256 if passed else None,
                "records": [c.__dict__ for c in self.calls],
            }

    # ---- server ------------------------------------------------------------------
    def close(self) -> None:
        """No further request is forwarded (emergency stop, end of the run)."""
        with self._lock:
            self._closed = True

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

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = False             # server_close waits for in-flight calls
            block_on_close = True

        self._server = Server(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()          # joins handler threads
            self._server = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}/v1"
