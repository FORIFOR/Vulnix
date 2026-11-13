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

# Unmistakable key formats: checked in EVERY message (also the model's own turns).
STRONG_SECRET_PATTERNS = [re.compile(p) for p in (
    r"sk-[A-Za-z0-9_\-]{16,}", r"ghp_[A-Za-z0-9]{20,}", r"github_pat_[A-Za-z0-9_]{20,}",
    r"AKIA[0-9A-Z]{16}", r"xox[abprs]-[A-Za-z0-9-]{10,}", r"AIza[0-9A-Za-z_\-]{30,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
)]
# Generic "credential-looking" text: checked in what ARTEX / Vulnix contribute (system,
# user, tool messages); the model's own earlier turns came from the upstream itself.
GENERIC_SECRET_PATTERNS = [re.compile(p) for p in (
    r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}",
    r"(?i)(password|passwd|secret|api[_-]?key|access[_-]?key|token)[\"']?\s*[:=]\s*[\"']?[^\s\"',}]{8,}",
)]
SECRET_PATTERNS = STRONG_SECRET_PATTERNS + GENERIC_SECRET_PATTERNS
SECRET_KEY_NAMES = re.compile(r"(?i)^(password|passwd|secret|api[_-]?key|access[_-]?key|token|auth|authorization)$")

# Host-like tokens: URLs of any scheme (userinfo allowed), bracketed IPv6, bare IPv4
# (also short / octal / hex forms), and names under internal-only suffixes.
_URLISH = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://(?:[^\s/@'\"<>]*@)?(\[[0-9a-f:.%]+\]|[^\s/:'\"<>?#]+)")
# bare IPv4 in text: the full dotted-quad only (short / octal / hex forms are checked
# where they act as hosts - inside URLs - so "2.0" or "10.5" in prose is not an address)
_BARE_IP = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
_BRACKET_V6 = re.compile(r"\[([0-9a-f]*:[0-9a-f:.]*)\]", re.I)        # needs a colon: [1] is not an address
_BARE_V6 = re.compile(r"(?<![\w:.])([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})(?![\w:])", re.I)
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
    found |= {m.group(1) for m in _BARE_V6.finditer(text)
              if re.search(r"[0-9a-f]", m.group(1), re.I) and _ip(m.group(1)) is not None}   # not a bare "::"
    found |= {m.group(0) for m in _INTERNAL_NAME.finditer(text)}
    return {h.lower().rstrip(".").strip("[]") for h in found if h}


_MSG_FIELDS = ("role", "content", "tool_calls", "tool_call_id", "name")


def _clean_message(m) -> dict:
    """A message reduced to the chat fields; tool calls to id / type / function{name,
    arguments}. Nothing else ARTEX might attach is forwarded."""
    if not isinstance(m, dict):
        raise GatewayRefused("bad_message", "a message is not an object")
    out = {k: m[k] for k in _MSG_FIELDS if k in m and k != "tool_calls"}
    if not isinstance(out.get("role"), str):
        raise GatewayRefused("bad_message", "a message without a role")
    calls = []
    for tc in m.get("tool_calls") or []:
        fn = tc.get("function") if isinstance(tc, dict) else None
        if not isinstance(fn, dict):
            raise GatewayRefused("bad_message", "a malformed tool call")
        calls.append({"id": str(tc.get("id", ""))[:64], "type": "function",
                      "function": {"name": str(fn.get("name", ""))[:80], "arguments": fn.get("arguments", "")}})
    if calls:
        out["tool_calls"] = calls
    return out


MAX_ERROR_SUMMARY = 200


def _error_details(e: BaseException) -> tuple[int | None, bytes]:
    """HTTP status and (at most 4 KiB of) the upstream's error body, if any."""
    code = getattr(e, "code", None)
    body = b""
    reader = getattr(e, "read", None)
    if callable(reader):
        try:
            body = reader(4096) or b""
        except Exception:  # noqa: BLE001
            body = b""
    return (code if isinstance(code, int) else None), body


def _compat_messages(messages: list) -> list:
    """The conversation in the shape of the official Chat Completions tool-calling
    format, without changing any tool's meaning: an assistant turn that carries
    tool_calls has null (not empty) content; a tool result's content is a string;
    and every tool call is answered by exactly one tool message, in order, before
    the next non-tool message - a request that breaks this is not sent at all."""
    out, pending = [], []
    for m in messages:
        m = dict(m)
        role = m.get("role")
        if role == "assistant" and m.get("tool_calls"):
            if pending:
                raise GatewayRefused("bad_sequence", "a tool call was not answered before the next turn")
            if m.get("content") == "":
                m["content"] = None
            pending = [tc["id"] for tc in m["tool_calls"]]
            if len(set(pending)) != len(pending) or not all(pending):
                raise GatewayRefused("bad_sequence", "tool calls without unique ids")
        elif role == "tool":
            if m.get("tool_call_id") not in pending:
                raise GatewayRefused("bad_sequence", "a tool result that answers no open tool call")
            pending.remove(m["tool_call_id"])
            c = m.get("content")
            if not isinstance(c, str):
                m["content"] = json.dumps(c, ensure_ascii=False) if c is not None else ""
        else:
            if pending:
                raise GatewayRefused("bad_sequence", "a tool call was not answered before the next turn")
            if role not in ("system", "user", "assistant", "developer"):
                raise GatewayRefused("bad_message", "an unknown message role")
        out.append(m)
    if pending:
        raise GatewayRefused("bad_sequence", "a tool call was not answered")
    return out


def _turn_digest(msg: dict) -> str:
    """A model turn, independent of formatting ARTEX may apply when resending it."""
    content = msg.get("content")
    text = _norm(content).strip() if isinstance(content, str) else ""
    calls = []
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function") if isinstance(tc, dict) else None
        if not isinstance(fn, dict):
            continue
        args = fn.get("arguments")
        try:
            args = json.dumps(json.loads(args), sort_keys=True, ensure_ascii=False) if isinstance(args, str) else ""
        except ValueError:
            args = _norm(args).strip()
        calls.append([str(fn.get("name")), args])
    return hashlib.sha256(json.dumps([text, calls], ensure_ascii=False).encode()).hexdigest()


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
        self._closed = threading.Event()      # lock-free: close() never waits for a request
        # one upstream failure ends the run: nothing more is sent, whatever retries
        self._failed = threading.Event()
        self.failure: dict | None = None
        self._send_lock = threading.Lock()   # one upstream request in flight per run
        # turns the model itself returned in this run: only these, resent, count as the
        # model's own (ARTEX writes the request - a role label alone proves nothing)
        self._model_turns: dict[str, dict] = {}       # digest -> the turn as the model returned it
        self._tools_sha: str | None = None            # tool schemas fixed by the first passed request
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
        out = {"model": self.model, "messages": [_clean_message(m) for m in body["messages"]]}
        for k in ("temperature", "top_p"):
            if isinstance(body.get(k), (int, float)):
                out[k] = body[k]
        tools = self._tools(body.get("tools"))
        if tools:
            out["tools"] = tools
            # the schemas are fixed for the run by the first request that passed (the one
            # an approval's fingerprint covers): they cannot change on later calls
            tools_sha = hashlib.sha256(json.dumps(tools, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            with self._lock:
                if self._tools_sha is not None and tools_sha != self._tools_sha:
                    raise GatewayRefused("tools_changed", "the tool schemas changed during the run")
        tc = body.get("tool_choice") if tools else None      # without tools the API rejects it
        if tc in ("auto", "none", "required"):
            out["tool_choice"] = tc
        elif isinstance(tc, dict) and (tc.get("function") or {}).get("name") in PLANNER_TOOL_ALLOWLIST:
            out["tool_choice"] = {"type": "function", "function": {"name": tc["function"]["name"]}}
        mt = body.get("max_tokens")
        out["max_tokens"] = mt if isinstance(mt, int) and 0 < mt <= MAX_COMPLETION_TOKENS else MAX_COMPLETION_TOKENS

        # everything: strong checks; what ARTEX / Vulnix contribute (not the model's own
        # earlier turns): also the generic credential and internal-host checks
        own, own_keyed = [], []
        with self._lock:
            model_turns = dict(self._model_turns)
        rebuilt, theirs = [], []
        for m in out["messages"]:
            d = _turn_digest(m) if m.get("role") == "assistant" else None
            if d in model_turns:
                # a resent model turn: what is forwarded is the gateway's own copy of
                # what the model returned - nothing ARTEX attached rides along
                rebuilt.append(json.loads(json.dumps(model_turns[d])))
            else:
                rebuilt.append(m)
                theirs.append(m)
        out["messages"] = _compat_messages(rebuilt)
        strings, keyed = [], []
        _strings(out["messages"], strings, keyed)
        _strings(theirs, own, own_keyed)
        # ARTEX writes the tool schemas too (descriptions, parameters, defaults, enums):
        # every string in them gets the full checks
        _strings(out.get("tools") or [], strings, keyed)
        _strings(out.get("tools") or [], own, own_keyed)
        normed = [_norm(s) for s in strings]
        own_normed = [_norm(s) for s in own]
        whole = "\n".join(normed)
        whole_joined = "".join(normed)                    # a secret split across strings
        own_whole = "\n".join(own_normed)
        for text in (*normed, whole, whole_joined):
            for form in self._key_forms:
                if form in text:
                    raise GatewayRefused("contains_key", "the request contains the API key")
            for pat in STRONG_SECRET_PATTERNS:
                if pat.search(text):
                    raise GatewayRefused("contains_secret", "the request contains something that looks like a secret")
        for text in (*own_normed, own_whole, "".join(own_normed)):
            for pat in GENERIC_SECRET_PATTERNS:
                if pat.search(text):
                    raise GatewayRefused("contains_secret", "the request contains something that looks like a secret")
        for k, v in own_keyed:
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
        for host in host_candidates(own_whole):
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
            tools_sha = hashlib.sha256(json.dumps(clean.get("tools") or [], sort_keys=True,
                                                  ensure_ascii=False).encode()).hexdigest()
            # asked OUTSIDE the gateway lock (it takes the service lock; an emergency stop
            # holds the service lock and closes gateways - opposite order would deadlock)
            if self._failed.is_set():
                raise GatewayRefused("run_failed", "the run failed upstream: nothing more is sent")
            if self._closed.is_set():
                raise GatewayRefused("closed", "the planner run is over")
            if self.mode == "forward" and self._may_forward is not None and not self._may_forward():
                raise GatewayRefused("stopped", "the planner run was stopped")
            with self._lock:
                if self._failed.is_set():
                    raise GatewayRefused("run_failed", "the run failed upstream: nothing more is sent")
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
            if self.mode == "preview":
                self.preview_requests.append(clean)
                resp = self._responder(clean)
                with self._lock:
                    self._first_passed = True
                    if self._tools_sha is None and clean.get("tools"):
                        self._tools_sha = tools_sha
            else:
                try:
                    self._record("planner_llm.forwarding", rec, required=True)      # no record, no send
                except GatewayRefused:
                    self._release(rec, "no_audit")
                    raise
                with self._send_lock:                    # one request in flight: a racer waits here
                    outcome = self._send(rec, clean, payload, tools_sha)
                if outcome[0] != 200:
                    return outcome
                resp = outcome[1]
            self._settle(rec, clean, resp, prompt_tokens)
            self._record("planner_llm.call", rec)
            return 200, resp
        except GatewayRefused as e:
            if rec is not None and rec.decision == "refused":
                self._record("planner_llm.refused", rec)
            else:
                r = CallRecord(len(self.calls) + 1, "refused", e.code, hashlib.sha256(raw).hexdigest(), len(raw), 0)
                with self._lock:
                    self.calls.append(r)
                self._record("planner_llm.refused", r)
            return 403, {"error": {"message": f"refused by the Vulnix planner gateway: {e}"}}

    def _send(self, rec: CallRecord, clean: dict, payload: bytes, tools_sha: str) -> tuple[int, dict]:
        """Under the send lock: the last checks, then the ONE upstream request."""
        # a failure or stop that landed while this request waited: it is not sent
        if self._failed.is_set():
            self._release(rec, "run_failed")
            raise GatewayRefused("run_failed", "the run failed upstream: nothing more is sent")
        if self._closed.is_set() or (self._may_forward is not None and not self._may_forward()):
            self._release(rec, "stopped")
            raise GatewayRefused("stopped", "the planner run was stopped")
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
            status, raw = _error_details(e)
            self._failed.set()                           # the run is over: no retry reaches upstream
            digest = hashlib.sha256(raw).hexdigest()
            with self._lock:
                rec.decision = "failed"
                rec.reason = f"upstream_http_{status}" if status else f"upstream_{type(e).__name__}"[:60]
                self.failure = {"index": rec.index, "http_status": status, "error_type": type(e).__name__,
                                "error_bytes": len(raw), "error_sha256": digest,
                                "error_summary": self._sanitize_error(raw)}
            # the audit gets the status, size and hash - never the error body
            self._record("planner_llm.upstream_error", rec,
                         extra={"http_status": status, "error_bytes": len(raw), "error_sha256": digest})
            # 409: a final answer for this run (not "try again")
            return 409, {"error": {"message": f"upstream refused the request (HTTP {status}); "
                                              "the run is over and nothing more is sent"}}
        with self._lock:
            self._first_passed = True
            if self._tools_sha is None and clean.get("tools"):
                self._tools_sha = tools_sha
        return 200, resp

    def _settle(self, rec: CallRecord, clean: dict, resp, prompt_tokens: int) -> None:
        usage = resp.get("usage") if isinstance(resp, dict) else None
        with self._lock:
            for ch in (resp.get("choices") or []) if isinstance(resp, dict) else []:
                msg = ch.get("message") if isinstance(ch, dict) else None
                if isinstance(msg, dict):
                    try:
                        turn = _clean_message({**msg, "role": "assistant"})
                    except GatewayRefused:
                        continue
                    self._model_turns[_turn_digest(turn)] = turn
            if isinstance(usage, dict) and isinstance(usage.get("completion_tokens"), int):
                completion = max(0, min(int(usage["completion_tokens"]), clean["max_tokens"]))
                pt = usage.get("prompt_tokens")
                prompt_real = max(0, pt) if isinstance(pt, int) else 0
                actual_tokens = max(prompt_real, prompt_tokens) + completion
                actual_cost = self.budget.estimate(max(prompt_real, prompt_tokens), completion)
                # settle against actual usage (never below zero)
                self._tokens_used += actual_tokens - rec.charged_tokens
                self._cost_used += actual_cost - rec.est_cost_usd
                rec.completion_tokens, rec.charged_tokens, rec.est_cost_usd = completion, actual_tokens, actual_cost
            # no usage figures: the reserved worst case stays charged

    def _release(self, rec: CallRecord, code: str) -> None:
        """A reserved call that was not sent after all: refused, reserve released."""
        with self._lock:
            self._tokens_used -= rec.charged_tokens
            self._cost_used -= rec.est_cost_usd
            rec.decision, rec.reason, rec.charged_tokens, rec.est_cost_usd = "refused", code, 0, 0.0

    def _sanitize_error(self, raw: bytes) -> str:
        """A short, secret-free summary of an upstream error body, for the operator."""
        text = _norm(raw.decode("utf-8", "replace"))
        for form in self._key_forms:
            text = text.replace(form, "[redacted]")
        for pat in SECRET_PATTERNS:
            text = pat.sub("[redacted]", text)
        text = " ".join(text.split())
        return text[:MAX_ERROR_SUMMARY]

    def _record(self, event: str, rec: CallRecord, required: bool = False, extra: dict | None = None) -> None:
        if self._audit is None:
            if required:
                raise GatewayRefused("no_audit", "no audit log: nothing is forwarded")
            return
        try:
            self._audit.record(event, mode=self.mode, index=rec.index, decision=rec.decision,
                               reason=rec.reason, request_sha256=rec.request_sha256,
                               request_bytes=rec.request_bytes, est_prompt_tokens=rec.est_prompt_tokens,
                               completion_tokens=rec.completion_tokens, charged_tokens=rec.charged_tokens,
                               est_cost_usd=rec.est_cost_usd, **(extra or {}))
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
                "failed_upstream": dict(self.failure) if self.failure else None,
                "records": [c.__dict__ for c in self.calls],
            }

    # ---- server ------------------------------------------------------------------
    def close(self) -> None:
        """No further request is forwarded (emergency stop, end of the run). Lock-free."""
        self._closed.set()

    def __enter__(self) -> "PlannerLLMGateway":
        gw = self

        class Handler(http.server.BaseHTTPRequestHandler):
            timeout = 10                       # an idle or slow client cannot hold shutdown

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
        self.close()                             # nothing more is forwarded, whatever follows
        if self._server is not None:
            srv, self._server = self._server, None
            srv.shutdown()
            # joins in-flight handlers, bounded: a client trickling bytes cannot hold the
            # planner run (forwarding is already closed)
            t = threading.Thread(target=srv.server_close, daemon=True)
            t.start()
            t.join(45)                           # longer than the transport's own timeout

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}/v1"
