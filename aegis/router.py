"""P1: proposal intake / LLM router (Abliteration AI adapter + ARTEX engine).

The platform's first principle: the model (ARTEX, an abliterated inference model,
any LLM) PROPOSES; only the Gateway DISPOSES. This router is the seam where model
backends plug in. It deliberately:
  * holds NO token authority, no approvals, no scope — it cannot self-authorize;
  * sanitizes every proposal down to the strict schema, so authority-shaped keys
    a backend might emit ("approved", "token", "scope") are dropped before the
    Gateway ever sees them;
  * carries rationale text as inert data (a backend's words never become actions);
  * records provenance (which backend proposed what) to the audit log;
  * supports both direct JSON {"proposals": [...]} AND OpenAI-compatible
    Chat Completions API (`messages` -> `choices[0].message.content`) used by
    Abliteration AI / vLLM / Ollama / OpenAI endpoints.
"""
from __future__ import annotations

import json
import math
import os
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from functools import partial
from typing import Callable, Protocol, runtime_checkable

from .policy import PROPOSAL_KEYS

MAX_RATIONALE = 500
DEFAULT_MODEL_TIMEOUT_SECONDS = 30.0
MAX_MODEL_TIMEOUT_SECONDS = 120.0


def _model_timeout(value: object) -> float:
    """Bound inference waits; malformed configuration retains the normal default."""
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return DEFAULT_MODEL_TIMEOUT_SECONDS
    if not math.isfinite(seconds) or not 1 <= seconds <= MAX_MODEL_TIMEOUT_SECONDS:
        return DEFAULT_MODEL_TIMEOUT_SECONDS
    return seconds

# transport(url, headers, body) -> response bytes. Injectable for offline tests.
Transport = Callable[[str, dict, bytes], bytes]

SYSTEM_PROPOSAL_PROMPT = (
    "You are the Vulnix / Abliteration AI diagnostic planner. "
    "Emit ONLY a JSON object of shape "
    '{"proposals": [{"tool": "<tool>", "target_id": "<id>", "action": "<action>", '
    '"args": {"url": "..."}, "rationale": "<why>"}]}. '
    "Never include execution tokens or approval flags; the Gateway enforces all permissions."
)

_CODE_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def _extract_json_from_text(text: str) -> object | None:
    """Parse JSON from a raw string or markdown code fence emitted by an LLM."""
    s = text.strip()
    m = _CODE_FENCE_RE.search(s)
    if m:
        s = m.group(1).strip()
    try:
        return json.loads(s)
    except Exception:
        # Try extracting the outermost {...} or [...]
        for open_ch, close_ch in (("{", "}"), ("[", "]")):
            i, j = s.find(open_ch), s.rfind(close_ch)
            if 0 <= i < j:
                try:
                    return json.loads(s[i : j + 1])
                except Exception:
                    pass
    return None


def extract_proposals_from_payload(data: object) -> list[dict]:
    """Normalize either direct {"proposals": [...]} or OpenAI Chat Completions
    {"choices": [{"message": {"content": "..."}}]} into a list of proposal dicts."""
    if not isinstance(data, dict):
        return []
    # 1. Direct {"proposals": [...]} format
    if isinstance(data.get("proposals"), list):
        return [p for p in data["proposals"] if isinstance(p, dict)]
    # 2. OpenAI-compatible Chat Completions format (choices[0].message.content)
    choices = data.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0] if isinstance(choices[0], dict) else {}
        msg = first.get("message") if isinstance(first.get("message"), dict) else {}
        content = msg.get("content")
        if isinstance(content, str):
            parsed = _extract_json_from_text(content)
            if isinstance(parsed, dict):
                if isinstance(parsed.get("proposals"), list):
                    return [p for p in parsed["proposals"] if isinstance(p, dict)]
                if "tool" in parsed and "action" in parsed:
                    return [parsed]
            elif isinstance(parsed, list):
                return [p for p in parsed if isinstance(p, dict)]
    return []


@runtime_checkable
class ModelBackend(Protocol):
    name: str

    def propose(self, context: dict) -> list[dict]: ...


@dataclass
class StubBackend:
    """A 'connected' backend that returns fixed, non-destructive proposals.
    Stands in for a real model; emits proposals but holds no authority."""
    name: str
    proposals: list[dict] = field(default_factory=list)

    def propose(self, context: dict) -> list[dict]:
        return [dict(p) for p in self.proposals]      # copies: callers can't mutate ours


MAX_MODEL_RESPONSE_BYTES = 1_000_000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None      # a redirect would carry the Authorization header to another origin


def _require_safe_model_url(url: str) -> None:
    """The request carries the API key: https only, except a loopback endpoint."""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme == "https":
        return
    if parts.scheme == "http" and host in ("127.0.0.1", "localhost", "::1"):
        return
    raise ValueError("model endpoint must be https (http is accepted for loopback only)")


def _open_model_url(req, *, timeout):
    """The API key never follows a redirect."""
    return urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout)


def _http_transport(url: str, headers: dict, body: bytes, *,
                    timeout_s: float = DEFAULT_MODEL_TIMEOUT_SECONDS) -> bytes:
    _require_safe_model_url(url)
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with _open_model_url(req, timeout=timeout_s) as r:      # pragma: no cover - needs network
        data = r.read(MAX_MODEL_RESPONSE_BYTES + 1)
    if len(data) > MAX_MODEL_RESPONSE_BYTES:
        raise ValueError("model response too large")
    return data


class HttpModelBackend:
    """HTTP inference adapter supporting both direct proposal JSON and
    OpenAI-compatible Chat Completions responses."""

    def __init__(self, name: str, url: str, *, api_key: str | None = None,
                 model: str = "", api_format: str = "auto",
                 timeout_s: float = DEFAULT_MODEL_TIMEOUT_SECONDS,
                 transport: Transport | None = None):
        self.name = name
        self._url = url
        self._key = api_key
        self._model = model
        self._format = api_format   # "auto" | "openai" | "native"
        self._timeout_s = _model_timeout(timeout_s)
        self._transport = transport or partial(_http_transport, timeout_s=self._timeout_s)

    @classmethod
    def from_env(cls, name: str = "model", prefix: str = "AEGIS_MODEL",
                 transport: Transport | None = None) -> "HttpModelBackend | None":
        """Build from env (VULNIX_MODEL_* or AEGIS_MODEL_*). Returns None when no
        endpoint is configured."""
        prefixes = [prefix, "VULNIX_MODEL"]
        if prefix == "AEGIS_MODEL":
            prefixes.insert(0, "VULNIX_ABLITERATION")
        source = next((p for p in prefixes if os.environ.get(f"{p}_URL")), None)
        if source is None:
            return None
        url = os.environ[f"{source}_URL"]
        # Credentials must come from the selected endpoint's namespace. A stale
        # key belonging to a different URL must never be sent to this endpoint.
        key = os.environ.get(f"{source}_KEY")
        model = os.environ.get(f"{source}_MODEL", "")
        fmt = os.environ.get(f"{source}_FORMAT", "auto")
        timeout = _model_timeout(os.environ.get(f"{source}_TIMEOUT_SECONDS"))
        return cls(name, url, api_key=key, model=model, api_format=fmt,
                   timeout_s=timeout, transport=transport)

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._key:
            h["Authorization"] = f"Bearer {self._key}"
        return h

    def _is_openai_endpoint(self) -> bool:
        if self._format == "openai":
            return True
        if self._format == "native":
            return False
        return "/chat/completions" in self._url

    def propose(self, context: dict) -> list[dict]:
        if self._is_openai_endpoint():
            payload = {
                "model": self._model or "abliteration-sec-1",
                "messages": [
                    {"role": "system", "content": SYSTEM_PROPOSAL_PROMPT},
                    {"role": "user", "content": json.dumps(context, ensure_ascii=False)},
                ],
                "temperature": 0.1,
            }
        else:
            payload = {"model": self._model, "context": context}
        body = json.dumps(payload, ensure_ascii=False).encode()
        try:
            raw = self._transport(self._url, self._headers(), body)
            data = json.loads(raw)
        except Exception:
            return []
        return extract_proposals_from_payload(data)


def _error_kind(e: BaseException) -> str:
    """A failure as a short, secret-free label: the exception class, plus the HTTP
    status when there is one. Never the message, URL, headers or response body,
    which may carry the API key or text the model returned."""
    code = getattr(e, "code", None)
    kind = type(e).__name__[:40]
    return f"{kind} {code}" if isinstance(code, int) else kind


class AbliterationBackend(HttpModelBackend):
    """Dedicated adapter for Abliteration AI / OpenAI-compatible Chat Completions API.

    Always formats requests as OpenAI `messages` and extracts proposals from
    `choices[0].message.content` (including fenced JSON blocks), while also
    supporting context-grounded Q&A via `chat()`. Holds zero execution authority."""

    def __init__(self, name_or_url: str, url: str | None = None, *,
                 api_key: str | None = None, model: str = "abliteration-sec-1",
                 name: str = "abliteration", transport: Transport | None = None,
                 timeout_s: float = DEFAULT_MODEL_TIMEOUT_SECONDS):
        if url is None:
            actual_url = name_or_url
            actual_name = name
        else:
            actual_name = name_or_url
            actual_url = url
        super().__init__(actual_name, actual_url, api_key=api_key, model=model,
                         api_format="openai", transport=transport, timeout_s=timeout_s)

    @classmethod
    def from_env(cls, name: str = "model", prefix: str = "AEGIS_MODEL",
                 transport: Transport | None = None) -> "AbliterationBackend | None":
        configured = HttpModelBackend.from_env(name, prefix, transport)
        if configured is None:
            return None
        # The dedicated adapter always uses OpenAI chat messages and does not
        # accept HttpModelBackend's api_format constructor argument.
        return cls(configured.name, configured._url, api_key=configured._key,
                   model=configured._model or "abliteration-sec-1",
                   transport=configured._transport, timeout_s=configured._timeout_s)

    def chat(self, question: str, context: dict) -> str | None:
        """Ask the OpenAI-compatible endpoint a natural-language question grounded
        in the assessment context. Output is plain text only (never executed)."""
        return self.chat_with_status(question, context)[0]

    def chat_with_status(self, question: str, context: dict) -> tuple[str | None, str | None]:
        """`chat()` plus this call's own failure kind (None when it answered). Returned,
        not stored on the shared instance, so concurrent questions cannot mix them up."""
        from .chat_guard import CHAT_SYSTEM_PROMPT   # local: chat_guard -> ai_advisor -> router
        payload = {
            "model": self._model or "abliteration-sec-1",
            "messages": [
                {
                    "role": "system",
                    "content": CHAT_SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": json.dumps({"question": question, "context": context}, ensure_ascii=False),
                },
            ],
            "temperature": 0.2,
        }
        try:
            raw = self._transport(self._url, self._headers(), json.dumps(payload, ensure_ascii=False).encode())
            data = json.loads(raw)
            choices = data.get("choices") if isinstance(data, dict) else None
            if isinstance(choices, list) and choices:
                content = choices[0].get("message", {}).get("content")
                if isinstance(content, str) and content.strip():
                    return content.strip(), None
        except Exception as e:   # noqa: BLE001 - any failure falls back to the built-in answer
            return None, _error_kind(e)
        return None, "empty_response"


@dataclass(frozen=True)
class RoutedProposal:
    backend: str
    proposal: dict          # sanitized; safe to hand to the Gateway
    rationale: str          # the backend's words, kept as inert data


def sanitize_proposal(raw: object) -> dict:
    """Reduce arbitrary backend output to the strict proposal schema. Unknown and
    authority-shaped keys (approved/token/scope/...) are dropped here, before the
    Gateway ever sees them. Raises ValueError on something that can't be a
    proposal at all."""
    if not isinstance(raw, dict):
        raise ValueError("proposal must be an object")
    out: dict = {}
    for k in ("tool", "target_id", "action"):
        v = raw.get(k)
        if not isinstance(v, str) or not v:
            raise ValueError(f"proposal.{k} must be a non-empty string")
        out[k] = v
    args = raw.get("args", {})
    if not isinstance(args, dict):
        raise ValueError("proposal.args must be an object")
    out["args"] = dict(args)
    out["rationale"] = str(raw.get("rationale", ""))[:MAX_RATIONALE]
    assert set(out) <= PROPOSAL_KEYS       # we only ever emit the strict schema
    return out


class ProposalRouter:
    """Collects untrusted proposals from backends and forwards them to the Gateway.
    It never holds the means to authorize execution."""

    def __init__(self, gateway, audit, backends: list[ModelBackend] | None = None):
        self.gateway = gateway
        self.audit = audit
        self._backends: dict[str, ModelBackend] = {}
        for b in backends or []:
            self.register(b)
        # Structural guarantee, checked at construction: no authority lives here.
        assert not hasattr(self, "tokens") and not hasattr(self, "approvals")

    def register(self, backend: ModelBackend) -> None:
        self._backends[backend.name] = backend

    @property
    def backends(self) -> list[str]:
        return list(self._backends)

    def collect(self, context: dict | None = None) -> list[RoutedProposal]:
        """Ask each backend for proposals; sanitize and record provenance."""
        context = context or {}
        routed: list[RoutedProposal] = []
        for name, backend in self._backends.items():
            for raw in backend.propose(context):
                try:
                    clean = sanitize_proposal(raw)
                except ValueError as e:
                    self.audit.record("proposal.rejected", backend=name, reason=str(e))
                    continue
                routed.append(RoutedProposal(name, clean, clean["rationale"]))
                self.audit.record("proposal.received", backend=name, tool=clean["tool"],
                                  target=clean["target_id"], action=clean["action"])
        return routed

    def submit(self, routed: RoutedProposal, token: str):
        """Hand a sanitized proposal to the Gateway. The token comes from the
        human-approved control plane — never from the router or a backend. The
        Gateway alone decides whether it runs."""
        return self.gateway.execute(routed.proposal, token)


@dataclass
class ArtexTask:
    id: str
    phase: str
    title: str
    risk_level: str          # L1 | L2 | L3
    routed: RoutedProposal
    status: str = "queued"   # queued | awaiting_approval | running | completed | skipped | denied


class ArtexplannerBackend:
    """Built-in deterministic ARTEX task planner that proposes phased diagnostic
    and reproduction actions based on current observations. Like any LLM backend,
    it is untrusted and routed through ProposalRouter."""

    name = "artex-planner"

    def propose(self, context: dict) -> list[dict]:
        phase = context.get("phase", "config")
        target_id = context.get("target_id", "lab")
        target_url = context.get("target_url", "http://lab.test/")
        if phase == "config":
            return [{
                "tool": "http_probe",
                "target_id": target_id,
                "action": "read_only_probe",
                "args": {"url": target_url, "method": "GET"},
                "rationale": "ARTEX Step 1: 公開HTTPヘッダーとバナー情報を非破壊GETで収集",
            }]
        if phase == "verification":
            proposals = [
                {
                    "tool": "reproduction_probe",
                    "target_id": target_id,
                    "action": "safe_reproduction",
                    "args": {"url": target_url, "check": "idor"},
                    "rationale": "ARTEX Step 2: テストアカウント acct_A から acct_B リソースへの認可境界（IDOR）を実証検証",
                },
            ]
            if context.get("has_cve_2021_41773"):
                proposals.append({
                    "tool": "reproduction_probe",
                    "target_id": target_id,
                    "action": "safe_reproduction",
                    "args": {"url": target_url, "check": "cve_2021_41773"},
                    "rationale": "ARTEX Step 3: 検出された CVE-2021-41773 パス正規化不備が隔離ラボマーカーで成立するか実証検証",
                })
            return proposals
        return []


class ArtexSubprocessBackend:
    """External ARTEX CLI / OSS process adapter (`python3 -m aegis.artex_cli` or custom binary).

    Executes the external ARTEX planner in an isolated subprocess, feeds the
    diagnostic context via stdin JSON, and extracts untrusted proposals for
    `ProposalRouter` sanitization. Holds zero execution tokens or authority."""

    def __init__(self, command: list[str] | None = None, *, name: str = "artex-cli",
                 timeout_s: float = 10.0):
        import shlex
        import sys
        self.name = name
        env_cmd = os.environ.get("VULNIX_ARTEX_CLI") or os.environ.get("AEGIS_ARTEX_CMD")
        if command is not None:
            self.command = list(command)
        elif env_cmd:
            self.command = shlex.split(env_cmd)
        else:
            self.command = [sys.executable, "-m", "aegis.artex_cli"]
        self.timeout_s = timeout_s
        self.last_engine_version: str | None = None
        assert not hasattr(self, "tokens") and not hasattr(self, "approvals")

    def version_info(self) -> dict:
        import subprocess
        try:
            proc = subprocess.run(
                [*self.command, "--version"],
                capture_output=True, text=True, timeout=self.timeout_s,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                info = json.loads(proc.stdout.strip())
                if isinstance(info, dict):
                    self.last_engine_version = str(info.get("version", ""))
                    return info
        except Exception:
            pass
        return {}

    def propose(self, context: dict) -> list[dict]:
        import subprocess
        try:
            proc = subprocess.run(
                self.command,
                input=json.dumps(context, ensure_ascii=False),
                capture_output=True, text=True, timeout=self.timeout_s,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                return []
            data = json.loads(proc.stdout.strip())
            if isinstance(data, dict) and data.get("engine_version"):
                self.last_engine_version = str(data["engine_version"])
            return extract_proposals_from_payload(data)
        except Exception:
            return []


class ArtexEngine:
    """ARTEX Execution Engine: coordinates diagnostic task planning, collects
    proposals from ARTEX + Abliteration backends via ProposalRouter, tracks task
    lifecycle, and never bypasses human approvals or Gateway tokens."""

    def __init__(self, router: ProposalRouter):
        self.router = router
        self.tasks: list[ArtexTask] = []
        assert not hasattr(self, "tokens") and not hasattr(self, "approvals")

    def plan_phase(self, phase: str, context: dict, *, router=None, accept=None) -> list[ArtexTask]:
        """`router`: the router to ask for THIS call (the engine's own by default) -
        the caller chooses it per call instead of swapping a shared field.
        `accept`: called after the backends answered; if it returns False the
        proposals are dropped (the caller's workspace is gone)."""
        router = router or self.router
        routed_list = router.collect({**context, "phase": phase})
        if accept is not None and not accept():
            return []
        created: list[ArtexTask] = []
        seen_keys: set[tuple[str, str, str, str]] = set()
        gateway_tools = getattr(router.gateway, "tools", None)
        for r in routed_list:
            p = r.proposal
            dedup_key = (
                p["tool"], p["target_id"], p["action"],
                json.dumps(p.get("args", {}), sort_keys=True),
            )
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            idx = len(created) + 1
            act = p["action"]
            level = "L1" if act == "read_only_probe" else "L2"

            unsupported_reason = None
            if isinstance(gateway_tools, dict):
                tool_spec = gateway_tools.get(p["tool"])
                if tool_spec is None:
                    unsupported_reason = f"未対応ツール: {p['tool']}"
                else:
                    chk = p.get("args", {}).get("check")
                    chk_spec = tool_spec.args.get("check") if hasattr(tool_spec, "args") else None
                    if chk and chk_spec and chk_spec.choices and chk not in chk_spec.choices:
                        unsupported_reason = f"未対応の検証項目: {chk}"

            if unsupported_reason:
                router.audit.record(
                    "proposal.unsupported",
                    backend=r.backend,
                    tool=p["tool"],
                    action=act,
                    reason=unsupported_reason,
                )
                t = ArtexTask(
                    id=f"artex_{phase}_{idx}",
                    phase=phase,
                    title=f"【未対応】{r.rationale or p['tool']}（{unsupported_reason}）",
                    risk_level=level,
                    routed=r,
                    status="unsupported",
                )
            else:
                t = ArtexTask(
                    id=f"artex_{phase}_{idx}",
                    phase=phase,
                    title=r.rationale or f"{p['tool']} ({act})",
                    risk_level=level,
                    routed=r,
                )
            self.tasks.append(t)
            created.append(t)
        return created


def verify_planner_connections(*, abliteration_url: str | None = None,
                               api_key: str | None = None,
                               model: str = "abliteration-sec-1") -> dict:
    """Execute a live end-to-end verification of both:
      1. External ARTEX CLI process (`ArtexSubprocessBackend`)
      2. OpenAI-compatible Abliteration AI API (`AbliterationBackend.propose` + `.chat`)
    over real subprocess pipes and real HTTP sockets, returning a cryptographic proof."""
    import hashlib
    import time
    from .abliteration_server import start_abliteration_server

    t0 = time.monotonic()
    # 1. Verify external ARTEX CLI subprocess execution
    artex_cli = ArtexSubprocessBackend()
    ver = artex_cli.version_info()
    cli_proposals = artex_cli.propose({
        "phase": "verification",
        "target_id": "lab",
        "target_url": "http://lab.test:18081/",
        "has_cve_2021_41773": True,
    })
    sanitized_cli = [sanitize_proposal(p) for p in cli_proposals]
    artex_ok = bool(ver.get("engine") and len(sanitized_cli) >= 2)

    # 2. Verify live OpenAI-compatible Abliteration API round-trip
    temp_srv = None
    target_url = abliteration_url
    endpoint_mode = "external"
    if not target_url:
        env_backend = AbliterationBackend.from_env()
        if env_backend is not None:
            target_url = env_backend._url
            api_key = env_backend._key
            model = env_backend._model or model
        else:
            temp_srv = start_abliteration_server(0)
            target_url = f"http://127.0.0.1:{temp_srv.server_port}/v1/chat/completions"
            endpoint_mode = "local_openai_server"

    try:
        ab = AbliterationBackend(
            "abliteration-ai",
            target_url,
            api_key=api_key,
            model=model,
        )
        ab_proposals = ab.propose({
            "phase": "verification",
            "target_id": "lab",
            "target_url": "http://lab.test:18081/",
        })
        sanitized_ab = [sanitize_proposal(p) for p in ab_proposals]
        chat_reply = ab.chat(
            "IDORの対策を教えてください",
            {"target_finding": {"id": "f_idor", "title": "アクセス制御の不備（IDOR）", "verdict": "proven"}},
        )
        ab_ok = bool(len(sanitized_ab) >= 1 and chat_reply and len(chat_reply) > 10)
    finally:
        if temp_srv is not None:
            temp_srv.shutdown()
            temp_srv.server_close()

    proof_payload = json.dumps({
        "artex_engine": ver,
        "artex_proposals": len(sanitized_cli),
        "abliteration_proposals": len(sanitized_ab),
        "abliteration_chat_sample": (chat_reply or "")[:120],
    }, sort_keys=True, ensure_ascii=False)
    proof_hash = hashlib.sha256(proof_payload.encode("utf-8")).hexdigest()

    return redact_verification_report({
        "verified_at": time.time(),
        "elapsed_ms": round((time.monotonic() - t0) * 1000, 2),
        "all_verified": bool(artex_ok and ab_ok),
        "proof_sha256": proof_hash,
        "artex_cli": {
            "verified": artex_ok,
            "command": artex_cli.command,
            "engine": ver.get("engine", "artex-oss-cli"),
            "version": ver.get("version", artex_cli.last_engine_version),
            "proposals_count": len(sanitized_cli),
        },
        "abliteration_api": {
            "verified": ab_ok,
            "endpoint_mode": endpoint_mode,
            "url": target_url,
            "model": model,
            "proposals_count": len(sanitized_ab),
            "chat_verified": bool(chat_reply),
            "chat_preview": (chat_reply or "")[:120],
        },
    })


def _safe_endpoint(url: object) -> str:
    """scheme://host[:port] only: never userinfo, path, query or fragment, any of which
    may carry an API key or token."""
    try:
        u = urllib.parse.urlsplit(str(url or ""))
        host = u.hostname or ""
        if not u.scheme or not host:
            return ""
        if ":" in host:
            host = f"[{host}]"
        port = f":{u.port}" if u.port else ""
        return f"{u.scheme}://{host}{port}"[:200]
    except ValueError:
        return ""


def redact_verification_report(rep: dict) -> dict:
    """A verification report as it may be stored, returned, shown or published:
    the endpoint without credentials, and none of the model's own text."""
    if not isinstance(rep, dict):
        return {}
    out = dict(rep)
    api = dict(out.get("abliteration_api") or {})
    if api:
        api["url"] = _safe_endpoint(api.get("url"))
        api.pop("chat_preview", None)
        out["abliteration_api"] = api
    return out

