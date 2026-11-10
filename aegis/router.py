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
import os
import re
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable

from .policy import PROPOSAL_KEYS

MAX_RATIONALE = 500

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


def _http_transport(url: str, headers: dict, body: bytes) -> bytes:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:    # pragma: no cover - needs network
        return r.read()


class HttpModelBackend:
    """HTTP inference adapter supporting both direct proposal JSON and
    OpenAI-compatible Chat Completions responses."""

    def __init__(self, name: str, url: str, *, api_key: str | None = None,
                 model: str = "", api_format: str = "auto",
                 transport: Transport | None = None):
        self.name = name
        self._url = url
        self._key = api_key
        self._model = model
        self._format = api_format   # "auto" | "openai" | "native"
        self._transport = transport or _http_transport

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
        return cls(name, url, api_key=key, model=model, api_format=fmt, transport=transport)

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


class AbliterationBackend(HttpModelBackend):
    """Dedicated adapter for Abliteration AI / OpenAI-compatible Chat Completions API.

    Always formats requests as OpenAI `messages` and extracts proposals from
    `choices[0].message.content` (including fenced JSON blocks), while also
    supporting context-grounded Q&A via `chat()`. Holds zero execution authority."""

    def __init__(self, name_or_url: str, url: str | None = None, *,
                 api_key: str | None = None, model: str = "abliteration-sec-1",
                 name: str = "abliteration", transport: Transport | None = None):
        if url is None:
            actual_url = name_or_url
            actual_name = name
        else:
            actual_name = name_or_url
            actual_url = url
        super().__init__(actual_name, actual_url, api_key=api_key, model=model,
                         api_format="openai", transport=transport)

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
                   transport=configured._transport)

    def chat(self, question: str, context: dict) -> str | None:
        """Ask the OpenAI-compatible endpoint a natural-language question grounded
        in the assessment context. Output is plain text only (never executed)."""
        payload = {
            "model": self._model or "abliteration-sec-1",
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "あなたは Vulnix AI セキュリティ診断アシスタントです。"
                        "与えられた診断コンテキストと証拠のみを根拠に、簡潔・正確に日本語で回答してください。"
                    ),
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
                    return content.strip()
        except Exception:
            return None
        return None


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


class ArtexEngine:
    """ARTEX Execution Engine: coordinates diagnostic task planning, collects
    proposals from ARTEX + Abliteration backends via ProposalRouter, tracks task
    lifecycle, and never bypasses human approvals or Gateway tokens."""

    def __init__(self, router: ProposalRouter):
        self.router = router
        self.tasks: list[ArtexTask] = []
        assert not hasattr(self, "tokens") and not hasattr(self, "approvals")

    def plan_phase(self, phase: str, context: dict) -> list[ArtexTask]:
        routed_list = self.router.collect({**context, "phase": phase})
        created: list[ArtexTask] = []
        for idx, r in enumerate(routed_list, start=1):
            act = r.proposal["action"]
            level = "L1" if act == "read_only_probe" else "L2"
            t = ArtexTask(
                id=f"artex_{phase}_{idx}",
                phase=phase,
                title=r.rationale or f"{r.proposal['tool']} ({act})",
                risk_level=level,
                routed=r,
            )
            self.tasks.append(t)
            created.append(t)
        return created
