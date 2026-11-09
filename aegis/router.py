"""P1: proposal intake / LLM router — treat model/agent output as untrusted data.

The platform's first principle: the model (ARTEX, an abliterated inference model,
any LLM) PROPOSES; only the Gateway DISPOSES. This router is the seam where model
backends plug in. It deliberately:
  * holds NO token authority, no approvals, no scope — it cannot self-authorize;
  * sanitizes every proposal down to the strict schema, so authority-shaped keys
    a backend might emit ("approved", "token", "scope") are dropped before the
    Gateway ever sees them;
  * carries rationale text as inert data (a backend's words never become actions);
  * records provenance (which backend proposed what) to the audit log.

No real model is called here. Backends are pluggable; the stub returns canned
proposals so the control flow is exercised without any network or inference. Real
backends (Abliteration / GPT / Claude) would implement ModelBackend and remain,
like the stub, proposal-only. Activating autonomous proposal execution is a
deliberate operator decision on top of the finished P0 safety foundation.
"""
from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable

from .policy import PROPOSAL_KEYS

MAX_RATIONALE = 500

# transport(url, headers, body) -> response bytes. Injectable for offline tests.
Transport = Callable[[str, dict, bytes], bytes]


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
    """A real model backend: asks an HTTP inference endpoint for proposed
    diagnostic actions. The endpoint URL and API key come from the runtime
    environment and are used only to build the request — never logged. The
    transport is injectable, so this adapter is fully testable offline and makes
    no network call in tests. Its output, like any backend's, is untrusted and
    is sanitized by the router before it can reach the Gateway.

    The model is expected to answer with JSON {"proposals": [ <proposal>, ... ]}.
    Anything else yields no proposals (and malformed items are dropped later)."""

    def __init__(self, name: str, url: str, *, api_key: str | None = None,
                 model: str = "", transport: Transport | None = None):
        self.name = name
        self._url = url
        self._key = api_key
        self._model = model
        self._transport = transport or _http_transport

    @classmethod
    def from_env(cls, name: str = "model", prefix: str = "AEGIS_MODEL",
                 transport: Transport | None = None) -> "HttpModelBackend | None":
        """Build from env (…_URL, …_KEY, …_MODEL). Returns None when no endpoint
        is configured — so the control plane simply has no model connected."""
        url = os.environ.get(f"{prefix}_URL")
        if not url:
            return None
        return cls(name, url, api_key=os.environ.get(f"{prefix}_KEY"),
                   model=os.environ.get(f"{prefix}_MODEL", ""), transport=transport)

    def propose(self, context: dict) -> list[dict]:
        headers = {"Content-Type": "application/json"}
        if self._key:
            headers["Authorization"] = f"Bearer {self._key}"
        body = json.dumps({"model": self._model, "context": context}).encode()
        try:
            raw = self._transport(self._url, headers, body)
            data = json.loads(raw)
        except Exception:
            return []                         # unreachable / malformed -> no proposals
        items = data.get("proposals") if isinstance(data, dict) else None
        return [p for p in items if isinstance(p, dict)] if isinstance(items, list) else []


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
