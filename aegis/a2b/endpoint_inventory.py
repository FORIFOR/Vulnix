"""Normalised backend endpoints from static hints, and comparison with an OpenAPI document."""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field

from .static_analyzer import Hints

# Hosts that belong to SDKs / platforms, not to the app owner's backend.
THIRD_PARTY_SUFFIXES = ("googleapis.com", "google.com", "gstatic.com", "firebaseio.com", "firebase.google.com",
                        "crashlytics.com", "facebook.com", "fbcdn.net", "apple.com", "android.com", "schemas.android.com",
                        "w3.org", "github.com", "sentry.io", "doubleclick.net", "appsflyer.com", "adjust.com",
                        "branch.io", "stripe.com", "paypal.com", "cloudflare.com", "jsdelivr.net", "unpkg.com",
                        "example.org", "apache.org", "xml.org", "kotlinlang.org", "jetbrains.com")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


@dataclass
class Endpoint:
    host: str | None            # None: relative path whose host is not known from the app
    method: str                 # GET/POST/... or UNKNOWN
    path: str                   # normalised template: /users/{param}/orders
    query_params: tuple[str, ...] = ()
    sources: set[str] = field(default_factory=set)
    host_inferred: bool = False

    def key(self) -> tuple:
        return (self.host or "", self.method, self.path)

    def to_dict(self) -> dict:
        return {"host": self.host, "method": self.method, "path": self.path,
                "query_params": list(self.query_params), "sources": sorted(self.sources)[:20],
                "host_inferred": self.host_inferred}


def is_third_party(host: str) -> bool:
    h = host.lower()
    return any(h == s or h.endswith("." + s) for s in THIRD_PARTY_SUFFIXES)


def normalise_path(path: str) -> str:
    path = path.split("?", 1)[0].split("#", 1)[0]
    segs = []
    for seg in path.split("/"):
        if not seg:
            continue
        if re.fullmatch(r"\{[^}]{1,60}\}|:[A-Za-z_]\w{0,40}", seg) or seg.isdigit() or _UUID.match(seg):
            segs.append("{param}")
        else:
            segs.append(seg[:80])
    return "/" + "/".join(segs[:20])


_OPAQUE = re.compile(r"[A-Za-z0-9_:+=-]{20,}")


def redact_path(path: str, secret_values: set[str]) -> str:
    """Replace path segments that are (or contain) a detected secret, or look like an opaque
    token (20+ characters mixing letters and digits), with {secret}."""
    out = []
    for seg in path.split("/"):
        hit = any(v and len(v) >= 8 and (v in seg or (len(seg) >= 8 and seg in v)) for v in secret_values)
        opaque = bool(_OPAQUE.fullmatch(seg)) and re.search(r"\d", seg) and re.search(r"[A-Za-z]", seg)
        out.append("{secret}" if hit or opaque else seg)
    return "/".join(out)


def _query_names(raw: str) -> tuple[str, ...]:
    q = raw.split("?", 1)[1] if "?" in raw else ""
    names = sorted({k for k, _ in urllib.parse.parse_qsl(q, keep_blank_values=True) if re.fullmatch(r"[\w.-]{1,40}", k)})
    return tuple(names[:20])


def build_inventory(hints: Hints) -> dict:
    """Endpoints of the app owner's backend (third-party SDK hosts are listed separately)."""
    eps: dict[tuple, Endpoint] = {}
    third: set[str] = set()
    bases: set[str] = set()

    def add(host, method, raw, src, inferred=False):
        try:
            raw_path = urllib.parse.urlsplit(raw).path if "://" in raw else raw
        except ValueError:
            return                                   # malformed URL in the app: not an endpoint
        path = redact_path(normalise_path(raw_path), hints.secret_values)
        ep = Endpoint(host, method, path, _query_names(raw), host_inferred=inferred)
        cur = eps.setdefault(ep.key(), ep)
        cur.sources.add(src)
        cur.query_params = tuple(sorted(set(cur.query_params) | set(ep.query_params)))

    for url, src in hints.urls:
        try:
            parts = urllib.parse.urlsplit(url)
            host = (parts.hostname or "").lower()
        except ValueError:
            continue
        if not host or "." not in host:
            continue
        if is_third_party(host):
            third.add(host)
            continue
        if parts.path in ("", "/") or re.fullmatch(r"/(?:api|v\d{1,2})/?", parts.path or ""):
            bases.add(host)          # a base URL, not an endpoint
            continue
        add(host, "UNKNOWN", url, src)
    owned_bases = sorted(bases)
    single = owned_bases[0] if len(owned_bases) == 1 else None
    for method, raw, src in hints.calls:
        if "://" in raw:
            try:
                host = (urllib.parse.urlsplit(raw).hostname or "").lower()
            except ValueError:
                continue
            if not host or is_third_party(host):
                third.add(host) if host else None
                continue
            add(host, method, raw, src)
        else:
            add(single, method, raw, src, inferred=single is not None)
    known_paths = {(e.path) for e in eps.values()}
    for raw, src in hints.paths:
        p = normalise_path(raw)
        if p not in known_paths and p != "/":
            add(single, "UNKNOWN", raw, src, inferred=single is not None)
            known_paths.add(p)
    # a path seen with a concrete method makes the UNKNOWN twin redundant
    concrete = {(e.host, e.path) for e in eps.values() if e.method != "UNKNOWN"}
    for k in [k for k, e in eps.items() if e.method == "UNKNOWN" and (e.host, e.path) in concrete]:
        src = eps.pop(k).sources
        for e in eps.values():
            if (e.host, e.path) == (k[0] or None, k[2]) and e.method != "UNKNOWN":
                e.sources |= src
                break
    endpoints = sorted(eps.values(), key=lambda e: (e.host or "~", e.path, e.method))
    return {"endpoints": endpoints, "owner_hosts": sorted({e.host for e in endpoints if e.host} | bases),
            "third_party_hosts": sorted(third)}


def compare_openapi(endpoints: list[Endpoint], spec: dict) -> dict:
    """Which app endpoints the owner's OpenAPI document declares, and which it does not."""
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        raise ValueError("OpenAPI document has no paths")
    declared: set[tuple[str, str]] = set()
    for path, ops in spec["paths"].items():
        if not isinstance(path, str) or not isinstance(ops, dict):
            continue
        for method in ops:
            if method.lower() in ("get", "post", "put", "patch", "delete", "head"):
                declared.add((method.upper(), normalise_path(path)))
    prefixes = {normalise_path(urllib.parse.urlsplit(s.get("url", "")).path)
                for s in spec.get("servers") or [] if isinstance(s, dict)} - {"/"}

    def strip(p: str) -> set[str]:
        out = {p}
        for pre in prefixes:
            if p.startswith(pre + "/"):
                out.add(p[len(pre):])
        return out
    matched, undocumented = [], []
    seen = set()
    for e in endpoints:
        cands = strip(e.path)
        hit = [d for d in declared if d[1] in cands and (e.method in ("UNKNOWN", d[0]))]
        if hit:
            matched.append(e.to_dict())
            seen |= set(hit)
        else:
            undocumented.append(e.to_dict())
    unseen = sorted(f"{m} {p}" for m, p in declared - seen)
    return {"matched": matched, "undocumented_in_spec": undocumented, "declared_not_seen_in_app": unseen}
