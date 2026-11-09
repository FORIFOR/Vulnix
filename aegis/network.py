"""Layer 3 Network (application side).

- Host must be an exact allowed hostname of the target.
- DNS is resolved once by the gateway; EVERY returned address (v4 and v6) must be
  inside the target's CIDRs, and the worker receives the pinned IP so it never
  re-resolves (defeats DNS rebinding).
- Some ranges are denied even if an operator lists them (cloud metadata, etc.).
- Redirects are never followed by workers; a Location becomes a new proposal.

NOTE: this is not sufficient alone. Worker egress must also be enforced at the
OS / network layer (netns + nftables, or VPC egress rules). The nftables ruleset
for that is built in netfilter.py; applying it to a kernel requires a Linux
worker host (see netfilter.supported()).
"""
from __future__ import annotations

import ipaddress
import socket
import threading
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from .authz import Target

HARD_DENY = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
    "100.100.100.200/32",                      # Alibaba metadata
    "::/128", "fe80::/10", "ff00::/8", "fd00:ec2::254/128",
)]

Resolver = Callable[[str], list[str]]


class NetworkError(Exception):
    pass


def system_resolver(host: str) -> list[str]:
    return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})


@dataclass(frozen=True)
class PinnedDestination:
    scheme: str
    host: str
    ip: str
    port: int
    path: str


def _norm_ip(raw: str) -> ipaddress._BaseAddress:
    ip = ipaddress.ip_address(raw.split("%")[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip


class EgressGuard:
    def __init__(self, resolver: Resolver = system_resolver):
        self._resolver = resolver
        self._blocked = False
        self._lock = threading.Lock()

    def block_all(self) -> None:
        with self._lock:
            self._blocked = True

    @property
    def blocked(self) -> bool:
        return self._blocked

    def check(self, url: str, target: Target) -> PinnedDestination:
        if self._blocked:
            raise NetworkError("egress blocked by emergency stop")
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise NetworkError("scheme not allowed")
        if parts.username or parts.password:
            raise NetworkError("credentials in URL not allowed")
        host = (parts.hostname or "").rstrip(".").lower()
        if not host:
            raise NetworkError("no host")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if port not in target.ports:
            raise NetworkError("port not in scope")

        try:
            literal = _norm_ip(host)
        except ValueError:
            literal = None
        if literal is None and host not in {h.lower() for h in target.hosts}:
            raise NetworkError("host not in scope")
        if literal is not None and host not in {h.lower() for h in target.hosts}:
            raise NetworkError("IP literal not in scope")

        addrs = [str(literal)] if literal is not None else self._resolver(host)
        if not addrs:
            raise NetworkError("no addresses")
        nets = [ipaddress.ip_network(c) for c in target.cidrs]
        checked = []
        for raw in addrs:
            ip = _norm_ip(raw)
            if any(ip.version == n.version and ip in n for n in HARD_DENY):
                raise NetworkError(f"address {ip} is hard-denied")
            if not any(ip.version == n.version and ip in n for n in nets):
                raise NetworkError(f"address {ip} not in scope")
            checked.append(str(ip))
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        return PinnedDestination(parts.scheme, host, checked[0], port, path)
