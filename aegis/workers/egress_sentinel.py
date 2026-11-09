"""In-process egress confinement for worker processes (defense in depth).

The gateway already pins a single destination and the probe worker connects by
that IP alone. This adds a second, independent backstop *inside the worker
process*: the socket layer is patched so a TCP connection can be opened ONLY to
the gateway-pinned destination(s). If the worker code — or a proposal it was
built from — ever tries to reach any other address, connect() raises before a
packet leaves the host.

This is NOT a kernel/OS egress firewall (layer 3 network namespaces + nftables
remain the stronger, Linux-only control and are not implemented here). It is a
portable, testable in-process control with an important property: the launcher
imposes it and the worker cannot opt out of it or widen it. A component that is
being confined is never trusted to confine itself.

Used two ways:
  * as a library:   install({(ip, port), ...})  — patches this process's sockets
  * as a bootstrap: python3 -I egress_sentinel.py --allow IP/PORT [...] -- worker.py [args]
    installs the guard, then runs the real worker in the same (now confined)
    process via runpy, so every worker is confined without having to remember to
    confine itself.
"""
from __future__ import annotations

import errno
import socket
import sys

_INET = (socket.AF_INET, socket.AF_INET6)


def _host_port(address) -> tuple[str, int] | None:
    """Extract (host, port) from a sockaddr, or None if it is not host/port shaped."""
    if not isinstance(address, (tuple, list)) or len(address) < 2:
        return None
    host, port = address[0], address[1]
    try:
        return str(host), int(port)
    except (TypeError, ValueError):
        return None


def _permitted(family, address, allow: set[tuple[str, int]]) -> bool:
    """A connect target is permitted if it is a non-IP socket (e.g. AF_UNIX) or
    an allowed (ip, port). A hostname that was never resolved to a pinned IP is
    not in `allow`, so it is denied — the worker must connect by pinned IP."""
    if family not in _INET:
        return True
    hp = _host_port(address)
    if hp is None:
        return False
    return hp in allow


class EgressBlocked(PermissionError):
    """Raised when a worker tries to connect outside its pinned destination(s)."""


def install(allow: set[tuple[str, int]]) -> None:
    allow = {(str(ip), int(port)) for ip, port in allow}
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def connect(self, address):
        if not _permitted(self.family, address, allow):
            raise EgressBlocked(f"egress to {address!r} blocked (allowed: {sorted(allow)})")
        return real_connect(self, address)

    def connect_ex(self, address):
        if not _permitted(self.family, address, allow):
            return errno.EACCES
        return real_connect_ex(self, address)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex


def _parse_allow(values: list[str]) -> set[tuple[str, int]]:
    allow = set()
    for v in values:
        ip, _, port = v.rpartition("/")   # IP/PORT; IPv6 contains no "/"
        if not ip or not port.isdigit():
            raise SystemExit(f"egress_sentinel: bad --allow value {v!r} (want IP/PORT)")
        allow.add((ip, int(port)))
    return allow


def _bootstrap(argv: list[str]) -> None:
    import runpy

    allow_vals: list[str] = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--allow":
            allow_vals.append(argv[i + 1]); i += 2
        elif a == "--":
            i += 1; break
        else:
            raise SystemExit(f"egress_sentinel: unexpected arg {a!r}")
    worker_argv = argv[i:]
    if not worker_argv:
        raise SystemExit("egress_sentinel: no worker given after --")
    install(_parse_allow(allow_vals))
    sys.argv = worker_argv
    runpy.run_path(worker_argv[0], run_name="__main__")


if __name__ == "__main__":
    _bootstrap(sys.argv)
