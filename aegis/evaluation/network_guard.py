"""Count and refuse every non-loopback connection while an evaluation step runs.

Used by the dry run and its tests to show "external connections: 0": any attempt to
reach a non-loopback address raises and is recorded (Worker subprocesses run under
their own confinement; this guards the evaluation process itself).
"""
from __future__ import annotations

import ipaddress
import socket
from contextlib import contextmanager


class ExternalConnectionRefused(OSError):
    pass


def _loopback(address) -> bool:
    if isinstance(address, tuple) and address:
        host = address[0]
    else:
        return isinstance(address, (str, bytes))          # AF_UNIX path
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


@contextmanager
def no_external_connections():
    attempts: list[str] = []
    original_connect, original_connect_ex = socket.socket.connect, socket.socket.connect_ex
    original_getaddrinfo = socket.getaddrinfo

    def connect(self, address):
        if not _loopback(address):
            attempts.append(repr(address))
            raise ExternalConnectionRefused(f"external connection refused: {address!r}")
        return original_connect(self, address)

    def connect_ex(self, address):
        if not _loopback(address):
            attempts.append(repr(address))
            raise ExternalConnectionRefused(f"external connection refused: {address!r}")
        return original_connect_ex(self, address)

    def getaddrinfo(host, *a, **kw):
        if host not in (None, "localhost") and not _loopback((host,)):
            attempts.append(f"dns:{host}")
            raise ExternalConnectionRefused(f"name lookup refused: {host}")
        return original_getaddrinfo(host, *a, **kw)

    socket.socket.connect, socket.socket.connect_ex = connect, connect_ex
    socket.getaddrinfo = getaddrinfo
    try:
        yield attempts
    finally:
        socket.socket.connect, socket.socket.connect_ex = original_connect, original_connect_ex
        socket.getaddrinfo = original_getaddrinfo


__all__ = ["ExternalConnectionRefused", "no_external_connections"]
