"""Layer 3 Network (OS / kernel side): nftables egress confinement.

The application-side EgressGuard (network.py) pins one destination and the
sentinel (workers/egress_sentinel.py) blocks other connects inside the worker
process. This module is the third, strongest layer: a kernel packet filter that
default-DROPs all egress from the worker's network namespace except the pinned
ip:port. A worker that is fully compromised — native code, a forked process, a
raw socket — still cannot send a packet anywhere else, because the decision is
made by the kernel, not by any code the worker can reach.

Intended deployment: on a Linux worker host, create a per-worker network
namespace, apply `nft_ruleset(...)` inside it, then launch the worker there.

Honesty note: this file BUILDS and (on Linux) APPLIES the ruleset. The ruleset
generation is unit-tested. Applying it against a live kernel requires Linux +
root + nft and is NOT exercised on macOS; `supported()` reports whether this
host can apply it. Do not claim kernel-level enforcement on a host where
`supported()` is False.
"""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
import sys
from collections.abc import Iterable

from .network import HARD_DENY

TABLE = "aegis_egress"


def _fam(ip: ipaddress._BaseAddress) -> str:
    return "ip6" if ip.version == 6 else "ip"


def nft_ruleset(pinned: Iterable[tuple[str, int]], *, hard_deny=HARD_DENY) -> str:
    """Return an `nft -f` script: drop all egress except loopback, established
    flows, and new TCP to each pinned (ip, port). Hard-denied ranges (cloud
    metadata, link-local, ...) are dropped explicitly and ahead of everything."""
    pinned = [(ipaddress.ip_address(ip), int(port)) for ip, port in pinned]
    lines = [
        f"table inet {TABLE} {{",
        "  chain output {",
        "    type filter hook output priority 0; policy drop;",
        "    oif \"lo\" accept",
        "    ct state established,related accept",
    ]
    for net in hard_deny:                       # explicit, logged, ahead of any allow
        fam = "ip6" if net.version == 6 else "ip"
        lines.append(f"    {fam} daddr {net} drop")
    for ip, port in pinned:                     # the only permitted new egress
        lines.append(f"    {_fam(ip)} daddr {ip} tcp dport {port} ct state new accept")
    lines += ["  }", "}", ""]
    return "\n".join(lines)


def supported(platform: str | None = None) -> bool:
    """True only where the ruleset can actually be applied to a kernel."""
    return (platform or sys.platform).startswith("linux")


def nft_path() -> str | None:
    return shutil.which("nft")


def check_ruleset(ruleset: str, *, runner=subprocess.run, nft: str | None = None) -> bool:
    """Syntax-check a ruleset with `nft -c -f -` (parses, does NOT apply to the
    kernel). Returns True when it parses. Raises FileNotFoundError where nft is
    not installed (e.g. macOS) and OSError on a syntax error. A pass here means
    the script is well-formed — NOT that egress is enforced on this host."""
    path = nft if nft is not None else nft_path()
    if not path:
        raise FileNotFoundError("nft not installed; cannot syntax-check the ruleset here")
    proc = runner([path, "-c", "-f", "-"], input=ruleset, text=True, capture_output=True)
    if proc.returncode != 0:
        raise OSError(f"ruleset syntax error: {proc.stderr.strip()}")
    return True


def apply_ruleset(ruleset: str, *, runner=subprocess.run, assume_linux: bool | None = None) -> None:
    """Apply a ruleset via `nft -f -`. Raises NotImplementedError off Linux so a
    caller can never mistake a no-op for enforcement."""
    linux = supported() if assume_linux is None else assume_linux
    if not linux:
        raise NotImplementedError(
            "kernel egress confinement requires Linux + root + nft; "
            "this host cannot apply it (application-layer guards still apply)")
    proc = runner(["nft", "-f", "-"], input=ruleset, text=True, capture_output=True)
    if proc.returncode != 0:
        raise OSError(f"nft failed (rc={proc.returncode}): {proc.stderr.strip()}")


def ruleset_for(pinned_ip: str, pinned_port: int) -> str:
    """Convenience wrapper for a single pinned destination."""
    return nft_ruleset([(pinned_ip, pinned_port)])
