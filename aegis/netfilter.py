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


def verify_linux_netns_enforcement(*, pinned_ip: str = "127.0.0.1", pinned_port: int = 18081) -> dict:
    """On Linux with root/sudo + `ip` + `nft`, create an isolated network namespace,
    apply the nftables egress ruleset to the live kernel, and verify that:
      1. The kernel table `inet aegis_egress` is active with `policy drop`;
      2. Loopback traffic to the pinned port succeeds;
      3. Outbound connections to cloud metadata (169.254.169.254:80) and external
         IPs (198.51.100.1:443) are blocked by the kernel even without userland hooks.
    Safe to call on any OS; returns structured status."""
    import json
    import os
    import secrets
    import time

    t0 = time.monotonic()
    rules = ruleset_for(pinned_ip, pinned_port)
    if not supported():
        return {
            "supported_os": False,
            "kernel_enforced": False,
            "reason": f"non-linux host ({sys.platform})",
            "elapsed_ms": round((time.monotonic() - t0) * 1000, 2),
        }

    ip_bin = shutil.which("ip")
    nft_bin = nft_path()
    if not ip_bin or not nft_bin:
        return {
            "supported_os": True,
            "kernel_enforced": False,
            "reason": "ip or nft binary not installed",
            "elapsed_ms": round((time.monotonic() - t0) * 1000, 2),
        }

    prefix: list[str] = []
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sudo_bin = shutil.which("sudo")
        if not sudo_bin:
            return {
                "supported_os": True,
                "kernel_enforced": False,
                "reason": "requires root or passwordless sudo",
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 2),
            }
        chk = subprocess.run([sudo_bin, "-n", "true"], capture_output=True, text=True)
        if chk.returncode != 0:
            return {
                "supported_os": True,
                "kernel_enforced": False,
                "reason": "sudo requires password",
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 2),
            }
        prefix = [sudo_bin, "-n"]

    ns = f"aegis_ns_{secrets.token_hex(4)}"
    try:
        add_p = subprocess.run([*prefix, ip_bin, "netns", "add", ns], capture_output=True, text=True)
        if add_p.returncode != 0:
            return {
                "supported_os": True,
                "kernel_enforced": False,
                "reason": f"ip netns add failed: {add_p.stderr.strip()}",
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 2),
            }

        subprocess.run([*prefix, ip_bin, "netns", "exec", ns, ip_bin, "link", "set", "lo", "up"],
                       capture_output=True, text=True, check=True)
        apply_p = subprocess.run(
            [*prefix, ip_bin, "netns", "exec", ns, nft_bin, "-f", "-"],
            input=rules, capture_output=True, text=True,
        )
        if apply_p.returncode != 0:
            return {
                "supported_os": True,
                "kernel_enforced": False,
                "reason": f"nft apply failed: {apply_p.stderr.strip()}",
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 2),
            }

        list_p = subprocess.run(
            [*prefix, ip_bin, "netns", "exec", ns, nft_bin, "list", "table", "inet", TABLE],
            capture_output=True, text=True,
        )
        active_table = list_p.stdout.strip()

        probe_code = (
            "import json, socket, threading\n"
            f"srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            f"srv.bind(('127.0.0.1', {int(pinned_port)}))\n"
            "srv.listen(1)\n"
            "threading.Thread(target=lambda: srv.accept()[0].close(), daemon=True).start()\n"
            "res = {}\n"
            "c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "c.settimeout(1.0)\n"
            f"c.connect(('127.0.0.1', {int(pinned_port)}))\n"
            "c.close()\n"
            "res['pinned_loopback'] = 'ALLOWED'\n"
            "for label, addr in [('metadata', ('169.254.169.254', 80)), ('external', ('198.51.100.1', 443))]:\n"
            "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "    s.settimeout(0.3)\n"
            "    try:\n"
            "        s.connect(addr)\n"
            "        res[label] = 'ALLOWED_UNEXPECTED'\n"
            "    except OSError as e:\n"
            "        res[label] = f'BLOCKED:{type(e).__name__}'\n"
            "    finally:\n"
            "        s.close()\n"
            "srv.close()\n"
            "print(json.dumps(res))\n"
        )
        probe_p = subprocess.run(
            [*prefix, ip_bin, "netns", "exec", ns, sys.executable, "-I", "-c", probe_code],
            capture_output=True, text=True, timeout=10,
        )
        probe_out = json.loads(probe_p.stdout.strip()) if probe_p.returncode == 0 and probe_p.stdout.strip() else {}
        enforced = (
            "policy drop" in active_table
            and probe_out.get("pinned_loopback") == "ALLOWED"
            and str(probe_out.get("metadata", "")).startswith("BLOCKED:")
            and str(probe_out.get("external", "")).startswith("BLOCKED:")
        )
        return {
            "supported_os": True,
            "kernel_enforced": enforced,
            "namespace": ns,
            "active_table_verified": "policy drop" in active_table,
            "probe_results": probe_out,
            "elapsed_ms": round((time.monotonic() - t0) * 1000, 2),
        }
    finally:
        subprocess.run([*prefix, ip_bin, "netns", "delete", ns], capture_output=True, text=True)

