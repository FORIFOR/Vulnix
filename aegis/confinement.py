"""Kernel-side confinement of ONE worker run (Linux only).

`netfilter.verify_linux_netns_enforcement()` is a self-test: it shows that this
host's kernel can enforce the egress ruleset in a scratch namespace. It says
nothing about the worker that is about to carry test-account tokens to a real
service. This module closes that gap: the confinement is created for a single
run, the worker is started INSIDE it, and before the worker starts the kernel is
asked to prove - with a probe launched exactly the way the worker will be - that
traffic from that place is in fact dropped.

Mechanism (host network namespace, no routing changes):
  * a fresh cgroup v2 directory `/sys/fs/cgroup/<name>`;
  * an nftables table whose output hook sends every packet of a socket owned by
    that cgroup to a chain that accepts established flows and NEW tcp to the one
    pinned ip:port, and drops (and counts) everything else;
  * the worker is exec'd by a tiny shell that first moves itself into the
    cgroup, so there is no moment at which the worker runs unconfined.

Verification before the worker is released:
  1. the table as listed by the kernel contains the cgroup match and the drop;
  2. a probe started through the same launcher reports that it is in the cgroup
     and that a connection to a documentation address (198.51.100.1:443, never
     the target) did not succeed;
  3. the kernel's drop counter for the chain went up - i.e. the kernel matched
     the probe's packets; "unreachable anyway" does not count.
If any step fails, nothing is launched (ConfinementError).

Off Linux, or without root / passwordless sudo, nft and cgroup v2, `status()`
says so and `session()` refuses. There is no fallback.
"""
from __future__ import annotations

import ipaddress
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .network import HARD_DENY

CGROUP_ROOT = Path("/sys/fs/cgroup")
PROBE_ADDR = ("198.51.100.1", 443)          # TEST-NET-2 (RFC 5737): documentation only
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_NAME = re.compile(r"aegis_l2_[0-9a-f]{12}")

# moves itself into the cgroup, then becomes the worker: `sh -c SCRIPT sh <procs-file> <cpu> argv...`
_ENTER = 'echo $$ > "$1" || exit 97; ulimit -t "$2" 2>/dev/null; shift 2; exec "$@"'


class ConfinementError(Exception):
    """Kernel confinement could not be applied or could not be confirmed."""


# The tools are looked up in the system directories only, never through $PATH:
# what they report is the evidence that the confinement is real.
SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


def _system_which(tool: str) -> str | None:
    return shutil.which(tool, path=SYSTEM_PATH)


def ruleset(name: str, ip: str, port: int) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise ConfinementError("invalid address") from None
    if str(addr) != str(ip).strip().lower() or "%" in str(ip):
        raise ConfinementError("address must be a plain, canonical IP literal")
    if any(addr.version == n.version and addr in n for n in HARD_DENY):
        raise ConfinementError(f"address {addr} is hard-denied")
    if not _NAME.fullmatch(name) or not 0 < int(port) < 65536:
        raise ConfinementError("invalid confinement parameters")
    fam = "ip6" if addr.version == 6 else "ip"
    return "\n".join([
        f"table inet {name} {{",
        "  chain confined {",
        # only flows this cgroup opened itself (those can only go to the pinned
        # destination); replies on a connection somebody else opened TO the worker
        # are not let out
        "    ct state established ct direction original accept",
        f"    {fam} daddr {addr} tcp dport {int(port)} ct state new accept",
        "    counter drop",
        "  }",
        "  chain output {",
        "    type filter hook output priority 0; policy accept;",
        f"    socket cgroupv2 level 1 \"{name}\" jump confined",
        "  }",
        "}",
        "",
    ])


def dropped_packets(listing: str) -> int:
    return sum(int(n) for n in re.findall(r"counter packets (\d+) bytes \d+ drop", listing))


def _table_is_live(listing: str, name: str) -> bool:
    return (f'socket cgroupv2 level 1 "{name}" jump confined' in listing
            and re.search(r"counter packets \d+ bytes \d+ drop", listing) is not None
            and "hook output" in listing)


class KernelConfinement:
    """Per-run cgroup v2 + nftables confinement. `status()` is a cheap preflight;
    the binding check happens in `session()`, for the run itself."""

    mechanism = "linux cgroup v2 + nftables (host namespace)"

    def __init__(self, *, runner=subprocess.run, platform: str | None = None,
                 cgroup_root: Path = CGROUP_ROOT, euid: int | None = None, which=_system_which):
        self._run = runner
        self._platform = platform or sys.platform
        self._root = Path(cgroup_root)
        self._euid = (os.geteuid() if hasattr(os, "geteuid") else -1) if euid is None else euid
        self._which = which
        self._status: tuple[float, dict] | None = None
        self._separate_uid: bool | None = None

    # ---- preflight -----------------------------------------------------------
    def status(self) -> dict:
        now = time.monotonic()
        if self._status and now - self._status[0] < 30:
            return dict(self._status[1])
        st = self._preflight()
        self._status = (now, st)
        return dict(st)

    def _preflight(self) -> dict:
        def no(reason: str) -> dict:
            return {"ok": False, "reason": reason, "mechanism": self.mechanism}
        if not self._platform.startswith("linux"):
            return no(f"Linux 以外のホスト（{self._platform}）ではカーネル隔離を適用できません")
        if not (self._root / "cgroup.controllers").exists():
            return no("cgroup v2 が利用できません")
        for tool in ("nft", "sh"):
            if not self._which(tool):
                return no(f"{tool} が見つかりません")
        if not self._which("setpriv"):
            return no("setpriv が見つかりません")
        if self._euid != 0:
            if not self._which("sudo"):
                return no("root 権限がなく、sudo も見つかりません")
            try:
                if self._run([self._which("sudo"), "-n", "true"], capture_output=True, text=True).returncode != 0:
                    return no("root 権限またはパスワード不要の sudo が必要です")
            except OSError as e:
                return no(f"sudo を実行できません（{type(e).__name__}）")
        return {"ok": True, "reason": "", "mechanism": self.mechanism}

    NOBODY = (65534, 65534)

    def worker_identity(self) -> tuple[int, int]:
        """uid/gid the confined worker runs as. Never root. Preferably `nobody`, so
        that a subverted worker cannot read the control plane's own 0600 files
        (master key, secret store, accounts) or ptrace it; that needs the worker's
        code and the interpreter to be readable by others. Otherwise the control
        plane's own account (or, under root, the account that invoked sudo)."""
        if self._worker_code_world_readable():
            return self.NOBODY
        if self._euid != 0:
            return os.getuid(), os.getgid()
        try:
            uid, gid = int(os.environ.get("SUDO_UID", "0")), int(os.environ.get("SUDO_GID", "0"))
        except ValueError:
            uid = gid = 0
        return (uid, gid) if uid > 0 and gid > 0 else self.NOBODY

    def _worker_code_world_readable(self) -> bool:
        if self._separate_uid is not None:
            return self._separate_uid
        import sysconfig
        targets = [Path(__file__).resolve().parent / "workers",
                   Path(sys.executable).resolve(),
                   Path(sysconfig.get_paths()["stdlib"]).resolve()]
        ok = True
        for target in targets:
            try:
                st = target.stat()
                need = 0o005 if target.is_dir() else 0o005
                if st.st_mode & need != need:
                    ok = False
                    break
                for parent in target.parents:
                    if parent.stat().st_mode & 0o001 == 0:       # others cannot traverse
                        ok = False
                        break
            except OSError:
                ok = False
            if not ok:
                break
        if ok:
            for f in (Path(__file__).resolve().parent / "workers").glob("*.py"):
                if f.stat().st_mode & 0o004 == 0:
                    ok = False
                    break
        self._separate_uid = ok
        return ok

    def _priv(self) -> list[str]:
        return [] if self._euid == 0 else [self._which("sudo") or "sudo", "-n"]

    # ---- one run -------------------------------------------------------------
    def session(self, ip: str, port: int) -> "ConfinementSession":
        st = self.status()
        if not st["ok"]:
            raise ConfinementError(st["reason"])
        return ConfinementSession(self, ip, int(port))


class ConfinementSession:
    def __init__(self, owner: KernelConfinement, ip: str, port: int):
        self._o = owner
        self.ip, self.port = ip, port
        self.name = "aegis_l2_" + secrets.token_hex(6)
        self.cgroup = owner._root / self.name
        self.evidence: dict = {}
        self._table = False
        self._dir = False
        self.leftover = False

    def _sh(self, script: str, *args: str, **kw):
        return self._o._run([*self._o._priv(), self._o._which("sh") or "sh", "-c", script, "sh", *args],
                            capture_output=True, text=True, **kw)

    def _nft(self, *args: str, **kw):
        return self._o._run([*self._o._priv(), self._o._which("nft") or "nft", *args],
                            capture_output=True, text=True, **kw)

    def wrap(self, argv: list[str], env_keys=(), cpu_seconds: int = 60) -> list[str]:
        """The command that starts `argv` inside the cgroup. Secrets stay in the
        environment: only the NAMES of the variables to keep appear on a command line."""
        enter = [self._o._which("sh") or "sh", "-c", _ENTER, "sh",
                 str(self.cgroup / "cgroup.procs"), str(int(cpu_seconds))]
        keys = sorted({k for k in env_keys if k != "PATH"})
        if any(not _ENV_NAME.fullmatch(k) for k in keys):
            raise ConfinementError("invalid environment variable name")
        uid, gid = self._o.worker_identity()
        # root only for the one write that joins the cgroup; the worker itself never
        # runs as root (a root worker could leave the cgroup or delete the rules)
        own = (uid, gid) == (os.getuid(), os.getgid()) and self._o._euid != 0
        drop = [self._o._which("setpriv") or "setpriv", f"--reuid={uid}", f"--regid={gid}",
                "--init-groups" if own else "--clear-groups", "--no-new-privs"]
        if self._o._euid == 0:
            return [*enter, *drop, *argv]
        keep = [f"--preserve-env={','.join(keys)}"] if keys else []
        return [*self._o._priv(), *keep, *enter, *drop, *argv]

    def __enter__(self) -> "ConfinementSession":
        try:
            self._apply_and_verify()
        except BaseException:
            self._teardown()
            raise
        return self

    def __exit__(self, *exc) -> None:
        self._teardown()

    def _apply_and_verify(self) -> None:
        rules = ruleset(self.name, self.ip, self.port)
        try:
            p = self._sh('mkdir "$1"', str(self.cgroup))
            if p.returncode != 0:
                raise ConfinementError(f"cgroup を作成できません: {p.stderr.strip()[:200]}")
            self._dir = True
            if self._sh('test -e "$1"', str(self.cgroup / "cgroup.kill")).returncode != 0:
                raise ConfinementError("このカーネルには cgroup.kill がありません（Linux 5.14 以降が必要です）")
            p = self._nft("-f", "-", input=rules)
            if p.returncode != 0:
                raise ConfinementError(f"nftables ルールを適用できません: {p.stderr.strip()[:200]}")
            self._table = True
            before = self._listing()
            if not _table_is_live(before, self.name):
                raise ConfinementError("適用した nftables ルールをカーネルから確認できません")
            probe = (
                "import json,socket\n"
                "s=socket.socket(); s.settimeout(0.6)\n"
                "try:\n"
                f"    s.connect({PROBE_ADDR!r}); r='CONNECTED'\n"
                "except OSError as e:\n"
                "    r='BLOCKED:'+type(e).__name__\n"
                "print(json.dumps({'connect': r, 'cgroup': open('/proc/self/cgroup').read().strip()}))\n"
            )
            pr = self._o._run(self.wrap([sys.executable, "-I", "-c", probe]),
                              capture_output=True, text=True, timeout=15, env={"PATH": "/usr/bin:/bin"})
            import json
            try:
                seen = json.loads(pr.stdout.strip().splitlines()[-1]) if pr.returncode == 0 else {}
            except (ValueError, IndexError):
                seen = {}
            after = self._listing()
            counted = dropped_packets(after) - dropped_packets(before)
            in_cgroup = any(line.split("::", 1)[-1] == f"/{self.name}"
                            for line in str(seen.get("cgroup", "")).splitlines())
            self.evidence = {"mechanism": self._o.mechanism, "cgroup": self.name,
                             "worker_uid": self._o.worker_identity()[0],
                             "pinned": f"{self.ip}:{self.port}",
                             "probe_connect": seen.get("connect"), "probe_in_cgroup": in_cgroup,
                             "kernel_dropped_packets": counted}
            if not (in_cgroup and str(seen.get("connect", "")).startswith("BLOCKED:") and counted >= 1):
                raise ConfinementError(
                    "カーネル隔離が実際に適用されていることを確認できませんでした"
                    f"（cgroup内={in_cgroup}, 接続={seen.get('connect')}, 遮断数={counted}）")
        except ConfinementError:
            raise
        except (OSError, subprocess.SubprocessError) as e:
            raise ConfinementError(f"カーネル隔離を適用できません（{type(e).__name__}）") from None

    def _listing(self) -> str:
        p = self._nft("list", "table", "inet", self.name)
        return p.stdout if p.returncode == 0 else ""

    def still_enforced(self) -> bool:
        """Asked again right before the worker starts and after it ends."""
        try:
            return _table_is_live(self._listing(), self.name)
        except (OSError, subprocess.SubprocessError):
            return False

    def empty(self) -> bool:
        """True only when the cgroup is known to hold no process (or is gone)."""
        try:
            return (self.cgroup / "cgroup.procs").read_text().strip() == ""
        except FileNotFoundError:
            return True
        except OSError:
            return False

    def kill(self) -> bool:
        """Kill everything in the cgroup (the worker may have been started through
        sudo, so signalling our own child is not enough)."""
        if not self._dir:
            return True
        try:
            return self._sh('echo 1 > "$1"', str(self.cgroup / "cgroup.kill"), timeout=10).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _teardown(self) -> None:
        """The rules go only AFTER the cgroup is empty and removed. If something in
        it cannot be killed, the rules stay (it remains confined) and that is
        reported: `leftover` is set and the caller records it."""
        self.kill()
        removed = not self._dir
        try:
            for _ in range(30):
                if removed:
                    break
                removed = self._sh('rmdir "$1"', str(self.cgroup), timeout=10).returncode == 0
                if not removed:
                    self.kill()
                    time.sleep(0.1)
            if removed and self._table:
                self._nft("delete", "table", "inet", self.name, timeout=10)
        except (OSError, subprocess.SubprocessError):
            removed = False
        self.leftover = not removed
        if removed:
            self._table = self._dir = False
