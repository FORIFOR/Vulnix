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


def _pinned(ip: str, port: int) -> tuple[ipaddress._BaseAddress, int]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise ConfinementError("invalid address") from None
    if str(addr) != str(ip).strip().lower() or "%" in str(ip):
        raise ConfinementError("address must be a plain, canonical IP literal")
    if any(addr.version == n.version and addr in n for n in HARD_DENY):
        raise ConfinementError(f"address {addr} is hard-denied")
    if not 0 < int(port) < 65536:
        raise ConfinementError("invalid confinement parameters")
    return addr, int(port)


def ruleset(name: str, ip: str, port: int, extra: tuple = ()) -> str:
    """`extra`: further (ip, port) pairs this run may open a TCP connection to (each
    pinned exactly like the first; e.g. a planner's local model and database)."""
    if not _NAME.fullmatch(name):
        raise ConfinementError("invalid confinement parameters")
    endpoints = [_pinned(ip, port), *(_pinned(i, p) for i, p in extra)]
    mark = flow_mark(name)
    allow = []
    for addr, prt in endpoints:
        fam = "ip6" if addr.version == 6 else "ip"
        est = f"    ct state established ct direction original ct mark {mark:#x} {fam} daddr {addr} accept"
        if est not in allow:
            allow.append(est)
        allow.append(f"    {fam} daddr {addr} tcp dport {prt} ct state new ct mark set {mark:#x} accept")
    return "\n".join([
        f"table inet {name} {{",
        "  chain confined {",
        # Established traffic passes only on a flow whose FIRST packet this run's
        # pinned rule accepted (it carries this run's conntrack mark) - not on a
        # flow somebody else opened (e.g. a UDP tuple a closed socket left in
        # conntrack), and not replies on a connection opened TO the worker.
        *allow,
        "    counter drop",
        "  }",
        "  chain output {",
        "    type filter hook output priority 0; policy accept;",
        f"    socket cgroupv2 level 1 \"{name}\" jump confined",
        "  }",
        "}",
        "",
    ])


def flow_mark(name: str) -> int:
    """A conntrack mark that belongs to one run (never 0)."""
    import hashlib as _h
    return (int.from_bytes(_h.sha256(name.encode()).digest()[:4], "big") | 0x1) & 0x7FFFFFFF


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
        self._staged: Path | None = None

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
        unreachable = self.interpreter_reachable_by_others()
        if unreachable:
            # the worker runs under a uid of its own; it has to be able to run Python
            return no("Worker を別の UID で実行できない配置です: " + unreachable)
        if self._euid != 0:
            if not self._which("sudo"):
                return no("root 権限がなく、sudo も見つかりません")
            try:
                if self._run([self._which("sudo"), "-n", "true"], capture_output=True, text=True).returncode != 0:
                    return no("root 権限またはパスワード不要の sudo が必要です")
            except OSError as e:
                return no(f"sudo を実行できません（{type(e).__name__}）")
        return {"ok": True, "reason": "", "mechanism": self.mechanism}

    # Worker uids are taken from a range no installer hands out; each run gets one
    # nobody else is using, so no other process shares its uid (it cannot read the
    # worker's environment, signal it, or be signalled by it).
    UID_RANGE = (3_000_000_000, 3_900_000_000)

    def fresh_identity(self) -> int:
        import pwd
        for _ in range(64):
            uid = self.UID_RANGE[0] + secrets.randbelow(self.UID_RANGE[1] - self.UID_RANGE[0])
            import grp
            try:
                pwd.getpwuid(uid)
                continue
            except KeyError:
                pass
            try:
                grp.getgrgid(uid)            # used as the gid as well
                continue
            except KeyError:
                return uid
        raise ConfinementError("Worker 用の未使用 UID を確保できません")

    def staged_workers(self) -> Path:
        """The worker programs, copied into a directory every user may read (the
        worker runs under a uid of its own, which cannot read the repository if it
        sits in a private home directory). No secrets in it.

        Checked on EVERY use, not only when created: the directory and each file
        must still be ours, not symlinks, not writable by anyone else, and
        byte-identical to the source. Anything else (e.g. /tmp was cleaned and
        another user recreated the name) means a fresh copy is made."""
        import shutil as _shutil
        import tempfile
        src = Path(__file__).resolve().parent / "workers"
        sources = {f.name: f.read_bytes() for f in src.glob("*.py")}
        if self._staged is not None and self._staged_intact(self._staged, sources):
            return self._staged
        staged = Path(tempfile.mkdtemp(prefix="vulnix-worker-"))
        for name, raw in sources.items():
            fd = os.open(staged / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
            with os.fdopen(fd, "wb") as fh:
                fh.write(raw)
            os.chmod(staged / name, 0o644)
        os.chmod(staged, 0o755)
        if not self._staged_intact(staged, sources):
            raise ConfinementError("Worker のコードを安全に配置できません")
        self._staged = staged
        return staged

    @staticmethod
    def _staged_intact(staged: Path, sources: dict) -> bool:
        import stat as _stat
        uid = os.getuid()
        try:
            st = os.lstat(staged)
            if not _stat.S_ISDIR(st.st_mode) or st.st_uid != uid or st.st_mode & 0o022:
                return False
            names = set(os.listdir(staged))
            if names != set(sources):
                return False
            for name, raw in sources.items():
                fst = os.lstat(staged / name)
                if not _stat.S_ISREG(fst.st_mode) or fst.st_uid != uid or fst.st_mode & 0o022:
                    return False
                if (staged / name).read_bytes() != raw:
                    return False
        except OSError:
            return False
        return True

    def reattach(self, name: str) -> "ConfinementSession":
        """A cgroup (and its nftables table) left behind by an earlier run of this
        installation, e.g. found on record after a restart: it can be checked,
        killed and removed, nothing else."""
        if not _NAME.fullmatch(name or ""):
            raise ConfinementError("invalid cgroup name")
        sess = ConfinementSession.__new__(ConfinementSession)
        sess._o, sess.name = self, name
        sess.cgroup = self._root / name
        sess.ip, sess.port, sess.uid, sess.forbidden = "", 0, None, ()
        sess.protected_pid, sess.evidence, sess.on_leftover = os.getpid(), {}, None
        sess._cancelled = False
        sess._entering = False
        sess._table = sess._dir = True
        sess.leftover = True
        return sess

    def interpreter_reachable_by_others(self) -> str:
        """"" when an unrelated uid can run this Python; otherwise why not."""
        import sysconfig
        for target in (Path(sys.executable).resolve(), Path(sysconfig.get_paths()["stdlib"]).resolve()):
            try:
                if target.stat().st_mode & 0o005 != 0o005:
                    return f"{target} を他のユーザーが読めません"
                for parent in target.parents:
                    if parent.stat().st_mode & 0o001 == 0:
                        return f"{parent} を他のユーザーがたどれません"
            except OSError as e:
                return f"{target} を確認できません（{type(e).__name__}）"
        return ""

    def _priv(self) -> list[str]:
        return [] if self._euid == 0 else [self._which("sudo") or "sudo", "-n"]

    # ---- one run -------------------------------------------------------------
    def session(self, ip: str, port: int, *, forbidden_paths=(), protected_pid: int | None = None,
                extra_endpoints: tuple = ()) -> "ConfinementSession":
        """`forbidden_paths`: files the worker must not be able to read (verified
        by the probe before the worker starts); `protected_pid`: a process the
        worker must not be able to signal (the control plane)."""
        st = self.status()
        if not st["ok"]:
            raise ConfinementError(st["reason"])
        return ConfinementSession(self, ip, int(port), forbidden_paths=tuple(str(p) for p in forbidden_paths),
                                  protected_pid=protected_pid if protected_pid is not None else os.getpid(),
                                  extra_endpoints=tuple((str(i), int(p)) for i, p in extra_endpoints))


class ConfinementSession:
    def __init__(self, owner: KernelConfinement, ip: str, port: int, *, forbidden_paths=(),
                 protected_pid: int | None = None, extra_endpoints: tuple = ()):
        self._o = owner
        self.ip, self.port = ip, port
        self.extra = tuple(extra_endpoints)
        self.forbidden = tuple(forbidden_paths)
        self.on_leftover = None
        self._cancelled = False      # killed (stopped) at any point: it may not start anything
        self._entering = False       # being applied: counts as busy until that has finished
        self.protected_pid = int(protected_pid if protected_pid is not None else os.getpid())
        self.uid = owner.fresh_identity()           # this run's own uid
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

    def wrap(self, argv: list[str], env_keys=(), cpu_seconds: int = 60, interpreter: str | None = None
             ) -> list[str]:
        """The command that starts `argv` inside the cgroup, as this run's own
        unprivileged uid, with no capabilities and no_new_privs, through the
        seccomp launcher (no UNIX-domain sockets). Secrets stay in the environment:
        only the NAMES of the variables to keep appear on a command line."""
        enter = [self._o._which("sh") or "sh", "-c", _ENTER, "sh",
                 str(self.cgroup / "cgroup.procs"), str(int(cpu_seconds))]
        keys = sorted({k for k in env_keys if k != "PATH"})
        if any(not _ENV_NAME.fullmatch(k) for k in keys):
            raise ConfinementError("invalid environment variable name")
        staged = self._o.staged_workers()
        real = Path(__file__).resolve().parent / "workers"
        mapped = [str(staged / Path(a).name) if Path(a).parent == real else a for a in argv]
        # root only for the one write that joins the cgroup and for dropping to the
        # worker's uid; the worker itself never holds root, a capability, or our uid
        drop = [self._o._which("setpriv") or "setpriv", f"--reuid={self.uid}", f"--regid={self.uid}",
                "--clear-groups", "--inh-caps=-all", "--bounding-set=-all", "--no-new-privs"]
        # the seccomp launcher is Python; a non-Python program names the interpreter
        launch = [interpreter or mapped[0], "-I", str(staged / "_sandbox_launch.py"), *mapped]
        if self._o._euid == 0:
            return [*enter, *drop, *launch]
        keep = [f"--preserve-env={','.join(keys)}"] if keys else []
        return [*self._o._priv(), *keep, *enter, *drop, *launch]

    def _check_cancelled(self) -> None:
        if self._cancelled:
            raise ConfinementError("停止されたため、隔離を作成しません")

    def __enter__(self) -> "ConfinementSession":
        self._entering = True
        try:
            self._apply_and_verify()
            self._check_cancelled()          # stopped during the probe: the worker never starts
        except BaseException:
            self._teardown()
            raise
        finally:
            self._entering = False
        return self

    def __exit__(self, *exc) -> None:
        self._teardown()

    def own_directory(self, path: str | os.PathLike) -> None:
        """Give an (empty) directory to this run's uid, mode 0700: the only place the
        confined program can write. Nothing else of ours becomes writable to it."""
        p = Path(path)
        if not p.is_dir() or p.is_symlink() or any(p.iterdir()):
            raise ConfinementError("隔離された実行用ディレクトリを準備できません")
        r = self._sh('chown "$1:$1" "$2" && chmod 700 "$2"', str(self.uid), str(p), timeout=10)
        if r.returncode != 0:
            raise ConfinementError(f"実行用ディレクトリの所有者を変更できません: {r.stderr.strip()[:200]}")

    def _apply_and_verify(self) -> None:
        rules = ruleset(self.name, self.ip, self.port, self.extra)
        self._check_cancelled()
        try:
            p = self._sh('mkdir "$1"', str(self.cgroup), timeout=10)
            if p.returncode != 0:
                raise ConfinementError(f"cgroup を作成できません: {p.stderr.strip()[:200]}")
            self._dir = True
            self._check_cancelled()          # stopped while the cgroup was being created
            if self._sh('test -e "$1"', str(self.cgroup / "cgroup.kill"), timeout=10).returncode != 0:
                raise ConfinementError("このカーネルには cgroup.kill がありません（Linux 5.14 以降が必要です）")
            self._check_cancelled()
            p = self._nft("-f", "-", input=rules, timeout=10)
            if p.returncode != 0:
                raise ConfinementError(f"nftables ルールを適用できません: {p.stderr.strip()[:200]}")
            self._table = True
            before = self._listing()
            if not _table_is_live(before, self.name):
                raise ConfinementError("適用した nftables ルールをカーネルから確認できません")
            probe = (
                "import json,os,socket\n"
                "out={}\n"
                # first, before this probe opens anything itself: what was inherited
                "fds={}\n"
                "for f in os.listdir('/proc/self/fd'):\n"
                "    try:\n        fds[f]=os.readlink('/proc/self/fd/'+f)\n"
                "    except OSError:\n        pass\n"
                "out['fds']=fds\n"

                "s=socket.socket(); s.settimeout(0.6)\n"
                "try:\n"
                f"    s.connect({PROBE_ADDR!r}); out['connect']='CONNECTED'\n"
                "except OSError as e:\n"
                "    out['connect']='BLOCKED:'+type(e).__name__\n"
                "out['cgroup']=open('/proc/self/cgroup').read().strip()\n"
                "out['uid']=[os.getuid(),os.geteuid(),os.getgid(),os.getegid()]\n"
                "out['groups']=os.getgroups()\n"
                "out['caps']=[l.split()[1] for l in open('/proc/self/status') if l.startswith(('CapEff','CapPrm','CapBnd'))]\n"
                "out['nnp']=[l.split()[1] for l in open('/proc/self/status') if l.startswith('NoNewPrivs')]\n"
                "try:\n"
                "    socket.socket(socket.AF_UNIX); out['unix']='CREATED'\n"
                "except OSError as e:\n"
                "    out['unix']='DENIED:'+type(e).__name__\n"
                "import ctypes\n"
                "libc=ctypes.CDLL(None,use_errno=True)\n"
                "p=ctypes.create_string_buffer(120)\n"
                "r=libc.syscall(425,4,p)\n"
                "out['io_uring']='CREATED' if r>=0 else 'DENIED:%d' % ctypes.get_errno()\n"
                "out['read']={}\n"
                f"for p in {list(self.forbidden)!r}:\n"
                "    try:\n"
                "        open(p,'rb').read(1); out['read'][p]='READ'\n"
                "    except OSError as e:\n"
                "        out['read'][p]='DENIED:'+type(e).__name__\n"
                "try:\n"
                f"    os.kill({self.protected_pid},0); out['signal']='ALLOWED'\n"
                "except OSError as e:\n"
                "    out['signal']='DENIED:'+type(e).__name__\n"
                "print(json.dumps(out))\n"
            )
            self._check_cancelled()          # last point before anything runs in the cgroup
            pr = self._o._run(self.wrap([sys.executable, "-I", "-c", probe]), stdin=subprocess.DEVNULL,
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
            reads = seen.get("read") if isinstance(seen.get("read"), dict) else {}
            uid_ok = seen.get("uid") == [self.uid, self.uid, self.uid, self.uid] and seen.get("groups") == []
            caps_ok = (isinstance(seen.get("caps"), list) and len(seen["caps"]) == 3
                       and all(int(c, 16) == 0 for c in seen["caps"]) and seen.get("nnp") == ["1"])
            files_ok = (set(reads) == set(self.forbidden)
                        and all(str(v).startswith("DENIED:") for v in reads.values()))
            unix_ok = (str(seen.get("unix", "")).startswith("DENIED:")
                       and str(seen.get("io_uring", "")).startswith("DENIED:"))
            fds = seen.get("fds") if isinstance(seen.get("fds"), dict) else None
            # only stdin (/dev/null), stdout/stderr (pipes) and the directory being listed:
            # nothing inherited - no socket, no terminal, no file of the control plane
            fds_ok = (fds is not None and fds.get("0") == "/dev/null"
                      and all(not str(t).startswith(("socket:", "/dev/pts", "/dev/tty", "anon_inode:"))
                              for t in fds.values())
                      and all(k in ("0", "1", "2") or str(t).startswith("/proc/") for k, t in fds.items()))
            signal_ok = str(seen.get("signal", "")).startswith("DENIED:")
            self.evidence = {"mechanism": self._o.mechanism, "cgroup": self.name,
                             "worker_uid": self.uid, "pinned": f"{self.ip}:{self.port}",
                             "pinned_extra": [f"{i}:{p}" for i, p in self.extra],
                             "probe_connect": seen.get("connect"), "probe_in_cgroup": in_cgroup,
                             "kernel_dropped_packets": counted,
                             "separate_uid": uid_ok, "no_capabilities": caps_ok,
                             "unix_sockets": seen.get("unix"), "io_uring": seen.get("io_uring"),
                             "inherited_fds_clean": fds_ok,
                             "control_plane_signal": seen.get("signal"),
                             "protected_files_denied": files_ok, "protected_files": len(self.forbidden)}
            if not (in_cgroup and str(seen.get("connect", "")).startswith("BLOCKED:") and counted >= 1):
                raise ConfinementError(
                    "カーネル隔離が実際に適用されていることを確認できませんでした"
                    f"（cgroup内={in_cgroup}, 接続={seen.get('connect')}, 遮断数={counted}）")
            if not (uid_ok and caps_ok and files_ok and unix_ok and signal_ok and fds_ok):
                raise ConfinementError(
                    "Worker の権限分離を確認できませんでした"
                    f"（UID={seen.get('uid')}, 権限なし={caps_ok}, UNIXソケット={seen.get('unix')}, "
                    f"io_uring={seen.get('io_uring')}, 継承fd={fds}, "
                    f"保護ファイル={reads}, シグナル={seen.get('signal')}）")
        except ConfinementError:
            raise
        except (OSError, subprocess.SubprocessError) as e:
            raise ConfinementError(f"カーネル隔離を適用できません（{type(e).__name__}）") from None

    def _listing(self) -> str:
        p = self._nft("list", "table", "inet", self.name, timeout=10)
        return p.stdout if p.returncode == 0 else ""

    def still_enforced(self) -> bool:
        """Asked again right before the worker starts and after it ends."""
        try:
            return _table_is_live(self._listing(), self.name)
        except (OSError, subprocess.SubprocessError):
            return False

    def empty(self) -> bool:
        """True only when the cgroup is known to hold no process (or is gone), and
        the session is not in the middle of being applied (a stop has to wait for
        that, or report itself unconfirmed)."""
        if getattr(self, "_entering", False):
            return False
        try:
            return (self.cgroup / "cgroup.procs").read_text().strip() == ""
        except FileNotFoundError:
            return True
        except OSError:
            return False

    def kill(self) -> bool:
        """Kill everything in the cgroup (the worker may have been started through
        sudo, so signalling our own child is not enough). A session killed before
        its cgroup exists is cancelled: it will refuse to be applied."""
        self._cancelled = True       # whatever state it is in, nothing more starts in it
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
                removed = (self._sh('rmdir "$1"', str(self.cgroup), timeout=10).returncode == 0
                           or not self.cgroup.exists())      # already gone (e.g. re-attached after a restart)
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
        elif self.on_leftover is not None:
            # something in the cgroup could not be killed: the caller keeps it on
            # record (blocks new launches, keeps killing, reports the stop unconfirmed)
            try:
                self.on_leftover(self)
            except Exception:
                pass
