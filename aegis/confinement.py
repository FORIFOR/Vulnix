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
# after joining: a frozen cgroup (killed by a stop) is never run in - a process that
# joins a moment after the stop is frozen on arrival and refuses here once thawed
_ENTER = ('echo $$ > "$1" || exit 97; [ "$(cat "${1%/*}/cgroup.freeze" 2>/dev/null)" = 0 ] || exit 97; '
          'ulimit -t "$2" 2>/dev/null; shift 2; exec "$@"')


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
                 cgroup_root: Path = CGROUP_ROOT, euid: int | None = None, which=_system_which,
                 popen=subprocess.Popen):
        self._run = runner
        self._popen = popen
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
        sess.extra, sess._owned, sess.limits, sess.files_left = (), [], {}, False
        # a namespace of a run left behind is deleted with it - only when there is one
        # (an L2-only host may have no iproute2 at all)
        sess.ns, sess._relay, sess.netns_left = None, None, False
        sess._netns = Path(f"/run/netns/{name}").exists()
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
                extra_endpoints: tuple = (), limits: dict | None = None,
                namespaces: dict | None = None) -> "ConfinementSession":
        """`forbidden_paths`: files the worker must not be able to read (verified
        by the probe before the worker starts); `protected_pid`: a process the
        worker must not be able to signal (the control plane)."""
        st = self.status()
        if not st["ok"]:
            raise ConfinementError(st["reason"])
        return ConfinementSession(self, ip, int(port), forbidden_paths=tuple(str(p) for p in forbidden_paths),
                                  protected_pid=protected_pid if protected_pid is not None else os.getpid(),
                                  extra_endpoints=tuple((str(i), int(p)) for i, p in extra_endpoints),
                                  limits=dict(limits or {}), namespaces=namespaces)


class ConfinementSession:
    def __init__(self, owner: KernelConfinement, ip: str, port: int, *, forbidden_paths=(),
                 protected_pid: int | None = None, extra_endpoints: tuple = (), limits: dict | None = None,
                 namespaces: dict | None = None):
        self._o = owner
        self.ip, self.port = ip, port
        self.extra = tuple(extra_endpoints)
        # cgroup resource limits, e.g. {"pids.max": 256, "memory.max": 1 << 30}; applied
        # before anything runs in the cgroup, or the session is not created
        self.limits = {k: int(v) for k, v in (limits or {}).items() if k in ("pids.max", "memory.max")}
        self.files_left = False
        self._owned: list[Path] = []          # directories given to this run's uid
        # namespaces={"hide": [...], "keep": [...]}: the program runs in a network
        # namespace of its own (only `lo`; the pinned endpoints reachable through a relay
        # in this cgroup) and a private mount view (`hide` covered by empty tmpfs, `keep`
        # bound back), with fresh /proc (hidepid) and the planner seccomp profile.
        self.ns = None
        if namespaces is not None:
            eps = [(self.ip, int(self.port)), *self.extra]
            if any(i != "127.0.0.1" for i, _ in eps):
                raise ConfinementError("名前空間隔離の接続先は 127.0.0.1 のみ指定できます")
            self.ns = {"hide": [str(Path(h)) for h in namespaces.get("hide", ())],
                       "keep": [str(Path(k)) for k in namespaces.get("keep", ())],
                       "ports": sorted({int(pt) for _, pt in eps})}
        self._netns = False
        self._relay = None
        self.netns_left = False
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
        profile = ["--profile=planner"] if self.ns is not None else []
        launch = [interpreter or mapped[0], "-I", str(staged / "_sandbox_launch.py"), *profile, *mapped]
        # in namespace mode: into the run's network namespace and a private mount view
        # (still root: the mounts are made there), and only then dropped to the uid
        ns = self._ns_chain(staged) if self.ns is not None else []
        if self._o._euid == 0:
            return [*enter, *ns, *drop, *launch]
        keep = [f"--preserve-env={','.join(keys)}"] if keys else []
        return [*self._o._priv(), *keep, *enter, *ns, *drop, *launch]

    def _keep_paths(self, staged: Path) -> list[str]:
        """What must stay visible under a hidden directory: given paths, the staged
        launcher and the interpreter's installation."""
        cands = [*self.ns["keep"], str(staged), sys.base_prefix, str(Path(os.path.realpath(sys.executable)).parent)]
        hide = self.ns["hide"]
        out = []
        for c in cands:
            c = str(Path(c))
            if any(c == h or c.startswith(h.rstrip("/") + "/") for h in hide) and c not in out:
                out.append(c)
        return out

    def _ns_chain(self, staged: Path) -> list[str]:
        import shlex
        q = shlex.quote
        keep = self._keep_paths(staged)
        hide = sorted({h for h in self.ns["hide"]}, key=lambda h: -h.count("/"))
        # -n everywhere: mount must not write its utab into the (empty) /run of the view
        lines = ["set -eu", "mount -n --make-rprivate /",
                 "mount -n -t tmpfs -o size=1m,mode=0700 vxstash /mnt"]
        for i, k in enumerate(keep):
            lines += [f"mkdir /mnt/k{i}", f"mount -n --bind {q(k)} /mnt/k{i}"]
        for h in hide:
            if h == "/mnt":
                continue                     # the stash itself: covered after it is gone
            mode = "1777" if h in ("/tmp", "/var/tmp", "/dev/shm") else "0755"
            lines.append(f"if [ -d {q(h)} ]; then mount -n -t tmpfs -o mode={mode},nosuid,nodev,size=64m vxhide {q(h)}; fi")
        for i, k in enumerate(keep):
            lines += [f"mkdir -p {q(k)}", f"mount -n --bind /mnt/k{i} {q(k)}"]
        lines += ["umount -n -l /mnt"]
        if "/mnt" in hide:
            lines.append("mount -n -t tmpfs -o mode=0755,nosuid,nodev,size=1m vxhide /mnt")
        lines += [
                  # a fresh /proc of this run's own PID namespace: nothing else is visible
                  "mount -n -t proc -o hidepid=invisible,subset=pid vxproc /proc",
                  # no working directory of the caller (it may lie under a hidden path)
                  "cd /",
                  'exec "$@"']
        ip = self._ip()
        unshare = self._o._which("unshare")
        if not unshare:
            raise ConfinementError("unshare が見つかりません")
        # own IPC (no SysV / POSIX IPC of the host) and PID namespaces as well
        return [ip, "netns", "exec", self.name, unshare, "--ipc", "--pid", "--fork",
                self._o._which("sh") or "sh", "-c", "\n".join(lines), "sh"]

    def _ip(self) -> str:
        ip = self._o._which("ip")
        if not ip:
            raise ConfinementError("ip（iproute2）が見つかりません")
        return ip

    def _setup_netns(self) -> None:
        """The run's network namespace (only `lo`, up) and the relay into it, started
        inside this run's cgroup (so the pinned rules apply to its upstream side)."""
        ip = self._ip()
        r = self._o._run([*self._o._priv(), ip, "netns", "add", self.name], capture_output=True, text=True,
                         timeout=10)
        if r.returncode != 0:
            raise ConfinementError(f"ネットワーク名前空間を作成できません: {r.stderr.strip()[:200]}")
        self._netns = True
        r = self._o._run([*self._o._priv(), ip, "netns", "exec", self.name, ip, "link", "set", "lo", "up"],
                         capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            raise ConfinementError("名前空間の lo を有効にできません")
        staged = self._o.staged_workers()
        enter = [self._o._which("sh") or "sh", "-c", _ENTER, "sh", str(self.cgroup / "cgroup.procs"), "100000"]
        argv = [*self._o._priv(), *enter, sys.executable, "-I", str(staged / "_ns_relay.py"),
                self.name, str(self.uid), *[str(pt) for pt in self.ns["ports"]]]
        self._relay = self._o._popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, close_fds=True, text=True)
        import select
        ready, _, _ = select.select([self._relay.stdout], [], [], 10)
        line = self._relay.stdout.readline().strip() if ready else ""
        if line != "READY":
            raise ConfinementError("名前空間への中継を起動できません")

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

    def _apply_limits(self) -> None:
        """Write the cgroup limits (enabling the controller in the parent if needed).
        Any failure means no session (fail closed)."""
        for key, value in self.limits.items():
            ctrl = key.split(".", 1)[0]
            f = self.cgroup / key
            if self._sh('test -e "$1"', str(f), timeout=10).returncode != 0:
                self._sh('echo "+$1" > "$2"', ctrl, str(self._o._root / "cgroup.subtree_control"), timeout=10)
            r = self._sh('echo "$1" > "$2" && test "$(cat "$2")" = "$1"', str(value), str(f), timeout=10)
            if r.returncode != 0:
                raise ConfinementError(f"cgroup の制限（{key}）を設定できません: {r.stderr.strip()[:200]}")

    def own_directory(self, path: str | os.PathLike) -> None:
        """Give an (empty) directory to this run's uid, mode 0700: the only place the
        confined program can write. Nothing else of ours becomes writable to it."""
        p = Path(path)
        if not p.is_dir() or p.is_symlink() or any(p.iterdir()):
            raise ConfinementError("隔離された実行用ディレクトリを準備できません")
        p = p.resolve()
        # every ancestor must be root's or ours and not writable by others (sticky dirs
        # such as /tmp allowed): the run's uid can never replace the path or a parent
        me = os.geteuid() if hasattr(os, "geteuid") else -1
        for anc in p.parents:
            st = anc.lstat()
            if st.st_uid not in (0, me) or (st.st_mode & 0o022 and not st.st_mode & 0o1000):
                raise ConfinementError(f"実行用ディレクトリの親 {anc} が安全ではありません")
        r = self._sh('chown -h "$1:$1" "$2" && chmod 700 "$2"', str(self.uid), str(p), timeout=10)
        if r.returncode != 0:
            raise ConfinementError(f"実行用ディレクトリの所有者を変更できません: {r.stderr.strip()[:200]}")
        self._owned.append(p)

    def _as_run_uid(self) -> list[str]:
        return [*self._o._priv(), self._o._which("setpriv") or "setpriv", f"--reuid={self.uid}",
                f"--regid={self.uid}", "--clear-groups", "--inh-caps=-all", "--bounding-set=-all",
                "--no-new-privs"]

    def _remove_owned(self) -> bool:
        """After the cgroup is empty: remove what this run's uid left - the directory it
        was given and its own files in the shared temp directories. Deleting is done AS
        that uid (no capabilities), so it can only ever delete what that uid could; only
        the then-empty directory is removed by us. True when everything is gone."""
        if not self._owned or self.uid is None:
            return True
        find = self._o._which("find") or "find"
        ok = True
        try:
            for p in self._owned:
                r = self._o._run([*self._as_run_uid(), find, str(p), "-xdev", "-mindepth", "1", "-delete"],
                                 capture_output=True, text=True, timeout=60)
                ok = ok and r.returncode == 0
                r = self._sh('rmdir -- "$1"', str(p), timeout=10)
                ok = ok and (r.returncode == 0 or not p.exists())
            for shared in ("/tmp", "/var/tmp", "/dev/shm"):
                self._o._run([*self._as_run_uid(), find, shared, "-xdev", "-mindepth", "1",
                              "-user", str(self.uid), "-delete"], capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            ok = False
        return ok

    def _apply_and_verify(self) -> None:
        rules = ruleset(self.name, self.ip, self.port, self.extra)
        self._check_cancelled()
        try:
            p = self._sh('mkdir "$1"', str(self.cgroup), timeout=10)
            if p.returncode != 0:
                raise ConfinementError(f"cgroup を作成できません: {p.stderr.strip()[:200]}")
            self._dir = True
            self._check_cancelled()          # stopped while the cgroup was being created
            if (self._sh('test -e "$1" && test -e "$2"', str(self.cgroup / "cgroup.kill"),
                         str(self.cgroup / "cgroup.freeze"), timeout=10).returncode != 0):
                raise ConfinementError("このカーネルには cgroup.kill / cgroup.freeze がありません（Linux 5.14 以降が必要です）")
            self._apply_limits()
            self._check_cancelled()
            p = self._nft("-f", "-", input=rules, timeout=10)
            if p.returncode != 0:
                raise ConfinementError(f"nftables ルールを適用できません: {p.stderr.strip()[:200]}")
            self._table = True
            before = self._listing()
            if not _table_is_live(before, self.name):
                raise ConfinementError("適用した nftables ルールをカーネルから確認できません")
            canary = None
            if self.ns is not None:
                self._check_cancelled()
                self._setup_netns()
                import socket as _socket
                canary = _socket.socket()
                canary.bind(("127.0.0.1", 0))
                canary.listen(4)
                canary.setblocking(False)
                self._canary_port = canary.getsockname()[1]
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
                + (self._ns_probe_code() if self.ns is not None else "")
                + "print(json.dumps(out))\n"
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
            ns_ok, ns_ev = True, {}
            if self.ns is not None:
                ns_ok, ns_ev = self._ns_verdict(seen, canary)
            self.evidence = {"mechanism": self._o.mechanism + (" + netns/mountns + planner seccomp"
                                                               if self.ns is not None else ""),
                             "cgroup": self.name, **ns_ev,
                             "worker_uid": self.uid, "pinned": f"{self.ip}:{self.port}",
                             "pinned_extra": [f"{i}:{p}" for i, p in self.extra],
                             "probe_connect": seen.get("connect"), "probe_in_cgroup": in_cgroup,
                             "kernel_dropped_packets": counted,
                             "separate_uid": uid_ok, "no_capabilities": caps_ok,
                             "unix_sockets": seen.get("unix"), "io_uring": seen.get("io_uring"),
                             "inherited_fds_clean": fds_ok,
                             "control_plane_signal": seen.get("signal"),
                             "protected_files_denied": files_ok, "protected_files": len(self.forbidden)}
            if not ns_ok:
                raise ConfinementError(f"名前空間隔離を確認できませんでした（{ns_ev}）")
            # in its own network namespace the host's rules never see the probe's packet
            # (there is no route at all): there the proof is the namespace verdict above
            dropped_ok = counted >= 1 if self.ns is None else True
            if not (in_cgroup and str(seen.get("connect", "")).startswith("BLOCKED:") and dropped_ok):
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

    def _ns_probe_code(self) -> str:
        import platform as _pf
        bpf = {"x86_64": 321, "aarch64": 280}.get(_pf.machine(), -1)
        hidden = [h for h in self.ns["hide"]]
        return (
            "out['netns']=os.readlink('/proc/self/ns/net')\n"
            "out['ifaces']=sorted(l.split(':')[0].strip() for l in open('/proc/self/net/dev').read().splitlines()[2:])\n"
            "c=socket.socket(); c.settimeout(0.6)\n"
            "try:\n"
            f"    c.connect(('127.0.0.1',{int(getattr(self, '_canary_port', 1))})); out['canary']='CONNECTED'\n"
            "except OSError as e:\n"
            "    out['canary']='BLOCKED:'+type(e).__name__\n"
            "out['relay']={}\n"
            f"for p in {self.ns['ports']!r}:\n"
            "    r=socket.socket(); r.settimeout(3)\n"
            "    try:\n"
            "        r.connect(('127.0.0.1',p)); out['relay'][str(p)]='OK'\n"
            "    except OSError as e:\n"
            "        out['relay'][str(p)]='FAILED:'+type(e).__name__\n"
            "    finally:\n"
            "        r.close()\n"
            "out['hidden']={}\n"
            f"for d in {hidden!r}:\n"
            "    try:\n"
            "        out['hidden'][d]=sorted(os.listdir(d))\n"
            "    except OSError as e:\n"
            "        out['hidden'][d]='GONE:'+type(e).__name__\n"
            "try:\n"
            "    socket.socket(16, socket.SOCK_RAW, 0); out['netlink']='CREATED'\n"
            "except OSError as e:\n"
            "    out['netlink']='DENIED:'+type(e).__name__\n"
            "try:\n"
            "    socket.socket(40, socket.SOCK_STREAM, 0); out['vsock']='CREATED'\n"
            "except OSError as e:\n"
            "    out['vsock']='DENIED:'+type(e).__name__\n"
            f"r=libc.syscall({bpf},0,0,0)\n"
            "out['bpf']='ALLOWED' if r>=0 else 'DENIED:%d' % ctypes.get_errno()\n"
            "out['procs_visible']=len([d for d in os.listdir('/proc') if d.isdigit()])\n"
            "out['seccomp']=[l.split()[1] for l in open('/proc/self/status') if l.startswith('Seccomp:')]\n"
        )

    def _ns_verdict(self, seen: dict, canary) -> tuple[bool, dict]:
        host_netns = os.readlink("/proc/self/ns/net") if os.path.exists("/proc/self/ns/net") else ""
        arrived = False
        if canary is not None:
            try:
                conn, _ = canary.accept()
                conn.close()
                arrived = True
            except (BlockingIOError, OSError):
                pass
            finally:
                canary.close()
        keep = set(self._keep_paths(self._o.staged_workers()))
        hidden = seen.get("hidden") if isinstance(seen.get("hidden"), dict) else {}

        def hidden_ok(d, v):
            if isinstance(v, str):
                return v.startswith("GONE:")
            # an empty tmpfs; under it only the bound-back paths' first components
            allowed = {Path(k).relative_to(d).parts[0] for k in keep
                       if k.startswith(d.rstrip("/") + "/")}
            return isinstance(v, list) and set(v) <= allowed
        relay = seen.get("relay") if isinstance(seen.get("relay"), dict) else {}
        ev = {
            "netns_separate": bool(seen.get("netns")) and seen.get("netns") != host_netns,
            "netns_interfaces": seen.get("ifaces"),
            "host_loopback_canary": seen.get("canary"),
            "host_loopback_canary_arrived": arrived,
            "relay_endpoints": relay,
            "hidden_paths_ok": bool(hidden) and set(hidden) == set(self.ns["hide"])
                               and all(hidden_ok(d, v) for d, v in hidden.items()),
            # which hidden path failed, and the first names visible there (names only)
            "hidden_paths_failed": {d: (v[:8] if isinstance(v, list) else v)
                                    for d, v in hidden.items() if not hidden_ok(d, v)},
            "netlink_socket": seen.get("netlink"), "vsock_socket": seen.get("vsock"),
            "bpf_syscall": seen.get("bpf"), "procs_visible": seen.get("procs_visible"),
            "seccomp_mode": seen.get("seccomp"),
        }
        ok = (ev["netns_separate"] and ev["netns_interfaces"] == ["lo"]
              and str(ev["host_loopback_canary"]).startswith("BLOCKED:") and not arrived
              and relay and all(v == "OK" for v in relay.values())
              and set(relay) == {str(pt) for pt in self.ns["ports"]}
              and ev["hidden_paths_ok"]
              # EPERM from the filter itself (not "module missing" / "disabled anyway")
              and ev["netlink_socket"] == "DENIED:PermissionError" and ev["vsock_socket"] == "DENIED:PermissionError"
              and ev["bpf_syscall"] == "DENIED:1" and ev["seccomp_mode"] == ["2"]
              and isinstance(ev["procs_visible"], int) and ev["procs_visible"] <= 8)
        return bool(ok), ev

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
            # freeze first: anything that joins after this write is stopped on arrival
            # (cgroup.kill acts only on the processes present at that moment); a frozen
            # process still dies from the kill, now and on every later write
            return self._sh('echo 1 > "$1"; echo 1 > "$2"', str(self.cgroup / "cgroup.freeze"),
                            str(self.cgroup / "cgroup.kill"), timeout=10).returncode == 0
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
            if removed and not self._remove_owned():
                self.files_left = True          # the cgroup is gone; files of the run remain
            if removed and self._table:
                self._nft("delete", "table", "inet", self.name, timeout=10)
            relay = getattr(self, "_relay", None)
            if relay is not None:
                try:
                    relay.wait(timeout=5)       # killed with the cgroup; reaped here
                except (subprocess.TimeoutExpired, OSError):
                    pass
            if removed and getattr(self, "_netns", False):
                ip = self._o._which("ip") or "/usr/sbin/ip"
                r = self._o._run([*self._o._priv(), ip, "netns", "delete", self.name],
                                 capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    self._netns = False
                else:
                    self.netns_left = True          # empty namespace: nothing runs in it
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
