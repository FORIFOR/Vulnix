"""The privilege broker: the ONLY program the Vulnix service may run as root.

The service runs as an unprivileged user. Kernel confinement of a worker run
(aegis/confinement.py) needs root for a handful of steps: create / limit / freeze /
kill / remove the run's cgroup, apply / list / delete the run's nftables table, add /
delete the run's network namespace, hand an empty directory to the run's uid, and
start a program inside the cgroup AS the run's uid (never as root). This program
performs exactly those operations, each one with arguments it validates itself, and
nothing else: there is no shell, no free command, no path or environment of the
caller's choosing that runs with root privileges.

    sudo -n /usr/local/libexec/vulnix-priv OP ARG...

Installed root-owned and read-only (the wrapper runs `/usr/bin/python3 -I -B` on this
file inside the root-owned installation; sudoers names only the wrapper, without
SETENV). Standard library only, apart from the installation's own aegis.confinement
and aegis.netfilter, which are themselves standard library only.

Exit codes: 0 done, 1 the operation failed, 2 refused (invalid request).
"""
from __future__ import annotations

import json
import os
import pwd
import grp
import resource
import stat
import subprocess
import sys
from pathlib import Path

if __package__ in (None, ""):
    # run as a file (`python3 -I privbroker.py`): import from the installation this
    # file is part of (root-owned in production), never from the caller's directories
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from aegis.confinement import (ConfinementError, KernelConfinement, _NAME, _ENV_NAME,  # noqa: E402
                                   _system_which, ns_script, ruleset)
else:
    from .confinement import ConfinementError, KernelConfinement, _NAME, _ENV_NAME, _system_which, ns_script, ruleset

CGROUP_ROOT = Path("/sys/fs/cgroup")
NETNS_DIR = Path("/run/netns")
ENV_PREFIX = "VXENV_"                 # the worker's variables travel under this prefix
WORKER_PATH = "/usr/bin:/bin"
LIMIT_KEYS = ("pids.max", "memory.max")
SHARED_TMP = ("/tmp", "/var/tmp", "/dev/shm")
RELAY = Path(__file__).resolve().parent / "workers" / "_ns_relay.py"


class Refused(Exception):
    """The request is not one this broker performs."""


# ---- validation ----------------------------------------------------------------------
def _name(s: str) -> str:
    if not isinstance(s, str) or not _NAME.fullmatch(s):
        raise Refused("invalid run name")
    return s


def _run_uid(s: str) -> int:
    """A worker uid: in the reserved range and not a user or group of this host."""
    try:
        uid = int(s, 10)
    except (TypeError, ValueError):
        raise Refused("invalid uid") from None
    lo, hi = KernelConfinement.UID_RANGE
    if str(uid) != s or not lo <= uid < hi:
        raise Refused("uid outside the worker range")
    for lookup in (pwd.getpwuid, grp.getgrgid):
        try:
            lookup(uid)
        except KeyError:
            continue
        raise Refused("uid belongs to an account of this host")
    return uid


def _int(s: str, lo: int, hi: int, what: str) -> int:
    try:
        v = int(s, 10)
    except (TypeError, ValueError):
        raise Refused(f"invalid {what}") from None
    if str(v) != s or not lo <= v <= hi:
        raise Refused(f"invalid {what}")
    return v


def _abs_path(s: str) -> str:
    if (not isinstance(s, str) or not s.startswith("/") or os.path.normpath(s) != s or s == "/"
            or any(c in s for c in "\0\n\r") or "/../" in s + "/" or len(s) > 1024):
        raise Refused("invalid path")
    return s


def _caller_uid() -> int:
    """The service user that asked (sudo sets SUDO_UID; a direct root call is uid 0)."""
    v = os.environ.get("SUDO_UID")
    if os.getuid() == 0 and v is not None:
        return _int(v, 0, 2**32 - 1, "caller")
    return os.getuid()


def _open_dir(path: str):
    """Open `path` as a directory without following any symlink on the way. Every
    ancestor must be root's or the caller's and not writable by others (sticky
    directories such as /tmp allowed). Returns (parent_fd, last_name, fd)."""
    caller = _caller_uid()
    parts = Path(_abs_path(path)).parts[1:]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open("/", flags)
    try:
        for comp in parts[:-1]:
            st = os.fstat(fd)
            if st.st_uid not in (0, caller) or (st.st_mode & 0o022 and not st.st_mode & 0o1000):
                raise Refused("unsafe ancestor directory")
            nfd = os.open(comp, flags, dir_fd=fd)
            os.close(fd)
            fd = nfd
        st = os.fstat(fd)
        if st.st_uid not in (0, caller) or (st.st_mode & 0o022 and not st.st_mode & 0o1000):
            raise Refused("unsafe parent directory")
        last = os.open(parts[-1], flags, dir_fd=fd)
    except OSError:
        os.close(fd)
        raise Refused("directory not found or not a plain directory") from None
    except Refused:
        os.close(fd)
        raise
    return fd, parts[-1], last


def _cgroup(name: str) -> Path:
    return CGROUP_ROOT / _name(name)


def _tool(name: str) -> str:
    path = _system_which(name)
    if not path:
        raise RuntimeError(f"{name} not found")
    return path


def _run(argv: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=30,
                          env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}, **kw)


def _drop(uid: int) -> list[str]:
    return [_tool("setpriv"), f"--reuid={uid}", f"--regid={uid}", "--clear-groups",
            "--inh-caps=-all", "--bounding-set=-all", "--no-new-privs"]


def _join(name: str, cpu_seconds: int) -> None:
    """Move THIS process into the run's cgroup, then refuse a frozen (stopped) one:
    a process that joins a moment after the stop is frozen on arrival and refuses
    here once thawed. Everything exec'd from here on runs inside the cgroup."""
    cg = _cgroup(name)
    with open(cg / "cgroup.procs", "w") as f:
        f.write(str(os.getpid()))
    if (cg / "cgroup.freeze").read_text().strip() != "0":
        sys.exit(97)
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))


def _worker_env(keys: list[str]) -> dict:
    env = {"PATH": WORKER_PATH}
    for k in keys:
        if not _ENV_NAME.fullmatch(k) or k == "PATH":
            raise Refused("invalid environment variable name")
        v = os.environ.get(ENV_PREFIX + k)
        if v is not None:
            env[k] = v
    return env


# ---- operations ----------------------------------------------------------------------
def op_check(args):
    if args or os.geteuid() != 0:
        raise Refused("check takes no arguments and needs root")
    print("ok")
    return 0


def op_cgroup_create(args):
    (name,) = args
    cg = _cgroup(name)
    os.mkdir(cg, 0o755)
    if not ((cg / "cgroup.kill").exists() and (cg / "cgroup.freeze").exists()):
        os.rmdir(cg)
        print("cgroup.kill / cgroup.freeze missing (Linux 5.14 or later)", file=sys.stderr)
        return 3
    return 0


def op_cgroup_limit(args):
    name, key, value = args
    if key not in LIMIT_KEYS:
        raise Refused("limit not allowed")
    value = str(_int(value, 1, 1 << 50, "limit"))
    cg = _cgroup(name)
    f = cg / key
    if not f.exists():
        with open(CGROUP_ROOT / "cgroup.subtree_control", "w") as sc:
            sc.write("+" + key.split(".", 1)[0])
    with open(f, "w") as fh:
        fh.write(value)
    return 0 if f.read_text().strip() == value else 1


def op_cgroup_kill(args):
    (name,) = args
    cg = _cgroup(name)
    ok = True
    for knob in ("cgroup.freeze", "cgroup.kill"):     # freeze first; the kill is always tried
        try:
            with open(cg / knob, "w") as fh:
                fh.write("1")
        except OSError:
            ok = False
    return 0 if ok else 1


def op_cgroup_remove(args):
    (name,) = args
    os.rmdir(_cgroup(name))
    return 0


def op_nft_apply(args):
    name, *endpoints = args
    eps = []
    for e in endpoints:
        ip, sep, port = e.rpartition(",")
        if not sep:
            raise Refused("endpoint must be ip,port")
        eps.append((ip, _int(port, 1, 65535, "port")))
    if not eps:
        raise Refused("no endpoint")
    rules = ruleset(_name(name), eps[0][0], eps[0][1], tuple(eps[1:]))
    p = _run([_tool("nft"), "-f", "-"], input=rules)
    sys.stderr.write(p.stderr[-400:])
    return 0 if p.returncode == 0 else 1


def op_nft_list(args):
    (name,) = args
    name = _name(name)                 # validated before anything else
    p = _run([_tool("nft"), "list", "table", "inet", _name(name)])
    sys.stdout.write(p.stdout)
    return 0 if p.returncode == 0 else 1


def op_nft_delete(args):
    (name,) = args
    name = _name(name)                 # validated before anything else
    return 0 if _run([_tool("nft"), "delete", "table", "inet", _name(name)]).returncode == 0 else 1


def op_netns_add(args):
    (name,) = args
    name = _name(name)                 # validated before anything else
    ip = _tool("ip")
    p = _run([ip, "netns", "add", _name(name)])
    if p.returncode != 0:
        sys.stderr.write(p.stderr[-400:])
        return 1
    if _run([ip, "netns", "exec", name, ip, "link", "set", "lo", "up"]).returncode != 0:
        _run([ip, "netns", "delete", name])
        print("could not bring lo up", file=sys.stderr)
        return 1
    return 0


def op_netns_delete(args):
    (name,) = args
    name = _name(name)                 # validated before anything else
    return 0 if _run([_tool("ip"), "netns", "delete", _name(name)]).returncode == 0 else 1


def op_own_dir(args):
    """Give the caller's own EMPTY directory to the run's uid, mode 0700."""
    uid_s, path = args
    uid = _run_uid(uid_s)
    parent, _, fd = _open_dir(path)
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != _caller_uid():
            raise Refused("not the caller's directory")
        if os.listdir(fd):
            raise Refused("directory not empty")
        os.fchown(fd, uid, uid)
        os.fchmod(fd, 0o700)
    finally:
        os.close(fd)
        os.close(parent)
    return 0


def op_remove_dir(args):
    """Remove the (empty) directory a run was given."""
    uid_s, path = args
    uid = _run_uid(uid_s)
    parent, last, fd = _open_dir(path)
    try:
        if os.fstat(fd).st_uid not in (uid, _caller_uid()):
            raise Refused("not the run's directory")
        os.rmdir(last, dir_fd=parent)
    finally:
        os.close(fd)
        os.close(parent)
    return 0


def op_purge_dir(args):
    """Delete the contents of a directory AS the run's uid (it can delete only what that uid can)."""
    uid_s, path = args
    uid, path = _run_uid(uid_s), _abs_path(path)
    p = _run([*_drop(uid), _tool("find"), path, "-xdev", "-mindepth", "1", "-delete"], timeout=60)
    return 0 if p.returncode == 0 else 1


def op_purge_tmp(args):
    """Delete the run uid's own files in the shared temporary directories, AS that uid."""
    (uid_s,) = args
    uid = _run_uid(uid_s)
    find = _tool("find")
    for shared in SHARED_TMP:
        _run([*_drop(uid), find, shared, "-xdev", "-mindepth", "1", "-user", str(uid), "-delete"], timeout=60)
    return 0


def plan_launch(args):
    """launch NAME UID CPU ENV NS -- ARGV...: what op_launch will exec (validated).
    Join the cgroup, (NS) enter the run's network namespace and a private mount view,
    drop to the run's uid with no capabilities and no_new_privs, exec ARGV. ARGV never
    runs as root.
    ENV: comma-separated variable names (values come from VXENV_<NAME>), or "-".
    NS: JSON {"hide": [...], "keep": [...]}, or "-". Returns (name, cpu, argv, env)."""
    if len(args) < 7 or args[5] != "--":
        raise Refused("launch NAME UID CPU ENV NS -- ARGV...")
    name, uid_s, cpu_s, env_s, ns_s = args[:5]
    argv = args[6:]
    name, uid = _name(name), _run_uid(uid_s)
    cpu = _int(cpu_s, 1, 100000, "cpu seconds")
    env = _worker_env([] if env_s == "-" else env_s.split(","))
    if not argv[0].startswith("/"):
        raise Refused("program must be an absolute path")
    chain: list[str] = []
    if ns_s != "-":
        try:
            ns = json.loads(ns_s)
            hide = [_abs_path(h) for h in ns["hide"]]
            keep = [_abs_path(k) for k in ns["keep"]]
        except (ValueError, KeyError, TypeError):
            raise Refused("invalid namespace request") from None
        if set(ns) != {"hide", "keep"} or not hide:
            raise Refused("invalid namespace request")
        if not (NETNS_DIR / name).exists():
            raise Refused("the run's network namespace does not exist")
        # own IPC and PID namespaces as well; the mounts are made in the private view
        # `ip netns exec` creates, never in the host's
        chain = [_tool("ip"), "netns", "exec", name, _tool("unshare"), "--ipc", "--pid", "--fork",
                 _tool("sh"), "-c", ns_script(hide, keep), "sh"]
    return name, cpu, [*chain, *_drop(uid), *argv], env


def op_launch(args):
    name, cpu, full, env = plan_launch(args)
    _join(name, cpu)
    os.execve(full[0], full, env)


def op_relay(args):
    """relay NAME UID PORT...: the installed _ns_relay.py, started in the cgroup; it
    opens its listeners in the run's namespace and drops to the run's uid itself."""
    name, uid_s, *ports = args
    name, uid = _name(name), _run_uid(uid_s)
    ports = [str(_int(p, 1, 65535, "port")) for p in ports]
    if not ports or not (NETNS_DIR / name).exists():
        raise Refused("relay NAME UID PORT... for an existing namespace")
    _join(name, 100000)
    exe = sys.executable
    os.execve(exe, [exe, "-I", "-B", str(RELAY), name, str(uid), *ports], {"PATH": WORKER_PATH})


def op_netns_selftest(args):
    """The netfilter self-test (fixed parameters) as root; prints its JSON report."""
    if args:
        raise Refused("netns-selftest takes no arguments")
    if __package__ in (None, ""):
        from aegis.netfilter import verify_linux_netns_enforcement
    else:
        from .netfilter import verify_linux_netns_enforcement
    print(json.dumps(verify_linux_netns_enforcement()))
    return 0


OPS = {
    "check": op_check,
    "cgroup-create": op_cgroup_create, "cgroup-limit": op_cgroup_limit,
    "cgroup-kill": op_cgroup_kill, "cgroup-remove": op_cgroup_remove,
    "nft-apply": op_nft_apply, "nft-list": op_nft_list, "nft-delete": op_nft_delete,
    "netns-add": op_netns_add, "netns-delete": op_netns_delete,
    "own-dir": op_own_dir, "remove-dir": op_remove_dir,
    "purge-dir": op_purge_dir, "purge-tmp": op_purge_tmp,
    "launch": op_launch, "relay": op_relay, "netns-selftest": op_netns_selftest,
}


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in OPS:
        print("refused: unknown operation", file=sys.stderr)
        return 2
    try:
        return OPS[argv[0]](argv[1:]) or 0
    except (Refused, ConfinementError) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    except ValueError:               # wrong number of arguments
        print("refused: wrong arguments", file=sys.stderr)
        return 2
    except (OSError, RuntimeError, subprocess.SubprocessError) as e:
        print(f"failed: {type(e).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
