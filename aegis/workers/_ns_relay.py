"""TCP relay into a confined planner's network namespace.

The planner runs in a network namespace of its own that contains only `lo`: nothing
of the host - its loopback services included - is reachable from there. This relay
is the planner's only way out, to exactly the endpoints it is given:

  * started as root (through sudo) INSIDE the run's cgroup, in the host namespace;
  * enters the planner's namespace just long enough to open one listening socket
    per endpoint on 127.0.0.1:<port> there, then returns to the host namespace;
  * drops to an unprivileged uid of its own - not the planner's (no capabilities,
    no_new_privs);
  * installs its own seccomp ALLOWLIST (`relay_filter_program`) before it handles any
    traffic: accept on the listeners it already has, AF_INET sockets and connect,
    send/recv, poll, close, threads, memory, exit. Everything else - open/openat,
    execve, fork, bind, listen, UNIX/netlink sockets, ptrace, kill, mount, ... - fails
    with EPERM; another ABI kills it. It cannot open a file or start a program;
  * forwards each accepted connection to 127.0.0.1:<the same port> in the host
    namespace - where the run's nftables rules (cgroup match) allow exactly these
    endpoints and drop everything else.

Usage: python -I _ns_relay.py <netns-name> <uid> <port> [<port> ...]
Prints "READY" once listening with the filter in place (exit 97 without it).
Standard library only; no secrets on argv."""
import ctypes
import os
import platform
import socket
import struct
import sys
import threading

CLONE_NEWNET = 0x40000000
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
RET_KILL_PROCESS = 0x80000000
RET_ERRNO = 0x00050000
RET_ALLOW = 0x7FFF0000
EPERM, ENOSYS = 1, 38
AF_INET = 2
CLONE_THREAD = 0x00010000
# CLONE_NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWUSER | NEWPID | NEWNET
CLONE_NEW_ANY = 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000
FIONBIO, FIOCLEX = 0x5421, 0x5451
# What the relay may do once it serves (numbers per architecture). socket, clone and
# ioctl are allowed only with the arguments checked below; clone3 -> ENOSYS so the C
# library starts threads through clone. Not here = EPERM.
RELAY_ALLOW = {
    "x86_64": {
        "read": 0, "write": 1, "close": 3, "poll": 7, "mmap": 9, "mprotect": 10, "munmap": 11, "brk": 12,
        "rt_sigaction": 13, "rt_sigprocmask": 14, "rt_sigreturn": 15, "sched_yield": 24, "mremap": 25,
        "madvise": 28, "nanosleep": 35, "getpid": 39, "connect": 42, "accept": 43, "sendto": 44,
        "recvfrom": 45, "sendmsg": 46, "recvmsg": 47, "shutdown": 48, "getsockname": 51, "getpeername": 52,
        "setsockopt": 54, "getsockopt": 55, "exit": 60, "fcntl": 72, "sigaltstack": 131, "gettid": 186,
        "futex": 202, "restart_syscall": 219, "clock_gettime": 228, "clock_nanosleep": 230,
        "exit_group": 231, "ppoll": 271, "set_robust_list": 273, "accept4": 288, "getrandom": 318,
        "rseq": 334,
    },
    "aarch64": {
        "fcntl": 25, "close": 57, "read": 63, "write": 64, "ppoll": 73, "exit": 93,
        "exit_group": 94, "futex": 98, "set_robust_list": 99, "nanosleep": 101, "clock_gettime": 113,
        "clock_nanosleep": 115, "sched_yield": 124, "restart_syscall": 128, "sigaltstack": 132,
        "rt_sigaction": 134, "rt_sigprocmask": 135, "rt_sigreturn": 139, "getpid": 172, "gettid": 178,
        "accept": 202, "connect": 203, "getsockname": 204, "getpeername": 205, "sendto": 206,
        "recvfrom": 207, "setsockopt": 208, "getsockopt": 209, "shutdown": 210, "sendmsg": 211,
        "recvmsg": 212, "brk": 214, "munmap": 215, "mremap": 216, "mmap": 222, "mprotect": 226,
        "madvise": 233, "accept4": 242, "getrandom": 278, "rseq": 293,
    },
}
RELAY_ARCHES = {
    "x86_64": {"arch": 0xC000003E, "socket": 41, "clone": 56, "ioctl": 16, "clone3": 435},
    "aarch64": {"arch": 0xC00000B7, "socket": 198, "clone": 220, "ioctl": 29, "clone3": 435},
}
LD, JEQ, JGE, JSET, RET = 0x20, 0x15, 0x35, 0x45, 0x06


def _assemble(items) -> bytes:
    """items: ("label", name) or (code, jt, jf, k) where jt/jf may be label names."""
    pos, n = {}, 0
    for it in items:
        if it[0] == "label":
            pos[it[1]] = n
        else:
            n += 1
    out, n = [], 0
    for it in items:
        if it[0] == "label":
            continue
        code, jt, jf, k = it
        rel = lambda t: t if isinstance(t, int) else pos[t] - n - 1      # noqa: E731
        out.append(struct.pack("HBBI", code, rel(jt), rel(jf), k))
        n += 1
    return b"".join(out)


def relay_filter_program(machine: str) -> bytes:
    """The relay's seccomp program: an allowlist (RELAY_ALLOW), socket() only for
    AF_INET, clone() only for a thread (CLONE_THREAD, no namespace flags), ioctl() only
    FIONBIO/FIOCLEX; any other system call fails with EPERM, any other ABI is killed."""
    cfg = RELAY_ARCHES[machine]
    allow = sorted(set(RELAY_ALLOW[machine].values()))
    return _assemble([
        (LD, 0, 0, 4),                                  # arch
        (JEQ, 0, "kill", cfg["arch"]),
        (LD, 0, 0, 0),                                  # syscall nr
        (JGE, "kill", 0, 0x40000000),                   # x32 ABI
        (JEQ, "enosys", 0, cfg["clone3"]),
        (JEQ, "socket", 0, cfg["socket"]),
        (JEQ, "clone", 0, cfg["clone"]),
        (JEQ, "ioctl", 0, cfg["ioctl"]),
        *[(JEQ, "allow", 0, nr) for nr in allow],
        (RET, 0, 0, RET_ERRNO | EPERM),
        ("label", "socket"),
        (LD, 0, 0, 16),                                 # args[0]: domain
        (JEQ, "allow", "eperm", AF_INET),
        ("label", "clone"),
        (LD, 0, 0, 16),                                 # args[0]: flags
        (JSET, "eperm", 0, CLONE_NEW_ANY),
        (JSET, "allow", "eperm", CLONE_THREAD),
        ("label", "ioctl"),
        (LD, 0, 0, 24),                                 # args[1]: request
        (JEQ, "allow", 0, FIONBIO),
        (JEQ, "allow", "eperm", FIOCLEX),
        ("label", "allow"),
        (RET, 0, 0, RET_ALLOW),
        ("label", "eperm"),
        (RET, 0, 0, RET_ERRNO | EPERM),
        ("label", "enosys"),
        (RET, 0, 0, RET_ERRNO | ENOSYS),
        ("label", "kill"),
        (RET, 0, 0, RET_KILL_PROCESS),
    ])


def install_relay_filter() -> None:
    """no_new_privs and the relay filter, for this thread and every thread it starts.
    Raises when either cannot be set."""
    if not sys.platform.startswith("linux"):
        raise OSError("seccomp is Linux only")
    machine = platform.machine()
    if machine not in RELAY_ARCHES:
        raise OSError(f"unsupported architecture {machine}")
    raw = relay_filter_program(machine)

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
    buf = ctypes.create_string_buffer(raw, len(raw))
    prog = SockFprog(len(raw) // 8, ctypes.cast(buf, ctypes.c_void_p))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.addressof(prog), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "seccomp filter not installed")


def _setns(fd: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.setns(fd, CLONE_NEWNET) != 0:
        raise OSError(ctypes.get_errno(), "setns failed")


def _pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _serve(listener: socket.socket, port: int) -> None:
    while True:
        try:
            client, _ = listener.accept()
        except OSError:
            return
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # an IP literal: no name lookup (which would open files the filter refuses)
            upstream.settimeout(10)
            upstream.connect(("127.0.0.1", port))
            upstream.settimeout(None)
        except OSError:
            upstream.close()
            client.close()
            continue
        threading.Thread(target=_pump, args=(client, upstream), daemon=True).start()
        threading.Thread(target=_pump, args=(upstream, client), daemon=True).start()


def main() -> None:
    if len(sys.argv) < 4:
        sys.exit(97)
    name, uid = sys.argv[1], int(sys.argv[2])
    ports = [int(p) for p in sys.argv[3:]]
    if not name.startswith("aegis_l2_") or "/" in name or uid <= 0 or not all(0 < p < 65536 for p in ports):
        sys.exit(97)
    host = os.open("/proc/self/ns/net", os.O_RDONLY)
    target = os.open(f"/run/netns/{name}", os.O_RDONLY)
    listeners = []
    _setns(target)                       # listen INSIDE the planner's namespace
    try:
        for p in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", p))
            s.listen(32)
            listeners.append((s, p))
    finally:
        _setns(host)                     # every later socket is a host-namespace socket
        os.close(target)
        os.close(host)
    # from here on: the run's own uid, nothing more
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        sys.exit(97)
    if os.getuid() != uid or os.geteuid() != uid or os.getgroups():
        sys.exit(97)
    try:
        install_relay_filter()          # before any traffic: no filter, no relay
    except Exception:
        sys.exit(97)
    threads = [threading.Thread(target=_serve, args=(s, p), daemon=True) for s, p in listeners]
    for t in threads:
        t.start()
    print("READY", flush=True)
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
