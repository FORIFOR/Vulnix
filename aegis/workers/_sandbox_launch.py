"""Starts a confined worker with UNIX-domain sockets disabled by the kernel.

Runs as the worker's own (unprivileged, unshared) uid, immediately before the
worker program. It sets no_new_privs and installs a seccomp filter that makes
socket(AF_UNIX, ...) and socketpair(AF_UNIX, ...) fail with EPERM, then execs
the worker; the filter is inherited and cannot be removed. Any failure to
install it ends the run (exit 97): nothing runs without it.

Usage: python -I _sandbox_launch.py <program> [args...]
Standard library only; no secrets on argv."""
import ctypes
import os
import platform
import struct
import sys

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
RET_KILL_PROCESS = 0x80000000
RET_ERRNO = 0x00050000
RET_ALLOW = 0x7FFF0000
EPERM = 1
ENOSYS = 38
AF_UNIX = 1
CLONE_NEWUSER = 0x10000000
# machine -> AUDIT_ARCH and the syscall numbers the filter looks at
ARCHES = {
    "x86_64": {"arch": 0xC000003E, "socket": 41, "socketpair": 53, "clone": 56,
               "unshare": 272, "setns": 308, "clone3": 435},
    "aarch64": {"arch": 0xC00000B7, "socket": 198, "socketpair": 199, "clone": 220,
                "unshare": 97, "setns": 268, "clone3": 435},
}
IO_URING = (425, 426, 427)   # io_uring_setup / _enter / _register (same on both): io_uring can
                             # create and connect sockets without passing through seccomp

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
        rel = lambda t: t if isinstance(t, int) else pos[t] - n - 1
        out.append(struct.pack("HBBI", code, rel(jt), rel(jf), k))
        n += 1
    return b"".join(out)


def filter_program(cfg: dict) -> bytes:
    """Refuse: UNIX-domain sockets, io_uring, new user namespaces (unshare, setns,
    clone with CLONE_NEWUSER; clone3 -> ENOSYS so the C library falls back to
    clone). Kill: any other ABI (i386, x32). Allow everything else."""
    eq = lambda nr, target: (JEQ, target, 0, nr)
    return _assemble([
        (LD, 0, 0, 4),                                  # arch
        (JEQ, 0, "kill", cfg["arch"]),
        (LD, 0, 0, 0),                                  # syscall nr
        (JGE, "kill", 0, 0x40000000),                   # x32 ABI
        eq(IO_URING[0], "eperm"), eq(IO_URING[1], "eperm"), eq(IO_URING[2], "eperm"),
        eq(cfg["unshare"], "eperm"), eq(cfg["setns"], "eperm"),
        eq(cfg["clone3"], "enosys"),
        eq(cfg["clone"], "clone"),
        eq(cfg["socket"], "domain"), eq(cfg["socketpair"], "domain"),
        (RET, 0, 0, RET_ALLOW),
        ("label", "domain"),
        (LD, 0, 0, 16),                                 # args[0] low 32 bits: domain
        (JEQ, "eperm", "allow", AF_UNIX),
        ("label", "clone"),
        (LD, 0, 0, 16),                                 # args[0]: clone flags (x86_64 and aarch64)
        (JSET, "eperm", "allow", CLONE_NEWUSER),
        ("label", "allow"),
        (RET, 0, 0, RET_ALLOW),
        ("label", "eperm"),
        (RET, 0, 0, RET_ERRNO | EPERM),
        ("label", "enosys"),
        (RET, 0, 0, RET_ERRNO | ENOSYS),
        ("label", "kill"),
        (RET, 0, 0, RET_KILL_PROCESS),
    ])


def _ins(code, jt, jf, k):
    return struct.pack("HBBI", code, jt, jf, k)


def install() -> None:
    if not sys.platform.startswith("linux"):
        raise OSError("seccomp is Linux only")
    machine = platform.machine()
    if machine not in ARCHES:
        raise OSError(f"unsupported architecture {machine}")
    raw = filter_program(ARCHES[machine])
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))     # no core file with the tokens in it (kept across exec)

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


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(97)
    try:
        install()
    except Exception as e:                       # no filter, no worker
        print(f"sandbox: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(97)
    os.execv(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
