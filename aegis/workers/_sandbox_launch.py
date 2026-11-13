"""Starts a confined worker with UNIX-domain sockets disabled by the kernel.

Runs as the worker's own (unprivileged, unshared) uid, immediately before the
worker program. It sets no_new_privs and installs a seccomp filter that makes
socket(AF_UNIX, ...) and socketpair(AF_UNIX, ...) fail with EPERM, then execs
the worker; the filter is inherited and cannot be removed. Any failure to
install it ends the run (exit 97): nothing runs without it.

Usage: python -I _sandbox_launch.py [--profile=planner] <program> [args...]

`--profile=planner` (the ARTEX planner): sockets of the IP families only (AF_INET,
AF_INET6 - no netlink, vsock, packet, ...), no socketpair, and the system calls a
planner never needs are refused (bpf, userfaultfd, perf_event_open, keys, ptrace,
process_vm_*, mount family, chroot, kexec, kernel modules, file handles, swap,
reboot, acct, quotactl, iopl/ioperm). Without it, the L2 worker filter is unchanged.
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
AF_INET, AF_INET6 = 2, 10
# --profile=planner: refused with EPERM (numbers per architecture)
PLANNER_DENY = {
    "x86_64": (321, 323, 298, 250, 248, 249, 101, 310, 311, 165, 166, 155, 161, 246, 320, 175, 313,
               176, 304, 303, 167, 168, 169, 163, 179, 172, 173, *range(428, 434), 442),
    # bpf userfaultfd perf_event_open keyctl add_key request_key ptrace process_vm_readv/writev
    # mount umount2 pivot_root chroot kexec_load kexec_file_load init_module finit_module
    # delete_module open_by_handle_at name_to_handle_at swapon swapoff reboot acct quotactl iopl ioperm
    "aarch64": (280, 282, 241, 219, 217, 218, 117, 270, 271, 40, 39, 41, 51, 104, 294, 105, 273,
                106, 265, 264, 224, 225, 142, 89, 60, *range(428, 434), 442),
    # (both) open_tree move_mount fsopen fsconfig fsmount fspick, mount_setattr
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


def filter_program(cfg: dict, planner: bool = False, deny: tuple = ()) -> bytes:
    """Refuse: UNIX-domain sockets, io_uring, new user namespaces (unshare, setns,
    clone with CLONE_NEWUSER; clone3 -> ENOSYS so the C library falls back to
    clone). Kill: any other ABI (i386, x32). Allow everything else."""
    eq = lambda nr, target: (JEQ, target, 0, nr)
    if planner:
        return _assemble([
            (LD, 0, 0, 4),
            (JEQ, 0, "kill", cfg["arch"]),
            (LD, 0, 0, 0),
            (JGE, "kill", 0, 0x40000000),
            eq(IO_URING[0], "eperm"), eq(IO_URING[1], "eperm"), eq(IO_URING[2], "eperm"),
            eq(cfg["unshare"], "eperm"), eq(cfg["setns"], "eperm"),
            eq(cfg["clone3"], "enosys"),
            eq(cfg["clone"], "clone"),
            eq(cfg["socketpair"], "eperm"),
            eq(cfg["socket"], "domain"),
            *[eq(nr, "eperm") for nr in deny],
            (RET, 0, 0, RET_ALLOW),
            ("label", "domain"),
            (LD, 0, 0, 16),                             # args[0]: domain - IP families only
            (JEQ, "allow", 0, AF_INET),
            (JEQ, "allow", "eperm", AF_INET6),
            ("label", "clone"),
            (LD, 0, 0, 16),
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


def install(planner: bool = False) -> None:
    if not sys.platform.startswith("linux"):
        raise OSError("seccomp is Linux only")
    machine = platform.machine()
    if machine not in ARCHES:
        raise OSError(f"unsupported architecture {machine}")
    raw = filter_program(ARCHES[machine], planner, PLANNER_DENY[machine] if planner else ())
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
    args = sys.argv[1:]
    planner = bool(args) and args[0] == "--profile=planner"
    if planner:
        args = args[1:]
    if not args or args[0].startswith("--profile"):
        sys.exit(97)
    try:
        install(planner)
    except Exception as e:                       # no filter, no worker
        print(f"sandbox: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(97)
    os.execv(args[0], args)


if __name__ == "__main__":
    main()
