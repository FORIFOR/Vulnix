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
AF_UNIX = 1
ARCHES = {  # machine -> (AUDIT_ARCH_*, __NR_socket, __NR_socketpair)
    "x86_64": (0xC000003E, 41, 53),
    "aarch64": (0xC00000B7, 198, 199),
}


def _ins(code, jt, jf, k):
    return struct.pack("HBBI", code, jt, jf, k)


IO_URING = (425, 426, 427)   # io_uring_setup / _enter / _register: same numbers on x86_64 and aarch64;
                             # io_uring can create and connect sockets without passing through seccomp


def filter_program(arch, nr_socket, nr_socketpair) -> bytes:
    LD, JEQ, JGE, RET = 0x20, 0x15, 0x35, 0x06
    prog = [
        _ins(LD, 0, 0, 4),                       # 0  arch
        _ins(JEQ, 1, 0, arch),                   # 1  -> 3 | 2
        _ins(RET, 0, 0, RET_KILL_PROCESS),       # 2  another ABI: never
        _ins(LD, 0, 0, 0),                       # 3  syscall nr
        _ins(JGE, 9, 0, 0x40000000),             # 4  x32 ABI -> 14 (kill)
        _ins(JEQ, 7, 0, IO_URING[0]),            # 5  -> 13 (EPERM)
        _ins(JEQ, 6, 0, IO_URING[1]),            # 6  -> 13
        _ins(JEQ, 5, 0, IO_URING[2]),            # 7  -> 13
        _ins(JEQ, 1, 0, nr_socket),              # 8  -> 10 | 9
        _ins(JEQ, 0, 2, nr_socketpair),          # 9  -> 10 | 12 (allow)
        _ins(LD, 0, 0, 16),                      # 10 args[0] (domain), low 32 bits
        _ins(JEQ, 1, 0, AF_UNIX),                # 11 -> 13 | 12
        _ins(RET, 0, 0, RET_ALLOW),              # 12
        _ins(RET, 0, 0, RET_ERRNO | EPERM),      # 13 refused
        _ins(RET, 0, 0, RET_KILL_PROCESS),       # 14
    ]
    return b"".join(prog)


def install() -> None:
    if not sys.platform.startswith("linux"):
        raise OSError("seccomp is Linux only")
    machine = platform.machine()
    if machine not in ARCHES:
        raise OSError(f"unsupported architecture {machine}")
    arch, nr_socket, nr_socketpair = ARCHES[machine]
    raw = filter_program(arch, nr_socket, nr_socketpair)

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
