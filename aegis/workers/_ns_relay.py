"""TCP relay into a confined planner's network namespace.

The planner runs in a network namespace of its own that contains only `lo`: nothing
of the host - its loopback services included - is reachable from there. This relay
is the planner's only way out, to exactly the endpoints it is given:

  * started as root (through sudo) INSIDE the run's cgroup, in the host namespace;
  * enters the planner's namespace just long enough to open one listening socket
    per endpoint on 127.0.0.1:<port> there, then returns to the host namespace;
  * drops to the run's own unprivileged uid (no capabilities, no_new_privs);
  * forwards each accepted connection to 127.0.0.1:<the same port> in the host
    namespace - where the run's nftables rules (cgroup match) allow exactly these
    endpoints and drop everything else.

Usage: python -I _ns_relay.py <netns-name> <uid> <port> [<port> ...]
Prints "READY" once listening. Standard library only; no secrets on argv."""
import ctypes
import os
import socket
import sys
import threading

CLONE_NEWNET = 0x40000000
PR_SET_NO_NEW_PRIVS = 38


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
        try:
            upstream = socket.create_connection(("127.0.0.1", port), timeout=10)
            upstream.settimeout(None)
        except OSError:
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
    threads = [threading.Thread(target=_serve, args=(s, p), daemon=True) for s, p in listeners]
    for t in threads:
        t.start()
    print("READY", flush=True)
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
