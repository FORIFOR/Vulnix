"""Local audit anchor: a separately privileged helper that remembers audit chain heads.

The service's audit log (aegis/audit.py) is a hash chain. A chain alone cannot show
that the newest entries were removed: an older, valid prefix still verifies, and the
service user can write both the log and its reservation file. This helper runs as a
DIFFERENT OS user, owns an append-only anchor file the service cannot write, and
accepts heads only forwards. The service can only talk to it over a Unix socket.

Helper side:  AnchorStore (the file) + AnchorServer (the socket)
Service side: AnchorClient
CLI:          python3 -m aegis.audit_anchor serve --dir DIR --socket PATH
              (or run this file directly: it imports the standard library only, so it
              can be installed alone in a directory the helper user can read)

Not protected: root, or anyone who can act as the helper user. See docs/AUDIT_ANCHOR.md.
"""
from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import re
import signal
import socket
import socketserver
import stat
import struct
import sys
import threading
import time
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - POSIX only, like aegis/audit.py
    fcntl = None

GENESIS = "0" * 64
ANCHOR_FILE = "anchors.jsonl"
SOCKET_ENV = "VULNIX_AUDIT_ANCHOR_SOCKET"
UID_ENV = "VULNIX_AUDIT_ANCHOR_UID"          # the helper's OS user id (verified per connection)
SOURCE_ENV = "VULNIX_AUDIT_ANCHOR_SOURCE"    # operator-chosen name of this installation
ENV_PREFIX = "VULNIX_AUDIT_ANCHOR_"          # never taken from .env.local (aegis/server.py)
_HASH = re.compile(r"[0-9a-f]{64}")
_SOURCE = re.compile(r"[A-Za-z0-9:._/-]{1,200}")
_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}")
_MAX_LINE = 4096


class AnchorError(ValueError):
    """The audit could not be anchored or verified. A ValueError, like every other audit
    failure, so audit-first callers do not apply the change they were about to make."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"audit anchor: {reason}")


class AnchorUnavailable(AnchorError):
    def __init__(self, reason: str = "anchor_unavailable"):
        super().__init__(reason)


class StoreRefused(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _valid_seq(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


# ---- helper side ---------------------------------------------------------------------
class AnchorStore:
    """Append-only JSONL of heads, itself hash-chained.

    Record: {"source", "seq", "hash", "ts", "prev", "anchor_hash"[, "reset": true]}
    A head is accepted only when seq > the source's last seq, or seq == last seq with
    the same hash (idempotent). Every operation re-reads the file when it changed on
    disk, so a restarted helper - or a second one - always works from the file."""

    def __init__(self, directory: str | Path):
        if fcntl is None:  # pragma: no cover
            raise StoreRefused("no_flock")
        self.dir = Path(directory)
        self.path = self.dir / ANCHOR_FILE
        self._lock = threading.Lock()
        self._heads: dict[str, dict] = {}
        self._tail = GENESIS
        self._sig = None
        self.error: str | None = None
        old = os.umask(0o077)
        try:
            self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._check_owned(self.dir, directory=True)
            if not os.access(self.dir, os.W_OK | os.X_OK):
                raise StoreRefused("store_unwritable")
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        except OSError:
            self.error = "store_unwritable"
            raise StoreRefused("store_unwritable") from None
        except StoreRefused as e:
            self.error = e.reason
            raise
        finally:
            os.umask(old)
        self._check_owned(self.path, directory=False)
        with self._lock, self._flock():
            self._sync_locked()

    def _check_owned(self, p: Path, directory: bool) -> None:
        """Only the helper may write here: owned by us, nobody else may write."""
        try:
            st = os.lstat(p)
        except OSError:
            self.error = "store_unwritable"
            raise StoreRefused("store_unwritable") from None
        kind_ok = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)
        if not kind_ok or st.st_uid != os.geteuid() or st.st_mode & 0o022:
            self.error = "store_permissions"
            raise StoreRefused("store_permissions")
        if not directory and not os.access(p, os.W_OK):
            self.error = "store_unwritable"
            raise StoreRefused("store_unwritable")

    def _flock(self):
        store = self

        class _Ctx:
            def __enter__(self_inner):
                try:
                    self_inner.fd = os.open(store.path, os.O_RDONLY | os.O_NOFOLLOW)
                except OSError:
                    store.error = "store_unreadable"
                    raise StoreRefused("store_unreadable") from None
                fcntl.flock(self_inner.fd, fcntl.LOCK_EX)
                return self_inner

            def __exit__(self_inner, *exc):
                try:
                    fcntl.flock(self_inner.fd, fcntl.LOCK_UN)
                finally:
                    os.close(self_inner.fd)
                return False
        return _Ctx()

    def _sync_locked(self) -> None:
        try:
            st = os.stat(self.path)
        except OSError:
            self.error = "store_unreadable"
            raise StoreRefused("store_unreadable") from None
        sig = (st.st_ino, st.st_size, st.st_mtime_ns)
        if sig == self._sig and self.error is None:
            return
        try:
            raw = self.path.read_bytes()
        except OSError:
            self.error = "store_unreadable"
            raise StoreRefused("store_unreadable") from None
        heads: dict[str, dict] = {}
        prev = GENESIS
        try:
            for line in raw.decode("utf-8").splitlines():
                if not line.strip():
                    raise ValueError("blank line")
                rec = json.loads(line)
                if not isinstance(rec, dict) or set(rec) - {"source", "seq", "hash", "ts", "prev",
                                                            "anchor_hash", "reset"}:
                    raise ValueError("unexpected record")
                body = {k: v for k, v in rec.items() if k != "anchor_hash"}
                if (rec.get("prev") != prev
                        or hashlib.sha256(_canon(body).encode()).hexdigest() != rec.get("anchor_hash")):
                    raise ValueError("chain")
                src, seq, h = rec.get("source"), rec.get("seq"), rec.get("hash")
                if (not isinstance(src, str) or not _SOURCE.fullmatch(src) or not _valid_seq(seq)
                        or not isinstance(h, str) or not _HASH.fullmatch(h)):
                    raise ValueError("fields")
                last = heads.get(src)
                if rec.get("reset") is True:
                    if seq != 0 or h != GENESIS:
                        raise ValueError("reset")
                    heads.pop(src, None)
                elif "reset" in rec or seq == 0 or (last is not None and seq <= last["seq"]):
                    raise ValueError("order")
                else:
                    heads[src] = {"seq": seq, "hash": h, "ts": rec.get("ts")}
                prev = rec["anchor_hash"]
        except (ValueError, UnicodeError, RecursionError):
            self.error = "corrupt"
            self._sig = sig
            raise StoreRefused("corrupt") from None
        self._heads, self._tail, self._sig, self.error = heads, prev, sig, None

    def _append_locked(self, record: dict) -> None:
        body = {**record, "ts": time.time(), "prev": self._tail}
        full = {**body, "anchor_hash": hashlib.sha256(_canon(body).encode()).hexdigest()}
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
            try:
                os.write(fd, (_canon(full) + "\n").encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            self.error = "store_unwritable"
            self._sig = None
            raise StoreRefused("store_unwritable") from None
        self._sig = None          # re-read (and re-verify) what was written next time
        self._sync_locked()

    def head(self, source: str) -> dict | None:
        if not isinstance(source, str) or not _SOURCE.fullmatch(source):
            raise StoreRefused("bad_request")
        with self._lock, self._flock():
            self._sync_locked()
            h = self._heads.get(source)
            return dict(h) if h else None

    def anchor(self, source: str, seq: int, digest: str) -> dict:
        if (not isinstance(source, str) or not _SOURCE.fullmatch(source) or not _valid_seq(seq)
                or seq == 0 or not isinstance(digest, str) or not _HASH.fullmatch(digest)):
            raise StoreRefused("bad_request")
        with self._lock, self._flock():
            self._sync_locked()
            last = self._heads.get(source)
            if last is not None:
                if seq < last["seq"]:
                    raise StoreRefused("rollback")
                if seq == last["seq"]:
                    if digest != last["hash"]:
                        raise StoreRefused("fork")
                    return dict(last)
            self._append_locked({"source": source, "seq": seq, "hash": digest})
            return dict(self._heads[source])

    def reset(self, source: str) -> None:
        """Operator action (CLI, as the helper user only): forget a source's heads, e.g.
        after its data directory was deliberately recreated. Never reachable by socket."""
        if not isinstance(source, str) or not _SOURCE.fullmatch(source):
            raise StoreRefused("bad_request")
        with self._lock, self._flock():
            self._sync_locked()
            self._append_locked({"source": source, "seq": 0, "hash": GENESIS, "reset": True})


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        try:
            line = self.rfile.readline(_MAX_LINE + 1)
            if not line.endswith(b"\n") or len(line) > _MAX_LINE:
                raise StoreRefused("bad_request")
            req = json.loads(line)
            if not isinstance(req, dict):
                raise StoreRefused("bad_request")
            store: AnchorStore = self.server.store
            op = req.get("op")
            if not self.server.source_allowed(req.get("source")):
                raise StoreRefused("unregistered_source")
            if op == "head":
                resp = {"ok": True, "head": store.head(req.get("source"))}
            elif op == "anchor":
                resp = {"ok": True, "head": store.anchor(req.get("source"), req.get("seq"), req.get("hash"))}
            else:
                raise StoreRefused("bad_request")
        except StoreRefused as e:
            resp = {"ok": False, "error": e.reason}
        except (ValueError, OSError, RecursionError):
            resp = {"ok": False, "error": "bad_request"}
        try:
            self.wfile.write((json.dumps(resp) + "\n").encode())
        except OSError:
            pass


class AnchorServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """One JSON request and one JSON response per connection, one line each.

    Socket permissions: the socket file gets `socket_mode` (default 0660) and, when
    given, the group `socket_group`. In production the helper runs as its own user
    (e.g. vulnix-anchor) and the service user is given connect access through that
    group only; the anchor directory stays 0700 and the file 0600, owned by the helper."""
    daemon_threads = True

    def __init__(self, store: AnchorStore, socket_path: str | Path,
                 socket_mode: int = 0o660, socket_group: str | None = None,
                 allow_sources: list[str] | tuple[str, ...] = ()):
        # Only installations registered at start may anchor: a source is "<name>:<path>"
        # and its name must be one of these (a renamed / re-rooted log cannot start afresh).
        self.allow_sources = tuple(allow_sources)
        if not self.allow_sources or not all(isinstance(a, str) and _NAME.fullmatch(a)
                                             for a in self.allow_sources):
            raise StoreRefused("no_allowed_sources")
        self.store = store
        self.socket_path = str(socket_path)
        try:
            st = os.lstat(self.socket_path)
        except FileNotFoundError:
            st = None
        if st is not None:
            if not stat.S_ISSOCK(st.st_mode):
                raise StoreRefused("socket_path_in_use")
            os.unlink(self.socket_path)        # a stale socket of an earlier run
        old = os.umask(0o177)
        try:
            super().__init__(self.socket_path, _Handler)
        finally:
            os.umask(old)
        if socket_group:
            os.chown(self.socket_path, -1, grp.getgrnam(socket_group).gr_gid)
        os.chmod(self.socket_path, socket_mode)

    def source_allowed(self, source) -> bool:
        return isinstance(source, str) and any(source.startswith(a + ":") for a in self.allow_sources)

    def server_close(self):
        super().server_close()
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass


# ---- service side ----------------------------------------------------------------------
def peer_uid(sock: socket.socket) -> int | None:
    """The OS user id of the process on the other end of a connected Unix socket."""
    if sys.platform.startswith("linux"):
        so_peercred = getattr(socket, "SO_PEERCRED", 17)
        raw = sock.getsockopt(socket.SOL_SOCKET, so_peercred, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", raw)
        return uid
    if sys.platform == "darwin":
        # getsockopt(SOL_LOCAL=0, LOCAL_PEERCRED=1) -> struct xucred
        # {u_int cr_version; uid_t cr_uid; short cr_ngroups; gid_t cr_groups[16]}
        raw = sock.getsockopt(0, 1, 76)
        version, uid = struct.unpack_from("=II", raw, 0)
        return uid if version == 0 else None
    return None


class AnchorClient:
    """Talks to the helper. Every connection is checked: the peer must run as
    `expected_uid` (the helper's user), or nothing it says is used."""

    def __init__(self, socket_path: str | Path, *, expected_uid: int, source_name: str,
                 timeout: float = 2.0, peer_uid=peer_uid):
        self.socket_path = str(socket_path)
        self.expected_uid = expected_uid
        self.source_name = source_name
        self.timeout = timeout
        self._peer_uid = peer_uid
        self.verified_peer_uid: int | None = None
        if (not isinstance(expected_uid, int) or isinstance(expected_uid, bool) or expected_uid < 0
                or not isinstance(source_name, str) or not _NAME.fullmatch(source_name)):
            raise AnchorError("anchor_misconfigured")

    def _call(self, req: dict) -> dict:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self.socket_path)
            try:
                uid = self._peer_uid(s)
            except (OSError, struct.error, ValueError):
                uid = None
            if uid is None:
                raise AnchorError("anchor_peer_unverified")
            if uid != self.expected_uid:
                raise AnchorError("anchor_peer_mismatch")
            self.verified_peer_uid = uid
            s.sendall((json.dumps(req) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(4096)
                if not chunk or len(buf) > _MAX_LINE:
                    raise AnchorUnavailable()
                buf += chunk
            resp = json.loads(buf)
        except AnchorError:
            raise
        except (OSError, ValueError):
            raise AnchorUnavailable() from None
        finally:
            s.close()
        if not isinstance(resp, dict):
            raise AnchorUnavailable()
        if resp.get("ok") is not True:
            reason = str(resp.get("error") or "refused")
            raise AnchorError(reason if reason in ("rollback", "fork") else f"anchor_{reason}")
        head = resp.get("head")
        if head is not None and (not isinstance(head, dict) or not _valid_seq(head.get("seq"))
                                 or not isinstance(head.get("hash"), str)
                                 or not _HASH.fullmatch(head["hash"])):
            raise AnchorUnavailable("anchor_bad_response")
        return resp

    def head(self, source: str) -> dict | None:
        return self._call({"op": "head", "source": source}).get("head")

    def anchor(self, source: str, seq: int, digest: str) -> dict:
        head = self._call({"op": "anchor", "source": source, "seq": seq, "hash": digest}).get("head")
        if not head or head.get("seq") != seq or head.get("hash") != digest:
            raise AnchorUnavailable("anchor_bad_response")
        return head


class MisconfiguredAnchor:
    """The socket is set but the rest is not: anchoring is required and cannot work."""
    source_name = "misconfigured"
    verified_peer_uid = None

    def head(self, source):
        raise AnchorError("anchor_misconfigured")

    def anchor(self, source, seq, digest):
        raise AnchorError("anchor_misconfigured")


def client_from_env():
    """VULNIX_AUDIT_ANCHOR_SOCKET set: anchoring is required (and VULNIX_AUDIT_ANCHOR_UID and
    VULNIX_AUDIT_ANCHOR_SOURCE must be valid, or every anchored record is refused).
    Unset or empty: disabled."""
    path = os.environ.get(SOCKET_ENV, "").strip()
    if not path:
        return None
    try:
        return AnchorClient(path, expected_uid=int(os.environ.get(UID_ENV, "").strip()),
                            source_name=os.environ.get(SOURCE_ENV, "").strip())
    except (ValueError, AnchorError):
        return MisconfiguredAnchor()


def source_id_for(name: str, root: str | Path, audit_path: str | Path) -> str | None:
    """"<name>:<audit path relative to the data root>" - never resolved, so a symlinked or
    renamed log keeps the id of the place it claims to be (and the symlink is refused by
    the caller). None when the log is not under the root."""
    rel = os.path.relpath(os.path.abspath(audit_path), os.path.abspath(root))
    if rel.startswith("..") or os.path.isabs(rel):
        return None
    source = f"{name}:{rel.replace(os.sep, '/')}"
    return source if _SOURCE.fullmatch(source) else None


def symlink_on_path(root: str | Path, audit_path: str | Path) -> bool:
    """True when the data root or any component from it down to the log is a symlink
    (or cannot be checked)."""
    root_abs = os.path.abspath(root)
    rel = os.path.relpath(os.path.abspath(audit_path), root_abs)
    if rel.startswith("..") or os.path.isabs(rel):
        return True
    current = root_abs
    parts = [] if rel == "." else rel.split(os.sep)
    for part in [None, *parts]:
        if part is not None:
            current = os.path.join(current, part)
        try:
            if stat.S_ISLNK(os.lstat(current).st_mode):
                return True
        except FileNotFoundError:
            continue           # not yet created: nothing to follow
        except OSError:
            return True
    return False


# ---- CLI -------------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m aegis.audit_anchor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sv = sub.add_parser("serve", help="run the anchor helper (as its own OS user)")
    sv.add_argument("--dir", required=True)
    sv.add_argument("--socket", required=True)
    sv.add_argument("--socket-mode", default="660", help="octal, default 660")
    sv.add_argument("--socket-group", default=None)
    sv.add_argument("--allow-source", action="append", default=[], required=True,
                    help="installation name allowed to anchor (VULNIX_AUDIT_ANCHOR_SOURCE); repeatable")
    rs = sub.add_parser("reset", help="forget one source's heads (operator action)")
    rs.add_argument("--dir", required=True)
    rs.add_argument("--source", required=True)
    vf = sub.add_parser("verify", help="verify the anchor file and print each source's head")
    vf.add_argument("--dir", required=True)
    a = ap.parse_args(argv)
    try:
        store = AnchorStore(a.dir)
    except StoreRefused as e:
        print(f"anchor store refused: {e.reason}", file=sys.stderr)
        return 2
    if a.cmd == "verify":
        print(json.dumps({"ok": True, "heads": store._heads}, indent=2))
        return 0
    if a.cmd == "reset":
        store.reset(a.source)
        print(f"reset {a.source}")
        return 0
    try:
        srv = AnchorServer(store, a.socket, int(a.socket_mode, 8), a.socket_group, a.allow_source)
    except StoreRefused as e:
        print(f"anchor helper refused: {e.reason}", file=sys.stderr)
        return 2

    def _stop(signum, frame):
        threading.Thread(target=srv.shutdown, daemon=True).start()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _stop)
    print(f"audit anchor serving on {a.socket}", flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
