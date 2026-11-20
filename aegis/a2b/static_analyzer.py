"""Bounded static reading of an owner-provided APK or source tree.

No network, no subprocess, no code execution, no extraction to disk: zip members are
read into memory under size/ratio limits, DEX files are reduced to their string table,
text files are scanned with fixed patterns. Secret values are never returned - only
their kind, location and a short SHA-256 fingerprint.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import itertools
import os
import re
import stat
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .manifest import (MAX_ENTRIES, MAX_MEMBER_BYTES, MAX_RATIO, MAX_SOURCE_FILE_BYTES, MAX_SOURCE_FILES,
                       MAX_TOTAL_UNCOMPRESSED, A2BInputError)

TEXT_SUFFIXES = (".js", ".bundle", ".json", ".txt", ".properties", ".html", ".yaml", ".yml", ".xml",
                 ".java", ".kt", ".kts", ".ts", ".tsx", ".jsx", ".dart", ".swift", ".gradle", ".cfg", ".ini")
MAX_DEX_STRINGS = 300_000
MAX_DEX_STRING_BYTES = 4096          # one string (longer ones are cut)
MAX_DEX_TOTAL_BYTES = 32 << 20       # all decoded strings of one DEX
MAX_HITS_PER_FILE = 2_000

URL_RE = re.compile(r"https?://(?:[^\s\"'`<>/@]+@)?[A-Za-z0-9.-]{1,253}(?::\d{1,5})?(?:/[A-Za-z0-9._~%!$&()*+,;=:@/{}-]*)?"
                    r"(?:\?[A-Za-z0-9._~%!$&()*+,;=:@/{}?-]*)?")
RETROFIT_RE = re.compile(r"@(GET|POST|PUT|PATCH|DELETE|HEAD)\(\s*(?:value\s*=\s*)?\"([^\"]{1,300})\"")
JS_CALL_RE = re.compile(r"\b(?:axios|http|api|client|request)\.(get|post|put|patch|delete)\(\s*[`'\"]([^`'\"]{1,300})[`'\"]",
                        re.I)
FETCH_RE = re.compile(r"\bfetch\(\s*[`'\"]([^`'\"]{1,300})[`'\"]\s*(?:,\s*\{[^}]{0,200}?method\s*:\s*[`'\"](\w+)[`'\"])?",
                      re.I)
PATH_RE = re.compile(r"[\"'`](/?(?:api|v\d{1,2}|graphql|rest|auth|oauth|admin|users?|accounts?|orders?|me|"
                     r"payments?|profile|internal)(?:/[A-Za-z0-9._~%{}:-]*)*)[\"'`]")
AUTH_HINTS = {
    "authorization_header": re.compile(r"\bAuthorization\b"),
    "bearer_token": re.compile(r"\bBearer\b"),
    "api_key_header": re.compile(r"\bX-API-Key\b|\bapi[_-]?key\b", re.I),
    "oauth": re.compile(r"\boauth2?\b|access_token|refresh_token", re.I),
    "cookie_session": re.compile(r"\bSet-Cookie\b|\bCookie\b"),
}
SECRET_PATTERNS = {
    "aws_access_key_id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{4,1024}"),
    "slack_webhook": re.compile(r"hooks\.slack\.com/services/([A-Za-z0-9/_-]{10,200})"),
    "telegram_bot_token": re.compile(r"\bbot?(\d{6,12}:[A-Za-z0-9_-]{30,60})"),
    "discord_webhook": re.compile(r"discord(?:app)?\.com/api/webhooks/(\d{5,30}/[A-Za-z0-9_-]{20,200})"),
    "stripe_secret_key": re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{10,200}"),
    "assigned_secret": re.compile(r"(?i)\b(?:client_secret|secret_key|api_secret|password|passwd)\b[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,200})[\"']"),
    "url_credentials": re.compile(r"https?://([^\s\"'/@:]+:[^\s\"'/@]+)@"),
}


@dataclass
class Hints:
    urls: list[tuple[str, str]] = field(default_factory=list)            # (url, location)
    calls: list[tuple[str, str, str]] = field(default_factory=list)      # (method, path_or_url, location)
    paths: list[tuple[str, str]] = field(default_factory=list)           # (path, location)
    auth: set[str] = field(default_factory=set)
    secrets: list[dict] = field(default_factory=list)                    # kind, location, fingerprint
    secret_values: set[str] = field(default_factory=set, repr=False)     # in memory only, for redaction
    fingerprint_key: bytes | None = field(default=None, repr=False)
    files_scanned: int = 0
    skipped: list[str] = field(default_factory=list)


def _fingerprint(value: str, key: bytes | None) -> str | None:
    """Keyed (HMAC) so a low-entropy value cannot be confirmed by guessing; none without a key."""
    if not key:
        return None
    return hmac.new(key, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:12]


def _strip_credentials(url: str) -> str:
    return re.sub(r"^(https?://)[^/@]+@", r"\1", url)


def scan_text(text: str, location: str, hints: Hints) -> None:
    hints.files_scanned += 1
    for kind, rx in SECRET_PATTERNS.items():
        for m in itertools.islice(rx.finditer(text), MAX_HITS_PER_FILE):
            value = m.group(1) if m.groups() else m.group(0)
            hints.secret_values.add(value)
            hints.secrets.append({"kind": kind, "location": location,
                                  "fingerprint": _fingerprint(value, hints.fingerprint_key)})
    for m in itertools.islice(URL_RE.finditer(text), MAX_HITS_PER_FILE):
        hints.urls.append((_strip_credentials(m.group(0)), location))
    for m in itertools.islice(RETROFIT_RE.finditer(text), MAX_HITS_PER_FILE):
        hints.calls.append((m.group(1).upper(), _strip_credentials(m.group(2)), location))
    for m in itertools.islice(JS_CALL_RE.finditer(text), MAX_HITS_PER_FILE):
        hints.calls.append((m.group(1).upper(), _strip_credentials(m.group(2)), location))
    for m in itertools.islice(FETCH_RE.finditer(text), MAX_HITS_PER_FILE):
        hints.calls.append(((m.group(2) or "GET").upper(), _strip_credentials(m.group(1)), location))
    for m in itertools.islice(PATH_RE.finditer(text), MAX_HITS_PER_FILE):
        hints.paths.append((m.group(1), location))
    for name, rx in AUTH_HINTS.items():
        if rx.search(text):
            hints.auth.add(name)


def _uleb128(buf: bytes, off: int) -> tuple[int, int]:
    result = shift = 0
    for _ in range(5):
        if off >= len(buf):
            raise A2BInputError("DEX の文字列表が壊れています")
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7
    raise A2BInputError("DEX の文字列表が壊れています")


def dex_strings(buf: bytes) -> list[str]:
    """The string table of one DEX file (MUTF-8 decoded leniently)."""
    if len(buf) < 0x70 or not buf.startswith(b"dex\n"):
        raise A2BInputError("DEX 形式ではありません")
    size, off = struct.unpack_from("<II", buf, 0x38)
    if size > MAX_DEX_STRINGS or off + 4 * size > len(buf):
        raise A2BInputError("DEX の文字列表が大きすぎるか壊れています")
    out: list[str] = []
    seen: set[int] = set()
    total = 0
    for i in range(size):
        (data_off,) = struct.unpack_from("<I", buf, off + 4 * i)
        if data_off >= len(buf):
            raise A2BInputError("DEX の文字列表が壊れています")
        if data_off in seen:            # entries sharing one string are read once
            continue
        seen.add(data_off)
        _, p = _uleb128(buf, data_off)
        end = buf.find(b"\x00", p, p + MAX_DEX_STRING_BYTES + 1)
        if end < 0:
            if buf.find(b"\x00", p) < 0:
                raise A2BInputError("DEX の文字列表が壊れています")
            end = p + MAX_DEX_STRING_BYTES
        total += end - p
        if total > MAX_DEX_TOTAL_BYTES:
            raise A2BInputError("DEX の文字列の合計が大きすぎます")
        out.append(buf[p:end].decode("utf-8", "replace"))
    return out


def _dex_text(strings: list[str]) -> str:
    # Retrofit annotation values survive compilation as plain strings ("users/{id}").
    quoted = []
    for s in strings:
        if re.fullmatch(r"[A-Za-z0-9._~%{}:/-]{2,200}", s) and ("/" in s or "{" in s):
            quoted.append(f"\"{s if s.startswith('/') else '/' + s}\"")
        else:
            quoted.append(s)
    return "\n".join(quoted)


def scan_apk(data: bytes, *, fingerprint_key: bytes | None = None) -> Hints:
    hints = Hints(fingerprint_key=fingerprint_key)
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise A2BInputError("APK（ZIP 形式）として読めません") from None
    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES:
        raise A2BInputError("APK のファイル数が多すぎます")
    if sum(i.file_size for i in infos) > MAX_TOTAL_UNCOMPRESSED:
        raise A2BInputError("APK の展開後サイズが大きすぎます（ZIP 爆弾の可能性）")
    for info in sorted(infos, key=lambda i: i.filename):
        name = info.filename
        if info.is_dir():
            continue
        if ".." in name.split("/") or name.startswith("/"):
            hints.skipped.append(f"{name[:120]}: unsafe path")
            continue
        if info.file_size > MAX_MEMBER_BYTES or (
                info.compress_size and info.file_size / info.compress_size > MAX_RATIO):
            hints.skipped.append(f"{name[:120]}: size or ratio limit")
            continue
        low = name.lower()
        if not (low.endswith(".dex") or low.endswith(TEXT_SUFFIXES)):
            continue
        try:
            with zf.open(info) as fh:
                raw = fh.read(MAX_MEMBER_BYTES + 1)
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError, ValueError) as e:
            hints.skipped.append(f"{name[:120]}: unreadable ({type(e).__name__})")
            continue
        if len(raw) > MAX_MEMBER_BYTES:
            hints.skipped.append(f"{name[:120]}: size limit")
            continue
        if low.endswith(".dex"):
            try:
                scan_text(_dex_text(dex_strings(raw)), name, hints)
            except A2BInputError as e:
                hints.skipped.append(f"{name[:120]}: {e}")
            continue
        if b"\x00" in raw[:512] and low.endswith(".xml"):
            continue                         # compiled binary XML (AndroidManifest, res/): not text
        scan_text(raw.decode("utf-8", "replace"), name, hints)
    return hints


def scan_source_tree(root: str | os.PathLike, *, fingerprint_key: bytes | None = None) -> Hints:
    hints = Hints(fingerprint_key=fingerprint_key)
    base = Path(root).resolve()
    count = 0
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d not in ("node_modules", "build"))
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            if p.is_symlink() or not fn.lower().endswith(TEXT_SUFFIXES):
                continue
            count += 1
            if count > MAX_SOURCE_FILES:
                raise A2BInputError("ソースのファイル数が多すぎます")
            st = p.lstat()
            if not stat.S_ISREG(st.st_mode):        # FIFOs, devices, sockets: never opened
                hints.skipped.append(f"{p.relative_to(base)}: not a regular file")
                continue
            if st.st_size > MAX_SOURCE_FILE_BYTES:
                hints.skipped.append(f"{p.relative_to(base)}: size limit")
                continue
            scan_text(p.read_text("utf-8", "replace"), str(p.relative_to(base)), hints)
    return hints
