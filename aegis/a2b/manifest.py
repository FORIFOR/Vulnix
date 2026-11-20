"""Upload record and input limits for A2B analysis."""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass

MAX_UPLOAD_BYTES = 200 << 20          # whole APK / archive
MAX_ENTRIES = 20_000                  # zip members
MAX_TOTAL_UNCOMPRESSED = 600 << 20    # zip bomb guard (sum of declared sizes)
MAX_RATIO = 200                       # per member compression ratio
MAX_MEMBER_BYTES = 64 << 20           # one member read into memory
MAX_SOURCE_FILES = 20_000
MAX_SOURCE_FILE_BYTES = 4 << 20
_NAME_OK = re.compile(r"[^A-Za-z0-9._-]+")


class A2BInputError(ValueError):
    """The input is refused before or during analysis."""


@dataclass(frozen=True)
class UploadRecord:
    sha256: str
    size: int
    kind: str                  # "apk" | "source_tree"
    display_name: str
    org_id: str
    uploaded_by: str
    owner_attested: bool       # the uploader declared they own / may analyse this app
    received_at: float

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def record_upload(data: bytes, *, filename: str, org_id: str, uploaded_by: str,
                  owner_attested: bool, kind: str = "apk", clock=time.time) -> UploadRecord:
    if not owner_attested:
        raise A2BInputError("アプリの所有者（または解析を許可された者）であることの申告が必要です")
    if not org_id or not uploaded_by:
        raise A2BInputError("組織と提出者が必要です")
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise A2BInputError("空のファイルは解析できません")
    if len(data) > MAX_UPLOAD_BYTES:
        raise A2BInputError("ファイルが大きすぎます")
    name = _NAME_OK.sub("_", (filename or "app").rsplit("/", 1)[-1])[:80] or "app"
    return UploadRecord(hashlib.sha256(data).hexdigest(), len(data), kind, name, org_id, uploaded_by,
                        True, clock())
