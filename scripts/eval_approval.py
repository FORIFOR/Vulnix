"""One owner approval = one paid evaluation request, enforced locally.

Used by scripts/eval_adaptive_holdout.py and scripts/eval_japanese_advice.py. The
gates, in the order the callers apply them:

1. the approval names the exact SHA-256 of the fixed request (checked against a
   locally rebuilt request; a different request needs a different approval);
2. a server-side API key and a hash-chained audit log that verifies are required;
3. the approval is consumed durably BEFORE anything is sent (O_EXCL marker file,
   fsync'd, 0700 directory): a second run - after a crash, a failed upstream call or
   in another process - finds the marker and refuses. There is no resend;
4. the worst-case cost is reserved before the send and the provider-reported usage
   must fit in it, or the answer is not adopted;
5. the consumption and the send are recorded in the audit log; a failed audit write
   stops the run before the send.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import time
from pathlib import Path

DEFAULT_APPROVAL_ROOT = Path.home() / ".local" / "share" / "vulnix" / "eval-approvals"
_SHA = re.compile(r"[0-9a-f]{64}")


class ApprovalError(ValueError):
    pass


def require_matching_approval(approval_sha256: str, fixed_sha256: str) -> None:
    if not isinstance(approval_sha256, str) or not _SHA.fullmatch(approval_sha256):
        raise ApprovalError("approval must be a lowercase SHA-256")
    if not hmac.compare_digest(approval_sha256, fixed_sha256):
        raise ApprovalError("approval does not match the fixed request")


def require_key_and_audit(api_key: str, audit) -> None:
    if not api_key or audit is None:
        raise ApprovalError("a server-side key and durable audit are required")
    try:
        ok = bool(audit.verify())
    except Exception as exc:  # noqa: BLE001
        raise ApprovalError("audit chain verification failed") from exc
    if not ok:
        raise ApprovalError("audit chain verification failed")


def consume_approval(approval_dir: Path, approval_sha256: str, audit, *, purpose: str) -> None:
    """Mark the approval used. Raises if it was used before (no resend, ever)."""
    approval_dir = Path(approval_dir)
    approval_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if approval_dir.is_symlink() or approval_dir.stat().st_mode & 0o077:
        raise ApprovalError("approval store permissions are too broad")
    marker = approval_dir / approval_sha256
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ApprovalError("approval already consumed") from None
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"request_sha256": approval_sha256, "purpose": purpose, "at": time.time()}) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    dir_fd = os.open(approval_dir, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    # the marker already exists: an audit failure here leaves the approval consumed and
    # stops the run before the send (fail closed, never a second chance to send)
    audit.record("eval.approval_consumed", request_sha256=approval_sha256, purpose=purpose)


def usage_fits(usage: object, *, usd_per_1k_input: float, usd_per_1k_output: float,
               reserved_usd: float) -> tuple[dict, str | None]:
    """Provider usage, and why it cannot be accepted (None when it can)."""
    if type(usage) is not dict:
        return {}, "missing_usage"
    got = {k: usage[k] for k in ("prompt_tokens", "completion_tokens", "total_tokens")
           if type(usage.get(k)) is int and usage[k] >= 0}
    if "prompt_tokens" not in got or "completion_tokens" not in got:
        return got, "incomplete_usage"
    cost = got["prompt_tokens"] / 1000 * usd_per_1k_input + got["completion_tokens"] / 1000 * usd_per_1k_output
    if cost > reserved_usd + 1e-12:
        return got, "usage_exceeded_budget"
    return got, None
