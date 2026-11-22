"""Linux CI: the audit anchor helper runs as a SEPARATE OS user (docs/AUDIT_ANCHOR.md).

Run as the service user while the helper runs as another user (see .github/workflows/ci.yml).
Proves: the service can anchor and verify through the socket, it cannot read or write the
anchor directory or file, and a rollback of both the audit log and its reservation file is
detected. Never skips: any missing precondition is a failure (exit 1).
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.audit import AuditLog  # noqa: E402
from aegis.audit_anchor import ANCHOR_FILE, AnchorClient, AnchorError  # noqa: E402

PAID = dict(endpoint_kind="external", reserve_micro_usd=100, cap_micro_usd=10_000)


def check(cond: bool, what: str) -> None:
    print(("ok   " if cond else "FAIL ") + what, flush=True)
    if not cond:
        raise SystemExit(1)


def refused(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except PermissionError:
        return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--anchor-dir", required=True)
    ap.add_argument("--helper-uid", type=int, required=True)
    ap.add_argument("--source-name", default="ci")
    a = ap.parse_args()
    anchor_dir = Path(a.anchor_dir)
    check(os.geteuid() != 0, "the service side is not root")
    st = os.stat(anchor_dir)
    check(st.st_uid != os.geteuid(), "the anchor directory belongs to another user")
    check(st.st_uid == a.helper_uid, "the anchor directory belongs to the helper user")
    check(st.st_mode & 0o077 == 0, "the anchor directory is private to its owner (0700)")
    check(refused(os.listdir, anchor_dir), "service user cannot list the anchor directory")
    check(refused(lambda: open(anchor_dir / ANCHOR_FILE, "a").close()),
          "service user cannot open the anchor file for writing")
    check(refused(lambda: open(anchor_dir / "planted", "w").close()),
          "service user cannot create files in the anchor directory")

    with tempfile.TemporaryDirectory() as tmp:
        data = Path(tmp) / "data"
        data.mkdir()
        log_path = data / "audit.jsonl"
        client = AnchorClient(a.socket, expected_uid=a.helper_uid, source_name=a.source_name, timeout=3)
        check(AuditLog(log_path, anchor=AnchorClient(a.socket, expected_uid=os.geteuid(),
                                                     source_name=a.source_name), anchor_root=tmp)
              .anchor_check()["error"] == "anchor_peer_mismatch",
              "a client expecting another user (e.g. a fake helper) is refused by the peer check")
        log = AuditLog(log_path, anchor=client, anchor_root=tmp)
        log.record("allow", tool="ci")
        log.record_with_budget("advisor.safe_send_requested", **PAID)
        status = log.anchor_status(max_age=None)
        check(status["protected"] and status["last_seq"] == 2 and client.verified_peer_uid == a.helper_uid,
              f"anchored through the socket, peer verified as the helper user: {status}")
        check(AuditLog(log_path, anchor=client, anchor_root=tmp).anchor_check()["protected"], "a restarted service verifies")

        floor = log_path.with_name(log_path.name + ".advisor-budget")
        old_log, old_floor = log_path.read_text(), floor.read_text()
        log.record_with_budget("advisor.safe_send_requested", **PAID)
        log_path.write_text(old_log)
        floor.write_text(old_floor)
        copy = Path(tmp) / "copy"
        shutil.copytree(data, copy)
        AuditLog(copy / "audit.jsonl").record_with_budget("advisor.safe_send_requested", **PAID)
        print("ok   without the anchor, the rolled-back pair is accepted after a restart", flush=True)
        restarted = AuditLog(log_path, anchor=client, anchor_root=tmp)
        check(restarted.anchor_check()["error"] == "rollback", "with the anchor the rollback is detected")
        # the same rollback through a symlink to an older copy (a new path must not pose as a new source)
        (data / "audit-old.jsonl").write_text(old_log)
        log_path.unlink()
        os.symlink("audit-old.jsonl", log_path)
        swapped = AuditLog(log_path, anchor=client, anchor_root=tmp)
        check(swapped.anchor_check()["error"] == "symlink", "a symlink swap to an older copy is refused")
        try:
            swapped.record("allow", tool="after-symlink-swap")
            check(False, "a Worker authorization after the symlink swap is refused")
        except AnchorError as e:
            check(e.reason == "symlink", "a Worker authorization after the symlink swap is refused")
        log_path.unlink()
        log_path.write_text(old_log)
        try:
            restarted.record("allow", tool="after-rollback")
            check(False, "a Worker authorization after the rollback is refused")
        except AnchorError as e:
            check(e.reason == "rollback", "a Worker authorization after the rollback is refused")
    print("AUDIT ANCHOR CI: OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
