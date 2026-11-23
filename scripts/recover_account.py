"""Host-side recovery of an operator account when no admin can sign in
(docs/PASSWORD_CHANGE_DURABILITY.md).

    python3 -m scripts.recover_account --data-dir <data directory> --account <name>

The control plane must be stopped: this refuses to run while another process holds
the data directory's `.lock`. A fresh temporary password is recorded in the audit
log first (intent: account, credential generation, digest of the new hash), then
written in two phases; it goes to `operators.recovery-credentials.txt` (0600) next
to the accounts file, never to the terminal or a log.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from aegis.audit_anchor import client_from_env as anchor_client_from_env
from aegis.operators import (AuditHistoryUnreadable, AuthError, CredentialStateUnverifiable, OperatorStore,
                             credential_audit_logs, credential_history_reader)

try:
    import fcntl
except ImportError:  # pragma: no cover - POSIX only, like the control plane's own lock
    fcntl = None

RECOVERY_FILE = "operators.recovery-credentials.txt"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Recover an operator account (control plane stopped).")
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--account", required=True)
    ap.add_argument("--quarantine-unreadable-audit", action="store_true",
                    help="An audit log that cannot be parsed is moved aside (kept, renamed) and a fresh one "
                         "started; every account is then refused sign-in until reset, except the one recovered")
    a = ap.parse_args(argv)
    data = Path(a.data_dir)
    seed = data / "operators.json"
    if not seed.is_file():
        print(f"アカウントファイルがありません: {seed}", file=sys.stderr)
        return 2
    if os.path.lexists(seed.with_name(RECOVERY_FILE)):
        print(f"前回の復旧ファイルが残っています。内容を確認して削除してから実行してください: {seed.with_name(RECOVERY_FILE)}",
              file=sys.stderr)
        return 2
    if fcntl is None:
        print("このプラットフォームではコントロールプレーンの停止を確認できないため、実行しません。", file=sys.stderr)
        return 3
    lock = open(data / ".lock", "a+")
    try:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print("コントロールプレーンが動作中です（データディレクトリが使用中）。停止してから実行してください。",
                  file=sys.stderr)
            return 3
        return _recover(data, seed, a.account, a.quarantine_unreadable_audit)
    finally:
        lock.close()


def _unusable_log(path: Path) -> bool:
    """True when the server could not use this log: a line that is not JSON, or not a
    complete audit record (an object with string event/prev/hash, as the hash chain
    requires). The same standard as the server's own chain check, so every log that
    stops the server can be moved aside here."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return True
    for line in lines:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            return True
        if not isinstance(entry, dict) or not all(isinstance(entry.get(k), str) for k in ("event", "prev", "hash")):
            return True
    return False


def _quarantine(data: Path) -> list[dict]:
    """Move every audit log that cannot be parsed aside (never deleted)."""
    moved = []
    for name in ("audit.jsonl", "platform-audit.jsonl"):
        path = data / name
        if not path.is_file():
            continue
        if not _unusable_log(path):
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        target = path.with_name(f"{name}.quarantined-{int(time.time())}")
        os.rename(path, target)
        moved.append({"log": name, "moved_to": target.name, "sha256": digest})
    return moved


def _recover(data: Path, seed: Path, account: str, quarantine: bool) -> int:
    anchor = anchor_client_from_env()
    reader = credential_history_reader(data, anchor=anchor)
    moved: list[dict] = []
    try:
        store = OperatorStore(seed, credential_generations=reader)
    except CredentialStateUnverifiable:
        if not quarantine:
            print("監査ログを読み取れないため、アカウントの状態を確認できません。読み取れない監査ログを退避して"
                  "復旧する場合は --quarantine-unreadable-audit を付けて実行してください"
                  "（退避したログは削除されません。全アカウントがリセットされるまでログインできなくなります）。",
                  file=sys.stderr)
            return 4
        moved = _quarantine(data)
        store = OperatorStore(seed, credential_generations=reader)
        if not store.block_all("audit_quarantined"):
            print("アカウントの状態を保存できませんでした（何も復旧していません）。", file=sys.stderr)
            return 1
    try:
        _logs, audit = credential_audit_logs(data, anchor=anchor)
    except AuditHistoryUnreadable as e:
        print(f"監査ログを開けません: {e}", file=sys.stderr)
        return 1
    for m in moved:
        try:
            audit.record("audit.log_quarantined", actor="host", **m)
        except Exception as e:  # noqa: BLE001
            print(f"監査ログに記録できないため、復旧しませんでした: {e}", file=sys.stderr)
            return 1

    def journal(**fields):
        audit.record("auth.account_recovered_offline", actor="host", **fields)

    try:
        password, gen = store.recover_account(account, journal=journal)
    except (AuthError, ValueError, OSError) as e:
        # ValueError/OSError from the audit log (disk, chain, anchor): not recorded, nothing changed
        print(f"復旧できませんでした: {e}", file=sys.stderr)
        return 1
    notes = list(store.recovery_events)
    notes.append({"event": "auth.password_change_committed", "account": account,
                  "credential_generation": gen, "offline": True})
    for ev in notes:
        try:
            audit.record(ev.pop("event"), **ev)
        except Exception as e:  # noqa: BLE001 - the change itself is in force (its intent is recorded)
            print(f"警告: 監査ログへの完了の記録に失敗しました: {e}", file=sys.stderr)
            break
    cred = seed.with_name(RECOVERY_FILE)
    # created fresh, 0600, never through a link left in its place
    fd = os.open(cred, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("Aegis アカウント復旧（ホスト上の操作・このファイルは手元で確認してください）\n"
                 "ログイン後すぐにパスワードを変更し、このファイルは削除してください。\n\n"
                 f"ユーザー名: {account}\nパスワード: {password}\n")
        fh.flush()
        os.fsync(fh.fileno())
    print(f"アカウント {account} を復旧しました（資格情報の世代 {gen}、監査ログに記録済み）。")
    print(f"一時パスワード（平文・600権限）: {cred}")
    if moved:
        print("読み取れない監査ログを退避しました: " + ", ".join(m["moved_to"] for m in moved)
              + "。他のアカウントは、このアカウントでログインしてからリセットしてください。")
    print("手順: 1) コントロールプレーンを起動する  2) このアカウントでログインし、直ちにパスワードを変更する"
          "  3) 上のファイルを削除する  4) 管理者は他にブロックされたアカウントがあればリセットする")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
