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
import os
import sys
from pathlib import Path

from aegis.audit import AuditLog
from aegis.operators import AuthError, OperatorStore, audit_credential_generations

try:
    import fcntl
except ImportError:  # pragma: no cover - POSIX only, like the control plane's own lock
    fcntl = None


def _audit_log_for(data: Path) -> Path:
    """Where the server records account events (server.make_handler: the platform log
    when organizations are on, the default)."""
    platform = data / "platform-audit.jsonl"
    if platform.exists() or os.environ.get("VULNIX_MULTI_TENANT", "1") != "0":
        return platform
    return data / "audit.jsonl"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Recover an operator account (control plane stopped).")
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--account", required=True)
    a = ap.parse_args(argv)
    data = Path(a.data_dir)
    seed = data / "operators.json"
    if not seed.is_file():
        print(f"アカウントファイルがありません: {seed}", file=sys.stderr)
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
        return _recover(data, seed, a.account)
    finally:
        lock.close()


def _recover(data: Path, seed: Path, account: str) -> int:
    logs = [data / "audit.jsonl", data / "platform-audit.jsonl"]
    store = OperatorStore(seed, credential_generations=lambda: audit_credential_generations(logs))
    audit = AuditLog(_audit_log_for(data))

    def journal(**fields):
        audit.record("auth.account_recovered_offline", actor="host", **fields)

    try:
        password, gen = store.recover_account(account, journal=journal)
    except (AuthError, ValueError, OSError) as e:
        # ValueError/OSError from the audit log: not recorded, so nothing changed
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
    cred = seed.with_name("operators.recovery-credentials.txt")
    store._write_private(
        cred,
        "Aegis アカウント復旧（ホスト上の操作・このファイルは手元で確認してください）\n"
        "ログイン後すぐにパスワードを変更し、このファイルは削除してください。\n\n"
        f"ユーザー名: {account}\nパスワード: {password}\n")
    print(f"アカウント {account} を復旧しました（資格情報の世代 {gen}、監査ログに記録済み）。")
    print(f"一時パスワード（平文・600権限）: {cred}")
    print("手順: 1) コントロールプレーンを起動する  2) このアカウントでログインし、直ちにパスワードを変更する"
          "  3) 上のファイルを削除する  4) 管理者は他にブロックされたアカウントがあればリセットする")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
