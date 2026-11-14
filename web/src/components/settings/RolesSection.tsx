"use client";

import { useEffect, useState } from "react";
import { getJSON, postJSON } from "@/lib/api";
import { isPlatformAdmin, useSession } from "@/lib/useSession";

interface OperatorRow {
  name: string;
  display: string;
  roles: string[];
  mfa_enabled: boolean;
  /** Approver role with no admin grant on record (e.g. self-assigned before roles were admin-granted). */
  needs_role_review: boolean;
  /** Seconds the sign-in for this account stays paused after repeated failures (0 = not locked). */
  locked_for: number;
}

const GRANTABLE: { key: string; label: string; hint: string }[] = [
  { key: "approver", label: "承認責任者", hint: "診断範囲の確定、検証用アカウントの設定、L2検証の承認と実行" },
  { key: "admin", label: "管理者", hint: "アカウントへのロール付与・剥奪" },
];

/** Admin-only: grant or revoke roles. Roles are never self-assigned. */
export function RolesSection() {
  const { session } = useSession();
  const admin = isPlatformAdmin(session);
  const [rows, setRows] = useState<OperatorRow[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const [version, setVersion] = useState(0);
  const [newName, setNewName] = useState("");
  const [newDisplay, setNewDisplay] = useState("");
  const [newPassword, setNewPassword] = useState("");

  useEffect(() => {
    if (!admin) return;
    let live = true;
    getJSON<{ operators: OperatorRow[] }>("/api/operators")
      .then((res) => { if (live) setRows(res.operators); })
      .catch((e: Error) => { if (live) setMsg({ ok: false, text: e.message }); });
    return () => { live = false; };
  }, [admin, version]);

  if (!admin) {
    return (
      <p className="text-sm text-zinc-600 dark:text-zinc-400">
        ロールの付与・剥奪は管理者だけが行えます。承認責任者のロールが必要な場合は管理者に依頼してください
        （自分のアカウントに自分で付与することはできません）。
      </p>
    );
  }

  const createAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy("create");
    setMsg(null);
    try {
      await postJSON("/api/auth/register", { name: newName.trim(), display: newDisplay.trim(), password: newPassword });
      setMsg({ ok: true, text: `${newName.trim()} を操作者として作成しました。初期パスワードは本人に安全な方法で伝えてください。` });
      setNewName("");
      setNewDisplay("");
      setNewPassword("");
      setVersion((v) => v + 1);
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(null);
    }
  };

  // Recovery for a legitimate user: lift a sign-in lock, or reset a lost second factor.
  const recover = async (row: OperatorRow, action: "unlock" | "reset-mfa") => {
    setBusy(`${row.name}:${action}`);
    setMsg(null);
    try {
      await postJSON(`/api/operators/${action}`, { name: row.name });
      setMsg({
        ok: true,
        text: action === "unlock"
          ? `${row.name} のログイン停止を解除しました。`
          : `${row.name} の2要素認証をリセットし、すべてのセッションを終了しました。`,
      });
      setVersion((v) => v + 1);
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(null);
    }
  };

  // Re-submitting the same roles records the admin's confirmation in the audit log.
  const attest = async (row: OperatorRow) => {
    setBusy(`${row.name}:attest`);
    setMsg(null);
    try {
      await postJSON("/api/operators/roles", { name: row.name, roles: row.roles });
      setMsg({ ok: true, text: `${row.name} の承認責任者ロールを確認済みとして記録しました。` });
      setVersion((v) => v + 1);
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(null);
    }
  };

  const toggle = async (row: OperatorRow, role: string) => {
    const next = row.roles.includes(role) ? row.roles.filter((r) => r !== role) : [...row.roles, role];
    setBusy(`${row.name}:${role}`);
    setMsg(null);
    try {
      await postJSON("/api/operators/roles", { name: row.name, roles: next });
      setMsg({ ok: true, text: `${row.name} のロールを変更しました（監査ログに記録済み）。` });
      setVersion((v) => v + 1);
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-3">
      <p className="text-sm text-zinc-600 dark:text-zinc-400">
        変更はすぐに有効になり、ログイン中のセッションにも反映されます。自分自身のロールは変更できません。
      </p>
      {(rows ?? []).some((r) => r.needs_role_review) && (
        <p role="note" className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
          管理者による付与記録のない承認責任者アカウントがあります。以前は登録時に自分でこのロールを付けられたため、
          本人に確認のうえ、不要ならチェックを外し、必要なら「このまま認める」で記録を残してください。
        </p>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="text-xs text-zinc-500">
            <tr>
              <th className="py-1.5 pr-3 font-medium">アカウント</th>
              {GRANTABLE.map((g) => (
                <th key={g.key} className="py-1.5 pr-3 font-medium" title={g.hint}>{g.label}</th>
              ))}
              <th className="py-1.5 font-medium">二要素認証</th>
            </tr>
          </thead>
          <tbody>
            {(rows ?? []).map((row) => {
              const self = row.name === session?.operator;
              return (
                <tr key={row.name} className="border-t border-zinc-100 dark:border-zinc-800">
                  <td className="py-1.5 pr-3">
                    <span className="font-medium">{row.display}</span>
                    <span className="ml-1.5 font-mono text-xs text-zinc-500">{row.name}{self ? "（自分）" : ""}</span>
                    {row.needs_role_review && (
                      <span className="mt-0.5 block text-xs text-amber-800 dark:text-amber-300">
                        承認責任者ロールの付与記録がありません（要確認）。
                        {!self && (
                          <button
                            type="button"
                            disabled={busy !== null}
                            onClick={() => attest(row)}
                            className="ml-1 underline underline-offset-2 disabled:opacity-50"
                          >
                            このまま認める
                          </button>
                        )}
                      </span>
                    )}
                  </td>
                  {GRANTABLE.map((g) => (
                    <td key={g.key} className="py-1.5 pr-3">
                      <label className="inline-flex items-center gap-1.5">
                        <input
                          type="checkbox"
                          checked={row.roles.includes(g.key)}
                          disabled={self || busy !== null}
                          onChange={() => toggle(row, g.key)}
                          aria-label={`${row.name} に ${g.label} ロールを付与`}
                        />
                        <span className="text-xs text-zinc-500">{row.roles.includes(g.key) ? "付与済み" : "なし"}</span>
                      </label>
                    </td>
                  ))}
                  <td className="py-1.5 text-xs text-zinc-500">
                    {row.mfa_enabled ? "有効" : "未設定"}
                    {row.mfa_enabled && !self && (
                      <button type="button" disabled={busy !== null} onClick={() => recover(row, "reset-mfa")}
                        className="ml-1.5 underline underline-offset-2 disabled:opacity-50">リセット</button>
                    )}
                    {row.locked_for > 0 && (
                      <span className="mt-0.5 block text-amber-800 dark:text-amber-300">
                        ログイン停止中（残り約{Math.ceil(row.locked_for / 60)}分）
                        <button type="button" disabled={busy !== null} onClick={() => recover(row, "unlock")}
                          className="ml-1 underline underline-offset-2 disabled:opacity-50">解除</button>
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {rows === null && !msg && <p className="text-xs text-zinc-500">読み込み中…</p>}
      <form onSubmit={createAccount} className="space-y-2 border-t border-zinc-100 pt-3 dark:border-zinc-800">
        <h3 className="text-sm font-semibold">アカウントを作成</h3>
        <p className="text-xs text-zinc-500">
          作成されるのは操作者（operator）です。承認責任者にする場合は、作成後に上の表で付与してください。
        </p>
        <div className="grid gap-2 sm:grid-cols-3">
          <input aria-label="ユーザー名" placeholder="ユーザー名" value={newName} onChange={(e) => setNewName(e.target.value)}
            autoComplete="off" className="rounded-lg border border-zinc-300 bg-white px-3 py-1.5 text-sm dark:border-zinc-600 dark:bg-zinc-900" />
          <input aria-label="表示名（任意）" placeholder="表示名（任意）" value={newDisplay} onChange={(e) => setNewDisplay(e.target.value)}
            autoComplete="off" className="rounded-lg border border-zinc-300 bg-white px-3 py-1.5 text-sm dark:border-zinc-600 dark:bg-zinc-900" />
          <input aria-label="初期パスワード（10文字以上）" placeholder="初期パスワード（10文字以上）" type="password" value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)} autoComplete="new-password"
            className="rounded-lg border border-zinc-300 bg-white px-3 py-1.5 text-sm dark:border-zinc-600 dark:bg-zinc-900" />
        </div>
        <button type="submit" disabled={busy !== null || !newName.trim() || newPassword.length < 10}
          className="rounded-lg bg-zinc-900 px-3 py-1.5 text-sm font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900">
          {busy === "create" ? "作成中…" : "操作者アカウントを作成"}
        </button>
      </form>
      {msg && (
        <p role={msg.ok ? "status" : "alert"} className={msg.ok ? "text-sm text-emerald-700 dark:text-emerald-300" : "text-sm text-red-700 dark:text-red-300"}>
          {msg.text}
        </p>
      )}
    </div>
  );
}
