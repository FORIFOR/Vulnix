"use client";

import { useEffect, useState } from "react";
import { getJSON, postJSON } from "@/lib/api";
import { isAdmin, useSession } from "@/lib/useSession";

interface OperatorRow {
  name: string;
  display: string;
  roles: string[];
  mfa_enabled: boolean;
}

const GRANTABLE: { key: string; label: string; hint: string }[] = [
  { key: "approver", label: "承認責任者", hint: "診断範囲の確定、検証用アカウントの設定、L2検証の承認と実行" },
  { key: "admin", label: "管理者", hint: "アカウントへのロール付与・剥奪" },
];

/** Admin-only: grant or revoke roles. Roles are never self-assigned. */
export function RolesSection() {
  const { session } = useSession();
  const admin = isAdmin(session);
  const [rows, setRows] = useState<OperatorRow[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const [version, setVersion] = useState(0);

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
                  <td className="py-1.5 text-xs text-zinc-500">{row.mfa_enabled ? "有効" : "未設定"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {rows === null && !msg && <p className="text-xs text-zinc-500">読み込み中…</p>}
      {msg && (
        <p role={msg.ok ? "status" : "alert"} className={msg.ok ? "text-sm text-emerald-700 dark:text-emerald-300" : "text-sm text-red-700 dark:text-red-300"}>
          {msg.text}
        </p>
      )}
    </div>
  );
}
