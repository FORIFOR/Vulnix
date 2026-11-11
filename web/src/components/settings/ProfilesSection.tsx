"use client";

import { useEffect, useState } from "react";
import { getJSON, postJSON } from "@/lib/api";
import { isAdmin, useSession } from "@/lib/useSession";

interface ProfileRow {
  id: string;
  label: string;
  file: string;
  site: boolean;
  sha256: string;
  hosts: string[];
  accepted: boolean;
  changed_since_acceptance: boolean;
  confirmed_checks: string[];
}

interface ProfilesStatus {
  profiles: ProfileRow[];
  rejected: { file: string; reason: string }[];
}

/** Site L2 profiles decide what may be run against a real service, so an admin
 *  has to accept their exact content (identified by its SHA-256). */
export function ProfilesSection() {
  const { session } = useSession();
  const admin = isAdmin(session);
  const [status, setStatus] = useState<ProfilesStatus | null>(null);
  const [version, setVersion] = useState(0);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    let live = true;
    getJSON<ProfilesStatus>("/api/l2-profiles")
      .then((res) => { if (live) setStatus(res); })
      .catch((e: Error) => { if (live) setMsg({ ok: false, text: e.message }); });
    return () => { live = false; };
  }, [version]);

  const accept = async (p: ProfileRow) => {
    setBusy(true);
    setMsg(null);
    try {
      const res = await postJSON<ProfilesStatus>("/api/l2-profiles/accept", { id: p.id, sha256: p.sha256 });
      setStatus(res);
      setMsg({ ok: true, text: `${p.label} の内容を承認しました（監査ログに記録済み）。` });
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
      setVersion((v) => v + 1);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3 text-sm">
      <p className="text-zinc-600 dark:text-zinc-400">
        データディレクトリに置いた導入先プロファイルは、管理者がその内容（SHA-256）を承認するまで実行できません。
        承認後にファイルが変わると、再び承認が必要になります。
      </p>
      <ul className="space-y-2">
        {(status?.profiles ?? []).map((p) => (
          <li key={p.id} className="rounded-lg border border-zinc-200 p-2.5 dark:border-zinc-800">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span>
                <span className="font-medium">{p.label}</span>
                <span className="ml-1.5 font-mono text-xs text-zinc-500">{p.file}</span>
              </span>
              <span className={p.accepted ? "text-xs text-emerald-700 dark:text-emerald-300" : "text-xs font-semibold text-amber-800 dark:text-amber-300"}>
                {!p.site ? "同梱（ひな形）" : p.accepted ? "承認済み" : p.changed_since_acceptance ? "承認後に変更あり・要再承認" : "未承認"}
              </span>
            </div>
            <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs text-zinc-600 dark:text-zinc-400">
              <dt>適用ホスト</dt><dd className="break-all">{p.hosts.length ? p.hosts.join("、") : "なし"}</dd>
              <dt>確定済みルール</dt><dd className="break-all">{p.confirmed_checks.length ? p.confirmed_checks.join("、") : "なし"}</dd>
              <dt>SHA-256</dt><dd className="break-all font-mono">{p.sha256}</dd>
            </dl>
            {p.site && !p.accepted && (
              admin ? (
                <button type="button" disabled={busy} onClick={() => accept(p)}
                  className="mt-2 rounded-lg bg-zinc-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900">
                  ファイルの内容を確認したうえで承認する
                </button>
              ) : (
                <p className="mt-2 text-xs text-zinc-500">承認できるのは管理者だけです。</p>
              )
            )}
          </li>
        ))}
      </ul>
      {(status?.rejected ?? []).length > 0 && (
        <div role="alert" className="rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900 dark:border-red-800 dark:bg-red-950/40 dark:text-red-200">
          <p className="font-semibold">読み込まなかったプロファイル</p>
          <ul className="mt-1 space-y-0.5">
            {status?.rejected.map((r) => (
              <li key={r.file} className="break-words"><span className="font-mono">{r.file}</span>：{r.reason}</li>
            ))}
          </ul>
        </div>
      )}
      {status === null && !msg && <p className="text-xs text-zinc-500">読み込み中…</p>}
      {msg && (
        <p role={msg.ok ? "status" : "alert"} className={msg.ok ? "text-emerald-700 dark:text-emerald-300" : "text-red-700 dark:text-red-300"}>
          {msg.text}
        </p>
      )}
    </div>
  );
}
