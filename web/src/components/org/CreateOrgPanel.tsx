"use client";

import { useState } from "react";
import { postJSON } from "@/lib/api";
import { selectOrg, type OrgInfo } from "@/lib/org";
import { useSession } from "@/lib/useSession";

/** Shown when the signed-in account belongs to no organization yet. */
export function CreateOrgPanel() {
  const { session, logout } = useSession();
  const [name, setName] = useState(session ? `${session.operator} の組織` : "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const res = await postJSON<{ org: OrgInfo }>("/api/orgs", { name });
      selectOrg(res.org.id);
      window.location.assign("/dashboard");
    } catch (x) {
      setErr((x as Error).message);
      setBusy(false);
    }
  };
  return (
    <div className="flex min-h-dvh items-center justify-center bg-zinc-50 px-4 dark:bg-zinc-950">
      <div className="w-full max-w-md rounded-2xl border border-zinc-200 bg-white p-8 dark:border-zinc-800 dark:bg-zinc-900">
        <h1 className="text-xl font-bold">組織を作成しましょう</h1>
        <p className="mt-2 text-sm leading-relaxed text-zinc-600 dark:text-zinc-400">
          サイトや診断結果は組織ごとに分かれて保存され、ほかの組織からは見えません。
          招待を受けている場合は、届いた招待リンクを開いてください。
        </p>
        <form onSubmit={create} className="mt-6 space-y-3">
          <label htmlFor="org-name" className="block text-xs font-semibold">組織名</label>
          <input id="org-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={60} required
            className="w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-950" />
          {err && <p role="alert" className="text-sm text-red-700 dark:text-red-300">{err}</p>}
          <button type="submit" disabled={busy}
            className="w-full rounded-lg bg-zinc-900 py-2 text-sm font-semibold text-white disabled:opacity-50 dark:bg-white dark:text-zinc-900">
            {busy ? "作成中…" : "組織を作成"}
          </button>
        </form>
        <button type="button" onClick={logout} className="mt-4 w-full text-center text-xs text-zinc-500 hover:underline">ログアウト</button>
      </div>
    </div>
  );
}
