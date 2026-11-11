"use client";

import { useState } from "react";
import { useSession } from "@/lib/useSession";

async function post(path: string, body: unknown) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Aegis-Request": "1" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`);
  return data;
}

export function MfaSection() {
  const { session, refresh } = useSession();
  const enabled = !!session?.mfa_enabled;

  const [secret, setSecret] = useState<string | null>(null);
  const [uri, setUri] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [current, setCurrent] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const field = "w-full rounded-lg border border-zinc-300 bg-white px-3 py-1.5 text-sm dark:border-zinc-600 dark:bg-zinc-900";

  async function run(fn: () => Promise<void>) {
    setBusy(true); setMsg(null);
    try { await fn(); } catch (e) { setMsg({ ok: false, text: e instanceof Error ? e.message : "失敗しました" }); }
    finally { setBusy(false); }
  }

  const startEnroll = () => run(async () => {
    const d = await post("/api/auth/totp/enroll", {});
    setSecret(d.secret); setUri(d.uri);
  });

  const confirmEnroll = () => run(async () => {
    await post("/api/auth/totp/confirm", { code });
    setSecret(null); setUri(null); setCode("");
    await refresh();
    setMsg({ ok: true, text: "2要素認証を有効化しました。次回ログインからコードが必要です。" });
  });

  const disable = () => run(async () => {
    await post("/api/auth/totp/disable", { current, code });
    setCurrent("");
    setCode("");
    await refresh();
    setMsg({ ok: true, text: "2要素認証を無効化しました。" });
  });

  return (
    <div className="mt-3 space-y-2 border-t border-zinc-200 pt-3 dark:border-zinc-700">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">2要素認証（TOTP）</h3>
        <span className={`rounded px-2 py-0.5 text-xs font-medium ${enabled
          ? "bg-emerald-100 text-emerald-900 dark:bg-emerald-900/50 dark:text-emerald-100"
          : "bg-zinc-200 text-zinc-700 dark:bg-zinc-700 dark:text-zinc-200"}`}>
          {enabled ? "有効" : "無効"}
        </span>
      </div>

      {!enabled && !secret && (
        <>
          <p className="text-xs text-zinc-500">認証アプリ（Google Authenticator 等）でコードを要求する第2要素を追加します。</p>
          <button onClick={startEnroll} disabled={busy}
            className="rounded-lg border border-zinc-300 px-3 py-1.5 text-sm font-medium hover:bg-zinc-100 disabled:opacity-40 dark:border-zinc-600 dark:hover:bg-zinc-800">
            有効化する
          </button>
        </>
      )}

      {!enabled && secret && (
        <div className="space-y-2">
          <p className="text-xs text-zinc-500">
            認証アプリに次のキーを手動で追加するか、otpauth URI を読み込んでください。追加後、表示される6桁コードを入力して確定します。
          </p>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
            <dt className="text-zinc-500">シークレット</dt>
            <dd className="break-all font-mono text-xs">{secret}</dd>
            <dt className="text-zinc-500">otpauth</dt>
            <dd className="break-all font-mono text-xs text-zinc-500">{uri}</dd>
          </dl>
          <div className="flex items-end gap-2">
            <label className="text-sm">
              <span className="mb-1 block text-xs text-zinc-500">認証コード</span>
              <input inputMode="numeric" autoComplete="one-time-code" value={code} placeholder="000000"
                onChange={(e) => setCode(e.target.value)} className={`${field} tracking-widest`} />
            </label>
            <button onClick={confirmEnroll} disabled={busy || code.length < 6}
              className="rounded-lg bg-zinc-900 px-3 py-1.5 text-sm font-medium text-white disabled:opacity-40 dark:bg-white dark:text-zinc-900">
              確定
            </button>
          </div>
        </div>
      )}

      {enabled && (
        <div className="flex flex-wrap items-end gap-2">
          <label className="text-sm">
            <span className="mb-1 block text-xs text-zinc-500">無効化するには現在のパスワード</span>
            <input type="password" autoComplete="current-password" value={current}
              onChange={(e) => setCurrent(e.target.value)} className={field} />
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-xs text-zinc-500">現在の認証コード</span>
            <input inputMode="numeric" autoComplete="one-time-code" value={code} placeholder="000000"
              onChange={(e) => setCode(e.target.value)} className={`${field} tracking-widest`} />
          </label>
          <button onClick={disable} disabled={busy || current.length === 0 || code.length < 6}
            className="rounded-lg border border-red-300 px-3 py-1.5 text-sm font-medium text-red-700 hover:bg-red-50 disabled:opacity-40 dark:border-red-700 dark:text-red-300 dark:hover:bg-red-950/40">
            無効化
          </button>
        </div>
      )}

      {msg && (
        <p role="status" className={`text-xs ${msg.ok ? "text-emerald-700 dark:text-emerald-300" : "text-red-700 dark:text-red-300"}`}>
          {msg.text}
        </p>
      )}
    </div>
  );
}
