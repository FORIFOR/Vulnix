"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { useSession } from "@/lib/useSession";

export default function LoginPage() {
  const { session, loading, refresh } = useSession();
  const router = useRouter();
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!loading && session) router.replace("/dashboard");
  }, [loading, session, router]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Aegis-Request": "1" },
        body: JSON.stringify({ name, password, code }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        if (data.mfa_required) setMfaRequired(true);
        throw new Error(data.error ?? `HTTP ${res.status}`);
      }
      await refresh();
      router.replace("/dashboard");
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="flex min-h-dvh items-center justify-center p-4">
      <form onSubmit={submit} className="w-full max-w-sm rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
        <div className="mb-6 flex items-center gap-2">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-zinc-900 text-sm font-bold text-white dark:bg-white dark:text-zinc-900">V</span>
          <div className="leading-tight">
            <div className="font-semibold">Vulnix</div>
            <div className="text-xs text-zinc-500">AI Security Testing Platform — ログイン</div>
          </div>
        </div>
        <label className="mb-1 block text-sm font-medium" htmlFor="name">ユーザー名</label>
        <input id="name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="username" autoFocus
          className="mb-3 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm dark:border-zinc-600 dark:bg-zinc-950" />
        <label className="mb-1 block text-sm font-medium" htmlFor="password">パスワード</label>
        <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password"
          className="mb-4 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm dark:border-zinc-600 dark:bg-zinc-950" />
        {mfaRequired && (
          <>
            <label className="mb-1 block text-sm font-medium" htmlFor="code">認証コード（2要素）</label>
            <input id="code" inputMode="numeric" autoComplete="one-time-code" value={code}
              onChange={(e) => setCode(e.target.value)} autoFocus placeholder="000000"
              className="mb-4 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm tabular-nums tracking-widest dark:border-zinc-600 dark:bg-zinc-950" />
          </>
        )}
        {err && <p role="alert" className="mb-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-800 dark:bg-red-950/40 dark:text-red-200">{err}</p>}
        <button type="submit" disabled={busy || !name || !password || (mfaRequired && !code)}
          className="w-full rounded-lg bg-zinc-900 py-2 text-sm font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900">
          {busy ? "確認中…" : "ログイン"}
        </button>
        <p className="mt-4 text-xs leading-relaxed text-zinc-500">
          初回起動時に生成された初期ログイン情報は、制御プレーンのデータディレクトリ内
          <code className="mx-1 rounded bg-zinc-100 px-1 dark:bg-zinc-800">operators.initial-credentials.txt</code>
          にあります（手元で確認してください）。
        </p>
      </form>
    </main>
  );
}
