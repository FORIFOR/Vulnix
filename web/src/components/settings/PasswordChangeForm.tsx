"use client";

import { useState } from "react";

const MIN_LEN = 10;

export function PasswordChangeForm() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const localError =
    next.length > 0 && next.length < MIN_LEN ? `新しいパスワードは${MIN_LEN}文字以上にしてください`
    : confirm.length > 0 && next !== confirm ? "確認用パスワードが一致しません"
    : null;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (localError || busy) return;
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch("/api/auth/password", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Aegis-Request": "1" },
        body: JSON.stringify({ current, new: next }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`);
      setMsg({ ok: true, text: "パスワードを変更しました。他の端末のセッションは失効しました。" });
      setCurrent(""); setNext(""); setConfirm("");
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "変更に失敗しました" });
    } finally {
      setBusy(false);
    }
  }

  const field = "w-full rounded-lg border border-zinc-300 bg-white px-3 py-1.5 text-sm dark:border-zinc-600 dark:bg-zinc-900";
  const canSubmit = !busy && !localError && current.length > 0 && next.length >= MIN_LEN && next === confirm;

  return (
    <form onSubmit={submit} className="mt-3 space-y-2 border-t border-zinc-200 pt-3 dark:border-zinc-700">
      <h3 className="text-sm font-semibold">パスワードの変更</h3>
      <div className="grid gap-2 sm:grid-cols-3">
        <label className="text-sm">
          <span className="mb-1 block text-xs text-zinc-500">現在のパスワード</span>
          <input type="password" autoComplete="current-password" className={field}
            value={current} onChange={(e) => setCurrent(e.target.value)} />
        </label>
        <label className="text-sm">
          <span className="mb-1 block text-xs text-zinc-500">新しいパスワード（{MIN_LEN}文字以上）</span>
          <input type="password" autoComplete="new-password" className={field}
            value={next} onChange={(e) => setNext(e.target.value)} />
        </label>
        <label className="text-sm">
          <span className="mb-1 block text-xs text-zinc-500">新しいパスワード（確認）</span>
          <input type="password" autoComplete="new-password" className={field}
            value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </label>
      </div>
      {localError && <p className="text-xs text-amber-700 dark:text-amber-300">{localError}</p>}
      {msg && (
        <p role="status" className={`text-xs ${msg.ok ? "text-emerald-700 dark:text-emerald-300" : "text-red-700 dark:text-red-300"}`}>
          {msg.text}
        </p>
      )}
      <button type="submit" disabled={!canSubmit}
        className="rounded-lg bg-zinc-900 px-3 py-1.5 text-sm font-medium text-white disabled:opacity-40 dark:bg-white dark:text-zinc-900">
        {busy ? "変更中…" : "パスワードを変更"}
      </button>
    </form>
  );
}
