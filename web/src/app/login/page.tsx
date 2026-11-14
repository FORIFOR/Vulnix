"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { useSession } from "@/lib/useSession";

export default function LoginPage() {
  const { session, loading, refresh } = useSession();
  const router = useRouter();
  const [mode, setMode] = useState<"login" | "register">("login");

  // Login state
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);

  // Registration state
  const [regName, setRegName] = useState("");
  const [regDisplay, setRegDisplay] = useState("");
  const [regPassword, setRegPassword] = useState("");
  const [regConfirm, setRegConfirm] = useState("");

  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!loading && session) router.replace("/dashboard");
  }, [loading, session, router]);

  // Self-registration exists only in development mode; otherwise an admin creates accounts.
  const [selfRegistration, setSelfRegistration] = useState(false);
  useEffect(() => {
    let live = true;
    fetch("/api/auth/me", { cache: "no-store" })
      .then((r) => r.json())
      .then((d) => { if (live) setSelfRegistration(Boolean(d?.self_registration)); })
      .catch(() => {});
    return () => { live = false; };
  }, []);

  const submitLogin = async (e: React.FormEvent) => {
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

  const submitRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (regPassword !== regConfirm) {
      setErr("確認用パスワードが一致しません");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Aegis-Request": "1" },
        body: JSON.stringify({
          name: regName.trim(),
          display: regDisplay.trim() || regName.trim(),
          password: regPassword,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
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
      <div className="w-full max-w-md rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
        <div className="mb-5 flex items-center gap-2.5">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-zinc-900 text-sm font-bold text-white dark:bg-white dark:text-zinc-900">
            V
          </span>
          <div className="leading-tight">
            <div className="font-semibold">Vulnix</div>
            <div className="text-xs text-zinc-500">Find. Prove. Secure. — AI Security Testing Platform</div>
          </div>
        </div>

        {/* Mode Switcher: Login vs Register */}
        <div role="tablist" className={`mb-5 grid ${selfRegistration ? "grid-cols-2" : "grid-cols-1"} rounded-xl bg-zinc-100 p-1 text-xs font-semibold dark:bg-zinc-800`}>
          <button
            type="button"
            role="tab"
            aria-selected={mode === "login"}
            onClick={() => {
              setMode("login");
              setErr(null);
            }}
            className={`rounded-lg py-2 transition ${
              mode === "login"
                ? "bg-white text-zinc-900 shadow-xs dark:bg-zinc-900 dark:text-white"
                : "text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200"
            }`}
          >
            ログイン
          </button>
          {selfRegistration && <button
            type="button"
            role="tab"
            aria-selected={mode === "register"}
            onClick={() => {
              setMode("register");
              setErr(null);
            }}
            className={`rounded-lg py-2 transition ${
              mode === "register"
                ? "bg-white text-zinc-900 shadow-xs dark:bg-zinc-900 dark:text-white"
                : "text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200"
            }`}
          >
            新規アカウント登録（開発モード）
          </button>}
        </div>

        {mode === "login" ? (
          <form onSubmit={submitLogin}>
            <label className="mb-1 block text-sm font-medium" htmlFor="name">
              ユーザー名
            </label>
            <input
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoComplete="username"
              autoFocus
              className="mb-3 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm dark:border-zinc-600 dark:bg-zinc-950"
            />
            <label className="mb-1 block text-sm font-medium" htmlFor="password">
              パスワード
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              className="mb-4 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm dark:border-zinc-600 dark:bg-zinc-950"
            />
            {mfaRequired && (
              <>
                <label className="mb-1 block text-sm font-medium" htmlFor="code">
                  認証コード（2要素）
                </label>
                <input
                  id="code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  autoFocus
                  placeholder="000000"
                  className="mb-4 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm tabular-nums tracking-widest dark:border-zinc-600 dark:bg-zinc-950"
                />
              </>
            )}
            {err && (
              <p role="alert" className="mb-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-800 dark:bg-red-950/40 dark:text-red-200">
                {err}
              </p>
            )}
            <button
              type="submit"
              disabled={busy || !name || !password || (mfaRequired && !code)}
              className="w-full rounded-lg bg-zinc-900 py-2.5 text-sm font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900"
            >
              {busy ? "確認中…" : "ログイン"}
            </button>
            <p className="mt-4 text-xs leading-relaxed text-zinc-500">
              {selfRegistration
                ? "アカウントをお持ちでない場合は上の「新規アカウント登録」タブから登録できます（開発モードのみ）。"
                : "アカウントは管理者が作成します（設定 → アカウントとロール）。"}
              初期生成アカウント情報は
              <code className="mx-1 rounded bg-zinc-100 px-1 dark:bg-zinc-800">operators.initial-credentials.txt</code>
              にも保存されています。
            </p>
          </form>
        ) : (
          <form onSubmit={submitRegister}>
            <label className="mb-1 block text-sm font-medium" htmlFor="reg-name">
              ユーザー名（半角英数字・2〜32文字）
            </label>
            <input
              id="reg-name"
              value={regName}
              onChange={(e) => setRegName(e.target.value)}
              placeholder="例: sec-admin"
              autoComplete="username"
              autoFocus
              className="mb-3 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm dark:border-zinc-600 dark:bg-zinc-950"
            />

            <label className="mb-1 block text-sm font-medium" htmlFor="reg-display">
              表示名（任意）
            </label>
            <input
              id="reg-display"
              value={regDisplay}
              onChange={(e) => setRegDisplay(e.target.value)}
              placeholder="例: セキュリティ診断責任者"
              className="mb-3 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm dark:border-zinc-600 dark:bg-zinc-950"
            />

            <div className="mb-3 grid gap-2 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-sm font-medium" htmlFor="reg-pw">
                  パスワード（10文字以上）
                </label>
                <input
                  id="reg-pw"
                  type="password"
                  value={regPassword}
                  onChange={(e) => setRegPassword(e.target.value)}
                  autoComplete="new-password"
                  className="w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm dark:border-zinc-600 dark:bg-zinc-950"
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium" htmlFor="reg-confirm">
                  パスワード（確認）
                </label>
                <input
                  id="reg-confirm"
                  type="password"
                  value={regConfirm}
                  onChange={(e) => setRegConfirm(e.target.value)}
                  autoComplete="new-password"
                  className="w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm dark:border-zinc-600 dark:bg-zinc-950"
                />
              </div>
            </div>

            <div className="mb-4 rounded-xl border border-zinc-200 bg-zinc-50 p-3 text-xs dark:border-zinc-800 dark:bg-zinc-950/60">
              <div className="mb-1 font-semibold">付与される権限ロール</div>
              <p className="text-zinc-600 dark:text-zinc-400">
                登録したアカウントは操作者（operator）になります。承認責任者（approver）のロールは自分では付与できません。
                必要な場合は、管理者に「設定 → アカウントとロール」から付与を依頼してください。
              </p>
            </div>

            {err && (
              <p role="alert" className="mb-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-800 dark:bg-red-950/40 dark:text-red-200">
                {err}
              </p>
            )}

            <button
              type="submit"
              disabled={busy || regName.trim().length < 2 || regPassword.length < 10 || !regConfirm}
              className="w-full rounded-lg bg-zinc-900 py-2.5 text-sm font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900"
            >
              {busy ? "登録中…" : "アカウントを登録して開始"}
            </button>
            <p className="mt-3 text-[11px] text-zinc-500">
              パスワードは scrypt（N=2^15, r=8, p=1）でハッシュ化され、平文は保存されません。登録後、設定画面から2要素認証（TOTP）を有効化できます。
            </p>
          </form>
        )}
      </div>
    </main>
  );
}
