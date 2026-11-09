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
  const [regApprover, setRegApprover] = useState(true);

  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!loading && session) router.replace("/dashboard");
  }, [loading, session, router]);

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
          roles: regApprover ? ["operator", "approver"] : ["operator"],
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
        <div role="tablist" className="mb-5 grid grid-cols-2 rounded-xl bg-zinc-100 p-1 text-xs font-semibold dark:bg-zinc-800">
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
          <button
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
            新規アカウント登録
          </button>
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
              アカウントをお持ちでない場合は上の「<strong>新規アカウント登録</strong>」タブから即座に登録できます。初期生成アカウント情報は
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

            <div className="mb-4 rounded-xl border border-zinc-200 bg-zinc-50 p-3 dark:border-zinc-800 dark:bg-zinc-950/60">
              <div className="mb-1.5 text-xs font-semibold">付与する権限ロール</div>
              <label className="flex cursor-pointer items-start gap-2 text-xs">
                <input
                  type="checkbox"
                  checked={regApprover}
                  onChange={(e) => setRegApprover(e.target.checked)}
                  className="mt-0.5 rounded border-zinc-300"
                />
                <span>
                  <strong>承認責任者権限（approver）を含める</strong>
                  <span className="block text-[11px] text-zinc-500">
                    診断の開始・停止（operator）に加え、L2 侵入実証テストの人間承認および修正後の再検証を実行できます。
                  </span>
                </span>
              </label>
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
