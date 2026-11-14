"use client";

import Link from "next/link";
import { useEffect, useState, useSyncExternalStore } from "react";
import { postJSON } from "@/lib/api";
import { inviteTokenFromHash, ORG_ROLE_LABELS, selectOrg } from "@/lib/org";
import { useSession } from "@/lib/useSession";

/** /invite#inv_xxx — join an organization. The token stays in the URL fragment, so it is
 *  never sent to a server log; it is posted once, to the control plane, on "参加する". */
export default function InvitePage() {
  const { session, loading, refresh } = useSession();
  const hash = useSyncExternalStore(subscribeHash, () => window.location.hash, () => "");
  const token = inviteTokenFromHash(hash);
  const [state, setState] = useState<"idle" | "busy" | "done">("idle");
  const [err, setErr] = useState<string | null>(null);
  const [joined, setJoined] = useState<{ name: string; roles: string[] } | null>(null);

  useEffect(() => {
    try {
      if (token) sessionStorage.setItem("vulnix_invite", token);      // kept for sign-up on /login
    } catch { /* storage unavailable: the user can reopen the link */ }
  }, [token]);

  const accept = async () => {
    if (!token) return;
    setState("busy");
    setErr(null);
    try {
      const res = await postJSON<{ org: { id: string; name: string }; roles: string[] }>("/api/invites/accept", { token });
      try { sessionStorage.removeItem("vulnix_invite"); } catch { /* ignore */ }
      selectOrg(res.org.id);
      setJoined({ name: res.org.name, roles: res.roles });
      setState("done");
      await refresh();
    } catch (e) {
      setErr((e as Error).message);
      setState("idle");
    }
  };

  return (
    <div className="flex min-h-dvh items-center justify-center bg-zinc-50 px-4 dark:bg-zinc-950">
      <div className="w-full max-w-md rounded-2xl border border-zinc-200 bg-white p-8 dark:border-zinc-800 dark:bg-zinc-900">
        <h1 className="text-xl font-bold">組織への招待</h1>
        {!token ? (
          <p className="mt-3 text-sm text-zinc-600 dark:text-zinc-400">招待リンクが正しくありません。招待した人にリンクをもう一度送ってもらってください。</p>
        ) : loading ? (
          <p className="mt-3 text-sm text-zinc-500">読み込み中…</p>
        ) : !session ? (
          <>
            <p className="mt-3 text-sm leading-relaxed text-zinc-600 dark:text-zinc-400">
              参加するには、ログインするか新しくアカウントを作成してください。作成したアカウントは、この招待の組織に参加します。
            </p>
            <Link href="/login" className="mt-6 block rounded-lg bg-zinc-900 py-2 text-center text-sm font-semibold text-white dark:bg-white dark:text-zinc-900">
              ログイン / 新規登録へ
            </Link>
          </>
        ) : state === "done" && joined ? (
          <>
            <p className="mt-3 text-sm text-zinc-700 dark:text-zinc-300">
              「{joined.name}」に {joined.roles.map((r) => ORG_ROLE_LABELS[r] ?? r).join("・")} として参加しました。
            </p>
            <Link href="/dashboard" className="mt-6 block rounded-lg bg-zinc-900 py-2 text-center text-sm font-semibold text-white dark:bg-white dark:text-zinc-900">
              ダッシュボードへ
            </Link>
          </>
        ) : (
          <>
            <p className="mt-3 text-sm text-zinc-600 dark:text-zinc-400">
              {session.operator} として組織に参加します。招待は一度だけ使え、使うと無効になります。
            </p>
            {err && <p role="alert" className="mt-3 text-sm text-red-700 dark:text-red-300">{err}</p>}
            <button type="button" onClick={accept} disabled={state === "busy"}
              className="mt-6 w-full rounded-lg bg-zinc-900 py-2 text-sm font-semibold text-white disabled:opacity-50 dark:bg-white dark:text-zinc-900">
              {state === "busy" ? "参加中…" : "参加する"}
            </button>
          </>
        )}
      </div>
    </div>
  );
}

function subscribeHash(cb: () => void) {
  window.addEventListener("hashchange", cb);
  return () => window.removeEventListener("hashchange", cb);
}
