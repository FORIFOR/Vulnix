"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import { postJSON } from "@/lib/api";

interface FinishResponse {
  host: string;
  verified: boolean;
}

/** Google sends the browser back here; the server finishes the check (the code is
 * exchanged and used on the server only) and the dialog continues on the dashboard. */
function Finish() {
  const params = useSearchParams();
  const router = useRouter();
  const code = params.get("code");
  const state = params.get("state");
  const cancelled = !code || !state;
  const [msg, setMsg] = useState(cancelled ? "Google での確認がキャンセルされました。" : "Google での確認結果を受け取っています…");
  const done = useRef(false);

  useEffect(() => {
    if (done.current) return;
    done.current = true;
    // the one-time code leaves the address bar (and history) at once
    window.history.replaceState(null, "", "/verify/google");
    if (!code || !state) {
      const t = setTimeout(() => router.replace("/dashboard"), 1500);
      return () => clearTimeout(t);
    }
    postJSON<FinishResponse>("/api/assets/google/finish", { code, state }).then(
      (res) => {
        const q = new URLSearchParams({ resume: res.host });
        if (!res.verified) q.set("google", "failed");
        router.replace(`/dashboard?${q.toString()}`);
      },
      (e) => {
        setMsg((e as Error).message);
        setTimeout(() => router.replace("/dashboard"), 2500);
      },
    );
  }, [code, state, router]);

  return (
    <main className="flex min-h-[60dvh] items-center justify-center p-6">
      <p role="status" className="text-sm text-zinc-600 dark:text-zinc-300">{msg}</p>
    </main>
  );
}

export default function GoogleVerifyPage() {
  return (
    <Suspense fallback={null}>
      <Finish />
    </Suspense>
  );
}
