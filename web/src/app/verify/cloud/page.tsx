"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { postJSON } from "@/lib/api";

function ReturnFromGoogle() {
  const router = useRouter();
  const params = useSearchParams();
  const code = params.get("code");
  const state = params.get("state");
  const started = useRef(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    window.history.replaceState(null, "", "/verify/cloud");
    if (!code || !state) {
      router.replace("/assets?inventory=cancelled");
      return;
    }
    void postJSON("/api/assets/cloud-inventory", { action: "finish", code, state }).then(
      () => router.replace("/assets?inventory=connected"),
      (e: Error) => setError(e.message),
    );
  }, [code, state, router]);

  return <main className="mx-auto max-w-xl p-6">
    <h1 className="text-xl font-bold">Google Cloud の閲覧連携</h1>
    {error ? <><p role="alert" className="mt-3">{error}</p><Link className="underline" href="/assets">サイト一覧に戻る</Link></>
      : <p role="status" className="mt-3">プロジェクト一覧を確認しています…</p>}
  </main>;
}

export default function CloudInventoryCallback() {
  return <Suspense><ReturnFromGoogle /></Suspense>;
}
