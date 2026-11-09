"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { RiskScore } from "@/components/findings/RiskScore";
import { Card, Pill } from "@/components/ui";
import { getJSON } from "@/lib/api";
import type { Asset } from "@/lib/types";

const STATUS_CLS: Record<string, string> = {
  診断済み: "bg-emerald-100 text-emerald-900 dark:bg-emerald-900/50 dark:text-emerald-100",
  診断中: "bg-blue-600 text-white",
  承認待ち: "bg-amber-200 text-amber-950",
  未診断: "bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-100",
};

export default function Dashboard() {
  const [assets, setAssets] = useState<Asset[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getJSON<Asset[]>("/api/assets").then(setAssets, (e) => setErr(e.message));
  }, []);

  return (
    <main className="mx-auto max-w-5xl p-4 md:p-8">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-bold">セキュリティ診断</h1>
        <Link href="/assessments/scan_001" className="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-semibold text-white hover:bg-zinc-700 dark:bg-white dark:text-zinc-900">
          ＋ 新しい診断
        </Link>
      </div>
      {err && <p role="alert" className="text-sm text-red-700">読み込めませんでした：{err}</p>}
      {!assets && !err && <p className="text-sm text-zinc-500">読み込み中…</p>}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {assets?.map((a) => {
          const body = (
            <Card className={`h-full ${a.assessment_id ? "transition hover:border-zinc-400 dark:hover:border-zinc-600" : "opacity-90"}`}>
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="truncate font-semibold">{a.name}</div>
                  <div className="text-xs text-zinc-500">{a.kind}・{a.environment}</div>
                </div>
                <Pill className={STATUS_CLS[a.status] ?? "bg-zinc-200 text-zinc-800"}>{a.status}</Pill>
              </div>
              <div className="mt-4">
                <RiskScore risk={a.risk} compact />
              </div>
              {a.note && <p className="mt-2 text-xs text-amber-800 dark:text-amber-300">{a.note}</p>}
            </Card>
          );
          return a.assessment_id ? (
            <Link key={a.id} href={`/assessments/${a.assessment_id}`}>{body}</Link>
          ) : (
            <div key={a.id}>{body}</div>
          );
        })}
      </div>
      <p className="mt-6 text-xs text-zinc-500">
        未診断の資産を安全とは判定しません。診断には書面許可と所有確認が必要です。
      </p>
    </main>
  );
}
