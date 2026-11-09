"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Card, Pill } from "@/components/ui";
import { getJSON } from "@/lib/api";
import type { Asset } from "@/lib/types";

const STATUS_CLS: Record<string, string> = {
  診断済み: "bg-emerald-100 text-emerald-900 dark:bg-emerald-900/50 dark:text-emerald-100",
  診断中: "bg-blue-600 text-white",
  一時停止中: "bg-amber-400 text-amber-950",
  中止: "bg-red-700 text-white",
  承認待ち: "bg-amber-200 text-amber-950",
  未診断: "bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-100",
};

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getJSON<Asset[]>("/api/assets").then(setAssets, (e) => setErr(e.message));
  }, []);

  return (
    <main className="mx-auto max-w-5xl p-4 md:p-8">
      <h1 className="mb-1 text-2xl font-bold">資産管理</h1>
      <p className="mb-6 text-sm text-zinc-500">
        診断対象の一覧です。未診断の資産を安全とは判定しません。診断には書面許可と所有確認が必要です。
      </p>
      {err && <p role="alert" className="text-sm text-red-700">読み込めませんでした：{err}</p>}
      {!assets && !err && <p className="text-sm text-zinc-500">読み込み中…</p>}

      <Card className="overflow-hidden p-0">
        <table className="w-full text-sm">
          <thead className="border-b border-zinc-200 bg-zinc-50 text-left text-xs text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900/60">
            <tr>
              <th scope="col" className="px-4 py-2 font-medium">資産</th>
              <th scope="col" className="hidden px-4 py-2 font-medium sm:table-cell">種別</th>
              <th scope="col" className="hidden px-4 py-2 font-medium md:table-cell">環境</th>
              <th scope="col" className="px-4 py-2 font-medium">状態</th>
              <th scope="col" className="px-4 py-2 font-medium">リスク</th>
              <th scope="col" className="px-4 py-2" />
            </tr>
          </thead>
          <tbody>
            {assets?.map((a) => (
              <tr key={a.id} className="border-b border-zinc-100 last:border-0 dark:border-zinc-800/60">
                <td className="px-4 py-3">
                  <div className="font-medium">{a.name}</div>
                  {a.note && <div className="text-xs text-amber-800 dark:text-amber-300">{a.note}</div>}
                </td>
                <td className="hidden px-4 py-3 text-zinc-500 sm:table-cell">{a.kind}</td>
                <td className="hidden px-4 py-3 text-zinc-500 md:table-cell">{a.environment}</td>
                <td className="px-4 py-3">
                  <Pill className={STATUS_CLS[a.status] ?? "bg-zinc-200 text-zinc-800"}>{a.status}</Pill>
                </td>
                <td className="px-4 py-3 tabular-nums">
                  {a.risk ? `${a.risk.score}/100` : <span className="text-zinc-400">—</span>}
                </td>
                <td className="px-4 py-3 text-right">
                  {a.assessment_id ? (
                    <Link href={`/assessments/${a.assessment_id}`} className="font-semibold underline-offset-2 hover:underline">
                      開く →
                    </Link>
                  ) : (
                    <span className="text-xs text-zinc-400">診断不可</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </main>
  );
}
