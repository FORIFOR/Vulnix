import Link from "next/link";
import type { EvidenceStatus, Snapshot } from "@/lib/types";

export const EVIDENCE_STATES: { key: EvidenceStatus; label: string; cls: string }[] = [
  { key: "candidate", label: "未計測の候補", cls: "text-zinc-700 dark:text-zinc-200" },
  { key: "detected", label: "検出・未実証", cls: "text-amber-700 dark:text-amber-300" },
  { key: "proven", label: "実証済み", cls: "text-red-700 dark:text-red-300" },
  { key: "not_reproduced", label: "再現せず", cls: "text-emerald-700 dark:text-emerald-300" },
  { key: "incomplete", label: "未完了・要確認", cls: "text-zinc-700 dark:text-zinc-200" },
];

export function EvidenceOverview({ snap, selected }: { snap: Snapshot; selected: string }) {
  return (
    <section aria-label="証拠の概要" className="mb-5 overflow-hidden rounded-2xl border border-zinc-200 bg-white shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-100 px-4 py-3 dark:border-zinc-800">
        <div>
          <h2 className="text-sm font-semibold">証拠で判断する</h2>
          <p className="mt-0.5 text-xs text-zinc-500">候補・検出・実証を区別。件数を選ぶと該当する問題を表示します。</p>
        </div>
        <Link href="?tab=findings" scroll={false} className="text-xs font-semibold underline underline-offset-4">すべての問題を見る</Link>
      </div>
      <div className="grid grid-cols-2 gap-2 p-3 sm:grid-cols-5">
        {EVIDENCE_STATES.map(({ key, label, cls }) => (
          <Link key={key} href={`?tab=findings&evidence=${key}`} scroll={false} aria-current={selected === key ? "true" : undefined}
            className={`rounded-xl border px-3 py-3 transition hover:bg-zinc-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 dark:hover:bg-zinc-800 ${selected === key ? "border-zinc-900 bg-zinc-50 dark:border-white dark:bg-zinc-800" : "border-zinc-200 dark:border-zinc-700"}`}>
            <span className={`block text-3xl font-bold tabular-nums ${cls}`}>{snap.evidence_summary[key] ?? 0}</span>
            <span className="mt-1 block text-xs font-medium">{label}</span>
          </Link>
        ))}
      </div>
      <p className="px-4 pb-3 text-[11px] leading-relaxed text-zinc-500">「再現せず」は今回の検証条件での結果です。安全性やすべての脆弱性の解消を保証するものではありません。</p>
    </section>
  );
}
