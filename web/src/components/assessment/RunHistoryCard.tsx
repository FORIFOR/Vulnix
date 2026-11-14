"use client";

import { Card } from "@/components/ui";
import { fmtTime } from "@/lib/labels";
import type { RunHistoryEntry } from "@/lib/types";

/** Completed runs of this organization's workspace, newest first (real records). */
export function RunHistoryCard({ runs }: { runs: RunHistoryEntry[] }) {
  return (
    <Card>
      <h2 className="mb-2 text-sm font-semibold">診断履歴</h2>
      {runs.length === 0 ? (
        <p className="text-xs text-zinc-500">完了した診断はまだありません。診断が完了すると、ここに記録されます。</p>
      ) : (
        <ol className="space-y-2 text-xs">
          {runs.slice(0, 10).map((r, i) => {
            const prev = runs[i + 1];
            const delta = prev && r.score != null && prev.score != null ? r.score - prev.score : null;
            return (
              <li key={`${r.at}-${i}`} className="rounded-lg border border-zinc-100 px-2.5 py-2 dark:border-zinc-800">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-medium">{r.asset}</span>
                  <span className="shrink-0 tabular-nums text-zinc-500">{fmtTime(r.at)}</span>
                </div>
                <div className="mt-1 flex flex-wrap gap-x-3 text-zinc-600 dark:text-zinc-400">
                  <span>リスク {r.score ?? "—"}/100（{r.label ?? "—"}）{delta != null && delta !== 0 && <span className={delta > 0 ? "text-red-700 dark:text-red-300" : "text-emerald-700 dark:text-emerald-300"}>（前回比 {delta > 0 ? "+" : ""}{delta}）</span>}</span>
                  <span>実証 {r.counts?.proven ?? 0}</span>
                  <span>検出・未実証 {r.counts?.detected ?? 0}</span>
                  <span>再現せず {r.counts?.not_reproduced ?? 0}</span>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </Card>
  );
}
