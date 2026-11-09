"use client";

import Link from "next/link";
import { useState } from "react";
import { postJSON } from "@/lib/api";
import type { Finding, Snapshot } from "@/lib/types";
import { HelpPopover } from "../learning/HelpPopover";
import { Card, FixtureBadge, Pill, SeverityBadge, VerdictBadge } from "../ui";

export function FindingCard({
  f,
  assessmentId,
  onUpdate,
}: {
  f: Finding;
  assessmentId: string;
  onUpdate?: (s: Snapshot) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const runLiveVerify = async () => {
    setBusy(true);
    setErr(null);
    try {
      const snap = await postJSON<Snapshot>(`/api/assessments/${assessmentId}/verify-finding`, {
        finding_id: f.id,
      });
      onUpdate?.(snap);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="flex flex-col justify-between">
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge s={f.severity} />
          <VerdictBadge v={f.verdict} />
          {(f._in_verification || busy) && <Pill className="bg-blue-600 text-white">実機Worker検証中</Pill>}
          {f.demo_fixture && <FixtureBadge />}
          <span className="ml-auto font-mono text-[11px] text-zinc-500">
            Worker: {f.executor.tool}
          </span>
        </div>
        <h3 className="mt-2 flex items-center font-semibold">
          {f.title}
          {f.help_term && <HelpPopover term={f.help_term} context={f.why_detected} findingId={f.id} />}
        </h3>
        <p className="mt-1 text-sm text-zinc-700 dark:text-zinc-300">{f.what_was_established ?? f.summary}</p>
        {f.verdict_note && (
          <p className="mt-1.5 rounded bg-zinc-100 px-2 py-1 text-xs text-zinc-700 dark:bg-zinc-800/80 dark:text-zinc-300">
            {f.verdict_note}
          </p>
        )}
        {f.cve.length > 0 && <p className="mt-1 font-mono text-xs text-zinc-500">{f.cve.join(" / ")}</p>}
        {err && <p className="mt-1 text-xs text-red-600 dark:text-red-400">{err}</p>}
      </div>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-zinc-100 pt-2.5 text-xs text-zinc-500 dark:border-zinc-800">
        <span>{f.category}・実測証拠 {f.evidence.length} 件</span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={busy}
            onClick={runLiveVerify}
            className="rounded-lg bg-zinc-900 px-2.5 py-1 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900"
          >
            {busy ? "Worker実行中…" : "▶ 実機Workerで今すぐ検証"}
          </button>
          <Link href={`/findings/${f.id}?a=${assessmentId}`} className="font-semibold text-zinc-900 underline-offset-2 hover:underline dark:text-zinc-100">
            詳しく見る →
          </Link>
        </div>
      </div>
    </Card>
  );
}
