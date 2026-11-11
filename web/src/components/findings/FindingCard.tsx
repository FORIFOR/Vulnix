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
  labEndpoint,
  onUpdate,
  onBusyChange,
}: {
  f: Finding;
  assessmentId: string;
  labEndpoint: string;
  onUpdate?: (s: Snapshot) => void;
  onBusyChange?: (busy: boolean) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [showLog, setShowLog] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const latestEv = f.evidence.at(-1);
  // L2 on a real service: an explicit, per-item approval by an approver.
  const needsApproval = Boolean(f.requires_l2_approval);
  const blocked = needsApproval && f.l2_ready === false && f.evidence.length === 0;

  const runLiveVerify = async () => {
    setBusy(true);
    setShowLog(true);
    onBusyChange?.(true);
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
      onBusyChange?.(false);
    }
  };

  return (
    <Card className="flex flex-col justify-between">
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge s={f.severity} />
          {f.evidence_status === "candidate" ? <Pill className="border border-zinc-400">未計測の候補</Pill> : <VerdictBadge v={f.verdict} />}
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

        {(busy || latestEv) && (
          <div className="mt-2.5 overflow-hidden rounded-xl border border-zinc-200 bg-zinc-50/90 text-xs dark:border-zinc-800 dark:bg-zinc-900/60">
            <button
              type="button"
              onClick={() => setShowLog((v) => !v)}
              aria-expanded={showLog || busy}
              className="flex w-full items-center justify-between px-3 py-1.5 text-left font-medium text-zinc-700 hover:bg-zinc-100 dark:text-zinc-300 dark:hover:bg-zinc-800/60"
            >
              <span className="flex items-center gap-2">
                {busy ? (
                  <span className="inline-block h-2 w-2 animate-ping rounded-full bg-blue-600" />
                ) : (
                  <span className="text-emerald-600 dark:text-emerald-400">✦</span>
                )}
                <span>
                  {busy
                    ? `計画・Worker実行中（${f.executor.tool} → ${labEndpoint}）…`
                    : `計画・Worker実行ログ（最新証拠 ${latestEv?.evidence_id}）`}
                </span>
              </span>
              <span className="text-[11px] text-zinc-500">{showLog ? "閉じる ▴" : "表示 ▾"}</span>
            </button>
            {(showLog || busy) && (
              <div className="space-y-1.5 border-t border-zinc-200/80 px-3 py-2 dark:border-zinc-800">
                <ol className="space-y-1 border-l-2 border-zinc-300 pl-2.5 text-[11px] text-zinc-600 dark:border-zinc-700 dark:text-zinc-300">
                  <li>1. 仮説形成：{f.why_detected}</li>
                  <li>2. Gateway検査：単一使用トークン発行・EgressGuard ({labEndpoint}) 固定・egress_sentinel 隔離起動</li>
                  <li>
                    3. Worker結果：
                    {busy ? " 応答待機中…" : ` 判定=${f.verdict} / 監査ハッシュ #${latestEv?.audit_hash?.slice(0, 12) ?? "—"}`}
                  </li>
                </ol>
                {latestEv?.content && (
                  <pre className="max-h-36 overflow-auto rounded-lg bg-zinc-950 p-2 font-mono text-[11px] text-emerald-300">
                    {latestEv.content}
                  </pre>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-zinc-100 pt-2.5 text-xs text-zinc-500 dark:border-zinc-800">
        <span>{f.category}・実測証拠 {f.evidence.length} 件</span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={busy || blocked}
            title={blocked ? "先に、診断画面上部の「L2検証用アカウント」でこの項目に必要なアカウントを設定してください" : undefined}
            onClick={runLiveVerify}
            className="rounded-lg bg-zinc-900 px-2.5 py-1 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900"
          >
            {busy
              ? "Worker実行中…"
              : blocked
                ? "検証用アカウント未設定"
                : needsApproval
                  ? "✓ 承認してL2検証を実行"
                  : "▶ 実機Workerで今すぐ検証"}
          </button>
          <Link href={`/findings/${f.id}?a=${assessmentId}`} className="font-semibold text-zinc-900 underline-offset-2 hover:underline dark:text-zinc-100">
            詳しく見る →
          </Link>
        </div>
      </div>
    </Card>
  );
}
