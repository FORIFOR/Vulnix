"use client";

import { useState } from "react";
import { command } from "@/lib/api";
import { fmtTime } from "@/lib/labels";
import { canApprove, useSession } from "@/lib/useSession";
import type { AegisEvent, Approval, Snapshot } from "@/lib/types";
import { HelpPopover } from "../learning/HelpPopover";
import { Card, Pill } from "../ui";

function Bubble({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <span aria-hidden className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-zinc-900 text-xs font-bold text-white dark:bg-white dark:text-zinc-900">
        A
      </span>
      <div className="min-w-0 flex-1">
        <div className="mb-1 text-xs font-semibold text-zinc-500">Aegis</div>
        <div className="text-sm leading-relaxed">{children}</div>
      </div>
    </div>
  );
}

function headline(s: Snapshot): string {
  const running = s.phases.find((p) => p.status === "running");
  switch (s.state) {
    case "idle": return "診断はまだ開始していません。許可範囲を確認のうえ「診断を開始」を押してください。";
    case "paused": return "一時停止中です。新しい操作は実行されません（実行中の処理は完了まで続きます）。";
    case "stopped": return "緊急停止しました。実行許可を失効させ、実行中の処理を強制終了しました。";
    case "failed": return "診断を中断しました。ログで理由を確認してください。";
    case "completed": return `診断が完了しました。${s.findings.filter((f) => !f.demo_fixture).length} 件の問題を記録しています。`;
    default: return running ? `${running.label}：${running.detail}` : "処理を進めています。";
  }
}

function ApprovalCard({ ap, base, onUpdate, approver }: { ap: Approval; base: string; onUpdate: (s: Snapshot) => void; approver: boolean }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const decide = async (decision: "approve" | "reject") => {
    setBusy(true);
    try {
      onUpdate((await command(`${base}/approvals/${ap.id}`, { decision })) as Snapshot);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const status = { pending: "承認待ち", approved: "承認済み", rejected: "却下" }[ap.status];
  return (
    <div className={`rounded-xl border p-3 ${ap.status === "pending" ? "border-amber-400 bg-amber-50 dark:bg-amber-950/30" : "border-zinc-200 dark:border-zinc-700"}`}>
      <div className="flex flex-wrap items-center gap-2 text-sm font-semibold">
        {ap.title}
        <Pill className="bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-100">危険度 {ap.risk_level}</Pill>
        <HelpPopover term="risk_level" />
        <Pill className="border border-zinc-400">{status}</Pill>
        <HelpPopover term="approval" />
      </div>
      <p className="mt-1 text-sm text-zinc-700 dark:text-zinc-300">{ap.description}</p>
      {ap.status === "pending" ? (
        approver ? (
          <div className="mt-2 flex gap-2">
            <button disabled={busy} onClick={() => decide("approve")} className="rounded-lg bg-zinc-900 px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-50 dark:bg-white dark:text-zinc-900">
              承認して実行
            </button>
            <button disabled={busy} onClick={() => decide("reject")} className="rounded-lg border border-zinc-300 px-3 py-1.5 text-sm dark:border-zinc-600">
              却下
            </button>
          </div>
        ) : (
          <p className="mt-2 text-xs text-amber-800 dark:text-amber-300">
            この操作の承認には「承認責任者」の権限が必要です。承認責任者のアカウントでログインしてください。
          </p>
        )
      ) : (
        <p className="mt-1 text-xs text-zinc-500">{ap.decided_by}・{fmtTime(ap.decided_at)}</p>
      )}
      {err && <p role="alert" className="mt-1 text-xs text-red-700">{err}</p>}
    </div>
  );
}

export function AgentActivity({ snap, notes, onUpdate }: { snap: Snapshot; notes: AegisEvent[]; onUpdate: (s: Snapshot) => void }) {
  const a = snap.activity;
  const base = `/api/assessments/${snap.id}`;
  const approver = canApprove(useSession().session);
  return (
    <div className="space-y-4">
      <Bubble>{headline(snap)}</Bubble>

      {a && (
        <Card className="ml-11">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="font-semibold">{a.title}</div>
            {snap.approvals.some((x) => x.status === "pending") ? (
              <Pill className="bg-amber-300 text-amber-950">承認待ち</Pill>
            ) : (
              <Pill className="bg-blue-600 text-white">実行中</Pill>
            )}
          </div>
          <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
            <dt className="text-zinc-500">使用ツール</dt><dd>{a.tool}</dd>
            <dt className="text-zinc-500">実行主体</dt><dd>{a.agent}</dd>
            <dt className="text-zinc-500">モデル</dt><dd>{a.model}</dd>
            <dt className="flex items-center text-zinc-500">危険度<HelpPopover term="risk_level" /></dt><dd>{a.risk_level}</dd>
          </dl>
        </Card>
      )}

      {snap.approvals.length > 0 && (
        <div className="ml-11 space-y-2">
          {snap.approvals.map((ap) => <ApprovalCard key={ap.id} ap={ap} base={base} onUpdate={onUpdate} approver={approver} />)}
        </div>
      )}

      {notes.map((n) => (
        <Bubble key={n.event_id}>
          <span className="rounded bg-violet-100 px-1 text-xs text-violet-800 dark:bg-violet-900/50 dark:text-violet-200">安全制御</span>{" "}
          {String(n.message)}
        </Bubble>
      ))}

      {snap.stop_report && (
        <Card className="ml-11 border-red-300 dark:border-red-800">
          <div className="font-semibold text-red-700 dark:text-red-300">
            緊急停止の結果：{snap.stop_report.confirmed ? "停止を確認しました" : "停止を確認できていません"}
          </div>
          <ol className="mt-2 space-y-0.5 text-xs tabular-nums">
            {snap.stop_report.steps.map((s) => (
              <li key={s.name}>{s.name} — {s.elapsed_ms} ms</li>
            ))}
          </ol>
          <p className="mt-2 text-xs text-zinc-500">
            強制終了したWorker: {snap.stop_report.killed_pids.length} 件 / 残存: {snap.stop_report.survivors.length} 件。
            通信遮断はアプリ層のみ（OSレベルの遮断は未実装）。
          </p>
        </Card>
      )}

      <div className="ml-11">
        <label className="sr-only" htmlFor="ask">AIに質問する</label>
        <input id="ask" disabled placeholder="AIに質問する…（AIチャットは未接続です）"
          className="w-full cursor-not-allowed rounded-2xl border border-zinc-300 bg-zinc-50 px-4 py-3 text-sm dark:border-zinc-700 dark:bg-zinc-900" />
      </div>
    </div>
  );
}
