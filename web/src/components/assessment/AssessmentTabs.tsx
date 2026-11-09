"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useState } from "react";
import { getJSON } from "@/lib/api";
import { fmtTime } from "@/lib/labels";
import { useAssessment } from "@/lib/useAssessment";
import { FindingCard } from "../findings/FindingCard";
import { WorkspaceHeader } from "../layout/WorkspaceHeader";
import { EventTimeline } from "../logs/EventTimeline";
import { RawLogViewer } from "../logs/RawLogViewer";
import { Card } from "../ui";
import { AgentActivity } from "./AgentActivity";
import { PhaseTimeline } from "./PhaseTimeline";

const TABS = [
  { key: "assessment", label: "診断" },
  { key: "findings", label: "問題" },
  { key: "logs", label: "ログ" },
] as const;

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function AssessmentTabs({ id }: { id: string }) {
  const tab = (useSearchParams().get("tab") ?? "assessment") as (typeof TABS)[number]["key"];
  const { snap, setSnap, error, conn, audit, chainValid, notes, refetch } = useAssessment(id);
  const [reportMd, setReportMd] = useState<string | null>(null);
  const [reportBusy, setReportBusy] = useState(false);

  if (!snap) {
    return (
      <div className="p-6 text-sm">
        {error ? <p role="alert" className="text-red-700">読み込めませんでした：{error}（制御プレーン `python3 -m aegis.server` が起動しているか確認してください）</p> : "読み込み中…"}
      </div>
    );
  }
  const findings = [...snap.findings].sort(
    (a, b) => Number(a.demo_fixture) - Number(b.demo_fixture) || SEV_ORDER[a.severity] - SEV_ORDER[b.severity],
  );
  const counts = { findings: snap.findings.filter((f) => !f.demo_fixture).length, logs: audit.length };
  const auth = snap.authorization;
  const hist = snap.history;

  const exportReport = async () => {
    setReportBusy(true);
    try {
      const r = await getJSON<{ markdown: string; filename: string }>(`/api/assessments/${snap.id}/report`);
      setReportMd(r.markdown);
      const blob = new Blob([r.markdown], { type: "text/markdown;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = r.filename;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setReportBusy(false);
    }
  };

  return (
    <div className="flex min-h-dvh flex-col">
      <WorkspaceHeader snap={snap} conn={conn} onUpdate={setSnap} refetch={refetch} />
      <div role="tablist" aria-label="ワークスペース" className="flex gap-1 border-b border-zinc-200 px-4 md:px-6 dark:border-zinc-800">
        {TABS.map((t) => (
          <Link
            key={t.key}
            role="tab"
            aria-selected={tab === t.key}
            href={`?tab=${t.key}`}
            scroll={false}
            className={`-mb-px border-b-2 px-3 py-2.5 text-sm ${tab === t.key ? "border-zinc-900 font-semibold dark:border-white" : "border-transparent text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100"}`}
          >
            {t.label}
            {t.key !== "assessment" && <span className="ml-1 text-xs text-zinc-500">{counts[t.key]}</span>}
          </Link>
        ))}
      </div>

      <main className="mx-auto w-full max-w-5xl flex-1 p-4 md:p-6">
        {snap.demo && (
          <p className="mb-4 rounded-lg bg-violet-50 px-3 py-2 text-xs text-violet-900 dark:bg-violet-950/40 dark:text-violet-200">
            ローカル検証ラボ（127.0.0.1）でのデモです。検査・承認・緊急停止は実際のGatewayとWorkerで動きます。「架空データ」と表示された問題は表示例です。
          </p>
        )}

        {tab === "assessment" && (
          <div className="grid gap-6 lg:grid-cols-[1fr_18rem]">
            <AgentActivity snap={snap} notes={notes} onUpdate={setSnap} />
            <div className="space-y-4">
              <Card>
                <h2 className="mb-3 text-sm font-semibold">進捗</h2>
                <PhaseTimeline phases={snap.phases} />
              </Card>
              <Card>
                <h2 className="mb-2 text-sm font-semibold">診断許可</h2>
                <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                  <dt className="text-zinc-500">書面許可</dt><dd>{auth.ref}</dd>
                  <dt className="text-zinc-500">所有確認</dt><dd>{auth.ownership_verified ? "確認済み" : "未確認"}</dd>
                  <dt className="text-zinc-500">期間</dt><dd>{fmtTime(auth.not_before)} 〜 {fmtTime(auth.not_after)}</dd>
                  <dt className="text-zinc-500">対象</dt><dd className="break-all">{auth.scope.hosts.join(", ")}</dd>
                  <dt className="text-zinc-500">許可IP</dt><dd>{auth.scope.cidrs.join(", ")}</dd>
                  <dt className="text-zinc-500">ポート</dt><dd>{auth.scope.ports.join(", ")}</dd>
                  <dt className="text-zinc-500">許可操作</dt><dd>{auth.allowed_actions.join(", ")}</dd>
                </dl>
              </Card>
              {snap.defense_comparison && (
                <Card className="border-emerald-300 dark:border-emerald-800">
                  <h2 className="mb-2 text-sm font-semibold text-emerald-800 dark:text-emerald-300">
                    ✓ 修正前後の防御比較（実測）
                  </h2>
                  <p className="mb-2 text-xs">
                    総合リスク：<span className="font-bold">{snap.defense_comparison.before_score}/100</span>
                    {" → "}
                    <span className="font-bold text-emerald-700 dark:text-emerald-300">
                      {snap.defense_comparison.after_score}/100
                    </span>
                  </p>
                  <ul className="space-y-1 text-xs">
                    {snap.defense_comparison.items.map((it) => (
                      <li key={it.id} className="rounded bg-emerald-50/70 p-1.5 dark:bg-emerald-950/30">
                        <div className="font-medium">{it.title}</div>
                        <div className="text-zinc-600 dark:text-zinc-400">
                          {it.before_verdict} → <span className="font-semibold text-emerald-700 dark:text-emerald-300">{it.after_verdict}</span>
                          {it.latest_evidence_id && <span className="ml-1 font-mono">({it.latest_evidence_id})</span>}
                        </div>
                      </li>
                    ))}
                  </ul>
                </Card>
              )}
              {hist && (
                <Card>
                  <h2 className="mb-2 text-sm font-semibold">前回診断との履歴比較</h2>
                  <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                    <dt className="text-zinc-500">前回 ({hist.previous_assessment_id})</dt>
                    <dd>{hist.previous_score}/100（{hist.previous_label}）</dd>
                    <dt className="text-zinc-500">スコア差分</dt>
                    <dd className="font-semibold">
                      {hist.delta_score === null
                        ? "診断後に算出"
                        : hist.delta_score > 0
                          ? `+${hist.delta_score} pt`
                          : `${hist.delta_score} pt（改善）`}
                    </dd>
                    <dt className="text-zinc-500">解消確認</dt>
                    <dd className="text-emerald-700 dark:text-emerald-300">{hist.resolved_findings.join("、")}</dd>
                  </dl>
                </Card>
              )}
              <Link href="?tab=findings" scroll={false} className="block rounded-xl border border-zinc-300 py-2 text-center text-sm font-semibold hover:bg-zinc-100 dark:border-zinc-700 dark:hover:bg-zinc-900">
                問題を見る →
              </Link>
              <button
                type="button"
                disabled={reportBusy}
                onClick={exportReport}
                className="w-full rounded-xl border border-zinc-300 py-2 text-center text-sm font-semibold hover:bg-zinc-100 disabled:opacity-50 dark:border-zinc-700 dark:hover:bg-zinc-900"
              >
                {reportBusy ? "レポート生成中…" : "⇩ 診断レポート出力 (Markdown)"}
              </button>
              {reportMd && (
                <details className="rounded-xl border border-zinc-200 p-2 text-xs dark:border-zinc-800">
                  <summary className="cursor-pointer font-semibold">レポートプレビューを表示</summary>
                  <pre className="mt-2 max-h-60 overflow-auto whitespace-pre-wrap rounded bg-zinc-50 p-2 text-[11px] dark:bg-zinc-950">
                    {reportMd}
                  </pre>
                </details>
              )}
            </div>
          </div>
        )}

        {tab === "findings" && (
          <div className="grid gap-3 md:grid-cols-2">
            {counts.findings === 0 && (
              <p className="text-sm text-zinc-500 md:col-span-2">
                {snap.state === "idle" ? "診断を開始すると、ここに問題が表示されます。" : "まだ問題は検出されていません（未検出は安全という意味ではありません）。"}
              </p>
            )}
            {findings.map((f) => <FindingCard key={f.id} f={f} assessmentId={snap.id} />)}
          </div>
        )}

        {tab === "logs" && (
          <div className="space-y-4">
            <EventTimeline entries={audit} chainValid={chainValid} />
            <RawLogViewer entries={audit} />
          </div>
        )}
      </main>
    </div>
  );
}
