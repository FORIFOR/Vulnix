"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useState } from "react";
import { getJSON, postJSON } from "@/lib/api";
import { fmtTime } from "@/lib/labels";
import type { Snapshot } from "@/lib/types";
import { useAssessment } from "@/lib/useAssessment";
import { FindingCard } from "../findings/FindingCard";
import { WorkspaceHeader } from "../layout/WorkspaceHeader";
import { EventTimeline } from "../logs/EventTimeline";
import { RawLogViewer } from "../logs/RawLogViewer";
import { Card } from "../ui";
import { AgentActivity } from "./AgentActivity";
import { PhaseTimeline } from "./PhaseTimeline";
import { ReasoningTrace } from "./ReasoningTrace";
import { EvidenceOverview, EVIDENCE_STATES } from "./EvidenceOverview";

const TABS = [
  { key: "assessment", label: "診断" },
  { key: "findings", label: "問題" },
  { key: "logs", label: "ログ" },
] as const;

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function AssessmentTabs({ id }: { id: string }) {
  const params = useSearchParams();
  const tabParam = params.get("tab");
  const tab = TABS.find((t) => t.key === tabParam)?.key ?? "assessment";
  const evidenceFilter = EVIDENCE_STATES.find((s) => s.key === params.get("evidence"))?.key ?? "all";
  const { snap, setSnap, error, conn, audit, chainValid, notes, refetch } = useAssessment(id);
  const [reportMd, setReportMd] = useState<string | null>(null);
  const [reportBusy, setReportBusy] = useState(false);
  const [reportErr, setReportErr] = useState<string | null>(null);
  const [labBusy, setLabBusy] = useState(false);
  const [cardBusy, setCardBusy] = useState(false);
  const [labErr, setLabErr] = useState<string | null>(null);

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
    if (reportBusy) return;
    setReportBusy(true);
    setReportErr(null);
    setReportMd(null);
    try {
      const r = await getJSON<{ markdown: string; filename: string }>(`/api/assessments/${snap.id}/report`);
      setReportMd(r.markdown);
      const blob = new Blob([r.markdown], { type: "text/markdown;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = r.filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      setReportErr((e as Error).message);
    } finally {
      setReportBusy(false);
    }
  };

  const runAllWorkers = async () => {
    setLabBusy(true);
    setLabErr(null);
    try {
      const updated = await postJSON<Snapshot>(`/api/assessments/${snap.id}/verify-finding`, {
        finding_id: "all",
      });
      setSnap(updated);
    } catch (e) {
      setLabErr((e as Error).message);
    } finally {
      setLabBusy(false);
    }
  };

  const toggleLabMode = async (mode: "vulnerable" | "patched") => {
    setLabBusy(true);
    setLabErr(null);
    try {
      await postJSON<Snapshot>(`/api/assessments/${snap.id}/lab-mode`, { mode });
      const updated = await postJSON<Snapshot>(`/api/assessments/${snap.id}/verify-finding`, {
        finding_id: "all",
      });
      setSnap(updated);
    } catch (e) {
      setLabErr((e as Error).message);
    } finally {
      setLabBusy(false);
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
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-violet-200 bg-violet-50/90 px-3.5 py-2.5 text-xs text-violet-950 dark:border-violet-900/60 dark:bg-violet-950/40 dark:text-violet-100">
            <div className="space-y-0.5">
              <div className="flex flex-wrap items-center gap-2 font-semibold">
                <span>ローカル模擬ラボ（{snap.lab_endpoint}）実測デモ</span>
                <span className={`rounded px-1.5 py-0.5 text-[11px] font-bold ${snap.lab_mode === "patched" ? "bg-emerald-200 text-emerald-950 dark:bg-emerald-900 dark:text-emerald-100" : "bg-amber-200 text-amber-950 dark:bg-amber-900 dark:text-amber-100"}`}>
                  現在：{snap.lab_mode === "patched" ? "防御挙動モード（模擬環境）" : "脆弱挙動モード（模擬環境）"}
                </span>
              </div>
              <p className="text-violet-800 dark:text-violet-200">
                Gateway と隔離 Worker がローカル HTTP 応答を実測します。Apache / IDOR / SQLi の挙動を模擬しており、本番環境や実在する Apache の診断結果ではありません。
              </p>
              {labErr && <p className="font-semibold text-red-700 dark:text-red-300">エラー：{labErr}</p>}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={labBusy}
                onClick={runAllWorkers}
                className="rounded-lg bg-violet-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-violet-800 disabled:opacity-50 dark:bg-violet-200 dark:text-violet-950 dark:hover:bg-violet-100"
              >
                {labBusy ? "Worker実行中…" : "⚡ 全問題を実機Workerで今すぐ検証"}
              </button>
              <button
                type="button"
                disabled={labBusy}
                onClick={() => toggleLabMode(snap.lab_mode === "patched" ? "vulnerable" : "patched")}
                className="rounded-lg border border-violet-300 bg-white px-2.5 py-1.5 text-xs font-semibold text-violet-900 hover:bg-violet-100 disabled:opacity-50 dark:border-violet-700 dark:bg-zinc-900 dark:text-violet-100"
              >
                {snap.lab_mode === "patched" ? "脆弱環境に戻して再検証" : "パッチ適用環境に切替えて再検証"}
              </button>
            </div>
          </div>
        )}

        <EvidenceOverview snap={snap} selected={tab === "findings" ? evidenceFilter : "all"} />

        {tab === "assessment" && (
          <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_18rem]">
            <AgentActivity
              snap={snap}
              notes={notes}
              audit={audit}
              chainValid={chainValid}
              externalBusy={labBusy || cardBusy}
              onUpdate={setSnap}
            />
            <div className="min-w-0 space-y-4">
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
                  <h2 className="mb-2 text-sm font-semibold">前回診断との履歴比較{hist.demo_fixture ? "（架空のデモ履歴）" : ""}</h2>
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
              {reportErr && <p role="alert" className="text-xs text-red-700 dark:text-red-300">レポートを出力できませんでした：{reportErr}。再度お試しください。</p>}
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
          <div className="min-w-0 space-y-4">
            <ReasoningTrace
              snap={snap}
              audit={audit}
              chainValid={chainValid}
              externalBusy={labBusy || cardBusy}
              compact
            />
            {evidenceFilter !== "all" && (
              <div role="status" className="flex items-center justify-between text-sm">
                <span>{EVIDENCE_STATES.find((s) => s.key === evidenceFilter)?.label}：{snap.evidence_summary[evidenceFilter]} 件</span>
                <Link href="?tab=findings" scroll={false} className="text-xs font-semibold underline">絞り込みを解除</Link>
              </div>
            )}
            {evidenceFilter !== "all" && snap.evidence_summary[evidenceFilter] === 0 && <p className="text-sm text-zinc-500">この状態の問題はありません。別の状態を選ぶか、絞り込みを解除してください。</p>}
            <div className="grid gap-3 md:grid-cols-2">
              {counts.findings === 0 && (
                <p className="text-sm text-zinc-500 md:col-span-2">
                  {snap.state === "idle" ? "診断を開始すると、ここに問題が表示されます。" : "まだ問題は検出されていません（未検出は安全という意味ではありません）。"}
                </p>
              )}
              {findings.filter((f) => evidenceFilter === "all" || f.evidence_status === evidenceFilter).map((f) => (
                <FindingCard
                  key={f.id}
                  f={f}
                  assessmentId={snap.id}
                  labEndpoint={snap.lab_endpoint}
                  onUpdate={setSnap}
                  onBusyChange={setCardBusy}
                />
              ))}
            </div>
          </div>
        )}

        {tab === "logs" && (
          <div className="min-w-0 space-y-4">
            <EventTimeline entries={audit} chainValid={chainValid} />
            <RawLogViewer entries={audit} />
          </div>
        )}
      </main>
    </div>
  );
}
