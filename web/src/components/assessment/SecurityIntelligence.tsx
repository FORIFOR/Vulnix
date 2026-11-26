"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import type { EChartsCoreOption } from "echarts/core";
import { fmtTime } from "@/lib/labels";
import type { AuditEntry, Snapshot } from "@/lib/types";
import type { Conn } from "@/lib/useAssessment";
import { IntelligenceRelationships } from "./IntelligenceRelationships";
import { useIntelligenceArchive } from "@/lib/useIntelligenceArchive";
import { EVIDENCE, EVIDENCE_LABEL, SEVERITIES, comparableRuns, findingQuery, type FindingFilters, type aggregate } from "@/lib/securityIntelligence";

import { Chart, Empty, IntelligencePanel } from "./IntelligencePanel";
const severityColors = ["#ad2435", "#6d727d", "#959aa4", "#b8bdc5", "#d8dbe0"];
const evidenceColors = ["#767b87", "#535864", "#303540", "#969ca7", "#aeb3bc", "#d1d5dc"];
const axis = { axisLine: { lineStyle: { color: "#71717a" } }, axisTick: { show: false } };
const STATUS = { idle: "未診断", running: "診断中", paused: "一時停止", stopped: "実行停止", failed: "完了できませんでした", completed: "診断完了" };
const CONNECTION = { live: "ライブ接続中", connecting: "接続中", reconnecting: "再接続中", offline: "通信切断" };
const ACTIVITY: Record<string, string> = {
  "assessment.start_requested": "診断開始の操作", "assessment.restarted": "再診断の操作",
  "assessment.failed": "診断を完了できませんでした", "state.persist_failed": "結果の保存に失敗",
  "intelligence.summary_persisted": "診断履歴を保存",
};

function Links({ rows }: { rows: { text: string; value: number; filter: FindingFilters }[] }) {
  return <ul className="flex flex-wrap gap-2" aria-label="結果の絞り込み">
    {rows.filter((r) => r.value > 0).map((row) => <li key={row.text}>
      <Link href={findingQuery(row.filter)} scroll={false} className="inline-flex gap-1 rounded-md border border-zinc-200 px-2 py-1 text-xs hover:underline dark:border-zinc-700">
        {row.text} <span className="font-semibold tabular-nums">{row.value}</span>
      </Link>
    </li>)}
  </ul>;
}

function pie(rows: { text: string; value: number }[], colors: string[]): EChartsCoreOption {
  return { series: [{ type: "pie", radius: ["48%", "73%"], label: { show: false }, minShowLabelAngle: 8,
    data: rows.map((row, index) => ({ name: row.text, value: row.value, itemStyle: { color: colors[index], borderWidth: 2, borderColor: "#a1a1aa" } })) }] };
}

export function SecurityIntelligence({ snap, data, conn, chainValid, audit }: {
  snap: Snapshot; audit: AuditEntry[]; data: ReturnType<typeof aggregate>; conn: Conn; chainValid: boolean | null;
}) {
  const router = useRouter();
  const select = (filter: FindingFilters | undefined) => { if (filter) router.push(findingQuery(filter), { scroll: false }); };
  const severity = SEVERITIES.map((key) => ({ text: key.toUpperCase(), value: data.severity[key], filter: { severity: key } }));
  const evidence = EVIDENCE.map((key) => ({ text: EVIDENCE_LABEL[key], value: data.evidence[key], filter: { evidence: key } }));
  const categories = Object.entries(data.categories).sort((a, b) => b[1] - a[1]).map(([text, value]) => ({ text, value, filter: { category: text } }));
  const cells = SEVERITIES.flatMap((s, y) => EVIDENCE.map((e, x) => ({
    name: `${s.toUpperCase()}・${EVIDENCE_LABEL[e]}`, value: [x, y, data.matrix[s][e]],
    filter: { severity: s, evidence: e }, itemStyle: { color: data.matrix[s][e] ? severityColors[y] : "#e4e4e7" },
    label: { color: data.matrix[s][e] && y < 2 ? "#fff" : "#18181b" },
  })));
  const view = useIntelligenceArchive(snap.asset.id, snap.state, conn);
  const archive = chainValid === false ? undefined : view?.archive ?? undefined;
  const persisted = archive?.runs.filter((r) => r.asset_id === snap.asset.id) ?? [];
  const archiveMessage = chainValid === false ? "監査整合性を確認できないため保存履歴を表示できません。"
    : snap.persistence_error || archive?.state === "persistence_error" ? "保存できなかった診断は履歴から除外しています。"
    : archive?.state === "audit_unavailable" ? "監査を確認できない診断は履歴から除外しています。"
    : view?.denied ? "履歴の閲覧権限を確認してください。"
    : !view ? "保存済みの履歴を読み込んでいます。" : !archive ? "診断履歴を取得できませんでした。" : null;
  const compared = comparableRuns(persisted, snap.asset.id);
  const points = persisted.filter((r) => typeof r.score === "number" && Number.isFinite(r.score) && Number.isFinite(r.at))
    .map((r) => [r.at * 1000, r.score]);
  const allowed = snap.authorization.status === "authorized";
  const recent = audit.filter((entry) => Object.hasOwn(ACTIVITY, entry.event)).slice(-5).reverse();

  if (view?.denied) return <p role="alert" className="py-5 text-sm">診断データの閲覧権限を確認できません。ログイン状態と組織を確認してください。</p>;

  return <section aria-labelledby="intelligence-title" className="space-y-5">
    <header className="flex flex-wrap items-end justify-between gap-3 border-b border-zinc-200 pb-4 dark:border-zinc-800">
      <div className="min-w-0">
        <p className="mb-1 break-all text-xs text-zinc-500">{snap.asset.name} · {snap.is_external_service ? "登録済みサービス" : "ローカル模擬ラボ"}</p>
        <h1 id="intelligence-title" className="text-2xl font-semibold tracking-tight sm:text-3xl">Security Intelligence</h1>
      </div>
      <p role="status" className="rounded-full border border-zinc-200 px-3 py-1 text-xs dark:border-zinc-700">{CONNECTION[conn]} · {STATUS[snap.state]}</p>
    </header>
    {conn !== "live" && <p className="text-sm text-zinc-500">最後に取得した結果を表示しています。</p>}
    {!allowed && <p className="text-sm text-zinc-500">現在は診断の実行許可を確認できません。</p>}
    {data.evidence.fixture > 0 && <p className="text-sm text-zinc-500">模擬ラボの記録にはデモ資料 {data.evidence.fixture} 件が含まれます。</p>}
    {chainValid !== true && <p className="text-sm text-zinc-500">監査整合性を確認できない実証は「未完了・要確認」として表示します。</p>}
    <div className="grid grid-cols-12 gap-4">
      <IntelligencePanel title="重大度">
        {data.rows.length ? <><Chart option={pie(severity, severityColors)} onSelect={(i) => severity[i]?.value && select(severity[i].filter)} label="重大度別ドーナツグラフ" /><Links rows={severity} /></> : <Empty>この資産には表示できる所見がありません。</Empty>}
      </IntelligencePanel>
      <IntelligencePanel title="証拠の状態">
        {data.rows.length ? <><Chart option={pie(evidence, evidenceColors)} onSelect={(i) => evidence[i]?.value && select(evidence[i].filter)} label="証拠状態のドーナツグラフ" /><Links rows={evidence} /></> : <Empty>表示できる証拠状態はありません。</Empty>}
        <p className="mt-3 text-xs text-zinc-500">「再現せず」は今回の条件での観測結果です。</p>
      </IntelligencePanel>
      <IntelligencePanel title="重大度と証拠状態" wide>
        {data.rows.length ? <><Chart label="重大度と証拠状態のマトリクス" onSelect={(i) => { if (cells[i]?.value[2]) select(cells[i].filter); }} option={{
          grid: { left: 59, right: 10, top: 10, bottom: 46 },
          xAxis: { ...axis, type: "category", data: ["未計測", "検出", "実証", "再現なし", "要確認", "デモ"], axisLabel: { interval: 0, fontSize: 9 }},
          yAxis: { ...axis, type: "category", inverse: true, data: SEVERITIES.map((s) => s.toUpperCase()) },
          tooltip: { formatter: "{b}" },
          visualMap: { show: false, dimension: 2, min: 0, max: Math.max(1, ...cells.map((c) => c.value[2])) },
          series: [{ type: "heatmap", data: cells, itemStyle: { borderWidth: 1, borderColor: "#a1a1aa" },
            label: { show: true, formatter: (p: { value: number[] }) => String(p.value[2]) } }],
        }} /><Links rows={cells.filter((c) => c.value[2]).map((c) => ({ text: c.name, value: c.value[2], filter: c.filter }))} /></> : <Empty>所見が取得できると項目ごとの件数が表示されます。</Empty>}
      </IntelligencePanel>
      <IntelligencePanel title="カテゴリ">
        {categories.length ? <><Chart label="カテゴリ別ツリーマップ" onSelect={(_, name) => select(categories.find((row) => row.text === name)?.filter)} option={{
          series: [{ type: "treemap", left: 3, right: 3, top: 12, bottom: 12, roam: false, nodeClick: false, breadcrumb: { show: false },
            color: ["#343945", "#535a67", "#626976", "#717885", "#4c535e"], itemStyle: { gapWidth: 3, borderColor: "#a1a1aa" },
            data: categories.map((row, i) => ({ name: row.text, value: row.value, itemStyle: { color: evidenceColors[i % evidenceColors.length] } })), label: { color: "#fff", overflow: "truncate" } }],
        }} /><Links rows={categories} /></> : <Empty>分類できる所見がありません。</Empty>}
      </IntelligencePanel>
      <IntelligencePanel title="診断履歴・リスク">
        {archiveMessage && <p role="status" className="text-xs text-zinc-500">{archiveMessage}</p>}
        {points.length ? <><Chart label="この資産の過去のリスクスコア" option={{
          grid: { left: 40, right: 18, top: 12, bottom: 35 }, xAxis: { ...axis, type: "time" },
          yAxis: { ...axis, type: "value", min: 0, max: 100, splitLine: { lineStyle: { color: "#a1a1aa", opacity: 0.25 } } },
          tooltip: { show: false },
          series: [{ type: "scatter", data: points, symbolSize: 10, itemStyle: { color: "#71717a" } },
            { type: "line", data: compared.length > 1 ? compared.map((r) => [r.at * 1000, r.score]) : [], itemStyle: { color: "#71717a" } }],
        }} /><p className="text-xs text-zinc-500">比較できるのは同じ資産・診断条件で保存された診断です。</p></> : <Empty>{archiveMessage ? "表示できるリスクスコアはありません。" : "この資産のリスクスコア付き完了履歴はありません。"}</Empty>}
      </IntelligencePanel>
      <IntelligencePanel title="診断アクティビティ" wide>
        <p className="mb-2 text-sm" aria-live="polite">{snap.phases.find((phase) => phase.status === "running")?.label ?? STATUS[snap.state]}</p>
        {recent.length && chainValid === true ? <ol className="space-y-2 text-sm">
          {recent.map((entry) => <li key={entry.hash} className="flex flex-wrap justify-between gap-2 border-t border-zinc-200 pt-2 dark:border-zinc-700">
            <span>{ACTIVITY[entry.event]}</span><time className="text-xs text-zinc-500">{fmtTime(entry.ts)}</time>
          </li>)}
        </ol> : <p className="text-xs text-zinc-500">表示できる診断の操作記録がありません。</p>}
      </IntelligencePanel>
      <IntelligenceRelationships snap={snap} data={data} chainValid={chainValid} audit={audit} archive={archive} compared={compared} select={select} />
    </div>
  </section>;
}
