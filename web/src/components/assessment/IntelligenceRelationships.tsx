"use client";

import Link from "next/link";
import { useState } from "react";
import type { EChartsCoreOption } from "echarts/core";
import { EVIDENCE_LABEL, SEVERITIES, findingQuery, type FindingFilters, type aggregate } from "@/lib/securityIntelligence";
import type { AuditEntry, Finding, PhaseStatus, RunHistoryEntry, Snapshot } from "@/lib/types";
import type { Archive } from "@/lib/useIntelligenceArchive";
import { fmtTime } from "@/lib/labels";
import { Chart, Empty, IntelligencePanel } from "./IntelligencePanel";

const phaseState: Record<PhaseStatus, string> = {
  pending: "未実施", running: "実行中", done: "完了", aborted: "中断", skipped: "対象外",
};
const colors = ["#ad2435", "#626975", "#87909f", "#adb4bd", "#c2c7ce"];
type Node = { id: string; name: string; x: number; y: number; value?: string };
type Edge = { source: string; target: string };
const axis = { axisLine: { lineStyle: { color: "#71717a" } }, axisTick: { show: false } };

function graph(nodes: Node[], links: Edge[]): EChartsCoreOption {
  return {
    tooltip: { show: false },
    series: [{
      type: "graph", layout: "none", data: nodes, links, roam: false, symbolSize: 16,
      left: "12%", right: "18%", top: 25, bottom: 35, label: { show: true, position: "bottom", fontSize: 10, color: "#71717a" },
      itemStyle: { color: "#707785" }, lineStyle: { color: "#8b909a", width: 1.2, opacity: 1 },
    }],
  };
}

function topology(archive: Archive | undefined, external: boolean) {
  const nodes: Node[] = [];
  const links: Edge[] = [];
  const assets = (archive?.assets ?? []).filter((a) => a.external === external);
  const projects = new Map<string, Node>();
  for (const [i, asset] of assets.slice(0, 6).entries()) {
    const node = { id: `asset-${i}`, name: asset.name, x: 240, y: i * 50, value: asset.id };
    nodes.push(node);
    if (asset.project_key) {
      let project = projects.get(asset.project_key);
      if (!project) {
        project = { id: `project-${projects.size}`, name: `登録プロジェクト ${projects.size + 1}`, x: 20, y: i * 50 };
        projects.set(asset.project_key, project);
        nodes.push(project);
      }
      links.push({ source: project.id, target: node.id });
    }
  }
  return { nodes, links, count: assets.length };
}

function audited(evidence: Finding["evidence"][number], hashes: Set<string>) {
  return Boolean(evidence.audit_hash && evidence.saved_at != null && hashes.has(evidence.audit_hash));
}

function graphEvidence(rows: Finding[], hashes: Set<string>) {
  const nodes: Node[] = [];
  const links: Edge[] = [];
  const observed = rows.filter((f) => !f.demo_fixture && f.evidence_status !== "fixture" && f.evidence.some((ev) => audited(ev, hashes)));
  observed.slice(0, 6).forEach((f, i) => {
    const row = f.evidence.filter((ev) => audited(ev, hashes)).at(-1);
    const observedState = row?.tool === "reproduction_probe" ? "検証記録" : "観測記録";
    nodes.push({ id: `f-${i}`, name: `所見 ${i + 1}`, x: 0, y: i * 50, value: f.id },
      { id: `e-${i}`, name: observedState, x: 110, y: i * 50, value: f.id },
      { id: `a-${i}`, name: "監査記録", x: 220, y: i * 50, value: f.id });
    links.push({ source: `f-${i}`, target: `e-${i}` }, { source: `e-${i}`, target: `a-${i}` });
  });
  return { nodes, links, observed };
}

export function IntelligenceRelationships({ snap, data, chainValid, audit, archive, compared, select }: {
  snap: Snapshot; data: ReturnType<typeof aggregate>; chainValid: boolean | null;
  audit: AuditEntry[]; archive: Archive | undefined; compared: RunHistoryEntry[];
  select: (filter: FindingFilters | undefined) => void;
}) {
  const [selectedAsset, setSelectedAsset] = useState<string>();
  const hashes = new Set(chainValid === true ? audit.map((e) => e.hash) : []);
  const related = topology(archive, Boolean(snap.is_external_service));
  const evidence = graphEvidence(data.rows, hashes);
  const landscape = SEVERITIES.flatMap((severity, y) => (["detected", "proven"] as const).flatMap((state, x) => {
    const count = data.rows.filter((f) => f.severity === severity && f.evidence_status === state && f.evidence.some((ev) => audited(ev, hashes))).length;
    return count ? [{ name: `${severity.toUpperCase()}・${EVIDENCE_LABEL[state]} ${count}件`, value: [x, y, count],
      itemStyle: { color: colors[y] }, filter: { severity, evidence: state } }] : [];
  }));
  const rows = Array.from(new Map((archive?.runs ?? []).filter((r) =>
    r.asset_id && r.severity && r.external === Boolean(snap.is_external_service)).reverse().map((r) => [r.asset_id!, r])).values()).reverse();
  const heatRows = rows.slice(0, 6);
  const heatCells = heatRows.flatMap((row, y) => SEVERITIES.map((severity, x) => ({
    name: `${row.asset}・${severity.toUpperCase()}`, value: [x, y, row.severity![severity]],
    itemStyle: { color: row.severity![severity] ? colors[x] : "#e4e4e7" },
    label: { color: row.severity![severity] && x < 2 ? "#fff" : "#18181b" }, asset: row.asset_id!, severity,
  })));
  const picked = heatRows.find((r) => r.asset_id === selectedAsset);
  const previous = compared.at(-2);
  const latest = compared.at(-1);
  return <>
    <IntelligencePanel title="資産の関係">
      {related.nodes.length ? <>
        <Chart label="登録された資産とプロジェクトの関係" option={graph(related.nodes, related.links)} />
        <p className="text-xs text-zinc-500">登録済みのプロジェクト所属を表示します。{related.count > 6 ? `表示 6 / ${related.count} 資産。` : ""}</p>
      </> : <Empty>この環境の登録資産を取得できませんでした。</Empty>}
    </IntelligencePanel>
    <IntelligencePanel title="証拠と監査の関係">
      {evidence.nodes.length ? <>
        <Chart label="所見・観測・監査の関係" option={graph(evidence.nodes, evidence.links)}
          onSelect={(index) => { const id = evidence.nodes[index]?.value; if (id) select({ finding: id }); }} />
        <div className="flex flex-wrap gap-2 text-xs">
          {evidence.observed.slice(0, 6).map((f, i) => <Link key={f.id} href={findingQuery({ finding: f.id })} scroll={false} className="underline">所見 {i + 1}を表示</Link>)}
        </div>
        {evidence.observed.length > 6 && <p className="mt-2 text-xs text-zinc-500">表示 6 / {evidence.observed.length} 所見。</p>}
      </> : <Empty>検証済みの監査記録と結び付く証拠はありません。</Empty>}
    </IntelligencePanel>
    <IntelligencePanel title="診断範囲">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        {snap.phases.map((phase) => <div key={phase.key} className="rounded-lg border border-zinc-200 p-2 dark:border-zinc-700">
          <p className="text-sm">{phase.label}</p>
          <p className="mt-2 text-xs text-zinc-500">{phaseState[phase.status] ?? "未確認"}</p>
        </div>)}
      </div>
      <p className="mt-3 text-xs text-zinc-500">未実施・中断・対象外の項目には判定がありません。</p>
    </IntelligencePanel>
    <IntelligencePanel title="修正前後の比較">
      {previous && latest && previous.severity && latest.severity ? <>
        <table className="w-full text-left text-sm tabular-nums">
          <thead><tr><th scope="col">項目</th><th scope="col">{fmtTime(previous.at)}</th><th scope="col">{fmtTime(latest.at)}</th></tr></thead>
          <tbody>
            <tr><th scope="row" className="py-2 font-medium">リスクスコア</th><td>{previous.score}/100</td><td>{latest.score}/100</td></tr>
            {SEVERITIES.map((severity) => <tr key={severity} className="border-t border-zinc-200 dark:border-zinc-700">
              <th scope="row" className="py-1 font-medium">{severity.toUpperCase()}</th>
              <td>{previous.severity![severity]}</td><td>{latest.severity![severity]}</td>
            </tr>)}
          </tbody>
        </table>
        <p className="mt-3 text-xs text-zinc-500">同じ対象と診断条件の観測値です。修正の成立は個別の検証結果で確認してください。</p>
      </> : <Empty>同じ対象と診断条件の保存済み記録が2件必要です。</Empty>}
    </IntelligencePanel>
    <IntelligencePanel title="資産別リスク分布">
      {heatRows.length ? <>
        <Chart label="資産別の重大度ヒートマップ" option={{
          grid: { left: 86, right: 9, top: 12, bottom: 32 }, tooltip: { formatter: "{b}" },
          xAxis: { ...axis, type: "category", data: SEVERITIES.map((s) => s.toUpperCase()), axisLabel: { fontSize: 9, interval: 0 } },
          yAxis: { ...axis, type: "category", inverse: true, data: heatRows.map((r) => r.asset),
            axisLabel: { width: 72, overflow: "truncate", fontSize: 9 } },
          visualMap: { show: false, dimension: 2, min: 0, max: Math.max(1, ...heatCells.map((c) => c.value[2])) },
          series: [{ type: "heatmap", data: heatCells, label: { show: true, formatter: (p: { value: number[] }) => String(p.value[2]) } }],
        }} onSelect={(i) => {
          const cell = heatCells[i];
          if (!cell) return;
          if (cell.asset === snap.asset.id && cell.value[2] > 0) select({ severity: cell.severity });
          else setSelectedAsset(cell.asset);
        }} />
        <div className="flex flex-wrap gap-2 text-xs">{heatRows.map((r) => <button key={r.asset_id} type="button"
          onClick={() => setSelectedAsset(r.asset_id)} aria-pressed={selectedAsset === r.asset_id} className="rounded border border-zinc-300 px-2 py-1 dark:border-zinc-700">{r.asset}</button>)}</div>
        {picked && <p className="mt-2 text-sm" role="status">{picked.asset} の保存済み所見 {picked.findings}件 · {fmtTime(picked.at)}</p>}
        <p className="mt-2 text-xs text-zinc-500">監査を確認できた最新の保存結果のみ。{rows.length > 6 ? `表示 6 / ${rows.length} 資産。` : ""}</p>
      </> : <Empty>監査を確認できた資産別の保存結果はありません。</Empty>}
    </IntelligencePanel>
    <IntelligencePanel title="悪用の根拠と影響度">
      {landscape.length ? <>
        <Chart label="悪用の根拠と所見の重大度の散布図" option={{
          grid: { left: 60, right: 22, top: 17, bottom: 38 },
          xAxis: { ...axis, type: "category", data: ["検出・未実証", "実証済み"] },
          yAxis: { ...axis, type: "category", inverse: true, data: SEVERITIES.map((s) => s.toUpperCase()) },
          tooltip: { formatter: "{b}" },
          series: [{ type: "scatter", data: landscape, symbolSize: (p: number[]) => Math.min(22, 9 + p[2] * 2) }],
        }} onSelect={(i) => select(landscape[i]?.filter)} />
        <p className="text-xs text-zinc-500">縦軸は記録された重大度、横軸は監査で確認できる根拠の状態です。悪用確率や実害は推定していません。</p>
      </> : <Empty>根拠と重大度の両方を確認できる検出・実証記録がありません。</Empty>}
    </IntelligencePanel>
  </>;
}
