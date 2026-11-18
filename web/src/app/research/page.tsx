"use client";

import { useEffect, useState } from "react";
import { getJSON } from "@/lib/api";

type Node = { id: string; kind: string; name: string; source_path: string; source_line: number; status: string; evidence_ids: string[] };
type Edge = { source: string; target: string; relation: string; confidence: number; evidence_ids: string[] };
type Evidence = { id: string; source_path: string; source_line: number; commit_sha: string; source_digest: string };
type Report = {
  status: string;
  scope?: string;
  commit_sha?: string;
  graph?: { nodes: Node[]; edges: Edge[] };
  evidence?: Evidence[];
  hypothesis?: { hypothesis_id: string; summary: string; category: string; evidence_ids: string[]; assumptions: string[]; counter_evidence: string[]; uncertainties: string[]; confidence: number };
  verification?: { before: { status: string; environment: string }; after: { fixed: boolean; same_tenant_preserved: boolean; after_status: string } };
  remediation?: { diff: string; description: string; review_status: string };
};

const sections = [
  { id: "graph", label: "Security Graph" },
  { id: "paths", label: "攻撃経路" },
  { id: "evidence", label: "原因と証拠" },
  { id: "remediation", label: "修正PR" },
  { id: "history", label: "検証履歴" },
];

export default function ResearchPage() {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    getJSON<Report>("/api/research/report").then(setReport, e => setError((e as Error).message));
  }, []);

  return (
    <main className="mx-auto max-w-6xl p-4 md:p-8">
      <h1 className="text-2xl font-bold">コード調査と修正</h1>
      <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-300">組織に保存された調査結果を表示します。仮説・実測・修正後の判定を分けて確認できます。</p>
      {error && <p role="alert" className="mt-5 rounded-lg border border-red-300 p-4 text-sm">取得できませんでした: {error}</p>}
      {!report && !error && <p className="mt-5 text-sm">読み込み中…</p>}
      {report?.status === "not_available" && <p className="mt-5 rounded-lg border p-5 text-sm">この組織には、コード調査レポートがありません。</p>}
      {report?.status === "synthetic_validated" && report.graph && report.hypothesis && report.verification && report.remediation && (
        <>
          <div className="mt-5 rounded-lg border border-amber-300 bg-amber-50 p-4 text-sm text-amber-950 dark:border-amber-800 dark:bg-amber-950/30 dark:text-amber-100">
            <strong>合成ラボの結果</strong> — {report.scope}
          </div>
          <p className="mt-3 break-all text-xs text-zinc-500">解析コミット: {report.commit_sha}</p>
          <nav aria-label="調査の目次" className="mt-6 flex flex-wrap gap-2">
            {sections.map(s => <a key={s.id} href={`#${s.id}`} className="rounded-lg border px-3 py-2 text-sm hover:bg-zinc-100 dark:hover:bg-zinc-800">{s.label}</a>)}
          </nav>
          <section id="graph" className="mt-8 scroll-mt-4 rounded-xl border p-4 md:p-6">
            <h2 className="text-lg font-semibold">Security Graph</h2>
            <p className="mt-1 text-sm text-zinc-500">API、処理、データ参照と根拠の関係</p>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              {report.graph.nodes.map(n => <div key={n.id} className="min-w-0 rounded-lg bg-zinc-100 p-3 text-sm dark:bg-zinc-900">
                <div className="font-semibold">{n.kind}: {n.name}</div>
                <div className="mt-1 break-all text-xs text-zinc-500">{n.source_path}:{n.source_line} · {n.status}</div>
              </div>)}
            </div>
            <ul className="mt-4 space-y-2 text-sm">{report.graph.edges.map((e, i) => <li key={`${e.source}-${e.target}-${i}`} className="break-all rounded border p-2">{e.relation}: {e.source} → {e.target} <span className="text-xs text-zinc-500">根拠 {e.evidence_ids.join(", ")}</span></li>)}</ul>
          </section>
          <section id="paths" className="mt-6 scroll-mt-4 rounded-xl border p-4 md:p-6">
            <h2 className="text-lg font-semibold">攻撃経路の仮説</h2>
            <p className="mt-2 text-sm">{report.hypothesis.summary}</p>
            <p className="mt-2 text-xs text-zinc-500">{report.hypothesis.hypothesis_id} · {report.hypothesis.category} · 仮説信頼度 {Math.round(report.hypothesis.confidence * 100)}%</p>
            <p className="mt-3 text-sm">前提: {report.hypothesis.assumptions.join("、")}</p>
            <p className="mt-1 text-sm">反証候補: {report.hypothesis.counter_evidence.join("、")}</p>
            <p className="mt-1 text-sm">未確認: {report.hypothesis.uncertainties.join("、")}</p>
          </section>
          <section id="evidence" className="mt-6 scroll-mt-4 rounded-xl border p-4 md:p-6">
            <h2 className="text-lg font-semibold">原因と証拠</h2>
            <p className="mt-1 text-sm text-zinc-500">コード本文や秘密値は保存していません。行位置とハッシュで照合します。</p>
            <ul className="mt-4 space-y-2">{report.evidence?.map(e => <li key={e.id} className="break-all rounded border p-3 text-sm"><strong>{e.id}</strong> — {e.source_path}:{e.source_line}<span className="block text-xs text-zinc-500">SHA-256: {e.source_digest}</span></li>)}</ul>
          </section>
          <section id="remediation" className="mt-6 scroll-mt-4 rounded-xl border p-4 md:p-6">
            <h2 className="text-lg font-semibold">修正PR</h2>
            <p className="mt-2 text-sm">{report.remediation.review_status}。実際の GitHub PR は作成していません。</p>
            <pre className="mt-3 max-w-full overflow-x-auto whitespace-pre-wrap rounded border p-3 text-sm">{report.remediation.description}</pre>
            <pre className="mt-4 max-w-full overflow-x-auto rounded bg-zinc-950 p-4 text-xs text-zinc-100">{report.remediation.diff}</pre>
          </section>
          <section id="history" className="mt-6 scroll-mt-4 rounded-xl border p-4 md:p-6">
            <h2 className="text-lg font-semibold">検証履歴</h2>
            <ol className="mt-4 space-y-2 text-sm">
              <li>修正前: {report.verification.before.status} ({report.verification.before.environment})</li>
              <li>修正後: {report.verification.after.after_status}</li>
              <li>同一組織の正常動作: {report.verification.after.same_tenant_preserved ? "維持" : "未確認"}</li>
            </ol>
          </section>
        </>
      )}
    </main>
  );
}
