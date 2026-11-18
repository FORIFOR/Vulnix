"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { getJSON } from "@/lib/api";
import type { GraphNode, GraphPath, GraphSnapshot } from "@/lib/securityGraph";

type Impact = { node_id: string; predicted_paths: number; path_ids: string[]; status: string; assumption: string };
type Difference = { before_snapshot: string; after_snapshot: string; guard_observed_after: string[]; status: string; verified_remediation: boolean };
type LocalRemediation = { remediation_id: string; status: string; diff: string; description: string; fixed: boolean; same_tenant_preserved: boolean };

export default function RemediationsPage() {
  const [snapshots, setSnapshots] = useState<GraphSnapshot[]>([]);
  const [before, setBefore] = useState("");
  const [after, setAfter] = useState("");
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [paths, setPaths] = useState<GraphPath[]>([]);
  const [selected, setSelected] = useState("");
  const [impact, setImpact] = useState<Impact | null>(null);
  const [diff, setDiff] = useState<Difference | null>(null);
  const [remediations, setRemediations] = useState<LocalRemediation[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    getJSON<GraphSnapshot[]>("/api/security-graph/snapshots").then(rows => {
      setSnapshots(rows);
      setBefore(rows[0]?.id ?? "");
      setAfter(rows[1]?.id ?? "");
    }, e => setError((e as Error).message));
  }, []);
  useEffect(() => {
    if (!before) return;
    const q = `?snapshot=${encodeURIComponent(before)}`;
    Promise.all([getJSON<GraphNode[]>(`/api/security-graph/nodes${q}`),
      getJSON<GraphPath[]>(`/api/security-graph/paths${q}`),
      getJSON<LocalRemediation[]>(`/api/security-graph/remediations${q}`)]).then(([n, p, r]) => {
      setNodes(n); setPaths(p); setRemediations(r); setSelected(""); setImpact(null);
    }, e => setError((e as Error).message));
  }, [before]);
  useEffect(() => {
    if (!before || !selected) return;
    getJSON<Impact>(`/api/security-graph/remediation-impact?snapshot=${encodeURIComponent(before)}&node=${encodeURIComponent(selected)}`)
      .then(setImpact, e => setError((e as Error).message));
  }, [before, selected]);
  useEffect(() => {
    if (!before || !after || before === after) return;
    getJSON<Difference>(`/api/security-graph/diff?snapshot=${encodeURIComponent(before)}&after=${encodeURIComponent(after)}`)
      .then(setDiff, e => setError((e as Error).message));
  }, [before, after]);

  const involved = new Set(paths.flatMap(path => path.nodes));
  const candidates = nodes.filter(node => involved.has(node.id) && node.kind === "handler");
  return <main className="mx-auto max-w-5xl p-4 text-zinc-900 md:p-8 dark:text-zinc-100">
    <h1 className="text-2xl font-semibold">修正効果の確認</h1>
    <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-300">経路への影響予測と、コミット間のコード構造の変化を表示します。修正の有効性は隔離テストの結果で確認してください。</p>
    {error && <p role="alert" className="mt-4 rounded-lg border border-red-300 p-3 text-sm">{error}</p>}
    {!snapshots.length && !error && <p className="mt-6 rounded-lg border p-4 text-sm">解析履歴がありません。</p>}
    {!!snapshots.length && <>
      <div className="mt-6 grid gap-3 sm:grid-cols-2">
        <label className="text-sm">修正前の解析
          <select value={before} onChange={e => setBefore(e.target.value)} className="mt-1 block w-full rounded-lg border bg-white p-2 dark:bg-zinc-900">
            {snapshots.map(s => <option key={s.id} value={s.id}>{s.repository_id} · {s.commit_sha.slice(0, 10)}</option>)}
          </select>
        </label>
        <label className="text-sm">比較する解析
          <select value={after} onChange={e => setAfter(e.target.value)} className="mt-1 block w-full rounded-lg border bg-white p-2 dark:bg-zinc-900">
            <option value="">選択してください</option>
            {snapshots.filter(s => s.id !== before).map(s => <option key={s.id} value={s.id}>{s.repository_id} · {s.commit_sha.slice(0, 10)}</option>)}
          </select>
        </label>
      </div>
      <section className="mt-6 rounded-xl border p-4">
        <h2 className="font-semibold">修正候補と予測効果</h2>
        <p className="mt-1 text-xs text-zinc-500">経路を共有する処理を選ぶと、影響する経路数を計算します。</p>
        <div className="mt-3 flex flex-wrap gap-2">{candidates.map(n => <button key={n.id} type="button" onClick={() => setSelected(n.id)} aria-pressed={selected === n.id}
          className="rounded-lg border px-3 py-2 text-sm aria-pressed:border-blue-500 aria-pressed:bg-blue-50 dark:aria-pressed:bg-blue-950">{n.name} · {n.source_path}:{n.source_line}</button>)}</div>
        {impact && <p className="mt-4 text-sm">対象経路の予測数: <strong>{impact.predicted_paths}</strong>。{impact.assumption}。実証済みの解消数ではありません。</p>}
        {!candidates.length && <p className="mt-3 text-sm text-zinc-500">修正候補となる処理は抽出されていません。</p>}
      </section>
      <section className="mt-4 rounded-xl border p-4">
        <h2 className="font-semibold">修正前後の比較</h2>
        {diff && diff.before_snapshot === before && diff.after_snapshot === after ? <p className="mt-3 text-sm">認可ガードを修正後のコードで観測した経路: {diff.guard_observed_after.length}。これは構造上の比較です。{diff.verified_remediation ? "隔離検証済み" : "修正効果は未検証"}。</p> : <p className="mt-3 text-sm text-zinc-500">比較する解析を選んでください。</p>}
        <Link href="/research" className="mt-4 inline-block rounded-lg border px-3 py-2 text-sm">隔離ラボの修正差分と検証履歴</Link>
      </section>
      <section className="mt-4 rounded-xl border p-4">
        <h2 className="font-semibold">ローカル Draft PR 相当の修正</h2>
        {!remediations.length && <p className="mt-2 text-sm text-zinc-500">この解析では隔離検証済みの修正差分がありません。</p>}
        {remediations.map(item => <article key={item.remediation_id} className="mt-4 rounded-lg border p-3">
          <p className="text-sm">合成ラボ: {item.fixed && item.same_tenant_preserved ? "修正後に別組織の参照を拒否し、正常な参照を維持" : "効果未確認"}。実サイト・顧客コードでは未検証。</p>
          <pre className="mt-3 overflow-x-auto whitespace-pre-wrap text-xs">{item.description}</pre>
          <pre className="mt-3 overflow-x-auto rounded-lg bg-zinc-950 p-3 text-xs text-zinc-100">{item.diff}</pre>
        </article>)}
      </section>
    </>}
  </main>;
}
