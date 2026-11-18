"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { getJSON, postJSON } from "@/lib/api";
import { mcpScopeLabel, mcpValidationStatusLabel, pathStatusLabel, syntheticValidationLabel, type GraphEvidence, type GraphHypothesis,
  type GraphNode, type GraphPath, type GraphSnapshot, type McpScopeCandidate, type McpValidation } from "@/lib/securityGraph";

type Panel = "assets" | "graph" | "detail";
type GraphSource = { id: string; repository_id: string; commit_sha: string; scope: string };

export function GraphWorkspace({ title = "Security Graph", initialPathId }: {
  title?: string; initialPathId?: string;
}) {
  const [snapshots, setSnapshots] = useState<GraphSnapshot[]>([]);
  const [sources, setSources] = useState<GraphSource[]>([]);
  const [snapshot, setSnapshot] = useState("");
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [paths, setPaths] = useState<GraphPath[]>([]);
  const [evidence, setEvidence] = useState<GraphEvidence[]>([]);
  const [hypotheses, setHypotheses] = useState<GraphHypothesis[]>([]);
  const [mcpScope, setMcpScope] = useState<McpScopeCandidate[]>([]);
  const [mcpValidations, setMcpValidations] = useState<McpValidation[]>([]);
  const [validations, setValidations] = useState<{ hypothesis_id: string; status: string; before: { status: string } }[]>([]);
  const [selectedPath, setSelectedPath] = useState(initialPathId ?? "");
  const [selectedNode, setSelectedNode] = useState("");
  const [mobilePanel, setMobilePanel] = useState<Panel>("assets");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    Promise.all([getJSON<GraphSnapshot[]>("/api/security-graph/snapshots"),
      getJSON<GraphSource[]>("/api/security-graph/sources")]).then(([items, registered]) => {
      setSnapshots(items);
      setSources(registered);
      setSnapshot(items[0]?.id ?? "");
    }, e => setError((e as Error).message));
  }, []);
  useEffect(() => {
    if (!snapshot) return;
    let cancelled = false;
    const q = `?snapshot=${encodeURIComponent(snapshot)}`;
    Promise.all([
      getJSON<GraphNode[]>(`/api/security-graph/nodes${q}`),
      getJSON<GraphPath[]>(`/api/security-graph/paths${q}`),
      getJSON<GraphEvidence[]>(`/api/security-graph/evidence${q}`),
      getJSON<GraphHypothesis[]>(`/api/security-graph/hypotheses${q}`),
      getJSON<McpScopeCandidate[]>(`/api/security-graph/mcp-scope${q}`),
      getJSON<McpValidation[]>(`/api/security-graph/mcp-validations${q}`),
      getJSON<typeof validations>(`/api/security-graph/validations${q}`),
    ]).then(([n, p, e, h, scope, mcpResults, v]) => {
      if (cancelled) return;
      setNodes(n); setPaths(p); setEvidence(e); setHypotheses(h); setMcpScope(scope);
      setMcpValidations(mcpResults); setValidations(v);
      setSelectedPath(current => p.some(path => path.id === current) ? current :
        p.some(path => path.id === initialPathId) ? initialPathId! : p[0]?.id ?? "");
    }, e => { if (!cancelled) setError((e as Error).message); });
    return () => { cancelled = true; };
  }, [snapshot, initialPathId]);

  const nodeMap = useMemo(() => new Map(nodes.map(node => [node.id, node])), [nodes]);
  const path = paths.find(item => item.id === selectedPath);
  const node = nodeMap.get(selectedNode) ?? (path ? nodeMap.get(path.nodes[0]) : undefined);
  const evidenceMap = useMemo(() => new Map(evidence.map(item => [item.id, item])), [evidence]);
  const relatedHypotheses = hypotheses.filter(item => path?.evidence_ids.some(id => item.evidence_ids.includes(id)));
  const selectedMcpScope = mcpScope.find(item => item.tool_id === path?.nodes[0]);
  const selectedMcpValidation = mcpValidations.find(item => item.candidate_id === selectedMcpScope?.id);
  const panelClass = (panel: Panel) => mobilePanel === panel ? "block" : "hidden md:block";

  async function runResearch() {
    if (!snapshot || busy) return;
    setBusy(true); setError("");
    try {
      const result = await postJSON<GraphHypothesis[]>("/api/security-graph/research", { snapshot_id: snapshot });
      setHypotheses(result);
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }

  async function validateSynthetic(hypothesisId: string) {
    if (!snapshot || busy) return;
    setBusy(true); setError("");
    try {
      await postJSON("/api/security-graph/validate-synthetic", {
        snapshot_id: snapshot, hypothesis_id: hypothesisId,
      });
      setValidations(await getJSON<typeof validations>(`/api/security-graph/validations?snapshot=${encodeURIComponent(snapshot)}`));
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }

  async function validateMcpSynthetic(candidateId: string) {
    if (!snapshot || busy) return;
    setBusy(true); setError("");
    try {
      await postJSON("/api/security-graph/mcp-validate-synthetic", {
        snapshot_id: snapshot, candidate_id: candidateId,
      });
      setMcpValidations(await getJSON<McpValidation[]>(`/api/security-graph/mcp-validations?snapshot=${encodeURIComponent(snapshot)}`));
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }

  async function importSynthetic(sourceId: string) {
    if (busy) return;
    setBusy(true); setError("");
    try {
      const result = await postJSON<{ snapshot_id: string }>("/api/security-graph/import", { source_id: sourceId });
      const rows = await getJSON<GraphSnapshot[]>("/api/security-graph/snapshots");
      setSnapshots(rows); setSnapshot(result.snapshot_id);
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }

  return <main className="mx-auto max-w-[1500px] p-4 text-zinc-900 md:p-6 dark:text-zinc-100">
    <header className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-2xl font-semibold">{title}</h1>
        <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-300">コード構造、認可条件、データ参照を根拠から確認します。接続だけでは脆弱性は確定しません。</p>
      </div>
      <Link href="/remediations" className="rounded-lg border px-3 py-2 text-sm">修正効果を見る</Link>
    </header>
    {error && <p role="alert" className="mt-4 rounded-lg border border-red-300 bg-red-50 p-3 text-sm text-red-800">{error}</p>}
    {sources.length > 0 && <section aria-label="登録済み合成ソース" className="mt-5 rounded-xl border bg-white p-4 dark:bg-zinc-900">
      <h2 className="text-sm font-semibold">登録済みの合成ソース</h2>
      <div className="mt-2 flex flex-wrap gap-2">{sources.map(source => <button key={source.id} type="button" disabled={busy}
        onClick={() => importSynthetic(source.id)} className="rounded-lg border px-3 py-2 text-sm disabled:opacity-50">
        {source.repository_id} · {source.commit_sha.slice(0, 10)} を解析
      </button>)}</div>
      <p className="mt-2 text-xs text-zinc-500">サーバーが事前登録した合成リポジトリのみ。顧客ソースへの接続ではありません。</p>
    </section>}
    {!snapshot && !error && <p className="mt-6 rounded-xl border bg-white p-5 text-sm dark:bg-zinc-900">この組織にはコード解析のスナップショットがありません。登録済みの合成ソースから解析を開始してください。</p>}
    {snapshot && <>
      <div className="mt-5 flex flex-wrap items-center gap-2">
        <label htmlFor="graph-snapshot" className="text-sm font-medium">解析コミット</label>
        <select id="graph-snapshot" value={snapshot} onChange={e => setSnapshot(e.target.value)} className="max-w-full rounded-lg border bg-white px-3 py-2 text-sm dark:bg-zinc-900">
          {snapshots.map(item => <option key={item.id} value={item.id}>{item.repository_id} · {item.commit_sha.slice(0, 10)}</option>)}
        </select>
        <button type="button" disabled={busy} onClick={runResearch} className="rounded-lg bg-zinc-900 px-3 py-2 text-sm font-semibold text-white disabled:opacity-50 dark:bg-white dark:text-zinc-900">{busy ? "照合中…" : "仮説を生成"}</button>
      </div>
      <nav aria-label="モバイル表示" className="mt-4 grid grid-cols-3 gap-1 rounded-lg bg-zinc-100 p-1 md:hidden dark:bg-zinc-800">
        {(["assets", "graph", "detail"] as Panel[]).map((panel, i) => <button key={panel} type="button" onClick={() => setMobilePanel(panel)} aria-pressed={mobilePanel === panel}
          className={`rounded-md px-2 py-2 text-sm ${mobilePanel === panel ? "bg-white font-semibold dark:bg-zinc-700" : ""}`}>{["経路一覧", "グラフ", "詳細"][i]}</button>)}
      </nav>
      <div className="mt-4 grid min-h-[520px] gap-3 md:grid-cols-[240px_minmax(0,1fr)_300px]">
        <section aria-label="経路一覧" className={`${panelClass("assets")} min-w-0 rounded-xl border bg-white p-3 dark:bg-zinc-900`}>
          <h2 className="px-1 text-sm font-semibold">重要資産への経路候補</h2>
          <p className="mt-1 px-1 text-xs text-zinc-500">最大100経路。表示は選択した経路に限定します。</p>
          <div className="mt-3 space-y-2">{paths.map(item => <button type="button" key={item.id} onClick={() => { setSelectedPath(item.id); setSelectedNode(""); setMobilePanel("graph"); }}
            aria-pressed={item.id === selectedPath} className={`w-full rounded-lg border p-3 text-left text-sm ${item.id === selectedPath ? "border-blue-500 bg-blue-50 dark:bg-blue-950/40" : ""}`}>
              <span className="block break-words font-medium">{nodeMap.get(item.nodes[0])?.name ?? "入口不明"}</span>
              <span className="mt-1 block break-words text-xs text-zinc-500">→ {nodeMap.get(item.nodes.at(-1) ?? "")?.name ?? "重要資産"}</span>
              <span className="mt-1 block text-xs">{pathStatusLabel(item.status)}</span>
            </button>)}</div>
          {!paths.length && <p className="mt-4 text-sm text-zinc-500">経路候補はありません。</p>}
        </section>
        <section aria-label="選択中のグラフ" className={`${panelClass("graph")} min-w-0 rounded-xl border bg-white p-4 dark:bg-zinc-900`}>
          <h2 className="text-sm font-semibold">選択中の経路</h2>
          {path ? <>
            <p className="mt-1 text-xs text-zinc-500">{pathStatusLabel(path.status)}</p>
            <div className="mt-8 flex flex-wrap items-center justify-center gap-2" role="img" aria-label="入口からデータへの関係図">
              {path.nodes.map((id, index) => <div key={`${id}-${index}`} className="flex min-w-0 items-center gap-2">
                {index > 0 && <span aria-hidden className="text-xl text-zinc-400">→</span>}
                <button type="button" onClick={() => { setSelectedNode(id); setMobilePanel("detail"); }} className={`max-w-[180px] rounded-xl border-2 p-3 text-left text-sm shadow-sm ${node?.id === id ? "border-blue-500" : "border-zinc-300"}`}>
                  <span className="block text-xs text-zinc-500">{nodeMap.get(id)?.kind ?? "unknown"}</span>
                  <span className="block break-all font-medium">{nodeMap.get(id)?.name ?? id}</span>
                </button>
              </div>)}</div>
            <ul className="mt-8 space-y-2 text-xs text-zinc-600 dark:text-zinc-300">{path.edges.map((edge, i) => <li key={`${edge.source}-${edge.target}-${i}`} className="break-all rounded-lg bg-zinc-50 p-2 dark:bg-zinc-800">
              {edge.relation} · {edge.evidence_status} · 根拠 {edge.evidence_ids.join(", ")}
            </li>)}</ul>
          </> : <p className="mt-6 text-sm text-zinc-500">左から経路を選んでください。</p>}
        </section>
        <section aria-label="根拠と詳細" className={`${panelClass("detail")} min-w-0 rounded-xl border bg-white p-4 dark:bg-zinc-900`}>
          <h2 className="text-sm font-semibold">原因と証拠</h2>
          {node ? <>
            <p className="mt-3 break-all text-sm font-medium">{node.name}</p>
            <p className="mt-1 break-all text-xs text-zinc-500">{node.source_path}:{node.source_line} · {node.status}</p>
            {selectedMcpScope && <div className="mt-4 rounded-lg border border-amber-300 bg-amber-50 p-3 text-xs text-amber-950 dark:bg-amber-950/30 dark:text-amber-100">
              <h3 className="font-semibold">MCPツールの権限範囲</h3>
              <p className="mt-1">{mcpScopeLabel(selectedMcpScope.status)}</p>
              <p className="mt-1">データ参照の関係を観測しました。MCPサーバー側の認証・承認と実行時の権限は未検証です。</p>
              <p className="mt-1">ロール宣言: {selectedMcpScope.declared_role_ids.length ? `${selectedMcpScope.declared_role_ids.length}件（実効性未検証）` : "この解析範囲では未確認"}</p>
              {selectedMcpValidation ? <>
                <p className="mt-1">{mcpValidationStatusLabel(selectedMcpValidation.status)}。顧客環境と当該MCP実装の権限は未検証です。</p>
                <ul className="mt-1 list-inside list-disc">{Object.entries(selectedMcpValidation.observation).map(([key, value]) =>
                  <li key={key}>{key === "viewer_denied" ? "合成viewerの拒否" :
                    key === "admin_reached_data" ? "合成adminのデータ到達" : "合成viewerのデータ到達"}: {value ? "観測" : "未観測"}</li>)}</ul>
              </> : <>
                <p className="mt-1">隔離検証: 未実施</p>
                <button type="button" disabled={busy} onClick={() => validateMcpSynthetic(selectedMcpScope.id)}
                  className="mt-2 rounded border border-amber-600 px-2 py-1 disabled:opacity-50">固定合成ケースを照合</button>
                <p className="mt-1">登録済みの固定合成ソースにだけ対応します。</p>
              </>}
            </div>}
            <h3 className="mt-5 text-xs font-semibold">根拠ID</h3>
            <ul className="mt-2 space-y-2">{Array.from(new Set([...(path?.evidence_ids ?? node.evidence_ids), ...(selectedMcpScope?.evidence_ids ?? [])])).map(id => {
              const item = evidenceMap.get(id);
              return <li key={id} className="break-all rounded-lg border p-2 text-xs"><strong>{id}</strong><br />{item ? `${item.source_path}:${item.source_line}` : "位置未取得"}</li>;
            })}</ul>
            <h3 className="mt-5 text-xs font-semibold">AI研究の仮説</h3>
            {relatedHypotheses.length ? relatedHypotheses.map(item => <div key={item.hypothesis_id} className="mt-2 rounded-lg bg-amber-50 p-3 text-xs text-amber-950 dark:bg-amber-950/30 dark:text-amber-100">
              <strong>{item.summary}</strong><p className="mt-1">仮説の前提: {item.assumptions.join("、")}</p>
              {validations.find(v => v.hypothesis_id === item.hypothesis_id) ?
                <p className="mt-2">{syntheticValidationLabel(validations.find(v => v.hypothesis_id === item.hypothesis_id)?.status ?? "")}。顧客環境では未検証。</p> :
                <button type="button" disabled={busy} onClick={() => validateSynthetic(item.hypothesis_id)} className="mt-2 rounded border px-2 py-1 disabled:opacity-50">登録済み合成ラボで検証</button>}
            </div>) : <p className="mt-2 text-xs text-zinc-500">保存された仮説はありません。</p>}
          </> : <p className="mt-4 text-sm text-zinc-500">ノードを選ぶと根拠を表示します。</p>}
        </section>
      </div>
    </>}
  </main>;
}
