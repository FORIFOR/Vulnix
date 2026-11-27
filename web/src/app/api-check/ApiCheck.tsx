"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { postJSON } from "@/lib/api";
import { analyzeRoutes, analyzeSpec, hasTemplate, KIND_LABEL, RUNTIME_KINDS, type ApiAnalysis, type ApiCandidate, type ApiKind } from "@/lib/apiSpec";
import { useSession } from "@/lib/useSession";

type Runtime = (typeof RUNTIME_KINDS)[number];
type Pick = { use: boolean; index: number; path: string; marker: string; confirmed: boolean };
const OWNER: Record<Runtime, string> = {
  cross_account: "同じ組織の利用者B", cross_tenant: "別組織の利用者C", admin_function: "同じ組織の管理者",
};
const KINDS = Object.keys(KIND_LABEL) as ApiKind[];
const SOURCE_EXT = /\.(?:py|js|ts|mjs|cjs)$/i;
const SPEC_NAME = /(?:openapi|swagger)[^/]*\.(?:json|ya?ml)$/i;

const field = "w-full rounded-lg border border-zinc-300 bg-white px-2.5 py-1.5 text-sm transition-colors focus:border-zinc-500 focus:outline-none dark:border-zinc-700 dark:bg-zinc-900";

export default function ApiCheck() {
  const { session } = useSession();
  const canSave = !!session && session.roles.some((r) => r === "approver" || r === "admin");
  const [analysis, setAnalysis] = useState<ApiAnalysis | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<ApiKind | null>(null);

  const load = async (list: FileList | null, folder: boolean) => {
    setError("");
    setAnalysis(null);
    if (!list?.length) return;
    try {
      const files = [...list];
      if (!folder) {
        const f = files[0];
        if (f.size > 5_000_000) throw new Error("API 定義が大きすぎます（5 MB まで）");
        setAnalysis(analyzeSpec(await f.text(), f.name));
        return;
      }
      const spec = files.find((f) => SPEC_NAME.test(f.webkitRelativePath || f.name));
      if (spec) { setAnalysis(analyzeSpec(await spec.text(), spec.webkitRelativePath || spec.name)); return; }
      const sources = files.filter((f) => SOURCE_EXT.test(f.name) && f.size < 1_000_000
        && !/(?:^|\/)(?:node_modules|\.venv|venv|dist|build|\.next)\//.test(f.webkitRelativePath)).slice(0, 3000);
      setAnalysis(analyzeRoutes(await Promise.all(sources.map(async (f) => ({ path: f.webkitRelativePath || f.name, text: await f.text() })))));
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const counts = useMemo(() => Object.fromEntries(KINDS.map((k) => [k, analysis?.candidates.filter((c) => c.kind === k).length ?? 0])), [analysis]);

  return (
    <main className="mx-auto max-w-4xl space-y-6 px-4 py-8">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">APIの安全性を確認</h1>
        <p className="text-sm text-zinc-600 dark:text-zinc-400">アプリが呼ぶバックエンドAPI（A2B）の認証・認可・組織分離を確認します。
          定義の読み取りはこのブラウザの中だけで行い、どこにも送信しません。</p>
      </header>

      <section aria-label="診断対象のAPI情報" className="grid gap-3 sm:grid-cols-2">
        <label className="group cursor-pointer rounded-2xl border border-zinc-200 bg-white p-4 transition-all hover:-translate-y-0.5 hover:shadow-md dark:border-zinc-800 dark:bg-zinc-900">
          <p className="font-semibold">OpenAPI・Swagger</p>
          <p className="text-xs text-zinc-500">API 仕様ファイル（JSON / YAML）から読み込む</p>
          <input type="file" accept=".json,.yaml,.yml" className="sr-only" aria-label="API 仕様ファイルを選ぶ"
            onChange={(e) => void load(e.target.files, false)} />
        </label>
        <label className="group cursor-pointer rounded-2xl border border-zinc-200 bg-white p-4 transition-all hover:-translate-y-0.5 hover:shadow-md dark:border-zinc-800 dark:bg-zinc-900">
          <p className="font-semibold">プロジェクトフォルダ</p>
          <p className="text-xs text-zinc-500">API の定義と認証処理を解析する（Flask・FastAPI・Express）</p>
          <input type="file" className="sr-only" aria-label="プロジェクトフォルダを選ぶ"
            {...{ webkitdirectory: "", directory: "" }} multiple onChange={(e) => void load(e.target.files, true)} />
        </label>
      </section>
      {error && <p role="alert" className="text-sm text-red-700 dark:text-red-300">{error}</p>}

      {analysis && <>
        <section aria-label="確認する項目" className="space-y-2">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2 className="text-lg font-semibold">{analysis.title}</h2>
            <p className="text-xs text-zinc-500">API {analysis.endpoints.length} 件を読み取りました（候補であり、判定ではありません）</p>
          </div>
          {analysis.notes.map((n) => <p key={n} className="text-xs text-amber-700 dark:text-amber-300">{n}</p>)}
          <ul className="grid gap-2 sm:grid-cols-5">
            {KINDS.map((k) => <li key={k}>
              <button type="button" onClick={() => setOpen(open === k ? null : k)} aria-expanded={open === k}
                className={`w-full rounded-xl border p-3 text-left transition-all ${open === k ? "border-zinc-900 shadow-sm dark:border-white" : "border-zinc-200 hover:border-zinc-400 dark:border-zinc-800"} bg-white dark:bg-zinc-900`}>
                <span className="block text-xs text-zinc-500">{KIND_LABEL[k]}</span>
                <span className="text-xl font-semibold tabular-nums">{counts[k]}</span>
                <span className="ml-1 text-xs text-zinc-500">候補</span>
              </button>
            </li>)}
          </ul>
          {open && <CandidateList items={analysis.candidates.filter((c) => c.kind === open)} />}
        </section>

        <RuntimeSetup analysis={analysis} canSave={canSave} signedIn={!!session} busy={busy} setBusy={setBusy} />
      </>}
      <p className="text-xs text-zinc-500">静的な分析は通信なしで行います。実行時の確認は、所有確認した対象または検証ラボに対し、
        管理者が承認した検証プロファイル・試験用アカウント・項目ごとの承認がそろったときだけ行います。</p>
    </main>
  );
}

function CandidateList({ items }: { items: ApiCandidate[] }) {
  if (!items.length) return <p className="text-sm text-zinc-500">この項目の候補はありません（問題がないという意味ではありません）。</p>;
  return <ul className="divide-y divide-zinc-200 rounded-xl border border-zinc-200 bg-white text-sm dark:divide-zinc-800 dark:border-zinc-800 dark:bg-zinc-900">
    {items.map((c, i) => <li key={i} className="space-y-1 p-3">
      <p><span className="rounded bg-zinc-100 px-1.5 py-0.5 font-mono text-xs dark:bg-zinc-800">{c.endpoint.method}</span>{" "}
        <span className="font-mono text-xs wrap-anywhere">{c.endpoint.path}</span></p>
      <p className="text-xs">{c.reason}<span className="text-zinc-500">（根拠：{c.endpoint.source}）</span></p>
      <p className="text-xs text-amber-700 dark:text-amber-300">未確認：{c.unknown.join("、")}</p>
    </li>)}
  </ul>;
}

function RuntimeSetup({ analysis, canSave, signedIn, busy, setBusy }: {
  analysis: ApiAnalysis; canSave: boolean; signedIn: boolean; busy: boolean; setBusy: (b: boolean) => void;
}) {
  const options = (k: Runtime) => analysis.candidates.filter((c) => c.kind === k);
  const [host, setHost] = useState(analysis.host ?? "");
  const [ownPath, setOwnPath] = useState(options("cross_account")[0]?.endpoint.path ?? "");
  const [ownMarker, setOwnMarker] = useState("");
  const [denied, setDenied] = useState<number[]>([403]);
  const [adminSame, setAdminSame] = useState(true);
  const [picks, setPicks] = useState<Record<Runtime, Pick>>(() => Object.fromEntries(RUNTIME_KINDS.map((k) =>
    [k, { use: options(k).length > 0, index: 0, path: options(k)[0]?.endpoint.path ?? "", marker: "", confirmed: false }])) as Record<Runtime, Pick>);
  const [result, setResult] = useState<{ saved: string; checks: string } | null>(null);
  const [error, setError] = useState("");
  const set = (k: Runtime, patch: Partial<Pick>) => setPicks((p) => ({ ...p, [k]: { ...p[k], ...patch } }));
  const chosen = RUNTIME_KINDS.filter((k) => picks[k].use);
  const missing = [
    !host && "対象のホスト名",
    (!ownPath || hasTemplate(ownPath)) && "試す側のデータのパス（{…} を実在の試験データの値に）",
    !ownMarker && "試す側のデータの目印",
    ...chosen.flatMap((k) => [(!picks[k].path || hasTemplate(picks[k].path)) && `${KIND_LABEL[k]}の対象パス`,
      !picks[k].marker && `${KIND_LABEL[k]}の目印`]),
  ].filter(Boolean) as string[];

  const save = async () => {
    setBusy(true);
    setError("");
    try {
      const draft = { name: analysis.title, host, source: analysis.endpoints[0]?.source.split(":")[0] ?? "API定義",
        own_path: ownPath, own_marker: ownMarker, denied_status: denied, admin_is_same_org: adminSame,
        checks: chosen.map((k) => { const c = options(k)[picks[k].index]; return { kind: k, path: picks[k].path, marker: picks[k].marker,
          confirmed: picks[k].confirmed, evidence: c ? [`${c.endpoint.source}（${c.reason}）`] : [] }; }) };
      const rep = await postJSON<{ saved: string; profiles: { id: string; confirmed_checks: string[] }[] }>("/api/a2b/profile-draft", { draft });
      const prof = rep.profiles.find((p) => p.id === rep.saved);
      setResult({ saved: rep.saved, checks: `${prof?.confirmed_checks.length ?? 0} / ${chosen.length}` });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return <section aria-label="実行時の確認の準備" className="space-y-4 rounded-2xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900">
    <div>
      <h2 className="text-lg font-semibold">実行時の確認の準備</h2>
      <p className="text-xs text-zinc-500">API 定義からは「誰のデータか」「拒否したときの応答」は分かりません。試験用アカウントと試験データについて、
        次の項目だけを入力してください。入力した内容から検証プロファイルを作ります（JSON を書く必要はありません）。</p>
    </div>
    <div className="grid gap-3 sm:grid-cols-2">
      <label className="text-sm">対象のホスト名<input className={field} value={host} onChange={(e) => setHost(e.target.value.trim())} placeholder="api.example.com" /></label>
      <fieldset className="text-sm"><legend>権限がないときの応答</legend>
        <div className="mt-1 flex gap-3">{[403, 404].map((s) => <label key={s} className="flex items-center gap-1">
          <input type="checkbox" checked={denied.includes(s)} onChange={(e) => setDenied((d) => e.target.checked ? [...d, s] : d.filter((x) => x !== s))} />{s}</label>)}
          <span className="text-xs text-zinc-500">401 はトークン失効と区別できないため使いません</span></div>
      </fieldset>
      <label className="text-sm">試す側（一般利用者A）が自分で取得できるデータのパス<input className={field} value={ownPath} onChange={(e) => setOwnPath(e.target.value.trim())} /></label>
      <label className="text-sm">そのデータにだけ含まれる目印<input className={field} value={ownMarker} onChange={(e) => setOwnMarker(e.target.value.trim())} placeholder="TEST_OWNER_A_7f3a" /></label>
    </div>
    <ul className="space-y-3">
      {RUNTIME_KINDS.map((k) => {
        const opts = options(k);
        const p = picks[k];
        return <li key={k} className={`rounded-xl border p-3 transition-colors ${p.use ? "border-zinc-300 dark:border-zinc-700" : "border-dashed border-zinc-200 opacity-70 dark:border-zinc-800"}`}>
          <label className="flex items-center gap-2 font-medium"><input type="checkbox" checked={p.use} disabled={!opts.length} onChange={(e) => set(k, { use: e.target.checked })} />
            {KIND_LABEL[k]}<span className="text-xs font-normal text-zinc-500">（所有者：{k === "admin_function" && adminSame ? "同じ組織の利用者B（管理者を兼ねる）" : OWNER[k]}）</span></label>
          {!opts.length && <p className="mt-1 text-xs text-zinc-500">定義から候補が見つかりませんでした。</p>}
          {p.use && <div className="mt-2 grid gap-2 sm:grid-cols-2">
            <label className="text-xs sm:col-span-2">対象のAPI
              <select className={field} value={p.index} onChange={(e) => { const i = Number(e.target.value); set(k, { index: i, path: opts[i].endpoint.path }); }}>
                {opts.map((c, i) => <option key={i} value={i}>{c.endpoint.method} {c.endpoint.path}</option>)}</select></label>
            <label className="text-xs">試験データのパス（{"{…}"} を実在の値に）<input className={`${field} ${hasTemplate(p.path) ? "border-amber-500" : ""}`} value={p.path} onChange={(e) => set(k, { path: e.target.value.trim() })} /></label>
            <label className="text-xs">そのデータにだけ含まれる目印<input className={field} value={p.marker} onChange={(e) => set(k, { marker: e.target.value.trim() })} /></label>
            <label className="flex items-start gap-2 text-xs sm:col-span-2"><input type="checkbox" className="mt-0.5" checked={p.confirmed} onChange={(e) => set(k, { confirmed: e.target.checked })} />
              この API で、所有者以外は拒否されるべきこと（仕様）と、上の試験データ・目印を確認した。確認しない場合は「未確認の候補」として保存し、実行しません。</label>
          </div>}
        </li>;
      })}
    </ul>
    <label className="flex items-center gap-2 text-xs"><input type="checkbox" checked={adminSame} onChange={(e) => setAdminSame(e.target.checked)} />同じ組織の利用者Bが管理者を兼ねる（試験用アカウントを3つにする）</label>
    {missing.length > 0 && chosen.length > 0 && <p className="text-xs text-amber-700 dark:text-amber-300">未入力：{missing.join("、")}</p>}
    {error && <p role="alert" className="text-sm text-red-700 dark:text-red-300">{error}</p>}
    {result ? <div role="status" className="rounded-xl bg-emerald-50 p-3 text-sm dark:bg-emerald-950/30">
      検証プロファイル <span className="font-mono">{result.saved}</span> を保存しました（実行できる項目 {result.checks}）。
      管理者が <Link className="underline" href="/settings">設定 → 検証プロファイル</Link> で内容を確認して承認するまで、何も実行されません。
      承認後、<Link className="underline" href="/assets">サイト</Link> で所有確認と試験用アカウントを登録すると、項目ごとの承認で確認できます。
    </div> : canSave ? <button type="button" disabled={busy || !chosen.length || missing.length > 0} onClick={() => void save()}
      className="inline-flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-semibold text-white transition-opacity disabled:opacity-40 dark:bg-white dark:text-zinc-900">
      {busy && <span aria-hidden="true" className="h-3 w-3 animate-spin rounded-full border-2 border-current border-r-transparent motion-reduce:animate-none" />}
      検証プロファイルを作る</button>
      : <p className="text-xs text-zinc-500">{signedIn ? "検証プロファイルの保存には承認責任者または管理者の権限が必要です。" : "検証プロファイルを保存するにはログインしてください。"}</p>}
  </section>;
}
