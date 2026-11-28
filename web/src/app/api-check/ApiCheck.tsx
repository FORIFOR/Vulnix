"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { getJSON, postJSON } from "@/lib/api";
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

type Approval = { status: "draft" | "requested" | "approved" | "changed" | "revoked" | "suspended"; voided?: string; reason?: string };
export type Draft = { id: string; name: string; host: string; sha256: string; revision: number; saved_by: string;
  checks: { kind: string; label: string; confirmed: boolean }[]; approval: Approval; approved_profile_loaded: boolean };
type DraftList = { drafts: Draft[]; org: string; may_approve: boolean };

const STATUS: Record<Approval["status"], { label: string; tone: string }> = {
  draft: { label: "下書き（実行できません）", tone: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300" },
  requested: { label: "管理者の承認待ち", tone: "bg-amber-50 text-amber-800 dark:bg-amber-950/40 dark:text-amber-200" },
  approved: { label: "承認済み（実行には項目ごとの承認が必要）", tone: "bg-emerald-50 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-200" },
  changed: { label: "内容が変わったため承認は無効", tone: "bg-red-50 text-red-800 dark:bg-red-950/40 dark:text-red-200" },
  revoked: { label: "取り下げ済み", tone: "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400" },
  suspended: { label: "権限の失効により停止中", tone: "bg-red-50 text-red-800 dark:bg-red-950/40 dark:text-red-200" },
};
/** The four steps a user sees; none of the earlier ones gives the power of a later one. */
const STEPS = ["仕様と試験データの確認", "下書きを保存", "管理者の承認", "実行の許可（項目ごと）"];
const stepOf = (d: Draft | null, ready: boolean) =>
  !d ? (ready ? 1 : 0) : d.approval.status === "requested" ? 2 : d.approval.status === "approved" ? 3 : 1;

const field = "w-full rounded-lg border border-zinc-300 bg-white px-2.5 py-1.5 text-sm transition-colors focus:border-zinc-500 focus:outline-none dark:border-zinc-700 dark:bg-zinc-900";

export default function ApiCheck() {
  const { session } = useSession();
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

        <RuntimeSetup analysis={analysis} signedIn={!!session} busy={busy} setBusy={setBusy} />
      </>}
      {session && <SavedDrafts />}
      {session && <AdminReview />}
      <p className="text-xs text-zinc-500">静的な分析は通信なしで行います。実行時の確認は、所有確認した対象または検証ラボに対し、
        管理者が承認した検証内容・試験用アカウント・項目ごとの承認（依頼者とは別の承認者）がそろったときだけ行います。実サイトへの実行時検証は行いません。</p>
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

function RuntimeSetup({ analysis, signedIn, busy, setBusy }: {
  analysis: ApiAnalysis; signedIn: boolean; busy: boolean; setBusy: (b: boolean) => void;
}) {
  const options = (k: Runtime) => analysis.candidates.filter((c) => c.kind === k);
  const [host, setHost] = useState(analysis.host ?? "");
  const [ownPath, setOwnPath] = useState(options("cross_account")[0]?.endpoint.path ?? "");
  const [ownMarker, setOwnMarker] = useState("");
  const [denied, setDenied] = useState<number[]>([403]);
  const [adminSame, setAdminSame] = useState(true);
  const [picks, setPicks] = useState<Record<Runtime, Pick>>(() => Object.fromEntries(RUNTIME_KINDS.map((k) =>
    [k, { use: options(k).length > 0, index: 0, path: options(k)[0]?.endpoint.path ?? "", marker: "", confirmed: false }])) as Record<Runtime, Pick>);
  const [saved, setSaved] = useState<Draft | null>(null);
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

  const readiness = (k: Runtime) => {
    const p = picks[k];
    if (!p.use) return { label: "対象外", tone: "text-zinc-500" };
    if (!p.path || hasTemplate(p.path) || !p.marker) return { label: "試験データが必要", tone: "text-amber-700 dark:text-amber-300" };
    if (!p.confirmed) return { label: "仕様の確認が必要（未確認の候補）", tone: "text-amber-700 dark:text-amber-300" };
    return { label: "仕様確認済み", tone: "text-emerald-700 dark:text-emerald-300" };
  };
  const step = stepOf(saved, chosen.length > 0 && missing.length === 0);

  const save = async () => {
    setBusy(true);
    setError("");
    try {
      const draft = { name: analysis.title, host, source: analysis.endpoints[0]?.source.split(":")[0] ?? "API定義",
        own_path: ownPath, own_marker: ownMarker, denied_status: denied, admin_is_same_org: adminSame,
        checks: chosen.map((k) => { const c = options(k)[picks[k].index]; return { kind: k, path: picks[k].path, marker: picks[k].marker,
          confirmed: picks[k].confirmed, evidence: c ? [`${c.endpoint.source}（${c.reason}）`] : [] }; }) };
      setSaved(await postJSON<Draft>("/api/assets/a2b-drafts", { draft, id: saved?.id }));
      window.dispatchEvent(new Event("a2b-drafts-changed"));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return <section aria-label="実行時の確認の準備" className="space-y-4 rounded-2xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900">
    <ol aria-label="準備の段階" className="grid grid-cols-2 gap-1 text-xs sm:grid-cols-4">
      {STEPS.map((label, i) => <li key={label} aria-current={i === step ? "step" : undefined}
        className={`rounded-lg px-2 py-1.5 transition-colors duration-300 ${i < step ? "bg-emerald-50 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-200" : i === step ? "bg-zinc-900 text-white dark:bg-white dark:text-zinc-900" : "bg-zinc-100 text-zinc-500 dark:bg-zinc-800"}`}>
        <span className="tabular-nums">{i + 1}.</span> {label}</li>)}
    </ol>
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
          <label className="flex flex-wrap items-center gap-2 font-medium"><input type="checkbox" checked={p.use} disabled={!opts.length} onChange={(e) => set(k, { use: e.target.checked })} />
            {KIND_LABEL[k]}<span className={`text-xs font-normal ${readiness(k).tone}`}>{readiness(k).label}</span><span className="text-xs font-normal text-zinc-500">（所有者：{k === "admin_function" && adminSame ? "同じ組織の利用者B（管理者を兼ねる）" : OWNER[k]}）</span></label>
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
    {saved && <DraftStatus draft={saved} onChange={setSaved} />}
    {signedIn ? <button type="button" disabled={busy || !chosen.length || missing.length > 0} onClick={() => void save()}
      className="inline-flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-semibold text-white transition-all hover:shadow-md active:scale-[0.98] disabled:opacity-40 dark:bg-white dark:text-zinc-900">
      {busy && <span aria-hidden="true" className="h-3 w-3 animate-spin rounded-full border-2 border-current border-r-transparent motion-reduce:animate-none" />}
      {saved ? "変更を保存（承認済みなら承認は無効になります）" : "検証内容を確認・保存"}</button>
      : <p className="text-xs text-zinc-500">下書きを保存するにはログインしてください。</p>}
  </section>;
}

function DraftStatus({ draft, onChange }: { draft: Draft; onChange: (d: Draft) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const st = STATUS[draft.approval.status];
  const confirmed = draft.checks.filter((c) => c.confirmed).length;
  const act = async (path: string, body: object) => {
    setBusy(true);
    setError("");
    try {
      onChange(await postJSON<Draft>(path, body));
      window.dispatchEvent(new Event("a2b-drafts-changed"));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const btn = "rounded-lg border border-zinc-300 px-3 py-1.5 text-xs font-medium transition-all hover:bg-zinc-50 active:scale-[0.98] disabled:opacity-40 dark:border-zinc-700 dark:hover:bg-zinc-800";
  return <div role="status" className="space-y-2 rounded-xl border border-zinc-200 p-3 text-sm transition-all dark:border-zinc-800">
    <div className="flex flex-wrap items-center gap-2">
      <span className="font-medium">{draft.name}</span>
      <span className="font-mono text-xs text-zinc-500">{draft.host}</span>
      <span className={`rounded-full px-2 py-0.5 text-xs ${st.tone}`}>{st.label}</span>
      {draft.approval.voided && <span className="text-xs text-red-700 dark:text-red-300">変更により以前の承認は無効になりました</span>}
    </div>
    {draft.approval.status === "suspended" && draft.approval.reason &&
      <p className="text-xs text-red-700 dark:text-red-300">{draft.approval.reason}</p>}
    <p className="text-xs text-zinc-500">仕様確認済みの項目 {confirmed} / {draft.checks.length}（未確認の候補は承認されても実行されません）・第 {draft.revision} 版</p>
    <div className="flex flex-wrap gap-2">
      {(draft.approval.status === "draft" || draft.approval.status === "changed" || draft.approval.status === "revoked"
        || draft.approval.status === "suspended") &&
        <button type="button" className={btn} disabled={busy || confirmed === 0}
          onClick={() => void act("/api/assets/a2b-drafts/request", { id: draft.id, sha256: draft.sha256 })}>管理者に承認を依頼</button>}
      {(draft.approval.status === "requested" || draft.approval.status === "approved" || draft.approval.status === "changed") &&
        <button type="button" className={btn} disabled={busy}
          onClick={() => void act("/api/assets/a2b-drafts/withdraw", { id: draft.id })}>取り下げる</button>}
    </div>
    {draft.approval.status === "approved" && <p className="text-xs text-zinc-600 dark:text-zinc-400">次の操作：<Link className="underline" href="/assets">サイト</Link> で所有確認と試験用アカウントを登録し、
      項目ごとに承認責任者（依頼者とは別の人）の承認を受けると実行できます。実サイトへの実行時検証は行いません。</p>}
    {error && <p role="alert" className="text-xs text-red-700 dark:text-red-300">{error}</p>}
  </div>;
}

function SavedDrafts() {
  const [list, setList] = useState<DraftList | null>(null);
  const reload = useCallback(() => { getJSON<DraftList>("/api/assets/a2b-drafts").then(setList).catch(() => setList(null)); }, []);
  useEffect(() => {
    reload();
    window.addEventListener("a2b-drafts-changed", reload);
    return () => window.removeEventListener("a2b-drafts-changed", reload);
  }, [reload]);
  if (!list?.drafts.length) return null;
  return <section aria-label="この組織の検証内容" className="space-y-2">
    <h2 className="text-lg font-semibold">この組織の検証内容</h2>
    <p className="text-xs text-zinc-500">保存した下書きと承認の状況です。下書きを保存しても実行の権限はありません。承認はプラットフォームの管理者だけが行えます。</p>
    <div className="space-y-2">{list.drafts.map((d) => <DraftStatus key={d.id} draft={d} onChange={() => reload()} />)}</div>
  </section>;
}

type Rule = { id: string; label: string; request: { account: string; path: string };
  controls: { label: string; account: string; path: string }[]; denied: { status: number[]; body_not_contains: string[] };
  exposed: { body_contains: string[] } };
type ReviewItem = Draft & { org: string; rules: Rule[] };

/** Platform admins only (the server checks again): the exact requests the SHA-256 covers, then approve. */
function AdminReview() {
  const [items, setItems] = useState<ReviewItem[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const reload = useCallback(() => { getJSON<{ drafts: ReviewItem[] }>("/api/a2b/review").then((r) => setItems(r.drafts)).catch(() => setItems([])); }, []);
  useEffect(() => {
    reload();
    window.addEventListener("a2b-drafts-changed", reload);
    return () => window.removeEventListener("a2b-drafts-changed", reload);
  }, [reload]);
  const act = async (path: string, body: object) => {
    setBusy(true);
    setError("");
    try {
      await postJSON(path, body);
      window.dispatchEvent(new Event("a2b-drafts-changed"));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  if (!items.length) return null;
  return <section aria-label="管理者の確認" className="space-y-2 rounded-2xl border border-zinc-200 bg-zinc-50 p-4 dark:border-zinc-800 dark:bg-zinc-900/60">
    <h3 className="font-semibold">管理者の確認（全組織）</h3>
    <p className="text-xs text-zinc-500">承認すると、下に示すリクエストだけが送信できるようになります（実行には、さらに所有確認・試験用アカウント・項目ごとの承認が必要）。依頼者・保存者本人は承認できません。</p>
    {items.map((d) => <div key={`${d.org}/${d.id}`} className="space-y-2 rounded-xl border border-zinc-200 bg-white p-3 text-sm dark:border-zinc-800 dark:bg-zinc-900">
      <div className="flex flex-wrap items-center gap-2"><span className="font-medium">{d.name}</span>
        <span className="font-mono text-xs text-zinc-500">{d.host}・組織 {d.org}</span>
        <span className={`rounded-full px-2 py-0.5 text-xs ${STATUS[d.approval.status].tone}`}>{STATUS[d.approval.status].label}</span></div>
      <ul className="space-y-1 text-xs">{d.rules.map((r) => <li key={r.id} className="rounded-lg bg-zinc-50 p-2 dark:bg-zinc-800/60">
        <p className="font-medium">{r.label}</p>
        <p className="wrap-anywhere">送信：{r.request.account} → <span className="font-mono">GET {r.request.path}</span></p>
        {r.controls.map((c) => <p key={c.label} className="wrap-anywhere text-zinc-500">前提：{c.label}（<span className="font-mono">{c.path}</span>）</p>)}
        <p className="text-zinc-500">拒否と判定：{r.denied.status.join("・")} かつ目印 <span className="font-mono">{r.denied.body_not_contains.join("・")}</span> を含まない</p>
      </li>)}</ul>
      <p className="font-mono text-[11px] text-zinc-400 wrap-anywhere">SHA-256 {d.sha256}</p>
      <div className="flex flex-wrap gap-2">
        {d.approval.status === "requested" && <button type="button" disabled={busy}
          className="rounded-lg bg-emerald-700 px-3 py-1.5 text-xs font-semibold text-white transition-all hover:bg-emerald-800 active:scale-[0.98] disabled:opacity-40"
          onClick={() => void act("/api/a2b/approve", { org: d.org, id: d.id, sha256: d.sha256 })}>この内容を承認する</button>}
        {(d.approval.status === "approved" || d.approval.status === "changed") && <button type="button" disabled={busy}
          className="rounded-lg border border-zinc-300 px-3 py-1.5 text-xs transition-all hover:bg-zinc-50 active:scale-[0.98] dark:border-zinc-700"
          onClick={() => void act("/api/a2b/revoke", { org: d.org, id: d.id })}>承認を取り消す</button>}
      </div>
    </div>)}
    {error && <p role="alert" className="text-xs text-red-700 dark:text-red-300">{error}</p>}
  </section>;
}
