"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { projectHref } from "@/components/ProjectOverview";
import RuntimeDefense from "./RuntimeDefense";
import ReviewedDefense from "./ReviewedDefense";
import DefenseOverview from "./DefenseOverview";
import { Suspense, useEffect, useMemo, useRef, useState } from "react";
import { useSession } from "@/lib/useSession";
import { catalogSources, osvSources, type CatalogSource } from "@/lib/catalogUpdate";
import type { ScanProgress } from "@/lib/projectDefense";
import { readCatalogCache, type CatalogFailure } from "@/lib/catalogCache";
import { advisorySeverityLabels, groupDependencyFindings, sortByAdvisorySeverity } from "@/lib/resultPresentation";
import { categories, categoryLabels, checkControls, checkCves, demoEvidence, labels, record, type FixCandidate } from "@/lib/quickDefense";

const button = "rounded-lg border border-zinc-300 px-3 py-2 text-sm font-medium dark:border-zinc-700";
const primary = "rounded-lg bg-zinc-900 px-3 py-2 text-sm font-semibold text-white disabled:opacity-50 dark:bg-white dark:text-zinc-900";
type ProjectReport = Awaited<ReturnType<typeof import("@/lib/projectDefense").scanProject>>;
const maxInput = 2 * 1024 * 1024;

function LocalProjectContext() {
  const value = useSearchParams().get("project") ?? "";
  if (!value || value.length > 80) return null;
  return <p className="mb-2 break-words text-sm">
    <Link href={projectHref("/dashboard", value)} className="underline">{value} に戻る</Link>
    <span className="ml-2 text-zinc-600 dark:text-zinc-300">この画面の入力と結果はブラウザ内で扱います。</span>
  </p>;
}

export default function QuickDefense({ bundledFeed }: { bundledFeed: unknown }) {
  const [selected, setSelected] = useState(new Set<string>(categories));
  const [files, setFiles] = useState<File[]>([]);
  const [sbom, setSbom] = useState<File | null>(null);
  const sbomInput = useRef<HTMLInputElement>(null);
  const [nvd, setNvd] = useState<unknown>(bundledFeed);
  const [osv, setOsv] = useState<unknown[]>([]);
  const [official, setOfficial] = useState<Awaited<ReturnType<typeof readCatalogCache>>>({ sources: [], legacy: {} });
  const [updateProgress, setUpdateProgress] = useState<{ source: CatalogSource; count: number } | null>(null);
  const catalogWorker = useRef<Worker | null>(null);
  const [cacheReady, setCacheReady] = useState(false);
  const [refreshErrors, setRefreshErrors] = useState<{ source: string; reason: string }[]>([]);
  const [updateSources, setUpdateSources] = useState<CatalogSource[]>([]);
  const folderInput = useRef<HTMLInputElement>(null);
  const [updating, setUpdating] = useState(false);
  const [display, setDisplay] = useState(100);
  const [feedLabels, setFeedLabels] = useState({
    nvd: "同梱NVDサンプル（収録2件、取得日時不明）", osv: "手動OSVデータなし",
  });
  const [mode, setMode] = useState<"local" | "demo">("local");
  const [report, setReport] = useState<ProjectReport | null>(null);
  const [results, setResults] = useState<ReturnType<typeof checkControls> | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const { session } = useSession();
  const signedIn = !!session;
  const [statusFilter, setStatusFilter] = useState<keyof typeof labels | null>(null);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [ended, setEnded] = useState<"timeout" | "cancelled" | null>(null);
  const running = useRef<(() => void) | null>(null);

  useEffect(() => {
    let active = true;
    void readCatalogCache().then((cached) => {
      if (active) setOfficial(cached);
    }).catch(() => {}).finally(() => { if (active) setCacheReady(true); });
    return () => { active = false; running.current?.(); catalogWorker.current?.terminate(); };
  }, []);

  const cachedSources = new Set(official.sources.map(({ source }) => source));
  const missingCatalogs = catalogSources().filter((source) => !cachedSources.has(source));

  function updateOfficial(sources: CatalogSource[]) {
    setUpdating(true);
    setUpdateSources(sources);
    setUpdateProgress(null);
    setRefreshErrors([]);
    const finish = async (failed: { source: string; reason: string }[]) => {
      catalogWorker.current?.terminate();
      catalogWorker.current = null;
      try { setOfficial(await readCatalogCache()); }
      catch { failed.push({ source: "保存領域", reason: "ブラウザに保存したカタログを読み込めませんでした" }); }
      setRefreshErrors(failed);
      setUpdating(false);
      setUpdateProgress(null);
      setResults(null);
      setReport(null);
    };
    try {
      const worker = new Worker(new URL("../../lib/catalogUpdate.worker.ts", import.meta.url));
      catalogWorker.current = worker;
      worker.onmessage = ({ data }: MessageEvent<{ failed?: CatalogFailure[]; progress?: { source: CatalogSource; count: number } }>) => {
        if (catalogWorker.current !== worker) return;
        if (data.progress) setUpdateProgress(data.progress);
        else void finish(data.failed ?? [{ source: "更新処理", reason: "別のタブでの更新を閉じ、再試行してください" }]);
      };
      worker.onerror = () => { if (catalogWorker.current === worker) void finish([{ source: "更新処理", reason: "別のタブでの更新を閉じ、再試行してください" }]); };
      worker.postMessage(sources);
    } catch { void finish([{ source: "更新処理", reason: "別のタブでの更新を閉じ、再試行してください" }]); }
  }

  async function importFeed(file: File) {
    setError("");
    try {
      if (file.size > maxInput) throw new Error();
      const data: unknown = JSON.parse(await file.text());
      const parsed = record(data);
      const nvd = parsed.format === "NVD_CVE" && parsed.version === "2.0" && Array.isArray(parsed.vulnerabilities);
      const osv = Array.isArray(data) ? data : [data];
      if (!nvd && (!osv.length || !osv.every((entry) => typeof record(entry).id === "string" &&
          Array.isArray(record(entry).affected)))) throw new Error();
      if (nvd) setNvd(parsed); else setOsv(osv);
      const count = nvd ? (parsed.vulnerabilities as unknown[]).length : osv.length;
      const origin = nvd ? "選択したNVDデータ（CPE）" : "選択したOSVデータ（npm・PyPI・Go）";
      const timestamp = typeof parsed.timestamp === "string" &&
        /^\d{4}-\d{2}-\d{2}T[\d:.+-]+Z?$/.test(parsed.timestamp) && parsed.timestamp.length < 40
        ? ` ／ 資料の出力日時 ${parsed.timestamp}` : " ／ 取得日時不明";
      setFeedLabels((previous) => ({ ...previous,
        [nvd ? "nvd" : "osv"]: `${origin} ${count}件 ／ 読込 ${new Date().toLocaleString()}${timestamp}`,
      }));
      setResults(null);
      setReport(null);
    } catch {
      setError("2 MB以下のNVD 2.0またはOSV JSONを選んでください。");
    }
  }

  function run(kind: "local" | "demo") {
    setReport(null);
    setResults(null);
    setError("");
    setMode(kind);
    setDisplay(100);
    setProgress(null);
    setEnded(null);
    if (kind === "demo") {
      setResults([...checkControls(demoEvidence.controls), ...checkCves(demoEvidence.components, bundledFeed)]);
      return;
    }
    setBusy(true);
    try {
      const worker = new Worker(new URL("../../lib/projectDefense.worker.ts", import.meta.url));
      const finish = () => {
        window.clearTimeout(timeout);
        worker.terminate();
        running.current = null;
      };
      const timeout = window.setTimeout(() => {
        finish();
        setBusy(false);
        setEnded("timeout");
      }, 35000);
      running.current = finish;
      worker.onmessage = ({ data }: MessageEvent<{ result?: ProjectReport; progress?: ScanProgress; error?: true | "entry-limit" }>) => {
        if (data.progress) {
          setProgress(data.progress);
          return;
        }
        finish();
        setBusy(false);
        if (!data.result) {
          setError(data.error === "entry-limit"
            ? "診断する設定・コードのファイルが多すぎます（上限 12,000 件）。リポジトリ全体ではなく、アプリのフォルダ（例: backend や web）を選んでください。"
            : "検証を完了できませんでした。フォルダを選び直してください。");
          return;
        }
        setReport(data.result);
        setResults(data.result.rows);
      };
      worker.onerror = () => {
        finish();
        setBusy(false);
        setError("検証処理を読み込めませんでした。ページを開き直してください。");
      };
      // The browser may not preserve webkitRelativePath through structured cloning.
      const nvdRows = record(nvd).vulnerabilities;
      const localNvd = Array.isArray(nvdRows) ? nvdRows.filter((row) => {
        if (nvd !== bundledFeed) return true;
        const match = /^CVE-(\d{4})-/.exec(String(record(record(row).cve).id));
        return !match || !cachedSources.has(`NVD-${Math.max(2002, Number(match[1]))}`);
      }) : [];
      const feed = {
        vulnerabilities: [...localNvd, ...(official.sources.some(({ source }) => source.startsWith("NVD-")) ? [] : official.legacy.NVD?.records ?? [])],
        osv: [...osv, ...osvSources.flatMap((source) => cachedSources.has(source) ? [] : official.legacy[source]?.records ?? [])],
      };
      const sources = files.map((file) => ({ file, path: file.webkitRelativePath || file.name }));
      if (sbom) sources.push({ file: sbom, path: "inventory.sbom.json" });
      worker.postMessage({ files: sources, feed });
    } catch {
      running.current?.();
      setBusy(false);
      setError("このブラウザでは検証を開始できませんでした。");
    }
  }

  const statusLabel = (status: keyof typeof labels) => mode === "local" && status === "confirmed" ? "設定・コードを確認" : labels[status];
  const visible = useMemo(() => results && sortByAdvisorySeverity(results.filter((row) => selected.has(row.category))),
    [results, selected]);
  const shown = useMemo(() => visible && statusFilter ? visible.filter((row) => row.status === statusFilter) : visible ?? [],
    [visible, statusFilter]);
  const dependencyGroups = useMemo(() => visible ? groupDependencyFindings(visible) : [], [visible]);

  return (
    <main className="mx-auto max-w-3xl space-y-5 p-4 md:p-8">
      <Suspense><LocalProjectContext /></Suspense>
      <h1 className="text-2xl font-bold">ローカルプロジェクトの診断</h1>
      <p className="text-sm text-zinc-600 dark:text-zinc-300">プロジェクトのフォルダを選ぶと、設定・依存関係・関連ソースをブラウザ内で調べます。実行時の防御は、対応する許可済み防御テストから確認します。</p>
      <fieldset className="flex flex-wrap gap-4">
        <legend className="mb-2 font-medium">検証項目</legend>
        {categories.map((category) => <label key={category} className="flex items-center gap-2">
          <input type="checkbox" checked={selected.has(category)} onChange={(event) => {
            const next = new Set(selected);
            if (event.target.checked) next.add(category); else next.delete(category);
            setSelected(next);
            setResults(null);
          }} />{categoryLabels[category]}
        </label>)}
      </fieldset>
      <section className="space-y-3 rounded-xl border border-zinc-200 p-4 dark:border-zinc-800">
        <label className="block text-sm font-semibold">プロジェクトフォルダを選択
          <input ref={folderInput} type="file" {...{ webkitdirectory: "" }} multiple disabled={busy} className="mt-2 block w-full text-sm" onChange={(event) => {
            const list = event.target.files;
            // files the scan never reads (images, generated reports) only have their names checked
            const tooMany = (list?.length ?? 0) > 200000;
            setFiles(!tooMany && list ? Array.from(list) : []);
            setReport(null);
            setResults(null);
            setProgress(null);
            setEnded(null);
            setError(tooMany ? "ファイルが20万件を超えています。さらに小さいフォルダを選んでください。" : "");
            event.target.value = "";
          }} />
        </label>
        {files.length > 0 && <p className="text-sm">フォルダ内のファイルを {files.length} 件選択済み</p>}
        <label id="sbom-input" className="block text-sm font-semibold">SBOM を選択（任意）
          <input ref={sbomInput} type="file" accept=".json,application/json" disabled={busy}
            className="mt-2 block w-full text-sm" onChange={(event) => {
              const file = event.target.files?.[0];
              event.target.value = "";
              setReport(null);
              setResults(null);
              setEnded(null);
              setSbom(file && file.size <= 4 * 1024 * 1024 ? file : null);
              setError(file && file.size > 4 * 1024 * 1024 ? "4 MB以下のCycloneDX／SPDX 2.3 JSONを選んでください。" : "");
            }} />
        </label>
        <p className="text-xs">CycloneDX／SPDX 2.3 JSONをブラウザ内で照合します。対応する識別子のない依存関係、SBOMと実配備の一致、実行時の防御は未確認です。</p>
        {sbom && <p className="text-sm">SBOM を選択済み <button type="button" disabled={busy} className="ml-2 underline"
          onClick={() => { setSbom(null); setReport(null); setResults(null); }}>選択を解除</button></p>}

        <div className="flex flex-wrap gap-2">
          <button type="button" className={primary} disabled={!cacheReady || busy || updating || !selected.size || (!files.length && !sbom)} onClick={() => run("local")}>
            {busy ? "検証中…" : "ローカル検証を開始"}
          </button>
          <button type="button" className={button} disabled={busy || updating || !selected.size} onClick={() => run("demo")}>模擬データで試す</button>
        </div>
        {busy && <button type="button" className={button} onClick={() => {
          running.current?.();
          setBusy(false);
          setEnded("cancelled");
        }}>中断する</button>}
        {(busy || ended) && <p role="status" className="text-sm">
          {ended === "cancelled" ? "検証を中断しました。" : ended === "timeout" ? "検証が制限時間を超えました。" : "検証中。"}
          {progress ? ` 直近の進捗では対象 ${progress.eligible}件のうち ${progress.processed}件まで処理。未処理 ${progress.eligible - progress.processed}件。` : " 対象件数の確定前です。"}
        </p>}
        {ended && progress && progress.pendingPaths.length > 0 && <details className="text-sm">
          <summary>直近の進捗で未処理だったファイル（先頭10件）</summary>
          <ul>{progress.pendingPaths.map((path) => <li key={path}><bdi>{path}</bdi></li>)}</ul>
        </details>}
        <details className="text-sm">
          <summary className="cursor-pointer">CVEカタログの更新</summary>
          <div className="flex flex-wrap gap-2">
            <button type="button" className={button} disabled={!cacheReady || busy || updating} onClick={() =>
              updateOfficial(missingCatalogs.length ? missingCatalogs : catalogSources())}>
              {updating ? "取得中…" : "NVD・OSVの公式データを取得"}
            </button>
            {official.sources.length > 0 && missingCatalogs.length > 0 &&
              <button type="button" className={button} disabled={busy || updating} onClick={() => updateOfficial(catalogSources())}>
                保存済みの分も再取得
              </button>}
            {updating && <button type="button" className={button} onClick={() => {
              catalogWorker.current?.terminate();
              catalogWorker.current = null;
              void readCatalogCache().then(setOfficial).catch(() => {}).finally(() => setUpdating(false));
              setUpdateProgress(null);
            }}>取得を中断</button>}
          </div>
          <p>OSVのnpm・PyPI・Go全件と、NVDの2002年版から今年までを順に取得します。初回は大容量です。プロジェクトの情報は送信しません。</p>
          {updateProgress && <p role="status">
            {updateSources.indexOf(updateProgress.source) + 1} / {updateSources.length}：{updateProgress.source}　
            {updateProgress.count ? `索引を作成中。処理済み ${updateProgress.count.toLocaleString()}件。` : "公式データを取得中。"}
          </p>}
          {refreshErrors.length > 0 && <div role="alert" className="space-y-2 text-red-800 dark:text-red-200">
            <p>一部の公式カタログを更新できませんでした。正常な保存済みデータで診断できます。</p>
            <ul className="list-disc pl-5">{refreshErrors.map(({ source, reason }) => <li key={source}>{source} — {reason}</li>)}</ul>
            {!updating && <button type="button" className={button} disabled={busy || !cacheReady}
              onClick={() => {
                const failed = new Set(refreshErrors.map(({ source }) => source));
                const retry = updateSources.filter((source) => failed.has(source));
                updateOfficial(retry.length ? retry : updateSources);
              }}>失敗した更新を再試行</button>}
          </div>}
          {official.sources.length > 0 && <details>
            <summary>提供元・年別の収録件数と取得日時</summary>
            {official.sources.map((entry) => <p key={entry.source}>
              {entry.source} ／ {entry.count.toLocaleString()}件 ／ 索引 {entry.indexed.toLocaleString()}件 ／ 取得 {new Date(entry.fetchedAt).toLocaleString()}
              {entry.publishedAt && ` ／ 提供元更新 ${new Date(entry.publishedAt).toLocaleString()}`}
            </p>)}
          </details>}
          <label className="block">NVD・OSVのJSONを手動で読み込む
            <input type="file" accept=".json" disabled={busy || updating} className="mt-1 block w-full" onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void importFeed(file);
              event.target.value = "";
            }} />
          </label>
        </details>
        <div className="space-y-1 text-xs text-zinc-500" aria-label="ローカルで使用するCVEカタログ">
          {!!official.sources.length && <p>保存済み {official.sources.reduce((sum, source) => sum + source.indexed, 0).toLocaleString()}件（索引対象）。最終更新 {new Date(Math.max(...official.sources.map(({ fetchedAt }) => Date.parse(fetchedAt)))).toLocaleString()}。</p>}
          <p>{feedLabels.nvd}</p>
          <p>{feedLabels.osv}</p>
          <p>公式アーカイブ {official.sources.length}/{catalogSources().length}件を保存済み。
            {missingCatalogs.length > 0 && ` 未取得 ${missingCatalogs.length}件（${missingCatalogs.slice(0, 3).join("・")}${missingCatalogs.length > 3 ? " ほか" : ""}）。取得するまで、依存関係のCVE照合は同梱サンプルだけで行い、結果は「未確認」になります。上の更新欄から取得できます。`}</p>
          <p>索引にない勧告や未対応の製品・版は未確認です。</p>
        </div>
        {error && <p role="alert" className="text-sm text-red-700 dark:text-red-300">{error}</p>}
      </section>
      {signedIn ? <ReviewedDefense files={files} />
        : <p className="text-sm text-zinc-600 dark:text-zinc-400">
          隔離環境でのレビュー済み防御テストと、サイト・APIの診断は<Link className="underline" href="/login">ログイン</Link>後に使えます。
        </p>}
      {visible && mode === "local" && <DefenseOverview rows={visible} files={files} signedIn={signedIn} />}
      {visible && <section className="space-y-3" aria-label="検証結果">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-lg font-semibold">{mode === "demo" ? "模擬データの結果" : "ローカル入力の結果"}</h2>
          {mode === "local" && <button type="button" className={button} disabled={busy || updating}
            onClick={() => (files.length ? folderInput : sbomInput).current?.click()}>{files.length ? "修正後のフォルダを選ぶ" : "更新したSBOMを選ぶ"}</button>}
        </div>
        <p role="status" className="text-sm">{Object.keys(labels).map((key) =>
          `${statusLabel(key as keyof typeof labels)} ${visible.filter((row) => row.status === key).length}件`).join(" ・ ")}
          {visible.some((row) => row.testCode) && `（うちテスト用コード ${visible.filter((row) => row.testCode).length}件。一覧の後ろに分けて表示）`}</p>
        <StatusBar rows={visible} label={statusLabel} active={statusFilter}
          onSelect={(key) => { setStatusFilter(key === statusFilter ? null : key); setDisplay(100); }} />
        {report && <p className="text-sm">
          {report.scanProgress.batches}バッチで処理。
          {report.read}ファイルの読取を試行。対象外 {report.skipped}件 ／ ファイル上限 {report.omitted}件 ／
          一部の検査を適用できなかったファイル {report.unsupported}件 ／ 読取失敗 {report.unreadable}件 ／ 解析上限 {report.skippedRules}か所 ／ 未処理 {report.pending}件 ／ 保存上限による未表示 {report.unretained}件。
          言語 {report.languages.join("・") || "不明"} ／ フレームワーク {report.frameworks.join("・") || "不明"} ／ ロック形式 {report.lockKinds}種 ／ 照合対象の固定依存関係 {report.packageCount}件。
        </p>}
        {report && <ul className="list-inside list-disc space-y-1 text-sm" aria-label="検査の内訳">
          <li>データフローを解析したJavaScript・TypeScript {report.coverage.source - (report.coverage.pythonFlow ?? 0)}件、Python（同じ関数内） {report.coverage.pythonFlow ?? 0}件。共通検査のみのソース {report.coverage.noSourceRules}件。</li>
          <li>固定版を照合した依存資料 {report.coverage.packageFiles}件。固定版不明のPython依存指定 {report.coverage.unresolvedDependencies}行。構文・記法で読むことができなかった設定 {report.coverage.parseFailed}件。</li>
          <li>今回の照合候補はOSV {report.coverage.osvAdvisories}件、NVD {report.coverage.nvdAdvisories}件。カタログ全体の収録件数は上の取得状況で確認できます。</li>
        </ul>}
        {report && report.incomplete.length > 0 && <details className="text-sm">
          <summary>検査が完了しなかったファイル（最大100件）</summary>
          <ul>{report.incomplete.map(({ path, reason }) => <li key={path}><bdi>{path}</bdi> ／ {reason}</li>)}</ul>
        </details>}
        <p className="text-sm">ファイルをまたぐソース解析は対象外です。</p>
        {report?.catalogIncomplete && <p role="alert">公式カタログを最後まで照合できませんでした。照合上限・時間上限または保存領域を確認してください。</p>}
        <p className="text-sm">{mode === "local" ? "設定を確認した項目の実行時の防御は未確認です。各項目の再検証方法を確認してください。" : "この結果は模擬入力に基づきます。"}</p>
        {mode === "local" && <a href="#runtime-defense" className="text-sm underline">実行時の防御確認へ</a>}
        {mode === "local" && <a href="#a2b-defense" className="ml-3 text-sm underline">A2B防御の状況へ</a>}
        {dependencyGroups.length > 0 && <details className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
          <summary className="cursor-pointer font-semibold">依存関係ごとの修正（{dependencyGroups.length}組）</summary>
          <p className="my-2 text-sm">勧告ごとの修正版候補です。すべての勧告に対応する導入可能な版を選び、ロックファイルを更新して再検証してください。</p>
          <ul className="space-y-2">
            {dependencyGroups.slice(0, display).map(({ name, version, ecosystem, severity, advisories, reachable }) => <li key={JSON.stringify([ecosystem, name, version])}>
              <details className="rounded border border-zinc-200 p-2 text-sm dark:border-zinc-800">
                <summary className="cursor-pointer break-all"><bdi>{name} {version}</bdi>{ecosystem && `（${ecosystem}）`} ／ {advisories.length}件 ／ {severity ? advisorySeverityLabels[severity] : "重大度不明"}
                  {" ／ "}<span className={reachable === "imported" ? "text-red-700 dark:text-red-300" : "text-zinc-500"}>
                    {reachable === "imported" ? "コードで使用（版一致・影響は未実証）" : reachable === "not_imported_directly"
                      ? "直接のimportなし（間接利用は未確認）" : "使用箇所は未確認"}</span></summary>
                <ul className="mt-2 list-inside list-disc space-y-2">
                  {advisories.map((entry) => <li key={entry.id}>
                    {entry.id} ／ {entry.fixed.length ? `修正版候補 ${entry.fixed.join("・")}` : "修正版は勧告を確認"}
                    <div className="break-all text-xs text-zinc-600 dark:text-zinc-300">
                      {entry.locations[0] && <><bdi>{entry.locations[0].path}</bdi>{entry.locations[0].line ? `:${entry.locations[0].line}` : ""}</>}
                      {entry.locations.length > 1 && ` ほか ${entry.locations.length - 1}か所（下の個別結果に表示）`}
                    </div>
                  </li>)}
                </ul>
              </details>
            </li>)}
          </ul>
        </details>}
        <p className="text-sm">個別結果は勧告の重大度順です（Critical → High → Medium → Low → 重大度不明）。対象サービスでの実際の影響は未確認です。</p>
        {shown.slice(0, display).map((row, index) => <details key={index} className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
          <summary className="cursor-pointer font-medium">{row.testCode && <span className="mr-1 rounded bg-zinc-100 px-1.5 py-0.5 text-xs font-normal text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300">テスト用コード</span>}{categoryLabels[row.category as keyof typeof categoryLabels] ?? row.category} ／ {row.title} ／ {statusLabel(row.status)}{row.severity && ` ／ 勧告の重大度 ${advisorySeverityLabels[row.severity]}`}</summary>
          <dl className="mt-2 space-y-1 break-words text-sm">
            {(row.locations?.length || row.location) && <><dt className="font-semibold">修正箇所</dt>
              {(row.locations ?? (row.location ? [row.location] : [])).map((location, i) => <dd key={i} className="font-mono">
                <span><bdi>{location.path}</bdi>{location.line ? `:${location.line}` : "（行番号不明）"}</span>
                {location.dependency && <span> ／ <bdi>{location.dependency} {location.version}</bdi></span>}
                {!!location.fixed?.length && <span> ／ 勧告の修正版 {location.fixed.join("・")}</span>}
              </dd>)}</>}
            <dt className="font-semibold">重大度</dt><dd>{row.severity
              ? `${advisorySeverityLabels[row.severity]}（勧告の評価。対象サービスでの影響は未確認）`
              : "重大度不明。危険性と実際の利用条件を確認してください。"}</dd>
            <dt className="font-semibold">原因・根拠</dt><dd>{row.evidence}</dd>
            <dt className="font-semibold">危険性</dt><dd>{row.risk}</dd>
            <dt className="font-semibold">修正方法</dt><dd>{row.fix}</dd>
            <dt className="font-semibold">再検証方法</dt><dd>{row.retest}</dd>
          </dl>
          {row.patch && <PatchView patch={row.patch} />}
        </details>)}
        {Math.max(shown.length, dependencyGroups.length) > display && <button type="button" className={button} onClick={() => setDisplay(display + 100)}>
          さらに表示（{Math.max(shown.length, dependencyGroups.length) - display}件）
        </button>}
        {mode === "local" && <>
          <RuntimeDefense plan={report?.runtimePlan ?? []} staticResults={visible} project={files[0]?.webkitRelativePath.split("/")[0] || "選択したフォルダ"} />
          <p className="text-sm">修正後は上のフォルダ選択から選び直して再検証してください。</p>
        </>}
      </section>}
      <Link href="/assets" prefetch={false} className="text-sm underline">所有確認済みWebサイト・APIと隔離ラボへ</Link>
    </main>
  );
}

const SEGMENT: Record<keyof typeof labels, string> = {
  action: "bg-red-500", unknown: "bg-amber-400", confirmed: "bg-emerald-500", na: "bg-zinc-300 dark:bg-zinc-600",
};

/** The result counts as one bar; a segment or its legend filters the list below to that status. */
function StatusBar({ rows, label, active, onSelect }: {
  rows: { status: keyof typeof labels }[]; label: (key: keyof typeof labels) => string;
  active: keyof typeof labels | null; onSelect: (key: keyof typeof labels) => void;
}) {
  const keys = (["action", "unknown", "confirmed", "na"] as const).filter((key) => rows.some((row) => row.status === key));
  if (!rows.length) return null;
  const count = (key: keyof typeof labels) => rows.filter((row) => row.status === key).length;
  return <div className="space-y-2">
    <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800" aria-hidden="true">
      {keys.map((key) => <button key={key} type="button" tabIndex={-1} onClick={() => onSelect(key)}
        style={{ width: `${(100 * count(key)) / rows.length}%` }}
        className={`${SEGMENT[key]} h-full transition-[width,opacity] duration-300 ease-out ${active && active !== key ? "opacity-30" : ""}`} />)}
    </div>
    <div className="flex flex-wrap gap-2" role="group" aria-label="状態で絞り込む">
      {keys.map((key) => <button key={key} type="button" aria-pressed={active === key} onClick={() => onSelect(key)}
        className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs transition-colors ${active === key
          ? "border-zinc-900 bg-zinc-900 text-white dark:border-white dark:bg-white dark:text-zinc-900"
          : "border-zinc-200 hover:border-zinc-400 dark:border-zinc-700"}`}>
        <span className={`h-2 w-2 rounded-full ${SEGMENT[key]}`} />{label(key)} {count(key)}件
      </button>)}
      {active && <button type="button" onClick={() => onSelect(active)} className="text-xs underline">すべて表示</button>}
    </div>
  </div>;
}

/** A minimal fix as a diff. Vulnix never writes the project: the user copies or saves it. */
function PatchView({ patch }: { patch: FixCandidate }) {
  const [copied, setCopied] = useState(false);
  const save = () => {
    const url = URL.createObjectURL(new Blob([patch.diff], { type: "text/x-diff" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `${patch.file.split("/").pop() || "fix"}.vulnix.patch`;
    a.click();
    URL.revokeObjectURL(url);
  };
  return <div className="mt-3 space-y-2 rounded-lg border border-emerald-200 bg-emerald-50/60 p-3 text-sm dark:border-emerald-900 dark:bg-emerald-950/30">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div>
        <p className="font-semibold">修正案（{patch.changedLines}行の差分）</p>
        <p className="font-mono text-xs text-zinc-600 dark:text-zinc-400">{patch.file}:{patch.line}</p>
      </div>
      <div className="flex gap-2">
        <button type="button" className="rounded-md border border-zinc-300 bg-white px-2.5 py-1 text-xs transition-colors hover:border-zinc-500 dark:border-zinc-700 dark:bg-zinc-900"
          onClick={() => { void navigator.clipboard?.writeText(patch.diff).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1500); }); }}>
          {copied ? "コピーしました" : "差分をコピー"}</button>
        <button type="button" className="rounded-md border border-zinc-300 bg-white px-2.5 py-1 text-xs transition-colors hover:border-zinc-500 dark:border-zinc-700 dark:bg-zinc-900"
          onClick={save}>パッチを保存</button>
      </div>
    </div>
    <pre className="max-h-72 overflow-auto rounded-md bg-white p-2 font-mono text-xs leading-5 dark:bg-zinc-900">{patch.diff.split("\n").map((line, i) =>
      <span key={i} className={line.startsWith("+") && !line.startsWith("+++") ? "block bg-emerald-100 dark:bg-emerald-900/40"
        : line.startsWith("-") && !line.startsWith("---") ? "block bg-red-100 dark:bg-red-900/40" : "block"}>{line || " "}</span>)}</pre>
    {patch.reason && <p className="text-xs"><span className="text-zinc-500">変更理由 </span>{patch.reason}</p>}
    <ul className="space-y-1 text-xs" aria-label="この修正案の検証状態">
      <li className="flex items-start gap-2"><span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${patch.sampleVerified ? "bg-emerald-500" : "border border-amber-500"}`} />
        <span><span className="text-zinc-500">サンプルアプリ </span>{patch.sampleVerified
          ? "同じ修正方式で、本物の Flask 上で攻撃が止まり正常な動作が保たれることを確認済み"
          : "未確認"}</span></li>
      <li className="flex items-start gap-2"><span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${patch.projectRecheck === "cleared" ? "bg-emerald-500" : "bg-red-500"}`} />
        <span><span className="text-zinc-500">このプロジェクト（静的） </span>{patch.projectRecheck === "cleared"
          ? "修正後のコードを再解析し、同じ経路は検出されなくなった"
          : "修正後のコードでも同じ経路が残る。手作業での修正が必要"}</span></li>
      <li className="flex items-start gap-2"><span className="mt-1 h-2 w-2 shrink-0 rounded-full border border-amber-500" />
        <span><span className="text-zinc-500">このプロジェクト（実行時） </span>未確認。適用して動作を確かめてから、「修正後のフォルダを選ぶ」で再検査してください</span></li>
    </ul>
    <p className="text-xs text-zinc-600 dark:text-zinc-400">差分はファイル単位です（同じファイルにある他の項目の修正も含みます）。元のフォルダは変更していません。</p>
  </div>;
}
