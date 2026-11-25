"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { categories, checkControls, checkCves, demoEvidence, labels, record } from "@/lib/quickDefense";

const button = "rounded-lg border border-zinc-300 px-3 py-2 text-sm font-medium dark:border-zinc-700";
const primary = "rounded-lg bg-zinc-900 px-3 py-2 text-sm font-semibold text-white disabled:opacity-50 dark:bg-white dark:text-zinc-900";
type ProjectReport = Awaited<ReturnType<typeof import("@/lib/projectDefense").scanProject>>;
const maxInput = 2 * 1024 * 1024;

export default function QuickDefense({ bundledFeed }: { bundledFeed: unknown }) {
  const [selected, setSelected] = useState(new Set<string>(categories));
  const [files, setFiles] = useState<File[]>([]);
  const [feed, setFeed] = useState<unknown>(bundledFeed);
  const [feedLabel, setFeedLabel] = useState("同梱NVDサンプル（収録2件、取得日時不明）");
  const [mode, setMode] = useState<"local" | "demo">("local");
  const [report, setReport] = useState<ProjectReport | null>(null);
  const [results, setResults] = useState<ReturnType<typeof checkControls> | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const running = useRef<(() => void) | null>(null);

  useEffect(() => () => running.current?.(), []);

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
      setFeed(nvd ? parsed : osv);
      const count = nvd ? (parsed.vulnerabilities as unknown[]).length : osv.length;
      const origin = nvd ? "選択したNVDデータ（CPE）" : "選択したOSVデータ（npm・PyPI・Go）";
      const timestamp = typeof parsed.timestamp === "string" &&
        /^\d{4}-\d{2}-\d{2}T[\d:.+-]+Z?$/.test(parsed.timestamp) && parsed.timestamp.length < 40
        ? ` ／ 資料の出力日時 ${parsed.timestamp}` : " ／ 取得日時不明";
      setFeedLabel(`${origin} ${count}件 ／ 読込 ${new Date().toLocaleString()}${timestamp}`);
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
        setError("検証が8秒の上限に達しました。対象を小さいフォルダに分けて選んでください。");
      }, 8000);
      running.current = finish;
      worker.onmessage = ({ data }: MessageEvent<{ result?: ProjectReport }>) => {
        finish();
        setBusy(false);
        if (!data.result) {
          setError("検証を完了できませんでした。フォルダを選び直してください。");
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
      worker.postMessage({ files: files.map((file) => ({ file, path: file.webkitRelativePath || file.name })), feed });
    } catch {
      running.current?.();
      setBusy(false);
      setError("このブラウザでは検証を開始できませんでした。");
    }
  }

  const visible = results?.filter((row) => selected.has(row.category));

  return (
    <main className="mx-auto max-w-3xl space-y-5 p-4 md:p-8">
      <h1 className="text-2xl font-bold">ローカルプロジェクトの診断</h1>
      <p className="text-sm text-zinc-600 dark:text-zinc-300">プロジェクトのフォルダを選ぶと、設定・依存関係・関連ソースをブラウザ内で調べます。</p>
      <fieldset className="flex flex-wrap gap-4">
        <legend className="mb-2 font-medium">検証項目</legend>
        {categories.map((category) => <label key={category} className="flex items-center gap-2">
          <input type="checkbox" checked={selected.has(category)} onChange={(event) => {
            const next = new Set(selected);
            if (event.target.checked) next.add(category); else next.delete(category);
            setSelected(next);
            setResults(null);
          }} />{category}対策
        </label>)}
      </fieldset>
      <section className="space-y-3 rounded-xl border border-zinc-200 p-4 dark:border-zinc-800">
        <label className="block text-sm font-semibold">プロジェクトフォルダを選択
          <input type="file" {...{ webkitdirectory: "" }} multiple disabled={busy} className="mt-2 block w-full text-sm" onChange={(event) => {
            const list = event.target.files;
            const tooMany = (list?.length ?? 0) > 12000;
            setFiles(!tooMany && list ? Array.from(list) : []);
            setReport(null);
            setResults(null);
            setError(tooMany ? "ファイルが12,000件を超えています。さらに小さいフォルダを選んでください。" : "");
            event.target.value = "";
          }} />
        </label>
        {files.length > 0 && <p className="text-sm">フォルダ内のファイルを {files.length} 件選択済み</p>}
        <div className="flex flex-wrap gap-2">
          <button type="button" className={primary} disabled={busy || !selected.size || !files.length} onClick={() => run("local")}>
            {busy ? "検証中…" : "ローカル検証を開始"}
          </button>
          <button type="button" className={button} disabled={busy || !selected.size} onClick={() => run("demo")}>模擬データで試す</button>
        </div>
        <details className="text-sm">
          <summary className="cursor-pointer">CVEカタログの更新</summary>
          <label className="block">NVD・OSVのJSONを手動で読み込む
            <input type="file" accept=".json" disabled={busy} className="mt-1 block w-full" onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void importFeed(file);
              event.target.value = "";
            }} />
          </label>
        </details>
        <p className="text-xs text-zinc-500">ローカルで使用するCVEカタログ　{feedLabel}</p>
        {error && <p role="alert" className="text-sm text-red-700 dark:text-red-300">{error}</p>}
      </section>
      {visible && <section className="space-y-3" aria-label="検証結果">
        <h2 className="text-lg font-semibold">{mode === "demo" ? "模擬データの結果" : "ローカル入力の結果"}</h2>
        <p role="status" className="text-sm">{Object.entries(labels).map(([key, label]) =>
          `${label} ${visible.filter((row) => row.status === key).length}件`).join(" ・ ")}</p>
        {report && <p className="text-sm">
          {report.read}ファイルの読取を試行。対象外 {report.skipped}件 ／ ファイル上限 {report.omitted}件 ／
          未対応形式または固定版なし {report.unsupported}件 ／ 読取失敗 {report.unreadable}件 ／ 解析上限 {report.skippedRules}か所。
          言語 {report.languages.join("・") || "不明"} ／ フレームワーク {report.frameworks.join("・") || "不明"} ／ ロック形式 {report.lockKinds}種 ／ 照合対象の固定依存関係 {report.packageCount}件。
        </p>}
        <p className="text-sm">防御確認済みは、確認できたコードや設定の範囲です。実稼働環境は各項目の再検証方法を確認してください。</p>
        {visible.map((row, index) => <details key={index} className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
          <summary className="cursor-pointer font-medium">{row.category} ／ {row.title} ／ {labels[row.status]}</summary>
          <dl className="mt-2 space-y-1 break-words text-sm">
            {row.location && <><dt className="font-semibold">修正箇所</dt><dd className="font-mono">
              <bdi>{row.location.path}</bdi>{row.location.line ? `:${row.location.line}` : "（行番号不明）"}
            </dd></>}
            <dt className="font-semibold">根拠</dt><dd>{row.evidence}</dd>
            <dt className="font-semibold">危険性</dt><dd>{row.risk}</dd>
            <dt className="font-semibold">修正方法</dt><dd>{row.fix}</dd>
            <dt className="font-semibold">再検証方法</dt><dd>{row.retest}</dd>
          </dl>
        </details>)}
        {mode === "local" && <p className="text-sm">修正後は上のフォルダ選択から選び直して再検証してください。</p>}
      </section>}
      <Link href="/assets" prefetch={false} className="text-sm underline">所有確認済みWebサイト・APIと隔離ラボへ</Link>
    </main>
  );
}
