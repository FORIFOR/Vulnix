"use client";

import Link from "next/link";
import { useState } from "react";
import { categories, checkCloudFormation, checkControls, checkCves, checkLockfile, checkSource, demoEvidence, labels, record } from "@/lib/quickDefense";

const button = "rounded-lg border border-zinc-300 px-3 py-2 text-sm font-medium dark:border-zinc-700";
const primary = "rounded-lg bg-zinc-900 px-3 py-2 text-sm font-semibold text-white disabled:opacity-50 dark:bg-white dark:text-zinc-900";
const template = JSON.stringify(demoEvidence, null, 2);
const maxInput = 2 * 1024 * 1024;

export default function QuickDefense({ bundledFeed }: { bundledFeed: unknown }) {
  const [selected, setSelected] = useState(new Set<string>(categories));
  const [input, setInput] = useState("");
  const [source, setSource] = useState("");
  const [lockfile, setLockfile] = useState<{ data: unknown } | null>(null);
  const [feed, setFeed] = useState<unknown>(bundledFeed);
  const [feedLabel, setFeedLabel] = useState("同梱のサンプル");
  const [mode, setMode] = useState<"local" | "demo">("local");
  const [results, setResults] = useState<ReturnType<typeof checkControls> | null>(null);
  const [error, setError] = useState("");

  async function readFile(file: File, kind: "source" | "feed" | "evidence" | "lockfile") {
    setError("");
    try {
      if (file.size > maxInput) throw new Error("ファイルは2 MBまでです。");
      const raw = await file.text();
      if (kind === "source") setSource(raw);
      if (kind === "lockfile") setLockfile({ data: JSON.parse(raw) });
      if (kind === "evidence") setInput(raw);
      if (kind === "feed") {
        const parsed = record(JSON.parse(raw));
        if (parsed.format !== "NVD_CVE" || parsed.version !== "2.0" ||
          !Array.isArray(parsed.vulnerabilities) || !parsed.vulnerabilities.length) {
          throw new Error("CVEを含むNVD CVE API 2.0形式のJSONを選んでください。");
        }
        setFeed(parsed);
        setFeedLabel(file.name);
      }
      setResults(null);
    } catch (err) {
      setError(err instanceof SyntaxError ? "JSONの形式を確認してください。" : (err as Error).message);
    }
  }

  function run(kind: "local" | "demo") {
    setResults(null);
    setError("");
    try {
      const data = kind === "demo" ? demoEvidence : record(input.trim() ? JSON.parse(input) : {});
      const rows = checkControls(data.controls);
      if (kind === "local") rows.push(...checkCloudFormation(data));
      rows.push(...checkCves(data.components, kind === "demo" ? bundledFeed : feed));
      if (kind === "local" && source) rows.push(checkSource(source));
      if (kind === "local" && lockfile) rows.push(checkLockfile(lockfile.data));
      setMode(kind);
      setResults(rows.filter((row) => selected.has(row.category)));
    } catch {
      setError("設定・依存関係のJSON形式を確認してください。");
    }
  }

  return (
    <main className="mx-auto max-w-3xl space-y-5 p-4 md:p-8">
      <h1 className="text-2xl font-bold">ローカルプロジェクトの診断</h1>
      <p className="text-sm text-zinc-600 dark:text-zinc-300">選んだファイルと入力はブラウザ内で読み取ります。設定の確認結果や導入済みバージョンを入力してください。</p>
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
        <h2 className="font-semibold">プロジェクトの情報</h2>
        <label className="block text-sm">設定・依存関係の証拠JSON
          <input type="file" accept=".json" className="mt-1 block w-full" onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) void readFile(file, "evidence");
            event.target.value = "";
          }} />
        </label>
        <label className="block text-sm">証拠JSONを編集
          <textarea value={input} maxLength={maxInput} rows={5} onChange={(event) => {
            setInput(event.target.value);
            setResults(null);
          }} className="mt-1 w-full rounded border border-zinc-300 p-2 font-mono dark:border-zinc-700" />
        </label>
        <label className="block text-sm">JavaScript / JSXソース（任意）
          <input type="file" accept=".js,.jsx,.ts,.tsx,.mjs" className="mt-1 block w-full" onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) void readFile(file, "source");
            event.target.value = "";
          }} />
        </label>
        {source && <button type="button" className={button} onClick={() => { setSource(""); setResults(null); }}>選択したソースを外す</button>}
        <label className="block text-sm">package-lock.json（任意）
          <input type="file" accept=".json" className="mt-1 block w-full" onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) void readFile(file, "lockfile");
            event.target.value = "";
          }} />
        </label>
        {lockfile && <button type="button" className={button} onClick={() => { setLockfile(null); setResults(null); }}>選択したロックファイルを外す</button>}
        <div className="flex flex-wrap gap-2">
          <button type="button" className={primary} disabled={!selected.size || !(input.trim() || source || lockfile)} onClick={() => run("local")}>ローカル検証を開始</button>
          <button type="button" className={button} disabled={!selected.size} onClick={() => run("demo")}>模擬データで試す</button>
        </div>
        <details className="text-sm">
          <summary className="cursor-pointer">入力形式とCVEカタログの更新</summary>
          <p className="mt-2">ソースや設定の確認箇所、テスト名、導入版を記入します。秘密値は省いてください。CVEごとの影響条件と修正状況は reviews に記録します。CloudFormation JSONを選ぶと、EC2起動テンプレートのメタデータ設定を確認できます。</p>
          <pre className="my-2 max-h-48 overflow-auto rounded bg-zinc-100 p-2 text-xs dark:bg-zinc-900">{template}</pre>
          <label className="block">NVD JSONを手動で読み込む
            <input type="file" accept=".json" className="mt-1 block w-full" onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void readFile(file, "feed");
              event.target.value = "";
            }} />
          </label>
        </details>
        <p className="text-xs text-zinc-500">ローカルで使用するCVEカタログ　{feedLabel}</p>
        {error && <p role="alert" className="text-sm text-red-700 dark:text-red-300">{error}</p>}
      </section>
      {results && <section className="space-y-3" aria-label="検証結果">
        <h2 className="text-lg font-semibold">{mode === "demo" ? "模擬データの結果" : "ローカル入力の結果"}</h2>
        <p role="status" className="text-sm">{Object.entries(labels).map(([key, label]) =>
          `${label} ${results.filter((row) => row.status === key).length}件`).join(" ・ ")}</p>
        <p className="text-sm">防御確認済みは入力された根拠の範囲に限ります。</p>
        {results.map((row, index) => <details key={index} className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
          <summary className="cursor-pointer font-medium">{row.category} ／ {row.title} ／ {labels[row.status]}</summary>
          <dl className="mt-2 space-y-1 break-words text-sm">
            <dt className="font-semibold">根拠</dt><dd>{row.evidence}</dd>
            <dt className="font-semibold">危険性</dt><dd>{row.risk}</dd>
            <dt className="font-semibold">修正方法</dt><dd>{row.fix}</dd>
            <dt className="font-semibold">再検証方法</dt><dd>{row.retest}</dd>
          </dl>
        </details>)}
        {mode === "local" && <button type="button" className={primary} onClick={() => run("local")}>同じ入力で再検証</button>}
      </section>}
      <Link href="/assets" className="text-sm underline">所有確認済みWebサイト・APIと隔離ラボへ</Link>
    </main>
  );
}
