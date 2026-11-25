"use client";

import { useRef, useState } from "react";
import { evidenceLabels, readJUnitReport, runtimeChecks, scopes, type EvidenceKind, type RuntimeCheck, type Verdict } from "@/lib/runtimeDefense";

const field = "block rounded border border-zinc-300 bg-transparent px-2 py-1 dark:border-zinc-600";
const button = "rounded border border-zinc-300 px-2 py-1 disabled:opacity-50 dark:border-zinc-600";

function CheckRow({ check, tests, verdict, setVerdict }: {
  check: RuntimeCheck; tests: boolean[]; verdict?: Verdict; setVerdict: (value?: Verdict) => void;
}) {
  const [, name, condition, settings] = check;
  const [kind, setKind] = useState<EvidenceKind | "">("");
  const [cases, setCases] = useState<number[]>([]);
  const [scope, setScope] = useState("");
  const [note, setNote] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const canSave = kind && scope && confirmed &&
    (kind === "runtime" ? cases.length > 0 && cases.every((id) => tests[id - 1]) : kind === "settings" || note.trim().length >= 8);

  return <details className="rounded border border-zinc-200 p-2 dark:border-zinc-800">
    <summary className="cursor-pointer">{name} ／ {verdict ? evidenceLabels[verdict.kind] : "未確認"}</summary>
    <div className="mt-2 space-y-2">
      <p>合格条件　{condition}</p>
      <p>読み取り専用の設定確認　{settings}</p>
      {verdict && <p role="status">{verdict.scope} ／ {verdict.detail}</p>}
      <label className="block">確認の種類
        <select className={field} value={kind} onChange={(event) => {
          setKind(event.target.value as EvidenceKind | ""); setCases([]); setScope(""); setNote(""); setConfirmed(false);
        }}>
          <option value="">選択してください</option>
          {Object.entries(evidenceLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
      </label>
      {kind && <>
        <label className="block">確認した環境
          <select className={field} value={scope} onChange={(event) => { setScope(event.target.value); setConfirmed(false); }}>
            <option value="">選択してください</option>
            {scopes.map((environment) => <option key={environment}>{environment}</option>)}
          </select>
        </label>
        {kind === "runtime" && <label className="block">該当するテスト
          <select className={field} multiple size={4} value={cases.map(String)} onChange={(event) => {
            setCases(Array.from(event.target.selectedOptions, (option) => Number(option.value))); setConfirmed(false);
          }}>
            {tests.map((passed, i) => <option key={i} value={i + 1} disabled={!passed}>報告書のテスト {i + 1} ／ {passed ? "成功" : "成功を確認できない"}</option>)}
          </select>
          <span>元の報告書と同じ順番です。合格条件に必要なケースを選びます。失敗・エラー・スキップは選べません。</span>
        </label>}
        {(kind === "action" || kind === "na") && <label className="block">根拠（秘密値や個人情報を含めない）
          <textarea className={`${field} w-full`} maxLength={240} rows={2} value={note}
            placeholder={kind === "na" ? "確認した構成資料と、利用していないことを示す記述" : "実際に観測した条件と結果"}
            onChange={(event) => { setNote(event.target.value); setConfirmed(false); }} />
        </label>}
        <label className="flex gap-2"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
          {kind === "runtime" ? "選択した対象・版と合格条件に対応する結果です" : "選択した対象・版で自分が確認した根拠です"}
        </label>
        <button className={button} type="button" disabled={!canSave} onClick={() => {
          if (!canSave) return;
          const detail = kind === "runtime" ? `利用者が対応付けたJUnitテスト ${cases.join("・")}` :
            kind === "settings" ? `利用者が読み取り専用で確認。${settings}` : note.trim();
          setVerdict({ kind, scope, detail });
          setConfirmed(false);
        }}>記録する</button>
      </>}
      {verdict && <button type="button" className={`${button} ml-2`} onClick={() => setVerdict()}>未確認に戻す</button>}
    </div>
  </details>;
}

export default function RuntimeDefense({ project }: { project: string }) {
  const [tests, setTests] = useState<boolean[]>([]);
  const [verdicts, setVerdicts] = useState<Partial<Record<RuntimeCheck[0], Verdict>>>({});
  const [error, setError] = useState("");
  const [reading, setReading] = useState(false);
  const [revision, setRevision] = useState(0);
  const request = useRef(0);

  async function load(file: File) {
    const id = ++request.current;
    setError(""); setTests([]); setReading(true); setRevision(id);
    setVerdicts((current) => Object.fromEntries(Object.entries(current).filter(([, verdict]) => verdict.kind !== "runtime")));
    try {
      const report = await readJUnitReport(file);
      if (request.current === id) setTests(report);
    } catch {
      if (request.current === id) setError("JUnit XMLを読み込めません。2 MiB以下のテスト結果を選んでください。");
    } finally {
      if (request.current === id) setReading(false);
    }
  }

  return <section id="runtime-defense" aria-label="実行時の防御確認" className="space-y-3 rounded-xl border border-zinc-200 p-4 text-sm dark:border-zinc-800">
    <h3 className="text-lg font-semibold">実行時の防御確認</h3>
    <p>対象　<bdi>{project}</bdi></p>
    <p>対象の既存テストで出力したJUnit XMLを読み込み、合格条件に対応するケースを選びます。テストの出力やファイルは送信されません。設定は許可された管理画面で読み取り専用で確認できます。</p>
    <p>記録は選択した環境と条件に限られます。再検証時には新しい結果を対応付けてください。項目に該当する技術の利用状況が不明なら未確認のままにします。</p>
    <label className="block">既存テストの結果（JUnit XML）
      <input type="file" accept=".xml,application/xml,text/xml" className="mt-1 block w-full" onChange={(event) => {
        const file = event.target.files?.[0];
        event.target.value = "";
        if (file) void load(file);
      }} />
    </label>
    {error && <p role="alert">{error}</p>}
    {reading && <p role="status">テスト結果を読み込み中</p>}
    {tests.length > 0 && <p role="status">成功 {tests.filter(Boolean).length} ／ 全 {tests.length} テスト</p>}
    {runtimeChecks.map((check) => <CheckRow key={`${revision}-${check[0]}`} check={check} tests={tests} verdict={verdicts[check[0]]}
      setVerdict={(verdict) => setVerdicts((current) => ({ ...current, [check[0]]: verdict }))} />)}
  </section>;
}
