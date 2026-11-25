"use client";

import { useRef, useState } from "react";
import Link from "next/link";
import type { PlannedCheck } from "@/lib/runtimePlan";
import { evidenceLabels, readJUnitReport, runtimeChecks, scopes, validCommit, validDeployment, type EvidenceKind, type JUnitReport, type RuntimeCheck, type Verdict } from "@/lib/runtimeDefense";

const field = "block rounded border border-zinc-300 bg-transparent px-2 py-1 dark:border-zinc-600";
const button = "rounded border border-zinc-300 px-2 py-1 disabled:opacity-50 dark:border-zinc-600";

function CheckRow({ check, plan, report, verdict, setVerdict }: {
  check: RuntimeCheck; plan?: PlannedCheck; report: JUnitReport | null; verdict?: Verdict; setVerdict: (value?: Verdict) => void;
}) {
  const [, name, condition, settings] = check;
  const [kind, setKind] = useState<EvidenceKind | "">("");
  const [cases, setCases] = useState<number[]>([]);
  const [scope, setScope] = useState("");
  const [note, setNote] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [commit, setCommit] = useState("");
  const [deployment, setDeployment] = useState("");
  const tests = report?.tests ?? [];
  const mismatch = report && ((report.commit && commit && report.commit !== commit.toLowerCase()) ||
    (report.deployment && deployment && report.deployment !== deployment) || (report.scope && scope && report.scope !== scope));
  const identified = validCommit(commit) && (scope === "許可済みSTG" || report?.deployment ? validDeployment(deployment) :
    !deployment || validDeployment(deployment));
  const canSave = kind && scope && confirmed &&
    (kind === "runtime" ? !mismatch && identified && cases.length > 0 && cases.every((id) => tests[id - 1]) : kind === "settings" || note.trim().length >= 8);

  return <details className="rounded border border-zinc-200 p-2 dark:border-zinc-800">
    <summary className="cursor-pointer">{name} ／ {verdict ? evidenceLabels[verdict.kind] : "未確認"}</summary>
    <div className="mt-2 space-y-2">
      <p>合格条件　{condition}</p>
      <p>読み取り専用の設定確認　{settings}</p>
      {plan?.locations.length ? <p>対象候補の根拠　{plan.locations.map((path, i) => <span key={path}>{i > 0 && "、"}<bdi>{path}</bdi></span>)}</p> : null}
      {plan?.candidates.length ? <ul className="list-inside list-disc">
        {plan.candidates.map((candidate) => <li key={`${candidate.path}:${candidate.line}`}>
          <bdi>{candidate.path}</bdi>:{candidate.line} ／ {candidate.permits && "許可側の確認候補"}{candidate.permits && candidate.denies && "・"}{candidate.denies && "拒否側の確認候補"}
        </li>)}
      </ul> : null}
      {verdict && <div role="status">
        <p>利用者確認 ／ {verdict.scope} ／ {verdict.detail}</p>
        {verdict.identity && <dl className="break-all">
          <dt>対象コミット</dt><dd>{verdict.identity.commit}</dd>
          <dt>配備版</dt><dd>{verdict.identity.deployment || "配備なし"}</dd>
          <dt>報告書 SHA-256</dt><dd>{verdict.identity.digest}</dd>
        </dl>}
      </div>}
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
        {kind === "runtime" && <>
          <label className="block">対象コミットSHA
            <input className={field} maxLength={64} value={commit} onChange={(event) => {
              setCommit(event.target.value.trim()); setConfirmed(false);
            }} />
          </label>
          <label className="block">配備版（STGでは必須）
            <input className={field} maxLength={128} value={deployment} onChange={(event) => {
              setDeployment(event.target.value.trim()); setConfirmed(false);
            }} />
          </label>
          {mismatch && <p role="alert">報告書の版または環境が入力した対象と一致しません。</p>}
          <label className="block">該当するテスト
          <select className={field} multiple size={4} value={cases.map(String)} onChange={(event) => {
            setCases(Array.from(event.target.selectedOptions, (option) => Number(option.value))); setConfirmed(false);
          }}>
            {tests.map((passed, i) => <option key={i} value={i + 1} disabled={!passed}>報告書のテスト {i + 1} ／ {passed ? "成功" : "成功を確認できない"}</option>)}
          </select>
          <span>元の報告書と同じ順番です。合格条件に必要なケースを選びます。失敗・エラー・スキップは選べません。</span>
        </label></>}
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
          setVerdict({ kind, scope, detail, identity: kind === "runtime" && report
            ? { commit: commit.toLowerCase(), deployment, digest: report.digest } : undefined });
          setConfirmed(false);
        }}>記録する</button>
      </>}
      {verdict && <button type="button" className={`${button} ml-2`} onClick={() => setVerdict()}>未確認に戻す</button>}
    </div>
  </details>;
}

export default function RuntimeDefense({ project, plan }: { project: string; plan: PlannedCheck[] }) {
  const [report, setReport] = useState<JUnitReport | null>(null);
  const tests = report?.tests ?? [];
  const [verdicts, setVerdicts] = useState<Partial<Record<RuntimeCheck[0], Verdict>>>({});
  const [error, setError] = useState("");
  const [reading, setReading] = useState(false);
  const [revision, setRevision] = useState(0);
  const request = useRef(0);

  async function load(file: File) {
    const id = ++request.current;
    setError(""); setReport(null); setReading(true); setRevision(id);
    setVerdicts((current) => Object.fromEntries(Object.entries(current).filter(([, verdict]) => verdict.kind !== "runtime")));
    try {
      const report = await readJUnitReport(file);
      if (request.current === id) setReport(report);
    } catch {
      if (request.current === id) setError("JUnit XMLを読み込めません。2 MiB以下のテスト結果を選んでください。");
    } finally {
      if (request.current === id) setReading(false);
    }
  }

  const orderedChecks = [...runtimeChecks].sort((a, b) =>
    Number(plan.some((row) => row.id === b[0])) - Number(plan.some((row) => row.id === a[0])));
  return <section id="runtime-defense" aria-label="実行時の防御確認" className="space-y-3 rounded-xl border border-zinc-200 p-4 text-sm dark:border-zinc-800">
    <h3 className="text-lg font-semibold">実行時の防御確認</h3>
    <p>対象　<bdi>{project}</bdi></p>
    <p>対象の既存テストで出力したJUnit XMLを読み込み、合格条件に対応するケースを選びます。テストの出力やファイルは送信されません。設定は許可された管理画面で読み取り専用で確認できます。</p>
    <p>資料から検証候補を {plan.length} 件選びました。候補は内容の確認に使い、テスト名や成功結果で動作を確定しません。</p>
    <details className="rounded border border-zinc-200 p-2 dark:border-zinc-800">
      <summary className="cursor-pointer">レビュー済みローカルテストを実行する</summary>
      <p>対応するのはVulnixのMFAテストです。LimaのLinuxゲストで先に実行計画を表示し、対象ファイル、合格条件、制限を確認します。</p>
      <pre className="overflow-x-auto"><code>python3 -m aegis.local_defense .</code></pre>
      <p>表示された計画SHA-256を承認して実行し、結果をこの画面に読み込みます。</p>
      <pre className="overflow-x-auto"><code>{"python3 -m aegis.local_defense . --approve <計画SHA-256> --junit > /tmp/vulnix-defense.xml"}</code></pre>
      <p>読み込んだファイルの出所は、利用者が確認します。</p>
    </details>
    <Link href="/settings#control-verification" className="underline" prefetch={false}>Vulnix自身の隔離・実行制御を確認する</Link>
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
    {orderedChecks.map((check) => <CheckRow key={`${revision}-${check[0]}`} check={check} plan={plan.find((item) => item.id === check[0])} report={report} verdict={verdicts[check[0]]}
      setVerdict={(verdict) => setVerdicts((current) => {
        const next = { ...current };
        if (verdict) next[check[0]] = verdict;
        else delete next[check[0]];
        return next;
      })} />)}
  </section>;
}
