"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { getJSON, postJSON } from "@/lib/api";

type Row = { category: string; status: "confirmed" | "action" | "unknown" | "na"; title: string };
type AgentRow = {
  id: string; label: string; verdict: "blocked" | "breached" | "unverified" | "not_tested";
  blocked_by: "rule" | "approval_required" | null; advice: string | null; secret_reached_model: boolean;
};
type AgentReport = { status: string; reason?: string; scope?: string; cli_version?: string; results?: AgentRow[] };

/** One view of the four defense areas for the selected project, from what was actually measured. */
export default function DefenseOverview({ rows, files, signedIn }: { rows: Row[] | null; files: File[]; signedIn: boolean }) {
  const [agent, setAgent] = useState<AgentReport | null>(null);
  const count = (pred: (r: Row) => boolean) => rows?.filter(pred).length ?? 0;
  const area = (category: string) => ({
    action: count((r) => r.category === category && r.status === "action"),
    confirmed: count((r) => r.category === category && r.status === "confirmed"),
    unknown: count((r) => r.category === category && r.status === "unknown"),
  });
  const agentBreached = agent?.results?.filter((r) => r.verdict === "breached").length ?? 0;
  const agentBlocked = agent?.results?.filter((r) => r.verdict === "blocked" && r.blocked_by === "rule").length ?? 0;
  const agentPending = agent?.results?.filter((r) => r.verdict !== "breached" && !(r.verdict === "blocked" && r.blocked_by === "rule")).length ?? 0;
  const cards = [
    { key: "ARTEX", title: "ARTEX対策", sub: "AIによる攻撃に使われる設定・経路", ...area("ARTEX") },
    { key: "Claude Code", title: "Claude Code対策", sub: "秘密情報・操作権限・通信制御",
      action: area("Claude Code").action + agentBreached, confirmed: area("Claude Code").confirmed + agentBlocked,
      unknown: area("Claude Code").unknown + agentPending },
    { key: "CVE", title: "最新CVE", sub: "依存関係・影響条件・修正版", ...area("CVE") },
  ];
  const total = cards.reduce((n, c) => ({ action: n.action + c.action, confirmed: n.confirmed + c.confirmed,
    unknown: n.unknown + c.unknown }), { action: 0, confirmed: 0, unknown: 0 });
  if (!rows) return null;
  return (
    <section aria-label="防御評価の全体像" className="space-y-3">
      <div className="grid grid-cols-3 gap-2 text-center">
        {([["対策が必要", total.action, "text-red-600"], ["確認済み", total.confirmed, "text-emerald-600"],
           ["未確認", total.unknown, "text-amber-600"]] as const).map(([label, n, cls]) =>
          <div key={label} className="rounded-xl border border-zinc-200 bg-white p-3 dark:border-zinc-800 dark:bg-zinc-900">
            <p className="text-xs text-zinc-500">{label}</p>
            <p className={`text-2xl font-semibold tabular-nums transition-all ${cls}`}>{n}</p>
          </div>)}
      </div>
      <div className="grid gap-2 sm:grid-cols-2">
        {cards.map((c) =>
          <div key={c.key} className="rounded-xl border border-zinc-200 bg-white p-3 transition-shadow hover:shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
            <p className="font-semibold">{c.title}</p>
            <p className="text-xs text-zinc-500">{c.sub}</p>
            <p className="mt-2 text-xs">対策が必要 {c.action} ・ 確認済み {c.confirmed} ・ 未確認 {c.unknown}</p>
          </div>)}
        <div className="rounded-xl border border-dashed border-zinc-300 bg-white p-3 dark:border-zinc-700 dark:bg-zinc-900">
          <p className="font-semibold">A2B対策</p>
          <p className="text-xs text-zinc-500">API認証・認可・組織分離</p>
          <p className="mt-2 text-xs">フォルダ診断では実行しません。所有確認したサイトまたは検証ラボのAPIに対し、
            テスト用アカウントで確認します。{signedIn ? <Link className="underline" href="/assets">サイト・APIの診断へ</Link> : "ログイン後に使えます。"}</p>
        </div>
      </div>
      <AgentDefensePanel files={files} signedIn={signedIn} report={agent} onReport={setAgent} />
    </section>
  );
}

const VERDICT = {
  breached: ["突破", "bg-red-100 text-red-800 dark:bg-red-950/50 dark:text-red-200"],
  blocked: ["防御", "bg-emerald-100 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-200"],
  approval: ["承認待ちで停止", "bg-amber-100 text-amber-800 dark:bg-amber-950/50 dark:text-amber-200"],
  unverified: ["未確認", "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"],
} as const;

function AgentDefensePanel({ files, signedIn, report, onReport }: {
  files: File[]; signedIn: boolean; report: AgentReport | null; onReport: (r: AgentReport | null) => void;
}) {
  const [status, setStatus] = useState<{ available: boolean; reason: string | null; scope: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const settings = files.find((f) => /(^|\/)\.claude\/settings\.json$/.test(f.webkitRelativePath || f.name));
  useEffect(() => {
    if (!signedIn) return;
    getJSON<{ available: boolean; reason: string | null; scope: string }>("/api/agent-defense/status")
      .then(setStatus).catch(() => setStatus(null));
  }, [signedIn]);
  const run = async () => {
    setBusy(true);
    setError("");
    try {
      const text = settings ? await settings.text() : null;     // only this file is sent, to this machine's Vulnix
      onReport(await postJSON<AgentReport>("/api/agent-defense/evaluate", { settings_json: text }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="space-y-2 rounded-xl border border-zinc-200 bg-white p-3 text-sm dark:border-zinc-800 dark:bg-zinc-900">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="font-semibold">Claude Code の実行時確認</p>
          <p className="text-xs text-zinc-500">
            {settings ? "選んだフォルダの .claude/settings.json" : "選んだフォルダに .claude/settings.json がありません（設定なしとして確認）"}
            の権限ルールで、秘密の読み取り・外部送信・権限変更・削除を本物の CLI が止めるかを、通信を遮断した使い捨て環境で試します。
          </p>
        </div>
        {signedIn && status?.available &&
          <button type="button" onClick={() => void run()} disabled={busy}
            className="inline-flex items-center gap-2 rounded-lg bg-zinc-900 px-3 py-1.5 text-xs font-semibold text-white transition-opacity disabled:opacity-50 dark:bg-white dark:text-zinc-900">
            {busy && <span aria-hidden="true" className="h-3 w-3 animate-spin rounded-full border-2 border-current border-r-transparent motion-reduce:animate-none" />}
            {busy ? "確認中…" : report ? "もう一度確認" : "実行時に確認"}
          </button>}
      </div>
      {!signedIn && <p className="text-xs text-zinc-600 dark:text-zinc-400">ログインすると、この端末で起動した Vulnix で実行できます。</p>}
      {signedIn && status && !status.available && <p role="status" className="text-xs text-amber-700 dark:text-amber-300">実行しません：{status.reason}</p>}
      {error && <p role="alert" className="text-xs text-red-700">{error}</p>}
      {report?.status && report.status !== "done" && <p role="status" className="text-xs text-amber-700">実行しませんでした：{report.reason}</p>}
      {report?.results && <ul className="space-y-1">
        {report.results.map((r) => {
          const [label, cls] = r.verdict === "breached" ? VERDICT.breached : r.verdict === "blocked"
            ? (r.blocked_by === "rule" ? VERDICT.blocked : VERDICT.approval) : VERDICT.unverified;
          return <li key={r.id} className="flex flex-wrap items-start gap-2">
            <span className={`shrink-0 rounded-full px-2 py-0.5 text-xs ${cls}`}>{label}</span>
            <span>{r.label}{r.secret_reached_model ? "（目印の秘密値がAIに渡りました）" : ""}
              {r.advice && <span className="block text-xs text-zinc-600 dark:text-zinc-400">対策：{r.advice}</span>}</span>
          </li>;
        })}
      </ul>}
      {(report?.scope || status?.scope) && <p className="text-xs text-zinc-500">{report?.scope ?? status?.scope}</p>}
    </div>
  );
}
