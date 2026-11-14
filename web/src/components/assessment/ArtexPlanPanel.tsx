"use client";

import { useState, type Dispatch, type SetStateAction } from "react";
import { postJSON } from "@/lib/api";
import type { Snapshot } from "@/lib/types";
import { canApprove, useSession } from "@/lib/useSession";
import { Card, Pill } from "../ui";

const STATUS: Record<string, { label: string; cls: string }> = {
  planned: { label: "実行可能（L1）", cls: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300" },
  awaiting_approval: { label: "承認待ち（L2）", cls: "bg-amber-100 text-amber-900 dark:bg-amber-900/50 dark:text-amber-100" },
  running: { label: "実行中", cls: "bg-sky-100 text-sky-900 dark:bg-sky-900/50 dark:text-sky-100" },
  completed: { label: "完了", cls: "bg-emerald-100 text-emerald-900 dark:bg-emerald-900/50 dark:text-emerald-100" },
  failed: { label: "失敗・拒否", cls: "bg-red-100 text-red-900 dark:bg-red-900/50 dark:text-red-100" },
};

/** The real ARTEX planner's plan, as rebuilt by Vulnix. ARTEX only suggests: every item
 *  below was reconstructed from Vulnix's registered targets and allowed catalog, and runs
 *  only through the Gateway (L2: approver, isolated worker). Advisories never run. */
export function ArtexPlanPanel({ snap, onUpdate }: {
  snap: Snapshot;
  onUpdate: Dispatch<SetStateAction<Snapshot | null>>;
}) {
  const approver = canApprove(useSession().session);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const plan = snap.artex_plan?.plan ?? null;
  const base = `/api/assessments/${snap.id}`;

  const run = async (key: string, path: string) => {
    setBusy(key);
    setErr(null);
    try {
      onUpdate(await postJSON<Snapshot>(path));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const verified = plan?.engine.kind === "artex-binary";
  return (
    <Card className="mb-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="font-semibold">ARTEX 計画（提案のみ・Gateway 経由で実行）</h2>
          <p className="mt-0.5 text-xs text-zinc-500">
            ARTEX は方向を提案するだけです。対象・操作・引数は Vulnix が登録済み対象と許可済み検証カタログから再構成します。
          </p>
        </div>
        <button
          type="button"
          disabled={busy !== null}
          onClick={() => run("plan", `${base}/artex/plan`)}
          className="rounded-lg bg-zinc-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900"
        >
          {busy === "plan" ? "ARTEX が計画中…" : plan ? "ARTEX で再計画" : "ARTEX で計画を作成"}
        </button>
      </div>

      {err && <p role="alert" className="mt-3 text-xs font-semibold text-red-700 dark:text-red-300">{err}</p>}

      {plan && (
        <div className="mt-3 space-y-3 text-sm">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <Pill className={verified ? "bg-emerald-100 text-emerald-900 dark:bg-emerald-900/50 dark:text-emerald-100"
              : "bg-amber-100 text-amber-900 dark:bg-amber-900/50 dark:text-amber-100"}>
              {plan.engine.label}
            </Pill>
            {plan.isolation && (
              <Pill className={plan.isolation.confined ? "bg-emerald-100 text-emerald-900 dark:bg-emerald-900/50 dark:text-emerald-100"
                : "bg-red-100 text-red-900 dark:bg-red-900/50 dark:text-red-100"}>
                {plan.isolation.label}
              </Pill>
            )}
            {plan.isolation?.confined && (
              <span className="text-zinc-500">
                許可通信：{[plan.isolation.pinned, ...(plan.isolation.pinned_extra ?? [])].filter(Boolean).join(", ")}
              </span>
            )}
            {plan.engine.artex_commit && <span className="font-mono text-zinc-500">commit {plan.engine.artex_commit.slice(0, 12)}</span>}
            {plan.engine.sha256 && <span className="font-mono text-zinc-500">bin {plan.engine.sha256.slice(0, 12)}</span>}
            <span className="text-zinc-500">intent {plan.intents} 件 / {Math.round(plan.elapsed_ms)} ms</span>
            {plan.denied_tool_calls.length > 0 && (
              <span className="text-zinc-500">遮断したツール呼び出し：{plan.denied_tool_calls.join(", ")}</span>
            )}
          </div>

          <ul className="divide-y divide-zinc-100 rounded-xl border border-zinc-200 dark:divide-zinc-800 dark:border-zinc-800">
            {plan.items.map((it) => {
              const st = STATUS[it.status] ?? STATUS.planned;
              const needsApprover = it.level === "L2" && !approver;
              const done = it.status === "completed" || it.status === "running";
              return (
                <li key={it.id} className="flex flex-wrap items-center justify-between gap-2 p-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <Pill className={it.level === "L2" ? "bg-orange-100 text-orange-900 dark:bg-orange-900/50 dark:text-orange-100" : "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"}>{it.level}</Pill>
                      <span className="font-medium">{it.label}</span>
                      <Pill className={st.cls}>{st.label}</Pill>
                    </div>
                    <p className="mt-1 break-words text-xs text-zinc-500">
                      <span className="font-medium">ARTEX の原文</span>（AI出力・未翻訳。実行内容は上の検証項目のとおりで、この文では決まりません）#{it.intent_id}：{it.intent_summary}
                    </p>
                  </div>
                  <button
                    type="button"
                    disabled={busy !== null || done || needsApprover}
                    title={needsApprover ? "L2 は承認責任者のみ実行できます" : undefined}
                    onClick={() => run(it.id, `${base}/artex/items/${it.id}/execute`)}
                    className="rounded-lg border border-zinc-300 px-2.5 py-1 text-xs font-semibold hover:bg-zinc-100 disabled:opacity-50 dark:border-zinc-700 dark:hover:bg-zinc-800"
                  >
                    {busy === it.id ? "実行中…" : it.level === "L2" ? (needsApprover ? "承認者のみ" : "承認して Gateway で実行") : "Gateway で実行"}
                  </button>
                </li>
              );
            })}
            {plan.items.length === 0 && <li className="p-3 text-xs text-zinc-500">実行可能な項目はありません。</li>}
          </ul>

          {plan.advisories.length > 0 && (
            <div>
              <h3 className="mb-1 text-xs font-semibold text-zinc-600 dark:text-zinc-400">参考提案（実行されません）</h3>
              <p className="mb-1 text-xs text-zinc-500">ARTEX の原文をそのまま表示しています（AI出力・未翻訳。日本語以外の場合があります）。</p>
              <ul className="space-y-1 text-xs">
                {plan.advisories.map((a, i) => (
                  <li key={i} className="rounded-lg bg-zinc-50 p-2 dark:bg-zinc-800/60">
                    <span className="break-words">#{a.intent_id} {a.summary}</span>
                    <span className="block text-zinc-500">{a.reason}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}
