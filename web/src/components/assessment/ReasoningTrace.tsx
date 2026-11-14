"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { AUDIT_EVENT } from "@/lib/labels";
import type { AuditEntry, Snapshot } from "@/lib/types";
import { Pill } from "../ui";

const EXECUTION_EVENTS = new Set([
  "agent.thought",
  "proposal.received",
  "proposal.rejected",
  "proposal.unsupported",
  "approval.auto",
  "approval.approved",
  "approval.rejected",
  "allow",
  "deny",
  "result",
  "pause",
  "resume",
  "emergency_stop",
  "lab.mode_changed",
  "assessment.restarted",
  "assessment.failed",
]);

function fmtClock(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString("ja-JP", { hour12: false });
}

interface TraceItem {
  key: string;
  ts: number;
  kind: "thought" | "proposal" | "approval" | "gateway" | "worker" | "control";
  badge: string;
  badgeCls: string;
  title: string;
  detail: string;
  tool?: string;
  codePreview?: string;
  hash: string;
}

function toTraceItem(e: AuditEntry): TraceItem {
  const f = e.fields as Record<string, unknown>;
  switch (e.event) {
    case "agent.thought":
      return {
        key: e.hash,
        ts: e.ts,
        kind: "thought",
        badge: "計画・仮説",
        badgeCls: "bg-violet-100 text-violet-900 dark:bg-violet-900/60 dark:text-violet-100",
        title: String(f.step ?? "計画ステップ"),
        detail: String(f.detail ?? ""),
        tool: f.tool ? String(f.tool) : undefined,
        hash: e.hash,
      };
    case "proposal.received":
      return {
        key: e.hash,
        ts: e.ts,
        kind: "proposal",
        badge: "提案",
        badgeCls: "bg-sky-100 text-sky-900 dark:bg-sky-900/60 dark:text-sky-100",
        title: `${f.backend} が ${f.tool}（${f.action}）を提案`,
        detail: `対象: ${f.target} — ProposalRouter によりスキーマ検証・無害化済み`,
        tool: String(f.tool ?? ""),
        hash: e.hash,
      };
    case "proposal.unsupported":
      return {
        key: e.hash,
        ts: e.ts,
        kind: "proposal",
        badge: "未対応",
        badgeCls: "bg-amber-200 text-amber-950 dark:bg-amber-900/60 dark:text-amber-100",
        title: `【未対応】${f.backend} が提案した検査（${f.tool}）は未実装のため実行しません`,
        detail: `理由: ${f.reason ?? "未対応ツール"}（未対応の提案を実行したと装うことはありません）`,
        tool: String(f.tool ?? ""),
        hash: e.hash,
      };
    case "approval.auto":
      return {
        key: e.hash,
        ts: e.ts,
        kind: "approval",
        badge: "L1自動承認",
        badgeCls: "bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-100",
        title: `非破壊操作（${f.action}）をポリシーにより自動承認`,
        detail: `ツール: ${f.tool} / 承認主体: ${f.actor}`,
        tool: String(f.tool ?? ""),
        hash: e.hash,
      };
    case "approval.approved":
    case "approval.rejected":
      return {
        key: e.hash,
        ts: e.ts,
        kind: "approval",
        badge: e.event === "approval.approved" ? "L2人間承認" : "L2却下",
        badgeCls:
          e.event === "approval.approved"
            ? "bg-amber-200 text-amber-950 dark:bg-amber-900/60 dark:text-amber-100"
            : "bg-red-100 text-red-900 dark:bg-red-900/60 dark:text-red-100",
        title: `${f.action}（危険度 ${f.risk_level}）を ${f.actor} が${e.event === "approval.approved" ? "承認" : "却下"}`,
        detail: `リクエストID: ${f.request ?? "—"}`,
        hash: e.hash,
      };
    case "allow": {
      const d = f.dest as { host?: string; ip?: string; port?: number; path?: string } | undefined;
      return {
        key: e.hash,
        ts: e.ts,
        kind: "gateway",
        badge: "Gateway許可",
        badgeCls: "bg-emerald-100 text-emerald-900 dark:bg-emerald-900/60 dark:text-emerald-100",
        title: `Gateway が隔離 Worker (${f.tool}) の起動を許可`,
        detail: `Egress固定: ${d?.host ?? ""} → ${d?.ip ?? "127.0.0.1"}:${d?.port ?? ""} / トークンJTI: ${String(f.jti ?? "").slice(0, 10)}`,
        tool: String(f.tool ?? ""),
        hash: e.hash,
      };
    }
    case "deny":
      return {
        key: e.hash,
        ts: e.ts,
        kind: "gateway",
        badge: "Gateway遮断",
        badgeCls: "bg-red-600 text-white",
        title: `Gateway が実行を遮断 (${f.kind})`,
        detail: `理由: ${f.reason}`,
        hash: e.hash,
      };
    case "result":
      return {
        key: e.hash,
        ts: e.ts,
        kind: "worker",
        badge: "Worker完了",
        badgeCls: "bg-blue-100 text-blue-900 dark:bg-blue-900/60 dark:text-blue-100",
        title: `隔離 Worker ${f.tool ? `(${f.tool}) ` : ""}実行完了 — rc=${f.rc} (${Number(f.elapsed ?? 0).toFixed(2)}s)`,
        detail: f.killed ? "SIGKILL により強制終了されました" : "標準出力を証拠として保存し、SHA-256 監査ハッシュを記録しました",
        tool: f.tool ? String(f.tool) : undefined,
        codePreview: f.stdout_preview ? String(f.stdout_preview) : undefined,
        hash: e.hash,
      };
    default:
      return {
        key: e.hash,
        ts: e.ts,
        kind: "control",
        badge: AUDIT_EVENT[e.event] ?? e.event,
        badgeCls: "bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-100",
        title: AUDIT_EVENT[e.event] ?? e.event,
        detail: JSON.stringify(f),
        hash: e.hash,
      };
  }
}

export function ReasoningTrace({
  snap,
  audit,
  chainValid,
  externalBusy = false,
  defaultOpen = false,
  compact = false,
}: {
  snap: Snapshot;
  audit: AuditEntry[];
  chainValid: boolean | null;
  externalBusy?: boolean;
  defaultOpen?: boolean;
  compact?: boolean;
}) {
  const isRunning = snap.state === "running" || externalBusy;
  const [userToggled, setUserToggled] = useState<boolean | null>(null);
  const [viewMode, setViewMode] = useState<"steps" | "raw">("steps");
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const open = userToggled !== null ? userToggled : isRunning || defaultOpen;

  const execEntries = useMemo(
    () => audit.filter((e) => EXECUTION_EVENTS.has(e.event)),
    [audit],
  );
  const items = useMemo(() => execEntries.map(toTraceItem), [execEntries]);
  const latestItem = items.at(-1);

  // Auto-scroll to bottom when new steps stream in while open
  useEffect(() => {
    if (open && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [items.length, open, isRunning]);

  const headerTitle = isRunning
    ? snap.activity?.title
      ? `計画・実機検証中：${snap.activity.title}`
      : "ARTEX が計画・Worker検証を実行中…"
    : items.length > 0
      ? `計画・実行プロセス（${items.length} ステップ・監査ログ ${audit.length} 件）`
      : "計画・実行プロセス（待機中 — 診断またはWorker検証を開始するとリアルタイム表示されます）";

  return (
    <div
      className={`min-w-0 max-w-full overflow-hidden rounded-2xl border transition-colors ${
        isRunning
          ? "border-blue-400/80 bg-blue-50/40 dark:border-blue-800 dark:bg-blue-950/20"
          : "border-zinc-200 bg-zinc-50/80 dark:border-zinc-800 dark:bg-zinc-900/50"
      }`}
    >
      {/* ChatGPT-style Thinking Accordion Header */}
      <button
        type="button"
        onClick={() => setUserToggled(!open)}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left hover:bg-zinc-100/70 dark:hover:bg-zinc-800/50"
      >
        <div className="flex min-w-0 items-center gap-2.5">
          {isRunning ? (
            <span className="relative flex h-3 w-3 shrink-0">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-blue-500 opacity-75" />
              <span className="relative inline-flex h-3 w-3 rounded-full bg-blue-600" />
            </span>
          ) : (
            <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-zinc-200 text-[11px] font-bold text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
              ✦
            </span>
          )}
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 text-xs font-semibold text-zinc-900 dark:text-zinc-100">
              <span>{headerTitle}</span>
              {chainValid && (
                <span className="rounded bg-emerald-100 px-1.5 py-0.5 text-[10px] font-medium text-emerald-900 dark:bg-emerald-900/50 dark:text-emerald-200">
                  SHA-256 監査チェーン検証済
                </span>
              )}
            </div>
            {latestItem && (
              <p className="truncate text-[11px] text-zinc-500 dark:text-zinc-400">
                最新 [{fmtClock(latestItem.ts)}] {latestItem.title} — {latestItem.detail}
              </p>
            )}
          </div>
        </div>
        <span className="shrink-0 text-xs font-medium text-zinc-500">
          {open ? "閉じる ▴" : "ログを展開 ▾"}
        </span>
      </button>

      {/* Collapsible Reasoning & Live Log Stream Body */}
      {open && (
        <div className="border-t border-zinc-200/80 px-4 py-3 dark:border-zinc-800">
          <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1 rounded-lg bg-zinc-200/70 p-0.5 text-xs dark:bg-zinc-800">
              <button
                type="button"
                onClick={() => setViewMode("steps")}
                className={`rounded-md px-2.5 py-1 font-medium transition ${
                  viewMode === "steps"
                    ? "bg-white text-zinc-900 shadow-xs dark:bg-zinc-900 dark:text-zinc-100"
                    : "text-zinc-600 hover:text-zinc-900 dark:text-zinc-400"
                }`}
              >
                計画・実行ステップ ({items.length})
              </button>
              <button
                type="button"
                onClick={() => setViewMode("raw")}
                className={`rounded-md px-2.5 py-1 font-medium transition ${
                  viewMode === "raw"
                    ? "bg-white text-zinc-900 shadow-xs dark:bg-zinc-900 dark:text-zinc-100"
                    : "text-zinc-600 hover:text-zinc-900 dark:text-zinc-400"
                }`}
              >
                リアルタイム生ログ JSONL ({audit.length})
              </button>
            </div>
            {snap.activity && (
              <span className="font-mono text-[11px] text-blue-700 dark:text-blue-300">
                実行中ツール: {snap.activity.tool} ({snap.activity.risk_level})
              </span>
            )}
          </div>

          <div
            ref={scrollRef}
            className={`${compact ? "max-h-56" : "max-h-80"} overflow-y-auto pr-1`}
          >
            {viewMode === "steps" ? (
              items.length === 0 ? (
                <p className="py-4 text-center text-xs text-zinc-500">
                  「診断を開始」または「実機Workerで今すぐ検証」を押すと、ここにプランナーの検証計画・Gateway検査・Worker応答がリアルタイムに流れます。
                </p>
              ) : (
                <ol className="relative ml-2 space-y-2.5 border-l-2 border-zinc-300 pl-3.5 dark:border-zinc-700">
                  {items.map((it, idx) => {
                    const isLast = idx === items.length - 1;
                    return (
                      <li key={it.key} className="relative text-xs">
                        <span
                          className={`absolute -left-[19px] top-1.5 h-2.5 w-2.5 rounded-full border-2 border-white dark:border-zinc-900 ${
                            isLast && isRunning
                              ? "animate-pulse bg-blue-600"
                              : it.kind === "thought"
                                ? "bg-violet-600"
                                : it.kind === "worker"
                                  ? "bg-emerald-600"
                                  : "bg-zinc-400 dark:bg-zinc-500"
                          }`}
                        />
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="font-mono text-[11px] tabular-nums text-zinc-400">
                            {fmtClock(it.ts)}
                          </span>
                          <Pill className={it.badgeCls}>{it.badge}</Pill>
                          {it.tool && (
                            <span className="rounded bg-zinc-200/80 px-1.5 py-0.5 font-mono text-[10px] text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
                              {it.tool}
                            </span>
                          )}
                          <span className="font-semibold text-zinc-900 dark:text-zinc-100">
                            {it.title}
                          </span>
                          <span className="ml-auto font-mono text-[10px] text-zinc-400">
                            #{it.hash.slice(0, 8)}
                          </span>
                        </div>
                        <p className="mt-0.5 text-zinc-600 dark:text-zinc-300">{it.detail}</p>
                        {it.codePreview && (
                          <pre className="mt-1 max-w-full overflow-x-auto rounded-lg bg-zinc-900 p-2 font-mono text-[11px] text-emerald-300">
                            {it.codePreview}
                          </pre>
                        )}
                      </li>
                    );
                  })}
                </ol>
              )
            ) : (
              <pre className="max-w-full overflow-x-auto rounded-xl bg-zinc-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-200">
                {audit.length === 0
                  ? "// まだ監査ログはありません"
                  : audit.map((e) => JSON.stringify(e)).join("\n")}
              </pre>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
