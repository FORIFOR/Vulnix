"use client";

import { STATE } from "@/lib/labels";
import type { Snapshot } from "@/lib/types";
import type { Conn } from "@/lib/useAssessment";
import { ExecutionControls } from "../assessment/ExecutionControls";
import { RiskScore } from "../findings/RiskScore";
import { Pill } from "../ui";

const CONN: Record<Conn, string> = {
  connecting: "接続中…",
  live: "リアルタイム更新中",
  reconnecting: "再接続中…",
  offline: "オフライン",
};

/** Sticky so the emergency stop is always reachable while running. */
export function WorkspaceHeader({ snap, conn, onUpdate, refetch }: {
  snap: Snapshot;
  conn: Conn;
  onUpdate: (s: Snapshot) => void;
  refetch: () => void;
}) {
  const done = snap.phases.filter((p) => p.status === "done").length;
  const auth = snap.authorization;
  return (
    <header className="sticky top-0 z-30 border-b border-zinc-200 bg-white/90 px-4 py-3 backdrop-blur md:px-6 dark:border-zinc-800 dark:bg-zinc-950/90">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="truncate text-xl font-bold">{snap.asset.name}</h1>
            {auth.status === "authorized" ? (
              <Pill className="bg-emerald-100 text-emerald-900 dark:bg-emerald-900/50 dark:text-emerald-100">✓ 許可済み</Pill>
            ) : (
              <Pill className="bg-red-100 text-red-900">✕ 許可なし</Pill>
            )}
            <Pill className={STATE[snap.state].cls}>{STATE[snap.state].label}</Pill>
          </div>
          <p className="mt-0.5 text-sm text-zinc-500">
            {snap.asset.kind}・{snap.asset.environment}・{done} / {snap.phases.length} ステップ完了
            <span className="ml-2 text-xs" aria-live="polite">● {CONN[conn]}</span>
          </p>
        </div>
        <div className="flex items-center gap-4">
          {/* Before any check has run, show "未診断" rather than a misleading 0 / 低リスク. */}
          <RiskScore risk={snap.state === "idle" ? null : snap.risk} />
        </div>
      </div>
      <div className="mt-3">
        <ExecutionControls snap={snap} onUpdate={onUpdate} refetch={refetch} />
      </div>
    </header>
  );
}
