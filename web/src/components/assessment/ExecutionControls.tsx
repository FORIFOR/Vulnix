"use client";

import { useState } from "react";
import { command } from "@/lib/api";
import type { Snapshot } from "@/lib/types";
import { HelpPopover } from "../learning/HelpPopover";

export function ExecutionControls({ snap, onUpdate, refetch }: {
  snap: Snapshot;
  onUpdate: (s: Snapshot) => void;
  refetch: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [armed, setArmed] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const base = `/api/assessments/${snap.id}`;

  const run = async (path: string) => {
    setBusy(true);
    setErr(null);
    try {
      const r = await command(base + path);
      if ("state" in r) onUpdate(r as Snapshot);
      else refetch();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
      setArmed(false);
    }
  };

  const live = snap.state === "running" || snap.state === "paused";
  return (
    <div className="flex flex-wrap items-center gap-2">
      {snap.state === "idle" && (
        <button disabled={busy} onClick={() => run("/start")}
          className="rounded-lg bg-zinc-900 px-3 py-2 text-sm font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900">
          診断を開始
        </button>
      )}
      {snap.state === "running" && (
        <span className="inline-flex items-center">
          <button disabled={busy} onClick={() => run("/pause")}
            className="rounded-lg border border-zinc-300 px-3 py-2 text-sm font-semibold hover:bg-zinc-100 disabled:opacity-50 dark:border-zinc-600 dark:hover:bg-zinc-800">
            ❚❚ 一時停止
          </button>
          <HelpPopover term="pause" />
        </span>
      )}
      {snap.state === "paused" && (
        <button disabled={busy} onClick={() => run("/resume")}
          className="rounded-lg border border-zinc-300 px-3 py-2 text-sm font-semibold hover:bg-zinc-100 disabled:opacity-50 dark:border-zinc-600 dark:hover:bg-zinc-800">
          ▶ 再開（許可を再確認）
        </button>
      )}
      {live && (
        <span className="inline-flex items-center gap-1">
          {!armed ? (
            <button disabled={busy} onClick={() => setArmed(true)}
              className="rounded-lg bg-red-600 px-3 py-2 text-sm font-semibold text-white hover:bg-red-700 disabled:opacity-50">
              ■ 緊急停止
            </button>
          ) : (
            <span role="alertdialog" aria-label="緊急停止の確認" className="inline-flex items-center gap-1 rounded-lg border border-red-500 bg-red-50 p-1 dark:bg-red-950/40">
              <span className="px-1 text-xs text-red-800 dark:text-red-200">再開できません。停止しますか？</span>
              <button autoFocus disabled={busy} onClick={() => run("/emergency-stop")}
                className="rounded-md bg-red-600 px-2.5 py-1.5 text-sm font-semibold text-white hover:bg-red-700">
                停止する
              </button>
              <button onClick={() => setArmed(false)} className="rounded-md px-2 py-1.5 text-sm hover:bg-red-100 dark:hover:bg-red-900/40">
                取消
              </button>
            </span>
          )}
          <HelpPopover term="emergency_stop" />
        </span>
      )}
      {err && <span role="alert" className="text-xs text-red-700 dark:text-red-300">操作に失敗しました：{err}</span>}
    </div>
  );
}
