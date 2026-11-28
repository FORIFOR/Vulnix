"use client";

import Link from "next/link";
import { useState } from "react";
import { command } from "@/lib/api";
import type { Snapshot } from "@/lib/types";
import { useSession } from "@/lib/useSession";
import { assetProject, projectHref } from "../ProjectOverview";
import { HelpPopover } from "../learning/HelpPopover";

export function ExecutionControls({ snap, onUpdate, refetch }: {
  snap: Snapshot;
  onUpdate: (s: Snapshot) => void;
  refetch: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [armed, setArmed] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const { multiTenant, externalSiteTrafficEnabled, session } = useSession();
  const canRun = Boolean(session?.roles.some((role) => ["operator", "approver", "admin"].includes(role)));
  const trafficBlocked = snap.is_external_service && externalSiteTrafficEnabled === false;
  const canStart = canRun && !busy && !trafficBlocked && (!snap.is_external_service || snap.authorization.status === "authorized");
  const base = `/api/assessments/${snap.id}`;

  const run = async (path: string) => {
    setBusy(true);
    setErr(null);
    try {
      const reviewed = snap.is_external_service && (path === "/start" || path === "/restart")
        ? { reviewed_asset_id: snap.asset.id, reviewed_authority_generation: snap.authority_generation }
        : undefined;
      const r = await command(base + path, reviewed);
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
      {snap.is_external_service && !live && (
        <div aria-label="診断内容と許可範囲" className="w-full rounded-lg border border-zinc-200 p-2 text-xs dark:border-zinc-800">
          <p className="font-semibold">診断内容と許可範囲</p>
          <p className="break-all">{snap.target_url ?? snap.asset.name}</p>
          <dl className="mt-1 space-y-1">
            <div><dt className="inline font-semibold">開始すると確認すること</dt><dd className="ml-2 inline">許可された公開ページの読み取り、HTTPS、セキュリティ設定、Cookieの属性、公開情報から分かるCVE候補</dd></div>
            {snap.optional_status_scope && <div><dt className="inline font-semibold">条件付きの追加確認</dt><dd className="ml-2 inline">許可済みのApache状態ページを、初回応答と実行条件がそろったときに最大1回読み取ります。</dd></div>}
            <div><dt className="inline font-semibold">この診断で未確認となること</dt><dd className="ml-2 inline">認証後の権限、組織分離、実行時のAI権限、依存関係。実サービスへの侵入の実証は行いません。</dd></div>
          </dl>
          <Link className="mt-1 inline-block underline" href={projectHref("/quick-defense", assetProject(snap.asset))}>ソースコード・SBOMの確認へ</Link>
          {trafficBlocked && <p role="status">実サイト通信は停止中です。対象の試験許可と受入環境を運用担当者に確認してください。</p>}
          {!trafficBlocked && snap.authorization.status !== "authorized" && <p role="status">資産一覧で所有確認と診断範囲を確認してください。</p>}
          {!canRun && <p role="status">閲覧権限のみです。診断担当者に実行を依頼してください。</p>}
          {snap.authorization.status === "authorized" && snap.authorization.not_after > 0 && <p>
            許可の期限 {new Date(snap.authorization.not_after * 1000).toLocaleString("ja-JP")}
          </p>}
        </div>
      )}
      {snap.state === "idle" && (
        <button disabled={!canStart} onClick={() => run("/start")}
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
      {(snap.state === "completed" || snap.state === "stopped" || snap.state === "failed") && (
        <button
          disabled={!canStart}
          onClick={() => run("/restart")}
          className="rounded-lg bg-zinc-900 px-3 py-2 text-sm font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900"
        >
          ↻ 再診断を実行
        </button>
      )}
      {snap.state === "completed" && !snap.defense_comparison && !(snap.is_external_service && (multiTenant || snap.real_site_read_only)) && !(multiTenant && !snap.is_external_service) && (
        <button
          disabled={busy}
          onClick={() => run("/verify-fix")}
          className="rounded-lg bg-emerald-700 px-3 py-2 text-sm font-semibold text-white hover:bg-emerald-800 disabled:opacity-50"
        >
          {busy
            ? "再検証中…"
            : snap.is_external_service
              ? "✓ 修正後の再検証（修正前後の比較）"
              : "✓ 防御パッチ適用・再検証（修正前後の比較）"}
        </button>
      )}
      {err && <span role="alert" className="text-xs text-red-700 dark:text-red-300">操作に失敗しました：{err}</span>}
    </div>
  );
}
