"use client";

import { useState, useSyncExternalStore } from "react";
import { MfaSection } from "@/components/settings/MfaSection";
import { ProfilesSection } from "@/components/settings/ProfilesSection";
import { RolesSection } from "@/components/settings/RolesSection";
import { OrgSection } from "@/components/settings/OrgSection";
import { PasswordChangeForm } from "@/components/settings/PasswordChangeForm";
import { Card, Pill } from "@/components/ui";
import { command } from "@/lib/api";
import { fmtTime } from "@/lib/labels";
import {
  clearLearningHistory,
  getLearningServerSnapshot,
  getLearningSnapshot,
  subscribeLearning,
} from "@/lib/learningHistory";
import { getThemeServerSnapshot, getThemeSnapshot, setTheme, subscribeTheme, type Theme } from "@/lib/theme";
import type { ControlVerificationReport } from "@/lib/types";
import { useAssessment } from "@/lib/useAssessment";
import { platformRoles, useSession } from "@/lib/useSession";

const THEMES: { key: Theme; label: string }[] = [
  { key: "system", label: "システムに合わせる" },
  { key: "light", label: "ライト" },
  { key: "dark", label: "ダーク" },
];

const LEVEL_LABEL = { easy: "かんたん", detail: "詳しく", expert: "専門家" } as const;

export default function Settings() {
  const { snap, error, refetch } = useAssessment("scan_001");
  const { session, logout } = useSession();
  const theme = useSyncExternalStore(subscribeTheme, getThemeSnapshot, getThemeServerSnapshot);
  const learning = useSyncExternalStore(subscribeLearning, getLearningSnapshot, getLearningServerSnapshot);
  const [verifyReport, setVerifyReport] = useState<ControlVerificationReport | null>(null);
  const [verifyBusy, setVerifyBusy] = useState(false);
  const [cveBusy, setCveBusy] = useState(false);
  const pick = (t: Theme) => setTheme(t);
  const a = snap?.authorization;
  const cveSt = snap?.cve_status;

  const runVerifyControls = async () => {
    setVerifyBusy(true);
    try {
      const rep = (await command("/api/system/verify-controls", {})) as unknown as ControlVerificationReport;
      setVerifyReport(rep);
    } finally {
      setVerifyBusy(false);
    }
  };

  const syncCve = async () => {
    setCveBusy(true);
    try {
      await command("/api/cve/sync", { source: "manual_ui_sync" });
      await refetch();
    } finally {
      setCveBusy(false);
    }
  };

  return (
    <main className="mx-auto max-w-3xl space-y-4 p-4 md:p-8">
      <h1 className="text-2xl font-bold">設定</h1>

      <Card>
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold">安全制御の実機検証（P0 Live Verification）</h2>
            <p className="text-xs text-zinc-500">
              実プロセス（egress_sentinel）・実ソケット・Gateway を駆動し、通信遮断・権限詐称剥離・承認強制・緊急停止SIGKILLを実機検証します。
            </p>
          </div>
          <button
            type="button"
            disabled={verifyBusy}
            onClick={runVerifyControls}
            className="rounded-lg bg-zinc-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900"
          >
            {verifyBusy ? "実機検証を実行中…" : "▶ 6層制御の実機検証を実行"}
          </button>
        </div>
        {verifyReport && (
          <div className="mt-3 space-y-2">
            <div className="flex items-center gap-2 text-xs font-semibold">
              <Pill className={verifyReport.all_passed ? "bg-emerald-600 text-white" : "bg-red-600 text-white"}>
                {verifyReport.all_passed ? "✓ 全5項目 PASS（実機検証済み）" : "✕ 一部失敗"}
              </Pill>
              <span className="text-zinc-500">
                Host: {verifyReport.host_platform} / 合計 {verifyReport.total_elapsed_ms} ms
              </span>
            </div>
            <ul className="space-y-1.5 text-xs">
              {verifyReport.checks.map((c) => (
                <li key={c.id} className="rounded-lg border border-zinc-200 p-2 dark:border-zinc-800">
                  <div className="flex items-center justify-between font-semibold">
                    <span>{c.passed ? "✓" : "✕"} {c.name}</span>
                    <span className="tabular-nums text-zinc-500">{c.elapsed_ms} ms</span>
                  </div>
                  <div className="mt-0.5 text-zinc-600 dark:text-zinc-400">{c.detail}</div>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Card>

      <Card>
        <h2 className="mb-2 text-sm font-semibold">アカウント</h2>
        {session ? (
          <div className="flex flex-wrap items-center justify-between gap-3">
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
              <dt className="text-zinc-500">ユーザー名</dt><dd>{session.operator}</dd>
              <dt className="text-zinc-500">権限</dt>
              <dd className="flex gap-1">
                {platformRoles(session).map((r) => (
                  <Pill key={r} className="bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-100">
                    {r === "approver" ? "承認責任者" : r === "admin" ? "管理者" : "診断オペレーター"}
                  </Pill>
                ))}
              </dd>
              <dt className="text-zinc-500">セッション期限</dt><dd>{fmtTime(session.expires)}</dd>
            </dl>
            <button onClick={logout} className="rounded-lg border border-zinc-300 px-3 py-1.5 text-sm font-medium hover:bg-zinc-100 dark:border-zinc-600 dark:hover:bg-zinc-800">
              ログアウト
            </button>
          </div>
        ) : <p className="text-sm text-zinc-500">読み込み中…</p>}
        {session && <PasswordChangeForm />}
        {session && <MfaSection />}
      </Card>

      {session && <OrgSection />}

      {session && (
        <Card>
          <h2 className="mb-2 text-sm font-semibold">アカウントとロール</h2>
          <RolesSection />
        </Card>
      )}

      {session && (platformRoles(session).includes("admin") || platformRoles(session).includes("approver")) && (
        <Card>
          <h2 className="mb-2 text-sm font-semibold">L2判定プロファイル</h2>
          <ProfilesSection />
        </Card>
      )}

      <Card>
        <h2 className="mb-2 text-sm font-semibold">表示テーマ</h2>
        <div role="radiogroup" aria-label="表示テーマ" className="grid grid-cols-3 gap-2">
          {THEMES.map((t) => (
            <button key={t.key} role="radio" aria-checked={theme === t.key} onClick={() => pick(t.key)}
              className={`rounded-lg border px-3 py-2 text-sm ${theme === t.key ? "border-zinc-900 bg-zinc-900 font-semibold text-white dark:border-white dark:bg-white dark:text-zinc-900" : "border-zinc-300 hover:bg-zinc-100 dark:border-zinc-600 dark:hover:bg-zinc-800"}`}>
              {t.label}
            </button>
          ))}
        </div>
        <p className="mt-2 text-xs text-zinc-500">この設定はこのブラウザにのみ保存されます。</p>
      </Card>

      <Card>
        <div className="mb-2 flex items-center justify-between">
          <h2 className="text-sm font-semibold">学習履歴（「？」による3段階解説）</h2>
          {learning.length > 0 && (
            <button
              type="button"
              onClick={clearLearningHistory}
              className="text-xs text-zinc-500 hover:underline"
            >
              履歴をクリア
            </button>
          )}
        </div>
        {learning.length === 0 ? (
          <p className="text-sm text-zinc-500">
            画面内の「？」ボタンを押して用語解説やAI解説を確認すると、ここに学習履歴が記録されます。
          </p>
        ) : (
          <ul className="space-y-1.5 text-sm">
            {learning.map((item) => (
              <li key={`${item.term}-${item.level}`} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-zinc-200 px-3 py-1.5 dark:border-zinc-800">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{item.title}</span>
                  <Pill className="bg-violet-100 text-violet-800 dark:bg-violet-900/50 dark:text-violet-200">
                    {LEVEL_LABEL[item.level]}
                  </Pill>
                  {item.askedAi && (
                    <Pill className="bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-100">
                      AI解説確認済み
                    </Pill>
                  )}
                </div>
                <span className="text-xs tabular-nums text-zinc-500">{fmtTime(item.ts)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card>
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold">モデルと脅威情報（ARTEX × Abliteration / NVD + CISA KEV）</h2>
          <button
            type="button"
            disabled={cveBusy}
            onClick={syncCve}
            className="rounded-lg border border-zinc-300 px-2.5 py-1 text-xs font-medium hover:bg-zinc-100 disabled:opacity-50 dark:border-zinc-600 dark:hover:bg-zinc-800"
          >
            {cveBusy ? "同期中…" : "↻ CVE / CISA KEV フィード同期"}
          </button>
        </div>
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
          <dt className="text-zinc-500">診断エージェント</dt><dd>ARTEX 実行エンジン — タスク計画・ProposalRouter 統合済み</dd>
          <dt className="text-zinc-500">推論アダプター</dt><dd>AbliterationBackend — OpenAI 互換 Chat Completions (`messages` / `choices`) 対応</dd>
          <dt className="text-zinc-500">モデルの権限</dt><dd>提案のみ（権限詐称キーは Router が自動除去）。実行は Gateway と人の承認が裁く</dd>
          <dt className="text-zinc-500">CVE / KEV 監視</dt>
          <dd>
            NVD 登録 {cveSt?.cve_count ?? 2} 件 / CISA KEV 悪用確認 {cveSt?.kev_count ?? 2} 件（最終同期: {fmtTime(cveSt?.last_synced_at)}）
          </dd>
        </dl>
      </Card>

      <Card>
        <h2 className="mb-2 text-sm font-semibold">診断権限</h2>
        {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
        {a ? (
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
            <dt className="text-zinc-500">書面許可</dt><dd>{a.ref}</dd>
            <dt className="text-zinc-500">期間</dt><dd>{fmtTime(a.not_before)} 〜 {fmtTime(a.not_after)}</dd>
            <dt className="text-zinc-500">対象ホスト</dt><dd>{a.scope.hosts.join(", ")}</dd>
            <dt className="text-zinc-500">許可IP / ポート</dt><dd>{a.scope.cidrs.join(", ")} / {a.scope.ports.join(", ")}</dd>
            <dt className="text-zinc-500">許可操作</dt><dd>{a.allowed_actions.join(", ")}</dd>
          </dl>
        ) : <p className="text-sm text-zinc-500">読み込み中…</p>}
      </Card>

      <Card>
        <h2 className="mb-2 text-sm font-semibold">制限（変更不可）</h2>
        <ul className="list-disc space-y-1 pl-5 text-sm">
          <li>L1（読み取りのみ）はポリシーで自動承認、L2以上は人の承認が必須</li>
          <li>実行トークン：単回使用・最大120秒・緊急停止で一括失効</li>
          <li>同時実行 2・CPU時間 60秒/Worker・操作予算 20回</li>
          <li>通信：許可ホストの全解決先が許可IP内であること。メタデータ等は常に拒否。リダイレクトは追従しない</li>
          <li>Worker プロセス内でも、ピン留め先の IP:ポート以外への接続をソケット層で遮断（多層防御）</li>
          <li>2要素認証（TOTP）：アカウントごとに任意で有効化可能（上のアカウント欄）</li>
          <li>OSカーネルレベルの通信遮断（nftables）：ルール生成は実装・検証済み。カーネルへの適用は Linux の Worker ホスト限定（この環境では未適用）</li>
        </ul>
        <p className="mt-3 rounded-lg bg-zinc-50 p-2 text-xs leading-relaxed text-zinc-600 dark:bg-zinc-800/60 dark:text-zinc-300">
          安全に関わる上限（通信範囲・トークン・予算・同時実行）は、UIからは変更できない設計です。
          AIにもUIにも実行権限を委ねないという原則（P0）に基づき、これらはサーバー側の設定でのみ変更します。
        </p>
      </Card>
    </main>
  );
}
