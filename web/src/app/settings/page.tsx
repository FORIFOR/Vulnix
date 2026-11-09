"use client";

import { useSyncExternalStore } from "react";
import { MfaSection } from "@/components/settings/MfaSection";
import { PasswordChangeForm } from "@/components/settings/PasswordChangeForm";
import { Card, Pill } from "@/components/ui";
import { fmtTime } from "@/lib/labels";
import {
  clearLearningHistory,
  getLearningServerSnapshot,
  getLearningSnapshot,
  subscribeLearning,
} from "@/lib/learningHistory";
import { getThemeServerSnapshot, getThemeSnapshot, setTheme, subscribeTheme, type Theme } from "@/lib/theme";
import { useAssessment } from "@/lib/useAssessment";
import { useSession } from "@/lib/useSession";

const THEMES: { key: Theme; label: string }[] = [
  { key: "system", label: "システムに合わせる" },
  { key: "light", label: "ライト" },
  { key: "dark", label: "ダーク" },
];

const LEVEL_LABEL = { easy: "かんたん", detail: "詳しく", expert: "専門家" } as const;

export default function Settings() {
  const { snap, error } = useAssessment("scan_001");
  const { session, logout } = useSession();
  const theme = useSyncExternalStore(subscribeTheme, getThemeSnapshot, getThemeServerSnapshot);
  const learning = useSyncExternalStore(subscribeLearning, getLearningSnapshot, getLearningServerSnapshot);
  const pick = (t: Theme) => setTheme(t);
  const a = snap?.authorization;

  return (
    <main className="mx-auto max-w-3xl space-y-4 p-4 md:p-8">
      <h1 className="text-2xl font-bold">設定</h1>

      <Card>
        <h2 className="mb-2 text-sm font-semibold">アカウント</h2>
        {session ? (
          <div className="flex flex-wrap items-center justify-between gap-3">
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
              <dt className="text-zinc-500">ユーザー名</dt><dd>{session.operator}</dd>
              <dt className="text-zinc-500">権限</dt>
              <dd className="flex gap-1">
                {session.roles.map((r) => (
                  <Pill key={r} className="bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-100">
                    {r === "approver" ? "承認責任者" : "診断オペレーター"}
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
        <h2 className="mb-2 text-sm font-semibold">モデルと脅威情報</h2>
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
          <dt className="text-zinc-500">診断エージェント</dt><dd>ARTEX — 未接続（提案は Gateway 経由でのみ実行）</dd>
          <dt className="text-zinc-500">推論モデル</dt><dd>Abliteration / GPT / Claude — 環境変数 AEGIS_MODEL_URL で接続（既定は未接続）</dd>
          <dt className="text-zinc-500">Proposal Router</dt><dd>実装済み・自律実行は無効（/api/router/status で確認）。Router は認可を持ちません</dd>
          <dt className="text-zinc-500">モデルの権限</dt><dd>提案のみ。実行の可否は Gateway と人の承認が決めます</dd>
          <dt className="text-zinc-500">CVE 照合</dt><dd>有効（検出のみ・「実証」とは区別）。NVD JSON フィード取り込みに対応</dd>
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
