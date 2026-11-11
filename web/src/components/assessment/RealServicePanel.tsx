"use client";

import { useState } from "react";
import { getJSON, postJSON } from "@/lib/api";
import type { SecretsStatus, Snapshot } from "@/lib/types";

const CHECK_LABELS: Record<string, string> = {
  deepnote_idor_notes: "他ユーザーのノート（IDOR）",
  deepnote_share_link: "失効済み共有リンク",
  deepnote_gcs_acl: "Cloud Storage のアクセス制御",
  deepnote_ai_chat_isolation: "AIチャットのテナント分離",
  deepnote_billing_plan: "課金プランのサーバー側制御",
};

const MISSING_LABELS: Record<string, string> = {
  user_a_token: "アカウントA",
  user_b_token: "アカウントB",
  free_plan_token: "Freeプラン",
};

const PATH_FIELDS = [
  ["mock_note_path", "模擬ノート（B所有）"],
  ["mock_share_path", "失効済み共有リンク"],
  ["mock_gcs_path", "模擬ストレージオブジェクト（B所有）"],
  ["mock_chat_path", "AIチャット（Bのノート指定）"],
  ["mock_billing_path", "上位プラン専用API"],
] as const;

/** Banner + L2 test-account settings shown only for an ownership-verified real service. */
export function RealServicePanel({ snap, onUpdate }: { snap: Snapshot; onUpdate: (s: Snapshot) => void }) {
  const status = snap.secrets_status;
  const [open, setOpen] = useState(false);
  const [tokens, setTokens] = useState({ user_a_token: "", user_b_token: "", free_plan_token: "" });
  const [paths, setPaths] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    setMsg(null);
    try {
      const res = await postJSON<{ secrets_status: SecretsStatus; snapshot: Snapshot }>("/api/assets/secrets", {
        host: snap.asset.name,
        ...tokens,
        mock_paths: paths,
      });
      // Drop the raw values from the page as soon as the server has stored them.
      setTokens({ user_a_token: "", user_b_token: "", free_plan_token: "" });
      setPaths({});
      onUpdate(res.snapshot);
      setMsg("暗号化して保存しました。入力値は画面から消去しました。");
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const exportVideoData = async () => {
    setErr(null);
    try {
      const data = await getJSON<unknown>(`/api/assessments/${snap.id}/remotion`);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vulnix-remotion-${snap.id}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const checks = Object.entries(status?.checks ?? {});
  const readyCount = checks.filter(([, c]) => c.ready).length;

  return (
    <div className="mb-4 rounded-xl border border-sky-200 bg-sky-50/90 px-3.5 py-3 text-xs text-sky-950 dark:border-sky-900/60 dark:bg-sky-950/40 dark:text-sky-100">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 space-y-0.5">
          <p className="font-semibold">
            実サービス診断（所有確認済み）：<span className="break-all font-mono">{snap.target_url}</span>
          </p>
          <p className="text-sky-900 dark:text-sky-200">
            L1は読み取り専用の実測です。L2検証は検証用アカウントと模擬データに限定し、項目ごとに承認責任者が実行します（一括実行はしません）。
            未計測の項目を「安全」とは表示しません。
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            className="rounded-lg border border-sky-300 bg-white px-2.5 py-1.5 font-semibold text-sky-900 hover:bg-sky-100 dark:border-sky-700 dark:bg-zinc-900 dark:text-sky-100"
          >
            L2検証用アカウント（{readyCount}/{checks.length} 項目が実行可能）{open ? " ▴" : " ▾"}
          </button>
          <button
            type="button"
            onClick={exportVideoData}
            className="rounded-lg border border-sky-300 bg-white px-2.5 py-1.5 font-semibold text-sky-900 hover:bg-sky-100 dark:border-sky-700 dark:bg-zinc-900 dark:text-sky-100"
          >
            ⇩ 動画用データ（匿名化JSON）
          </button>
        </div>
      </div>

      {open && (
        <div className="mt-3 grid gap-4 border-t border-sky-200 pt-3 md:grid-cols-2 dark:border-sky-900/60">
          <div className="space-y-2">
            <h3 className="font-semibold">項目ごとの準備状況</h3>
            <ul className="space-y-1">
              {checks.map(([key, c]) => (
                <li key={key} className="flex items-center justify-between gap-2">
                  <span>{CHECK_LABELS[key] ?? key}</span>
                  <span className={c.ready ? "font-semibold text-emerald-700 dark:text-emerald-300" : "text-amber-800 dark:text-amber-300"}>
                    {c.ready ? "実行可能（承認待ち）" : `未設定: ${c.missing.map((m) => MISSING_LABELS[m] ?? m).join("・")}`}
                  </span>
                </li>
              ))}
            </ul>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 pt-1 text-[11px] text-sky-900 dark:text-sky-200">
              <dt>保存方式</dt><dd>{status?.encryption ?? "—"}</dd>
              <dt>A 指紋</dt><dd className="font-mono">{status?.user_a_fingerprint ?? "未設定"}</dd>
              <dt>B 指紋</dt><dd className="font-mono">{status?.user_b_fingerprint ?? "未設定"}</dd>
              <dt>Free 指紋</dt><dd className="font-mono">{status?.free_plan_fingerprint ?? "未設定"}</dd>
            </dl>
            <p className="text-[11px] text-sky-900 dark:text-sky-200">
              指紋はトークンのSHA-256の先頭8桁です。トークン自体は画面・ログ・レポートに表示されません。
            </p>
          </div>

          <form onSubmit={save} className="space-y-2">
            <h3 className="font-semibold">検証専用アカウントを設定</h3>
            <p className="text-[11px] text-sky-900 dark:text-sky-200">
              本番利用者のものではない、検証専用アカウントのトークンだけを入力してください。AとBは別アカウントである必要があります
              （Bが模擬データの所有者、Aが権限のない側です）。空欄の項目は変更しません。
            </p>
            {(
              [
                ["user_a_token", "アカウントA（権限のない側）"],
                ["user_b_token", "アカウントB（模擬データの所有者）"],
                ["free_plan_token", "Freeプランのアカウント（課金項目用）"],
              ] as const
            ).map(([key, label]) => (
              <label key={key} className="block">
                <span className="mb-0.5 block font-semibold">{label}</span>
                <input
                  type="password"
                  autoComplete="off"
                  value={tokens[key]}
                  onChange={(e) => setTokens((t) => ({ ...t, [key]: e.target.value }))}
                  className="w-full rounded-lg border border-sky-300 bg-white px-2.5 py-1.5 font-mono text-xs text-zinc-900 dark:border-sky-800 dark:bg-zinc-950 dark:text-zinc-100"
                />
              </label>
            ))}
            <details>
              <summary className="cursor-pointer font-semibold">模擬データのパスを変更（任意）</summary>
              <div className="mt-1.5 space-y-1.5">
                {PATH_FIELDS.map(([key, label]) => (
                  <label key={key} className="block">
                    <span className="mb-0.5 block">{label}</span>
                    <input
                      value={paths[key] ?? ""}
                      onChange={(e) => setPaths((p) => ({ ...p, [key]: e.target.value }))}
                      placeholder={status?.mock_paths?.[key] ?? "既定の模擬パスを使用"}
                      className="w-full rounded-lg border border-sky-300 bg-white px-2.5 py-1.5 font-mono text-xs text-zinc-900 dark:border-sky-800 dark:bg-zinc-950 dark:text-zinc-100"
                    />
                  </label>
                ))}
              </div>
            </details>
            <button
              type="submit"
              disabled={busy}
              className="rounded-lg bg-sky-900 px-3 py-1.5 font-semibold text-white hover:bg-sky-800 disabled:opacity-50 dark:bg-sky-200 dark:text-sky-950"
            >
              {busy ? "保存中…" : "暗号化して保存"}
            </button>
            {msg && <p role="status" className="text-emerald-800 dark:text-emerald-300">{msg}</p>}
          </form>
        </div>
      )}
      {err && <p role="alert" className="mt-2 font-semibold text-red-700 dark:text-red-300">エラー：{err}</p>}
    </div>
  );
}
