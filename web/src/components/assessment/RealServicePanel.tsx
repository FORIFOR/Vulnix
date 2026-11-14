"use client";

import { useState } from "react";
import { getJSON, postJSON } from "@/lib/api";
import type { SecretsStatus, Snapshot } from "@/lib/types";
import { useSession } from "@/lib/useSession";

/** Banner + L2 test-account settings shown only for an ownership-verified real service. */
export function RealServicePanel({ snap, onUpdate }: { snap: Snapshot; onUpdate: (s: Snapshot) => void }) {
  const status = snap.secrets_status;
  const [open, setOpen] = useState(false);
  // the public beta (multi-tenant) only reads real sites: no test accounts, no extra checks
  const { multiTenant: readOnly } = useSession();
  const [tokens, setTokens] = useState<Record<string, string>>({});
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
        tokens,
        mock_paths: paths,
      });
      // Drop the raw values from the page as soon as the server has stored them.
      setTokens({});
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

  const profile = status?.profile ?? null;
  const tokenFields = status?.tokens ?? [];
  const pathFields = status?.paths ?? [];
  const tokenLabel = (key: string) => tokenFields.find((t) => t.key === key)?.label ?? key;
  const checks = Object.entries(status?.checks ?? {});
  const readyCount = checks.filter(([, c]) => c.ready).length;

  return (
    <div className="mb-4 rounded-xl border border-sky-200 bg-sky-50/90 px-3.5 py-3 text-xs text-sky-950 dark:border-sky-900/60 dark:bg-sky-950/40 dark:text-sky-100">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 space-y-0.5">
          <p className="font-semibold">
            {readOnly ? "診断中のサイト（所有確認済み）：" : "実サービス診断（所有確認済み）："}
            <span className="break-all font-mono">{snap.target_url}</span>
          </p>
          <p className="text-sky-900 dark:text-sky-200">
            {readOnly
              ? "公開されているページを読み取って調べた結果です。サイトのデータを変更したり、ログインを試したりはしていません。調べていない項目を「安全」とは表示しません。"
              : "L1は読み取り専用の実測です。L2検証は検証用アカウントと模擬データに限定し、項目ごとに承認責任者が実行します（一括実行はしません）。未計測の項目を「安全」とは表示しません。"}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {!readOnly && <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            className="rounded-lg border border-sky-300 bg-white px-2.5 py-1.5 font-semibold text-sky-900 hover:bg-sky-100 dark:border-sky-700 dark:bg-zinc-900 dark:text-sky-100"
          >
            {profile
              ? `L2検証用アカウント（${readyCount}/${checks.length} 項目が実行可能）`
              : "L2検証（判定ルール未設定）"}
            {open ? " ▴" : " ▾"}
          </button>}
          <button
            type="button"
            onClick={exportVideoData}
            className="rounded-lg border border-sky-300 bg-white px-2.5 py-1.5 font-semibold text-sky-900 hover:bg-sky-100 dark:border-sky-700 dark:bg-zinc-900 dark:text-sky-100"
          >
            ⇩ 動画用データ（匿名化JSON）
          </button>
        </div>
      </div>

      {open && !readOnly && !profile && (
        <p className="mt-3 border-t border-sky-200 pt-3 dark:border-sky-900/60">
          この対象に適用できるL2判定ルール（サービスプロファイル）がありません。実行できるのはL1の読み取り専用診断だけです。
          L2検証を行うには、対象APIの仕様に基づく判定ルールをサーバー側の設定（<span className="font-mono">aegis/l2_profiles/</span>）に追加してください。
        </p>
      )}

      {open && !readOnly && profile && (
        <div className="mt-3 grid gap-4 border-t border-sky-200 pt-3 md:grid-cols-2 dark:border-sky-900/60">
          <div className="space-y-2">
            <h3 className="font-semibold">項目ごとの準備状況（判定ルール：{profile.label}）</h3>
            {profile.spec_status !== "confirmed" && (
              <p role="note" className="rounded-lg border border-amber-300 bg-amber-50 px-2.5 py-1.5 text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
                {profile.spec_status === "unaccepted"
                  ? "このプロファイルの内容は管理者にまだ承認されていない（または承認後に変更された）ため、L2検証は実行できません。設定 → L2判定プロファイル で管理者が承認してください。"
                  : profile.spec_status === "placeholder"
                  ? "この判定ルールはすべて対象APIの仕様と未照合のため、L2検証は実行できません。"
                  : "仕様と未照合の項目は実行できません（承認しても送信されません）。"}
                {profile.spec_note}
              </p>
            )}
            <ul className="space-y-1.5">
              {checks.map(([key, c]) => (
                <li key={key}>
                  <div className="flex items-center justify-between gap-2">
                    <span>{c.label}</span>
                    <span className={c.ready ? "font-semibold text-emerald-700 dark:text-emerald-300" : "text-amber-800 dark:text-amber-300"}>
                      {c.spec_status === "unaccepted"
                        ? "実行不可（プロファイル未承認）"
                        : c.spec_status !== "confirmed"
                        ? "実行不可（仕様未照合）"
                        : c.ready ? "実行可能（承認待ち）" : `未設定: ${c.missing.map(tokenLabel).join("・")}`}
                    </span>
                  </div>
                  {c.spec_status === "confirmed" ? (
                    <p className="text-[11px] text-sky-900 dark:text-sky-200">同時に確認する前提：{c.preconditions.join("／")}</p>
                  ) : (
                    c.spec_note && <p className="break-words text-[11px] text-amber-900 dark:text-amber-200">{c.spec_note}</p>
                  )}
                </li>
              ))}
            </ul>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 pt-1 text-[11px] text-sky-900 dark:text-sky-200">
              <dt>保存方式</dt><dd>{status?.encryption ?? "—"}</dd>
              {tokenFields.filter((t) => t.usable).map((t) => (
                <div key={t.key} className="contents">
                  <dt>{t.label} 指紋</dt><dd className="font-mono">{t.fingerprint ?? "未設定"}</dd>
                </div>
              ))}
            </dl>
            <p className="text-[11px] text-sky-900 dark:text-sky-200">
              指紋はトークンのSHA-256の先頭8桁です。トークン自体は画面・ログ・レポートに表示されません。
              前提を確認できなかった場合や、応答内容が条件と一致しない場合は「未完了・要確認」となり、「再現せず」とは表示しません。
            </p>
          </div>

          <form onSubmit={save} className="space-y-2">
            <h3 className="font-semibold">検証専用アカウントを設定</h3>
            <p className="text-[11px] text-sky-900 dark:text-sky-200">
              本番利用者のものではない、検証専用アカウントのトークンだけを入力してください。役割の異なるアカウントには別々のアカウントを使う必要があります。
              空欄の項目は変更しません。
            </p>
            {tokenFields.filter((t) => t.usable).map((t) => (
              <label key={t.key} className="block">
                <span className="mb-0.5 block font-semibold">{t.label}{t.set ? "（設定済み）" : ""}</span>
                <input
                  type="password"
                  autoComplete="off"
                  name={t.key}
                  value={tokens[t.key] ?? ""}
                  onChange={(e) => setTokens((cur) => ({ ...cur, [t.key]: e.target.value }))}
                  className="w-full rounded-lg border border-sky-300 bg-white px-2.5 py-1.5 font-mono text-xs text-zinc-900 dark:border-sky-800 dark:bg-zinc-950 dark:text-zinc-100"
                />
              </label>
            ))}
            <details>
              <summary className="cursor-pointer font-semibold">模擬データのパスを変更（任意）</summary>
              <div className="mt-1.5 space-y-1.5">
                {pathFields.map((f) => (
                  <label key={f.key} className="block">
                    <span className="mb-0.5 block">{f.label}</span>
                    <input
                      name={f.key}
                      value={paths[f.key] ?? ""}
                      onChange={(e) => setPaths((p) => ({ ...p, [f.key]: e.target.value }))}
                      placeholder={f.value ?? f.default}
                      className="w-full rounded-lg border border-sky-300 bg-white px-2.5 py-1.5 font-mono text-xs text-zinc-900 dark:border-sky-800 dark:bg-zinc-950 dark:text-zinc-100"
                    />
                  </label>
                ))}
              </div>
            </details>
            {tokenFields.some((t) => !t.usable) && (
              <p className="text-[11px] text-sky-900 dark:text-sky-200">
                仕様未照合の項目でしか使わないアカウント（{tokenFields.filter((t) => !t.usable).map((t) => t.label).join("・")}）は保存できないため、入力欄を表示していません。
              </p>
            )}
            <button
              type="submit"
              disabled={busy || !tokenFields.some((t) => t.usable)}
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
