"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { postJSON } from "@/lib/api";
import type { Asset, OwnershipChallenge, Snapshot } from "@/lib/types";

interface Props {
  open: boolean;
  onClose: () => void;
  onAssetsChanged: (assets: Asset[]) => void;
  /** Resume the flow for an asset that already has a challenge. */
  initialAsset?: Asset | null;
}

type Method = "dns_txt" | "well_known";

interface ChallengeResponse {
  asset: Asset;
  challenge: OwnershipChallenge;
  prohibited_actions: string[];
  assets: Asset[];
}

interface VerifyResponse {
  verified: boolean;
  verification: { detail: string };
  asset: Asset | null;
  assets: Asset[];
}

interface ScopeResponse {
  asset: Asset;
  assets: Asset[];
  snapshot: Snapshot;
}

const FALLBACK_PROHIBITED = [
  "データの取得・変更・削除",
  "ログインの試行や攻撃的な検査",
  "大量のアクセス（サイトに負荷をかけること）",
  "リンク先など、登録したサイト以外へのアクセス",
];

const STEPS = ["URLを入力", "所有確認", "診断を開始"] as const;

function CopyRow({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-start gap-2">
      <dt className="w-14 shrink-0 pt-1 text-[11px] text-zinc-500">{label}</dt>
      <dd className="min-w-0 flex-1 break-all rounded bg-zinc-100 px-2 py-1 font-mono text-[11px] dark:bg-zinc-800">{value}</dd>
      <button
        type="button"
        onClick={() => {
          navigator.clipboard?.writeText(value).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }, () => undefined);
        }}
        className="shrink-0 rounded border border-zinc-300 px-1.5 py-0.5 text-[11px] hover:bg-zinc-100 dark:border-zinc-700 dark:hover:bg-zinc-800"
      >
        {copied ? "コピー済み" : "コピー"}
      </button>
    </div>
  );
}

export function OwnershipWizard({ open, onClose, onAssetsChanged, initialAsset }: Props) {
  const router = useRouter();
  const resumeAt = initialAsset?.challenge ? (initialAsset.ownership_verified ? 2 : 1) : 0;
  const [step, setStep] = useState(resumeAt);
  const [url, setUrl] = useState(initialAsset?.target_url ?? (initialAsset?.name ? `https://${initialAsset.name}` : ""));
  const [challenge, setChallenge] = useState<OwnershipChallenge | null>(initialAsset?.challenge ?? null);
  const [targetUrl, setTargetUrl] = useState<string>((initialAsset as { target_url?: string } | undefined)?.target_url ?? "");
  const prohibited = FALLBACK_PROHIBITED;
  const [method, setMethod] = useState<Method>("dns_txt");
  const [verifyDetail, setVerifyDetail] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (!open) return null;

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setErr(null);
    try {
      await fn();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const issue = () =>
    run(async () => {
      const res = await postJSON<ChallengeResponse>("/api/assets/challenge", { url: url.trim() });
      setChallenge(res.challenge);
      setTargetUrl((res.asset as { target_url?: string }).target_url ?? url.trim());
      onAssetsChanged(res.assets);
      // An already-verified asset keeps its proof; skip straight to scope confirmation.
      setStep(res.asset.ownership_verified ? 2 : 1);
    });

  const verify = () =>
    run(async () => {
      setVerifyDetail(null);
      const res = await postJSON<VerifyResponse>("/api/assets/verify-ownership", { url: url.trim(), method });
      onAssetsChanged(res.assets);
      setVerifyDetail(res.verification.detail);
      if (res.verified) setStep(2);
    });

  const confirmScope = () =>
    run(async () => {
      const res = await postJSON<ScopeResponse>("/api/assets/confirm-scope", {
        url: url.trim(),
        confirmed_prohibited: confirmed,
        activate_workspace: true,
      });
      onAssetsChanged(res.assets);
      // the diagnosis starts right away: the user asked for it with this button
      await postJSON(`/api/assessments/${res.snapshot.id}/start`, {});
      onClose();
      router.push(`/assessments/${res.snapshot.id}`);
    });

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-xs"
      role="dialog"
      aria-modal="true"
      aria-labelledby="ownership-wizard-title"
    >
      <div className="max-h-[90dvh] w-full max-w-xl overflow-y-auto rounded-2xl border border-zinc-200 bg-white p-6 shadow-xl dark:border-zinc-800 dark:bg-zinc-900">
        <div className="mb-4 flex items-start justify-between gap-2">
          <div>
            <h2 id="ownership-wizard-title" className="text-lg font-bold">サイトを診断する</h2>
            <p className="mt-0.5 text-xs text-zinc-500">
              あなたが管理しているサイトだけを診断できます。所有確認が終わるまで、サイトへは一切アクセスしません。
            </p>
          </div>
          <button type="button" onClick={onClose} className="shrink-0 whitespace-nowrap rounded-lg px-2.5 py-1 text-xs text-zinc-500 hover:bg-zinc-100 dark:hover:bg-zinc-800">
            閉じる ✕
          </button>
        </div>

        <ol className="mb-4 flex flex-wrap gap-1.5 text-[11px]">
          {STEPS.map((label, i) => (
            <li
              key={label}
              aria-current={i === step ? "step" : undefined}
              className={`rounded-full px-2.5 py-1 font-semibold ${
                i < step
                  ? "bg-emerald-100 text-emerald-900 dark:bg-emerald-900/50 dark:text-emerald-100"
                  : i === step
                    ? "bg-zinc-900 text-white dark:bg-white dark:text-zinc-900"
                    : "bg-zinc-100 text-zinc-500 dark:bg-zinc-800"
              }`}
            >
              {i < step ? "✓ " : `${i + 1}. `}
              {label}
            </li>
          ))}
        </ol>

        {step === 0 && (
          <form
            className="space-y-3 text-sm"
            onSubmit={(e) => {
              e.preventDefault();
              if (url.trim()) issue();
            }}
          >
            <div>
              <label htmlFor="own-url" className="mb-1 block text-xs font-semibold">診断するサイトのURL</label>
              <input
                id="own-url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="例: https://example.com"
                required
                className="w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-950"
              />
            </div>
            <div className="flex justify-end">
              <button type="submit" disabled={busy || !url.trim()} className="rounded-lg bg-zinc-900 px-4 py-2 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900">
                {busy ? "準備中…" : "次へ"}
              </button>
            </div>
          </form>
        )}

        {step === 1 && challenge && (
          <div className="space-y-3 text-sm">
            <p className="text-xs text-zinc-600 dark:text-zinc-300">
              サイトの管理者であることを確認します。次のどちらかを設定してから「確認する」を押してください（DNS の場合、反映まで数分かかることがあります）。
            </p>
            <fieldset className="space-y-2">
              <legend className="sr-only">確認方法</legend>
              <label className={`block cursor-pointer rounded-xl border p-3 ${method === "dns_txt" ? "border-zinc-900 dark:border-white" : "border-zinc-200 dark:border-zinc-800"}`}>
                <span className="flex items-center gap-2 text-xs font-semibold">
                  <input type="radio" name="own-method" checked={method === "dns_txt"} onChange={() => setMethod("dns_txt")} />
                  DNS に TXT レコードを追加（おすすめ）
                </span>
                <dl className="mt-2 space-y-1.5">
                  <CopyRow label="名前" value={challenge.dns_txt_name} />
                  <CopyRow label="値" value={challenge.dns_txt_value} />
                </dl>
              </label>
              <label className={`block cursor-pointer rounded-xl border p-3 ${method === "well_known" ? "border-zinc-900 dark:border-white" : "border-zinc-200 dark:border-zinc-800"}`}>
                <span className="flex items-center gap-2 text-xs font-semibold">
                  <input type="radio" name="own-method" checked={method === "well_known"} onChange={() => setMethod("well_known")} />
                  サイトに確認用ファイルを置く
                </span>
                <dl className="mt-2 space-y-1.5">
                  <CopyRow label="URL" value={challenge.well_known_url} />
                  <CopyRow label="内容" value={challenge.well_known_content} />
                </dl>
              </label>
            </fieldset>
            {verifyDetail && (
              <p role="status" className="rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
                {verifyDetail}
              </p>
            )}
            <div className="flex justify-between gap-2">
              <button type="button" onClick={() => setStep(0)} className="rounded-lg border border-zinc-300 px-3 py-2 text-xs hover:bg-zinc-50 dark:border-zinc-700 dark:hover:bg-zinc-800">
                ← URLを修正
              </button>
              <button type="button" disabled={busy} onClick={verify} className="rounded-lg bg-zinc-900 px-4 py-2 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900">
                {busy ? "確認中…" : "確認する"}
              </button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-3 text-sm">
            <p className="rounded-lg bg-emerald-50 px-3 py-2 text-xs text-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-100">
              ✓ 所有確認が完了しました。診断するのはこのサイトだけです：
              <span className="mt-0.5 block break-all font-mono font-semibold">{targetUrl || "（登録したURL）"}</span>
            </p>
            <div className="rounded-xl border border-zinc-200 p-3 text-xs text-zinc-700 dark:border-zinc-800 dark:text-zinc-300">
              <p className="mb-1.5">
                公開されているページを1回だけ読み取り、通信の暗号化・セキュリティ設定・Cookie などを調べます。
                結果は数十秒で表示され、AI が問題点と直し方を分かりやすく説明します。
              </p>
              <h3 className="mb-1 mt-2 font-semibold">行わないこと</h3>
              <ul className="list-disc space-y-0.5 pl-4">
                {prohibited.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            </div>
            <label className="flex cursor-pointer items-start gap-2.5 text-xs">
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} className="mt-0.5 rounded border-zinc-300" />
              <span>このサイトの管理者として、上記の内容で診断することに同意します。</span>
            </label>
            <div className="flex justify-end">
              <button type="button" disabled={busy || !confirmed} onClick={confirmScope} className="rounded-lg bg-zinc-900 px-4 py-2 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900">
                {busy ? "開始しています…" : "診断を開始"}
              </button>
            </div>
          </div>
        )}

        {err && (
          <p role="alert" className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-xs text-red-800 dark:bg-red-950/40 dark:text-red-200">
            {err}
          </p>
        )}
      </div>
    </div>
  );
}
