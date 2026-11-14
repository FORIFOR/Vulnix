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
  "本番データの取得禁止",
  "他ユーザーへの影響・データ変更・削除禁止",
  "高負荷・DoS送信禁止",
  "リダイレクト先・外部サービスの自動スコープ追加禁止",
  "所有確認のみでのL2侵入実証（再現試験）の自動承認禁止",
];

const STEPS = ["URLを入力", "所有確認", "範囲と禁止事項", "L1診断へ"] as const;

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
  const [sowId, setSowId] = useState("");
  const [challenge, setChallenge] = useState<OwnershipChallenge | null>(initialAsset?.challenge ?? null);
  const [targetUrl, setTargetUrl] = useState<string>((initialAsset as { target_url?: string } | undefined)?.target_url ?? "");
  const [prohibited, setProhibited] = useState<string[]>(FALLBACK_PROHIBITED);
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
      const res = await postJSON<ChallengeResponse>("/api/assets/challenge", { url: url.trim(), sow_id: sowId.trim() });
      setChallenge(res.challenge);
      setTargetUrl((res.asset as { target_url?: string }).target_url ?? url.trim());
      setProhibited(res.prohibited_actions?.length ? res.prohibited_actions : FALLBACK_PROHIBITED);
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
        sow_id: sowId.trim(),
        activate_workspace: true,
      });
      onAssetsChanged(res.assets);
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
            <h2 id="ownership-wizard-title" className="text-lg font-bold">実サービスの登録（所有確認）</h2>
            <p className="mt-0.5 text-xs text-zinc-500">
              管理権限を証明できたサービスだけを診断対象にします。所有確認と範囲確認が終わるまで、対象へは一切通信しません。
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
              <label htmlFor="own-url" className="mb-1 block text-xs font-semibold">サービスのURLまたはホスト名</label>
              <input
                id="own-url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="例: https://staging.example.com"
                required
                className="w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-950"
              />
            </div>
            <div>
              <label htmlFor="own-sow" className="mb-1 block text-xs font-semibold">
                書面許可番号（任意）
              </label>
              <input
                id="own-sow"
                value={sowId}
                onChange={(e) => setSowId(e.target.value)}
                placeholder="未入力の場合は内部の許可記録IDを自動発行します"
                className="w-full rounded-lg border border-zinc-300 px-3 py-2 font-mono text-sm dark:border-zinc-700 dark:bg-zinc-950"
              />
            </div>
            <div className="flex justify-end">
              <button type="submit" disabled={busy || !url.trim()} className="rounded-lg bg-zinc-900 px-4 py-2 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900">
                {busy ? "発行中…" : "検証トークンを発行"}
              </button>
            </div>
          </form>
        )}

        {step === 1 && challenge && (
          <div className="space-y-3 text-sm">
            <p className="text-xs text-zinc-600 dark:text-zinc-300">
              次のどちらかを設定してから「確認する」を押してください。設定できるのはサービスの管理者だけなので、これが管理権限の証明になります。
            </p>
            <fieldset className="space-y-2">
              <legend className="sr-only">確認方法</legend>
              <label className={`block cursor-pointer rounded-xl border p-3 ${method === "dns_txt" ? "border-zinc-900 dark:border-white" : "border-zinc-200 dark:border-zinc-800"}`}>
                <span className="flex items-center gap-2 text-xs font-semibold">
                  <input type="radio" name="own-method" checked={method === "dns_txt"} onChange={() => setMethod("dns_txt")} />
                  DNS TXT レコード
                </span>
                <dl className="mt-2 space-y-1.5">
                  <CopyRow label="名前" value={challenge.dns_txt_name} />
                  <CopyRow label="値" value={challenge.dns_txt_value} />
                </dl>
              </label>
              <label className={`block cursor-pointer rounded-xl border p-3 ${method === "well_known" ? "border-zinc-900 dark:border-white" : "border-zinc-200 dark:border-zinc-800"}`}>
                <span className="flex items-center gap-2 text-xs font-semibold">
                  <input type="radio" name="own-method" checked={method === "well_known"} onChange={() => setMethod("well_known")} />
                  検証ファイル
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
              ✓ 所有確認が完了しました。診断できるのは次の宛先（このホスト・このスキーム・このポート）だけです：
              <span className="mt-0.5 block break-all font-mono font-semibold">{targetUrl || "（登録したURL）"}</span>
            </p>
            <div className="rounded-xl border border-zinc-200 p-3 dark:border-zinc-800">
              <h3 className="mb-1.5 text-xs font-semibold">この診断で行わないこと</h3>
              <ul className="list-disc space-y-0.5 pl-4 text-xs text-zinc-700 dark:text-zinc-300">
                {prohibited.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            </div>
            <p className="text-xs text-zinc-600 dark:text-zinc-300">
              確認後に実行できるのは、読み取り専用のL1診断（1回のGETによるTLS・ヘッダー・Cookie・CORSの検査）です。
              L2検証は、検証用アカウントを設定したうえで、項目ごとに承認責任者が承認したときだけ実行されます。
            </p>
            <label className="flex cursor-pointer items-start gap-2.5 text-xs">
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} className="mt-0.5 rounded border-zinc-300" />
              <span>診断対象と上記の禁止事項を確認しました。</span>
            </label>
            <div className="flex justify-end">
              <button type="button" disabled={busy || !confirmed} onClick={confirmScope} className="rounded-lg bg-zinc-900 px-4 py-2 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900">
                {busy ? "登録中…" : "範囲を確定して診断ワークスペースを開く"}
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
