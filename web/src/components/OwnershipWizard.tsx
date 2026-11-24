"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { getJSON, postJSON } from "@/lib/api";
import type { Asset, OwnershipChallenge, Snapshot } from "@/lib/types";
import { useSession } from "@/lib/useSession";

interface Props {
  open: boolean;
  onClose: () => void;
  onAssetsChanged: (assets: Asset[]) => void;
  /** Resume the flow for an asset that already has a challenge. */
  initialAsset?: Asset | null;
  /** shown on the ownership step (e.g. Google could not confirm this site) */
  notice?: string | null;
}

type Method = "dns_txt" | "well_known" | "meta_tag" | "verification_code";

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

interface CloudBinding { subject: string | null; configured: boolean; ownership_verified: boolean; scope_confirmed: boolean }
interface CloudChallenge { challenge: string; audience: string; proof_token: string; host_url: string; expires_at: number }

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

export function OwnershipWizard({ open, onClose, onAssetsChanged, initialAsset, notice }: Props) {
  const router = useRouter();
  const { googleOwnership, optionalStatusCheck, session } = useSession();
  const [otherWays, setOtherWays] = useState(Boolean(notice));
  const resumeAt = initialAsset?.challenge ? (initialAsset.ownership_verified ? 2 : 1) : 0;
  const [step, setStep] = useState(resumeAt);
  const [url, setUrl] = useState(initialAsset?.target_url ?? (initialAsset?.name ? `https://${initialAsset.name}` : ""));
  const [challenge, setChallenge] = useState<OwnershipChallenge | null>(initialAsset?.challenge ?? null);
  const [targetUrl, setTargetUrl] = useState<string>((initialAsset as { target_url?: string } | undefined)?.target_url ?? "");
  const prohibited = FALLBACK_PROHIBITED;
  const [method, setMethod] = useState<Method>("dns_txt");
  const [verifyDetail, setVerifyDetail] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [statusCheckConsent, setStatusCheckConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [cloudBinding, setCloudBinding] = useState<CloudBinding | null>(null);
  const [cloudSubjectEntry, setCloudSubjectEntry] = useState({ host: "", value: "" });
  const [cloudChallenge, setCloudChallenge] = useState<CloudChallenge | null>(null);
  const [cloudToken, setCloudToken] = useState("");
  const [cloudStatus, setCloudStatus] = useState("未設定");
  const cloudHost = (() => { try { return new URL(url).hostname; } catch { return ""; } })();
  const cloudSubject = cloudSubjectEntry.host === cloudHost ? cloudSubjectEntry.value : "";
  const cloudAdmin = session?.roles.includes("admin") ?? false;

  useEffect(() => {
    if (!open || !cloudAdmin || !cloudHost || step === 0) return;
    let active = true;
    getJSON<CloudBinding>(`/api/assets/cloud-run/binding?host=${encodeURIComponent(cloudHost)}`)
      .then((binding) => {
        if (!active) return;
        setCloudBinding(binding);
        setCloudSubjectEntry((current) => current.host === cloudHost && current.value
          ? current : { host: cloudHost, value: binding.subject || "" });
        setCloudStatus(binding.configured ? (binding.ownership_verified ? "検証成功" : "検証待ち") : "未設定");
      }).catch(() => { if (active) setCloudStatus("未設定"); });
    return () => { active = false; };
  }, [open, cloudAdmin, cloudHost, step]);

  useEffect(() => {
    if (!cloudChallenge) return;
    const delay = Math.max(0, cloudChallenge.expires_at * 1000 - Date.now());
    const timer = window.setTimeout(() => setCloudStatus("期限切れ"), delay);
    return () => window.clearTimeout(timer);
  }, [cloudChallenge]);

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
      // An existing proof (including a stored Google Domain proof for a subdomain)
      // needs no repeated OAuth. Otherwise one click registers and starts Google.
      if (res.asset.ownership_verified) {
        setStep(2);
      } else {
        setStep(1);
        if (googleOwnership) {
          try {
            const next = await postJSON<{ url: string }>("/api/assets/google/start", { url: url.trim() });
            try { sessionStorage.setItem("vulnix_google_pending_host", res.asset.name); } catch { /* ignore */ }
            window.location.assign(next.url);
          } catch {
            setOtherWays(true);
            setVerifyDetail("Google での確認を開始できませんでした。DNS または確認用ファイルでお試しください。");
          }
        }
      }
    });

  const viaGoogle = () =>
    run(async () => {
      const res = await postJSON<{ url: string }>("/api/assets/google/start", { url: url.trim() });
      try { sessionStorage.setItem("vulnix_google_pending_host", new URL(url.trim()).hostname); } catch { /* ignore */ }
      window.location.assign(res.url);       // Google, then back to /verify/google
    });

  const verify = () =>
    run(async () => {
      setVerifyDetail(null);
      const res = await postJSON<VerifyResponse>("/api/assets/verify-ownership", { url: url.trim(), method });
      onAssetsChanged(res.assets);
      setVerifyDetail(res.verification.detail);
      if (res.verified) setStep(2);
    });

  const registerCloud = () => run(async () => {
    const binding = await postJSON<CloudBinding & { assets: Asset[] }>("/api/assets/cloud-run/register",
      { host: cloudHost, subject: cloudSubject.trim() });
    setCloudBinding(binding);
    setCloudChallenge(null);
    setCloudStatus("検証待ち");
    onAssetsChanged(binding.assets);
  });

  const issueCloud = () => run(async () => {
    const issued = await postJSON<CloudChallenge>("/api/assets/cloud-run/issue", { host: cloudHost });
    setCloudChallenge(issued);
    setCloudStatus("検証待ち");
  });

  const finishCloud = () => run(async () => {
    if (!cloudChallenge) return;
    if (Date.now() / 1000 >= cloudChallenge.expires_at) { setCloudStatus("期限切れ"); return; }
    const res = await postJSON<VerifyResponse>("/api/assets/cloud-run/finish",
      { host: cloudHost, challenge: cloudChallenge.challenge, id_token: cloudToken.trim() });
    onAssetsChanged(res.assets);
    setCloudChallenge(null);
    setCloudToken("");
    setVerifyDetail(res.verification.detail);
    setCloudStatus(res.verified ? "検証成功" : "検証待ち");
    if (res.verified) setStep(2);
  });

  const revokeCloud = () => run(async () => {
    const res = await postJSON<{ assets: Asset[] }>("/api/assets/cloud-run/revoke", { host: cloudHost });
    onAssetsChanged(res.assets);
    setCloudBinding(null);
    setCloudChallenge(null);
    setCloudStatus("失効");
  });

  const confirmScope = () =>
    run(async () => {
      const res = await postJSON<ScopeResponse>("/api/assets/confirm-scope", {
        url: url.trim(),
        confirmed_prohibited: confirmed,
        allow_status_probe: optionalStatusCheck && statusCheckConsent,
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
              あなたが管理しているサイトだけを診断できます。所有確認には、利用可能なGoogle連携、DNS、確認用ファイルを使います。診断は所有確認と範囲の確定後に始まります。
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
                {busy ? "準備中…" : googleOwnership ? "Google で所有確認" : "所有確認へ"}
              </button>
            </div>
          </form>
        )}

        {step === 1 && challenge && (
          <div className="space-y-3 text-sm">
            {cloudAdmin && (
              <section className="space-y-2 rounded-xl border border-zinc-300 p-3 text-xs dark:border-zinc-700">
                <h3 className="font-semibold">Cloud Run OIDC 所有確認</h3>
                <p role="status">状態: {cloudStatus}</p>
                <label className="block">登録するサービスアカウントの sub
                  <input value={cloudSubject} onChange={(e) => setCloudSubjectEntry({ host: cloudHost, value: e.target.value })}
                    className="mt-1 w-full rounded border border-zinc-300 px-2 py-1 dark:border-zinc-700 dark:bg-zinc-950" />
                </label>
                <div className="flex gap-2">
                  <button type="button" disabled={busy || !cloudSubject.trim()} onClick={registerCloud} className="rounded border px-2 py-1 disabled:opacity-50">主体を登録</button>
                  <button type="button" disabled={busy || !cloudBinding?.configured} onClick={revokeCloud} className="rounded border px-2 py-1 disabled:opacity-50">登録を解除</button>
                  <button type="button" disabled={busy || !cloudBinding?.configured} onClick={issueCloud} className="rounded border px-2 py-1 disabled:opacity-50">チャレンジ発行</button>
                </div>
                {cloudChallenge && (
                  <div className="space-y-2">
                    <CopyRow label="対象" value={cloudChallenge.host_url} />
                    <CopyRow label="aud" value={cloudChallenge.audience} />
                    <CopyRow label="meta" value={`<meta name="vulnix-verify" content="${cloudChallenge.proof_token}">`} />
                    <p>有効期限: {new Date(cloudChallenge.expires_at * 1000).toLocaleString()}</p>
                    <label className="block">Google署名付き ID トークン
                      <textarea value={cloudToken} onChange={(e) => setCloudToken(e.target.value)}
                        className="mt-1 w-full rounded border border-zinc-300 px-2 py-1 dark:border-zinc-700 dark:bg-zinc-950" />
                    </label>
                    <button type="button" disabled={busy || !cloudToken.trim()} onClick={finishCloud}
                      className="rounded border px-2 py-1 disabled:opacity-50">Cloud Run で確認</button>
                  </div>
                )}
              </section>
            )}
            {notice && (
              <p role="status" className="rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
                {notice}
              </p>
            )}
            {googleOwnership && (
              <div className="rounded-xl border border-zinc-900 p-3 dark:border-white">
                <p className="mb-2 text-xs text-zinc-600 dark:text-zinc-300">
                  Google Search Console でこのサイトの所有者になっている Google アカウントで確認できます（読み取りのみ）。
                </p>
                <button type="button" disabled={busy} onClick={viaGoogle}
                  className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900">
                  {busy ? "Google に移動しています…" : "Google で確認する"}
                </button>
              </div>
            )}
            {googleOwnership && !otherWays ? (
              <button type="button" onClick={() => setOtherWays(true)} className="text-xs text-zinc-500 underline hover:text-zinc-800 dark:hover:text-zinc-200">
                Google で確認できない場合（DNS・確認用ファイル）
              </button>
            ) : (
              <>
            <p className="text-xs text-zinc-600 dark:text-zinc-300">
              次のどちらかを設定してから「確認する」を押してください（DNS の場合、反映まで数分かかることがあります）。
            </p>
            <fieldset className="space-y-2">
              <legend className="sr-only">確認方法</legend>
              <label className={`block cursor-pointer rounded-xl border p-3 ${method === "dns_txt" ? "border-zinc-900 dark:border-white" : "border-zinc-200 dark:border-zinc-800"}`}>
                <span className="flex items-center gap-2 text-xs font-semibold">
                  <input type="radio" name="own-method" checked={method === "dns_txt"} onChange={() => setMethod("dns_txt")} />
                  DNS に TXT レコードを追加
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
              <label className={`block cursor-pointer rounded-xl border p-3 ${method === "meta_tag" ? "border-zinc-900 dark:border-white" : "border-zinc-200 dark:border-zinc-800"}`}>
                <span className="flex items-center gap-2 text-xs font-semibold">
                  <input type="radio" name="own-method" checked={method === "meta_tag"} onChange={() => setMethod("meta_tag")} />
                  トップページの &lt;head&gt; に meta タグを追加
                </span>
                <dl className="mt-2 space-y-1.5">
                  <CopyRow label="URL" value={challenge.meta_tag_url || challenge.well_known_url.replace(/\/\.well-known\/vulnix-verify\.txt$/, "/")} />
                  <CopyRow label="タグ" value={challenge.meta_tag_html || `<meta name="vulnix-verify" content="${challenge.token}">`} />
                </dl>
              </label>
              <label className={`block cursor-pointer rounded-xl border p-3 ${method === "verification_code" ? "border-zinc-900 dark:border-white" : "border-zinc-200 dark:border-zinc-800"}`}>
                <span className="flex items-center gap-2 text-xs font-semibold">
                  <input type="radio" name="own-method" checked={method === "verification_code"} onChange={() => setMethod("verification_code")} />
                  管理画面に検証コードを設定（公開ページへ反映）
                </span>
                <dl className="mt-2 space-y-1.5">
                  <CopyRow label="コード" value={challenge.code || challenge.token} />
                </dl>
                <p className="mt-2 text-xs text-zinc-500">このコードは同じ対象の再確認に使えます。確認結果は範囲確定まで24時間有効で、診断中も接続先を定期的に再確認します。</p>
              </label>
            </fieldset>
            {verifyDetail && (
              <p role="status" className="rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
                {verifyDetail}
              </p>
            )}
            <div className="flex justify-end">
              <button type="button" disabled={busy} onClick={verify} className="rounded-lg bg-zinc-900 px-4 py-2 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900">
                {busy ? "確認中…" : "確認する"}
              </button>
            </div>
              </>
            )}
            <div>
              <button type="button" onClick={() => setStep(0)} className="rounded-lg border border-zinc-300 px-3 py-2 text-xs hover:bg-zinc-50 dark:border-zinc-700 dark:hover:bg-zinc-800">
                ← URLを修正
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
                結果と対策を表示します。公開ページだけでは判断できない項目は、未計測の候補として区別します。
              </p>
              {optionalStatusCheck && <p className="mb-1.5">
                希望する場合は、AIが必要と判断したときに限り、Apacheの状態情報が公開されているか
                <code className="mx-1">/server-status?auto</code>を追加で最大1回確認できます。
              </p>}
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
            {optionalStatusCheck && <label className="flex cursor-pointer items-start gap-2.5 text-xs">
              <input type="checkbox" checked={statusCheckConsent} onChange={(e) => setStatusCheckConsent(e.target.checked)} className="mt-0.5 rounded border-zinc-300" />
              <span>AIが提案した場合、上記の固定パスへの追加の読み取りを最大1回許可します（任意）。</span>
            </label>}
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
