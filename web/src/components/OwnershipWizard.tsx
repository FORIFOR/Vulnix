"use client";

import { useRouter } from "next/navigation";
import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiHttpError, getJSON, postJSON } from "@/lib/api";
import type { Asset, OwnershipChallenge, Snapshot } from "@/lib/types";
import { assetProject, projectHref } from "./ProjectOverview";
import { canApprove, useSession } from "@/lib/useSession";

interface Props {
  open: boolean;
  onClose: () => void;
  onAssetsChanged: (assets: Asset[]) => void;
  /** Resume the flow for an asset that already has a challenge. */
  initialAsset?: Asset | null;
  initialUrl?: string;
  projectLabel?: string;
  knownAssets?: Asset[] | null;
  /** shown on the ownership step (e.g. Google could not confirm this site) */
  notice?: string | null;
}

type Method = "google_search_console" | "dns_txt" | "well_known" | "meta_tag" | "verification_code";

interface OwnershipTraffic {
  status: "not_requested" | "pending" | "approved" | "rejected" | "expired";
  id?: string;
  expires_at?: number;
  can_decide: boolean;
  can_verify: boolean;
  stopped: boolean;
}

const TRAFFIC_STATUS = {
  not_requested: "未申請", pending: "申請中", approved: "承認済み",
  rejected: "拒否", expired: "期限切れ",
};

const METHOD_CARDS = [
  { id: "google_search_console", name: "Google", hint: "Search Console の所有者アカウント" },
  { id: "dns_txt", name: "DNS", hint: "ドメインの設定に確認情報を追加" },
  { id: "well_known", name: "確認用ファイル", hint: "サイトにテキストファイルを置く" },
] as const;

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

const STEPS = ["URLを入力", "所有確認", "診断範囲"] as const;

function endpoint(value: string): string | null {
  try {
    const url = new URL(value.includes("://") ? value : `https://${value}`);
    if (!["https:", "http:"].includes(url.protocol) || url.username || url.password) return null;
    return `${url.protocol}//${url.hostname.replace(/\.$/, "")}${url.port ? `:${url.port}` : ""}`;
  } catch {
    return null;
  }
}

function supportsFileProof(value: string) {
  const target = endpoint(value);
  if (!target) return true;
  const parsed = new URL(target);
  return parsed.protocol === "https:" && !parsed.port;
}

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

export function OwnershipWizard({ open, onClose, onAssetsChanged, initialAsset, initialUrl, projectLabel, knownAssets, notice }: Props) {
  const router = useRouter();
  const { googleOwnership, ownershipTrafficMode, optionalStatusCheck, externalSiteTrafficEnabled, session } = useSession();
  const [cloudOpen, setCloudOpen] = useState(false);
  const resumeAt = initialAsset?.challenge ? (initialAsset.ownership_verified ? 2 : 1) : 0;
  const [step, setStep] = useState(resumeAt);
  const [url, setUrl] = useState(initialAsset?.target_url ?? (initialAsset?.name ? `https://${initialAsset.name}` : initialUrl ?? ""));
  const [challenge, setChallenge] = useState<OwnershipChallenge | null>(initialAsset?.challenge ?? null);
  const [targetUrl, setTargetUrl] = useState<string>((initialAsset as { target_url?: string } | undefined)?.target_url ?? "");
  const prohibited = FALLBACK_PROHIBITED;
  const recommendedMethod: Method = googleOwnership ? "google_search_console" : supportsFileProof(url) ? "well_known" : "dns_txt";
  const [method, setMethod] = useState<Method>(recommendedMethod);
  const [proofTraffic, setProofTraffic] = useState<{ key: string; value: OwnershipTraffic } | null>(null);
  const [copiedDns, setCopiedDns] = useState(false);
  const [registeredAsset, setRegisteredAsset] = useState<Asset | null | undefined>(initialAsset);
  const [verifyDetail, setVerifyDetail] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [statusCheckConsent, setStatusCheckConsent] = useState(false);
  const [failedReuse, setFailedReuse] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [cloudBinding, setCloudBinding] = useState<CloudBinding | null>(null);
  const [cloudSubjectEntry, setCloudSubjectEntry] = useState({ host: "", value: "" });
  const [cloudChallenge, setCloudChallenge] = useState<CloudChallenge | null>(null);
  const [cloudToken, setCloudToken] = useState("");
  const [cloudStatus, setCloudStatus] = useState("未設定");
  const cloudHost = (() => { try { return new URL(url).hostname; } catch { return ""; } })();
  const cloudSubject = cloudSubjectEntry.host === cloudHost ? cloudSubjectEntry.value : "";
  const trafficBlocked = externalSiteTrafficEnabled === false;
  const cloudAdmin = session?.roles.includes("admin") ?? false;
  const canRegister = Boolean(session?.roles.some((role) => ["operator", "approver", "admin"].includes(role)));
  const canConfirmScope = canApprove(session);
  const fileAvailable = supportsFileProof(url);
  const approvalRequired = ownershipTrafficMode === "approved";
  const proofMethod = cloudOpen ? "cloud_run_oidc" : method;
  const proofUrl = targetUrl || url.trim();
  const proofKey = `${proofUrl}:${proofMethod}`;
  const permission = proofTraffic?.key === proofKey ? proofTraffic.value : null;
  const expires = permission?.expires_at;
  const proofAllowed = ownershipTrafficMode === "existing" || (approvalRequired && permission?.can_verify === true);

  useEffect(() => {
    if (!open || step !== 1 || !approvalRequired || !proofUrl || !canRegister) return;
    let active = true;
    const read = async () => {
      try {
        const value = await postJSON<OwnershipTraffic>("/api/assets/ownership-traffic", { action: "status", url: proofUrl, method: proofMethod });
        if (active) setProofTraffic({ key: proofKey, value });
      } catch {
        if (active) setProofTraffic(null);
      }
    };
    void read();
    const timer = window.setInterval(read, 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, [open, step, approvalRequired, proofUrl, proofMethod, proofKey, canRegister]);

  useEffect(() => {
    if (!open || !cloudAdmin || !cloudHost || !cloudOpen || step !== 1) return;
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
  }, [open, cloudAdmin, cloudHost, cloudOpen, step]);

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
      const message = (e as Error).message;
      setErr(e instanceof ApiHttpError && e.status === 401
        ? "ログインが切れました。ログインし直してから操作してください。"
        : e instanceof ApiHttpError && e.status === 403
          ? `${message} 現在の組織と、この対象を操作できる権限を確認してください。`
          : message);
    } finally {
      setBusy(false);
    }
  };

  const requested = endpoint(url.trim());
  const targetName = registeredAsset && (step > 0 || endpoint(registeredAsset.target_url ?? "") === requested)
    ? registeredAsset.display_name || registeredAsset.name
    : requested ? new URL(requested).hostname : "診断対象";
  const permittedAsset = requested && !trafficBlocked && failedReuse !== requested && knownAssets?.find((asset) => asset.challenge && asset.ownership_verified &&
    asset.scope_confirmed && asset.assessment_id && asset.target_url && endpoint(asset.target_url) === requested);

  const issue = () =>
    run(async () => {
      if (permittedAsset) {
        if (projectLabel && assetProject(permittedAsset) !== projectLabel) {
          const grouped = await postJSON<{ assets: Asset[] }>("/api/assets/project", {
            id: permittedAsset.id, project_label: projectLabel,
          });
          onAssetsChanged(grouped.assets);
        }
        try {
          await postJSON("/api/assets/select", { id: permittedAsset.id });
        } catch (error) {
          setFailedReuse(requested);
          throw error;
        }
        onClose();
        router.push(`/assessments/${permittedAsset.assessment_id}`);
        return;
      }
      const verified = requested && knownAssets?.find((asset) => asset.challenge && asset.ownership_verified
        && asset.target_url && endpoint(asset.target_url) === requested);
      if (verified) {
        setRegisteredAsset(verified);
        setTargetUrl(verified.target_url ?? url.trim());
        setStep(2);
        return;
      }
      setMethod(recommendedMethod);
      const res = await postJSON<ChallengeResponse>("/api/assets/challenge", { url: url.trim(), ...(projectLabel ? { project_label: projectLabel } : {}) });
      const registered = res.assets.find((asset) => asset.id === res.asset.id) ?? res.asset;
      setRegisteredAsset(registered);
      setChallenge(res.challenge);
      setTargetUrl((res.asset as { target_url?: string }).target_url ?? url.trim());
      onAssetsChanged(res.assets);
      setStep(registered.ownership_verified ? 2 : 1);
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

  const changeTraffic = (action: "request" | "approve" | "reject") => run(async () => {
    const value = await postJSON<OwnershipTraffic>("/api/assets/ownership-traffic", {
      url: proofUrl, method: proofMethod, action, ...(action !== "request" ? { id: permission?.id } : {}),
    });
    setProofTraffic({ key: proofKey, value });
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
      <div className="max-h-[90dvh] w-full max-w-xl overflow-y-auto rounded-2xl border border-zinc-200 bg-white p-4 shadow-xl sm:p-6 dark:border-zinc-800 dark:bg-zinc-900">
        <div className="sticky -top-4 z-10 -mx-4 mb-3 space-y-2 bg-white px-4 pb-2 pt-3 sm:-top-6 sm:-mx-6 sm:px-6 dark:bg-zinc-900">
          <div className="flex items-start justify-between gap-2">
            <div>
              <h2 id="ownership-wizard-title" className="text-lg font-bold">サイトを診断する</h2>
              <p className="mt-0.5 text-sm text-zinc-600 dark:text-zinc-300">所有確認と診断の許可を、順に確認します。</p>
            </div>
            <button type="button" onClick={onClose} className="shrink-0 whitespace-nowrap rounded-lg px-2.5 py-1 text-xs text-zinc-500 hover:bg-zinc-100 dark:hover:bg-zinc-800">
              閉じる ✕
            </button>
          </div>
          <div className="rounded-xl bg-zinc-50 px-3 py-2 text-sm dark:bg-zinc-800">
            <p className="font-semibold wrap-anywhere">{targetName}</p>
            <p className="wrap-anywhere text-zinc-600 dark:text-zinc-300">{step === 0 ? (url || "URLを入力してください") : proofUrl}</p>
          </div>
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

        {!canRegister && <p role="status" className="text-sm">閲覧権限のみです。対象を登録できる担当者に所有確認を依頼してください。</p>}
        {projectLabel && <p className="mb-2 break-words text-xs text-zinc-600 dark:text-zinc-300">プロジェクト {projectLabel}</p>}
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
              <button type="submit" disabled={busy || !canRegister || !url.trim()} className="rounded-lg bg-zinc-900 px-4 py-2 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900">
                {busy ? "準備中…" : permittedAsset ? "診断ワークスペースへ" : "所有確認へ"}
              </button>
            </div>
          </form>
        )}

        {step === 1 && challenge && (
          <div className="space-y-3 text-sm">
            {notice && (
              <p role="status" className="rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
                {notice}
              </p>
            )}
            <fieldset className="space-y-2">
              <legend className="mb-2 font-semibold">所有確認の方法を選ぶ</legend>
              <div className="grid gap-2 sm:grid-cols-3">
                {METHOD_CARDS.map((option) => {
                  const unavailable = option.id === "google_search_console" ? !googleOwnership
                    : option.id === "well_known" && !fileAvailable;
                  return <label key={option.id} className={`rounded-xl border p-3 ${method === option.id ? "border-zinc-900 bg-zinc-50 dark:border-white dark:bg-zinc-800" : "border-zinc-200 dark:border-zinc-700"}`}>
                    <span className="flex items-center gap-2 font-semibold">
                      <input type="radio" name="own-method" aria-label={option.name} checked={method === option.id} disabled={unavailable}
                        onChange={() => { setMethod(option.id); setVerifyDetail(null); }} />
                      {option.name}
                    </span>
                    <span className="mt-1 block text-zinc-600 dark:text-zinc-300">{option.hint}</span>
                    {option.id === recommendedMethod && <span className="mt-1 block font-medium text-emerald-700 dark:text-emerald-300">おすすめ</span>}
                    {option.id === "google_search_console" && unavailable && <Link className="mt-1 block underline" href="/settings#ownership-google">未設定・設定状況を確認</Link>}
                    {option.id === "well_known" && unavailable && <span className="mt-1 block">HTTPSの標準ポートが必要です。</span>}
                  </label>;
                })}
              </div>
            </fieldset>
            {verifyDetail && <p role="status" className="rounded-lg bg-amber-50 p-3 dark:bg-amber-950/40">{verifyDetail}</p>}
            {approvalRequired && <div className="space-y-2 rounded-xl border border-zinc-200 p-3 dark:border-zinc-700">
              <p className="font-semibold" role="status">
                {cloudOpen ? "Cloud Run の確認通信" : "所有確認用の通信"} {permission ? TRAFFIC_STATUS[permission.status] : "状態を確認中"}
              </p>
              {expires && permission?.status === "approved" && <p>有効期限 {new Date(expires * 1000).toLocaleString("ja-JP")}</p>}
              {permission?.stopped && <p>緊急停止中です。運用担当者に確認してください。</p>}
              {permission && !permission.stopped && ["not_requested", "expired", "rejected"].includes(permission.status)
                && (proofMethod !== "google_search_console" || googleOwnership)
                && (proofMethod === "dns_txt" || proofMethod === "google_search_console" || fileAvailable)
                && <button type="button" disabled={busy} onClick={() => changeTraffic("request")} className="rounded-lg border px-3 py-2 font-medium">
                  管理者に所有確認の許可を依頼する
                </button>}
              {permission?.can_decide && <div className="flex flex-wrap gap-2">
                <button type="button" disabled={busy} onClick={() => changeTraffic("approve")} className="rounded-lg border px-3 py-2">この方法を15分間承認する</button>
                <button type="button" disabled={busy} onClick={() => changeTraffic("reject")} className="rounded-lg border px-3 py-2">拒否する</button>
              </div>}
            </div>}
            {ownershipTrafficMode === "off" && <p role="status" className="rounded-lg bg-amber-50 p-3 dark:bg-amber-950/40">
              所有確認の通信は停止中です。<Link className="underline" href="/settings#ownership-google">設定状況を確認</Link>
            </p>}
            {!cloudOpen && <div className="flex flex-wrap justify-end gap-2">
              <button type="button" disabled={busy || !proofAllowed || !canRegister || (method === "google_search_console" && !googleOwnership)
                || (method !== "dns_txt" && method !== "google_search_console" && !fileAvailable)}
                onClick={method === "google_search_console" ? viaGoogle : verify}
                className="rounded-lg bg-zinc-900 px-4 py-2 font-semibold text-white disabled:opacity-50 dark:bg-white dark:text-zinc-900">
                {busy ? "確認中…" : method === "google_search_console" ? "Google で確認する" : "確認する"}
              </button>
            </div>}
            {method === "well_known" && fileAvailable && canRegister && ownershipTrafficMode !== "off" && (
              <div className="space-y-2 rounded-lg bg-zinc-50 p-3 dark:bg-zinc-800">
                <p>ファイルを下のURLで公開してください。</p>
                <dl><CopyRow label="URL" value={challenge.well_known_url} /></dl>
                <a className="inline-block font-semibold underline" download="vulnix-verify.txt"
                  href={`data:text/plain;charset=utf-8,${encodeURIComponent(challenge.well_known_content)}`}>確認用ファイルをダウンロード</a>
              </div>
            )}
            {method === "dns_txt" && canRegister && ownershipTrafficMode !== "off" && (
              <div className="space-y-2 rounded-lg bg-zinc-50 p-3 dark:bg-zinc-800">
                <p>ドメインの設定でTXTレコードを追加してください。</p>
                <dl className="space-y-1.5">
                  <CopyRow label="名前" value={challenge.dns_txt_name} />
                  <CopyRow label="値" value={challenge.dns_txt_value} />
                </dl>
                <button type="button" className="font-semibold underline" onClick={() => {
                  void run(async () => {
                    await navigator.clipboard.writeText(`${challenge.dns_txt_name}\t${challenge.dns_txt_value}`);
                    setCopiedDns(true);
                  });
                }}>{copiedDns ? "名前と値をコピーしました" : "名前と値をまとめてコピー"}</button>
              </div>
            )}
            <details className="space-y-2">
              <summary className="cursor-pointer text-sm">その他の確認方法</summary>
              <label className="block"><input type="radio" name="own-method" checked={method === "meta_tag"}
                disabled={!fileAvailable} onChange={() => setMethod("meta_tag")} /> HTMLに確認タグを追加</label>
              {method === "meta_tag" && canRegister && ownershipTrafficMode !== "off" && <dl>
                <CopyRow label="タグ" value={challenge.meta_tag_html || `<meta name="vulnix-verify" content="${challenge.token}">`} />
              </dl>}
              <label className="block"><input type="radio" name="own-method" checked={method === "verification_code"}
                disabled={!fileAvailable} onChange={() => setMethod("verification_code")} /> 管理画面に確認コードを設定</label>
              {method === "verification_code" && canRegister && ownershipTrafficMode !== "off" && <dl>
                <CopyRow label="コード" value={challenge.code || challenge.token} />
              </dl>}
            </details>
            {cloudAdmin && ownershipTrafficMode !== "off" && fileAvailable && (
              <details onToggle={(event) => setCloudOpen(event.currentTarget.open)} className="space-y-2 rounded-xl border border-zinc-300 p-3 text-xs dark:border-zinc-700">
                <summary className="cursor-pointer font-semibold">詳細設定（Cloud Run OIDC 所有確認）</summary>
                {cloudOpen && <div className="space-y-2">
                <p role="status">状態 {cloudStatus}</p>
                <label className="block">サービスアカウントの識別子（sub）
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
                    <button type="button" disabled={busy || !proofAllowed || !cloudToken.trim()} onClick={finishCloud}
                      className="rounded border px-2 py-1 disabled:opacity-50">Cloud Run で確認</button>
                  </div>
                )}
              </div>}
              </details>
            )}
            <div className="flex flex-wrap items-center gap-3">
              <button type="button" onClick={onClose} className="underline">所有確認を後で行う</button>
              <Link className="underline" href={projectHref("/quick-defense", projectLabel ?? "")}>ソースコード・SBOM診断へ進む</Link>
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
            {!canConfirmScope && <p role="status" className="text-sm">所有確認は完了しています。診断範囲の確定は、この組織の承認責任者に依頼してください。</p>}
            {trafficBlocked && <p role="status" className="text-sm">実サイトへの通信が停止中です。運用担当者にこの対象の許可範囲と受入環境を確認してください。</p>}
            <label className="flex cursor-pointer items-start gap-2.5 text-xs">
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} className="mt-0.5 rounded border-zinc-300" />
              <span>このサイトの管理者として、上記の内容で診断することに同意します。</span>
            </label>
            {optionalStatusCheck && <label className="flex cursor-pointer items-start gap-2.5 text-xs">
              <input type="checkbox" checked={statusCheckConsent} onChange={(e) => setStatusCheckConsent(e.target.checked)} className="mt-0.5 rounded border-zinc-300" />
              <span>AIが提案した場合、上記の固定パスへの追加の読み取りを最大1回許可します（任意）。</span>
            </label>}
            <div className="flex justify-end">
              <button type="button" disabled={busy || trafficBlocked || !canConfirmScope || !confirmed} onClick={confirmScope} className="rounded-lg bg-zinc-900 px-4 py-2 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900">
                {busy ? "保存しています…" : "診断範囲を保存"}
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
