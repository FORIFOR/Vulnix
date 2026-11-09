"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { postJSON } from "@/lib/api";
import type { Asset } from "@/lib/types";

interface Props {
  open: boolean;
  onClose: () => void;
  onRegistered: (assets: Asset[], created: Asset) => void;
  initialAsset?: Partial<Asset> | null;
}

export function AssetRegistrationModal({ open, onClose, onRegistered, initialAsset }: Props) {
  const router = useRouter();
  const [name, setName] = useState(initialAsset?.name ?? "");
  const [kind, setKind] = useState(initialAsset?.kind ?? "Webアプリケーション");
  const [environment, setEnvironment] = useState(initialAsset?.environment ?? "検証環境");
  const [authRef, setAuthRef] = useState(initialAsset?.authorization_ref ?? "SOW-2026-001");
  const [ownershipVerified, setOwnershipVerified] = useState(initialAsset?.ownership_verified ?? true);
  const [activateWorkspace, setActivateWorkspace] = useState(true);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (!open) return null;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setErr(null);
    try {
      const res = await postJSON<{ asset: Asset; assets: Asset[] }>("/api/assets", {
        name: name.trim(),
        kind,
        environment,
        authorization_ref: authRef.trim(),
        ownership_verified: ownershipVerified,
        activate_workspace: activateWorkspace,
      });
      onRegistered(res.assets, res.asset);
      onClose();
      if (activateWorkspace && res.asset.assessment_id) {
        router.push(`/assessments/${res.asset.assessment_id}`);
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-xs"
      role="dialog"
      aria-modal="true"
      aria-labelledby="asset-reg-title"
    >
      <div className="w-full max-w-lg rounded-2xl border border-zinc-200 bg-white p-6 shadow-xl dark:border-zinc-800 dark:bg-zinc-900">
        <div className="mb-4 flex items-start justify-between gap-2">
          <div>
            <h2 id="asset-reg-title" className="text-lg font-bold">
              {initialAsset?.name ? `診断許可（SOW）の登録：${initialAsset.name}` : "新しい診断対象・書面許可の登録"}
            </h2>
            <p className="mt-0.5 text-xs text-zinc-500">
              Vulnix は書面による診断許可と所有確認が完了した対象のみ診断を有効化します。
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg px-2.5 py-1 text-xs text-zinc-500 hover:bg-zinc-100 dark:hover:bg-zinc-800"
          >
            閉じる ✕
          </button>
        </div>

        <form onSubmit={submit} className="space-y-3 text-sm">
          <div>
            <label htmlFor="asset-name" className="mb-1 block text-xs font-semibold">
              対象ドメイン / ホスト名
            </label>
            <input
              id="asset-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="例: app.example.com / internal-staging"
              required
              className="w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-950"
            />
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label htmlFor="asset-kind" className="mb-1 block text-xs font-semibold">
                資産種別
              </label>
              <select
                id="asset-kind"
                value={kind}
                onChange={(e) => setKind(e.target.value)}
                className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-950"
              >
                <option value="Webアプリケーション">Webアプリケーション</option>
                <option value="API">API</option>
                <option value="検証環境">検証環境</option>
                <option value="社内システム">社内システム</option>
              </select>
            </div>
            <div>
              <label htmlFor="asset-env" className="mb-1 block text-xs font-semibold">
                環境区分
              </label>
              <select
                id="asset-env"
                value={environment}
                onChange={(e) => setEnvironment(e.target.value)}
                className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-950"
              >
                <option value="検証環境">検証環境</option>
                <option value="ステージング">ステージング</option>
                <option value="ローカル検証ラボ">ローカル検証ラボ</option>
                <option value="本番環境">本番環境（要慎重確認）</option>
              </select>
            </div>
          </div>

          <div>
            <label htmlFor="asset-auth-ref" className="mb-1 block text-xs font-semibold">
              書面許可番号（SOW / 診断合意書リファレンス）
            </label>
            <input
              id="asset-auth-ref"
              value={authRef}
              onChange={(e) => setAuthRef(e.target.value)}
              placeholder="例: SOW-2026-001（未入力の場合は「承認待ち」として登録）"
              className="w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm font-mono dark:border-zinc-700 dark:bg-zinc-950"
            />
          </div>

          <div className="space-y-2 rounded-xl border border-zinc-200 bg-zinc-50 p-3 dark:border-zinc-800 dark:bg-zinc-950/60">
            <label className="flex cursor-pointer items-start gap-2.5 text-xs">
              <input
                type="checkbox"
                checked={ownershipVerified}
                onChange={(e) => setOwnershipVerified(e.target.checked)}
                className="mt-0.5 rounded border-zinc-300"
              />
              <span>
                <strong>所有権および書面許可の確認済み：</strong>
                この対象に対する診断権限（SOW）が確認されており、Gateway のスコープ制御下に登録することを承認します。
                <span className="block text-[11px] text-zinc-500">
                  ※ チェックを外すか許可番号を空欄にすると「承認待ち（診断不可）」として安全にロックされます。
                </span>
              </span>
            </label>

            <label className="flex cursor-pointer items-center gap-2.5 text-xs">
              <input
                type="checkbox"
                checked={activateWorkspace}
                disabled={!ownershipVerified || !authRef.trim()}
                onChange={(e) => setActivateWorkspace(e.target.checked)}
                className="rounded border-zinc-300 disabled:opacity-50"
              />
              <span>登録後すぐにこの対象の診断ワークスペースを開く</span>
            </label>
          </div>

          {err && (
            <p role="alert" className="rounded-lg bg-red-50 px-3 py-2 text-xs text-red-800 dark:bg-red-950/40 dark:text-red-200">
              {err}
            </p>
          )}

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-zinc-300 px-4 py-2 text-xs font-medium hover:bg-zinc-50 dark:border-zinc-700 dark:hover:bg-zinc-800"
            >
              キャンセル
            </button>
            <button
              type="submit"
              disabled={busy || !name.trim()}
              className="rounded-lg bg-zinc-900 px-4 py-2 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900"
            >
              {busy ? "登録中…" : ownershipVerified && authRef.trim() ? "許可済み資産として登録" : "承認待ちとして登録"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
