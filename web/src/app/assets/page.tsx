"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { AssetRegistrationModal } from "@/components/AssetRegistrationModal";
import { Card, Pill } from "@/components/ui";
import { getJSON, postJSON } from "@/lib/api";
import type { Asset } from "@/lib/types";

const STATUS_CLS: Record<string, string> = {
  診断済み: "bg-emerald-100 text-emerald-900 dark:bg-emerald-900/50 dark:text-emerald-100",
  診断中: "bg-blue-600 text-white",
  一時停止中: "bg-amber-400 text-amber-950",
  中止: "bg-red-700 text-white",
  承認待ち: "bg-amber-200 text-amber-950",
  未診断: "bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-100",
};

export default function AssetsPage() {
  const router = useRouter();
  const [assets, setAssets] = useState<Asset[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState<Asset | null>(null);

  useEffect(() => {
    getJSON<Asset[]>("/api/assets").then(setAssets, (e) => setErr(e.message));
  }, []);

  const handleSelectAsset = async (a: Asset) => {
    if (!a.assessment_id) return;
    setBusyId(a.id);
    setErr(null);
    try {
      await postJSON("/api/assets/select", { id: a.id });
      router.push(`/assessments/${a.assessment_id}`);
    } catch (e) {
      setErr((e as Error).message);
      setBusyId(null);
    }
  };

  const handleDeleteAsset = async (a: Asset) => {
    setBusyId(a.id);
    setErr(null);
    try {
      const res = await postJSON<{ assets: Asset[] }>("/api/assets/delete", { id: a.id });
      setAssets(res.assets);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusyId(null);
    }
  };

  return (
    <main className="mx-auto max-w-5xl p-4 md:p-8">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="mb-1 text-2xl font-bold">資産管理・診断許可登録</h1>
          <p className="text-sm text-zinc-500">
            診断対象の一覧です。対象の切り替え・削除・書面許可（SOW）の登録が行えます。
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            setEditingAsset(null);
            setModalOpen(true);
          }}
          className="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-semibold text-white hover:bg-zinc-700 dark:bg-white dark:text-zinc-900"
        >
          ＋ 新規資産・診断許可を登録
        </button>
      </div>

      {err && <p role="alert" className="mb-4 rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950/40 dark:text-red-200">{err}</p>}
      {!assets && !err && <p className="text-sm text-zinc-500">読み込み中…</p>}

      <Card className="overflow-hidden p-0">
        <table className="w-full text-sm">
          <thead className="border-b border-zinc-200 bg-zinc-50 text-left text-xs text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900/60">
            <tr>
              <th scope="col" className="px-4 py-2 font-medium">資産</th>
              <th scope="col" className="hidden px-4 py-2 font-medium sm:table-cell">種別</th>
              <th scope="col" className="hidden px-4 py-2 font-medium md:table-cell">環境</th>
              <th scope="col" className="hidden px-4 py-2 font-medium lg:table-cell">書面許可（SOW）</th>
              <th scope="col" className="px-4 py-2 font-medium">状態</th>
              <th scope="col" className="px-4 py-2 font-medium">リスク（前回比）</th>
              <th scope="col" className="px-4 py-2 text-right font-medium">操作</th>
            </tr>
          </thead>
          <tbody>
            {assets?.map((a) => (
              <tr key={a.id} className="border-b border-zinc-100 last:border-0 dark:border-zinc-800/60">
                <td className="px-4 py-3">
                  <div className="font-medium">{a.name}</div>
                  {a.note && <div className="text-xs text-amber-800 dark:text-amber-300">{a.note}</div>}
                </td>
                <td className="hidden px-4 py-3 text-zinc-500 sm:table-cell">{a.kind}</td>
                <td className="hidden px-4 py-3 text-zinc-500 md:table-cell">{a.environment}</td>
                <td className="hidden px-4 py-3 font-mono text-xs lg:table-cell">
                  {a.authorization_ref ? (
                    <span className="text-emerald-700 dark:text-emerald-400">{a.authorization_ref}</span>
                  ) : (
                    <span className="text-amber-700 dark:text-amber-400">未登録</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <Pill className={STATUS_CLS[a.status] ?? "bg-zinc-200 text-zinc-800"}>{a.status}</Pill>
                </td>
                <td className="px-4 py-3 tabular-nums">
                  {a.risk ? (
                    <span>
                      {a.risk.score}/100
                      {typeof a.previous_risk_score === "number" && (
                        <span className="ml-1.5 text-xs text-zinc-500">
                          （前回 {a.previous_risk_score}/100）
                        </span>
                      )}
                    </span>
                  ) : typeof a.previous_risk_score === "number" ? (
                    <span className="text-xs text-zinc-500">未診断（前回 {a.previous_risk_score}/100）</span>
                  ) : (
                    <span className="text-zinc-400">—</span>
                  )}
                </td>
                <td className="px-4 py-3 text-right">
                  <div className="inline-flex items-center justify-end gap-2">
                    {a.assessment_id ? (
                      <button
                        type="button"
                        disabled={busyId === a.id}
                        onClick={() => handleSelectAsset(a)}
                        className="rounded-md bg-zinc-900 px-2.5 py-1 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900"
                      >
                        診断を開く →
                      </button>
                    ) : (
                      <button
                        type="button"
                        disabled={busyId === a.id}
                        onClick={() => {
                          setEditingAsset(a);
                          setModalOpen(true);
                        }}
                        className="rounded-md border border-amber-300 bg-amber-50 px-2.5 py-1 text-xs font-semibold text-amber-900 hover:bg-amber-100 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200"
                      >
                        許可を登録
                      </button>
                    )}
                    <button
                      type="button"
                      disabled={busyId === a.id}
                      onClick={() => handleDeleteAsset(a)}
                      className="rounded-md border border-red-200 px-2.5 py-1 text-xs font-medium text-red-700 hover:bg-red-50 disabled:opacity-50 dark:border-red-900/60 dark:text-red-300 dark:hover:bg-red-950/40"
                    >
                      削除
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <AssetRegistrationModal
        key={editingAsset?.id ?? "new"}
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        initialAsset={editingAsset}
        onRegistered={(updated) => setAssets(updated)}
      />
    </main>
  );
}
