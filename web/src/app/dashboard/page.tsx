"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { AssetRegistrationModal } from "@/components/AssetRegistrationModal";
import { RiskScore } from "@/components/findings/RiskScore";
import { Card, Pill } from "@/components/ui";
import { getJSON, postJSON } from "@/lib/api";
import type { Asset } from "@/lib/types";

const STATUS_CLS: Record<string, string> = {
  診断済み: "bg-emerald-100 text-emerald-900 dark:bg-emerald-900/50 dark:text-emerald-100",
  診断中: "bg-blue-600 text-white",
  承認待ち: "bg-amber-200 text-amber-950",
  未診断: "bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-100",
};

export default function Dashboard() {
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
          <h1 className="text-2xl font-bold">セキュリティ診断</h1>
          <p className="text-xs text-zinc-500">
            診断対象を選択・削除するか、新しい診断対象と書面許可（SOW）を登録してください。
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => {
              setEditingAsset(null);
              setModalOpen(true);
            }}
            className="rounded-lg border border-zinc-300 bg-white px-3.5 py-2 text-sm font-semibold text-zinc-900 hover:bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:hover:bg-zinc-800"
          >
            ＋ 診断対象を登録
          </button>
          <Link
            href="/assessments/scan_001"
            className="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-semibold text-white hover:bg-zinc-700 dark:bg-white dark:text-zinc-900"
          >
            新しい診断を開始 →
          </Link>
        </div>
      </div>

      {err && <p role="alert" className="mb-4 rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950/40 dark:text-red-200">{err}</p>}
      {!assets && !err && <p className="text-sm text-zinc-500">読み込み中…</p>}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {assets?.map((a) => (
          <Card key={a.id} className="flex h-full flex-col justify-between">
            <div>
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="truncate font-semibold">{a.name}</div>
                  <div className="text-xs text-zinc-500">{a.kind}・{a.environment}</div>
                </div>
                <Pill className={STATUS_CLS[a.status] ?? "bg-zinc-200 text-zinc-800"}>{a.status}</Pill>
              </div>
              {a.authorization_ref && (
                <div className="mt-2 text-[11px] font-mono text-emerald-700 dark:text-emerald-400">
                  許可証: {a.authorization_ref}
                </div>
              )}
              <div className="mt-4">
                <RiskScore risk={a.risk} compact />
              </div>
              {a.note && <p className="mt-2 text-xs text-amber-800 dark:text-amber-300">{a.note}</p>}
            </div>

            <div className="mt-4 flex items-center justify-between gap-2 border-t border-zinc-100 pt-3 dark:border-zinc-800">
              {a.assessment_id ? (
                <button
                  type="button"
                  disabled={busyId === a.id}
                  onClick={() => handleSelectAsset(a)}
                  className="flex-1 rounded-lg bg-zinc-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900"
                >
                  {busyId === a.id ? "切替中…" : "この対象を診断 →"}
                </button>
              ) : (
                <button
                  type="button"
                  disabled={busyId === a.id}
                  onClick={() => {
                    setEditingAsset(a);
                    setModalOpen(true);
                  }}
                  className="flex-1 rounded-lg border border-amber-300 bg-amber-50 px-3 py-1.5 text-xs font-semibold text-amber-900 hover:bg-amber-100 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200"
                >
                  書面許可（SOW）を登録
                </button>
              )}
              <button
                type="button"
                disabled={busyId === a.id}
                onClick={() => handleDeleteAsset(a)}
                className="rounded-lg border border-red-200 px-2.5 py-1.5 text-xs font-medium text-red-700 hover:bg-red-50 disabled:opacity-50 dark:border-red-900/60 dark:text-red-300 dark:hover:bg-red-950/40"
                title={`${a.name} を削除`}
              >
                削除
              </button>
            </div>
          </Card>
        ))}
      </div>

      <p className="mt-6 text-xs text-zinc-500">
        未診断の資産を安全とは判定しません。診断には書面許可と所有確認が必要です。
      </p>

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
