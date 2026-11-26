"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { assetProject, ProjectOverview } from "@/components/ProjectOverview";
import { CloudInventory } from "@/components/CloudInventory";
import { useSession } from "@/lib/useSession";
import { Suspense, useEffect, useState } from "react";
import { AssetRegistrationModal } from "@/components/AssetRegistrationModal";
import { OwnershipWizard } from "@/components/OwnershipWizard";
import { Card, Pill } from "@/components/ui";
import { getJSON, postJSON } from "@/lib/api";
import type { Asset, Snapshot } from "@/lib/types";

const STATUS_CLS: Record<string, string> = {
  診断済み: "bg-emerald-100 text-emerald-900 dark:bg-emerald-900/50 dark:text-emerald-100",
  診断中: "bg-blue-600 text-white",
  一時停止中: "bg-amber-400 text-amber-950",
  中止: "bg-red-700 text-white",
  承認待ち: "bg-amber-200 text-amber-950",
  所有確認待ち: "bg-amber-200 text-amber-950",
  範囲確認待ち: "bg-sky-200 text-sky-950",
  未診断: "bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-100",
};

export default function AssetsPage() {
  return <Suspense fallback={null}><Assets /></Suspense>;
}

function Assets() {
  const router = useRouter();
  const { session, org } = useSession();
  const params = useSearchParams();
  const orgKey = `${session?.operator ?? ""}:${org?.id ?? ""}`;
  const [assets, setAssets] = useState<Asset[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState<Asset | null>(null);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [wizardAsset, setWizardAsset] = useState<Asset | null>(null);
  const [cloudTarget, setCloudTarget] = useState<{ url: string; orgKey: string; project: string } | null>(null);

  const requestedProject = params.get("project") ?? "";
  const project = requestedProject && assets?.some((a) => assetProject(a) === requestedProject) ? requestedProject : "";
  const visible = project ? assets?.filter((a) => assetProject(a) === project) : assets;
  const canEdit = Boolean(session?.roles.some((role) => ["operator", "approver", "admin"].includes(role)));

  useEffect(() => {
    let active = true;
    getJSON<Asset[]>("/api/assets").then((rows) => { if (active) setAssets(rows); }, (e) => { if (active) setErr(e.message); });
    return () => { active = false; };
  }, [orgKey]);

  const saveProject = async (asset: Asset, label: string) => {
    setBusyId(asset.id);
    setErr(null);
    try {
      const result = await postJSON<{ assets: Asset[] }>("/api/assets/project", {id: asset.id, project_label: label});
      setAssets(result.assets);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusyId(null);
    }
  };

  const handleSelectAsset = async (a: Asset) => {
    if (!a.assessment_id) return;
    setBusyId(a.id);
    setErr(null);
    try {
      const { snapshot } = await postJSON<{ snapshot: Snapshot }>("/api/assets/select", { id: a.id });
      if (snapshot.asset.id !== a.id) throw new Error("対象が切り替わりました。サイトを選び直してください。");
      router.push(`/assessments/${snapshot.id}`);
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
      // The error stays on screen (e.g. the asset was deleted but a worker could not be
      // confirmed stopped). The list is re-read so it shows what the server actually holds.
      setErr((e as Error).message);
      getJSON<Asset[]>("/api/assets").then(setAssets, () => {});
    } finally {
      setBusyId(null);
    }
  };

  return (
    <main className="mx-auto max-w-5xl p-4 md:p-8">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="mb-1 text-2xl font-bold">診断対象の管理</h1>
          <p className="text-sm text-zinc-500">
            Webサイト、API、クラウドをプロジェクトにまとめます。診断には対象ごとの所有確認と許可が必要です。
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => {
              setCloudTarget(null);
              setWizardAsset(null);
              setWizardOpen(true);
            }}
            className="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-semibold text-white hover:bg-zinc-700 dark:bg-white dark:text-zinc-900"
          >
            ＋ サイトを診断する
          </button>
          <button
            type="button"
            onClick={() => {
              setEditingAsset(null);
              setModalOpen(true);
            }}
            className="rounded-lg border border-zinc-300 px-4 py-2 text-sm font-semibold hover:bg-zinc-50 dark:border-zinc-700 dark:hover:bg-zinc-800"
          >
            練習用サイトを追加
          </button>
        </div>
      </div>

      {assets && <ProjectOverview assets={assets} selected={project} page="/assets" />}
      {session && <CloudInventory key={orgKey} projectLabel={project} onChoose={(url, cloudProject) => {
        setCloudTarget({ url, orgKey, project: project || cloudProject });
        setWizardAsset(null);
        setWizardOpen(true);
      }} />}
      {err && <p role="alert" className="mb-4 rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950/40 dark:text-red-200">{err}</p>}
      {!assets && !err && <p className="text-sm text-zinc-500">読み込み中…</p>}

      <Card className="overflow-hidden p-0">
        <table role="table" aria-label="登録済みのサイト" className="block w-full text-sm md:table">
          <thead className="hidden md:table-header-group border-b border-zinc-200 bg-zinc-50 text-left text-xs text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900/60">
            <tr>
              <th scope="col" className="px-4 py-2 font-medium">資産</th>
              <th scope="col" className="hidden px-4 py-2 font-medium md:table-cell">種別</th>
              <th scope="col" className="hidden px-4 py-2 font-medium md:table-cell">環境</th>
              <th scope="col" className="px-4 py-2 font-medium">状態</th>
              <th scope="col" className="px-4 py-2 font-medium">リスク（前回比）</th>
              <th scope="col" className="px-4 py-2 text-right font-medium">操作</th>
            </tr>
          </thead>
          <tbody role="rowgroup" className="block md:table-row-group">
            {visible?.map((a) => (
              <tr key={a.id} role="row" className="grid min-w-0 grid-cols-2 md:table-row border-b border-zinc-100 last:border-0 dark:border-zinc-800/60">
                <td role="cell" className="col-span-2 min-w-0 px-4 py-3 md:table-cell">
                  <div className="break-all font-medium">{a.display_name ?? a.name}</div>
                  {a.display_name && <div className="break-all font-mono text-[11px] text-zinc-500">{a.name}</div>}
                  {assetProject(a) && <p className="break-words text-xs text-zinc-600 dark:text-zinc-300">プロジェクト {assetProject(a)}</p>}
                  {canEdit && a.id !== "lab" && <details className="mt-2 text-xs">
                    <summary className="cursor-pointer underline">プロジェクトを設定</summary>
                    <form className="mt-2 flex flex-wrap items-end gap-2" onSubmit={(e) => {
                      e.preventDefault();
                      const name = new FormData(e.currentTarget).get("name");
                      if (typeof name === "string") void saveProject(a, name);
                    }}>
                      <label>プロジェクト名
                        <input key={assetProject(a)} name="name" maxLength={80} defaultValue={assetProject(a)}
                          list="asset-project-names" className="ml-1 max-w-full rounded border border-zinc-300 p-1 dark:border-zinc-700" />
                      </label>
                      <button type="submit" disabled={busyId === a.id} className="rounded border border-zinc-300 px-2 py-1 dark:border-zinc-700">保存</button>
                    </form>
                  </details>}
                  {a.note && <div className="text-xs text-amber-800 dark:text-amber-300">{a.note}</div>}
                </td>
                <td className="hidden px-4 py-3 text-zinc-500 md:table-cell">{a.kind}</td>
                <td className="hidden px-4 py-3 text-zinc-500 md:table-cell">{a.environment}</td>
                <td role="cell" className="px-4 py-1 md:py-3">
                  <Pill className={STATUS_CLS[a.status] ?? "bg-zinc-200 text-zinc-800"}>{a.status}</Pill>
                </td>
                <td role="cell" className="px-4 py-1 tabular-nums md:py-3">
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
                <td role="cell" className="col-span-2 px-4 py-3 md:text-right">
                  <div className="inline-flex flex-wrap items-center gap-2 md:justify-end">
                    {a.challenge && !(a.ownership_verified && a.scope_confirmed) ? (
                      <button
                        type="button"
                        disabled={busyId === a.id}
                        onClick={() => {
                          setCloudTarget(null);
                          setWizardAsset(a);
                          setWizardOpen(true);
                        }}
                        className="rounded-md border border-amber-300 bg-amber-50 px-2.5 py-1 text-xs font-semibold text-amber-900 hover:bg-amber-100 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200"
                      >
                        {a.ownership_verified ? "範囲確認へ進む" : "所有確認を進める"}
                      </button>
                    ) : a.assessment_id ? (
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

      <datalist id="asset-project-names">
        {[...new Set((assets ?? []).map(assetProject).filter(Boolean))].map((name) => <option key={name} value={name} />)}
      </datalist>
      <OwnershipWizard
        key={`wizard-${wizardAsset?.id ?? cloudTarget?.url ?? "new"}-${wizardOpen}-${orgKey}`}
        open={wizardOpen && (!cloudTarget || cloudTarget.orgKey === orgKey)}
        onClose={() => setWizardOpen(false)}
        initialAsset={wizardAsset}
        initialUrl={cloudTarget?.orgKey === orgKey ? cloudTarget.url : undefined}
        projectLabel={wizardAsset ? assetProject(wizardAsset) : cloudTarget?.orgKey === orgKey ? cloudTarget.project : project}
        knownAssets={assets}
        onAssetsChanged={setAssets}
      />
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
