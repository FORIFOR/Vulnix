import Link from "next/link";
import type { Asset } from "@/lib/types";

export function assetProject(asset: Pick<Asset, "project_label" | "gcp_project">) {
  return asset.project_label ?? asset.gcp_project ?? "";
}

export function projectHref(path: string, project: string) {
  return project ? `${path}?project=${encodeURIComponent(project)}` : path;
}

export function ProjectOverview({ assets, selected, page }: {
  assets: Asset[];
  selected: string;
  page: "/assets" | "/dashboard";
}) {
  const counts = new Map<string, number>();
  for (const asset of assets) {
    const project = assetProject(asset);
    if (project) counts.set(project, (counts.get(project) ?? 0) + 1);
  }
  return <section aria-label="診断プロジェクト" className="mb-5 space-y-3 rounded-xl border border-zinc-200 p-4 dark:border-zinc-800">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <h2 className="font-semibold">診断プロジェクト</h2>
      {page === "/dashboard" && <Link className="text-sm underline" href={projectHref("/assets", selected)}>資産とクラウドを管理</Link>}
    </div>
    {counts.size > 0 ? <nav aria-label="プロジェクトで絞り込む" className="flex flex-wrap gap-2">
      <Link href={page} aria-current={selected ? undefined : "page"} className="rounded border border-zinc-300 px-2.5 py-1 text-sm aria-[current=page]:font-bold dark:border-zinc-700">すべて</Link>
      {[...counts].sort(([a], [b]) => a.localeCompare(b)).map(([name, count]) =>
        <Link key={name} href={projectHref(page, name)} aria-current={selected === name ? "page" : undefined}
          className="max-w-full break-words rounded border border-zinc-300 px-2.5 py-1 text-sm aria-[current=page]:font-bold dark:border-zinc-700">
          {name}（{count}件）
        </Link>
      )}
    </nav> : <p className="text-sm">資産管理でWebサイトやAPIに同じプロジェクト名を設定すると、まとめて表示できます。</p>}
    <div className="flex flex-wrap gap-x-4 gap-y-2 text-sm">
      <Link href={projectHref("/quick-defense", selected)} className="underline">ソースコード・SBOMを診断</Link>
      {page === "/dashboard" && <Link href={`${projectHref("/assets", selected)}#cloud-inventory-title`} className="underline">Google Cloudの対象を追加</Link>}
    </div>
    {selected && <p className="text-xs text-zinc-600 dark:text-zinc-300">所有確認と診断許可は資産ごとに必要です。フォルダ、SBOM、静的診断結果はブラウザ内で扱います。</p>}
  </section>;
}
