"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { projectHref } from "./ProjectOverview";
import { postJSON } from "@/lib/api";
import { cloudExportLimit, importCloudRunService, type CloudProject, type CloudRunService } from "@/lib/cloudRunInventory";

interface Inventory { configured: boolean; projects?: CloudProject[]; incomplete?: boolean }

const actionClass = "rounded border border-zinc-300 px-3 py-2 text-sm font-semibold disabled:opacity-50";
const inputClass = "mt-1 block w-full rounded border border-zinc-300 p-2 text-sm";

export function CloudInventory({ onChoose, projectLabel }: { onChoose: (url: string, project: string) => void; projectLabel?: string }) {
  const [data, setData] = useState<Inventory>();
  const [projectId, setProjectId] = useState("");
  const [services, setServices] = useState<CloudRunService[]>([]);
  const [url, setUrl] = useState("");
  const [input, setInput] = useState("");
  const [serviceUrl, setServiceUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [cancelled, setCancelled] = useState(false);
  const [error, setError] = useState("");
  const projectGeneration = useRef(0);
  const project = data?.projects?.find((p) => p.id === projectId);
  const service = services.find((s) => s.url === url);

  useEffect(() => {
    let active = true;
    void postJSON<Inventory>("/api/assets/cloud-inventory", { action: "status" }).then(async (status) => {
      if (!active) return;
      setData(status);
      setCancelled(new URL(window.location.href).searchParams.get("inventory") === "cancelled");
      if (status.configured) {
        const result = await postJSON<Inventory>("/api/assets/cloud-inventory", { action: "projects" });
        if (active) setData(result);
      }
    }).catch(() => {
      if (active) setError("この組織では Google Cloud の閲覧連携を利用できません。URL入力から続けられます。");
    });
    return () => { active = false; };
  }, []);

  function projectChanged(next: string) {
    projectGeneration.current++;
    setProjectId(next);
    setServices([]);
    setUrl("");
    setInput("");
    setServiceUrl("");
  }

  function add(text: string, selected: CloudProject, generation: number) {
    if (generation !== projectGeneration.current) return;
    const parsed = importCloudRunService(text, selected);
    setServices((rows) => [...rows.filter((s) => s.url !== parsed.url).slice(-49), parsed]);
    setUrl(parsed.url);
    setInput("");
    setError("");
  }

  async function connect() {
    setBusy(true);
    setError("");
    try {
      const reply = await postJSON<{url: string}>("/api/assets/cloud-inventory", { action: "start" });
      window.location.assign(reply.url);
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  }

  async function clear() {
    setBusy(true);
    try {
      setData(await postJSON<Inventory>("/api/assets/cloud-inventory", { action: "clear" }));
      projectChanged("");
      setError("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return <section aria-labelledby="cloud-inventory-title" className="mb-5 space-y-3 rounded-xl border border-zinc-200 p-4 dark:border-zinc-800">
    <h2 id="cloud-inventory-title" className="font-semibold">Google Cloud から対象を選ぶ</h2>
    <p className="text-sm">連携はプロジェクト一覧の閲覧に使います。サイトの所有確認と診断実行の許可は、対象ごとに続く画面で確認します。</p>
    {error && <p role="alert" className="text-sm text-red-700 dark:text-red-300">{error}</p>}
    {cancelled && <p role="status" className="text-sm">Google Cloud との接続をキャンセルしました。</p>}
    {data?.configured === false && <p className="text-sm">閲覧連携はこの環境で未設定です。運用管理者にお問い合わせいただくか、URL入力をお使いください。</p>}
    {data?.configured && data.projects === undefined && <button type="button" onClick={connect} disabled={busy} className={actionClass}>Google Cloud に読み取り専用で接続</button>}
    {data?.projects !== undefined && <>
      <div className="flex flex-wrap gap-2">
        <button type="button" onClick={connect} disabled={busy} className={actionClass}>接続し直す</button>
        <button type="button" onClick={clear} disabled={busy} className={actionClass}>Vulnixの連携を解除</button>
      </div>
      <p className="text-xs">解除すると、このセッションのプロジェクト一覧を消去します。Google側の同意は
        <a className="mx-1 underline" target="_blank" rel="noreferrer" href="https://myaccount.google.com/connections">Googleアカウントの連携設定</a>
        で取り消せます。</p>
      {!data.projects.length ? <p className="text-sm">閲覧できるプロジェクトがありません。選んだ Google アカウントと、対象のプロジェクト閲覧権限を確認してください。</p> :
        <label className="block text-sm">プロジェクト
          <select className={inputClass} value={projectId} onChange={(e) => projectChanged(e.target.value)}>
            <option value="">プロジェクトを選択</option>
            {data.projects.map((p) => <option key={p.id} value={p.id}>{p.label} ({p.id})</option>)}
          </select>
        </label>}
      {data.incomplete && <p role="status" className="text-sm">一覧は最大300件です。表示されないサービスはURL入力から登録できます。</p>}
    </>}
    {project && <>
      <p className="text-sm">
        <a className="underline" target="_blank" rel="noreferrer" href={`https://console.cloud.google.com/run/services?project=${encodeURIComponent(project.id)}`}>Cloud Run コンソールでサービスを選ぶ</a>
        。サービス詳細のURLを入力すると、対象の所有確認へ進めます。
      </p>
      <form onSubmit={(event) => {
        event.preventDefault();
        onChoose(serviceUrl.trim(), project.id);
      }} className="flex flex-wrap items-end gap-2">
        <label className="flex-1 text-sm">サービスのURL
          <input type="url" required value={serviceUrl} onChange={(event) => setServiceUrl(event.target.value)} className={inputClass} placeholder="https://example.run.app" />
        </label>
        <button type="submit" className={actionClass} disabled={!serviceUrl.trim()}>所有確認へ</button>
      </form>
      <details className="space-y-2">
        <summary className="cursor-pointer text-sm">保存済みの配備資料を確認する</summary>
      <label className="block text-sm">サービス定義（YAML）
        <textarea className={inputClass} rows={3} maxLength={cloudExportLimit} value={input} onChange={(e) => setInput(e.target.value)} />
      </label>
      <button type="button" className={actionClass} disabled={!input.trim()} onClick={() => {
        try { add(input, project, projectGeneration.current); } catch (e) { setError((e as Error).message); }
      }}>サービス定義を取り込む</button>
      <label className="block text-sm">保存済みサービス定義を選択
        <input type="file" accept=".yaml,.yml,.json" className={inputClass} onChange={async (e) => {
          const file = e.target.files?.[0];
          e.target.value = "";
          if (!file) return;
          const generation = projectGeneration.current;
          try {
            if (file.size > cloudExportLimit) throw new Error("256 KB以下のサービス定義を選択してください。");
            add(await file.text(), project, generation);
          } catch (error) {
            if (generation === projectGeneration.current) setError((error as Error).message);
          }
        }} />
      </label>
      </details>
      {services.length > 0 && <label className="block text-sm">Cloud Run サービス
        <select className={inputClass} value={url} onChange={(e) => setUrl(e.target.value)}>
          {services.map((s) => <option key={s.url} value={s.url}>{s.name}</option>)}
        </select>
      </label>}
      {service && <div className="space-y-2 border-t border-zinc-200 pt-3 text-sm">
        <p className="break-all">{service.url}</p>
        <p className="break-all">取り込んだ配備リビジョン {service.revision ?? "未確認"}</p>
        <p className="break-all">定義上のイメージ {service.images.join("、") || "未確認"}</p>
        <p>この定義からは実際に稼働中の構成と所有権は確認できません。対象イメージのSBOMを別途照合できます。</p>
        <p>Artifact Registry で対象ダイジェストの「依存関係」から既存のSBOMを開けます。閲覧には対象リポジトリ、分析の記録、保存先ファイルへの読み取り権限が必要です。</p>
        <div className="flex flex-wrap gap-3">
          <a className="underline" target="_blank" rel="noreferrer" href={`https://console.cloud.google.com/artifacts?project=${encodeURIComponent(project.id)}`}>Artifact Registry を開く</a>
          <Link className="underline" href={`${projectHref("/quick-defense", projectLabel || project.id)}#sbom-input`}>SBOMを取り込んで調べる</Link>
        </div>
        <div><button type="button" className={actionClass} onClick={() => onChoose(service.url, project.id)}>プロジェクトに追加して所有確認へ</button></div>
      </div>}
    </>}
    {!data && !error && <p role="status" className="text-sm">連携の設定を確認しています…</p>}
  </section>;
}
