"use client";

import { useEffect, useState } from "react";
import { getJSON, postJSON } from "@/lib/api";

const endpoint = "/api/assets/local-defense";
const button = "rounded border border-zinc-300 px-2 py-1 disabled:opacity-50 dark:border-zinc-600";
type Profile = {
  plan: { id: string; test: string; review_revision: string; environment: string;
    timeout_seconds: number; conditions?: string[] };
  files: Record<string, string>;
  plan_sha256: string;
};
type Receipt = {
  run_id: string; receipt_sha256: string;
  result: { verdict: string; observation: { passed?: number; excluded?: number;
    checks?: Record<string, { verdict: string; observed?: { allow: boolean; deny: boolean } }> } | null };
};
type View = {
  actor: string; assessment: string; available: boolean; may_approve: boolean; may_request: boolean;
  profiles: Profile[];
  job: { id: string; requester: string; profile: string; status: string;
    approval: { status: string } | null; receipt: Receipt | null } | null;
};

async function hexDigest(input: BufferSource) {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function matchFolder(files: File[], profile: Profile) {
  const paths = new Map(files.map((file) => [file.webkitRelativePath.split("/").slice(1).join("/"), file]));
  const entries = Object.entries(profile.files).sort(([a], [b]) => a < b ? -1 : Number(a !== b));
  for (const [name, expected] of entries) {
    const file = paths.get(name);
    if (!file || file.size > 512 * 1024 || await hexDigest(await file.arrayBuffer()) !== expected) {
      throw new Error("選択したフォルダは、この計画のレビュー済みファイルと一致しません。");
    }
  }
  const canonical = "{" + entries.map(([name, digest]) => JSON.stringify(name) + ":" + JSON.stringify(digest)).join(",") + "}";
  return hexDigest(new TextEncoder().encode(canonical));
}

const statuses: Record<string, string> = {
  waiting: "承認待ち", running: "隔離実行中", cancelling: "中断・回収中",
  cancelled: "中断", completed: "実行完了", unverified: "証拠不足", failed: "実行に失敗", expired: "失効",
};
const checkAdvice: Record<string, [string, string]> = {
  authentication: ["認証", "セッションの存在・有効期限をサーバー側で確認し、無効な場合は操作を拒否してください。"],
  authorization: ["認可", "対象操作の必要権限をサーバー側で確認し、権限が足りない場合は処理を開始しないでください。"],
  "tenant-selection": ["テナント選択", "組織変更前に現在の所属を再照合し、所属外ならセッションを更新しないでください。"],
  "webhook-signature": ["Webhook署名", "処理前に生のリクエスト本文と署名・時刻を検証してください。"],
  "ai-policy": ["AI操作ポリシー", "許可リストと承認条件をツール呼び出し前に強制してください。"],
  mfa: ["多要素認証", "第二要素の検証に成功した場合にだけセッションを発行してください。"],
};

function verdictLabel(verdict: string) {
  return verdict === "passed" ? "動作確認済み" : verdict === "failed" ? "対策が必要" : "未確認";
}

export default function ReviewedDefense({ files }: { files: File[] }) {
  const [open, setOpen] = useState(false);
  const [view, setView] = useState<View | null>(null);
  const [choice, setChoice] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const job = view?.job;
  const active = job && ["waiting", "running", "cancelling"].includes(job.status);
  const profile = view?.profiles.find(({ plan }) => plan.id === (active ? job.profile : choice)) ?? view?.profiles[0];

  useEffect(() => {
    if (!open) return;
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    async function read() {
      try {
        const next = await getJSON<View>(endpoint);
        if (!disposed) setView(next);
      } catch (problem) {
        if (disposed) return;
        setView(null);
        setError(problem instanceof Error ? problem.message : "計画を読み込めません。");
        return;
      }
      if (!disposed) timer = setTimeout(read, 1500);
    }
    void read();
    return () => { disposed = true; clearTimeout(timer); };
  }, [open]);

  async function action(op: () => Promise<unknown>) {
    setPending(true);
    setError("");
    try {
      await op();
      setView(await getJSON<View>(endpoint));
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "操作を完了できません。");
    } finally {
      setPending(false);
    }
  }

  return <section className="space-y-2 rounded-xl border border-zinc-200 p-4 text-sm dark:border-zinc-800">
    <h2 className="font-semibold">レビュー済み防御の隔離実行</h2>
    {!open && <button type="button" className={button} onClick={() => setOpen(true)}>実行計画を見る</button>}
    {open && !view && !error && <p role="status">実行計画を取得中</p>}
    {error && <p role="alert">{error}</p>}
    {view && profile && <>
      {!active && <label className="block">検証プロファイル{" "}
        <select value={profile.plan.id} onChange={(event) => setChoice(event.target.value)}>
          {view.profiles.map(({ plan }) => <option key={plan.id} value={plan.id}>{plan.test}</option>)}
        </select>
      </label>}
      <dl className="break-all">
        <dt>対象コミット</dt><dd>{profile.plan.review_revision}</dd>
        <dt>環境・制限</dt><dd>{profile.plan.environment} ／ {profile.plan.timeout_seconds}秒・外部通信なし</dd>
        <dt>計画 SHA-256</dt><dd>{profile.plan_sha256}</dd>
      </dl>
      {profile.plan.conditions?.map((condition) => <p key={condition}>{checkAdvice[condition]?.[0] ?? condition}</p>)}
      {profile.plan.conditions?.some((condition) => checkAdvice[condition]) &&
        <p>正規操作は許可され、権限外の操作は拒否されることを確認します。</p>}
      <p>レビュー済みの対象 {Object.keys(profile.files).length} ファイルを照合します。管理側に登録済みの固定スナップショットに対して、独立した承認者の承認後に実行します。</p>
      {!view.available && <p role="status">緊急停止中か、隔離実行を利用できない状態です。</p>}
      {!active && view.may_request && <button type="button" className={button}
        disabled={!view.available || !files.length || pending}
        onClick={() => void action(async () => {
          const folder_sha256 = await matchFolder(files, profile);
          await postJSON<View>(endpoint, { action: "request", profile: profile.plan.id,
            plan_sha256: profile.plan_sha256, folder_sha256 });
        })}>{job ? "再検証を依頼する" : "実行を依頼する"}</button>}
      {job && <div className="space-y-2">
        <p role="status">{job.status === "waiting" && job.approval?.status === "approved"
          ? "承認済み・実行待ち" : statuses[job.status] ?? "未確認"} ／ 依頼者 {job.requester}</p>
        {job.status === "waiting" && job.approval?.status === "pending" && view.may_approve && view.actor !== job.requester &&
          <button type="button" className={button} disabled={pending || !view.available}
            onClick={() => void action(() => postJSON(`/api/assessments/${encodeURIComponent(view.assessment)}/approvals/${encodeURIComponent(job.id)}`, { decision: "approve" }))}>
            この計画を承認する
          </button>}
        {job.status === "waiting" && job.approval?.status === "approved" && view.actor === job.requester &&
          <button type="button" className={button} disabled={pending || !view.available || !files.length}
            onClick={() => void action(async () => {
              const folder_sha256 = await matchFolder(files, profile);
              await postJSON(endpoint, { action: "start", id: job.id, folder_sha256 });
            })}>承認済みの隔離検証を開始する</button>}
        {["waiting", "running"].includes(job.status) && (view.actor === job.requester || view.may_approve) &&
          <button type="button" className={button} disabled={pending}
            onClick={() => void action(() => postJSON(endpoint, { action: "cancel", id: job.id }))}>隔離検証を中断する</button>}
        {job.receipt && <>
          <p>ローカル隔離での結果 ／ {verdictLabel(job.receipt.result.verdict)}</p>
          {job.receipt.result.observation?.passed !== undefined && <p>選択テスト {job.receipt.result.observation.passed} 件成功 ／ 選択外 {job.receipt.result.observation.excluded} 件</p>}
          {Object.entries(job.receipt.result.observation?.checks ?? {}).map(([name, observed]) =>
            <details key={name}>
              <summary>{checkAdvice[name]?.[0] ?? name} ／ {verdictLabel(observed.verdict)}</summary>
              {observed.observed ?
                <p>正規操作 {observed.observed.allow ? "許可" : "拒否"} ／ 権限外の操作 {observed.observed.deny ? "許可" : "拒否"}</p> :
                <p>正規操作と拒否側の両方を観測できませんでした。</p>}
              {observed.verdict !== "passed" && <p>{checkAdvice[name]?.[1]} 修正後にフォルダを選び直してください。</p>}
            </details>)}
          <p className="break-all">実行ID {job.receipt.run_id} ／ 証跡 SHA-256 {job.receipt.receipt_sha256}</p>
        </>}
      </div>}
    </>}
  </section>;
}
