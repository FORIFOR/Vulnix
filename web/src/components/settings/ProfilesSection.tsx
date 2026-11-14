"use client";

import { useEffect, useState } from "react";
import { getJSON, postJSON } from "@/lib/api";
import { isPlatformAdmin, useSession } from "@/lib/useSession";

interface ProfileRow {
  id: string;
  label: string;
  file: string;
  site: boolean;
  sha256: string;
  hosts: string[];
  accepted: boolean;
  changed_since_acceptance: boolean;
  confirmed_checks: string[];
  directory: string;
  rules: RuleSummary[];
}

interface RequestSummary { account: string; token_key: string; path: string; headers: string[] }
interface Expectation { status: number[]; body_contains?: string[]; body_not_contains?: string[]; json_fields?: Record<string, unknown>; content_type?: string }
interface RuleSummary {
  id: string;
  label: string;
  request: RequestSummary;
  controls: (RequestSummary & { label: string; expect: Expectation })[];
  denied: Expectation;
  exposed: Expectation;
  spec_evidence: string[];
}

const expectText = (e: Expectation) =>
  [
    `HTTP ${e.status.join("/")}`,
    e.content_type ? `Content-Type: ${e.content_type}` : "",
    e.body_contains?.length ? `含む: ${e.body_contains.join(", ")}` : "",
    e.body_not_contains?.length ? `含まない: ${e.body_not_contains.join(", ")}` : "",
    e.json_fields ? `JSON: ${JSON.stringify(e.json_fields)}` : "",
  ].filter(Boolean).join(" ／ ");

interface ProfilesStatus {
  profiles: ProfileRow[];
  rejected: { file: string; reason: string }[];
}

/** Site L2 profiles decide what may be run against a real service, so an admin
 *  has to accept their exact content (identified by its SHA-256). */
export function ProfilesSection() {
  const { session } = useSession();
  const admin = isPlatformAdmin(session);
  const [status, setStatus] = useState<ProfilesStatus | null>(null);
  const [version, setVersion] = useState(0);
  const [busy, setBusy] = useState(false);
  const [reviewed, setReviewed] = useState<Record<string, boolean>>({});
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    let live = true;
    getJSON<ProfilesStatus>("/api/l2-profiles")
      .then((res) => { if (live) setStatus(res); })
      .catch((e: Error) => { if (live) setMsg({ ok: false, text: e.message }); });
    return () => { live = false; };
  }, [version]);

  const accept = async (p: ProfileRow) => {
    setBusy(true);
    setMsg(null);
    try {
      const res = await postJSON<ProfilesStatus>("/api/l2-profiles/accept", { id: p.id, sha256: p.sha256 });
      setStatus(res);
      setMsg({ ok: true, text: `${p.label} の内容を承認しました（監査ログに記録済み）。` });
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
      setVersion((v) => v + 1);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3 text-sm">
      <p className="text-zinc-600 dark:text-zinc-400">
        データディレクトリに置いた導入先プロファイルは、管理者がその内容（SHA-256）を承認するまで実行できません。
        承認後にファイルが変わると、再び承認が必要になります。
      </p>
      <ul className="space-y-2">
        {(status?.profiles ?? []).map((p) => (
          <li key={p.id} className="rounded-lg border border-zinc-200 p-2.5 dark:border-zinc-800">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span>
                <span className="font-medium">{p.label}</span>
                <span className="ml-1.5 font-mono text-xs text-zinc-500">{p.file}</span>
              </span>
              <span className={p.accepted ? "text-xs text-emerald-700 dark:text-emerald-300" : "text-xs font-semibold text-amber-800 dark:text-amber-300"}>
                {!p.site ? "同梱・コード指定（承認対象外）" : p.accepted ? "承認済み" : p.changed_since_acceptance ? "承認後に変更あり・要再承認" : "未承認"}
              </span>
            </div>
            <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs text-zinc-600 dark:text-zinc-400">
              <dt>適用ホスト</dt><dd className="break-all">{p.hosts.length ? p.hosts.join("、") : "なし"}</dd>
              <dt>確定済みルール</dt><dd className="break-all">{p.confirmed_checks.length ? p.confirmed_checks.join("、") : "なし"}</dd>
              <dt>SHA-256</dt><dd className="break-all font-mono">{p.sha256}</dd>
              {p.site && <><dt>場所</dt><dd className="break-all font-mono">{p.directory}</dd></>}
            </dl>
            {p.rules.length > 0 && (
              <details className="mt-2 text-xs" open={p.site && !p.accepted}>
                <summary className="cursor-pointer font-semibold">
                  承認すると送信できるようになるリクエスト（{p.rules.length} ルール）
                </summary>
                <ul className="mt-1.5 space-y-2">
                  {p.rules.map((r) => (
                    <li key={r.id} className="rounded border border-zinc-200 p-2 dark:border-zinc-800">
                      <p className="font-medium">{r.label} <span className="font-mono text-zinc-500">{r.id}</span></p>
                      <p className="mt-0.5 break-all">
                        検証リクエスト：<span className="font-mono">GET {r.request.path}</span>（{r.request.account} のトークンを送信）
                      </p>
                      {r.controls.map((c) => (
                        <p key={c.label} className="break-all text-zinc-600 dark:text-zinc-400">
                          対照：{c.label} — <span className="font-mono">GET {c.path}</span>（{c.account}）→ {expectText(c.expect)}
                        </p>
                      ))}
                      <p className="break-all text-zinc-600 dark:text-zinc-400">拒否とみなす条件：{expectText(r.denied)}</p>
                      <p className="break-all text-zinc-600 dark:text-zinc-400">露出とみなす条件：{expectText(r.exposed)}</p>
                      <p className="break-all text-zinc-600 dark:text-zinc-400">仕様の根拠：{r.spec_evidence.join(" ； ") || "なし"}</p>
                    </li>
                  ))}
                </ul>
              </details>
            )}
            {p.site && !p.accepted && (
              admin ? (
                <div className="mt-2 space-y-1.5">
                  <label className="flex items-start gap-2 text-xs">
                    <input type="checkbox" checked={!!reviewed[p.id + p.sha256]} className="mt-0.5"
                      onChange={(e) => setReviewed((r) => ({ ...r, [p.id + p.sha256]: e.target.checked }))} />
                    <span>
                      上のリクエスト・適用ホスト・拒否/露出の条件を確認しました。これらが、適用ホストに対して検証用アカウントのトークン付きで送信されることを理解しています。
                    </span>
                  </label>
                  <button type="button" disabled={busy || !reviewed[p.id + p.sha256]} onClick={() => accept(p)}
                    className="rounded-lg bg-zinc-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-white dark:text-zinc-900">
                    この内容を承認する
                  </button>
                </div>
              ) : (
                <p className="mt-2 text-xs text-zinc-500">承認できるのは管理者だけです。</p>
              )
            )}
          </li>
        ))}
      </ul>
      {(status?.rejected ?? []).length > 0 && (
        <div role="alert" className="rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900 dark:border-red-800 dark:bg-red-950/40 dark:text-red-200">
          <p className="font-semibold">読み込まなかったプロファイル</p>
          <ul className="mt-1 space-y-0.5">
            {status?.rejected.map((r) => (
              <li key={r.file} className="break-words"><span className="font-mono">{r.file}</span>：{r.reason}</li>
            ))}
          </ul>
        </div>
      )}
      {status === null && !msg && <p className="text-xs text-zinc-500">読み込み中…</p>}
      {msg && (
        <p role={msg.ok ? "status" : "alert"} className={msg.ok ? "text-emerald-700 dark:text-emerald-300" : "text-red-700 dark:text-red-300"}>
          {msg.text}
        </p>
      )}
    </div>
  );
}
