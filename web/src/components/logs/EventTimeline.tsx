import { AUDIT_EVENT, fmtTime } from "@/lib/labels";
import type { AuditEntry } from "@/lib/types";
import { HelpPopover } from "../learning/HelpPopover";
import { Pill } from "../ui";

const TONE: Record<string, string> = {
  deny: "bg-red-100 text-red-900 dark:bg-red-900/50 dark:text-red-100",
  emergency_stop: "bg-red-600 text-white",
  allow: "bg-emerald-100 text-emerald-900 dark:bg-emerald-900/50 dark:text-emerald-100",
  "agent.thought": "bg-violet-100 text-violet-900 dark:bg-violet-900/50 dark:text-violet-100",
};

function describe(e: AuditEntry): string {
  const f = e.fields as Record<string, unknown>;
  switch (e.event) {
    case "agent.thought":
      return `【${f.step}】${f.detail}${f.tool ? `（ツール: ${f.tool} / ${f.risk_level ?? "L1"}）` : ""}`;
    case "allow": {
      const d = f.dest as { host?: string; ip?: string; port?: number } | undefined;
      return `${f.tool} を ${f.target} に対して実行（宛先 ${d?.host} → ${d?.ip}:${d?.port}、承認 ${f.approval}）`;
    }
    case "deny": return `理由: ${f.reason}`;
    case "result": {
      const tool = f.tool ? `[${f.tool}] ` : "";
      const preview = f.stdout_preview ? ` — 応答: ${f.stdout_preview}` : "";
      return `${tool}終了コード ${f.rc}${f.killed ? "（強制終了）" : ""}・${Number(f.elapsed).toFixed(2)} 秒${preview}`;
    }
    case "proposal.received":
      return `${f.backend} が ${f.tool}（${f.action} → ${f.target}）を提案`;
    case "approval.auto": return `${f.tool}（${f.action}）をポリシーにより自動承認`;
    case "approval.approved":
    case "approval.rejected": return `${f.action}（${f.risk_level}）・${f.actor}`;
    case "emergency_stop": return `実行者 ${f.actor}・強制終了 ${(f.killed as number[])?.length ?? 0} 件・残存 ${(f.survivors as number[])?.length ?? 0} 件`;
    case "auth.login": return `${f.actor}（${(f.roles as string[])?.join(", ")}）がログイン`;
    case "auth.logout": return `${f.actor} がログアウト`;
    case "auth.password_changed": return `${f.actor} がパスワードを変更（他のセッションは失効）`;
    case "auth.mfa_enabled": return `${f.actor} が2要素認証を有効化`;
    case "auth.mfa_disabled": return `${f.actor} が2要素認証を無効化`;
    default: return f.actor ? `実行者 ${f.actor}` : "";
  }
}

export function EventTimeline({ entries, chainValid }: { entries: AuditEntry[]; chainValid: boolean | null }) {
  return (
    <div>
      <div className="mb-3 flex items-center text-sm">
        監査チェーン：
        {chainValid === null ? "確認中" : chainValid ? (
          <Pill className="ml-1 bg-emerald-100 text-emerald-900 dark:bg-emerald-900/50 dark:text-emerald-100">✓ 改ざんなし（監視中）</Pill>
        ) : (
          <Pill className="ml-1 bg-red-600 text-white">✕ 不整合を検出</Pill>
        )}
        <HelpPopover term="audit_chain" />
      </div>
      {entries.length === 0 ? (
        <p className="text-sm text-zinc-500">まだ記録はありません。</p>
      ) : (
        <ol className="space-y-2">
          {[...entries].reverse().map((e) => (
            <li key={e.hash} className="flex gap-3 rounded-lg border border-zinc-200 p-2.5 text-sm dark:border-zinc-800">
              <span className="w-36 shrink-0 text-xs tabular-nums text-zinc-500">{fmtTime(e.ts)}</span>
              <div className="min-w-0">
                <Pill className={TONE[e.event] ?? "bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-100"}>
                  {AUDIT_EVENT[e.event] ?? e.event}
                </Pill>
                <p className="mt-1 break-all text-zinc-700 dark:text-zinc-300">{describe(e)}</p>
              </div>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
