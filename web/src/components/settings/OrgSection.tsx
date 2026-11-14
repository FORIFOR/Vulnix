"use client";

import { useEffect, useState } from "react";
import { Card } from "@/components/ui";
import { getJSON, postJSON } from "@/lib/api";
import { fmtTime } from "@/lib/labels";
import { ORG_ROLE_HELP, ORG_ROLE_LABELS, ORG_ROLES, selectOrg, type OrgInfo } from "@/lib/org";
import { useSession } from "@/lib/useSession";

interface Member { name: string; roles: string[] }
interface Invite { id: string; roles: string[]; created_by: string; expires_at: number; expired: boolean }

/** Members, roles and invitations of the current organization. */
export function OrgSection() {
  const { session, multiTenant, org, refresh } = useSession();
  const [members, setMembers] = useState<Member[]>([]);
  const [invites, setInvites] = useState<Invite[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [newRole, setNewRole] = useState("runner");
  const [link, setLink] = useState<string | null>(null);
  const [orgName, setOrgName] = useState("");
  const manager = !!org?.roles.some((r) => r === "owner" || r === "admin");
  const owner = !!org?.roles.includes("owner");

  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (!multiTenant || !org) return;
    let live = true;
    Promise.all([
      getJSON<{ members: Member[] }>("/api/orgs/members"),
      manager ? getJSON<{ invites: Invite[] }>("/api/orgs/invites") : Promise.resolve({ invites: [] as Invite[] }),
    ]).then(([m, i]) => {
      if (!live) return;
      setMembers(m.members);
      setInvites(i.invites);
    }, (e: Error) => { if (live) setErr(e.message); });
    return () => { live = false; };
  }, [multiTenant, org, manager, tick]);

  if (!multiTenant || !org) return null;

  const run = async (fn: () => Promise<unknown>) => {
    setErr(null);
    try {
      await fn();
      setTick((t) => t + 1);
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const toggleRole = (m: Member, role: string) =>
    run(() => postJSON("/api/orgs/members/roles", {
      name: m.name,
      roles: m.roles.includes(role) ? m.roles.filter((r) => r !== role) : [...m.roles, role],
    }));

  const invite = () => run(async () => {
    const res = await postJSON<{ token: string }>("/api/orgs/invites", { roles: [newRole], ttl_hours: 168 });
    setLink(`${window.location.origin}/invite#${res.token}`);
  });

  const createOrg = () => run(async () => {
    const res = await postJSON<{ org: OrgInfo }>("/api/orgs", { name: orgName });
    selectOrg(res.org.id);
    window.location.assign("/dashboard");
  });

  return (
    <Card className="p-5">
      <h2 className="font-semibold">組織とメンバー</h2>
      <p className="mt-1 text-xs text-zinc-500">
        「{org.name}」のサイト・診断結果・証拠・監査ログは、この組織のメンバーだけが見られます。
      </p>
      {err && <p role="alert" className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-xs text-red-800 dark:bg-red-950/40 dark:text-red-200">{err}</p>}

      <div className="mt-4 overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-zinc-500">
              <th className="py-1.5 pr-3 font-medium">メンバー</th>
              {ORG_ROLES.map((r) => <th key={r} className="px-1.5 py-1.5 text-center font-medium" title={ORG_ROLE_HELP[r]}>{ORG_ROLE_LABELS[r]}</th>)}
              {manager && <th />}
            </tr>
          </thead>
          <tbody>
            {members.map((m) => (
              <tr key={m.name} className="border-t border-zinc-100 dark:border-zinc-800">
                <td className="py-2 pr-3">{m.name}{m.name === session?.operator && <span className="ml-1 text-xs text-zinc-500">（自分）</span>}</td>
                {ORG_ROLES.map((r) => (
                  <td key={r} className="px-1.5 text-center">
                    <input type="checkbox" aria-label={`${m.name} の ${ORG_ROLE_LABELS[r]}`}
                      checked={m.roles.includes(r)}
                      disabled={!manager || (r === "owner" && !owner)}
                      onChange={() => toggleRole(m, r)} />
                  </td>
                ))}
                {manager && (
                  <td className="pl-2 text-right">
                    {m.name !== session?.operator && (
                      <button type="button" onClick={() => run(() => postJSON("/api/orgs/members/remove", { name: m.name }))}
                        className="text-xs text-red-700 hover:underline dark:text-red-300">外す</button>
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {manager && (
        <div className="mt-6 border-t border-zinc-100 pt-4 dark:border-zinc-800">
          <h3 className="text-sm font-semibold">メンバーを招待</h3>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <select value={newRole} onChange={(e) => setNewRole(e.target.value)} aria-label="招待する役割"
              className="rounded-lg border border-zinc-300 bg-white px-2 py-1.5 text-sm dark:border-zinc-700 dark:bg-zinc-900">
              {ORG_ROLES.filter((r) => owner || r !== "owner").map((r) => <option key={r} value={r}>{ORG_ROLE_LABELS[r]}</option>)}
            </select>
            <button type="button" onClick={invite}
              className="rounded-lg bg-zinc-900 px-3 py-1.5 text-sm font-semibold text-white dark:bg-white dark:text-zinc-900">招待リンクを作成</button>
            <span className="text-xs text-zinc-500">{ORG_ROLE_HELP[newRole]}</span>
          </div>
          {link && (
            <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs dark:border-amber-900 dark:bg-amber-950/40">
              <p className="font-semibold">招待リンク（この画面でだけ表示されます・7日間有効・1回限り）</p>
              <div className="mt-2 flex gap-2">
                <input readOnly value={link} className="min-w-0 flex-1 rounded border border-zinc-300 bg-white px-2 py-1 font-mono dark:border-zinc-700 dark:bg-zinc-900" />
                <button type="button" onClick={() => navigator.clipboard?.writeText(link)}
                  className="rounded border border-zinc-300 px-2 py-1 dark:border-zinc-700">コピー</button>
              </div>
            </div>
          )}
          {invites.length > 0 && (
            <ul className="mt-3 space-y-1 text-xs">
              {invites.map((i) => (
                <li key={i.id} className="flex items-center justify-between rounded-lg bg-zinc-50 px-3 py-1.5 dark:bg-zinc-800/60">
                  <span>{i.roles.map((r) => ORG_ROLE_LABELS[r] ?? r).join("・")}／{i.created_by}／{i.expired ? "期限切れ" : `${fmtTime(i.expires_at)} まで`}</span>
                  <button type="button" onClick={() => run(() => postJSON("/api/orgs/invites/revoke", { id: i.id }))}
                    className="text-red-700 hover:underline dark:text-red-300">取り消す</button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div className="mt-6 border-t border-zinc-100 pt-4 dark:border-zinc-800">
        <h3 className="text-sm font-semibold">新しい組織を作成</h3>
        <div className="mt-2 flex gap-2">
          <input value={orgName} onChange={(e) => setOrgName(e.target.value)} maxLength={60} placeholder="組織名" aria-label="新しい組織名"
            className="min-w-0 flex-1 rounded-lg border border-zinc-300 px-3 py-1.5 text-sm dark:border-zinc-700 dark:bg-zinc-950" />
          <button type="button" onClick={createOrg} disabled={!orgName.trim()}
            className="rounded-lg border border-zinc-300 px-3 py-1.5 text-sm font-semibold disabled:opacity-50 dark:border-zinc-700">作成</button>
        </div>
      </div>
      <button type="button" onClick={refresh} className="sr-only">再読み込み</button>
    </Card>
  );
}
