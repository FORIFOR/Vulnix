"use client";

import { ORG_ROLE_LABELS, selectOrg } from "@/lib/org";
import { useSession } from "@/lib/useSession";

/** Sidebar: which organization the workspace shows. Switching reloads every view. */
export function OrgSwitcher() {
  const { multiTenant, orgs, org } = useSession();
  if (!multiTenant || !org) return null;
  return (
    <div className="w-full px-2 md:mb-4">
      <label htmlFor="org-switch" className="mb-1 block text-[11px] font-medium text-zinc-500">組織</label>
      {orgs.length > 1 ? (
        <select
          id="org-switch"
          value={org.id}
          onChange={(e) => { selectOrg(e.target.value); window.location.assign("/dashboard"); }}
          className="w-full rounded-lg border border-zinc-300 bg-white px-2 py-1.5 text-sm dark:border-zinc-700 dark:bg-zinc-900"
        >
          {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
        </select>
      ) : (
        <div id="org-switch" className="truncate rounded-lg border border-zinc-200 bg-white px-2 py-1.5 text-sm dark:border-zinc-800 dark:bg-zinc-900">{org.name}</div>
      )}
      <div className="mt-1 truncate text-[11px] text-zinc-500">{org.roles.map((r) => ORG_ROLE_LABELS[r] ?? r).join("・")}</div>
    </div>
  );
}
