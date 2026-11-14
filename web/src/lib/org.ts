// The organization the UI works in. Kept in the `vulnix_org` cookie so every request
// (fetch and the event stream alike) carries it; the control plane checks membership on
// every request, so the cookie is only a choice, never a permission.

export interface OrgInfo {
  id: string;
  name: string;
  roles: string[];
}

export const ORG_ROLE_LABELS: Record<string, string> = {
  owner: "オーナー",
  admin: "管理者",
  runner: "診断実行者",
  approver: "承認者",
  viewer: "閲覧者",
};

export const ORG_ROLE_HELP: Record<string, string> = {
  owner: "すべての操作とメンバー管理。オーナーの付与・削除もできます",
  admin: "メンバーの招待・役割の変更、サイトの登録と診断",
  runner: "サイトの登録・所有確認・L1 診断・L2 の依頼",
  approver: "L2 検証の承認（自分が依頼したものは承認できません）",
  viewer: "閲覧のみ（緊急停止だけは操作できます）",
};

export const ORG_ROLES = ["owner", "admin", "runner", "approver", "viewer"] as const;

const COOKIE = "vulnix_org";
const ID_RE = /^(org_[0-9a-f]{12}|default)$/;

export function readOrgCookie(cookie: string): string | null {
  for (const part of cookie.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === COOKIE) {
      const val = decodeURIComponent(v.join("="));
      return ID_RE.test(val) ? val : null;
    }
  }
  return null;
}

/** The selected organization if the account belongs to it, else its first organization. */
export function activeOrg(orgs: OrgInfo[], selected: string | null): OrgInfo | null {
  return orgs.find((o) => o.id === selected) ?? orgs[0] ?? null;
}

export function orgCookieValue(id: string): string {
  if (!ID_RE.test(id)) throw new Error("invalid organization id");
  return `${COOKIE}=${id}; Path=/; SameSite=Strict; Max-Age=31536000`;
}

export function getSelectedOrg(): string | null {
  return typeof document === "undefined" ? null : readOrgCookie(document.cookie);
}

export function selectOrg(id: string): void {
  document.cookie = orgCookieValue(id);
}

/** The invite token from a link like /invite#inv_xxx (kept out of server logs). */
export function inviteTokenFromHash(hash: string): string | null {
  const t = hash.replace(/^#/, "").trim();
  return /^inv_[A-Za-z0-9_-]{16,64}$/.test(t) ? t : null;
}

// ---- the server's membership rules (aegis/tenancy.py), so the UI offers only what works ----
const SERVICE_ROLES: Record<string, string[]> = {
  owner: ["admin", "operator", "approver"],
  admin: ["admin", "operator"],
  runner: ["operator"],
  approver: ["approver"],
  viewer: [],
};
const serviceRoles = (roles: string[]) => new Set(roles.flatMap((r) => SERVICE_ROLES[r] ?? []));
const isManager = (roles: string[]) => roles.includes("owner") || roles.includes("admin");

export interface MemberRow { name: string; roles: string[] }

/** Whether `actor` (with `actorRoles`) may switch `role` on or off for `member`. */
export function canToggleRole(actor: string, actorRoles: string[], member: MemberRow, role: string, ownerCount: number): boolean {
  if (!isManager(actorRoles)) return false;
  const next = member.roles.includes(role) ? member.roles.filter((r) => r !== role) : [...member.roles, role];
  if (next.length === 0) return false;                                          // at least one role
  const ownerInvolved = member.roles.includes("owner") || next.includes("owner");
  if (ownerInvolved && !actorRoles.includes("owner")) return false;             // owners decide about owners
  if (member.roles.includes("owner") && !next.includes("owner") && ownerCount <= 1) return false;  // last owner
  if (member.name === actor) {                                                  // never more power for oneself
    const now = serviceRoles(member.roles);
    if ([...serviceRoles(next)].some((s) => !now.has(s))) return false;
  }
  return true;
}

/** Whether `actor` may remove `member` (leaving oneself is allowed, except as the last owner). */
export function canRemove(actor: string, actorRoles: string[], member: MemberRow, ownerCount: number): boolean {
  if (member.roles.includes("owner") && ownerCount <= 1) return false;
  if (member.name === actor) return true;
  if (!isManager(actorRoles)) return false;
  return !member.roles.includes("owner") || actorRoles.includes("owner");
}
