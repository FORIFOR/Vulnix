"use client";

import { usePathname, useRouter } from "next/navigation";
import { isPublicPage } from "@/lib/publicMode";
import { useCallback, useEffect, useState } from "react";
import { getJSON } from "@/lib/api";
import { SessionContext, type SessionInfo } from "@/lib/useSession";
import { activeOrg, getSelectedOrg, serviceRolesOf, type OrgInfo } from "@/lib/org";

/** Loads the session, and redirects to /login when a protected page has none. */
export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [orgs, setOrgs] = useState<OrgInfo[]>([]);
  const [multiTenant, setMultiTenant] = useState(false);
  const [googleOwnership, setGoogleOwnership] = useState(false);
  const path = usePathname();
  const router = useRouter();

  const refresh = useCallback(async () => {
    try {
      const me = await getJSON<{ session: SessionInfo | null; orgs?: OrgInfo[]; multi_tenant?: boolean; google_ownership?: boolean }>("/api/auth/me");
      const current = me.multi_tenant ? activeOrg(me.orgs ?? [], getSelectedOrg()) : null;
      // in an organization the workspace acts with the roles there, as the server does
      setSession(me.session && current
        ? { ...me.session, platform_roles: me.session.roles, roles: serviceRolesOf(current.roles) }
        : me.session);
      setOrgs(me.orgs ?? []);
      setMultiTenant(Boolean(me.multi_tenant));
      setGoogleOwnership(Boolean(me.google_ownership));
    } catch {
      setSession(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    const res = await fetch("/api/auth/logout", { method: "POST", headers: { "X-Aegis-Request": "1" } }).catch(() => null);
    if (!res || !res.ok) {
      // signed out here, but the server could not record it: say so instead of pretending
      const body = res ? await res.json().catch(() => ({})) : {};
      window.alert?.((body as { error?: string }).error ??
        "ログアウトをサーバーに記録できませんでした。再起動するとセッションが復活する可能性があります。管理者に連絡してください。");
    }
    setSession(null);
    router.push("/login");
  }, [router]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      await refresh();
      if (cancelled) return;
    })();
    return () => {
      cancelled = true;
    };
  }, [refresh]);

  useEffect(() => {
    if (!loading && !session && !isPublicPage(path)) router.replace("/login");
  }, [loading, session, path, router]);

  return (
    <SessionContext.Provider value={{ session, loading, refresh, logout, orgs, multiTenant, googleOwnership,
                                      org: activeOrg(orgs, typeof document === "undefined" ? null : getSelectedOrg()) }}>
      {children}
    </SessionContext.Provider>
  );
}
