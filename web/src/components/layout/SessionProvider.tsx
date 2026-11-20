"use client";

import { usePathname, useRouter } from "next/navigation";
import { isPublicPage } from "@/lib/publicMode";
import { useCallback, useEffect, useRef, useState } from "react";
import { getJSON } from "@/lib/api";
import { SessionContext, type SessionInfo } from "@/lib/useSession";
import { activeOrg, getSelectedOrg, serviceRolesOf, type OrgInfo } from "@/lib/org";
import { shouldApplySessionResponse } from "@/lib/sessionResponse";

const LOGOUT_NOTICE = "vulnix:logout-notice";

/** Loads the session, and redirects to /login when a protected page has none. */
export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [orgs, setOrgs] = useState<OrgInfo[]>([]);
  const [multiTenant, setMultiTenant] = useState(false);
  const [selfRegistration, setSelfRegistration] = useState(false);
  const [googleOwnership, setGoogleOwnership] = useState(false);
  const [optionalStatusCheck, setOptionalStatusCheck] = useState(false);
  const [logoutUnconfirmed, setLogoutUnconfirmed] = useState(false);
  const refreshVersion = useRef(0);
  const signingOut = useRef(false);
  const externalLogout = useRef<string | null>(null);
  const localLogout = useRef<string | null>(null);
  const path = usePathname();
  const router = useRouter();

  const refresh = useCallback(async () => {
    const version = ++refreshVersion.current;
    try {
      const me = await getJSON<{ session: SessionInfo | null; orgs?: OrgInfo[]; multi_tenant?: boolean; self_registration?: boolean; google_ownership?: boolean; optional_status_check?: boolean }>("/api/auth/me");
      if (!shouldApplySessionResponse(version, refreshVersion.current, signingOut.current)) return;
      const current = me.multi_tenant ? activeOrg(me.orgs ?? [], getSelectedOrg()) : null;
      // in an organization the workspace acts with the roles there, as the server does
      setSession(me.session && current
        ? { ...me.session, platform_roles: me.session.roles, roles: serviceRolesOf(current.roles) }
        : me.session);
      setOrgs(me.orgs ?? []);
      setMultiTenant(Boolean(me.multi_tenant));
      setSelfRegistration(Boolean(me.self_registration));
      setGoogleOwnership(Boolean(me.google_ownership));
      setOptionalStatusCheck(Boolean(me.optional_status_check));
    } catch {
      if (!shouldApplySessionResponse(version, refreshVersion.current, signingOut.current)) return;
      setSession(null);
      setOrgs([]);
      setMultiTenant(false);
      setSelfRegistration(false);
      setGoogleOwnership(false);
      setOptionalStatusCheck(false);
    } finally {
      if (shouldApplySessionResponse(version, refreshVersion.current, signingOut.current)) setLoading(false);
    }
  }, []);

  const hideSession = useCallback(() => {
    ++refreshVersion.current;
    setSession(null);
    setOrgs([]);
    setMultiTenant(false);
    setSelfRegistration(false);
    setGoogleOwnership(false);
    setOptionalStatusCheck(false);
    setLoading(true);
  }, []);

  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key !== LOGOUT_NOTICE || !event.newValue) return;
      let notice: unknown;
      try { notice = JSON.parse(event.newValue); } catch { return; }
      if (!notice || typeof notice !== "object") return;
      const message = notice as { phase?: unknown; id?: unknown };
      if (typeof message.id !== "string" || !message.id) return;
      if (message.phase === "start") {
        externalLogout.current = message.id;
        signingOut.current = true;
        setLogoutUnconfirmed(false);
        hideSession();
        window.setTimeout(() => {
          if (externalLogout.current === message.id) setLogoutUnconfirmed(true);
        }, 30000);
      } else if (message.phase === "settled" && externalLogout.current === message.id) {
        externalLogout.current = null;
        setLogoutUnconfirmed(false);
        hideSession();
        signingOut.current = false;
        setLoading(false);
        router.push("/login");
      } else if (message.phase === "settled" && !signingOut.current) {
        // This tab may have opened after the start notice. Hide its cached
        // result and ask the server, rather than trusting a pre-logout 200.
        hideSession();
        void refresh();
      } else if (message.phase === "failed" && externalLogout.current === message.id) {
        externalLogout.current = null;
        setLogoutUnconfirmed(false);
        signingOut.current = false;
        // The server may still consider this session valid. Recheck before
        // showing anything, and tell this tab that logout did not complete.
        void refresh();
        window.alert?.("別のタブでログアウトを完了できませんでした。認証状態を再確認してください。");
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [hideSession, refresh, router]);

  const logout = useCallback(async () => {
    signingOut.current = true;
    setLogoutUnconfirmed(false);
    hideSession();
    const noticeId = `${Date.now()}:${Math.random()}`;
    localLogout.current = noticeId;
    window.setTimeout(() => {
      if (localLogout.current === noticeId) setLogoutUnconfirmed(true);
    }, 30000);
    const notify = (phase: "start" | "settled" | "failed") => {
      try { window.localStorage.setItem(LOGOUT_NOTICE, JSON.stringify({ phase, id: noticeId })); }
      catch { /* server-side session checks still enforce access */ }
    };
    notify("start");
    const res = await fetch("/api/auth/logout", { method: "POST", headers: { "X-Aegis-Request": "1" } }).catch(() => null);
    const success = Boolean(res?.ok);
    if (!success) {
      // signed out here, but the server could not record it: say so instead of pretending
      const body = res ? await res.json().catch(() => ({})) : {};
      notify("failed");
      window.alert?.((body as { error?: string }).error ??
        "ログアウトをサーバーに記録できませんでした。再起動するとセッションが復活する可能性があります。管理者に連絡してください。");
    }
    ++refreshVersion.current;
    signingOut.current = false;
    localLogout.current = null;
    setLogoutUnconfirmed(false);
    if (success) notify("settled");
    setLoading(false);
    router.push("/login");
  }, [hideSession, router]);

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
    // Keep protected content hidden while the logout POST is pending, but do
    // not offer another login until its Set-Cookie response has settled.
    if (!loading && !session && !signingOut.current && !isPublicPage(path)) router.replace("/login");
  }, [loading, session, path, router]);

  return (
    <SessionContext.Provider value={{ session, loading, refresh, logout, orgs, multiTenant, selfRegistration, googleOwnership, optionalStatusCheck,
                                      org: activeOrg(orgs, typeof document === "undefined" ? null : getSelectedOrg()) }}>
      {logoutUnconfirmed ? (
        <main className="flex min-h-dvh flex-col items-center justify-center gap-4 p-6 text-center text-sm">
          <p>ログアウト状態を確認できません。ページを再読み込みして認証状態を確認してください。</p>
          <button type="button" className="rounded-lg border px-4 py-2" onClick={() => window.location.reload()}>
            ページを再読み込み
          </button>
        </main>
      ) : children}
    </SessionContext.Provider>
  );
}
