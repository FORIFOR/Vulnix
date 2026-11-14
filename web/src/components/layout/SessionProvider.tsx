"use client";

import { usePathname, useRouter } from "next/navigation";
import { isPublicPage } from "@/lib/publicMode";
import { useCallback, useEffect, useState } from "react";
import { getJSON } from "@/lib/api";
import { SessionContext, type SessionInfo } from "@/lib/useSession";

/** Loads the session, and redirects to /login when a protected page has none. */
export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const path = usePathname();
  const router = useRouter();

  const refresh = useCallback(async () => {
    try {
      const { session } = await getJSON<{ session: SessionInfo | null }>("/api/auth/me");
      setSession(session);
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
    <SessionContext.Provider value={{ session, loading, refresh, logout }}>
      {children}
    </SessionContext.Provider>
  );
}
