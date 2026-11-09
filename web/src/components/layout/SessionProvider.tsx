"use client";

import { usePathname, useRouter } from "next/navigation";
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
    await fetch("/api/auth/logout", { method: "POST", headers: { "X-Aegis-Request": "1" } });
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
    if (!loading && !session && path !== "/login") router.replace("/login");
  }, [loading, session, path, router]);

  return (
    <SessionContext.Provider value={{ session, loading, refresh, logout }}>
      {children}
    </SessionContext.Provider>
  );
}
