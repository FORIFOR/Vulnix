"use client";

import { usePathname } from "next/navigation";
import { useSession } from "@/lib/useSession";
import { AppSidebar } from "./AppSidebar";
import { CreateOrgPanel } from "@/components/org/CreateOrgPanel";

/** App chrome: sidebar + content, except on the login page. */
export function Shell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const { session, loading, multiTenant, orgs } = useSession();

  if (path === "/login" || path === "/invite") return <>{children}</>;

  // Avoid a flash of protected content before the redirect in SessionProvider.
  if (loading || !session) {
    return (
      <div className="flex min-h-dvh items-center justify-center text-sm text-zinc-500">
        {loading ? "読み込み中…" : "ログイン画面へ移動します…"}
      </div>
    );
  }
  if (multiTenant && orgs.length === 0) return <CreateOrgPanel />;
  return (
    <div className="flex min-h-dvh flex-col md:flex-row">
      <AppSidebar />
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}
