"use client";

import { usePathname } from "next/navigation";
import { useSession } from "@/lib/useSession";
import { AppSidebar } from "./AppSidebar";
import { CreateOrgPanel } from "@/components/org/CreateOrgPanel";
import Link from "next/link";
import { isGuestPage, isPublicPage } from "@/lib/publicMode";

/** App chrome: sidebar + content, except on the login page. */
export function Shell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const { session, loading, multiTenant, orgs } = useSession();

  if (isPublicPage(path)) return <>{children}</>;
  if (!loading && !session && isGuestPage(path)) {
    return (
      <div className="min-h-dvh">
        <div className="flex items-center justify-between gap-3 border-b border-zinc-200 bg-white px-4 py-2 text-xs text-zinc-600 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-400">
          <span>ログインせずに利用中です。選んだフォルダはこの端末のブラウザ内だけで調べ、送信しません。</span>
          <Link href="/login" className="shrink-0 font-semibold text-zinc-900 underline dark:text-zinc-100">ログイン</Link>
        </div>
        {children}
      </div>
    );
  }

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
