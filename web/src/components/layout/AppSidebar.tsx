"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useSession } from "@/lib/useSession";

const NAV = [
  { href: "/dashboard", label: "ホーム", icon: "⌂" },
  { href: "/assets", label: "資産管理", icon: "▤" },
  { href: "/assessments/scan_001", label: "診断ワークスペース", icon: "◎" },
  { href: "/settings", label: "設定", icon: "⚙" },
];

export function AppSidebar() {
  const path = usePathname();
  return (
    <nav
      aria-label="メイン"
      className="flex shrink-0 items-center gap-1 border-b border-zinc-200 bg-zinc-50 px-3 py-2 md:h-dvh md:w-56 md:flex-col md:items-stretch md:border-b-0 md:border-r md:px-3 md:py-4 dark:border-zinc-800 dark:bg-zinc-950"
    >
      <Link href="/dashboard" className="mr-auto flex items-center gap-2 px-2 md:mb-6 md:mr-0">
        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-zinc-900 text-sm font-bold text-white dark:bg-white dark:text-zinc-900">
          V
        </span>
        <span className="leading-tight">
          <span className="block text-sm font-semibold">Vulnix</span>
          <span className="hidden text-[11px] text-zinc-500 md:block">Find. Prove. Secure.</span>
        </span>
      </Link>
      {NAV.map((n) => {
        const active = path === n.href || (n.href !== "/dashboard" && path.startsWith(n.href.split("/").slice(0, 2).join("/")));
        return (
          <Link
            key={n.href}
            href={n.href}
            aria-current={active ? "page" : undefined}
            className={`flex items-center gap-2 rounded-lg px-2.5 py-2 text-sm ${
              active ? "bg-zinc-200 font-semibold dark:bg-zinc-800" : "text-zinc-600 hover:bg-zinc-100 dark:text-zinc-400 dark:hover:bg-zinc-900"
            }`}
          >
            <span aria-hidden className="w-4 text-center">{n.icon}</span>
            <span className="hidden sm:inline">{n.label}</span>
          </Link>
        );
      })}
      <div className="mt-auto flex items-center gap-2 md:block">
        <OperatorBadge />
        <p className="mt-2 hidden px-2 text-[11px] leading-relaxed text-zinc-500 md:block">
          ローカル模擬ラボのデモです。提案エンジンの設定状態は診断画面で確認できます。
        </p>
      </div>
    </nav>
  );
}

function OperatorBadge() {
  const { session, logout } = useSession();
  if (!session) return null;
  const role = session.roles.includes("approver") ? "承認責任者" : "診断オペレーター";
  return (
    <div className="rounded-lg border border-zinc-200 px-2.5 py-2 text-xs dark:border-zinc-800">
      <div className="truncate font-semibold">{session.operator}</div>
      <div className="text-zinc-500">{role}</div>
      <button onClick={logout} className="mt-1.5 w-full rounded-md border border-zinc-300 py-1 font-medium hover:bg-zinc-100 dark:border-zinc-600 dark:hover:bg-zinc-800">
        ログアウト
      </button>
    </div>
  );
}
