"use client";

import dynamic from "next/dynamic";
import type { ReactNode } from "react";

export const Chart = dynamic(() => import("./IntelligenceChart").then((m) => m.IntelligenceChart), { ssr: false });

export function IntelligencePanel({ title, children, wide = false }: { title: string; children: ReactNode; wide?: boolean }) {
  return <section aria-label={title} className={`col-span-12 min-w-0 overflow-hidden rounded-2xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900 ${wide ? "" : "md:col-span-6"}`}>
    <h2 className="mb-2 text-sm font-semibold">{title}</h2>{children}
  </section>;
}
export function Empty({ children }: { children: ReactNode }) {
  return <p className="my-5 text-sm text-zinc-500">{children}</p>;
}
