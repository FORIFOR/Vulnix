import type { ReactNode } from "react";
import { SEVERITY, VERDICT } from "@/lib/labels";
import type { Severity, Verdict } from "@/lib/types";
import { HelpPopover } from "./learning/HelpPopover";

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm dark:border-zinc-800 dark:bg-zinc-900 ${className}`}>
      {children}
    </div>
  );
}

export function Pill({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <span className={`inline-flex items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-semibold ${className}`}>
      {children}
    </span>
  );
}

export function SeverityBadge({ s }: { s: Severity }) {
  return <Pill className={SEVERITY[s].cls}>深刻度 {SEVERITY[s].label}</Pill>;
}

export function VerdictBadge({ v, help = true }: { v: Verdict; help?: boolean }) {
  return (
    <span className="inline-flex items-center">
      <Pill className={`border bg-transparent ${VERDICT[v].cls}`}>{VERDICT[v].label}</Pill>
      {help && <HelpPopover term={VERDICT[v].help} />}
    </span>
  );
}

export function FixtureBadge() {
  return (
    <Pill className="border border-dashed border-violet-400 text-violet-700 dark:text-violet-300">
      架空データ
    </Pill>
  );
}
