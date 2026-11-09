import { PHASE } from "@/lib/labels";
import type { Phase } from "@/lib/types";

const TONE: Record<Phase["status"], string> = {
  pending: "border-zinc-300 text-zinc-400",
  running: "border-blue-600 text-blue-600 animate-pulse",
  done: "border-emerald-600 bg-emerald-600 text-white",
  aborted: "border-red-600 text-red-600",
  skipped: "border-zinc-400 text-zinc-500",
};

export function PhaseTimeline({ phases }: { phases: Phase[] }) {
  return (
    <ol className="space-y-3" aria-label="診断ステップ">
      {phases.map((p) => (
        <li key={p.key} className="flex gap-3">
          <span aria-hidden className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border-2 text-xs font-bold ${TONE[p.status]}`}>
            {PHASE[p.status].icon}
          </span>
          <div className="min-w-0">
            <div className="text-sm font-medium">
              {p.label}
              <span className="ml-2 text-xs font-normal text-zinc-500">{PHASE[p.status].label}</span>
            </div>
            {p.detail && <div className="text-xs text-zinc-500">{p.detail}</div>}
          </div>
        </li>
      ))}
    </ol>
  );
}
