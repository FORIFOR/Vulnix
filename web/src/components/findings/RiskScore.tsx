import type { Risk } from "@/lib/types";
import { HelpPopover } from "../learning/HelpPopover";

export function RiskScore({ risk, compact = false }: { risk: Risk | null; compact?: boolean }) {
  if (!risk) {
    return <div className="text-sm text-zinc-500">未診断（安全とは判定していません）</div>;
  }
  const tone = risk.score >= 70 ? "text-red-600" : risk.score >= 40 ? "text-orange-600" : "text-sky-700 dark:text-sky-300";
  return (
    <div>
      {!compact && (
        <div className="flex items-center text-xs text-zinc-500">
          総合リスク
          <HelpPopover term="risk_score" context={risk.basis} />
        </div>
      )}
      <div className="flex items-baseline gap-1">
        <span className={`text-3xl font-bold tabular-nums ${tone}`}>{risk.score}</span>
        <span className="text-sm text-zinc-500">/100</span>
      </div>
      <div className="text-sm font-semibold">
        {risk.label}
        {risk.provisional && <span className="ml-1 text-xs font-normal text-zinc-500">（暫定）</span>}
      </div>
    </div>
  );
}
