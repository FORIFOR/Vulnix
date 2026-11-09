import Link from "next/link";
import type { Finding } from "@/lib/types";
import { HelpPopover } from "../learning/HelpPopover";
import { Card, FixtureBadge, Pill, SeverityBadge, VerdictBadge } from "../ui";

export function FindingCard({ f, assessmentId }: { f: Finding; assessmentId: string }) {
  return (
    <Card className={f.demo_fixture ? "border-dashed" : ""}>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge s={f.severity} />
        <VerdictBadge v={f.verdict} />
        {f._in_verification && <Pill className="bg-blue-600 text-white">検証中</Pill>}
        {f.demo_fixture && <FixtureBadge />}
      </div>
      <h3 className="mt-2 flex items-center font-semibold">
        {f.title}
        {f.help_term && <HelpPopover term={f.help_term} context={f.why_detected} />}
      </h3>
      <p className="mt-1 text-sm text-zinc-700 dark:text-zinc-300">{f.what_was_established ?? f.summary}</p>
      {f.cve.length > 0 && <p className="mt-1 font-mono text-xs text-zinc-500">{f.cve.join(" / ")}</p>}
      <div className="mt-3 flex items-center justify-between text-xs text-zinc-500">
        <span>{f.category}・証拠 {f.evidence.length} 件</span>
        <Link href={`/findings/${f.id}?a=${assessmentId}`} className="font-semibold text-zinc-900 underline-offset-2 hover:underline dark:text-zinc-100">
          詳しく見る →
        </Link>
      </div>
    </Card>
  );
}
