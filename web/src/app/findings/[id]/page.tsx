"use client";

import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { Suspense } from "react";
import { EvidencePanel } from "@/components/findings/EvidencePanel";
import { RemediationPanel } from "@/components/findings/RemediationPanel";
import { HelpPopover } from "@/components/learning/HelpPopover";
import { Card, FixtureBadge, SeverityBadge, VerdictBadge } from "@/components/ui";
import { useAssessment } from "@/lib/useAssessment";

function Detail() {
  const { id } = useParams<{ id: string }>();
  const aid = useSearchParams().get("a") ?? "scan_001";
  const { snap, error } = useAssessment(aid);
  if (!snap) return <p className="p-6 text-sm">{error ? `読み込めませんでした：${error}` : "読み込み中…"}</p>;
  const f = snap.findings.find((x) => x.id === id);
  if (!f) return <p className="p-6 text-sm">この問題は見つかりません。</p>;

  return (
    <main className="mx-auto max-w-3xl space-y-4 p-4 md:p-8">
      <Link href={`/assessments/${aid}?tab=findings`} className="text-sm text-zinc-500 hover:underline">← 問題一覧</Link>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge s={f.severity} />
        <VerdictBadge v={f.verdict} />
        {f.demo_fixture && <FixtureBadge />}
      </div>
      <h1 className="flex items-center text-2xl font-bold">
        {f.title}
        {f.help_term && <HelpPopover term={f.help_term} context={f.why_detected} />}
      </h1>

      <Card>
        <h2 className="mb-1 text-sm font-semibold">何が危険か</h2>
        <p className="text-sm">{f.summary}</p>
        {f.what_was_established && (
          <p className="mt-2 rounded-lg bg-red-50 p-2 text-sm dark:bg-red-950/30">
            <span className="font-semibold">実証で成立したこと：</span>{f.what_was_established}
          </p>
        )}
        {f.verdict_note && <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">{f.verdict_note}</p>}
        {f.caveat && <p className="mt-2 text-xs text-zinc-500">※ {f.caveat}</p>}
        {f.cve.length > 0 && (
          <p className="mt-2 flex items-center font-mono text-xs">{f.cve.join(" / ")}<HelpPopover term="cve" /></p>
        )}
      </Card>

      <Card>
        <h2 className="mb-1 text-sm font-semibold">なぜ検出されたか</h2>
        <p className="text-sm">{f.why_detected}</p>
        <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
          <dt className="text-zinc-500">実行主体</dt><dd>{f.executor.agent}</dd>
          <dt className="text-zinc-500">モデル</dt><dd>{f.executor.model}</dd>
          <dt className="text-zinc-500">ツール</dt><dd>{f.executor.tool}</dd>
          <dt className="flex items-center text-zinc-500">危険度<HelpPopover term="risk_level" /></dt><dd>{f.risk_level}</dd>
        </dl>
      </Card>

      <Card>
        <h2 className="mb-2 text-sm font-semibold">どう直すか</h2>
        <RemediationPanel r={f.remediation} />
      </Card>

      <Card>
        <h2 className="mb-2 text-sm font-semibold">証拠</h2>
        <EvidencePanel evidence={f.evidence} />
      </Card>
    </main>
  );
}

export default function FindingPage() {
  return (
    <Suspense>
      <Detail />
    </Suspense>
  );
}
