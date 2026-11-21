"use client";

import { useEffect, useState } from "react";
import { fmtTime } from "@/lib/labels";
import type { Evidence } from "@/lib/types";

/** `#evidence-<id>` in the address (a link from the diagnosis loop) opens that record. */
export function evidenceAnchor(evidenceId: string): string {
  return `evidence-${evidenceId}`;
}

export function EvidencePanel({ evidence }: { evidence: Evidence[] }) {
  const [target, setTarget] = useState<string | null>(null);
  useEffect(() => {
    const read = () => setTarget(window.location.hash.replace(/^#/, "") || null);
    read();
    window.addEventListener("hashchange", read);
    return () => window.removeEventListener("hashchange", read);
  }, []);
  useEffect(() => {
    if (target) document.getElementById(target)?.scrollIntoView({ block: "start" });
  }, [target, evidence.length]);
  return (
    <div className="space-y-2">
      {evidence.map((e) => (
        <details key={e.evidence_id} id={evidenceAnchor(e.evidence_id)} open={target === evidenceAnchor(e.evidence_id) || undefined}
                 className="scroll-mt-24 rounded-lg border border-zinc-200 dark:border-zinc-700">
          <summary className="cursor-pointer px-3 py-2 text-sm">
            <span className="font-mono text-xs">{e.evidence_id}</span>
            <span className="ml-2 text-zinc-600 dark:text-zinc-400">{e.kind}</span>
            <span className="ml-2 text-xs text-zinc-500">保存: {fmtTime(e.saved_at)}</span>
          </summary>
          <div className="border-t border-zinc-200 px-3 py-2 dark:border-zinc-700">
            {e.audit_hash && (
              <p className="mb-2 break-all text-xs text-zinc-500">
                監査ハッシュ: <span className="font-mono">{e.audit_hash}</span>
              </p>
            )}
            <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-zinc-50 p-2 text-xs dark:bg-zinc-950">
              {pretty(e.content)}
            </pre>
          </div>
        </details>
      ))}
    </div>
  );
}

function pretty(s: string) {
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
}
