import type { AuditEntry } from "@/lib/types";

export function RawLogViewer({ entries }: { entries: AuditEntry[] }) {
  return (
    <details className="rounded-lg border border-zinc-200 dark:border-zinc-800">
      <summary className="cursor-pointer px-3 py-2 text-sm font-semibold">生ログ（JSONL・専門家向け）</summary>
      <pre className="max-h-[32rem] overflow-auto border-t border-zinc-200 p-3 text-[11px] leading-relaxed dark:border-zinc-800">
        {entries.map((e) => JSON.stringify(e)).join("\n")}
      </pre>
    </details>
  );
}
