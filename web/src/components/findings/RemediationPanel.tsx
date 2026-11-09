import type { Finding } from "@/lib/types";

export function RemediationPanel({ r }: { r: Finding["remediation"] }) {
  return (
    <div className="text-sm">
      <ol className="list-decimal space-y-1 pl-5">
        {r.steps.map((s) => <li key={s}>{s}</li>)}
      </ol>
      <p className="mt-2 text-zinc-600 dark:text-zinc-400">
        <span className="font-semibold">修正後の確認方法：</span>{r.how_to_verify}
      </p>
    </div>
  );
}
