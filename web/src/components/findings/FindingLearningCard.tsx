import { Card } from "@/components/ui";
import { GLOSSARY } from "@/lib/glossary";
import { currentIdorEvidence } from "@/lib/idorEvidence";
import type { Finding } from "@/lib/types";

export function FindingLearningCard({ finding: f, localLab, busy = false }: { finding: Finding; localLab: boolean; busy?: boolean }) {
  const term = f.help_term ? GLOSSARY[f.help_term] : undefined;
  const isIdor = f.help_term === "idor" || f.category.toLowerCase() === "idor";
  const evidence = isIdor ? currentIdorEvidence(f, busy) : null;
  return (
    <Card>
      <h2 className="text-base font-semibold">この問題をひと目で理解</h2>
      {localLab && <p className="mt-1 text-xs text-zinc-500">ローカル模擬ラボ・テストアカウントの検証です。顧客データではありません。</p>}
      <dl className="mt-3 space-y-3 text-sm">
        <div><dt className="font-semibold">どこが弱い？</dt><dd className="mt-1">{term?.detail || f.why_detected || "弱点の説明はまだ記録されていません。"}</dd></div>
        <div><dt className="font-semibold">何が起こる？</dt><dd className="mt-1">{term?.easy || f.summary}</dd><dd className="mt-1 text-xs text-zinc-500">問題が成立する場合の一般的な影響です。今回の検証結果とは区別してください。</dd></div>
        <div><dt className="font-semibold">どう直す？</dt><dd className="mt-1">{f.remediation.steps[0] || "修正手順はまだ記録されていません。"}</dd></div>
      </dl>
      {evidence && (
        <section aria-label="最新のIDOR検証" className="mt-4 rounded-lg border border-zinc-200 p-3 dark:border-zinc-700">
          <h3 className="text-sm font-semibold">最新の証拠で確認できること</h3>
          <p className="mt-2 text-lg font-bold">
            {evidence.outcome === "pending" ? "検証中"
              : evidence.outcome === "unavailable" ? "修正確認できず"
              : evidence.outcome === "read" ? "別アカウントのデータ取得を確認"
              : evidence.outcome === "blocked" ? "今回のアクセスは拒否されました"
                : "最新の証拠だけでは成立を確認できません"}
          </p>
          {evidence.outcome === "pending" || evidence.outcome === "unavailable" ? (
            <p className="mt-2 text-sm">今回の検証結果はまだ確認できません。以前の証拠を現在の結果として表示しません。</p>
          ) : <><dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
            <dt>アクセスしたアカウント</dt><dd className="break-all font-mono">{evidence.caller ?? "記録なし"}</dd>
            <dt>データの持ち主</dt><dd className="break-all font-mono">{evidence.owner ?? "記録なし"}</dd>
            <dt>HTTP結果</dt><dd>{evidence.status ?? "記録なし"}</dd>
            <dt>証拠ID</dt><dd className="break-all font-mono">{evidence.evidenceId ?? "証拠なし"}</dd>
          </dl>
          <p className="mt-2 text-xs text-zinc-500">最後に添付された証拠のみを表示しています。過去の成功結果は補いません。拒否された場合も、他の経路まで安全と確認したものではありません。</p></>}
        </section>
      )}
    </Card>
  );
}
