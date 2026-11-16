import type { Finding } from "@/lib/types";

const PURPOSE = { session: "認証用（所有者仕様）", non_session: "一般用途（所有者仕様）", unknown: "用途未確認" };
const RESULT = { detected: "属性不足・不一致を確認", candidate: "確認候補", none: "属性上の問題は未検出" };

export function CookieCheckList({ checks }: { checks: NonNullable<Finding["cookie_checks"]> }) {
  return (
    <div className="mt-3 min-w-0 rounded-lg border border-zinc-200 p-2 text-xs dark:border-zinc-700" aria-label="Cookieごとの確認結果">
      <p className="font-semibold">Cookieごとの確認結果</p>
      <ul className="mt-1 space-y-1">
        {checks.map((check, index) => (
          <li key={`${check.name}-${index}`} className="min-w-0 break-words">
            <span className="font-mono">{check.name}</span>：{PURPOSE[check.purpose]}／{check.purpose === "non_session" ? "認証セッションの判定対象外" : RESULT[check.verdict]}
            {check.gaps.length > 0 && <span>（{check.gaps.join("、")}）</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}
