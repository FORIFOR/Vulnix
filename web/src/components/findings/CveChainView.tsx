import type { CveChain } from "@/lib/types";

type Step = { label: string; value: string; state: "done" | "no" | "open" };

const RANGE: Record<string, string> = { eq: "=", ge: "≥", gt: ">", le: "≤", lt: "<" };

function range(r: Record<string, string>): string {
  return Object.entries(r).filter(([k]) => k in RANGE).map(([k, v]) => `${RANGE[k]} ${v}`).join(" かつ ");
}

/** Each link of a CVE's impact chain, shown only as far as its own evidence goes. */
export function steps(c: CveChain): Step[] {
  const affected = c.status !== "not_affected";
  const history = c.lab_history ?? (c.reproduction ? [c.reproduction] : []);
  const provenOnce = history.includes("proven");
  const obs = (v: boolean | null, yes: string, no: string): [string, Step["state"]] =>
    v === true ? [yes, "done"] : v === false ? [no, "no"] : ["未確認", "open"];
  const [confValue, confState] = obs(c.configuration.observed, "条件を満たす設定を観測", "条件を満たさない設定を観測");
  const [reachValue, reachState] = obs(c.reachability.observed, "到達できる経路を観測", "到達できない");
  return [
    { label: "対象ソフトウェアの特定", value: `${c.product}（${c.version_source}で観測）`, state: "done" },
    { label: "影響バージョンとの一致", value: affected ? `${c.version}（影響範囲 ${c.affected_ranges.map(range).join(" / ") || "未登録"}）`
      : `${c.version} は影響範囲外`, state: affected ? "done" : "no" },
    { label: "既知の影響条件", value: `${c.configuration.required} — ${confValue}`, state: confState },
    { label: "到達性", value: `${c.reachability.path ?? "経路は未登録"} — ${reachValue}`, state: reachState },
    { label: "隔離ラボでの影響確認", value: !c.lab_check ? "審査済みのラボ検査なし（未確認）"
      : provenOnce ? "影響を確認（隔離ラボ）" : c.reproduction === "not_reproduced" ? "再現せず" : "未実施",
      state: provenOnce ? "done" : c.lab_check && c.reproduction === "not_reproduced" ? "no" : "open" },
    ...(provenOnce ? [{ label: "修正後の再検証", value: c.fixed_after_reproduction ? "再現せず" : "未実施",
      state: (c.fixed_after_reproduction ? "done" : "open") as Step["state"] }] : []),
  ];
}

const DOT = { done: "bg-emerald-500", no: "bg-zinc-400", open: "border border-amber-500 bg-white dark:bg-zinc-900" };

export default function CveChainView({ chain }: { chain: CveChain[] }) {
  return (
    <div className="mt-2 space-y-2">
      {chain.map((c) => (
        <section key={c.cve} aria-label={`${c.cve} の影響の確認状況`}
          className="rounded-xl border border-zinc-200 bg-white p-3 text-xs dark:border-zinc-800 dark:bg-zinc-900">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono font-semibold">{c.cve}</span>
            {c.kev && <span className="rounded-full bg-red-100 px-2 py-0.5 text-red-800 dark:bg-red-950/50 dark:text-red-200">悪用確認済み（KEV）</span>}
            <span className="rounded-full bg-zinc-100 px-2 py-0.5 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">{c.status_label}</span>
          </div>
          <ol className="mt-2 space-y-1.5">
            {steps(c).map((s) => (
              <li key={s.label} className="flex items-start gap-2">
                <span aria-hidden="true" className={`mt-1 h-2.5 w-2.5 shrink-0 rounded-full ${DOT[s.state]}`} />
                <span><span className="text-zinc-500">{s.label}</span><span className="block wrap-anywhere">{s.value}</span></span>
              </li>
            ))}
          </ol>
          {c.fixed_in.length > 0
            ? <p className="mt-2">推奨対応：公式勧告に基づき修正版（{c.fixed_in.join(" / ")} 以降）に更新し、同じ条件で再検証する。</p>
            : <p className="mt-2">修正版：取り込んだ脆弱性情報に記載がないため未確認（推測では補いません）。推奨対応：製品の公式勧告で修正版を確認して更新し、同じ条件で再検証する。</p>}
          <p className="mt-1 text-zinc-500">{c.confirmed_impact || c.fixed_after_reproduction
            ? "隔離ラボでの結果であり、実際の配備環境の安全性を保証するものではありません。"
            : "版の一致だけでは影響は確定しません。未確認の項目は推測で補っていません。"}</p>
        </section>
      ))}
    </div>
  );
}
