"use client";

// The diagnosis loop, read only (docs/DIAGNOSIS_UI_DESIGN.md). Every fact shown here
// came from GET /api/assessments/{id}/diagnosis or the `diagnosis.updated` event: the
// server rebuilt it from the verified audit log. A view the server could not verify, or
// one this page cannot read, shows its reason and nothing else.
//
// This panel has no buttons that change anything. Starting a diagnosis, entering the
// owner's specification and the after-fix check come later (PR-C); L2 approval stays
// on the existing plan items (link only).
import Link from "next/link";
import { useState } from "react";
import {
  announcement, checkText, claimText, endText, evidenceText, fixResult, fmtIso, hypothesisStateLabel, nextText,
  observationText, planStateText, reasonText, refusalText, ruleText, shortHash, stateClass,
  stepLabel, stepsNewestFirst, type DiagnosisSlot,
} from "@/lib/diagnosisView";
import { DIAG_END } from "@/lib/labels";
import type {
  DiagnosisEvidence, DiagnosisFix, DiagnosisFixSide, DiagnosisHypothesis, DiagnosisNext, DiagnosisStep,
  DiagnosisView,
} from "@/lib/types";
import { Card, Pill } from "../ui";

const LINK = "font-semibold underline underline-offset-2 hover:text-zinc-950 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-900 dark:hover:text-white dark:focus-visible:outline-white";

function StateBadge({ state, purpose }: { state: string; purpose: DiagnosisHypothesis["purpose"] }) {
  return (
    <Pill className={`border ${stateClass(state)}`}>
      {hypothesisStateLabel({ state: state as DiagnosisHypothesis["state"], purpose })}
    </Pill>
  );
}

function AuditRef({ label, hash }: { label: string; hash: string | null }) {
  if (!hash) return null;
  return (
    <Link href={`?tab=logs#audit-${hash}`} scroll={false} className={`${LINK} font-mono font-normal`}
          title={`${label}の監査記録 ${hash}`}>
      {label} {shortHash(hash)}…
    </Link>
  );
}

function NextAction({ next }: { next: DiagnosisNext }) {
  const text = nextText(next);
  if (!text) return null;
  const action = next.kind === "plan_ended"
    ? (next.reason && Object.hasOwn(DIAG_END, next.reason) ? DIAG_END[next.reason].action : next.state === "FAILED" ? "audit" : null)
    : next.kind === "approve_l2" ? "approval" : next.kind === "check_audit" ? "audit" : null;
  return (
    <p className="text-sm">
      <span className="text-zinc-500">次に必要なこと：</span>
      <span className="font-semibold">{text}</span>
      {action === "approval" && next.item_id && (
        <> <a href={`#artex-item-${next.item_id}`} className={LINK}>承認待ちの項目へ</a></>
      )}
      {action === "audit" && <> <Link href="?tab=logs" scroll={false} className={LINK}>監査ログを見る</Link></>}
      {action === "findings" && <> <Link href="?tab=findings" scroll={false} className={LINK}>所見を見る</Link></>}
    </p>
  );
}

function Hypotheses({ view }: { view: DiagnosisView }) {
  if (view.hypotheses.length === 0) return <p className="text-sm text-zinc-500">まだ仮説はありません。</p>;
  const refs = (label: string, ids: string[]) => ids.length > 0 && (
    <span>{label} {ids.join("・")}</span>
  );
  return (
    <ul className="divide-y divide-zinc-100 rounded-xl border border-zinc-200 dark:divide-zinc-800 dark:border-zinc-800">
      {view.hypotheses.map((h) => (
        <li key={h.id} className="flex flex-col gap-1 p-3 sm:flex-row sm:items-start sm:justify-between sm:gap-3">
          <div className="min-w-0">
            <p className="text-sm">
              <span className="mr-1.5 font-mono text-xs text-zinc-500">{h.id}</span>
              <span className="font-medium">{claimText(h.claim)}</span>
              <span className="ml-1 text-xs text-zinc-500">（対象 {h.target_ref}・世代 {h.generation}）</span>
            </p>
            {h.purpose === "confirm_fix" && (
              <p className="text-xs text-zinc-600 dark:text-zinc-400">修正後の確認：{h.supersedes ?? "—"} を同じ検査で確かめ直します</p>
            )}
            <p className="mt-0.5 flex flex-wrap gap-x-3 text-xs text-zinc-500">
              {refs("根拠", h.basis)}{refs("支持", h.supporting)}{refs("反証", h.contradicting)}
              {refs("判断不能", h.inconclusive)}
            </p>
          </div>
          <div className="shrink-0"><StateBadge state={h.state} purpose={h.purpose} /></div>
        </li>
      ))}
    </ul>
  );
}

function Step({ s, view, evidence }: { s: DiagnosisStep; view: DiagnosisView; evidence: Map<string, DiagnosisEvidence> }) {
  const h = view.hypotheses.find((x) => x.id === s.hypothesis_id);
  const purpose = h?.purpose ?? "diagnose";
  const cited = s.evidence_refs.map((id) => evidence.get(id));
  const observed = observationText(s.observation.attrs);
  return (
    <li className="rounded-xl border border-zinc-200 dark:border-zinc-800">
      <details open className="group">
        <summary className="flex cursor-pointer list-none flex-wrap items-center gap-2 rounded-xl p-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-900 dark:focus-visible:outline-white">
          <span aria-hidden className="text-xs text-zinc-400 transition group-open:rotate-90">▶</span>
          {/* each plan numbers its steps from S1: the generation tells the rounds apart */}
          <span className="font-mono text-xs text-zinc-500">{stepLabel(s)}</span>
          <span className="font-medium">{checkText(s.catalog_id)}</span>
          <StateBadge state={s.judgement.to} purpose={purpose} />
        </summary>
        <dl className="grid grid-cols-1 gap-x-3 gap-y-1.5 border-t border-zinc-100 p-3 text-sm sm:grid-cols-[6rem_1fr] dark:border-zinc-800">
          <dt className="text-xs text-zinc-500 sm:pt-0.5">確かめた仮説</dt>
          <dd>{s.hypothesis_id}：{h ? claimText(h.claim) : "—"}</dd>
          <dt className="text-xs text-zinc-500 sm:pt-0.5">なぜ</dt>
          <dd>
            {reasonText(s.reason, s.hypothesis_id)}
            {cited.length > 0 && (
              <ul className="mt-0.5 text-xs text-zinc-600 dark:text-zinc-400">
                {cited.map((e, i) => <li key={s.evidence_refs[i]}>根拠 {e ? evidenceText(e) : `${s.evidence_refs[i]}：—`}</li>)}
              </ul>
            )}
          </dd>
          <dt className="text-xs text-zinc-500 sm:pt-0.5">承認</dt>
          <dd>{s.level === "L2" ? `L2・承認者 ${s.approved_by ?? "—"}` : `${s.level ?? "—"}（人の承認は不要）`}</dd>
          <dt className="text-xs text-zinc-500 sm:pt-0.5">観測</dt>
          <dd>
            <span className="mr-1 font-mono text-xs text-zinc-500">{s.observation.evidence_id}</span>
            {observed.length > 0 ? observed.join(" / ") : "—"}
          </dd>
          <dt className="text-xs text-zinc-500 sm:pt-0.5">判定</dt>
          <dd>
            <span className="font-semibold">{hypothesisStateLabel({ state: s.judgement.to, purpose })}</span>
            {" — "}{ruleText(s.judgement.rule)}
            {s.judgement.from && s.judgement.from !== s.judgement.to && (
              <span className="ml-1 text-xs text-zinc-500">（前：{hypothesisStateLabel({ state: s.judgement.from as DiagnosisStep["judgement"]["to"], purpose })}）</span>
            )}
          </dd>
          <dt className="text-xs text-zinc-500 sm:pt-0.5">証拠</dt>
          <dd className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
            <AuditRef label="検査結果" hash={s.result_audit_hash} />
            <AuditRef label="判定" hash={s.judged_audit_hash} />
            <span className="text-zinc-500">{fmtIso(s.at)}</span>
          </dd>
        </dl>
      </details>
    </li>
  );
}

function FixSide({ title, side, purpose }: { title: string; side: DiagnosisFixSide | null; purpose: DiagnosisHypothesis["purpose"] }) {
  return (
    <div className="min-w-0 rounded-lg bg-zinc-50 p-2.5 dark:bg-zinc-800/60">
      <p className="text-xs text-zinc-500">{title}{side ? `（世代 ${side.generation}）` : ""}</p>
      {side ? (
        <>
          <p className="mt-1"><StateBadge state={side.to} purpose={purpose} /></p>
          <p className="mt-1 text-xs">{ruleText(side.rule)}</p>
          <p className="mt-1 text-xs"><AuditRef label="判定" hash={side.judged_audit_hash} /></p>
        </>
      ) : <p className="mt-1 text-xs text-zinc-500">まだ検査していません</p>}
    </div>
  );
}

function FixComparison({ fix }: { fix: DiagnosisFix[] }) {
  return (
    <ul className="space-y-3">
      {fix.map((f) => {
        const result = fixResult(f.result);
        return (
          <li key={f.hypothesis_id} className="rounded-xl border border-zinc-200 p-3 dark:border-zinc-800">
            <p className="text-sm">
              <span className="text-zinc-500">検査：</span><span className="font-medium">{checkText(f.catalog_id)}</span>
              <span className="ml-1 text-xs text-zinc-500">（{f.supersedes} → {f.hypothesis_id}）</span>
            </p>
            {/* two columns from sm up, stacked on a phone */}
            <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
              <FixSide title="修正前" side={f.before} purpose="diagnose" />
              <FixSide title="修正後" side={f.after} purpose="confirm_fix" />
            </div>
            <p className="mt-2 text-sm">
              <span className="text-zinc-500">結果：</span>
              <Pill className={`border ${result.cls}`}>{result.label}</Pill>
            </p>
          </li>
        );
      })}
    </ul>
  );
}

function EvidenceList({ evidence }: { evidence: DiagnosisEvidence[] }) {
  return (
    <details className="rounded-xl border border-zinc-200 dark:border-zinc-800">
      <summary className="cursor-pointer rounded-xl p-3 text-sm font-semibold focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-900 dark:focus-visible:outline-white">
        観測の一覧（{evidence.length} 件）
      </summary>
      <ul className="divide-y divide-zinc-100 border-t border-zinc-100 text-sm dark:divide-zinc-800 dark:border-zinc-800">
        {evidence.map((e) => (
          <li key={e.evidence_id} className="p-3">
            <p>{evidenceText(e)}<span className="ml-1 text-xs text-zinc-500">対象 {e.target_ref}・世代 {e.generation}</span></p>
            <p className="text-xs text-zinc-600 dark:text-zinc-400">{observationText(e.attrs).join(" / ") || "—"}</p>
            <p className="mt-0.5 flex flex-wrap gap-x-3 text-xs text-zinc-500">
              {e.recorded_by && <span>記録者 {e.recorded_by}</span>}
              {e.audit_hash ? <AuditRef label="検査結果" hash={e.audit_hash} /> : <AuditRef label="記録" hash={e.journal_hash} />}
              <span>{fmtIso(e.at)}</span>
            </p>
          </li>
        ))}
      </ul>
    </details>
  );
}

function Results({ view }: { view: DiagnosisView }) {
  const evidence = new Map(view.evidence.map((e) => [e.evidence_id, e]));
  const steps = stepsNewestFirst(view);
  return (
    <div className="space-y-5">
      <section aria-labelledby="diag-hypotheses">
        <h3 id="diag-hypotheses" className="mb-2 text-sm font-semibold">① 確認しようとしていること</h3>
        <Hypotheses view={view} />
      </section>
      <section aria-labelledby="diag-steps">
        <h3 id="diag-steps" className="mb-2 text-sm font-semibold">② 手順の記録（新しい順）</h3>
        {steps.length === 0 ? <p className="text-sm text-zinc-500">まだ検査した手順はありません。</p> : (
          <ol className="space-y-2">
            {steps.map((s) => <Step key={s.judged_audit_hash} s={s} view={view} evidence={evidence} />)}
          </ol>
        )}
      </section>
      {view.fix_comparison.length > 0 && (
        <section aria-labelledby="diag-fix">
          <h3 id="diag-fix" className="mb-2 text-sm font-semibold">③ 修正の前後</h3>
          <FixComparison fix={view.fix_comparison} />
        </section>
      )}
      {view.evidence.length > 0 && <EvidenceList evidence={view.evidence} />}
    </div>
  );
}

export function DiagnosisLoopPanel({ slot }: { slot: DiagnosisSlot }) {
  const current = slot.kind === "view" ? slot.view : null;
  // one sentence for screen readers when a new judgement (or a refusal) arrives
  const [seen, setSeen] = useState<{ view: DiagnosisView | null; message: string | null }>({ view: null, message: null });
  if (current !== seen.view) {
    // an update without a new judgement keeps the last sentence (a live region reads changes only)
    setSeen({ view: current, message: (current && seen.view ? announcement(seen.view, current) : null) ?? seen.message });
  }
  if (slot.kind !== "view") return null;
  const view = slot.view;
  const plan = view.status === "ok" ? view.plan : null;
  return (
    <Card className="mb-6">
      <section aria-labelledby="diag-title" data-testid="diagnosis-loop">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0">
            <h2 id="diag-title" className="font-semibold">診断ループ</h2>
            <p className="mt-0.5 text-xs text-zinc-500">
              観測 → 仮説 → 検査 → 判定 の記録です。表示しているのは、監査ログで確かめられた事実と、決まった判定規則の理由だけです。
            </p>
          </div>
          <div className="flex flex-wrap gap-1.5">
            <Pill className="border border-violet-300 text-violet-800 dark:border-violet-700 dark:text-violet-200">ラボ専用</Pill>
            {view.status === "ok" && view.generation !== null && (
              <Pill className="border border-zinc-300 text-zinc-700 dark:border-zinc-700 dark:text-zinc-300">世代 {view.generation}</Pill>
            )}
            {view.restored && (
              <Pill className="border border-sky-300 text-sky-900 dark:border-sky-700 dark:text-sky-200">再起動前の記録（読み取り専用）</Pill>
            )}
          </div>
        </div>

        <div role="status" aria-live="polite" className="sr-only">{seen.message ?? ""}</div>

        {slot.stale && (
          <p role="status" className="mt-3 rounded-lg border border-amber-300 bg-amber-50 p-2 text-xs text-amber-950 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100">
            最新の状態を取得できませんでした。前回確かめた内容を表示しています。
          </p>
        )}
        {!view.persisted && (
          <p role="status" className="mt-3 rounded-lg border border-amber-300 bg-amber-50 p-2 text-xs text-amber-950 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100">
            診断の状態をファイルに保存できていません。再起動すると、この記録は表示できなくなります。
          </p>
        )}

        <div className="mt-3 space-y-1">
          {plan && (
            <p className="text-sm">
              <span className="text-zinc-500">状態：</span>
              <span className="font-semibold">{planStateText(plan.state)}</span>
              <span className="ml-1 text-zinc-500">（{plan.steps_used}{plan.steps_max !== null ? ` / ${plan.steps_max}` : ""} 手順）</span>
              {/* the end reason is said once: on the "next" line when that line carries it */}
              {plan.reason && view.next.kind !== "plan_ended" && <span className="ml-1">— {endText(plan)}</span>}
            </p>
          )}
          {view.status !== "unverified" && <NextAction next={view.next} />}
        </div>

        <div className="mt-4">
          {view.status === "not_started" && (
            <p className="text-sm text-zinc-500">このラボでは、まだ診断ループを実行していません。</p>
          )}
          {view.status === "unverified" && (
            <div role="alert" className="rounded-xl border border-red-300 bg-red-50 p-3 text-sm text-red-900 dark:border-red-800 dark:bg-red-950/40 dark:text-red-100">
              <p className="font-semibold">記録を確かめられないため、診断ループの結果を表示していません。</p>
              <p className="mt-1">理由：{refusalText(view.reason)}</p>
              <p className="mt-1 text-xs">
                推測で表示を埋めることはしません。<Link href="?tab=logs" scroll={false} className={LINK}>監査ログを確認</Link>してください。
              </p>
            </div>
          )}
          {view.status === "ok" && <Results view={view} />}
        </div>
      </section>
    </Card>
  );
}
