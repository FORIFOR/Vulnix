// The diagnosis loop panel's logic, kept out of the component so it can be tested
// without a browser. docs/DIAGNOSIS_UI_DESIGN.md, docs/DIAGNOSIS_READ_API.md.
//
// Rules:
// - Only a view whose status is "ok" shows results. Anything else (refused by the
//   server, or malformed here) shows the reason and nothing else.
// - A view for another assessment is never shown (an event or response is dropped).
// - Every text comes from the fixed tables in labels.ts. An id without an entry is
//   shown as "未定義の値（id）", never guessed.
import {
  DIAG_ATTR_VALUE, DIAG_CHECK, DIAG_CLAIM, DIAG_END, DIAG_EVIDENCE_KIND, DIAG_FIX_RESULT, DIAG_FIX_STATE, DIAG_NEXT,
  DIAG_PLAN_STATE, DIAG_REASON, DIAG_REFUSAL, DIAG_REQUIREMENT, DIAG_RULE, DIAG_SOURCE, DIAG_STATE,
} from "./labels";
import type {
  DiagnosisAttrs, DiagnosisEvidence, DiagnosisHypothesis, DiagnosisNext, DiagnosisPlan, DiagnosisStep,
  DiagnosisView,
} from "./types";

/** What the panel has: still loading, nothing to show (a real site, an ownership flow:
 *  the API answers 404), or a view. `stale` marks a view kept after a failed refresh. */
export type DiagnosisSlot =
  | { kind: "loading" }
  | { kind: "absent" }
  | { kind: "view"; view: DiagnosisView; stale: boolean };

const STATUSES = new Set(["not_started", "ok", "unverified"]);
const HASH = /^[0-9a-f]{64}$/;

export function unknown(id: unknown): string {
  return `未定義の値（${String(id)}）`;
}

function word(table: Record<string, string>, id: unknown): string {
  return typeof id === "string" && Object.hasOwn(table, id) ? table[id] : unknown(id);
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function emptied(view: DiagnosisView, reason?: string): DiagnosisView {
  return {
    ...view, status: reason ? "unverified" : view.status, reason: reason ?? view.reason,
    plan: null, hypotheses: [], steps: [], evidence: [], fix_comparison: [],
    next: { kind: reason || view.status === "unverified" ? "check_audit" : "none" },
  };
}

const isStr = (v: unknown): v is string => typeof v === "string";
const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const strOrNull = (v: unknown) => v === null || v === undefined || isStr(v);
const strList = (v: unknown) => Array.isArray(v) && v.every(isStr);
const attrsOk = (v: unknown) => isObj(v) && Object.values(v).every((x) => isStr(x) || isNum(x) || typeof x === "boolean");
const hashOrNull = (v: unknown) => v === null || v === undefined || (isStr(v) && HASH.test(v));

function stepIsAudited(s: unknown): s is DiagnosisStep {
  return isObj(s) && isStr(s.result_audit_hash) && HASH.test(s.result_audit_hash)
    && isStr(s.judged_audit_hash) && HASH.test(s.judged_audit_hash)
    && isObj(s.judgement) && isStr(s.judgement.to) && isStr(s.judgement.rule) && strOrNull(s.judgement.from)
    && isObj(s.observation) && isStr(s.observation.evidence_id) && attrsOk(s.observation.attrs)
    && isStr(s.catalog_id) && isStr(s.hypothesis_id) && strList(s.evidence_refs) && isNum(s.generation)
    && strOrNull(s.step_id) && strOrNull(s.level) && strOrNull(s.reason) && strOrNull(s.approved_by)
    && strOrNull(s.at);
}

function hypothesisOk(h: unknown): boolean {
  return isObj(h) && isStr(h.id) && isStr(h.claim) && isStr(h.state) && isStr(h.target_ref)
    && isStr(h.purpose) && isNum(h.generation) && strOrNull(h.supersedes)
    && ["basis", "supporting", "contradicting", "inconclusive"].every((k) => strList(h[k]));
}

function evidenceOk(e: unknown): boolean {
  return isObj(e) && isStr(e.evidence_id) && isStr(e.kind) && isStr(e.source) && isStr(e.target_ref)
    && isNum(e.generation) && attrsOk(e.attrs) && hashOrNull(e.audit_hash) && hashOrNull(e.journal_hash)
    && strOrNull(e.recorded_by) && strOrNull(e.at);
}

const sideOk = (x: unknown) => x === null || (isObj(x) && isNum(x.generation) && isStr(x.to) && isStr(x.rule)
  && isStr(x.judged_audit_hash) && HASH.test(x.judged_audit_hash));

function fixOk(f: unknown): boolean {
  return isObj(f) && isStr(f.hypothesis_id) && isStr(f.supersedes) && strOrNull(f.catalog_id)
    && sideOk(f.before) && sideOk(f.after) && isStr(f.result);
}

function planOk(p: unknown): boolean {
  return p === null || (isObj(p) && isStr(p.plan_id) && isStr(p.state) && strOrNull(p.reason)
    && isNum(p.steps_used) && (p.steps_max === null || isNum(p.steps_max)));
}

/** Check a response or event body before it reaches the screen. Returns null when it
 *  belongs to another assessment (dropped), an "unverified" view when it is not in the
 *  expected shape, and otherwise the view. A view that is not "ok" never keeps results. */
export function parseDiagnosis(raw: unknown, assessmentId: string): DiagnosisView | null {
  if (!isObj(raw) || raw.assessment_id !== assessmentId) return null;
  const base: DiagnosisView = {
    schema_version: 1, lab_only: true, assessment_id: assessmentId, status: "unverified",
    // persisted defaults to true: a malformed answer is not evidence of a failed save
    restored: raw.restored === true, persisted: raw.persisted !== false, generation: null, plan: null,
    hypotheses: [], steps: [], evidence: [], fix_comparison: [], next: { kind: "check_audit" },
  };
  if (raw.schema_version !== 1 || raw.lab_only !== true || typeof raw.status !== "string"
      || !STATUSES.has(raw.status)) {
    return emptied(base, "invalid_response");
  }
  const view = raw as unknown as DiagnosisView;
  if (view.status !== "ok") return emptied({ ...base, ...view }, view.status === "unverified" ? (view.reason ?? "invalid_response") : undefined);
  const lists = [view.hypotheses, view.steps, view.evidence, view.fix_comparison];
  if (!lists.every(Array.isArray) || !isObj(view.next) || !isStr(view.next.kind)) {
    return emptied(base, "invalid_response");
  }
  // every step must name both of its audit records (the server checked them against the chain);
  // any other field out of shape is a malformed answer, never rendered half-way
  if (!view.steps.every(stepIsAudited) || !view.hypotheses.every(hypothesisOk) || !view.evidence.every(evidenceOk)
      || !view.fix_comparison.every(fixOk) || !planOk(view.plan) || !(view.generation === null || isNum(view.generation))) {
    return emptied(base, "invalid_response");
  }
  return view;
}

/** Apply a `diagnosis.updated` event. The caller has already dropped duplicate and
 *  stale events by `seq` (lib/useAssessment.ts); this only checks what the event holds. */
export function applyDiagnosisEvent(slot: DiagnosisSlot, ev: { assessment_id?: unknown; diagnosis?: unknown },
                                    assessmentId: string): DiagnosisSlot {
  if (ev.assessment_id !== assessmentId) return slot;
  const view = parseDiagnosis(ev.diagnosis, assessmentId);
  return view ? { kind: "view", view, stale: false } : slot;
}

/** The result of GET .../diagnosis: a view, 404 (nothing to show), or another failure
 *  (the last view is kept and marked stale; a refusal is never turned into results). */
export function slotFromFetch(prev: DiagnosisSlot, outcome: { ok: true; body: unknown } | { ok: false; status: number },
                              assessmentId: string): DiagnosisSlot {
  if (outcome.ok) {
    const view = parseDiagnosis(outcome.body, assessmentId);
    return view ? { kind: "view", view, stale: false } : { kind: "view", view: emptied({
      schema_version: 1, lab_only: true, assessment_id: assessmentId, status: "unverified", restored: false,
      persisted: true, generation: null, plan: null, hypotheses: [], steps: [], evidence: [], fix_comparison: [],
      next: { kind: "check_audit" } }, "invalid_response"), stale: false };
  }
  if (outcome.status === 404) return { kind: "absent" };
  return prev.kind === "view" ? { ...prev, stale: true } : prev;
}

// ---- words ---------------------------------------------------------------------------

export function hypothesisStateLabel(h: Pick<DiagnosisHypothesis, "state" | "purpose">): string {
  if (h.purpose === "confirm_fix" && Object.hasOwn(DIAG_FIX_STATE, h.state)) return DIAG_FIX_STATE[h.state];
  return Object.hasOwn(DIAG_STATE, h.state) ? DIAG_STATE[h.state].label : unknown(h.state);
}

export function stateClass(state: string): string {
  return Object.hasOwn(DIAG_STATE, state) ? DIAG_STATE[state].cls : DIAG_STATE.open.cls;
}

export const claimText = (claim: string) => word(DIAG_CLAIM, claim);
export const checkText = (catalogId: string | null) => word(DIAG_CHECK, catalogId);
export const ruleText = (rule: string) => word(DIAG_RULE, rule);
export const refusalText = (reason: string | undefined) => word(DIAG_REFUSAL, reason);
export const planStateText = (state: string) => word(DIAG_PLAN_STATE, state);

export function reasonText(reason: string | null, hypothesisId: string): string {
  return typeof reason === "string" && Object.hasOwn(DIAG_REASON, reason)
    ? DIAG_REASON[reason].replace("{h}", hypothesisId) : unknown(reason);
}

/** Observed facts in words: "応答 200"、"所有者 B の対照 成立" ... */
export function observationText(attrs: DiagnosisAttrs): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (k === "status") {
      out.push(typeof v === "number" ? `応答 ${v}` : "応答なし");
    } else if (k === "requirement") {
      out.push(`仕様：${word(DIAG_REQUIREMENT, v)}`);
    } else if (Object.hasOwn(DIAG_ATTR_VALUE, k)) {
      const text = DIAG_ATTR_VALUE[k][String(v)];
      if (text === undefined) out.push(unknown(`${k}=${v}`));
      else if (text) out.push(text);
    } else {
      out.push(unknown(`${k}=${v}`));
    }
  }
  return out;
}

export function evidenceText(e: Pick<DiagnosisEvidence, "evidence_id" | "kind" | "source">): string {
  return `${e.evidence_id}：${word(DIAG_EVIDENCE_KIND, e.kind)}（${word(DIAG_SOURCE, e.source)}）`;
}

export function endText(plan: Pick<DiagnosisPlan, "state" | "reason">): string {
  if (plan.reason && Object.hasOwn(DIAG_END, plan.reason)) return DIAG_END[plan.reason].text;
  // "item_<status>": the Worker item did not complete (aegis.adaptive_plan_runner)
  if (plan.reason && /^item_[a-z_]+$/.test(plan.reason)) return DIAG_END.execute_failed.text;
  // an unknown reason (or the server's "other") is not interpreted: state and raw id only
  return `${planStateText(plan.state)}（理由：${plan.reason ? unknown(plan.reason) : "記録なし"}）`;
}

export function fixResult(result: string): { label: string; cls: string } {
  return Object.hasOwn(DIAG_FIX_RESULT, result) ? DIAG_FIX_RESULT[result]
    : { label: unknown(result), cls: DIAG_STATE.open.cls };
}

export function nextText(next: DiagnosisNext): string {
  if (next.kind === "plan_ended") return endText({ state: next.state ?? "", reason: next.reason ?? null });
  return word(DIAG_NEXT, next.kind);
}

export function shortHash(h: string | null | undefined): string {
  return h ? h.slice(0, 12) : "—";
}

export function fmtIso(at: string | null | undefined): string {
  if (!at) return "—";
  const d = new Date(at);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString("ja-JP", { hour12: false });
}

/** "S1" in the first generation, "世代 2・S1" after a fix (each plan starts again at S1). */
export function stepLabel(s: Pick<DiagnosisStep, "step_id" | "generation">): string {
  const id = s.step_id ?? "手順";
  return s.generation > 1 ? `世代 ${s.generation}・${id}` : id;
}

/** Newest first, as the design shows them. The API sends them oldest first. */
export function stepsNewestFirst(view: DiagnosisView): DiagnosisStep[] {
  return [...view.steps].reverse();
}

/** One sentence for the live region when a new judgement or a refusal arrives. */
export function announcement(prev: DiagnosisView | null, next: DiagnosisView): string | null {
  if (next.status === "unverified" && prev?.status !== "unverified") {
    return "診断の記録を確かめられないため、結果を表示していません";
  }
  if (next.status !== "ok") return null;
  const seen = new Set((prev?.status === "ok" ? prev.steps : []).map((s) => s.judged_audit_hash));
  const fresh = next.steps.filter((s) => !seen.has(s.judged_audit_hash));
  const last = fresh.at(-1);
  if (!last || !prev) return null;
  const h = next.hypotheses.find((x) => x.id === last.hypothesis_id);
  const label = h ? hypothesisStateLabel({ state: last.judgement.to, purpose: h.purpose })
    : hypothesisStateLabel({ state: last.judgement.to, purpose: "diagnose" });
  return `${stepLabel(last)} の判定：${label}`;
}
