import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

// diagnosisView.ts imports ./labels: transpile both and point the import at the labels module.
const toUrl = (file, replace = (s) => s) => {
  const src = readFileSync(new URL(`../src/lib/${file}`, import.meta.url), "utf8");
  const { outputText } = ts.transpileModule(src, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
  return `data:text/javascript;base64,${Buffer.from(replace(outputText)).toString("base64")}`;
};
const labelsUrl = toUrl("labels.ts");
const labels = await import(labelsUrl);
const dv = await import(toUrl("diagnosisView.ts", (s) => s.replace(/from "\.\/labels"/g, `from "${labelsUrl}"`)));
const polling = await import(toUrl("polling.ts"));

const H = (c) => c.repeat(64);
const step = (over = {}) => ({
  plan_id: "ap_1", step_id: "S2", catalog_id: "l2_idor", level: "L2", hypothesis_id: "H2", target_ref: "T2",
  reason: "test_hypothesis", evidence_refs: ["E2"], approved_by: "approver-human", generation: 1,
  observation: { evidence_id: "E5", attrs: { status: 200, auth: "other_account", control: "established", reproduction: "proven", own_resource: false } },
  judgement: { from: "open", to: "supported", rule: "cross_account_read" },
  result_audit_hash: H("a"), judged_audit_hash: H("b"), at: "2026-11-21T10:42:00Z", ...over,
});
const okView = (over = {}) => ({
  schema_version: 1, lab_only: true, assessment_id: "scan_001", status: "ok", restored: false, persisted: true,
  diag_id: "dg_1", generation: 1,
  plan: { plan_id: "ap_1", state: "COMPLETED", reason: "all_settled", steps_used: 2, steps_max: 3 },
  hypotheses: [{ id: "H2", claim: "other_account_read", target_ref: "T2", state: "supported", purpose: "diagnose",
                 generation: 1, supersedes: null, basis: ["E2"], supporting: ["E5"], contradicting: [], inconclusive: [] }],
  steps: [step()], evidence: [{ evidence_id: "E2", kind: "account_resource_link", source: "l1", target_ref: "T2",
                                generation: 1, attrs: { present: true }, audit_hash: H("c") }],
  fix_comparison: [], next: { kind: "confirm_fix_available" }, ...over,
});

test("a refused view shows its reason and none of the results, whatever else it carries", () => {
  const v = dv.parseDiagnosis({ ...okView(), status: "unverified", reason: "audit_chain_invalid" }, "scan_001");
  assert.equal(v.status, "unverified");
  assert.equal(v.reason, "audit_chain_invalid");
  assert.deepEqual([v.plan, v.hypotheses, v.steps, v.evidence, v.fix_comparison], [null, [], [], [], []]);
  assert.equal(v.next.kind, "check_audit");
});

test("a view for another assessment is dropped, an event for it changes nothing", () => {
  assert.equal(dv.parseDiagnosis(okView({ assessment_id: "scan_999" }), "scan_001"), null);
  const slot = { kind: "view", view: dv.parseDiagnosis(okView(), "scan_001"), stale: false };
  assert.equal(dv.applyDiagnosisEvent(slot, { assessment_id: "scan_999", diagnosis: okView({ assessment_id: "scan_999" }) }, "scan_001"), slot);
  assert.equal(dv.applyDiagnosisEvent(slot, { assessment_id: "scan_001", diagnosis: okView({ assessment_id: "scan_999" }) }, "scan_001"), slot);
});

test("a step without both audit hashes, or an unknown shape, is not shown as a result", () => {
  for (const bad of [
    okView({ steps: [step({ result_audit_hash: "" })] }),
    okView({ steps: [step({ judged_audit_hash: "not-a-hash" })] }),
    okView({ schema_version: 2 }),
    okView({ lab_only: false }),
    okView({ status: "maybe" }),
    okView({ hypotheses: "x" }),
    okView({ hypotheses: [{ ...okView().hypotheses[0], basis: undefined }] }),
    okView({ plan: { plan_id: "p", state: "COMPLETED", reason: null, steps_used: { x: 1 }, steps_max: 3 } }),
    okView({ steps: [step({ evidence_refs: "E2" })] }),
    okView({ steps: [step({ observation: { evidence_id: "E5", attrs: { status: { nested: 1 } } } })] }),
    okView({ evidence: [{ evidence_id: "E2" }] }),
    okView({ fix_comparison: [{ hypothesis_id: "H4", supersedes: "H2", catalog_id: "l2_idor", before: "x", after: null, result: "fixed" }] }),
    okView({ next: { kind: 3 } }),
  ]) {
    const v = dv.parseDiagnosis(bad, "scan_001");
    assert.equal(v.status, "unverified", JSON.stringify(bad).slice(0, 80));
    assert.equal(v.reason, "invalid_response");
    assert.deepEqual(v.steps, []);
    assert.deepEqual(v.hypotheses, []);
  }
});

test("fetch outcomes: 404 hides the panel, a failure keeps the last view marked stale", () => {
  const view = { kind: "view", view: dv.parseDiagnosis(okView(), "scan_001"), stale: false };
  assert.deepEqual(dv.slotFromFetch(view, { ok: false, status: 404 }, "scan_001"), { kind: "absent" });
  assert.deepEqual(dv.slotFromFetch(view, { ok: false, status: 500 }, "scan_001"), { ...view, stale: true });
  assert.deepEqual(dv.slotFromFetch({ kind: "loading" }, { ok: false, status: 0 }, "scan_001"), { kind: "loading" });
  const fresh = dv.slotFromFetch({ ...view, stale: true }, { ok: true, body: okView() }, "scan_001");
  assert.equal(fresh.stale, false);
  // a response for another assessment is not shown as results either
  const other = dv.slotFromFetch(view, { ok: true, body: okView({ assessment_id: "scan_2" }) }, "scan_001");
  assert.equal(other.view.status, "unverified");
  assert.deepEqual(other.view.steps, []);
  assert.equal(other.view.persisted, true);       // no false "not saved" warning
  assert.equal(dv.parseDiagnosis(okView({ schema_version: 7 }), "scan_001").persisted, true);
});

test("events: duplicates and replays are dropped, a gap asks for a refetch", () => {
  assert.equal(polling.eventDecision(5, 5), "drop");      // duplicate
  assert.equal(polling.eventDecision(3, 5), "drop");      // replay after a reconnect
  assert.equal(polling.eventDecision(6, 5), "apply");
  assert.equal(polling.eventDecision(8, 5), "refetch");   // 6 and 7 were missed
  assert.equal(polling.eventDecision("6", 5), "drop");
  assert.equal(polling.eventDecision(Number.NaN, 5), "drop");
});

test("a restarted server is recognised by its boot id, not by a lower sequence", () => {
  assert.equal(polling.serverRestarted(null, "b1"), false);      // first read
  assert.equal(polling.serverRestarted("b1", "b1"), false);
  assert.equal(polling.serverRestarted("b1", "b2"), true);
  assert.equal(polling.serverRestarted("b1", undefined), false);
  assert.equal(polling.serverRestarted("b1", ""), false);
});

test("observations, reasons and rules are words from the fixed tables", () => {
  assert.deepEqual(dv.observationText(step().observation.attrs),
    ["応答 200", "別アカウント（A）で要求", "所有者 B の対照 成立", "再現 成立"]);
  assert.deepEqual(dv.observationText({ status: 403, auth: "none" }), ["応答 403", "認証なし"]);
  assert.deepEqual(dv.observationText({ requirement: "authentication_required" }), ["仕様：認証必須"]);
  assert.deepEqual(dv.observationText({ mystery: "x" }), ["未定義の値（mystery=x）"]);
  assert.equal(dv.reasonText("test_hypothesis", "H2"), "H2 を確かめるため");
  assert.equal(dv.reasonText("free text from a model", "H2"), "未定義の値（free text from a model）");
  assert.equal(dv.ruleText("cross_account_read"), labels.DIAG_RULE.cross_account_read);
  assert.equal(dv.claimText("__proto__"), "未定義の値（__proto__）");
});

test("a confirm-fix hypothesis reads its result the other way round", () => {
  assert.equal(dv.hypothesisStateLabel({ state: "contradicted", purpose: "confirm_fix" }), "改善を確認");
  assert.equal(dv.hypothesisStateLabel({ state: "supported", purpose: "confirm_fix" }), "改善されていない");
  assert.equal(dv.hypothesisStateLabel({ state: "contradicted", purpose: "diagnose" }), "反証（不成立）");
});

test("plan end reasons: exception text is never needed, unknown failures read as integrity failures", () => {
  assert.equal(dv.endText({ state: "COMPLETED", reason: "all_settled" }), "すべての仮説を判断しました");
  assert.equal(dv.endText({ state: "FAILED", reason: "item_failed" }), labels.DIAG_END.execute_failed.text);
  assert.equal(dv.endText({ state: "FAILED", reason: "something_new" }), "整合を確認できず終了（理由：未定義の値（something_new））");
  assert.equal(dv.endText({ state: "EXPIRED", reason: "other" }), "上限で終了（理由：未定義の値（other））");
  assert.equal(dv.fixResult("constructor").label, "未定義の値（constructor）");
  assert.equal(dv.fixResult("fixed").label, "改善を確認");
  assert.equal(dv.nextText({ kind: "plan_ended", state: "CANCELLED", reason: "stopped_or_reset" }), labels.DIAG_END.stopped_or_reset.text);
  assert.match(dv.nextText({ kind: "approve_l2", item_id: "it_1" }), /承認/);
});

test("the live region announces a new judgement and a refusal, once", () => {
  const before = dv.parseDiagnosis(okView({ steps: [] }), "scan_001");
  const after = dv.parseDiagnosis(okView(), "scan_001");
  assert.equal(dv.announcement(before, after), "S2 の判定：支持（成立）");
  assert.equal(dv.announcement(after, after), null);
  const fix = dv.parseDiagnosis(okView({ steps: [step(), step({ step_id: "S1", generation: 2, judged_audit_hash: H("e"),
    judgement: { from: "open", to: "contradicted", rule: "denied" } })] }), "scan_001");
  assert.equal(dv.announcement(after, fix), "世代 2・S1 の判定：反証（不成立）");
  const refused = dv.parseDiagnosis({ ...okView(), status: "unverified", reason: "state_audit_mismatch" }, "scan_001");
  assert.match(dv.announcement(after, refused), /確かめられない/);
  assert.equal(dv.announcement(refused, refused), null);
});

test("steps are shown newest first; the API order is kept in the view", () => {
  const v = dv.parseDiagnosis(okView({ steps: [step({ step_id: "S1", judged_audit_hash: H("d") }), step()] }), "scan_001");
  assert.deepEqual(dv.stepsNewestFirst(v).map((s) => s.step_id), ["S2", "S1"]);
  assert.deepEqual(v.steps.map((s) => s.step_id), ["S1", "S2"]);
});

test("every diagnosis label has words, and every coloured state has words too", () => {
  const tables = ["DIAG_CLAIM", "DIAG_FIX_STATE", "DIAG_CHECK", "DIAG_REASON", "DIAG_RULE", "DIAG_EVIDENCE_KIND",
                  "DIAG_SOURCE", "DIAG_REQUIREMENT", "DIAG_PLAN_STATE", "DIAG_REFUSAL"];
  for (const t of tables) {
    for (const [k, v] of Object.entries(labels[t])) assert.ok(typeof v === "string" && v.trim(), `${t}.${k}`);
  }
  for (const [k, v] of Object.entries(labels.DIAG_STATE)) assert.ok(v.label.trim() && v.cls.trim(), k);
  for (const [k, v] of Object.entries(labels.DIAG_FIX_RESULT)) assert.ok(v.label.trim() && v.cls.trim(), k);
  for (const [k, v] of Object.entries(labels.DIAG_END)) assert.ok(v.text.trim(), k);
  for (const [k, v] of Object.entries(labels.DIAG_NEXT)) {
    // plan_ended takes its words from DIAG_END; none says nothing
    assert.ok(v.trim() || k === "plan_ended" || k === "none", k);
  }
  for (const s of ["open", "supported", "contradicted", "inconclusive", "needs_spec"]) assert.ok(labels.DIAG_STATE[s], s);
});
