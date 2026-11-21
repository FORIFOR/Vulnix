import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

// PR-C (docs/DIAGNOSIS_ACTIONS.md): which controls a reader gets, the job and viewer
// parsing, the fix comparison's finding, and the Idempotency-Key reuse rule.
const toUrl = (file, replace = (s) => s) => {
  const src = readFileSync(new URL(`../src/lib/${file}`, import.meta.url), "utf8");
  const { outputText } = ts.transpileModule(src, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
  return `data:text/javascript;base64,${Buffer.from(replace(outputText)).toString("base64")}`;
};
const labelsUrl = toUrl("labels.ts");
const dv = await import(toUrl("diagnosisView.ts", (s) => s.replace(/from "\.\/labels"/g, `from "${labelsUrl}"`)));
const actions = await import(toUrl("diagnosisActions.ts"));

const H = (c) => c.repeat(64);
const ALL = ["asset:specify", "diagnosis:approve_l2", "diagnosis:read", "diagnosis:request"];
const job = (over = {}) => ({ id: "dj_1", kind: "start", state: "running", requested_by: "qa", diag_id: "dg_1",
                              generation: 1, waiting_item_id: null, needs_spec: [], result: null, started_at: 1, ...over });
const view = (over = {}) => dv.parseDiagnosis({
  schema_version: 1, lab_only: true, assessment_id: "scan_001", status: "ok", restored: false, persisted: true,
  diag_id: "dg_1", generation: 1, plan: null, hypotheses: [], steps: [], evidence: [], fix_comparison: [],
  next: { kind: "none" }, operation: null, viewer: { actor: "qa", permissions: ["diagnosis:read", "diagnosis:request"] },
  ...over,
}, "scan_001");
const ops = (v) => dv.availableControls(v).controls.map((c) => c.op);

test("start: only with diagnosis:request, never while a loop is active", () => {
  const fresh = view({ status: "not_started", generation: null });
  assert.deepEqual(ops(fresh), ["start"]);
  assert.deepEqual(ops(view({ status: "not_started", viewer: { actor: "v", permissions: ["diagnosis:read"] } })), []);
  for (const state of ["awaiting_spec", "running", "waiting_approval"]) {
    assert.ok(!ops(view({ status: "not_started", operation: job({ state }) })).includes("start"), state);
  }
  assert.deepEqual(ops(view({ status: "not_started", operation: job({ state: "interrupted" }) })), ["start"]);
});

test("the owner's specification: only asset:specify, for the targets the job waits on", () => {
  const waiting = { operation: job({ state: "awaiting_spec", needs_spec: ["T2"] }) };
  const owner = dv.availableControls(view({ ...waiting, viewer: { actor: "alice", permissions: ALL } }));
  assert.deepEqual(owner.controls, [{ op: "owner-spec", targets: ["T2"] }]);
  const qa = dv.availableControls(view(waiting));
  assert.deepEqual(qa.controls, []);
  assert.deepEqual(qa.notes, ["対象資産の管理者が仕様を入力するのを待っています"]);
});

test("L2 approval: an approver who is not the requester; the requester is told why not", () => {
  const w = { operation: job({ state: "waiting_approval", waiting_item_id: "ax1_2" }) };
  const appr = dv.availableControls(view({ ...w, viewer: { actor: "approver-human", permissions: ["diagnosis:approve_l2", "diagnosis:read"] } }));
  assert.deepEqual(appr.controls, [{ op: "approve", itemId: "ax1_2" }]);
  const self = dv.availableControls(view({ ...w, viewer: { actor: "qa", permissions: ALL } }));
  assert.deepEqual(self.controls, []);
  assert.deepEqual(self.notes, ["依頼者本人は承認できません。別の承認者が承認します"]);
  assert.deepEqual(dv.availableControls(view({ ...w, viewer: { actor: "op-2", permissions: ["diagnosis:read", "diagnosis:request"] } })).notes,
                   ["承認者の承認を待っています"]);
});

test("fix-check: offered when the view says a proven finding can be re-checked", () => {
  assert.deepEqual(ops(view({ next: { kind: "confirm_fix_available" },
                              plan: { plan_id: "p", state: "COMPLETED", reason: "all_settled", steps_used: 2, steps_max: 3 } })),
                   ["fix-check"]);
  assert.deepEqual(ops(view({ next: { kind: "confirm_fix_available" }, operation: job() })), []);
});

test("a view that is not verified offers no operation, whatever its viewer may do", () => {
  const v = dv.parseDiagnosis({ schema_version: 1, lab_only: true, assessment_id: "scan_001", status: "unverified",
                                reason: "audit_chain_invalid", operation: job({ state: "awaiting_spec", needs_spec: ["T2"] }),
                                viewer: { actor: "alice", permissions: ALL } }, "scan_001");
  assert.equal(v.operation, null);
  assert.deepEqual(dv.availableControls(v), { controls: [], notes: [] });
});

test("a malformed job or viewer gives no control (never a guess)", () => {
  const v = view({ status: "not_started", operation: { id: 1 }, viewer: { actor: "qa", permissions: "all" } });
  assert.equal(v.operation, null);
  assert.equal(v.viewer, undefined);
  assert.deepEqual(dv.availableControls(v).controls, []);
});

test("an event keeps the reader's permissions from GET (events are the same for every member)", () => {
  const slot = { kind: "view", view: view({ status: "not_started" }), stale: false };
  const next = dv.applyDiagnosisEvent(slot, { assessment_id: "scan_001", diagnosis: {
    schema_version: 1, lab_only: true, assessment_id: "scan_001", status: "not_started", restored: false, persisted: true,
    generation: null, plan: null, hypotheses: [], steps: [], evidence: [], fix_comparison: [], next: { kind: "none" },
    operation: job({ state: "awaiting_spec", needs_spec: ["T2"] }) } }, "scan_001");
  assert.deepEqual(next.view.viewer, slot.view.viewer);
  assert.equal(next.view.operation.state, "awaiting_spec");
});

test("the fix comparison names the finding and what each side's result said", () => {
  const side = (gen, to, rep, c) => ({ generation: gen, to, rule: "x", judged_audit_hash: H(c), result_audit_hash: H(c === "a" ? "b" : "d"), reproduction: rep });
  const v = view({ fix_comparison: [{ hypothesis_id: "H3", supersedes: "H2", catalog_id: "l2_idor",
                                       before: side(1, "supported", "proven", "a"), after: side(2, "contradicted", "not_reproduced", "c"),
                                       result: "fixed", finding: { finding_id: "f_idor", status: "not_reproduced" } }] });
  assert.equal(v.status, "ok");
  assert.equal(dv.reproductionText("proven"), "再現 成立");
  assert.equal(dv.reproductionText("not_reproduced"), "再現せず");
  assert.equal(dv.findingStatusText("not_reproduced"), "再現せず");
  assert.equal(dv.findingStatusText("weird"), "未定義の値（weird）");
  const bad = view({ fix_comparison: [{ ...v.fix_comparison[0], finding: { finding_id: 3 } }] });
  assert.equal(bad.status, "unverified");
});

test("job and refusal words come from the tables", () => {
  assert.equal(dv.operationText(job({ state: "waiting_approval" })), "診断：L2 検査の承認を待っています");
  assert.equal(dv.operationText(job({ state: "failed", result: { reason: "initial_observation_failed" } })),
               "診断：開始できませんでした（初期観測を記録できませんでした）");
  assert.equal(dv.opReasonText("self_approval"), "診断を依頼した本人は、その L2 検査を承認できません");
  assert.equal(dv.opReasonText("nope"), "未定義の値（nope）");
});

test("Idempotency-Key: the same request keeps its key until the server answers; another gets a new one", () => {
  let n = 0;
  const make = () => `dk-test-key-${String(++n).padStart(8, "0")}`;
  const sig = actions.requestSignature("approve", { item_id: "ax1_2" });
  const first = actions.keyFor(null, sig, make);
  assert.match(first.key, actions.KEY_PATTERN);
  assert.equal(actions.keyFor(first, sig, make).key, first.key);                 // retry after no answer
  const other = actions.keyFor(first, actions.requestSignature("approve", { item_id: "ax1_3" }), make);
  assert.notEqual(other.key, first.key);
  assert.equal(actions.requestSignature("x", { b: 1, a: 2 }), actions.requestSignature("x", { a: 2, b: 1 }));
  assert.match(actions.newIdempotencyKey(), actions.KEY_PATTERN);
});
