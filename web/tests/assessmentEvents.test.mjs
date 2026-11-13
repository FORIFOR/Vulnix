import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";
const source = readFileSync(new URL("../src/lib/assessmentEvents.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { applyEvent, applyChatReply } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

const initial = {
  findings: [{ id: "f", evidence_status: "candidate" }],
  evidence_summary: { candidate: 1, detected: 0, proven: 0, not_reproduced: 0, incomplete: 0, fixture: 0 },
  risk: { score: 0 },
};

for (const status of ["detected", "proven", "not_reproduced", "incomplete"]) {
  test(`SSE ${status} updates finding and counters together without a reload`, () => {
    const counts = { ...initial.evidence_summary, candidate: 0, [status]: 1 };
    const finding = { id: "f", evidence_status: status };
    const next = applyEvent(initial, { type: "finding.upserted", finding, evidence_summary: counts, risk: { score: 25 } });
    assert.deepEqual(next.evidence_summary, counts);
    assert.equal(next.findings.length, 1);
    assert.deepEqual(next.findings[0], finding);
    assert.deepEqual(initial.evidence_summary, { candidate: 1, detected: 0, proven: 0, not_reproduced: 0, incomplete: 0, fixture: 0 });
    assert.equal(initial.findings[0].evidence_status, "candidate");
  });
}
test("unrelated stream events retain evidence state", () => {
  const next = applyEvent(initial, { type: "assessment.state", state: "paused", risk: initial.risk });
  assert.equal(next.evidence_summary, initial.evidence_summary);
  assert.equal(next.findings, initial.findings);
});

test("slow chat reply preserves the latest SSE evidence and messages", () => {
  const latest = { ...initial, evidence_summary: { ...initial.evidence_summary, candidate: 0, not_reproduced: 1 }, findings: [{ id: "f", verdict: "not_reproduced" }], planner: { connection_verified: true }, chat_messages: [{ id: "newer", text: "newer event" }] };
  const next = applyChatReply(latest, { chat_messages: [{ id: "older", text: "reply" }], planner: { connection_verified: false } });
  assert.equal(next.findings, latest.findings);
  assert.equal(next.evidence_summary, latest.evidence_summary);
  assert.equal(next.planner.connection_verified, true);
  assert.deepEqual(next.chat_messages.map((m) => m.id), ["newer", "older"]);
});

test("the ARTEX plan event replaces the plan view", () => {
  const s0 = { ...initial, artex_plan: { configured: true, plan: null } };
  const view = { configured: true, plan: { run_id: "ax1", items: [{ id: "ax1_1", status: "completed" }], advisories: [] } };
  const next = applyEvent(s0, { type: "artex.plan", artex_plan: view });
  assert.equal(next.artex_plan.plan.items[0].status, "completed");
  assert.equal(next.findings, s0.findings);
});
