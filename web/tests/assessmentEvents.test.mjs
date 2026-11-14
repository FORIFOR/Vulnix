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
  const latest = { ...initial, evidence_summary: { ...initial.evidence_summary, candidate: 0, not_reproduced: 1 }, findings: [{ id: "f", verdict: "not_reproduced" }], planner: { connection_verified: true, connection_state: "verified", status_seq: 3 }, chat_messages: [{ id: "newer", text: "newer event" }] };
  const next = applyChatReply(latest, { chat_messages: [{ id: "older", text: "reply" }], planner: { connection_verified: false, connection_state: "configured", status_seq: 2 } });
  assert.equal(next.findings, latest.findings);
  assert.equal(next.evidence_summary, latest.evidence_summary);
  assert.equal(next.planner.connection_verified, true);
  assert.deepEqual(next.chat_messages.map((m) => m.id), ["newer", "older"]);
});

test("a newer failed call replaces an older verified state (no sticky verified)", () => {
  const s0 = { ...initial, planner: { connection_verified: true, connection_state: "verified", status_seq: 1 }, chat_messages: [] };
  const next = applyChatReply(s0, { chat_messages: [], planner: { connection_verified: false, connection_state: "failed", connection_error: "HTTPError 401", status_seq: 2 } });
  assert.equal(next.planner.connection_state, "failed");
  assert.equal(next.planner.connection_verified, false);
});

test("the chat SSE event updates the header state for views that did not ask", () => {
  const s0 = { ...initial, planner: { connection_verified: false, connection_state: "configured", status_seq: 0 }, chat_messages: [] };
  const next = applyEvent(s0, { type: "chat.message", messages: [{ id: "m1", text: "a" }], planner: { connection_verified: true, connection_state: "verified", status_seq: 1 } });
  assert.equal(next.planner.connection_state, "verified");
  assert.deepEqual(next.chat_messages.map((m) => m.id), ["m1"]);
  const stale = applyEvent(next, { type: "chat.message", messages: [], planner: { connection_verified: false, connection_state: "configured", status_seq: 0 } });
  assert.equal(stale.planner.connection_state, "verified");
});

test("an event with only connection fields keeps the rest of the planner", () => {
  const s0 = { ...initial, planner: { model_name: "m", note: "n0", backends: ["x"], connection_state: "configured", status_seq: 0, boot_id: "b1" }, chat_messages: [] };
  const next = applyEvent(s0, { type: "chat.message", messages: [], planner: { connection_state: "verified", connection_verified: true, status_seq: 1, boot_id: "b1" } });
  assert.equal(next.planner.model_name, "m");
  assert.deepEqual(next.planner.backends, ["x"]);
  assert.equal(next.planner.connection_state, "verified");
});

test("a restarted server (new boot id) wins even with a lower sequence number", () => {
  const s0 = { ...initial, planner: { connection_state: "verified", status_seq: 5, boot_id: "old" }, chat_messages: [] };
  const next = applyChatReply(s0, { chat_messages: [], planner: { connection_state: "failed", status_seq: 1, boot_id: "new" } });
  assert.equal(next.planner.connection_state, "failed");
});

test("a whole-snapshot refetch cannot undo a newer connection state", async () => {
  const { withNewerPlanner } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);
  const prev = { ...initial, planner: { connection_state: "failed", status_seq: 3, boot_id: "b" } };
  const stale = { ...initial, findings: [{ id: "g" }], planner: { connection_state: "verified", status_seq: 2, boot_id: "b" } };
  const next = withNewerPlanner(prev, stale);
  assert.equal(next.planner.connection_state, "failed");
  assert.deepEqual(next.findings, [{ id: "g" }]);
});

test("an older full snapshot keeps our connection state but brings its other planner fields", () => {
  const s0 = { ...initial, planner: { connection_state: "failed", status_seq: 3, boot_id: "b", artex_cli_verified: false }, chat_messages: [] };
  const next = applyChatReply(s0, { chat_messages: [], planner: { connection_state: "verified", status_seq: 2, boot_id: "b", artex_cli_verified: true } });
  assert.equal(next.planner.connection_state, "failed");
  assert.equal(next.planner.artex_cli_verified, true);
});

test("the ARTEX plan event replaces the plan view", () => {
  const s0 = { ...initial, artex_plan: { configured: true, plan: null } };
  const view = { configured: true, plan: { run_id: "ax1", items: [{ id: "ax1_1", status: "completed" }], advisories: [] } };
  const next = applyEvent(s0, { type: "artex.plan", artex_plan: view });
  assert.equal(next.artex_plan.plan.items[0].status, "completed");
  assert.equal(next.findings, s0.findings);
});
