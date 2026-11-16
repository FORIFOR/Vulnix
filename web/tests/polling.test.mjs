import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";
const source = readFileSync(new URL("../src/lib/polling.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { needsPoll, needsAuthoritativeRefresh, shouldApplySnapshot, heartbeatDecision, QUIET_MS, MAX_SNAPSHOT_AGE_MS } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

test("a quiet stream on a visible page is backed up by polling", () => {
  assert.equal(needsPoll(0, QUIET_MS, true), true);
  assert.equal(needsPoll(0, QUIET_MS - 1, true), false);      // events are flowing: no polling
  assert.equal(needsPoll(0, QUIET_MS * 10, false), false);    // hidden tab: no polling
});

test("only a current heartbeat suppresses backup polling", () => {
  assert.equal(heartbeatDecision(10, 10), "healthy");
  assert.equal(heartbeatDecision(11, 10), "refresh");
  for (const staleOrInvalid of [9, -1, "10", null, Number.NaN, 1.5]) {
    assert.equal(heartbeatDecision(staleOrInvalid, 10), "ignore");
  }
});

test("healthy heartbeats cannot suppress an authoritative refresh indefinitely", () => {
  assert.equal(needsAuthoritativeRefresh(100, 100 + MAX_SNAPSHOT_AGE_MS - 1, true), false);
  assert.equal(needsAuthoritativeRefresh(100, 100 + MAX_SNAPSHOT_AGE_MS, true), true);
  assert.equal(needsAuthoritativeRefresh(100, 100 + MAX_SNAPSHOT_AGE_MS * 2, false), false);
});

test("a delayed snapshot cannot replace a newer SSE state", () => {
  assert.equal(shouldApplySnapshot(9, 10), false);
  assert.equal(shouldApplySnapshot(10, 10), true);
  assert.equal(shouldApplySnapshot(11, 10), true);
});

test("an older same-sequence request cannot overwrite a newer snapshot", () => {
  assert.equal(shouldApplySnapshot(10, 10, 1, 2), false);
  assert.equal(shouldApplySnapshot(10, 10, 2, 2), true);
  assert.equal(shouldApplySnapshot(11, 10, 1, 2), true);
});
