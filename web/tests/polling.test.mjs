import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";
const source = readFileSync(new URL("../src/lib/polling.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { needsPoll, QUIET_MS } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

test("a quiet stream on a visible page is backed up by polling", () => {
  assert.equal(needsPoll(0, QUIET_MS, true), true);
  assert.equal(needsPoll(0, QUIET_MS - 1, true), false);      // events are flowing: no polling
  assert.equal(needsPoll(0, QUIET_MS * 10, false), false);    // hidden tab: no polling
});
