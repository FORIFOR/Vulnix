import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";

const source = readFileSync(new URL("../src/lib/securityGraph.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { pathStatusLabel, pathIsVerified } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

test("observed structure is never labelled a confirmed attack", () => {
  assert.equal(pathIsVerified("observed_structure"), false);
  assert.match(pathStatusLabel("observed_structure"), /構造/);
});
test("guarded and hypothetical routes retain uncertainty", () => {
  assert.equal(pathIsVerified("guard_observed"), false);
  assert.equal(pathIsVerified("hypothesized"), false);
  assert.match(pathStatusLabel("guard_observed"), /ガード/);
});
test("only verified state receives verified language", () => {
  assert.equal(pathIsVerified("verified"), true);
  assert.match(pathStatusLabel("verified"), /隔離検証/);
});
