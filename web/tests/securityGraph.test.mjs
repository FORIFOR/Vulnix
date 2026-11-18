import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";

const source = readFileSync(new URL("../src/lib/securityGraph.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { pathStatusLabel, pathIsVerified, syntheticValidationLabel, mcpScopeLabel,
  mcpValidationStatusLabel } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

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
test("synthetic validation is labelled without claiming customer verification", () => {
  assert.match(syntheticValidationLabel("synthetic_fixed"), /合成ラボ/);
  assert.match(syntheticValidationLabel("synthetic_fixed"), /ローカル修正/);
  assert.doesNotMatch(syntheticValidationLabel("synthetic_fixed"), /顧客環境/);
});
test("MCP role declaration is never labelled as effective authorization", () => {
  assert.match(mcpScopeLabel("scope_unknown"), /未確認/);
  assert.match(mcpScopeLabel("role_declaration_unverified"), /未検証/);
  assert.doesNotMatch(mcpScopeLabel("role_declaration_unverified"), /安全|防御済み/);
});
test("MCP control results stay explicitly synthetic", () => {
  assert.match(mcpValidationStatusLabel("synthetic_control_observed"), /合成/);
  assert.doesNotMatch(mcpValidationStatusLabel("synthetic_control_observed"), /顧客環境で検証済み/);
  assert.match(mcpValidationStatusLabel("inconclusive"), /判定不能/);
});
