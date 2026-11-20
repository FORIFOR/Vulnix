import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";

const source = readFileSync(new URL("../src/lib/sessionResponse.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
});
const { shouldApplySessionResponse } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

test("a pre-logout session response cannot restore a signed-out user", () => {
  assert.equal(shouldApplySessionResponse(1, 2), false);
});

test("only the newest session refresh can change visible auth state", () => {
  assert.equal(shouldApplySessionResponse(1, 2), false);
  assert.equal(shouldApplySessionResponse(2, 2), true);
  assert.equal(shouldApplySessionResponse(3, 2), false);
  assert.equal(shouldApplySessionResponse(2, 2, true), false);
});
