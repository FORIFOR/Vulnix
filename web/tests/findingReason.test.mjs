import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import ts from "typescript";

const require = createRequire(import.meta.url);
const source = readFileSync(new URL("../src/lib/findingReason.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
});
const renderedModule = { exports: {} };
new Function("require", "module", "exports", outputText)(require, renderedModule, renderedModule.exports);
const { findingReason } = renderedModule.exports;

test("a recheck that did not reproduce the issue explains the latest result", () => {
  const reason = findingReason({ evidence_status: "not_reproduced", why_detected: null,
    verdict_note: "最新のHTTP応答では再現できませんでした。", summary: "古い所見" });
  assert.deepEqual(reason, {
    heading: "再確認の結果", text: "最新のHTTP応答では再現できませんでした。",
  });
});
