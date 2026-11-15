import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";

const source = readFileSync(new URL("../src/lib/diagnosisSource.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
});
const { diagnosisSource } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

const base = {
  is_external_service: false,
  real_site_read_only: false,
  planner: { external_model_configured: false, explanation_model_configured: false, model_name: null },
  artex_plan: { configured: false, plan: null },
};

test("a real site never claims ARTEX planning or external AI explanation", () => {
  const source = diagnosisSource({
    ...base,
    is_external_service: true,
    real_site_read_only: true,
    planner: { external_model_configured: true, explanation_model_configured: true, model_name: "paid-model" },
    artex_plan: { configured: true, plan: { engine: { kind: "artex-binary", pinned: true } } },
  });
  assert.equal(source.plan, "公開ページの設定を確認");
  assert.equal(source.explanation, "解説は内蔵機能で作成");
});

test("a built-in lab run does not inherit the ARTEX name from its backend", () => {
  assert.deepEqual(diagnosisSource(base), {
    plan: "内蔵の診断手順",
    explanation: "解説は内蔵機能で作成",
  });
});

test("only a pinned real ARTEX plan is attributed to ARTEX", () => {
  const run = { ...base, artex_plan: { configured: true, plan: { engine: { kind: "artex-binary", pinned: true } } } };
  assert.equal(diagnosisSource(run).plan, "ARTEXで作成した計画");
  assert.equal(diagnosisSource({ ...run, artex_plan: { configured: true, plan: { engine: { kind: "stand-in", pinned: false } } } }).plan,
    "内蔵の診断手順");
});
