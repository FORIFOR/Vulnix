import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import ts from "typescript";

const require = createRequire(import.meta.url);
const source = readFileSync(new URL("../src/lib/securityIntelligence.ts", import.meta.url), "utf8");
const {outputText} = ts.transpileModule(source, {compilerOptions: {module: ts.ModuleKind.CommonJS}});
const loaded = {exports: {}};
new Function("require", "module", "exports", outputText)(require, loaded, loaded.exports);
const {aggregate, filterFindings, findingQuery, comparableRuns} = loaded.exports;

const audited = {id: "p", severity: "high", evidence_status: "proven", verdict: "proven",
  category: "アクセス制御", evidence: [{tool: "reproduction_probe", saved_at: 1, audit_hash: "verified"}]};
const fixture = {id: "fixture", severity: "high", evidence_status: "proven", demo_fixture: true, evidence: []};

test("each finding is counted once and external surfaces exclude fixtures", () => {
  const totals = aggregate([audited, fixture, {...audited, id: "c", evidence_status: "candidate"}], true, true, ["verified"]);
  assert.equal(totals.rows.length, 2);
  assert.equal(totals.severity.high, 2);
  assert.equal(totals.evidence.fixture, 0);
  assert.equal(totals.matrix.high.proven, 1);
  assert.equal(totals.matrix.high.candidate, 1);
});

test("missing evidence and a broken audit do not count as proof or a successful recheck", () => {
  for (const [chain, hashes] of [[false, ["verified"]], [true, ["other"]], [null, []]]) {
    const totals = aggregate([audited, {...audited, id: "r", evidence_status: "not_reproduced"}], false, chain, hashes);
    assert.equal(totals.evidence.proven, 0);
    assert.equal(totals.evidence.incomplete, 2);
    assert.equal(totals.rows[0].verdict, "unverified");
  }
});

test("invalid and unrecognized category text stays grouped under a fixed label", () => {
  const totals = aggregate([{...audited, category: "<img>", evidence: []}, fixture], false, true, []);
  assert.deepEqual(totals.categories, {"その他": 2});
  const params = new URLSearchParams(findingQuery({severity: "high", evidence: "fixture", category: "その他"}).slice(1));
  assert.deepEqual(filterFindings(totals.rows, params).map(f => f.id), ["fixture"]);
});

test("comparisons require the same asset and recorded condition", () => {
  const base = {run_id: "before", asset_id: "site", condition_id: "same", score: 12, at: 1};
  assert.deepEqual(comparableRuns([base, {...base, run_id: "after", at: 4},
    {...base, run_id: "other-asset", asset_id: "other", at: 2}, {...base, run_id: "other-condition", condition_id: "changed", at: 3}], "site").map(r => r.run_id), ["before", "after"]);
  assert.deepEqual(comparableRuns([{asset_id: "site", score: 12, at: 1}], "site"), []);
});
