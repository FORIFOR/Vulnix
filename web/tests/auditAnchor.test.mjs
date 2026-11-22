import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";
const source = readFileSync(new URL("../src/lib/auditAnchor.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { auditAnchorLine } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

test("protected only when enabled and protected", () => {
  const ok = auditAnchorLine({ enabled: true, protected: true, last_seq: 12, error: null });
  assert.equal(ok.tone, "ok");
  assert.match(ok.text, /保護あり/);
  assert.match(ok.text, /12 件目/);
});

test("enabled but failing is never shown as protected", () => {
  for (const error of ["rollback", "fork", "anchor_unavailable", "anchor_corrupt", "chain_invalid", "something_new", null]) {
    const line = auditAnchorLine({ enabled: true, protected: false, last_seq: 3, error });
    assert.equal(line.tone, "error");
    assert.doesNotMatch(line.text, /保護あり/);
    assert.match(line.text, /保護なし/);
  }
  assert.match(auditAnchorLine({ enabled: true, protected: false, last_seq: null, error: "rollback" }).text, /巻き戻し/);
});

test("disabled says rollback of both files is not detectable", () => {
  const line = auditAnchorLine({ enabled: false, protected: false, last_seq: null, error: null });
  assert.equal(line.tone, "off");
  assert.doesNotMatch(line.text, /保護あり/);
  assert.match(line.text, /両方とも古い状態へ戻された場合は検知できません/);
});

test("a malformed status (protected without enabled, or missing) is not protected", () => {
  assert.doesNotMatch(auditAnchorLine({ enabled: false, protected: true, last_seq: 1, error: null }).text, /保護あり/);
  assert.doesNotMatch(auditAnchorLine(undefined).text, /保護あり/);
  assert.doesNotMatch(auditAnchorLine(null).text, /保護あり/);
});

test("a same-user helper works but is shown as not protected, without claiming a stop", () => {
  const line = auditAnchorLine({ enabled: true, protected: false, last_seq: 4, error: "same_user" });
  assert.equal(line.tone, "error");
  assert.doesNotMatch(line.text, /保護あり/);
  assert.match(line.text, /同じ OS ユーザー/);
  assert.doesNotMatch(line.text, /停止しています/);
});

test("the platform-wide files are named as not covered", () => {
  for (const s of [{ enabled: true, protected: true, last_seq: 1, error: null },
                   { enabled: true, protected: false, last_seq: 1, error: "rollback" }]) {
    assert.match(auditAnchorLine(s).text, /platform-advisor-spend\.json は対象外/);
  }
});
