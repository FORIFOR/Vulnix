import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";
const source = readFileSync(new URL("../src/lib/helpPopoverPosition.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { helpPopoverPosition } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);
const anchor = { left: 672, width: 20, top: 100, bottom: 120 };

test("720px filmed right-edge trigger keeps entire 352px panel inside viewport", () => {
  const p = helpPopoverPosition(anchor, { width: 720, height: 900 }, 300);
  assert.equal(p.left, 352);
  assert.equal(p.width, 352);
  assert.equal(p.left + p.width, 704);
});
for (const width of [320, 360, 375, 720]) {
  for (const left of [0, width / 2, width - 20]) {
    test(`${width}px viewport clamps trigger at ${left}px`, () => {
      const p = helpPopoverPosition({ ...anchor, left }, { width, height: 640 }, 300);
      assert.ok(p.left >= 16);
      assert.ok(p.left + p.width <= width - 16);
    });
  }
}
test("resize and reopen recompute from current viewport and anchor, not cached position", () => {
  const wide = helpPopoverPosition(anchor, { width: 1024, height: 900 }, 300);
  const narrow = helpPopoverPosition({ ...anchor, left: 290 }, { width: 320, height: 640 }, 300);
  const reopened = helpPopoverPosition(anchor, { width: 720, height: 900 }, 300);
  assert.notEqual(wide.left, narrow.left);
  assert.equal(narrow.left, 16);
  assert.equal(narrow.width, 288);
  assert.equal(reopened.left, 352);
});
test("near bottom opens above the trigger", () => {
  const p = helpPopoverPosition({ ...anchor, top: 600, bottom: 620 }, { width: 720, height: 640 }, 300);
  assert.equal(p.top, 292);
  assert.equal(p.maxHeight, 576);
});
test("tall content is constrained to available viewport space for scrolling", () => {
  const p = helpPopoverPosition({ ...anchor, top: 200, bottom: 220 }, { width: 320, height: 400 }, 1000);
  assert.equal(p.top, 16);
  assert.equal(p.maxHeight, 176);
  assert.ok(p.top + p.maxHeight <= 384);
});
