import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const { outputText } = ts.transpileModule(readFileSync(new URL("../src/lib/catalogUpdate.ts", import.meta.url), "utf8"), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
});
const { catalogSources, catalogSource } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

test("catalog update allows only fixed ecosystems and historical NVD years", () => {
  const sources = catalogSources(2026);
  assert.deepEqual(sources.slice(0, 4), ["npm", "PyPI", "Go", "NVD-2026"]);
  assert.equal(sources.at(-1), "NVD-2002");
  assert.equal(new Set(sources).size, sources.length);
  for (const invalid of ["npm/../../", "NVD-1999", "NVD-latest", "https://elsewhere.invalid", null])
    assert.equal(catalogSource(invalid), undefined);
});
