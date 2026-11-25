import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

function dataModule(source) {
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
  });
  return `data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`;
}
const quick = dataModule(readFileSync(new URL("../src/lib/quickDefense.ts", import.meta.url), "utf8"));
const source = readFileSync(new URL("../src/lib/projectPackages.ts", import.meta.url), "utf8")
  .replace('from "./quickDefense"', `from "${quick}"`)
  .replace('from "semver"', `from "${import.meta.resolve("semver")}"`)
  .replace('from "@renovatebot/pep440"', `from "${import.meta.resolve("@renovatebot/pep440")}"`);
const { affects, collectPackages } = await import(dataModule(source));

test("OSV ranges use ecosystem ordering and preserve boundary semantics", () => {
  const npm = { ranges: [{ type: "SEMVER", events: [
    { introduced: "1.0.0" }, { fixed: "1.2.0" }, { introduced: "2.0.0" }, { last_affected: "2.2.0" },
  ] }] };
  assert.equal(affects("1.2.0", "npm", npm), false);
  assert.equal(affects("2.2.0", "npm", npm), true);
  assert.equal(affects("2.2.1", "npm", npm), false);
  assert.equal(affects("1.1rc1", "PyPI", { ranges: [{ type: "ECOSYSTEM", events: [
    { introduced: "1.0" }, { fixed: "1.1" },
  ] }] }), true);
  assert.equal(affects("v1.2.0-0.20260606000000-aaaaaaaaaaaa", "Go", { ranges: [{ type: "SEMVER", events: [
    { introduced: "1.1.0" }, { fixed: "1.2.0" },
  ] }] }), true);
});

test("unsupported ranges, malformed events and unresolved requirements stay unmatched", () => {
  assert.equal(affects("2.2.1", "npm", { ranges: [{ type: "GIT", events: [{ introduced: "0" }] }] }), false);
  assert.equal(affects("2.2.1", "npm", { ranges: [{ type: "SEMVER", events: [
    { introduced: "0" }, { fixed: "3.0.0" }, { introduced: "2.0.0" },
  ] }] }), false);
  assert.deepEqual(collectPackages("requirements.txt", "requirements.txt", "example >= 1.0\nexample==2.0; os_name == 'posix'"), []);
  assert.deepEqual(collectPackages("go.mod", "go.mod", "require example.invalid/mod v1.0.0\nreplace example.invalid/mod => ./local"), []);
});
