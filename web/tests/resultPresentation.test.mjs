import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const source = readFileSync(new URL("../src/lib/resultPresentation.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { groupDependencyFindings, sortByAdvisorySeverity } = await import(
  `data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`
);

test("sorts by advisory severity with unknown last and stable ties", () => {
  const rows = [{ title: "unknown" }, { title: "high1", severity: "HIGH" },
    { title: "critical", severity: "CRITICAL" }, { title: "low", severity: "LOW" },
    { title: "high2", severity: "HIGH" }, { title: "medium", severity: "MEDIUM" }];
  assert.deepEqual(sortByAdvisorySeverity(rows).map(({ title }) => title),
    ["critical", "high1", "high2", "medium", "low", "unknown"]);
  assert.equal(rows[0].title, "unknown");
});

test("groups package versions while preserving locations and per-advisory fixed alternatives", () => {
  const loc = { dependency: "example", ecosystem: "npm", version: "1.0.0", path: "package-lock.json", line: 8, fixed: ["1.1.0", "2.1.0"] };
  const rows = [
    { category: "CVE", status: "action", title: "CVE-2099-9999", severity: "HIGH", locations: [loc, { ...loc, line: 18 }] },
    { category: "CVE", status: "action", title: "CVE-2099-9998", severity: "CRITICAL",
      locations: [{ ...loc, fixed: ["1.2.0"] }, { ...loc, version: "1.1.0", fixed: [] }, { ...loc, ecosystem: "PyPI" }] },
    { category: "CVE", status: "unknown", title: "CVE-2099-9997", locations: [loc] },
  ];
  const [group, otherVersion, otherEcosystem] = groupDependencyFindings(rows);
  assert.equal(group.severity, "CRITICAL");
  assert.deepEqual(group.advisories.map((item) => [item.id, item.fixed, item.locations.length]), [
    ["CVE-2099-9998", ["1.2.0"], 1], ["CVE-2099-9999", ["1.1.0", "2.1.0"], 2],
  ]);
  assert.equal(otherVersion.version, "1.1.0");
  assert.deepEqual(otherVersion.advisories[0].fixed, []);
  assert.equal(otherEcosystem.ecosystem, "PyPI");
});
