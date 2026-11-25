import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

function source(name, imports) {
  const file = readFileSync(new URL(`../src/lib/${name}.ts`, import.meta.url), "utf8");
  const input = Object.entries(imports).reduce((text, [before, after]) =>
    text.replace(`from "${before}"`, `from "${after}"`), file);
  const { outputText } = ts.transpileModule(input, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
  });
  return `data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`;
}
const quick = source("quickDefense", {});
const packages = source("projectPackages", {
  "./quickDefense": quick, semver: import.meta.resolve("semver"),
  "@renovatebot/pep440": import.meta.resolve("@renovatebot/pep440"),
});
const { scanProject } = await import(source("projectDefense", {
  "./quickDefense": quick, "./projectPackages": packages, typescript: import.meta.resolve("typescript"),
  yaml: import.meta.resolve("yaml"),
}));
const fixture = (path, contents) => ({ path: `project/${path}`, file: new File([contents], path.split("/").at(-1)) });

test("bounded YAML rejects custom tags and aliases and accepts Kubernetes documents", async () => {
  const report = await scanProject([
    fixture("bad.yaml", "spec: !unsafe value"),
    fixture("alias.yaml", "first: &data hi\nsecond: *data"),
    fixture("network.yaml", "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nspec:\n  policyTypes: [Egress]\n  egress: [{}]\n"),
    fixture("main.tf.json", JSON.stringify({ resource: { aws_security_group: {
      admin: { ingress: [{ protocol: "tcp", from_port: 22, to_port: 22, cidr_blocks: ["0.0.0.0/0"] }] },
    } } })),
  ], { vulnerabilities: [], osv: [] });
  assert.equal(report.unsupported, 2);
  assert.ok(report.rows.some((row) => row.status === "action" && row.location?.path === "network.yaml"));
  assert.ok(report.rows.some((row) => row.status === "action" && row.location?.path === "main.tf.json"));
});

test("more than 100 results do not stop scanning later files", async () => {
  const highVolume = Array.from({ length: 105 }, (_, i) =>
    fixture(`.github/workflows/sample-${i}.yml`, "name: local\npermissions: write-all\njobs: {}\n"));
  const report = await scanProject([...highVolume, fixture("db.ts", "el.innerHTML = req.query.title;")], {});
  assert.equal(report.read, 106);
  assert.ok(report.rows.some((row) => row.location?.path === "db.ts"));
  assert.equal(report.skippedRules, 0);
});

test("flag the absence of an explicit runtime user only for a recognized default base", async () => {
  const report = await scanProject([
    fixture("Dockerfile.node", "FROM node:22-bookworm-slim\n"),
    fixture("Dockerfile.explicit", "FROM node:22-bookworm-slim\nUSER node\n"),
    fixture("Dockerfile.custom", "FROM custom.invalid/base:v1\n"),
  ], {});
  const results = report.rows.filter((row) => row.title === "コンテナの既定ユーザー");
  assert.deepEqual(results.map((row) => row.status), ["action", "unknown", "unknown"]);
  assert.equal(results[0].location.line, 1);
});

test("same CVE from NVD and OSV appears once and preserves the package match", async () => {
  const cve = "CVE-2099-10001";
  const nvd = { cve: { id: cve, configurations: [{ nodes: [{ operator: "OR", cpeMatch: [
    { vulnerable: true, criteria: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" },
  ] }] }] } };
  const osv = { id: "GHSA-abc-test-only", aliases: [cve],
    affected: [{ package: { ecosystem: "PyPI", name: "fixture" }, versions: ["1.0"] }] };
  const report = await scanProject([fixture("Dockerfile", "FROM httpd:2.4.49\n"),
    fixture("requirements.txt", "fixture==1.0\n")], { vulnerabilities: [nvd, nvd], osv: [osv] });
  const results = report.rows.filter((row) => row.title === cve);
  assert.equal(results.length, 1);
  assert.equal(results[0].location.path, "requirements.txt");
  assert.match(results[0].evidence, /NVDにも/);
});
