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
const { scanProject, limits } = await import(source("projectDefense", {
  "./quickDefense": quick, "./projectPackages": packages, "./runtimePlan": source("runtimePlan", {}), "./pythonFlow": source("pythonFlow", {}), typescript: import.meta.resolve("typescript"),
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
  const osv = { id: "GHSA-abc-test-only", aliases: [cve], database_specific: { severity: "HIGH" },
    affected: [{ package: { ecosystem: "PyPI", name: "fixture" }, versions: ["1.0"] }] };
  const report = await scanProject([fixture("Dockerfile", "FROM httpd:2.4.49\n"),
    fixture("requirements.txt", "fixture==1.0\n")], { vulnerabilities: [nvd, nvd], osv: [osv] });
  const results = report.rows.filter((row) => row.title === cve);
  assert.equal(results.length, 1);
  assert.equal(results[0].location.path, "requirements.txt");
  assert.match(results[0].evidence, /NVDにも/);
  assert.equal(results[0].severity, "HIGH");
});

test("automatically scans later batches and reads a repeated path once", async () => {
  const inputs = Array.from({ length: 360 }, (_, i) => fixture(`src/sample-${i}.ts`, "const ready = true;"));
  const tail = fixture("src/final.ts", "el.innerHTML = req.query.title;");
  const progress = [];
  const report = await scanProject([...inputs, tail, tail], {}, (update) => progress.push(update));
  assert.equal(report.read, 361);
  assert.equal(report.pending, 0);
  assert.equal(report.skipped, 1);
  assert.equal(report.rows.filter((row) => row.location?.path === "src/final.ts").length, 1);
  assert.deepEqual(progress.map(({ batches, processed }) => [batches, processed]).filter(([, count]) =>
    [0, 180, 360, 361].includes(count)), [[0, 0], [2, 180], [3, 360], [3, 361]]);
});

test("rolls the read budget into another batch without lifting a single-file cap", async () => {
  const inputs = Array.from({ length: 50 }, (_, i) => ({ path: `project/src/sized-${i}.ts`, file: {
    name: `sized-${i}.ts`, size: limits.fileBytes, text: async () => "const ready = true;",
  } }));
  const unreadable = { path: "project/src/large.ts", file: {
    name: "large.ts", size: limits.fileBytes + 1, text: async () => assert.fail("file exceeded its read limit"),
  } };
  const report = await scanProject([...inputs, unreadable], {});
  assert.ok(report.scanProgress.batches >= 2);
  assert.equal(report.scanProgress.batches, Math.ceil(50 / Math.floor(limits.bytes / limits.fileBytes)));
  assert.equal(report.read, 50);
  assert.equal(report.omitted, 1);
  assert.equal(report.pending, 0);
});

test("a versionless platform qualifier needs an exact CPE in the same inventory", async () => {
  const device = "cpe:2.3:h:example:platform:-:*:*:*:*:*:*:*";
  const software = "cpe:2.3:a:example:software:1.0:*:*:*:*:*:*:*";
  const cve = "CVE-2099-10002";
  const feed = { vulnerabilities: [{ cve: { id: cve, configurations: [{ operator: "AND", nodes: [
    { operator: "OR", cpeMatch: [{ vulnerable: true, criteria: software }] },
    { operator: "OR", cpeMatch: [{ vulnerable: false, criteria: device }] },
  ] }] } }] };
  const sbom = (filename, ...cpes) => fixture(filename, JSON.stringify({ bomFormat: "CycloneDX",
    components: cpes.map((cpe) => ({ cpe })) }));
  for (const [inputs, evidence] of [
    [[sbom("app-sbom.json", software, device)], /組み合わせがあります/],
    [[sbom("app-sbom.json", software), sbom("other-sbom.json", device)], /一部を確認できません/],
    [[sbom("app-sbom.json", software, device.replace(":-:", ":1.0:"))], /一部を確認できません/],
  ]) {
    const report = await scanProject(inputs, feed);
    const row = report.rows.find((entry) => entry.title === cve);
    assert.equal(row?.status, "unknown");
    assert.match(row.evidence, evidence);
  }
});

test("defense planning uses technology and assertions without granting a verdict", async () => {
  const report = await scanProject([
    fixture("package.json", '{"dependencies":{"next":"16.0.0","@node-saml/node-saml":"1.0.0"}}'),
    fixture("Dockerfile", "FROM node:22-bookworm-slim"),
    fixture("tests/auth.test.ts", 'test("session policy", async () => { const response = await client.session(); expect(response.status).toBe(200); expect((await client.session()).status).toBe(401); });'),
    fixture("tests/lookalike.test.ts", 'test("saml rejects forged signatures", () => { expect(true).toBe(true); });'),
    fixture("tests/comments.test.ts", '// test("session", () => expect(response.status).toBe(401));'),
  ], {});
  assert.ok(report.runtimePlan.some(({ id }) => id === "saml"));
  assert.ok(report.runtimePlan.some(({ id, locations }) => id === "container" && locations.includes("Dockerfile")));
  const auth = report.runtimePlan.find(({ id }) => id === "authentication");
  assert.deepEqual(auth.candidates.map(({ path, permits, denies }) => [path, permits, denies]), [["tests/auth.test.ts", true, true]]);
  assert.deepEqual(report.runtimePlan.find(({ id }) => id === "saml").candidates, []);
  assert.ok(report.runtimePlan.every((row) => !("verdict" in row)));
});

test("an uploaded CycloneDX SBOM discovers fixed npm, PyPI and Go package identities", async () => {
  const sbom = JSON.stringify({ bomFormat: "CycloneDX", components: [
    { purl: "pkg:npm/%40fixture/pkg@1.2.3", version: "1.2.3" },
    { purl: "pkg:pypi/Python_Fixture@2.0.0" },
    { purl: "pkg:golang/example.invalid/fake@v1.2.3" },
    { purl: "pkg:npm/fake@2.0.0", version: "3.0.0" },
    { purl: "pkg:deb/debian/example@1" },
  ] });
  const report = await scanProject([fixture("inventory.sbom.json", sbom)], {});
  assert.equal(report.packageCount, 3);
  assert.equal(report.unsupported, 0);
  assert.ok(report.skippedRules);
});

test("Google Artifact Analysis SPDX 2.3 maps package references without trusting inconsistent versions", async () => {
  const reference = (referenceType, referenceLocator) => ({ referenceType, referenceLocator });
  const input = { spdxVersion: "SPDX-2.3", packages: [
    { versionInfo: "2.0.0", externalRefs: [reference("purl", "pkg:pypi/Python_Fixture@2.0.0")] },
    { versionInfo: "3.0.0", externalRefs: [reference("purl", "pkg:npm/fake@2.0.0")] },
    { externalRefs: [reference("purl", "pkg:npm/first@1.0.0"), reference("purl", "pkg:npm/second@1.0.0")] },
  ] };
  const report = await scanProject([fixture("inventory.sbom.json", JSON.stringify(input))], {});
  assert.equal(report.packageCount, 1);
  assert.ok(report.skippedRules);
});

test("folder inventory checks named SPDX and CycloneDX files and reports partial requirements coverage", async () => {
  const cve = "CVE-2099-12345";
  const feed = { osv: [{ id: cve, affected: [{ package: { ecosystem: "PyPI", name: "example-auth" },
    ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.0" }] }],
  }] }] };
  const inputs = (version) => [
    fixture("api/requirements-prod.txt", `Example_Auth[http,crypto]==${version}\nunresolved>=2\n`),
    fixture("deploy/api-sbom.json", JSON.stringify({ bomFormat: "CycloneDX",
      components: [{ purl: `pkg:pypi/example-auth@${version}`, version }] })),
    fixture("deploy/web.spdx.json", JSON.stringify({ spdxVersion: "SPDX-2.3",
      packages: [{ versionInfo: version, externalRefs: [{ referenceType: "purl",
        referenceLocator: `pkg:pypi/example-auth@${version}` }] }] })),
    fixture("src/service.py", "def ready(): return True"),
    fixture("config/broken.yaml", "spec: !unsupported value"),
    fixture("README.md", "# Example"),
  ];
  const affected = await scanProject(inputs("1.0"), feed);
  assert.deepEqual(affected.rows.find((row) => row.title === cve)?.locations?.map(({ path }) => path),
    ["api/requirements-prod.txt", "deploy/api-sbom.json", "deploy/web.spdx.json"]);
  assert.equal(affected.coverage.source, 1);          // src/service.py: single-function Python flow rules
  assert.equal(affected.coverage.pythonFlow, 1);
  assert.equal(affected.coverage.packageFiles, 3);
  assert.equal(affected.coverage.noSourceRules, 0);
  assert.equal(affected.coverage.parseFailed, 1);
  assert.equal(affected.coverage.unresolvedDependencies, 1);
  assert.equal(affected.coverage.osvAdvisories, 1);
  const repaired = await scanProject(inputs("2.0"), feed);
  assert.ok(!repaired.rows.some((row) => row.title === cve));
  assert.ok(repaired.rows.some((row) => row.status === "unknown"));
});

test("a large hand-written source file is read instead of omitted, and size limits still apply", async () => {
  const big = "x = 1\n".repeat(70_000);          // ~420 KB of Python
  const huge = "x = 1\n".repeat(200_000);        // ~1.2 MB stays outside the source limit
  const report = await scanProject([fixture("app/service.py", big), fixture("app/generated.py", huge)], {});
  assert.equal(report.scanProgress.read, 1);
  assert.equal(report.omitted, 1);
  assert.deepEqual(report.incomplete.filter((entry) => entry.reason === "ファイル上限").map((entry) => entry.path), ["app/generated.py"]);
});

test("Python sources get the single-function flow check instead of being listed as unanalysed", async () => {
  const report = await scanProject([
    fixture("app/routes.py", "def search(db):\n    q = request.args['q']\n    db.execute(f\"SELECT * FROM t WHERE a = '{q}'\")\n"),
    fixture("app/util.py", "def add(a, b):\n    return a + b\n"),
  ], {});
  const flow = report.rows.filter((row) => row.title === "外部入力からSQL実行");
  assert.equal(flow.length, 1);
  assert.deepEqual(flow[0].location, { path: "app/routes.py", line: 3 });
  assert.equal(flow[0].status, "action");
  assert.equal(report.coverage.pythonFlow, 2);
  assert.equal(report.incomplete.filter((entry) => /データフロー検査がない/.test(entry.reason)).length, 0);
  // no finding is not a pass
  assert.equal(report.rows.filter((row) => row.location?.path === "app/util.py" && row.status === "confirmed").length, 0);
});
