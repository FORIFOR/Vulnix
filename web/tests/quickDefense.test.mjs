import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import ts from "typescript";
const { outputText } = ts.transpileModule(readFileSync(new URL("../src/lib/quickDefense.ts", import.meta.url), "utf8"), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
});
const { checkCves, checkControls, demoEvidence, checkSource, checkLockfile, checkCloudFormation } = await import(
  `data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`
);

const feed = JSON.parse(readFileSync(new URL("../../aegis/feeds/nvd-recent.json", import.meta.url)));

test("mock evidence distinguishes protected, exposed and unknown in all three groups", () => {
  const controls = checkControls(demoEvidence.controls);
  assert.ok(controls.some((item) => item.status === "confirmed"));
  assert.ok(controls.some((item) => item.status === "action"));
  assert.ok(controls.some((item) => item.status === "unknown"));
  assert.deepEqual(new Set(controls.map((item) => item.category)), new Set(["ARTEX", "Claude Code"]));
  assert.ok(checkCves(demoEvidence.components, feed).some((item) => item.status === "action"));
});

test("CVE version matches require applicability and patch evidence", () => {
  const component = { vendor: "apache", product: "http_server", version: "2.4.49" };
  const status = ({ version = component.version, vendor = component.vendor, ...review }) =>
    checkCves([{ ...component, version, vendor, reviews: { "CVE-2021-41773": review } }], feed)[0].status;
  assert.equal(status({}), "unknown");
  assert.equal(status({ applies: true, patched: false }), "action");
  assert.equal(status({ applies: true, patched: true }), "unknown");
  assert.equal(status({ applies: true, patched: true, evidence: "vendor erratum and installed build" }), "confirmed");
  assert.equal(status({ applies: false, evidence: "affected feature absent in effective config" }), "na");
  assert.equal(status({ version: "2.4.58" }), "unknown");
  assert.equal(status({ vendor: "other" }), "unknown");
});

test("missing and contradictory control evidence never confirms a defense", () => {
  assert.equal(checkControls({ saml: { enabled: true } })[0].status, "unknown");
  assert.equal(checkControls({ saml: { enabled: true, applicable: false, evidence: "test" } })[0].status, "unknown");
  assert.equal(checkControls({ saml: { applicable: false, evidence: "No SAML integration" } })[0].status, "na");
});

test("source review reports only line numbers and never confirms safety", () => {
  assert.equal(checkSource("element.innerHTML = userInput;").status, "unknown");
  assert.match(checkSource("element.innerHTML = userInput;").evidence, /1行目/);
  assert.doesNotMatch(checkSource("element.innerHTML = secretValue;").evidence, /secretValue/);
});

test("lockfile audit spots cleartext registry URLs without showing credentials", () => {
  const unsafe = checkLockfile({ lockfileVersion: 3, packages: {
    "": { name: "demo" },
    "node_modules/example": { resolved: "http://secret@registry.invalid/example.tgz", version: "1.2.3" },
  } });
  assert.equal(unsafe.status, "action");
  assert.doesNotMatch(unsafe.evidence, /secret|registry\.invalid/);
  assert.equal(checkLockfile({ lockfileVersion: 3, packages: { "": {} } }).status, "unknown");
});

test("CloudFormation audit checks literal metadata settings and leaves parameters unknown", () => {
  const template = { Resources: {
    Required: { Type: "AWS::EC2::LaunchTemplate", Properties: { LaunchTemplateData: { MetadataOptions: { HttpTokens: "required" } } } },
    Optional: { Type: "AWS::EC2::LaunchTemplate", Properties: { LaunchTemplateData: { MetadataOptions: { HttpEndpoint: "enabled", HttpTokens: "optional" } } } },
    Parameter: { Type: "AWS::EC2::LaunchTemplate", Properties: { LaunchTemplateData: { MetadataOptions: { HttpTokens: { Ref: "Mode" } } } } },
    Disabled: { Type: "AWS::EC2::LaunchTemplate", Properties: { LaunchTemplateData: { MetadataOptions: { HttpEndpoint: "disabled" } } } },
    Unrelated: { Type: "AWS::S3::Bucket" },
  } };
  assert.deepEqual(checkCloudFormation(template).map((item) => item.status), ["confirmed", "action", "unknown", "confirmed"]);
  assert.deepEqual(checkCloudFormation({ Resources: {} }), []);
});

test("an unrecognized inventory entry stays visible alongside matched CVEs", () => {
  const rows = checkCves([
    ...demoEvidence.components,
    { vendor: "unknown", product: "private_service", version: "1.0" },
  ], feed);
  assert.ok(rows.some((row) => row.title.includes("CVE-2021-41773")));
  assert.equal(rows.at(-1).title, "製品 2 の公開CVEとの照合");
  assert.equal(rows.at(-1).status, "unknown");
});
