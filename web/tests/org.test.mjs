import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";
const source = readFileSync(new URL("../src/lib/org.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { readOrgCookie, activeOrg, orgCookieValue, inviteTokenFromHash } =
  await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

const ORGS = [{ id: "org_aaaaaaaaaaaa", name: "A", roles: ["owner"] }, { id: "default", name: "D", roles: ["viewer"] }];

test("the org cookie is read only when it is a well-formed id", () => {
  assert.equal(readOrgCookie("aegis_session=x; vulnix_org=org_aaaaaaaaaaaa"), "org_aaaaaaaaaaaa");
  assert.equal(readOrgCookie("vulnix_org=default"), "default");
  assert.equal(readOrgCookie("vulnix_org=../etc"), null);
  assert.equal(readOrgCookie("vulnix_org=org_AAAA"), null);
  assert.equal(readOrgCookie("other=1"), null);
});

test("the active org is the selected one when the account belongs to it", () => {
  assert.equal(activeOrg(ORGS, "default").id, "default");
  assert.equal(activeOrg(ORGS, "org_bbbbbbbbbbbb").id, "org_aaaaaaaaaaaa");   // not a member: first org
  assert.equal(activeOrg([], "default"), null);
});

test("the cookie value refuses anything but an org id", () => {
  assert.match(orgCookieValue("org_aaaaaaaaaaaa"), /^vulnix_org=org_aaaaaaaaaaaa; Path=\/; SameSite=Strict/);
  assert.throws(() => orgCookieValue("x; Domain=evil"));
});

test("invite tokens come from the URL fragment only in their exact shape", () => {
  assert.equal(inviteTokenFromHash("#inv_abcdefghijklmnopqrstuvwxyz012345"), "inv_abcdefghijklmnopqrstuvwxyz012345");
  assert.equal(inviteTokenFromHash("#inv_short"), null);
  assert.equal(inviteTokenFromHash("#<script>"), null);
  assert.equal(inviteTokenFromHash(""), null);
});
