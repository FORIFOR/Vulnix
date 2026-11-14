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

const { canToggleRole, canRemove } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

test("role toggles mirror the server rules", () => {
  const owner = { name: "alice", roles: ["owner"] };
  const admin = { name: "adam", roles: ["admin"] };
  const runner = { name: "rita", roles: ["runner"] };
  // an admin manages non-owners, but neither owners nor the owner role
  assert.equal(canToggleRole("adam", ["admin"], runner, "approver", 1), true);
  assert.equal(canToggleRole("adam", ["admin"], runner, "owner", 1), false);
  assert.equal(canToggleRole("adam", ["admin"], owner, "viewer", 1), false);
  // nobody adds power to themselves; lowering is fine
  assert.equal(canToggleRole("adam", ["admin"], admin, "approver", 1), false);
  assert.equal(canToggleRole("adam", ["admin", "runner"], { name: "adam", roles: ["admin", "runner"] }, "admin", 1), true);
  // the last owner stays an owner; a member keeps at least one role
  assert.equal(canToggleRole("alice", ["owner"], owner, "owner", 1), false);
  assert.equal(canToggleRole("alice", ["owner"], { name: "bob", roles: ["owner", "runner"] }, "owner", 2), true);
  assert.equal(canToggleRole("alice", ["owner"], runner, "runner", 1), false);
  // runners and viewers change nothing
  assert.equal(canToggleRole("rita", ["runner"], { name: "v", roles: ["viewer"] }, "runner", 1), false);
});

test("removal mirrors the server rules", () => {
  assert.equal(canRemove("adam", ["admin"], { name: "rita", roles: ["runner"] }, 1), true);
  assert.equal(canRemove("adam", ["admin"], { name: "alice", roles: ["owner"] }, 2), false);   // admin cannot remove an owner
  assert.equal(canRemove("alice", ["owner"], { name: "bob", roles: ["owner"] }, 2), true);
  assert.equal(canRemove("alice", ["owner"], { name: "alice", roles: ["owner"] }, 1), false);  // last owner
  assert.equal(canRemove("rita", ["runner"], { name: "rita", roles: ["runner"] }, 1), true);   // leaving oneself
  assert.equal(canRemove("rita", ["runner"], { name: "v", roles: ["viewer"] }, 1), false);
});
