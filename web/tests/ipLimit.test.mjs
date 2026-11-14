import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";
const source = readFileSync(new URL("../src/lib/ipLimit.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { IpLimiter, clientIp } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

test("sign-ups are limited per client address", () => {
  const l = new IpLimiter();
  for (let i = 0; i < 3; i++) assert.equal(l.check("1.2.3.4", "POST", "auth/register", 1000), null);
  assert.equal(l.check("1.2.3.4", "POST", "auth/register", 1000), "register");
  assert.equal(l.check("5.6.7.8", "POST", "auth/register", 1000), null);          // another person is unaffected
  assert.equal(l.check("1.2.3.4", "POST", "auth/register", 1000 + 60_001), null); // the window passes
});

test("a refused request is not counted", () => {
  const l = new IpLimiter([{ name: "x", match: () => true, limit: 1, windowMs: 60_000 }]);
  assert.equal(l.check("a", "GET", "p", 0), null);
  assert.equal(l.check("a", "GET", "p", 1), "x");
  assert.equal(l.check("a", "GET", "p", 60_001), null);
});

test("general API use is limited too", () => {
  const l = new IpLimiter();
  for (let i = 0; i < 240; i++) assert.equal(l.check("9.9.9.9", "GET", "assets", 0), null);
  assert.equal(l.check("9.9.9.9", "GET", "assets", 0), "any");
});

test("only address-like header values are used", () => {
  assert.equal(clientIp("203.0.113.7"), "203.0.113.7");
  assert.equal(clientIp("2001:db8::1"), "2001:db8::1");
  assert.equal(clientIp("1.2.3.4, 5.6.7.8"), null);
  assert.equal(clientIp(null), null);
});

const mod = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

test("IPv6 addresses of one /64 share a limit", () => {
  const l = new mod.IpLimiter();
  for (let i = 0; i < 3; i++) assert.equal(l.check(`2001:db8:1:2::${i + 1}`, "POST", "auth/register", 0), null);
  assert.equal(l.check("2001:db8:1:2:ffff::9", "POST", "auth/register", 0), "register");
  assert.equal(l.check("2001:db8:1:3::1", "POST", "auth/register", 0), null);   // another /64
  assert.equal(mod.limitKey("2001:db8:1:2::1"), mod.limitKey("2001:0db8:0001:0002:abcd::5"));
  assert.equal(mod.limitKey("203.0.113.7"), "203.0.113.7");
});

test("a flood of addresses does not reset everyone's limits", () => {
  const l = new mod.IpLimiter(undefined, 100);
  for (let i = 0; i < 3; i++) l.check("198.51.100.1", "POST", "auth/register", 1000);
  for (let i = 0; i < 500; i++) l.check(`10.0.${i >> 8}.${i & 255}`, "GET", "assets", 1000 + i);
  assert.equal(l.check("198.51.100.1", "POST", "auth/register", 2000), "register");      // still limited
});

test("sign-ups through the entrance have an overall cap too", () => {
  const l = new mod.IpLimiter();
  let refused = null;
  for (let i = 0; i < 40 && !refused; i++) refused = l.check(`2001:db8:${i}::1`, "POST", "auth/register", 0);
  assert.equal(refused, "register-all");
});
