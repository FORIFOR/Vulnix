import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";
const source = readFileSync(new URL("../src/lib/publicMode.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { publicDecision, isPublicPage } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

test("the landing page and its static assets are served", () => {
  for (const p of ["/", "/_next/static/chunks/app.js", "/_next/image", "/media/vulnix-ad.mp4", "/media/shot-chat.png",
                   "/favicon.ico", "/robots.txt"]) {
    assert.equal(publicDecision(p), "allow", p);
  }
});

test("every API path is refused, whatever its spelling", () => {
  for (const p of ["/api", "/api/", "/api/auth/me", "/api/health", "/api/assessments/scan_001", "/API/auth/me",
                   "/api/../api/auth/login", "//api/auth/me", "/api%2fauth/me", "/%61pi/auth/me"]) {
    assert.equal(publicDecision(p), "deny", p);
  }
});

test("operator pages are not reachable: they go to the landing page", () => {
  for (const p of ["/dashboard", "/login", "/assessments/scan_001", "/assets", "/findings/f_idor", "/settings",
                   "/media/../dashboard", "/_next/../dashboard", "/media", "/mediax/a.png"]) {
    assert.equal(publicDecision(p), "redirect", p);
  }
});

test("media paths are plain file names only", () => {
  for (const p of ["/media/a/b.png", "/media/.env", "/media/x.html", "/media/%2e%2e/secret"]) {
    assert.notEqual(publicDecision(p), "allow", p);
  }
});

test("pages that skip the login redirect and the app chrome", () => {
  assert.equal(isPublicPage("/"), true);
  assert.equal(isPublicPage("/login"), true);
  assert.equal(isPublicPage("/welcome"), true);
  assert.equal(isPublicPage("/invite"), true);
  assert.equal(isPublicPage("/dashboard"), false);
});
