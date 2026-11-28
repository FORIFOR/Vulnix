import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const file = readFileSync(new URL("../src/lib/apiSpec.ts", import.meta.url), "utf8")
  .replace('from "yaml"', `from "${import.meta.resolve("yaml")}"`);
const { outputText } = ts.transpileModule(file, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { analyzeSpec, analyzeRoutes, hasTemplate } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);
const lab = readFileSync(new URL("../../tests/fixtures/a2b_openapi.json", import.meta.url), "utf8");

test("the lab's OpenAPI file gives one candidate per axis, each with its source and unknowns", () => {
  const a = analyzeSpec(lab, "a2b_openapi.json");
  assert.equal(a.host, "a2b.lab.test");
  const kinds = (k) => a.candidates.filter((c) => c.kind === k).map((c) => c.endpoint.path);
  assert.deepEqual(kinds("cross_account"), ["/api/orgs/{org}/notes/{note}"]);
  assert.deepEqual(kinds("cross_tenant"), ["/api/orgs/{org}/notes/{note}", "/api/orgs/{org}/admin/export"]);
  assert.deepEqual(kinds("admin_function"), ["/api/orgs/{org}/admin/export"]);
  assert.deepEqual(kinds("sensitive"), ["/api/orgs/{org}/admin/export"]);        // api_token in the export
  assert.deepEqual(kinds("auth"), []);                                           // /api/health is public by name
  for (const c of a.candidates) {
    assert.match(c.endpoint.source, /^a2b_openapi\.json: paths\./);
    assert.ok(c.unknown.length > 0, "every candidate says what the definition cannot tell");
  }
});

test("YAML and Swagger 2 are read; a definition without global security leaves auth unknown", () => {
  const yaml = "swagger: '2.0'\nhost: api.example.test\npaths:\n  /users/{user_id}:\n    get:\n      responses:\n        '200': {description: ok}\n";
  const a = analyzeSpec(yaml, "swagger.yaml");
  assert.equal(a.host, "api.example.test");
  assert.deepEqual(a.candidates.map((c) => c.kind).sort(), ["auth", "cross_account"]);
  assert.equal(a.candidates.find((c) => c.kind === "auth").endpoint.auth, "unknown");
  assert.throws(() => analyzeSpec("{\"paths\": {}}", "x.json"), /OpenAPI/);
});

test("Flask, FastAPI and Express routes become candidates; auth is 'declared' only when seen", () => {
  const a = analyzeRoutes([
    { path: "app.py", text: "@app.route('/api/teams/<int:team_id>/docs/<doc_id>', methods=['GET', 'DELETE'])\n@login_required\ndef doc(team_id, doc_id): ..." },
    { path: "main.py", text: "@router.get('/admin/users')\ndef users(): ..." },
    { path: "server.js", text: "router.get('/api/invoices/:invoiceId', requireAuth, handler)" },
  ]);
  const doc = a.endpoints.filter((e) => e.path === "/api/teams/{team_id}/docs/{doc_id}");
  assert.deepEqual(doc.map((e) => e.method), ["GET", "DELETE"]);
  assert.equal(doc[0].auth, "declared");
  assert.equal(doc[0].orgParam, "team_id");
  assert.equal(a.endpoints.find((e) => e.path === "/admin/users").admin, true);
  assert.equal(a.endpoints.find((e) => e.path === "/admin/users").auth, "unknown");
  assert.equal(a.endpoints.find((e) => e.path === "/api/invoices/{invoiceId}").auth, "declared");
  assert.ok(hasTemplate("/api/x/{id}") && !hasTemplate("/api/x/1"));
});

test("FastAPI dependency aliases and an app-wide 401 middleware count as declared auth", () => {
  const a = analyzeRoutes([
    { path: "deps.py", text: "CurrentUser = Annotated[User, Depends(get_current_user)]\n" },
    { path: "routes.py", text: [
      "@router.patch(\"/children/{child_id}\")",
      "def update_child(child_id: str, guardian: CurrentUser, db: Db):",
      "    return 1",
      "@router.get(\"/open\")",
      "def open_route():",
      "    return 1",
    ].join("\n") },
    { path: "main.py", text: [
      "@app.middleware(\"http\")",
      "async def _require_device(request, call_next):",
      "    if not ok(request):",
      "        return JSONResponse(status_code=401, content={})",
      "    return await call_next(request)",
      "@app.get(\"/sessions/{sid}\")",
      "def get_session(sid: str):",
      "    return 1",
    ].join("\n") },
  ]);
  const auth = Object.fromEntries(a.endpoints.map((e) => [e.path, e.auth]));
  assert.equal(auth["/children/{child_id}"], "declared");
  assert.equal(auth["/open"], "unknown");
  assert.equal(auth["/sessions/{sid}"], "declared");
  assert.ok(a.notes.some((n) => n.includes("ミドルウェア")));
});
