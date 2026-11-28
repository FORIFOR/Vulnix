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

test("a middleware's excluded paths stay unknown; declared says where it came from", () => {
  const a = analyzeRoutes([{ path: "main.py", text: [
    "PUBLIC_PATHS = {",
    "    \"/health\",",
    "    \"/public\",",
    "}",
    "@app.middleware(\"http\")",
    "async def gate(request, call_next):",
    "    if request.url.path in PUBLIC_PATHS or request.url.path.startswith(\"/static/\"):",
    "        return await call_next(request)",
    "    if not ok(request):",
    "        return JSONResponse(status_code=401, content={})",
    "    return await call_next(request)",
    "",
    "@app.get(\"/public/items/{item_id}\")",
    "def pub(item_id: str):",
    "    return 1",
    "@app.get(\"/static/logo\")",
    "def logo():",
    "    return 1",
    "@app.get(\"/sessions/{sid}\")",
    "def get_session(sid: str):",
    "    return 1",
    "@app.get(\"/me\")",
    "def me(user = Depends(get_current_user)):",
    "    return 1",
    "@app.get(\"/publications\")",
    "def pubs():",
    "    return 1",
  ].join("\n") }]);
  const by = Object.fromEntries(a.endpoints.map((e) => [e.path, [e.auth, e.authBasis]]));
  assert.deepEqual(by["/public/items/{item_id}"], ["declared", "middleware"]);   // `in PUBLIC_PATHS` is an exact match
  assert.deepEqual(by["/public"] ?? ["unknown", "middleware_excluded"], ["unknown", "middleware_excluded"]);
  assert.deepEqual(by["/static/logo"], ["unknown", "middleware_excluded"]);
  assert.deepEqual(by["/sessions/{sid}"], ["declared", "middleware"]);
  assert.deepEqual(by["/me"], ["declared", "route"]);
  assert.deepEqual(by["/publications"], ["declared", "middleware"]);      // "/public" is not a prefix of it
  const c = a.candidates.find((x) => x.kind === "auth" && x.endpoint.path === "/static/logo");
  assert.match(c.reason, /対象外/);
  assert.ok(a.notes.some((n) => n.includes("実際に認証が強制されているか")));
});

test("a middleware without a 401 declares nothing", () => {
  const a = analyzeRoutes([{ path: "main.py", text: [
    "@app.middleware(\"http\")",
    "async def timing(request, call_next):",
    "    return await call_next(request)",
    "@app.get(\"/x\")",
    "def x():",
    "    return JSONResponse(status_code=401, content={})",
  ].join("\n") }]);
  assert.equal(a.endpoints[0].auth, "unknown");
});

test("exclusions defined in another module and conditions that skip the 401 are reported", () => {
  const a = analyzeRoutes([
    { path: "app/access.py", text: 'OPEN_PATHS = {"/auth/login", "/auth/status"}\n' },
    { path: "app/main.py", text: [
      "@app.middleware(\"http\")",
      "async def _require_device(request, call_next):",
      "    if access.required() and not access.is_direct(request.headers) and request.url.path not in access.OPEN_PATHS:",
      "        dev = access.device_for(request.cookies.get(access.COOKIE))",
      "        if dev is None:",
      "            return JSONResponse(status_code=401, content={})",
      "    return await call_next(request)",
      "",
      "@app.get(\"/auth/status\")",
      "def status():",
      "    return 1",
      "@app.get(\"/sessions/{sid}\")",
      "def get_session(sid: str):",
      "    return 1",
    ].join("\n") },
  ]);
  const by = Object.fromEntries(a.endpoints.map((e) => [e.path, e.authBasis]));
  assert.equal(by["/auth/status"], "middleware_excluded");
  assert.equal(by["/sessions/{sid}"], "middleware");
  const note = a.notes.find((n) => n.startsWith("app/main.py"));
  assert.match(note, /access\.required\(\)/);
  assert.match(note, /access\.is_direct\(…\)/);
  assert.doesNotMatch(note, /device_for/);
});

test("a word in the path itself is not an authentication declaration", () => {
  const a = analyzeRoutes([{ path: "app.py", text: "@app.get(\"/auth/status\")\ndef s():\n    return 1\n" },
    { path: "server.js", text: "router.get('/auth/callback', handler);\nrouter.get('/me', requireAuth, me);\n" }]);
  const by = Object.fromEntries(a.endpoints.map((e) => [e.path, e.auth]));
  assert.equal(by["/auth/status"], "unknown");
  assert.equal(by["/auth/callback"], "unknown");
  assert.equal(by["/me"], "declared");
});

test("middlewares that check only some paths, only a present credential, or skip early are not read as covering everything", () => {
  const mw = (body) => analyzeRoutes([{ path: "main.py", text: [
    "open_paths = {\"/export\"}",
    "@app.middleware(\"http\")",
    "async def gate(request, call_next):",
    ...body,
    "    return await call_next(request)",
    "",
    "@app.get(\"/admin/users\")", "def u():", "    return 1",
    "@app.get(\"/files/{name}\")", "def f(name: str):", "    return 1",
    "@app.get(\"/export\")", "def e():", "    return 1",
    "@app.get(\"/public-files/{n}\")", "def p(n: str):", "    return 1",
  ].join("\n") }]);
  const auth = (a) => Object.fromEntries(a.endpoints.map((e) => [e.path, e.auth]));
  // only /admin is checked
  let a = auth(mw(["    if request.url.path.startswith(\"/admin\"):", "        if not ok(request):", "            return JSONResponse(status_code=401, content={})"]));
  assert.equal(a["/admin/users"], "declared");
  assert.equal(a["/files/{name}"], "unknown");
  // a request without a token is let through
  a = auth(mw(["    token = request.headers.get(\"x-token\")", "    if token and not verify(token):", "        return JSONResponse(status_code=401, content={})"]));
  assert.ok(Object.values(a).every((v) => v === "unknown"));
  // an early pass-through in debug mode is reported; a lower-case list and a startswith prefix are exclusions
  const r = mw(["    if settings.DEBUG or request.url.path in open_paths or request.url.path.startswith(\"/public\"):",
    "        return await call_next(request)", "    if not ok(request):", "        return JSONResponse(status_code=401, content={})"]);
  a = auth(r);
  assert.equal(a["/export"], "unknown");
  assert.equal(a["/public-files/{n}"], "unknown");
  assert.equal(a["/files/{name}"], "declared");
  assert.match(r.notes.find((n) => n.startsWith("main.py")), /settings\.DEBUG/);
});
