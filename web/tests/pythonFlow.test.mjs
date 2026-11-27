import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";
const source = readFileSync(new URL("../src/lib/pythonFlow.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { pythonFlow } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

const kinds = (code) => pythonFlow(code).map((f) => `${f.kind}@${f.line}`);

test("request data reaching a sink in the same function is reported with its line", () => {
  const code = [
    "from flask import request",
    "def search(db):",
    "    term = request.args.get('q')",
    "    sql = f\"SELECT * FROM items WHERE name = '{term}'\"",
    "    db.execute(sql)",
    "    os.system('ls ' + term)",
    "    subprocess.run(term, shell=True)",
    "    eval(request.form['expr'])",
    "    return render_template_string(term)",
  ].join("\n");
  assert.deepEqual(kinds(code), ["sql@5", "command@6", "command@7", "code@8", "template@9"]);
});

test("route parameters, Django and FastAPI sources, SSRF, paths, deserialization and redirects", () => {
  const code = [
    "@app.route('/files/<name>')",
    "def download(name):",
    "    return send_file(name)",
    "",
    "def view(request):",
    "    url = request.GET['next']",
    "    requests.get(url, timeout=5)",
    "    data = pickle.loads(request.body)",
    "    return redirect(url)",
    "",
    "@router.get('/fetch')",
    "async def fetch(target: str, db: Session = Depends(get_db)):",
    "    with open(target) as f:",
    "        return f.read()",
  ].join("\n");
  assert.deepEqual(kinds(code), ["path@3", "ssrf@7", "deserialize@8", "redirect@9", "path@13"]);
});

test("parameterized SQL, sanitizers, reassignment, literals and comments are not reported", () => {
  const code = [
    "def ok(db):",
    "    term = request.args.get('q')",
    "    db.execute('SELECT * FROM t WHERE a = %s', (term,))",
    "    n = int(request.args['n'])",
    "    os.system('sleep ' + str(n))",
    "    safe = shlex.quote(term)",
    "    os.system('echo ' + safe)",
    "    term = 'fixed'",
    "    os.system(term)",
    "    # os.system(request.args['x'])",
    "    print(\"eval(request.args['x'])\")",
    "    subprocess.run(['ls', request.args['p']])",
    "",
    "def other(db):",
    "    db.execute(f'SELECT {term}')",
  ].join("\n");
  assert.deepEqual(kinds(code), []);
});

test("multi-line calls, continuation and tuple assignment keep the flow", () => {
  const code = [
    "def multi(cur):",
    "    a, b = request.args['a'], 1",
    "    query = (\"SELECT * FROM t WHERE x = '%s'\"",
    "             % a)",
    "    cur.execute(",
    "        query,",
    "    )",
    "    cmd = 'ls ' \\",
    "        + b",
    "    os.system(cmd)",
  ].join("\n");
  assert.deepEqual(kinds(code), ["sql@5"]);
});

test("output is bounded and survives unterminated input", () => {
  const many = ["def f():", ...Array.from({ length: 80 }, () => "    eval(request.args['x'])")].join("\n");
  assert.equal(pythonFlow(many).length, 20);
  assert.deepEqual(kinds("def g():\n    x = request.args['q\n    eval(x"), []);
});

test("a conditional reassignment keeps the taint, a sanitizer clears only its own kind", () => {
  const code = [
    "@app.route('/x', methods=['POST'])",
    "def x():",
    "    param = request.form.get('p')",
    "    if not param:",
    "        param = ''",
    "    bar = html.escape(param)",
    "    pickle.loads(bar)",
    "    return make_response(bar)",
  ].join("\n");
  assert.deepEqual(kinds(code), ["deserialize@7"]);
});

test("literal keys of dicts and ConfigParser are tracked separately", () => {
  const code = [
    "def y():",
    "    param = request.args.get('p')",
    "    m = {}",
    "    m['safe'] = 'a'",
    "    m['user'] = param",
    "    flask.redirect(m['safe'])",
    "    conf = configparser.ConfigParser()",
    "    conf.set('s', 'keyA', 'a')",
    "    conf.set('s', 'keyB', param)",
    "    codecs.open(conf.get('s', 'keyA'))",
    "    codecs.open(conf.get('s', 'keyB'))",
    "    flask.redirect(m['user'])",
    "    eval('{0[user]}'.format(m))",
  ].join("\n");
  assert.deepEqual(kinds(code), ["path@11", "redirect@12", "code@13"]);
});

test("returned request data is HTML only in Flask views, and a '..' check guards a path", () => {
  const code = [
    "@app.route('/a')",
    "def a():",
    "    name = request.args['n']",
    "    if '../' in name:",
    "        abort(400)",
    "    open(name)",
    "    return f'<p>{name}</p>'",
    "",
    "@router.get('/b')",
    "def b(q: str):",
    "    return q",
    "",
    "@app.route('/c')",
    "def c():",
    "    return jsonify(request.args['n'])",
  ].join("\n");
  assert.deepEqual(kinds(code), ["xss@7"]);
});

test("a resolved path checked against its base directory is not reported", () => {
  const code = [
    "@app.get('/audio/{path:path}')",
    "def audio(path: str):",
    "    base = AUDIO.resolve()",
    "    p = (base / path).resolve()",
    "    if base not in p.parents or not p.is_file():",
    "        raise HTTPException(404)",
    "    return FileResponse(p)",
    "",
    "@app.get('/{path:path}')",
    "async def spa(path: str):",
    "    f = DIST / path",
    "    return FileResponse(f)",
  ].join("\n");
  assert.deepEqual(kinds(code), ["path@12"]);
});

test("an allowlist guard and a fixed destination host are not open redirects", () => {
  const code = [
    "@router.get('/cb')",
    "async def cb(state: str = Query(None), err: str = Query(None)):",
    "    url = state or 'x'",
    "    if not _is_allowed_redirect(url):",
    "        url = 'https://app.example/login'",
    "    return RedirectResponse(_append_query(url, 'e', err))",
    "",
    "@router.get('/start')",
    "async def start(redirect: str):",
    "    auth = f'{AUTH_URL}?{urlencode({\"state\": redirect})}'",
    "    go = f'https://idp.example/auth?state={redirect}'",
    "    RedirectResponse(go)",
    "    return RedirectResponse(redirect)",
  ].join("\n");
  assert.deepEqual(kinds(code), ["redirect@13"]);
});
