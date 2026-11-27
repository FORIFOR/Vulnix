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
