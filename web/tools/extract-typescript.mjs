// Parse source only. Never import or execute the analyzed module.
import fs from "node:fs";
import ts from "typescript";

const filename = process.argv[2] ?? "route.ts";
const source = fs.readFileSync(0, "utf8");
if (source.length > 1_000_000) process.exit(2);
const file = ts.createSourceFile(filename, source, ts.ScriptTarget.Latest, true,
  filename.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
const line = node => file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1;
const identifierPath = node => {
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) {
    const left = identifierPath(node.expression);
    return left ? `${left}.${node.name.text}` : "";
  }
  return "";
};
const visit = (node, fn) => { fn(node); ts.forEachChild(node, child => visit(child, fn)); };
const authNames = new Set(["auth", "getServerSession", "getSession", "currentUser"]);
const dataNames = new Set(["findUnique", "findFirst", "findMany", "get", "read"]);
const methods = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);

function describe(name, node) {
  const calls = [];
  let guardObserved = false;
  visit(node.body ?? node, item => {
    if (ts.isCallExpression(item)) {
      const callee = identifierPath(item.expression);
      if (callee && callee.length <= 160) calls.push({ name: callee, line: line(item) });
    }
  });
  for (const item of node.body?.statements ?? []) {
    if (!ts.isIfStatement(item) || !ts.isBinaryExpression(item.expression)) continue;
    const op = item.expression.operatorToken.kind;
    if (![ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken].includes(op)) continue;
    const condition = item.expression.getText(file);
    const branch = item.thenStatement.getText(file);
    if (/orgId|org_id/.test(condition) && /order|resource/.test(condition) &&
        /session|identity|user/.test(condition) &&
        (/throw\b/.test(branch) || (/return\b/.test(branch) && /403/.test(branch)))) {
      guardObserved = true;
    }
  }
  return {
    method: name, line: line(node), handler: name,
    auth: calls.filter(c => authNames.has(c.name.split(".").at(-1))),
    data: calls.filter(c => dataNames.has(c.name.split(".").at(-1)) &&
      /^(db|prisma|store)\./.test(c.name)),
    guard_status: guardObserved ? "guard_observed" : "unknown",
  };
}

const routes = [];
if (file.parseDiagnostics.length === 0) {
  for (const statement of file.statements) {
    if (!ts.isFunctionDeclaration(statement) || !statement.name || !statement.body) continue;
    const exported = statement.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword);
    if (exported && methods.has(statement.name.text)) routes.push(describe(statement.name.text, statement));
  }
}
process.stdout.write(JSON.stringify({ routes, parse_ok: file.parseDiagnostics.length === 0 }));
