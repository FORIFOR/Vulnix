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
const orgProperties = new Set(["orgId", "org_id"]);
const resourceBases = new Set(["order", "resource"]);
const identityBases = new Set(["session", "identity", "user"]);

function orgOwner(node) {
  if (!ts.isPropertyAccessExpression(node) || !orgProperties.has(node.name.text) ||
      !ts.isIdentifier(node.expression)) return "";
  const base = node.expression.text;
  if (resourceBases.has(base)) return "resource";
  if (identityBases.has(base)) return "identity";
  return "";
}

function directOrgMismatch(node) {
  if (!ts.isBinaryExpression(node) || ![
    ts.SyntaxKind.ExclamationEqualsEqualsToken,
    ts.SyntaxKind.ExclamationEqualsToken,
  ].includes(node.operatorToken.kind)) return false;
  const owners = new Set([orgOwner(node.left), orgOwner(node.right)]);
  return owners.size === 2 && owners.has("resource") && owners.has("identity");
}

function emptyForbiddenResponse(node) {
  if (!node || !ts.isNewExpression(node) || identifierPath(node.expression) !== "Response") return false;
  const args = node.arguments ?? [];
  if (args.length < 2 || args[0].kind !== ts.SyntaxKind.NullKeyword ||
      !ts.isObjectLiteralExpression(args[1])) return false;
  return args[1].properties.some(prop => ts.isPropertyAssignment(prop) &&
    (ts.isIdentifier(prop.name) || ts.isStringLiteral(prop.name)) &&
    prop.name.text === "status" && ts.isNumericLiteral(prop.initializer) &&
    prop.initializer.text === "403");
}

function directlyRejects(statement) {
  const first = ts.isBlock(statement) ? statement.statements[0] : statement;
  return !!first && (ts.isThrowStatement(first) ||
    (ts.isReturnStatement(first) && emptyForbiddenResponse(first.expression)));
}

function describe(name, node) {
  const calls = [];
  let guardObserved = false;
  visit(node.body ?? node, item => {
    if (ts.isCallExpression(item)) {
      const callee = identifierPath(item.expression);
      if (callee && callee.length <= 160) calls.push({ name: callee, line: line(item) });
    }
  });
  let mayExitBefore = false;
  for (const item of node.body?.statements ?? []) {
    if (!mayExitBefore && ts.isIfStatement(item) && directOrgMismatch(item.expression) &&
        directlyRejects(item.thenStatement)) {
      guardObserved = true;
    }
    visit(item, child => { if (ts.isReturnStatement(child)) mayExitBefore = true; });
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
    const exported = statement.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword);
    if (!exported) continue;
    if (ts.isFunctionDeclaration(statement) && statement.name && statement.body &&
        methods.has(statement.name.text)) {
      routes.push(describe(statement.name.text, statement));
    } else if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name) || !methods.has(declaration.name.text)) continue;
        const fn = declaration.initializer;
        if (fn && (ts.isArrowFunction(fn) || ts.isFunctionExpression(fn)) && ts.isBlock(fn.body)) {
          routes.push(describe(declaration.name.text, fn));
        }
      }
    }
  }
}
process.stdout.write(JSON.stringify({ routes, parse_ok: file.parseDiagnostics.length === 0 }));
