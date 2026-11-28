// Run the folder scan (the same scanProject the browser runs) on a local folder and print the
// results as JSON: status, title, file and line - never file contents. Reads only; secret files
// (.env*, *.key, *.pem, data*/ and the like) are never opened.
// Usage: node scripts/scan_project_cli.mjs <folder> [feed.json]
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { createRequire } from "node:module";
const require = createRequire(new URL("../web/package.json", import.meta.url));
const ts = require("typescript");
const lib = (name, imports = {}) => {
  let text = readFileSync(new URL(`../web/src/lib/${name}.ts`, import.meta.url), "utf8");
  for (const [before, after] of Object.entries(imports)) text = text.replace(`from "${before}"`, `from "${after}"`);
  const out = ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText;
  return `data:text/javascript;base64,${Buffer.from(out).toString("base64")}`;
};
const resolve = (m) => require.resolve(m).startsWith("/") ? "file://" + require.resolve(m) : require.resolve(m);
const quick = lib("quickDefense");
const flow = lib("pythonFlow");
const packages = lib("projectPackages", { "./quickDefense": quick, semver: resolve("semver"), "@renovatebot/pep440": resolve("@renovatebot/pep440") });
const { scanProject } = await import(lib("projectDefense", {
  "./quickDefense": quick, "./projectPackages": packages, "./runtimePlan": lib("runtimePlan"), "./pythonFlow": flow,
  "./fixPatch": lib("fixPatch", { "./pythonFlow": flow }), typescript: resolve("typescript"), yaml: resolve("yaml"),
}));
const SECRET = /(^|\/)(\.env[^/]*|.*\.(key|pem|p12|pfx)|id_[a-z0-9]+|credentials[^/]*|secrets?[^/]*\.(json|ya?ml)|data[^/]*\/.*)$/i;
const SKIP = new Set(["node_modules", ".git", ".venv", "venv", ".next", "dist", "build", "__pycache__", ".mypy_cache", ".pytest_cache"]);
const root = process.argv[2];
const files = [];
(function walk(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name) || name.startsWith(".venv")) continue;
    const full = join(dir, name);
    let st; try { st = statSync(full); } catch { continue; }
    const rel = relative(root, full).split(sep).join("/");
    if (st.isDirectory()) walk(full);
    else if (!SECRET.test(rel) && st.size < 2_000_000) files.push({ path: `project/${rel}`, file: new File([readFileSync(full)], name) });
  }
})(root);
const feed = process.argv[3] ? JSON.parse(readFileSync(process.argv[3], "utf8")) : { vulnerabilities: [] };
const report = await scanProject(files, feed);
const rows = report.rows.map((r) => ({ status: r.status, title: r.title, kind: r.kind, path: r.location?.path, line: r.location?.line,
  fixes: (r.fixes || []).length || undefined, testCode: r.testCode || undefined }));
console.log(JSON.stringify({ read: report.read, unsupported: report.unsupported, files: files.length, rows }, null, 1));
