// Print fix candidates (unified diff + patched text) for one Python file as JSON.
// Usage: node scripts/fix_patch_cli.mjs <file.py> [display-name]   (reads only; never writes the file)
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const require = createRequire(new URL("../web/package.json", import.meta.url));
const ts = require("typescript");
const load = (name) => ts.transpileModule(readFileSync(fileURLToPath(new URL(`../web/src/lib/${name}.ts`, import.meta.url)), "utf8"),
  { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText;
const url = (code) => `data:text/javascript;base64,${Buffer.from(code).toString("base64")}`;
const flowUrl = url(load("pythonFlow"));
const { generateFixes } = await import(url(load("fixPatch").replace('"./pythonFlow"', JSON.stringify(flowUrl))));
const file = process.argv[2];
console.log(JSON.stringify(generateFixes(process.argv[3] || file, readFileSync(file, "utf8"))));
