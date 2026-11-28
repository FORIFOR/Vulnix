// Measure web/src/lib/pythonFlow.ts against the OWASP Benchmark for Python (labelled data).
// Usage: node scripts/eval_python_flow.mjs <path-to-BenchmarkPython checkout> [--misses]
// The benchmark is GPL-3 evaluation data; it is read here, never copied into Vulnix.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const require = createRequire(new URL("../web/package.json", import.meta.url));
const ts = require("typescript");
const source = readFileSync(fileURLToPath(new URL("../web/src/lib/pythonFlow.ts", import.meta.url)), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { pythonFlow } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

const root = process.argv[2];
const MAP = { cmdi: "command", codeinj: "code", deserialization: "deserialize", pathtraver: "path", redirect: "redirect", sqli: "sql", xss: ["xss", "template"] };
const rows = readFileSync(`${root}/expectedresults-0.1.csv`, "utf8").split("\n").filter((l) => l && !l.startsWith("#")).map((l) => l.split(","));
const stats = {};
const misses = [];
for (const [name, cat, real] of rows) {
  const kind = MAP[cat];
  const s = (stats[cat] ??= { tp: 0, fn: 0, fp: 0, tn: 0, supported: !!kind });
  const found = kind ? pythonFlow(readFileSync(`${root}/testcode/${name}.py`, "utf8")).some((f) => [kind].flat().includes(f.kind)) : false;
  if (real === "true") found ? s.tp++ : (s.fn++, misses.push(`FN ${name} ${cat}`));
  else found ? (s.fp++, misses.push(`FP ${name} ${cat}`)) : s.tn++;
}
const pct = (a, b) => (b ? Math.round((100 * a) / b) : 0);
let T = { tp: 0, fn: 0, fp: 0, tn: 0 };
console.log("category        supported  TP  FN  FP  TN  TPR%  FPR%  score");
for (const [cat, s] of Object.entries(stats)) {
  const tpr = pct(s.tp, s.tp + s.fn), fpr = pct(s.fp, s.fp + s.tn);
  console.log(`${cat.padEnd(16)}${String(s.supported).padEnd(10)}${[s.tp, s.fn, s.fp, s.tn].map((v) => String(v).padStart(4)).join("")}${String(tpr).padStart(6)}${String(fpr).padStart(6)}${String(tpr - fpr).padStart(7)}`);
  if (s.supported) for (const k of Object.keys(T)) T[k] += s[k];
}
console.log(`supported total  TP=${T.tp} FN=${T.fn} FP=${T.fp} TN=${T.tn} TPR=${pct(T.tp, T.tp + T.fn)}% FPR=${pct(T.fp, T.fp + T.tn)}% precision=${pct(T.tp, T.tp + T.fp)}%`);
if (process.argv.includes("--misses")) console.log(misses.join("\n"));
