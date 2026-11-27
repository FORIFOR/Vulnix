/**
 * Minimal fix candidates for Python flow findings, as a unified diff the user reviews.
 *
 * Nothing here writes to the user's project: the patched text and the diff are returned
 * for display, download or testing on a copy. Only shapes with one well-understood,
 * behaviour-preserving fix are patched; everything else returns a reason for a manual fix.
 *
 * redirect  the destination goes through a helper that keeps a same-site relative path
 * path      os.path.join(base, ...) becomes a join that refuses a result outside `base`
 * sql       an f-string or "..." + value + "..." query becomes placeholders + a parameter tuple
 * command   values put into a shell command line are shell-quoted (shlex.quote)
 * xss       values put into an HTML string a Flask view returns are HTML-escaped
 */
import { logicalLines, pythonFlow, type PythonFlowFinding, type PythonFlowKind } from "./pythonFlow";

export type FixPatch =
  | { ok: true; file: string; finding: PythonFlowFinding; patched: string; diff: string; changedLines: number }
  | { ok: false; file: string; finding: PythonFlowFinding; reason: string };

export const REDIRECT_HELPER = "_vulnix_safe_redirect";
export const PATH_HELPER = "_vulnix_safe_join";
const HELPERS: Record<string, string[]> = {
  [REDIRECT_HELPER]: [
    `def ${REDIRECT_HELPER}(target, default="/"):`,
    '    """Fix suggested by Vulnix: redirect only to a same-site relative path."""',
    "    from urllib.parse import urlsplit",
    '    value = str(target or "")',
    '    if value.startswith("/") and not value.startswith(("//", "/\\\\")) and "\\\\" not in value \\',
    "            and not urlsplit(value).netloc:",
    "        return value",
    "    return default",
  ],
  [PATH_HELPER]: [
    `def ${PATH_HELPER}(base, *parts):`,
    '    """Fix suggested by Vulnix: keep the joined path inside base."""',
    "    import os",
    "    root = os.path.realpath(base)",
    "    path = os.path.realpath(os.path.join(root, *parts))",
    "    if os.path.commonpath([root, path]) != root:",
    '        raise PermissionError("path outside the allowed directory")',
    "    return path",
  ],
};
const MANUAL = "この形の修正は自動生成していません。下の修正方法に沿って手動で修正してください";

/** The text inside the parentheses that open at `open` (same line only): first argument span. */
function firstArgSpan(line: string, open: number): [number, number] | null {
  let level = 0;
  let quote = "";
  for (let k = open; k < line.length; k++) {
    const c = line[k];
    if (quote) { if (c === "\\") k++; else if (c === quote) quote = ""; continue; }
    if (c === "'" || c === '"') { quote = c; continue; }
    if (c === "(" || c === "[" || c === "{") level++;
    else if (c === ")" || c === "]" || c === "}") { level--; if (level === 0) return [open + 1, k]; }
    else if (c === "," && level === 1) return [open + 1, k];
  }
  return null;
}

/** End index (exclusive) of the call whose "(" is at `open`. */
function callEnd(line: string, open: number): number {
  let level = 0;
  let quote = "";
  for (let k = open; k < line.length; k++) {
    const c = line[k];
    if (quote) { if (c === "\\") k++; else if (c === quote) quote = ""; continue; }
    if (c === "'" || c === '"') { quote = c; continue; }
    if (c === "(" || c === "[" || c === "{") level++;
    else if (c === ")" || c === "]" || c === "}") { level--; if (level === 0) return k + 1; }
  }
  return -1;
}

/** Split an expression at top-level "+" (outside brackets and strings). */
function splitConcat(expr: string): string[] {
  const parts: string[] = [];
  let level = 0;
  let quote = "";
  let last = 0;
  for (let k = 0; k < expr.length; k++) {
    const c = expr[k];
    if (quote) { if (c === "\\") k++; else if (c === quote) quote = ""; continue; }
    if (c === "'" || c === '"') { quote = c; continue; }
    if ("([{".includes(c)) level++;
    else if (")]}".includes(c)) level--;
    else if (c === "+" && level === 0) { parts.push(expr.slice(last, k).trim()); last = k + 1; }
  }
  parts.push(expr.slice(last).trim());
  return parts;
}

type Piece = { text: string } | { expr: string };
/** A string expression as literal text and value pieces: f"a{x}b", 'a' + x + 'b', or a plain literal. */
function pieces(expr: string): Piece[] | null {
  const out: Piece[] = [];
  for (const part of splitConcat(expr)) {
    const lit = /^([rRuU]?)(['"])(.*)\2$/s.exec(part);
    const fstr = /^[fF][rR]?(['"])(.*)\1$/s.exec(part) ?? /^[rR][fF](['"])(.*)\1$/s.exec(part);
    if (lit && !lit[3].includes(lit[2])) out.push({ text: lit[3] });
    else if (fstr) {
      const body = fstr[2];
      let k = 0;
      while (k < body.length) {
        if (body.startsWith("{{", k) || body.startsWith("}}", k)) { out.push({ text: body[k] }); k += 2; continue; }
        if (body[k] === "{") {
          const end = body.indexOf("}", k);
          if (end < 0) return null;
          const inner = body.slice(k + 1, end);
          if (/[!:]/.test(inner.replace(/!=|==|:=/g, ""))) return null;   // format specs: not handled
          out.push({ expr: inner.trim() });
          k = end + 1;
          continue;
        }
        out.push({ text: body[k] });
        k++;
      }
    } else if (/^[A-Za-z_][\w.]*(\(.*\))?$/.test(part) || /^\w+\[.*\]$/.test(part)) out.push({ expr: part });
    else return null;
  }
  // merge adjacent text pieces
  return out.reduce<Piece[]>((acc, p) => {
    const prev = acc[acc.length - 1];
    if ("text" in p && prev && "text" in prev) prev.text += p.text; else acc.push({ ...p });
    return acc;
  }, []);
}

function pyString(text: string): string {
  return text.includes('"') && !text.includes("'") ? `'${text}'` : `"${text.replace(/"/g, '\\"')}"`;
}

/** f"..." with every value wrapped by `wrap`; literal braces doubled again. */
function wrappedFString(ps: Piece[], wrap: (e: string) => string): string {
  const body = ps.map((p) => "text" in p ? p.text.replace(/\{/g, "{{").replace(/\}/g, "}}") : `{${wrap(p.expr)}}`).join("");
  return `f${pyString(body)}`;
}

type Change = { line: number; text: string };
type Need = { imports: Set<string>; helpers: Set<string> };
type Fix = { changes: Change[] } | { reason: string };

function sinkCall(line: string, sink: string): { open: number; end: number } | null {
  const name = sink.split(".").pop() ?? "";
  const at = line.search(new RegExp(`(?<![\\w])(?:[\\w]+\\.)*${name}\\s*\\(`));
  if (at < 0) return null;
  const open = line.indexOf("(", at + line.slice(at).indexOf(name));
  const end = callEnd(line, open);
  return end < 0 ? null : { open, end };
}

/** The line in the same function that assigns `name` last before `before` (0-based). */
function assignmentOf(lines: string[], name: string, before: number): number {
  for (let k = before - 1; k >= 0; k--) {
    if (/^\s*(?:async\s+)?def\s/.test(lines[k])) return -1;
    if (new RegExp(`^\\s*${name}\\s*=(?!=)`).test(lines[k])) return k;
  }
  return -1;
}

function fixRedirect(lines: string[], f: PythonFlowFinding, need: Need): Fix {
  const i = f.line - 1;
  const call = sinkCall(lines[i], f.sink);
  const span = call && firstArgSpan(lines[i], call.open);
  const arg = span ? lines[i].slice(span[0], span[1]) : "";
  if (!span || !arg.trim() || lines[i].includes(REDIRECT_HELPER)) return { reason: MANUAL };
  need.helpers.add(REDIRECT_HELPER);
  const lead = span[0] + (arg.length - arg.trimStart().length);
  return { changes: [{ line: i, text: lines[i].slice(0, lead) + `${REDIRECT_HELPER}(${arg.trim()})` + lines[i].slice(lead + arg.trim().length) }] };
}

function fixPath(lines: string[], f: PythonFlowFinding, need: Need): Fix {
  const i = f.line - 1;
  const call = sinkCall(lines[i], f.sink);
  const span = call && firstArgSpan(lines[i], call.open);
  let arg = span ? lines[i].slice(span[0], span[1]).trim() : "";
  let at = i;
  const assigned = /^[A-Za-z_]\w*$/.test(arg) ? assignmentOf(lines, arg, i) : -1;
  if (assigned >= 0) {                                      // name = os.path.join(...); open(name)
    at = assigned;
    arg = lines[at].slice(lines[at].indexOf("=") + 1).trim();
  }
  const join = /^os\.path\.join\s*\(/.exec(arg);
  if (!join) return { reason: MANUAL };
  const pos = lines[at].indexOf(arg);
  need.helpers.add(PATH_HELPER);
  return { changes: [{ line: at, text: lines[at].slice(0, pos) + PATH_HELPER + arg.slice(join[0].length - 1) + lines[at].slice(pos + arg.length) }] };
}

function fixSql(lines: string[], f: PythonFlowFinding, source: string): Fix {
  const i = f.line - 1;
  const call = sinkCall(lines[i], f.sink);
  const span = call && firstArgSpan(lines[i], call.open);
  if (!call || !span || lines[i].slice(span[1], call.end - 1).trim()) return { reason: MANUAL };  // already has params
  const ph = /^\s*import\s+sqlite3|^\s*from\s+sqlite3\s+import/m.test(source) ? "?" : "%s";
  const toParams = (expr: string): { query: string; values: string[] } | null => {
    const ps = pieces(expr);
    if (!ps || !ps.some((p) => "expr" in p)) return null;
    let query = "";
    const values: string[] = [];
    ps.forEach((p, k) => {
      if ("text" in p) { query += p.text; return; }
      const before = query.slice(-1);
      const next = ps[k + 1];
      if ((before === "'" || before === '"') && next && "text" in next && next.text.startsWith(before)) {
        query = query.slice(0, -1);                       // '{value}' -> ?
        next.text = next.text.slice(1);
      }
      query += ph;
      values.push(p.expr);
    });
    return { query, values };
  };
  const arg = lines[i].slice(span[0], span[1]).trim();
  const tuple = (vs: string[]) => `(${vs.join(", ")}${vs.length === 1 ? "," : ""})`;
  if (/^[A-Za-z_]\w*$/.test(arg)) {                         // query = "..." + v; cur.execute(query)
    const at = assignmentOf(lines, arg, i);
    if (at < 0) return { reason: MANUAL };
    const rhs = lines[at].slice(lines[at].indexOf("=") + 1).trim();
    const built = toParams(rhs);
    if (!built) return { reason: MANUAL };
    const indent = /^\s*/.exec(lines[at])![0];
    return { changes: [
      { line: at, text: `${indent}${arg} = ${pyString(built.query)}` },
      { line: i, text: lines[i].slice(0, call.end - 1) + `, ${tuple(built.values)})` + lines[i].slice(call.end) },
    ] };
  }
  const built = toParams(arg);
  if (!built) return { reason: MANUAL };
  const lead = lines[i].indexOf(arg, span[0]);
  return { changes: [{ line: i, text: lines[i].slice(0, lead) + `${pyString(built.query)}, ${tuple(built.values)}` + lines[i].slice(lead + arg.length) }] };
}

function wrapValues(lines: string[], f: PythonFlowFinding, need: Need, module: string, fn: string, returnExpr: boolean): Fix {
  const i = f.line - 1;
  let start: number, end: number;
  if (returnExpr) {
    const m = /^(\s*return\s+)(.+?)\s*$/.exec(lines[i]);
    if (!m) return { reason: MANUAL };
    start = m[1].length;
    end = m[1].length + m[2].length;
  } else {
    const call = sinkCall(lines[i], f.sink);
    const span = call && firstArgSpan(lines[i], call.open);
    if (!span) return { reason: MANUAL };
    const raw = lines[i].slice(span[0], span[1]);
    start = span[0] + (raw.length - raw.trimStart().length);
    end = start + raw.trim().length;
  }
  const expr = lines[i].slice(start, end);
  const ps = pieces(expr);
  if (!ps || !ps.some((p) => "expr" in p)) return { reason: MANUAL };
  const wrap = (e: string) => `${module}.${fn}(str(${e}))`;
  const isF = /^(?:[fF][rR]?|[rR][fF])['"]/.test(expr.trim()) && splitConcat(expr).length === 1;
  const out = isF ? wrappedFString(ps, wrap)
    : ps.map((p) => "text" in p ? pyString(p.text) : wrap(p.expr)).join(" + ");
  need.imports.add(module);
  return { changes: [{ line: i, text: lines[i].slice(0, start) + out + lines[i].slice(end) }] };
}

function fixOne(lines: string[], source: string, f: PythonFlowFinding, need: Need): Fix {
  switch (f.kind) {
    case "redirect": return fixRedirect(lines, f, need);
    case "path": return fixPath(lines, f, need);
    case "sql": return fixSql(lines, f, source);
    case "command": return wrapValues(lines, f, need, "shlex", "quote", false);
    case "xss": return f.sink === "return" ? wrapValues(lines, f, need, "html", "escape", true) : { reason: MANUAL };
    default: return { reason: MANUAL };
  }
}

type Edit = { at: number; remove: number; add: string[] };   // at: index in the original lines

/** A unified diff from explicit edits (sorted, non-overlapping), with 2 lines of context. */
function unifiedDiff(file: string, before: string[], edits: Edit[]): string {
  const out = [`--- a/${file}`, `+++ b/${file}`];
  let shift = 0;
  for (const e of [...edits].sort((a, b) => a.at - b.at)) {
    const from = Math.max(0, e.at - 2);
    const to = Math.min(before.length, e.at + e.remove + 2);
    const oldLen = to - from;
    out.push(`@@ -${from + 1},${oldLen} +${from + 1 + shift},${oldLen - e.remove + e.add.length} @@`);
    for (let k = from; k < e.at; k++) out.push(" " + before[k]);
    for (let k = e.at; k < e.at + e.remove; k++) out.push("-" + before[k]);
    for (const line of e.add) out.push("+" + line);
    for (let k = e.at + e.remove; k < to; k++) out.push(" " + before[k]);
    shift += e.add.length - e.remove;
  }
  return out.join("\n") + "\n";
}

/** Fix candidates for every supported finding in one Python file (one combined patch). */
export function generateFixes(file: string, source: string, kinds?: readonly PythonFlowKind[]): FixPatch[] {
  const findings = pythonFlow(source).filter((f) => !kinds || kinds.includes(f.kind));
  if (!findings.length) return [];
  const lines = source.split("\n");
  const physical = new Set(logicalLines(source).map((l) => l.line));
  const need: Need = { imports: new Set(), helpers: new Set() };
  const changed = new Map<number, string>();
  const results: FixPatch[] = [];
  const okFindings: PythonFlowFinding[] = [];
  for (const finding of findings) {
    const fix = physical.has(finding.line) ? fixOne(lines, source, finding, need) : { reason: MANUAL };
    if ("reason" in fix || fix.changes.some((c) => changed.has(c.line))) {
      results.push({ ok: false, file, finding, reason: "reason" in fix ? fix.reason : MANUAL });
      continue;
    }
    for (const c of fix.changes) changed.set(c.line, c.text);
    okFindings.push(finding);
  }
  if (!okFindings.length) return results;
  const edits: Edit[] = [...changed].map(([at, text]) => ({ at, remove: 1, add: [text] }));
  const missingImports = [...need.imports].sort().filter((m) => !new RegExp(`^import\\s+${m}\\s*$`, "m").test(source));
  const helpers = [...need.helpers].filter((h) => !source.includes(`def ${h}(`));
  if (missingImports.length || helpers.length) {
    // after the last top-level import before the first definition
    let at = -1;
    for (let k = 0; k < lines.length; k++) {
      if (/^(?:from\s+\S+\s+import\s|import\s)/.test(lines[k])) {
        at = k;
        if (/\(\s*$/.test(lines[k])) while (at + 1 < lines.length && !/\)/.test(lines[at])) at++;
      } else if (/^(?:def |class |@|async def )/.test(lines[k])) break;
    }
    const add = [...missingImports.map((m) => `import ${m}`),
      ...helpers.flatMap((h) => ["", "", ...HELPERS[h]])];
    if (changed.has(at + 1)) return results.concat(okFindings.map((finding) => ({ ok: false, file, finding, reason: MANUAL })));
    edits.push({ at: at + 1, remove: 0, add });
  }
  const sorted = [...edits].sort((a, b) => a.at - b.at || b.remove - a.remove);
  const patchedLines: string[] = [];
  let k = 0;
  for (const e of sorted) {
    while (k < e.at) patchedLines.push(lines[k++]);
    patchedLines.push(...e.add);
    k += e.remove;
  }
  while (k < lines.length) patchedLines.push(lines[k++]);
  const patched = patchedLines.join("\n");
  const diff = unifiedDiff(file, lines, sorted);
  const changedLines = sorted.reduce((n, e) => n + Math.max(e.remove, e.add.length), 0);
  return results.concat(okFindings.map((finding) => ({ ok: true as const, file, finding, patched, diff, changedLines })));
}

/** Fix candidates for the redirect findings in one Python file. */
export function redirectFixes(file: string, source: string): FixPatch[] {
  return generateFixes(file, source, ["redirect"]);
}
