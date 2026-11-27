/**
 * Static data flow for Python source, inside one function at a time.
 *
 * It follows request data (Flask, Django, FastAPI / Starlette sources and route
 * parameters) through assignments to a fixed set of dangerous calls in the same
 * function. It does not follow calls between functions or files, attributes,
 * containers mutated later, or framework configuration. A file with no finding is
 * therefore "not found by these rules", never "safe".
 */

export type PythonFlowKind = "sql" | "command" | "code" | "template" | "path" | "ssrf" | "deserialize" | "redirect";
export type PythonFlowFinding = { kind: PythonFlowKind; line: number; func: string; sink: string };

type Logical = { indent: number; code: string; line: number };

const MAX_FINDINGS = 20;
const SOURCE = /\brequest\.(?:args|form|values|json|files|cookies|headers|data|get_json|get_data|GET|POST|COOKIES|META|FILES|body|query_params|path_params)\b/;
const ROUTE_DECORATOR = /^@[\w.]*\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(/;
const NOT_INPUT_PARAM = /^(?:self|cls|request|req|db|session|current_user|background_tasks|response)$/;
const SANITIZER = /(?<![\w.])(?:[\w]+\.)*(?:int|float|bool|len|escape|quote|secure_filename|clean|UUID)\s*\(/g;

/** Logical lines with comments removed, plain strings as "" and f-strings as F(expr, ...). */
export function logicalLines(input: string): Logical[] {
  const out: Logical[] = [];
  let cur = "";
  let depth = 0;
  let line = 1;
  let start = 1;
  let indent = 0;
  let atLineStart = true;
  let i = 0;
  const n = input.length;
  const flush = () => {
    if (cur.trim()) out.push({ indent, code: cur.trim(), line: start });
    cur = "";
  };
  while (i < n) {
    const ch = input[i];
    if (atLineStart) {
      let width = 0;
      while (i < n && (input[i] === " " || input[i] === "\t")) { width += input[i] === "\t" ? 8 : 1; i++; }
      indent = width;
      start = line;
      atLineStart = false;
      continue;
    }
    if (ch === "#") { while (i < n && input[i] !== "\n") i++; continue; }
    if (ch === "\\" && input[i + 1] === "\n") { cur += " "; i += 2; line++; continue; }
    if (ch === "\n") {
      line++;
      i++;
      if (depth > 0) { cur += " "; continue; }
      flush();
      atLineStart = true;
      continue;
    }
    if (ch === "'" || ch === "\"") {
      const prefix = /([rRbBfFuU]{1,2})$/.exec(cur);
      const fstring = !!prefix && /f/i.test(prefix[1]) && !/[\w]/.test(cur.slice(0, cur.length - prefix[1].length).slice(-1));
      if (prefix && !/[\w]/.test(cur.slice(0, cur.length - prefix[1].length).slice(-1))) cur = cur.slice(0, cur.length - prefix[1].length);
      const triple = input.startsWith(ch.repeat(3), i);
      const quote = triple ? ch.repeat(3) : ch;
      i += quote.length;
      let body = "";
      while (i < n) {
        if (input[i] === "\\" && i + 1 < n) { body += input[i] + input[i + 1]; if (input[i + 1] === "\n") line++; i += 2; continue; }
        if (input.startsWith(quote, i)) { i += quote.length; break; }
        if (input[i] === "\n") { if (!triple) break; line++; }
        body += input[i];
        i++;
      }
      if (fstring) {
        const exprs: string[] = [];
        for (let k = 0; k < body.length; k++) {
          if (body[k] === "{" && body[k + 1] === "{") { k++; continue; }
          if (body[k] !== "{") continue;
          let level = 1;
          let j = k + 1;
          while (j < body.length && level) { if (body[j] === "{") level++; else if (body[j] === "}") level--; j++; }
          exprs.push(body.slice(k + 1, j - 1).split(/[!:](?![=])/)[0]);
          k = j - 1;
        }
        cur += `F(${exprs.join(",")})`;
      } else cur += "\"\"";
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if ((ch === ")" || ch === "]" || ch === "}") && depth > 0) depth--;
    cur += ch;
    i++;
  }
  flush();
  return out;
}

/** The text inside the parentheses that open at `open`, and the top-level arguments. */
function callArgs(code: string, open: number): string[] {
  let level = 0;
  let k = open;
  for (; k < code.length; k++) {
    const c = code[k];
    if (c === "(" || c === "[" || c === "{") level++;
    else if (c === ")" || c === "]" || c === "}") { level--; if (level === 0) break; }
  }
  return splitTop(code.slice(open + 1, k));
}

function splitTop(text: string): string[] {
  const parts: string[] = [];
  let level = 0;
  let last = 0;
  for (let k = 0; k < text.length; k++) {
    const c = text[k];
    if (c === "(" || c === "[" || c === "{") level++;
    else if (c === ")" || c === "]" || c === "}") level--;
    else if (c === "," && level === 0) { parts.push(text.slice(last, k).trim()); last = k + 1; }
  }
  const tail = text.slice(last).trim();
  if (tail) parts.push(tail);
  return parts;
}

function withoutSanitized(expr: string): string {
  let text = expr;
  for (let guard = 0; guard < 20; guard++) {
    SANITIZER.lastIndex = 0;
    const m = SANITIZER.exec(text);
    if (!m) break;
    const open = m.index + m[0].length - 1;
    let level = 0;
    let k = open;
    for (; k < text.length; k++) {
      if (text[k] === "(") level++;
      else if (text[k] === ")") { level--; if (level === 0) break; }
    }
    text = text.slice(0, m.index) + "0" + text.slice(k + 1);
  }
  return text;
}

function isTainted(expr: string, tainted: Set<string>): boolean {
  const text = withoutSanitized(expr);
  if (SOURCE.test(text)) return true;
  for (const m of text.matchAll(/(?<![\w.])[A-Za-z_]\w*/g)) if (tainted.has(m[0])) return true;
  return false;
}

type Sink = { kind: PythonFlowKind; pattern: RegExp; arg?: number; requires?: RegExp; unless?: RegExp };
const SINKS: Sink[] = [
  { kind: "sql", pattern: /\.(?:execute|executemany|executescript|raw)\s*\(/g },
  { kind: "command", pattern: /(?<![\w.])os\.(?:system|popen)\s*\(/g },
  { kind: "command", pattern: /(?<![\w.])subprocess\.(?:run|call|check_call|check_output|Popen)\s*\(/g, requires: /\bshell\s*=\s*True\b/ },
  { kind: "code", pattern: /(?<![\w.])(?:eval|exec)\s*\(/g },
  { kind: "template", pattern: /(?<![\w.])(?:render_template_string|Markup|mark_safe)\s*\(/g },
  { kind: "path", pattern: /(?<![\w.])(?:open|send_file|FileResponse)\s*\(/g },
  { kind: "ssrf", pattern: /(?<![\w.])(?:requests|httpx)\.(?:get|post|put|patch|delete|head)\s*\(|(?<![\w])urlopen\s*\(/g },
  { kind: "ssrf", pattern: /(?<![\w.])(?:requests|httpx)\.request\s*\(/g, arg: 1 },
  { kind: "deserialize", pattern: /(?<![\w.])(?:pickle|marshal|dill)\.loads?\s*\(/g },
  { kind: "deserialize", pattern: /(?<![\w.])yaml\.(?:load|load_all)\s*\(/g, unless: /SafeLoader|CSafeLoader/ },
  { kind: "redirect", pattern: /(?<![\w.])(?:redirect|HttpResponseRedirect|RedirectResponse)\s*\(/g },
];

function params(signature: string): string[] {
  return splitTop(signature).flatMap((part) => {
    if (/Depends\s*\(|:\s*(?:Session|Request|Response|BackgroundTasks)\b/.test(part)) return [];
    const name = /^\*{0,2}([A-Za-z_]\w*)/.exec(part)?.[1];
    return name && !NOT_INPUT_PARAM.test(name) ? [name] : [];
  });
}

export function pythonFlow(input: string): PythonFlowFinding[] {
  const lines = logicalLines(input);
  const findings: PythonFlowFinding[] = [];
  type Scope = { indent: number; name: string; tainted: Set<string> };
  const stack: Scope[] = [];
  for (let index = 0; index < lines.length && findings.length < MAX_FINDINGS; index++) {
    const { indent, code, line } = lines[index];
    while (stack.length && indent <= stack[stack.length - 1].indent) stack.pop();
    const def = /^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\((.*)\)\s*(?:->.*)?:\s*$/.exec(code);
    if (def) {
      const decorators: string[] = [];
      for (let back = index - 1; back >= 0 && lines[back].indent === indent && lines[back].code.startsWith("@"); back--)
        decorators.push(lines[back].code);
      const all = splitTop(def[2]);
      const firstName = /^\*{0,2}([A-Za-z_]\w*)/.exec(all[0] ?? "")?.[1];
      const route = decorators.some((d) => ROUTE_DECORATOR.test(d));
      const djangoView = !route && firstName === "request";
      stack.push({ indent, name: def[1], tainted: new Set(route || djangoView ? params(def[2]) : []) });
      continue;
    }
    const scope = stack[stack.length - 1];
    if (!scope) continue;
    const reported = new Set<PythonFlowKind>();
    for (const sink of SINKS) {
      sink.pattern.lastIndex = 0;
      for (const m of code.matchAll(sink.pattern)) {
        if (reported.has(sink.kind)) break;
        const args = callArgs(code, m.index + m[0].length - 1);
        const value = args[sink.arg ?? 0];
        if (value === undefined || /^\w+\s*=/.test(value) && !/^\w+\s*==/.test(value)) continue;
        if (sink.requires && !args.some((a) => sink.requires!.test(a))) continue;
        if (sink.unless && args.some((a) => sink.unless!.test(a))) continue;
        if (!isTainted(value, scope.tainted)) continue;
        reported.add(sink.kind);
        findings.push({ kind: sink.kind, line, func: scope.name, sink: m[0].replace(/\s*\($/, "") });
        if (findings.length >= MAX_FINDINGS) break;
      }
    }
    const loop = /^(?:async\s+)?for\s+(.+?)\s+in\s+(.+):\s*$/.exec(code);
    if (loop) {
      if (isTainted(loop[2], scope.tainted)) for (const name of loop[1].match(/[A-Za-z_]\w*/g) ?? []) scope.tainted.add(name);
      continue;
    }
    const assign = /^((?:[A-Za-z_]\w*\s*,\s*)*[A-Za-z_]\w*)\s*(?::[^=]+)?(\+?=)(?!=)\s*(.+)$/.exec(code);
    if (!assign) continue;
    const names = assign[1].split(",").map((s) => s.trim());
    const values = names.length > 1 ? splitTop(assign[3].replace(/^\((.*)\)$/, "$1")) : [assign[3]];
    names.forEach((name, k) => {
      const expr = values.length === names.length ? values[k] : assign[3];
      const tainted = isTainted(expr, scope.tainted);
      if (tainted) scope.tainted.add(name);
      else if (assign[2] === "=") scope.tainted.delete(name);
    });
  }
  return findings;
}
