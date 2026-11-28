/**
 * Static data flow for Python source, inside one function at a time.
 *
 * It follows request data (Flask, Django, FastAPI / Starlette sources and route
 * parameters) through assignments to a fixed set of dangerous calls in the same
 * function. It does not follow calls between functions or files, attributes,
 * containers mutated later, or framework configuration. A file with no finding is
 * therefore "not found by these rules", never "safe".
 */

export type PythonFlowKind = "sql" | "command" | "code" | "template" | "xss" | "path" | "ssrf" | "deserialize" | "redirect";
/** `via`: a file path that reaches the sink only through the return value of a helper of the
 * project (e.g. `path = rendered(cid, jid)`). What that helper checks is not followed. */
export type PythonFlowFinding = { kind: PythonFlowKind; line: number; func: string; sink: string; via?: string };
const KINDS: PythonFlowKind[] = ["sql", "command", "code", "template", "xss", "path", "ssrf", "deserialize", "redirect"];

type Logical = { indent: number; code: string; line: number };

const MAX_FINDINGS = 20;
const SOURCE = /\brequest\.(?:args|form|values|json|files|cookies|headers|data|get_json|get_data|GET|POST|COOKIES|META|FILES|body|query_params|path_params)\b/;
const ROUTE_DECORATOR = /^@[\w.]*\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(/;
const NOT_INPUT_PARAM = /^(?:self|cls|request|req|db|session|current_user|background_tasks|response)$/;
// A sanitizer only clears the kinds it actually protects: html.escape stops HTML
// injection but not a pickle or a shell, and secure_filename only a file path.
const ANY_KIND = String.raw`int|float|bool|len|UUID|uuid\.UUID`;
const SANITIZERS: Partial<Record<PythonFlowKind, string>> = {
  template: String.raw`(?:\w+\.)*escape\w*|(?:bleach\.)?clean`,
  xss: String.raw`(?:\w+\.)*escape\w*|(?:bleach\.)?clean`,
  path: String.raw`(?:werkzeug\.utils\.)?secure_filename|(?:os\.path\.)?basename|[\w.]*safe_join\w*|[\w.]*safe_path\w*`,
  command: String.raw`(?:shlex\.)?quote`,
  // the helper a Vulnix fix adds (fixPatch.ts) and similarly named same-site checks
  redirect: String.raw`[\w.]*safe_redirect\w*`,
};
const SANITIZER: Record<string, RegExp> = Object.fromEntries(KINDS.map((k) =>
  [k, new RegExp(String.raw`(?<![\w.])(?:${ANY_KIND}${SANITIZERS[k] ? "|" + SANITIZERS[k] : ""})\s*\(`, "g")]));
const CONDITIONAL = /^(?:if|elif|else|for|async\s+for|while|except|case|match)\b/;
const MUTATOR = /^([A-Za-z_]\w*)\.(?:append|extend|insert|add|update|set|put|setdefault|write|writelines|__setitem__)\s*\(/;
const STORE = /^([A-Za-z_]\w*)(\[.*\]|\.\w+)\s*(?::[^=]+)?\+?=(?!=)\s*(.+)$/;
const NOT_HTML = /^(?:jsonify|json\.dumps|render_template|redirect|flask\.redirect|send_file|send_from_directory|abort|make_response|HttpResponse|JsonResponse|Response|FileResponse|RedirectResponse|None|True|False)\b|^[{[]|^-?\d/;

/**
 * Logical lines with comments removed and f-strings as F(expr, ...). Plain strings keep
 * their text only when it is a short word-like key or a path fragment ("keyA", "../");
 * any other string becomes "". Quotes therefore only ever delimit literals.
 */
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
        // a literal start that is more than slashes ("https://host/...") fixes the destination host
        const lead = body.split("{")[0];
        cur += `${/[^/\\]/.test(lead) ? "FP" : "F"}(${exprs.join(",")})`;
      } else cur += /^(?:[./\\]{1,4}|[\w.-]{1,40})$/.test(body) ? `"${body}"` : "\"\"";
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

function withoutSanitized(expr: string, kind: PythonFlowKind): string {
  const pattern = SANITIZER[kind];
  let text = expr;
  for (let guard = 0; guard < 20; guard++) {
    pattern.lastIndex = 0;
    const m = pattern.exec(text);
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

type Taint = Map<string, Set<PythonFlowKind>>;

// d["key"], d.get("key", ...) and ConfigParser's conf.get("section", "key")
const KEY_READ = /(?<![\w.])([A-Za-z_]\w*)\s*(?:\[\s*"([^"]*)"\s*\]|\.get\(\s*(?:"[^"]*"\s*,\s*)?"([^"]*)"[^()]*\))/g;

function taintedFor(expr: string, kind: PythonFlowKind, tainted: Taint): boolean {
  // Request data after a fixed scheme and host only reaches the path or query, not the destination.
  if (kind === "redirect" || kind === "ssrf") {
    const e = expr.trim();
    // a literal or a module constant (AUTH_URL, client.AUTH_URL) as the start fixes the host
    if (/^(?:FP\(|""\s*(?:\+|%)|(?:F\()?(?:[\w.]*\.)?[A-Z][A-Z0-9_]+\s*(?:[+,)]|$))/.test(e)) return false;
    // helpers that only add query parameters keep the destination given as their first argument
    const helper = /^[\w.]*(?:append|add|set|with|update)_?(?:query|params?)\w*\s*\(/i.exec(e);
    if (helper) return taintedFor(callArgs(e, helper[0].length - 1)[0] ?? "", kind, tainted);
  }
  let text = withoutSanitized(expr, kind);
  if (SOURCE.test(text)) return true;
  // A container that only holds request data under some literal keys is tainted only
  // when one of those keys is read; a whole-object taint is kept under the bare name.
  let hit = false;
  text = text.replace(KEY_READ, (all, name: string, a?: string, b?: string) => {
    if (tainted.get(`${name}[${a ?? b}]`)?.has(kind)) hit = true;
    return tainted.has(name) ? all : "0";
  });
  if (hit) return true;
  text = text.replace(/"[^"]*"/g, "\"\"");
  for (const m of text.matchAll(/(?<![\w.])[A-Za-z_]\w*/g)) {
    if (tainted.get(m[0])?.has(kind)) return true;
    // the whole container, e.g. "...".format(d), carries every key it holds
    for (const [name, kinds] of tainted) if (kinds.has(kind) && name.startsWith(`${m[0]}[`)) return true;
  }
  return false;
}

/** The kinds of sink this expression would be dangerous in. */
function taintKinds(expr: string, tainted: Taint): Set<PythonFlowKind> {
  return new Set(KINDS.filter((k) => taintedFor(expr, k, tainted)));
}

function merge(tainted: Taint, name: string, kinds: Set<PythonFlowKind>): void {
  if (!kinds.size) return;
  const prior = tainted.get(name);
  tainted.set(name, prior ? new Set([...prior, ...kinds]) : kinds);
}

// `x = helper(...)` / `a, b = helper(...)`: the whole value is one call of a bare-named function
const HELPER_CALL = /^([A-Za-z_]\w*)\s*\((?:[^()]|\([^()]*\))*\)$/;
// builtins and wrappers that pass a value on unchanged are not helpers that could check it
const NOT_HELPER = /^(?:str|bytes|repr|format|list|tuple|set|frozenset|dict|sorted|reversed|Path|PurePath|PosixPath|PurePosixPath|WindowsPath|PureWindowsPath|F|FP|open|getattr|join|normpath|normcase|abspath|realpath|relpath|dirname|expanduser|expandvars|fspath|cast|unquote|unquote_plus|quote|quote_plus|urljoin|strip|lower|upper|replace|decode|encode)$/;

type Sink = { kind: PythonFlowKind; pattern: RegExp; arg?: number; requires?: RegExp; unless?: RegExp };
const SINKS: Sink[] = [
  { kind: "sql", pattern: /\.(?:execute|executemany|executescript|raw)\s*\(/g },
  { kind: "command", pattern: /(?<![\w.])os\.(?:system|popen)\s*\(/g },
  { kind: "command", pattern: /(?<![\w.])subprocess\.(?:run|call|check_call|check_output|Popen)\s*\(/g, requires: /\bshell\s*=\s*True\b/ },
  { kind: "code", pattern: /(?<![\w.])(?:eval|exec)\s*\(/g },
  { kind: "template", pattern: /(?<![\w.])(?:flask\.)?(?:render_template_string|Markup|mark_safe)\s*\(/g },
  { kind: "xss", pattern: /(?<![\w.])(?:flask\.)?(?:make_response|HttpResponse)\s*\(/g },
  { kind: "path", pattern: /(?<![\w.])(?:codecs\.|io\.|os\.)?open\s*\(|(?<![\w.])(?:flask\.)?(?:send_file|FileResponse)\s*\(/g },
  { kind: "ssrf", pattern: /(?<![\w.])(?:requests|httpx)\.(?:get|post|put|patch|delete|head)\s*\(|(?<![\w])urlopen\s*\(/g },
  { kind: "ssrf", pattern: /(?<![\w.])(?:requests|httpx)\.request\s*\(/g, arg: 1 },
  { kind: "deserialize", pattern: /(?<![\w.])(?:pickle|marshal|dill)\.loads?\s*\(/g },
  { kind: "deserialize", pattern: /(?<![\w.])yaml\.(?:load|load_all)\s*\(/g, unless: /SafeLoader|CSafeLoader/ },
  { kind: "redirect", pattern: /(?<![\w.])(?:flask\.|shortcuts\.)?(?:redirect|HttpResponseRedirect|RedirectResponse)\s*\(/g },
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
  type Scope = { indent: number; name: string; flask: boolean; tainted: Taint; blocks: { indent: number; conditional: boolean }[];
    via: Map<string, string>; params: Set<string> };
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
      const tainted: Taint = new Map();
      if (route || djangoView) for (const name of params(def[2])) tainted.set(name, new Set(KINDS));
      // Flask sends a returned str as HTML; FastAPI encodes it as JSON and Django needs a response object.
      const flask = decorators.some((d) => /^@[\w.]*\.route\s*\(/.test(d));
      stack.push({ indent, name: def[1], flask, tainted, blocks: [], via: new Map(), params: new Set(tainted.keys()) });
      continue;
    }
    const scope = stack[stack.length - 1];
    if (!scope) continue;
    while (scope.blocks.length && indent <= scope.blocks[scope.blocks.length - 1].indent) scope.blocks.pop();
    // An assignment under if/else/for/while/except may not run, so it adds taint but never clears it.
    const conditional = scope.blocks.some((b) => b.conditional);
    const reported = new Set<PythonFlowKind>();
    const report = (kind: PythonFlowKind, sink: string, via?: string) => {
      if (reported.has(kind) || findings.length >= MAX_FINDINGS) return;
      reported.add(kind);
      findings.push({ kind, line, func: scope.name, sink, ...(via ? { via } : {}) });
    };
    for (const sink of SINKS) {
      sink.pattern.lastIndex = 0;
      for (const m of code.matchAll(sink.pattern)) {
        if (reported.has(sink.kind)) break;
        const args = callArgs(code, m.index + m[0].length - 1);
        const value = args[sink.arg ?? 0];
        if (value === undefined || /^\w+\s*=/.test(value) && !/^\w+\s*==/.test(value)) continue;
        if (sink.requires && !args.some((a) => sink.requires!.test(a))) continue;
        if (sink.unless && args.some((a) => sink.unless!.test(a))) continue;
        if (!taintedFor(value, sink.kind, scope.tainted)) continue;
        // a path whose every tainted name came back from a project helper: that helper's checks are not followed
        const names = [...new Set(value.match(/[A-Za-z_]\w*/g) ?? [])].filter((n) => scope.tainted.get(n)?.has(sink.kind));
        const via = sink.kind === "path" && names.length && names.every((n) => scope.via.has(n)) ? scope.via.get(names[0]) : undefined;
        report(sink.kind, m[0].replace(/\s*\($/, ""), via);
      }
    }
    // A Flask view that returns request data as a plain string sends it as HTML.
    const ret = /^return\s+(.+)$/.exec(code);
    if (ret && scope.flask && !NOT_HTML.test(ret[1]) && taintedFor(ret[1], "xss", scope.tainted)) report("xss", "return");
    if (/:\s*$/.test(code) && /^(?:if|elif|else|for|async\s+for|while|try|except|finally|with|async\s+with|match|case)\b/.test(code)) {
      // `if '..' in name:` (or '/', '\\') rejects path traversal for that name.
      // Only at the function's own level: a check inside another `if` leaves the other branch unchecked.
      const guard = /^if\s+"(?:\.\.?[/\\]?|[/\\])"\s+in\s+([A-Za-z_]\w*)\s*:/.exec(code);
      if (guard && !conditional) scope.tainted.get(guard[1])?.delete("path");
      // `if name not in allowed:` whose block exits: an allowlist, unless the collection is itself the
      // request (request.*, or a parameter of the view). One looked up by a request value is the server's.
      const member = /^if\s+([A-Za-z_]\w*)\s+not\s+in\s+(.+):\s*$/.exec(code);
      const exit = lines[index + 1];
      const fromRequest = (expr: string) => SOURCE.test(expr) || (expr.match(/[A-Za-z_]\w*/g) ?? []).some((n) =>
        scope.params.has(n) || (scope.tainted.get(n)?.size && !scope.via.has(n)));
      if (member && !conditional && exit && exit.indent > indent && /^(?:return|raise|abort)\b/.test(exit.code)
        && !new RegExp(`(?<![\\w.])${member[1]}(?![\\w])`).test(exit.code) && !fromRequest(member[2]))
        for (const k of ["redirect", "ssrf", "path"] as const) scope.tainted.get(member[1])?.delete(k);
      // `if not is_allowed_redirect(x):` (any allow/safe/valid/trusted check) whose block replaces x or exits
      const allow = /^if\s+not\s+[\w.]*(?:allow|safe|valid|trust)\w*\s*\(\s*([A-Za-z_]\w*)\b/i.exec(code);
      const next = lines[index + 1];
      if (allow && next && next.indent > indent
        && (/^(?:return|raise|abort)\b/.test(next.code) || new RegExp(`^${allow[1]}\\s*=\\s*(?:""|"[^"]*")\\s*$`).test(next.code)
          || new RegExp(`^${allow[1]}\\s*=`).test(next.code) && !taintKinds(next.code.split("=").slice(1).join("="), scope.tainted).size)) {
        for (const k of ["redirect", "ssrf", "path"] as const) scope.tainted.get(allow[1])?.delete(k);
        index++;    // the replacement inside the guard does not re-taint
      }
      // a containment check after resolving: p.is_relative_to(base), base in p.parents, commonpath
      for (const m of code.matchAll(/(?<![\w.])([A-Za-z_]\w*)\.(?:is_relative_to\s*\(|parents\b)|commonpath\s*\(\s*\[[^\]]*?(?<![\w.])([A-Za-z_]\w*)\s*\]/g))
        scope.tainted.get(m[1] ?? m[2])?.delete("path");
      const loop = /^(?:async\s+)?for\s+(.+?)\s+in\s+(.+):\s*$/.exec(code);
      if (loop) {
        const kinds = taintKinds(loop[2], scope.tainted);
        for (const name of loop[1].match(/[A-Za-z_]\w*/g) ?? []) merge(scope.tainted, name, kinds);
      }
      const asName = /^(?:async\s+)?with\s+(.+?)\s+as\s+([A-Za-z_]\w*)\s*:\s*$/.exec(code);
      if (asName) merge(scope.tainted, asName[2], taintKinds(asName[1], scope.tainted));
      scope.blocks.push({ indent, conditional: CONDITIONAL.test(code) });
      continue;
    }
    const mutate = MUTATOR.exec(code);
    if (mutate) {
      const args = callArgs(code, code.indexOf("(", mutate[1].length));
      // conf.set("section", "key", value) stores under one literal key
      const key = /\.set\s*\($/.test(mutate[0]) && args.length === 3 ? /^"([^"]*)"$/.exec(args[1])?.[1] : undefined;
      if (key !== undefined) merge(scope.tainted, `${mutate[1]}[${key}]`, taintKinds(args[2], scope.tainted));
      else merge(scope.tainted, mutate[1], taintKinds(args.join(","), scope.tainted));
      continue;
    }
    const assign = /^((?:[A-Za-z_]\w*\s*,\s*)*[A-Za-z_]\w*)\s*(?::[^=]+)?(\+?=)(?!=)\s*(.+)$/.exec(code);
    if (!assign) {
      // Storing into a container or attribute taints the whole object (never cleared).
      const store = STORE.exec(code);
      const key = store && /^\[\s*"([^"]*)"\s*\]$/.exec(store[2])?.[1];
      if (store) merge(scope.tainted, key !== undefined && key !== null ? `${store[1]}[${key}]` : store[1], taintKinds(store[3], scope.tainted));
      continue;
    }
    const names = assign[1].split(",").map((s) => s.trim());
    const values = names.length > 1 ? splitTop(assign[3].replace(/^\((.*)\)$/, "$1")) : [assign[3]];
    names.forEach((name, k) => {
      const value = values.length === names.length ? values[k] : assign[3];
      const kinds = taintKinds(value, scope.tainted);
      const called = HELPER_CALL.exec(value.trim())?.[1];
      const taintedNames = [...new Set(value.match(/[A-Za-z_]\w*/g) ?? [])].filter((n) => scope.tainted.get(n)?.size);
      const derived = !called && taintedNames.length > 0 && taintedNames.every((n) => scope.via.has(n)) ? scope.via.get(taintedNames[0]) : undefined;
      const helper = called && !NOT_HELPER.test(called) ? called : derived;
      const fromHelper = !!helper && kinds.size > 0;
      if (assign[2] === "+=" || conditional) {
        const before = scope.tainted.get(name)?.size;
        merge(scope.tainted, name, kinds);
        if (kinds.size && !(fromHelper && (!before || scope.via.has(name)))) scope.via.delete(name);
        else if (fromHelper && !before) scope.via.set(name, helper!);
      } else {
        if (kinds.size) scope.tainted.set(name, kinds);
        else scope.tainted.delete(name);
        if (fromHelper) scope.via.set(name, helper!);
        else scope.via.delete(name);
      }
    });
  }
  return findings;
}
